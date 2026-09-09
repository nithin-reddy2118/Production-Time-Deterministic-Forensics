//! Causality tracking: Hybrid Logical Clock (HLC) per architecture §15.
//!
//! We use a single HLC value per event (wall-time + logical counter) rather
//! than a full vector clock with one counter per host. Rationale: a vector
//! clock's size grows with the number of hosts in the session, which is
//! unbounded for a production fleet and would bloat every single recorded
//! event. An HLC gives us:
//!   - A total order consistent with causality when combined with the
//!     explicit happens-before edges recorded separately (§9, §15) for
//!     cross-thread/cross-host synchronization points.
//!   - Human-readable, monotonically-useful timestamps for free.
//!   - O(1) per-event size regardless of fleet size.
//!
//! Reference: Kulkarni et al., "Logical Physical Clocks and Consistent
//! Snapshots in Globally Distributed Databases" (HLC paper).

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

/// A Hybrid Logical Clock timestamp: (physical_ns, logical_counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HlcTimestamp {
    physical_ns: u64,
    logical: u32,
}

impl HlcTimestamp {
    pub const fn new(physical_ns: u64, logical: u32) -> Self {
        Self {
            physical_ns,
            logical,
        }
    }

    pub const fn physical_ns(&self) -> u64 {
        self.physical_ns
    }

    pub const fn logical(&self) -> u32 {
        self.logical
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.physical_ns, self.logical).cmp(&(other.physical_ns, other.logical))
    }
}

/// Source of physical time. Abstracted so tests can inject a fake clock and
/// so the recorder's real implementation (Module 5) can plug in a
/// platform-specific monotonic-but-wall-aligned source (`CLOCK_TAI`-derived
/// on Linux, `QueryPerformanceCounter`-derived on Windows) without this
/// crate depending on either platform.
pub trait PhysicalClock {
    fn now_ns(&self) -> u64;
}

/// Default physical clock backed by `SystemTime`. Adequate for tests and
/// for any host where sub-microsecond wall-clock precision isn't required;
/// the recorder crate overrides this with a platform-specific source.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPhysicalClock;

impl PhysicalClock for SystemPhysicalClock {
    fn now_ns(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos() as u64
    }
}

/// A single HLC generator. One instance is owned per recording thread
/// (never shared without synchronization — see `ptdf-recorder-core`).
#[derive(Debug)]
pub struct HlcGenerator<C: PhysicalClock = SystemPhysicalClock> {
    clock: C,
    last: HlcTimestamp,
}

impl<C: PhysicalClock> HlcGenerator<C> {
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            last: HlcTimestamp::new(0, 0),
        }
    }

    /// Produce the next local HLC value. Monotonic even if the physical
    /// clock stalls or goes backwards (NTP step, VM migration, etc.).
    pub fn tick(&mut self) -> HlcTimestamp {
        let physical_now = self.clock.now_ns();
        let next = if physical_now > self.last.physical_ns {
            HlcTimestamp::new(physical_now, 0)
        } else {
            HlcTimestamp::new(self.last.physical_ns, self.last.logical + 1)
        };
        self.last = next;
        next
    }

    /// Merge in a remote HLC value observed on a received event (e.g. a
    /// `NetIO` recv whose payload carried the sender's HLC, per §15), then
    /// produce the local event's timestamp. This is what creates the
    /// happens-before edge across hosts without any synchronization
    /// protocol beyond piggybacking the value on data already in flight.
    pub fn receive(&mut self, remote: HlcTimestamp) -> HlcTimestamp {
        let physical_now = self.clock.now_ns();
        let max_physical = physical_now
            .max(self.last.physical_ns)
            .max(remote.physical_ns);
        let next = if max_physical == self.last.physical_ns && max_physical == remote.physical_ns {
            HlcTimestamp::new(max_physical, self.last.logical.max(remote.logical) + 1)
        } else if max_physical == self.last.physical_ns {
            HlcTimestamp::new(max_physical, self.last.logical + 1)
        } else if max_physical == remote.physical_ns {
            HlcTimestamp::new(max_physical, remote.logical + 1)
        } else {
            HlcTimestamp::new(max_physical, 0)
        };
        self.last = next;
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Deterministic fake clock for tests: returns a pre-programmed
    /// sequence, repeating the last value once exhausted.
    struct FakeClock {
        values: Vec<u64>,
        idx: Cell<usize>,
    }

    impl FakeClock {
        fn new(values: Vec<u64>) -> Self {
            Self {
                values,
                idx: Cell::new(0),
            }
        }
    }

    impl PhysicalClock for FakeClock {
        fn now_ns(&self) -> u64 {
            let i = self.idx.get();
            let v = *self.values.get(i).unwrap_or(self.values.last().unwrap());
            self.idx.set((i + 1).min(self.values.len() - 1));
            v
        }
    }

    #[test]
    fn tick_advances_physical_when_clock_advances() {
        let mut hlc = HlcGenerator::new(FakeClock::new(vec![100, 200, 300]));
        let a = hlc.tick();
        let b = hlc.tick();
        assert!(b > a);
        assert_eq!(a.physical_ns(), 100);
        assert_eq!(b.physical_ns(), 200);
        assert_eq!(b.logical(), 0);
    }

    #[test]
    fn tick_bumps_logical_when_physical_clock_stalls() {
        // Clock returns the same value repeatedly (stall / low resolution).
        let mut hlc = HlcGenerator::new(FakeClock::new(vec![100]));
        let a = hlc.tick();
        let b = hlc.tick();
        let c = hlc.tick();
        assert!(
            a < b && b < c,
            "HLC must stay monotonic under a stalled clock"
        );
        assert_eq!(a.physical_ns(), 100);
        assert_eq!(b.physical_ns(), 100);
        assert_eq!(b.logical(), 1);
        assert_eq!(c.logical(), 2);
    }

    #[test]
    fn tick_is_monotonic_even_if_physical_clock_goes_backwards() {
        let mut hlc = HlcGenerator::new(FakeClock::new(vec![500, 100]));
        let a = hlc.tick();
        let b = hlc.tick(); // physical clock "jumps back" to 100 (e.g. NTP step)
        assert!(b > a, "HLC must never go backwards even if wall clock does");
        assert_eq!(b.physical_ns(), 500);
        assert_eq!(b.logical(), 1);
    }

    #[test]
    fn receive_advances_past_a_remote_timestamp_from_the_future() {
        let mut local = HlcGenerator::new(FakeClock::new(vec![100]));
        let remote = HlcTimestamp::new(1_000_000, 5);
        let observed = local.receive(remote);
        assert!(
            observed > remote,
            "receiving must create a happens-after event"
        );
        assert_eq!(observed.physical_ns(), 1_000_000);
        assert_eq!(observed.logical(), 6);
    }

    #[test]
    fn receive_is_a_noop_advance_when_local_is_already_ahead() {
        let mut local = HlcGenerator::new(FakeClock::new(vec![1_000_000]));
        let _ = local.tick(); // local.last = (1_000_000, 0)
        let remote = HlcTimestamp::new(100, 0); // remote is "behind"
        let observed = local.receive(remote);
        assert_eq!(observed.physical_ns(), 1_000_000);
        assert_eq!(observed.logical(), 1);
    }
}
