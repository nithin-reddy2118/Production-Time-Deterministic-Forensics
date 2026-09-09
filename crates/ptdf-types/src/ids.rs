//! Identifier types.
//!
//! Design decision: IDs are opaque 128-bit values constructed by the
//! *caller* rather than generated internally via a RNG/UUID dependency.
//! Rationale:
//!   - `HostId` is assigned once at agent provisioning time by the control
//!     plane (which already needs a proper UUIDv4/v7 + CSPRNG story tied to
//!     its cert issuance, see Security Architecture §18). Generating a second,
//!     weaker ID scheme here would be redundant and a potential source of
//!     collisions if the two ever diverge.
//!   - `EventId` is NOT random at all — see `EventId::new`, it is
//!     deterministically derived from `(HostId, pid, tid, seq)`, which is
//!     strictly better than a random UUID for this field: it's collision-free
//!     by construction, sorts usefully, and is reproducible for testing.
//!   - `SessionId` is control-plane-assigned for the same reason as `HostId`.
//!
//! This keeps `ptdf-types` dependency-free (no `uuid`, no RNG) which matters
//! because it is a transitive dependency of the recorder's hot path.

use std::fmt;

macro_rules! opaque_id128 {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u128);

        impl $name {
            /// Construct from a raw 128-bit value. Callers are responsible
            /// for uniqueness (see module docs).
            pub const fn from_raw(raw: u128) -> Self {
                Self(raw)
            }

            pub const fn as_raw(self) -> u128 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:032x}", self.0)
            }
        }
    };
}

opaque_id128!(HostId);
opaque_id128!(SessionId);

/// Deterministic per-event identifier.
///
/// Uniqueness proof: for a fixed `HostId`, `(pid, tid, seq)` is unique
/// because `seq` is a strictly monotonic per-thread counter owned by a
/// single recorder thread (see `ptdf-recorder-core::SeqAllocator`, Module 5).
/// Across hosts, `HostId` is unique by control-plane assignment. Therefore
/// the 128-bit packing below is collision-free without any randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId {
    host_id: HostId,
    pid: u32,
    tid: u32,
    seq: u64,
}

impl EventId {
    pub const fn new(host_id: HostId, pid: u32, tid: u32, seq: u64) -> Self {
        Self {
            host_id,
            pid,
            tid,
            seq,
        }
    }

    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn tid(&self) -> u32 {
        self.tid
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}/{}", self.host_id, self.pid, self.tid, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_id_roundtrip() {
        let h = HostId::from_raw(0xDEAD_BEEF);
        assert_eq!(h.as_raw(), 0xDEAD_BEEF);
    }

    #[test]
    fn event_id_distinguishes_all_fields() {
        let h1 = HostId::from_raw(1);
        let h2 = HostId::from_raw(2);
        let a = EventId::new(h1, 10, 20, 30);
        let b = EventId::new(h2, 10, 20, 30);
        let c = EventId::new(h1, 11, 20, 30);
        let d = EventId::new(h1, 10, 21, 30);
        let e = EventId::new(h1, 10, 20, 31);
        let ids = [a, b, c, d, e];
        for i in 0..ids.len() {
            for j in 0..ids.len() {
                if i != j {
                    assert_ne!(ids[i], ids[j], "ids[{i}] and ids[{j}] must differ");
                }
            }
        }
    }

    #[test]
    fn event_id_ordering_is_by_field_order() {
        let h = HostId::from_raw(1);
        let low = EventId::new(h, 1, 1, 1);
        let high = EventId::new(h, 1, 1, 2);
        assert!(low < high);
    }

    #[test]
    fn display_formats_are_stable() {
        let h = HostId::from_raw(0x1);
        assert_eq!(format!("{h}"), "00000000000000000000000000000001");
    }
}
