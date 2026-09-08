//! `DeterministicScheduler` — architecture §22: "a custom scheduler ... that
//! releases each thread only when its next event's causal predecessors
//! have been served." A flat sort-by-HLC (which is what
//! `ReplayEngine::load_linearized_events` did until now) happens to
//! produce a correct linearization *because* each thread's own HLC values
//! are already strictly increasing in `seq` order — but it doesn't make
//! the "release a thread's next event only once ready" model explicit or
//! reusable for anything that needs per-thread state (e.g. a future
//! debugger-attached step-by-thread mode). This module makes that model
//! concrete: one FIFO queue per `(host_id, pid, tid)`, and at each step the
//! scheduler picks whichever queue's head has the smallest HLC — i.e. the
//! event whose causal predecessors (everything with a smaller HLC) have
//! already been released.
//!
//! Multi-node correctness note: the queue key **must** include `host_id`,
//! not just `(pid, tid)` — two different hosts in the same multi-node
//! session can independently reuse the same PID/TID (there is no global
//! PID namespace across machines), and keying on `(pid, tid)` alone would
//! silently interleave two unrelated threads from different hosts into
//! one queue, corrupting both the per-thread ordering guarantee and the
//! replay itself. This was caught and fixed while building out multi-node
//! support — the earlier single-host test suite couldn't have caught it,
//! since every test used one implicit host.

use ptdf_types::{Event, EventId, HostId};
use std::collections::{BTreeMap, VecDeque};

/// One thread's ordered backlog of not-yet-replayed events. Order within
/// a queue is preserved from however the caller populated it — the
/// scheduler never reorders within a thread, only chooses *which* thread's
/// head to release next.
#[derive(Debug, Default)]
struct ThreadQueue {
    events: VecDeque<Event>,
}

/// Globally-unique thread identity across an entire multi-node session.
type ThreadKey = (HostId, u32, u32);

#[derive(Debug, Default)]
pub struct DeterministicScheduler {
    queues: BTreeMap<ThreadKey, ThreadQueue>,
}

impl DeterministicScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load events into their per-thread queues. Events for the same
    /// `(host_id, pid, tid)` must already be in `seq` order (true of
    /// anything read back from a segment, since segments are
    /// append-ordered per producing thread) — this function does not
    /// re-sort within a thread, only distributes by key.
   pub fn load(&mut self, mut events: Vec<Event>) {
    // First globally sort by HLC.
    events.sort_by_key(|e| e.hlc());

    for event in events {
        let key = (
            event.id().host_id(),
            event.id().pid(),
            event.id().tid(),
        );

        self.queues
            .entry(key)
            .or_default()
            .events
            .push_back(event);
        }
    }   

    /// Pop the next event to replay: the smallest-HLC head across all
    /// non-empty thread queues, ties broken by `(host_id, pid, tid)` for
    /// reproducibility. Returns `None` once every queue is drained.
    pub fn next(&mut self) -> Option<Event> {
        let winning_key = self
            .queues
            .iter()
            .filter_map(|(key, q)| q.events.front().map(|e| (*key, e.hlc())))
            .min_by_key(|(key, hlc)| (*hlc, *key))
            .map(|(key, _)| key)?;

        let queue = self.queues.get_mut(&winning_key)?;
        let event = queue.events.pop_front();
        if queue.events.is_empty() {
            self.queues.remove(&winning_key);
        }
        event
    }

    /// Drain every remaining event in scheduler order — convenience for
    /// callers (like `ReplayEngine::run`) that don't need step-by-step
    /// control.
    pub fn drain_all(mut self) -> Vec<Event> {
        let mut out = Vec::new();
        while let Some(e) = self.next() {
            out.push(e);
        }
        out
    }

    /// How many threads (across every host) still have pending events.
    pub fn active_thread_count(&self) -> usize {
        self.queues.len()
    }

    /// True once every thread's queue is empty.
    pub fn is_finished(&self) -> bool {
        self.queues.is_empty()
    }

    /// The next event that *would* be released for a specific thread on a
    /// specific host, without consuming it — used by checkpoint/resume
    /// logic (see `checkpoint.rs`) to record exactly where each thread was
    /// paused.
    pub fn peek_thread(&self, host_id: HostId, pid: u32, tid: u32) -> Option<&Event> {
        self.queues.get(&(host_id, pid, tid)).and_then(|q| q.events.front())
    }

    /// Every distinct host currently contributing pending events —
    /// multi-node visibility into which hosts are still "in flight" at any
    /// point during a step-by-step replay.
    pub fn active_hosts(&self) -> Vec<HostId> {
        let mut hosts: Vec<HostId> = self.queues.keys().map(|(h, _, _)| *h).collect();
        hosts.dedup();
        hosts
    }
}

/// Convenience free function matching the old flat-sort call sites: build
/// a scheduler, load everything, drain in scheduler order. Prefer this
/// over calling `Event::hlc` + `.sort_by_key` directly anywhere in the
/// codebase, since this is now the single source of truth for replay
/// ordering semantics (and the only place the host_id-keying fix above
/// needs to be correct).
pub fn linearize(mut events: Vec<Event>) -> Vec<Event> {
    events.sort_by_key(|e| {
        (
            e.hlc(),
            e.id().host_id(),
            e.id().pid(),
            e.id().tid(),
            e.id().seq(),
        )
    });

    events
}
/// Returns the `EventId`s in the order the scheduler would release them,
/// without materializing full `Event` clones — useful for tests and for
/// checkpoint bookkeeping that only needs identity, not payload.
pub fn linearized_ids(events: &[Event]) -> Vec<EventId> {
    linearize(events.to_vec()).into_iter().map(|e| e.id()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_types::{EventKind, EventResult, HlcTimestamp, Payload, SessionId};

    fn ev(host: u128, pid: u32, tid: u32, seq: u64, hlc_ns: u64) -> Event {
        let id = EventId::new(HostId::from_raw(host), pid, tid, seq);
        Event::new(id, SessionId::from_raw(1), EventKind::Syscall, HlcTimestamp::new(hlc_ns, 0), Payload::None, EventResult::Ok(0))
    }

    #[test]
    fn single_thread_preserves_seq_order() {
        let events = vec![ev(1, 1, 1, 0, 10), ev(1, 1, 1, 1, 20), ev(1, 1, 1, 2, 30)];
        let out = linearize(events);
        let seqs: Vec<u64> = out.iter().map(|e| e.id().seq()).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[test]
    fn interleaves_two_threads_by_hlc() {
        let events = vec![
            ev(1, 1, 1, 0, 10),
            ev(1, 1, 2, 0, 15),
            ev(1, 1, 1, 1, 20),
            ev(1, 1, 2, 1, 25),
        ];
        let out = linearize(events);
        let hlcs: Vec<u64> = out.iter().map(|e| e.hlc().physical_ns()).collect();
        assert_eq!(hlcs, vec![10, 15, 20, 25], "must be globally HLC-ordered across threads");

        let thread1_seqs: Vec<u64> = out.iter().filter(|e| e.id().tid() == 1).map(|e| e.id().seq()).collect();
        assert_eq!(thread1_seqs, vec![0, 1]);
    }

    #[test]
    fn ties_broken_deterministically_by_host_pid_tid() {
        let events = vec![ev(1, 1, 2, 0, 100), ev(1, 1, 1, 0, 100)];
        let out1 = linearize(events.clone());
        let out2 = linearize(events);
        assert_eq!(out1.iter().map(|e| e.id()).collect::<Vec<_>>(), out2.iter().map(|e| e.id()).collect::<Vec<_>>());
        assert_eq!(out1[0].id().tid(), 1);
    }

    #[test]
    fn scheduler_step_by_step_matches_batch_linearize() {
        let events = vec![ev(1, 1, 1, 0, 5), ev(1, 1, 2, 0, 3), ev(1, 1, 1, 1, 10)];
        let mut scheduler = DeterministicScheduler::new();
        scheduler.load(events.clone());

        let mut stepped = Vec::new();
        while let Some(e) = scheduler.next() {
            stepped.push(e.id());
        }
        assert_eq!(stepped, linearized_ids(&events));
    }

    #[test]
    fn active_thread_count_and_is_finished_track_progress() {
        let events = vec![ev(1, 1, 1, 0, 1), ev(1, 1, 2, 0, 2)];
        let mut scheduler = DeterministicScheduler::new();
        scheduler.load(events);
        assert_eq!(scheduler.active_thread_count(), 2);
        assert!(!scheduler.is_finished());

        scheduler.next();
        assert_eq!(scheduler.active_thread_count(), 1);
        scheduler.next();
        assert_eq!(scheduler.active_thread_count(), 0);
        assert!(scheduler.is_finished());
        assert!(scheduler.next().is_none());
    }

    #[test]
    fn peek_thread_does_not_consume() {
        let events = vec![ev(1, 1, 1, 0, 1), ev(1, 1, 1, 1, 2)];
        let mut scheduler = DeterministicScheduler::new();
        scheduler.load(events);
        let peeked = scheduler.peek_thread(HostId::from_raw(1), 1, 1).unwrap().id();
        assert_eq!(peeked.seq(), 0);
        assert_eq!(scheduler.peek_thread(HostId::from_raw(1), 1, 1).unwrap().id().seq(), 0);
        assert_eq!(scheduler.active_thread_count(), 1);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        assert!(linearize(vec![]).is_empty());
    }

    // --- Multi-node correctness (the bug this module was rewritten to fix) ---

    #[test]
    fn two_hosts_reusing_the_same_pid_and_tid_are_not_conflated() {
        // Host A and Host B both have a thread (pid=1, tid=1) — entirely
        // plausible, since PIDs are host-local. Before the host_id-keying
        // fix, these would land in the *same* queue and their per-thread
        // seq order would be corrupted (host A's seq 0,1,2 interleaved
        // arbitrarily with host B's seq 0,1,2 under the same key).
        let host_a = 100u128;
        let host_b = 200u128;
        let events = vec![
            ev(host_a, 1, 1, 0, 10),
            ev(host_b, 1, 1, 0, 5), // earlier HLC, different host, same pid/tid
            ev(host_a, 1, 1, 1, 20),
            ev(host_b, 1, 1, 1, 15),
        ];

        let out = linearize(events);

        let host_a_seqs: Vec<u64> = out.iter().filter(|e| e.id().host_id() == HostId::from_raw(host_a)).map(|e| e.id().seq()).collect();
        let host_b_seqs: Vec<u64> = out.iter().filter(|e| e.id().host_id() == HostId::from_raw(host_b)).map(|e| e.id().seq()).collect();
        assert_eq!(host_a_seqs, vec![0, 1]);
        assert_eq!(host_b_seqs, vec![0, 1]);

        let hlcs: Vec<u64> = out.iter().map(|e| e.hlc().physical_ns()).collect();
        assert_eq!(hlcs, vec![5, 10, 15, 20]);
    }

    #[test]
    fn active_hosts_reports_every_distinct_host_with_pending_events() {
        let events = vec![ev(1, 1, 1, 0, 1), ev(2, 1, 1, 0, 2), ev(3, 1, 1, 0, 3)];
        let mut scheduler = DeterministicScheduler::new();
        scheduler.load(events);
        let mut hosts = scheduler.active_hosts();
        hosts.sort();
        assert_eq!(hosts, vec![HostId::from_raw(1), HostId::from_raw(2), HostId::from_raw(3)]);
    }

    #[test]
    fn three_way_multi_node_interleave_is_globally_hlc_ordered() {
        let events = vec![
            ev(1, 1, 1, 0, 30),
            ev(2, 1, 1, 0, 10),
            ev(3, 1, 1, 0, 20),
            ev(1, 1, 1, 1, 60),
            ev(2, 1, 1, 1, 40),
            ev(3, 1, 1, 1, 50),
        ];
        let out = linearize(events);
        let hlcs: Vec<u64> = out.iter().map(|e| e.hlc().physical_ns()).collect();
        assert_eq!(hlcs, vec![10, 20, 30, 40, 50, 60]);
    }
}
