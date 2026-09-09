//! `SeqAllocator` — owns the strictly-monotonic per-thread sequence counter
//! that `ptdf-types::EventId`'s uniqueness proof depends on (see
//! `ptdf-types::ids` module docs). Exactly one `SeqAllocator` must exist per
//! `(pid, tid)` being recorded; this is enforced structurally by the
//! recorder core owning allocation per capture thread rather than letting
//! adapters mint their own sequence numbers.

#[derive(Debug)]
pub struct SeqAllocator {
    pid: u32,
    tid: u32,
    next: u64,
}

impl SeqAllocator {
    pub const fn new(pid: u32, tid: u32) -> Self {
        Self { pid, tid, next: 0 }
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn tid(&self) -> u32 {
        self.tid
    }

    /// Allocate the next sequence number. Panics on overflow rather than
    /// silently wrapping, because a wrapped sequence number would violate
    /// the `EventId` uniqueness proof — at ~10^9 events/sec sustained this
    /// would take >500 years to hit, so a panic here indicates a bug
    /// (e.g. a shared allocator being reused across threads), not a
    /// reachable production condition.
    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next;
        self.next = self.next.checked_add(1).expect(
            "SeqAllocator overflow: u64 sequence exhausted — this indicates allocator reuse \
             across threads, which violates the EventId uniqueness invariant",
        );
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_starts_at_zero_and_increments() {
        let mut a = SeqAllocator::new(1, 1);
        assert_eq!(a.next_seq(), 0);
        assert_eq!(a.next_seq(), 1);
        assert_eq!(a.next_seq(), 2);
    }

    #[test]
    fn pid_tid_are_preserved() {
        let a = SeqAllocator::new(42, 7);
        assert_eq!(a.pid(), 42);
        assert_eq!(a.tid(), 7);
    }

    #[test]
    #[should_panic(expected = "SeqAllocator overflow")]
    fn overflow_panics_rather_than_wraps() {
        let mut a = SeqAllocator {
            pid: 1,
            tid: 1,
            next: u64::MAX,
        };
        a.next_seq();
    }
}
