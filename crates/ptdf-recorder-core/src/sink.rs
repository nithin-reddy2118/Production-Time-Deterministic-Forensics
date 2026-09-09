//! `RecorderSink` — where platform adapters (implementors of
//! `ptdf_pal::PlatformInterceptor`) push captured events. The default
//! implementation, `BoundedSink`, is the local buffering stage from
//! architecture §5 step 4: a size-bounded queue that, under backpressure,
//! sheds non-load-bearing events first (§8) rather than blocking the
//! capture path or dropping load-bearing (syscall/network/signal) events.
//!
//! `BoundedSink` is deliberately synchronous and lock-based (`Mutex`-guarded
//! `VecDeque`), not lock-free, for Module 1. Architecture §22 specifies a
//! lock-free single-writer-per-CPU ring buffer as the production target;
//! that's a drop-in replacement behind this same `RecorderSink` trait once
//! Module 5 needs the real per-CPU throughput, and is intentionally not
//! built prematurely here — a correct, testable, simple implementation is
//! more valuable at this stage than an unverified lock-free one.

use ptdf_types::Event;
use std::collections::VecDeque;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SinkError {
    #[error("sink is closed and no longer accepts events")]
    Closed,
}

/// Where captured events go. Kept minimal and synchronous; the shipping
/// stage (agent → ingestion, §5 step 5) is a separate consumer that drains
/// via `drain_batch`, not part of this trait.
pub trait RecorderSink: Send + Sync {
    /// Push a captured event. May silently shed the event (see
    /// `BoundedSink` doc) rather than erroring, *unless* the sink is
    /// closed, in which case `Err(SinkError::Closed)` is returned so the
    /// caller (the adapter) knows recording has stopped.
    fn push(&self, event: Event) -> Result<(), SinkError>;

    /// Total events shed since the sink was created (for the overhead
    /// metrics in §25).
    fn shed_count(&self) -> u64;
}

#[derive(Debug)]
struct BoundedSinkState {
    queue: VecDeque<Event>,
    closed: bool,
}

/// A capacity-bounded `RecorderSink`. When full:
///   - Load-bearing events (`Event::is_load_bearing`, §8) evict the oldest
///     *non*-load-bearing event to make room, if one exists.
///   - If no non-load-bearing event can be evicted (queue is all
///     load-bearing), the new load-bearing event is still accepted by
///     growing past `capacity` — architecture §8 is explicit that
///     load-bearing events "never shed"; a bounded queue that drops them
///     would violate that guarantee, so bounded here means "soft target",
///     not "hard cap" for the load-bearing subset.
///   - Non-load-bearing events are dropped (shed) when full and no
///     load-bearing eviction is needed.
#[derive(Debug)]
pub struct BoundedSink {
    state: Mutex<BoundedSinkState>,
    capacity: usize,
    shed_count: std::sync::atomic::AtomicU64,
}

impl BoundedSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(BoundedSinkState {
                queue: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            capacity,
            shed_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Drain up to `max` events for shipping (§5 step 5). Returns fewer
    /// than `max` if the queue has less available; never blocks.
    pub fn drain_batch(&self, max: usize) -> Vec<Event> {
        let mut state = self.state.lock().expect("BoundedSink mutex poisoned");
        let n = max.min(state.queue.len());
        state.queue.drain(..n).collect()
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("BoundedSink mutex poisoned")
            .queue
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn close(&self) {
        self.state
            .lock()
            .expect("BoundedSink mutex poisoned")
            .closed = true;
    }
}

impl RecorderSink for BoundedSink {
    fn push(&self, event: Event) -> Result<(), SinkError> {
        let mut state = self.state.lock().expect("BoundedSink mutex poisoned");
        if state.closed {
            return Err(SinkError::Closed);
        }

        if state.queue.len() < self.capacity {
            state.queue.push_back(event);
            return Ok(());
        }

        // Queue is at capacity: try to make room.
        if event.is_load_bearing() {
            // Evict the oldest non-load-bearing event to make room, if any.
            if let Some(pos) = state.queue.iter().position(|e| !e.is_load_bearing()) {
                state.queue.remove(pos);
                self.shed_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                state.queue.push_back(event);
            } else {
                // Entirely load-bearing queue: grow past capacity rather
                // than drop a load-bearing event (§8 guarantee).
                state.queue.push_back(event);
            }
        } else {
            // Non-load-bearing and queue is full: shed the incoming event.
            self.shed_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }

    fn shed_count(&self) -> u64 {
        self.shed_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_types::{EventKind, EventResult, HlcTimestamp, HostId, Payload, SessionId};

    fn make_event(kind: EventKind, seq: u64) -> Event {
        let host = HostId::from_raw(1);
        let id = ptdf_types::EventId::new(host, 1, 1, seq);
        Event::new(
            id,
            SessionId::from_raw(1),
            kind,
            HlcTimestamp::new(seq, 0),
            Payload::None,
            EventResult::Ok(0),
        )
    }

    #[test]
    fn push_and_drain_preserve_order_below_capacity() {
        let sink = BoundedSink::new(10);
        for i in 0..5 {
            sink.push(make_event(EventKind::Syscall, i)).unwrap();
        }
        assert_eq!(sink.len(), 5);
        let drained = sink.drain_batch(100);
        assert_eq!(drained.len(), 5);
        for (i, ev) in drained.iter().enumerate() {
            assert_eq!(ev.id().seq(), i as u64);
        }
        assert!(sink.is_empty());
    }

    #[test]
    fn non_load_bearing_events_are_shed_when_full() {
        let sink = BoundedSink::new(2);
        sink.push(make_event(EventKind::ClockRead, 0)).unwrap();
        sink.push(make_event(EventKind::ClockRead, 1)).unwrap();
        // Queue full of non-load-bearing events; next non-load-bearing push sheds.
        sink.push(make_event(EventKind::ClockRead, 2)).unwrap();
        assert_eq!(sink.len(), 2, "queue must stay at capacity");
        assert_eq!(sink.shed_count(), 1);
    }

    #[test]
    fn load_bearing_events_evict_non_load_bearing_rather_than_being_shed() {
        let sink = BoundedSink::new(2);
        sink.push(make_event(EventKind::ClockRead, 0)).unwrap();
        sink.push(make_event(EventKind::ClockRead, 1)).unwrap();
        sink.push(make_event(EventKind::Syscall, 2)).unwrap();

        assert_eq!(sink.len(), 2);
        assert_eq!(
            sink.shed_count(),
            1,
            "one ClockRead was evicted to make room"
        );
        let drained = sink.drain_batch(10);
        let kinds: Vec<_> = drained.iter().map(|e| e.kind()).collect();
        assert!(
            kinds.contains(&EventKind::Syscall),
            "the load-bearing event must survive"
        );
    }

    #[test]
    fn load_bearing_events_are_never_shed_even_when_queue_is_all_load_bearing() {
        let sink = BoundedSink::new(2);
        sink.push(make_event(EventKind::Syscall, 0)).unwrap();
        sink.push(make_event(EventKind::Syscall, 1)).unwrap();
        sink.push(make_event(EventKind::NetIo, 2)).unwrap();

        assert_eq!(
            sink.len(),
            3,
            "queue must grow past capacity rather than drop a load-bearing event"
        );
        assert_eq!(
            sink.shed_count(),
            0,
            "no load-bearing event may ever be counted as shed"
        );
    }

    #[test]
    fn push_after_close_is_rejected() {
        let sink = BoundedSink::new(10);
        sink.close();
        let err = sink.push(make_event(EventKind::Syscall, 0)).unwrap_err();
        assert_eq!(err, SinkError::Closed);
    }

    #[test]
    fn drain_batch_respects_max_and_leaves_remainder() {
        let sink = BoundedSink::new(10);
        for i in 0..5 {
            sink.push(make_event(EventKind::Syscall, i)).unwrap();
        }
        let first = sink.drain_batch(3);
        assert_eq!(first.len(), 3);
        assert_eq!(sink.len(), 2);
        let second = sink.drain_batch(100);
        assert_eq!(second.len(), 2);
    }
}
