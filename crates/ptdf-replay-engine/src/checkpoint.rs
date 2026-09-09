//! Checkpointing (architecture "Checkpoint System"). A checkpoint here is
//! a position in the *deterministically linearized* event stream for a
//! session — since `scheduler::linearize` is a pure function of the
//! session's recorded events, the same session always linearizes to the
//! same sequence, which is exactly what makes "resume replay from index N"
//! well-defined and safe: re-running `load_linearized_events` for the same
//! session and jumping to `event_index` reproduces the identical
//! prior-history that would have been served by running from the start.
//!
//! `validate` guards against the one way this could go wrong in practice:
//! the underlying segments changing between when a checkpoint was taken
//! and when it's resumed (e.g. a segment file was deleted/replaced) — it
//! re-checks that the event actually at `event_index` today is still the
//! same `EventId` the checkpoint was taken against, and refuses to resume
//! silently onto a different history otherwise.

use ptdf_types::{Event, EventId};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("checkpoint event_index {index} is out of range for a stream of {stream_len} events")]
    IndexOutOfRange { index: usize, stream_len: usize },

    #[error("checkpoint is stale: expected event {expected} at index {index}, but the current linearization has {found} there — the underlying segments changed since this checkpoint was taken")]
    Stale {
        index: usize,
        expected: EventId,
        found: EventId,
    },
}

/// A resumable position within one session's linearized replay stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayCheckpoint {
    /// Index into the linearized event vector (`scheduler::linearize`'s
    /// output) of the *next* event to replay — i.e. everything before this
    /// index has already been served.
    pub event_index: usize,
    /// The event expected at `event_index`, captured at checkpoint-creation
    /// time, for staleness detection (see `validate`).
    pub next_event_id: EventId,
}

impl ReplayCheckpoint {
    /// Take a checkpoint at `event_index` within `linearized_events`.
    /// Returns `None` if `event_index >= linearized_events.len()` (there's
    /// nothing left to resume from — the replay is already complete).
    pub fn take(linearized_events: &[Event], event_index: usize) -> Option<Self> {
        linearized_events.get(event_index).map(|e| Self {
            event_index,
            next_event_id: e.id(),
        })
    }

    /// Confirm this checkpoint is still valid against a freshly-loaded
    /// linearization of the same session, per the module-level staleness
    /// rationale.
    pub fn validate(&self, linearized_events: &[Event]) -> Result<(), CheckpointError> {
        let found =
            linearized_events
                .get(self.event_index)
                .ok_or(CheckpointError::IndexOutOfRange {
                    index: self.event_index,
                    stream_len: linearized_events.len(),
                })?;

        if found.id() != self.next_event_id {
            return Err(CheckpointError::Stale {
                index: self.event_index,
                expected: self.next_event_id,
                found: found.id(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_types::{EventKind, EventResult, HlcTimestamp, HostId, Payload, SessionId};

    fn ev(seq: u64) -> Event {
        let id = EventId::new(HostId::from_raw(1), 1, 1, seq);
        Event::new(
            id,
            SessionId::from_raw(1),
            EventKind::Syscall,
            HlcTimestamp::new(seq, 0),
            Payload::None,
            EventResult::Ok(0),
        )
    }

    #[test]
    fn take_and_validate_round_trip_on_unchanged_stream() {
        let events: Vec<Event> = (0..5).map(ev).collect();
        let checkpoint = ReplayCheckpoint::take(&events, 2).unwrap();
        assert_eq!(checkpoint.next_event_id, events[2].id());
        assert!(checkpoint.validate(&events).is_ok());
    }

    #[test]
    fn take_at_end_of_stream_returns_none() {
        let events: Vec<Event> = (0..3).map(ev).collect();
        assert!(ReplayCheckpoint::take(&events, 3).is_none());
        assert!(ReplayCheckpoint::take(&events, 100).is_none());
    }

    #[test]
    fn validate_detects_out_of_range_after_stream_shrinks() {
        let events: Vec<Event> = (0..5).map(ev).collect();
        let checkpoint = ReplayCheckpoint::take(&events, 4).unwrap();
        let shrunk: Vec<Event> = events[..2].to_vec();
        assert_eq!(
            checkpoint.validate(&shrunk),
            Err(CheckpointError::IndexOutOfRange {
                index: 4,
                stream_len: 2
            })
        );
    }

    #[test]
    fn validate_detects_staleness_when_history_changed() {
        let events: Vec<Event> = (0..5).map(ev).collect();
        let checkpoint = ReplayCheckpoint::take(&events, 2).unwrap();

        // Simulate the underlying segments having been rewritten with
        // different content at the same position.
        let mut changed = events.clone();
        changed[2] = Event::new(
            EventId::new(HostId::from_raw(1), 9, 9, 999),
            SessionId::from_raw(1),
            EventKind::Syscall,
            HlcTimestamp::new(2, 0),
            Payload::None,
            EventResult::Ok(0),
        );

        let err = checkpoint.validate(&changed).unwrap_err();
        assert!(matches!(err, CheckpointError::Stale { .. }));
    }
}
