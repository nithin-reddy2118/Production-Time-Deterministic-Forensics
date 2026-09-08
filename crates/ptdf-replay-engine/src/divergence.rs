//! Standalone divergence detection (architecture §6 step 4).
//!
//! `ptdf_pal::ReplayDriver::step` already returns `StepOutcome::Diverged`
//! as the *result* of a divergence check, but until now each driver
//! implementation had to invent its own comparison logic to decide when a
//! divergence has occurred. This module gives every driver (Linux, and
//! eventually Windows/macOS) one shared, tested comparator: feed it what
//! was *expected* (the next recorded `Event`) and what was *actually
//! observed* live, and it returns the verdict. This is what makes
//! divergence detection a platform-independent policy rather than N
//! reimplementations of "do these two things match".

use ptdf_pal::Divergence;
use ptdf_types::{Event, EventKind, EventResult};

/// What a driver observed live, in platform-neutral terms, at the point
/// where it expected to serve `expected`. Drivers construct this from
/// whatever platform-specific signal they have (a ptrace syscall number,
/// an ETW event) by mapping it through their own syscall/event table
/// (e.g. `ptdf_pal_linux::syscall_table::lookup`) before calling
/// `check` — this module deliberately has zero platform dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedOperation {
    pub kind: EventKind,
    /// Human-readable detail for the divergence report if this doesn't
    /// match — e.g. `"write(fd=4, len=128)"`. Not used for comparison
    /// itself (only `kind` and, when both are syscalls, `result` are)
    /// so a caller doesn't need to make this string match anything to
    /// avoid a false divergence.
    pub description: String,
    pub result: Option<EventResult>,
}

/// Compare `expected` (from the recording) against `observed` (from live
/// re-execution). Returns `None` when they match (replay should proceed
/// normally) or `Some(Divergence)` describing the mismatch.
///
/// Comparison policy:
///   - Different `EventKind` is always a divergence (the live target is
///     doing a fundamentally different operation than what was recorded —
///     e.g. recorded a `write` but observed a `connect`).
///   - Same `EventKind` with a `result` on both sides: results must match
///     exactly. A syscall that took the same *action* but returned a
///     different *outcome* (e.g. `write` succeeded during recording but
///     fails now) is exactly the class of divergence this platform exists
///     to catch — silently accepting it would defeat the purpose.
///   - Same `EventKind` with no `result` supplied by the observer (a
///     driver that can't yet determine the outcome at the point it calls
///     `check`, e.g. checking at syscall-entry before the exit stop) is
///     not treated as a divergence — absence of a comparable result is not
///     evidence of a mismatch.
pub fn check(expected: &Event, observed: &ObservedOperation) -> Option<Divergence> {
    if expected.kind() != observed.kind {
        return Some(Divergence {
            expected: expected.id(),
            observed_description: format!(
                "expected {:?} but observed {:?} ({})",
                expected.kind(),
                observed.kind,
                observed.description
            ),
        });
    }

    if let Some(observed_result) = &observed.result {
        if observed_result != expected.result() {
            return Some(Divergence {
                expected: expected.id(),
                observed_description: format!(
                    "expected result {:?} but observed {:?} ({})",
                    expected.result(),
                    observed_result,
                    observed.description
                ),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_types::{EventId, HlcTimestamp, HostId, Payload, SessionId};

    fn sample_event(kind: EventKind, result: EventResult) -> Event {
        let id = EventId::new(HostId::from_raw(1), 1, 1, 0);
        Event::new(id, SessionId::from_raw(1), kind, HlcTimestamp::new(0, 0), Payload::None, result)
    }

    #[test]
    fn matching_kind_and_result_is_not_a_divergence() {
        let expected = sample_event(EventKind::Syscall, EventResult::Ok(0));
        let observed = ObservedOperation { kind: EventKind::Syscall, description: "write".into(), result: Some(EventResult::Ok(0)) };
        assert_eq!(check(&expected, &observed), None);
    }

    #[test]
    fn different_kind_is_always_a_divergence() {
        let expected = sample_event(EventKind::Syscall, EventResult::Ok(0));
        let observed = ObservedOperation { kind: EventKind::NetIo, description: "connect".into(), result: None };
        let divergence = check(&expected, &observed).unwrap();
        assert_eq!(divergence.expected, expected.id());
        assert!(divergence.observed_description.contains("NetIo"));
    }

    #[test]
    fn same_kind_different_result_is_a_divergence() {
        let expected = sample_event(EventKind::Syscall, EventResult::Ok(128));
        let observed = ObservedOperation {
            kind: EventKind::Syscall,
            description: "write".into(),
            result: Some(EventResult::Err { retval: -1, errno: 9 }),
        };
        assert!(check(&expected, &observed).is_some());
    }

    #[test]
    fn same_kind_with_no_observed_result_yet_is_not_a_divergence() {
        // Models a driver checking at syscall-entry, before it knows the
        // outcome — absence of comparable data must not be misreported as
        // a mismatch.
        let expected = sample_event(EventKind::Syscall, EventResult::Ok(0));
        let observed = ObservedOperation { kind: EventKind::Syscall, description: "write (entry)".into(), result: None };
        assert_eq!(check(&expected, &observed), None);
    }

    #[test]
    fn same_kind_same_result_variant_different_errno_is_a_divergence() {
        let expected = sample_event(EventKind::Syscall, EventResult::Err { retval: -1, errno: 9 });
        let observed = ObservedOperation {
            kind: EventKind::Syscall,
            description: "read".into(),
            result: Some(EventResult::Err { retval: -1, errno: 11 }),
        };
        assert!(check(&expected, &observed).is_some(), "different errno is a real behavioral difference");
    }
}
