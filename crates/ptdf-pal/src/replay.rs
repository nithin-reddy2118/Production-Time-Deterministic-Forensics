//! `ReplayDriver` — the replay-side half of the PAL contract (architecture
//! §6, §13). Where `PlatformInterceptor` captures real outcomes from the
//! OS, `ReplayDriver` *injects* previously-recorded outcomes back into a
//! re-executing target, and reports divergences when live behavior doesn't
//! match what was recorded (§6 step 4).

use ptdf_types::{Event, EventId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("failed to reconstruct sandboxed execution environment: {0}")]
    EnvironmentSetupFailed(String),

    #[error("replay target {pid} exited unexpectedly during replay")]
    TargetExitedEarly { pid: u32 },

    #[error("underlying platform error: {0}")]
    Platform(String),
}

/// A divergence between what was recorded and what live re-execution is
/// about to do. This is a first-class forensic signal (§6 step 4), not
/// just an internal error — the Query API (§17) surfaces these to users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The event we expected next, based on the recorded stream.
    pub expected: EventId,
    /// Human-readable description of what live execution attempted
    /// instead (e.g. "syscall write(fd=4, len=128) vs recorded read(fd=4)").
    pub observed_description: String,
}

/// Outcome of driving the target through one step of replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// The expected recorded event was served; replay may continue.
    Served(EventId),
    /// Live execution diverged from the recorded stream (§6 step 4).
    Diverged(Divergence),
    /// The target has completed execution (process exit).
    TargetCompleted { exit_code: i32 },
}

/// The replay-side platform contract. Implementors reconstruct a sandboxed
/// environment matching the recording (namespace/container on Linux, Job
/// Object on Windows — §6 step 2) and then drive the target one
/// intercepted-point-at-a-time, serving recorded results instead of
/// letting the real syscall/API reach the OS.
pub trait ReplayDriver: Send {
    /// Reconstruct the execution environment for a target described by the
    /// binary path, pinned library hashes, env vars, and file-view
    /// snapshot reference. Concrete environment-description types belong
    /// to the replay engine crate (Module 12); this trait only needs an
    /// opaque handle back.
    fn prepare_environment(&mut self, binary_path: &str) -> Result<(), ReplayError>;

    /// Launch the (already-prepared) target under replay control, stopped
    /// at the first intercepted point.
    fn launch(&mut self) -> Result<(), ReplayError>;

    /// Advance the target to the next intercepted point, serving `next`
    /// (the next expected recorded event) if live execution's intercepted
    /// call matches it.
    fn step(&mut self, next: &Event) -> Result<StepOutcome, ReplayError>;

    /// Tear down the sandboxed environment.
    fn teardown(&mut self) -> Result<(), ReplayError>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use ptdf_types::{EventKind, EventResult, HlcTimestamp, Payload, SessionId};

    /// Deterministic in-memory `ReplayDriver`. Whether `step` reports
    /// `Served` or `Diverged` is controlled by the test via
    /// `force_divergence_on`, letting divergence-handling logic be tested
    /// without any real process.
    #[derive(Debug, Default)]
    pub struct MockReplayDriver {
        pub prepared: bool,
        pub launched: bool,
        pub steps_served: Vec<EventId>,
        pub force_divergence_on: Option<EventId>,
        pub exit_after_n_steps: Option<usize>,
    }

    impl ReplayDriver for MockReplayDriver {
        fn prepare_environment(&mut self, binary_path: &str) -> Result<(), ReplayError> {
            if binary_path.is_empty() {
                return Err(ReplayError::EnvironmentSetupFailed("empty binary path".into()));
            }
            self.prepared = true;
            Ok(())
        }

        fn launch(&mut self) -> Result<(), ReplayError> {
            if !self.prepared {
                return Err(ReplayError::Platform("environment not prepared".into()));
            }
            self.launched = true;
            Ok(())
        }

        fn step(&mut self, next: &Event) -> Result<StepOutcome, ReplayError> {
            if !self.launched {
                return Err(ReplayError::Platform("target not launched".into()));
            }
            if let Some(n) = self.exit_after_n_steps {
                if self.steps_served.len() >= n {
                    return Ok(StepOutcome::TargetCompleted { exit_code: 0 });
                }
            }
            if self.force_divergence_on == Some(next.id()) {
                return Ok(StepOutcome::Diverged(Divergence {
                    expected: next.id(),
                    observed_description: "simulated divergence".into(),
                }));
            }
            self.steps_served.push(next.id());
            Ok(StepOutcome::Served(next.id()))
        }

        fn teardown(&mut self) -> Result<(), ReplayError> {
            self.launched = false;
            self.prepared = false;
            Ok(())
        }
    }

    pub fn sample_event(seq: u64) -> Event {
        use ptdf_types::HostId;
        let host = HostId::from_raw(1);
        let id = EventId::new(host, 1, 1, seq);
        Event::new(
            id,
            SessionId::from_raw(1),
            EventKind::Syscall,
            HlcTimestamp::new(seq, 0),
            Payload::None,
            EventResult::Ok(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{sample_event, MockReplayDriver};
    use super::*;

    #[test]
    fn full_lifecycle_serves_events_in_order() {
        let mut d = MockReplayDriver::default();
        d.prepare_environment("/usr/bin/target").unwrap();
        d.launch().unwrap();

        let e1 = sample_event(1);
        let e2 = sample_event(2);

        assert_eq!(d.step(&e1).unwrap(), StepOutcome::Served(e1.id()));
        assert_eq!(d.step(&e2).unwrap(), StepOutcome::Served(e2.id()));
        assert_eq!(d.steps_served, vec![e1.id(), e2.id()]);

        d.teardown().unwrap();
        assert!(!d.launched);
    }

    #[test]
    fn step_before_launch_is_rejected() {
        let mut d = MockReplayDriver::default();
        let e = sample_event(1);
        assert!(matches!(d.step(&e), Err(ReplayError::Platform(_))));
    }

    #[test]
    fn empty_binary_path_fails_environment_setup() {
        let mut d = MockReplayDriver::default();
        assert!(matches!(
            d.prepare_environment(""),
            Err(ReplayError::EnvironmentSetupFailed(_))
        ));
    }

    #[test]
    fn divergence_is_reported_instead_of_silently_served() {
        let mut d = MockReplayDriver::default();
        d.prepare_environment("/bin/x").unwrap();
        d.launch().unwrap();
        let e1 = sample_event(1);
        d.force_divergence_on = Some(e1.id());

        let outcome = d.step(&e1).unwrap();
        match outcome {
            StepOutcome::Diverged(div) => assert_eq!(div.expected, e1.id()),
            other => panic!("expected Diverged, got {other:?}"),
        }
        assert!(d.steps_served.is_empty(), "a diverged event must not count as served");
    }

    #[test]
    fn target_completion_is_reported_and_stops_serving() {
        let mut d = MockReplayDriver { exit_after_n_steps: Some(1), ..Default::default() };
        d.prepare_environment("/bin/x").unwrap();
        d.launch().unwrap();
        let e1 = sample_event(1);
        let e2 = sample_event(2);

        assert_eq!(d.step(&e1).unwrap(), StepOutcome::Served(e1.id()));
        assert_eq!(
            d.step(&e2).unwrap(),
            StepOutcome::TargetCompleted { exit_code: 0 }
        );
    }
}
