//! `PlatformInterceptor` — the recording-side half of the PAL contract
//! (architecture §13). Every OS adapter (Linux eBPF/ptrace, Windows
//! ETW/minifilter, macOS EndpointSecurity) implements this trait. The core
//! recorder (`ptdf-recorder-core`, Module 5) depends only on this trait,
//! never on platform types — that's the entire point of the PAL boundary.

use ptdf_types::Event;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InterceptorError {
    #[error("failed to attach to target pid {pid}: {reason}")]
    AttachFailed { pid: u32, reason: String },

    #[error("target process {pid} is no longer traceable (exited or detached)")]
    TargetGone { pid: u32 },

    #[error("platform capability not available on this host: {0}")]
    CapabilityUnavailable(String),

    #[error("underlying platform error: {0}")]
    Platform(String),
}

/// A target process (and optionally its descendants) to attach to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachTarget {
    pub pid: u32,
    pub follow_children: bool,
}

/// Capabilities an adapter may or may not support on the current host —
/// queried before recording starts so the core can decide fidelity level
/// (§8, adaptive fidelity) rather than failing at the first unsupported
/// intercept point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterceptorCapabilities {
    pub syscalls: bool,
    pub scheduler: bool,
    pub signals: bool,
    pub network_payloads: bool,
    pub memory_race_detection: bool,
}

/// The recording-side platform contract.
///
/// Implementors are expected to push captured events into whatever
/// `RecorderSink` (defined in `ptdf-recorder-core`) they were configured
/// with; this trait only governs attach/detach/capability lifecycle and
/// the pull-based `poll_events` fallback for adapters that can't push
/// directly (e.g. a ptrace-based adapter that must be driven from a loop
/// owning the traced thread).
pub trait PlatformInterceptor: Send {
    /// Attach to the given target. Must be idempotent-safe to call once per
    /// interceptor instance; a second call before `detach` is an error.
    fn attach(&mut self, target: AttachTarget) -> Result<(), InterceptorError>;

    /// Detach cleanly, allowing the target to continue running unmonitored
    /// (as opposed to killing it).
    fn detach(&mut self) -> Result<(), InterceptorError>;

    /// Query what this adapter can actually capture on the current host.
    /// Must be callable both before and after `attach`.
    fn capabilities(&self) -> InterceptorCapabilities;

    /// Pull the next batch of captured events, blocking up to
    /// `max_wait_ms` if none are immediately available. Returns an empty
    /// vec on timeout (not an error — an idle target is normal).
    fn poll_events(&mut self, max_wait_ms: u32) -> Result<Vec<Event>, InterceptorError>;
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A deterministic in-memory `PlatformInterceptor` used by this crate's
    //! own tests and re-exported (via `#[cfg(feature = "test-util")]` in a
    //! later module, once other crates need it) so `ptdf-recorder-core` can
    //! test its consumption logic without any real OS dependency.
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Default)]
    pub struct MockInterceptor {
        pub attached_to: Option<AttachTarget>,
        pub queued_events: VecDeque<Event>,
        pub caps: InterceptorCapabilities,
        pub fail_next_attach: bool,
    }

    impl PlatformInterceptor for MockInterceptor {
        fn attach(&mut self, target: AttachTarget) -> Result<(), InterceptorError> {
            if self.fail_next_attach {
                self.fail_next_attach = false;
                return Err(InterceptorError::AttachFailed {
                    pid: target.pid,
                    reason: "simulated failure".into(),
                });
            }
            if self.attached_to.is_some() {
                return Err(InterceptorError::Platform("already attached".into()));
            }
            self.attached_to = Some(target);
            Ok(())
        }

        fn detach(&mut self) -> Result<(), InterceptorError> {
            if self.attached_to.take().is_none() {
                return Err(InterceptorError::Platform("not attached".into()));
            }
            Ok(())
        }

        fn capabilities(&self) -> InterceptorCapabilities {
            self.caps
        }

        fn poll_events(&mut self, _max_wait_ms: u32) -> Result<Vec<Event>, InterceptorError> {
            if self.attached_to.is_none() {
                return Err(InterceptorError::Platform("not attached".into()));
            }
            Ok(self.queued_events.drain(..).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockInterceptor;
    use super::*;

    #[test]
    fn attach_then_detach_succeeds() {
        let mut i = MockInterceptor::default();
        let target = AttachTarget { pid: 123, follow_children: true };
        assert!(i.attach(target).is_ok());
        assert_eq!(i.attached_to, Some(target));
        assert!(i.detach().is_ok());
        assert_eq!(i.attached_to, None);
    }

    #[test]
    fn double_attach_is_rejected() {
        let mut i = MockInterceptor::default();
        let target = AttachTarget { pid: 1, follow_children: false };
        i.attach(target).unwrap();
        let err = i.attach(target).unwrap_err();
        assert!(matches!(err, InterceptorError::Platform(_)));
    }

    #[test]
    fn detach_without_attach_is_rejected() {
        let mut i = MockInterceptor::default();
        assert!(i.detach().is_err());
    }

    #[test]
    fn poll_before_attach_is_rejected() {
        let mut i = MockInterceptor::default();
        assert!(i.poll_events(0).is_err());
    }

    #[test]
    fn attach_failure_is_reported_and_leaves_state_clean() {
        let mut i = MockInterceptor { fail_next_attach: true, ..Default::default() };
        let target = AttachTarget { pid: 7, follow_children: false };
        let err = i.attach(target).unwrap_err();
        assert!(matches!(err, InterceptorError::AttachFailed { pid: 7, .. }));
        assert_eq!(i.attached_to, None, "failed attach must not leave partial state");
        // Retry should now succeed since fail_next_attach was consumed.
        assert!(i.attach(target).is_ok());
    }
}
