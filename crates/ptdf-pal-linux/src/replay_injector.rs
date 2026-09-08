//! Replay Injectors (architecture: "Replay Injectors", "Syscall Replay").
//!
//! During replay, once a target hits a syscall-exit ptrace-stop for a
//! syscall we're replaying, we don't let the real kernel's result stand —
//! we overwrite the tracee's `rax` register with the *recorded* result via
//! `PTRACE_SETREGS`, so the target observes exactly what it observed in
//! production regardless of what the sandboxed replay environment's real
//! kernel actually did. This module is the pure part of that: computing
//! what `rax` should become for a given recorded `EventResult`. Pure
//! because there is no `ptrace` call in this file — the actual
//! `PTRACE_SETREGS` write is the caller's job (a `ReplayDriver`
//! implementation, not built in this pass; see crate-level `README`
//! status for what's outstanding), which is exactly why this logic is
//! separated out: it's fully unit-testable without a live tracee.

use ptdf_types::EventResult;

/// The x86_64 Linux syscall ABI packs both a successful return value and
/// an error into the same signed 64-bit `rax`: success is the
/// non-negative value itself, and an error is `-errno` (a small negative
/// number, kernel convention `-4095..=-1`). This function performs exactly
/// that encoding for a recorded `EventResult`, so a `ReplayDriver` can
/// write the returned value straight into `regs.rax` and resume the
/// tracee — the tracee's own libc will decode `-errno` back out via
/// `errno` the same way it would for a live syscall.
///
/// `EventResult::Status`/`EventResult::None` are Windows/no-result
/// variants that never arise from a Linux ptrace-recorded syscall (see
/// `interceptor.rs`, which only ever produces `Ok`/`Err`); passing one
/// here is a caller bug — replaying a recording against the wrong
/// platform's driver — and is reported as an error rather than silently
/// coerced to some value that would just fail differently, less clearly,
/// downstream.
pub fn syscall_result_to_rax(result: &EventResult) -> Result<u64, InjectorError> {
    match result {
        EventResult::Ok(v) => Ok(*v as u64),
        EventResult::Err { errno, .. } => {
            if !(1..=4095).contains(errno) {
                return Err(InjectorError::ErrnoOutOfRange(*errno));
            }
            Ok((-(*errno as i64)) as u64)
        }
        EventResult::Status(_) => Err(InjectorError::UnsupportedResultVariant("Status")),
        EventResult::None => Err(InjectorError::UnsupportedResultVariant("None")),
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InjectorError {
    #[error("errno {0} is outside the valid Linux range 1..=4095")]
    ErrnoOutOfRange(i32),

    #[error("EventResult::{0} cannot be replayed by the Linux syscall injector (recording was not produced by ptdf-pal-linux)")]
    UnsupportedResultVariant(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_result_maps_to_its_value_directly() {
        assert_eq!(syscall_result_to_rax(&EventResult::Ok(0)).unwrap(), 0);
        assert_eq!(syscall_result_to_rax(&EventResult::Ok(128)).unwrap(), 128);
    }

    #[test]
    fn error_result_maps_to_negative_errno_as_u64_two_complement() {
        // -1 (EPERM) as an i64 reinterpreted as u64 is the well-known
        // 0xFFFFFFFFFFFFFFFF pattern; this is exactly the bit pattern the
        // kernel itself would have placed in rax for a failing syscall.
        let rax = syscall_result_to_rax(&EventResult::Err { retval: -1, errno: 1 }).unwrap();
        assert_eq!(rax, u64::MAX);

        // -11 (EAGAIN) similarly.
        let rax = syscall_result_to_rax(&EventResult::Err { retval: -11, errno: 11 }).unwrap();
        assert_eq!(rax as i64, -11);
    }

    #[test]
    fn errno_out_of_valid_range_is_rejected() {
        assert_eq!(
            syscall_result_to_rax(&EventResult::Err { retval: -1, errno: 0 }),
            Err(InjectorError::ErrnoOutOfRange(0))
        );
        assert_eq!(
            syscall_result_to_rax(&EventResult::Err { retval: -1, errno: 5000 }),
            Err(InjectorError::ErrnoOutOfRange(5000))
        );
    }

    #[test]
    fn windows_style_variants_are_rejected_not_silently_coerced() {
        assert!(matches!(syscall_result_to_rax(&EventResult::Status(-1)), Err(InjectorError::UnsupportedResultVariant("Status"))));
        assert!(matches!(syscall_result_to_rax(&EventResult::None), Err(InjectorError::UnsupportedResultVariant("None"))));
    }

    #[test]
    fn round_trip_matches_kernel_convention_for_common_errnos() {
        // A handful of very common Linux errnos, verifying the two's
        // complement packing is exactly what the kernel ABI expects.
        for errno in [1i32, 2, 9, 11, 22, 110] {
            let rax = syscall_result_to_rax(&EventResult::Err { retval: -1, errno }).unwrap();
            assert_eq!(rax as i64, -(errno as i64));
        }
    }
}
