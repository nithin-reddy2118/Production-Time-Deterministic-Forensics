//! Thin, safety-documented wrappers over the raw `ptrace(2)`/`waitpid(2)`
//! syscalls this adapter needs. Kept in its own module so every `unsafe`
//! block in the crate has exactly one place its invariants are argued —
//! everything above this module (`interceptor.rs`) is safe Rust.
//!
//! We define `UserRegsX86_64` ourselves (matching the Linux kernel's
//! `struct user_regs_struct` ABI for x86_64) rather than depending on the
//! `libc` crate to provide it, because that struct's availability/shape in
//! `libc` has varied across versions and targets — pinning our own
//! `#[repr(C)]` copy of a kernel-stable ABI is more robust than depending
//! on a third-party crate's re-export of it.
//!
//! Architecture scope: **x86_64 Linux only**. aarch64 has a different
//! register set and uses `PTRACE_GETREGSET`/`NT_PRSTATUS` instead of
//! `PTRACE_GETREGS`; that's a real, separate implementation, not a
//! same-shaped stub, and is out of scope for this module.

use std::io;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("ptdf-pal-linux currently supports only Linux on x86_64");

const PTRACE_PEEKTEXT: i32 = 1;
const PTRACE_GETREGS: i32 = 12;
const PTRACE_SETOPTIONS: i32 = 0x4200;
const PTRACE_SEIZE: i32 = 0x4206;
const PTRACE_INTERRUPT: i32 = 0x4207;
const PTRACE_SYSCALL: i32 = 24;
const PTRACE_DETACH: i32 = 17;

pub const PTRACE_O_TRACESYSGOOD: i64 = 0x0000_0001;
pub const PTRACE_O_EXITKILL: i64 = 0x0010_0000;

/// Mirrors the Linux kernel's `struct user_regs_struct` for x86_64
/// (see `<sys/user.h>` / `arch/x86/include/asm/user_64.h`). Field order
/// and widths are kernel ABI, not an implementation choice.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UserRegsX86_64 {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

/// Result of a `waitpid` call, decoded into a small enum instead of leaving
/// callers to re-derive `WIFSTOPPED`/`WSTOPSIG`/etc. by hand at every call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    /// Stopped by a signal. `is_syscall_stop` is true when the stop signal
    /// is `SIGTRAP | 0x80`, which is what `PTRACE_O_TRACESYSGOOD` produces
    /// specifically for syscall-entry/exit stops (distinguishing them from
    /// ordinary signal-delivery stops, which matter for a correct forensic
    /// recording — a signal delivered to the tracee is itself a `Signal`
    /// event, not a syscall boundary).
    Stopped {
        signal: i32,
        is_syscall_stop: bool,
    },
    Exited {
        exit_code: i32,
    },
    Signaled {
        signal: i32,
    },
}

/// `ptrace(PTRACE_SEIZE, pid, 0, options)` — attach without stopping the
/// tracee and without requiring it to be our child (unlike classic
/// `PTRACE_ATTACH`, `SEIZE` doesn't send `SIGSTOP`, avoiding a
/// signal-delivery side effect on the target).
///
/// # Safety
/// `pid` must name a process the caller has permission to trace (same
/// UID, or `CAP_SYS_PTRACE`), and must not already be traced by this or
/// another tracer.
pub unsafe fn seize(pid: i32, options: i64) -> io::Result<()> {
    let ret = libc::ptrace(
        PTRACE_SEIZE as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        options,
    );
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// # Safety
/// `pid` must be a currently-seized tracee owned by the calling thread
/// (ptrace requests must originate from the thread that attached).
pub unsafe fn interrupt(pid: i32) -> io::Result<()> {
    let ret = libc::ptrace(
        PTRACE_INTERRUPT as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        std::ptr::null_mut::<libc::c_void>(),
    );
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// # Safety
/// Same preconditions as `interrupt`.
pub unsafe fn set_options(pid: i32, options: i64) -> io::Result<()> {
    let ret = libc::ptrace(
        PTRACE_SETOPTIONS as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        options,
    );
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Resume the tracee until the next syscall-entry or syscall-exit stop.
///
/// # Safety
/// Same preconditions as `interrupt`.
pub unsafe fn resume_to_next_syscall_stop(pid: i32) -> io::Result<()> {
    let ret = libc::ptrace(
        PTRACE_SYSCALL as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        std::ptr::null_mut::<libc::c_void>(),
    );
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Resume the tracee until the next syscall-entry or syscall-exit stop,
/// re-injecting `signal` into the tracee first (use `0` for "no signal",
/// equivalent to `resume_to_next_syscall_stop`). This is how a real signal
/// delivered to the tracee (SIGSEGV, SIGUSR1, ...) is forwarded rather than
/// silently swallowed — swallowing it would change the target's observed
/// behavior, which is exactly what this project must never do.
///
/// # Safety
/// Same preconditions as `interrupt`.
pub unsafe fn resume_to_next_syscall_stop_with_signal(pid: i32, signal: i32) -> io::Result<()> {
    let ret = libc::ptrace(
        PTRACE_SYSCALL as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        signal as *mut libc::c_void,
    );
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// # Safety
/// Same preconditions as `interrupt`. The tracee must currently be in a
/// ptrace-stop (i.e. this is called immediately after a `waitpid` that
/// reported `WaitStatus::Stopped`).
pub unsafe fn get_regs(pid: i32) -> io::Result<UserRegsX86_64> {
    let mut regs = UserRegsX86_64::default();

    let ret = libc::ptrace(
        PTRACE_GETREGS as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        &mut regs as *mut _ as *mut libc::c_void,
    );

    if ret == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(regs)
}
/// Read one word (8 bytes on x86_64) from the tracee's address space at
/// `addr`, via `PTRACE_PEEKTEXT`. Used for resolving pointer arguments
/// (e.g. the buffer address in a `write(2)` call) when a future module
/// needs argument payload capture beyond the raw register values recorded
/// today; exposed now so `interceptor.rs` doesn't need a second `unsafe`
/// surface added later for the same purpose.
///
/// # Safety
/// Same preconditions as `interrupt`.
pub unsafe fn peek_text(pid: i32, addr: u64) -> io::Result<u64> {
    // PTRACE_PEEKTEXT returns the read word as the return value, which
    // means -1 is ambiguous with an error unless we clear errno first and
    // check it after — the standard pattern for this specific request.
    *libc::__errno_location() = 0;
    let ret = libc::ptrace(
        PTRACE_PEEKTEXT as libc::c_uint,
        pid,
        addr as *mut libc::c_void,
        std::ptr::null_mut::<libc::c_void>(),
    );
    if ret == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(0) {
            return Err(err);
        }
    }
    Ok(ret as u64)
}

/// # Safety
/// Same preconditions as `interrupt`.
pub unsafe fn detach(pid: i32) -> io::Result<()> {
    let ret = libc::ptrace(
        PTRACE_DETACH as libc::c_uint,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        std::ptr::null_mut::<libc::c_void>(),
    );
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Blocking `waitpid(pid, ..., 0)`, decoded into `WaitStatus`.
///
/// # Safety
/// `pid` must be a valid, waitable child/tracee of the calling thread.
pub unsafe fn wait_for_stop(pid: i32) -> io::Result<WaitStatus> {
    let mut status: i32 = 0;
    let ret = libc::waitpid(pid, &mut status as *mut i32, 0);
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    if libc::WIFEXITED(status) {
        return Ok(WaitStatus::Exited {
            exit_code: libc::WEXITSTATUS(status),
        });
    }
    if libc::WIFSIGNALED(status) {
        return Ok(WaitStatus::Signaled {
            signal: libc::WTERMSIG(status),
        });
    }
    if libc::WIFSTOPPED(status) {
        let sig = libc::WSTOPSIG(status);
        let is_syscall_stop = sig == (libc::SIGTRAP | 0x80);
        return Ok(WaitStatus::Stopped {
            signal: sig,
            is_syscall_stop,
        });
    }
    Err(io::Error::other(format!(
        "unrecognized waitpid status: {status:#x}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests exercise the real kernel ptrace/waitpid interface
    /// end-to-end against a genuine child process — they are the correct
    /// way to test this module (mocking `unsafe extern "C"` syscalls would
    /// test nothing) but they require `CAP_SYS_PTRACE`/appropriate
    /// `yama.ptrace_scope`, so they're marked `#[ignore]` and meant to be
    /// run explicitly in CI on a Linux runner with `cargo test -- --ignored`,
    /// not silently skipped as part of a false-positive-passing default
    /// suite in a sandboxed/restricted CI container.
    #[test]
    #[ignore = "requires ptrace permissions; run explicitly on a Linux CI runner"]
    fn seize_interrupt_and_wait_on_a_real_child() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // Child: sleep so the parent has time to seize it.
                libc::sleep(5);
                libc::_exit(0);
            }
            // Parent:
            seize(pid, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL).expect("seize failed");
            interrupt(pid).expect("interrupt failed");
            let status = wait_for_stop(pid).expect("waitpid failed");
            assert!(matches!(status, WaitStatus::Stopped { .. }));
            detach(pid).expect("detach failed");
            libc::kill(pid, libc::SIGKILL);
            let _ = wait_for_stop(pid);
        }
    }

    #[test]
    fn user_regs_struct_has_kernel_abi_size() {
        // struct user_regs_struct on x86_64 is 27 * 8 = 216 bytes. A size
        // mismatch here means a field was added/removed/misordered
        // relative to the kernel ABI, which would silently corrupt every
        // register read — this is the cheapest possible guard against
        // that, runnable with no special privileges.
        assert_eq!(std::mem::size_of::<UserRegsX86_64>(), 216);
    }
}
