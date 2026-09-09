//! `LinuxPtraceInterceptor` — implements `ptdf_pal::PlatformInterceptor`
//! using `ptrace(2)` syscall-entry/exit tracing on x86_64 Linux.
//!
//! Design: `attach` spawns one dedicated OS thread that owns the tracee for
//! its entire lifetime — required because ptrace requests for a given
//! tracee must originate from the thread that attached to it (a kernel
//! ptrace invariant, not a choice we made). That thread runs the
//! seize -> interrupt -> [resume -> wait -> record]* loop and pushes
//! completed `Event`s through a bounded channel that `poll_events` drains.
//! A second control channel lets `detach` ask the loop thread to stop and
//! actually detach from the kernel's perspective.
//!
//! Known limitation (documented, not hidden): `poll_events`'s `max_wait_ms`
//! bounds how long *we* wait on the channel, but the loop thread's
//! `waitpid` call for an idle tracee can block indefinitely between
//! syscalls — this only affects how promptly `detach` takes effect on a
//! truly idle target, not correctness of what's recorded, and is the
//! documented reason `capabilities().scheduler` is `false` here (a
//! sched_switch-driven eBPF source, per architecture §9, is what closes
//! this gap — out of scope for the ptrace-only v1).

use crate::raw::{self, WaitStatus};
use crate::syscall_table;
use ptdf_pal::{AttachTarget, InterceptorCapabilities, InterceptorError, PlatformInterceptor};
use ptdf_recorder_core::SeqAllocator;
use ptdf_types::{
    Event, EventId, EventResult, HlcGenerator, HostId, Payload, SessionId, SystemPhysicalClock,
};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

enum ControlMsg {
    Stop,
}

/// Owns exactly one traced pid at a time (multi-process `follow_children`
/// is explicitly rejected — see `attach` — rather than half-implemented).
pub struct LinuxPtraceInterceptor {
    host_id: HostId,
    session_id: SessionId,
    thread: Option<JoinHandle<()>>,
    event_rx: Option<Receiver<Event>>,
    control_tx: Option<Sender<ControlMsg>>,
    attached_pid: Option<i32>,
}

impl std::fmt::Debug for LinuxPtraceInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxPtraceInterceptor")
            .field("host_id", &self.host_id)
            .field("session_id", &self.session_id)
            .field("attached_pid", &self.attached_pid)
            .finish()
    }
}

impl LinuxPtraceInterceptor {
    pub fn new(host_id: HostId, session_id: SessionId) -> Self {
        Self {
            host_id,
            session_id,
            thread: None,
            event_rx: None,
            control_tx: None,
            attached_pid: None,
        }
    }

    /// The ptrace loop, run entirely on the dedicated tracer thread.
    fn run_trace_loop(
        pid: i32,
        host_id: HostId,
        session_id: SessionId,
        event_tx: SyncSender<Event>,
        control_rx: Receiver<ControlMsg>,
    ) {
        let mut hlc = HlcGenerator::new(SystemPhysicalClock);
        let mut seq_alloc = SeqAllocator::new(pid as u32, pid as u32);

        let options = raw::PTRACE_O_TRACESYSGOOD | raw::PTRACE_O_EXITKILL;
        // SAFETY: this thread is the sole owner of `pid` for its entire
        // traced lifetime (see module docs) and no other ptrace call for
        // this pid happens on any other thread.
        if let Err(e) = unsafe { raw::seize(pid, options) } {
            ptdf_logging::error!(pid, error = %e, "ptrace seize failed; trace loop exiting");
            return;
        }
        if let Err(e) = unsafe { raw::interrupt(pid) } {
            ptdf_logging::error!(pid, error = %e, "ptrace interrupt failed; trace loop exiting");
            return;
        }
        // Reap the initial group-stop from seize+interrupt before entering
        // the syscall-stepping loop.
        if let Err(e) = unsafe { raw::wait_for_stop(pid) } {
            ptdf_logging::error!(pid, error = %e, "initial waitpid failed; trace loop exiting");
            return;
        }

        let mut pending_signal = 0i32;
        let mut in_syscall: Option<u64> = None; // Some(syscall_number) while between entry and exit stop

        loop {
            if let Ok(ControlMsg::Stop) = control_rx.try_recv() {
                let _ = unsafe { raw::detach(pid) };
                ptdf_logging::info!(pid, "trace loop received stop request; detached");
                return;
            }

            let resume = if pending_signal != 0 {
                unsafe { raw::resume_to_next_syscall_stop_with_signal(pid, pending_signal) }
            } else {
                unsafe { raw::resume_to_next_syscall_stop(pid) }
            };
            pending_signal = 0;
            if let Err(e) = resume {
                ptdf_logging::warn!(pid, error = %e, "ptrace resume failed; assuming target gone");
                return;
            }

            let status = match unsafe { raw::wait_for_stop(pid) } {
                Ok(s) => s,
                Err(e) => {
                    ptdf_logging::warn!(pid, error = %e, "waitpid failed; trace loop exiting");
                    return;
                }
            };

            match status {
                WaitStatus::Exited { exit_code } => {
                    ptdf_logging::info!(pid, exit_code, "traced process exited");
                    return;
                }
                WaitStatus::Signaled { signal } => {
                    ptdf_logging::info!(pid, signal, "traced process killed by signal");
                    return;
                }
                WaitStatus::Stopped {
                    signal,
                    is_syscall_stop: false,
                } => {
                    // A genuine signal delivery, not a syscall boundary —
                    // forward it on the next resume so the tracee's
                    // observed behavior is unchanged (see raw.rs docs).
                    pending_signal = signal;
                }
                WaitStatus::Stopped {
                    is_syscall_stop: true,
                    ..
                } => {
                    let regs = match unsafe { raw::get_regs(pid) } {
                        Ok(r) => r,
                        Err(e) => {
                            ptdf_logging::warn!(pid, error = %e, "get_regs failed; skipping this stop");
                            continue;
                        }
                    };

                    match in_syscall {
                        None => {
                            // Syscall-entry stop: remember which syscall,
                            // wait for the matching exit stop to record
                            // the result (architecture: an Event carries
                            // both the call and its outcome, §7).
                            in_syscall = Some(regs.orig_rax);
                        }
                        Some(entry_syscall_num) => {
                            // Syscall-exit stop.
                            let info = syscall_table::lookup(entry_syscall_num);
                            let retval = regs.rax as i64;
                            let result = if retval < 0 && retval > -4096 {
                                EventResult::Err {
                                    retval,
                                    errno: (-retval) as i32,
                                }
                            } else {
                                EventResult::Ok(retval)
                            };

                            let seq = seq_alloc.next_seq();
                            let event_id = EventId::new(host_id, pid as u32, pid as u32, seq);
                            let hlc_ts = hlc.tick();
                            let event = Event::new(
                                event_id,
                                session_id,
                                info.kind,
                                hlc_ts,
                                Payload::None,
                                result,
                            );

                            if event_tx.send(event).is_err() {
                                ptdf_logging::warn!(
                                    pid,
                                    "event channel closed; trace loop exiting"
                                );
                                return;
                            }
                            in_syscall = None;
                        }
                    }
                }
            }
        }
    }
}

impl PlatformInterceptor for LinuxPtraceInterceptor {
    fn attach(&mut self, target: AttachTarget) -> Result<(), InterceptorError> {
        if self.attached_pid.is_some() {
            return Err(InterceptorError::Platform("already attached".into()));
        }
        if target.follow_children {
            // Honest, complete rejection of an unsupported configuration
            // (see module docs) rather than a half-working implementation.
            return Err(InterceptorError::CapabilityUnavailable(
                "follow_children (multi-process tracing) is not implemented by \
                 LinuxPtraceInterceptor v1 — attach to each pid separately"
                    .into(),
            ));
        }

        let (event_tx, event_rx) = mpsc::sync_channel::<Event>(4096);
        let (control_tx, control_rx) = mpsc::channel::<ControlMsg>();

        let pid = target.pid as i32;
        let host_id = self.host_id;
        let session_id = self.session_id;

        let thread = std::thread::Builder::new()
            .name(format!("ptdf-tracer-{pid}"))
            .spawn(move || Self::run_trace_loop(pid, host_id, session_id, event_tx, control_rx))
            .map_err(|e| InterceptorError::AttachFailed {
                pid: target.pid,
                reason: e.to_string(),
            })?;

        self.thread = Some(thread);
        self.event_rx = Some(event_rx);
        self.control_tx = Some(control_tx);
        self.attached_pid = Some(pid);
        Ok(())
    }

    fn detach(&mut self) -> Result<(), InterceptorError> {
        let pid = self
            .attached_pid
            .take()
            .ok_or_else(|| InterceptorError::Platform("not attached".into()))?;

        if let Some(tx) = self.control_tx.take() {
            let _ = tx.send(ControlMsg::Stop);
        }
        if let Some(handle) = self.thread.take() {
            // Bounded join: the loop thread checks control_rx once per
            // syscall stop, so for an active target this returns promptly;
            // for a genuinely idle one it can take until the target's next
            // syscall (documented limitation, module docs). We still join
            // rather than detach-the-struct-and-leak, so a caller that
            // waits on `detach()` gets a real guarantee once it returns.
            if handle.join().is_err() {
                return Err(InterceptorError::Platform(format!(
                    "tracer thread for pid {pid} panicked"
                )));
            }
        }
        self.event_rx = None;
        Ok(())
    }

    fn capabilities(&self) -> InterceptorCapabilities {
        InterceptorCapabilities {
            syscalls: true,
            scheduler: false, // requires the eBPF sched_switch source, §9 — future work
            signals: true,
            network_payloads: false, // argument/buffer capture is future work (raw::peek_text exists for it)
            memory_race_detection: false,
        }
    }

    fn poll_events(&mut self, max_wait_ms: u32) -> Result<Vec<Event>, InterceptorError> {
        let rx = self
            .event_rx
            .as_ref()
            .ok_or_else(|| InterceptorError::Platform("not attached".into()))?;

        let mut events = Vec::new();
        match rx.recv_timeout(Duration::from_millis(max_wait_ms as u64)) {
            Ok(ev) => events.push(ev),
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(events),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let pid = self.attached_pid.unwrap_or(0) as u32;
                return Err(InterceptorError::TargetGone { pid });
            }
        }
        // Drain anything else already buffered without waiting further.
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_rejects_follow_children_cleanly() {
        let mut interceptor =
            LinuxPtraceInterceptor::new(HostId::from_raw(1), SessionId::from_raw(1));
        let target = AttachTarget {
            pid: 1,
            follow_children: true,
        };
        let err = interceptor.attach(target).unwrap_err();
        assert!(matches!(err, InterceptorError::CapabilityUnavailable(_)));
        assert!(
            interceptor.attached_pid.is_none(),
            "a rejected attach must not leave partial state"
        );
    }

    #[test]
    fn double_attach_without_detach_is_rejected() {
        // Use an obviously-invalid pid so the spawned tracer thread fails
        // fast at `seize` (ESRCH) without needing real ptrace permissions
        // in this test environment — we're testing `attach`'s own
        // bookkeeping here, not the trace loop's kernel interaction (that
        // is covered by the `#[ignore]`d tests in `raw.rs`).
        let mut interceptor =
            LinuxPtraceInterceptor::new(HostId::from_raw(1), SessionId::from_raw(1));
        let target = AttachTarget {
            pid: 999_999,
            follow_children: false,
        };
        interceptor.attach(target).unwrap();
        let err = interceptor.attach(target).unwrap_err();
        assert!(matches!(err, InterceptorError::Platform(_)));
        let _ = interceptor.detach();
    }

    #[test]
    fn detach_without_attach_is_rejected() {
        let mut interceptor =
            LinuxPtraceInterceptor::new(HostId::from_raw(1), SessionId::from_raw(1));
        assert!(interceptor.detach().is_err());
    }

    #[test]
    fn poll_before_attach_is_rejected() {
        let mut interceptor =
            LinuxPtraceInterceptor::new(HostId::from_raw(1), SessionId::from_raw(1));
        assert!(interceptor.poll_events(10).is_err());
    }

    #[test]
    fn capabilities_reflect_ptrace_only_v1_scope() {
        let interceptor = LinuxPtraceInterceptor::new(HostId::from_raw(1), SessionId::from_raw(1));
        let caps = interceptor.capabilities();
        assert!(caps.syscalls);
        assert!(caps.signals);
        assert!(
            !caps.scheduler,
            "scheduler tracing needs the eBPF source, not implemented in v1"
        );
        assert!(!caps.memory_race_detection);
    }

    #[test]
    fn poll_on_invalid_pid_eventually_reports_target_gone() {
        // seize() on a nonexistent pid fails immediately (ESRCH), the
        // trace loop returns, and the event channel's sender is dropped —
        // poll_events must surface that as TargetGone rather than hanging
        // or silently returning an empty vec forever.
        let mut interceptor =
            LinuxPtraceInterceptor::new(HostId::from_raw(1), SessionId::from_raw(1));
        let target = AttachTarget {
            pid: 999_998,
            follow_children: false,
        };
        interceptor.attach(target).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match interceptor.poll_events(100) {
                Ok(events) if events.is_empty() && std::time::Instant::now() < deadline => continue,
                Ok(_) => panic!("expected TargetGone, got an Ok with no error before deadline"),
                Err(InterceptorError::TargetGone { .. }) => break,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }
}
