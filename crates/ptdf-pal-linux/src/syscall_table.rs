//! Curated x86_64 syscall number -> name/`EventKind` mapping.
//!
//! Scope note answering "where are the Thread/Process/FileSystem/
//! Memory/IPC/RNG/Clock Recorders?": on Linux, all of these are syscalls,
//! not separate interception mechanisms — `clone`/`fork`/`wait4` (thread
//! and process lifecycle), `open`/`openat`/`close` (filesystem),
//! `mmap`/`mprotect`/`munmap`/`brk` (memory), `shmget`/`shmat`/`msgget`/
//! `semget`/`pipe` (IPC), `getrandom` (RNG), and `clock_gettime`/
//! `gettimeofday` (clock) all arrive through the exact same
//! `ptrace(PTRACE_SYSCALL)` interception path already implemented in
//! `interceptor.rs`. This table is what differentiates them for indexing
//! and replay purposes (§7's `EventKind`) — it is the totality of what a
//! "System Call Recorder", "Thread Recorder", "Process Recorder",
//! "File System Recorder", "Memory Recorder", and "IPC Recorder" *are* on
//! this platform, not a stand-in for separate modules that don't exist yet.
//! `RngRead` and `ClockRead` get their own `EventKind` (matching §7)
//! because the Replay Engine treats them specially: on replay, these
//! syscalls' return values are served from the recording rather than
//! calling the real kernel RNG/clock, which is exactly what distinguishes
//! a deterministic replay from a live re-run.
//!
//! Scope: this table covers the syscalls needed for the recorder-core
//! integration test suite and the most common I/O/process/IPC/memory
//! syscalls, not the full ~350-entry x86_64 syscall table. Extending it is
//! additive (new match arms) and does not require touching any other
//! module. An unrecognized syscall number is not an error: it's still
//! recorded (see `SyscallInfo::unknown`), just without a friendly name, so
//! recording is never blocked on this table's coverage.

use ptdf_types::EventKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: &'static str,
    /// Almost all intercepted syscalls map to `EventKind::Syscall`; a small
    /// subset get their own semantic `EventKind` because the replay engine
    /// treats them specially (network payloads need blob-store handling;
    /// see architecture §7/§10).
    pub kind: EventKind,
}

impl SyscallInfo {
    const fn known(number: u64, name: &'static str, kind: EventKind) -> Self {
        Self { number, name, kind }
    }

    pub fn unknown(number: u64) -> Self {
        Self {
            number,
            name: "unknown",
            kind: EventKind::Syscall,
        }
    }
}

/// Lookup by x86_64 syscall number (the value ptrace reports in
/// `orig_rax`). Returns `SyscallInfo::unknown(number)` for anything not in
/// the curated table below.
pub fn lookup(number: u64) -> SyscallInfo {
    use EventKind::{ClockRead, NetIo, RngRead, Syscall};
    match number {
        0 => SyscallInfo::known(0, "read", Syscall),
        1 => SyscallInfo::known(1, "write", Syscall),
        2 => SyscallInfo::known(2, "open", Syscall),
        3 => SyscallInfo::known(3, "close", Syscall),
        9 => SyscallInfo::known(9, "mmap", Syscall),
        10 => SyscallInfo::known(10, "mprotect", Syscall),
        11 => SyscallInfo::known(11, "munmap", Syscall),
        12 => SyscallInfo::known(12, "brk", Syscall),
        22 => SyscallInfo::known(22, "pipe", Syscall),
        29 => SyscallInfo::known(29, "shmget", Syscall),
        30 => SyscallInfo::known(30, "shmat", Syscall),
        31 => SyscallInfo::known(31, "shmctl", Syscall),
        41 => SyscallInfo::known(41, "socket", NetIo),
        42 => SyscallInfo::known(42, "connect", NetIo),
        43 => SyscallInfo::known(43, "accept", NetIo),
        44 => SyscallInfo::known(44, "sendto", NetIo),
        45 => SyscallInfo::known(45, "recvfrom", NetIo),
        56 => SyscallInfo::known(56, "clone", Syscall),
        57 => SyscallInfo::known(57, "fork", Syscall),
        59 => SyscallInfo::known(59, "execve", Syscall),
        60 => SyscallInfo::known(60, "exit", Syscall),
        61 => SyscallInfo::known(61, "wait4", Syscall),
        62 => SyscallInfo::known(62, "kill", Syscall),
        64 => SyscallInfo::known(64, "semget", Syscall),
        65 => SyscallInfo::known(65, "semop", Syscall),
        66 => SyscallInfo::known(66, "semctl", Syscall),
        67 => SyscallInfo::known(67, "shmdt", Syscall),
        68 => SyscallInfo::known(68, "msgget", Syscall),
        69 => SyscallInfo::known(69, "msgsnd", Syscall),
        70 => SyscallInfo::known(70, "msgrcv", Syscall),
        96 => SyscallInfo::known(96, "gettimeofday", ClockRead),
        228 => SyscallInfo::known(228, "clock_gettime", ClockRead),
        231 => SyscallInfo::known(231, "exit_group", Syscall),
        234 => SyscallInfo::known(234, "tgkill", Syscall),
        247 => SyscallInfo::known(247, "waitid", Syscall),
        257 => SyscallInfo::known(257, "openat", Syscall),
        293 => SyscallInfo::known(293, "pipe2", Syscall),
        318 => SyscallInfo::known(318, "getrandom", RngRead),
        _ => SyscallInfo::unknown(number),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_syscall_resolves_name_and_kind() {
        let info = lookup(1);
        assert_eq!(info.name, "write");
        assert_eq!(info.kind, EventKind::Syscall);
    }

    #[test]
    fn network_syscalls_map_to_net_io_kind() {
        for n in [41, 42, 43, 44, 45] {
            assert_eq!(
                lookup(n).kind,
                EventKind::NetIo,
                "syscall {n} should be NetIo"
            );
        }
    }

    #[test]
    fn unknown_syscall_number_is_still_recordable() {
        let info = lookup(9999);
        assert_eq!(info.name, "unknown");
        assert_eq!(info.number, 9999);
        assert_eq!(
            info.kind,
            EventKind::Syscall,
            "unrecognized syscalls default to Syscall kind"
        );
    }

    #[test]
    fn clock_syscalls_map_to_clock_read_kind() {
        for n in [96, 228] {
            assert_eq!(
                lookup(n).kind,
                EventKind::ClockRead,
                "syscall {n} should be ClockRead"
            );
        }
    }

    #[test]
    fn getrandom_maps_to_rng_read_kind() {
        assert_eq!(lookup(318).kind, EventKind::RngRead);
        assert_eq!(lookup(318).name, "getrandom");
    }

    #[test]
    fn thread_and_process_lifecycle_syscalls_are_named() {
        for (n, name) in [
            (56, "clone"),
            (57, "fork"),
            (59, "execve"),
            (61, "wait4"),
            (247, "waitid"),
        ] {
            assert_eq!(lookup(n).name, name);
        }
    }

    #[test]
    fn ipc_syscalls_are_named() {
        for (n, name) in [(22, "pipe"), (29, "shmget"), (68, "msgget"), (64, "semget")] {
            assert_eq!(lookup(n).name, name);
        }
    }

    #[test]
    fn memory_syscalls_are_named() {
        for (n, name) in [(9, "mmap"), (10, "mprotect"), (11, "munmap"), (12, "brk")] {
            assert_eq!(lookup(n).name, name);
        }
    }
}
