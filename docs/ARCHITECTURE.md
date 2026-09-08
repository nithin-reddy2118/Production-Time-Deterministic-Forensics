# PTDF — Production-Time Deterministic Forensics
## Phase 1: System Architecture Document (v1.0)

---

## 1. Vision

PTDF is a cross-platform execution recording and deterministic replay platform. It captures the non-deterministic inputs of a running production system — syscalls, scheduling decisions, network I/O, shared-memory interleavings, timing sources, and external environment responses — with low enough overhead to run continuously in production, and later **deterministically replays** that exact execution for debugging, incident forensics, and root-cause analysis.

It is not tracing (which samples/summarizes) and not a simulator (which approximates). PTDF's contract is: *replay must reproduce the same instruction-level control flow and data values that occurred in production*, bounded by what the target OS/hardware exposes.

## 2. Goals

**Functional**
- Record process execution with all sources of nondeterminism captured or made replayable.
- Deterministically replay a recorded session, single-stepped or free-run, with debugger attach.
- Support multi-process / multi-threaded / multi-host recordings with causal ordering preserved.
- Support Linux and Windows natively at GA; macOS and containers/K8s as adapters over the same core.
- Query recorded sessions (by time range, syscall, PID, host, event type) without full replay.

**Non-functional**
- Recording overhead target: <5% CPU/latency overhead on Linux (ptrace/eBPF hybrid), <10% on Windows (ETW-based), configurable sampling fallback beyond that.
- Storage overhead: <1x original I/O volume after compression for typical workloads (syscall-heavy workloads compress well; data-heavy less so — addressed via reference/copy-on-write storage).
- Crash-safe: a crash of the recorder must not corrupt already-flushed segments.
- Horizontally scalable ingestion and storage; no single point of failure in the control plane.
- Security: recordings may contain sensitive data (memory contents, arguments) — encryption at rest and in transit, RBAC on read/replay, redaction hooks.

## 3. Non-Goals (explicit)
- Not a general APM/tracing product (no sampling-based statistical profiles as the primary output).
- Not a network simulator — external systems the target talks to are **recorded as responses**, not modeled.
- Full bit-exact replay of true SMP data races is only guaranteed under our race-recording mode (higher overhead); default mode guarantees deterministic *scheduling of recorded events*, not arbitrary shared-memory interleavings beyond what the hardware/OS exposes cheaply (see §14, Risks).

## 4. High-Level Architecture

Five planes:

1. **Recording Plane** — in-target agents (per-OS) that intercept nondeterministic sources and emit an event stream.
2. **Ingestion Plane** — receives, orders, and durably persists event streams from many hosts.
3. **Storage Plane** — segmented, compressed, indexed event log + content-addressed data store for large payloads (memory pages, buffers).
4. **Replay Plane** — reconstructs a sandboxed execution environment and drives target process(es) through the recorded event stream via the same platform abstraction layer used for recording.
5. **Control Plane** — configuration, session management, authn/authz, query API, plugin registry.

```
 ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 │  Target Host │   │  Target Host│   │ Target Host │
 │ ┌─────────┐  │   │ ┌─────────┐ │   │ ┌─────────┐ │
 │ │ Recorder │  │   │ │ Recorder│ │   │ │ Recorder│ │
 │ │  Agent   │  │   │ │  Agent  │ │   │ │  Agent  │ │
 │ └────┬────┘  │   │ └────┬────┘ │   │ └────┬────┘ │
 └──────┼───────┘   └──────┼──────┘   └──────┼──────┘
        └───────────────────┼──────────────────┘
                             ▼
                    ┌──────────────────┐
                    │  Ingestion Plane  │  (gRPC/QUIC, backpressure,
                    │  (segment writer) │   per-host ordered streams)
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │   Storage Plane   │  (event log + CAS blob store
                    │                   │   + metadata/index engine)
                    └────────┬─────────┘
              ┌──────────────┼──────────────┐
              ▼                             ▼
     ┌────────────────┐           ┌──────────────────┐
     │  Query / API    │           │   Replay Engine   │
     │  (control plane)│           │  (sandboxed exec) │
     └─────────────────┘           └──────────────────┘
```

## 5. Recording Pipeline

1. **Attach** — agent attaches to target (process launch hook, container runtime hook, or live-attach via ptrace/EBPF/ETW).
2. **Intercept** — platform adapter intercepts: syscalls, scheduler decisions (context switch points relevant to the target), signals/exceptions, network I/O payloads, clock reads, RNG reads, shared-memory-relevant events (optional race mode), and environment reads (env vars, files opened).
3. **Event construction** — each intercepted point becomes an `Event` (see §7) with a monotonic per-thread sequence number, a vector-clock-style causality stamp, and a payload (or a reference into the blob store for large payloads).
4. **Local buffering** — lock-free per-CPU ring buffers (Linux: eBPF ring buffer / perf buffer; Windows: ETW session buffers) drain to a local write-ahead segment.
5. **Batched transmission** — local segments are compressed and shipped to the Ingestion Plane; local disk acts as durable backpressure buffer if the network is unavailable.

## 6. Replay Pipeline

1. **Session load** — Replay Engine loads session metadata + event index for the target process tree/time range.
2. **Environment reconstruction** — a sandboxed execution context is built (namespace/container on Linux, Job Object on Windows) with the same binary, loaded libraries (version-pinned via recorded hashes), env vars, and file view (via CAS-backed file snapshots or overlay).
3. **Driven execution** — the target binary is re-executed under the platform adapter in **replay mode**: every intercepted point that would normally hit the real OS/kernel/network instead is served from the recorded event stream in causal order (syscalls return recorded values, clock reads return recorded timestamps, network recv returns recorded bytes).
4. **Divergence detection** — if live execution's intercepted call signature doesn't match the next expected recorded event (wrong syscall, wrong argument shape), replay halts and reports a divergence with full context — this is itself a primary forensic signal (e.g., detects a binary that no longer matches what ran in prod).
5. **Debugger integration** — replay can run under GDB/LLDB/WinDbg with reverse-step support (checkpoint + re-run-to-N, since raw reverse execution isn't available on commodity hardware).

## 7. Event Model

```
Event {
  event_id: u128            // globally unique
  session_id: Uuid
  host_id: Uuid
  pid, tid: u32
  seq: u64                  // per-thread monotonic
  vclock: VectorClock        // causal ordering across threads/hosts
  wall_time_ns: u64          // recorded, not trusted for ordering
  kind: EventKind            // Syscall | Sched | Signal | NetIO | ClockRead | RngRead | MemRace | EnvRead
  payload: Inline(bytes) | BlobRef(ContentHash)
  result: EventResult        // return value / errno / bytes-transferred
}
```

Event kinds are extensible via the plugin architecture (§17) — new adapters register new `EventKind` variants without touching the core.

## 8. Recording Engine

- **Core**: OS-agnostic Rust crate (`ptdf-recorder-core`) defining `Event`, `RecorderSink` trait, causality tracking, and buffering/backpressure logic.
- Adapters (below) implement `PlatformInterceptor` and push into the core sink.
- Overhead control: adaptive sampling degrades gracefully — under load, race-detection and low-value clock-read events shed first; syscalls affecting external state never shed (replay correctness is defined around syscalls/network — these are load-bearing).

## 9. Scheduler Architecture (Recording)

Goal is not to record every hardware interleaving, but to record enough scheduling information to reproduce **observable behavior**: thread creation/join order, lock acquisition order (via a lightweight lock-wrapping shim or eBPF uprobes on pthread/Win32 sync primitives), and context-switch points that affect shared state accessed without a captured lock (best-effort, flagged as "unverified" if the race-detection mode is off). This is recorded as a per-process **happens-before graph**, stored alongside the event log, and is what the Replay Engine's scheduler consults to sequence threads deterministically during replay.

## 10. Storage Engine

- **Event log**: append-only, segment-based (default 128 MB segments), similar in spirit to an LSM-adjacent WAL — segments are immutable once sealed and sealed segments are what gets replicated/compressed.
- **Blob store**: content-addressed store (BLAKE3-keyed) for large payloads (memory snapshots, network payloads over a size threshold, file snapshots) — enables deduplication across sessions (e.g., identical shared library pages).
- **Replication**: segments replicated N=3 across storage nodes (Raft-managed segment placement metadata; segment bytes themselves are immutable so replication is simple copy + checksum, not consensus over content).
- Language: Rust, built on top of a custom segment format rather than an off-the-shelf embedded DB, because (a) we need content-addressed blob dedup + WAL semantics together, (b) sequential append/segment-seal maps directly onto cheap replication, (c) avoids paying for transactional/B-tree machinery we don't need on the hot write path. Metadata/index (§11) does use an embedded engine (RocksDB) since it needs point lookups and range scans and isn't the throughput-critical path.

## 11. Compression Engine

- Per-segment: Zstd (dictionary-trained per event-kind, since syscall argument structures are highly repetitive — this is where most of the size reduction comes from) at level tuned by ingestion load (fast level under backpressure, max level on background recompaction).
- Blob store: content-addressing already removes duplicate blobs; individual blobs compressed with Zstd; memory-page blobs get delta-compressed against the previous recorded snapshot of the same page when available.

## 12. Metadata Engine

- RocksDB-backed index: `session_id -> {hosts, pids, time_range, segment_list}`, `(pid, seq_range) -> segment_offset`, `content_hash -> blob_location`, plus secondary indices for query (event kind, syscall name, error codes) to support "find all sessions where syscall X returned EAGAIN" without full replay.

## 13. Platform Abstraction Layer (PAL)

Rust trait boundary (`ptdf-pal`) exposing: `attach`, `intercept_syscall`, `intercept_sched`, `intercept_signal`, `intercept_net`, `read_clock`, `snapshot_memory`, and the replay-mode duals (`inject_syscall_result`, etc.). All platform adapters implement this trait; the core engine only depends on the trait, never on OS-specific types.

### Linux Adapter
- Recording: hybrid of eBPF (tracepoints/kprobes for syscalls, sched_switch tracepoint for scheduling, low overhead, no ptrace-induced context-switch tax) + ptrace fallback for full argument/memory capture when eBPF's argument access is insufficient (e.g., full buffer contents on `read`/`write`).
- Replay: `seccomp`-filtered + `ptrace`-driven — replay executes under a seccomp policy that traps all syscalls to the replay engine, which serves recorded results instead of calling the real kernel.
- Language: Rust with `libbpf-rs`/`aya` for eBPF; small C shims only where CO-RE/eBPF verifier constraints require it.

### Windows Adapter
- Recording: ETW (Event Tracing for Windows) providers for syscalls/scheduler where available, plus a minifilter/minidriver for cases ETW doesn't expose sufficient argument detail, plus Detours-style user-mode API hooking for Win32 API-level interception where kernel-level isn't necessary.
- Replay: user-mode hooking layer intercepts the same API surface and serves recorded results; kernel-level replay (driver-based) is a stretch goal for syscall-exact replay parity with Linux.
- Language: Rust for the agent process; C for the minifilter/driver (unavoidable — WDK is a C ABI).

### macOS Adapter
- Recording: EndpointSecurity framework + `dtrace`/`ktrace` where entitlements allow; significantly more constrained by Apple's sandboxing than Linux/Windows, so macOS is treated as **best-effort / dev-workflow** rather than a production-parity target at GA — documented explicitly as reduced-fidelity.

### Container/Orchestration Adapters
- Docker/Podman/Kubernetes are not separate recording mechanisms — they're **deployment adapters** for the Linux adapter (agent runs as a sidecar or injected into the container's PID namespace via a runtime hook — OCI `prestart` hook for Docker/Podman, a mutating admission webhook + init container for Kubernetes).

## 14. Networking Architecture

- Agent → Ingestion: gRPC over QUIC (multiplexed streams per session, survives connection migration for mobile/edge hosts, built-in flow control for backpressure).
- Ingestion → Storage: internal RPC, same stack, but batched at segment granularity.
- Control plane: standard REST/gRPC API gateway in front of the Query API.

## 15. Distributed Synchronization & Causality

- Each host's agent maintains a **hybrid logical clock (HLC)** — combines wall-clock (for human-readable ordering) with a logical counter (for causal correctness), per Lamport/HLC literature.
- Cross-host causality (e.g., host A sends a network message host B receives) is captured by piggybacking the sender's HLC value on the recorded network payload; the receiver's `NetIO` recv event records the piggybacked value, giving a happens-before edge without a synchronization protocol.
- Event ordering for replay: within a thread, `seq` (total order). Across threads/hosts, HLC + explicit happens-before edges from §9/§15 form a partial order; the Replay Engine's scheduler picks any linearization consistent with that partial order (any such linearization reproduces observable behavior identically, by construction).

## 16. Storage Format & Indexing Strategy
(Detailed in §10/§12 above — segment format spec, index schema, and on-disk layout get a dedicated design doc before Module 9 implementation, per the "explain every important decision" requirement — flagged here as a Phase-1.5 deliverable rather than duplicated in this document.)

## 17. Public / Internal APIs

- **Public**: gRPC + REST Query API (session list/search, event query, replay-session start/stop/step, divergence report fetch); CLI (`ptdfctl`) wraps this API.
- **Internal**: `RecorderSink` trait (agent → local buffer), `SegmentWriter` trait (ingestion → storage), `PlatformInterceptor` trait (PAL, §13), `ReplayDriver` trait (replay engine → PAL in replay mode). All internal boundaries are trait-based so alternate implementations (e.g., a future eBPF-only Windows path) can be swapped without touching core logic.

## 18. Security Architecture

- **Encryption**: TLS 1.3 (via QUIC) in transit; segments and blobs encrypted at rest with AES-256-GCM, per-session data-encryption-keys wrapped by a KMS-held key (pluggable: AWS KMS/Azure Key Vault/HashiCorp Vault).
- **Authentication**: mTLS between agents and ingestion (cert-per-host, issued by an internal CA); OIDC for human users of the Query API/CLI.
- **Authorization**: RBAC at the session level (who can query, who can replay — replay access is more sensitive since it can reconstruct full memory contents).
- **Redaction**: pluggable redaction hooks run at the agent before data leaves the host (e.g., strip known-sensitive buffer patterns), configurable per-syscall/per-argument.

## 19. Failure Recovery / Crash Recovery

- Agent-local WAL segments are fsync'd before being marked eligible for deletion post-ack from ingestion — an agent crash loses at most the unflushed tail, which is bounded and configurable.
- Ingestion nodes are stateless with respect to segment content (segments are immutable once sealed) — an ingestion node crash mid-segment just means the agent resends the unacked tail on reconnect (idempotent via segment sequence numbers).
- Storage replication (§10) tolerates N-1 of N replica failures per segment.

## 20. Scalability Strategy

- Ingestion scales horizontally behind a load balancer keyed by `host_id` (sticky routing preferred but not required, since segments are self-describing).
- Storage scales by adding storage nodes; segment placement is rebalanced in the background (Raft-managed placement metadata, §10).
- Query API scales by read-replica RocksDB followers for the metadata index.

## 21. Performance Optimization Strategy

- Zero-copy from eBPF ring buffer to local segment where possible (Rust `bytes::Bytes` slices over mmap'd buffers).
- Batching at every plane boundary (agent→ingestion, ingestion→storage) to amortize network/syscall overhead.
- Adaptive fidelity (§8) as the primary lever for keeping overhead under target on hot targets.

## 22. Memory Management & Threading Model

- Agent: single-writer-per-CPU ring buffer draining pattern (avoids cross-CPU contention on the hot capture path), Tokio async runtime for the network/shipping side, kept strictly separate from the capture side (capture must never block on network backpressure — it spills to local disk instead, §5).
- Replay Engine: one OS thread per recorded thread being replayed, coordinated via the happens-before graph (§9) using a custom scheduler (not the OS scheduler) that releases each thread only when its next event's causal predecessors have been served.

## 23. Plugin Architecture

- Rust `dlopen`-based plugin ABI (stable `extern "C"` boundary + versioned struct-of-function-pointers, since Rust doesn't have a stable ABI across compiler versions) for: new `EventKind`s, new platform adapters, new storage backends, new redaction rules. Plugin manifest declares capabilities and required core-API version for compatibility checking at load time.

## 24. Configuration System

- Layered config (defaults → file (TOML) → environment → CLI flags → dynamic control-plane push), single `ptdf-config` crate shared by agent/ingestion/replay/CLI so schema is defined once. Hot-reloadable where safe (redaction rules, sampling thresholds); requires restart where not (storage backend selection).

## 25. Logging & Monitoring

- Structured logging (`tracing` crate) throughout, separate from the recorded event stream (this is operational logging about PTDF itself, not to be confused with what PTDF records).
- Metrics: Prometheus-compatible `/metrics` on every plane (agent overhead %, ingestion throughput/backpressure, storage segment counts, replay divergence rate) — dogfooding note: PTDF's own components are natural first users of PTDF for debugging PTDF itself.

## 26. Testing & Benchmarking Strategy

- Unit tests per module (required per module, per the process rules).
- Integration tests: record-then-replay round-trip tests against known workloads (single-threaded, multi-threaded with locks, multi-process pipes, multi-host network) asserting byte-identical observable output.
- Benchmarks: overhead percentage vs. an un-recorded baseline across a standard workload suite (to be defined at Module 18), tracked over time to catch regressions.

## 27. Deployment Strategy

- Agent: static binary (or minimal container image) per platform; Kubernetes deployment via the admission-webhook adapter (§13); VM/bare-metal via systemd unit (Linux) or Windows Service.
- Control plane / ingestion / storage: containerized, deployed via Helm chart for K8s or standalone binaries for VM/bare-metal ops.

## 28. Future Roadmap
- Kernel-level Windows replay parity with Linux (driver-based).
- Full hardware-assisted race recording (e.g., leveraging Intel PT) as an opt-in high-fidelity mode.
- macOS production-parity if Apple's platform security model permits sufficient interception.

## 29. Risks & Engineering Trade-offs
- **SMP race fidelity**: default mode does not guarantee bit-exact reproduction of arbitrary unsynchronized shared-memory races — flagged explicitly (§2, §9) rather than overpromised; race-recording mode exists but costs more overhead.
- **Windows kernel depth**: ETW/minifilter approach doesn't reach full syscall-level parity with the Linux ptrace/eBPF path at GA — documented as a known gap, not hidden.
- **Rust ABI stability for plugins**: mitigated via a C-style stable ABI boundary rather than relying on Rust's own ABI.
- **Storage growth**: content-addressing and delta-compression mitigate but don't eliminate the fact that data-heavy (not syscall-heavy) workloads compress poorly — sampling/retention policy is the real lever there, called out as an operational concern, not purely engineering.

---

### Current status

This document is the original Phase 1 deliverable and is kept as-written
for historical/design reference — the numbered sections above describe
the target architecture, not a live status. **For current implementation
status, see the root `README.md` (crate-by-crate layout) and
`PRODUCTION_READINESS.md` (what's implemented, tested, verified vs.
unverifiable, and the production-readiness score).** As of the most recent
engineering pass: 16 crates exist covering the core recording/storage/
replay pipeline, security primitives, and a REST API for Linux/x86_64;
Windows/macOS adapters, the eBPF fast path, gRPC, and all deployment
assets (Docker/K8s/Helm) remain outstanding. No code in this repository
has been compiled in the environment that produced it — see
`FINAL_VERIFICATION.md` for exactly what was and wasn't checked.
