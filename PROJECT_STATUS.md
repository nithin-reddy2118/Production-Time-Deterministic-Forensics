# PTDF Project Status

**As of this pass.** 15 crates, 56 Rust source files. No code in this
repository has ever been compiled (no toolchain/network in the authoring
sandbox — see `FINAL_VERIFICATION.md`).

## Completed features

- **Core types & causality**: `Event`/`EventKind`/`EventId`, Hybrid
  Logical Clock with monotonicity under clock stall/skew (`ptdf-types`).
- **Platform abstraction**: `PlatformInterceptor`/`ReplayDriver` trait
  boundary (`ptdf-pal`); real `ptrace(2)`-based Linux x86_64 implementation
  covering syscall/signal/thread/process/filesystem/memory/IPC/RNG/clock
  interception via one syscall table (`ptdf-pal-linux`).
- **Recording pipeline**: sequence allocation, backpressure/shedding
  `BoundedSink` (`ptdf-recorder-core`); full attach→sink→segment→metadata→
  metrics orchestration (`ptdf-recorder`).
- **Storage**: checksummed, versioned, optionally Zstd-compressed
  append-only segments (`ptdf-storage`).
- **Metadata**: `MetadataStore` trait + in-memory reference implementation
  (`ptdf-metadata`).
- **Replay**: deterministic per-thread scheduler (host_id-aware, fixing a
  real multi-node PID-collision bug found mid-project), standalone
  divergence comparator, checkpoint/resume with staleness detection
  (`ptdf-replay-engine`).
- **Distributed sync**: HLC piggyback wire codec + cross-host causal
  merge, proven via a 3-simulated-host integration test (`ptdf-distributed`).
- **Config**: defaults → TOML file → env → explicit-override layering
  (`ptdf-config`).
- **Observability**: structured logging (`ptdf-logging`); Prometheus-format
  metrics registry with the platform's canonical metric set
  (`ptdf-metrics`).
- **Security**: SHA-256-hashed API-key auth, RBAC, AES-256-GCM encryption
  (via the audited `aes-gcm` crate), append-only schema-versioned audit
  log (`ptdf-security`).
- **REST API**: HTTP/1.1 query API over `MetadataStore`+`ReplayEngine`,
  with a pure/unit-tested core and a real socket-level integration test
  suite (`ptdf-rest-api`).
- **CLI**: segment inspect/dump/verify (`ptdfctl`).
- **CI/tooling**: GitHub Actions workflow (build/test/clippy/doc across 3
  OSes, plus a dedicated audit/deny job), `deny.toml` license/advisory
  policy, local `scripts/ci-check.sh`.

## Remaining work

- Windows PAL adapter (ETW/minifilter) — needs a real WDK build
  environment to write against meaningfully, let alone verify.
- macOS PAL adapter (EndpointSecurity) — same category of gap.
- eBPF fast path for Linux (scheduler/`sched_switch` tracing) — needs
  `aya`/kernel headers + BPF verifier.
- gRPC API (REST exists; gRPC does not).
- Docker/Kubernetes/Helm deployment assets — none exist yet.
- Persistent (e.g. RocksDB-backed) `MetadataStore` — only in-memory exists.
- TLS for `ptdf-rest-api` (currently documented as a reverse-proxy
  responsibility, not implemented in-crate).
- Persistent principal store for `ptdf-security` (bootstrap admin key
  regenerates on every process start).
- **Compiling and running this code for the first time**, in any form.

## Known limitations

- Segment rotation is count-based only, not size-based.
- `ptdf-rest-api` is one-thread-per-connection — fine for an internal ops
  API, not internet-scale.
- No OIDC/human-user auth path (API-key auth only).
- SMP shared-memory race replay fidelity is explicitly out of scope by
  design for the default (non-opt-in) recording mode (see
  `docs/ARCHITECTURE.md` §29).
- `cargo audit`/`cargo deny` are wired into CI and the local script but
  have never actually been run against this dependency set.

## Future enhancements

See `PRODUCTION_READINESS.md` §9 and this file's "Remaining work" above;
they're the same list, prioritized as: compile it first, then gRPC, then
Windows adapter, then a persistent metadata backend, then Docker/Compose
before Helm/K8s.
