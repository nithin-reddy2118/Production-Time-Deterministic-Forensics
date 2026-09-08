# PTDF — Production-Time Deterministic Forensics

Cross-platform execution recording and deterministic replay platform.
Full architecture: see `docs/ARCHITECTURE.md`. Detailed, evidence-based
production-readiness assessment: see `PRODUCTION_READINESS.md`.

## Build environment note

This repository was written in a sandbox with **no Rust toolchain and no
network access** (`cargo`/`rustc` are not installed; crates.io is
unreachable). No code in this repository has been compiled, and no test
has been run, by the process that wrote it. Every file has been manually
reviewed for correctness against Rust's known semantics, and structural
checks (brace/paren balance, MSRV-sensitive API usage, dependency
consistency) were run where possible — see `PRODUCTION_READINESS.md` for
exactly what was and wasn't verified. Run `scripts/ci-check.sh` (or the
commands in "Build" below) yourself before relying on this code.

## Workspace layout

```
ptdf/
├── Cargo.toml                     # workspace root — all dependency versions centralized here
├── crates/
│   ├── ptdf-types/                # Event, EventKind, EventId, HLC — zero I/O, zero platform code
│   ├── ptdf-pal/                  # PlatformInterceptor + ReplayDriver trait boundary (§13)
│   ├── ptdf-recorder-core/        # SeqAllocator, RecorderSink/BoundedSink (§5, §8)
│   ├── ptdf-config/               # Layered config: defaults -> TOML file -> env -> explicit (§24)
│   ├── ptdf-logging/              # tracing-based structured logging (§25)
│   ├── ptdf-pal-linux/            # Linux ptrace(2) PlatformInterceptor (§13) — x86_64 only
│   ├── ptdf-storage/              # Segment writer/reader, binary codec, CRC32, Zstd (§10, §11)
│   ├── ptdf-metadata/             # MetadataStore trait + in-memory reference impl (§12)
│   ├── ptdf-replay-engine/        # DeterministicScheduler, divergence, checkpoint/resume (§6, §15, §22)
│   ├── ptdf-metrics/              # Counter/Gauge/Registry, Prometheus text exposition (§25)
│   ├── ptdf-recorder/             # Event Recorder: attach -> sink -> segment -> metadata -> metrics (§5, §8)
│   ├── ptdf-distributed/          # HLC piggyback wire codec + cross-host causal merge (§15)
│   ├── ptdf-security/             # API-key auth, RBAC, AES-256-GCM encryption, audit log (§18)
│   ├── ptdf-rest-api/             # REST/Query API: HTTP/1.1 over MetadataStore+ReplayEngine (§17)
│   └── ptdfctl/                   # CLI: segment inspect/dump/verify (§17)
├── docs/
│   └── ARCHITECTURE.md            # Phase 1 architecture document
├── scripts/
│   └── ci-check.sh                # Local pre-push check mirroring ci.yml (never executed — see note above)
├── PRODUCTION_READINESS.md
├── deny.toml                       # cargo-deny license/advisory/source policy
└── .github/workflows/ci.yml
```

## Build

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps
cargo audit
cargo deny check
```

`ptdf-pal-linux` is Linux/x86_64-only by design (its `raw.rs` has a
`compile_error!` guard for any other target); on other platforms, exclude
it: `cargo build --workspace --exclude ptdf-pal-linux`. `scripts/ci-check.sh`
does this detection automatically, and also runs `cargo audit`/`cargo deny`
locally if those subcommands are installed (skipping each with a clear
message otherwise, rather than failing) — see `.github/workflows/ci.yml`'s
`security-and-license-audit` job for the CI-enforced equivalent.
`deny.toml` at the repo root configures `cargo deny`'s license/advisory/
source policy.

## Dependency policy

Every crate's `Cargo.toml` `description` states *why* its dependencies
exist. `ptdf-types`, `ptdf-pal`, `ptdf-recorder-core`, and `ptdf-metadata`
depend on nothing but `thiserror` and each other — no async runtime, no
serialization, no platform crates — by design. Heavier dependencies
(`serde`+`toml`, `zstd`, `libc`, `aes-gcm`, `sha2`, `clap`) are each scoped
to the one crate that actually needs them, with the reason noted inline in
that crate's `Cargo.toml`. All dependency *versions* are centralized in
the root `[workspace.dependencies]` table; every crate references them via
`{ workspace = true }` rather than pinning its own version, so there is a
single place to bump a version across the whole workspace.

## Module status

See `PRODUCTION_READINESS.md` for the full, evidence-based breakdown of
what's implemented, what's tested, what's verified vs. unverifiable, and
the production-readiness score. Summary: the core recording/storage/replay
pipeline, security primitives, and a REST API are implemented with unit
and integration tests, for Linux/x86_64. Windows/macOS adapters, the eBPF
fast path, gRPC, Docker/Kubernetes/Helm assets, and any form of compiled
or run verification remain outstanding.
