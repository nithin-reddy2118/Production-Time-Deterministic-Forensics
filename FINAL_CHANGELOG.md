# PTDF Final Changelog

All changes made while building and auditing this repository, in
chronological order by engineering phase. "Breaking" means it would
require a caller outside the crate to change code; internal/private
changes and additive API changes are marked Non-breaking.

## Phase 1 — Architecture

- **`docs/ARCHITECTURE.md`** (created): full Phase 1 architecture document,
  29 sections. Non-breaking (new file).

## Phase 2 — Core crates (initial build)

- **`Cargo.toml`** (created): workspace root, `[workspace.dependencies]`
  centralization policy established from the start.
- **`ptdf-types`** (created): `Event`, `EventKind`, `EventId`, `HostId`,
  `SessionId`, `HlcTimestamp`/`HlcGenerator`. Zero dependencies beyond
  `thiserror`, by design.
- **`ptdf-pal`** (created): `PlatformInterceptor`/`ReplayDriver` trait
  boundary, with in-memory mock implementations under `#[cfg(test)]`.
- **`ptdf-recorder-core`** (created): `SeqAllocator`, `BoundedSink`
  implementing the "load-bearing events never shed" backpressure policy.
- **`ptdf-config`** (created, later extended): layered config, initially
  defaults+env only.
- **`ptdf-logging`** (created): `tracing`-based init with Pretty/JSON
  formats.
- **`ptdf-pal-linux`** (created): `ptrace(2)`-based Linux x86_64
  interceptor — `raw.rs` (unsafe FFI boundary), `syscall_table.rs`,
  `interceptor.rs`.
- **`ptdf-storage`** (created, later extended): segment writer/reader,
  binary event codec, self-contained CRC32.
- **`ptdf-metadata`** (created): `MetadataStore` trait + in-memory
  implementation.
- **`ptdf-replay-engine`** (created, later substantially extended):
  initial version did a flat HLC sort for linearization.
- **`ptdfctl`** (created): CLI — `segment inspect/dump/verify`.

## Phase 3 — Observability, compression, recorder integration

- **`ptdf-config/src/schema.rs`**: added TOML file layer
  (`from_toml_str`/`from_toml_file`), completing 4 of 5 architecture-§24
  layers. Non-breaking (additive).
- **`ptdf-storage/src/segment.rs`**: added Zstd per-record compression
  (`create_compressed`/`create_compressed_default`), format-versioned
  (v1 uncompressed, v2 compressed) so both remain readable by one reader.
  Non-breaking (additive; `create` unchanged).
- **`ptdf-metrics`** (created): `Counter`/`Gauge`/`Registry`, Prometheus
  text exposition, `StandardMetrics` canonical metric names.
- **`ptdf-recorder`** (created): `RecordingSession` — the top-level Event
  Recorder orchestrator tying interceptor->sink->segment->metadata->metrics
  together, with segment rotation and a `StopHandle`.
- **`ptdf-pal-linux/src/syscall_table.rs`**: extended from a small curated
  set to cover thread/process lifecycle, filesystem, memory, IPC, RNG,
  and clock syscalls, with module docs explaining why these are table
  entries rather than separate recorder subsystems on Linux. Non-breaking
  (additive match arms).

## Phase 4 — Multi-node, checkpointing, divergence

- **`ptdf-replay-engine/src/scheduler.rs`** (created; later **fixed**):
  `DeterministicScheduler`, a k-way merge replacing the flat sort.
  **Bug found and fixed**: initially keyed threads by `(pid, tid)`, which
  conflates two different hosts' threads reusing the same PID/TID in a
  multi-node session. Rekeyed to `(host_id, pid, tid)`, with a targeted
  regression test. Non-breaking (internal to the crate).
- **`ptdf-replay-engine/src/divergence.rs`** (created): standalone,
  platform-neutral `ObservedOperation`/`check` comparator.
- **`ptdf-replay-engine/src/checkpoint.rs`** (created): `ReplayCheckpoint`
  with staleness validation; `ReplayEngine::run_with_options` added
  (`run` kept as the zero-config default — non-breaking).
- **`ptdf-pal-linux/src/replay_injector.rs`** (created): pure
  `syscall_result_to_rax` mapping a recorded `EventResult` to the exact
  register value the Linux syscall ABI expects.
- **`ptdf-distributed`** (created): HLC piggyback wire codec
  (`piggyback.rs`) + cross-host causal merge (`sync.rs`), plus
  `tests/multi_node_replay.rs` proving correct 3-host causal ordering.

## Phase 5 — Security & REST API

- **`ptdf-security`** (created): `auth.rs` (SHA-256 hashed API keys,
  `generate_random_api_key`), `authz.rs` (RBAC), `encryption.rs`
  (AES-256-GCM via `aes-gcm`), `audit.rs` (append-only JSON-lines log).
- **`ptdf-rest-api`** (created): `http.rs` (pure parse/response),
  `routes.rs` (handlers over `MetadataStore`+`ReplayEngine`), `server.rs`
  (thin `TcpListener` wrapper), `main.rs` (binary), plus
  `tests/rest_api_integration.rs` (real-socket integration tests).
- **`Cargo.toml`**: registered `ptdf-security`, `ptdf-rest-api` in
  workspace `members` (initially missing — found and fixed same pass).

## Phase 6 — First audit pass

- **`ptdf-recorder/src/session.rs`**: **bug fix** — a `break` inside the
  inner `for event in events` loop only exited that loop, not the outer
  record loop, contradicting the adjacent comment's stated intent.
  Added `RecorderError::Sink` (there was no `From<SinkError>` at all
  before this, so the path couldn't have propagated correctly even if
  reached); changed `break` to `return Err(e.into())`. Non-breaking
  (new enum variant; the fixed path was previously unreachable-by-design
  defensive code).
- **`ptdf-security/src/encryption.rs`**: removed a tautological test
  assertion (`... || debug_str == "<the literal just asserted above>"`,
  always true) and replaced it with a real cross-key comparison. Two
  iterations — first replacement was itself flawed (an escape clause
  that would incorrectly pass ~24% of random bytes); caught and corrected
  in the same pass. Non-breaking (test-only).
- **`ptdf-rest-api/src/server.rs`**: added a 10-second read timeout on
  accepted connections — previously absent, a slowloris-class resource
  exhaustion gap. Non-breaking.
- **`ptdf-rest-api/src/routes.rs`**: replaced `Option::is_none_or`
  (stabilized Rust 1.82) with `map_or` — the workspace declares
  `rust-version = "1.75"`; the original would not compile at that MSRV.
  Non-breaking.

## Phase 7 — Second audit pass

- **8 crates** (`ptdf-recorder`, `ptdf-storage`, `ptdf-metadata`,
  `ptdfctl`, `ptdf-logging`, `ptdf-security`, `ptdf-rest-api`,
  `ptdf-replay-engine`) **`src/lib.rs`**: added `#![forbid(unsafe_code)]`
  — verified each had zero unsafe usage first. Non-breaking (a lint
  attribute cannot break correct callers; it can only reject code that
  was already invalid for this crate's intent).
- **`ptdf-security/src/audit.rs`**: added `schema_version` field to
  `AuditRecord` with `serde(default)`, plus a test that feeds a
  hand-written pre-versioning JSON line through the reader to prove
  backward compatibility actually works. Non-breaking (new field has a
  default; old logs still parse).
- **`README.md`**: full rewrite — the previous version had accreted
  self-contradictory status paragraphs (claiming the REST API both
  "not done" and, elsewhere, fully built) and referenced
  `scripts/ci-check.sh`, which did not exist. Non-breaking (docs only).
- **`scripts/ci-check.sh`** (created): local pre-push script mirroring
  the CI workflow, closing the reference gap above.
- **`PRODUCTION_READINESS.md`** (created): first evidence-based
  production-readiness report.

## Phase 8 — Third audit pass (this pass)

- **`docs/ARCHITECTURE.md`**: fixed a stale closing section that still
  read as if no code existed ("Phase 2 starts with Module 1") despite 15
  crates being built; replaced with a pointer to `README.md`/
  `PRODUCTION_READINESS.md` for live status. Non-breaking (docs only).
- **`deny.toml`** (created): real `cargo-deny` policy (license allowlist,
  advisory/source rules) — written for a real environment to execute,
  never run here.
- **`.github/workflows/ci.yml`**: added `cargo doc --workspace --no-deps`
  to the main job; added a second job, `security-and-license-audit`,
  running `rustsec/audit-check` and `EmbarkStudios/cargo-deny-action`.
  Non-breaking (CI config only).
- **`Cargo.toml`**: **removed `panic = "abort"` from `[profile.release]`**
  — this profile is shared with `cargo test --release`, and the standard
  libtest harness needs unwinding to isolate individual test panics as
  failures rather than aborting the whole test binary; kept as a
  documented comment for anyone wanting a dedicated abort-on-panic
  deployment profile instead. Non-breaking for library/test consumers;
  binary artifacts (`ptdfctl`, `ptdf-api-server`) will now unwind on
  panic in release builds rather than abort, which is a behavior change
  for anything specifically relying on abort-triggered process semantics
  (e.g. an orchestrator that expected an immediate SIGABRT-style exit) —
  called out explicitly since "non-breaking for the API" is not the same
  claim as "no behavior changes anywhere."
- **`scripts/ci-check.sh`**: added `cargo doc`, `cargo audit` (if
  installed), `cargo deny check` (if installed) steps, each skipping
  gracefully with a message rather than failing if the tool isn't present.
  Non-breaking (script only).
- **`README.md`**: updated the `ci-check.sh` description to match its
  new actual behavior (it previously said the opposite — that audit/deny
  were *not* run locally — which became stale the moment the script was
  extended in this same pass; caught and fixed immediately).
- **`FINAL_PROJECT_REPORT.md`, `FINAL_CHANGELOG.md`,
  `FINAL_VERIFICATION.md`, `PROJECT_STATUS.md`** (created): this handoff
  package.
