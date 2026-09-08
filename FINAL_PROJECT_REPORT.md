# PTDF Final Project Report

## 1. Overall architecture

15 crates, 56 Rust source files, organized as five planes matching
`docs/ARCHITECTURE.md`'s design: types -> platform abstraction -> recording
-> storage/metadata -> replay, with security and a REST API layered on top.
Verified by reading every `Cargo.toml`: no dependency cycles; `ptdf-types`
has zero internal dependencies; every crate's dependency footprint is
scoped to what it actually needs (e.g. `ptdf-types`/`ptdf-pal`/
`ptdf-recorder-core`/`ptdf-metadata` depend on nothing but `thiserror`).
The one architectural gap between the design doc and this implementation:
there is no separate networked "Ingestion Plane" — the recorder writes
segments directly to local disk, read directly by the replay engine.

## 2. Security review

- API keys: SHA-256 hashed, never stored raw (test-verified against the
  actual stored `HashMap`).
- RBAC: 3 roles, permission sets verified to nest correctly by test.
- Encryption: AES-256-GCM via the audited `aes-gcm` crate, not hand-rolled;
  fresh nonce per call (test-verified: identical plaintext encrypts
  differently each time); tampering detected via the GCM tag (test-
  verified).
- Audit log: append-only, fsync'd, now schema-versioned with a tested
  backward-compatibility path for pre-versioning log lines.
- Hardening added during audit: `#![forbid(unsafe_code)]` on all 14 crates
  with zero unsafe usage; every one of the 9 `unsafe fn`s in the one crate
  that needs them (`ptdf-pal-linux`) documented with `# Safety`; a
  slowloris-class missing read-timeout fixed in `ptdf-rest-api`.
- Known, stated gaps: no TLS in-crate (reverse-proxy responsibility, a
  defensible split); no persistent principal store; no KMS integration.

## 3. Performance review

Cannot be measured — no toolchain to build or benchmark in this
environment. Structural choices are correctness-first by explicit design
(per-record fsync in both `SegmentWriter` and `AuditLogger`), with the
tradeoff documented in each module rather than hidden. `ptdf-rest-api`
is thread-per-connection, appropriate for an internal ops API.

## 4. Dependency review

All versions centralized in root `[workspace.dependencies]`, referenced
via `{ workspace = true }` everywhere — verified across all 15 manifests,
zero drift. Automated cross-reference of declared vs. source-referenced
dependencies flagged nothing unused (heuristic method, stated as such).
New dependencies added this project (`serde`, `serde_json`, `toml`,
`clap`, `zstd`, `libc`, `aes-gcm`, `sha2`) are all mainstream, actively
maintained. `deny.toml` now encodes a real license/advisory policy for
`cargo deny` to enforce once run in a real environment.

## 5. Testing review

~110+ unit tests across 15 crates' `#[cfg(test)]` modules, plus 2
integration-test files: `ptdf-distributed/tests/multi_node_replay.rs`
(proves correct causal ordering across 3 simulated hosts, including a
PID/TID-collision regression test for a bug found and fixed mid-project)
and `ptdf-rest-api/tests/rest_api_integration.rs` (binds a real TCP port,
drives it with real `TcpStream` connections, including 10 concurrent
connections). Coverage is deliberately thin exactly where it has to be —
real `ptrace` behavior against a live process, the HTTP server's accept
loop under real production load — and each such gap is documented inline
rather than silently absent.

## 6. Documentation review

Every public module carries doc comments explaining design rationale, not
just mechanics — a standard held from the first crate through the last.
Two staleness issues were found and fixed during audit passes: a
self-contradictory README (fixed by a full rewrite) and a stale
`docs/ARCHITECTURE.md` closing section that read as if no code existed.
Both are now consistent with the actual repository state as of this
report.

## 7. Remaining limitations

See `PROJECT_STATUS.md` for the full, current list. Headline items:
Windows/macOS platform adapters, eBPF fast path, gRPC API, all deployment
assets (Docker/K8s/Helm), persistent metadata/principal storage, and —
above all — **this code has never been compiled**.

## 8. Production readiness assessment

Manual review quality is high and improving (issue counts per audit pass:
8, 5, 3 new real findings on a growing codebase — see `FINAL_CHANGELOG.md`
Phases 6-8), but production readiness cannot be assessed above the
low-40s percentage range without the one verification that matters most:
an actual successful build. See `FINAL_VERIFICATION.md` for the complete,
itemized breakdown of what was and wasn't checked, and
`PRODUCTION_READINESS.md` for the original detailed scoring rationale
(score: ~38%, unchanged by this pass's fixes since they were consistency/
hardening fixes rather than new capability — the score is bottlenecked on
compilation, not on further manual polish).

## 9. Complete list of files changed

See `FINAL_CHANGELOG.md` for the full, phase-by-phase list with reasons
and breaking/non-breaking status for every file touched across the
project's entire history — not duplicated here to avoid the two documents
drifting out of sync with each other.

## 10. Complete list of issues fixed

1. `DeterministicScheduler` conflating threads across hosts with the same
   PID/TID (multi-node correctness bug).
2. `ptdf-recorder::session::run` — a `break` that only exited an inner
   loop, contradicting its own comment's stated intent; also had no
   `From<SinkError>` to propagate through even if reached.
3. Tautological (then, on first fix attempt, actually-weakened) test
   assertion in `ptdf-security::encryption`.
4. Missing connection read-timeout in `ptdf-rest-api::server`
   (slowloris-class gap).
5. `Option::is_none_or` used against a declared MSRV that predates its
   stabilization.
6. 8 crates missing `#![forbid(unsafe_code)]` despite having zero unsafe
   code.
7. `AuditRecord` had no schema-version field, risking silent parse
   failures on any future field change.
8. README self-contradiction plus a reference to a script
   (`scripts/ci-check.sh`) that didn't exist.
9. Stale `docs/ARCHITECTURE.md` closing section.
10. `panic = "abort"` in the shared `[profile.release]`, which would have
    made `cargo test --release` behave incorrectly against the standard
    libtest harness.
11. A second, self-introduced README staleness (the `ci-check.sh`
    description became wrong the moment the script was extended in the
    same pass it was described in) — caught and fixed immediately rather
    than left for a future pass.

Every item above is described with its file, reason, and effect in
`FINAL_CHANGELOG.md`.
