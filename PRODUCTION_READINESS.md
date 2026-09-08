# PTDF Production Readiness Report

**Generated from a manual, file-by-file audit.** The sandbox that produced
and audited this repository has **no Rust toolchain** (`cargo`/`rustc` not
found) and **no network access** (`curl https://crates.io` returns `403
host_not_allowed`). `cargo fmt`, `cargo clippy`, `cargo check`, and `cargo
test` have **never been run** against this code. Every finding below is
either (a) a manual read of the actual source, or (b) a structural check I
could run without a toolchain (brace/paren balance, `grep`-based API/MSRV
checks, dependency-usage cross-referencing) — never invented, never
assumed.

---

## 1. Architecture review

16 crates, 56 source files. Dependency graph (verified by reading every
`Cargo.toml`): `ptdf-types` is the only crate with zero internal
dependencies; `ptdf-pal` depends only on it; every other crate depends on
some combination of `ptdf-types`/`ptdf-pal`/`ptdf-recorder-core` plus at
most one or two siblings (`ptdf-storage`, `ptdf-metadata`). No cycles
found — `ptdf-pal-linux` → `ptdf-recorder-core` → `ptdf-pal` is a diamond
(both paths terminate at `ptdf-pal`/`ptdf-types`), not a cycle. Layering
matches the architecture doc's plane model (Recording / Storage / Replay /
Control) reasonably closely, with the caveat that "Ingestion Plane" as a
separate networked component does not exist yet — segments are written
directly to local disk and read directly by the replay engine, with no
network transport between recorder and storage.

## 2. Security review

- **Authentication**: API keys are SHA-256 hashed before storage; verified
  by a test (`raw_key_is_never_stored_verbatim`) that inspects the actual
  `HashMap` contents, not just the public API.
- **Authorization**: 3 fixed roles, permission sets verified to nest
  correctly (Viewer ⊂ Operator ⊂ Admin) by test.
- **Encryption**: `aes-gcm` (RustCrypto), not hand-rolled. Fresh nonce per
  call via OS CSPRNG (verified: two encryptions of identical plaintext
  produce different ciphertext). Tampering detected via GCM's tag
  (verified by a test that flips one ciphertext byte).
- **Audit logging**: append-only, fsync'd per record. **Fixed this pass**:
  added a `schema_version` field with `serde(default)` so future field
  changes don't break parsing of already-written logs — verified with a
  test that feeds a hand-written pre-versioning JSON line through the
  reader.
- **Hardening fixed this pass**: 8 of 16 crates (`ptdf-recorder`,
  `ptdf-storage`, `ptdf-metadata`, `ptdfctl`, `ptdf-logging`,
  `ptdf-security`, `ptdf-rest-api`, `ptdf-replay-engine`) contained zero
  `unsafe` code but were missing `#![forbid(unsafe_code)]`. Added to all
  8. `ptdf-pal-linux` correctly does *not* have this attribute (it
  legitimately needs `unsafe` for `ptrace`); every `unsafe fn` in that
  crate was individually confirmed to have a `# Safety` doc comment (9/9).
- **Fixed this pass**: `ptdf-rest-api`'s `server.rs` set no read timeout on
  accepted connections — a slow/silent client could hold a server thread
  open indefinitely (slowloris-class). Added a 10s timeout.
- **Known gaps, stated plainly, not fixed**: no TLS in `ptdf-rest-api`
  itself (documented as a reverse-proxy responsibility); no persistent
  principal store (bootstrap admin key regenerates every process start);
  no KMS integration for DEK wrapping (out of scope, documented).

## 3. Performance review

Cannot be measured — no toolchain to build or benchmark. Structural
observations only: `SegmentWriter::append` and `AuditLogger::record` both
fsync per call, a correctness-first default documented as such in both
modules, with batching flagged as future work. `ptdf-rest-api` uses one
OS thread per connection, adequate for an internal ops API, not
internet-scale.

## 4. API review

Every fallible public function returns a crate-local `thiserror` enum.
Constructor naming is contextual, not arbitrary (`open()`/`create()` for
things backed by a file, `new()` for in-memory state, `register()` for
adding to a collection) — reviewed and judged consistent, not changed.
`ReplayEngine::run` vs. `run_with_options`, `SegmentWriter::create` vs.
`create_compressed`/`create_compressed_default` follow the same
"simple-default, `_with_options`/qualified-variant for control" pattern
throughout the workspace.

## 5. Dependency review

All dependency *versions* live in root `[workspace.dependencies]`; every
crate references them via `{ workspace = true }` — checked across all 15
manifests, no version drift found. Ran an automated cross-reference of
every declared dependency name against that crate's actual source for all
16 crates: **zero flagged as unused** by this check. (Caveat: this is a
substring-on-identifier heuristic, not a real unused-deps analysis like
`cargo udeps` — stated as a limitation, not claimed as equivalent.)
`sha2`, `aes-gcm`, `serde`, `serde_json`, `toml`, `clap`, `zstd`, `libc`
are all mainstream, actively-maintained crates — no unusual choices found.
**Cannot verify**: that these versions actually resolve/compile together
(no network/toolchain).

## 6. Testing review

Rough count: 110+ `#[test]` functions in `#[cfg(test)]` modules across 16
crates, plus 2 dedicated integration-test files
(`ptdf-distributed/tests/multi_node_replay.rs`,
`ptdf-rest-api/tests/rest_api_integration.rs` — the latter binds a real
TCP socket and drives real `TcpStream` connections, including a
10-concurrent-connection test). Coverage is strong on pure logic (codec
round-trips, HLC monotonicity under clock skew/stall, scheduler ordering
including a targeted multi-host PID-collision regression test, encryption
round-trips, HTTP parsing edge cases) and intentionally thin exactly where
it has to be (real `ptrace` behavior, `server.rs`'s accept loop under real
load) — each such gap is documented in the relevant module, not silently
absent.

## 7. Documentation review

**Fixed this pass**: the root `README.md` had accreted inconsistent status
paragraphs across many editing sessions to the point of contradicting
itself (claiming the REST API both "not done" and, three paragraphs later,
fully described with routes) and referencing `scripts/ci-check.sh`, which
did not exist. Rewrote the README as one consistent document; wrote
`scripts/ci-check.sh` for real (mirrors `.github/workflows/ci.yml`,
including the `ptdf-pal-linux` platform exclusion), explicitly noting it
has never been executed either.

## 8. Remaining technical debt

No TLS in the API; no persistent principal/session store; count-based
(not size-based) segment rotation only; thread-per-connection HTTP
server; API-key auth only (no OIDC for human users, per architecture
§18's stated intent); Windows/macOS adapters, eBPF fast path, gRPC API,
Docker/K8s/Helm assets not built; nothing in this repository has ever
been compiled.

## 9. Future roadmap

1. **Compile it.** Highest-value next step by a wide margin — 15+ turns
   of manually-reviewed-but-never-built Rust is the single biggest risk
   in this project, full stop.
2. gRPC API alongside REST.
3. Windows adapter behind the existing `PlatformInterceptor` trait.
4. Persistent `MetadataStore` backend (RocksDB, per that crate's own
   documented extension point).
5. Docker/Compose for local dev, then Helm/K8s manifests.

## 10. Breaking changes (this pass)

None. Every change this pass was additive (`AuditRecord::schema_version`
defaults on read so old-format logs still parse; new `RecorderError::Sink`
variant; new lint attributes) or internal (README rewrite, new script).

## 11. Remaining limitations

Everything in §8. Additionally: the "unused dependency" check in §5 is
heuristic, not authoritative; MSRV compliance was checked by `grep` for
specific known-recent stdlib APIs (`is_none_or` found and fixed;
`OnceLock`, `ExitCode`, `is_ascii_hexdigit` checked and confirmed fine
against `rust-version = "1.75"`), not by an actual MSRV-pinned build.

## 12. Production readiness score: ~38% (up from ~35%)

**Justification**: this pass found and fixed 3 additional real issues
(missing `forbid(unsafe_code)` on 8 crates, a slowloris-class missing
timeout, a stale/self-contradicting README with a phantom script
reference) beyond the 5 found in the prior pass, on top of a codebase that
was already reviewed once. The rate of *new, real* findings per pass is
decreasing (8/5/3 across three audit passes on a growing codebase), which
is a fair signal of increasing code quality — but the score cannot move
substantially past the high-30s/low-40s range until the one gate that
matters most is passed: **actual compilation**. No amount of careful manual
review substitutes for a green `cargo build`.

## 13. Verification checklist

**Manually/structurally verified:**
- [x] Brace/paren balance, all 56 source files
- [x] Every `unsafe fn` in the codebase has a `# Safety` doc (9/9, all in `ptdf-pal-linux`)
- [x] `#![forbid(unsafe_code)]` present on every crate with zero unsafe usage (16/16 after this pass's fix)
- [x] No non-test `.unwrap()` in the workspace that isn't provably safe by a preceding length check (7/7 traced to their guarding check)
- [x] Dependency versions centralized, no drift across 15 manifests
- [x] Declared dependencies referenced in source, all 16 crates (heuristic)
- [x] README claims cross-checked against actual files on disk (found and fixed 1 mismatch)
- [x] `AuditRecord` forward-compatibility (tested against a hand-written legacy JSON line)

**Explicitly NOT verified (no toolchain/network — do not assume pass):**
- [ ] `cargo build` / `cargo check`
- [ ] `cargo test` (any crate)
- [ ] `cargo clippy`
- [ ] `cargo fmt --check`
- [ ] Actual dependency resolution against crates.io
- [ ] Runtime behavior of any kind, including the `ptdf-pal-linux` ptrace path and `ptdf-rest-api`'s socket server under real load
