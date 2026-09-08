# PTDF Final Verification Record

## Environment (checked this session, not assumed)

```
$ which cargo rustc
(not found)
$ curl -sI https://crates.io
HTTP/2 403
x-deny-reason: host_not_allowed
```

**No Rust toolchain. No network access.** Every item below is either a
command that was **actually run** with its **actual output shown**, or is
explicitly marked **Not Verified** with the reason.

## Build results

**Not Verified.** `cargo build --workspace` was never run — `cargo` is not
installed in this environment. No claim is made about whether the
workspace compiles.

## Test results

**Not Verified.** `cargo test --workspace` and `cargo test --release` were
never run, for the same reason. No claim is made about whether any test
passes, including the ~110+ `#[test]` functions and 2 integration-test
files written across this repository.

## Lint results

**Not Verified.** `cargo clippy --workspace --all-targets --all-features
-- -D warnings` was never run.

## Formatting results

**Not Verified.** `cargo fmt --all --check` was never run. Code was
written by hand with consistent indentation/style conventions but has not
been machine-formatted or checked against `rustfmt`'s actual rules.

## Documentation results

**Not Verified.** `cargo doc --workspace --no-deps` was never run. Doc
comments were manually reviewed for content accuracy (see
`FINAL_PROJECT_REPORT.md` §6) but not checked for rustdoc syntax
correctness (e.g. valid intra-doc links, no broken code-fence
annotations).

## Security checks

**Not Verified by tool.** `cargo audit` and `cargo deny check` were never
run — neither is installed, and there is no network access to fetch the
RustSec advisory database or crates.io metadata either command needs.
`deny.toml` was authored with a real, specific license allowlist
(MIT/Apache-2.0/BSD-2/BSD-3/Unicode-3.0) matching what this workspace's
declared dependencies are known to use as of when each was added, and
`.github/workflows/ci.yml` has a dedicated `security-and-license-audit`
job wired to `rustsec/audit-check` and `EmbarkStudios/cargo-deny-action`
— both real, standard GitHub Actions — but neither has executed.

Manual security review (performed, with evidence) is recorded in
`FINAL_PROJECT_REPORT.md` §2; it is a substitute in *depth* for some of
what these tools check (e.g. hand-tracing every `.unwrap()` call) but not
a substitute for what only they can check (known-CVE advisory matching,
full license-compatibility graph resolution).

## What WAS actually performed and verified in this environment

These are structural/textual checks that do not require a Rust toolchain,
run via shell/file-read tools against the actual repository, with results
recorded at the time:

| Check | Method | Result |
|---|---|---|
| Brace/paren balance, all `.rs` files | Python script counting `{}()` per file | 56/56 balanced |
| Every `unsafe fn` has a `# Safety` doc | Regex scan of `ptdf-pal-linux/src/raw.rs` | 9/9 documented |
| `#![forbid(unsafe_code)]` on every crate with zero unsafe | grep count per crate vs. attribute presence | 15/15 correct (14 have the attribute; `ptdf-pal-linux` correctly does not, since it needs unsafe) |
| Non-test `.unwrap()` calls traced to a guarding check | Python script excluding `#[cfg(test)]` regions, manual trace of each hit | 7/7 traced to a preceding length/bounds check |
| Dependency versions centralized, no drift | Read of all 15 `Cargo.toml`s | Confirmed — all use `{ workspace = true }` |
| Declared deps referenced in source | Automated per-crate cross-reference script | 0 flagged unused (heuristic, not `cargo-udeps`-equivalent) |
| MSRV-sensitive stdlib API usage | grep for `is_none_or`, `OnceLock`, `ExitCode`, etc. against `rust-version = "1.75"` | 1 violation found and fixed (`is_none_or`, stabilized 1.82); `OnceLock`/`ExitCode`/others confirmed fine |
| `panic = "abort"` in shared release profile vs. `cargo test --release` | Manual reasoning from documented Cargo/rustc behavior (libtest needs unwind to isolate per-test panics) | Real risk identified and removed from `[profile.release]` |
| README claims vs. files on disk | Direct `ls`/`find` cross-check | 1 mismatch found and fixed (`scripts/ci-check.sh` was referenced but didn't exist) |
| CI YAML syntax | `yaml.safe_load()` via Python | Parses without error |
| `deny.toml` bracket balance | Python bracket count | Balanced |

## Explicitly unverifiable in this environment (do not assume pass)

- Whether the crate graph actually resolves against real crates.io package
  data (versions, feature flags, MSRV of transitive dependencies).
- Whether `aes-gcm 0.10`'s actual API surface matches what
  `ptdf-security/src/encryption.rs` calls (`Aes256Gcm::generate_key`,
  `Key<Aes256Gcm>::from_slice`, `AeadCore::generate_nonce`) — written from
  documented API knowledge, never compiled against the real crate.
- Borrow-checker acceptance of any file, most notably the closure-heavy
  control flow in `ptdf-recorder/src/session.rs::run`.
- Runtime behavior of the `ptrace`-based Linux interceptor against a real
  traced process.
- `ptdf-rest-api`'s socket server under concurrent load beyond the
  10-connection integration test *as written* (never executed).
- That `cargo fmt` would leave the code's formatting unchanged (i.e. that
  hand-formatting matches rustfmt's actual output byte-for-byte).

## Verification methodology limitations

The dependency-usage and MSRV checks above are `grep`/regex-based
heuristics, not equivalent to `cargo-udeps` or an actual MSRV-pinned
toolchain run. They are reported as what they are — supporting evidence
for a manual review, not a replacement for the tool-based checks this
document also lists as Not Verified.
