#!/usr/bin/env bash
# Local pre-push verification, mirroring both jobs in
# .github/workflows/ci.yml (build/test/lint/doc, plus audit/deny if those
# tools are installed locally) so contributors can catch the same failures
# before pushing. Requires a real Rust toolchain (stable, with
# rustfmt+clippy components) and network access to crates.io — neither was
# available in the sandbox that generated this repository, so this script
# itself has never been executed; it is written to match the CI workflow
# file exactly, not verified by a successful run.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
cargo fmt --all -- --check

# ptdf-pal-linux is Linux/x86_64-only by design (see its raw.rs
# compile_error! guard) — excluded on any other host, matching ci.yml.
EXCLUDE_FLAGS=""
if [[ "$(uname -s)" != "Linux" ]]; then
  EXCLUDE_FLAGS="--exclude ptdf-pal-linux"
fi

echo "==> cargo build --workspace ${EXCLUDE_FLAGS} --all-targets"
# shellcheck disable=SC2086
cargo build --workspace ${EXCLUDE_FLAGS} --all-targets

echo "==> cargo test --workspace ${EXCLUDE_FLAGS}"
# shellcheck disable=SC2086
cargo test --workspace ${EXCLUDE_FLAGS}

echo "==> cargo clippy --workspace ${EXCLUDE_FLAGS} --all-targets -- -D warnings"
# shellcheck disable=SC2086
cargo clippy --workspace ${EXCLUDE_FLAGS} --all-targets -- -D warnings

echo "==> cargo doc --workspace ${EXCLUDE_FLAGS} --no-deps"
# shellcheck disable=SC2086
cargo doc --workspace ${EXCLUDE_FLAGS} --no-deps

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
else
  echo "==> SKIPPED cargo audit (cargo-audit not installed; run: cargo install cargo-audit)"
fi

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny check"
  cargo deny check
else
  echo "==> SKIPPED cargo deny (cargo-deny not installed; run: cargo install cargo-deny)"
fi

if [[ "$(uname -s)" == "Linux" ]]; then
  echo "==> cargo test -p ptdf-pal-linux -- --ignored   (requires ptrace permissions)"
  cargo test -p ptdf-pal-linux -- --ignored || {
    echo "NOTE: privileged ptrace tests failed or were skipped — this commonly"
    echo "means the environment lacks CAP_SYS_PTRACE or yama.ptrace_scope"
    echo "restricts it. This is an environment limitation, not necessarily a"
    echo "code defect; investigate before assuming either way."
  }
fi

echo "==> cargo doc --workspace ${EXCLUDE_FLAGS} --no-deps"
# shellcheck disable=SC2086
cargo doc --workspace ${EXCLUDE_FLAGS} --no-deps

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
else
  echo "==> cargo audit: SKIPPED (cargo-audit not installed — 'cargo install cargo-audit')"
fi

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny check (config: deny.toml)"
  cargo deny check
else
  echo "==> cargo deny: SKIPPED (cargo-deny not installed — 'cargo install cargo-deny')"
fi

echo "==> all checks passed"
