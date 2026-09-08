//! Logging initialization (architecture §25).
//!
//! Two output formats are supported, chosen by `LogFormat`:
//!   - `Pretty`: human-readable, for local dev / interactive CLI use.
//!   - `Json`: structured, for production (agent/ingestion/replay running
//!     under a log collector — the "PTDF's own components are natural
//!     first users of PTDF for debugging PTDF itself" dogfooding note in
//!     §25 assumes machine-parseable logs in production).
//!
//! Filtering is env-driven (`RUST_LOG`, standard `tracing-subscriber`
//! convention) with a caller-supplied fallback so each binary (agent,
//! ingestion, replay, CLI) can pick a sane default level without
//! requiring the operator to set `RUST_LOG` explicitly.

use thiserror::Error;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("logging has already been initialized for this process")]
    AlreadyInitialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub format: LogFormat,
    /// Used only if `RUST_LOG` is not set in the environment.
    pub default_filter: String,
}

impl LoggingConfig {
    pub fn production_default() -> Self {
        Self { format: LogFormat::Json, default_filter: "info".to_string() }
    }

    pub fn dev_default() -> Self {
        Self { format: LogFormat::Pretty, default_filter: "debug".to_string() }
    }
}

/// Initialize the global `tracing` subscriber. Must be called exactly once
/// per process, as early as possible (before any other PTDF crate emits a
/// log event), typically as the first line of `main`.
pub fn init(config: LoggingConfig) -> Result<(), LoggingError> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.default_filter.clone()));

    let result = match config.format {
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(true)
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(true)
            .json()
            .try_init(),
    };

    result.map_err(|_| LoggingError::AlreadyInitialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `tracing`'s global subscriber can only be set once per process, and
    // `cargo test` runs tests in the same process, so we can only exercise
    // one successful `init` across the whole test binary. We test the
    // "already initialized" error path explicitly by calling `init` twice
    // in the same test, and keep it as the *only* test that calls `init`
    // to avoid poisoning other tests in this crate with ordering
    // dependencies on a shared global.
    #[test]
    fn second_init_in_same_process_reports_already_initialized() {
        let first = init(LoggingConfig::dev_default());
        // First call may already have failed if the test harness or an
        // earlier test in this binary initialized a subscriber; either way
        // exactly one further call must fail.
        let second = init(LoggingConfig::production_default());
        assert!(first.is_ok() || second.is_err());
        if first.is_ok() {
            assert!(matches!(second, Err(LoggingError::AlreadyInitialized)));
        }
    }

    #[test]
    fn production_default_uses_json_and_info_level() {
        let cfg = LoggingConfig::production_default();
        assert_eq!(cfg.format, LogFormat::Json);
        assert_eq!(cfg.default_filter, "info");
    }

    #[test]
    fn dev_default_uses_pretty_and_debug_level() {
        let cfg = LoggingConfig::dev_default();
        assert_eq!(cfg.format, LogFormat::Pretty);
        assert_eq!(cfg.default_filter, "debug");
    }
}
