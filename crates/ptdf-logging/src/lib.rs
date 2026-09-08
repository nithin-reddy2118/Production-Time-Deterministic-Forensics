//! `ptdf-logging` — structured logging init (architecture §25).
//! Re-exports `tracing`'s macros so downstream crates only need to depend
//! on `ptdf-logging`, not on `tracing` directly, keeping the logging
//! backend swappable in one place.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod init;

pub use init::{init, LogFormat, LoggingConfig, LoggingError};
pub use tracing::{debug, error, info, instrument, trace, warn};
