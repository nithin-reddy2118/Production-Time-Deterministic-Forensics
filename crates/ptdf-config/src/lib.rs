//! `ptdf-config` — layered configuration (architecture §24).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod schema;

pub use schema::{ConfigError, PartialRecorderConfig, RecorderConfig};
