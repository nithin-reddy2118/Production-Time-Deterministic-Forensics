//! `ptdfctl` library — see `commands.rs` for the actual command logic.
//! `main.rs` is a thin CLI-parsing shell over this crate.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod commands;

pub use commands::{dump_segment, inspect_segment, verify_segment, CliError, SegmentSummary};
