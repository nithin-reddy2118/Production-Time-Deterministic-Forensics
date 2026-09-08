//! Shared error type for domain-level validation failures.
//!
//! Platform errors (errno, NTSTATUS) are represented as *data* inside
//! `EventResult` (see `event.rs`), not as Rust `Error`s — a syscall
//! returning `EAGAIN` is a normal, expected recorded outcome, not a failure
//! of PTDF itself. `PtdfTypesError` is only for misuse of this crate's API.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PtdfTypesError {
    #[error("invalid HLC ordering: attempted to construct a timestamp that would violate monotonicity")]
    InvalidHlcOrdering,

    #[error("empty content hash is not permitted")]
    EmptyContentHash,
}
