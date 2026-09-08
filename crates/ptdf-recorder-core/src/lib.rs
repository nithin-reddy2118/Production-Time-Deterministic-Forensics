//! `ptdf-recorder-core` — OS-agnostic recording core (architecture §8).
//!
//! Owns: per-thread sequence allocation (`seq`), the local buffering/
//! backpressure stage (`sink`). Depends on `ptdf-pal` only through its
//! traits (`PlatformInterceptor`) — never on any platform adapter crate,
//! which is what keeps this crate compilable and testable on any host
//! regardless of target OS.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod seq;
pub mod sink;

pub use seq::SeqAllocator;
pub use sink::{BoundedSink, RecorderSink, SinkError};
