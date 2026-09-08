//! `ptdf-types` — core domain types shared across every PTDF crate.
//!
//! This crate deliberately contains **no I/O and no platform-specific
//! code**. It is the dependency every other crate (recorder, PAL, storage,
//! replay) depends on, so it must stay small, dependency-light, and stable.
//! If you're tempted to add `tokio`, `serde`, or a platform crate here —
//! don't; put it in the crate that actually needs it.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod error;
pub mod event;
pub mod ids;
pub mod vclock;

pub use error::PtdfTypesError;
pub use event::{ContentHash, Event, EventKind, EventResult, Payload};
pub use ids::{EventId, HostId, SessionId};
pub use vclock::{HlcGenerator, HlcTimestamp, PhysicalClock, SystemPhysicalClock};
