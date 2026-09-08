//! `ptdf-recorder` — the Event Recorder (architecture §5/§8): the
//! top-level orchestrator tying `PlatformInterceptor` -> `RecorderSink` ->
//! `SegmentWriter` -> `MetadataStore` -> metrics into one run loop.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod session;

pub use session::{RecorderError, RecordingSession, RecordingSessionConfig, RecordingSummary, StopHandle};
