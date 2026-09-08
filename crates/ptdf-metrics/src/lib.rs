//! `ptdf-metrics` — Counter/Gauge primitives, a `Registry`, Prometheus
//! text-exposition rendering, and the platform's standard metric names
//! (architecture §25).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod primitives;
pub mod registry;
pub mod standard;

pub use primitives::{Counter, Gauge};
pub use registry::{MetricsError, Registry};
pub use standard::StandardMetrics;
