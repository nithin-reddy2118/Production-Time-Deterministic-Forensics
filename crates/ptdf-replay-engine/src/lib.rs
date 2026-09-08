//! `ptdf-replay-engine` — Replay Engine core (architecture §6).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod checkpoint;
pub mod divergence;
pub mod engine;
pub mod scheduler;

pub use checkpoint::{CheckpointError, ReplayCheckpoint};
pub use divergence::{check as check_divergence, ObservedOperation};
pub use engine::{ReplayEngine, ReplayEngineError, ReplayOutcome, ReplayRunOptions};
pub use scheduler::{linearize, linearized_ids, DeterministicScheduler};
