//! `ptdf-distributed` — Distributed Synchronization Engine (architecture
//! §15): HLC piggyback wire format + cross-host causal merge. See
//! `tests/multi_node_replay.rs` for the end-to-end proof that this,
//! combined with `ptdf-replay-engine::scheduler`'s host_id-aware
//! ordering, produces correct multi-node replay ordering.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod piggyback;
pub mod sync;

pub use piggyback::{decode, encode, PiggybackError, PIGGYBACK_LEN};
pub use sync::simulate_send_receive;
