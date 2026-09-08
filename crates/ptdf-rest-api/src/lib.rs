//! `ptdf-rest-api` — REST API (architecture §17 Query API). See `http.rs`
//! for the pure, unit-tested parsing/response layer, `routes.rs` for the
//! pure, unit-tested request handlers, and `server.rs` for the thin
//! (unavoidably-untested-without-a-live-process) socket wrapper.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod http;
pub mod routes;
pub mod server;

pub use routes::{handle_request, AppState};
pub use server::{serve, ServerError};
