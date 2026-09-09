//! Blocking `TcpListener` accept/serve loop. **This module cannot be unit
//! tested without actually binding a port and running the process** — it
//! is deliberately kept to the thinnest possible wrapper around
//! `http::parse` and `routes::handle_request` (both fully unit-tested
//! elsewhere) precisely so there is as little untested surface here as
//! possible. Validating this module means running `ptdf-api-server` and
//! making real HTTP requests against it (e.g. with `curl`) in a real
//! environment — that has not been done as part of generating this code
//! and should be the first thing checked before relying on it.
//!
//! Concurrency model: one OS thread per accepted connection. Adequate for
//! an internal operations API (this is not meant to be internet-facing —
//! see the crate-level TLS note); a production deployment fronting this
//! with a reverse proxy would also typically add connection limiting,
//! which is a proxy-layer concern, not this server's.

use crate::routes::{handle_request, AppState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("failed to bind to {addr}: {source}")]
    Bind {
        addr: String,
        source: std::io::Error,
    },
}

/// Read one HTTP request head (up to and including the blank-line
/// terminator, or up to a fixed cap) from `stream` into a `String` ready
/// for `http::parse`.
fn read_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
    const MAX_HEAD_BYTES: usize = 64 * 1024;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= MAX_HEAD_BYTES {
            break;
        }
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break; // connection closed
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn handle_connection(mut stream: TcpStream, state: &AppState) {
    // Bound how long a single connection may take to send its request
    // head. Without this, a slow or malicious client that trickles bytes
    // (or sends none at all) ties up one server thread indefinitely — a
    // classic slowloris-style resource exhaustion, and a real gap in the
    // original version of this function that had no timeout at all.
    const CONNECTION_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    if let Err(e) = stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT)) {
        ptdf_logging::warn!(error = %e, "failed to set read timeout on accepted connection; proceeding without it");
    }

    let raw = match read_request_head(&mut stream) {
        Ok(s) => s,
        Err(e) => {
            ptdf_logging::warn!(error = %e, "failed to read request from connection");
            return;
        }
    };

    let response = match crate::http::parse(&raw) {
        Ok(req) => handle_request(state, &req),
        Err(e) => crate::http::text_response(
            crate::http::StatusCode::BadRequest400,
            &format!("bad request: {e}"),
        ),
    };

    if let Err(e) = stream.write_all(&response) {
        ptdf_logging::warn!(error = %e, "failed to write response to connection");
    }
}

/// Bind `addr` and serve requests until the process is terminated. Blocks
/// the calling thread forever (or until a bind/accept error).
pub fn serve(addr: &str, state: Arc<AppState>) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).map_err(|source| ServerError::Bind {
        addr: addr.to_string(),
        source,
    })?;
    ptdf_logging::info!(addr, "PTDF REST API listening");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || handle_connection(stream, &state));
            }
            Err(e) => {
                ptdf_logging::warn!(error = %e, "failed to accept connection");
            }
        }
    }
    Ok(())
}
