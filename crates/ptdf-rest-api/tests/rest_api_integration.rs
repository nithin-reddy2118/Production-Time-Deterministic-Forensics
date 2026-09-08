//! Integration test for `ptdf-rest-api`: actually binds a TCP port and
//! drives the server with real `TcpStream` connections, exercising
//! `server.rs`'s accept/read/write loop end to end — the one part of this
//! crate `routes.rs`'s unit tests deliberately can't reach (see
//! `server.rs`'s module docs on why it's kept minimal specifically because
//! it can only be validated this way, by actually running it).

use ptdf_metadata::InMemoryMetadataStore;
use ptdf_metrics::Registry;
use ptdf_rest_api::{serve, AppState};
use ptdf_security::{ApiKeyAuthenticator, AuditLogger, Principal, Role};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

fn start_test_server() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");

    let mut authenticator = ApiKeyAuthenticator::new();
    authenticator.register_key("test-key", Principal { id: "tester".into(), role: Role::Viewer }).unwrap();

    let state = Arc::new(AppState {
        metadata: Arc::new(InMemoryMetadataStore::new()),
        metrics_registry: Arc::new(Registry::new()),
        authenticator: Arc::new(authenticator),
        audit: Arc::new(AuditLogger::open(&audit_path).unwrap()),
    });

    // Bind to port 0 to let the OS pick a free port, then discover which
    // one it chose — avoids test flakiness/collisions from a hardcoded
    // port across parallel test runs.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // release it so `serve` can bind the same address

    let addr_string = addr.to_string();
    let serve_addr = addr_string.clone();
    std::thread::spawn(move || {
        let _ = serve(&serve_addr, state);
    });

    // Give the server a moment to bind before the test issues requests.
    // A fixed sleep is not ideal, but `serve` blocks forever with no
    // ready-signal channel in v1 — acceptable for a test with generous
    // margin; a flaky failure here would point at a real startup
    // regression worth investigating, not just test timing noise.
    std::thread::sleep(Duration::from_millis(100));

    (addr_string, dir)
}

fn raw_http_request(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.shutdown(std::net::Shutdown::Write).ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn health_endpoint_responds_over_a_real_socket() {
    let (addr, _dir) = start_test_server();
    let response = raw_http_request(&addr, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("ok"));
}

#[test]
fn metrics_endpoint_requires_authentication_over_a_real_socket() {
    let (addr, _dir) = start_test_server();
    let response = raw_http_request(&addr, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with("HTTP/1.1 401"));
}

#[test]
fn metrics_endpoint_succeeds_with_a_valid_key_over_a_real_socket() {
    let (addr, _dir) = start_test_server();
    let response = raw_http_request(&addr, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-key\r\n\r\n");
    assert!(response.starts_with("HTTP/1.1 200"));
}

#[test]
fn unknown_route_returns_404_over_a_real_socket() {
    let (addr, _dir) = start_test_server();
    let response = raw_http_request(&addr, "GET /does-not-exist HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with("HTTP/1.1 404"));
}

#[test]
fn multiple_concurrent_connections_are_each_served_correctly() {
    let (addr, _dir) = start_test_server();
    let mut handles = Vec::new();
    for _ in 0..10 {
        let addr = addr.clone();
        handles.push(std::thread::spawn(move || {
            raw_http_request(&addr, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        }));
    }
    for handle in handles {
        let response = handle.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
    }
}
