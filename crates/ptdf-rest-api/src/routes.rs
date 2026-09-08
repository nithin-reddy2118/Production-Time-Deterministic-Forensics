//! Route handlers. `handle_request` is the single entry point — a pure
//! function from `(&AppState, &Request)` to response bytes, with no
//! socket I/O, so it's fully unit-testable by constructing a `Request`
//! directly (via `http::parse` on a literal string) rather than needing a
//! live connection.

use crate::http::{self, json_response, text_response, Method, Request, StatusCode};
use ptdf_metadata::MetadataStore;
use ptdf_metrics::Registry;
use ptdf_replay_engine::ReplayEngine;
use ptdf_security::{authorize, ApiKeyAuthenticator, AuditLogger, AuditOutcome, Permission, Principal};
use ptdf_types::SessionId;
use serde::Serialize;
use std::sync::Arc;

pub struct AppState {
    pub metadata: Arc<dyn MetadataStore>,
    pub metrics_registry: Arc<Registry>,
    pub authenticator: Arc<ApiKeyAuthenticator>,
    pub audit: Arc<AuditLogger>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

fn bearer_token(req: &Request) -> &str {
    req.header("authorization").and_then(|h| h.strip_prefix("Bearer ")).unwrap_or("")
}

/// Authenticate the request and authorize it for `permission`, auditing
/// both the allow and deny paths. Returns the authenticated `Principal` on
/// success, or the response to send back on failure.
fn authenticate_and_authorize(state: &AppState, req: &Request, path: &str, permission: Permission) -> Result<Principal, Vec<u8>> {
    let token = bearer_token(req);
    let principal = match state.authenticator.authenticate(token) {
        Ok(p) => p.clone(),
        Err(_) => {
            return Err(text_response(StatusCode::Unauthorized401, "unauthorized: missing or invalid API key"));
        }
    };

    match authorize(principal.role, permission) {
        Ok(()) => {
            let _ = state.audit.record(&principal.id, principal.role, permission, "http_request", path, AuditOutcome::Allowed);
            Ok(principal)
        }
        Err(_) => {
            let _ = state.audit.record(&principal.id, principal.role, permission, "http_request", path, AuditOutcome::Denied);
            Err(text_response(StatusCode::Forbidden403, "forbidden: insufficient role for this operation"))
        }
    }
}

#[derive(Debug, Serialize)]
struct SegmentDto {
    host_id: String,
    path: String,
    event_count: u64,
    size_bytes: u64,
    min_physical_ns: u64,
    max_physical_ns: u64,
}

#[derive(Debug, Serialize)]
struct EventDto {
    host_id: String,
    pid: u32,
    tid: u32,
    seq: u64,
    kind: String,
    physical_ns: u64,
    logical: u32,
    result: String,
}

fn parse_session_id(raw: &str) -> Option<SessionId> {
    raw.parse::<u128>().ok().map(SessionId::from_raw)
}

/// Handle one parsed request end to end, returning the raw bytes to write
/// back to the client.
pub fn handle_request(state: &AppState, req: &Request) -> Vec<u8> {
    if req.method != Method::Get {
        return text_response(StatusCode::BadRequest400, "only GET is supported by this API");
    }

    let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();

    match segments.as_slice() {
        [""] | [] => text_response(StatusCode::Ok200, "PTDF REST API"),

        ["health"] => text_response(StatusCode::Ok200, "ok"),

        ["metrics"] => match authenticate_and_authorize(state, req, &req.path, Permission::ViewMetrics) {
            Ok(_principal) => http::build_response(StatusCode::Ok200, "text/plain; version=0.0.4", state.metrics_registry.render().as_bytes()),
            Err(resp) => resp,
        },

        ["sessions", session_id_raw, "segments"] => {
            match authenticate_and_authorize(state, req, &req.path, Permission::QuerySessions) {
                Ok(_principal) => {
                    let Some(session_id) = parse_session_id(session_id_raw) else {
                        return text_response(StatusCode::BadRequest400, "invalid session id: must be a u128");
                    };
                    match state.metadata.segments_for_session(session_id) {
                        Ok(records) => {
                            let dtos: Vec<SegmentDto> = records
                                .into_iter()
                                .map(|r| SegmentDto {
                                    host_id: r.host_id.to_string(),
                                    path: r.path.display().to_string(),
                                    event_count: r.event_count,
                                    size_bytes: r.size_bytes,
                                    min_physical_ns: r.min_physical_ns,
                                    max_physical_ns: r.max_physical_ns,
                                })
                                .collect();
                            match serde_json::to_vec(&dtos) {
                                Ok(body) => json_response(StatusCode::Ok200, &body),
                                Err(_) => text_response(StatusCode::InternalServerError500, "failed to serialize response"),
                            }
                        }
                        Err(_) => text_response(StatusCode::NotFound404, "unknown session"),
                    }
                }
                Err(resp) => resp,
            }
        }

        ["sessions", session_id_raw, "hosts"] => {
            match authenticate_and_authorize(state, req, &req.path, Permission::QuerySessions) {
                Ok(_principal) => {
                    let Some(session_id) = parse_session_id(session_id_raw) else {
                        return text_response(StatusCode::BadRequest400, "invalid session id: must be a u128");
                    };
                    match state.metadata.hosts_for_session(session_id) {
                        Ok(hosts) => {
                            let host_strings: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
                            match serde_json::to_vec(&host_strings) {
                                Ok(body) => json_response(StatusCode::Ok200, &body),
                                Err(_) => text_response(StatusCode::InternalServerError500, "failed to serialize response"),
                            }
                        }
                        Err(_) => text_response(StatusCode::NotFound404, "unknown session"),
                    }
                }
                Err(resp) => resp,
            }
        }

        ["sessions", session_id_raw, "events"] => {
            match authenticate_and_authorize(state, req, &req.path, Permission::QuerySessions) {
                Ok(_principal) => {
                    let Some(session_id) = parse_session_id(session_id_raw) else {
                        return text_response(StatusCode::BadRequest400, "invalid session id: must be a u128");
                    };
                    // Real use of the Replay Engine's linearization for a
                    // read-only query, not just replay driving — §17
                    // explicitly calls out event queries as a Query API
                    // capability distinct from full replay.
                    match ReplayEngine::load_linearized_events(state.metadata.as_ref(), session_id) {
                        Ok(events) => {
                            let kind_filter = req.query.get("kind").map(|s| s.as_str());
                            let limit: usize = req.query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);

                            let dtos: Vec<EventDto> = events
                                .iter()
                                .map(|e| EventDto {
                                    host_id: e.id().host_id().to_string(),
                                    pid: e.id().pid(),
                                    tid: e.id().tid(),
                                    seq: e.id().seq(),
                                    kind: format!("{:?}", e.kind()),
                                    physical_ns: e.hlc().physical_ns(),
                                    logical: e.hlc().logical(),
                                    result: format!("{:?}", e.result()),
                                })
                                .filter(|dto| kind_filter.map_or(true, |k| dto.kind == k))
                                .take(limit)
                                .collect();

                            match serde_json::to_vec(&dtos) {
                                Ok(body) => json_response(StatusCode::Ok200, &body),
                                Err(_) => text_response(StatusCode::InternalServerError500, "failed to serialize response"),
                            }
                        }
                        Err(_) => text_response(StatusCode::NotFound404, "unknown session or no segments registered"),
                    }
                }
                Err(resp) => resp,
            }
        }

        _ => text_response(StatusCode::NotFound404, "not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_metadata::{InMemoryMetadataStore, SegmentRecord};
    use ptdf_security::Role;
    use ptdf_types::HostId;
    use std::path::PathBuf;

    fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.log");
        // Leak the tempdir so the audit log file stays alive for the
        // duration of the test — acceptable in a test-only helper.
        std::mem::forget(dir);

        let mut authenticator = ApiKeyAuthenticator::new();
        authenticator.register_key("viewer-key", Principal { id: "viewer".into(), role: Role::Viewer }).unwrap();
        authenticator.register_key("operator-key", Principal { id: "operator".into(), role: Role::Operator }).unwrap();

        AppState {
            metadata: Arc::new(InMemoryMetadataStore::new()),
            metrics_registry: Arc::new(Registry::new()),
            authenticator: Arc::new(authenticator),
            audit: Arc::new(AuditLogger::open(&audit_path).unwrap()),
        }
    }

    fn get(path: &str, bearer: Option<&str>) -> Request {
        let auth_header = bearer.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
        let raw = format!("GET {path} HTTP/1.1\r\n{auth_header}\r\n");
        http::parse(&raw).unwrap()
    }

    #[test]
    fn health_check_requires_no_auth() {
        let state = test_state();
        let resp = handle_request(&state, &get("/health", None));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.ends_with("ok"));
    }

    #[test]
    fn metrics_without_auth_is_unauthorized() {
        let state = test_state();
        let resp = handle_request(&state, &get("/metrics", None));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn metrics_with_valid_viewer_key_succeeds() {
        let state = test_state();
        state.metrics_registry.counter("ptdf_test_total", "test").unwrap().inc();
        let resp = handle_request(&state, &get("/metrics", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("ptdf_test_total 1"));
    }

    #[test]
    fn unknown_key_is_unauthorized() {
        let state = test_state();
        let resp = handle_request(&state, &get("/metrics", Some("not-a-real-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn segments_for_unknown_session_is_not_found() {
        let state = test_state();
        let resp = handle_request(&state, &get("/sessions/999/segments", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn segments_for_known_session_returns_json() {
        let state = test_state();
        state
            .metadata
            .register_segment(SegmentRecord {
                session_id: SessionId::from_raw(1),
                host_id: HostId::from_raw(1),
                path: PathBuf::from("/data/seg.ptds"),
                event_count: 5,
                size_bytes: 1024,
                min_physical_ns: 0,
                max_physical_ns: 100,
            })
            .unwrap();

        let resp = handle_request(&state, &get("/sessions/1/segments", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("\"event_count\":5"));
    }

    #[test]
    fn invalid_session_id_is_bad_request() {
        let state = test_state();
        let resp = handle_request(&state, &get("/sessions/not-a-number/segments", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn unknown_route_is_not_found() {
        let state = test_state();
        let resp = handle_request(&state, &get("/nope", None));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn non_get_method_is_rejected() {
        let state = test_state();
        let req = http::parse("POST /sessions HTTP/1.1\r\n\r\n").unwrap();
        let resp = handle_request(&state, &req);
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn viewer_role_can_query_sessions_but_the_authorization_path_is_exercised() {
        // Viewer has QuerySessions permission (see ptdf_security::authz),
        // so this should succeed — this test documents that the route's
        // permission requirement matches the intended RBAC policy.
        let state = test_state();
        let resp = handle_request(&state, &get("/sessions/1/hosts", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        // 404 because the session doesn't exist, but critically NOT 401/403 —
        // proving the viewer key passed authentication+authorization.
        assert!(text.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn events_route_returns_linearized_events_for_a_real_session() {
        use ptdf_storage::SegmentWriter;
        use ptdf_types::{Event, EventId, EventKind, EventResult, HlcTimestamp, Payload};

        let state = test_state();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.ptds");
        let host = HostId::from_raw(1);
        let session = SessionId::from_raw(7);

        let mut writer = SegmentWriter::create(&path).unwrap();
        for seq in 0..3u64 {
            let id = EventId::new(host, 1, 1, seq);
            let ev = Event::new(id, session, EventKind::Syscall, HlcTimestamp::new(seq, 0), Payload::None, EventResult::Ok(0));
            writer.append(&ev).unwrap();
        }
        let info = writer.seal().unwrap();

        state
            .metadata
            .register_segment(SegmentRecord {
                session_id: session,
                host_id: host,
                path: info.path,
                event_count: info.event_count,
                size_bytes: info.size_bytes,
                min_physical_ns: 0,
                max_physical_ns: 2,
            })
            .unwrap();

        let resp = handle_request(&state, &get("/sessions/7/events", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("\"seq\":0"));
        assert!(text.contains("\"seq\":1"));
        assert!(text.contains("\"seq\":2"));
    }

    #[test]
    fn events_route_respects_limit_query_parameter() {
        use ptdf_storage::SegmentWriter;
        use ptdf_types::{Event, EventId, EventKind, EventResult, HlcTimestamp, Payload};

        let state = test_state();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.ptds");
        let host = HostId::from_raw(1);
        let session = SessionId::from_raw(8);

        let mut writer = SegmentWriter::create(&path).unwrap();
        for seq in 0..5u64 {
            let id = EventId::new(host, 1, 1, seq);
            let ev = Event::new(id, session, EventKind::Syscall, HlcTimestamp::new(seq, 0), Payload::None, EventResult::Ok(0));
            writer.append(&ev).unwrap();
        }
        let info = writer.seal().unwrap();
        state
            .metadata
            .register_segment(SegmentRecord {
                session_id: session,
                host_id: host,
                path: info.path,
                event_count: info.event_count,
                size_bytes: info.size_bytes,
                min_physical_ns: 0,
                max_physical_ns: 4,
            })
            .unwrap();

        let resp = handle_request(&state, &get("/sessions/8/events?limit=2", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        let body_start = text.find("\r\n\r\n").unwrap() + 4;
        let parsed: serde_json::Value = serde_json::from_str(&text[body_start..]).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn events_route_for_unknown_session_is_not_found() {
        let state = test_state();
        let resp = handle_request(&state, &get("/sessions/12345/events", Some("viewer-key")));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn events_route_without_auth_is_unauthorized() {
        let state = test_state();
        let resp = handle_request(&state, &get("/sessions/1/events", None));
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 401"));
    }
}
