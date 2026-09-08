//! Minimal HTTP/1.1 request parsing and response building. Deliberately
//! scoped to exactly what this API needs: `GET` requests with a path,
//! query string, and headers (used for the `Authorization` header) — no
//! request bodies, no chunked transfer encoding, no keep-alive pipelining.
//! Every function here is a pure transformation over bytes/strings with no
//! socket I/O, which is what makes it fully unit-testable without binding
//! a port (see `server.rs` for the thin, unavoidably-untestable-without-a-
//! running-process I/O wrapper around this).

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("empty request")]
    Empty,

    #[error("malformed request line: {0:?}")]
    MalformedRequestLine(String),

    #[error("unsupported HTTP method: {0}")]
    UnsupportedMethod(String),

    #[error("malformed header line: {0:?}")]
    MalformedHeader(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// Path only, query string split off into `query`.
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        // Header names are case-insensitive per RFC 7230; we normalize to
        // lowercase at parse time (see `parse`), so callers just pass the
        // lowercase form.
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }
}

fn parse_query_string(qs: &str) -> HashMap<String, String> {
    qs.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Parse a raw HTTP/1.1 request from its head (request line + headers;
/// the blank-line terminator and any body are not required to be present
/// in `raw` for this function — it stops at the first blank line or the
/// end of input, whichever comes first, since none of this API's routes
/// need a request body).
pub fn parse(raw: &str) -> Result<Request, HttpParseError> {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().filter(|l| !l.is_empty()).ok_or(HttpParseError::Empty)?;

    let mut parts = request_line.split(' ');
    let method_str = parts.next().ok_or_else(|| HttpParseError::MalformedRequestLine(request_line.to_string()))?;
    let target = parts.next().ok_or_else(|| HttpParseError::MalformedRequestLine(request_line.to_string()))?;
    let _version = parts.next().ok_or_else(|| HttpParseError::MalformedRequestLine(request_line.to_string()))?;

    let method = match method_str {
        "GET" => Method::Get,
        "POST" => Method::Post,
        other => return Err(HttpParseError::UnsupportedMethod(other.to_string())),
    };

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query_string(q)),
        None => (target.to_string(), HashMap::new()),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        let (name, value) = line.split_once(':').ok_or_else(|| HttpParseError::MalformedHeader(line.to_string()))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok(Request { method, path, query, headers })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Ok200,
    BadRequest400,
    Unauthorized401,
    Forbidden403,
    NotFound404,
    InternalServerError500,
}

impl StatusCode {
    pub fn code_and_reason(self) -> (u16, &'static str) {
        match self {
            StatusCode::Ok200 => (200, "OK"),
            StatusCode::BadRequest400 => (400, "Bad Request"),
            StatusCode::Unauthorized401 => (401, "Unauthorized"),
            StatusCode::Forbidden403 => (403, "Forbidden"),
            StatusCode::NotFound404 => (404, "Not Found"),
            StatusCode::InternalServerError500 => (500, "Internal Server Error"),
        }
    }
}

/// Build a complete HTTP/1.1 response (status line + headers + body) as
/// raw bytes ready to write to a socket.
pub fn build_response(status: StatusCode, content_type: &str, body: &[u8]) -> Vec<u8> {
    let (code, reason) = status.code_and_reason();
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn json_response(status: StatusCode, body: &[u8]) -> Vec<u8> {
    build_response(status, "application/json", body)
}

pub fn text_response(status: StatusCode, body: &str) -> Vec<u8> {
    build_response(status, "text/plain; charset=utf-8", body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_get_request() {
        let raw = "GET /sessions HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req = parse(raw).unwrap();
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.path, "/sessions");
        assert!(req.query.is_empty());
        assert_eq!(req.header("host"), Some("localhost"));
    }

    #[test]
    fn parses_query_string_parameters() {
        let raw = "GET /sessions?kind=Syscall&limit=10 HTTP/1.1\r\n\r\n";
        let req = parse(raw).unwrap();
        assert_eq!(req.path, "/sessions");
        assert_eq!(req.query.get("kind"), Some(&"Syscall".to_string()));
        assert_eq!(req.query.get("limit"), Some(&"10".to_string()));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let raw = "GET / HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n";
        let req = parse(raw).unwrap();
        assert_eq!(req.header("authorization"), Some("Bearer abc123"));
        assert_eq!(req.header("AUTHORIZATION"), Some("Bearer abc123"));
    }

    #[test]
    fn empty_request_is_rejected() {
        assert_eq!(parse(""), Err(HttpParseError::Empty));
    }

    #[test]
    fn malformed_request_line_is_rejected() {
        assert!(matches!(parse("GET\r\n\r\n"), Err(HttpParseError::MalformedRequestLine(_))));
    }

    #[test]
    fn unsupported_method_is_rejected() {
        assert_eq!(parse("DELETE / HTTP/1.1\r\n\r\n"), Err(HttpParseError::UnsupportedMethod("DELETE".to_string())));
    }

    #[test]
    fn malformed_header_line_is_rejected() {
        assert!(matches!(parse("GET / HTTP/1.1\r\nnotaheader\r\n\r\n"), Err(HttpParseError::MalformedHeader(_))));
    }

    #[test]
    fn build_response_produces_well_formed_http() {
        let bytes = text_response(StatusCode::Ok200, "hello");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn json_response_sets_json_content_type() {
        let bytes = json_response(StatusCode::Ok200, b"{}");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Content-Type: application/json\r\n"));
    }

    #[test]
    fn error_statuses_produce_correct_code_and_reason() {
        assert_eq!(StatusCode::Unauthorized401.code_and_reason(), (401, "Unauthorized"));
        assert_eq!(StatusCode::NotFound404.code_and_reason(), (404, "Not Found"));
    }
}
