use ptdf_metadata::InMemoryMetadataStore;
use ptdf_metrics::Registry;
use ptdf_rest_api::{serve, AppState};
use ptdf_security::{generate_random_api_key, ApiKeyAuthenticator, AuditLogger, Principal, Role};
use std::sync::Arc;

fn main() {
    let _ = ptdf_logging::init(ptdf_logging::LoggingConfig::production_default());

    let bind_addr = std::env::var("PTDF_API_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let audit_log_path = std::env::var("PTDF_AUDIT_LOG_PATH").unwrap_or_else(|_| "./ptdf-audit.log".to_string());

    let audit = match AuditLogger::open(&audit_log_path) {
        Ok(logger) => logger,
        Err(e) => {
            eprintln!("failed to open audit log at {audit_log_path}: {e}");
            std::process::exit(1);
        }
    };

    let mut authenticator = ApiKeyAuthenticator::new();

    // Bootstrap: generate one admin key on every startup and print it once
    // to stdout. This process holds no other credential store yet (no
    // persistent principal database — see crate README status), so this
    // is the intended way to obtain the first key to manage the rest
    // through; a production deployment would instead load principals from
    // a persistent, KMS-backed store, which is a defined but not-yet-built
    // extension point (`ApiKeyAuthenticator::register_key` is already the
    // seam such a loader would call into).
    let bootstrap_key = generate_random_api_key();
    if let Err(e) = authenticator.register_key(&bootstrap_key, Principal { id: "bootstrap-admin".to_string(), role: Role::Admin }) {
        eprintln!("failed to register bootstrap admin key: {e}");
        std::process::exit(1);
    }
    println!("Bootstrap admin API key (shown once): {bootstrap_key}");

    // In-memory only for this v1 wiring — a real deployment would back
    // this AppState with the same MetadataStore instance the ingestion
    // pipeline writes to (e.g. a shared RocksDB-backed store per
    // ptdf-metadata's crate docs), not a fresh empty one per API process.
    let state = Arc::new(AppState {
        metadata: Arc::new(InMemoryMetadataStore::new()),
        metrics_registry: Arc::new(Registry::new()),
        authenticator: Arc::new(authenticator),
        audit: Arc::new(audit),
    });

    if let Err(e) = serve(&bind_addr, state) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
