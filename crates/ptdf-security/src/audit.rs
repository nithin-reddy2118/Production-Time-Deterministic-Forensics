//! Audit Logging (architecture §18/security). A structured, append-only,
//! JSON-lines audit trail: every authorization decision and every
//! sensitive action (starting a recording, starting a replay, managing
//! principals) gets one immutable record. Append-only + fsync-per-record
//! for the same reason `ptdf-storage::SegmentWriter` does it (see that
//! crate's docs): an audit log that can lose its tail on a crash, or that
//! can be edited after the fact, isn't an audit log.

use crate::authz::{Permission, Role};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to open audit log at {path}: {source}")]
    Open {
        path: String,
        source: std::io::Error,
    },

    #[error("audit I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to serialize/deserialize audit record: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Allowed,
    Denied,
}

/// Schema version for `AuditRecord`'s on-disk JSON representation.
/// Bump this and handle old values explicitly (rather than just adding a
/// field) whenever a change would alter the *meaning* of an existing
/// field, not just add a new one.
pub const AUDIT_SCHEMA_VERSION: u8 = 1;

fn default_schema_version() -> u8 {
    // Log lines written before this field existed have no
    // `schema_version` key at all; `serde(default)` fills it in as `1` on
    // read, which is correct because version 1 *is* the pre-versioning
    // format — there is no version 0 to distinguish it from.
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
    pub timestamp_ns: u64,
    pub principal_id: String,
    pub role: Role,
    pub permission: Permission,
    pub action: String,
    pub resource: String,
    pub outcome: AuditOutcome,
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos() as u64
}

pub struct AuditLogger {
    file: Mutex<File>,
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger").finish_non_exhaustive()
    }
}

impl AuditLogger {
    /// Open (creating if necessary) an append-only audit log at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path_ref = path.as_ref();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path_ref)
            .map_err(|source| AuditError::Open {
                path: path_ref.display().to_string(),
                source,
            })?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Record one audit event: fsync'd before this call returns, so a
    /// caller that gets `Ok(())` back has a durability guarantee matching
    /// what an audit trail needs to be trustworthy.
    pub fn record(
        &self,
        principal_id: &str,
        role: Role,
        permission: Permission,
        action: &str,
        resource: &str,
        outcome: AuditOutcome,
    ) -> Result<(), AuditError> {
        let record = AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            timestamp_ns: now_ns(),
            principal_id: principal_id.to_string(),
            role,
            permission,
            action: action.to_string(),
            resource: resource.to_string(),
            outcome,
        };

        let mut line = serde_json::to_string(&record)?;
        line.push('\n');

        let mut file = self.file.lock().expect("AuditLogger mutex poisoned");
        file.write_all(line.as_bytes())?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    /// Read back every record currently in the log — used by tests and by
    /// any future audit-query tooling. Malformed lines are reported as an
    /// error rather than silently skipped, matching this workspace's
    /// general policy that a forensic/audit trail never silently drops
    /// something it can't parse.
    pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, AuditError> {
        let contents = std::fs::read_to_string(path)?;
        contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(AuditError::from))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_events_round_trip_through_the_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = AuditLogger::open(&path).unwrap();

        logger
            .record(
                "svc-a",
                Role::Operator,
                Permission::StartReplay,
                "replay_session",
                "session:123",
                AuditOutcome::Allowed,
            )
            .unwrap();
        logger
            .record(
                "svc-b",
                Role::Viewer,
                Permission::StartReplay,
                "replay_session",
                "session:456",
                AuditOutcome::Denied,
            )
            .unwrap();

        let records = AuditLogger::read_all(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].principal_id, "svc-a");
        assert_eq!(records[0].outcome, AuditOutcome::Allowed);
        assert_eq!(records[1].principal_id, "svc-b");
        assert_eq!(records[1].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn log_is_append_only_across_multiple_logger_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");

        {
            let logger = AuditLogger::open(&path).unwrap();
            logger
                .record(
                    "a",
                    Role::Admin,
                    Permission::ManagePrincipals,
                    "create_principal",
                    "principal:x",
                    AuditOutcome::Allowed,
                )
                .unwrap();
        }
        {
            let logger = AuditLogger::open(&path).unwrap();
            logger
                .record(
                    "a",
                    Role::Admin,
                    Permission::ManagePrincipals,
                    "delete_principal",
                    "principal:x",
                    AuditOutcome::Allowed,
                )
                .unwrap();
        }

        let records = AuditLogger::read_all(&path).unwrap();
        assert_eq!(
            records.len(),
            2,
            "reopening the log must append, never truncate"
        );
        assert_eq!(records[0].action, "create_principal");
        assert_eq!(records[1].action, "delete_principal");
    }

    #[test]
    fn each_record_has_a_nonzero_increasing_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = AuditLogger::open(&path).unwrap();
        logger
            .record(
                "a",
                Role::Viewer,
                Permission::ViewMetrics,
                "view",
                "metrics",
                AuditOutcome::Allowed,
            )
            .unwrap();
        logger
            .record(
                "a",
                Role::Viewer,
                Permission::ViewMetrics,
                "view",
                "metrics",
                AuditOutcome::Allowed,
            )
            .unwrap();

        let records = AuditLogger::read_all(&path).unwrap();
        assert!(records[0].timestamp_ns > 0);
        assert!(records[1].timestamp_ns >= records[0].timestamp_ns);
    }

    #[test]
    fn permission_and_role_serialize_as_stable_strings() {
        let json = serde_json::to_string(&Permission::StartReplay).unwrap();
        assert_eq!(json, "\"StartReplay\"");
        let decoded: Permission = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, Permission::StartReplay);
    }

    #[test]
    fn malformed_log_line_is_reported_not_silently_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "not valid json\n").unwrap();
        assert!(AuditLogger::read_all(&path).is_err());
    }

    #[test]
    fn pre_versioning_log_lines_without_schema_version_still_parse() {
        // Simulates a log line written before `schema_version` existed —
        // proves the `serde(default)` backward-compatibility path actually
        // works, not just that it compiles.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let legacy_line = r#"{"timestamp_ns":123,"principal_id":"a","role":"Admin","permission":"ViewMetrics","action":"view","resource":"metrics","outcome":"allowed"}"#;
        std::fs::write(&path, format!("{legacy_line}\n")).unwrap();

        let records = AuditLogger::read_all(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].schema_version, 1,
            "missing field must default to version 1, the pre-versioning format"
        );
        assert_eq!(records[0].principal_id, "a");
    }

    #[test]
    fn newly_written_records_carry_the_current_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = AuditLogger::open(&path).unwrap();
        logger
            .record(
                "a",
                Role::Viewer,
                Permission::ViewMetrics,
                "view",
                "metrics",
                AuditOutcome::Allowed,
            )
            .unwrap();

        let records = AuditLogger::read_all(&path).unwrap();
        assert_eq!(records[0].schema_version, AUDIT_SCHEMA_VERSION);
    }
}
