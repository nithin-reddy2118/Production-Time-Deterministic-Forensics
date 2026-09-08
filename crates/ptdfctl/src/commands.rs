//! Core command implementations for `ptdfctl`, factored into a library so
//! they're testable directly (calling functions, asserting on return
//! values) rather than only via spawning the compiled binary and parsing
//! stdout — the latter is an integration-test concern (covered in
//! `tests/cli_integration.rs`), the former is what makes unit testing this
//! crate's actual logic fast and precise.

use ptdf_storage::{SegmentError, SegmentReader};
use ptdf_types::EventKind;
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("segment error: {0}")]
    Segment(#[from] SegmentError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentSummary {
    pub compressed: bool,
    pub event_count: u64,
    /// Counts per `EventKind`, in a stable (sorted-by-name) order for
    /// deterministic, diffable CLI output.
    pub counts_by_kind: BTreeMap<&'static str, u64>,
}

fn kind_name(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Syscall => "Syscall",
        EventKind::Sched => "Sched",
        EventKind::Signal => "Signal",
        EventKind::NetIo => "NetIo",
        EventKind::ClockRead => "ClockRead",
        EventKind::RngRead => "RngRead",
        EventKind::MemRace => "MemRace",
        EventKind::EnvRead => "EnvRead",
    }
}

/// `ptdfctl segment inspect <path>` — summary without printing every event.
pub fn inspect_segment(path: impl AsRef<Path>) -> Result<SegmentSummary, CliError> {
    let reader = SegmentReader::open(path)?;
    let compressed = reader.is_compressed();
    let events = reader.read_all()?;

    let mut counts_by_kind: BTreeMap<&'static str, u64> = BTreeMap::new();
    for event in &events {
        *counts_by_kind.entry(kind_name(event.kind())).or_insert(0) += 1;
    }

    Ok(SegmentSummary { compressed, event_count: events.len() as u64, counts_by_kind })
}

/// `ptdfctl segment dump <path> [--limit N]` — one human-readable line per
/// event, in on-disk order.
pub fn dump_segment(path: impl AsRef<Path>, limit: Option<usize>) -> Result<Vec<String>, CliError> {
    let reader = SegmentReader::open(path)?;
    let events = reader.read_all()?;

    let take = limit.unwrap_or(events.len());
    Ok(events
        .into_iter()
        .take(take)
        .map(|e| {
            format!(
                "seq={} kind={:?} hlc=({},{}) result={:?}",
                e.id().seq(),
                e.kind(),
                e.hlc().physical_ns(),
                e.hlc().logical(),
                e.result()
            )
        })
        .collect())
}

/// `ptdfctl segment verify <path>` — read every record, verifying every
/// checksum, returning the count of events that verified cleanly. Any
/// checksum or codec failure is returned as `Err` rather than partial
/// output — see `SegmentReader::read_all`'s docs on why a forensic tool
/// never silently skips a corrupted record.
pub fn verify_segment(path: impl AsRef<Path>) -> Result<u64, CliError> {
    let reader = SegmentReader::open(path)?;
    let events = reader.read_all()?;
    Ok(events.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_storage::SegmentWriter;
    use ptdf_types::{Event, EventId, EventResult, HlcTimestamp, HostId, Payload, SessionId};

    fn write_sample_segment(path: &Path, kinds: &[EventKind]) {
        let mut writer = SegmentWriter::create(path).unwrap();
        for (i, &kind) in kinds.iter().enumerate() {
            let id = EventId::new(HostId::from_raw(1), 1, 1, i as u64);
            let ev = Event::new(id, SessionId::from_raw(1), kind, HlcTimestamp::new(i as u64, 0), Payload::None, EventResult::Ok(0));
            writer.append(&ev).unwrap();
        }
        writer.seal().unwrap();
    }

    #[test]
    fn inspect_counts_events_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.ptds");
        write_sample_segment(&path, &[EventKind::Syscall, EventKind::Syscall, EventKind::NetIo]);

        let summary = inspect_segment(&path).unwrap();
        assert_eq!(summary.event_count, 3);
        assert!(!summary.compressed);
        assert_eq!(summary.counts_by_kind.get("Syscall"), Some(&2));
        assert_eq!(summary.counts_by_kind.get("NetIo"), Some(&1));
    }

    #[test]
    fn dump_respects_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.ptds");
        write_sample_segment(&path, &[EventKind::Syscall; 5]);

        let all = dump_segment(&path, None).unwrap();
        assert_eq!(all.len(), 5);

        let limited = dump_segment(&path, Some(2)).unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn verify_returns_event_count_on_clean_segment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.ptds");
        write_sample_segment(&path, &[EventKind::Syscall; 7]);
        assert_eq!(verify_segment(&path).unwrap(), 7);
    }

    #[test]
    fn verify_fails_on_corrupted_segment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.ptds");
        write_sample_segment(&path, &[EventKind::Syscall]);

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        assert!(verify_segment(&path).is_err());
    }

    #[test]
    fn inspect_on_missing_file_reports_segment_error() {
        let err = inspect_segment("/nonexistent/path/does-not-exist.ptds").unwrap_err();
        assert!(matches!(err, CliError::Segment(_)));
    }
}
