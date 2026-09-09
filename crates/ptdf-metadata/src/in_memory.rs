//! `InMemoryMetadataStore` — a fully-implemented, thread-safe reference
//! `MetadataStore`. Suitable for the CLI's local-recording workflow and
//! for tests; a fleet-scale deployment swaps in a RocksDB-backed store
//! behind the same trait (see crate docs) without touching any caller.

use crate::store::{EventLocation, MetadataError, MetadataStore, SegmentRecord};
use ptdf_types::{EventId, EventKind, HostId, SessionId};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Default)]
struct SessionState {
    segments: Vec<SegmentRecord>,
    hosts: std::collections::HashSet<HostId>,
}

#[derive(Debug, Default)]
struct Inner {
    sessions: HashMap<SessionId, SessionState>,
    event_locations: HashMap<EventId, EventLocation>,
    kind_index: HashMap<(SessionId, EventKind), Vec<EventId>>,
}

#[derive(Debug, Default)]
pub struct InMemoryMetadataStore {
    inner: RwLock<Inner>,
}

impl InMemoryMetadataStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MetadataStore for InMemoryMetadataStore {
    fn register_segment(&self, segment: SegmentRecord) -> Result<(), MetadataError> {
        let mut inner = self
            .inner
            .write()
            .expect("InMemoryMetadataStore lock poisoned");
        let session = inner.sessions.entry(segment.session_id).or_default();

        if session.segments.iter().any(|s| s.path == segment.path) {
            return Err(MetadataError::DuplicateSegment {
                session: segment.session_id,
                path: segment.path,
            });
        }

        session.hosts.insert(segment.host_id);
        session.segments.push(segment);
        Ok(())
    }

    fn segments_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<SegmentRecord>, MetadataError> {
        let inner = self
            .inner
            .read()
            .expect("InMemoryMetadataStore lock poisoned");
        inner
            .sessions
            .get(&session_id)
            .map(|s| s.segments.clone())
            .ok_or(MetadataError::UnknownSession(session_id))
    }

    fn index_event(
        &self,
        event_id: EventId,
        session_id: SessionId,
        kind: EventKind,
        location: EventLocation,
    ) -> Result<(), MetadataError> {
        let mut inner = self
            .inner
            .write()
            .expect("InMemoryMetadataStore lock poisoned");
        if !inner.sessions.contains_key(&session_id) {
            return Err(MetadataError::UnknownSession(session_id));
        }
        inner.event_locations.insert(event_id, location);
        inner
            .kind_index
            .entry((session_id, kind))
            .or_default()
            .push(event_id);
        Ok(())
    }

    fn locate_event(&self, event_id: EventId) -> Result<EventLocation, MetadataError> {
        let inner = self
            .inner
            .read()
            .expect("InMemoryMetadataStore lock poisoned");
        inner
            .event_locations
            .get(&event_id)
            .copied()
            .ok_or(MetadataError::UnknownEvent(event_id))
    }

    fn events_by_kind(
        &self,
        session_id: SessionId,
        kind: EventKind,
    ) -> Result<Vec<EventId>, MetadataError> {
        let inner = self
            .inner
            .read()
            .expect("InMemoryMetadataStore lock poisoned");
        if !inner.sessions.contains_key(&session_id) {
            return Err(MetadataError::UnknownSession(session_id));
        }
        Ok(inner
            .kind_index
            .get(&(session_id, kind))
            .cloned()
            .unwrap_or_default())
    }

    fn hosts_for_session(&self, session_id: SessionId) -> Result<Vec<HostId>, MetadataError> {
        let inner = self
            .inner
            .read()
            .expect("InMemoryMetadataStore lock poisoned");
        inner
            .sessions
            .get(&session_id)
            .map(|s| s.hosts.iter().copied().collect())
            .ok_or(MetadataError::UnknownSession(session_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_segment(session: SessionId, host: HostId, path: &str) -> SegmentRecord {
        SegmentRecord {
            session_id: session,
            host_id: host,
            path: PathBuf::from(path),
            event_count: 10,
            size_bytes: 1024,
            min_physical_ns: 1_000,
            max_physical_ns: 2_000,
        }
    }

    #[test]
    fn register_and_fetch_segments_for_session() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        store
            .register_segment(sample_segment(session, host, "/data/seg-1.ptds"))
            .unwrap();
        store
            .register_segment(sample_segment(session, host, "/data/seg-2.ptds"))
            .unwrap();

        let segments = store.segments_for_session(session).unwrap();
        assert_eq!(segments.len(), 2);
    }

    #[test]
    fn duplicate_segment_registration_is_rejected() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        store
            .register_segment(sample_segment(session, host, "/data/seg-1.ptds"))
            .unwrap();
        let err = store
            .register_segment(sample_segment(session, host, "/data/seg-1.ptds"))
            .unwrap_err();
        assert!(matches!(err, MetadataError::DuplicateSegment { .. }));
    }

    #[test]
    fn unknown_session_queries_return_unknown_session_error() {
        let store = InMemoryMetadataStore::new();
        let missing = SessionId::from_raw(999);
        assert_eq!(
            store.segments_for_session(missing),
            Err(MetadataError::UnknownSession(missing))
        );
        assert_eq!(
            store.hosts_for_session(missing),
            Err(MetadataError::UnknownSession(missing))
        );
        assert_eq!(
            store.events_by_kind(missing, EventKind::Syscall),
            Err(MetadataError::UnknownSession(missing))
        );
    }

    #[test]
    fn index_and_locate_event_round_trips() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        store
            .register_segment(sample_segment(session, host, "/data/seg-1.ptds"))
            .unwrap();

        let event_id = EventId::new(host, 100, 200, 0);
        let location = EventLocation {
            segment_index: 0,
            byte_offset: 5,
        };
        store
            .index_event(event_id, session, EventKind::Syscall, location)
            .unwrap();

        assert_eq!(store.locate_event(event_id).unwrap(), location);
    }

    #[test]
    fn locate_unindexed_event_reports_unknown_event() {
        let store = InMemoryMetadataStore::new();
        let host = HostId::from_raw(1);
        let event_id = EventId::new(host, 1, 1, 0);
        assert_eq!(
            store.locate_event(event_id),
            Err(MetadataError::UnknownEvent(event_id))
        );
    }

    #[test]
    fn events_by_kind_only_returns_matching_kind_within_session() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        store
            .register_segment(sample_segment(session, host, "/data/seg-1.ptds"))
            .unwrap();

        let syscall_event = EventId::new(host, 1, 1, 0);
        let netio_event = EventId::new(host, 1, 1, 1);
        store
            .index_event(
                syscall_event,
                session,
                EventKind::Syscall,
                EventLocation {
                    segment_index: 0,
                    byte_offset: 0,
                },
            )
            .unwrap();
        store
            .index_event(
                netio_event,
                session,
                EventKind::NetIo,
                EventLocation {
                    segment_index: 0,
                    byte_offset: 10,
                },
            )
            .unwrap();

        let syscalls = store.events_by_kind(session, EventKind::Syscall).unwrap();
        assert_eq!(syscalls, vec![syscall_event]);
        let net = store.events_by_kind(session, EventKind::NetIo).unwrap();
        assert_eq!(net, vec![netio_event]);
    }

    #[test]
    fn hosts_for_session_deduplicates_across_multiple_segments_from_same_host() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        store
            .register_segment(sample_segment(session, host, "/data/seg-1.ptds"))
            .unwrap();
        store
            .register_segment(sample_segment(session, host, "/data/seg-2.ptds"))
            .unwrap();

        let hosts = store.hosts_for_session(session).unwrap();
        assert_eq!(hosts, vec![host]);
    }

    #[test]
    fn indexing_event_for_unregistered_session_is_rejected() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(42);
        let host = HostId::from_raw(1);
        let event_id = EventId::new(host, 1, 1, 0);
        let err = store
            .index_event(
                event_id,
                session,
                EventKind::Syscall,
                EventLocation {
                    segment_index: 0,
                    byte_offset: 0,
                },
            )
            .unwrap_err();
        assert_eq!(err, MetadataError::UnknownSession(session));
    }
}
