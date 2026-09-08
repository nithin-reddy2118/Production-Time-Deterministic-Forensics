//! `MetadataStore` — the trait boundary for the metadata/index engine
//! (architecture §12). Query API (§17) and Replay Engine (§6) both depend
//! only on this trait, never on a specific backend, matching the pattern
//! established by `ptdf-pal`'s `PlatformInterceptor`/`ReplayDriver`.

use ptdf_types::{EventId, EventKind, HostId, SessionId};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MetadataError {
    #[error("session {0} is not registered")]
    UnknownSession(SessionId),

    #[error("event {0} has no recorded location")]
    UnknownEvent(EventId),

    #[error("segment already registered for session {session}: {path:?}")]
    DuplicateSegment { session: SessionId, path: PathBuf },
}

/// What's known about one sealed segment, for the purposes of the index
/// (a superset of `ptdf_storage::SealedSegmentInfo`, adding the session/host
/// context that only the recorder/ingestion pipeline knows — kept as a
/// separate type here rather than depending on `ptdf-storage`, since the
/// metadata engine's job is indexing locations, not writing segment
/// files, and shouldn't need to depend on the segment format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecord {
    pub session_id: SessionId,
    pub host_id: HostId,
    pub path: PathBuf,
    pub event_count: u64,
    pub size_bytes: u64,
    /// HLC physical-time range covered, for time-range queries (§17).
    pub min_physical_ns: u64,
    pub max_physical_ns: u64,
}

/// Where one event physically lives, for point lookups without a full
/// segment scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLocation {
    pub segment_index: usize, // index into the owning session's segment list
    pub byte_offset: u64,
}

pub trait MetadataStore: Send + Sync {
    /// Register a newly-sealed segment. Errors if this exact
    /// `(session_id, path)` was already registered — segments are
    /// immutable and registered exactly once, so a duplicate call
    /// indicates a bug upstream (e.g. ingestion retrying without
    /// idempotency) rather than something to silently absorb.
    fn register_segment(&self, segment: SegmentRecord) -> Result<(), MetadataError>;

    /// All segments known for a session, in registration order (which is
    /// also chronological, since segments are sealed and registered in
    /// the order they fill up).
    fn segments_for_session(&self, session_id: SessionId) -> Result<Vec<SegmentRecord>, MetadataError>;

    /// Index one event's on-disk location, and its kind for secondary
    /// lookup. `segment_index` refers to the position in
    /// `segments_for_session`'s return order at the time of indexing.
    fn index_event(&self, event_id: EventId, session_id: SessionId, kind: EventKind, location: EventLocation) -> Result<(), MetadataError>;

    /// Point lookup: where does this event live?
    fn locate_event(&self, event_id: EventId) -> Result<EventLocation, MetadataError>;

    /// Secondary index query: all event IDs of a given kind within a
    /// session (§17: "find all sessions where syscall X returned EAGAIN"
    /// starts from a query like this, refined further by the caller
    /// reading the actual events once located).
    fn events_by_kind(&self, session_id: SessionId, kind: EventKind) -> Result<Vec<EventId>, MetadataError>;

    /// All distinct hosts that have contributed segments to a session —
    /// used by the Replay Engine (§6 step 1) to know which hosts'
    /// recorders participated.
    fn hosts_for_session(&self, session_id: SessionId) -> Result<Vec<HostId>, MetadataError>;
}
