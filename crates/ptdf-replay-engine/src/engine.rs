//! Replay Engine core (architecture §6, §15).
//!
//! `ReplayEngine::run` implements the replay pipeline:
//!   1. Session load — via `MetadataStore::segments_for_session`.
//!   2. Read every event from every segment (`ptdf-storage::SegmentReader`).
//!   3. Linearize by HLC (`Event::hlc`, total order) — architecture §15:
//!      "the Replay Engine's scheduler picks any linearization consistent
//!      with [the causal partial order]"; HLC order is exactly such a
//!      linearization by construction (HLC never violates a captured
//!      happens-before edge, see `ptdf_types::vclock` docs).
//!   4. Drive the target (`ReplayDriver`) through the linearized stream,
//!      recording every `Divergence` rather than aborting on the first one
//!      — architecture §6 step 4 treats divergence as a forensic signal to
//!      *report*, not a fatal error to stop at, since a session with one
//!      divergence still has useful information in the events before and
//!      after it.

use crate::checkpoint::{CheckpointError, ReplayCheckpoint};
use ptdf_metadata::{MetadataError, MetadataStore};
use ptdf_pal::{Divergence, ReplayDriver, ReplayError, StepOutcome};
use ptdf_storage::{SegmentError, SegmentReader};
use ptdf_types::{Event, SessionId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReplayEngineError {
    #[error("metadata error: {0}")]
    Metadata(#[from] MetadataError),

    #[error("segment read error: {0}")]
    Segment(#[from] SegmentError),

    #[error("replay driver error: {0}")]
    Driver(#[from] ReplayError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),

    #[error("session {0} has no events to replay")]
    EmptySession(SessionId),
}

/// The full outcome of a replay run: every divergence encountered, how the
/// run ended (target completed, or we ran out of events without a
/// completion signal — the latter is not itself an error, since a session
/// can legitimately be a truncated live capture), and any checkpoints
/// taken along the way (see `checkpoint.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutcome {
    pub events_served: u64,
    pub divergences: Vec<Divergence>,
    pub target_exit_code: Option<i32>,
    pub checkpoints: Vec<ReplayCheckpoint>,
}

/// Options controlling one `ReplayEngine::run_with_options` call.
#[derive(Debug, Clone, Default)]
pub struct ReplayRunOptions {
    /// Resume from a previously-taken checkpoint instead of the start of
    /// the session. Validated against the freshly-loaded linearization
    /// before any events are replayed (see `ReplayCheckpoint::validate`).
    pub resume_from: Option<ReplayCheckpoint>,
    /// If set, take a checkpoint every N served events (in addition to
    /// implicitly being able to resume from the start). `None` disables
    /// periodic checkpointing — appropriate for short sessions where
    /// resuming mid-replay has no practical value.
    pub checkpoint_every: Option<usize>,
}

#[derive(Debug)]
pub struct ReplayEngine;

impl ReplayEngine {
    /// Load every event for `session_id` from every registered segment and
    /// return them linearized by the deterministic scheduler (§22).
    /// Exposed separately from `run` so the Query API (§17) can reuse it
    /// for non-replay event queries without needing a `ReplayDriver`.
    pub fn load_linearized_events(
        metadata: &dyn MetadataStore,
        session_id: SessionId,
    ) -> Result<Vec<Event>, ReplayEngineError> {
        let segments = metadata.segments_for_session(session_id)?;
        let mut events = Vec::new();
        for segment in &segments {
            let reader = SegmentReader::open(&segment.path)?;
            events.extend(reader.read_all()?);
        }
        Ok(crate::scheduler::linearize(events))
    }

    /// Run a full replay of `session_id` against `driver`, from the start,
    /// with no periodic checkpointing. Equivalent to
    /// `run_with_options(.., ReplayRunOptions::default())`.
    pub fn run(
        metadata: &dyn MetadataStore,
        session_id: SessionId,
        binary_path: &str,
        driver: &mut dyn ReplayDriver,
    ) -> Result<ReplayOutcome, ReplayEngineError> {
        Self::run_with_options(metadata, session_id, binary_path, driver, ReplayRunOptions::default())
    }

    /// Run a replay with full control over resume position and
    /// checkpoint cadence (architecture: Checkpoint System).
    pub fn run_with_options(
        metadata: &dyn MetadataStore,
        session_id: SessionId,
        binary_path: &str,
        driver: &mut dyn ReplayDriver,
        options: ReplayRunOptions,
    ) -> Result<ReplayOutcome, ReplayEngineError> {
        let events = Self::load_linearized_events(metadata, session_id)?;
        if events.is_empty() {
            return Err(ReplayEngineError::EmptySession(session_id));
        }

        let start_index = if let Some(checkpoint) = &options.resume_from {
            checkpoint.validate(&events)?;
            checkpoint.event_index
        } else {
            0
        };

        driver.prepare_environment(binary_path)?;
        driver.launch()?;

        let mut outcome =
            ReplayOutcome { events_served: 0, divergences: Vec::new(), target_exit_code: None, checkpoints: Vec::new() };

        for (offset, event) in events[start_index..].iter().enumerate() {
            let absolute_index = start_index + offset;

            match driver.step(event)? {
                StepOutcome::Served(_) => {
                    outcome.events_served += 1;

                    if let Some(interval) = options.checkpoint_every {
                        if interval > 0 && outcome.events_served as usize % interval == 0 {
                            if let Some(checkpoint) = ReplayCheckpoint::take(&events, absolute_index + 1) {
                                outcome.checkpoints.push(checkpoint);
                            }
                        }
                    }
                }
                StepOutcome::Diverged(div) => {
                    ptdf_logging::warn!(
                        expected = %div.expected,
                        observed = %div.observed_description,
                        "replay divergence detected"
                    );
                    outcome.divergences.push(div);
                }
                StepOutcome::TargetCompleted { exit_code } => {
                    outcome.target_exit_code = Some(exit_code);
                    break;
                }
            }
        }

        driver.teardown()?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_metadata::{InMemoryMetadataStore, SegmentRecord};
    use ptdf_storage::SegmentWriter;
    use ptdf_types::HostId;

    // Re-export path note: `ptdf-pal`'s mock types live under
    // `#[cfg(test)] pub(crate) mod test_support`, which by design is not
    // visible outside that crate. For this integration test we need a
    // realistic `ReplayDriver` double from outside `ptdf-pal`, so we
    // define an equivalent one locally rather than reaching into another
    // crate's private test internals (which `pub(crate)` correctly
    // prevents — that visibility is intentional API hygiene, not an
    // oversight to work around).
    mod local_mock {
        use ptdf_pal::{Divergence, ReplayDriver, ReplayError, StepOutcome};
        use ptdf_types::{Event, EventId};

        #[derive(Debug, Default)]
        pub struct MockReplayDriver {
            pub prepared: bool,
            pub launched: bool,
            pub steps_served: Vec<EventId>,
            pub force_divergence_on: Option<EventId>,
        }

        impl ReplayDriver for MockReplayDriver {
            fn prepare_environment(&mut self, binary_path: &str) -> Result<(), ReplayError> {
                if binary_path.is_empty() {
                    return Err(ReplayError::EnvironmentSetupFailed("empty binary path".into()));
                }
                self.prepared = true;
                Ok(())
            }
            fn launch(&mut self) -> Result<(), ReplayError> {
                self.launched = true;
                Ok(())
            }
            fn step(&mut self, next: &Event) -> Result<StepOutcome, ReplayError> {
                if self.force_divergence_on == Some(next.id()) {
                    return Ok(StepOutcome::Diverged(Divergence {
                        expected: next.id(),
                        observed_description: "test-forced divergence".into(),
                    }));
                }
                self.steps_served.push(next.id());
                Ok(StepOutcome::Served(next.id()))
            }
            fn teardown(&mut self) -> Result<(), ReplayError> {
                Ok(())
            }
        }
    }
    use local_mock::MockReplayDriver;
    use ptdf_types::{EventId, EventKind, EventResult, HlcTimestamp, Payload};

    fn write_segment(dir: &std::path::Path, name: &str, session: SessionId, host: HostId, seqs: &[u64]) -> SegmentRecord {
        let path = dir.join(name);
        let mut writer = SegmentWriter::create(&path).unwrap();
        for &seq in seqs {
            let id = EventId::new(host, 1, 1, seq);
            let ev = Event::new(id, session, EventKind::Syscall, HlcTimestamp::new(seq, 0), Payload::None, EventResult::Ok(0));
            writer.append(&ev).unwrap();
        }
        let info = writer.seal().unwrap();
        SegmentRecord {
            session_id: session,
            host_id: host,
            path: info.path,
            event_count: info.event_count,
            size_bytes: info.size_bytes,
            min_physical_ns: *seqs.first().unwrap_or(&0),
            max_physical_ns: *seqs.last().unwrap_or(&0),
        }
    }

    #[test]
    fn load_linearized_events_merges_and_sorts_across_segments() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);

        // Segment A has HLC values 0,2,4; segment B has 1,3,5 — out of
        // registration order, but linearization must interleave them
        // correctly by HLC regardless of which segment they came from.
        let seg_a = write_segment(dir.path(), "a.ptds", session, host, &[0, 2, 4]);
        let seg_b = write_segment(dir.path(), "b.ptds", session, host, &[1, 3, 5]);
        store.register_segment(seg_a).unwrap();
        store.register_segment(seg_b).unwrap();

        let events = ReplayEngine::load_linearized_events(&store, session).unwrap();
        let seqs: Vec<u64> = events.iter().map(|e| e.hlc().physical_ns()).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn run_drives_driver_through_all_events_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        let seg = write_segment(dir.path(), "a.ptds", session, host, &[0, 1, 2]);
        store.register_segment(seg).unwrap();

        let mut driver = MockReplayDriver::default();
        let outcome = ReplayEngine::run(&store, session, "/bin/target", &mut driver).unwrap();

        assert_eq!(outcome.events_served, 3);
        assert!(outcome.divergences.is_empty());
        assert!(driver.launched);
        assert_eq!(driver.steps_served.len(), 3);
    }

    #[test]
    fn run_reports_divergence_without_aborting_the_whole_run() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        let seg = write_segment(dir.path(), "a.ptds", session, host, &[0, 1, 2]);
        store.register_segment(seg).unwrap();

        let diverging_id = EventId::new(host, 1, 1, 1);
        let mut driver = MockReplayDriver { force_divergence_on: Some(diverging_id), ..Default::default() };
        let outcome = ReplayEngine::run(&store, session, "/bin/target", &mut driver).unwrap();

        assert_eq!(outcome.divergences.len(), 1);
        assert_eq!(outcome.divergences[0].expected, diverging_id);
        // The two non-diverging events on either side must still be served.
        assert_eq!(outcome.events_served, 2);
    }

    #[test]
    fn run_on_empty_session_is_rejected_cleanly() {
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        // Register the session (via a segment with zero events) so
        // `segments_for_session` succeeds but yields no events.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.ptds");
        let writer = SegmentWriter::create(&path).unwrap();
        let info = writer.seal().unwrap();
        store
            .register_segment(SegmentRecord {
                session_id: session,
                host_id: host,
                path: info.path,
                event_count: 0,
                size_bytes: info.size_bytes,
                min_physical_ns: 0,
                max_physical_ns: 0,
            })
            .unwrap();

        let mut driver = MockReplayDriver::default();
        let err = ReplayEngine::run(&store, session, "/bin/target", &mut driver).unwrap_err();
        assert!(matches!(err, ReplayEngineError::EmptySession(_)));
    }

    #[test]
    fn periodic_checkpoints_are_taken_at_the_requested_interval() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        let seg = write_segment(dir.path(), "a.ptds", session, host, &[0, 1, 2, 3, 4]);
        store.register_segment(seg).unwrap();

        let mut driver = MockReplayDriver::default();
        let options = ReplayRunOptions { resume_from: None, checkpoint_every: Some(2) };
        let outcome = ReplayEngine::run_with_options(&store, session, "/bin/target", &mut driver, options).unwrap();

        assert_eq!(outcome.events_served, 5);
        // 5 events, checkpoint every 2 served -> checkpoints after event 2 and event 4.
        assert_eq!(outcome.checkpoints.len(), 2);
        assert_eq!(outcome.checkpoints[0].event_index, 2);
        assert_eq!(outcome.checkpoints[1].event_index, 4);
    }

    #[test]
    fn resuming_from_a_checkpoint_replays_only_the_remaining_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        let seg = write_segment(dir.path(), "a.ptds", session, host, &[0, 1, 2, 3, 4]);
        store.register_segment(seg).unwrap();

        // First run: take a checkpoint after 3 events, then stop early by
        // simulating a completed target at that point isn't necessary —
        // we just take the checkpoint directly from a fresh linearization,
        // as a control-plane restarting a paused session would.
        let events = ReplayEngine::load_linearized_events(&store, session).unwrap();
        let checkpoint = ReplayCheckpoint::take(&events, 3).unwrap();

        let mut driver = MockReplayDriver::default();
        let options = ReplayRunOptions { resume_from: Some(checkpoint), checkpoint_every: None };
        let outcome = ReplayEngine::run_with_options(&store, session, "/bin/target", &mut driver, options).unwrap();

        assert_eq!(outcome.events_served, 2, "only events at index 3 and 4 should be replayed");
        assert_eq!(driver.steps_served.len(), 2);
    }

    #[test]
    fn resuming_from_a_stale_checkpoint_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryMetadataStore::new();
        let session = SessionId::from_raw(1);
        let host = HostId::from_raw(1);
        let seg = write_segment(dir.path(), "a.ptds", session, host, &[0, 1, 2]);
        store.register_segment(seg).unwrap();

        let events = ReplayEngine::load_linearized_events(&store, session).unwrap();
        let checkpoint = ReplayCheckpoint::take(&events, 5);
        assert!(checkpoint.is_none(), "index 5 is out of range for a 3-event stream, so no checkpoint can be taken there");

        // Construct an artificially stale checkpoint (valid index, wrong id)
        // to exercise the resume-time rejection path.
        let stale = ReplayCheckpoint::take(&events, 1).map(|mut c| {
            c.next_event_id = EventId::new(HostId::from_raw(1), 99, 99, 999);
            c
        }).unwrap();

        let mut driver = MockReplayDriver::default();
        let options = ReplayRunOptions { resume_from: Some(stale), checkpoint_every: None };
        let err = ReplayEngine::run_with_options(&store, session, "/bin/target", &mut driver, options).unwrap_err();
        assert!(matches!(err, ReplayEngineError::Checkpoint(_)));
    }
}
