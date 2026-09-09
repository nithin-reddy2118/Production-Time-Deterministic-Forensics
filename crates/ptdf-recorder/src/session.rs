//! `RecordingSession` — the Event Recorder (architecture §5/§8 tied
//! together end to end): attach a `PlatformInterceptor`, drain captured
//! events through a `BoundedSink` (backpressure/shedding, §8), roll them
//! into sealed, checksummed segments (`ptdf-storage`, §10), register each
//! sealed segment with a `MetadataStore` (§12), and report progress via
//! `StandardMetrics` (§25) — the same run loop regardless of which
//! `EventKind`s are flowing through it, which is what makes this one
//! module the integration point for every category of "recorder" listed
//! in the architecture doc rather than needing one run loop per category.

use ptdf_metadata::{MetadataStore, SegmentRecord};
use ptdf_metrics::StandardMetrics;
use ptdf_pal::{AttachTarget, InterceptorError, PlatformInterceptor};
use ptdf_recorder_core::{BoundedSink, RecorderSink, SinkError};
use ptdf_storage::{SegmentError, SegmentWriter};
use ptdf_types::{HostId, SessionId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecorderError {
    #[error("interceptor error: {0}")]
    Interceptor(#[from] InterceptorError),

    #[error("segment error: {0}")]
    Segment(#[from] SegmentError),

    #[error("metadata error: {0}")]
    Metadata(#[from] ptdf_metadata::MetadataError),

    #[error("sink error: {0}")]
    Sink(#[from] SinkError),
}

#[derive(Debug, Clone)]
pub struct RecordingSessionConfig {
    /// Directory sealed segments are written into. Must already exist.
    pub segment_dir: PathBuf,
    /// Roll to a new segment after this many events (architecture §10
    /// mentions 128 MB as a size-based default; we roll by event count
    /// here since that's what this crate can control directly without
    /// re-deriving on-disk size mid-write — a size-based rotation policy
    /// on top of this is a straightforward addition once real workloads
    /// establish the right byte threshold empirically).
    pub max_events_per_segment: u64,
    pub compress_segments: bool,
    pub sink_capacity: usize,
}

impl Default for RecordingSessionConfig {
    fn default() -> Self {
        Self {
            segment_dir: PathBuf::from("."),
            max_events_per_segment: 100_000,
            compress_segments: true,
            sink_capacity: 65_536,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingSummary {
    pub events_recorded: u64,
    pub events_shed: u64,
    pub segments_sealed: u64,
}

/// Handle a caller can use to ask a running session to stop cleanly after
/// its current poll iteration, without needing to kill the target.
#[derive(Debug, Clone, Default)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn request_stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn is_stop_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct RecordingSession {
    interceptor: Box<dyn PlatformInterceptor>,
    sink: BoundedSink,
    metadata: Arc<dyn MetadataStore>,
    metrics: Arc<StandardMetrics>,
    config: RecordingSessionConfig,
    session_id: SessionId,
    host_id: HostId,
    segment_index: u64,
}

impl std::fmt::Debug for RecordingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingSession")
            .field("session_id", &self.session_id)
            .field("host_id", &self.host_id)
            .field("segment_index", &self.segment_index)
            .finish()
    }
}

impl RecordingSession {
    pub fn new(
        interceptor: Box<dyn PlatformInterceptor>,
        metadata: Arc<dyn MetadataStore>,
        metrics: Arc<StandardMetrics>,
        session_id: SessionId,
        host_id: HostId,
        config: RecordingSessionConfig,
    ) -> Self {
        let sink = BoundedSink::new(config.sink_capacity);
        Self {
            interceptor,
            sink,
            metadata,
            metrics,
            config,
            session_id,
            host_id,
            segment_index: 0,
        }
    }

    fn next_segment_path(&mut self) -> PathBuf {
        let path = self
            .config
            .segment_dir
            .join(format!("segment-{:08}.ptds", self.segment_index));
        self.segment_index += 1;
        path
    }

    fn open_segment(&mut self) -> Result<SegmentWriter, RecorderError> {
        let path = self.next_segment_path();
        let writer = if self.config.compress_segments {
            SegmentWriter::create_compressed_default(&path)?
        } else {
            SegmentWriter::create(&path)?
        };
        Ok(writer)
    }

    /// Seal `writer` (if it has at least one event — an empty final
    /// segment is discarded rather than registered, since it carries no
    /// information and would otherwise leave a zero-event segment file
    /// behind on every run) and register it with the metadata store.
    fn seal_and_register(
        &self,
        writer: SegmentWriter,
        min_hlc_ns: u64,
        max_hlc_ns: u64,
    ) -> Result<Option<SegmentRecord>, RecorderError> {
        if writer.event_count() == 0 {
            return Ok(None);
        }
        let info = writer.seal()?;
        let record = SegmentRecord {
            session_id: self.session_id,
            host_id: self.host_id,
            path: info.path,
            event_count: info.event_count,
            size_bytes: info.size_bytes,
            min_physical_ns: min_hlc_ns,
            max_physical_ns: max_hlc_ns,
        };
        self.metadata.register_segment(record.clone())?;
        self.metrics.segments_sealed_total.inc();
        Ok(Some(record))
    }

    /// Attach to `target` and run the record loop until the target exits
    /// (`InterceptorError::TargetGone`) or `stop.request_stop()` is called.
    /// Any other interceptor error propagates immediately — a forensic
    /// recorder must not silently swallow an error that could mean it
    /// stopped capturing without the caller knowing.
    pub fn run(
        &mut self,
        target: AttachTarget,
        stop: &StopHandle,
        poll_wait_ms: u32,
    ) -> Result<RecordingSummary, RecorderError> {
        self.interceptor.attach(target)?;

        let mut writer = self.open_segment()?;
        let mut min_hlc_ns = u64::MAX;
        let mut max_hlc_ns = 0u64;
        let mut total_recorded = 0u64;
        let mut total_shed_before = self.sink.shed_count();

        let run_result: Result<(), RecorderError> = (|| {
            loop {
                if stop.is_stop_requested() {
                    break;
                }

                let events = match self.interceptor.poll_events(poll_wait_ms) {
                    Ok(events) => events,
                    Err(InterceptorError::TargetGone { .. }) => break,
                    Err(e) => return Err(e.into()),
                };

                for event in events {
                    // Sink push failure only happens if the sink was
                    // explicitly closed, which this session never does
                    // mid-run — a push error here would indicate a bug,
                    // and per architecture §8 load-bearing events are
                    // never dropped by the sink itself, so we propagate
                    // (exiting the whole run loop, not just this inner
                    // for-loop — a bare `break` here previously only
                    // exited the inner loop and let the outer loop keep
                    // polling, silently contradicting this comment's
                    // stated intent; fixed to actually stop).
                    if let Err(e) = self.sink.push(event) {
                        ptdf_logging::error!(error = %e, "sink rejected event unexpectedly; stopping recording");
                        return Err(e.into());
                    }
                }

                let shed_now = self.sink.shed_count();
                if shed_now > total_shed_before {
                    self.metrics
                        .events_shed_total
                        .inc_by(shed_now - total_shed_before);
                    total_shed_before = shed_now;
                }
                self.metrics.sink_queue_depth.set(self.sink.len() as i64);

                let batch = self.sink.drain_batch(self.sink.len().max(1));
                for event in &batch {
                    writer.append(event)?;
                    let ns = event.hlc().physical_ns();
                    min_hlc_ns = min_hlc_ns.min(ns);
                    max_hlc_ns = max_hlc_ns.max(ns);
                    total_recorded += 1;
                    self.metrics.events_recorded_total.inc();

                    if writer.event_count() >= self.config.max_events_per_segment {
                        let sealed_min = min_hlc_ns;
                        let sealed_max = max_hlc_ns;
                        let old_writer = std::mem::replace(&mut writer, self.open_segment()?);
                        self.seal_and_register(old_writer, sealed_min, sealed_max)?;
                        min_hlc_ns = u64::MAX;
                        max_hlc_ns = 0;
                    }
                }
            }
            Ok(())
        })();

        // Always try to seal and detach, even if the run loop errored,
        // so a mid-run failure doesn't also lose whatever was already
        // captured or leave the target permanently traced.
        let seal_result = self.seal_and_register(writer, min_hlc_ns, max_hlc_ns);
        let detach_result = self.interceptor.detach();

        run_result?;
        seal_result?;
        detach_result?;

        Ok(RecordingSummary {
            events_recorded: total_recorded,
            events_shed: self.sink.shed_count(),
            segments_sealed: self.segment_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_metadata::InMemoryMetadataStore;
    use ptdf_metrics::Registry;
    use ptdf_pal::interceptor::{InterceptorCapabilities, InterceptorError as IErr};
    use ptdf_types::{Event, EventId, EventKind, EventResult, HlcTimestamp, Payload};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A deterministic fake interceptor: yields a pre-programmed batch of
    /// events on each `poll_events` call, then reports `TargetGone` once
    /// exhausted — enough to drive `RecordingSession::run` through a full
    /// realistic lifecycle without any real OS dependency.
    struct FakeInterceptor {
        batches: Mutex<VecDeque<Vec<Event>>>,
        attached: Mutex<bool>,
    }

    impl PlatformInterceptor for FakeInterceptor {
        fn attach(&mut self, _target: AttachTarget) -> Result<(), IErr> {
            *self.attached.lock().unwrap() = true;
            Ok(())
        }
        fn detach(&mut self) -> Result<(), IErr> {
            *self.attached.lock().unwrap() = false;
            Ok(())
        }
        fn capabilities(&self) -> InterceptorCapabilities {
            InterceptorCapabilities::default()
        }
        fn poll_events(&mut self, _max_wait_ms: u32) -> Result<Vec<Event>, IErr> {
            let mut batches = self.batches.lock().unwrap();
            match batches.pop_front() {
                Some(batch) => Ok(batch),
                None => Err(IErr::TargetGone { pid: 1 }),
            }
        }
    }

    fn make_event(seq: u64) -> Event {
        let id = EventId::new(HostId::from_raw(1), 1, 1, seq);
        Event::new(
            id,
            SessionId::from_raw(1),
            EventKind::Syscall,
            HlcTimestamp::new(seq, 0),
            Payload::None,
            EventResult::Ok(0),
        )
    }

    #[test]
    fn full_run_records_all_events_across_batches_into_one_segment() {
        let dir = tempfile::tempdir().unwrap();
        let interceptor = Box::new(FakeInterceptor {
            batches: Mutex::new(VecDeque::from(vec![
                vec![make_event(0), make_event(1)],
                vec![make_event(2)],
            ])),
            attached: Mutex::new(false),
        });
        let metadata = Arc::new(InMemoryMetadataStore::new());
        let metrics = Arc::new(StandardMetrics::register(&Registry::new()).unwrap());
        let config = RecordingSessionConfig {
            segment_dir: dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut session = RecordingSession::new(
            interceptor,
            metadata.clone(),
            metrics.clone(),
            SessionId::from_raw(1),
            HostId::from_raw(1),
            config,
        );
        let stop = StopHandle::new();
        let summary = session
            .run(
                AttachTarget {
                    pid: 1,
                    follow_children: false,
                },
                &stop,
                10,
            )
            .unwrap();

        assert_eq!(summary.events_recorded, 3);
        assert_eq!(summary.events_shed, 0);
        assert_eq!(metrics.events_recorded_total.get(), 3);
        assert_eq!(metrics.segments_sealed_total.get(), 1);

        let segments = metadata
            .segments_for_session(SessionId::from_raw(1))
            .unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].event_count, 3);
    }

    #[test]
    fn rolls_to_a_new_segment_when_max_events_per_segment_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        let events: Vec<Event> = (0..5).map(make_event).collect();
        let interceptor = Box::new(FakeInterceptor {
            batches: Mutex::new(VecDeque::from(vec![events])),
            attached: Mutex::new(false),
        });
        let metadata = Arc::new(InMemoryMetadataStore::new());
        let metrics = Arc::new(StandardMetrics::register(&Registry::new()).unwrap());
        let config = RecordingSessionConfig {
            segment_dir: dir.path().to_path_buf(),
            max_events_per_segment: 2,
            compress_segments: false,
            ..Default::default()
        };

        let mut session = RecordingSession::new(
            interceptor,
            metadata.clone(),
            metrics,
            SessionId::from_raw(1),
            HostId::from_raw(1),
            config,
        );
        let stop = StopHandle::new();
        let summary = session
            .run(
                AttachTarget {
                    pid: 1,
                    follow_children: false,
                },
                &stop,
                10,
            )
            .unwrap();

        assert_eq!(summary.events_recorded, 5);
        let segments = metadata
            .segments_for_session(SessionId::from_raw(1))
            .unwrap();
        // 5 events at 2-per-segment: segments of 2, 2, 1.
        assert_eq!(segments.len(), 3);
        assert_eq!(segments.iter().map(|s| s.event_count).sum::<u64>(), 5);
    }

    #[test]
    fn empty_recording_registers_no_segments() {
        let dir = tempfile::tempdir().unwrap();
        let interceptor = Box::new(FakeInterceptor {
            batches: Mutex::new(VecDeque::new()),
            attached: Mutex::new(false),
        });
        let metadata = Arc::new(InMemoryMetadataStore::new());
        let metrics = Arc::new(StandardMetrics::register(&Registry::new()).unwrap());
        let config = RecordingSessionConfig {
            segment_dir: dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut session = RecordingSession::new(
            interceptor,
            metadata.clone(),
            metrics,
            SessionId::from_raw(1),
            HostId::from_raw(1),
            config,
        );
        let stop = StopHandle::new();
        let summary = session
            .run(
                AttachTarget {
                    pid: 1,
                    follow_children: false,
                },
                &stop,
                10,
            )
            .unwrap();

        assert_eq!(summary.events_recorded, 0);
        // No segment ever had an event, so nothing should be registered —
        // registering an empty segment would fail anyway since the
        // session is never explicitly created in the metadata store
        // otherwise, and this asserts that path is correctly skipped.
        assert!(metadata
            .segments_for_session(SessionId::from_raw(1))
            .is_err());
    }

    #[test]
    fn stop_handle_halts_the_run_loop_before_target_gone() {
        // An interceptor with effectively infinite batches (always
        // returns one event) — the only way this test terminates is via
        // the stop handle, proving `run` actually honors it rather than
        // looping until TargetGone.
        struct InfiniteInterceptor {
            attached: Mutex<bool>,
            seq: Mutex<u64>,
        }
        impl PlatformInterceptor for InfiniteInterceptor {
            fn attach(&mut self, _t: AttachTarget) -> Result<(), IErr> {
                *self.attached.lock().unwrap() = true;
                Ok(())
            }
            fn detach(&mut self) -> Result<(), IErr> {
                Ok(())
            }
            fn capabilities(&self) -> InterceptorCapabilities {
                InterceptorCapabilities::default()
            }
            fn poll_events(&mut self, _max_wait_ms: u32) -> Result<Vec<Event>, IErr> {
                let mut seq = self.seq.lock().unwrap();
                let ev = make_event(*seq);
                *seq += 1;
                Ok(vec![ev])
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let interceptor = Box::new(InfiniteInterceptor {
            attached: Mutex::new(false),
            seq: Mutex::new(0),
        });
        let metadata = Arc::new(InMemoryMetadataStore::new());
        let metrics = Arc::new(StandardMetrics::register(&Registry::new()).unwrap());
        let config = RecordingSessionConfig {
            segment_dir: dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut session = RecordingSession::new(
            interceptor,
            metadata,
            metrics,
            SessionId::from_raw(1),
            HostId::from_raw(1),
            config,
        );
        let stop = StopHandle::new();
        let stop_clone = stop.clone();

        // Request stop from a separate thread shortly after starting, so
        // `run` (which blocks this thread) actually gets a chance to
        // observe a nonzero number of events before halting.
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            stop_clone.request_stop();
        });

        let summary = session
            .run(
                AttachTarget {
                    pid: 1,
                    follow_children: false,
                },
                &stop,
                1,
            )
            .unwrap();
        handle.join().unwrap();

        assert!(
            summary.events_recorded > 0,
            "the loop should have recorded at least some events before stopping"
        );
    }
}
