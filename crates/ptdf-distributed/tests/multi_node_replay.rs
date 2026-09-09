//! End-to-end proof of Multi-node Event Recording + Multi-node Replay:
//! three independently-recorded "hosts" (each just a segment file, as a
//! real recorder on a real host would produce), registered under one
//! session in a shared `MetadataStore`, where two of the hosts have a real
//! causal link (host B's send causes host C's receive, via the HLC
//! piggyback protocol in `ptdf-distributed`) — and asserts the replay
//! engine reconstructs a linearization that respects that causal link
//! even though the three hosts' local physical clocks are skewed relative
//! to each other.

use ptdf_distributed::simulate_send_receive;
use ptdf_metadata::{InMemoryMetadataStore, MetadataStore, SegmentRecord};
use ptdf_pal::{ReplayDriver, ReplayError, StepOutcome};
use ptdf_replay_engine::ReplayEngine;
use ptdf_storage::SegmentWriter;
use ptdf_types::{
    Event, EventId, EventKind, EventResult, HlcGenerator, HostId, Payload, SessionId,
    SystemPhysicalClock,
};

/// A driver that just records the order it was asked to serve events in —
/// enough to assert on the linearization the engine actually drove.
#[derive(Debug, Default)]
struct RecordingOrderDriver {
    served_order: Vec<EventId>,
}

impl ReplayDriver for RecordingOrderDriver {
    fn prepare_environment(&mut self, _binary_path: &str) -> Result<(), ReplayError> {
        Ok(())
    }
    fn launch(&mut self) -> Result<(), ReplayError> {
        Ok(())
    }
    fn step(&mut self, next: &Event) -> Result<StepOutcome, ReplayError> {
        self.served_order.push(next.id());
        Ok(StepOutcome::Served(next.id()))
    }
    fn teardown(&mut self) -> Result<(), ReplayError> {
        Ok(())
    }
}

fn write_host_segment(
    dir: &std::path::Path,
    name: &str,
    session: SessionId,
    host: HostId,
    events: &[Event],
) -> SegmentRecord {
    let path = dir.join(name);
    let mut writer = SegmentWriter::create(&path).unwrap();
    for e in events {
        writer.append(e).unwrap();
    }
    let info = writer.seal().unwrap();
    let min_ns = events
        .iter()
        .map(|e| e.hlc().physical_ns())
        .min()
        .unwrap_or(0);
    let max_ns = events
        .iter()
        .map(|e| e.hlc().physical_ns())
        .max()
        .unwrap_or(0);
    SegmentRecord {
        session_id: session,
        host_id: host,
        path: info.path,
        event_count: info.event_count,
        size_bytes: info.size_bytes,
        min_physical_ns: min_ns,
        max_physical_ns: max_ns,
    }
}

fn make_event(
    host: HostId,
    pid: u32,
    tid: u32,
    seq: u64,
    session: SessionId,
    hlc: ptdf_types::HlcTimestamp,
    kind: EventKind,
) -> Event {
    let id = EventId::new(host, pid, tid, seq);
    Event::new(id, session, kind, hlc, Payload::None, EventResult::Ok(0))
}

#[test]
fn three_host_session_replays_in_globally_causal_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = InMemoryMetadataStore::new();
    let session = SessionId::from_raw(1);

    let host_a = HostId::from_raw(1);
    let host_b = HostId::from_raw(2);
    let host_c = HostId::from_raw(3);

    // Host A: two local-only events, no cross-host interaction.
    let mut hlc_a = HlcGenerator::new(SystemPhysicalClock);
    let a1 = make_event(host_a, 1, 1, 0, session, hlc_a.tick(), EventKind::Syscall);
    let a2 = make_event(host_a, 1, 1, 1, session, hlc_a.tick(), EventKind::Syscall);

    // Host B sends a network message; Host C receives it. The receive
    // must be ordered strictly after the send in any correct replay,
    // regardless of B and C's independent physical clocks.
    let mut hlc_b = HlcGenerator::new(SystemPhysicalClock);
    let mut hlc_c = HlcGenerator::new(SystemPhysicalClock);
    let (send_hlc, receive_hlc, _wire) =
        simulate_send_receive(&mut hlc_b, &mut hlc_c, b"cross-host-message").unwrap();

    let b_send = make_event(host_b, 2, 2, 0, session, send_hlc, EventKind::NetIo);
    let c_receive = make_event(host_c, 3, 3, 0, session, receive_hlc, EventKind::NetIo);

    let seg_a = write_host_segment(
        dir.path(),
        "host-a.ptds",
        session,
        host_a,
        &[a1.clone(), a2.clone()],
    );
    let seg_b = write_host_segment(
        dir.path(),
        "host-b.ptds",
        session,
        host_b,
        std::slice::from_ref(&b_send),
    );
    let seg_c = write_host_segment(
        dir.path(),
        "host-c.ptds",
        session,
        host_c,
        std::slice::from_ref(&c_receive),
    );

    store.register_segment(seg_a).unwrap();
    store.register_segment(seg_b).unwrap();
    store.register_segment(seg_c).unwrap();

    // Multi-node visibility: the metadata engine must report all three
    // hosts as having contributed to this one session.
    let mut hosts = store.hosts_for_session(session).unwrap();
    hosts.sort();
    let mut expected_hosts = vec![host_a, host_b, host_c];
    expected_hosts.sort();
    assert_eq!(hosts, expected_hosts);

    let mut driver = RecordingOrderDriver::default();
    let outcome =
        ReplayEngine::run(&store, session, "/bin/multi-host-target", &mut driver).unwrap();
    assert_eq!(outcome.events_served, 4);

    // The core multi-node replay correctness property: wherever the send
    // and receive land in the overall interleaving, the send must come
    // strictly before its corresponding receive.
    let send_pos = driver
        .served_order
        .iter()
        .position(|id| *id == b_send.id())
        .unwrap();
    let receive_pos = driver
        .served_order
        .iter()
        .position(|id| *id == c_receive.id())
        .unwrap();
    assert!(
        send_pos < receive_pos,
        "a NetIo send must always be scheduled before the receive it caused"
    );

    // Host A's two events must keep their own relative order too, since
    // multi-node merging must never disturb single-host ordering.
    let a1_pos = driver
        .served_order
        .iter()
        .position(|id| *id == a1.id())
        .unwrap();
    let a2_pos = driver
        .served_order
        .iter()
        .position(|id| *id == a2.id())
        .unwrap();
    assert!(a1_pos < a2_pos);
}

#[test]
fn multi_node_session_survives_pid_tid_reuse_across_hosts() {
    // Direct regression test for the scheduler bug fixed alongside this
    // feature: two hosts both using (pid=1, tid=1) must not have their
    // events conflated during multi-node replay.
    let dir = tempfile::tempdir().unwrap();
    let store = InMemoryMetadataStore::new();
    let session = SessionId::from_raw(1);
    let host_a = HostId::from_raw(10);
    let host_b = HostId::from_raw(20);

    let a_events: Vec<Event> = (0..3)
        .map(|seq| {
            make_event(
                host_a,
                1,
                1,
                seq,
                session,
                ptdf_types::HlcTimestamp::new(seq * 2, 0),
                EventKind::Syscall,
            )
        })
        .collect();
    let b_events: Vec<Event> = (0..3)
        .map(|seq| {
            make_event(
                host_b,
                1,
                1,
                seq,
                session,
                ptdf_types::HlcTimestamp::new(seq * 2 + 1, 0),
                EventKind::Syscall,
            )
        })
        .collect();

    store
        .register_segment(write_host_segment(
            dir.path(),
            "a.ptds",
            session,
            host_a,
            &a_events,
        ))
        .unwrap();
    store
        .register_segment(write_host_segment(
            dir.path(),
            "b.ptds",
            session,
            host_b,
            &b_events,
        ))
        .unwrap();

    let mut driver = RecordingOrderDriver::default();
    ReplayEngine::run(&store, session, "/bin/target", &mut driver).unwrap();

    let a_order: Vec<u64> = driver
        .served_order
        .iter()
        .filter(|id| id.host_id() == host_a)
        .map(|id| id.seq())
        .collect();
    let b_order: Vec<u64> = driver
        .served_order
        .iter()
        .filter(|id| id.host_id() == host_b)
        .map(|id| id.seq())
        .collect();
    assert_eq!(
        a_order,
        vec![0, 1, 2],
        "host A's own seq order must be intact despite pid/tid reuse on host B"
    );
    assert_eq!(
        b_order,
        vec![0, 1, 2],
        "host B's own seq order must be intact despite pid/tid reuse on host A"
    );
}
