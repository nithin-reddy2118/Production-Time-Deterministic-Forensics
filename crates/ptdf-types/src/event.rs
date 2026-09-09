//! The `Event` model — the single unit of record/replay, per architecture §7.

use crate::ids::{EventId, SessionId};
use crate::vclock::HlcTimestamp;

/// Content hash key into the blob store (BLAKE3, per §10/§11). Stored as raw
/// bytes here (not tied to a specific hashing crate) so `ptdf-types` doesn't
/// pull in a hashing dependency — the blob store crate (Module 9) owns
/// hashing and produces `ContentHash` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Where an event's payload lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Small payloads travel inline in the event log segment.
    Inline(Vec<u8>),
    /// Large payloads (memory snapshots, big buffers) are stored once in
    /// the content-addressed blob store and referenced here, enabling
    /// dedup across events/sessions (§10, §11).
    BlobRef(ContentHash),
    /// No payload (e.g. a `ClockRead` event only needs `result`).
    None,
}

/// The outcome of the intercepted operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventResult {
    /// POSIX-style: non-negative return value.
    Ok(i64),
    /// POSIX-style: negative return value + errno.
    Err { retval: i64, errno: i32 },
    /// Windows-style NTSTATUS / HRESULT.
    Status(i32),
    /// The intercepted point has no meaningful return value.
    None,
}

/// Extensible event category. New platform adapters and plugins add new
/// variants without the core engine needing to understand their semantics
/// beyond the shared `Event` envelope (§17, plugin architecture).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    Syscall,
    Sched,
    Signal,
    NetIo,
    ClockRead,
    RngRead,
    MemRace,
    EnvRead,
}

/// A single recorded (or, at replay time, expected) event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    id: EventId,
    session_id: SessionId,
    kind: EventKind,
    hlc: HlcTimestamp,
    payload: Payload,
    result: EventResult,
}

impl Event {
    pub fn new(
        id: EventId,
        session_id: SessionId,
        kind: EventKind,
        hlc: HlcTimestamp,
        payload: Payload,
        result: EventResult,
    ) -> Self {
        Self {
            id,
            session_id,
            kind,
            hlc,
            payload,
            result,
        }
    }

    pub fn id(&self) -> EventId {
        self.id
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn kind(&self) -> EventKind {
        self.kind
    }

    pub fn hlc(&self) -> HlcTimestamp {
        self.hlc
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn result(&self) -> &EventResult {
        &self.result
    }

    /// Approximate on-the-wire/on-disk size before compression, used by the
    /// recorder's adaptive-fidelity shedding logic (§8, §21) to decide what
    /// to drop under backpressure without needing to serialize first.
    pub fn approx_size_bytes(&self) -> usize {
        let payload_len = match &self.payload {
            Payload::Inline(bytes) => bytes.len(),
            Payload::BlobRef(_) => 32,
            Payload::None => 0,
        };
        // Fixed envelope: id (32) + session_id (16) + kind (1) + hlc (12) +
        // result (worst case 16) — approximate, not a wire format spec.
        32 + 16 + 1 + 12 + 16 + payload_len
    }

    /// Whether this event kind is load-bearing for replay correctness and
    /// therefore must never be shed under backpressure (§8: "syscalls
    /// affecting external state never shed").
    pub fn is_load_bearing(&self) -> bool {
        matches!(
            self.kind,
            EventKind::Syscall | EventKind::NetIo | EventKind::Signal
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::HostId;

    fn sample_event(kind: EventKind, payload: Payload) -> Event {
        let host = HostId::from_raw(1);
        let id = EventId::new(host, 100, 200, 1);
        let session = SessionId::from_raw(42);
        let hlc = HlcTimestamp::new(1_000, 0);
        Event::new(id, session, kind, hlc, payload, EventResult::Ok(0))
    }

    #[test]
    fn load_bearing_kinds_are_correctly_classified() {
        assert!(sample_event(EventKind::Syscall, Payload::None).is_load_bearing());
        assert!(sample_event(EventKind::NetIo, Payload::None).is_load_bearing());
        assert!(sample_event(EventKind::Signal, Payload::None).is_load_bearing());
        assert!(!sample_event(EventKind::ClockRead, Payload::None).is_load_bearing());
        assert!(!sample_event(EventKind::RngRead, Payload::None).is_load_bearing());
    }

    #[test]
    fn approx_size_grows_with_inline_payload() {
        let small = sample_event(EventKind::Syscall, Payload::Inline(vec![0u8; 4]));
        let large = sample_event(EventKind::Syscall, Payload::Inline(vec![0u8; 4096]));
        assert!(large.approx_size_bytes() > small.approx_size_bytes());
        assert_eq!(
            large.approx_size_bytes() - small.approx_size_bytes(),
            4096 - 4
        );
    }

    #[test]
    fn blob_ref_payload_has_fixed_small_size() {
        let ev = sample_event(
            EventKind::Syscall,
            Payload::BlobRef(ContentHash::from_bytes([0u8; 32])),
        );
        let none_ev = sample_event(EventKind::ClockRead, Payload::None);
        assert_eq!(ev.approx_size_bytes() - none_ev.approx_size_bytes(), 32);
    }

    #[test]
    fn accessors_round_trip_constructor_args() {
        let ev = sample_event(EventKind::MemRace, Payload::None);
        assert_eq!(ev.kind(), EventKind::MemRace);
        assert_eq!(ev.result(), &EventResult::Ok(0));
    }
}
