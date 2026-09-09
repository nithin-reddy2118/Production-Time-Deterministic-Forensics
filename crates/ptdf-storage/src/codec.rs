//! Binary encode/decode for `Event` — the on-disk record format inside a
//! segment (architecture §10/§16). Deliberately a hand-rolled, versioned,
//! length-prefixed format rather than `serde` + a generic serializer: the
//! wire format needs to be a stable, auditable byte layout that survives
//! independent of any serialization library's internal representation
//! choices (which can change between major versions), since old segments
//! must remain readable indefinitely.

use ptdf_types::{
    ContentHash, Event, EventId, EventKind, EventResult, HlcTimestamp, HostId, Payload, SessionId,
};
use thiserror::Error;

/// Format version tag written at the start of every encoded record, so a
/// future format change can be detected and either migrated or rejected
/// cleanly instead of silently misparsed.
pub const CODEC_VERSION: u8 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("unexpected end of buffer while decoding at offset {offset}")]
    UnexpectedEof { offset: usize },

    #[error("unsupported codec version {found}, this reader supports version {supported}")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("invalid EventKind tag: {0}")]
    InvalidEventKindTag(u8),

    #[error("invalid Payload tag: {0}")]
    InvalidPayloadTag(u8),

    #[error("invalid EventResult tag: {0}")]
    InvalidEventResultTag(u8),
}

struct ByteWriter {
    buf: Vec<u8>,
}

impl ByteWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes_with_len(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
    fn fixed_bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
}

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), CodecError> {
        if self.pos + n > self.buf.len() {
            Err(CodecError::UnexpectedEof { offset: self.pos })
        } else {
            Ok(())
        }
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn i64(&mut self) -> Result<i64, CodecError> {
        self.need(8)?;
        let v = i64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn i32(&mut self) -> Result<i32, CodecError> {
        self.need(4)?;
        let v = i32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn u128(&mut self) -> Result<u128, CodecError> {
        self.need(16)?;
        let v = u128::from_le_bytes(self.buf[self.pos..self.pos + 16].try_into().unwrap());
        self.pos += 16;
        Ok(v)
    }
    fn bytes_with_len(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()? as usize;
        self.need(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
    fn fixed_bytes(&mut self, n: usize) -> Result<Vec<u8>, CodecError> {
        self.need(n)?;
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }
}

fn kind_tag(kind: EventKind) -> u8 {
    match kind {
        EventKind::Syscall => 0,
        EventKind::Sched => 1,
        EventKind::Signal => 2,
        EventKind::NetIo => 3,
        EventKind::ClockRead => 4,
        EventKind::RngRead => 5,
        EventKind::MemRace => 6,
        EventKind::EnvRead => 7,
    }
}

fn kind_from_tag(tag: u8) -> Result<EventKind, CodecError> {
    match tag {
        0 => Ok(EventKind::Syscall),
        1 => Ok(EventKind::Sched),
        2 => Ok(EventKind::Signal),
        3 => Ok(EventKind::NetIo),
        4 => Ok(EventKind::ClockRead),
        5 => Ok(EventKind::RngRead),
        6 => Ok(EventKind::MemRace),
        7 => Ok(EventKind::EnvRead),
        other => Err(CodecError::InvalidEventKindTag(other)),
    }
}

/// Encode a single `Event` to its versioned binary representation.
/// Does **not** include the outer segment framing (record length prefix +
/// CRC) — that's added by `segment.rs`, keeping "how an event looks" and
/// "how a segment frames records" independently testable.
pub fn encode_event(event: &Event) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.u8(CODEC_VERSION);

    w.u128(event.id().host_id().as_raw());
    w.u32(event.id().pid());
    w.u32(event.id().tid());
    w.u64(event.id().seq());

    w.u128(event.session_id().as_raw());
    w.u8(kind_tag(event.kind()));
    w.u64(event.hlc().physical_ns());
    w.u32(event.hlc().logical());

    match event.payload() {
        Payload::Inline(bytes) => {
            w.u8(0);
            w.bytes_with_len(bytes);
        }
        Payload::BlobRef(hash) => {
            w.u8(1);
            w.fixed_bytes(hash.as_bytes());
        }
        Payload::None => {
            w.u8(2);
        }
    }

    match event.result() {
        EventResult::Ok(v) => {
            w.u8(0);
            w.i64(*v);
        }
        EventResult::Err { retval, errno } => {
            w.u8(1);
            w.i64(*retval);
            w.i32(*errno);
        }
        EventResult::Status(v) => {
            w.u8(2);
            w.i32(*v);
        }
        EventResult::None => {
            w.u8(3);
        }
    }

    w.buf
}

/// Decode a single `Event` previously produced by `encode_event`.
pub fn decode_event(buf: &[u8]) -> Result<Event, CodecError> {
    let mut r = ByteReader::new(buf);

    let version = r.u8()?;
    if version != CODEC_VERSION {
        return Err(CodecError::UnsupportedVersion {
            found: version,
            supported: CODEC_VERSION,
        });
    }

    let host_id = HostId::from_raw(r.u128()?);
    let pid = r.u32()?;
    let tid = r.u32()?;
    let seq = r.u64()?;
    let id = EventId::new(host_id, pid, tid, seq);

    let session_id = SessionId::from_raw(r.u128()?);
    let kind = kind_from_tag(r.u8()?)?;
    let physical_ns = r.u64()?;
    let logical = r.u32()?;
    let hlc = HlcTimestamp::new(physical_ns, logical);

    let payload_tag = r.u8()?;
    let payload = match payload_tag {
        0 => Payload::Inline(r.bytes_with_len()?),
        1 => {
            let bytes = r.fixed_bytes(32)?;
            let arr: [u8; 32] = bytes.try_into().expect("fixed_bytes(32) guarantees length");
            Payload::BlobRef(ContentHash::from_bytes(arr))
        }
        2 => Payload::None,
        other => return Err(CodecError::InvalidPayloadTag(other)),
    };

    let result_tag = r.u8()?;
    let result = match result_tag {
        0 => EventResult::Ok(r.i64()?),
        1 => {
            let retval = r.i64()?;
            let errno = r.i32()?;
            EventResult::Err { retval, errno }
        }
        2 => EventResult::Status(r.i32()?),
        3 => EventResult::None,
        other => return Err(CodecError::InvalidEventResultTag(other)),
    };

    Ok(Event::new(id, session_id, kind, hlc, payload, result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: EventKind, payload: Payload, result: EventResult) -> Event {
        let id = EventId::new(HostId::from_raw(0xAB), 10, 20, 30);
        Event::new(
            id,
            SessionId::from_raw(0xCD),
            kind,
            HlcTimestamp::new(123_456, 7),
            payload,
            result,
        )
    }

    #[test]
    fn round_trip_inline_payload() {
        let ev = sample(
            EventKind::Syscall,
            Payload::Inline(vec![1, 2, 3, 4]),
            EventResult::Ok(0),
        );
        let encoded = encode_event(&ev);
        let decoded = decode_event(&encoded).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn round_trip_blob_ref_payload() {
        let ev = sample(
            EventKind::NetIo,
            Payload::BlobRef(ContentHash::from_bytes([9u8; 32])),
            EventResult::Ok(1),
        );
        let encoded = encode_event(&ev);
        let decoded = decode_event(&encoded).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn round_trip_none_payload() {
        let ev = sample(EventKind::ClockRead, Payload::None, EventResult::None);
        let encoded = encode_event(&ev);
        let decoded = decode_event(&encoded).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn round_trip_err_result() {
        let ev = sample(
            EventKind::Syscall,
            Payload::None,
            EventResult::Err {
                retval: -1,
                errno: 11,
            },
        );
        let encoded = encode_event(&ev);
        let decoded = decode_event(&encoded).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn round_trip_status_result() {
        let ev = sample(
            EventKind::Syscall,
            Payload::None,
            EventResult::Status(-1073741819),
        );
        let encoded = encode_event(&ev);
        let decoded = decode_event(&encoded).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn round_trip_all_event_kinds() {
        let kinds = [
            EventKind::Syscall,
            EventKind::Sched,
            EventKind::Signal,
            EventKind::NetIo,
            EventKind::ClockRead,
            EventKind::RngRead,
            EventKind::MemRace,
            EventKind::EnvRead,
        ];
        for kind in kinds {
            let ev = sample(kind, Payload::None, EventResult::Ok(0));
            let decoded = decode_event(&encode_event(&ev)).unwrap();
            assert_eq!(ev.kind(), decoded.kind());
        }
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let ev = sample(
            EventKind::Syscall,
            Payload::Inline(vec![1, 2, 3]),
            EventResult::Ok(0),
        );
        let mut encoded = encode_event(&ev);
        encoded.truncate(encoded.len() - 2);
        assert!(matches!(
            decode_event(&encoded),
            Err(CodecError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let ev = sample(EventKind::Syscall, Payload::None, EventResult::Ok(0));
        let mut encoded = encode_event(&ev);
        encoded[0] = 99;
        assert_eq!(
            decode_event(&encoded),
            Err(CodecError::UnsupportedVersion {
                found: 99,
                supported: CODEC_VERSION
            })
        );
    }

    #[test]
    fn decode_rejects_invalid_event_kind_tag() {
        let ev = sample(EventKind::Syscall, Payload::None, EventResult::Ok(0));
        let mut encoded = encode_event(&ev);
        // Byte layout: version(1) + host_id(16) + pid(4) + tid(4) + seq(8)
        // + session_id(16) = offset 49 is the kind tag byte.
        let kind_offset = 1 + 16 + 4 + 4 + 8 + 16;
        encoded[kind_offset] = 200;
        assert_eq!(
            decode_event(&encoded),
            Err(CodecError::InvalidEventKindTag(200))
        );
    }
}
