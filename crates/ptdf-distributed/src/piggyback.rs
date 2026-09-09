//! HLC piggyback wire format (architecture §15): "cross-host causality
//! ... is captured by piggybacking the sender's HLC value on the recorded
//! network payload; the receiver's `NetIo` recv event records the
//! piggybacked value, giving a happens-before edge without a
//! synchronization protocol."
//!
//! This is deliberately a tiny, dependency-free, fixed-width binary format
//! (12 bytes: 8-byte physical_ns + 4-byte logical, both little-endian) —
//! it needs to be cheap enough to prepend to *every* outgoing recorded
//! network payload without materially changing the payload's size profile,
//! and it needs to be readable by a receiver running a different build of
//! PTDF than the sender in a rolling multi-host deployment, which a
//! hand-rolled fixed format guarantees more simply than a generic
//! serializer would.

use ptdf_types::HlcTimestamp;
use thiserror::Error;

pub const PIGGYBACK_LEN: usize = 12;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PiggybackError {
    #[error("payload too short to contain an HLC piggyback: need at least {PIGGYBACK_LEN} bytes, got {0}")]
    TooShort(usize),
}

/// Prepend a sender-side HLC timestamp to `payload`, producing the bytes
/// that should actually go out on the wire (e.g. what a Linux replay
/// injector or a future network-payload-capturing recorder would pass to
/// `sendto`/write into the socket buffer).
pub fn encode(hlc: HlcTimestamp, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PIGGYBACK_LEN + payload.len());
    out.extend_from_slice(&hlc.physical_ns().to_le_bytes());
    out.extend_from_slice(&hlc.logical().to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Split a received wire payload back into the sender's HLC timestamp and
/// the original application payload. This is what a `NetIo` recv-side
/// recorder calls before feeding the sender's timestamp into
/// `HlcGenerator::receive` (see crate-level docs and `sync.rs`).
pub fn decode(wire_bytes: &[u8]) -> Result<(HlcTimestamp, &[u8]), PiggybackError> {
    if wire_bytes.len() < PIGGYBACK_LEN {
        return Err(PiggybackError::TooShort(wire_bytes.len()));
    }
    let physical_ns = u64::from_le_bytes(wire_bytes[0..8].try_into().unwrap());
    let logical = u32::from_le_bytes(wire_bytes[8..12].try_into().unwrap());
    let hlc = HlcTimestamp::new(physical_ns, logical);
    Ok((hlc, &wire_bytes[PIGGYBACK_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_hlc_and_payload() {
        let hlc = HlcTimestamp::new(123_456_789, 7);
        let payload = b"application data";
        let wire = encode(hlc, payload);

        let (decoded_hlc, decoded_payload) = decode(&wire).unwrap();
        assert_eq!(decoded_hlc, hlc);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn round_trip_with_empty_payload() {
        let hlc = HlcTimestamp::new(1, 0);
        let wire = encode(hlc, &[]);
        assert_eq!(wire.len(), PIGGYBACK_LEN);
        let (decoded_hlc, decoded_payload) = decode(&wire).unwrap();
        assert_eq!(decoded_hlc, hlc);
        assert!(decoded_payload.is_empty());
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let hlc = HlcTimestamp::new(1, 0);
        let wire = encode(hlc, b"data");
        let truncated = &wire[..PIGGYBACK_LEN - 1];
        assert_eq!(
            decode(truncated),
            Err(PiggybackError::TooShort(PIGGYBACK_LEN - 1))
        );
    }

    #[test]
    fn encoded_length_is_header_plus_payload() {
        let hlc = HlcTimestamp::new(1, 0);
        let payload = vec![0u8; 100];
        let wire = encode(hlc, &payload);
        assert_eq!(wire.len(), PIGGYBACK_LEN + 100);
    }
}
