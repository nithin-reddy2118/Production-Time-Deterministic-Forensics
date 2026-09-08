//! `ptdf-storage` — segment-based append-only event log (architecture §10).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod checksum;
pub mod codec;
pub mod segment;

pub use checksum::crc32;
pub use codec::{decode_event, encode_event, CodecError, CODEC_VERSION};
pub use segment::{SealedSegmentInfo, SegmentError, SegmentReader, SegmentWriter};