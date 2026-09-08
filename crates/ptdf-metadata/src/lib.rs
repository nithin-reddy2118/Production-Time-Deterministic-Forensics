//! `ptdf-metadata` — metadata/index engine (architecture §12).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod in_memory;
pub mod store;

pub use in_memory::InMemoryMetadataStore;
pub use store::{EventLocation, MetadataError, MetadataStore, SegmentRecord};
