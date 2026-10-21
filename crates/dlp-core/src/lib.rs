//! dlp-core: shared data model, the `Detector` trait, offset utilities and the
//! multi-detector result merger. Everything that crosses a crate boundary lives here.
//!
//! Offsets: all native offsets are **UTF-8 byte offsets** into the exact text that was
//! scanned. The API layer converts to Unicode code point offsets with [`OffsetMap`].

pub mod detector;
pub mod merge;
pub mod offsets;
pub mod types;

pub use detector::*;
pub use merge::*;
pub use offsets::*;
pub use types::*;
