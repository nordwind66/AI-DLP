//! Stateful SSE stream scanning.
//!
//! * [`sse`]     – incremental SSE parser/encoder (CRLF/LF/CR, multi-line data, comments, UTF-8 split
//!                 across chunks, size limits).
//! * [`format`]  – adapters that find text deltas in OpenAI chat / OpenAI Responses / Anthropic /
//!                 plain streams and rewrite them without touching any other field.
//! * [`scanner`] – strict (buffer everything, verdict first) and window (provable hold-back) modes.
pub mod format;
pub mod scanner;
pub mod sse;

pub use format::*;
pub use scanner::*;
pub use sse::*;
