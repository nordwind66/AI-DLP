//! dlp-engine: the facade that wires rules, NLP detectors, policy, vault, executor, protocol and
//! stream scanning into one thread-safe `DlpEngine`. This is what the server, CLI and C ABI call.
pub mod api;
mod engine;
mod gate;
pub mod protocol_scan;

pub use api::*;
pub use engine::*;
mod stream_adapter;
pub use stream_adapter::*;
pub mod api_json;
