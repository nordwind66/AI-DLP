//! NLP-backed detectors (Presidio, GLiNER). They talk to the Python companion service over a
//! loopback HTTP keep-alive connection pool; models stay resident in that service.
pub mod nlp;
pub use nlp::*;
