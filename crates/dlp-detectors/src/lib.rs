//! NLP-backed detectors (Presidio pattern/checksum recognizers, no statistical models). They talk to the Python
//! companion service over a loopback HTTP keep-alive connection pool.
pub mod nlp;
pub use nlp::*;
