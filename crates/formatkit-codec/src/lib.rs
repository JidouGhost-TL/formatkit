//! Reusable bounded compression codecs; no platform catalog or envelope policy.
#![forbid(unsafe_code)]

/// Bytes decoded from one framed stream and the exact number of source bytes
/// consumed by that stream.
///
/// Containers use `consumed` to distinguish codec bytes from a following
/// stream or carrier padding. Format-specific callers remain responsible for
/// deciding whether trailing bytes are permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeOutcome {
    /// Decoded bytes produced by the stream.
    pub bytes: Vec<u8>,
    /// Source bytes consumed through the stream's terminating token or frame.
    pub consumed: usize,
}
pub mod deflate;
pub use deflate::*;
pub mod inflate;
pub use inflate::*;
pub mod gzip;
pub use gzip::*;
pub mod lzma;
pub use lzma::*;
pub mod okumura;
pub use okumura::*;
pub mod rnc;
pub use rnc::*;
