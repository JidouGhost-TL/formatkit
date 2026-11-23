//! Reusable bounded compression and image codecs; no platform catalog or envelope policy.
//!
//! # Choosing an LZSS / sliding-window primitive
//! - [`okumura`]: classic 4096-byte pre-filled ring-buffer LZSS (Okumura `LZSS.C` variants with
//!   LSB-first or MSB-first flag bytes).
//! - [`flag_lzss`]: parameterized flag-byte / flag-word LZSS executor for custom match-token
//!   grammars, flag polarities, and linear sliding-window history.
//! - [`counted_lsb`]: externally counted commands with lazy interleaved LSB-first control bytes.
//! - [`sliding_window`]: low-level linear [`append_match`], [`find_longest_match`], and
//!   [`RingBuffer`] building blocks when you own the entire control loop.
//!
//! # Other codecs
//! - **Stream compression**: [`deflate`], [`mod@inflate`], [`gzip`], [`lzma`], [`rnc`], [`huffman`],
//!   [`rle`], [`delta`].
//! - **Image containers**: [`png`], [`pcx`], [`tga`], and optional [`dds`] (feature `dds`).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
/// Raw DEFLATE and zlib compression.
pub mod deflate;
pub use deflate::*;
/// Bounded raw DEFLATE and zlib decompression.
pub mod inflate;
pub use inflate::*;
/// Bounded gzip stream decompression and compression.
pub mod gzip;
pub use gzip::*;
/// Bounded LZMA / LZMA2 stream decompression.
pub mod lzma;
pub use lzma::*;
/// Okumura 4096-byte ring-buffer LZSS decompression and compression.
#[doc(alias = "lzss")]
#[doc(alias = "ring-buffer")]
pub mod okumura;
pub use okumura::*;
/// RNC (Rob Northen Compression) method 1 and method 2 decompression.
pub mod rnc;
pub use rnc::*;

/// Externally counted LZ commands with lazy interleaved LSB-first control bytes.
#[doc(alias = "lz")]
#[doc(alias = "lzss")]
pub mod counted_lsb;
/// DirectDraw Surface (DDS) container decoding, encoding, and rect patching.
#[cfg(feature = "dds")]
pub mod dds;
#[cfg(feature = "dds")]
pub use dds::{
    encode_dds_level, encode_dds_like, patch_dds_rects, Dds, DdsFormat, DdsPatch, DdsPatchLevel,
    DdsRect, DDS_ENCODER_ID,
};
/// Allocation-free byte and 16-bit delta encoding and decoding.
pub mod delta;
pub use delta::{
    delta_decode_u16_be_into, delta_decode_u16_le_into, delta_decode_u8_into,
    delta_encode_u16_be_into, delta_encode_u16_le_into, delta_encode_u8_into,
};
/// Parameterized flag-byte / flag-word LZSS stream executor.
#[doc(alias = "lzss")]
pub mod flag_lzss;
/// Canonical Huffman code-length construction and table decoding.
pub mod huffman;
pub use huffman::{
    build_code_lengths, CanonicalCode, CanonicalHuffmanTable, HuffmanBitOrder,
    MAX_HUFFMAN_CODE_BITS,
};
/// PCX image decoding and indexed/RGBA encoding.
pub mod pcx;
pub use pcx::{decode_pcx_rgba, encode_pcx_indexed, encode_pcx_rgba};
/// PNG image decoding and RGBA encoding.
pub mod png;
pub use png::{decode_png_rgba, encode_rgba_png};
/// Configurable high-bit run-length encoding (RLE) and decoding.
pub mod rle;
pub use rle::{decode_high_bit_rle, encode_high_bit_rle, HighBitRleConfig};
/// Bounded sliding-window match copying, longest-match search, and ring buffer.
pub mod sliding_window;
pub use sliding_window::{append_match, find_longest_match, MatchError, RingBuffer};
/// TGA (Truevision TARGA) image decoding and indexed/RGBA encoding.
pub mod tga;
pub use tga::{
    decode_tga_rgba, encode_tga_indexed, encode_tga_rgba, has_tga_footer, TgaEncoding, TgaHeader,
    TgaOrigin, TGA_FOOTER_SIGNATURE,
};
