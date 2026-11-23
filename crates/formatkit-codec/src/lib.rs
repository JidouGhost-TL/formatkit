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

pub mod counted_lsb;
pub mod dds;
pub use dds::{
    encode_dds_level, encode_dds_like, patch_dds_rects, Dds, DdsFormat, DdsPatch, DdsPatchLevel,
    DdsRect, DDS_ENCODER_ID,
};
pub mod delta;
pub use delta::{
    delta_decode_u16_be_into, delta_decode_u16_le_into, delta_decode_u8_into,
    delta_encode_u16_be_into, delta_encode_u16_le_into, delta_encode_u8_into,
};
pub mod flag_lzss;
pub mod huffman;
pub use huffman::{
    build_code_lengths, CanonicalCode, CanonicalHuffmanTable, HuffmanBitOrder,
    MAX_HUFFMAN_CODE_BITS,
};
pub mod pcx;
pub use pcx::{decode_pcx_rgba, encode_pcx_indexed, encode_pcx_rgba};
pub mod png;
pub use png::{decode_png_rgba, encode_rgba_png};
pub mod rle;
pub use rle::{decode_high_bit_rle, encode_high_bit_rle, HighBitRleConfig};
pub mod sliding_window;
pub use sliding_window::find_longest_match;
pub mod tga;
pub use tga::{
    decode_tga_rgba, encode_tga_indexed, encode_tga_rgba, has_tga_footer, TgaEncoding, TgaHeader,
    TgaOrigin, TGA_FOOTER_SIGNATURE,
};
