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
//! - **Tagged-header stream family** (one tag byte + 24-bit size, see [`tagged_header`]):
//!   [`tagged_lz77`] (compact and extended-length LZ77), [`tagged_huffman`] (packed-tree
//!   4/8-bit Huffman), [`rle::decode_tagged_rle`], and [`delta::decode_tagged_delta`].
//! - **Audio**: [`ima_adpcm`] (IMA ADPCM 4-bit codes) and [`smf`] (Standard MIDI File writer).
//! - **Bit-depth widening**: [`mod@bit_unpack`].
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

/// Bit-depth widening of packed 1/2/4/8-bit units with a conditional offset.
#[doc(alias = "bitunpack")]
pub mod bit_unpack;
pub use bit_unpack::{bit_unpack, BitUnpackConfig};
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
/// Allocation-free byte and 16-bit delta encoding and decoding, plus tagged-header framing.
#[doc(alias = "diff")]
#[doc(alias = "delta filter")]
pub mod delta;
pub use delta::{
    decode_tagged_delta, delta_decode_u16_be_into, delta_decode_u16_le_into, delta_decode_u8_into,
    delta_encode_u16_be_into, delta_encode_u16_le_into, delta_encode_u8_into, encode_tagged_delta,
    TaggedDeltaWidth,
};
/// IMA ADPCM 4-bit audio codes: reference tables, state, block headers, and exact re-encoding.
#[doc(alias = "adpcm")]
#[doc(alias = "ima")]
#[doc(alias = "dvi adpcm")]
pub mod ima_adpcm;
pub use ima_adpcm::{
    decode_ima_adpcm_block, decode_ima_adpcm_codes, encode_ima_adpcm_block, encode_ima_adpcm_codes,
    encode_ima_adpcm_codes_exact, encode_ima_adpcm_codes_nearest, ImaAdpcmHeader, ImaAdpcmState,
    ImaHeaderSample, ImaNibbleOrder, IMA_INDEX_TABLE, IMA_MAX_STEP_INDEX, IMA_STEP_TABLE,
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
pub use png::{
    decode_png_rgba, encode_rgba_png, encode_rgba_png_with, PngCompression, PngEncodeOptions,
    PngFilter,
};
/// Configurable high-bit run-length encoding (RLE) and decoding, plus tagged-header framing.
pub mod rle;
pub use rle::{
    decode_high_bit_rle, decode_tagged_rle, encode_high_bit_rle, encode_tagged_rle,
    HighBitRleConfig,
};
/// Bounded sliding-window match copying, longest-match search, and ring buffer.
pub mod sliding_window;
pub use sliding_window::{append_match, find_longest_match, MatchError, RingBuffer};
/// Standard MIDI File (SMF) format 0/1 writer with meta events and running status.
#[doc(alias = "midi")]
#[doc(alias = "mid")]
#[doc(alias = "standard midi file")]
pub mod smf;
pub use smf::{
    read_smf_vlq, write_smf, write_smf_vlq, SmfDivision, SmfEvent, SmfFormat, SmfTextKind,
    SmfTimedEvent, SmfTrack, SmfWriteOptions, SMF_MAX_VLQ,
};
/// Tag byte + 24-bit little-endian size stream headers (with 32-bit extended form).
pub mod tagged_header;
pub use tagged_header::{
    read_tagged_header, read_tagged_header_extended, write_tagged_header,
    write_tagged_header_extended, TaggedHeader, MAX_TAGGED_SIZE, TAGGED_HEADER_EXTENDED_LEN,
    TAGGED_HEADER_LEN,
};
/// Tagged-header packed-tree Huffman streams with 4-bit or 8-bit symbols.
#[doc(alias = "huff")]
pub mod tagged_huffman;
pub use tagged_huffman::{decode_tagged_huffman, encode_tagged_huffman, TaggedHuffmanWidth};
/// Tagged-header LZ77 streams (compact 2-byte tokens and extended-length tokens).
#[doc(alias = "lz77")]
#[doc(alias = "lz10")]
#[doc(alias = "lz11")]
#[doc(alias = "lzss")]
pub mod tagged_lz77;
pub use tagged_lz77::{
    decode_tagged_lz77, decode_tagged_lz77_extended, encode_tagged_lz77,
    encode_tagged_lz77_extended, encode_tagged_lz77_with_min_distance,
};
/// TGA (Truevision TARGA) image decoding and indexed/RGBA encoding.
pub mod tga;
pub use tga::{
    decode_tga_rgba, encode_tga_indexed, encode_tga_rgba, has_tga_footer, TgaEncoding, TgaHeader,
    TgaOrigin, TGA_FOOTER_SIGNATURE,
};
