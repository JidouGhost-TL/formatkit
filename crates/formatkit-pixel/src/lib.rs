//! Container-independent palette, packed-pixel, tile, swizzle, and block-codec mechanics.
//!
//! # Modules
//! - [`atlas`]: RGBA cropping, blitting, and grid atlas composition.
//! - [`dxt`]: S3TC / DXT1–DXT5 block decoding and arbitrary channel-mask pixel unpacking.
//! - [`glyph`]: 1bpp, 2bpp, and 4bpp packed glyph row unpacking and packing.
//! - [`morton`]: Morton (Z-order) coordinate interleaving and 2D texture swizzle/unswizzle.
//! - [`palette`]: Grayscale palettes, nearest-color lookup, and RGBA quantization.
//! - [`planar`]: Interleaved-row planar 8×8 tile unpacking and packing (1/2/4 bitplanes).
//! - [`tilemap`]: 16-bit text tilemap entries, 32×32 screen-block entry order, and 8×8
//!   indexed tile-to-RGBA blitting with palette base, flips, and index-0 transparency.
//!
//! Crate-root items provide allocation-free 4bpp/8bpp index packing, 16-bit color-word
//! conversions (`RGB565`, `BGR555`, `RGBA5551`, `RGBA4444`, `RGB444`), and explicit
//! [`NibbleOrder`], [`BitOrder`], and [`IndexPolicy`] controls.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// RGBA image cropping, blitting, and grid atlas composition.
pub mod atlas;
pub use atlas::{blit_rgba, compose_grid_atlas, crop_rgba, GridAtlasLayout};

/// S3TC / DXT1–DXT5 block decoding and arbitrary channel-mask decoding.
pub mod dxt;
pub use dxt::{decode_dxt, decode_masked, is_contiguous, rgb565_to_rgba, ChannelMasks, DxtFormat};

/// Packed 1bpp, 2bpp, and 4bpp bitmap glyph unpacking and packing.
pub mod glyph;
pub use glyph::{
    pack_glyph_1bpp, pack_glyph_2bpp, pack_glyph_4bpp, unpack_glyph_1bpp, unpack_glyph_2bpp,
    unpack_glyph_4bpp,
};

/// Morton (Z-order) coordinate interleaving and 2D texture swizzle/unswizzle.
#[doc(alias = "z-order")]
#[doc(alias = "swizzle")]
pub mod morton;
pub use morton::{morton_index, swizzle_morton, unswizzle_morton, MortonAxisOrder};

/// Palette generation, nearest-color lookup, and RGBA quantization.
pub mod palette;
pub use palette::{grayscale_palette, nearest_palette_index, quantize_rgba, PaletteDistanceMetric};

/// Interleaved-row planar 8×8 tile packing and unpacking.
#[doc(alias = "bitplane")]
#[doc(alias = "tile")]
#[doc(alias = "chr")]
pub mod planar;
pub use planar::{pack_planar_tile_8x8_into, unpack_planar_tile_8x8_into};

/// Text tilemap entries, 32×32 screen-block entry order, and 8×8 indexed tile blitting.
#[doc(alias = "screen block")]
#[doc(alias = "bg map")]
pub mod tilemap;
pub use tilemap::{
    blit_indexed_tile_8x8, decode_text_tilemap_le, encode_text_tilemap_le, IndexedTileBlit,
    ScreenBlockLayout, TextTilemapEntry,
};

/// Bits per palette index in a CLUT (paletted) image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexBits {
    /// 4-bit indices, two per byte, packed low-nibble-first.
    Four,
    /// 8-bit indices, one per byte.
    Eight,
}

/// Pixel ordering within a byte for 4-bit packed palette indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleOrder {
    /// Low nibble (`b & 0x0F`) is the first (left) pixel; high nibble (`b >> 4`) is the second.
    /// Common in little-endian 4bpp packed pixel and bitmap layouts.
    LowFirst,
    /// High nibble (`b >> 4`) is the first (left) pixel; low nibble (`b & 0x0F`) is the second.
    /// Common in big-endian and MSB-first 4bpp packed pixel layouts.
    HighFirst,
}

/// Bit ordering within a byte for 1bpp and 2bpp packed pixel rows/glyphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    /// Least-significant bit(s) hold the first (leftmost) pixel.
    LsbFirst,
    /// Most-significant bit(s) hold the first (leftmost) pixel.
    MsbFirst,
}

/// Out-of-range index handling when packing 4-bit palette indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexPolicy {
    /// Mask each index to the low 4 bits (`v & 0x0F`).
    Mask,
    /// Return [`PackError::IndexOutOfRange`] if any index exceeds `15`.
    Reject,
}

/// Error returned by allocation-free packed-index decode/encode helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackError {
    /// Output or input slice length did not match the required length.
    LengthMismatch {
        /// Required slice length in bytes or pixels.
        expected: usize,
        /// Actual slice length supplied by the caller.
        actual: usize,
    },
    /// An index exceeded the maximum allowed by the target bit depth under [`IndexPolicy::Reject`].
    IndexOutOfRange {
        /// Position of the offending index in the input slice.
        index: usize,
        /// Out-of-range index value.
        value: u8,
    },
    /// A planar tile bitplane count is not supported.
    UnsupportedPlanes {
        /// Unsupported bitplane count.
        planes: u8,
    },
    /// A layout parameter (dimension, stride, or scale) was invalid or overflowed.
    InvalidLayout {
        /// Short static description of the layout error.
        reason: &'static str,
    },
    /// A requested output buffer size exceeded an explicit caller limit.
    LimitExceeded {
        /// Requested buffer size in bytes or pixels.
        requested: usize,
        /// Caller-imposed upper bound.
        limit: usize,
    },
}

impl core::fmt::Display for PackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "packed index buffer length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::IndexOutOfRange { index, value } => {
                write!(f, "palette index out of range at pixel {index}: {value}")
            }
            Self::UnsupportedPlanes { planes } => {
                write!(f, "unsupported planar tile bitplane count: {planes}")
            }
            Self::InvalidLayout { reason } => {
                write!(f, "invalid pixel layout: {reason}")
            }
            Self::LimitExceeded { requested, limit } => {
                write!(
                    f,
                    "pixel buffer size {requested} exceeds caller limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for PackError {}

/// Unpack 4-bit palette indices directly into a caller-supplied output slice without allocation.
///
/// `out.len()` must be at most `packed.len() * 2`; typically `out.len() == packed.len() * 2`
/// (or `packed.len() * 2 - 1` for odd pixel counts).
pub fn unpack_4bpp_into(
    packed: &[u8],
    order: NibbleOrder,
    out: &mut [u8],
) -> Result<(), PackError> {
    let required_bytes = out.len().div_ceil(2);
    if packed.len() < required_bytes {
        return Err(PackError::LengthMismatch {
            expected: required_bytes,
            actual: packed.len(),
        });
    }
    let mut dst = 0;
    for &b in &packed[..required_bytes] {
        let (first, second) = match order {
            NibbleOrder::LowFirst => (b & 0x0f, b >> 4),
            NibbleOrder::HighFirst => (b >> 4, b & 0x0f),
        };
        out[dst] = first;
        dst += 1;
        if dst < out.len() {
            out[dst] = second;
            dst += 1;
        }
    }
    Ok(())
}

/// Pack 4-bit palette indices directly into a caller-supplied byte slice without allocation.
///
/// `out.len()` must equal `indices.len().div_ceil(2)`. For an odd number of input indices,
/// the trailing half-byte is padded with zero.
pub fn pack_4bpp_into(
    indices: &[u8],
    order: NibbleOrder,
    policy: IndexPolicy,
    out: &mut [u8],
) -> Result<(), PackError> {
    let expected_bytes = indices.len().div_ceil(2);
    if out.len() != expected_bytes {
        return Err(PackError::LengthMismatch {
            expected: expected_bytes,
            actual: out.len(),
        });
    }
    for (byte_idx, dst) in out.iter_mut().enumerate() {
        let i0 = byte_idx * 2;
        let raw0 = indices[i0];
        if policy == IndexPolicy::Reject && raw0 > 0x0f {
            return Err(PackError::IndexOutOfRange {
                index: i0,
                value: raw0,
            });
        }
        let n0 = raw0 & 0x0f;

        let n1 = if i0 + 1 < indices.len() {
            let raw1 = indices[i0 + 1];
            if policy == IndexPolicy::Reject && raw1 > 0x0f {
                return Err(PackError::IndexOutOfRange {
                    index: i0 + 1,
                    value: raw1,
                });
            }
            raw1 & 0x0f
        } else {
            0
        };

        *dst = match order {
            NibbleOrder::LowFirst => n0 | (n1 << 4),
            NibbleOrder::HighFirst => (n0 << 4) | n1,
        };
    }
    Ok(())
}

/// Unpack 1-bit-per-pixel data directly into `out` (`0` or `1` per pixel) without allocation.
pub fn unpack_1bpp_into(packed: &[u8], order: BitOrder, out: &mut [u8]) -> Result<(), PackError> {
    let required_bytes = out.len().div_ceil(8);
    if packed.len() < required_bytes {
        return Err(PackError::LengthMismatch {
            expected: required_bytes,
            actual: packed.len(),
        });
    }
    let mut dst = 0;
    for &b in &packed[..required_bytes] {
        for bit in 0..8 {
            if dst >= out.len() {
                break;
            }
            let shift = match order {
                BitOrder::LsbFirst => bit,
                BitOrder::MsbFirst => 7 - bit,
            };
            out[dst] = (b >> shift) & 1;
            dst += 1;
        }
    }
    Ok(())
}

/// Unpack 2-bit-per-pixel data directly into `out` (`0..=3` per pixel) without allocation.
pub fn unpack_2bpp_into(packed: &[u8], order: BitOrder, out: &mut [u8]) -> Result<(), PackError> {
    let required_bytes = out.len().div_ceil(4);
    if packed.len() < required_bytes {
        return Err(PackError::LengthMismatch {
            expected: required_bytes,
            actual: packed.len(),
        });
    }
    let mut dst = 0;
    for &b in &packed[..required_bytes] {
        for slot in 0..4 {
            if dst >= out.len() {
                break;
            }
            let shift = match order {
                BitOrder::LsbFirst => slot * 2,
                BitOrder::MsbFirst => (3 - slot) * 2,
            };
            out[dst] = (b >> shift) & 0x03;
            dst += 1;
        }
    }
    Ok(())
}

/// Pack 1-bit-per-pixel palette indices directly into `out` without allocation.
///
/// `out.len()` must equal `indices.len().div_ceil(8)`. Trailing bits in the
/// final byte are zero-padded when `indices.len()` is not a multiple of 8.
pub fn pack_1bpp_into(
    indices: &[u8],
    order: BitOrder,
    policy: IndexPolicy,
    out: &mut [u8],
) -> Result<(), PackError> {
    let expected_bytes = indices.len().div_ceil(8);
    if out.len() != expected_bytes {
        return Err(PackError::LengthMismatch {
            expected: expected_bytes,
            actual: out.len(),
        });
    }
    if policy == IndexPolicy::Reject {
        for (index, &value) in indices.iter().enumerate() {
            if value > 1 {
                return Err(PackError::IndexOutOfRange { index, value });
            }
        }
    }
    for (byte_idx, dst) in out.iter_mut().enumerate() {
        let base = byte_idx * 8;
        let mut byte = 0u8;
        for bit in 0..8 {
            if base + bit >= indices.len() {
                break;
            }
            let v = indices[base + bit] & 1;
            let shift = match order {
                BitOrder::LsbFirst => bit,
                BitOrder::MsbFirst => 7 - bit,
            };
            byte |= v << shift;
        }
        *dst = byte;
    }
    Ok(())
}

/// Pack 2-bit-per-pixel palette indices directly into `out` without allocation.
///
/// `out.len()` must equal `indices.len().div_ceil(4)`. Trailing 2-bit slots in
/// the final byte are zero-padded when `indices.len()` is not a multiple of 4.
pub fn pack_2bpp_into(
    indices: &[u8],
    order: BitOrder,
    policy: IndexPolicy,
    out: &mut [u8],
) -> Result<(), PackError> {
    let expected_bytes = indices.len().div_ceil(4);
    if out.len() != expected_bytes {
        return Err(PackError::LengthMismatch {
            expected: expected_bytes,
            actual: out.len(),
        });
    }
    if policy == IndexPolicy::Reject {
        for (index, &value) in indices.iter().enumerate() {
            if value > 0x03 {
                return Err(PackError::IndexOutOfRange { index, value });
            }
        }
    }
    for (byte_idx, dst) in out.iter_mut().enumerate() {
        let base = byte_idx * 4;
        let mut byte = 0u8;
        for slot in 0..4 {
            if base + slot >= indices.len() {
                break;
            }
            let v = indices[base + slot] & 0x03;
            let shift = match order {
                BitOrder::LsbFirst => slot * 2,
                BitOrder::MsbFirst => (3 - slot) * 2,
            };
            byte |= v << shift;
        }
        *dst = byte;
    }
    Ok(())
}

/// Extent of one dimension at a floor-halved mip level.
///
/// This is the DDS/GTF/GXT-style rule: each level shifts right and clamps to
/// one. Oversized level indices are total and therefore also produce one.
/// Formats that use ceil halving or declared per-level sizes must not use this
/// helper.
#[inline]
pub fn mip_extent(dimension: u32, level: u32) -> u32 {
    dimension.checked_shr(level).unwrap_or(0).max(1)
}

/// Append RGBA pixels selected by `indices` to an owner-provided output.
///
/// Palette storage and lookup policy remain with the format owner: the
/// callback can select a CLUT row, undo a platform-specific CLUT permutation,
/// or decode the owner's packed palette representation. This helper owns only
/// the common checked index-to-RGBA loop; output allocation and capacity policy
/// remain with the caller-provided vector.
pub fn apply_palette<E>(
    indices: impl IntoIterator<Item = usize>,
    out: &mut Vec<u8>,
    mut lookup: impl FnMut(usize) -> Result<[u8; 4], E>,
) -> Result<(), E> {
    for index in indices {
        let color = lookup(index)?;
        out.extend_from_slice(&color);
    }
    Ok(())
}

/// Unpack packed CLUT indices into one `u16` palette index per pixel, truncated
/// to `count` pixels.
///
/// 4-bit indices are packed **low-nibble-first**: the low nibble of each byte is
/// the left pixel. Any pixels a short `data` buffer can't supply are simply
/// absent from the (then shorter-than-`count`) result — the caller is expected
/// to have validated that `data` covers `count` pixels for this depth.
pub fn expand_indices(data: &[u8], bits: IndexBits, count: usize) -> Vec<u16> {
    // Pre-allocate to what the data can actually yield, capped by `count`, so a
    // caller passing a huge `count` with a tiny buffer can't drive a giant
    // allocation (the container layer bounds-checks too, but the primitive is
    // safe on its own).
    let producible = match bits {
        IndexBits::Four => data.len().saturating_mul(2),
        IndexBits::Eight => data.len(),
    };
    let mut out = Vec::with_capacity(count.min(producible));
    match bits {
        IndexBits::Four => {
            for &b in data {
                if out.len() == count {
                    break;
                }
                out.push((b & 0x0f) as u16); // low nibble = left pixel
                if out.len() < count {
                    out.push((b >> 4) as u16);
                }
            }
        }
        IndexBits::Eight => {
            for &b in data.iter().take(count) {
                out.push(b as u16);
            }
        }
    }
    out
}

/// Expand a 16-bit RGBA5650 texel to RGBA8888.
///
/// Packed channel order: red in the low 5 bits, then 6-bit green, then 5-bit blue; no
/// alpha channel (always opaque). Each channel is bit-replicated to 8 bits.
pub fn rgba5650_to_rgba(c: u16) -> [u8; 4] {
    let e5 = |v: u16| (((v << 3) | (v >> 2)) & 0xff) as u8;
    let e6 = |v: u16| (((v << 2) | (v >> 4)) & 0xff) as u8;
    [e5(c & 0x1f), e6((c >> 5) & 0x3f), e5((c >> 11) & 0x1f), 255]
}

/// Expand a 16-bit RGBA5551 texel to RGBA8888.
///
/// Packed channel order: 5-bit red/green/blue in the low bits, then a 1-bit alpha in
/// the top bit (`0` fully transparent, `1` fully opaque). RGB bit-replicated.
pub fn rgba5551_to_rgba(c: u16) -> [u8; 4] {
    let e5 = |v: u16| (((v << 3) | (v >> 2)) & 0xff) as u8;
    [
        e5(c & 0x1f),
        e5((c >> 5) & 0x1f),
        e5((c >> 10) & 0x1f),
        if (c >> 15) & 1 == 1 { 255 } else { 0 },
    ]
}

/// Expand a 16-bit RGBA4444 texel to RGBA8888.
///
/// Packed channel order: 4 bits each of red, green, blue, alpha, red in the low nibble.
/// Each nibble is replicated to 8 bits (`v * 0x11`).
pub fn rgba4444_to_rgba(c: u16) -> [u8; 4] {
    let nib = |v: u16| (((v << 4) | v) & 0xff) as u8;
    [
        nib(c & 0xf),
        nib((c >> 4) & 0xf),
        nib((c >> 8) & 0xf),
        nib((c >> 12) & 0xf),
    ]
}

/// Alpha derivation policy for 15-bit BGR555 color words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alpha555Policy {
    /// Every pixel is fully opaque (`0xFF`).
    Opaque,
    /// Word `0x0000` is fully transparent (`0x00`); all other words are opaque (`0xFF`).
    ZeroIsTransparent,
    /// Bit 15 selects alpha: `1` is fully opaque (`0xFF`), `0` is fully transparent (`0x00`).
    TopBitAlpha,
}

/// Pack 8-bit RGB channels into a 15-bit BGR555 word (bit 15 cleared).
///
/// Packed channel order: 5-bit red in bits `0..5`, 5-bit green in bits `5..10`,
/// and 5-bit blue in bits `10..15`. Each channel is quantized via `c >> 3`.
#[inline]
pub fn rgb8_to_bgr555(r: u8, g: u8, b: u8) -> u16 {
    u16::from(r >> 3) | (u16::from(g >> 3) << 5) | (u16::from(b >> 3) << 10)
}

/// Pack an RGBA8888 pixel into a 16-bit BGR555 word using the given [`Alpha555Policy`].
///
/// - [`Alpha555Policy::Opaque`]: leaves bit 15 cleared (`0`).
/// - [`Alpha555Policy::TopBitAlpha`]: sets bit 15 (`0x8000`) when `rgba[3] >= 0x80`.
/// - [`Alpha555Policy::ZeroIsTransparent`]: returns `0x0000` when `rgba[3] < 0x80`;
///   otherwise packs RGB with bit 15 cleared.
#[inline]
pub fn rgba8_to_bgr555(rgba: [u8; 4], alpha: Alpha555Policy) -> u16 {
    let rgb = rgb8_to_bgr555(rgba[0], rgba[1], rgba[2]);
    match alpha {
        Alpha555Policy::Opaque => rgb,
        Alpha555Policy::TopBitAlpha => {
            if rgba[3] >= 0x80 {
                rgb | 0x8000
            } else {
                rgb
            }
        }
        Alpha555Policy::ZeroIsTransparent => {
            if rgba[3] < 0x80 {
                0
            } else {
                rgb
            }
        }
    }
}

/// Expand a 16-bit BGR555 word to RGBA8888 using the given [`Alpha555Policy`].
///
/// Packed channel order: 5-bit red in bits `0..5`, 5-bit green in bits `5..10`,
/// 5-bit blue in bits `10..15`, and optional alpha/flag bit in bit `15`.
/// Each 5-bit channel is bit-replicated to 8 bits.
pub fn bgr555_to_rgba(c: u16, alpha: Alpha555Policy) -> [u8; 4] {
    let e5 = |v: u16| (((v << 3) | (v >> 2)) & 0xff) as u8;
    let a = match alpha {
        Alpha555Policy::Opaque => 255,
        Alpha555Policy::ZeroIsTransparent => {
            if c == 0 {
                0
            } else {
                255
            }
        }
        Alpha555Policy::TopBitAlpha => {
            if (c & 0x8000) != 0 {
                255
            } else {
                0
            }
        }
    };
    [e5(c & 0x1f), e5((c >> 5) & 0x1f), e5((c >> 10) & 0x1f), a]
}

/// Decode little-endian 16-bit BGR555 words into a caller-supplied RGBA8888 byte buffer.
///
/// `bytes.len()` must be even, and `out.len()` must equal `(bytes.len() / 2) * 4`.
pub fn bgr555_le_words_to_rgba(
    bytes: &[u8],
    alpha: Alpha555Policy,
    out: &mut [u8],
) -> Result<(), PackError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(PackError::LengthMismatch {
            expected: bytes.len() + 1,
            actual: bytes.len(),
        });
    }
    let expected_out = (bytes.len() / 2).saturating_mul(4);
    if out.len() != expected_out {
        return Err(PackError::LengthMismatch {
            expected: expected_out,
            actual: out.len(),
        });
    }
    for (src, dst) in bytes.chunks_exact(2).zip(out.chunks_exact_mut(4)) {
        let word = u16::from_le_bytes([src[0], src[1]]);
        dst.copy_from_slice(&bgr555_to_rgba(word, alpha));
    }
    Ok(())
}

/// Expand a 12-bit RGB444 word (`0x0RGB`) to opaque RGBA8888.
///
/// Packed channel order: 4-bit red in bits `8..12`, 4-bit green in bits `4..8`,
/// 4-bit blue in bits `0..4`. Each nibble is replicated to 8 bits (`v * 0x11`).
pub fn rgb444_to_rgba(c: u16) -> [u8; 4] {
    let nib = |v: u16| (((v << 4) | v) & 0xff) as u8;
    [nib((c >> 8) & 0xf), nib((c >> 4) & 0xf), nib(c & 0xf), 0xff]
}

/// Expand a 12-bit BGR444 word (`0x0BGR`) to opaque RGBA8888.
///
/// Packed channel order: 4-bit red in bits `0..4`, 4-bit green in bits `4..8`,
/// 4-bit blue in bits `8..12`. Each nibble is replicated to 8 bits (`v * 0x11`).
pub fn bgr444_to_rgba(c: u16) -> [u8; 4] {
    let nib = |v: u16| (((v << 4) | v) & 0xff) as u8;
    [nib(c & 0xf), nib((c >> 4) & 0xf), nib((c >> 8) & 0xf), 0xff]
}

/// Pack an RGBA8888 pixel into a 16-bit RGB565 word (`0bRRRRR_GGGGGG_BBBBB`).
///
/// Inverse of [`rgb565_to_rgba`]: red occupies the high 5 bits, green occupies
/// the middle 6 bits, and blue occupies the low 5 bits. Alpha is ignored.
#[inline]
pub fn rgba8_to_rgb565(rgba: [u8; 4]) -> u16 {
    (u16::from(rgba[0] >> 3) << 11) | (u16::from(rgba[1] >> 2) << 5) | u16::from(rgba[2] >> 3)
}

/// Pack an RGBA8888 pixel into a 16-bit RGBA5650 word (`0bBBBBB_GGGGGG_RRRRR`).
///
/// Inverse of [`rgba5650_to_rgba`]: red occupies the low 5 bits, green occupies
/// the middle 6 bits, and blue occupies the high 5 bits. Alpha is ignored.
#[inline]
pub fn rgba8_to_rgba5650(rgba: [u8; 4]) -> u16 {
    u16::from(rgba[0] >> 3) | (u16::from(rgba[1] >> 2) << 5) | (u16::from(rgba[2] >> 3) << 11)
}

/// Pack an RGBA8888 pixel into a 16-bit RGBA5551 word.
///
/// Inverse of [`rgba5551_to_rgba`]: 5-bit red/green/blue in bits `0..15`, and
/// 1-bit alpha in bit `15` (`1` when `rgba[3] >= 0x80`, else `0`).
#[inline]
pub fn rgba8_to_rgba5551(rgba: [u8; 4]) -> u16 {
    u16::from(rgba[0] >> 3)
        | (u16::from(rgba[1] >> 3) << 5)
        | (u16::from(rgba[2] >> 3) << 10)
        | if rgba[3] >= 0x80 { 0x8000 } else { 0 }
}

/// Pack an RGBA8888 pixel into a 16-bit RGBA4444 word.
///
/// Inverse of [`rgba4444_to_rgba`]: 4 bits each of red, green, blue, and alpha,
/// with red in the low nibble.
#[inline]
pub fn rgba8_to_rgba4444(rgba: [u8; 4]) -> u16 {
    u16::from(rgba[0] >> 4)
        | (u16::from(rgba[1] >> 4) << 4)
        | (u16::from(rgba[2] >> 4) << 8)
        | (u16::from(rgba[3] >> 4) << 12)
}

/// Pack 8-bit RGB channels into a 12-bit RGB444 word (`0x0RGB`).
///
/// Inverse of [`rgb444_to_rgba`]: 4-bit red in bits `8..12`, green in `4..8`,
/// and blue in `0..4`.
#[inline]
pub fn rgb8_to_rgb444(r: u8, g: u8, b: u8) -> u16 {
    (u16::from(r >> 4) << 8) | (u16::from(g >> 4) << 4) | u16::from(b >> 4)
}

/// Pack 8-bit RGB channels into a 12-bit BGR444 word (`0x0BGR`).
///
/// Inverse of [`bgr444_to_rgba`]: 4-bit red in bits `0..4`, green in `4..8`,
/// and blue in `8..12`.
#[inline]
pub fn rgb8_to_bgr444(r: u8, g: u8, b: u8) -> u16 {
    u16::from(r >> 4) | (u16::from(g >> 4) << 4) | (u16::from(b >> 4) << 8)
}

/// Encode RGBA8888 pixels into little-endian 16-bit BGR555 words in `out`.
///
/// Inverse of [`bgr555_le_words_to_rgba`]. `rgba.len()` must be a multiple of
/// `4`, and `out.len()` must equal `(rgba.len() / 4) * 2`.
pub fn rgba_to_bgr555_le_words(
    rgba: &[u8],
    alpha: Alpha555Policy,
    out: &mut [u8],
) -> Result<(), PackError> {
    if !rgba.len().is_multiple_of(4) {
        return Err(PackError::LengthMismatch {
            expected: rgba.len() + (4 - rgba.len() % 4),
            actual: rgba.len(),
        });
    }
    let expected_out = (rgba.len() / 4).saturating_mul(2);
    if out.len() != expected_out {
        return Err(PackError::LengthMismatch {
            expected: expected_out,
            actual: out.len(),
        });
    }
    for (src, dst) in rgba.chunks_exact(4).zip(out.chunks_exact_mut(2)) {
        let word = rgba8_to_bgr555([src[0], src[1], src[2], src[3]], alpha);
        dst.copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_mip_extent_is_total_and_distinct_from_ceil_halving() {
        assert_eq!(mip_extent(0, 0), 1);
        assert_eq!(mip_extent(1, 0), 1);
        assert_eq!(mip_extent(4, 0), 4);
        assert_eq!(mip_extent(4, 1), 2);
        assert_eq!(mip_extent(4, 2), 1);
        assert_eq!(mip_extent(4, 3), 1);
        assert_eq!(mip_extent(3, 1), 1, "ceil-halving would be 2");
        assert_eq!(mip_extent(u32::MAX, 31), 1);
        assert_eq!(mip_extent(u32::MAX, 32), 1);
        assert_eq!(mip_extent(u32::MAX, u32::MAX), 1);
    }

    #[test]
    fn four_bit_unpacks_low_nibble_first() {
        // 0x21 -> [1, 2]; 0x8F -> [0xF, 8].
        let out = expand_indices(&[0x21, 0x8F], IndexBits::Four, 4);
        assert_eq!(out, vec![1, 2, 0xF, 8]);
    }

    #[test]
    fn eight_bit_is_one_index_per_byte() {
        let out = expand_indices(&[0, 5, 255, 128], IndexBits::Eight, 4);
        assert_eq!(out, vec![0, 5, 255, 128]);
    }

    #[test]
    fn truncates_to_count() {
        assert_eq!(
            expand_indices(&[0x21, 0x43], IndexBits::Four, 3),
            vec![1, 2, 3]
        );
        assert_eq!(
            expand_indices(&[1, 2, 3, 4], IndexBits::Eight, 2),
            vec![1, 2]
        );
    }

    #[test]
    fn huge_count_tiny_buffer_does_not_over_allocate() {
        // 4-bit: one byte yields at most two indices, regardless of count.
        let out = expand_indices(&[0xAB], IndexBits::Four, usize::MAX);
        assert_eq!(out, vec![0xB, 0xA]);
    }

    #[test]
    fn tiny_count_large_buffer_bounds_work_and_capacity() {
        let data = vec![0x21; 1024 * 1024];
        for bits in [IndexBits::Four, IndexBits::Eight] {
            let empty = expand_indices(&data, bits, 0);
            assert!(empty.is_empty());
            assert_eq!(empty.capacity(), 0);

            let one = expand_indices(&data, bits, 1);
            assert_eq!(
                one,
                vec![match bits {
                    IndexBits::Four => 1,
                    IndexBits::Eight => 0x21,
                }]
            );
            assert!(one.capacity() < data.len());
        }
    }

    #[test]
    fn palette_application_uses_caller_output_and_reports_the_bad_index() {
        let palette = [[1, 2, 3, 4], [5, 6, 7, 8]];
        let mut rgba = Vec::with_capacity(12);
        apply_palette([1, 0, 1], &mut rgba, |index| {
            palette.get(index).copied().ok_or(index)
        })
        .unwrap();
        assert_eq!(rgba, [5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);

        let before = rgba.len();
        let error = apply_palette([0, 2], &mut rgba, |index| {
            palette.get(index).copied().ok_or(index)
        })
        .unwrap_err();
        assert_eq!(error, 2);
        assert_eq!(rgba.len(), before + 4);
    }

    #[test]
    fn rgba5650_pure_channels_are_opaque() {
        assert_eq!(rgba5650_to_rgba(0x001F), [255, 0, 0, 255]); // red = low 5 bits
        assert_eq!(rgba5650_to_rgba(0x07E0), [0, 255, 0, 255]); // green = 6 bits
        assert_eq!(rgba5650_to_rgba(0xF800), [0, 0, 255, 255]); // blue = high 5 bits
    }

    #[test]
    fn rgba5551_reads_the_top_alpha_bit() {
        assert_eq!(rgba5551_to_rgba(0x001F), [255, 0, 0, 0]); // red, alpha off
        assert_eq!(rgba5551_to_rgba(0x801F), [255, 0, 0, 255]); // red, alpha on
        assert_eq!(rgba5551_to_rgba(0x8000), [0, 0, 0, 255]); // alpha only
        assert_eq!(rgba5551_to_rgba(0x03E0), [0, 255, 0, 0]); // green
        assert_eq!(rgba5551_to_rgba(0x7C00), [0, 0, 255, 0]); // blue
    }

    #[test]
    fn rgba4444_replicates_each_nibble() {
        assert_eq!(rgba4444_to_rgba(0x000F), [255, 0, 0, 0]); // red nibble
        assert_eq!(rgba4444_to_rgba(0xF000), [0, 0, 0, 255]); // alpha nibble
        assert_eq!(rgba4444_to_rgba(0xFFFF), [255, 255, 255, 255]);
        assert_eq!(rgba4444_to_rgba(0x0080), [0, 0x88, 0, 0]); // green nibble = 8 -> 0x88
    }

    #[test]
    fn unpack_and_pack_4bpp_low_and_high_first() {
        let mut pixels = [0u8; 4];
        unpack_4bpp_into(&[0x21, 0x8F], NibbleOrder::LowFirst, &mut pixels).unwrap();
        assert_eq!(pixels, [1, 2, 0xF, 8]);

        let mut repacked = [0u8; 2];
        pack_4bpp_into(
            &pixels,
            NibbleOrder::LowFirst,
            IndexPolicy::Reject,
            &mut repacked,
        )
        .unwrap();
        assert_eq!(repacked, [0x21, 0x8F]);

        unpack_4bpp_into(&[0x21, 0x8F], NibbleOrder::HighFirst, &mut pixels).unwrap();
        assert_eq!(pixels, [2, 1, 8, 0xF]);
        pack_4bpp_into(
            &pixels,
            NibbleOrder::HighFirst,
            IndexPolicy::Reject,
            &mut repacked,
        )
        .unwrap();
        assert_eq!(repacked, [0x21, 0x8F]);
    }

    #[test]
    fn pack_4bpp_policies_and_odd_lengths() {
        let mut out = [0u8; 2];
        assert_eq!(
            pack_4bpp_into(
                &[1, 16, 3],
                NibbleOrder::LowFirst,
                IndexPolicy::Reject,
                &mut out
            ),
            Err(PackError::IndexOutOfRange {
                index: 1,
                value: 16
            })
        );
        pack_4bpp_into(
            &[1, 0x12, 3],
            NibbleOrder::LowFirst,
            IndexPolicy::Mask,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, [0x21, 0x03]);

        let mut odd_px = [0u8; 3];
        unpack_4bpp_into(&out, NibbleOrder::LowFirst, &mut odd_px).unwrap();
        assert_eq!(odd_px, [1, 2, 3]);

        let mut too_small = [0u8; 1];
        assert_eq!(
            pack_4bpp_into(
                &[1, 2, 3],
                NibbleOrder::LowFirst,
                IndexPolicy::Mask,
                &mut too_small
            ),
            Err(PackError::LengthMismatch {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            unpack_4bpp_into(&[0x21], NibbleOrder::LowFirst, &mut odd_px),
            Err(PackError::LengthMismatch {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn unpack_1bpp_and_2bpp_lsb_and_msb_first() {
        let mut p1 = [0u8; 8];
        unpack_1bpp_into(&[0b1011_0010], BitOrder::MsbFirst, &mut p1).unwrap();
        assert_eq!(p1, [1, 0, 1, 1, 0, 0, 1, 0]);
        unpack_1bpp_into(&[0b1011_0010], BitOrder::LsbFirst, &mut p1).unwrap();
        assert_eq!(p1, [0, 1, 0, 0, 1, 1, 0, 1]);

        let mut p2 = [0u8; 4];
        unpack_2bpp_into(&[0b11_10_01_00], BitOrder::MsbFirst, &mut p2).unwrap();
        assert_eq!(p2, [3, 2, 1, 0]);
        unpack_2bpp_into(&[0b11_10_01_00], BitOrder::LsbFirst, &mut p2).unwrap();
        assert_eq!(p2, [0, 1, 2, 3]);
    }

    #[test]
    fn bgr555_policies_and_slice_decoder() {
        assert_eq!(
            bgr555_to_rgba(0x001F, Alpha555Policy::Opaque),
            [255, 0, 0, 255]
        );
        assert_eq!(
            bgr555_to_rgba(0x03E0, Alpha555Policy::Opaque),
            [0, 255, 0, 255]
        );
        assert_eq!(
            bgr555_to_rgba(0x7C00, Alpha555Policy::Opaque),
            [0, 0, 255, 255]
        );

        assert_eq!(
            bgr555_to_rgba(0x0000, Alpha555Policy::ZeroIsTransparent),
            [0, 0, 0, 0]
        );
        assert_eq!(
            bgr555_to_rgba(0x8000, Alpha555Policy::ZeroIsTransparent),
            [0, 0, 0, 255]
        );
        assert_eq!(
            bgr555_to_rgba(0x001F, Alpha555Policy::TopBitAlpha),
            [255, 0, 0, 0]
        );
        assert_eq!(
            bgr555_to_rgba(0x801F, Alpha555Policy::TopBitAlpha),
            [255, 0, 0, 255]
        );

        let src = [0x00, 0x00, 0x1F, 0x00];
        let mut rgba = [0u8; 8];
        bgr555_le_words_to_rgba(&src, Alpha555Policy::ZeroIsTransparent, &mut rgba).unwrap();
        assert_eq!(rgba, [0, 0, 0, 0, 255, 0, 0, 255]);

        assert_eq!(
            bgr555_le_words_to_rgba(&[0x00], Alpha555Policy::Opaque, &mut []),
            Err(PackError::LengthMismatch {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            bgr555_le_words_to_rgba(&src, Alpha555Policy::Opaque, &mut [0u8; 4]),
            Err(PackError::LengthMismatch {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn rgb444_and_bgr444_replicate_nibbles_with_opaque_alpha() {
        assert_eq!(rgb444_to_rgba(0x0F00), [0xFF, 0x00, 0x00, 0xFF]);
        assert_eq!(rgb444_to_rgba(0x0080), [0x00, 0x88, 0x00, 0xFF]);
        assert_eq!(rgb444_to_rgba(0x000F), [0x00, 0x00, 0xFF, 0xFF]);
        assert_eq!(rgb444_to_rgba(0xF123), [0x11, 0x22, 0x33, 0xFF]);

        assert_eq!(bgr444_to_rgba(0x000F), [0xFF, 0x00, 0x00, 0xFF]);
        assert_eq!(bgr444_to_rgba(0x0080), [0x00, 0x88, 0x00, 0xFF]);
        assert_eq!(bgr444_to_rgba(0x0F00), [0x00, 0x00, 0xFF, 0xFF]);
        assert_eq!(bgr444_to_rgba(0xF123), [0x33, 0x22, 0x11, 0xFF]);
    }

    #[test]
    fn rgb8_and_rgba8_pack_to_bgr555_with_policies() {
        assert_eq!(rgb8_to_bgr555(0xFF, 0x00, 0x00), 0x001F);
        assert_eq!(rgb8_to_bgr555(0x00, 0xFF, 0x00), 0x03E0);
        assert_eq!(rgb8_to_bgr555(0x00, 0x00, 0xFF), 0x7C00);
        assert_eq!(rgb8_to_bgr555(0xFF, 0xFF, 0xFF), 0x7FFF);
        assert_eq!(rgb8_to_bgr555(0x07, 0x07, 0x07), 0x0000);

        // Opaque always leaves bit 15 cleared.
        assert_eq!(
            rgba8_to_bgr555([0xFF, 0x00, 0x00, 0xFF], Alpha555Policy::Opaque),
            0x001F
        );
        assert_eq!(
            rgba8_to_bgr555([0xFF, 0x00, 0x00, 0x00], Alpha555Policy::Opaque),
            0x001F
        );

        // TopBitAlpha sets bit 15 when alpha >= 0x80.
        assert_eq!(
            rgba8_to_bgr555([0xFF, 0x00, 0x00, 0x80], Alpha555Policy::TopBitAlpha),
            0x801F
        );
        assert_eq!(
            rgba8_to_bgr555([0xFF, 0x00, 0x00, 0x7F], Alpha555Policy::TopBitAlpha),
            0x001F
        );

        // ZeroIsTransparent returns 0 when alpha < 0x80.
        assert_eq!(
            rgba8_to_bgr555([0xFF, 0xFF, 0xFF, 0x7F], Alpha555Policy::ZeroIsTransparent),
            0x0000
        );
        assert_eq!(
            rgba8_to_bgr555([0x00, 0xFF, 0x00, 0x80], Alpha555Policy::ZeroIsTransparent),
            0x03E0
        );

        // Round-trip quantized values through bgr555_to_rgba.
        for word in [0x001Fu16, 0x03E0, 0x7C00, 0x801F, 0xFFFF] {
            let rgba = bgr555_to_rgba(word, Alpha555Policy::TopBitAlpha);
            assert_eq!(rgba8_to_bgr555(rgba, Alpha555Policy::TopBitAlpha), word);
        }
    }

    #[test]
    fn pack_1bpp_and_2bpp_round_trip_and_validate() {
        let idx1 = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0];
        for order in [BitOrder::MsbFirst, BitOrder::LsbFirst] {
            let mut packed = [0u8; 2];
            pack_1bpp_into(&idx1, order, IndexPolicy::Reject, &mut packed).unwrap();
            let mut unpacked = [0u8; 11];
            unpack_1bpp_into(&packed, order, &mut unpacked).unwrap();
            assert_eq!(unpacked, idx1);
        }
        let mut out1 = [0xAAu8; 1];
        assert_eq!(
            pack_1bpp_into(&[0, 2], BitOrder::MsbFirst, IndexPolicy::Reject, &mut out1),
            Err(PackError::IndexOutOfRange { index: 1, value: 2 })
        );
        assert_eq!(out1, [0xAA]);
        pack_1bpp_into(&[0, 3], BitOrder::MsbFirst, IndexPolicy::Mask, &mut out1).unwrap();
        assert_eq!(out1, [0b0100_0000]);

        let idx2 = [3, 2, 1, 0, 2, 3];
        for order in [BitOrder::MsbFirst, BitOrder::LsbFirst] {
            let mut packed = [0u8; 2];
            pack_2bpp_into(&idx2, order, IndexPolicy::Reject, &mut packed).unwrap();
            let mut unpacked = [0u8; 6];
            unpack_2bpp_into(&packed, order, &mut unpacked).unwrap();
            assert_eq!(unpacked, idx2);
        }
        let mut out2 = [0xAAu8; 1];
        assert_eq!(
            pack_2bpp_into(&[1, 4], BitOrder::LsbFirst, IndexPolicy::Reject, &mut out2),
            Err(PackError::IndexOutOfRange { index: 1, value: 4 })
        );
        assert_eq!(out2, [0xAA]);
        pack_2bpp_into(&[1, 6], BitOrder::LsbFirst, IndexPolicy::Mask, &mut out2).unwrap();
        assert_eq!(out2, [0b00_00_10_01]);
    }

    #[test]
    fn inverse_color_encoders_and_bgr555_batch_round_trip() {
        for word in [0x0000u16, 0x001F, 0x07E0, 0xF800, 0x1234, 0xFFFF] {
            assert_eq!(rgba8_to_rgb565(rgb565_to_rgba(word)), word);
            assert_eq!(rgba8_to_rgba5650(rgba5650_to_rgba(word)), word);
            assert_eq!(rgba8_to_rgba5551(rgba5551_to_rgba(word)), word);
            assert_eq!(rgba8_to_rgba4444(rgba4444_to_rgba(word)), word);
        }
        for word in [0x0000u16, 0x0F00, 0x00F0, 0x000F, 0x0123, 0x0FFF] {
            let rgb = rgb444_to_rgba(word);
            assert_eq!(rgb8_to_rgb444(rgb[0], rgb[1], rgb[2]), word);
            let bgr = bgr444_to_rgba(word);
            assert_eq!(rgb8_to_bgr444(bgr[0], bgr[1], bgr[2]), word);
        }

        let words = [0x00, 0x00, 0x1F, 0x80, 0xE0, 0x03];
        let mut rgba = [0u8; 12];
        bgr555_le_words_to_rgba(&words, Alpha555Policy::TopBitAlpha, &mut rgba).unwrap();
        let mut repacked = [0u8; 6];
        rgba_to_bgr555_le_words(&rgba, Alpha555Policy::TopBitAlpha, &mut repacked).unwrap();
        assert_eq!(repacked, words);

        assert_eq!(
            rgba_to_bgr555_le_words(&[0u8; 3], Alpha555Policy::Opaque, &mut []),
            Err(PackError::LengthMismatch {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            rgba_to_bgr555_le_words(&rgba, Alpha555Policy::Opaque, &mut [0u8; 4]),
            Err(PackError::LengthMismatch {
                expected: 6,
                actual: 4
            })
        );
    }
}
