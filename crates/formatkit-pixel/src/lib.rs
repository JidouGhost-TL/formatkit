//! Container-independent palette, packed-pixel and block-codec mechanics.
#![forbid(unsafe_code)]

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
    /// Used by GBA 4bpp tiles, TIM2, GIM, and BMP-like layouts.
    LowFirst,
    /// High nibble (`b >> 4`) is the first (left) pixel; low nibble (`b & 0x0F`) is the second.
    /// Used by WonderSwan packed tiles and big-endian 4bpp layouts.
    HighFirst,
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
    /// Output slice length did not match the required length for the input.
    LengthMismatch { expected: usize, actual: usize },
    /// An index exceeded the 4-bit maximum (`15`) under [`IndexPolicy::Reject`].
    IndexOutOfRange { index: usize, value: u8 },
}

impl core::fmt::Display for PackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::LengthMismatch { expected, actual } => {
                write!(f, "packed index buffer length mismatch: expected {expected}, got {actual}")
            }
            Self::IndexOutOfRange { index, value } => {
                write!(f, "4bpp palette index out of range at pixel {index}: {value} > 15")
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
        pack_4bpp_into(&pixels, NibbleOrder::LowFirst, IndexPolicy::Reject, &mut repacked).unwrap();
        assert_eq!(repacked, [0x21, 0x8F]);

        unpack_4bpp_into(&[0x21, 0x8F], NibbleOrder::HighFirst, &mut pixels).unwrap();
        assert_eq!(pixels, [2, 1, 8, 0xF]);
        pack_4bpp_into(&pixels, NibbleOrder::HighFirst, IndexPolicy::Reject, &mut repacked).unwrap();
        assert_eq!(repacked, [0x21, 0x8F]);
    }

    #[test]
    fn pack_4bpp_policies_and_odd_lengths() {
        let mut out = [0u8; 2];
        assert_eq!(
            pack_4bpp_into(&[1, 16, 3], NibbleOrder::LowFirst, IndexPolicy::Reject, &mut out),
            Err(PackError::IndexOutOfRange { index: 1, value: 16 })
        );
        pack_4bpp_into(&[1, 0x12, 3], NibbleOrder::LowFirst, IndexPolicy::Mask, &mut out).unwrap();
        assert_eq!(out, [0x21, 0x03]);

        let mut odd_px = [0u8; 3];
        unpack_4bpp_into(&out, NibbleOrder::LowFirst, &mut odd_px).unwrap();
        assert_eq!(odd_px, [1, 2, 3]);

        let mut too_small = [0u8; 1];
        assert_eq!(
            pack_4bpp_into(&[1, 2, 3], NibbleOrder::LowFirst, IndexPolicy::Mask, &mut too_small),
            Err(PackError::LengthMismatch { expected: 2, actual: 1 })
        );
        assert_eq!(
            unpack_4bpp_into(&[0x21], NibbleOrder::LowFirst, &mut odd_px),
            Err(PackError::LengthMismatch { expected: 2, actual: 1 })
        );
    }
}

pub mod dxt;
pub use dxt::{decode_dxt, decode_masked, is_contiguous, rgb565_to_rgba, ChannelMasks, DxtFormat};
