//! S3TC blocks and contiguous channel-mask decoding, independent of containers.
use formatkit_core::{Error, Result};

#[cfg(test)]
#[path = "dxt_reference_tests.rs"]
mod reference_tests;

/// The block-compressed flavours, in their standard S3TC byte layout.
///
/// This is the *format-invariant* block encoding, not a container's packaging
/// of it: some consoles store the two 16-bit endpoints and the index word
/// word-swapped relative to this, and those containers must reorder before
/// calling [`decode_dxt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DxtFormat {
    /// 8 bytes per 4×4 block; 1-bit alpha carried by the endpoint ordering.
    Dxt1,
    /// 16 bytes per block: 4 bits of explicit alpha per texel, then the colour
    /// block.
    Dxt3,
    /// 16 bytes per block: two alpha endpoints plus 3-bit interpolation
    /// indices, then the colour block.
    Dxt5,
}

/// Per-channel bit masks for an uncompressed texel.
///
/// A zero `alpha` mask means the format carries no alpha (`X8R8G8B8` and
/// friends) and every decoded texel is opaque — distinct from an alpha mask
/// whose stored value happens to be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMasks {
    pub red: u32,
    pub green: u32,
    pub blue: u32,
    pub alpha: u32,
}

/// Whether a non-zero mask is one unbroken run of set bits.
pub fn is_contiguous(mask: u32) -> bool {
    if mask == 0 {
        return false;
    }
    let shifted = mask >> mask.trailing_zeros();
    shifted & shifted.wrapping_add(1) == 0
}

/// Expand an `n`-bit channel value to 8 bits by **bit replication**: the value
/// is shifted up and its own high bits repeated into the vacated low bits.
///
/// This is what the block-compression endpoint expansion is defined as, and it
/// is the property that matters: full scale maps to 255. A bare
/// `value << (8 - bits)` instead tops out at 248 for a 5-bit channel, so white
/// decodes as light grey and every gradient bands — a whole-image error that
/// still looks like an image.
fn expand_channel(value: u32, bits: u32) -> u8 {
    if bits == 0 {
        return 0;
    }
    if bits >= 8 {
        return (value >> (bits - 8)) as u8;
    }
    let mut out = 0u32;
    let mut shift = 8;
    while shift >= bits {
        shift -= bits;
        out |= value << shift;
    }
    if shift > 0 {
        out |= value >> (bits - shift);
    }
    (out & 0xff) as u8
}

/// Expand a 16-bit RGB565 texel to RGBA8888, opaque.
///
/// **Red occupies the high bits** here: `0bRRRRR_GGGGGG_BBBBB`. This is the
/// endpoint encoding used by the S3TC block formats, and it is the mirror image
/// of [`crate::rgba5650_to_rgba`], whose red sits in the *low* bits. Feeding a
/// block endpoint to the wrong one swaps red and blue and still produces a
/// perfectly plausible image.
pub fn rgb565_to_rgba(c: u16) -> [u8; 4] {
    [
        expand_channel(u32::from(c >> 11) & 0x1f, 5),
        expand_channel(u32::from(c >> 5) & 0x3f, 6),
        expand_channel(u32::from(c) & 0x1f, 5),
        255,
    ]
}

/// Build the four-entry colour table of one 8-byte S3TC colour block.
///
/// `punchthrough` enables the 1-bit-alpha rule, which only DXT1 has: when its
/// endpoints are stored in non-descending order the block switches to three
/// opaque colours plus a fully transparent black. DXT3 and DXT5 carry alpha
/// separately and always use the four-colour rule, *even when their endpoints
/// happen to be ordered the other way* — applying the punchthrough rule to them
/// silently blacks out texels.
fn dxt_color_table(block: &[u8], punchthrough: bool) -> [[u8; 4]; 4] {
    let c0_word = u16::from_le_bytes([block[0], block[1]]);
    let c1_word = u16::from_le_bytes([block[2], block[3]]);
    let c0 = rgb565_to_rgba(c0_word);
    let c1 = rgb565_to_rgba(c1_word);
    let mut table = [c0, c1, [0, 0, 0, 255], [0, 0, 0, 255]];
    if !punchthrough || c0_word > c1_word {
        for ch in 0..3 {
            let a = u16::from(c0[ch]);
            let b = u16::from(c1[ch]);
            table[2][ch] = ((2 * a + b) / 3) as u8;
            table[3][ch] = ((a + 2 * b) / 3) as u8;
        }
    } else {
        for ch in 0..3 {
            table[2][ch] = ((u16::from(c0[ch]) + u16::from(c1[ch])) / 2) as u8;
        }
        table[3] = [0, 0, 0, 0];
    }
    table
}

/// Build the eight-entry alpha table of a DXT5 alpha block.
///
/// The interpolation constants are the whole point of this function:
///
/// ```text
///   a0 > a1:  table[i + 2] = ((6 - i) * a0 + (i + 1) * a1) / 7,  i in 0..6
///   a0 <= a1: table[i + 2] = ((4 - i) * a0 + (i + 1) * a1) / 5,  i in 0..4
///             table[6] = 0, table[7] = 255
/// ```
///
/// Every interpolant is a convex combination of the endpoints, so it must land
/// between them. An off-by-one in either numerator — `(7 - i)` with `(i + 1)`,
/// say — breaks that: the weights then sum to more than the denominator and the
/// result runs past `a0` and past 255 on bright blocks, wrapping when it is cast
/// to `u8`. It produces a picture, not an error, which is why
/// `dxt5_alpha_interpolants_never_leave_the_endpoint_range` exists.
fn dxt5_alpha_table(a0: u8, a1: u8) -> [u8; 8] {
    let (a0w, a1w) = (u16::from(a0), u16::from(a1));
    let mut table = [0u8; 8];
    table[0] = a0;
    table[1] = a1;
    if a0 > a1 {
        for i in 0..6u16 {
            table[i as usize + 2] = (((6 - i) * a0w + (i + 1) * a1w) / 7) as u8;
        }
    } else {
        for i in 0..4u16 {
            table[i as usize + 2] = (((4 - i) * a0w + (i + 1) * a1w) / 5) as u8;
        }
        table[6] = 0;
        table[7] = 255;
    }
    table
}

/// Decode block-compressed texels in the standard S3TC layout to RGBA8888.
///
/// `src` must hold at least `ceil(w/4) * ceil(h/4)` whole blocks. Texels of a
/// partial edge block that fall outside the extent are decoded and discarded,
/// which is what makes a non-power-of-two extent work.
pub fn decode_dxt(src: &[u8], width: u32, height: u32, format: DxtFormat) -> Result<Vec<u8>> {
    let blocks_wide = width.div_ceil(4).max(1) as usize;
    let blocks_high = height.div_ceil(4).max(1) as usize;
    let block_bytes = format.block_bytes();
    let needed = blocks_wide
        .checked_mul(blocks_high)
        .and_then(|blocks| blocks.checked_mul(block_bytes))
        .ok_or_else(|| Error::Malformed("S3TC source extent overflow".into()))?;
    if src.len() < needed {
        return Err(Error::Truncated {
            offset: 0,
            needed,
            available: src.len(),
        });
    }
    let (width, height) = (width as usize, height as usize);
    let output_len = width
        .checked_mul(height)
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| Error::Malformed("S3TC output extent overflow".into()))?;
    let mut out = vec![0u8; output_len];

    for block_y in 0..blocks_high {
        for block_x in 0..blocks_wide {
            let base = (block_y * blocks_wide + block_x) * block_bytes;
            let block = &src[base..base + block_bytes];
            // DXT3 and DXT5 put their 8 alpha bytes *first*; the colour block
            // that follows is byte-identical to a DXT1 block.
            let (alpha, color) = match format {
                DxtFormat::Dxt1 => (&block[..0], block),
                DxtFormat::Dxt3 | DxtFormat::Dxt5 => block.split_at(8),
            };
            let table = dxt_color_table(color, matches!(format, DxtFormat::Dxt1));
            let indices = u32::from_le_bytes([color[4], color[5], color[6], color[7]]);

            let alpha5 = match format {
                DxtFormat::Dxt5 => Some((
                    dxt5_alpha_table(alpha[0], alpha[1]),
                    // Six bytes of 3-bit indices, little-endian, texel 0 lowest.
                    u64::from_le_bytes([
                        alpha[2], alpha[3], alpha[4], alpha[5], alpha[6], alpha[7], 0, 0,
                    ]),
                )),
                _ => None,
            };
            let alpha3 = match format {
                DxtFormat::Dxt3 => Some(u64::from_le_bytes([
                    alpha[0], alpha[1], alpha[2], alpha[3], alpha[4], alpha[5], alpha[6], alpha[7],
                ])),
                _ => None,
            };

            for texel in 0..16usize {
                let x = block_x * 4 + texel % 4;
                let y = block_y * 4 + texel / 4;
                if x >= width || y >= height {
                    continue;
                }
                let mut rgba = table[((indices >> (texel * 2)) & 3) as usize];
                if let Some(packed) = alpha3 {
                    // 4 bits per texel, expanded by ×17 so 0xf maps to 255.
                    rgba[3] = (((packed >> (texel * 4)) & 0xf) as u8) * 17;
                } else if let Some((table, packed)) = alpha5 {
                    rgba[3] = table[((packed >> (texel * 3)) & 7) as usize];
                }
                let dst = (y * width + x) * 4;
                out[dst..dst + 4].copy_from_slice(&rgba);
            }
        }
    }
    Ok(out)
}

/// Decode uncompressed texels described by channel masks to RGBA8888.
///
/// Texels are read little-endian at `bits_per_pixel / 8` bytes each, rows tight
/// against one another. A zero alpha mask yields opaque texels.
pub fn decode_masked(
    src: &[u8],
    width: u32,
    height: u32,
    bits_per_pixel: u32,
    masks: ChannelMasks,
) -> Result<Vec<u8>> {
    let texel_bytes = (bits_per_pixel / 8) as usize;
    if texel_bytes == 0 || texel_bytes > 4 || !bits_per_pixel.is_multiple_of(8) {
        return Err(Error::Unsupported(format!(
            "DDS {bits_per_pixel}-bit uncompressed texel"
        )));
    }
    let (width, height) = (width as usize, height as usize);
    let count = width
        .checked_mul(height)
        .ok_or_else(|| Error::Malformed("masked pixel count overflow".into()))?;
    let needed = count
        .checked_mul(texel_bytes)
        .ok_or_else(|| Error::Malformed("masked pixel source extent overflow".into()))?;
    if src.len() < needed {
        return Err(Error::Truncated {
            offset: 0,
            needed,
            available: src.len(),
        });
    }

    let channel = |mask: u32| -> (u32, u32) {
        if mask == 0 {
            (0, 0)
        } else {
            (
                mask.trailing_zeros(),
                32 - mask.leading_zeros() - mask.trailing_zeros(),
            )
        }
    };
    let (r_shift, r_bits) = channel(masks.red);
    let (g_shift, g_bits) = channel(masks.green);
    let (b_shift, b_bits) = channel(masks.blue);
    let (a_shift, a_bits) = channel(masks.alpha);

    let output_len = count
        .checked_mul(4)
        .ok_or_else(|| Error::Malformed("masked pixel output extent overflow".into()))?;
    let mut out = vec![0u8; output_len];
    for i in 0..count {
        let mut texel = 0u32;
        for byte in 0..texel_bytes {
            texel |= u32::from(src[i * texel_bytes + byte]) << (byte * 8);
        }
        out[i * 4] = expand_channel((texel & masks.red) >> r_shift, r_bits);
        out[i * 4 + 1] = expand_channel((texel & masks.green) >> g_shift, g_bits);
        out[i * 4 + 2] = expand_channel((texel & masks.blue) >> b_shift, b_bits);
        out[i * 4 + 3] = if masks.alpha == 0 {
            255
        } else {
            expand_channel((texel & masks.alpha) >> a_shift, a_bits)
        };
    }
    Ok(out)
}

impl DxtFormat {
    /// Bytes occupied by one 4×4 block.
    pub fn block_bytes(self) -> usize {
        match self {
            DxtFormat::Dxt1 => 8,
            DxtFormat::Dxt3 | DxtFormat::Dxt5 => 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_masks_are_total_including_zero_and_full_width() {
        for mask in [1, 0x1f, 0xff00, 0xffff_ffff] {
            assert!(is_contiguous(mask));
        }
        for mask in [0, 0x101, 0x8000_0001] {
            assert!(!is_contiguous(mask));
        }
    }

    #[test]
    fn dxt_clips_partial_edges_and_keeps_distinct_alpha_rules() {
        let color = [0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            decode_dxt(&color, 1, 1, DxtFormat::Dxt1).unwrap(),
            [0, 0, 0, 0]
        );
        let block = [vec![0xff; 8], color.to_vec()].concat();
        assert_eq!(
            decode_dxt(&block, 1, 1, DxtFormat::Dxt3).unwrap(),
            [170, 170, 170, 255]
        );
        assert_eq!(
            decode_dxt(&block, 1, 1, DxtFormat::Dxt5).unwrap(),
            [170, 170, 170, 255]
        );
        assert!(matches!(
            decode_dxt(&color[..7], 1, 1, DxtFormat::Dxt1),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn masked_pixels_reject_partial_byte_widths_and_truncation() {
        let masks = ChannelMasks {
            red: 0xf800,
            green: 0x7e0,
            blue: 0x1f,
            alpha: 0,
        };
        assert_eq!(
            decode_masked(&[0xff, 0xff], 1, 1, 16, masks).unwrap(),
            [255; 4]
        );
        assert!(decode_masked(&[0xff, 0xff], 1, 1, 17, masks).is_err());
        assert!(matches!(
            decode_masked(&[0], 1, 1, 16, masks),
            Err(Error::Truncated { .. })
        ));
        assert!(decode_masked(&[], u32::MAX, u32::MAX, 32, masks).is_err());
    }
}
