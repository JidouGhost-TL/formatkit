//! Morton (Z-order) coordinate interleaving and 2D texture swizzle/unswizzle.
//!
//! Rectangular textures whose shorter dimension `short = min(width, height)` is
//! a power of two and whose longer dimension is a multiple of `short` are tiled
//! as row-major `short × short` Morton squares. For power-of-two dimensions this
//! is identical to interleaving the low `log2(short)` bits of `x` and `y` and
//! placing the remaining high bits of the longer axis above them.

use crate::PackError;

/// Which coordinate supplies bit 0 of the interleaved Morton index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MortonAxisOrder {
    /// Bit 0 comes from `x`, bit 1 from `y`, bit 2 from `x`, etc. (standard Z-order).
    XFirst,
    /// Bit 0 comes from `y`, bit 1 from `x`, bit 2 from `y`, etc. (transposed Z-order).
    YFirst,
}

#[inline]
const fn spread_bits_u16(mut v: u32) -> u32 {
    v &= 0x0000_FFFF;
    v = (v | (v << 8)) & 0x00FF_00FF;
    v = (v | (v << 4)) & 0x0F0F_0F0F;
    v = (v | (v << 2)) & 0x3333_3333;
    v = (v | (v << 1)) & 0x5555_5555;
    v
}

#[inline]
const fn interleave_u32(x: u32, y: u32, order: MortonAxisOrder) -> u64 {
    let x_lo = spread_bits_u16(x & 0xFFFF) as u64;
    let x_hi = spread_bits_u16(x >> 16) as u64;
    let y_lo = spread_bits_u16(y & 0xFFFF) as u64;
    let y_hi = spread_bits_u16(y >> 16) as u64;
    let sx = x_lo | (x_hi << 32);
    let sy = y_lo | (y_hi << 32);
    match order {
        MortonAxisOrder::XFirst => sx | (sy << 1),
        MortonAxisOrder::YFirst => sy | (sx << 1),
    }
}

fn validate_morton_geometry(width: u32, height: u32) -> Result<u32, PackError> {
    if width == 0 || height == 0 {
        return Err(PackError::InvalidLayout {
            reason: "Morton dimensions must be non-zero",
        });
    }
    let short = width.min(height);
    let long = width.max(height);
    if !short.is_power_of_two() || !long.is_multiple_of(short) {
        return Err(PackError::InvalidLayout {
            reason: "Morton shorter dimension must be a power of two dividing the longer dimension",
        });
    }
    Ok(short)
}

/// Compute the linear Morton storage index for `(x, y)` in a `width × height` surface.
///
/// Returns `None` if `(x, y)` is out of bounds, `width` or `height` is zero,
/// the shorter dimension is not a power of two dividing the longer dimension,
/// or the resulting index overflows `usize`.
#[must_use]
pub fn morton_index(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    order: MortonAxisOrder,
) -> Option<usize> {
    if x >= width || y >= height {
        return None;
    }
    let tile_size = validate_morton_geometry(width, height).ok()?;
    let tiles_per_row = u64::from(width / tile_size);
    let tile_x = u64::from(x / tile_size);
    let tile_y = u64::from(y / tile_size);
    let local_x = x % tile_size;
    let local_y = y % tile_size;
    let tile_area = u64::from(tile_size).checked_mul(u64::from(tile_size))?;
    let tile_idx = tile_y.checked_mul(tiles_per_row)?.checked_add(tile_x)?;
    let local_idx = interleave_u32(local_x, local_y, order);
    let index = tile_idx.checked_mul(tile_area)?.checked_add(local_idx)?;
    usize::try_from(index).ok()
}

#[inline]
const fn spread_u32(v: u32) -> u64 {
    let lo = spread_bits_u16(v & 0xFFFF) as u64;
    let hi = spread_bits_u16(v >> 16) as u64;
    lo | (hi << 32)
}

fn validate_buffer_len(
    src_len: usize,
    width: u32,
    height: u32,
    bytes_per_pixel: usize,
) -> Result<(u32, usize, usize), PackError> {
    if bytes_per_pixel == 0 {
        return Err(PackError::InvalidLayout {
            reason: "bytes_per_pixel must be non-zero",
        });
    }
    let tile_size = validate_morton_geometry(width, height)?;
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or(PackError::InvalidLayout {
            reason: "Morton pixel count overflow",
        })?;
    let expected = pixels
        .checked_mul(bytes_per_pixel)
        .ok_or(PackError::InvalidLayout {
            reason: "Morton byte length overflow",
        })?;
    if src_len != expected {
        return Err(PackError::LengthMismatch {
            expected,
            actual: src_len,
        });
    }
    Ok((tile_size, pixels, expected))
}

fn build_spread_tables(tile_size: usize, order: MortonAxisOrder) -> (Vec<usize>, Vec<usize>) {
    let (x_shift, y_shift) = match order {
        MortonAxisOrder::XFirst => (0u32, 1u32),
        MortonAxisOrder::YFirst => (1u32, 0u32),
    };
    let mut sx = Vec::with_capacity(tile_size);
    let mut sy = Vec::with_capacity(tile_size);
    for i in 0..tile_size {
        let s = spread_u32(i as u32) as usize;
        sx.push(s << x_shift);
        sy.push(s << y_shift);
    }
    (sx, sy)
}

/// Convert a Morton-swizzled surface into row-major linear pixel order.
pub fn unswizzle_morton(
    src: &[u8],
    width: u32,
    height: u32,
    bytes_per_pixel: usize,
    order: MortonAxisOrder,
) -> Result<Vec<u8>, PackError> {
    let (tile_size_u32, _, expected) =
        validate_buffer_len(src.len(), width, height, bytes_per_pixel)?;
    let tile_size = tile_size_u32 as usize;
    let tile_mask = tile_size - 1;
    let tile_shift = tile_size.trailing_zeros();
    let tile_area = tile_size * tile_size;
    let tiles_per_row = (width as usize) >> tile_shift;
    let (sx, sy) = build_spread_tables(tile_size, order);

    let mut dst = vec![0u8; expected];
    let w = width as usize;
    let h = height as usize;

    match bytes_per_pixel {
        1 => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let dst_row = &mut dst[y * w..(y + 1) * w];
                for (x, out) in dst_row.iter_mut().enumerate() {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = tile_idx * tile_area + (y_morton | sx[x & tile_mask]);
                    *out = src[m];
                }
            }
        }
        2 => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let row_off = y * w * 2;
                for x in 0..w {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = (tile_idx * tile_area + (y_morton | sx[x & tile_mask])) * 2;
                    let d = row_off + x * 2;
                    dst[d] = src[m];
                    dst[d + 1] = src[m + 1];
                }
            }
        }
        4 => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let row_off = y * w * 4;
                for x in 0..w {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = (tile_idx * tile_area + (y_morton | sx[x & tile_mask])) * 4;
                    let d = row_off + x * 4;
                    dst[d..d + 4].copy_from_slice(&src[m..m + 4]);
                }
            }
        }
        bpp => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let row_off = y * w * bpp;
                for x in 0..w {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = (tile_idx * tile_area + (y_morton | sx[x & tile_mask])) * bpp;
                    let d = row_off + x * bpp;
                    dst[d..d + bpp].copy_from_slice(&src[m..m + bpp]);
                }
            }
        }
    }
    Ok(dst)
}

/// Convert a row-major linear surface into Morton-swizzled pixel order.
pub fn swizzle_morton(
    src: &[u8],
    width: u32,
    height: u32,
    bytes_per_pixel: usize,
    order: MortonAxisOrder,
) -> Result<Vec<u8>, PackError> {
    let (tile_size_u32, _, expected) =
        validate_buffer_len(src.len(), width, height, bytes_per_pixel)?;
    let tile_size = tile_size_u32 as usize;
    let tile_mask = tile_size - 1;
    let tile_shift = tile_size.trailing_zeros();
    let tile_area = tile_size * tile_size;
    let tiles_per_row = (width as usize) >> tile_shift;
    let (sx, sy) = build_spread_tables(tile_size, order);

    let mut dst = vec![0u8; expected];
    let w = width as usize;
    let h = height as usize;

    match bytes_per_pixel {
        1 => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let src_row = &src[y * w..(y + 1) * w];
                for (x, &px) in src_row.iter().enumerate() {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = tile_idx * tile_area + (y_morton | sx[x & tile_mask]);
                    dst[m] = px;
                }
            }
        }
        2 => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let row_off = y * w * 2;
                for x in 0..w {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = (tile_idx * tile_area + (y_morton | sx[x & tile_mask])) * 2;
                    let s = row_off + x * 2;
                    dst[m] = src[s];
                    dst[m + 1] = src[s + 1];
                }
            }
        }
        4 => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let row_off = y * w * 4;
                for x in 0..w {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = (tile_idx * tile_area + (y_morton | sx[x & tile_mask])) * 4;
                    let s = row_off + x * 4;
                    dst[m..m + 4].copy_from_slice(&src[s..s + 4]);
                }
            }
        }
        bpp => {
            for y in 0..h {
                let tile_row_base = (y >> tile_shift) * tiles_per_row;
                let y_morton = sy[y & tile_mask];
                let row_off = y * w * bpp;
                for x in 0..w {
                    let tile_idx = tile_row_base + (x >> tile_shift);
                    let m = (tile_idx * tile_area + (y_morton | sx[x & tile_mask])) * bpp;
                    let s = row_off + x * bpp;
                    dst[m..m + bpp].copy_from_slice(&src[s..s + bpp]);
                }
            }
        }
    }
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn morton_index_4x4_both_axis_orders() {
        // XFirst 4x4:
        //  0  1  4  5
        //  2  3  6  7
        //  8  9 12 13
        // 10 11 14 15
        let expected_x = [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];
        for y in 0..4u32 {
            for x in 0..4u32 {
                assert_eq!(
                    morton_index(x, y, 4, 4, MortonAxisOrder::XFirst),
                    Some(expected_x[(y * 4 + x) as usize])
                );
            }
        }

        // YFirst 4x4 (transposed):
        //  0  2  8 10
        //  1  3  9 11
        //  4  6 12 14
        //  5  7 13 15
        let expected_y = [0, 2, 8, 10, 1, 3, 9, 11, 4, 6, 12, 14, 5, 7, 13, 15];
        for y in 0..4u32 {
            for x in 0..4u32 {
                assert_eq!(
                    morton_index(x, y, 4, 4, MortonAxisOrder::YFirst),
                    Some(expected_y[(y * 4 + x) as usize])
                );
            }
        }
    }

    #[test]
    fn rectangular_morton_is_a_bijection_and_round_trips() {
        for (w, h) in [(8u32, 4u32), (4, 8), (12, 4), (4, 12), (1, 4), (16, 16)] {
            for order in [MortonAxisOrder::XFirst, MortonAxisOrder::YFirst] {
                let bpp = 2usize;
                let linear: Vec<u8> = (0..(w * h) as usize)
                    .flat_map(|i| [(i & 0xff) as u8, ((i >> 8) & 0xff) as u8])
                    .collect();
                let swizzled = swizzle_morton(&linear, w, h, bpp, order).unwrap();
                let unswizzled = unswizzle_morton(&swizzled, w, h, bpp, order).unwrap();
                assert_eq!(unswizzled, linear);
            }
        }
    }

    #[test]
    fn morton_rejects_invalid_geometry_and_lengths() {
        assert_eq!(morton_index(4, 0, 4, 4, MortonAxisOrder::XFirst), None);
        assert_eq!(morton_index(0, 0, 0, 4, MortonAxisOrder::XFirst), None);
        assert_eq!(morton_index(0, 0, 6, 4, MortonAxisOrder::XFirst), None);
        assert_eq!(morton_index(0, 0, 3, 3, MortonAxisOrder::XFirst), None);
        assert!(swizzle_morton(&[0u8; 15], 4, 4, 1, MortonAxisOrder::XFirst).is_err());
        assert!(unswizzle_morton(&[0u8; 16], 4, 4, 0, MortonAxisOrder::XFirst).is_err());
    }
}
