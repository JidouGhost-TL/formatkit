//! Byte-aligned 1bpp and 2bpp 2D glyph unpackers.

use crate::{unpack_1bpp_into, unpack_2bpp_into, BitOrder, PackError};

/// Unpack a 1-bit-per-pixel 2D glyph with byte-aligned rows into `out` (`0` or
/// `1` per pixel).
///
/// Each row occupies `width.div_ceil(8)` bytes in `src`; trailing bits in the
/// last byte of each row are ignored. `out.len()` must equal `width * height`.
pub fn unpack_glyph_1bpp(
    src: &[u8],
    width: usize,
    height: usize,
    bit_order: BitOrder,
    out: &mut [u8],
) -> Result<(), PackError> {
    let row_bytes = width.div_ceil(8);
    let required_src = row_bytes
        .checked_mul(height)
        .ok_or(PackError::InvalidLayout {
            reason: "glyph source size overflow",
        })?;
    if src.len() < required_src {
        return Err(PackError::LengthMismatch {
            expected: required_src,
            actual: src.len(),
        });
    }
    let expected_out = width.checked_mul(height).ok_or(PackError::InvalidLayout {
        reason: "glyph pixel count overflow",
    })?;
    if out.len() != expected_out {
        return Err(PackError::LengthMismatch {
            expected: expected_out,
            actual: out.len(),
        });
    }

    for row in 0..height {
        let src_row = &src[row * row_bytes..(row + 1) * row_bytes];
        let dst_row = &mut out[row * width..(row + 1) * width];
        unpack_1bpp_into(src_row, bit_order, dst_row)?;
    }
    Ok(())
}

/// Unpack a 2-bit-per-pixel 2D glyph with byte-aligned rows into `out`
/// (`0..=3` per pixel).
///
/// Each row occupies `width.div_ceil(4)` bytes in `src`; trailing bit pairs in
/// the last byte of each row are ignored. `out.len()` must equal
/// `width * height`.
pub fn unpack_glyph_2bpp(
    src: &[u8],
    width: usize,
    height: usize,
    bit_order: BitOrder,
    out: &mut [u8],
) -> Result<(), PackError> {
    let row_bytes = width.div_ceil(4);
    let required_src = row_bytes
        .checked_mul(height)
        .ok_or(PackError::InvalidLayout {
            reason: "glyph source size overflow",
        })?;
    if src.len() < required_src {
        return Err(PackError::LengthMismatch {
            expected: required_src,
            actual: src.len(),
        });
    }
    let expected_out = width.checked_mul(height).ok_or(PackError::InvalidLayout {
        reason: "glyph pixel count overflow",
    })?;
    if out.len() != expected_out {
        return Err(PackError::LengthMismatch {
            expected: expected_out,
            actual: out.len(),
        });
    }

    for row in 0..height {
        let src_row = &src[row * row_bytes..(row + 1) * row_bytes];
        let dst_row = &mut out[row * width..(row + 1) * width];
        unpack_2bpp_into(src_row, bit_order, dst_row)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_1bpp_byte_aligned_rows_in_both_bit_orders() {
        // 5x2 glyph -> 1 byte per row, 3 trailing padding bits ignored.
        let src = [0b1011_0111, 0b0100_1111];
        let mut out = [0u8; 10];
        unpack_glyph_1bpp(&src, 5, 2, BitOrder::MsbFirst, &mut out).unwrap();
        assert_eq!(out, [1, 0, 1, 1, 0, 0, 1, 0, 0, 1]);

        let src_lsb = [0b1110_1101, 0b1111_0010];
        unpack_glyph_1bpp(&src_lsb, 5, 2, BitOrder::LsbFirst, &mut out).unwrap();
        assert_eq!(out, [1, 0, 1, 1, 0, 0, 1, 0, 0, 1]);
    }

    #[test]
    fn unpacks_2bpp_byte_aligned_rows_in_both_bit_orders() {
        // 3x2 glyph -> 1 byte per row, 1 trailing 2-bit slot ignored.
        let src_msb = [0b11_10_01_11, 0b00_01_10_11];
        let mut out = [0u8; 6];
        unpack_glyph_2bpp(&src_msb, 3, 2, BitOrder::MsbFirst, &mut out).unwrap();
        assert_eq!(out, [3, 2, 1, 0, 1, 2]);

        let src_lsb = [0b11_01_10_11, 0b11_10_01_00];
        unpack_glyph_2bpp(&src_lsb, 3, 2, BitOrder::LsbFirst, &mut out).unwrap();
        assert_eq!(out, [3, 2, 1, 0, 1, 2]);
    }

    #[test]
    fn rejects_short_source_or_wrong_output_length() {
        let mut out = [0u8; 10];
        assert_eq!(
            unpack_glyph_1bpp(&[0u8; 1], 5, 2, BitOrder::MsbFirst, &mut out),
            Err(PackError::LengthMismatch {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            unpack_glyph_2bpp(&[0u8; 2], 3, 2, BitOrder::MsbFirst, &mut out),
            Err(PackError::LengthMismatch {
                expected: 6,
                actual: 10,
            })
        );
    }
}
