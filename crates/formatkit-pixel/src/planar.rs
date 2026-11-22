//! Interleaved-row planar 8x8 tile packing and unpacking.

use crate::{BitOrder, IndexPolicy, PackError};

fn expected_tile_bytes(planes: u8) -> Result<usize, PackError> {
    match planes {
        2 => Ok(16),
        4 => Ok(32),
        _ => Err(PackError::UnsupportedPlanes { planes }),
    }
}

/// Unpack an interleaved-row planar 8x8 tile into 64 row-major palette indices.
///
/// Supported bitplane depths:
/// - `planes == 2`: 16 bytes total (2 bytes per row: plane 0, plane 1), indices in `0..=3`.
/// - `planes == 4`: 32 bytes total (4 bytes per row: planes 0..=3), indices in `0..=15`.
pub fn unpack_planar_tile_8x8_into(
    src: &[u8],
    planes: u8,
    bit_order: BitOrder,
    out: &mut [u8; 64],
) -> Result<(), PackError> {
    let expected = expected_tile_bytes(planes)?;
    if src.len() != expected {
        return Err(PackError::LengthMismatch {
            expected,
            actual: src.len(),
        });
    }

    let stride = usize::from(planes);
    for row in 0..8 {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for col in 0..8 {
            let shift = match bit_order {
                BitOrder::MsbFirst => 7 - col,
                BitOrder::LsbFirst => col,
            };
            let mut idx = 0u8;
            for (plane, &byte) in row_bytes.iter().enumerate() {
                idx |= ((byte >> shift) & 1) << plane;
            }
            out[row * 8 + col] = idx;
        }
    }
    Ok(())
}

/// Pack 64 row-major palette indices into an interleaved-row planar 8x8 tile.
///
/// Supported bitplane depths:
/// - `planes == 2`: writes 16 bytes (2 bytes per row), valid index range `0..=3`.
/// - `planes == 4`: writes 32 bytes (4 bytes per row), valid index range `0..=15`.
pub fn pack_planar_tile_8x8_into(
    indices: &[u8; 64],
    planes: u8,
    bit_order: BitOrder,
    policy: IndexPolicy,
    out: &mut [u8],
) -> Result<(), PackError> {
    let expected = expected_tile_bytes(planes)?;
    if out.len() != expected {
        return Err(PackError::LengthMismatch {
            expected,
            actual: out.len(),
        });
    }

    let max_index = (1u8 << planes) - 1;
    if policy == IndexPolicy::Reject {
        for (i, &value) in indices.iter().enumerate() {
            if value > max_index {
                return Err(PackError::IndexOutOfRange { index: i, value });
            }
        }
    }

    let stride = usize::from(planes);
    for row in 0..8 {
        let row_bytes = &mut out[row * stride..(row + 1) * stride];
        row_bytes.fill(0);
        for col in 0..8 {
            let shift = match bit_order {
                BitOrder::MsbFirst => 7 - col,
                BitOrder::LsbFirst => col,
            };
            let value = indices[row * 8 + col] & max_index;
            for (plane, byte) in row_bytes.iter_mut().enumerate() {
                *byte |= ((value >> plane) & 1) << shift;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_2bpp_and_4bpp_both_bit_orders() {
        for (planes, max_val) in [(2u8, 3u8), (4u8, 15u8)] {
            let mut tile = [0u8; 64];
            for (i, px) in tile.iter_mut().enumerate() {
                *px = (i as u8) % (max_val + 1);
            }
            for order in [BitOrder::MsbFirst, BitOrder::LsbFirst] {
                let mut packed = vec![0u8; usize::from(planes) * 8];
                pack_planar_tile_8x8_into(&tile, planes, order, IndexPolicy::Reject, &mut packed)
                    .unwrap();

                let mut unpacked = [0u8; 64];
                unpack_planar_tile_8x8_into(&packed, planes, order, &mut unpacked).unwrap();
                assert_eq!(unpacked, tile);
            }
        }
    }

    #[test]
    fn known_2bpp_msb_first_row_pattern() {
        // Row 0: plane 0 = 0b1010_0000, plane 1 = 0b1100_0000
        // Pixels 0..4 => [3, 2, 1, 0], pixels 4..8 => [0, 0, 0, 0]
        let mut src = [0u8; 16];
        src[0] = 0b1010_0000;
        src[1] = 0b1100_0000;

        let mut out = [0u8; 64];
        unpack_planar_tile_8x8_into(&src, 2, BitOrder::MsbFirst, &mut out).unwrap();
        assert_eq!(&out[0..8], &[3, 2, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_bad_plane_count_length_and_out_of_range_indices() {
        let mut out = [0u8; 64];
        assert_eq!(
            unpack_planar_tile_8x8_into(&[0u8; 24], 3, BitOrder::MsbFirst, &mut out),
            Err(PackError::UnsupportedPlanes { planes: 3 })
        );
        assert_eq!(
            unpack_planar_tile_8x8_into(&[0u8; 15], 2, BitOrder::MsbFirst, &mut out),
            Err(PackError::LengthMismatch {
                expected: 16,
                actual: 15
            })
        );

        let mut indices = [0u8; 64];
        indices[5] = 4;
        let mut packed = [0xAAu8; 16];
        assert_eq!(
            pack_planar_tile_8x8_into(
                &indices,
                2,
                BitOrder::MsbFirst,
                IndexPolicy::Reject,
                &mut packed
            ),
            Err(PackError::IndexOutOfRange { index: 5, value: 4 })
        );
        // Output slice left untouched when Reject fails.
        assert_eq!(packed, [0xAAu8; 16]);

        // Mask policy truncates index 4 -> 0 for 2-plane tile.
        pack_planar_tile_8x8_into(
            &indices,
            2,
            BitOrder::MsbFirst,
            IndexPolicy::Mask,
            &mut packed,
        )
        .unwrap();
        assert_eq!(packed, [0u8; 16]);
    }
}
