//! 2D RGBA8888 blitting and bounded grid atlas composition.

use crate::PackError;

fn checked_rgba_len(width: u32, height: u32) -> Result<usize, PackError> {
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(PackError::InvalidLayout {
            reason: "RGBA image dimensions overflow usize",
        })
}

/// Blit an RGBA8888 source rectangle into an RGBA8888 destination buffer.
///
/// Supports horizontal and vertical flipping, integer nearest-neighbor scaling
/// (`scale >= 1`), and optional alpha-zero transparency skipping
/// (`transparent_zero_alpha`). Pixels landing outside `(dst_w, dst_h)` are
/// clipped without error.
#[allow(clippy::too_many_arguments)]
pub fn blit_rgba(
    dst: &mut [u8],
    dst_w: u32,
    dst_h: u32,
    dst_x: u32,
    dst_y: u32,
    src: &[u8],
    src_w: u32,
    src_h: u32,
    h_flip: bool,
    v_flip: bool,
    scale: u32,
    transparent_zero_alpha: bool,
) -> Result<(), PackError> {
    if scale == 0 {
        return Err(PackError::InvalidLayout {
            reason: "scale must be at least 1",
        });
    }
    let expected_dst = checked_rgba_len(dst_w, dst_h)?;
    if dst.len() != expected_dst {
        return Err(PackError::LengthMismatch {
            expected: expected_dst,
            actual: dst.len(),
        });
    }
    let expected_src = checked_rgba_len(src_w, src_h)?;
    if src.len() != expected_src {
        return Err(PackError::LengthMismatch {
            expected: expected_src,
            actual: src.len(),
        });
    }

    let dst_w_u64 = u64::from(dst_w);
    let dst_h_u64 = u64::from(dst_h);
    let scale_u64 = u64::from(scale);

    for sy in 0..src_h {
        let src_row = if v_flip { src_h - 1 - sy } else { sy };
        let base_y = u64::from(dst_y) + u64::from(sy) * scale_u64;
        if base_y >= dst_h_u64 {
            continue;
        }
        for sx in 0..src_w {
            let src_col = if h_flip { src_w - 1 - sx } else { sx };
            let src_off = ((src_row as usize) * (src_w as usize) + (src_col as usize)) * 4;
            let px = &src[src_off..src_off + 4];
            if transparent_zero_alpha && px[3] == 0 {
                continue;
            }
            let base_x = u64::from(dst_x) + u64::from(sx) * scale_u64;
            if base_x >= dst_w_u64 {
                continue;
            }
            for dy in 0..scale_u64 {
                let ty = base_y + dy;
                if ty >= dst_h_u64 {
                    break;
                }
                let row_base = (ty as usize) * (dst_w as usize);
                for dx in 0..scale_u64 {
                    let tx = base_x + dx;
                    if tx >= dst_w_u64 {
                        break;
                    }
                    let dst_off = (row_base + (tx as usize)) * 4;
                    dst[dst_off..dst_off + 4].copy_from_slice(px);
                }
            }
        }
    }

    Ok(())
}

/// Crop an axis-aligned RGBA8888 sub-rectangle `(x, y, w, h)` from `src`
/// (`src_w` × `src_h`) into `dst` (`w` × `h`).
///
/// Validates buffer lengths and requires `x + w <= src_w` and `y + h <= src_h`
/// without overflow before copying.
#[allow(clippy::too_many_arguments)]
pub fn crop_rgba(
    src: &[u8],
    src_w: u32,
    src_h: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    dst: &mut [u8],
) -> Result<(), PackError> {
    let expected_src = checked_rgba_len(src_w, src_h)?;
    if src.len() != expected_src {
        return Err(PackError::LengthMismatch {
            expected: expected_src,
            actual: src.len(),
        });
    }
    let expected_dst = checked_rgba_len(w, h)?;
    if dst.len() != expected_dst {
        return Err(PackError::LengthMismatch {
            expected: expected_dst,
            actual: dst.len(),
        });
    }
    if x.checked_add(w).is_none_or(|end| end > src_w)
        || y.checked_add(h).is_none_or(|end| end > src_h)
    {
        return Err(PackError::InvalidLayout {
            reason: "crop rectangle exceeds source bounds",
        });
    }

    let row_bytes = (w as usize) * 4;
    let src_stride = (src_w as usize) * 4;
    for row in 0..(h as usize) {
        let src_off = ((y as usize) + row) * src_stride + (x as usize) * 4;
        let dst_off = row * row_bytes;
        dst[dst_off..dst_off + row_bytes].copy_from_slice(&src[src_off..src_off + row_bytes]);
    }
    Ok(())
}

/// Geometry and memory limit for [`compose_grid_atlas`].
///
/// Each rendered cell is scaled by `scale` and separated from adjacent cells
/// and the outer border by `padding` pixels on all four sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridAtlasLayout {
    /// Unscaled cell width in pixels (must be >= 1).
    pub cell_width: u32,
    /// Unscaled cell height in pixels (must be >= 1).
    pub cell_height: u32,
    /// Maximum cells per row (must be >= 1).
    pub columns: u32,
    /// Padding in pixels between cells and around the outer border.
    pub padding: u32,
    /// Nearest-neighbor integer scale factor applied to each cell (must be >= 1).
    pub scale: u32,
    /// Maximum allowed RGBA output byte length; enforced before allocation.
    pub max_bytes: usize,
}

/// Compose `count` cells rendered by `render_cell` into a single RGBA8888 grid
/// atlas, returning `(width, height, rgba)`.
///
/// `render_cell` receives the zero-based cell index and a zero-initialized
/// RGBA8888 buffer of length `cell_width * cell_height * 4`. When `count == 0`,
/// returns `(0, 0, Vec::new())`.
pub fn compose_grid_atlas(
    count: usize,
    layout: &GridAtlasLayout,
    bg: [u8; 4],
    mut render_cell: impl FnMut(usize, &mut [u8]) -> Result<(), PackError>,
) -> Result<(u32, u32, Vec<u8>), PackError> {
    if layout.cell_width == 0 || layout.cell_height == 0 || layout.columns == 0 || layout.scale == 0
    {
        return Err(PackError::InvalidLayout {
            reason: "cell_width, cell_height, columns, and scale must be at least 1",
        });
    }
    if count == 0 {
        return Ok((0, 0, Vec::new()));
    }

    let scaled_w = layout
        .cell_width
        .checked_mul(layout.scale)
        .ok_or(PackError::InvalidLayout {
            reason: "scaled cell width overflow",
        })?;
    let scaled_h =
        layout
            .cell_height
            .checked_mul(layout.scale)
            .ok_or(PackError::InvalidLayout {
                reason: "scaled cell height overflow",
            })?;

    let cols = count.min(layout.columns as usize) as u32;
    let rows = u32::try_from(count.div_ceil(layout.columns as usize)).map_err(|_| {
        PackError::InvalidLayout {
            reason: "atlas row count overflow",
        }
    })?;

    let stride_x = scaled_w
        .checked_add(layout.padding)
        .ok_or(PackError::InvalidLayout {
            reason: "atlas horizontal stride overflow",
        })?;
    let stride_y = scaled_h
        .checked_add(layout.padding)
        .ok_or(PackError::InvalidLayout {
            reason: "atlas vertical stride overflow",
        })?;

    let width = cols
        .checked_mul(stride_x)
        .and_then(|w| w.checked_add(layout.padding))
        .ok_or(PackError::InvalidLayout {
            reason: "atlas width overflow",
        })?;
    let height = rows
        .checked_mul(stride_y)
        .and_then(|h| h.checked_add(layout.padding))
        .ok_or(PackError::InvalidLayout {
            reason: "atlas height overflow",
        })?;

    let total_bytes = checked_rgba_len(width, height)?;
    if total_bytes > layout.max_bytes {
        return Err(PackError::LimitExceeded {
            requested: total_bytes,
            limit: layout.max_bytes,
        });
    }

    let cell_bytes = checked_rgba_len(layout.cell_width, layout.cell_height)?;
    let mut canvas = Vec::with_capacity(total_bytes);
    for _ in 0..(total_bytes / 4) {
        canvas.extend_from_slice(&bg);
    }

    let mut cell_buf = vec![0u8; cell_bytes];
    let columns_usize = layout.columns as usize;
    for idx in 0..count {
        cell_buf.fill(0);
        render_cell(idx, &mut cell_buf)?;
        let col = (idx % columns_usize) as u32;
        let row = (idx / columns_usize) as u32;
        let dst_x = layout.padding + col * stride_x;
        let dst_y = layout.padding + row * stride_y;
        blit_rgba(
            &mut canvas,
            width,
            height,
            dst_x,
            dst_y,
            &cell_buf,
            layout.cell_width,
            layout.cell_height,
            false,
            false,
            layout.scale,
            false,
        )?;
    }

    Ok((width, height, canvas))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blit_supports_flips_scaling_transparency_and_clipping() {
        // 2x2 source:
        // [R, T]
        // [G, B]
        let r = [255, 0, 0, 255];
        let t = [9, 9, 9, 0];
        let g = [0, 255, 0, 255];
        let b = [0, 0, 255, 255];
        let mut src = Vec::new();
        for px in [r, t, g, b] {
            src.extend_from_slice(&px);
        }

        // h_flip + v_flip reverses to:
        // [B, G]
        // [T, R]
        let bg = [10, 20, 30, 255];
        let mut dst = Vec::new();
        for _ in 0..16 {
            dst.extend_from_slice(&bg);
        }

        blit_rgba(&mut dst, 4, 4, 0, 0, &src, 2, 2, true, true, 2, true).unwrap();

        let pixel = |x: usize, y: usize| -> [u8; 4] {
            let off = (y * 4 + x) * 4;
            dst[off..off + 4].try_into().unwrap()
        };

        assert_eq!(pixel(0, 0), b);
        assert_eq!(pixel(1, 1), b);
        assert_eq!(pixel(2, 0), g);
        assert_eq!(pixel(3, 1), g);
        // Transparent pixel left background untouched.
        assert_eq!(pixel(0, 2), bg);
        assert_eq!(pixel(1, 3), bg);
        assert_eq!(pixel(2, 2), r);
        assert_eq!(pixel(3, 3), r);

        // Clipping at destination edge does not panic or error.
        let mut small = vec![0u8; 2 * 2 * 4];
        blit_rgba(&mut small, 2, 2, 1, 1, &src, 2, 2, false, false, 2, false).unwrap();
        assert_eq!(&small[12..16], &r);
    }

    #[test]
    fn compose_grid_atlas_places_cells_and_enforces_limit() {
        let layout = GridAtlasLayout {
            cell_width: 2,
            cell_height: 1,
            columns: 2,
            padding: 1,
            scale: 2,
            max_bytes: 1024,
        };
        let bg = [5, 6, 7, 255];
        let (w, h, rgba) = compose_grid_atlas(3, &layout, bg, |idx, buf| {
            let c = [(idx as u8 + 1) * 40, 0, 0, 255];
            buf[0..4].copy_from_slice(&c);
            buf[4..8].copy_from_slice(&[0, (idx as u8 + 1) * 50, 0, 255]);
            Ok(())
        })
        .unwrap();

        // cols=2, rows=2, scaled cell = 4x2, padding=1 -> w = 2*(4+1)+1 = 11, h = 2*(2+1)+1 = 7.
        assert_eq!((w, h), (11, 7));
        assert_eq!(rgba.len(), 11 * 7 * 4);

        let pixel = |x: usize, y: usize| -> [u8; 4] {
            let off = (y * 11 + x) * 4;
            rgba[off..off + 4].try_into().unwrap()
        };
        // Border pixel is background.
        assert_eq!(pixel(0, 0), bg);
        // Cell 0 starts at (1, 1), scaled 2x.
        assert_eq!(pixel(1, 1), [40, 0, 0, 255]);
        assert_eq!(pixel(3, 2), [0, 50, 0, 255]);
        // Cell 1 starts at (6, 1).
        assert_eq!(pixel(6, 1), [80, 0, 0, 255]);
        // Cell 2 starts at (1, 4).
        assert_eq!(pixel(1, 4), [120, 0, 0, 255]);
        // Empty 4th slot remains background.
        assert_eq!(pixel(6, 4), bg);

        // Enforce max_bytes before allocating.
        let tight = GridAtlasLayout {
            max_bytes: rgba.len() - 1,
            ..layout
        };
        assert_eq!(
            compose_grid_atlas(3, &tight, bg, |_, _| Ok(())),
            Err(PackError::LimitExceeded {
                requested: rgba.len(),
                limit: rgba.len() - 1,
            })
        );

        // Count 0 returns empty atlas.
        assert_eq!(
            compose_grid_atlas(0, &layout, bg, |_, _| Ok(())),
            Ok((0, 0, Vec::new()))
        );
    }

    #[test]
    fn rejects_invalid_layout_and_length_mismatches() {
        let mut dst = [0u8; 16];
        let src = [0u8; 4];
        assert!(matches!(
            blit_rgba(&mut dst, 2, 2, 0, 0, &src, 1, 1, false, false, 0, false),
            Err(PackError::InvalidLayout { .. })
        ));
        assert_eq!(
            blit_rgba(
                &mut dst[..12],
                2,
                2,
                0,
                0,
                &src,
                1,
                1,
                false,
                false,
                1,
                false
            ),
            Err(PackError::LengthMismatch {
                expected: 16,
                actual: 12,
            })
        );
    }

    #[test]
    fn crop_rgba_extracts_subrect_and_validates_bounds() {
        // 3x3 image where pixel (x, y) has color [x, y, x+y, 255].
        let mut src = Vec::with_capacity(3 * 3 * 4);
        for y in 0..3u8 {
            for x in 0..3u8 {
                src.extend_from_slice(&[x, y, x + y, 255]);
            }
        }
        let mut dst = vec![0u8; 2 * 2 * 4];
        crop_rgba(&src, 3, 3, 1, 1, 2, 2, &mut dst).unwrap();
        assert_eq!(
            dst,
            vec![
                1, 1, 2, 255, 2, 1, 3, 255, //
                1, 2, 3, 255, 2, 2, 4, 255,
            ]
        );

        // Out-of-bounds crop rejected.
        assert!(matches!(
            crop_rgba(&src, 3, 3, 2, 0, 2, 2, &mut dst),
            Err(PackError::InvalidLayout { .. })
        ));
        assert!(matches!(
            crop_rgba(&src, 3, 3, u32::MAX, 0, 1, 1, &mut [0u8; 4]),
            Err(PackError::InvalidLayout { .. })
        ));
        // Destination length mismatch rejected.
        assert_eq!(
            crop_rgba(&src, 3, 3, 0, 0, 2, 2, &mut [0u8; 8]),
            Err(PackError::LengthMismatch {
                expected: 16,
                actual: 8,
            })
        );
    }
}
