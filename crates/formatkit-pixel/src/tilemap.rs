//! Tile-mapped background mechanics: 16-bit text tilemap entries, 32×32
//! screen-block entry order, and 8×8 indexed tile blitting to RGBA.
//!
//! - [`TextTilemapEntry`] is the common 16-bit tilemap word: a 10-bit tile
//!   number (bits 0–9), horizontal flip (bit 10), vertical flip (bit 11) and a
//!   4-bit palette bank (bits 12–15).
//! - [`ScreenBlockLayout`] maps tile coordinates to entry indices for maps
//!   stored as 32×32-entry screen blocks, row-major within and between blocks,
//!   where a final band (or block column) shorter than 32 holds blocks of its
//!   own height (or width). Maps up to 32 tiles wide reduce to row-major order.
//! - [`blit_indexed_tile_8x8`] draws one 8×8 tile of palette indices into an
//!   RGBA8888 image through a palette with a bank base, flips, and optional
//!   index-0 transparency.
//!
//! ```
//! use formatkit_pixel::tilemap::{ScreenBlockLayout, TextTilemapEntry};
//!
//! let entry = TextTilemapEntry::from_raw(0x5C05);
//! assert_eq!((entry.tile, entry.h_flip, entry.v_flip, entry.palette), (5, true, true, 5));
//! assert_eq!(entry.to_raw(), 0x5C05);
//!
//! // 64×40 tiles: two 32×32 blocks, then two 32×8 blocks in the short last band.
//! let layout = ScreenBlockLayout::new(64, 40).unwrap();
//! assert_eq!(layout.index(32, 0), Some(1024));
//! assert_eq!(layout.index(0, 32), Some(2048));
//! assert_eq!(layout.index(32, 32), Some(2048 + 256));
//! ```

use crate::PackError;

/// One 16-bit text-mode tilemap entry.
#[doc(alias = "screen entry")]
#[doc(alias = "map entry")]
#[doc(alias = "nametable entry")]
#[doc(alias = "bg map")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TextTilemapEntry {
    /// Tile number, `0..=1023` (bits 0–9).
    pub tile: u16,
    /// Mirror the tile horizontally (bit 10).
    pub h_flip: bool,
    /// Mirror the tile vertically (bit 11).
    pub v_flip: bool,
    /// Palette bank, `0..=15` (bits 12–15).
    pub palette: u8,
}

impl TextTilemapEntry {
    /// Largest tile number.
    pub const MAX_TILE: u16 = 0x03ff;
    /// Largest palette bank.
    pub const MAX_PALETTE: u8 = 0x0f;

    /// Construct an entry, rejecting `tile > 1023` or `palette > 15`.
    pub fn new(tile: u16, h_flip: bool, v_flip: bool, palette: u8) -> Result<Self, PackError> {
        if tile > Self::MAX_TILE {
            return Err(PackError::InvalidLayout {
                reason: "tilemap tile number exceeds 10 bits",
            });
        }
        if palette > Self::MAX_PALETTE {
            return Err(PackError::InvalidLayout {
                reason: "tilemap palette bank exceeds 4 bits",
            });
        }
        Ok(Self {
            tile,
            h_flip,
            v_flip,
            palette,
        })
    }

    /// Decode a raw entry word.
    pub const fn from_raw(raw: u16) -> Self {
        Self {
            tile: raw & 0x03ff,
            h_flip: raw & 0x0400 != 0,
            v_flip: raw & 0x0800 != 0,
            palette: (raw >> 12) as u8,
        }
    }

    /// Encode as a raw entry word. Out-of-range `tile` and `palette` values
    /// are masked to their field widths; use [`Self::new`] to reject them.
    pub const fn to_raw(self) -> u16 {
        (self.tile & 0x03ff)
            | if self.h_flip { 0x0400 } else { 0 }
            | if self.v_flip { 0x0800 } else { 0 }
            | ((self.palette as u16 & 0x0f) << 12)
    }
}

/// Decode little-endian 16-bit tilemap words (`bytes.len()` must be even).
pub fn decode_text_tilemap_le(bytes: &[u8]) -> Result<Vec<TextTilemapEntry>, PackError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(PackError::LengthMismatch {
            expected: bytes.len() + 1,
            actual: bytes.len(),
        });
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| TextTilemapEntry::from_raw(u16::from_le_bytes([c[0], c[1]])))
        .collect())
}

/// Encode entries as little-endian 16-bit words (fields masked as in
/// [`TextTilemapEntry::to_raw`]).
pub fn encode_text_tilemap_le(entries: &[TextTilemapEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 2);
    for e in entries {
        out.extend_from_slice(&e.to_raw().to_le_bytes());
    }
    out
}

/// Entry order of a tilemap stored as 32×32-entry screen blocks.
///
/// Blocks are row-major within and between themselves. Every band of block
/// rows is 32 tiles tall except a shorter final band, whose blocks are only
/// as tall as the band; likewise a final block column narrower than 32 holds
/// blocks of its own width. For maps at most 32 tiles wide this is plain
/// row-major order.
#[doc(alias = "screen block")]
#[doc(alias = "screenblock")]
#[doc(alias = "tilemap order")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScreenBlockLayout {
    width: usize,
    height: usize,
}

impl ScreenBlockLayout {
    /// Block edge length in entries.
    pub const BLOCK: usize = 32;

    /// A layout for a `width` × `height` tile map. Rejects zero dimensions
    /// and entry counts that overflow `usize`.
    pub fn new(width: usize, height: usize) -> Result<Self, PackError> {
        if width == 0 || height == 0 {
            return Err(PackError::InvalidLayout {
                reason: "tilemap dimensions must be non-zero",
            });
        }
        width.checked_mul(height).ok_or(PackError::InvalidLayout {
            reason: "tilemap entry count overflows usize",
        })?;
        Ok(Self { width, height })
    }

    /// Map width in tiles.
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Map height in tiles.
    pub const fn height(&self) -> usize {
        self.height
    }

    /// Total entry count.
    pub const fn len(&self) -> usize {
        self.width * self.height
    }

    /// Always `false`: dimensions are non-zero.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Stored entry index of tile (`x`, `y`), or `None` outside the map.
    pub fn index(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let b = Self::BLOCK;
        let band = y / b;
        let rows = b.min(self.height - band * b);
        let column = x / b;
        let cols = b.min(self.width - column * b);
        Some(band * b * self.width + column * b * rows + (y % b) * cols + x % b)
    }

    /// Reorder entries from this block order into row-major order.
    pub fn blocks_to_row_major<T: Copy>(&self, blocked: &[T]) -> Result<Vec<T>, PackError> {
        self.check_len(blocked.len())?;
        let mut out = Vec::with_capacity(self.len());
        for y in 0..self.height {
            for x in 0..self.width {
                out.push(blocked[self.index(x, y).expect("in bounds")]);
            }
        }
        Ok(out)
    }

    /// Reorder row-major entries into this block order.
    pub fn row_major_to_blocks<T: Copy>(&self, row_major: &[T]) -> Result<Vec<T>, PackError> {
        self.check_len(row_major.len())?;
        let mut out = row_major.to_vec();
        for y in 0..self.height {
            for x in 0..self.width {
                out[self.index(x, y).expect("in bounds")] = row_major[y * self.width + x];
            }
        }
        Ok(out)
    }

    fn check_len(&self, actual: usize) -> Result<(), PackError> {
        if actual != self.len() {
            return Err(PackError::LengthMismatch {
                expected: self.len(),
                actual,
            });
        }
        Ok(())
    }
}

/// Drawing options for [`blit_indexed_tile_8x8`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexedTileBlit {
    /// Mirror horizontally.
    pub h_flip: bool,
    /// Mirror vertically.
    pub v_flip: bool,
    /// Added to every pixel index before the palette lookup (for example
    /// `16 * bank` for 4-bit tiles).
    pub palette_base: usize,
    /// Leave the destination unchanged where the pixel index (before adding
    /// `palette_base`) is `0`.
    pub transparent_zero: bool,
}

/// Draw one 8×8 tile of palette indices (row-major, 64 entries) into an
/// RGBA8888 image of `dst_w` × `dst_h` pixels at (`x`, `y`).
///
/// Pixels outside the destination are clipped. Rejects a destination whose
/// length is not `dst_w * dst_h * 4`, and any drawn pixel whose
/// `palette_base + index` falls outside `palette` (reported as
/// [`PackError::IndexOutOfRange`] with the tile pixel position).
///
/// ```
/// use formatkit_pixel::tilemap::{blit_indexed_tile_8x8, IndexedTileBlit};
///
/// let mut tile = [0u8; 64];
/// tile[0] = 1; // top-left pixel
/// let palette = [[0, 0, 0, 0], [9, 9, 9, 255], [0, 0, 0, 0], [7, 7, 7, 255]];
/// let mut dst = vec![0u8; 8 * 8 * 4];
/// let opts = IndexedTileBlit { h_flip: true, palette_base: 2, transparent_zero: true, ..Default::default() };
/// blit_indexed_tile_8x8(&mut dst, 8, 8, 0, 0, &tile, &palette, &opts).unwrap();
/// assert_eq!(&dst[7 * 4..8 * 4], &[7, 7, 7, 255]); // flipped to the top-right
/// assert_eq!(&dst[..4], &[0, 0, 0, 0]); // index 0 left transparent
/// ```
#[allow(clippy::too_many_arguments)]
pub fn blit_indexed_tile_8x8(
    dst: &mut [u8],
    dst_w: u32,
    dst_h: u32,
    x: i64,
    y: i64,
    tile: &[u8; 64],
    palette: &[[u8; 4]],
    options: &IndexedTileBlit,
) -> Result<(), PackError> {
    let expected = (dst_w as usize)
        .checked_mul(dst_h as usize)
        .and_then(|p| p.checked_mul(4))
        .ok_or(PackError::InvalidLayout {
            reason: "RGBA image dimensions overflow usize",
        })?;
    if dst.len() != expected {
        return Err(PackError::LengthMismatch {
            expected,
            actual: dst.len(),
        });
    }
    for ty in 0..8usize {
        let dy = y + ty as i64;
        if dy < 0 || dy >= i64::from(dst_h) {
            continue;
        }
        let sy = if options.v_flip { 7 - ty } else { ty };
        for tx in 0..8usize {
            let dx = x + tx as i64;
            if dx < 0 || dx >= i64::from(dst_w) {
                continue;
            }
            let sx = if options.h_flip { 7 - tx } else { tx };
            let pos = sy * 8 + sx;
            let index = tile[pos];
            if index == 0 && options.transparent_zero {
                continue;
            }
            let color = options
                .palette_base
                .checked_add(usize::from(index))
                .and_then(|i| palette.get(i))
                .ok_or(PackError::IndexOutOfRange {
                    index: pos,
                    value: index,
                })?;
            let at = (dy as usize * dst_w as usize + dx as usize) * 4;
            dst[at..at + 4].copy_from_slice(color);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_bits_round_trip_and_validate() {
        for raw in [0u16, 0x03ff, 0x0400, 0x0800, 0xf000, 0xabcd, 0xffff] {
            assert_eq!(TextTilemapEntry::from_raw(raw).to_raw(), raw);
        }
        let e = TextTilemapEntry::new(1023, false, true, 15).unwrap();
        assert_eq!(e.to_raw(), 0xfbff);
        assert!(TextTilemapEntry::new(1024, false, false, 0).is_err());
        assert!(TextTilemapEntry::new(0, false, false, 16).is_err());
        let masked = TextTilemapEntry {
            tile: 0x0fff,
            palette: 0x1f,
            ..Default::default()
        };
        assert_eq!(masked.to_raw(), 0xf3ff);

        let bytes = [0x05, 0x5c, 0xff, 0x03];
        let entries = decode_text_tilemap_le(&bytes).unwrap();
        assert_eq!(entries[1].tile, 1023);
        assert_eq!(encode_text_tilemap_le(&entries), bytes);
        assert!(decode_text_tilemap_le(&bytes[..3]).is_err());
    }

    #[test]
    fn screen_blocks_match_row_major_blocks_and_short_band() {
        // Square two-by-two block map.
        let l = ScreenBlockLayout::new(64, 64).unwrap();
        assert_eq!(l.index(0, 0), Some(0));
        assert_eq!(l.index(31, 0), Some(31));
        assert_eq!(l.index(0, 1), Some(32));
        assert_eq!(l.index(32, 0), Some(1024));
        assert_eq!(l.index(0, 32), Some(2048));
        assert_eq!(l.index(63, 63), Some(4095));
        assert_eq!(l.index(64, 0), None);

        // Short final band of 8 rows.
        let l = ScreenBlockLayout::new(64, 40).unwrap();
        assert_eq!(l.index(0, 33), Some(2048 + 32));
        assert_eq!(l.index(32, 32), Some(2048 + 256));
        assert_eq!(l.index(63, 39), Some(64 * 40 - 1));

        // Narrow maps reduce to row-major; a short last block column is
        // packed to its own width.
        let narrow = ScreenBlockLayout::new(20, 50).unwrap();
        for y in 0..50 {
            for x in 0..20 {
                assert_eq!(narrow.index(x, y), Some(y * 20 + x));
            }
        }
        let ragged = ScreenBlockLayout::new(40, 8).unwrap();
        assert_eq!(ragged.index(32, 0), Some(256));
        assert_eq!(ragged.index(32, 1), Some(256 + 8));
        assert!(ScreenBlockLayout::new(0, 1).is_err());
    }

    #[test]
    fn screen_block_index_is_a_bijection_and_reorders_round_trip() {
        for (w, h) in [(64, 64), (96, 40), (40, 70), (33, 1), (1, 1), (128, 33)] {
            let l = ScreenBlockLayout::new(w, h).unwrap();
            let mut seen = vec![false; l.len()];
            for y in 0..h {
                for x in 0..w {
                    let i = l.index(x, y).unwrap();
                    assert!(!seen[i], "{w}x{h} duplicate at {x},{y}");
                    seen[i] = true;
                }
            }
            let row_major: Vec<usize> = (0..l.len()).collect();
            let blocked = l.row_major_to_blocks(&row_major).unwrap();
            assert_eq!(l.blocks_to_row_major(&blocked).unwrap(), row_major);
        }
        let l = ScreenBlockLayout::new(64, 32).unwrap();
        assert!(l.blocks_to_row_major(&[0u16; 10]).is_err());
    }

    #[test]
    fn tile_blit_flips_clips_and_reports_palette_overrun() {
        let mut tile = [0u8; 64];
        for (i, t) in tile.iter_mut().enumerate() {
            *t = (i % 4) as u8;
        }
        let palette: Vec<[u8; 4]> = (0..8u8).map(|i| [i, i, i, 255]).collect();
        let mut dst = vec![0xeeu8; 10 * 10 * 4];
        let opts = IndexedTileBlit {
            v_flip: true,
            palette_base: 4,
            transparent_zero: true,
            ..Default::default()
        };
        blit_indexed_tile_8x8(&mut dst, 10, 10, 4, -2, &tile, &palette, &opts).unwrap();
        // Destination row 0 is tile row 2 (y = -2), read from source row 5
        // under the vertical flip; source index = column % 4.
        let px = |x: usize, y: usize| &dst[(y * 10 + x) * 4..(y * 10 + x) * 4 + 4];
        assert_eq!(px(4, 0), &[0xee; 4]); // source index 0: transparent
        assert_eq!(px(5, 0), &[5, 5, 5, 255]);
        assert_eq!(px(9, 0), &[5, 5, 5, 255]); // tx 5 -> index 1
        assert_eq!(px(3, 0), &[0xee; 4]); // left of the tile
        assert_eq!(px(4, 6), &[0xee; 4]); // below the clipped tile

        let opaque = IndexedTileBlit {
            palette_base: 5,
            ..Default::default()
        };
        assert!(matches!(
            blit_indexed_tile_8x8(&mut dst, 10, 10, 0, 0, &tile, &palette, &opaque),
            Err(PackError::IndexOutOfRange { index: 3, value: 3 })
        ));
        assert!(
            blit_indexed_tile_8x8(&mut dst[..4], 10, 10, 0, 0, &tile, &palette, &opaque).is_err()
        );
    }
}
