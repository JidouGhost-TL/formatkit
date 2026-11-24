//! Deterministic palette lookup, ramp generation, and median-cut quantization.

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap};

use crate::PackError;

/// Color distance metric used when matching or quantizing RGBA pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteDistanceMetric {
    /// Squared Euclidean distance across the red, green, and blue channels only.
    Rgb,
    /// Squared Euclidean distance across all four red, green, blue, and alpha channels.
    Rgba,
}

#[inline]
fn channel_sq_diff(a: u8, b: u8) -> u32 {
    let d = i32::from(a) - i32::from(b);
    (d * d) as u32
}

#[inline]
fn color_distance(a: [u8; 4], b: [u8; 4], metric: PaletteDistanceMetric) -> u32 {
    let rgb =
        channel_sq_diff(a[0], b[0]) + channel_sq_diff(a[1], b[1]) + channel_sq_diff(a[2], b[2]);
    match metric {
        PaletteDistanceMetric::Rgb => rgb,
        PaletteDistanceMetric::Rgba => rgb + channel_sq_diff(a[3], b[3]),
    }
}

/// Return the index of the palette entry closest to `pixel` under `metric`.
///
/// Ties are broken deterministically in favor of the lowest palette index.
/// Returns `None` when `palette` is empty.
#[must_use]
pub fn nearest_palette_index(
    pixel: [u8; 4],
    palette: &[[u8; 4]],
    metric: PaletteDistanceMetric,
) -> Option<usize> {
    let mut best_idx = None;
    let mut best_dist = u32::MAX;
    for (idx, &entry) in palette.iter().enumerate() {
        let dist = color_distance(pixel, entry, metric);
        if best_idx.is_none() || dist < best_dist {
            best_dist = dist;
            best_idx = Some(idx);
            if dist == 0 {
                break;
            }
        }
    }
    best_idx
}

/// Build an opaque linear grayscale RGBA palette with `count` entries.
///
/// - `count == 0` returns an empty vector.
/// - `count == 1` returns `[[0, 0, 0, 255]]`.
/// - `count >= 2` spaces luminance evenly from `0` to `255` with nearest-integer rounding.
#[must_use]
pub fn grayscale_palette(count: usize) -> Vec<[u8; 4]> {
    match count {
        0 => Vec::new(),
        1 => vec![[0, 0, 0, 255]],
        n => {
            let denom = (n - 1) as u64;
            let half = denom / 2;
            (0..n)
                .map(|i| {
                    let v = (((i as u64) * 255 + half) / denom) as u8;
                    [v, v, v, 255]
                })
                .collect()
        }
    }
}

#[derive(Debug, Clone)]
struct ColorBox {
    entries: Vec<([u8; 4], usize)>,
    split_ch: usize,
    range: u8,
    total_count: usize,
    seq: usize,
}

impl ColorBox {
    fn new(entries: Vec<([u8; 4], usize)>, channel_count: usize, seq: usize) -> Self {
        let mut min_c = [255u8; 4];
        let mut max_c = [0u8; 4];
        let mut total_count = 0usize;
        for &(c, count) in &entries {
            total_count += count;
            for ch in 0..channel_count {
                if c[ch] < min_c[ch] {
                    min_c[ch] = c[ch];
                }
                if c[ch] > max_c[ch] {
                    max_c[ch] = c[ch];
                }
            }
        }
        let mut split_ch = 0usize;
        let mut range = 0u8;
        for ch in 0..channel_count {
            let r = max_c[ch].saturating_sub(min_c[ch]);
            if r > range {
                range = r;
                split_ch = ch;
            }
        }
        Self {
            entries,
            split_ch,
            range,
            total_count,
            seq,
        }
    }

    fn average_color(&self) -> [u8; 4] {
        let mut sums = [0u64; 4];
        let mut total = 0u64;
        for &(c, count) in &self.entries {
            let n = count as u64;
            total += n;
            for ch in 0..4 {
                sums[ch] += u64::from(c[ch]) * n;
            }
        }
        if total == 0 {
            return [0, 0, 0, 255];
        }
        let half = total / 2;
        [
            ((sums[0] + half) / total) as u8,
            ((sums[1] + half) / total) as u8,
            ((sums[2] + half) / total) as u8,
            ((sums[3] + half) / total) as u8,
        ]
    }
}

impl PartialEq for ColorBox {
    fn eq(&self, other: &Self) -> bool {
        (self.range, self.total_count, Reverse(self.seq))
            == (other.range, other.total_count, Reverse(other.seq))
    }
}

impl Eq for ColorBox {}

impl PartialOrd for ColorBox {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ColorBox {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.range, self.total_count, Reverse(self.seq)).cmp(&(
            other.range,
            other.total_count,
            Reverse(other.seq),
        ))
    }
}

/// Deterministically quantize tightly packed RGBA8888 pixels to at most `max_colors`
/// palette entries using median-cut, returning `(palette, indices)`.
///
/// - `rgba.len()` must be a multiple of `4`.
/// - `max_colors` must be in `1..=256`.
/// - If the input contains at most `max_colors` unique colors, the exact unique
///   palette is preserved without loss.
/// - All tie-breaking is deterministic (ordered by channel range, pixel count,
///   and lexicographic RGBA value).
pub fn quantize_rgba(
    rgba: &[u8],
    max_colors: usize,
    metric: PaletteDistanceMetric,
) -> Result<(Vec<[u8; 4]>, Vec<u8>), PackError> {
    if !rgba.len().is_multiple_of(4) {
        return Err(PackError::LengthMismatch {
            expected: rgba.len() + (4 - rgba.len() % 4),
            actual: rgba.len(),
        });
    }
    if max_colors == 0 || max_colors > 256 {
        return Err(PackError::InvalidLayout {
            reason: "max_colors must be in 1..=256",
        });
    }
    if rgba.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut histogram: HashMap<[u8; 4], usize> = HashMap::new();
    for px in rgba.chunks_exact(4) {
        let color = [px[0], px[1], px[2], px[3]];
        *histogram.entry(color).or_insert(0) += 1;
    }

    let pixel_count = rgba.len() / 4;
    if histogram.len() <= max_colors {
        let mut palette: Vec<[u8; 4]> = histogram.keys().copied().collect();
        palette.sort_unstable();
        let mut indices = Vec::with_capacity(pixel_count);
        match metric {
            PaletteDistanceMetric::Rgba => {
                let mut color_to_idx: HashMap<[u8; 4], u8> = HashMap::with_capacity(palette.len());
                for (idx, &c) in palette.iter().enumerate() {
                    color_to_idx.insert(c, idx as u8);
                }
                for px in rgba.chunks_exact(4) {
                    indices.push(color_to_idx[&[px[0], px[1], px[2], px[3]]]);
                }
            }
            PaletteDistanceMetric::Rgb => {
                let mut rgb_to_idx: HashMap<[u8; 3], u8> = HashMap::with_capacity(palette.len());
                for (idx, &c) in palette.iter().enumerate() {
                    rgb_to_idx.entry([c[0], c[1], c[2]]).or_insert(idx as u8);
                }
                for px in rgba.chunks_exact(4) {
                    indices.push(rgb_to_idx[&[px[0], px[1], px[2]]]);
                }
            }
        }
        return Ok((palette, indices));
    }

    let unique_count = histogram.len();
    let channel_count = match metric {
        PaletteDistanceMetric::Rgb => 3,
        PaletteDistanceMetric::Rgba => 4,
    };
    let mut next_seq = 0usize;
    let initial = ColorBox::new(histogram.into_iter().collect(), channel_count, next_seq);
    next_seq += 1;

    let mut heap = BinaryHeap::new();
    let mut done = Vec::new();
    if initial.entries.len() > 1 {
        heap.push(initial);
    } else {
        done.push(initial);
    }

    while heap.len() + done.len() < max_colors {
        let Some(mut chosen) = heap.pop() else {
            break;
        };
        let split_ch = chosen.split_ch;
        let total_count = chosen.total_count;
        chosen.entries.sort_unstable_by(|(a, _), (b, _)| {
            a[split_ch].cmp(&b[split_ch]).then_with(|| a.cmp(b))
        });

        let half = total_count / 2;
        let mut acc = 0usize;
        let mut split_at = 1usize;
        for (i, &(_, count)) in chosen.entries.iter().enumerate() {
            acc += count;
            if acc >= half {
                split_at = (i + 1).clamp(1, chosen.entries.len() - 1);
                break;
            }
        }
        let right_entries = chosen.entries.split_off(split_at);
        let left_box = ColorBox::new(chosen.entries, channel_count, next_seq);
        next_seq += 1;
        let right_box = ColorBox::new(right_entries, channel_count, next_seq);
        next_seq += 1;

        for b in [left_box, right_box] {
            if b.entries.len() > 1 {
                heap.push(b);
            } else {
                done.push(b);
            }
        }
    }

    done.extend(heap);
    let mut palette: Vec<[u8; 4]> = done.iter().map(ColorBox::average_color).collect();
    palette.sort_unstable();
    palette.dedup();

    let mut color_to_idx: HashMap<[u8; 4], u8> = HashMap::with_capacity(unique_count);
    for b in done {
        for (color, _) in b.entries {
            let idx = nearest_palette_index(color, &palette, metric).unwrap_or(0) as u8;
            color_to_idx.insert(color, idx);
        }
    }

    let mut indices = Vec::with_capacity(pixel_count);
    for px in rgba.chunks_exact(4) {
        let color = [px[0], px[1], px[2], px[3]];
        indices.push(color_to_idx[&color]);
    }
    Ok((palette, indices))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_palette_index_handles_empty_metrics_and_deterministic_ties() {
        assert_eq!(
            nearest_palette_index([10, 20, 30, 255], &[], PaletteDistanceMetric::Rgb),
            None
        );
        let pal = [[0, 0, 0, 255], [100, 0, 0, 0], [100, 0, 0, 255]];
        // Under RGB metric, entries 1 and 2 are equidistant (0); lowest index wins.
        assert_eq!(
            nearest_palette_index([100, 0, 0, 255], &pal, PaletteDistanceMetric::Rgb),
            Some(1)
        );
        // Under RGBA metric, entry 2 is exact.
        assert_eq!(
            nearest_palette_index([100, 0, 0, 255], &pal, PaletteDistanceMetric::Rgba),
            Some(2)
        );
    }

    #[test]
    fn grayscale_palette_endpoints_and_sizes() {
        assert!(grayscale_palette(0).is_empty());
        assert_eq!(grayscale_palette(1), vec![[0, 0, 0, 255]]);
        assert_eq!(
            grayscale_palette(2),
            vec![[0, 0, 0, 255], [255, 255, 255, 255]]
        );
        assert_eq!(
            grayscale_palette(4),
            vec![
                [0, 0, 0, 255],
                [85, 85, 85, 255],
                [170, 170, 170, 255],
                [255, 255, 255, 255]
            ]
        );
        let p256 = grayscale_palette(256);
        assert_eq!(p256.len(), 256);
        assert_eq!(p256[0], [0, 0, 0, 255]);
        assert_eq!(p256[128], [128, 128, 128, 255]);
        assert_eq!(p256[255], [255, 255, 255, 255]);
    }

    #[test]
    fn quantize_rgba_preserves_small_palettes_and_quantizes_deterministically() {
        let exact_in = [
            255, 0, 0, 255, // red
            0, 255, 0, 255, // green
            255, 0, 0, 255, // red
        ];
        let (pal, idx) = quantize_rgba(&exact_in, 16, PaletteDistanceMetric::Rgba).unwrap();
        assert_eq!(pal.len(), 2);
        assert_eq!(pal[idx[0] as usize], [255, 0, 0, 255]);
        assert_eq!(pal[idx[1] as usize], [0, 255, 0, 255]);
        assert_eq!(idx[0], idx[2]);

        // 64 distinct colors quantized down to 8 must be deterministic and bounded.
        let mut gradient = Vec::with_capacity(64 * 4);
        for i in 0..64u8 {
            gradient.extend_from_slice(&[i * 4, 255 - i * 4, i.wrapping_mul(7), 255]);
        }
        let (p1, i1) = quantize_rgba(&gradient, 8, PaletteDistanceMetric::Rgb).unwrap();
        let (p2, i2) = quantize_rgba(&gradient, 8, PaletteDistanceMetric::Rgb).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(i1, i2);
        assert!(p1.len() <= 8);
        assert_eq!(i1.len(), 64);
        assert!(i1.iter().all(|&x| (x as usize) < p1.len()));

        // Validation errors.
        assert!(quantize_rgba(&[0, 1, 2], 4, PaletteDistanceMetric::Rgb).is_err());
        assert!(quantize_rgba(&exact_in, 0, PaletteDistanceMetric::Rgb).is_err());
        assert!(quantize_rgba(&exact_in, 257, PaletteDistanceMetric::Rgb).is_err());
        assert_eq!(
            quantize_rgba(&[], 16, PaletteDistanceMetric::Rgb).unwrap(),
            (Vec::new(), Vec::new())
        );
    }
}
