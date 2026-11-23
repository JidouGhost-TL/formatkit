//! Bounded deterministic ZSoft PCX encoder and decoder.
//!
//! Decoding validates the 128-byte PCX header (`manufacturer == 0x0A`,
//! `encoding` 0 uncompressed or 1 RLE), checks dimensions, scanline stride,
//! and pixel/work limits before allocating, and decodes to an RGBA8 [`Image`]:
//! - 8bpp 1-plane indexed with trailing `0x0C` + 768-byte VGA RGB24 palette
//!   (falling back to the 16-color EGA header palette when `version < 5` or no
//!   `0x0C` palette marker is present),
//! - 8bpp 3-plane 24-bit RGB,
//! - 1bpp 1-plane monochrome, and
//! - 1bpp 4-plane 16-color EGA.
//!
//! Encoding emits deterministic version 5 RLE-compressed PCX streams for
//! 24-bit RGB ([`encode_pcx_rgba`]) and 256-color indexed
//! ([`encode_pcx_indexed`]) images while enforcing `max_bytes`.

use formatkit_core::{Error, Image, Result};

const PCX_HEADER_LEN: usize = 128;
const PCX_MANUFACTURER: u8 = 0x0A;
const PCX_PALETTE_MARKER: u8 = 0x0C;
const PCX_VGA_PALETTE_LEN: usize = 768;
const PCX_VGA_TRAILER_LEN: usize = 1 + PCX_VGA_PALETTE_LEN;
const MAX_PCX_8BPP_WIDTH: u32 = 65534;
const MAX_PCX_HEIGHT: u32 = 65536;

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn rle_encode_plane(
    plane: &[u8],
    out: &mut Vec<u8>,
    max_bytes: usize,
    reserved_tail: usize,
) -> Result<()> {
    let mut i = 0;
    while i < plane.len() {
        let val = plane[i];
        let mut run = 1usize;
        while i + run < plane.len() && run < 63 && plane[i + run] == val {
            run += 1;
        }
        if run > 1 || val >= 0xC0 {
            let needed = out
                .len()
                .checked_add(2)
                .and_then(|n| n.checked_add(reserved_tail))
                .ok_or(Error::ResourceLimit {
                    resource: "PCX output bytes",
                    requested: u64::MAX,
                    limit: max_bytes as u64,
                })?;
            if needed > max_bytes {
                return Err(Error::ResourceLimit {
                    resource: "PCX output bytes",
                    requested: needed as u64,
                    limit: max_bytes as u64,
                });
            }
            out.push(0xC0 | (run as u8));
            out.push(val);
        } else {
            let needed = out
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_add(reserved_tail))
                .ok_or(Error::ResourceLimit {
                    resource: "PCX output bytes",
                    requested: u64::MAX,
                    limit: max_bytes as u64,
                })?;
            if needed > max_bytes {
                return Err(Error::ResourceLimit {
                    resource: "PCX output bytes",
                    requested: needed as u64,
                    limit: max_bytes as u64,
                });
            }
            out.push(val);
        }
        i += run;
    }
    Ok(())
}

fn write_pcx_header(
    out: &mut Vec<u8>,
    width: u32,
    height: u32,
    color_planes: u8,
    bytes_per_line: u16,
    ega_palette: &[u8; 48],
) {
    let mut header = [0u8; PCX_HEADER_LEN];
    header[0] = PCX_MANUFACTURER;
    header[1] = 5; // version 5 (3.0+)
    header[2] = 1; // RLE encoding
    header[3] = 8; // bits per pixel per plane
                   // xmin = 0, ymin = 0
    header[8..10].copy_from_slice(&((width - 1) as u16).to_le_bytes());
    header[10..12].copy_from_slice(&((height - 1) as u16).to_le_bytes());
    header[12..14].copy_from_slice(&72u16.to_le_bytes());
    header[14..16].copy_from_slice(&72u16.to_le_bytes());
    header[16..64].copy_from_slice(ega_palette);
    header[64] = 0; // reserved
    header[65] = color_planes;
    header[66..68].copy_from_slice(&bytes_per_line.to_le_bytes());
    header[68..70].copy_from_slice(&1u16.to_le_bytes()); // color/BW palette info
    out.extend_from_slice(&header);
}

/// Encode an RGBA8 [`Image`] into a deterministic 24-bit (8bpp, 3-plane) RLE
/// ZSoft PCX byte stream.
///
/// Alpha values are discarded because PCX does not store an alpha channel.
/// Enforces `max_bytes` before allocating or growing output beyond the limit.
pub fn encode_pcx_rgba(image: &Image, max_bytes: usize) -> Result<Vec<u8>> {
    image.validate()?;
    if image.width == 0
        || image.height == 0
        || image.width > MAX_PCX_8BPP_WIDTH
        || image.height > MAX_PCX_HEIGHT
    {
        return Err(Error::InvalidField {
            what: "PCX dimensions",
            value: (u64::from(image.width) << 32) | u64::from(image.height),
        });
    }
    if max_bytes < PCX_HEADER_LEN {
        return Err(Error::ResourceLimit {
            resource: "PCX output bytes",
            requested: PCX_HEADER_LEN as u64,
            limit: max_bytes as u64,
        });
    }

    let width = image.width as usize;
    let height = image.height as usize;
    let bytes_per_line = width + (width & 1);
    let bpl_u16 = u16::try_from(bytes_per_line).map_err(|_| Error::InvalidField {
        what: "PCX bytes_per_line",
        value: bytes_per_line as u64,
    })?;

    let mut out = Vec::with_capacity(PCX_HEADER_LEN.min(max_bytes));
    write_pcx_header(&mut out, image.width, image.height, 3, bpl_u16, &[0u8; 48]);

    let mut plane_buf = vec![0u8; bytes_per_line];
    let row_rgba_bytes = width * 4;
    for y in 0..height {
        let row = &image.rgba[y * row_rgba_bytes..(y + 1) * row_rgba_bytes];
        for channel in 0..3 {
            for x in 0..width {
                plane_buf[x] = row[x * 4 + channel];
            }
            if bytes_per_line > width {
                plane_buf[width] = 0;
            }
            rle_encode_plane(&plane_buf, &mut out, max_bytes, 0)?;
        }
    }

    Ok(out)
}

/// Encode an 8-bit indexed image and 256-color RGB24 VGA palette into a
/// deterministic version 5 RLE ZSoft PCX byte stream.
///
/// The first 16 palette entries are mirrored into the 48-byte EGA header
/// palette, and the full 256-color palette is appended after the `0x0C`
/// trailer marker. Enforces `max_bytes` including header and trailer.
pub fn encode_pcx_indexed(
    width: u32,
    height: u32,
    indices: &[u8],
    palette_rgb: &[u8; PCX_VGA_PALETTE_LEN],
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if width == 0 || height == 0 || width > MAX_PCX_8BPP_WIDTH || height > MAX_PCX_HEIGHT {
        return Err(Error::InvalidField {
            what: "PCX dimensions",
            value: (u64::from(width) << 32) | u64::from(height),
        });
    }
    let expected_pixels =
        (width as usize)
            .checked_mul(height as usize)
            .ok_or(Error::InvalidField {
                what: "PCX dimensions",
                value: (u64::from(width) << 32) | u64::from(height),
            })?;
    if indices.len() != expected_pixels {
        return Err(Error::InvalidField {
            what: "PCX indexed pixel count",
            value: indices.len() as u64,
        });
    }

    let min_len = PCX_HEADER_LEN + PCX_VGA_TRAILER_LEN;
    if max_bytes < min_len {
        return Err(Error::ResourceLimit {
            resource: "PCX output bytes",
            requested: min_len as u64,
            limit: max_bytes as u64,
        });
    }

    let w = width as usize;
    let h = height as usize;
    let bytes_per_line = w + (w & 1);
    let bpl_u16 = u16::try_from(bytes_per_line).map_err(|_| Error::InvalidField {
        what: "PCX bytes_per_line",
        value: bytes_per_line as u64,
    })?;

    let mut ega_palette = [0u8; 48];
    ega_palette.copy_from_slice(&palette_rgb[..48]);

    let mut out = Vec::with_capacity(min_len.min(max_bytes));
    write_pcx_header(&mut out, width, height, 1, bpl_u16, &ega_palette);

    let mut plane_buf = vec![0u8; bytes_per_line];
    for y in 0..h {
        let row = &indices[y * w..(y + 1) * w];
        plane_buf[..w].copy_from_slice(row);
        if bytes_per_line > w {
            plane_buf[w] = 0;
        }
        rle_encode_plane(&plane_buf, &mut out, max_bytes, PCX_VGA_TRAILER_LEN)?;
    }

    out.push(PCX_PALETTE_MARKER);
    out.extend_from_slice(palette_rgb);
    debug_assert!(out.len() <= max_bytes);
    Ok(out)
}

/// Decode a ZSoft PCX byte stream into an RGBA8 [`Image`].
///
/// Supports:
/// - 8bpp 1-plane indexed (256-color trailing `0x0C` VGA palette, or 16-color
///   header EGA palette fallback when `version < 5` or no `0x0C` marker is
///   present),
/// - 8bpp 3-plane 24-bit RGB,
/// - 1bpp 1-plane monochrome, and
/// - 1bpp 4-plane 16-color EGA.
///
/// Enforces `max_pixels` and bounded scanline work before allocating output
/// buffers.
pub fn decode_pcx_rgba(bytes: &[u8], max_pixels: u64) -> Result<Image> {
    if bytes.len() < PCX_HEADER_LEN {
        return Err(Error::Truncated {
            offset: 0,
            needed: PCX_HEADER_LEN,
            available: bytes.len(),
        });
    }

    let manufacturer = bytes[0];
    if manufacturer != PCX_MANUFACTURER {
        return Err(Error::Malformed("invalid PCX manufacturer byte".into()));
    }

    let version = bytes[1];
    if !matches!(version, 0 | 2 | 3 | 4 | 5) {
        return Err(Error::InvalidField {
            what: "PCX version",
            value: u64::from(version),
        });
    }

    let encoding = bytes[2];
    if !matches!(encoding, 0 | 1) {
        return Err(Error::InvalidField {
            what: "PCX encoding",
            value: u64::from(encoding),
        });
    }

    let bits_per_pixel = bytes[3];
    let xmin = read_u16_le(bytes, 4);
    let ymin = read_u16_le(bytes, 6);
    let xmax = read_u16_le(bytes, 8);
    let ymax = read_u16_le(bytes, 10);
    if xmax < xmin || ymax < ymin {
        return Err(Error::InvalidField {
            what: "PCX bounds",
            value: (u64::from(xmax) << 16) | u64::from(ymax),
        });
    }

    let width = u32::from(xmax - xmin) + 1;
    let height = u32::from(ymax - ymin) + 1;
    let pixels = u64::from(width) * u64::from(height);
    if pixels > max_pixels {
        return Err(Error::ResourceLimit {
            resource: "PCX pixels",
            requested: pixels,
            limit: max_pixels,
        });
    }

    let ega_palette = &bytes[16..64];
    let color_planes = bytes[65];
    let bytes_per_line = usize::from(read_u16_le(bytes, 66));

    match (bits_per_pixel, color_planes) {
        (8, 1) | (8, 3) | (1, 1) | (1, 4) => {}
        _ => {
            return Err(Error::Unsupported(format!(
                "PCX bits_per_pixel={bits_per_pixel}, color_planes={color_planes}"
            )));
        }
    }

    let min_bytes_per_line = match bits_per_pixel {
        8 => width as usize,
        1 => (width as usize).div_ceil(8),
        _ => unreachable!(),
    };
    if bytes_per_line == 0 || bytes_per_line < min_bytes_per_line {
        return Err(Error::InvalidField {
            what: "PCX bytes_per_line",
            value: bytes_per_line as u64,
        });
    }

    let scanline_stride = bytes_per_line
        .checked_mul(usize::from(color_planes))
        .ok_or(Error::InvalidField {
            what: "PCX scanline stride",
            value: bytes_per_line as u64,
        })?;
    let total_scanline_bytes = (scanline_stride as u64)
        .checked_mul(u64::from(height))
        .ok_or(Error::ResourceLimit {
            resource: "PCX decoded scanline bytes",
            requested: u64::MAX,
            limit: max_pixels.saturating_mul(4),
        })?;
    let max_scanline_work = max_pixels
        .saturating_mul(4)
        .saturating_add(u64::from(height).saturating_mul(64));
    if total_scanline_bytes > max_scanline_work {
        return Err(Error::ResourceLimit {
            resource: "PCX decoded scanline bytes",
            requested: total_scanline_bytes,
            limit: max_scanline_work,
        });
    }

    let rgba_len = Image::rgba_len(width, height)?;
    let available_stream = bytes.len() - PCX_HEADER_LEN;
    if encoding == 0 {
        if (available_stream as u64) < total_scanline_bytes {
            return Err(Error::Truncated {
                offset: PCX_HEADER_LEN,
                needed: total_scanline_bytes.min(usize::MAX as u64) as usize,
                available: available_stream,
            });
        }
    } else if available_stream == 0 {
        return Err(Error::Truncated {
            offset: PCX_HEADER_LEN,
            needed: 1,
            available: 0,
        });
    }

    const INITIAL_DECODE_CAP: usize = 64 * 1024;
    let mut scanline_buf = vec![0u8; scanline_stride];
    let mut decoded_indices = if bits_per_pixel == 8 && color_planes == 1 {
        Vec::with_capacity((pixels as usize).min(INITIAL_DECODE_CAP))
    } else {
        Vec::new()
    };
    let mut rgba = if bits_per_pixel == 8 && color_planes == 1 {
        Vec::new()
    } else {
        Vec::with_capacity(rgba_len.min(INITIAL_DECODE_CAP))
    };

    let mut pos = PCX_HEADER_LEN;
    let w = width as usize;

    for _ in 0..height {
        if encoding == 0 {
            let end = pos.checked_add(scanline_stride).ok_or(Error::Truncated {
                offset: pos,
                needed: scanline_stride,
                available: bytes.len().saturating_sub(pos),
            })?;
            if end > bytes.len() {
                return Err(Error::Truncated {
                    offset: pos,
                    needed: scanline_stride,
                    available: bytes.len() - pos,
                });
            }
            scanline_buf.copy_from_slice(&bytes[pos..end]);
            pos = end;
        } else {
            let mut written = 0usize;
            while written < scanline_stride {
                if pos >= bytes.len() {
                    return Err(Error::Truncated {
                        offset: pos,
                        needed: 1,
                        available: 0,
                    });
                }
                let byte = bytes[pos];
                pos += 1;
                if (byte & 0xC0) == 0xC0 {
                    let count = usize::from(byte & 0x3F);
                    if pos >= bytes.len() {
                        return Err(Error::Truncated {
                            offset: pos,
                            needed: 1,
                            available: 0,
                        });
                    }
                    let value = bytes[pos];
                    pos += 1;
                    let next_written = written.checked_add(count).ok_or_else(|| {
                        Error::Malformed("PCX RLE run overflows scanline stride".into())
                    })?;
                    if next_written > scanline_stride {
                        return Err(Error::Malformed(
                            "PCX RLE run exceeds scanline stride".into(),
                        ));
                    }
                    scanline_buf[written..next_written].fill(value);
                    written = next_written;
                } else {
                    scanline_buf[written] = byte;
                    written += 1;
                }
            }
        }

        match (bits_per_pixel, color_planes) {
            (8, 1) => {
                decoded_indices.extend_from_slice(&scanline_buf[..w]);
            }
            (8, 3) => {
                let r_plane = &scanline_buf[0..bytes_per_line];
                let g_plane = &scanline_buf[bytes_per_line..2 * bytes_per_line];
                let b_plane = &scanline_buf[2 * bytes_per_line..3 * bytes_per_line];
                for x in 0..w {
                    rgba.extend_from_slice(&[r_plane[x], g_plane[x], b_plane[x], 255]);
                }
            }
            (1, 1) => {
                for x in 0..w {
                    let bit = (scanline_buf[x / 8] >> (7 - (x % 8))) & 1;
                    let v = if bit != 0 { 255 } else { 0 };
                    rgba.extend_from_slice(&[v, v, v, 255]);
                }
            }
            (1, 4) => {
                let p0 = &scanline_buf[0..bytes_per_line];
                let p1 = &scanline_buf[bytes_per_line..2 * bytes_per_line];
                let p2 = &scanline_buf[2 * bytes_per_line..3 * bytes_per_line];
                let p3 = &scanline_buf[3 * bytes_per_line..4 * bytes_per_line];
                for x in 0..w {
                    let byte_idx = x / 8;
                    let shift = 7 - (x % 8);
                    let idx = usize::from(
                        ((p0[byte_idx] >> shift) & 1)
                            | (((p1[byte_idx] >> shift) & 1) << 1)
                            | (((p2[byte_idx] >> shift) & 1) << 2)
                            | (((p3[byte_idx] >> shift) & 1) << 3),
                    );
                    let base = idx * 3;
                    rgba.extend_from_slice(&[
                        ega_palette[base],
                        ega_palette[base + 1],
                        ega_palette[base + 2],
                        255,
                    ]);
                }
            }
            _ => unreachable!(),
        }
    }

    if bits_per_pixel == 8 && color_planes == 1 {
        rgba.reserve_exact(rgba_len);
        let vga_palette = if version >= 5
            && bytes.len() >= PCX_HEADER_LEN + PCX_VGA_TRAILER_LEN
            && pos <= bytes.len() - PCX_VGA_TRAILER_LEN
            && bytes[bytes.len() - PCX_VGA_TRAILER_LEN] == PCX_PALETTE_MARKER
        {
            Some(&bytes[bytes.len() - PCX_VGA_PALETTE_LEN..])
        } else {
            None
        };

        for idx in decoded_indices {
            let i = usize::from(idx);
            let [r, g, b] = if let Some(pal) = vga_palette {
                let base = i * 3;
                [pal[base], pal[base + 1], pal[base + 2]]
            } else if i < 16 {
                let base = i * 3;
                [
                    ega_palette[base],
                    ega_palette[base + 1],
                    ega_palette[base + 2],
                ]
            } else {
                [0, 0, 0]
            };
            rgba.extend_from_slice(&[r, g, b, 255]);
        }
    }

    Image::try_new(width, height, rgba)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn build_raw_pcx(
        version: u8,
        encoding: u8,
        bits_per_pixel: u8,
        color_planes: u8,
        width: u16,
        height: u16,
        bytes_per_line: u16,
        ega_palette: &[u8; 48],
        pixel_data: &[u8],
        vga_palette: Option<&[u8; 768]>,
    ) -> Vec<u8> {
        let mut out = vec![0u8; PCX_HEADER_LEN];
        out[0] = PCX_MANUFACTURER;
        out[1] = version;
        out[2] = encoding;
        out[3] = bits_per_pixel;
        out[8..10].copy_from_slice(&(width - 1).to_le_bytes());
        out[10..12].copy_from_slice(&(height - 1).to_le_bytes());
        out[16..64].copy_from_slice(ega_palette);
        out[65] = color_planes;
        out[66..68].copy_from_slice(&bytes_per_line.to_le_bytes());
        out[68..70].copy_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(pixel_data);
        if let Some(pal) = vga_palette {
            out.push(PCX_PALETTE_MARKER);
            out.extend_from_slice(pal);
        }
        out
    }

    #[test]
    fn round_trips_rgba_24bit_odd_and_even_widths_including_high_bytes() {
        // Odd width (5x2) exercises even bytes_per_line padding and RLE bytes >= 0xC0.
        let mut rgba = Vec::new();
        for y in 0..2u8 {
            for x in 0..5u8 {
                let r = if x < 3 { 0xC5 } else { 0x20 + x + y };
                let g = if y == 0 { 0xFF } else { 0xC0 + x };
                let b = x * 40 + y * 17;
                rgba.extend_from_slice(&[r, g, b, 255]);
            }
        }
        let img = Image::try_new(5, 2, rgba).unwrap();

        let encoded_a = encode_pcx_rgba(&img, 4096).unwrap();
        let encoded_b = encode_pcx_rgba(&img, 4096).unwrap();
        assert_eq!(encoded_a, encoded_b);

        // Exact max_bytes boundary succeeds; one less fails.
        assert!(encode_pcx_rgba(&img, encoded_a.len()).is_ok());
        assert!(matches!(
            encode_pcx_rgba(&img, encoded_a.len() - 1),
            Err(Error::ResourceLimit {
                resource: "PCX output bytes",
                ..
            })
        ));

        let decoded = decode_pcx_rgba(&encoded_a, 10).unwrap();
        assert_eq!(decoded, img);

        // max_pixels enforced.
        assert!(matches!(
            decode_pcx_rgba(&encoded_a, 9),
            Err(Error::ResourceLimit {
                resource: "PCX pixels",
                requested: 10,
                limit: 9,
            })
        ));
    }

    #[test]
    fn round_trips_8bpp_indexed_with_vga_palette_and_long_runs() {
        let mut palette = [0u8; 768];
        for i in 0..256usize {
            palette[i * 3] = i as u8;
            palette[i * 3 + 1] = (255 - i) as u8;
            palette[i * 3 + 2] = ((i * 7) & 0xFF) as u8;
        }

        // 70x2 image exercises RLE runs longer than 63 and indices >= 0xC0.
        let mut indices = Vec::with_capacity(140);
        indices.extend(std::iter::repeat_n(0xC0u8, 68));
        indices.push(0x01);
        indices.push(0xFF);
        for x in 0..70u8 {
            indices.push(x.wrapping_mul(3));
        }

        let encoded = encode_pcx_indexed(70, 2, &indices, &palette, 4096).unwrap();
        assert!(encode_pcx_indexed(70, 2, &indices, &palette, encoded.len()).is_ok());
        assert!(matches!(
            encode_pcx_indexed(70, 2, &indices, &palette, encoded.len() - 1),
            Err(Error::ResourceLimit {
                resource: "PCX output bytes",
                ..
            })
        ));

        let decoded = decode_pcx_rgba(&encoded, 140).unwrap();
        assert_eq!(decoded.width, 70);
        assert_eq!(decoded.height, 2);
        for (i, &idx) in indices.iter().enumerate() {
            let p = usize::from(idx) * 3;
            assert_eq!(
                &decoded.rgba[i * 4..i * 4 + 4],
                &[palette[p], palette[p + 1], palette[p + 2], 255]
            );
        }
    }

    #[test]
    fn decodes_8bpp_indexed_ega_fallback_when_version_lt_5_or_no_marker() {
        let mut ega = [0u8; 48];
        ega[0..3].copy_from_slice(&[10, 20, 30]);
        ega[3..6].copy_from_slice(&[40, 50, 60]);
        ega[45..48].copy_from_slice(&[200, 210, 220]);

        // Uncompressed version 2 (no VGA palette trailer).
        let pcx_v2 = build_raw_pcx(2, 0, 8, 1, 3, 1, 4, &ega, &[0, 1, 15, 0], None);
        let img = decode_pcx_rgba(&pcx_v2, 4).unwrap();
        assert_eq!(
            img.rgba,
            vec![10, 20, 30, 255, 40, 50, 60, 255, 200, 210, 220, 255]
        );

        // Version 5 without trailing 0x0C palette also falls back to EGA header palette.
        let pcx_v5_no_pal = build_raw_pcx(5, 0, 8, 1, 2, 1, 2, &ega, &[1, 0], None);
        let img2 = decode_pcx_rgba(&pcx_v5_no_pal, 4).unwrap();
        assert_eq!(img2.rgba, vec![40, 50, 60, 255, 10, 20, 30, 255]);
    }

    #[test]
    fn decodes_1bpp_monochrome_and_1bpp_4plane_ega() {
        // 1bpp 1-plane monochrome: 9x1, bits 1010_0101 1...
        let mono_data = [0b1010_0101, 0b1000_0000];
        let mono_pcx = build_raw_pcx(5, 0, 1, 1, 9, 1, 2, &[0u8; 48], &mono_data, None);
        let mono = decode_pcx_rgba(&mono_pcx, 16).unwrap();
        let expected_bits = [1, 0, 1, 0, 0, 1, 0, 1, 1];
        for (i, &bit) in expected_bits.iter().enumerate() {
            let v = if bit != 0 { 255 } else { 0 };
            assert_eq!(&mono.rgba[i * 4..i * 4 + 4], &[v, v, v, 255]);
        }

        // 1bpp 4-plane EGA: 4x1 with palette indices [0, 5, 10, 15].
        let mut ega = [0u8; 48];
        ega[0..3].copy_from_slice(&[1, 2, 3]);
        ega[15..18].copy_from_slice(&[50, 60, 70]);
        ega[30..33].copy_from_slice(&[100, 110, 120]);
        ega[45..48].copy_from_slice(&[250, 251, 252]);

        // Pixel 0 = 0 (0000), Pixel 1 = 5 (0101), Pixel 2 = 10 (1010), Pixel 3 = 15 (1111)
        // Plane 0 (bit 0): 0,1,0,1 -> 0b0101_0000
        // Plane 1 (bit 1): 0,0,1,1 -> 0b0011_0000
        // Plane 2 (bit 2): 0,1,0,1 -> 0b0101_0000
        // Plane 3 (bit 3): 0,0,1,1 -> 0b0011_0000
        // RLE-encoded (none >= 0xC0 so literal bytes work, with 2-byte padded bytes_per_line):
        let ega_data = [
            0b0101_0000,
            0,
            0b0011_0000,
            0,
            0b0101_0000,
            0,
            0b0011_0000,
            0,
        ];
        let ega_pcx = build_raw_pcx(5, 1, 1, 4, 4, 1, 2, &ega, &ega_data, None);
        let decoded = decode_pcx_rgba(&ega_pcx, 16).unwrap();
        assert_eq!(
            decoded.rgba,
            vec![
                1, 2, 3, 255, //
                50, 60, 70, 255, //
                100, 110, 120, 255, //
                250, 251, 252, 255,
            ]
        );
    }

    #[test]
    fn rejects_malformed_truncated_bad_magic_and_excessive_stride() {
        // Truncated header.
        assert!(matches!(
            decode_pcx_rgba(&[0x0A; 64], 16),
            Err(Error::Truncated {
                offset: 0,
                needed: 128,
                available: 64
            })
        ));

        // Bad manufacturer magic.
        let mut bad_magic = build_raw_pcx(5, 0, 8, 1, 1, 1, 2, &[0u8; 48], &[0, 0], None);
        bad_magic[0] = 0x0B;
        assert!(matches!(
            decode_pcx_rgba(&bad_magic, 16),
            Err(Error::Malformed(_))
        ));

        // Bad encoding.
        let bad_enc = build_raw_pcx(5, 2, 8, 1, 1, 1, 2, &[0u8; 48], &[0, 0], None);
        assert!(matches!(
            decode_pcx_rgba(&bad_enc, 16),
            Err(Error::InvalidField {
                what: "PCX encoding",
                value: 2
            })
        ));

        // Inverted bounds (xmax < xmin).
        let mut bad_bounds = build_raw_pcx(5, 0, 8, 1, 2, 2, 2, &[0u8; 48], &[0; 4], None);
        bad_bounds[4..6].copy_from_slice(&10u16.to_le_bytes());
        bad_bounds[8..10].copy_from_slice(&5u16.to_le_bytes());
        assert!(matches!(
            decode_pcx_rgba(&bad_bounds, 16),
            Err(Error::InvalidField {
                what: "PCX bounds",
                ..
            })
        ));

        // bytes_per_line smaller than width.
        let small_bpl = build_raw_pcx(5, 0, 8, 1, 4, 1, 2, &[0u8; 48], &[0, 0], None);
        assert!(matches!(
            decode_pcx_rgba(&small_bpl, 16),
            Err(Error::InvalidField {
                what: "PCX bytes_per_line",
                value: 2
            })
        ));

        // Excessive bytes_per_line stride vs max_pixels budget.
        let huge_bpl = build_raw_pcx(5, 1, 8, 1, 1, 1, 65534, &[0u8; 48], &[], None);
        assert!(matches!(
            decode_pcx_rgba(&huge_bpl, 4),
            Err(Error::ResourceLimit {
                resource: "PCX decoded scanline bytes",
                ..
            })
        ));

        // RLE run exceeding scanline stride.
        let overflow_rle = build_raw_pcx(5, 1, 8, 1, 2, 1, 2, &[0u8; 48], &[0xC5, 0x00], None);
        assert!(matches!(
            decode_pcx_rgba(&overflow_rle, 16),
            Err(Error::Malformed(_))
        ));

        // Truncated RLE pair (marker without value byte).
        let trunc_rle = build_raw_pcx(5, 1, 8, 1, 2, 1, 2, &[0u8; 48], &[0xC2], None);
        assert!(matches!(
            decode_pcx_rgba(&trunc_rle, 16),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn crafted_128_byte_4096x4096_pcx_fails_truncated_fast() {
        for encoding in [0u8, 1u8] {
            for (bpp, planes) in [(8u8, 1u8), (8, 3)] {
                let crafted = build_raw_pcx(
                    5,
                    encoding,
                    bpp,
                    planes,
                    4096,
                    4096,
                    4096,
                    &[0u8; 48],
                    &[],
                    None,
                );
                assert_eq!(crafted.len(), PCX_HEADER_LEN);
                assert!(matches!(
                    decode_pcx_rgba(&crafted, 4096 * 4096),
                    Err(Error::Truncated { .. })
                ));
            }
        }

        // Even with 1 byte of RLE payload, decoding fails truncated without a 64 MB pre-allocation.
        let crafted_129 = build_raw_pcx(5, 1, 8, 3, 4096, 4096, 4096, &[0u8; 48], &[0x01], None);
        assert!(matches!(
            decode_pcx_rgba(&crafted_129, 4096 * 4096),
            Err(Error::Truncated { .. })
        ));
    }
}
