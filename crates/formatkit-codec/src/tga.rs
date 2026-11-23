//! Bounded deterministic Truevision TGA decoder and encoder.
//!
//! Supports:
//! - Type 1: uncompressed 8-bit color-mapped (15/16/24/32-bit color map entries)
//! - Type 2: uncompressed 16/24/32-bit true-color
//! - Type 10: RLE-compressed 16/24/32-bit true-color
//! - Top-left and bottom-left vertical origins (plus right-to-left horizontal flip)
//! - Optional 26-byte TGA 2.0 `TRUEVISION-XFILE.\0` footer

use formatkit_core::{Error, Image, Result};

use crate::rle::{decode_high_bit_rle, encode_high_bit_rle, HighBitRleConfig};

const TGA_HEADER_LEN: usize = 18;
const TGA_FOOTER_LEN: usize = 26;

/// 18-byte TGA 2.0 footer signature.
pub const TGA_FOOTER_SIGNATURE: &[u8; 18] = b"TRUEVISION-XFILE.\0";

/// Vertical row ordering stored in a TGA file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TgaOrigin {
    /// Row 0 in the file is the bottom row of the image (descriptor bit 5 = 0).
    BottomLeft,
    /// Row 0 in the file is the top row of the image (descriptor bit 5 = 1).
    TopLeft,
}

/// Pixel storage encoding for true-color TGA images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TgaEncoding {
    /// Uncompressed true-color (image type 2).
    Uncompressed,
    /// Run-length encoded true-color (image type 10).
    Rle,
}

/// Parsed 18-byte Truevision TGA header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TgaHeader {
    /// Length in bytes of the optional image ID field immediately following the header.
    pub id_length: u8,
    /// Color map type (`0` = none, `1` = present).
    pub color_map_type: u8,
    /// Image type (`1` = color-mapped, `2` = uncompressed true-color, `10` = RLE true-color).
    pub image_type: u8,
    /// Index of first color-map entry.
    pub color_map_first_entry: u16,
    /// Number of entries in the color map.
    pub color_map_length: u16,
    /// Bits per color-map entry (`15`, `16`, `24`, or `32`).
    pub color_map_entry_size: u8,
    /// Declared X origin.
    pub x_origin: u16,
    /// Declared Y origin.
    pub y_origin: u16,
    /// Image width in pixels.
    pub width: u16,
    /// Image height in pixels.
    pub height: u16,
    /// Bits per stored pixel (`8`, `16`, `24`, or `32`).
    pub pixel_depth: u8,
    /// Raw image descriptor byte.
    pub image_descriptor: u8,
}

impl TgaHeader {
    /// Parse an 18-byte TGA header from the start of `data`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < TGA_HEADER_LEN {
            return Err(Error::Truncated {
                offset: 0,
                needed: TGA_HEADER_LEN,
                available: data.len(),
            });
        }
        Ok(Self {
            id_length: data[0],
            color_map_type: data[1],
            image_type: data[2],
            color_map_first_entry: u16::from_le_bytes([data[3], data[4]]),
            color_map_length: u16::from_le_bytes([data[5], data[6]]),
            color_map_entry_size: data[7],
            x_origin: u16::from_le_bytes([data[8], data[9]]),
            y_origin: u16::from_le_bytes([data[10], data[11]]),
            width: u16::from_le_bytes([data[12], data[13]]),
            height: u16::from_le_bytes([data[14], data[15]]),
            pixel_depth: data[16],
            image_descriptor: data[17],
        })
    }

    /// Vertical origin selected by descriptor bit 5.
    #[must_use]
    pub const fn origin(&self) -> TgaOrigin {
        if self.image_descriptor & 0x20 != 0 {
            TgaOrigin::TopLeft
        } else {
            TgaOrigin::BottomLeft
        }
    }

    /// Whether descriptor bit 4 requests right-to-left horizontal order.
    #[must_use]
    pub const fn right_to_left(&self) -> bool {
        self.image_descriptor & 0x10 != 0
    }

    /// Number of alpha/attribute bits declared in descriptor bits `0..4`.
    #[must_use]
    pub const fn alpha_bits(&self) -> u8 {
        self.image_descriptor & 0x0F
    }
}

/// Return whether `data` ends with the 26-byte TGA 2.0 `TRUEVISION-XFILE.\0` footer.
#[must_use]
pub fn has_tga_footer(data: &[u8]) -> bool {
    data.len() >= TGA_HEADER_LEN + TGA_FOOTER_LEN
        && &data[data.len() - TGA_FOOTER_SIGNATURE.len()..] == TGA_FOOTER_SIGNATURE
}

fn expand_5bit(v: u16) -> u8 {
    (((v << 3) | (v >> 2)) & 0xFF) as u8
}

fn decode_tga_pixel(raw: &[u8], depth: u8, alpha_bits: u8) -> [u8; 4] {
    match depth {
        15 | 16 => {
            let w = u16::from_le_bytes([raw[0], raw[1]]);
            let b = expand_5bit(w & 0x1F);
            let g = expand_5bit((w >> 5) & 0x1F);
            let r = expand_5bit((w >> 10) & 0x1F);
            let a = if depth == 16 && alpha_bits > 0 {
                if (w & 0x8000) != 0 {
                    255
                } else {
                    0
                }
            } else {
                255
            };
            [r, g, b, a]
        }
        24 => [raw[2], raw[1], raw[0], 255],
        32 => {
            let a = if alpha_bits == 0 { 255 } else { raw[3] };
            [raw[2], raw[1], raw[0], a]
        }
        _ => [0, 0, 0, 255],
    }
}

/// Decode a Truevision TGA image (type 1, type 2, or type 10) into a top-down
/// RGBA8888 [`Image`], enforcing `max_pixels` before allocating.
pub fn decode_tga_rgba(data: &[u8], max_pixels: usize) -> Result<Image> {
    let header = TgaHeader::parse(data)?;
    if header.width == 0 || header.height == 0 {
        return Err(Error::InvalidField {
            what: "TGA extent",
            value: (u64::from(header.width) << 32) | u64::from(header.height),
        });
    }
    if header.image_descriptor & 0xC0 != 0 {
        return Err(Error::InvalidField {
            what: "TGA descriptor reserved bits",
            value: u64::from(header.image_descriptor),
        });
    }

    let width = usize::from(header.width);
    let height = usize::from(header.height);
    let pixel_count = width
        .checked_mul(height)
        .ok_or_else(|| Error::Malformed("TGA pixel count overflow".into()))?;
    if pixel_count > max_pixels {
        return Err(Error::ResourceLimit {
            resource: "TGA pixels",
            requested: pixel_count as u64,
            limit: max_pixels as u64,
        });
    }

    let payload_end = if has_tga_footer(data) {
        data.len() - TGA_FOOTER_LEN
    } else {
        data.len()
    };

    let cmap_start = TGA_HEADER_LEN + usize::from(header.id_length);
    if cmap_start > payload_end {
        return Err(Error::Truncated {
            offset: TGA_HEADER_LEN,
            needed: usize::from(header.id_length),
            available: payload_end.saturating_sub(TGA_HEADER_LEN),
        });
    }

    let cmap_bytes = match header.color_map_type {
        0 => 0usize,
        1 => {
            let entry_bytes = match header.color_map_entry_size {
                15 | 16 => 2usize,
                24 => 3usize,
                32 => 4usize,
                other => {
                    return Err(Error::Unsupported(format!(
                        "TGA {other}-bit color map entry"
                    )));
                }
            };
            usize::from(header.color_map_length)
                .checked_mul(entry_bytes)
                .ok_or_else(|| Error::Malformed("TGA color map length overflow".into()))?
        }
        other => {
            return Err(Error::Unsupported(format!("TGA color map type {other}")));
        }
    };

    let pixels_start = cmap_start
        .checked_add(cmap_bytes)
        .ok_or_else(|| Error::Malformed("TGA pixel data offset overflow".into()))?;
    if pixels_start > payload_end {
        return Err(Error::Truncated {
            offset: cmap_start,
            needed: cmap_bytes,
            available: payload_end.saturating_sub(cmap_start),
        });
    }

    let cmap_slice = &data[cmap_start..pixels_start];
    let pixel_stream = &data[pixels_start..payload_end];
    let alpha_bits = header.alpha_bits();

    let mut linear_rgba = vec![0u8; pixel_count * 4];

    match header.image_type {
        1 => {
            if header.color_map_type != 1 {
                return Err(Error::Malformed(
                    "TGA type 1 image requires a color map".into(),
                ));
            }
            if header.pixel_depth != 8 {
                return Err(Error::Unsupported(format!(
                    "TGA type 1 {}-bit indices",
                    header.pixel_depth
                )));
            }
            if pixel_stream.len() < pixel_count {
                return Err(Error::Truncated {
                    offset: pixels_start,
                    needed: pixel_count,
                    available: pixel_stream.len(),
                });
            }
            let entry_bytes = match header.color_map_entry_size {
                15 | 16 => 2usize,
                24 => 3usize,
                32 => 4usize,
                _ => unreachable!("validated above"),
            };
            let cmap_alpha_bits = if header.color_map_entry_size == 32 {
                8
            } else if header.color_map_entry_size == 16 {
                alpha_bits
            } else {
                0
            };
            let mut palette = Vec::with_capacity(usize::from(header.color_map_length));
            for entry in cmap_slice.chunks_exact(entry_bytes) {
                palette.push(decode_tga_pixel(
                    entry,
                    header.color_map_entry_size,
                    cmap_alpha_bits,
                ));
            }
            let first = usize::from(header.color_map_first_entry);
            for (i, &idx) in pixel_stream[..pixel_count].iter().enumerate() {
                let raw_idx = usize::from(idx);
                let pal_idx = raw_idx.checked_sub(first).ok_or(Error::InvalidField {
                    what: "TGA color map index",
                    value: u64::from(idx),
                })?;
                let color = *palette.get(pal_idx).ok_or(Error::InvalidField {
                    what: "TGA color map index",
                    value: u64::from(idx),
                })?;
                linear_rgba[i * 4..i * 4 + 4].copy_from_slice(&color);
            }
        }
        2 => {
            if !matches!(header.pixel_depth, 16 | 24 | 32) {
                return Err(Error::Unsupported(format!(
                    "TGA type 2 {}-bit pixel depth",
                    header.pixel_depth
                )));
            }
            let bpp = usize::from(header.pixel_depth / 8);
            let needed = pixel_count
                .checked_mul(bpp)
                .ok_or_else(|| Error::Malformed("TGA pixel byte length overflow".into()))?;
            if pixel_stream.len() < needed {
                return Err(Error::Truncated {
                    offset: pixels_start,
                    needed,
                    available: pixel_stream.len(),
                });
            }
            for (dst, raw) in linear_rgba
                .chunks_exact_mut(4)
                .zip(pixel_stream[..needed].chunks_exact(bpp))
            {
                dst.copy_from_slice(&decode_tga_pixel(raw, header.pixel_depth, alpha_bits));
            }
        }
        10 => {
            if !matches!(header.pixel_depth, 16 | 24 | 32) {
                return Err(Error::Unsupported(format!(
                    "TGA type 10 {}-bit pixel depth",
                    header.pixel_depth
                )));
            }
            let bpp = usize::from(header.pixel_depth / 8);
            let outcome = decode_high_bit_rle(
                pixel_stream,
                pixel_count,
                HighBitRleConfig::pixel_units(bpp),
            )?;
            for (dst, raw) in linear_rgba
                .chunks_exact_mut(4)
                .zip(outcome.bytes.chunks_exact(bpp))
            {
                dst.copy_from_slice(&decode_tga_pixel(raw, header.pixel_depth, alpha_bits));
            }
        }
        other => {
            return Err(Error::Unsupported(format!("TGA image type {other}")));
        }
    }

    let flip_y = header.origin() == TgaOrigin::BottomLeft;
    let flip_x = header.right_to_left();
    let rgba = if !flip_y && !flip_x {
        linear_rgba
    } else {
        let mut out = vec![0u8; pixel_count * 4];
        for src_y in 0..height {
            let dst_y = if flip_y { height - 1 - src_y } else { src_y };
            for src_x in 0..width {
                let dst_x = if flip_x { width - 1 - src_x } else { src_x };
                let src_off = (src_y * width + src_x) * 4;
                let dst_off = (dst_y * width + dst_x) * 4;
                out[dst_off..dst_off + 4].copy_from_slice(&linear_rgba[src_off..src_off + 4]);
            }
        }
        out
    };

    Image::try_new(u32::from(header.width), u32::from(header.height), rgba)
}

fn check_max_bytes(requested: usize, max_bytes: usize) -> Result<()> {
    if requested > max_bytes {
        Err(Error::ResourceLimit {
            resource: "TGA output bytes",
            requested: requested as u64,
            limit: max_bytes as u64,
        })
    } else {
        Ok(())
    }
}

fn append_footer(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(TGA_FOOTER_SIGNATURE);
}

/// Encode an RGBA8888 [`Image`] as a 32-bit BGRA Truevision TGA (type 2 or type 10).
pub fn encode_tga_rgba(
    image: &Image,
    encoding: TgaEncoding,
    origin: TgaOrigin,
    include_footer: bool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    image.validate()?;
    if image.width == 0 || image.height == 0 {
        return Err(Error::InvalidField {
            what: "TGA extent",
            value: (u64::from(image.width) << 32) | u64::from(image.height),
        });
    }
    let width = u16::try_from(image.width).map_err(|_| Error::InvalidField {
        what: "TGA width",
        value: u64::from(image.width),
    })?;
    let height = u16::try_from(image.height).map_err(|_| Error::InvalidField {
        what: "TGA height",
        value: u64::from(image.height),
    })?;

    let w = usize::from(width);
    let h = usize::from(height);
    let mut bgra = Vec::with_capacity(w * h * 4);
    for row in 0..h {
        let src_y = match origin {
            TgaOrigin::TopLeft => row,
            TgaOrigin::BottomLeft => h - 1 - row,
        };
        let row_slice = &image.rgba[src_y * w * 4..(src_y + 1) * w * 4];
        for px in row_slice.chunks_exact(4) {
            bgra.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
    }

    let (image_type, payload) = match encoding {
        TgaEncoding::Uncompressed => (2u8, bgra),
        TgaEncoding::Rle => (
            10u8,
            encode_high_bit_rle(&bgra, HighBitRleConfig::pixel_units(4))?,
        ),
    };

    let footer_len = if include_footer { TGA_FOOTER_LEN } else { 0 };
    let total_len = TGA_HEADER_LEN
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(footer_len))
        .ok_or_else(|| Error::Malformed("TGA output length overflow".into()))?;
    check_max_bytes(total_len, max_bytes)?;

    let mut out = Vec::with_capacity(total_len);
    let mut header = [0u8; TGA_HEADER_LEN];
    header[2] = image_type;
    header[12..14].copy_from_slice(&width.to_le_bytes());
    header[14..16].copy_from_slice(&height.to_le_bytes());
    header[16] = 32;
    header[17] = 0x08
        | match origin {
            TgaOrigin::TopLeft => 0x20,
            TgaOrigin::BottomLeft => 0x00,
        };
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload);
    if include_footer {
        append_footer(&mut out);
    }
    Ok(out)
}

/// Encode an 8-bit indexed image and RGBA8888 palette as a type 1 color-mapped TGA.
pub fn encode_tga_indexed(
    width: u32,
    height: u32,
    indices: &[u8],
    palette: &[[u8; 4]],
    origin: TgaOrigin,
    include_footer: bool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if width == 0 || height == 0 {
        return Err(Error::InvalidField {
            what: "TGA extent",
            value: (u64::from(width) << 32) | u64::from(height),
        });
    }
    let w16 = u16::try_from(width).map_err(|_| Error::InvalidField {
        what: "TGA width",
        value: u64::from(width),
    })?;
    let h16 = u16::try_from(height).map_err(|_| Error::InvalidField {
        what: "TGA height",
        value: u64::from(height),
    })?;
    if palette.is_empty() || palette.len() > 256 {
        return Err(Error::InvalidField {
            what: "TGA color map length",
            value: palette.len() as u64,
        });
    }
    let w = usize::from(w16);
    let h = usize::from(h16);
    let pixel_count = w
        .checked_mul(h)
        .ok_or_else(|| Error::Malformed("TGA pixel count overflow".into()))?;
    if indices.len() != pixel_count {
        return Err(Error::InvalidField {
            what: "TGA index buffer length",
            value: indices.len() as u64,
        });
    }
    for &idx in indices {
        if usize::from(idx) >= palette.len() {
            return Err(Error::InvalidField {
                what: "TGA palette index",
                value: u64::from(idx),
            });
        }
    }

    let cmap_bytes = palette.len() * 4;
    let footer_len = if include_footer { TGA_FOOTER_LEN } else { 0 };
    let total_len = TGA_HEADER_LEN
        .checked_add(cmap_bytes)
        .and_then(|n| n.checked_add(pixel_count))
        .and_then(|n| n.checked_add(footer_len))
        .ok_or_else(|| Error::Malformed("TGA output length overflow".into()))?;
    check_max_bytes(total_len, max_bytes)?;

    let mut out = Vec::with_capacity(total_len);
    let mut header = [0u8; TGA_HEADER_LEN];
    header[1] = 1; // color map present
    header[2] = 1; // uncompressed color-mapped
    header[5..7].copy_from_slice(&(palette.len() as u16).to_le_bytes());
    header[7] = 32; // 32-bit BGRA color map entries
    header[12..14].copy_from_slice(&w16.to_le_bytes());
    header[14..16].copy_from_slice(&h16.to_le_bytes());
    header[16] = 8;
    header[17] = 0x08
        | match origin {
            TgaOrigin::TopLeft => 0x20,
            TgaOrigin::BottomLeft => 0x00,
        };
    out.extend_from_slice(&header);
    for &[r, g, b, a] in palette {
        out.extend_from_slice(&[b, g, r, a]);
    }
    for row in 0..h {
        let src_y = match origin {
            TgaOrigin::TopLeft => row,
            TgaOrigin::BottomLeft => h - 1 - row,
        };
        out.extend_from_slice(&indices[src_y * w..(src_y + 1) * w]);
    }
    if include_footer {
        append_footer(&mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> Image {
        let rgba = vec![
            255, 0, 0, 255, // (0,0) red
            0, 255, 0, 128, // (1,0) semi-green
            0, 0, 255, 255, // (0,1) blue
            255, 255, 0, 0, // (1,1) transparent yellow
        ];
        Image::try_new(2, 2, rgba).unwrap()
    }

    #[test]
    fn type2_and_type10_round_trip_both_origins_and_optional_footer() {
        let img = sample_image();
        for encoding in [TgaEncoding::Uncompressed, TgaEncoding::Rle] {
            for origin in [TgaOrigin::BottomLeft, TgaOrigin::TopLeft] {
                for footer in [false, true] {
                    let bytes = encode_tga_rgba(&img, encoding, origin, footer, 4096).unwrap();
                    assert_eq!(has_tga_footer(&bytes), footer);
                    let decoded = decode_tga_rgba(&bytes, 16).unwrap();
                    assert_eq!(decoded, img);
                }
            }
        }
    }

    #[test]
    fn type1_indexed_round_trips_both_origins() {
        let palette = [
            [10, 20, 30, 255],
            [200, 100, 50, 128],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ];
        let indices = [0, 1, 2, 3, 3, 2];
        for origin in [TgaOrigin::BottomLeft, TgaOrigin::TopLeft] {
            let bytes = encode_tga_indexed(3, 2, &indices, &palette, origin, true, 4096).unwrap();
            assert!(has_tga_footer(&bytes));
            let decoded = decode_tga_rgba(&bytes, 16).unwrap();
            assert_eq!((decoded.width, decoded.height), (3, 2));
            for (i, &idx) in indices.iter().enumerate() {
                assert_eq!(&decoded.rgba[i * 4..i * 4 + 4], &palette[usize::from(idx)]);
            }
        }
    }

    #[test]
    fn decodes_16bit_and_24bit_type2_with_bottom_left_flip() {
        // 16-bit A1R5G5B5, 2x1, top-left, alpha_bits=1.
        let mut tga16 = vec![0u8; TGA_HEADER_LEN];
        tga16[2] = 2;
        tga16[12..14].copy_from_slice(&2u16.to_le_bytes());
        tga16[14..16].copy_from_slice(&1u16.to_le_bytes());
        tga16[16] = 16;
        tga16[17] = 0x21; // TopLeft + 1 alpha bit
                          // Pixel 0: red (0x8000 | (31 << 10) = 0xFC00), Pixel 1: blue transparent (0x001F).
        tga16.extend_from_slice(&0xFC00u16.to_le_bytes());
        tga16.extend_from_slice(&0x001Fu16.to_le_bytes());
        let img16 = decode_tga_rgba(&tga16, 16).unwrap();
        assert_eq!(img16.rgba, vec![255, 0, 0, 255, 0, 0, 255, 0]);

        // 24-bit BGR, 1x2, bottom-left.
        let mut tga24 = vec![0u8; TGA_HEADER_LEN];
        tga24[2] = 2;
        tga24[12..14].copy_from_slice(&1u16.to_le_bytes());
        tga24[14..16].copy_from_slice(&2u16.to_le_bytes());
        tga24[16] = 24;
        tga24[17] = 0x00; // BottomLeft
                          // File row 0 (bottom) = blue, file row 1 (top) = red.
        tga24.extend_from_slice(&[255, 0, 0, 0, 0, 255]);
        let img24 = decode_tga_rgba(&tga24, 16).unwrap();
        assert_eq!(img24.rgba, vec![255, 0, 0, 255, 0, 0, 255, 255]);
    }

    #[test]
    fn enforces_pixel_and_byte_limits_and_rejects_malformed() {
        let img = sample_image();
        assert!(matches!(
            encode_tga_rgba(
                &img,
                TgaEncoding::Uncompressed,
                TgaOrigin::TopLeft,
                false,
                10
            ),
            Err(Error::ResourceLimit { .. })
        ));
        let bytes = encode_tga_rgba(
            &img,
            TgaEncoding::Uncompressed,
            TgaOrigin::TopLeft,
            false,
            4096,
        )
        .unwrap();
        assert!(matches!(
            decode_tga_rgba(&bytes, 3),
            Err(Error::ResourceLimit { .. })
        ));
        assert!(decode_tga_rgba(&bytes[..10], 16).is_err());
    }
}
