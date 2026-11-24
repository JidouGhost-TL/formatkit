//! Bounded deterministic PNG encoder and decoder for RGBA8 images.
//!
//! [`encode_rgba_png`] emits a minimal, deterministic PNG stream using filter
//! type 0 (`None`) and stored zlib blocks (`IDAT`), checking `max_bytes` before
//! allocating. Its output is byte-stable across releases.
//!
//! [`encode_rgba_png_with`] takes [`PngEncodeOptions`] and can instead emit
//! real DEFLATE-compressed image data (RFC 1950 zlib framing around RFC 1951
//! coded blocks) with per-scanline adaptive filter selection, using the
//! minimum-sum-of-absolute-differences heuristic recommended by the PNG
//! specification (ISO/IEC 15948, section 12.8). Flat or repetitive sheets such
//! as glyph atlases typically shrink by one to two orders of magnitude.
//!
//! Decoding validates the PNG signature, `IHDR`, chunk CRCs, consecutive
//! `IDAT` payloads, and standard scanline filter types `0..=4`, returning an
//! RGBA8 [`formatkit_core::Image`].

use formatkit_core::checksum::Crc32IsoHdlc;
use formatkit_core::{Error, Image, Result};

const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const MAX_PNG_DIM: u32 = 0x7fff_ffff;
const MAX_CHUNK_LEN: usize = 0x7fff_ffff;

fn write_chunk(out: &mut Vec<u8>, chunk_type: [u8; 4], data: &[u8]) {
    let len = u32::try_from(data.len()).expect("PNG chunk length fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&chunk_type);
    out.extend_from_slice(data);
    let mut crc = Crc32IsoHdlc::new();
    crc.update(&chunk_type);
    crc.update(data);
    out.extend_from_slice(&crc.finish().to_be_bytes());
}

/// Encode an RGBA8 [`Image`] into a deterministic PNG byte stream.
///
/// Uses 8-bit RGBA (`IHDR` color type 6), filter type 0 (`None`) on every
/// scanline, and stored DEFLATE blocks via [`crate::zlib_store`]. Enforces
/// `max_bytes` before allocating output buffers.
pub fn encode_rgba_png(image: &Image, max_bytes: usize) -> Result<Vec<u8>> {
    image.validate()?;
    if image.width == 0
        || image.height == 0
        || image.width > MAX_PNG_DIM
        || image.height > MAX_PNG_DIM
    {
        return Err(Error::InvalidField {
            what: "PNG dimensions",
            value: (u64::from(image.width) << 32) | u64::from(image.height),
        });
    }

    let row_bytes = (image.width as usize)
        .checked_mul(4)
        .ok_or(Error::ResourceLimit {
            resource: "PNG output bytes",
            requested: u64::MAX,
            limit: max_bytes as u64,
        })?;
    let scanline_bytes = row_bytes.checked_add(1).ok_or(Error::ResourceLimit {
        resource: "PNG output bytes",
        requested: u64::MAX,
        limit: max_bytes as u64,
    })?;
    let raw_len =
        scanline_bytes
            .checked_mul(image.height as usize)
            .ok_or(Error::ResourceLimit {
                resource: "PNG output bytes",
                requested: u64::MAX,
                limit: max_bytes as u64,
            })?;

    let block_count = raw_len.max(1).div_ceil(u16::MAX as usize);
    let zlib_len = block_count
        .checked_mul(5)
        .and_then(|n| n.checked_add(raw_len))
        .and_then(|n| n.checked_add(6))
        .ok_or(Error::ResourceLimit {
            resource: "PNG output bytes",
            requested: u64::MAX,
            limit: max_bytes as u64,
        })?;
    if zlib_len > MAX_CHUNK_LEN {
        return Err(Error::ResourceLimit {
            resource: "PNG output bytes",
            requested: zlib_len as u64,
            limit: (MAX_CHUNK_LEN as u64).min(max_bytes as u64),
        });
    }

    // 8 (signature) + 25 (IHDR) + 12 (IDAT framing) + zlib_len + 12 (IEND) = 57 + zlib_len
    let total_len = zlib_len.checked_add(57).ok_or(Error::ResourceLimit {
        resource: "PNG output bytes",
        requested: u64::MAX,
        limit: max_bytes as u64,
    })?;
    if total_len > max_bytes {
        return Err(Error::ResourceLimit {
            resource: "PNG output bytes",
            requested: total_len as u64,
            limit: max_bytes as u64,
        });
    }

    let mut raw = Vec::with_capacity(raw_len);
    for row in image.rgba.chunks_exact(row_bytes) {
        raw.push(0);
        raw.extend_from_slice(row);
    }

    let idat = crate::zlib_store(&raw);
    debug_assert_eq!(idat.len(), zlib_len);

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&image.width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&image.height.to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // color type: RGBA
    ihdr[10] = 0; // compression method: deflate
    ihdr[11] = 0; // filter method: adaptive
    ihdr[12] = 0; // interlace method: none

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&PNG_SIGNATURE);
    write_chunk(&mut out, *b"IHDR", &ihdr);
    write_chunk(&mut out, *b"IDAT", &idat);
    write_chunk(&mut out, *b"IEND", &[]);
    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

/// Zlib payload strategy for [`encode_rgba_png_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PngCompression {
    /// Stored (uncompressed) DEFLATE blocks via [`crate::zlib_store`].
    ///
    /// Combined with [`PngFilter::None`] this reproduces [`encode_rgba_png`]
    /// byte for byte.
    Stored,
    /// Real DEFLATE compression at `level` (`1..=10`, where `9` is the usual
    /// maximum and `10` enables the encoder's slowest exhaustive search).
    Deflate {
        /// Compression level in `1..=10`.
        level: u8,
    },
}

/// Scanline filter selection for [`encode_rgba_png_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PngFilter {
    /// Filter type 0 (`None`) on every scanline.
    None,
    /// Per scanline, the filter type `0..=4` whose output has the smallest
    /// sum of absolute values (bytes read as signed), lowest type on ties.
    Adaptive,
}

/// Encoder settings for [`encode_rgba_png_with`].
///
/// [`Default`] is [`PngEncodeOptions::COMPRESSED`].
#[doc(alias = "png compression")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PngEncodeOptions {
    /// Zlib payload strategy.
    pub compression: PngCompression,
    /// Scanline filter selection.
    pub filter: PngFilter,
}

impl PngEncodeOptions {
    /// Stored blocks with filter `None`: identical output to [`encode_rgba_png`].
    pub const STORED: Self = Self {
        compression: PngCompression::Stored,
        filter: PngFilter::None,
    };
    /// DEFLATE level 9 with adaptive filtering.
    pub const COMPRESSED: Self = Self {
        compression: PngCompression::Deflate { level: 9 },
        filter: PngFilter::Adaptive,
    };
}

impl Default for PngEncodeOptions {
    fn default() -> Self {
        Self::COMPRESSED
    }
}

fn png_limit(max_bytes: usize) -> Error {
    Error::ResourceLimit {
        resource: "PNG output bytes",
        requested: u64::MAX,
        limit: max_bytes as u64,
    }
}

fn filter_scanline_into(filter_type: u8, row: &[u8], prev: &[u8], bpp: usize, out: &mut Vec<u8>) {
    out.push(filter_type);
    for i in 0..row.len() {
        let left = if i >= bpp { row[i - bpp] } else { 0 };
        let up = prev[i];
        let up_left = if i >= bpp { prev[i - bpp] } else { 0 };
        let pred = match filter_type {
            0 => 0,
            1 => left,
            2 => up,
            3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
            _ => paeth_predictor(left, up, up_left),
        };
        out.push(row[i].wrapping_sub(pred));
    }
}

fn signed_abs_sum(filtered: &[u8]) -> u64 {
    filtered
        .iter()
        .map(|&b| u64::from((b as i8).unsigned_abs()))
        .sum()
}

/// Encode an RGBA8 [`Image`] into a deterministic PNG byte stream using
/// explicit [`PngEncodeOptions`].
///
/// Output is 8-bit RGBA (`IHDR` color type 6), non-interlaced, with a single
/// `IDAT` chunk. With [`PngEncodeOptions::STORED`] the result equals
/// [`encode_rgba_png`]. With DEFLATE compression the filtered scanlines
/// (`height * (1 + 4 * width)` bytes, about the size of the input image) are
/// built before compressing, and `max_bytes` bounds the final PNG length;
/// compressed output larger than `max_bytes` is rejected with
/// [`Error::ResourceLimit`]. Given the same build and input, output is
/// deterministic.
///
/// ```
/// use formatkit_codec::png::{decode_png_rgba, encode_rgba_png, encode_rgba_png_with, PngEncodeOptions};
/// use formatkit_core::Image;
///
/// let image = Image::try_new(64, 64, vec![0x40; 64 * 64 * 4]).unwrap();
/// let small = encode_rgba_png_with(&image, 1 << 20, &PngEncodeOptions::COMPRESSED).unwrap();
/// let stored = encode_rgba_png(&image, 1 << 20).unwrap();
/// assert!(small.len() * 20 < stored.len());
/// assert_eq!(decode_png_rgba(&small, 64 * 64).unwrap(), image);
/// ```
pub fn encode_rgba_png_with(
    image: &Image,
    max_bytes: usize,
    options: &PngEncodeOptions,
) -> Result<Vec<u8>> {
    let level = match options.compression {
        PngCompression::Stored if options.filter == PngFilter::None => {
            return encode_rgba_png(image, max_bytes);
        }
        PngCompression::Stored => None,
        PngCompression::Deflate { level } => {
            if !(1..=10).contains(&level) {
                return Err(Error::InvalidField {
                    what: "PNG deflate level",
                    value: u64::from(level),
                });
            }
            Some(level)
        }
    };
    image.validate()?;
    if image.width == 0
        || image.height == 0
        || image.width > MAX_PNG_DIM
        || image.height > MAX_PNG_DIM
    {
        return Err(Error::InvalidField {
            what: "PNG dimensions",
            value: (u64::from(image.width) << 32) | u64::from(image.height),
        });
    }
    let row_bytes = (image.width as usize)
        .checked_mul(4)
        .ok_or_else(|| png_limit(max_bytes))?;
    let scanline_bytes = row_bytes
        .checked_add(1)
        .ok_or_else(|| png_limit(max_bytes))?;
    let raw_len = scanline_bytes
        .checked_mul(image.height as usize)
        .ok_or_else(|| png_limit(max_bytes))?;
    if level.is_none() {
        // Stored payload size is exact; reject before allocating.
        let stored = raw_len
            .max(1)
            .div_ceil(u16::MAX as usize)
            .checked_mul(5)
            .and_then(|n| n.checked_add(raw_len))
            .and_then(|n| n.checked_add(6 + 57))
            .ok_or_else(|| png_limit(max_bytes))?;
        let zlib_len = stored - 57;
        if zlib_len > MAX_CHUNK_LEN {
            return Err(Error::ResourceLimit {
                resource: "PNG output bytes",
                requested: zlib_len as u64,
                limit: (MAX_CHUNK_LEN as u64).min(max_bytes as u64),
            });
        }
        if stored > max_bytes {
            return Err(Error::ResourceLimit {
                resource: "PNG output bytes",
                requested: stored as u64,
                limit: max_bytes as u64,
            });
        }
    }

    let mut raw = Vec::with_capacity(raw_len);
    let zero_row = vec![0u8; row_bytes];
    let mut candidate = Vec::with_capacity(scanline_bytes);
    let mut best = Vec::with_capacity(scanline_bytes);
    let mut prev: &[u8] = &zero_row;
    for row in image.rgba.chunks_exact(row_bytes) {
        match options.filter {
            PngFilter::None => filter_scanline_into(0, row, prev, 4, &mut raw),
            PngFilter::Adaptive => {
                let mut best_sum = u64::MAX;
                for filter_type in 0..=4u8 {
                    candidate.clear();
                    filter_scanline_into(filter_type, row, prev, 4, &mut candidate);
                    let sum = signed_abs_sum(&candidate[1..]);
                    if sum < best_sum {
                        best_sum = sum;
                        std::mem::swap(&mut best, &mut candidate);
                    }
                }
                raw.extend_from_slice(&best);
            }
        }
        prev = row;
    }

    let idat = match level {
        None => crate::zlib_store(&raw),
        Some(level) => miniz_oxide::deflate::compress_to_vec_zlib(&raw, level),
    };
    drop(raw);
    let total_len = idat
        .len()
        .checked_add(57)
        .ok_or_else(|| png_limit(max_bytes))?;
    if idat.len() > MAX_CHUNK_LEN {
        return Err(Error::ResourceLimit {
            resource: "PNG output bytes",
            requested: idat.len() as u64,
            limit: (MAX_CHUNK_LEN as u64).min(max_bytes as u64),
        });
    }
    if total_len > max_bytes {
        return Err(Error::ResourceLimit {
            resource: "PNG output bytes",
            requested: total_len as u64,
            limit: max_bytes as u64,
        });
    }

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&image.width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&image.height.to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // color type: RGBA

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&PNG_SIGNATURE);
    write_chunk(&mut out, *b"IHDR", &ihdr);
    write_chunk(&mut out, *b"IDAT", &idat);
    write_chunk(&mut out, *b"IEND", &[]);
    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let a = i32::from(a);
    let b = i32::from(b);
    let c = i32::from(c);
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

fn unfilter_scanline(
    filter_type: u8,
    src: &[u8],
    prev: &[u8],
    cur: &mut [u8],
    bpp: usize,
) -> Result<()> {
    match filter_type {
        0 => {
            cur.copy_from_slice(src);
        }
        1 => {
            for i in 0..src.len() {
                let left = if i >= bpp { cur[i - bpp] } else { 0 };
                cur[i] = src[i].wrapping_add(left);
            }
        }
        2 => {
            for i in 0..src.len() {
                cur[i] = src[i].wrapping_add(prev[i]);
            }
        }
        3 => {
            for i in 0..src.len() {
                let left = if i >= bpp { u16::from(cur[i - bpp]) } else { 0 };
                let up = u16::from(prev[i]);
                cur[i] = src[i].wrapping_add(((left + up) / 2) as u8);
            }
        }
        4 => {
            for i in 0..src.len() {
                let left = if i >= bpp { cur[i - bpp] } else { 0 };
                let up = prev[i];
                let up_left = if i >= bpp { prev[i - bpp] } else { 0 };
                cur[i] = src[i].wrapping_add(paeth_predictor(left, up, up_left));
            }
        }
        _ => {
            return Err(Error::InvalidField {
                what: "PNG filter type",
                value: u64::from(filter_type),
            });
        }
    }
    Ok(())
}

/// Decode a standard non-interlaced PNG byte stream into an RGBA8 [`Image`].
///
/// Validates the PNG signature, `IHDR`, chunk CRCs (`Crc32IsoHdlc`),
/// consecutive `IDAT` chunks, zlib decompression, and scanline filters `0..=4`.
/// Supports Grayscale (color type 0) and Indexed (`PLTE` + optional `tRNS`, 3)
/// at bit depths `1`, `2`, `4`, and `8`, plus 8-bit RGB (2), GrayAlpha (4),
/// and RGBA (6).
pub fn decode_png_rgba(bytes: &[u8], max_pixels: u64) -> Result<Image> {
    if bytes.len() < PNG_SIGNATURE.len() {
        return Err(Error::Truncated {
            offset: 0,
            needed: PNG_SIGNATURE.len(),
            available: bytes.len(),
        });
    }
    if bytes[..8] != PNG_SIGNATURE {
        return Err(Error::Malformed("invalid PNG signature".into()));
    }

    let mut pos = 8usize;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut seen_ihdr = false;
    let mut seen_idat = false;
    let mut idat_ended = false;
    let mut seen_iend = false;
    let mut plte: Option<&[u8]> = None;
    let mut trns: Option<&[u8]> = None;
    let mut idat_data = Vec::new();

    while pos < bytes.len() {
        if bytes.len() - pos < 12 {
            return Err(Error::Truncated {
                offset: pos,
                needed: 12,
                available: bytes.len() - pos,
            });
        }
        let chunk_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        if chunk_len > MAX_CHUNK_LEN {
            return Err(Error::InvalidField {
                what: "PNG chunk length",
                value: chunk_len as u64,
            });
        }
        let chunk_type: [u8; 4] = bytes[pos + 4..pos + 8].try_into().unwrap();
        let data_start = pos + 8;
        let data_end = data_start
            .checked_add(chunk_len)
            .ok_or(Error::InvalidField {
                what: "PNG chunk length",
                value: chunk_len as u64,
            })?;
        let crc_end = data_end.checked_add(4).ok_or(Error::InvalidField {
            what: "PNG chunk length",
            value: chunk_len as u64,
        })?;
        if crc_end > bytes.len() {
            return Err(Error::Truncated {
                offset: data_start,
                needed: chunk_len + 4,
                available: bytes.len() - data_start,
            });
        }

        let data = &bytes[data_start..data_end];
        let expected_crc = u32::from_be_bytes(bytes[data_end..crc_end].try_into().unwrap());
        let mut crc = Crc32IsoHdlc::new();
        crc.update(&chunk_type);
        crc.update(data);
        if crc.finish() != expected_crc {
            return Err(Error::Malformed("PNG chunk CRC mismatch".into()));
        }

        pos = crc_end;

        if !seen_ihdr {
            if chunk_type != *b"IHDR" {
                return Err(Error::Malformed("PNG must begin with IHDR chunk".into()));
            }
            if data.len() != 13 {
                return Err(Error::InvalidField {
                    what: "PNG IHDR length",
                    value: data.len() as u64,
                });
            }
            width = u32::from_be_bytes(data[0..4].try_into().unwrap());
            height = u32::from_be_bytes(data[4..8].try_into().unwrap());
            bit_depth = data[8];
            color_type = data[9];
            let compression = data[10];
            let filter = data[11];
            let interlace = data[12];

            if width == 0 || height == 0 || width > MAX_PNG_DIM || height > MAX_PNG_DIM {
                return Err(Error::InvalidField {
                    what: "PNG dimensions",
                    value: (u64::from(width) << 32) | u64::from(height),
                });
            }
            let pixels = u64::from(width) * u64::from(height);
            if pixels > max_pixels {
                return Err(Error::ResourceLimit {
                    resource: "PNG pixels",
                    requested: pixels,
                    limit: max_pixels,
                });
            }
            if !matches!(color_type, 0 | 2 | 3 | 4 | 6) {
                return Err(Error::InvalidField {
                    what: "PNG color type",
                    value: u64::from(color_type),
                });
            }
            let valid_depth = match color_type {
                0 | 3 => matches!(bit_depth, 1 | 2 | 4 | 8),
                2 | 4 | 6 => bit_depth == 8,
                _ => unreachable!(),
            };
            if !valid_depth {
                return Err(Error::Unsupported(format!(
                    "PNG bit depth {bit_depth} for color type {color_type}"
                )));
            }
            if compression != 0 {
                return Err(Error::InvalidField {
                    what: "PNG compression method",
                    value: u64::from(compression),
                });
            }
            if filter != 0 {
                return Err(Error::InvalidField {
                    what: "PNG filter method",
                    value: u64::from(filter),
                });
            }
            if interlace != 0 {
                return Err(Error::Unsupported(
                    "interlaced PNG images are not supported".into(),
                ));
            }
            seen_ihdr = true;
            continue;
        }

        if chunk_type != *b"IDAT" && seen_idat {
            idat_ended = true;
        }

        match &chunk_type {
            b"IHDR" => {
                return Err(Error::Malformed("duplicate PNG IHDR chunk".into()));
            }
            b"PLTE" => {
                if seen_idat || plte.is_some() || matches!(color_type, 0 | 4) {
                    return Err(Error::Malformed("unexpected PNG PLTE chunk".into()));
                }
                if data.is_empty() || !data.len().is_multiple_of(3) || data.len() > 256 * 3 {
                    return Err(Error::InvalidField {
                        what: "PNG PLTE length",
                        value: data.len() as u64,
                    });
                }
                plte = Some(data);
            }
            b"tRNS" => {
                if seen_idat || trns.is_some() || matches!(color_type, 4 | 6) {
                    return Err(Error::Malformed("unexpected PNG tRNS chunk".into()));
                }
                match color_type {
                    0 => {
                        if data.len() != 2 {
                            return Err(Error::InvalidField {
                                what: "PNG tRNS length",
                                value: data.len() as u64,
                            });
                        }
                    }
                    2 => {
                        if data.len() != 6 {
                            return Err(Error::InvalidField {
                                what: "PNG tRNS length",
                                value: data.len() as u64,
                            });
                        }
                    }
                    3 => {
                        let Some(palette) = plte else {
                            return Err(Error::Malformed(
                                "PNG tRNS chunk before PLTE chunk".into(),
                            ));
                        };
                        if data.len() > palette.len() / 3 {
                            return Err(Error::InvalidField {
                                what: "PNG tRNS length",
                                value: data.len() as u64,
                            });
                        }
                    }
                    _ => unreachable!(),
                }
                trns = Some(data);
            }
            b"IDAT" => {
                if idat_ended {
                    return Err(Error::Malformed("non-consecutive PNG IDAT chunks".into()));
                }
                seen_idat = true;
                idat_data.extend_from_slice(data);
            }
            b"IEND" => {
                if !data.is_empty() {
                    return Err(Error::InvalidField {
                        what: "PNG IEND length",
                        value: data.len() as u64,
                    });
                }
                seen_iend = true;
                break;
            }
            _ => {
                // Bit 5 of the first byte marks ancillary chunks; unknown
                // critical chunks must be rejected.
                if (chunk_type[0] & 0x20) == 0 {
                    return Err(Error::Unsupported(format!(
                        "unknown critical PNG chunk {:?}",
                        chunk_type
                    )));
                }
            }
        }
    }

    if !seen_ihdr || !seen_iend || !seen_idat {
        return Err(Error::Malformed(
            "incomplete PNG stream: missing IHDR, IDAT, or IEND".into(),
        ));
    }
    if pos != bytes.len() {
        return Err(Error::Trailing(bytes.len() - pos));
    }

    if color_type == 3 && plte.is_none() {
        return Err(Error::Malformed(
            "indexed PNG image is missing PLTE chunk".into(),
        ));
    }

    let bpp: usize = match color_type {
        0 | 3 => 1,
        4 => 2,
        2 => 3,
        6 => 4,
        _ => unreachable!(),
    };
    let row_bytes = if bit_depth < 8 {
        let pixels_per_byte = 8 / usize::from(bit_depth);
        (width as usize).div_ceil(pixels_per_byte)
    } else {
        (width as usize)
            .checked_mul(bpp)
            .ok_or(Error::InvalidField {
                what: "PNG scanline width",
                value: u64::from(width),
            })?
    };
    let scanline_bytes = row_bytes.checked_add(1).ok_or(Error::InvalidField {
        what: "PNG scanline width",
        value: u64::from(width),
    })?;
    let expected_raw_len =
        scanline_bytes
            .checked_mul(height as usize)
            .ok_or(Error::InvalidField {
                what: "PNG scanline size",
                value: u64::from(width) * u64::from(height),
            })?;

    let inflated = crate::zlib_inflate_with_limit(&idat_data, expected_raw_len)
        .ok_or_else(|| Error::Malformed("invalid PNG IDAT zlib stream".into()))?;
    if inflated.len() != expected_raw_len {
        return Err(Error::Malformed(format!(
            "PNG IDAT decoded to {} bytes, expected {expected_raw_len}",
            inflated.len()
        )));
    }

    let rgba_len = Image::rgba_len(width, height)?;
    let mut rgba = Vec::with_capacity(rgba_len);
    let mut prev_row = vec![0u8; row_bytes];
    let mut cur_row = vec![0u8; row_bytes];

    let trns_gray = if color_type == 0 {
        trns.map(|t| u16::from_be_bytes([t[0], t[1]]))
    } else {
        None
    };
    let trns_rgb = if color_type == 2 {
        trns.map(|t| {
            [
                u16::from_be_bytes([t[0], t[1]]),
                u16::from_be_bytes([t[2], t[3]]),
                u16::from_be_bytes([t[4], t[5]]),
            ]
        })
    } else {
        None
    };

    for scanline in inflated.chunks_exact(scanline_bytes) {
        unfilter_scanline(scanline[0], &scanline[1..], &prev_row, &mut cur_row, bpp)?;
        match color_type {
            0 => {
                if bit_depth == 8 {
                    for &g in &cur_row {
                        let a = if trns_gray == Some(u16::from(g)) {
                            0
                        } else {
                            255
                        };
                        rgba.extend_from_slice(&[g, g, g, a]);
                    }
                } else {
                    let bd = usize::from(bit_depth);
                    let pixels_per_byte = 8 / bd;
                    let mask = (1u8 << bit_depth) - 1;
                    let scale = 255 / mask;
                    for x in 0..(width as usize) {
                        let byte = cur_row[x / pixels_per_byte];
                        let shift = 8 - bd * ((x % pixels_per_byte) + 1);
                        let sample = (byte >> shift) & mask;
                        let g = sample * scale;
                        let a = if trns_gray == Some(u16::from(sample)) {
                            0
                        } else {
                            255
                        };
                        rgba.extend_from_slice(&[g, g, g, a]);
                    }
                }
            }
            2 => {
                for px in cur_row.chunks_exact(3) {
                    let a = if trns_rgb
                        == Some([u16::from(px[0]), u16::from(px[1]), u16::from(px[2])])
                    {
                        0
                    } else {
                        255
                    };
                    rgba.extend_from_slice(&[px[0], px[1], px[2], a]);
                }
            }
            3 => {
                let palette = plte.expect("validated PLTE presence");
                let palette_entries = palette.len() / 3;
                let alphas = trns.unwrap_or(&[]);
                let bd = usize::from(bit_depth);
                let pixels_per_byte = 8 / bd;
                let mask = if bit_depth == 8 {
                    0xffu8
                } else {
                    (1u8 << bit_depth) - 1
                };
                for x in 0..(width as usize) {
                    let idx = if bit_depth == 8 {
                        cur_row[x]
                    } else {
                        let byte = cur_row[x / pixels_per_byte];
                        let shift = 8 - bd * ((x % pixels_per_byte) + 1);
                        (byte >> shift) & mask
                    };
                    let i = usize::from(idx);
                    if i >= palette_entries {
                        return Err(Error::InvalidField {
                            what: "PNG palette index",
                            value: u64::from(idx),
                        });
                    }
                    let base = i * 3;
                    let a = alphas.get(i).copied().unwrap_or(255);
                    rgba.extend_from_slice(&[
                        palette[base],
                        palette[base + 1],
                        palette[base + 2],
                        a,
                    ]);
                }
            }
            4 => {
                for px in cur_row.chunks_exact(2) {
                    rgba.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
                }
            }
            6 => {
                rgba.extend_from_slice(&cur_row);
            }
            _ => unreachable!(),
        }
        std::mem::swap(&mut prev_row, &mut cur_row);
    }

    Image::try_new(width, height, rgba)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_png(
        width: u32,
        height: u32,
        color_type: u8,
        extra_chunks: &[([u8; 4], &[u8])],
        raw_scanlines: &[u8],
        split_idat: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PNG_SIGNATURE);

        let mut ihdr = [0u8; 13];
        ihdr[0..4].copy_from_slice(&width.to_be_bytes());
        ihdr[4..8].copy_from_slice(&height.to_be_bytes());
        ihdr[8] = 8;
        ihdr[9] = color_type;
        write_chunk(&mut out, *b"IHDR", &ihdr);

        for &(tag, payload) in extra_chunks {
            write_chunk(&mut out, tag, payload);
        }

        let compressed = crate::zlib_compress(raw_scanlines);
        if split_idat && compressed.len() > 2 {
            let mid = compressed.len() / 2;
            write_chunk(&mut out, *b"IDAT", &compressed[..mid]);
            write_chunk(&mut out, *b"IDAT", &compressed[mid..]);
        } else {
            write_chunk(&mut out, *b"IDAT", &compressed);
        }
        write_chunk(&mut out, *b"IEND", &[]);
        out
    }

    fn apply_filter(filter_type: u8, row: &[u8], prev: &[u8], bpp: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + row.len());
        out.push(filter_type);
        for i in 0..row.len() {
            let left = if i >= bpp { row[i - bpp] } else { 0 };
            let up = prev[i];
            let up_left = if i >= bpp { prev[i - bpp] } else { 0 };
            let pred = match filter_type {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => paeth_predictor(left, up, up_left),
                _ => unreachable!(),
            };
            out.push(row[i].wrapping_sub(pred));
        }
        out
    }

    #[test]
    fn encode_and_decode_rgba_round_trip_deterministically() {
        let img = Image::try_new(
            3,
            2,
            vec![
                10, 20, 30, 255, 40, 50, 60, 128, 70, 80, 90, 0, //
                100, 110, 120, 255, 130, 140, 150, 64, 160, 170, 180, 200,
            ],
        )
        .unwrap();

        let png_a = encode_rgba_png(&img, 4096).unwrap();
        let png_b = encode_rgba_png(&img, 4096).unwrap();
        assert_eq!(png_a, png_b);

        // Exact max_bytes boundary succeeds; one less fails before allocation.
        assert!(encode_rgba_png(&img, png_a.len()).is_ok());
        assert!(matches!(
            encode_rgba_png(&img, png_a.len() - 1),
            Err(Error::ResourceLimit {
                resource: "PNG output bytes",
                ..
            })
        ));

        let decoded = decode_png_rgba(&png_a, 6).unwrap();
        assert_eq!(decoded, img);

        // max_pixels enforced.
        assert!(matches!(
            decode_png_rgba(&png_a, 5),
            Err(Error::ResourceLimit {
                resource: "PNG pixels",
                requested: 6,
                limit: 5,
            })
        ));
    }

    fn sheet_image(width: u32, height: u32) -> Image {
        // Mostly transparent sheet with sparse opaque strokes, like a glyph atlas.
        let mut rgba = vec![0u8; (width * height * 4) as usize];
        for y in 0..height {
            for x in 0..width {
                if (x % 16 < 3 && y % 16 < 12) || (y % 16 == 5 && x % 16 < 10) {
                    let at = ((y * width + x) * 4) as usize;
                    rgba[at..at + 4].copy_from_slice(&[255, 255, (x * 7) as u8, 255]);
                }
            }
        }
        Image::try_new(width, height, rgba).unwrap()
    }

    #[test]
    fn stored_options_match_legacy_encoder_byte_for_byte() {
        let img = sheet_image(37, 21);
        let legacy = encode_rgba_png(&img, 1 << 20).unwrap();
        assert_eq!(
            encode_rgba_png_with(&img, 1 << 20, &PngEncodeOptions::STORED).unwrap(),
            legacy
        );
        // Pin the legacy stored framing: one stored block after the zlib header.
        let idat_data = 8 + 25 + 8;
        assert_eq!(&legacy[idat_data..idat_data + 3], &[0x78, 0x01, 0x01]);
        assert_eq!(PngEncodeOptions::default(), PngEncodeOptions::COMPRESSED);
    }

    #[test]
    fn compressed_round_trips_and_is_much_smaller() {
        let img = sheet_image(256, 128);
        let stored = encode_rgba_png(&img, 1 << 22).unwrap();
        for options in [
            PngEncodeOptions::COMPRESSED,
            PngEncodeOptions {
                compression: PngCompression::Deflate { level: 1 },
                filter: PngFilter::None,
            },
            PngEncodeOptions {
                compression: PngCompression::Stored,
                filter: PngFilter::Adaptive,
            },
        ] {
            let png = encode_rgba_png_with(&img, 1 << 22, &options).unwrap();
            assert_eq!(png, encode_rgba_png_with(&img, 1 << 22, &options).unwrap());
            assert_eq!(decode_png_rgba(&png, 1 << 20).unwrap(), img);
            if matches!(options.compression, PngCompression::Deflate { .. }) {
                assert!(png.len() * 20 < stored.len(), "{options:?}: {}", png.len());
            }
        }
    }

    #[test]
    fn adaptive_filter_picks_minimum_signed_sum() {
        // A horizontal gradient: Sub (1) leaves constant deltas, so it wins.
        let width = 8u32;
        let mut rgba = Vec::new();
        for y in 0..2u32 {
            for x in 0..width {
                let v = (x * 30 + y) as u8;
                rgba.extend_from_slice(&[v, v, v, 255]);
            }
        }
        let img = Image::try_new(width, 2, rgba).unwrap();
        let options = PngEncodeOptions {
            compression: PngCompression::Stored,
            filter: PngFilter::Adaptive,
        };
        let png = encode_rgba_png_with(&img, 4096, &options).unwrap();
        // Stored block data starts after zlib header (2) + block header (5).
        let raw = &png[8 + 25 + 8 + 7..];
        assert_eq!(raw[0], 1);
        assert_eq!(raw[1 + 4 * width as usize], 2); // second row: Up leaves constant +1
        assert_eq!(decode_png_rgba(&png, 16).unwrap(), img);
    }

    #[test]
    fn compressed_rejects_bad_level_and_limits() {
        let img = sheet_image(16, 16);
        assert!(matches!(
            encode_rgba_png_with(
                &img,
                1 << 20,
                &PngEncodeOptions {
                    compression: PngCompression::Deflate { level: 0 },
                    filter: PngFilter::None,
                }
            ),
            Err(Error::InvalidField {
                what: "PNG deflate level",
                value: 0
            })
        ));
        let png = encode_rgba_png_with(&img, 1 << 20, &PngEncodeOptions::COMPRESSED).unwrap();
        assert!(encode_rgba_png_with(&img, png.len(), &PngEncodeOptions::COMPRESSED).is_ok());
        assert!(matches!(
            encode_rgba_png_with(&img, png.len() - 1, &PngEncodeOptions::COMPRESSED),
            Err(Error::ResourceLimit {
                resource: "PNG output bytes",
                ..
            })
        ));
        let stored_adaptive = PngEncodeOptions {
            compression: PngCompression::Stored,
            filter: PngFilter::Adaptive,
        };
        assert!(matches!(
            encode_rgba_png_with(&img, 100, &stored_adaptive),
            Err(Error::ResourceLimit { .. })
        ));
    }

    #[test]
    fn decodes_all_five_filter_types_and_split_idat() {
        let width = 4u32;
        let height = 5u32;
        let bpp = 4usize;
        let rows: Vec<Vec<u8>> = (0..height)
            .map(|y| {
                (0..width)
                    .flat_map(|x| {
                        [
                            ((x * 37 + y * 53) & 0xff) as u8,
                            ((x * 19 + y * 97 + 11) & 0xff) as u8,
                            ((x * 71 + y * 29 + 7) & 0xff) as u8,
                            ((x * 43 + y * 61 + 200) & 0xff) as u8,
                        ]
                    })
                    .collect()
            })
            .collect();

        let mut raw = Vec::new();
        let zero_row = vec![0u8; width as usize * bpp];
        for (y, row) in rows.iter().enumerate() {
            let prev = if y == 0 { &zero_row } else { &rows[y - 1] };
            raw.extend_from_slice(&apply_filter(y as u8, row, prev, bpp));
        }

        let png = build_png(width, height, 6, &[(*b"tEXt", b"note\0ok")], &raw, true);
        let decoded = decode_png_rgba(&png, 64).unwrap();
        let expected: Vec<u8> = rows.into_iter().flatten().collect();
        assert_eq!(decoded, Image::try_new(width, height, expected).unwrap());
    }

    #[test]
    fn decodes_rgb_grayscale_grayalpha_and_indexed_with_trns() {
        // Color type 2 (RGB) with tRNS.
        let rgb_raw = vec![0, 10, 20, 30, 40, 50, 60];
        let rgb_png = build_png(
            2,
            1,
            2,
            &[(*b"tRNS", &[0, 40, 0, 50, 0, 60])],
            &rgb_raw,
            false,
        );
        let rgb = decode_png_rgba(&rgb_png, 4).unwrap();
        assert_eq!(rgb.rgba, vec![10, 20, 30, 255, 40, 50, 60, 0]);

        // Color type 0 (Grayscale) with tRNS.
        let gray_raw = vec![0, 12, 99];
        let gray_png = build_png(2, 1, 0, &[(*b"tRNS", &[0, 99])], &gray_raw, false);
        let gray = decode_png_rgba(&gray_png, 4).unwrap();
        assert_eq!(gray.rgba, vec![12, 12, 12, 255, 99, 99, 99, 0]);

        // Color type 4 (GrayAlpha).
        let ga_raw = vec![0, 77, 128, 200, 255];
        let ga_png = build_png(2, 1, 4, &[], &ga_raw, false);
        let ga = decode_png_rgba(&ga_png, 4).unwrap();
        assert_eq!(ga.rgba, vec![77, 77, 77, 128, 200, 200, 200, 255]);

        // Color type 3 (Indexed) with PLTE + partial tRNS.
        let plte = [255, 0, 0, 0, 255, 0, 0, 0, 255];
        let trns = [0, 128];
        let idx_raw = vec![0, 0, 1, 2];
        let idx_png = build_png(
            3,
            1,
            3,
            &[(*b"PLTE", &plte), (*b"tRNS", &trns)],
            &idx_raw,
            false,
        );
        let idx = decode_png_rgba(&idx_png, 4).unwrap();
        assert_eq!(idx.rgba, vec![255, 0, 0, 0, 0, 255, 0, 128, 0, 0, 255, 255]);
    }

    #[test]
    fn rejects_bad_crc_signature_and_zero_dimensions() {
        assert!(encode_rgba_png(&Image::new(0, 1, Vec::new()), 1024).is_err());

        let img = Image::try_new(1, 1, vec![1, 2, 3, 4]).unwrap();
        let mut png = encode_rgba_png(&img, 1024).unwrap();

        let mut bad_sig = png.clone();
        bad_sig[0] ^= 1;
        assert!(decode_png_rgba(&bad_sig, 4).is_err());

        // Corrupt a byte inside the IHDR CRC.
        png[29] ^= 0x80;
        assert!(decode_png_rgba(&png, 4).is_err());
    }

    fn build_png_with_depth(
        width: u32,
        height: u32,
        bit_depth: u8,
        color_type: u8,
        extra_chunks: &[([u8; 4], &[u8])],
        raw_scanlines: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PNG_SIGNATURE);

        let mut ihdr = [0u8; 13];
        ihdr[0..4].copy_from_slice(&width.to_be_bytes());
        ihdr[4..8].copy_from_slice(&height.to_be_bytes());
        ihdr[8] = bit_depth;
        ihdr[9] = color_type;
        write_chunk(&mut out, *b"IHDR", &ihdr);
        for &(tag, payload) in extra_chunks {
            write_chunk(&mut out, tag, payload);
        }
        let compressed = crate::zlib_compress(raw_scanlines);
        write_chunk(&mut out, *b"IDAT", &compressed);
        write_chunk(&mut out, *b"IEND", &[]);
        out
    }

    #[test]
    fn decodes_sub_byte_grayscale_and_indexed_pngs() {
        // 1-bit Grayscale (width=5, height=1): bits 1,0,1,1,0 (+ 3 padding bits).
        let g1_png = build_png_with_depth(5, 1, 1, 0, &[(*b"tRNS", &[0, 0])], &[0, 0b1011_0111]);
        let g1 = decode_png_rgba(&g1_png, 16).unwrap();
        assert_eq!(
            g1.rgba,
            vec![
                255, 255, 255, 255, // 1
                0, 0, 0, 0, // 0 (transparent via tRNS)
                255, 255, 255, 255, // 1
                255, 255, 255, 255, // 1
                0, 0, 0, 0, // 0
            ]
        );

        // 2-bit Grayscale (width=3, height=1): samples 0, 1, 3 -> 0, 85, 255.
        let g2_png = build_png_with_depth(3, 1, 2, 0, &[], &[0, 0b00_01_11_10]);
        let g2 = decode_png_rgba(&g2_png, 16).unwrap();
        assert_eq!(
            g2.rgba,
            vec![0, 0, 0, 255, 85, 85, 85, 255, 255, 255, 255, 255]
        );

        // 4-bit Grayscale (width=3, height=1): samples 0, 8, 15 -> 0, 0x88, 0xFF.
        let g4_png = build_png_with_depth(3, 1, 4, 0, &[], &[0, 0x08, 0xF0]);
        let g4 = decode_png_rgba(&g4_png, 16).unwrap();
        assert_eq!(
            g4.rgba,
            vec![0, 0, 0, 255, 0x88, 0x88, 0x88, 255, 255, 255, 255, 255]
        );

        // 1-bit, 2-bit, and 4-bit Indexed with PLTE + tRNS.
        let plte = [
            255, 0, 0, // 0
            0, 255, 0, // 1
            0, 0, 255, // 2
            255, 255, 0, // 3
        ];
        let trns = [0, 128];
        let i1_png = build_png_with_depth(
            3,
            1,
            1,
            3,
            &[(*b"PLTE", &plte[..6]), (*b"tRNS", &trns)],
            &[0, 0b1010_0000],
        );
        let i1 = decode_png_rgba(&i1_png, 16).unwrap();
        assert_eq!(i1.rgba, vec![0, 255, 0, 128, 255, 0, 0, 0, 0, 255, 0, 128]);

        let i2_png = build_png_with_depth(
            3,
            1,
            2,
            3,
            &[(*b"PLTE", &plte), (*b"tRNS", &trns)],
            &[0, 0b00_01_10_11],
        );
        let i2 = decode_png_rgba(&i2_png, 16).unwrap();
        assert_eq!(i2.rgba, vec![255, 0, 0, 0, 0, 255, 0, 128, 0, 0, 255, 255]);

        let i4_png = build_png_with_depth(
            3,
            1,
            4,
            3,
            &[(*b"PLTE", &plte), (*b"tRNS", &trns)],
            &[0, 0x32, 0x10],
        );
        let i4 = decode_png_rgba(&i4_png, 16).unwrap();
        assert_eq!(
            i4.rgba,
            vec![255, 255, 0, 255, 0, 0, 255, 255, 0, 255, 0, 128]
        );

        // Sub-byte depth is rejected for RGB (color type 2).
        let bad_rgb = build_png_with_depth(2, 1, 4, 2, &[], &[0, 0x00]);
        assert!(matches!(
            decode_png_rgba(&bad_rgb, 16),
            Err(Error::Unsupported(_))
        ));
    }
}
