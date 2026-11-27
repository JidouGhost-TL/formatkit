//! DirectDraw Surface (`DDS `) container parse, mip/cubemap layout, RGBA8888
//! decode, deterministic encoding, and exact-template rectangle patching.
//!
//! Surface data is face-major: each cubemap face carries its own complete mip
//! chain. Within a chain each level halves both extents (flooring at 1), and
//! block-compressed levels never shrink below one 4×4 block.

use crate::prelude::*;

use formatkit_core::{Error, Image, Result};
use formatkit_pixel::{
    decode_dxt, decode_masked, is_contiguous, mip_extent, rgb565_to_rgba, ChannelMasks, DxtFormat,
};

/// `"DDS "`, little-endian, at offset 0.
const MAGIC: &[u8; 4] = b"DDS ";
/// Magic plus `DDS_HEADER`; the surface data starts here.
const HEADER_LEN: usize = 128;
/// The only legal `dwSize`.
const HEADER_SIZE: u32 = 124;
/// The only legal `pfSize`.
const PIXELFORMAT_SIZE: u32 = 32;

// DDSD_* flags.
const DDSD_PITCH: u32 = 0x0000_0008;
const DDSD_MIPMAPCOUNT: u32 = 0x0002_0000;

// DDPF_* flags.
const DDPF_ALPHAPIXELS: u32 = 0x0000_0001;
const DDPF_ALPHA: u32 = 0x0000_0002;
const DDPF_FOURCC: u32 = 0x0000_0004;
const DDPF_RGB: u32 = 0x0000_0040;
const DDPF_YUV: u32 = 0x0000_0200;
const DDPF_LUMINANCE: u32 = 0x0002_0000;

// DDSCAPS2_* flags.
const DDSCAPS2_CUBEMAP: u32 = 0x0000_0200;
/// The six per-face presence bits (+X, -X, +Y, -Y, +Z, -Z).
const DDSCAPS2_CUBEMAP_FACES: u32 = 0x0000_FC00;
const DDSCAPS2_VOLUME: u32 = 0x0020_0000;

/// Ceiling on a declared extent (`65536`).
pub const MAX_DIMENSION: u32 = 65536;

/// Ceiling on the mip chain: `log2(MAX_DIMENSION) + 1`.
const MAX_MIP_LEVELS: u32 = 17;

/// Stable encoder identity for deterministic DDS authoring.
pub const DDS_ENCODER_ID: &str = "formatkit-bcn-v1-box2x2";

fn dxt_from_fourcc(fourcc: &[u8; 4]) -> Option<DxtFormat> {
    match fourcc {
        b"DXT1" => Some(DxtFormat::Dxt1),
        b"DXT3" => Some(DxtFormat::Dxt3),
        b"DXT5" => Some(DxtFormat::Dxt5),
        _ => None,
    }
}

/// How a DDS file describes its texels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdsFormat {
    /// Block-compressed S3TC (DXT1, DXT3, or DXT5).
    Dxt(DxtFormat),
    /// Uncompressed little-endian texels decomposed by bit masks.
    Uncompressed {
        /// Whole-byte bit depth (`8`, `16`, `24`, or `32`).
        bits_per_pixel: u32,
        /// Per-channel bit masks.
        masks: ChannelMasks,
    },
}

impl DdsFormat {
    fn level_len(self, width: u32, height: u32) -> u64 {
        match self {
            DdsFormat::Dxt(dxt) => {
                let blocks_wide = u64::from(width.div_ceil(4).max(1));
                let blocks_high = u64::from(height.div_ceil(4).max(1));
                blocks_wide * blocks_high * dxt.block_bytes() as u64
            }
            DdsFormat::Uncompressed { bits_per_pixel, .. } => {
                u64::from(width) * u64::from(height) * u64::from(bits_per_pixel / 8)
            }
        }
    }
}

/// A parsed DDS file: validated layout plus a borrow of the surface data.
#[derive(Debug, Clone)]
pub struct Dds<'a> {
    width: u32,
    height: u32,
    mip_levels: u32,
    faces: u32,
    cubemap: bool,
    format: DdsFormat,
    surface: &'a [u8],
}

impl<'a> Dds<'a> {
    /// Parse a DDS file and validate that its declared surface layout fits in `data`.
    pub fn parse(data: &'a [u8]) -> Result<Dds<'a>> {
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated {
                offset: 0,
                needed: HEADER_LEN,
                available: data.len(),
            });
        }
        if &data[0..4] != MAGIC {
            return Err(Error::BadMagic {
                offset: 0,
                expected: u32::from_le_bytes(*MAGIC),
                found: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            });
        }

        let word = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let header_size = word(0x04);
        if header_size != HEADER_SIZE {
            return Err(Error::InvalidField {
                what: "DDS header size",
                value: u64::from(header_size),
            });
        }
        let pixelformat_size = word(0x4c);
        if pixelformat_size != PIXELFORMAT_SIZE {
            return Err(Error::InvalidField {
                what: "DDS pixel format size",
                value: u64::from(pixelformat_size),
            });
        }

        let flags = word(0x08);
        let height = word(0x0c);
        let width = word(0x10);
        let pitch_or_linear_size = word(0x14);
        let depth = word(0x18);
        let mip_map_count = word(0x1c);
        let caps2 = word(0x70);

        if width == 0 || height == 0 {
            return Err(Error::InvalidField {
                what: "DDS extent",
                value: (u64::from(width) << 32) | u64::from(height),
            });
        }
        if width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Error::ResourceLimit {
                resource: "DDS extent",
                requested: u64::from(width.max(height)),
                limit: u64::from(MAX_DIMENSION),
            });
        }

        if caps2 & DDSCAPS2_VOLUME != 0 || depth > 1 {
            return Err(Error::Unsupported("DDS volume texture".into()));
        }

        let format = parse_pixel_format(&data[0x50..0x6c])?;

        if flags & DDSD_PITCH != 0 {
            if let DdsFormat::Uncompressed { bits_per_pixel, .. } = format {
                let tight = u64::from(width) * u64::from(bits_per_pixel / 8);
                if u64::from(pitch_or_linear_size) != tight {
                    return Err(Error::Unsupported("DDS row pitch with padding".into()));
                }
            }
        }

        let mip_levels = if flags & DDSD_MIPMAPCOUNT == 0 || mip_map_count == 0 {
            1
        } else {
            mip_map_count
        };
        if mip_levels > MAX_MIP_LEVELS || mip_levels > full_chain_len(width, height) {
            return Err(Error::InvalidField {
                what: "DDS mip level count",
                value: u64::from(mip_levels),
            });
        }

        let cubemap = caps2 & DDSCAPS2_CUBEMAP != 0;
        let faces = if cubemap {
            let present = (caps2 & DDSCAPS2_CUBEMAP_FACES).count_ones();
            if present == 0 {
                return Err(Error::InvalidField {
                    what: "DDS cubemap face mask",
                    value: u64::from(caps2),
                });
            }
            present
        } else {
            1
        };

        let chain_len = chain_len(format, width, height, mip_levels);
        let surface_len = chain_len * u64::from(faces);
        let available = (data.len() - HEADER_LEN) as u64;
        if surface_len > available {
            return Err(Error::Truncated {
                offset: HEADER_LEN,
                needed: surface_len.min(usize::MAX as u64) as usize,
                available: available as usize,
            });
        }

        Ok(Dds {
            width,
            height,
            mip_levels,
            faces,
            cubemap,
            format,
            surface: &data[HEADER_LEN..],
        })
    }

    /// Top-level width in texels.
    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Top-level height in texels.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Number of mip levels present, always at least 1.
    #[must_use]
    pub fn mip_levels(&self) -> u32 {
        self.mip_levels
    }

    /// Number of surfaces: 1 for a plain texture, or the number of cubemap faces stored.
    #[must_use]
    pub fn faces(&self) -> u32 {
        self.faces
    }

    /// The declared texel format.
    #[must_use]
    pub fn format(&self) -> DdsFormat {
        self.format
    }

    /// Whether the file declares itself a cubemap.
    #[must_use]
    pub fn is_cubemap(&self) -> bool {
        self.cubemap
    }

    /// Total surface bytes accounted for by the header across all faces and mip levels.
    #[must_use]
    pub fn surface_len(&self) -> u64 {
        chain_len(self.format, self.width, self.height, self.mip_levels) * u64::from(self.faces)
    }

    /// Extent of mip `level`: both dimensions halved per level, flooring at 1.
    pub fn level_extent(&self, level: u32) -> Result<(u32, u32)> {
        if level >= self.mip_levels {
            return Err(Error::InvalidField {
                what: "DDS mip level",
                value: u64::from(level),
            });
        }
        Ok((
            mip_extent(self.width, level),
            mip_extent(self.height, level),
        ))
    }

    /// Raw stored bytes of one level of one face.
    pub fn level_bytes(&self, face: u32, level: u32) -> Result<&'a [u8]> {
        if face >= self.faces {
            return Err(Error::InvalidField {
                what: "DDS cubemap face",
                value: u64::from(face),
            });
        }
        let (width, height) = self.level_extent(level)?;
        let mut offset =
            chain_len(self.format, self.width, self.height, self.mip_levels) * u64::from(face);
        for earlier in 0..level {
            offset += self.format.level_len(
                mip_extent(self.width, earlier),
                mip_extent(self.height, earlier),
            );
        }
        let len = self.format.level_len(width, height);
        let end = offset.saturating_add(len);
        if end > self.surface.len() as u64 {
            let offset_usize = usize::try_from(offset).unwrap_or(usize::MAX);
            return Err(Error::Truncated {
                offset: HEADER_LEN.saturating_add(offset_usize),
                needed: usize::try_from(len).unwrap_or(usize::MAX),
                available: self.surface.len().saturating_sub(offset_usize),
            });
        }
        Ok(&self.surface[offset as usize..end as usize])
    }

    /// Decode one level of one face to RGBA8888, enforcing `max_pixels` before decoding.
    pub fn decode_level_with_limit(&self, face: u32, level: u32, max_pixels: u64) -> Result<Image> {
        let (width, height) = self.level_extent(level)?;
        let pixels = u64::from(width) * u64::from(height);
        if pixels > max_pixels {
            return Err(Error::ResourceLimit {
                resource: "DDS pixels",
                requested: pixels,
                limit: max_pixels,
            });
        }
        let bytes = self.level_bytes(face, level)?;
        let rgba = match self.format {
            DdsFormat::Dxt(dxt) => decode_dxt(bytes, width, height, dxt)?,
            DdsFormat::Uncompressed {
                bits_per_pixel,
                masks,
            } => decode_masked(bytes, width, height, bits_per_pixel, masks)?,
        };
        Image::try_new(width, height, rgba)
    }

    /// Decode one level of one face to RGBA8888.
    pub fn decode_level(&self, face: u32, level: u32) -> Result<Image> {
        self.decode_level_with_limit(face, level, u64::MAX)
    }

    /// Decode the base level of the first face, enforcing `max_pixels` before decoding.
    pub fn decode_with_limit(&self, max_pixels: u64) -> Result<Image> {
        self.decode_level_with_limit(0, 0, max_pixels)
    }

    /// Decode the base level of the first face.
    pub fn decode(&self) -> Result<Image> {
        self.decode_level(0, 0)
    }
}

fn chain_len(format: DdsFormat, width: u32, height: u32, mip_levels: u32) -> u64 {
    (0..mip_levels)
        .map(|level| format.level_len(mip_extent(width, level), mip_extent(height, level)))
        .sum()
}

fn full_chain_len(width: u32, height: u32) -> u32 {
    32 - width.max(height).leading_zeros()
}

fn parse_pixel_format(pf: &[u8]) -> Result<DdsFormat> {
    let word = |offset: usize| -> u32 {
        u32::from_le_bytes([pf[offset], pf[offset + 1], pf[offset + 2], pf[offset + 3]])
    };
    let flags = word(0x00);
    let fourcc = [pf[4], pf[5], pf[6], pf[7]];
    let bits_per_pixel = word(0x08);

    if flags & DDPF_FOURCC != 0 {
        if &fourcc == b"DX10" {
            return Err(Error::Unsupported("DDS DX10 header extension".into()));
        }
        return dxt_from_fourcc(&fourcc).map(DdsFormat::Dxt).ok_or_else(|| {
            Error::Unsupported(format!(
                "DDS fourCC {:?}",
                String::from_utf8_lossy(&fourcc).into_owned()
            ))
        });
    }

    if flags & (DDPF_LUMINANCE | DDPF_YUV | DDPF_ALPHA) != 0 {
        return Err(Error::Unsupported("DDS non-RGB pixel format".into()));
    }
    if flags & DDPF_RGB == 0 {
        return Err(Error::Unsupported(format!(
            "DDS pixel format flags {flags:#x}"
        )));
    }
    if !matches!(bits_per_pixel, 8 | 16 | 24 | 32) {
        return Err(Error::Unsupported(format!(
            "DDS {bits_per_pixel}-bit uncompressed texel"
        )));
    }

    let masks = ChannelMasks {
        red: word(0x0c),
        green: word(0x10),
        blue: word(0x14),
        alpha: if flags & DDPF_ALPHAPIXELS != 0 {
            word(0x18)
        } else {
            0
        },
    };

    let texel_mask: u64 = if bits_per_pixel == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << bits_per_pixel) - 1
    };
    let mut seen: u64 = 0;
    for mask in [masks.red, masks.green, masks.blue, masks.alpha] {
        if mask == 0 {
            continue;
        }
        if u64::from(mask) & !texel_mask != 0 {
            return Err(Error::InvalidField {
                what: "DDS channel mask outside texel",
                value: u64::from(mask),
            });
        }
        if !is_contiguous(mask) {
            return Err(Error::Unsupported("DDS non-contiguous channel mask".into()));
        }
        if seen & u64::from(mask) != 0 {
            return Err(Error::InvalidField {
                what: "DDS overlapping channel masks",
                value: u64::from(mask),
            });
        }
        seen |= u64::from(mask);
    }
    if masks.red == 0 && masks.green == 0 && masks.blue == 0 {
        return Err(Error::InvalidField {
            what: "DDS RGB masks",
            value: 0,
        });
    }

    Ok(DdsFormat::Uncompressed {
        bits_per_pixel,
        masks,
    })
}

/// A source-space rectangle to patch through every mip level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdsRect {
    /// Left edge in base-level texels.
    pub x: u32,
    /// Top edge in base-level texels.
    pub y: u32,
    /// Rectangle width in base-level texels.
    pub width: u32,
    /// Rectangle height in base-level texels.
    pub height: u32,
}

/// Containment report for one patched mip level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdsPatchLevel {
    /// Zero-based mip level index.
    pub level: u32,
    /// Mip level width in texels.
    pub width: u32,
    /// Mip level height in texels.
    pub height: u32,
    /// Number of 4×4 blocks covered by the requested rectangles.
    pub selected_blocks: usize,
    /// Number of selected blocks whose encoded bytes differed from the template.
    pub changed_selected_blocks: usize,
    /// Number of unselected blocks that changed (always `0`).
    pub changed_outside_selected_blocks: usize,
}

/// Exact-template rectangle patch result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdsPatch {
    /// Patched DDS file bytes.
    pub bytes: Vec<u8>,
    /// Per-level containment statistics.
    pub levels: Vec<DdsPatchLevel>,
}

/// Encode one tightly packed RGBA8888 image into a DDS surface level.
pub fn encode_dds_level(image: &Image, format: DdsFormat) -> Result<Vec<u8>> {
    image.validate()?;
    match format {
        DdsFormat::Dxt(format) => encode_dxt(image, format),
        DdsFormat::Uncompressed {
            bits_per_pixel,
            masks,
        } => encode_masked(image, bits_per_pixel, masks),
    }
}

/// Rebuild every declared mip behind an unchanged 128-byte DDS template.
///
/// Mips are generated from the previous level with an integer RGBA 2×2 box
/// filter, rounding to nearest. Cubemaps are refused because one source image
/// cannot author multiple independently meaningful faces.
pub fn encode_dds_like(template: &[u8], source: &Image) -> Result<Vec<u8>> {
    let dds = exact_template(template)?;
    validate_source(&dds, source)?;
    if dds.faces() != 1 || dds.is_cubemap() {
        return Err(Error::Unsupported(
            "DDS authoring from one image does not support cubemaps".into(),
        ));
    }
    let chain = mip_chain(source, dds.mip_levels())?;
    let mut out = Vec::with_capacity(template.len());
    out.extend_from_slice(&template[..HEADER_LEN]);
    for image in &chain {
        out.extend_from_slice(&encode_dds_level(image, dds.format())?);
    }
    if out.len() != template.len() {
        return Err(Error::InvalidField {
            what: "DDS rebuilt length",
            value: out.len() as u64,
        });
    }
    Ok(out)
}

/// Replace only DXT blocks touched by `rectangles` at every declared mip.
pub fn patch_dds_rects(
    template: &[u8],
    source: &Image,
    rectangles: &[DdsRect],
) -> Result<DdsPatch> {
    let dds = exact_template(template)?;
    validate_source(&dds, source)?;
    if dds.faces() != 1 || dds.is_cubemap() {
        return Err(Error::Unsupported(
            "DDS rectangle patching does not support cubemaps".into(),
        ));
    }
    let DdsFormat::Dxt(format) = dds.format() else {
        return Err(Error::Unsupported(
            "DDS rectangle patching requires DXT1/DXT3/DXT5".into(),
        ));
    };
    if rectangles.is_empty() {
        return Err(Error::Malformed(
            "DDS rectangle patch requires at least one rectangle".into(),
        ));
    }
    for rect in rectangles {
        if rect.width == 0
            || rect.height == 0
            || rect
                .x
                .checked_add(rect.width)
                .is_none_or(|end| end > dds.width())
            || rect
                .y
                .checked_add(rect.height)
                .is_none_or(|end| end > dds.height())
        {
            return Err(Error::InvalidField {
                what: "DDS patch rectangle",
                value: (u64::from(rect.x) << 32) | u64::from(rect.y),
            });
        }
    }

    let chain = mip_chain(source, dds.mip_levels())?;
    let mut out = template.to_vec();
    let mut reports = Vec::with_capacity(chain.len());
    let mut level_start = HEADER_LEN;
    for (level, image) in chain.iter().enumerate() {
        let level = level as u32;
        let candidate = encode_dxt(image, format)?;
        let original = dds.level_bytes(0, level)?;
        let blocks_x = image.width.div_ceil(4) as usize;
        let blocks_y = image.height.div_ceil(4) as usize;
        let block_bytes = format.block_bytes();
        let mut selected = vec![false; blocks_x * blocks_y];
        let scale = 1u64 << level;
        for rect in rectangles {
            let x0 = u64::from(rect.x) / scale;
            let y0 = u64::from(rect.y) / scale;
            let x1 = u64::from(rect.x + rect.width).div_ceil(scale);
            let y1 = u64::from(rect.y + rect.height).div_ceil(scale);
            let x0 = x0.min(u64::from(image.width - 1)) as usize;
            let y0 = y0.min(u64::from(image.height - 1)) as usize;
            let x1 = x1.min(u64::from(image.width)).max((x0 + 1) as u64) as usize;
            let y1 = y1.min(u64::from(image.height)).max((y0 + 1) as u64) as usize;
            for by in y0 / 4..=(y1 - 1) / 4 {
                for bx in x0 / 4..=(x1 - 1) / 4 {
                    selected[by * blocks_x + bx] = true;
                }
            }
        }

        let mut changed_selected = 0usize;
        for (block, &use_candidate) in selected.iter().enumerate() {
            if !use_candidate {
                continue;
            }
            let within = block * block_bytes;
            let range = level_start + within..level_start + within + block_bytes;
            if original[within..within + block_bytes] != candidate[within..within + block_bytes] {
                changed_selected += 1;
            }
            out[range].copy_from_slice(&candidate[within..within + block_bytes]);
        }
        let changed_outside = (0..blocks_x * blocks_y)
            .filter(|&block| {
                !selected[block]
                    && out
                        [level_start + block * block_bytes..level_start + (block + 1) * block_bytes]
                        != original[block * block_bytes..(block + 1) * block_bytes]
            })
            .count();
        reports.push(DdsPatchLevel {
            level,
            width: image.width,
            height: image.height,
            selected_blocks: selected.iter().filter(|&&selected| selected).count(),
            changed_selected_blocks: changed_selected,
            changed_outside_selected_blocks: changed_outside,
        });
        level_start += original.len();
    }
    Ok(DdsPatch {
        bytes: out,
        levels: reports,
    })
}

fn exact_template<'a>(template: &'a [u8]) -> Result<Dds<'a>> {
    let dds = Dds::parse(template)?;
    let expected = HEADER_LEN as u64 + dds.surface_len();
    if expected != template.len() as u64 {
        return Err(Error::InvalidField {
            what: "DDS exact-template length",
            value: template.len() as u64,
        });
    }
    Ok(dds)
}

fn validate_source(dds: &Dds<'_>, source: &Image) -> Result<()> {
    source.validate()?;
    if source.width != dds.width() || source.height != dds.height() {
        return Err(Error::InvalidField {
            what: "DDS source extent",
            value: (u64::from(source.width) << 32) | u64::from(source.height),
        });
    }
    Ok(())
}

fn mip_chain(source: &Image, levels: u32) -> Result<Vec<Image>> {
    let mut chain = Vec::with_capacity(levels as usize);
    chain.push(source.clone());
    while chain.len() < levels as usize {
        let previous = chain.last().expect("base mip exists");
        let width = mip_extent(previous.width, 1);
        let height = mip_extent(previous.height, 1);
        let mut rgba = vec![0; Image::rgba_len(width, height)?];
        for y in 0..height {
            for x in 0..width {
                for channel in 0..4usize {
                    let mut sum = 0u32;
                    let mut count = 0u32;
                    for dy in 0..2 {
                        for dx in 0..2 {
                            let sx = x * 2 + dx;
                            let sy = y * 2 + dy;
                            if sx < previous.width && sy < previous.height {
                                let at = ((sy * previous.width + sx) * 4) as usize + channel;
                                sum += u32::from(previous.rgba[at]);
                                count += 1;
                            }
                        }
                    }
                    rgba[((y * width + x) * 4) as usize + channel] =
                        ((sum + count / 2) / count) as u8;
                }
            }
        }
        chain.push(Image::try_new(width, height, rgba)?);
    }
    Ok(chain)
}

fn encode_masked(image: &Image, bits: u32, masks: ChannelMasks) -> Result<Vec<u8>> {
    if bits == 0 || !bits.is_multiple_of(8) || bits > 32 {
        return Err(Error::Unsupported(format!(
            "DDS {bits}-bit uncompressed texel"
        )));
    }
    let bytes_per_pixel = (bits / 8) as usize;
    let out_len = (image.width as usize)
        .checked_mul(image.height as usize)
        .and_then(|n| n.checked_mul(bytes_per_pixel))
        .ok_or_else(|| Error::Malformed("DDS masked output length overflow".into()))?;
    let mut out = Vec::with_capacity(out_len);
    for pixel in image.rgba.chunks_exact(4) {
        let mut value = 0u32;
        for (channel, mask) in [pixel[0], pixel[1], pixel[2], pixel[3]].into_iter().zip([
            masks.red,
            masks.green,
            masks.blue,
            masks.alpha,
        ]) {
            if mask == 0 {
                continue;
            }
            let shift = mask.trailing_zeros();
            let maximum = mask >> shift;
            let encoded = (u32::from(channel) * maximum + 127) / 255;
            value |= (encoded << shift) & mask;
        }
        out.extend_from_slice(&value.to_le_bytes()[..bytes_per_pixel]);
    }
    Ok(out)
}

fn encode_dxt(image: &Image, format: DxtFormat) -> Result<Vec<u8>> {
    let blocks_x = image.width.div_ceil(4);
    let blocks_y = image.height.div_ceil(4);
    let out_len = (blocks_x as usize)
        .checked_mul(blocks_y as usize)
        .and_then(|n| n.checked_mul(format.block_bytes()))
        .ok_or_else(|| Error::Malformed("DDS DXT output length overflow".into()))?;
    let mut out = Vec::with_capacity(out_len);
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let mut pixels = [[0u8; 4]; 16];
            for y in 0..4 {
                for x in 0..4 {
                    let sx = (bx * 4 + x).min(image.width - 1);
                    let sy = (by * 4 + y).min(image.height - 1);
                    let at = ((sy * image.width + sx) * 4) as usize;
                    pixels[(y * 4 + x) as usize].copy_from_slice(&image.rgba[at..at + 4]);
                }
            }
            match format {
                DxtFormat::Dxt1 => out.extend_from_slice(&encode_color_block(&pixels, true)),
                DxtFormat::Dxt3 => {
                    out.extend_from_slice(&encode_dxt3_alpha(&pixels));
                    out.extend_from_slice(&encode_color_block(&pixels, false));
                }
                DxtFormat::Dxt5 => {
                    out.extend_from_slice(&encode_dxt5_alpha(&pixels));
                    out.extend_from_slice(&encode_color_block(&pixels, false));
                }
            }
        }
    }
    Ok(out)
}

fn encode_color_block(pixels: &[[u8; 4]; 16], punchthrough: bool) -> [u8; 8] {
    let transparent = punchthrough && pixels.iter().any(|pixel| pixel[3] < 128);
    let mut colors = [0u16; 16];
    let mut opaque = [[0u8; 4]; 16];
    let mut color_count = 0usize;
    for &pixel in pixels {
        if !transparent || pixel[3] >= 128 {
            colors[color_count] = rgb_to_565(pixel[0], pixel[1], pixel[2]);
            opaque[color_count] = pixel;
            color_count += 1;
        }
    }
    let opaque_pixels = &opaque[..color_count];
    colors[..color_count].sort_unstable();
    let mut unique_len = 0usize;
    for i in 0..color_count {
        if unique_len == 0 || colors[i] != colors[unique_len - 1] {
            colors[unique_len] = colors[i];
            unique_len += 1;
        }
    }
    let unique = &colors[..unique_len];
    let usable = if transparent { 3 } else { 4 };
    let (c0, c1) = if unique.is_empty() {
        (0, 0)
    } else {
        let mut best_err = u32::MAX;
        let mut best_c0 = u16::MAX;
        let mut best_c1 = u16::MAX;
        'outer: for i in 0..unique_len {
            let a = unique[i];
            for &b in &unique[i..unique_len] {
                let (c0, c1) = order_color_endpoints(a, b, transparent);
                let palette = color_palette(c0, c1, transparent);
                let mut error = 0u32;
                let tie_worse = (c0, c1) >= (best_c0, best_c1);
                for pixel in opaque_pixels {
                    let mut min_err = rgb_error(pixel, &palette[0]);
                    for candidate in &palette[1..usable] {
                        let e = rgb_error(pixel, candidate);
                        if e < min_err {
                            min_err = e;
                        }
                    }
                    error += min_err;
                    if error > best_err || (error == best_err && tie_worse) {
                        break;
                    }
                }
                if (error, c0, c1) < (best_err, best_c0, best_c1) {
                    best_err = error;
                    best_c0 = c0;
                    best_c1 = c1;
                    if best_err == 0 && transparent {
                        break 'outer;
                    }
                }
            }
        }
        (best_c0, best_c1)
    };
    let mut block = [0u8; 8];
    block[..2].copy_from_slice(&c0.to_le_bytes());
    block[2..4].copy_from_slice(&c1.to_le_bytes());
    let palette = color_palette(c0, c1, transparent);
    let mut indices = 0u32;
    for (index, pixel) in pixels.iter().enumerate() {
        let choice = if transparent && pixel[3] < 128 {
            3
        } else {
            let mut best_choice = 0usize;
            let mut best_e = rgb_error(pixel, &palette[0]);
            for (candidate, entry) in palette.iter().enumerate().take(usable).skip(1) {
                let e = rgb_error(pixel, entry);
                if e < best_e {
                    best_e = e;
                    best_choice = candidate;
                }
            }
            best_choice
        };
        indices |= (choice as u32) << (index * 2);
    }
    block[4..].copy_from_slice(&indices.to_le_bytes());
    block
}

fn order_color_endpoints(mut a: u16, mut b: u16, transparent: bool) -> (u16, u16) {
    if transparent {
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }
    } else {
        if a < b {
            core::mem::swap(&mut a, &mut b);
        }
        if a == b {
            if a < u16::MAX {
                a += 1;
            } else {
                b -= 1;
            }
        }
    }
    (a, b)
}

fn encode_dxt3_alpha(pixels: &[[u8; 4]; 16]) -> [u8; 8] {
    let mut bits = 0u64;
    for (index, pixel) in pixels.iter().enumerate() {
        let alpha = (u64::from(pixel[3]) * 15 + 127) / 255;
        bits |= alpha << (index * 4);
    }
    bits.to_le_bytes()
}

fn encode_dxt5_alpha(pixels: &[[u8; 4]; 16]) -> [u8; 8] {
    let a0 = pixels.iter().map(|pixel| pixel[3]).max().unwrap_or(255);
    let a1 = pixels.iter().map(|pixel| pixel[3]).min().unwrap_or(0);
    let table = alpha_palette(a0, a1);
    let mut indices = 0u64;
    for (index, pixel) in pixels.iter().enumerate() {
        let choice = (0..8)
            .min_by_key(|&candidate| pixel[3].abs_diff(table[candidate]))
            .unwrap_or(0);
        indices |= (choice as u64) << (index * 3);
    }
    let mut out = [0u8; 8];
    out[0] = a0;
    out[1] = a1;
    out[2..].copy_from_slice(&indices.to_le_bytes()[..6]);
    out
}

fn rgb_to_565(red: u8, green: u8, blue: u8) -> u16 {
    let red = ((u16::from(red) * 31 + 127) / 255) << 11;
    let green = ((u16::from(green) * 63 + 127) / 255) << 5;
    let blue = (u16::from(blue) * 31 + 127) / 255;
    red | green | blue
}

fn color_palette(c0: u16, c1: u16, punchthrough: bool) -> [[u8; 4]; 4] {
    let mut table = [rgb565_to_rgba(c0), rgb565_to_rgba(c1), [0; 4], [0; 4]];
    if punchthrough && c0 <= c1 {
        let [first, second, third, _] = &mut table;
        for ((a, b), c) in first[..3].iter().zip(&second[..3]).zip(&mut third[..3]) {
            *c = ((u16::from(*a) + u16::from(*b)) / 2) as u8;
        }
        table[2][3] = 255;
    } else {
        let [first, second, third, fourth] = &mut table;
        for ((a, b), (c, d)) in first[..3]
            .iter()
            .zip(&second[..3])
            .zip(third[..3].iter_mut().zip(&mut fourth[..3]))
        {
            *c = ((2 * u16::from(*a) + u16::from(*b)) / 3) as u8;
            *d = ((u16::from(*a) + 2 * u16::from(*b)) / 3) as u8;
        }
        table[2][3] = 255;
        table[3][3] = 255;
    }
    table
}

fn alpha_palette(a0: u8, a1: u8) -> [u8; 8] {
    let mut table = [a0, a1, 0, 0, 0, 0, 0, 0];
    if a0 > a1 {
        for i in 1..=6 {
            table[i + 1] = (((7 - i) as u16 * u16::from(a0) + i as u16 * u16::from(a1)) / 7) as u8;
        }
    } else {
        for i in 1..=4 {
            table[i + 1] = (((5 - i) as u16 * u16::from(a0) + i as u16 * u16::from(a1)) / 5) as u8;
        }
        table[6] = 0;
        table[7] = 255;
    }
    table
}

fn rgb_error(pixel: &[u8; 4], candidate: &[u8; 4]) -> u32 {
    (0..3)
        .map(|channel| {
            let delta = i32::from(pixel[channel]) - i32::from(candidate[channel]);
            (delta * delta) as u32
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(width: u32, height: u32, mips: u32, fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; HEADER_LEN];
        f[0..4].copy_from_slice(MAGIC);
        f[4..8].copy_from_slice(&HEADER_SIZE.to_le_bytes());
        let flags = 0x1007 | if mips > 1 { DDSD_MIPMAPCOUNT } else { 0 };
        f[8..12].copy_from_slice(&flags.to_le_bytes());
        f[12..16].copy_from_slice(&height.to_le_bytes());
        f[16..20].copy_from_slice(&width.to_le_bytes());
        f[28..32].copy_from_slice(&mips.to_le_bytes());
        f[0x4c..0x50].copy_from_slice(&PIXELFORMAT_SIZE.to_le_bytes());
        f[0x50..0x54].copy_from_slice(&DDPF_FOURCC.to_le_bytes());
        f[0x54..0x58].copy_from_slice(fourcc);
        f.extend_from_slice(payload);
        f
    }

    fn dxt1_block(c0: u16, c1: u16, indices: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&c0.to_le_bytes());
        b.extend_from_slice(&c1.to_le_bytes());
        b.extend_from_slice(&indices.to_le_bytes());
        b
    }

    fn test_image(width: u32, height: u32) -> Image {
        let mut rgba = Vec::new();
        for y in 0..height {
            for x in 0..width {
                rgba.extend_from_slice(&[
                    (x * 37) as u8,
                    (y * 53) as u8,
                    ((x + y) * 29) as u8,
                    if (x + y) % 3 == 0 { 64 } else { 255 },
                ]);
            }
        }
        Image::try_new(width, height, rgba).unwrap()
    }

    #[test]
    fn rejects_invalid_headers_and_oversized_layouts() {
        assert!(Dds::parse(&[0u8; 4]).is_err());
        let mut f = file(4, 4, 1, b"DXT1", &[0u8; 8]);
        f[0] = b'X';
        assert!(Dds::parse(&f).is_err());
        let mut f = file(4, 4, 1, b"DXT1", &[0u8; 8]);
        f[4..8].copy_from_slice(&125u32.to_le_bytes());
        assert!(Dds::parse(&f).is_err());

        let f = file(1024, 1024, 1, b"DXT1", &[0u8; 8]);
        assert!(matches!(Dds::parse(&f), Err(Error::Truncated { .. })));
        let f = file(u32::MAX, u32::MAX, 1, b"DXT1", &[0u8; 8]);
        assert!(matches!(Dds::parse(&f), Err(Error::ResourceLimit { .. })));
        let f = file(4, 4, 9, b"DXT1", &[0u8; 4096]);
        assert!(matches!(Dds::parse(&f), Err(Error::InvalidField { .. })));
        let f = file(4, 4, 1, b"DX10", &[0u8; 16]);
        assert!(matches!(Dds::parse(&f), Err(Error::Unsupported(_))));
    }

    #[test]
    fn mip_chain_and_cubemap_face_major_layout() {
        let dds = file(4, 4, 3, b"DXT1", &[0u8; 24]);
        let dds = Dds::parse(&dds).unwrap();
        assert_eq!(dds.surface_len(), 24);
        assert_eq!(dds.level_bytes(0, 2).unwrap().len(), 8);
        assert_eq!(dds.level_extent(2).unwrap(), (1, 1));

        let mut payload = Vec::new();
        for face in 0..6u8 {
            payload.extend(core::iter::repeat_n(face, 16));
        }
        let mut f = file(4, 4, 2, b"DXT1", &payload);
        f[0x70..0x74].copy_from_slice(&(DDSCAPS2_CUBEMAP | DDSCAPS2_CUBEMAP_FACES).to_le_bytes());
        let dds = Dds::parse(&f).unwrap();
        assert!(dds.is_cubemap());
        assert_eq!(dds.faces(), 6);
        assert_eq!(dds.surface_len(), 96);
        assert_eq!(dds.level_bytes(3, 0).unwrap(), &[3u8; 8]);
        assert_eq!(dds.level_bytes(3, 1).unwrap(), &[3u8; 8]);
        assert!(dds.level_bytes(6, 0).is_err());
    }

    #[test]
    fn decodes_each_level_from_its_own_bytes() {
        let mut payload = Vec::new();
        for _ in 0..4 {
            payload.extend(dxt1_block(0xf800, 0xf800, 0));
        }
        payload.extend(dxt1_block(0x001f, 0x001f, 0));
        let f = file(8, 8, 2, b"DXT1", &payload);
        let dds = Dds::parse(&f).unwrap();
        let l0 = dds.decode().unwrap();
        assert_eq!((l0.width, l0.height), (8, 8));
        assert_eq!(&l0.rgba[0..4], &[255, 0, 0, 255]);
        let l1 = dds.decode_level(0, 1).unwrap();
        assert_eq!((l1.width, l1.height), (4, 4));
        assert_eq!(&l1.rgba[0..4], &[0, 0, 255, 255]);

        // Pixel limit enforcement on base and mip levels.
        assert_eq!(dds.decode_with_limit(64).unwrap(), l0);
        assert!(matches!(
            dds.decode_with_limit(63),
            Err(Error::ResourceLimit {
                resource: "DDS pixels",
                requested: 64,
                limit: 63,
            })
        ));
        assert_eq!(dds.decode_level_with_limit(0, 1, 16).unwrap(), l1);
        assert!(matches!(
            dds.decode_level_with_limit(0, 1, 15),
            Err(Error::ResourceLimit {
                resource: "DDS pixels",
                requested: 16,
                limit: 15,
            })
        ));
    }

    #[test]
    fn encode_dds_level_like_and_patch_rects() {
        let source = test_image(8, 8);
        for format in [DxtFormat::Dxt1, DxtFormat::Dxt3, DxtFormat::Dxt5] {
            let encoded = encode_dds_level(&source, DdsFormat::Dxt(format)).unwrap();
            assert_eq!(
                encoded,
                encode_dds_level(&source, DdsFormat::Dxt(format)).unwrap()
            );
            assert_eq!(decode_dxt(&encoded, 8, 8, format).unwrap().len(), 8 * 8 * 4);
        }

        // Exact-template rebuild and rectangle containment patch.
        let template = file(8, 8, 2, b"DXT1", &[0u8; 40]);
        let rebuilt = encode_dds_like(&template, &source).unwrap();
        assert_eq!(rebuilt.len(), template.len());
        let parsed = Dds::parse(&rebuilt).unwrap();
        assert_eq!(parsed.mip_levels(), 2);

        let mut modified = source.clone();
        for y in 0..4 {
            for x in 0..4 {
                let off = ((y * 8 + x) * 4) as usize;
                modified.rgba[off..off + 4].copy_from_slice(&[255, 255, 0, 255]);
            }
        }
        let patch = patch_dds_rects(
            &rebuilt,
            &modified,
            &[DdsRect {
                x: 0,
                y: 0,
                width: 4,
                height: 4,
            }],
        )
        .unwrap();
        assert_eq!(patch.levels.len(), 2);
        assert_eq!(patch.levels[0].selected_blocks, 1);
        assert_eq!(patch.levels[0].changed_outside_selected_blocks, 0);
        assert_eq!(patch.levels[1].selected_blocks, 1);
        assert_eq!(patch.levels[1].changed_outside_selected_blocks, 0);
    }

    #[test]
    fn uncompressed_argb8888_round_trips_and_rejects_padded_pitch() {
        let source = test_image(3, 2);
        let masks = ChannelMasks {
            red: 0x00ff_0000,
            green: 0x0000_ff00,
            blue: 0x0000_00ff,
            alpha: 0xff00_0000,
        };
        let encoded = encode_dds_level(
            &source,
            DdsFormat::Uncompressed {
                bits_per_pixel: 32,
                masks,
            },
        )
        .unwrap();
        assert_eq!(
            decode_masked(&encoded, 3, 2, 32, masks).unwrap(),
            source.rgba
        );

        let mut f = vec![0u8; HEADER_LEN];
        f[0..4].copy_from_slice(MAGIC);
        f[4..8].copy_from_slice(&HEADER_SIZE.to_le_bytes());
        f[8..12].copy_from_slice(&(0x1007u32 | DDSD_PITCH).to_le_bytes());
        f[12..16].copy_from_slice(&2u32.to_le_bytes());
        f[16..20].copy_from_slice(&2u32.to_le_bytes());
        f[20..24].copy_from_slice(&16u32.to_le_bytes());
        f[0x4c..0x50].copy_from_slice(&PIXELFORMAT_SIZE.to_le_bytes());
        f[0x50..0x54].copy_from_slice(&(DDPF_RGB | DDPF_ALPHAPIXELS).to_le_bytes());
        f[0x58..0x5c].copy_from_slice(&32u32.to_le_bytes());
        f[0x5c..0x60].copy_from_slice(&masks.red.to_le_bytes());
        f[0x60..0x64].copy_from_slice(&masks.green.to_le_bytes());
        f[0x64..0x68].copy_from_slice(&masks.blue.to_le_bytes());
        f[0x68..0x6c].copy_from_slice(&masks.alpha.to_le_bytes());
        f.extend_from_slice(&[0u8; 16]);
        assert!(matches!(Dds::parse(&f), Err(Error::Unsupported(_))));
        f[20..24].copy_from_slice(&8u32.to_le_bytes());
        assert!(Dds::parse(&f).is_ok());
    }
}
