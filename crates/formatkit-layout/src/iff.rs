//! Big-endian IFF-85 `"FORM"` and little-endian `"RIFF"` container walkers.
//!
//! Validates the outer `"FORM"` / `"RIFF"` header (`u32 body_len` + 4-byte
//! `form_type`) and walks nested `(id[4], u32 chunk_len, payload)` chunks
//! strictly within `8 + body_len`, consuming an optional 1-byte even-alignment
//! pad when `chunk_len` is odd.

use crate::prelude::*;

use formatkit_core::{Endian, Error, Result};

/// Four-byte magic identifying a standard big-endian IFF-85 `FORM` container.
pub const IFF_FORM_MAGIC: [u8; 4] = *b"FORM";

/// Four-byte magic identifying a standard little-endian `RIFF` container.
pub const RIFF_MAGIC: [u8; 4] = *b"RIFF";

/// One chunk discovered inside an IFF-85 [`IffForm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IffChunk {
    /// Four-byte chunk identifier.
    pub id: [u8; 4],
    /// Byte offset of the chunk payload relative to the start of the `FORM` buffer.
    pub payload_offset: usize,
    /// Declared payload length in bytes (excluding any odd-length pad byte).
    pub payload_len: usize,
}

/// Parsed outer header and child chunk index of an IFF-85 `FORM` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IffForm {
    /// Four-byte form type immediately following the `FORM` length field.
    pub form_type: [u8; 4],
    /// Declared byte length of the `FORM` body (including `form_type`).
    pub body_len: u32,
    /// Child chunks found in order within `8..8 + body_len`.
    pub chunks: Vec<IffChunk>,
}

/// How outer container and child chunk size fields are interpreted in an IFF/RIFF container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RiffSizeMode {
    /// Standard IFF/RIFF framing: size fields exclude their 8-byte `(magic/id, u32 len)` header
    /// (default).
    #[default]
    Exclusive,
    /// Header-inclusive variant: size fields include their 8-byte `(magic/id, u32 len)` header
    /// (requiring outer `size >= 12` and child `size >= 8`).
    Inclusive,
    /// Automatically detect exclusive vs. header-inclusive framing by checking container bounds:
    /// prefers standard [`RiffSizeMode::Exclusive`], falling back to header-inclusive outer sizing
    /// (with exclusive or header-inclusive child chunks) when exclusive framing fails.
    Auto,
}

/// Options controlling [`parse_riff_form_with_options`] and [`parse_iff_form_with_options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RiffParseOptions {
    /// Whether outer and/or child chunk length fields exclude or include their 8-byte headers
    /// (default [`RiffSizeMode::Exclusive`]).
    pub size_mode: RiffSizeMode,
    /// When `true`, clamp a final chunk (or container body) whose declared length extends past
    /// the available slice instead of returning [`formatkit_core::Error::Truncated`] (default `false`).
    pub allow_truncated_final_chunk: bool,
}

impl RiffParseOptions {
    /// Construct default [`RiffParseOptions`] (`RiffSizeMode::Exclusive`,
    /// `allow_truncated_final_chunk: false`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size_mode: RiffSizeMode::Exclusive,
            allow_truncated_final_chunk: false,
        }
    }

    /// Set [`RiffParseOptions::size_mode`].
    #[must_use]
    pub const fn with_size_mode(mut self, size_mode: RiffSizeMode) -> Self {
        self.size_mode = size_mode;
        self
    }

    /// Set [`RiffParseOptions::allow_truncated_final_chunk`].
    #[must_use]
    pub const fn with_allow_truncated_final_chunk(mut self, allow: bool) -> Self {
        self.allow_truncated_final_chunk = allow;
        self
    }
}

#[inline]
fn read_four(bytes: &[u8], offset: usize) -> [u8; 4] {
    [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]
}

#[inline]
fn decode_u32(raw: [u8; 4], endian: Endian) -> u32 {
    match endian {
        Endian::Big => u32::from_be_bytes(raw),
        Endian::Little => u32::from_le_bytes(raw),
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_form_explicit(
    bytes: &[u8],
    magic: [u8; 4],
    endian: Endian,
    body_what: &'static str,
    chunk_what: &'static str,
    outer_inclusive: bool,
    child_inclusive: bool,
    allow_truncated_final_chunk: bool,
) -> Result<IffForm> {
    if bytes.len() < 12 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 12,
            available: bytes.len(),
        });
    }
    let found_magic = read_four(bytes, 0);
    if found_magic != magic {
        return Err(Error::BadMagic {
            offset: 0,
            expected: u32::from_be_bytes(magic),
            found: u32::from_be_bytes(found_magic),
        });
    }

    let raw_size = decode_u32(read_four(bytes, 4), endian);
    let (body_len, form_end) = if outer_inclusive {
        if raw_size < 12 {
            return Err(Error::InvalidField {
                what: body_what,
                value: u64::from(raw_size),
            });
        }
        let body = raw_size - 8;
        let end = raw_size as usize;
        if end > bytes.len() && !allow_truncated_final_chunk {
            return Err(Error::Truncated {
                offset: 8,
                needed: body as usize,
                available: bytes.len() - 8,
            });
        }
        (body, end.min(bytes.len()))
    } else {
        if raw_size < 4 {
            return Err(Error::InvalidField {
                what: body_what,
                value: u64::from(raw_size),
            });
        }
        let end = 8usize
            .checked_add(raw_size as usize)
            .ok_or(Error::InvalidField {
                what: body_what,
                value: u64::from(raw_size),
            })?;
        if end > bytes.len() && !allow_truncated_final_chunk {
            return Err(Error::Truncated {
                offset: 8,
                needed: raw_size as usize,
                available: bytes.len() - 8,
            });
        }
        (raw_size, end.min(bytes.len()))
    };

    let form_type = read_four(bytes, 8);
    let mut chunks = Vec::new();
    let mut pos = 12usize;

    while pos < form_end {
        if form_end - pos < 8 {
            if allow_truncated_final_chunk {
                break;
            }
            return Err(Error::Truncated {
                offset: pos,
                needed: 8,
                available: form_end - pos,
            });
        }
        let id = read_four(bytes, pos);
        let raw_chunk_len = decode_u32(read_four(bytes, pos + 4), endian);
        let chunk_len = if child_inclusive {
            if raw_chunk_len < 8 {
                return Err(Error::InvalidField {
                    what: chunk_what,
                    value: u64::from(raw_chunk_len),
                });
            }
            (raw_chunk_len - 8) as usize
        } else {
            raw_chunk_len as usize
        };
        let payload_offset = pos + 8;
        let payload_end = payload_offset
            .checked_add(chunk_len)
            .ok_or(Error::InvalidField {
                what: chunk_what,
                value: chunk_len as u64,
            })?;
        if payload_end > form_end {
            if allow_truncated_final_chunk {
                let clamped_len = form_end - payload_offset;
                chunks.push(IffChunk {
                    id,
                    payload_offset,
                    payload_len: clamped_len,
                });
                break;
            }
            return Err(Error::Truncated {
                offset: payload_offset,
                needed: chunk_len,
                available: form_end - payload_offset,
            });
        }

        chunks.push(IffChunk {
            id,
            payload_offset,
            payload_len: chunk_len,
        });

        pos = if (chunk_len & 1) == 1 && payload_end < form_end {
            payload_end + 1
        } else {
            payload_end
        };
    }

    Ok(IffForm {
        form_type,
        body_len,
        chunks,
    })
}

fn parse_form_with_endian(
    bytes: &[u8],
    magic: [u8; 4],
    endian: Endian,
    body_what: &'static str,
    chunk_what: &'static str,
    options: RiffParseOptions,
) -> Result<IffForm> {
    match options.size_mode {
        RiffSizeMode::Exclusive => parse_form_explicit(
            bytes,
            magic,
            endian,
            body_what,
            chunk_what,
            false,
            false,
            options.allow_truncated_final_chunk,
        ),
        RiffSizeMode::Inclusive => parse_form_explicit(
            bytes,
            magic,
            endian,
            body_what,
            chunk_what,
            true,
            true,
            options.allow_truncated_final_chunk,
        ),
        RiffSizeMode::Auto => {
            // 1. Standard exclusive outer + exclusive children.
            match parse_form_explicit(
                bytes,
                magic,
                endian,
                body_what,
                chunk_what,
                false,
                false,
                options.allow_truncated_final_chunk,
            ) {
                Ok(form) => Ok(form),
                Err(exclusive_err) => {
                    // 2. Header-inclusive outer + exclusive children.
                    if let Ok(form) = parse_form_explicit(
                        bytes,
                        magic,
                        endian,
                        body_what,
                        chunk_what,
                        true,
                        false,
                        options.allow_truncated_final_chunk,
                    ) {
                        return Ok(form);
                    }
                    // 3. Header-inclusive outer + header-inclusive children.
                    if let Ok(form) = parse_form_explicit(
                        bytes,
                        magic,
                        endian,
                        body_what,
                        chunk_what,
                        true,
                        true,
                        options.allow_truncated_final_chunk,
                    ) {
                        return Ok(form);
                    }
                    Err(exclusive_err)
                }
            }
        }
    }
}

/// Parse a big-endian IFF-85 `"FORM"` container and index its child chunks.
///
/// Validates `"FORM"` magic, big-endian `body_len >= 4`, `8 + body_len <= bytes.len()`,
/// and every nested chunk header and payload strictly within `8 + body_len`.
/// When a chunk has an odd `payload_len` and at least one byte remains before
/// `8 + body_len`, the trailing alignment pad byte is skipped.
pub fn parse_iff_form(bytes: &[u8]) -> Result<IffForm> {
    parse_iff_form_with_options(bytes, RiffParseOptions::new())
}

/// Parse a big-endian IFF-85 `"FORM"` container using explicit [`RiffParseOptions`].
pub fn parse_iff_form_with_options(bytes: &[u8], options: RiffParseOptions) -> Result<IffForm> {
    parse_form_with_endian(
        bytes,
        IFF_FORM_MAGIC,
        Endian::Big,
        "IFF FORM body_len",
        "IFF chunk length",
        options,
    )
}

/// Parse a little-endian `"RIFF"` container and index its child chunks.
///
/// Mirror of [`parse_iff_form`]: validates `"RIFF"` magic, little-endian
/// `body_len >= 4`, `8 + body_len <= bytes.len()`, and every nested chunk
/// header and payload strictly within `8 + body_len`.
pub fn parse_riff_form(bytes: &[u8]) -> Result<IffForm> {
    parse_riff_form_with_options(bytes, RiffParseOptions::new())
}

/// Parse a little-endian `"RIFF"` container using explicit [`RiffParseOptions`].
pub fn parse_riff_form_with_options(bytes: &[u8], options: RiffParseOptions) -> Result<IffForm> {
    parse_form_with_endian(
        bytes,
        RIFF_MAGIC,
        Endian::Little,
        "RIFF body_len",
        "RIFF chunk length",
        options,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_form(form_type: [u8; 4], chunks: &[([u8; 4], &[u8], bool)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&form_type);
        for &(id, payload, pad_odd) in chunks {
            body.extend_from_slice(&id);
            body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            body.extend_from_slice(payload);
            if (payload.len() & 1) == 1 && pad_odd {
                body.push(0);
            }
        }
        let mut out = Vec::with_capacity(8 + body.len());
        out.extend_from_slice(&IFF_FORM_MAGIC);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parses_even_and_odd_padded_chunks_and_ignores_trailing_carrier_bytes() {
        let mut bytes = build_form(
            *b"TEST",
            &[
                (*b"HDR ", b"abcd", true),
                (*b"ODD ", b"123", true),
                (*b"TAIL", b"xy", true),
            ],
        );
        bytes.extend_from_slice(b"carrier");

        let form = parse_iff_form(&bytes).unwrap();
        assert_eq!(form.form_type, *b"TEST");
        assert_eq!(form.chunks.len(), 3);
        assert_eq!(
            form.chunks[0],
            IffChunk {
                id: *b"HDR ",
                payload_offset: 20,
                payload_len: 4,
            }
        );
        assert_eq!(
            form.chunks[1],
            IffChunk {
                id: *b"ODD ",
                payload_offset: 32,
                payload_len: 3,
            }
        );
        // 32 + 3 + 1 pad = 36 header -> 44 payload
        assert_eq!(
            form.chunks[2],
            IffChunk {
                id: *b"TAIL",
                payload_offset: 44,
                payload_len: 2,
            }
        );
    }

    #[test]
    fn accepts_unpadded_final_odd_chunk_at_form_boundary() {
        let bytes = build_form(*b"DEMO", &[(*b"LAST", b"abc", false)]);
        let form = parse_iff_form(&bytes).unwrap();
        assert_eq!(form.chunks.len(), 1);
        assert_eq!(form.chunks[0].payload_len, 3);
    }

    #[test]
    fn rejects_bad_magic_short_body_and_out_of_bounds_chunks() {
        assert!(matches!(
            parse_iff_form(b"FORM\0\0\0"),
            Err(Error::Truncated { needed: 12, .. })
        ));
        assert!(matches!(
            parse_iff_form(b"RIFF\0\0\0\x04WAVE"),
            Err(Error::BadMagic { offset: 0, .. })
        ));
        assert!(matches!(
            parse_iff_form(b"FORM\0\0\0\x03TEST"),
            Err(Error::InvalidField {
                what: "IFF FORM body_len",
                value: 3,
            })
        ));
        assert!(matches!(
            parse_iff_form(b"FORM\0\0\0\x20TEST"),
            Err(Error::Truncated {
                offset: 8,
                needed: 32,
                available: 4,
            })
        ));

        // Chunk declares 10 bytes when only 2 remain in FORM.
        let bad_chunk = b"FORM\0\0\0\x0eTESTDATA\0\0\0\x0a!!";
        assert!(matches!(
            parse_iff_form(bad_chunk),
            Err(Error::Truncated { needed: 10, .. })
        ));

        // Truncated child chunk header (< 8 bytes remaining).
        let short_child = b"FORM\0\0\0\x08TESTABCD";
        assert!(matches!(
            parse_iff_form(short_child),
            Err(Error::Truncated {
                offset: 12,
                needed: 8,
                available: 4,
            })
        ));
    }

    #[test]
    fn parses_little_endian_riff_chunks_and_rejects_form_magic() {
        let mut body = Vec::new();
        body.extend_from_slice(b"WAVE");
        body.extend_from_slice(b"ODD ");
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"xyz");
        body.push(0);
        body.extend_from_slice(b"data");
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);

        let mut riff = Vec::new();
        riff.extend_from_slice(&RIFF_MAGIC);
        riff.extend_from_slice(&(body.len() as u32).to_le_bytes());
        riff.extend_from_slice(&body);
        riff.extend_from_slice(b"extra");

        let form = parse_riff_form(&riff).unwrap();
        assert_eq!(form.form_type, *b"WAVE");
        assert_eq!(form.body_len as usize, body.len());
        assert_eq!(form.chunks.len(), 2);
        assert_eq!(
            form.chunks[0],
            IffChunk {
                id: *b"ODD ",
                payload_offset: 20,
                payload_len: 3,
            }
        );
        assert_eq!(
            form.chunks[1],
            IffChunk {
                id: *b"data",
                payload_offset: 32,
                payload_len: 4,
            }
        );
        assert!(matches!(
            parse_riff_form(b"FORM\x04\x00\x00\x00TEST"),
            Err(Error::BadMagic { offset: 0, .. })
        ));
    }

    #[test]
    fn riff_size_mode_inclusive_auto_and_truncated_final_chunk() {
        // 1. Header-inclusive outer RIFF + exclusive child chunks (detected by Auto)
        let mut outer_incl = Vec::new();
        outer_incl.extend_from_slice(&RIFF_MAGIC);
        // Total length = 12 (RIFF+size+type) + 8 (CODE+len) + 4 (payload) = 24
        outer_incl.extend_from_slice(&24u32.to_le_bytes());
        outer_incl.extend_from_slice(b"SCR ");
        outer_incl.extend_from_slice(b"CODE");
        outer_incl.extend_from_slice(&4u32.to_le_bytes());
        outer_incl.extend_from_slice(&[0x10, 0x20, 0x30, 0x40]);

        assert!(matches!(
            parse_riff_form(&outer_incl),
            Err(Error::Truncated {
                offset: 8,
                needed: 24,
                available: 16,
            })
        ));
        let auto_form = parse_riff_form_with_options(
            &outer_incl,
            RiffParseOptions::new().with_size_mode(RiffSizeMode::Auto),
        )
        .unwrap();
        assert_eq!(auto_form.form_type, *b"SCR ");
        assert_eq!(auto_form.body_len, 16);
        assert_eq!(auto_form.chunks.len(), 1);
        assert_eq!(auto_form.chunks[0].id, *b"CODE");
        assert_eq!(auto_form.chunks[0].payload_offset, 20);
        assert_eq!(auto_form.chunks[0].payload_len, 4);

        // 2. Fully header-inclusive RIFF (both outer and child chunk sizes include 8-byte header)
        let mut full_incl = Vec::new();
        full_incl.extend_from_slice(&RIFF_MAGIC);
        full_incl.extend_from_slice(&24u32.to_le_bytes());
        full_incl.extend_from_slice(b"INCL");
        full_incl.extend_from_slice(b"DATA");
        full_incl.extend_from_slice(&12u32.to_le_bytes()); // 8-byte header + 4-byte payload
        full_incl.extend_from_slice(b"WXYZ");

        let incl_form = parse_riff_form_with_options(
            &full_incl,
            RiffParseOptions::new().with_size_mode(RiffSizeMode::Inclusive),
        )
        .unwrap();
        assert_eq!(incl_form.form_type, *b"INCL");
        assert_eq!(incl_form.chunks.len(), 1);
        assert_eq!(incl_form.chunks[0].id, *b"DATA");
        assert_eq!(incl_form.chunks[0].payload_len, 4);

        let auto_incl = parse_riff_form_with_options(
            &full_incl,
            RiffParseOptions::new().with_size_mode(RiffSizeMode::Auto),
        )
        .unwrap();
        assert_eq!(auto_incl, incl_form);

        // Inclusive rejects outer size < 12 or child size < 8
        assert!(matches!(
            parse_riff_form_with_options(
                b"RIFF\x08\x00\x00\x00TEST",
                RiffParseOptions::new().with_size_mode(RiffSizeMode::Inclusive),
            ),
            Err(Error::InvalidField { value: 8, .. })
        ));
        assert!(matches!(
            parse_riff_form_with_options(
                b"RIFF\x14\x00\x00\x00TESTBAD \x04\x00\x00\x00",
                RiffParseOptions::new().with_size_mode(RiffSizeMode::Inclusive),
            ),
            Err(Error::InvalidField { value: 4, .. })
        ));

        // 3. allow_truncated_final_chunk clamps truncated payload within bounded slice
        let mut trunc = Vec::new();
        trunc.extend_from_slice(&RIFF_MAGIC);
        trunc.extend_from_slice(&200u32.to_le_bytes());
        trunc.extend_from_slice(b"WAVE");
        trunc.extend_from_slice(b"fmt ");
        trunc.extend_from_slice(&4u32.to_le_bytes());
        trunc.extend_from_slice(&[1, 2, 3, 4]);
        trunc.extend_from_slice(b"data");
        trunc.extend_from_slice(&100u32.to_le_bytes());
        trunc.extend_from_slice(b"part");

        assert!(parse_riff_form(&trunc).is_err());
        let clamped = parse_riff_form_with_options(
            &trunc,
            RiffParseOptions::new().with_allow_truncated_final_chunk(true),
        )
        .unwrap();
        assert_eq!(clamped.chunks.len(), 2);
        assert_eq!(clamped.chunks[0].payload_len, 4);
        assert_eq!(clamped.chunks[1].id, *b"data");
        assert_eq!(clamped.chunks[1].payload_len, 4);
    }
}
