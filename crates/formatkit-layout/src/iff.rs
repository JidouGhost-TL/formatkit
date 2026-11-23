//! Big-endian IFF-85 `"FORM"` and little-endian `"RIFF"` container walkers.
//!
//! Validates the outer `"FORM"` / `"RIFF"` header (`u32 body_len` + 4-byte
//! `form_type`) and walks nested `(id[4], u32 chunk_len, payload)` chunks
//! strictly within `8 + body_len`, consuming an optional 1-byte even-alignment
//! pad when `chunk_len` is odd.

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

fn parse_form_with_endian(
    bytes: &[u8],
    magic: [u8; 4],
    endian: Endian,
    body_what: &'static str,
    chunk_what: &'static str,
) -> Result<IffForm> {
    if bytes.len() < 12 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 12,
            available: bytes.len(),
        });
    }
    if bytes[0..4] != magic {
        return Err(Error::BadMagic {
            offset: 0,
            expected: u32::from_be_bytes(magic),
            found: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        });
    }

    let raw_body = bytes[4..8].try_into().unwrap();
    let body_len = match endian {
        Endian::Big => u32::from_be_bytes(raw_body),
        Endian::Little => u32::from_le_bytes(raw_body),
    };
    if body_len < 4 {
        return Err(Error::InvalidField {
            what: body_what,
            value: u64::from(body_len),
        });
    }
    let form_end = 8usize
        .checked_add(body_len as usize)
        .ok_or(Error::InvalidField {
            what: body_what,
            value: u64::from(body_len),
        })?;
    if form_end > bytes.len() {
        return Err(Error::Truncated {
            offset: 8,
            needed: body_len as usize,
            available: bytes.len() - 8,
        });
    }

    let form_type: [u8; 4] = bytes[8..12].try_into().unwrap();
    let mut chunks = Vec::new();
    let mut pos = 12usize;

    while pos < form_end {
        if form_end - pos < 8 {
            return Err(Error::Truncated {
                offset: pos,
                needed: 8,
                available: form_end - pos,
            });
        }
        let id: [u8; 4] = bytes[pos..pos + 4].try_into().unwrap();
        let raw_chunk = bytes[pos + 4..pos + 8].try_into().unwrap();
        let chunk_len = match endian {
            Endian::Big => u32::from_be_bytes(raw_chunk),
            Endian::Little => u32::from_le_bytes(raw_chunk),
        } as usize;
        let payload_offset = pos + 8;
        let payload_end = payload_offset
            .checked_add(chunk_len)
            .ok_or(Error::InvalidField {
                what: chunk_what,
                value: chunk_len as u64,
            })?;
        if payload_end > form_end {
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

/// Parse a big-endian IFF-85 `"FORM"` container and index its child chunks.
///
/// Validates `"FORM"` magic, big-endian `body_len >= 4`, `8 + body_len <= bytes.len()`,
/// and every nested chunk header and payload strictly within `8 + body_len`.
/// When a chunk has an odd `payload_len` and at least one byte remains before
/// `8 + body_len`, the trailing alignment pad byte is skipped.
pub fn parse_iff_form(bytes: &[u8]) -> Result<IffForm> {
    parse_form_with_endian(
        bytes,
        IFF_FORM_MAGIC,
        Endian::Big,
        "IFF FORM body_len",
        "IFF chunk length",
    )
}

/// Parse a little-endian `"RIFF"` container and index its child chunks.
///
/// Mirror of [`parse_iff_form`]: validates `"RIFF"` magic, little-endian
/// `body_len >= 4`, `8 + body_len <= bytes.len()`, and every nested chunk
/// header and payload strictly within `8 + body_len`.
pub fn parse_riff_form(bytes: &[u8]) -> Result<IffForm> {
    parse_form_with_endian(
        bytes,
        RIFF_MAGIC,
        Endian::Little,
        "RIFF body_len",
        "RIFF chunk length",
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
}
