//! Strict glTF 2.0 binary (`.glb`) container reader and writer.
//!
//! A GLB 2.0 container consists of a 12-byte header (`"glTF"`, version `2`,
//! total byte length), a required 4-byte-aligned `JSON` chunk (padded with
//! ASCII spaces `0x20`), and an optional 4-byte-aligned `BIN\0` chunk (padded
//! with zero bytes `0x00`).

use crate::prelude::*;

use formatkit_core::{Error, Result};

/// GLB magic header (`b"glTF"`, `0x46546C67` little-endian).
pub const GLB_MAGIC: [u8; 4] = *b"glTF";
/// Supported GLB container version (`2`).
pub const GLB_VERSION: u32 = 2;
/// GLB JSON chunk type (`b"JSON"`, `0x4E4F534A` little-endian).
pub const GLB_CHUNK_JSON: [u8; 4] = *b"JSON";
/// GLB binary buffer chunk type (`b"BIN\0"`, `0x004E4942` little-endian).
pub const GLB_CHUNK_BIN: [u8; 4] = *b"BIN\0";

fn u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// Assemble a glTF 2.0 binary (`.glb`) container from a UTF-8 JSON document
/// and an optional binary buffer.
///
/// The JSON chunk is padded with ASCII space (`0x20`) to a 4-byte boundary.
/// When `bin` is `Some(data)`, the `BIN\0` chunk is padded with zero bytes
/// (`0x00`) to a 4-byte boundary.
pub fn write_glb(json: &[u8], bin: Option<&[u8]>) -> Result<Vec<u8>> {
    let json_pad = (4 - (json.len() & 3)) & 3;
    let json_chunk_len = json
        .len()
        .checked_add(json_pad)
        .ok_or(Error::InvalidField {
            what: "GLB JSON chunk length",
            value: json.len() as u64,
        })?;
    let json_chunk_len_u32 = u32::try_from(json_chunk_len).map_err(|_| Error::InvalidField {
        what: "GLB JSON chunk length",
        value: json_chunk_len as u64,
    })?;

    let (bin_part_len, bin_chunk_len_u32, bin_pad) = if let Some(b) = bin {
        let pad = (4 - (b.len() & 3)) & 3;
        let len = b.len().checked_add(pad).ok_or(Error::InvalidField {
            what: "GLB BIN chunk length",
            value: b.len() as u64,
        })?;
        let len_u32 = u32::try_from(len).map_err(|_| Error::InvalidField {
            what: "GLB BIN chunk length",
            value: len as u64,
        })?;
        let part = 8usize.checked_add(len).ok_or(Error::InvalidField {
            what: "GLB BIN chunk length",
            value: len as u64,
        })?;
        (part, Some(len_u32), pad)
    } else {
        (0, None, 0)
    };

    let total = 12usize
        .checked_add(8)
        .and_then(|n| n.checked_add(json_chunk_len))
        .and_then(|n| n.checked_add(bin_part_len))
        .ok_or(Error::InvalidField {
            what: "GLB total length",
            value: u64::MAX,
        })?;
    let total_u32 = u32::try_from(total).map_err(|_| Error::InvalidField {
        what: "GLB total length",
        value: total as u64,
    })?;

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&GLB_MAGIC);
    out.extend_from_slice(&GLB_VERSION.to_le_bytes());
    out.extend_from_slice(&total_u32.to_le_bytes());

    out.extend_from_slice(&json_chunk_len_u32.to_le_bytes());
    out.extend_from_slice(&GLB_CHUNK_JSON);
    out.extend_from_slice(json);
    out.resize(out.len() + json_pad, b' ');

    if let (Some(b), Some(len_u32)) = (bin, bin_chunk_len_u32) {
        out.extend_from_slice(&len_u32.to_le_bytes());
        out.extend_from_slice(&GLB_CHUNK_BIN);
        out.extend_from_slice(b);
        out.resize(out.len() + bin_pad, 0);
    }

    Ok(out)
}

/// Parse a glTF 2.0 binary (`.glb`) container, returning `(json_bytes, bin_bytes)`.
///
/// Validates:
/// - `"glTF"` magic and version `2`.
/// - Declared total length is 4-byte-aligned and matches `bytes.len()` exactly.
/// - First chunk is a 4-byte-aligned `"JSON"` chunk within bounds.
/// - Optional second chunk (when present) is a 4-byte-aligned `"BIN\0"` chunk
///   within bounds (unknown trailing chunks, if any, are also checked for
///   4-byte alignment and exact containment).
pub fn read_glb(bytes: &[u8]) -> Result<(&[u8], Option<&[u8]>)> {
    if bytes.len() < 12 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 12,
            available: bytes.len(),
        });
    }
    if bytes[0..4] != GLB_MAGIC {
        return Err(Error::BadMagic {
            offset: 0,
            expected: u32::from_be_bytes(GLB_MAGIC),
            found: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        });
    }
    let version = u32_le(bytes, 4);
    if version != GLB_VERSION {
        return Err(Error::Unsupported(format!(
            "GLB version {version} (only version 2 is supported)"
        )));
    }
    let total_len = u32_le(bytes, 8) as usize;
    if total_len < 20 || !total_len.is_multiple_of(4) {
        return Err(Error::InvalidField {
            what: "GLB total length",
            value: total_len as u64,
        });
    }
    if total_len > bytes.len() {
        return Err(Error::Truncated {
            offset: 0,
            needed: total_len,
            available: bytes.len(),
        });
    }
    if total_len < bytes.len() {
        return Err(Error::Trailing(bytes.len() - total_len));
    }

    // Chunk 0: required JSON chunk.
    let json_len = u32_le(bytes, 12) as usize;
    if !json_len.is_multiple_of(4) {
        return Err(Error::InvalidField {
            what: "GLB JSON chunk length",
            value: json_len as u64,
        });
    }
    if bytes[16..20] != GLB_CHUNK_JSON {
        return Err(Error::BadMagic {
            offset: 16,
            expected: u32::from_be_bytes(GLB_CHUNK_JSON),
            found: u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
        });
    }
    let json_end = 20usize.checked_add(json_len).ok_or(Error::InvalidField {
        what: "GLB JSON chunk length",
        value: json_len as u64,
    })?;
    if json_end > total_len {
        return Err(Error::Truncated {
            offset: 20,
            needed: json_len,
            available: total_len - 20,
        });
    }
    let json_bytes = &bytes[20..json_end];

    let mut bin_bytes: Option<&[u8]> = None;
    let mut pos = json_end;
    let mut chunk_idx = 1usize;

    while pos < total_len {
        if total_len - pos < 8 {
            return Err(Error::Truncated {
                offset: pos,
                needed: 8,
                available: total_len - pos,
            });
        }
        let chunk_len = u32_le(bytes, pos) as usize;
        if !chunk_len.is_multiple_of(4) {
            return Err(Error::InvalidField {
                what: "GLB chunk length",
                value: chunk_len as u64,
            });
        }
        let chunk_type = &bytes[pos + 4..pos + 8];
        let payload_start = pos + 8;
        let payload_end = payload_start
            .checked_add(chunk_len)
            .ok_or(Error::InvalidField {
                what: "GLB chunk length",
                value: chunk_len as u64,
            })?;
        if payload_end > total_len {
            return Err(Error::Truncated {
                offset: payload_start,
                needed: chunk_len,
                available: total_len - payload_start,
            });
        }
        if chunk_idx == 1 && chunk_type == GLB_CHUNK_BIN {
            bin_bytes = Some(&bytes[payload_start..payload_end]);
        }
        pos = payload_end;
        chunk_idx += 1;
    }

    Ok((json_bytes, bin_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_glb_round_trip_with_and_without_bin() {
        let json = br#"{"asset":{"version":"2.0"}}"#;
        let bin = &[1u8, 2, 3, 4, 5];

        let glb = write_glb(json, Some(bin)).unwrap();
        let (out_json, out_bin) = read_glb(&glb).unwrap();
        assert_eq!(out_json.len() % 4, 0);
        assert!(out_json.starts_with(json));
        assert!(out_json[json.len()..].iter().all(|&b| b == b' '));
        let out_bin = out_bin.unwrap();
        assert_eq!(out_bin.len(), 8);
        assert_eq!(&out_bin[..5], bin);
        assert_eq!(&out_bin[5..], &[0, 0, 0]);

        let glb_no_bin = write_glb(json, None).unwrap();
        let (out_json2, out_bin2) = read_glb(&glb_no_bin).unwrap();
        assert!(out_json2.starts_with(json));
        assert_eq!(out_bin2, None);
    }

    #[test]
    fn read_glb_rejects_invalid_headers_and_bounds() {
        let valid = write_glb(br#"{"asset":{"version":"2.0"}}"#, Some(&[1, 2, 3, 4])).unwrap();

        // Short header
        assert!(matches!(
            read_glb(&valid[..8]),
            Err(Error::Truncated { .. })
        ));

        // Wrong magic
        let mut bad_magic = valid.clone();
        bad_magic[0..4].copy_from_slice(b"NOPE");
        assert!(matches!(read_glb(&bad_magic), Err(Error::BadMagic { .. })));

        // Unsupported version
        let mut bad_ver = valid.clone();
        bad_ver[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(read_glb(&bad_ver), Err(Error::Unsupported(_))));

        // Truncated payload
        assert!(matches!(
            read_glb(&valid[..valid.len() - 4]),
            Err(Error::Truncated { .. })
        ));

        // Trailing bytes
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(read_glb(&trailing), Err(Error::Trailing(4))));

        // First chunk not JSON
        let mut bad_chunk = valid.clone();
        bad_chunk[16..20].copy_from_slice(b"BIN\0");
        assert!(matches!(read_glb(&bad_chunk), Err(Error::BadMagic { .. })));

        // Unaligned chunk length
        let mut unaligned = valid.clone();
        unaligned[12..16].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            read_glb(&unaligned),
            Err(Error::InvalidField { .. })
        ));
    }
}
