//! Bounded RFC 1952 gzip member decoding.
//!
//! Containers may carry gzip as a member codec. This module validates one
//! complete member, including optional header fields, CRC-32 and ISIZE, while
//! delegating the compressed body to the bounded raw DEFLATE decoder.

use formatkit_core::checksum::crc32_iso_hdlc;

use crate::{inflate_one_with_limit, DecodeOutcome};

const FIXED_HEADER_LEN: usize = 10;
const TRAILER_LEN: usize = 8;

fn nul_terminated_end(src: &[u8], start: usize) -> Option<usize> {
    let relative = src.get(start..)?.iter().position(|&byte| byte == 0)?;
    start.checked_add(relative)?.checked_add(1)
}

/// Decode one gzip member, refusing to produce more than `max_output_len`
/// bytes. The returned extent ends immediately after its eight-byte trailer;
/// callers decide whether concatenated members or trailing bytes are legal.
pub fn gzip_one_with_limit(src: &[u8], max_output_len: usize) -> Option<DecodeOutcome> {
    let header = src.get(..FIXED_HEADER_LEN)?;
    if header[0..3] != [0x1f, 0x8b, 8] || header[3] & 0xe0 != 0 {
        return None;
    }
    let flags = header[3];
    let mut body_start = FIXED_HEADER_LEN;
    if flags & 0x04 != 0 {
        let extra_len =
            u16::from_le_bytes(src.get(body_start..body_start + 2)?.try_into().ok()?) as usize;
        body_start = body_start.checked_add(2)?.checked_add(extra_len)?;
        src.get(..body_start)?;
    }
    if flags & 0x08 != 0 {
        body_start = nul_terminated_end(src, body_start)?;
    }
    if flags & 0x10 != 0 {
        body_start = nul_terminated_end(src, body_start)?;
    }
    if flags & 0x02 != 0 {
        let expected = u16::from_le_bytes(src.get(body_start..body_start + 2)?.try_into().ok()?);
        if crc32_iso_hdlc(src.get(..body_start)?) as u16 != expected {
            return None;
        }
        body_start = body_start.checked_add(2)?;
    }
    let decoded = inflate_one_with_limit(src.get(body_start..)?, max_output_len)?;
    let trailer_start = body_start.checked_add(decoded.consumed)?;
    let trailer_end = trailer_start.checked_add(TRAILER_LEN)?;
    let trailer = src.get(trailer_start..trailer_end)?;
    let expected_crc = u32::from_le_bytes(trailer[..4].try_into().ok()?);
    let expected_size = u32::from_le_bytes(trailer[4..].try_into().ok()?);
    if crc32_iso_hdlc(&decoded.bytes) != expected_crc || decoded.bytes.len() as u32 != expected_size
    {
        return None;
    }
    Some(DecodeOutcome {
        bytes: decoded.bytes,
        consumed: trailer_end,
    })
}

/// Decode exactly one gzip member. Trailing bytes and concatenated members
/// are rejected; use [`gzip_one_with_limit`] for a container with its own
/// framing rule.
pub fn gzip_with_limit(src: &[u8], max_output_len: usize) -> Option<Vec<u8>> {
    let decoded = gzip_one_with_limit(src, max_output_len)?;
    (decoded.consumed == src.len()).then_some(decoded.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(input: &[u8], flags: u8) -> Vec<u8> {
        let mut gzip = vec![0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3];
        if flags & 0x04 != 0 {
            gzip.extend_from_slice(&3u16.to_le_bytes());
            gzip.extend_from_slice(&[7, 8, 9]);
        }
        if flags & 0x08 != 0 {
            gzip.extend_from_slice(b"asset.bin\0");
        }
        if flags & 0x10 != 0 {
            gzip.extend_from_slice(b"comment\0");
        }
        if flags & 0x02 != 0 {
            let check = crc32_iso_hdlc(&gzip) as u16;
            gzip.extend_from_slice(&check.to_le_bytes());
        }
        gzip.extend_from_slice(&crate::deflate_compress(input));
        gzip.extend_from_slice(&crc32_iso_hdlc(input).to_le_bytes());
        gzip.extend_from_slice(&(input.len() as u32).to_le_bytes());
        gzip
    }

    #[test]
    fn round_trip_and_exact_extent() {
        let input = b"bounded gzip member".repeat(500);
        for flags in [0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f] {
            let gzip = encoded(&input, flags);
            assert_eq!(gzip_with_limit(&gzip, input.len()), Some(input.clone()));
            assert!(gzip_with_limit(&gzip, input.len() - 1).is_none());
            let mut concatenated = gzip.clone();
            concatenated.extend_from_slice(&gzip);
            assert!(gzip_with_limit(&concatenated, input.len()).is_none());
            let first = gzip_one_with_limit(&concatenated, input.len()).unwrap();
            assert_eq!(first.consumed, gzip.len());
            assert_eq!(first.bytes, input);
        }
    }

    #[test]
    fn rejects_corrupt_or_incomplete_members() {
        let valid = encoded(b"member", 0x1e);
        for length in 0..valid.len() {
            assert!(
                gzip_with_limit(&valid[..length], 6).is_none(),
                "length {length}"
            );
        }
        for offset in [0, 2, 3, 10, 13, valid.len() - 8, valid.len() - 4] {
            let mut bad = valid.clone();
            bad[offset] ^= 0x80;
            assert!(gzip_with_limit(&bad, 6).is_none(), "offset {offset}");
        }
        let mut reserved = valid.clone();
        reserved[3] |= 0x20;
        assert!(gzip_with_limit(&reserved, 6).is_none());
    }
}
