//! Tagged-header LZ77 streams with MSB-first flag bytes and 12-bit distances.
//!
//! Both variants start with a [`crate::tagged_header`] and then alternate an
//! 8-bit flag byte (consumed most-significant bit first; `0` = literal byte,
//! `1` = back-reference) with up to eight tokens. Distances are one-based and
//! stored as `distance - 1` in 12 bits (`1..=4096`) over the linear output
//! history. A final match that extends past the declared size is clipped.
//!
//! - **Compact** ([`TAG_LZ77`], `0x10`): 2-byte match `LLLL DDDD DDDD DDDD`,
//!   length `3..=18`.
//! - **Extended** ([`TAG_LZ77_EXTENDED`], `0x11`): the high nibble of the
//!   first match byte selects the token size: `2..=15` is a 2-byte match of
//!   length `nibble + 1` (`3..=16`), `0` is a 3-byte match carrying an 8-bit
//!   length biased by `0x11` (`17..=272`), and `1` is a 4-byte match carrying a
//!   16-bit length biased by `0x111` (`273..=65808`). The header may use the
//!   32-bit extended-size form.
//!
//! Decoders report the exact consumed extent through the last token needed to
//! produce the declared size, so trailing padding or a following stream is
//! left unconsumed. Encoders use the brute-force
//! [`crate::sliding_window::find_longest_match`] greedy parse.
//!
//! ```
//! use formatkit_codec::tagged_lz77::{decode_tagged_lz77, encode_tagged_lz77};
//!
//! let data = b"abcabcabcabcabcabc".repeat(4);
//! let mut stream = encode_tagged_lz77(&data).unwrap();
//! let exact = stream.len();
//! stream.extend_from_slice(&[0, 0, 0]); // carrier padding
//!
//! let decoded = decode_tagged_lz77(&stream, 1 << 20).unwrap();
//! assert_eq!(decoded.bytes, data);
//! assert_eq!(decoded.consumed, exact);
//! ```
//!
//! [`TAG_LZ77`]: crate::tagged_header::TAG_LZ77
//! [`TAG_LZ77_EXTENDED`]: crate::tagged_header::TAG_LZ77_EXTENDED

use formatkit_core::{bytes_at, Error, Result};

use crate::flag_lzss::{
    decode_flag_lzss, FlagBitOrder, FlagLzssConfig, FlagLzssMatch, FlagPolarity, FlagWidth,
    OvershootPolicy,
};
use crate::sliding_window::find_longest_match;
use crate::tagged_header::{
    check_decoded_size, check_encode_len, expect_tag, expect_tagged_header, read_tagged_header,
    read_tagged_header_extended, shift_truncated, write_tagged_header,
    write_tagged_header_extended, TAGGED_HEADER_LEN,
};
pub use crate::tagged_header::{TAG_LZ77, TAG_LZ77_EXTENDED};
use crate::DecodeOutcome;

/// Largest one-based back-reference distance (12-bit field).
pub const TAGGED_LZ77_MAX_DISTANCE: usize = 4096;
/// Largest match length of the compact (`0x10`) token.
pub const TAGGED_LZ77_MAX_LEN: usize = 18;
/// Largest match length of the extended (`0x11`) 4-byte token.
pub const TAGGED_LZ77_EXTENDED_MAX_LEN: usize = 0x111 + 0xFFFF;
/// Shortest match length either variant encodes.
pub const TAGGED_LZ77_MIN_LEN: usize = 3;

const FLAG_CONFIG: FlagLzssConfig = FlagLzssConfig {
    flag_width: FlagWidth::U8,
    bit_order: FlagBitOrder::MsbFirst,
    polarity: FlagPolarity::LiteralIsZero,
    overshoot: OvershootPolicy::ClampToDecodedSize,
};

/// Decode a compact tagged LZ77 (`0x10`) stream starting at `input[0]`.
///
/// Rejects a wrong tag, a zero declared size, or a declared size above
/// `max_output` before allocating. Returns the decoded bytes and the exact
/// number of bytes consumed (header included).
#[doc(alias = "lz10")]
pub fn decode_tagged_lz77(input: &[u8], max_output: usize) -> Result<DecodeOutcome> {
    let header = expect_tagged_header(
        input,
        TAG_LZ77,
        "tagged LZ77 decoded size",
        "tagged LZ77 decoded output",
        max_output,
    )?;
    let body = &input[TAGGED_HEADER_LEN..];
    let outcome = decode_flag_lzss(
        body,
        &[],
        header.decoded_size,
        max_output,
        FLAG_CONFIG,
        |src, pos| {
            let token = bytes_at(src, pos, 2)?;
            let (b1, b2) = (usize::from(token[0]), usize::from(token[1]));
            Ok((
                FlagLzssMatch {
                    distance: ((b1 & 0x0F) << 8 | b2) + 1,
                    length: (b1 >> 4) + TAGGED_LZ77_MIN_LEN,
                },
                2,
            ))
        },
    )
    .map_err(|err| shift_truncated(err, TAGGED_HEADER_LEN))?;
    Ok(DecodeOutcome {
        bytes: outcome.output,
        consumed: TAGGED_HEADER_LEN + outcome.bytes_consumed,
    })
}

/// Encode `data` as a compact tagged LZ77 (`0x10`) stream with distances `>= 1`.
///
/// `data` must be `1..=0xFF_FFFF` bytes.
#[doc(alias = "lz10")]
pub fn encode_tagged_lz77(data: &[u8]) -> Result<Vec<u8>> {
    encode_tagged_lz77_with_min_distance(data, 1)
}

/// Encode `data` as a compact tagged LZ77 (`0x10`) stream whose back-references
/// never use a distance below `min_distance` (`1..=4096`).
///
/// A minimum distance of `2` keeps every copy at least one 16-bit unit behind
/// the write cursor, which decoders that write output in 16-bit units need.
pub fn encode_tagged_lz77_with_min_distance(data: &[u8], min_distance: usize) -> Result<Vec<u8>> {
    check_encode_len(data.len(), "tagged LZ77 input size")?;
    if !(1..=TAGGED_LZ77_MAX_DISTANCE).contains(&min_distance) {
        return Err(Error::InvalidField {
            what: "tagged LZ77 minimum distance",
            value: min_distance as u64,
        });
    }
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + TAGGED_HEADER_LEN + 1);
    write_tagged_header(&mut out, TAG_LZ77, data.len())?;
    encode_flag_groups(data, &mut out, |data, idx, out| {
        let (distance, len) = find_longest_match(
            data,
            idx,
            min_distance,
            TAGGED_LZ77_MAX_DISTANCE,
            TAGGED_LZ77_MIN_LEN,
            TAGGED_LZ77_MAX_LEN,
        )?;
        let d = distance - 1;
        let l = len - TAGGED_LZ77_MIN_LEN;
        out.push((l << 4 | d >> 8) as u8);
        out.push((d & 0xFF) as u8);
        Some(len)
    });
    Ok(out)
}

/// Decode an extended-length tagged LZ77 (`0x11`) stream starting at `input[0]`.
///
/// Accepts both the compact 4-byte header and the 8-byte extended-size header.
/// Rejects a wrong tag, a zero declared size, or a declared size above
/// `max_output` before allocating.
#[doc(alias = "lz11")]
pub fn decode_tagged_lz77_extended(input: &[u8], max_output: usize) -> Result<DecodeOutcome> {
    expect_tag(read_tagged_header(input)?, TAG_LZ77_EXTENDED)?;
    let header = read_tagged_header_extended(input)?;
    check_decoded_size(
        header,
        "tagged LZ77 extended decoded size",
        "tagged LZ77 extended decoded output",
        max_output,
    )?;
    let body = &input[header.header_len..];
    let outcome = decode_flag_lzss(
        body,
        &[],
        header.decoded_size,
        max_output,
        FLAG_CONFIG,
        |src, pos| {
            let b1 = usize::from(*src.get(pos).ok_or(Error::Truncated {
                offset: pos,
                needed: 1,
                available: src.len().saturating_sub(pos),
            })?);
            match b1 >> 4 {
                0 => {
                    let t = bytes_at(src, pos, 3)?;
                    let (b2, b3) = (usize::from(t[1]), usize::from(t[2]));
                    Ok((
                        FlagLzssMatch {
                            distance: ((b2 & 0x0F) << 8 | b3) + 1,
                            length: ((b1 & 0x0F) << 4 | b2 >> 4) + 0x11,
                        },
                        3,
                    ))
                }
                1 => {
                    let t = bytes_at(src, pos, 4)?;
                    let (b2, b3, b4) = (usize::from(t[1]), usize::from(t[2]), usize::from(t[3]));
                    Ok((
                        FlagLzssMatch {
                            distance: ((b3 & 0x0F) << 8 | b4) + 1,
                            length: ((b1 & 0x0F) << 12 | b2 << 4 | b3 >> 4) + 0x111,
                        },
                        4,
                    ))
                }
                mode => {
                    let t = bytes_at(src, pos, 2)?;
                    Ok((
                        FlagLzssMatch {
                            distance: ((b1 & 0x0F) << 8 | usize::from(t[1])) + 1,
                            length: mode + 1,
                        },
                        2,
                    ))
                }
            }
        },
    )
    .map_err(|err| shift_truncated(err, header.header_len))?;
    Ok(DecodeOutcome {
        bytes: outcome.output,
        consumed: header.header_len + outcome.bytes_consumed,
    })
}

/// Encode `data` as an extended-length tagged LZ77 (`0x11`) stream.
///
/// Inputs above `0xFF_FFFF` bytes use the 8-byte extended-size header; inputs
/// must be `1..=u32::MAX` bytes.
#[doc(alias = "lz11")]
pub fn encode_tagged_lz77_extended(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::InvalidField {
            what: "tagged LZ77 extended input size",
            value: 0,
        });
    }
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 9);
    write_tagged_header_extended(&mut out, TAG_LZ77_EXTENDED, data.len())?;
    encode_flag_groups(data, &mut out, |data, idx, out| {
        let (distance, len) = find_longest_match(
            data,
            idx,
            1,
            TAGGED_LZ77_MAX_DISTANCE,
            TAGGED_LZ77_MIN_LEN,
            TAGGED_LZ77_EXTENDED_MAX_LEN,
        )?;
        let d = distance - 1;
        if len <= 16 {
            out.push(((len - 1) << 4 | d >> 8) as u8);
            out.push((d & 0xFF) as u8);
        } else if len <= 0x110 {
            let extra = len - 0x11;
            out.push((extra >> 4) as u8);
            out.push(((extra & 0x0F) << 4 | d >> 8) as u8);
            out.push((d & 0xFF) as u8);
        } else {
            let extra = len - 0x111;
            out.push((0x10 | extra >> 12) as u8);
            out.push((extra >> 4 & 0xFF) as u8);
            out.push(((extra & 0x0F) << 4 | d >> 8) as u8);
            out.push((d & 0xFF) as u8);
        }
        Some(len)
    });
    Ok(out)
}

/// Emit MSB-first flag groups of eight tokens. `emit_match` writes a match
/// token for `data[idx..]` and returns its length, or returns `None` (writing
/// nothing) to request a literal.
fn encode_flag_groups<F>(data: &[u8], out: &mut Vec<u8>, mut emit_match: F)
where
    F: FnMut(&[u8], usize, &mut Vec<u8>) -> Option<usize>,
{
    let mut idx = 0usize;
    while idx < data.len() {
        let flag_pos = out.len();
        out.push(0);
        let mut flags = 0u8;
        for bit in 0..8 {
            if idx >= data.len() {
                break;
            }
            if let Some(len) = emit_match(data, idx, out) {
                flags |= 0x80 >> bit;
                idx += len;
            } else {
                out.push(data[idx]);
                idx += 1;
            }
        }
        out[flag_pos] = flags;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg_bytes(seed: u64, len: usize, alphabet: u8) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ((state >> 33) as u8) % alphabet
            })
            .collect()
    }

    /// Walk a compact stream's tokens and return every back-reference distance.
    fn compact_distances(stream: &[u8]) -> Vec<usize> {
        let size = read_tagged_header(stream).unwrap().decoded_size;
        let (mut pos, mut produced, mut distances) = (4usize, 0usize, Vec::new());
        while produced < size {
            let flags = stream[pos];
            pos += 1;
            for bit in 0..8 {
                if produced >= size {
                    break;
                }
                if flags & (0x80 >> bit) == 0 {
                    pos += 1;
                    produced += 1;
                } else {
                    let (b1, b2) = (usize::from(stream[pos]), usize::from(stream[pos + 1]));
                    distances.push(((b1 & 0x0F) << 8 | b2) + 1);
                    produced += (b1 >> 4) + 3;
                    pos += 2;
                }
            }
        }
        distances
    }

    #[test]
    fn reference_vector_clips_final_overlapping_match_and_reports_extent() {
        // Literal 'A', then match length 7 distance 1, clipped to size 6.
        let stream = [0x10, 0x06, 0x00, 0x00, 0x40, b'A', 0x40, 0x00, 0x99];
        let dec = decode_tagged_lz77(&stream, 64).unwrap();
        assert_eq!(dec.bytes, b"AAAAAA");
        assert_eq!(dec.consumed, 8);
    }

    #[test]
    fn compact_round_trips_with_exact_extent_and_min_distance() {
        let mut data = b"PATTERN_0123_".repeat(20);
        data.extend(lcg_bytes(7, 700, 5));
        data.extend(std::iter::repeat_n(0x5A, 64));
        for min_distance in [1, 2, 3, 4096] {
            let mut stream = encode_tagged_lz77_with_min_distance(&data, min_distance).unwrap();
            assert!(compact_distances(&stream)
                .iter()
                .all(|&d| d >= min_distance));
            let exact = stream.len();
            stream.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
            let dec = decode_tagged_lz77(&stream, data.len()).unwrap();
            assert_eq!(dec.bytes, data);
            assert_eq!(dec.consumed, exact);
        }
        assert!(encode_tagged_lz77_with_min_distance(&data, 0).is_err());
        assert!(encode_tagged_lz77_with_min_distance(&data, 4097).is_err());
        assert!(encode_tagged_lz77(&[]).is_err());
    }

    #[test]
    fn extended_round_trips_every_token_size_and_boundary() {
        let mut data = b"SHORT_MATCH_1234".repeat(10);
        data.extend_from_slice(&[0x42; 100]);
        data.extend_from_slice(&[0x99; 1000]);
        data.extend(lcg_bytes(3, 300, 4));
        let mut stream = encode_tagged_lz77_extended(&data).unwrap();
        assert_eq!(stream[0], TAG_LZ77_EXTENDED);
        let exact = stream.len();
        stream.extend_from_slice(&[0xAA, 0xBB]);
        let dec = decode_tagged_lz77_extended(&stream, 1 << 20).unwrap();
        assert_eq!(dec.bytes, data);
        assert_eq!(dec.consumed, exact);

        for len in [
            3,
            16,
            17,
            18,
            0x110,
            0x111,
            0x112,
            TAGGED_LZ77_EXTENDED_MAX_LEN + 5,
        ] {
            let mut data = vec![0x5Au8; 20];
            data.extend(std::iter::repeat_n(0x7B, len));
            let stream = encode_tagged_lz77_extended(&data).unwrap();
            let dec = decode_tagged_lz77_extended(&stream, 1 << 20).unwrap();
            assert_eq!(dec.bytes, data, "length {len}");
            assert_eq!(dec.consumed, stream.len());
        }
    }

    #[test]
    fn extended_token_size_nibbles_match_shipped_streams() {
        // Pins the token layout seen in shipped DS data: nibble 0 = 3-byte match
        // (length + 0x11), nibble 1 = 4-byte match (length + 0x111). A matching
        // encoder swap would still round-trip, so check fixed bytes both ways.
        let three = [0x11, 18, 0, 0, 0x40, b'A', 0x00, 0x00, 0x00];
        assert_eq!(
            decode_tagged_lz77_extended(&three, 64).unwrap().bytes,
            vec![b'A'; 18]
        );
        let four = [0x11, 0x12, 0x01, 0, 0x40, b'B', 0x10, 0x00, 0x00, 0x00];
        assert_eq!(
            decode_tagged_lz77_extended(&four, 1024).unwrap().bytes,
            vec![b'B'; 0x112]
        );
        let mut data = vec![b'A'];
        data.extend([b'A'; 17]);
        assert_eq!(encode_tagged_lz77_extended(&data).unwrap(), three.to_vec());
    }

    #[test]
    fn extended_accepts_32_bit_size_header() {
        // Extended header declaring 5 bytes, literal 'Q', then 2-byte match length 4 distance 1.
        let stream = [0x11, 0, 0, 0, 5, 0, 0, 0, 0x40, b'Q', 0x30, 0x00, 0xFF];
        let dec = decode_tagged_lz77_extended(&stream, 64).unwrap();
        assert_eq!(dec.bytes, b"QQQQQ");
        assert_eq!(dec.consumed, 12);
        let short = [0x11, 0, 0, 0, 5];
        assert!(matches!(
            decode_tagged_lz77_extended(&short, 64),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_bad_tag_zero_size_limits_and_bad_distance() {
        assert!(matches!(
            decode_tagged_lz77(&[0x11, 4, 0, 0], 64),
            Err(Error::BadMagic { .. })
        ));
        assert!(matches!(
            decode_tagged_lz77_extended(&[0x10, 4, 0, 0], 64),
            Err(Error::BadMagic { .. })
        ));
        assert!(matches!(
            decode_tagged_lz77(&[0x10, 0, 0, 0], 64),
            Err(Error::InvalidField { .. })
        ));
        assert!(matches!(
            decode_tagged_lz77_extended(&[0x11, 0, 0, 0, 0, 0, 0, 0], 64),
            Err(Error::InvalidField { .. })
        ));
        // Header claims 4 MiB on a five-byte input: limit and truncation fail cleanly.
        assert!(matches!(
            decode_tagged_lz77(&[0x10, 0, 0, 0x40, 0], 1024),
            Err(Error::ResourceLimit { .. })
        ));
        assert!(matches!(
            decode_tagged_lz77(&[0x10, 0, 0, 0x40, 0], 1 << 23),
            Err(Error::Truncated { offset: 5, .. })
        ));
        // Back-reference before the start of output.
        assert!(matches!(
            decode_tagged_lz77(&[0x10, 4, 0, 0, 0x80, 0x00, 0x04], 64),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn truncated_and_mutated_streams_never_panic() {
        let data: Vec<u8> = b"mutation-fixture-".repeat(12);
        let compact = encode_tagged_lz77(&data).unwrap();
        let extended = encode_tagged_lz77_extended(&data).unwrap();
        for stream in [&compact, &extended] {
            for cut in 0..stream.len() {
                assert!(decode_tagged_lz77(&stream[..cut], 1 << 16).is_err());
                assert!(decode_tagged_lz77_extended(&stream[..cut], 1 << 16).is_err());
            }
            for seed in 0..256u64 {
                let mut mutated = stream.clone();
                for (i, noise) in lcg_bytes(seed, 4, 255).into_iter().enumerate() {
                    let at = (seed as usize * 31 + i * 17) % mutated.len();
                    mutated[at] ^= noise | 1;
                }
                if let Ok(dec) = decode_tagged_lz77(&mutated, 1 << 16) {
                    assert!(dec.consumed <= mutated.len());
                }
                if let Ok(dec) = decode_tagged_lz77_extended(&mutated, 1 << 16) {
                    assert!(dec.consumed <= mutated.len());
                }
            }
        }
    }
}
