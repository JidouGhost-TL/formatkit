//! Parameterized flag-byte / flag-word LZSS stream executor.
//!
//! Many LZSS-family compression formats share the same high-level control loop
//! — reading a fixed-width flag word, consuming one flag bit per token in
//! LSB-first or MSB-first order, emitting literal bytes or invoking a
//! format-specific back-reference parser — while differing in flag width, bit
//! order, literal/match polarity, match-token encoding, and overshoot policy.
//!
//! This module implements that shared bounded control loop and delegates
//! overlapping back-reference copies to [`crate::sliding_window::append_match`].
//! Header parsing, match-token grammar, trailing-flag policy, and carrier
//! framing remain with the caller.

use formatkit_core::{u16_at, u16_at_endian, u32_at, u32_at_endian, u8_at, Endian, Error, Result};

use crate::sliding_window::{self, MatchError};

/// Width of each interleaved control flag word in the compressed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagWidth {
    /// 8-bit flag byte (8 tokens per flag group).
    U8,
    /// Little-endian 16-bit flag word (16 tokens per flag group).
    U16Le,
    /// Big-endian 16-bit flag word (16 tokens per flag group).
    U16Be,
    /// Little-endian 32-bit flag word (32 tokens per flag group).
    U32Le,
    /// Big-endian 32-bit flag word (32 tokens per flag group).
    U32Be,
}

impl FlagWidth {
    #[inline]
    const fn bits(self) -> u8 {
        match self {
            Self::U8 => 8,
            Self::U16Le | Self::U16Be => 16,
            Self::U32Le | Self::U32Be => 32,
        }
    }
}

/// Bit consumption order within each control flag word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagBitOrder {
    /// Consume bit 0 (least-significant bit) first.
    LsbFirst,
    /// Consume the most-significant bit of the flag word first.
    MsbFirst,
}

/// Meaning of each control flag bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagPolarity {
    /// A `1` bit selects a literal byte; a `0` bit selects a back-reference match.
    LiteralIsOne,
    /// A `0` bit selects a literal byte; a `1` bit selects a back-reference match.
    LiteralIsZero,
}

/// Policy when a decoded match extends past `decoded_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OvershootPolicy {
    /// Reject any match whose length would exceed `decoded_size`.
    Reject,
    /// Truncate the final match length so total output equals `decoded_size`.
    ClampToDecodedSize,
}

/// Parameters controlling flag reading, polarity, and overshoot handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagLzssConfig {
    /// Width of each interleaved flag word.
    pub flag_width: FlagWidth,
    /// Order in which bits are consumed from each flag word.
    pub bit_order: FlagBitOrder,
    /// Which bit value denotes a literal byte versus a back-reference match.
    pub polarity: FlagPolarity,
    /// How to handle a match whose length exceeds the remaining output size.
    pub overshoot: OvershootPolicy,
}

/// Decoded back-reference parameters returned by a format's match parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagLzssMatch {
    /// One-based lookback distance into `history || output`.
    pub distance: usize,
    /// Number of bytes to copy.
    pub length: usize,
}

/// Result of decoding one bounded flag-word LZSS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagLzssOutcome {
    /// Decoded output bytes (length equals `decoded_size`).
    pub output: Vec<u8>,
    /// Exact number of source bytes consumed from `src`.
    pub bytes_consumed: usize,
    /// Unused bits remaining in the last loaded flag word (`0..flag_width.bits()`).
    pub remaining_flag_bits: u8,
}

/// Decode a bounded flag-byte or flag-word LZSS stream.
///
/// Reads interleaved flag words from `src` according to `config`, emits
/// literals directly, and invokes `decode_match(src, pos)` for each match flag
/// bit. The callback returns `(match_spec, token_bytes_consumed)`.
///
/// Back-reference copies resolve against `history || output` via
/// [`crate::sliding_window::append_match`], supporting overlapping runs.
///
/// Fails with [`Error::ResourceLimit`] before allocating if
/// `decoded_size > max_output`. Refills a flag word only when
/// `remaining_flag_bits == 0` and `output.len() < decoded_size`, leaving any
/// trailing bytes in `src` unconsumed so the caller can enforce its own
/// trailing-flag or exact-EOF policy.
pub fn decode_flag_lzss<F>(
    src: &[u8],
    history: &[u8],
    decoded_size: usize,
    max_output: usize,
    config: FlagLzssConfig,
    mut decode_match: F,
) -> Result<FlagLzssOutcome>
where
    F: FnMut(&[u8], usize) -> Result<(FlagLzssMatch, usize)>,
{
    if decoded_size > max_output {
        return Err(Error::ResourceLimit {
            resource: "flag_lzss decoded output",
            requested: decoded_size as u64,
            limit: max_output as u64,
        });
    }

    if decoded_size == 0 {
        return Ok(FlagLzssOutcome {
            output: Vec::new(),
            bytes_consumed: 0,
            remaining_flag_bits: 0,
        });
    }

    // Bound initial reservation by available source bytes so a malformed header
    // declaring a large decoded size on a short input fails before allocating.
    let initial_capacity = decoded_size.min(src.len().saturating_mul(16));
    let mut output = Vec::with_capacity(initial_capacity);
    let mut pos = 0usize;
    let mut flag_word = 0u32;
    let mut remaining_bits = 0u8;

    while output.len() < decoded_size {
        if remaining_bits == 0 {
            let raw = match config.flag_width {
                FlagWidth::U8 => {
                    let v = u8_at(src, pos)?;
                    pos += 1;
                    u32::from(v)
                }
                FlagWidth::U16Le => {
                    let v = u16_at(src, pos)?;
                    pos += 2;
                    u32::from(v)
                }
                FlagWidth::U16Be => {
                    let v = u16_at_endian(src, pos, Endian::Big)?;
                    pos += 2;
                    u32::from(v)
                }
                FlagWidth::U32Le => {
                    let v = u32_at(src, pos)?;
                    pos += 4;
                    v
                }
                FlagWidth::U32Be => {
                    let v = u32_at_endian(src, pos, Endian::Big)?;
                    pos += 4;
                    v
                }
            };
            remaining_bits = config.flag_width.bits();
            flag_word = match config.bit_order {
                FlagBitOrder::LsbFirst => raw,
                FlagBitOrder::MsbFirst => raw << (32 - u32::from(remaining_bits)),
            };
        }

        let bit = match config.bit_order {
            FlagBitOrder::LsbFirst => {
                let b = (flag_word & 1) != 0;
                flag_word >>= 1;
                b
            }
            FlagBitOrder::MsbFirst => {
                let b = (flag_word & 0x8000_0000) != 0;
                flag_word <<= 1;
                b
            }
        };
        remaining_bits -= 1;

        let is_literal = match config.polarity {
            FlagPolarity::LiteralIsOne => bit,
            FlagPolarity::LiteralIsZero => !bit,
        };

        if is_literal {
            let byte = u8_at(src, pos)?;
            pos += 1;
            output.push(byte);
        } else {
            let (match_spec, token_bytes) = decode_match(src, pos)?;
            let next_pos = pos.checked_add(token_bytes).ok_or(Error::Truncated {
                offset: pos,
                needed: token_bytes,
                available: src.len().saturating_sub(pos),
            })?;
            if next_pos > src.len() {
                return Err(Error::Truncated {
                    offset: pos,
                    needed: token_bytes,
                    available: src.len().saturating_sub(pos),
                });
            }
            pos = next_pos;

            let remaining = decoded_size - output.len();
            let effective_len = if match_spec.length > remaining {
                match config.overshoot {
                    OvershootPolicy::Reject => {
                        return Err(Error::Malformed(format!(
                            "flag_lzss match overshoot: produced {}, match length {}, decoded size {}",
                            output.len(),
                            match_spec.length,
                            decoded_size
                        )));
                    }
                    OvershootPolicy::ClampToDecodedSize => remaining,
                }
            } else {
                match_spec.length
            };

            sliding_window::append_match(
                &mut output,
                history,
                match_spec.distance,
                effective_len,
                max_output,
            )
            .map_err(|err| match err {
                MatchError::Distance => Error::Malformed(format!(
                    "flag_lzss match distance {} out of range at output offset {} (history {})",
                    match_spec.distance,
                    output.len(),
                    history.len()
                )),
                MatchError::OutputLimit => Error::ResourceLimit {
                    resource: "flag_lzss decoded output",
                    requested: output.len().saturating_add(effective_len) as u64,
                    limit: max_output as u64,
                },
            })?;
        }
    }

    Ok(FlagLzssOutcome {
        output,
        bytes_consumed: pos,
        remaining_flag_bits: remaining_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    enum Token {
        Literal(u8),
        Match(usize, usize),
    }

    /// Encode a synthetic token sequence with simple 2-byte LE `(distance, length)`
    /// match tokens for testing every flag width, bit order, and polarity.
    fn encode_synthetic(tokens: &[Token], config: FlagLzssConfig) -> Vec<u8> {
        let width_bits = usize::from(config.flag_width.bits());
        let mut out = Vec::new();
        for chunk in tokens.chunks(width_bits) {
            let mut flags = 0u32;
            let mut payload = Vec::new();
            for (i, token) in chunk.iter().enumerate() {
                let is_lit = matches!(token, Token::Literal(_));
                let bit_set = match config.polarity {
                    FlagPolarity::LiteralIsOne => is_lit,
                    FlagPolarity::LiteralIsZero => !is_lit,
                };
                if bit_set {
                    match config.bit_order {
                        FlagBitOrder::LsbFirst => flags |= 1u32 << i,
                        FlagBitOrder::MsbFirst => flags |= 1u32 << (width_bits - 1 - i),
                    }
                }
                match *token {
                    Token::Literal(b) => payload.push(b),
                    Token::Match(dist, len) => {
                        payload.push(dist as u8);
                        payload.push(len as u8);
                    }
                }
            }
            match config.flag_width {
                FlagWidth::U8 => out.push(flags as u8),
                FlagWidth::U16Le => out.extend_from_slice(&(flags as u16).to_le_bytes()),
                FlagWidth::U16Be => out.extend_from_slice(&(flags as u16).to_be_bytes()),
                FlagWidth::U32Le => out.extend_from_slice(&flags.to_le_bytes()),
                FlagWidth::U32Be => out.extend_from_slice(&flags.to_be_bytes()),
            }
            out.extend_from_slice(&payload);
        }
        out
    }

    fn decode_simple_match(src: &[u8], pos: usize) -> Result<(FlagLzssMatch, usize)> {
        let dist = usize::from(u8_at(src, pos)?);
        let len = usize::from(u8_at(src, pos + 1)?);
        Ok((
            FlagLzssMatch {
                distance: dist,
                length: len,
            },
            2,
        ))
    }

    #[test]
    fn empty_decoded_size_consumes_nothing() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        let mut called = false;
        let outcome = decode_flag_lzss(b"\xff\xaa", &[], 0, 16, config, |_, _| {
            called = true;
            unreachable!()
        })
        .unwrap();
        assert!(!called);
        assert!(outcome.output.is_empty());
        assert_eq!(outcome.bytes_consumed, 0);
        assert_eq!(outcome.remaining_flag_bits, 0);
    }

    #[test]
    fn rejects_decoded_size_over_max_output_before_allocating() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        let err =
            decode_flag_lzss(&[], &[], usize::MAX, 64, config, decode_simple_match).unwrap_err();
        assert!(matches!(err, Error::ResourceLimit { limit: 64, .. }));
    }

    #[test]
    fn all_widths_orders_and_polarities_multi_group() {
        // 35 tokens exercises multiple flag groups for U8 (5 groups), U16Le (3 groups),
        // and U32Le (2 groups), mixing literals and overlapping/non-overlapping matches.
        let mut tokens = Vec::new();
        let mut expected = Vec::new();
        for i in 0u8..34 {
            if i >= 4 && i % 5 == 0 {
                tokens.push(Token::Match(3, 4));
                for _ in 0..4 {
                    let b = expected[expected.len() - 3];
                    expected.push(b);
                }
            } else {
                let b = b'a' + (i % 26);
                tokens.push(Token::Literal(b));
                expected.push(b);
            }
        }
        tokens.push(Token::Match(2, 5));
        for _ in 0..5 {
            let b = expected[expected.len() - 2];
            expected.push(b);
        }

        let widths = [
            FlagWidth::U8,
            FlagWidth::U16Le,
            FlagWidth::U16Be,
            FlagWidth::U32Le,
            FlagWidth::U32Be,
        ];
        let orders = [FlagBitOrder::LsbFirst, FlagBitOrder::MsbFirst];
        let polarities = [FlagPolarity::LiteralIsOne, FlagPolarity::LiteralIsZero];

        for flag_width in widths {
            for bit_order in orders {
                for polarity in polarities {
                    let config = FlagLzssConfig {
                        flag_width,
                        bit_order,
                        polarity,
                        overshoot: OvershootPolicy::Reject,
                    };
                    let encoded = encode_synthetic(&tokens, config);
                    let mut carrier = encoded.clone();
                    carrier.extend_from_slice(b"TRAILING");

                    let outcome = decode_flag_lzss(
                        &carrier,
                        &[],
                        expected.len(),
                        expected.len(),
                        config,
                        decode_simple_match,
                    )
                    .unwrap();

                    let width_bits = usize::from(flag_width.bits());
                    let expected_rem =
                        ((width_bits - (tokens.len() % width_bits)) % width_bits) as u8;
                    assert_eq!(outcome.output, expected);
                    assert_eq!(outcome.bytes_consumed, encoded.len());
                    assert_eq!(outcome.remaining_flag_bits, expected_rem);
                }
            }
        }
    }

    #[test]
    fn exact_group_boundary_reports_zero_remaining_flag_bits() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        let tokens: Vec<Token> = b"ABCDEFGH".iter().copied().map(Token::Literal).collect();
        let encoded = encode_synthetic(&tokens, config);
        let mut carrier = encoded.clone();
        carrier.push(0x00); // Extra flag byte must NOT be consumed.

        let outcome = decode_flag_lzss(&carrier, &[], 8, 8, config, decode_simple_match).unwrap();
        assert_eq!(outcome.output, b"ABCDEFGH");
        assert_eq!(outcome.bytes_consumed, encoded.len());
        assert_eq!(outcome.remaining_flag_bits, 0);
    }

    #[test]
    fn pre_seeded_history_and_self_overlapping_matches() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U16Le,
            bit_order: FlagBitOrder::MsbFirst,
            polarity: FlagPolarity::LiteralIsZero,
            overshoot: OvershootPolicy::Reject,
        };
        // History = "ABCD"; token 0 = literal 'E'; token 1 = match(dist=4, len=6) -> "BCDEBC";
        // token 2 = match(dist=1, len=4) -> "CCCC" (RLE self-overlap).
        let tokens = [Token::Literal(b'E'), Token::Match(4, 6), Token::Match(1, 4)];
        let encoded = encode_synthetic(&tokens, config);
        let outcome =
            decode_flag_lzss(&encoded, b"ABCD", 11, 16, config, decode_simple_match).unwrap();
        assert_eq!(outcome.output, b"EBCDEBCCCCC");
        assert_eq!(outcome.bytes_consumed, encoded.len());
        assert_eq!(outcome.remaining_flag_bits, 13);
    }

    #[test]
    fn msb_zero_literal_clamped_dialect() {
        // 8-bit MSB-first, 0 = literal / 1 = match, 2-byte big-endian match token:
        // high nibble = length - 3, low 12 bits = distance - 1; overshoot clamped.
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::MsbFirst,
            polarity: FlagPolarity::LiteralIsZero,
            overshoot: OvershootPolicy::ClampToDecodedSize,
        };
        let decode_be12 = |src: &[u8], pos: usize| -> Result<(FlagLzssMatch, usize)> {
            let hi = usize::from(u8_at(src, pos)?);
            let lo = usize::from(u8_at(src, pos + 1)?);
            let length = (hi >> 4) + 3;
            let distance = (((hi & 0x0f) << 8) | lo) + 1;
            Ok((FlagLzssMatch { distance, length }, 2))
        };

        // Flag 0b0010_0000: lit 'X', lit 'Y', match(dist=2, len=8) clamped to 3 bytes -> "XYXYX".
        let dist_field = 2usize - 1;
        let len_field = 8usize - 3;
        let stream = [
            0b0010_0000,
            b'X',
            b'Y',
            ((len_field << 4) | (dist_field >> 8)) as u8,
            (dist_field & 0xff) as u8,
            0x99, // trailing byte outside stream
        ];
        let outcome = decode_flag_lzss(&stream, &[], 5, 16, config, decode_be12).unwrap();
        assert_eq!(outcome.output, b"XYXYX");
        assert_eq!(outcome.bytes_consumed, 5);
        assert_eq!(outcome.remaining_flag_bits, 5);
    }

    #[test]
    fn lsb_one_literal_strict_dialect_and_overshoot_rejection() {
        // 8-bit LSB-first, 1 = literal / 0 = match, strict overshoot rejection.
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        let tokens = [
            Token::Literal(b'A'),
            Token::Literal(b'B'),
            Token::Match(2, 4),
        ];
        let encoded = encode_synthetic(&tokens, config);

        // Exact decoded size (6) succeeds.
        let ok = decode_flag_lzss(&encoded, &[], 6, 16, config, decode_simple_match).unwrap();
        assert_eq!(ok.output, b"ABABAB");
        assert_eq!(ok.bytes_consumed, encoded.len());
        assert_eq!(ok.remaining_flag_bits, 5);

        // Decoded size 5 causes match(2, 4) to overshoot by 1 byte -> Malformed.
        let err = decode_flag_lzss(&encoded, &[], 5, 16, config, decode_simple_match).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn overshoot_handles_usize_max_length_without_overflow() {
        let reject_cfg = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        // Flag 0b0000_0001: lit 'Z', then match with length = usize::MAX.
        let stream = [0b0000_0001, b'Z'];
        let huge_match = |_: &[u8], _: usize| {
            Ok((
                FlagLzssMatch {
                    distance: 1,
                    length: usize::MAX,
                },
                0,
            ))
        };

        let err = decode_flag_lzss(&stream, &[], 4, 16, reject_cfg, huge_match).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));

        let clamp_cfg = FlagLzssConfig {
            overshoot: OvershootPolicy::ClampToDecodedSize,
            ..reject_cfg
        };
        let outcome = decode_flag_lzss(&stream, &[], 4, 16, clamp_cfg, huge_match).unwrap();
        assert_eq!(outcome.output, b"ZZZZ");
        assert_eq!(outcome.bytes_consumed, 2);
        assert_eq!(outcome.remaining_flag_bits, 6);
    }

    #[test]
    fn truncated_flags_literals_and_match_tokens_fail() {
        for (flag_width, short_src, needed) in [
            (FlagWidth::U8, &[][..], 1usize),
            (FlagWidth::U16Le, &[0x01][..], 2usize),
            (FlagWidth::U16Be, &[0x01][..], 2usize),
            (FlagWidth::U32Le, &[0x01, 0x02, 0x03][..], 4usize),
            (FlagWidth::U32Be, &[0x01, 0x02, 0x03][..], 4usize),
        ] {
            let cfg = FlagLzssConfig {
                flag_width,
                bit_order: FlagBitOrder::LsbFirst,
                polarity: FlagPolarity::LiteralIsOne,
                overshoot: OvershootPolicy::Reject,
            };
            let err =
                decode_flag_lzss(short_src, &[], 1, 16, cfg, decode_simple_match).unwrap_err();
            assert_eq!(
                err,
                Error::Truncated {
                    offset: 0,
                    needed,
                    available: short_src.len(),
                }
            );
        }

        // Truncated literal byte.
        let cfg = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        let err = decode_flag_lzss(&[0x01], &[], 1, 16, cfg, decode_simple_match).unwrap_err();
        assert_eq!(
            err,
            Error::Truncated {
                offset: 1,
                needed: 1,
                available: 0,
            }
        );

        // Truncated match token (only 1 of 2 bytes available).
        let err =
            decode_flag_lzss(&[0x00, 0x01], &[], 3, 16, cfg, decode_simple_match).unwrap_err();
        assert_eq!(
            err,
            Error::Truncated {
                offset: 2,
                needed: 1,
                available: 0,
            }
        );

        // Callback reporting token_bytes past end of src.
        let err = decode_flag_lzss(&[0x00], &[], 1, 16, cfg, |_, _| {
            Ok((
                FlagLzssMatch {
                    distance: 1,
                    length: 1,
                },
                5,
            ))
        })
        .unwrap_err();
        assert_eq!(
            err,
            Error::Truncated {
                offset: 1,
                needed: 5,
                available: 0,
            }
        );
    }

    #[test]
    fn invalid_match_distances_rejected() {
        let cfg = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };

        // Zero distance.
        let zero_dist = encode_synthetic(&[Token::Literal(b'A'), Token::Match(0, 2)], cfg);
        let err = decode_flag_lzss(&zero_dist, &[], 3, 16, cfg, decode_simple_match).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));

        // Distance larger than output + history.
        let far_dist = encode_synthetic(&[Token::Literal(b'A'), Token::Match(4, 2)], cfg);
        let err = decode_flag_lzss(&far_dist, b"XY", 3, 16, cfg, decode_simple_match).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }
}
