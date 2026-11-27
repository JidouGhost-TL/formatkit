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

use crate::prelude::*;

use formatkit_core::{u16_at, u16_at_endian, u32_at, u32_at_endian, u8_at, Endian, Error, Result};

use crate::sliding_window::{self, MatchError, RingBuffer};

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

/// Decoded non-literal action returned by a format's token parser in
/// [`decode_flag_lzss_actions`] or [`decode_flag_lzss_ring_to_end`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagAction<'a> {
    /// One-based lookback match into linear `history || output`.
    LinearMatch {
        /// One-based lookback distance into `history || output`.
        distance: usize,
        /// Number of bytes to copy.
        length: usize,
    },
    /// Absolute ring-buffer match starting at `pos % N` (which is `pos & (N - 1)`
    /// for power-of-two `N`).
    RingMatch {
        /// Starting index in the ring buffer (wrapped modulo `N`).
        pos: usize,
        /// Number of bytes to copy.
        length: usize,
    },
    /// Relative ring-buffer lookback starting at `(cursor - distance) mod N`,
    /// copying byte-by-byte through the write cursor.
    RingRelativeMatch {
        /// One-based lookback distance behind the current write cursor (`1..=N`).
        distance: usize,
        /// Number of bytes to copy.
        length: usize,
    },
    /// Copy a slice of literal bytes directly into output (and into the ring
    /// buffer when using [`decode_flag_lzss_ring_to_end`]).
    LiteralRun(&'a [u8]),
    /// Cleanly terminate decoding without producing further output.
    EndOfStream,
}

/// Result of decoding one bounded flag-word LZSS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagLzssOutcome {
    /// Decoded output bytes (length equals `decoded_size` when a declared size
    /// is given).
    pub output: Vec<u8>,
    /// Exact number of source bytes consumed from `src`.
    pub bytes_consumed: usize,
    /// Unused bits remaining in the last loaded flag word (`0..flag_width.bits()`).
    pub remaining_flag_bits: u8,
}

#[inline]
fn load_flag_word(src: &[u8], pos: &mut usize, config: FlagLzssConfig) -> Result<(u32, u8)> {
    let raw = match config.flag_width {
        FlagWidth::U8 => {
            let v = u8_at(src, *pos)?;
            *pos += 1;
            u32::from(v)
        }
        FlagWidth::U16Le => {
            let v = u16_at(src, *pos)?;
            *pos += 2;
            u32::from(v)
        }
        FlagWidth::U16Be => {
            let v = u16_at_endian(src, *pos, Endian::Big)?;
            *pos += 2;
            u32::from(v)
        }
        FlagWidth::U32Le => {
            let v = u32_at(src, *pos)?;
            *pos += 4;
            v
        }
        FlagWidth::U32Be => {
            let v = u32_at_endian(src, *pos, Endian::Big)?;
            *pos += 4;
            v
        }
    };
    let remaining_bits = config.flag_width.bits();
    let flag_word = match config.bit_order {
        FlagBitOrder::LsbFirst => raw,
        FlagBitOrder::MsbFirst => raw << (32 - u32::from(remaining_bits)),
    };
    Ok((flag_word, remaining_bits))
}

#[inline]
fn next_flag_is_literal(
    flag_word: &mut u32,
    remaining_bits: &mut u8,
    config: FlagLzssConfig,
) -> bool {
    let bit = match config.bit_order {
        FlagBitOrder::LsbFirst => {
            let b = (*flag_word & 1) != 0;
            *flag_word >>= 1;
            b
        }
        FlagBitOrder::MsbFirst => {
            let b = (*flag_word & 0x8000_0000) != 0;
            *flag_word <<= 1;
            b
        }
    };
    *remaining_bits -= 1;
    match config.polarity {
        FlagPolarity::LiteralIsOne => bit,
        FlagPolarity::LiteralIsZero => !bit,
    }
}

#[inline]
fn advance_token_pos(src: &[u8], pos: usize, token_bytes: usize) -> Result<usize> {
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
    Ok(next_pos)
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

#[inline]
fn output_limit_error(requested: usize, max_output: usize) -> Error {
    Error::ResourceLimit {
        resource: "flag_lzss decoded output",
        requested: requested as u64,
        limit: max_output as u64,
    }
}

#[inline]
fn ensure_output_room(produced: usize, len: usize, max_output: usize) -> Result<()> {
    match produced.checked_add(len) {
        Some(end) if end <= max_output => Ok(()),
        _ => Err(output_limit_error(produced.saturating_add(len), max_output)),
    }
}

/// Apply the declared-size overshoot policy to a token producing `len` bytes.
#[inline]
fn declared_token_len(
    len: usize,
    produced: usize,
    decoded_size: Option<usize>,
    overshoot: OvershootPolicy,
) -> Result<usize> {
    let Some(size) = decoded_size else {
        return Ok(len);
    };
    let remaining = size - produced;
    if len <= remaining {
        return Ok(len);
    }
    match overshoot {
        OvershootPolicy::Reject => Err(Error::Malformed(format!(
            "flag_lzss token overshoot: produced {produced}, token length {len}, decoded size {size}"
        ))),
        OvershootPolicy::ClampToDecodedSize => Ok(remaining),
    }
}

/// Decode a flag-word LZSS stream into a fixed power-of-two ring buffer until
/// an [`FlagAction::EndOfStream`] token or clean input exhaustion.
///
/// The `N`-byte ring is pre-filled with `fill` and written starting at
/// `initial_cursor`. Literal flag bits copy one source byte; every other flag
/// bit invokes `decode_token(src, pos)`, which returns the parsed action and
/// the number of token bytes it consumed at `pos`. Supported actions are
/// [`FlagAction::RingMatch`], [`FlagAction::RingRelativeMatch`],
/// [`FlagAction::LiteralRun`] and [`FlagAction::EndOfStream`]; a
/// [`FlagAction::LinearMatch`] is rejected as malformed. Every produced byte is
/// written through the ring cursor, so overlapping copies repeat bytes.
///
/// Termination: decoding stops after an `EndOfStream` token (leaving any later
/// bytes unconsumed) or when the input ends exactly after a complete token. The
/// first token of a freshly loaded flag word is always attempted, so a stream
/// ending immediately after a flag word fails as truncated (unless that token
/// consumes no bytes). Output growth is checked against `max_output` before
/// every token.
///
/// Fails with [`Error::InvalidField`] if `N` is not a nonzero power of two or
/// if `initial_cursor >= N`. The overshoot policy in `config` does not apply,
/// because no decoded size is declared.
pub fn decode_flag_lzss_ring_to_end<'a, const N: usize, F>(
    src: &'a [u8],
    max_output: usize,
    config: FlagLzssConfig,
    fill: u8,
    initial_cursor: usize,
    mut decode_token: F,
) -> Result<FlagLzssOutcome>
where
    F: FnMut(&'a [u8], usize) -> Result<(FlagAction<'a>, usize)>,
{
    if !N.is_power_of_two() {
        return Err(Error::InvalidField {
            what: "flag_lzss ring size",
            value: N as u64,
        });
    }
    if initial_cursor >= N {
        return Err(Error::InvalidField {
            what: "flag_lzss ring initial cursor",
            value: initial_cursor as u64,
        });
    }

    let mut ring = RingBuffer::<N>::new(fill, initial_cursor);
    let mut output = Vec::with_capacity(src.len().min(max_output));
    let mut pos = 0usize;
    let mut flag_word = 0u32;
    let mut remaining_bits = 0u8;

    loop {
        if remaining_bits == 0 {
            if pos == src.len() {
                break;
            }
            (flag_word, remaining_bits) = load_flag_word(src, &mut pos, config)?;
        } else if pos == src.len() {
            break;
        }

        if next_flag_is_literal(&mut flag_word, &mut remaining_bits, config) {
            let byte = u8_at(src, pos)?;
            ensure_output_room(output.len(), 1, max_output)?;
            pos += 1;
            ring.push(byte);
            output.push(byte);
            continue;
        }

        let (action, token_bytes) = decode_token(src, pos)?;
        pos = advance_token_pos(src, pos, token_bytes)?;
        match action {
            FlagAction::RingMatch { pos: start, length } => {
                ring.copy_match(start, length, &mut output, max_output)
                    .map_err(|_| {
                        output_limit_error(output.len().saturating_add(length), max_output)
                    })?;
            }
            FlagAction::RingRelativeMatch { distance, length } => {
                if distance == 0 || distance > N {
                    return Err(Error::Malformed(format!(
                        "flag_lzss ring distance {distance} out of range at output offset {} (ring {N})",
                        output.len()
                    )));
                }
                let start = ring.cursor().wrapping_sub(distance) & (N - 1);
                ring.copy_match(start, length, &mut output, max_output)
                    .map_err(|_| {
                        output_limit_error(output.len().saturating_add(length), max_output)
                    })?;
            }
            FlagAction::LiteralRun(bytes) => {
                ensure_output_room(output.len(), bytes.len(), max_output)?;
                for &byte in bytes {
                    ring.push(byte);
                }
                output.extend_from_slice(bytes);
            }
            FlagAction::EndOfStream => break,
            FlagAction::LinearMatch { .. } => {
                return Err(Error::Malformed(format!(
                    "flag_lzss ring executor received a linear match at output offset {}",
                    output.len()
                )));
            }
        }
    }

    Ok(FlagLzssOutcome {
        output,
        bytes_consumed: pos,
        remaining_flag_bits: remaining_bits,
    })
}

/// Decode a flag-word LZSS stream with multi-action tokens over linear
/// `history || output`.
///
/// Literal flag bits copy one source byte; every other flag bit invokes
/// `decode_token(src, pos)`, which returns the parsed action and the number of
/// token bytes it consumed at `pos`. Supported actions are
/// [`FlagAction::LinearMatch`] (resolved via
/// [`crate::sliding_window::append_match`], so overlapping copies repeat
/// bytes), [`FlagAction::LiteralRun`] and [`FlagAction::EndOfStream`]; ring
/// actions are rejected as malformed.
///
/// With `decoded_size = Some(size)` the loop matches [`decode_flag_lzss`]: it
/// fails with [`Error::ResourceLimit`] before allocating when
/// `size > max_output`, stops once `size` bytes exist (leaving later bytes
/// unconsumed), and applies `config.overshoot` to matches and literal runs that
/// would cross `size`. An [`FlagAction::EndOfStream`] token before `size`
/// output bytes have been produced fails with [`Error::Malformed`].
///
/// With `decoded_size = None` decoding stops after an `EndOfStream` token or
/// when the input ends exactly after a complete token (the first token of a
/// freshly loaded flag word is always attempted). Output growth is checked
/// against `max_output` before every token.
///
/// ```
/// use formatkit_codec::flag_lzss::{
///     decode_flag_lzss_actions, FlagAction, FlagBitOrder, FlagLzssConfig, FlagPolarity,
///     FlagWidth, OvershootPolicy,
/// };
///
/// let config = FlagLzssConfig {
///     flag_width: FlagWidth::U8,
///     bit_order: FlagBitOrder::LsbFirst,
///     polarity: FlagPolarity::LiteralIsOne,
///     overshoot: OvershootPolicy::Reject,
/// };
/// // Literal 'a', then a match token `[distance, length]`, then a zero end marker.
/// let stream = [0b0000_0001, b'a', 1, 3, 0];
/// let outcome = decode_flag_lzss_actions(&stream, &[], None, 16, config, |src, pos| {
///     Ok(match src[pos] {
///         0 => (FlagAction::EndOfStream, 1),
///         distance => (
///             FlagAction::LinearMatch {
///                 distance: usize::from(distance),
///                 length: usize::from(src[pos + 1]),
///             },
///             2,
///         ),
///     })
/// })
/// .unwrap();
/// assert_eq!(outcome.output, b"aaaa");
/// assert_eq!(outcome.bytes_consumed, stream.len());
/// ```
pub fn decode_flag_lzss_actions<'a, F>(
    src: &'a [u8],
    history: &[u8],
    decoded_size: Option<usize>,
    max_output: usize,
    config: FlagLzssConfig,
    mut decode_token: F,
) -> Result<FlagLzssOutcome>
where
    F: FnMut(&'a [u8], usize) -> Result<(FlagAction<'a>, usize)>,
{
    let initial_capacity = match decoded_size {
        Some(size) => {
            if size > max_output {
                return Err(output_limit_error(size, max_output));
            }
            size.min(src.len().saturating_mul(16))
        }
        None => src.len().min(max_output),
    };
    let mut output = Vec::with_capacity(initial_capacity);
    let mut pos = 0usize;
    let mut flag_word = 0u32;
    let mut remaining_bits = 0u8;

    loop {
        match decoded_size {
            Some(size) if output.len() >= size => break,
            Some(_) => {
                if remaining_bits == 0 {
                    (flag_word, remaining_bits) = load_flag_word(src, &mut pos, config)?;
                }
            }
            None => {
                if remaining_bits == 0 {
                    if pos == src.len() {
                        break;
                    }
                    (flag_word, remaining_bits) = load_flag_word(src, &mut pos, config)?;
                } else if pos == src.len() {
                    break;
                }
            }
        }

        if next_flag_is_literal(&mut flag_word, &mut remaining_bits, config) {
            let byte = u8_at(src, pos)?;
            ensure_output_room(output.len(), 1, max_output)?;
            pos += 1;
            output.push(byte);
            continue;
        }

        let (action, token_bytes) = decode_token(src, pos)?;
        pos = advance_token_pos(src, pos, token_bytes)?;
        match action {
            FlagAction::LinearMatch { distance, length } => {
                let effective_len =
                    declared_token_len(length, output.len(), decoded_size, config.overshoot)?;
                sliding_window::append_match(
                    &mut output,
                    history,
                    distance,
                    effective_len,
                    max_output,
                )
                .map_err(|err| match err {
                    MatchError::Distance => Error::Malformed(format!(
                        "flag_lzss match distance {distance} out of range at output offset {} (history {})",
                        output.len(),
                        history.len()
                    )),
                    MatchError::OutputLimit => {
                        output_limit_error(output.len().saturating_add(effective_len), max_output)
                    }
                })?;
            }
            FlagAction::LiteralRun(bytes) => {
                let effective_len =
                    declared_token_len(bytes.len(), output.len(), decoded_size, config.overshoot)?;
                ensure_output_room(output.len(), effective_len, max_output)?;
                output.extend_from_slice(&bytes[..effective_len]);
            }
            FlagAction::EndOfStream => {
                if let Some(expected) = decoded_size {
                    if output.len() < expected {
                        return Err(Error::Malformed(format!(
                            "flag_lzss end of stream before declared size: produced {}, decoded size {expected}",
                            output.len()
                        )));
                    }
                }
                break;
            }
            FlagAction::RingMatch { .. } | FlagAction::RingRelativeMatch { .. } => {
                return Err(Error::Malformed(format!(
                    "flag_lzss linear executor received a ring match at output offset {}",
                    output.len()
                )));
            }
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

    /// Synthetic multi-action token grammar used by the action executor tests:
    /// `0` = end of stream; `1 lo hi len` = ring match; `2 lo hi len` = ring
    /// relative match; `3 n bytes..` = literal run; `4 dist len` = linear match.
    fn decode_synthetic_action(src: &[u8], pos: usize) -> Result<(FlagAction<'_>, usize)> {
        let u16_arg = |at: usize| -> Result<usize> { Ok(usize::from(u16_at(src, at)?)) };
        Ok(match u8_at(src, pos)? {
            0 => (FlagAction::EndOfStream, 1),
            1 => (
                FlagAction::RingMatch {
                    pos: u16_arg(pos + 1)?,
                    length: usize::from(u8_at(src, pos + 3)?),
                },
                4,
            ),
            2 => (
                FlagAction::RingRelativeMatch {
                    distance: u16_arg(pos + 1)?,
                    length: usize::from(u8_at(src, pos + 3)?),
                },
                4,
            ),
            3 => {
                let n = usize::from(u8_at(src, pos + 1)?);
                let run = src.get(pos + 2..pos + 2 + n).ok_or(Error::Truncated {
                    offset: pos + 2,
                    needed: n,
                    available: src.len().saturating_sub(pos + 2),
                })?;
                (FlagAction::LiteralRun(run), 2 + n)
            }
            4 => (
                FlagAction::LinearMatch {
                    distance: usize::from(u8_at(src, pos + 1)?),
                    length: usize::from(u8_at(src, pos + 2)?),
                },
                3,
            ),
            tag => return Err(Error::Malformed(format!("synthetic tag {tag}"))),
        })
    }

    const RUN: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    /// One full flag group exercising every ring action, including a literal run
    /// that wraps the 1024-byte ring and a relative match across the wrap.
    fn ring_group() -> (Vec<u8>, Vec<u8>) {
        let mut stream = vec![0b1111_1000, b'A', b'B', b'C'];
        stream.extend_from_slice(&[1, 0xDE, 0x03, 5]); // ring[0x3DE..] -> "ABCAB"
        stream.extend_from_slice(&[2, 3, 0, 4]); // 3 back, overlapping -> "CABC"
        stream.extend_from_slice(&[3, RUN.len() as u8]);
        stream.extend_from_slice(RUN); // cursor wraps past 1023
        stream.extend_from_slice(&[2, 16, 0, 4]); // across the wrap -> "klmn"
        stream.extend_from_slice(&[1, 0xDD, 0x03, 3]); // untouched fill, then "AB"
        let mut expected = b"ABCABCABCABC".to_vec();
        expected.extend_from_slice(RUN);
        expected.extend_from_slice(b"klmn AB");
        (stream, expected)
    }

    #[test]
    fn ring_executor_runs_every_ring_action_and_stops_at_end_of_stream() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsZero,
            overshoot: OvershootPolicy::Reject,
        };
        let (group, expected) = ring_group();
        let mut stream = group.clone();
        stream.extend_from_slice(&[0b0000_0001, 0]); // end-of-stream token
        let terminated = stream.len();
        stream.extend_from_slice(b"JUNK");

        let outcome = decode_flag_lzss_ring_to_end::<1024, _>(
            &stream,
            expected.len(),
            config,
            b' ',
            0x3DE,
            decode_synthetic_action,
        )
        .unwrap();
        assert_eq!(outcome.output, expected);
        assert_eq!(outcome.bytes_consumed, terminated);
        assert_eq!(outcome.remaining_flag_bits, 7);

        // Clean EOF after a complete token also terminates.
        let outcome = decode_flag_lzss_ring_to_end::<1024, _>(
            &group,
            usize::MAX,
            config,
            b' ',
            0x3DE,
            decode_synthetic_action,
        )
        .unwrap();
        assert_eq!(outcome.output, expected);
        assert_eq!(outcome.bytes_consumed, group.len());
        assert_eq!(outcome.remaining_flag_bits, 0);

        // Empty input is an empty stream.
        let empty =
            decode_flag_lzss_ring_to_end::<1024, _>(&[], 0, config, 0, 0, decode_synthetic_action)
                .unwrap();
        assert!(empty.output.is_empty());
        assert_eq!(empty.bytes_consumed, 0);

        // A flag word with no following token is truncated.
        let dangling = [group.as_slice(), &[0]].concat();
        let err = decode_flag_lzss_ring_to_end::<1024, _>(
            &dangling,
            usize::MAX,
            config,
            b' ',
            0x3DE,
            decode_synthetic_action,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn ring_executor_enforces_limits_and_parameters() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsZero,
            overshoot: OvershootPolicy::Reject,
        };
        let (group, expected) = ring_group();
        for limit in [0, 3, 7, 12, 47, expected.len() - 1] {
            let err = decode_flag_lzss_ring_to_end::<1024, _>(
                &group,
                limit,
                config,
                b' ',
                0x3DE,
                decode_synthetic_action,
            )
            .unwrap_err();
            assert!(
                matches!(err, Error::ResourceLimit { limit: l, .. } if l == limit as u64),
                "limit {limit}: {err:?}"
            );
        }

        let run = |cursor: usize| {
            decode_flag_lzss_ring_to_end::<1024, _>(
                &group,
                usize::MAX,
                config,
                b' ',
                cursor,
                decode_synthetic_action,
            )
        };
        assert!(matches!(
            run(1024),
            Err(Error::InvalidField { value: 1024, .. })
        ));
        assert!(matches!(
            decode_flag_lzss_ring_to_end::<1000, _>(
                &group,
                usize::MAX,
                config,
                b' ',
                0,
                decode_synthetic_action,
            ),
            Err(Error::InvalidField { value: 1000, .. })
        ));

        // Relative distances must be 1..=N; linear matches are not ring actions.
        for bad in [[0b0000_0001, 2, 0, 0, 1], [0b0000_0001, 2, 1, 4, 1]] {
            let err = decode_flag_lzss_ring_to_end::<1024, _>(
                &bad,
                16,
                config,
                0,
                0,
                decode_synthetic_action,
            )
            .unwrap_err();
            assert!(matches!(err, Error::Malformed(_)));
        }
        let full = decode_flag_lzss_ring_to_end::<1024, _>(
            &[0b0000_0001, 2, 0, 4, 2],
            16,
            config,
            7,
            0,
            decode_synthetic_action,
        )
        .unwrap();
        assert_eq!(full.output, [7, 7]);
        let err = decode_flag_lzss_ring_to_end::<1024, _>(
            &[0b0000_0001, 4, 1, 1],
            16,
            config,
            0,
            0,
            decode_synthetic_action,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn linear_action_executor_with_declared_and_open_sizes() {
        let config = FlagLzssConfig {
            flag_width: FlagWidth::U8,
            bit_order: FlagBitOrder::LsbFirst,
            polarity: FlagPolarity::LiteralIsOne,
            overshoot: OvershootPolicy::Reject,
        };
        // lit 'h', lit 'i', run "abc", match(5, 7) overlapping, match(14, 2) into
        // history, end of stream.
        let mut stream = vec![0b0000_0011, b'h', b'i', 3, 3, b'a', b'b', b'c'];
        stream.extend_from_slice(&[4, 5, 7, 4, 14, 2]);
        let before_end = stream.len();
        stream.push(0);
        let terminated = stream.len();
        stream.extend_from_slice(b"JUNK");
        let expected = b"hiabchiabchiXY";
        let decode = |size: Option<usize>, max: usize, cfg: FlagLzssConfig| {
            decode_flag_lzss_actions(&stream, b"XY", size, max, cfg, decode_synthetic_action)
        };

        let open = decode(None, 64, config).unwrap();
        assert_eq!(open.output, expected);
        assert_eq!(open.bytes_consumed, terminated);
        assert_eq!(open.remaining_flag_bits, 2);

        let exact = decode(Some(expected.len()), 64, config).unwrap();
        assert_eq!(exact.output, expected);
        assert_eq!(exact.bytes_consumed, before_end);
        assert_eq!(exact.remaining_flag_bits, 3);

        // End of stream before the declared size is rejected as malformed.
        assert!(matches!(
            decode(Some(20), 64, config),
            Err(Error::Malformed(_))
        ));

        // Zero declared size consumes nothing and succeeds even when the stream
        // begins with an EndOfStream token.
        let empty = decode_flag_lzss_actions(
            &[0b0000_0000, 0],
            &[],
            Some(0),
            64,
            config,
            decode_synthetic_action,
        )
        .unwrap();
        assert!(empty.output.is_empty());
        assert_eq!(empty.bytes_consumed, 0);

        // Declared-size overshoot policy applies to matches and literal runs.
        assert!(matches!(
            decode(Some(10), 64, config),
            Err(Error::Malformed(_))
        ));
        let clamp = FlagLzssConfig {
            overshoot: OvershootPolicy::ClampToDecodedSize,
            ..config
        };
        let clamped = decode(Some(10), 64, clamp).unwrap();
        assert_eq!(clamped.output, b"hiabchiabc");
        let clamped_run = decode(Some(4), 64, clamp).unwrap();
        assert_eq!(clamped_run.output, b"hiab");
        assert_eq!(clamped_run.bytes_consumed, 8);
        assert!(matches!(
            decode(Some(4), 64, config),
            Err(Error::Malformed(_))
        ));

        // Output limits: before allocating with a declared size, per token without.
        assert!(matches!(
            decode(Some(usize::MAX), 64, config),
            Err(Error::ResourceLimit { limit: 64, .. })
        ));
        for limit in [0, 1, 4, 11, 13] {
            assert!(
                matches!(
                    decode(None, limit, config),
                    Err(Error::ResourceLimit { limit: l, .. }) if l == limit as u64
                ),
                "limit {limit}"
            );
        }

        // Clean EOF after a complete token terminates an open-sized stream.
        let eof = decode_flag_lzss_actions(
            &stream[..before_end],
            b"XY",
            None,
            64,
            config,
            decode_synthetic_action,
        )
        .unwrap();
        assert_eq!(eof.output, expected);
        assert_eq!(eof.bytes_consumed, before_end);

        // Ring actions are rejected by the linear executor.
        for ring in [[0b0000_0000, 1, 0, 0, 3], [0b0000_0000, 2, 1, 0, 3]] {
            let err =
                decode_flag_lzss_actions(&ring, b"XY", None, 64, config, decode_synthetic_action)
                    .unwrap_err();
            assert!(matches!(err, Error::Malformed(_)));
        }
    }
}
