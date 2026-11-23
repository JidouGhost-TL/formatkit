//! Unit-sized high-bit-flag packet run-length encoding (RLE).
//!
//! Each packet begins with a 1-byte header `flag`:
//! - When `flag & 0x80 != 0` (run packet), the next single unit of
//!   `unit_bytes` bytes is repeated `(flag & 0x7F) + min_run_len` times.
//! - When `flag & 0x80 == 0` (literal packet), `(flag & 0x7F) + min_literal_len`
//!   verbatim units follow.
//!
//! This single parameterization covers both byte-oriented packet RLE
//! (`unit_bytes = 1, min_run_len = 3, min_literal_len = 1`) and TGA-style
//! pixel-unit RLE (`unit_bytes = 1..=4, min_run_len = 1, min_literal_len = 1`).

use formatkit_core::{Error, Result};

use crate::DecodeOutcome;

/// Configuration for a high-bit-flag packet RLE stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HighBitRleConfig {
    /// Byte width of one atomic unit (for example `1` for bytes or `1..=4` for pixels).
    pub unit_bytes: usize,
    /// Minimum repeat count encoded by a run packet (`flag & 0x80 != 0`).
    pub min_run_len: usize,
    /// Minimum unit count encoded by a literal packet (`flag & 0x80 == 0`).
    pub min_literal_len: usize,
}

impl HighBitRleConfig {
    /// Byte-oriented packet RLE with runs of `3..=130` and literals of `1..=128`.
    pub const BYTE_RUN3: Self = Self {
        unit_bytes: 1,
        min_run_len: 3,
        min_literal_len: 1,
    };

    /// Pixel-unit packet RLE with runs and literals of `1..=128` units.
    #[must_use]
    pub const fn pixel_units(unit_bytes: usize) -> Self {
        Self {
            unit_bytes,
            min_run_len: 1,
            min_literal_len: 1,
        }
    }

    fn validate(self) -> Result<()> {
        if self.unit_bytes == 0 {
            return Err(Error::InvalidField {
                what: "RLE unit_bytes",
                value: 0,
            });
        }
        if self.min_run_len == 0 {
            return Err(Error::InvalidField {
                what: "RLE min_run_len",
                value: 0,
            });
        }
        if self.min_literal_len == 0 {
            return Err(Error::InvalidField {
                what: "RLE min_literal_len",
                value: 0,
            });
        }
        Ok(())
    }
}

/// Decode a high-bit-flag packet RLE stream into exactly `expected_units` units.
///
/// Returns the decoded byte buffer (`expected_units * config.unit_bytes` bytes)
/// and the exact number of source bytes consumed. Overruns and truncated packets
/// are rejected without over-allocating.
pub fn decode_high_bit_rle(
    src: &[u8],
    expected_units: usize,
    config: HighBitRleConfig,
) -> Result<DecodeOutcome> {
    config.validate()?;
    let expected_bytes = expected_units
        .checked_mul(config.unit_bytes)
        .ok_or_else(|| Error::Malformed("RLE expected byte length overflow".into()))?;
    let mut out = Vec::with_capacity(expected_bytes.min(64 * 1024));
    let mut cursor = 0usize;
    let mut units_written = 0usize;

    while units_written < expected_units {
        let flag = *src.get(cursor).ok_or(Error::Truncated {
            offset: cursor,
            needed: 1,
            available: src.len().saturating_sub(cursor),
        })?;
        cursor += 1;

        if flag & 0x80 != 0 {
            let count = usize::from(flag & 0x7F)
                .checked_add(config.min_run_len)
                .ok_or_else(|| Error::Malformed("RLE run length overflow".into()))?;
            let next_units = units_written
                .checked_add(count)
                .filter(|&total| total <= expected_units)
                .ok_or_else(|| {
                    Error::Malformed("RLE run packet overruns expected output".into())
                })?;
            let end = cursor
                .checked_add(config.unit_bytes)
                .ok_or_else(|| Error::Malformed("RLE run packet offset overflow".into()))?;
            let unit = src.get(cursor..end).ok_or(Error::Truncated {
                offset: cursor,
                needed: config.unit_bytes,
                available: src.len().saturating_sub(cursor),
            })?;
            cursor = end;
            for _ in 0..count {
                out.extend_from_slice(unit);
            }
            units_written = next_units;
        } else {
            let count = usize::from(flag & 0x7F)
                .checked_add(config.min_literal_len)
                .ok_or_else(|| Error::Malformed("RLE literal length overflow".into()))?;
            let next_units = units_written
                .checked_add(count)
                .filter(|&total| total <= expected_units)
                .ok_or_else(|| {
                    Error::Malformed("RLE literal packet overruns expected output".into())
                })?;
            let byte_len = count
                .checked_mul(config.unit_bytes)
                .ok_or_else(|| Error::Malformed("RLE literal byte length overflow".into()))?;
            let end = cursor
                .checked_add(byte_len)
                .ok_or_else(|| Error::Malformed("RLE literal packet offset overflow".into()))?;
            let raw = src.get(cursor..end).ok_or(Error::Truncated {
                offset: cursor,
                needed: byte_len,
                available: src.len().saturating_sub(cursor),
            })?;
            cursor = end;
            out.extend_from_slice(raw);
            units_written = next_units;
        }
    }

    Ok(DecodeOutcome {
        bytes: out,
        consumed: cursor,
    })
}

/// Encode `src` (whose length must be a multiple of `config.unit_bytes`) using
/// high-bit-flag packet RLE.
pub fn encode_high_bit_rle(src: &[u8], config: HighBitRleConfig) -> Result<Vec<u8>> {
    config.validate()?;
    if !src.len().is_multiple_of(config.unit_bytes) {
        return Err(Error::InvalidField {
            what: "RLE input byte length",
            value: src.len() as u64,
        });
    }
    if src.is_empty() {
        return Ok(Vec::new());
    }

    let unit_bytes = config.unit_bytes;
    let total_units = src.len() / unit_bytes;
    let max_run = config.min_run_len.saturating_add(127);
    let max_lit = config.min_literal_len.saturating_add(127);
    let run_threshold = config.min_run_len.max(2);

    let unit_at = |idx: usize| &src[idx * unit_bytes..(idx + 1) * unit_bytes];

    let mut out = Vec::new();
    let mut i = 0usize;
    let mut lit_start = 0usize;

    let flush_literals = |out: &mut Vec<u8>, start: usize, end: usize| -> Result<()> {
        let mut pos = start;
        while pos < end {
            let chunk = (end - pos).min(max_lit);
            if chunk < config.min_literal_len {
                return Err(Error::Unsupported(
                    "RLE literal run shorter than min_literal_len".into(),
                ));
            }
            out.push((chunk - config.min_literal_len) as u8);
            out.extend_from_slice(&src[pos * unit_bytes..(pos + chunk) * unit_bytes]);
            pos += chunk;
        }
        Ok(())
    };

    while i < total_units {
        let cur = unit_at(i);
        let mut run = 1usize;
        while i + run < total_units && run < max_run && unit_at(i + run) == cur {
            run += 1;
        }
        if run >= run_threshold {
            if lit_start < i {
                flush_literals(&mut out, lit_start, i)?;
            }
            out.push(0x80 | ((run - config.min_run_len) as u8));
            out.extend_from_slice(cur);
            i += run;
            lit_start = i;
        } else {
            i += 1;
            if i - lit_start == max_lit {
                flush_literals(&mut out, lit_start, i)?;
                lit_start = i;
            }
        }
    }

    if lit_start < total_units {
        flush_literals(&mut out, lit_start, total_units)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_run3_round_trips_mixed_runs_and_literals() {
        let mut data = Vec::new();
        data.extend_from_slice(b"AB");
        data.extend(std::iter::repeat_n(b'X', 150));
        data.extend_from_slice(b"CD");
        data.extend(std::iter::repeat_n(b'Y', 3));
        data.extend_from_slice(&(0u8..200).collect::<Vec<_>>());

        let encoded = encode_high_bit_rle(&data, HighBitRleConfig::BYTE_RUN3).unwrap();
        assert!(encoded.len() < data.len());
        let decoded =
            decode_high_bit_rle(&encoded, data.len(), HighBitRleConfig::BYTE_RUN3).unwrap();
        assert_eq!(decoded.bytes, data);
        assert_eq!(decoded.consumed, encoded.len());
    }

    #[test]
    fn pixel_unit_rle_round_trips_1_to_4_bytes_and_preserves_consumed() {
        for unit_bytes in 1..=4usize {
            let cfg = HighBitRleConfig::pixel_units(unit_bytes);
            let mut data = Vec::new();
            let a = vec![0x11u8; unit_bytes];
            let b = vec![0x22u8; unit_bytes];
            let c: Vec<u8> = (0..unit_bytes as u8).map(|i| 0xA0 + i).collect();
            for _ in 0..5 {
                data.extend_from_slice(&a);
            }
            data.extend_from_slice(&b);
            for _ in 0..130 {
                data.extend_from_slice(&c);
            }
            let units = data.len() / unit_bytes;
            let mut encoded = encode_high_bit_rle(&data, cfg).unwrap();
            let exact_len = encoded.len();
            encoded.extend_from_slice(&[0xDE, 0xAD]);

            let decoded = decode_high_bit_rle(&encoded, units, cfg).unwrap();
            assert_eq!(decoded.bytes, data);
            assert_eq!(decoded.consumed, exact_len);
        }
    }

    #[test]
    fn rejects_invalid_config_truncation_and_overrun() {
        let bad = HighBitRleConfig {
            unit_bytes: 0,
            min_run_len: 1,
            min_literal_len: 1,
        };
        assert!(decode_high_bit_rle(&[], 0, bad).is_err());
        assert!(encode_high_bit_rle(&[], bad).is_err());

        let cfg = HighBitRleConfig::pixel_units(4);
        assert!(encode_high_bit_rle(&[0, 1, 2], cfg).is_err());
        // Run of 2 pixels (flag 0x81) into expected_units = 1 -> overrun.
        assert!(decode_high_bit_rle(&[0x81, 1, 2, 3, 4], 1, cfg).is_err());
        // Truncated run pixel.
        assert!(matches!(
            decode_high_bit_rle(&[0x80, 1, 2], 1, cfg),
            Err(Error::Truncated { .. })
        ));
        // Truncated literal payload.
        assert!(matches!(
            decode_high_bit_rle(&[0x01, 1, 2, 3, 4], 2, cfg),
            Err(Error::Truncated { .. })
        ));
    }
}
