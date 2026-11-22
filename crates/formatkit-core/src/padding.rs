//! Platform-neutral classification of uniform padding regions.
//!
//! Identifies contiguous byte sequences consisting entirely of zeros, a single
//! repeated byte, or a repeated 32-bit little-endian word, both for in-memory
//! slices and bounded streaming [`RangeSource`] scans.

#![forbid(unsafe_code)]

use crate::{RangeSource, Result, WorkBudget};

/// Bounded streaming chunk size (64 KiB, aligned to 4 bytes).
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Classification of a uniform padding region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaddingKind {
    /// Every byte in the region is `0x00`.
    AllZero,
    /// Every byte in the region equals the same non-zero byte value.
    RepeatedByte(u8),
    /// Every 4-byte little-endian word in the region equals the same 32-bit value
    /// (requires at least 8 bytes, length divisible by 4, and not all identical bytes).
    RepeatedWord32(u32),
}

/// Summary of a classified uniform padding region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaddingSummary {
    /// Detected padding pattern.
    pub kind: PaddingKind,
    /// Total length of the classified region in bytes.
    pub byte_len: u64,
}

impl PaddingSummary {
    /// Returns `true` when `alignment` is non-zero and `self.byte_len` is an
    /// exact multiple of `alignment`.
    #[must_use]
    pub const fn is_aligned_to(&self, alignment: u64) -> bool {
        alignment != 0 && self.byte_len.is_multiple_of(alignment)
    }
}

/// Trailing uniform padding region located at the end of a byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrailingPadding {
    /// Byte offset where the trailing padding region begins.
    pub start_offset: usize,
    /// Classification and byte length of the trailing padding region.
    pub summary: PaddingSummary,
}

/// Detect the longest trailing uniform single-byte padding run at the end of `bytes`.
///
/// Scans backward from the end of `bytes` to find the longest contiguous run of
/// identical bytes (`0x00` yields [`PaddingKind::AllZero`], any other byte `b`
/// yields [`PaddingKind::RepeatedByte`]).
///
/// Returns `None` if `min_bytes == 0`, `bytes` is empty, or the trailing run is
/// shorter than `min_bytes`.
#[must_use]
pub fn detect_trailing_padding(bytes: &[u8], min_bytes: usize) -> Option<TrailingPadding> {
    if min_bytes == 0 || bytes.len() < min_bytes {
        return None;
    }
    let fill = *bytes.last()?;
    let run_len = bytes.iter().rev().take_while(|&&b| b == fill).count();
    if run_len < min_bytes {
        return None;
    }
    let kind = if fill == 0 {
        PaddingKind::AllZero
    } else {
        PaddingKind::RepeatedByte(fill)
    };
    Some(TrailingPadding {
        start_offset: bytes.len() - run_len,
        summary: PaddingSummary {
            kind,
            byte_len: run_len as u64,
        },
    })
}

/// Classify `bytes` as a uniform padding region if its length is at least
/// `min_bytes` (and non-empty).
///
/// Precedence is canonical:
/// 1. [`PaddingKind::AllZero`] when every byte is `0x00`.
/// 2. [`PaddingKind::RepeatedByte`] when every byte equals the same non-zero byte.
/// 3. [`PaddingKind::RepeatedWord32`] when `bytes.len() >= 8`, `bytes.len() % 4 == 0`,
///    and every 4-byte little-endian word matches the first 4 bytes.
///
/// Returns `None` if `bytes` is empty, shorter than `min_bytes`, or does not
/// match any uniform pattern.
#[must_use]
pub fn classify_padding(bytes: &[u8], min_bytes: usize) -> Option<PaddingSummary> {
    if bytes.is_empty() || bytes.len() < min_bytes {
        return None;
    }

    let first_byte = bytes[0];
    if bytes.iter().all(|&b| b == first_byte) {
        let kind = if first_byte == 0 {
            PaddingKind::AllZero
        } else {
            PaddingKind::RepeatedByte(first_byte)
        };
        return Some(PaddingSummary {
            kind,
            byte_len: bytes.len() as u64,
        });
    }

    if bytes.len() >= 8 && bytes.len().is_multiple_of(4) {
        let first_word = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if bytes.as_chunks::<4>().0.iter().all(|w| *w == first_word) {
            return Some(PaddingSummary {
                kind: PaddingKind::RepeatedWord32(u32::from_le_bytes(first_word)),
                byte_len: bytes.len() as u64,
            });
        }
    }

    None
}

/// Classify an entire [`RangeSource`] as a uniform padding region by streaming
/// in bounded 64 KiB chunks under `work`.
///
/// Checks cooperative cancellation on every chunk, revalidates source stability
/// via [`RangeSource::verify_unchanged`] before and after reading (and on read
/// errors), and short-circuits immediately on the first mismatching chunk.
///
/// Returns `Ok(None)` when the source is empty, shorter than `min_bytes`, or
/// contains non-uniform data.
pub fn classify_padding_source(
    source: &dyn RangeSource,
    min_bytes: u64,
    work: &mut WorkBudget,
) -> Result<Option<PaddingSummary>> {
    work.check_cancelled()?;
    let total_len = source.size();
    if total_len == 0 || total_len < min_bytes {
        return Ok(None);
    }

    source.verify_unchanged()?;

    let buf_len = total_len.min(STREAM_CHUNK_BYTES as u64) as usize;
    let mut buf = vec![0u8; buf_len];

    let mut offset = 0u64;
    let mut first_byte = 0u8;
    let mut first_word = [0u8; 4];
    let mut all_same_byte = true;
    let mut all_same_word = total_len >= 8 && total_len.is_multiple_of(4);

    while offset < total_len {
        work.check_cancelled()?;
        let chunk_len = (total_len - offset).min(buf_len as u64) as usize;
        let slice = &mut buf[..chunk_len];
        if let Err(err) = source.read_exact_into_assuming_unchanged(offset, slice, work) {
            source.verify_unchanged()?;
            return Err(err);
        }

        if offset == 0 {
            first_byte = slice[0];
            if all_same_word {
                // Guaranteed chunk_len >= 8 because total_len >= 8 and STREAM_CHUNK_BYTES >= 8.
                first_word = [slice[0], slice[1], slice[2], slice[3]];
            }
        }

        if all_same_byte && !slice.iter().all(|&b| b == first_byte) {
            all_same_byte = false;
        }

        if !all_same_byte
            && all_same_word
            && !slice.as_chunks::<4>().0.iter().all(|w| *w == first_word)
        {
            all_same_word = false;
        }

        if !all_same_byte && !all_same_word {
            work.check_cancelled()?;
            source.verify_unchanged()?;
            return Ok(None);
        }

        offset += chunk_len as u64;
    }

    work.check_cancelled()?;
    source.verify_unchanged()?;

    let kind = if all_same_byte {
        if first_byte == 0 {
            PaddingKind::AllZero
        } else {
            PaddingKind::RepeatedByte(first_byte)
        }
    } else if all_same_word {
        PaddingKind::RepeatedWord32(u32::from_le_bytes(first_word))
    } else {
        return Ok(None);
    };

    Ok(Some(PaddingSummary {
        kind,
        byte_len: total_len,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CancellationToken, Error, InjectedError, MemoryRangeSource, RangeSourceTestDouble,
        WorkLimits, WorkResource,
    };

    #[test]
    fn classifies_all_zero_and_alignment() {
        let data = vec![0u8; 2048];
        let summary = classify_padding(&data, 16).expect("all-zero padding");
        assert_eq!(
            summary,
            PaddingSummary {
                kind: PaddingKind::AllZero,
                byte_len: 2048,
            }
        );
        assert!(summary.is_aligned_to(2048));
        assert!(summary.is_aligned_to(512));
        assert!(!summary.is_aligned_to(4096));
        assert!(!summary.is_aligned_to(0));
    }

    #[test]
    fn classifies_repeated_byte_over_word32() {
        let data = vec![0xFFu8; 32];
        let summary = classify_padding(&data, 16).expect("repeated byte");
        assert_eq!(summary.kind, PaddingKind::RepeatedByte(0xFF));
        assert_eq!(summary.byte_len, 32);
    }

    #[test]
    fn classifies_repeated_word32() {
        let word = 0xDEAD_BEEFu32;
        let mut data = Vec::with_capacity(64);
        for _ in 0..16 {
            data.extend_from_slice(&word.to_le_bytes());
        }
        let summary = classify_padding(&data, 8).expect("repeated word32");
        assert_eq!(
            summary,
            PaddingSummary {
                kind: PaddingKind::RepeatedWord32(word),
                byte_len: 64,
            }
        );
    }

    #[test]
    fn rejects_empty_short_unaligned_and_single_word() {
        assert_eq!(classify_padding(&[], 0), None);
        assert_eq!(classify_padding(&[0u8; 7], 8), None);
        // Single 4-byte non-uniform word is not a repeated word.
        assert_eq!(classify_padding(&[1, 2, 3, 4], 4), None);
        // Non-multiple-of-4 length cannot be RepeatedWord32.
        assert_eq!(classify_padding(&[1, 2, 3, 4, 1, 2, 3, 4, 1], 4), None);
        // Mixed content returns None.
        let mut mixed = vec![0u8; 32];
        mixed[31] = 1;
        assert_eq!(classify_padding(&mixed, 8), None);
    }

    #[test]
    fn streaming_matches_slice_across_multiple_chunks() {
        let word = 0x1122_3344u32;
        let count = (STREAM_CHUNK_BYTES / 4) * 2 + 5;
        let mut data = Vec::with_capacity(count * 4);
        for _ in 0..count {
            data.extend_from_slice(&word.to_le_bytes());
        }
        let source = MemoryRangeSource::new(data.clone(), "multi-chunk-word");
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let streamed = classify_padding_source(&source, 16, &mut work)
            .unwrap()
            .expect("word padding");
        assert_eq!(streamed, classify_padding(&data, 16).unwrap());
        assert_eq!(
            work.usage().spent(WorkResource::LogicalReadBytes),
            data.len() as u64
        );
    }

    #[test]
    fn streaming_short_circuits_on_first_mismatch_chunk() {
        let mut data = vec![0xAAu8; STREAM_CHUNK_BYTES * 4];
        data[17] = 0xBB;
        let source = MemoryRangeSource::new(data, "early-mismatch");
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let result = classify_padding_source(&source, 16, &mut work).unwrap();
        assert_eq!(result, None);
        // Only the first 64 KiB chunk should have been read.
        assert_eq!(
            work.usage().spent(WorkResource::LogicalReadBytes),
            STREAM_CHUNK_BYTES as u64
        );
    }

    #[test]
    fn streaming_respects_cancellation_and_budget_and_short_source() {
        let source = MemoryRangeSource::new(vec![0u8; 1024], "short");
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        assert_eq!(
            classify_padding_source(&source, 2048, &mut work).unwrap(),
            None
        );
        assert_eq!(work.usage().spent(WorkResource::LogicalReadBytes), 0);

        let token = CancellationToken::new();
        token.cancel();
        let mut cancelled_work = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert_eq!(
            classify_padding_source(&source, 16, &mut cancelled_work),
            Err(Error::Cancelled)
        );

        let mut tight =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 64));
        let err = classify_padding_source(&source, 16, &mut tight).unwrap_err();
        assert!(matches!(err, Error::ResourceLimit { .. }));
    }

    #[test]
    fn streaming_detects_changed_source_identity() {
        let double_before = RangeSourceTestDouble::resident(vec![0u8; 1024], "mutable-before")
            .with_verification_fault(0, InjectedError::Malformed("changed before read"));
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let err = classify_padding_source(&double_before, 16, &mut work).unwrap_err();
        assert_eq!(err, Error::Malformed("changed before read".into()));
        assert_eq!(double_before.read_calls(), 0);

        let double_after = RangeSourceTestDouble::resident(vec![0u8; 1024], "mutable-after")
            .with_verification_fault(1, InjectedError::Malformed("changed after read"));
        let mut work2 = WorkBudget::new(WorkLimits::unlimited());
        let err2 = classify_padding_source(&double_after, 16, &mut work2).unwrap_err();
        assert_eq!(err2, Error::Malformed("changed after read".into()));
        assert_eq!(double_after.verification_calls(), 2);
    }

    #[test]
    fn detects_trailing_zero_and_repeated_byte_padding() {
        let mut with_zeros = vec![0x11, 0x22, 0x33];
        with_zeros.extend_from_slice(&[0x00; 16]);
        assert_eq!(
            detect_trailing_padding(&with_zeros, 8),
            Some(TrailingPadding {
                start_offset: 3,
                summary: PaddingSummary {
                    kind: PaddingKind::AllZero,
                    byte_len: 16,
                },
            })
        );

        let mut with_ff = vec![0x00, 0x00, 0xAA];
        with_ff.extend_from_slice(&[0xFF; 5]);
        assert_eq!(
            detect_trailing_padding(&with_ff, 5),
            Some(TrailingPadding {
                start_offset: 3,
                summary: PaddingSummary {
                    kind: PaddingKind::RepeatedByte(0xFF),
                    byte_len: 5,
                },
            })
        );

        // Entire slice uniform gives start_offset 0.
        assert_eq!(
            detect_trailing_padding(&[0xEE; 4], 4),
            Some(TrailingPadding {
                start_offset: 0,
                summary: PaddingSummary {
                    kind: PaddingKind::RepeatedByte(0xEE),
                    byte_len: 4,
                },
            })
        );

        // Short runs, empty slices, and min_bytes == 0 return None.
        assert_eq!(detect_trailing_padding(&with_ff, 6), None);
        assert_eq!(detect_trailing_padding(&[], 1), None);
        assert_eq!(detect_trailing_padding(&[0x00; 8], 0), None);
    }
}
