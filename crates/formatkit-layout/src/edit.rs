//! Bounded byte replacement mechanics for resident layouts.

use formatkit_core::{bytes_at, bytes_at_mut, Error, Result, SourceRange};

/// Failure while applying already-authorized same-size replacements.
#[derive(Debug, PartialEq, Eq)]
pub enum SameSizeSpliceError {
    /// A replacement range was outside the resident carrier.
    InvalidRange {
        /// Zero-based position in the supplied edit iterator.
        edit: usize,
        /// The checked resident-range failure.
        error: Error,
    },
    /// A wide source offset cannot address resident memory on this host.
    OffsetDoesNotFitHost {
        /// Zero-based position in the supplied edit iterator.
        edit: usize,
        /// The source-relative offset that cannot be represented.
        offset: u64,
    },
    /// A replacement length differed from its authorized stored extent.
    SizeMismatch {
        /// Zero-based position in the supplied edit iterator.
        edit: usize,
        /// Authorized stored length.
        expected: u64,
        /// Supplied replacement length.
        actual: u64,
    },
}

/// Clone a carrier and apply sparse, already-authorized same-size replacements.
///
/// Every size, offset, and bound is validated before the carrier is cloned or
/// any replacement is written. Edit indices, duplicate edit policy, alias
/// safety, semantic validation, and reparsing remain with the owner.
pub fn same_size_splice<'a>(
    bytes: &[u8],
    edits: impl IntoIterator<Item = (SourceRange, &'a [u8])>,
) -> std::result::Result<Vec<u8>, SameSizeSpliceError> {
    let mut validated = Vec::new();
    for (edit, (extent, replacement)) in edits.into_iter().enumerate() {
        let actual = replacement.len() as u64;
        if actual != extent.length {
            return Err(SameSizeSpliceError::SizeMismatch {
                edit,
                expected: extent.length,
                actual,
            });
        }
        let start = usize::try_from(extent.start).map_err(|_| {
            SameSizeSpliceError::OffsetDoesNotFitHost {
                edit,
                offset: extent.start,
            }
        })?;
        bytes_at(bytes, start, replacement.len())
            .map_err(|error| SameSizeSpliceError::InvalidRange { edit, error })?;
        validated.push((start, replacement));
    }

    let mut output = bytes.to_vec();
    for (start, replacement) in validated {
        output[start..start + replacement.len()].copy_from_slice(replacement);
    }
    Ok(output)
}

/// Apply one already-authorized replacement without resizing the carrier.
///
/// The complete destination range is checked before any byte is written, so a
/// failure leaves `bytes` unchanged. The caller retains edit authorization,
/// semantic validation, and any requirement that a logical field keep its
/// original size.
pub fn patch_bytes(bytes: &mut [u8], offset: usize, replacement: &[u8]) -> Result<()> {
    bytes_at_mut(bytes, offset, replacement.len())?.copy_from_slice(replacement);
    Ok(())
}

/// Clone a carrier and apply one already-authorized bounded replacement.
///
/// Bounds are checked before allocation. This function does not reparse or
/// validate the resulting format.
pub fn patched_bytes(bytes: &[u8], offset: usize, replacement: &[u8]) -> Result<Vec<u8>> {
    let destination = bytes_at(bytes, offset, replacement.len())?;
    let end = offset + destination.len();
    let mut output = bytes.to_vec();
    output[offset..end].copy_from_slice(replacement);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacements_are_confined_and_fail_atomically_for_every_small_range() {
        let source = [0x10, 0x20, 0x30, 0x40];
        for offset in 0usize..=source.len() + 1 {
            for replacement_len in 0usize..=source.len() + 1 {
                let replacement = vec![0xa5; replacement_len];
                let mut in_place = source;
                let cloned = patched_bytes(&source, offset, &replacement);
                let result = patch_bytes(&mut in_place, offset, &replacement);
                if offset
                    .checked_add(replacement_len)
                    .is_some_and(|end| end <= source.len())
                {
                    result.unwrap();
                    let cloned = cloned.unwrap();
                    assert_eq!(in_place, cloned.as_slice());
                    assert_eq!(&in_place[..offset], &source[..offset]);
                    assert_eq!(&in_place[offset..offset + replacement_len], replacement);
                    assert_eq!(
                        &in_place[offset + replacement_len..],
                        &source[offset + replacement_len..]
                    );
                } else {
                    let expected = Error::Truncated {
                        offset,
                        needed: replacement_len,
                        available: source.len().saturating_sub(offset),
                    };
                    assert_eq!(result.unwrap_err(), expected);
                    assert_eq!(cloned.unwrap_err(), expected);
                    assert_eq!(in_place, source);
                }
            }
        }
        assert_eq!(source, [0x10, 0x20, 0x30, 0x40]);
    }

    #[test]
    fn overflowing_ranges_are_rejected_before_clone_or_mutation() {
        let source = [1, 2, 3, 4];
        for (offset, replacement) in [(usize::MAX, &[9][..]), (usize::MAX - 1, &[9, 8][..])] {
            let mut in_place = source;
            let expected = Error::Truncated {
                offset,
                needed: replacement.len(),
                available: 0,
            };
            let result = patch_bytes(&mut in_place, offset, replacement);
            assert_eq!(result.as_ref().unwrap_err(), &expected);
            assert_eq!(patched_bytes(&source, offset, replacement), Err(expected));
            assert_eq!(in_place, source);
        }
    }

    #[test]
    fn sparse_splice_preserves_gaps_and_input_order() {
        let source = [0, 1, 2, 3, 4, 5, 6, 7];
        let output = same_size_splice(
            &source,
            [
                (SourceRange::new(6, 1), &[9][..]),
                (SourceRange::new(2, 2), &[8, 7][..]),
            ],
        )
        .unwrap();
        assert_eq!(output, [0, 1, 8, 7, 4, 5, 9, 7]);
        assert_eq!(source, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn sparse_splice_keeps_size_offset_and_bounds_failures_distinct() {
        let source = [0, 1, 2, 3];
        assert_eq!(
            same_size_splice(&source, [(SourceRange::new(u64::MAX, 2), &[9][..])]),
            Err(SameSizeSpliceError::SizeMismatch {
                edit: 0,
                expected: 2,
                actual: 1,
            })
        );
        if usize::BITS < u64::BITS {
            let offset = usize::MAX as u64 + 1;
            assert_eq!(
                same_size_splice(&source, [(SourceRange::new(offset, 1), &[9][..])]),
                Err(SameSizeSpliceError::OffsetDoesNotFitHost { edit: 0, offset })
            );
        }
        assert_eq!(
            same_size_splice(&source, [(SourceRange::new(4, 1), &[9][..])]),
            Err(SameSizeSpliceError::InvalidRange {
                edit: 0,
                error: Error::Truncated {
                    offset: 4,
                    needed: 1,
                    available: 0,
                },
            })
        );
    }

    #[test]
    fn table_ranges_feed_same_size_splice_without_an_extent_adapter() {
        let mut source = [0u8; 16];
        source[..4].copy_from_slice(&8u32.to_le_bytes());
        source[4..8].copy_from_slice(&12u32.to_le_bytes());
        let ranges = crate::FirstWordOffsetTable::new(8)
            .ranges(&source[..8], source.len() as u64)
            .unwrap();

        let output = same_size_splice(&source, [(ranges[1], &[1, 2, 3, 4][..])]).unwrap();
        assert_eq!(&output[..12], &source[..12]);
        assert_eq!(&output[12..], &[1, 2, 3, 4]);
    }
}
