//! Checked arithmetic for relationships among layout ranges.

use std::ops::Range;

use formatkit_core::SourceRange;

/// Round a wide extent up to a power-of-two boundary.
///
/// Returns `None` when `alignment` is zero or is not a power of two, or when
/// rounding would overflow `u64`. Interpretation of the alignment and the
/// diagnostic exposed to users remain with the format owner.
#[must_use]
#[inline]
pub fn checked_align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    if !alignment.is_power_of_two() {
        return None;
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
}

/// Why a contiguous child range could not be represented or bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildRunError {
    /// `first + count` overflowed `usize`.
    Overflow,
    /// The exclusive end was greater than the supplied item count.
    OutOfBounds,
}

/// Why ordered member starts could not be converted into successor ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessorRangesError {
    /// A start is at or beyond the exclusive terminal boundary.
    OutsideTerminal {
        /// Index of the invalid start.
        index: usize,
        /// Invalid start value.
        start: u64,
        /// Exclusive terminal boundary supplied by the owner.
        terminal: u64,
    },
    /// A start is not strictly greater than the preceding start.
    NonIncreasing {
        /// Index of the latter start.
        index: usize,
        /// Preceding start value.
        previous: u64,
        /// Latter start value.
        start: u64,
    },
}

/// Why nondecreasing starts could not be converted into successor ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NondecreasingSuccessorRangesError {
    /// A start lies beyond the exclusive terminal boundary. A start exactly at
    /// the terminal is accepted and produces an empty range.
    OutsideTerminal {
        /// Index of the invalid start.
        index: usize,
        /// Invalid start value.
        start: u64,
        /// Exclusive terminal boundary supplied by the owner.
        terminal: u64,
    },
    /// A start is less than the preceding start.
    Decreasing {
        /// Index of the latter start.
        index: usize,
        /// Preceding start value.
        previous: u64,
        /// Latter start value.
        start: u64,
    },
}

/// Why a caller-ordered extent view failed a policy-neutral relationship
/// audit. Indices are the original owner indices supplied with the extents,
/// not positions in the physical-order view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderedExtentError {
    /// Computing the half-open end overflowed `u64`.
    EndOverflow {
        /// Original index of the invalid extent.
        index: usize,
        /// Extent start.
        start: u64,
        /// Extent length.
        length: u64,
    },
    /// An extent begins before the preceding extent ends.
    Overlap {
        /// Original index of the preceding extent.
        previous_index: usize,
        /// Checked exclusive end of the preceding extent.
        previous_end: u64,
        /// Original index of the overlapping extent.
        index: usize,
        /// Start of the overlapping extent.
        start: u64,
    },
    /// A contiguous run did not begin or continue at its required position.
    Discontiguous {
        /// Original index of the extent that broke the run.
        index: usize,
        /// Required start for this extent.
        expected: u64,
        /// Actual start for this extent.
        start: u64,
    },
    /// An exact tiling ended at a different terminal boundary.
    TerminalMismatch {
        /// Required exclusive terminal boundary.
        expected: u64,
        /// Actual checked end of the run.
        actual: u64,
    },
}

/// Audit caller-ordered extents for checked ends and pairwise non-overlap.
///
/// The caller chooses and, when necessary, constructs physical order. Empty
/// extents and gaps are accepted. The result is the final checked end, or
/// `None` for an empty view.
pub fn audit_ordered_non_overlapping<I>(extents: I) -> Result<Option<u64>, OrderedExtentError>
where
    I: IntoIterator<Item = (usize, SourceRange)>,
{
    let mut previous = None;
    for (index, extent) in extents {
        let end =
            extent
                .start
                .checked_add(extent.length)
                .ok_or(OrderedExtentError::EndOverflow {
                    index,
                    start: extent.start,
                    length: extent.length,
                })?;
        if let Some((previous_index, previous_end)) = previous {
            if extent.start < previous_end {
                return Err(OrderedExtentError::Overlap {
                    previous_index,
                    previous_end,
                    index,
                    start: extent.start,
                });
            }
        }
        previous = Some((index, end));
    }
    Ok(previous.map(|(_, end)| end))
}

/// Audit a caller-ordered, gapless extent run beginning at `origin` and return
/// its checked exclusive end. An empty run ends at its origin.
pub fn audit_ordered_contiguous_run<I>(extents: I, origin: u64) -> Result<u64, OrderedExtentError>
where
    I: IntoIterator<Item = (usize, SourceRange)>,
{
    let mut cursor = origin;
    for (index, extent) in extents {
        let end =
            extent
                .start
                .checked_add(extent.length)
                .ok_or(OrderedExtentError::EndOverflow {
                    index,
                    start: extent.start,
                    length: extent.length,
                })?;
        if extent.start != cursor {
            return Err(OrderedExtentError::Discontiguous {
                index,
                expected: cursor,
                start: extent.start,
            });
        }
        cursor = end;
    }
    Ok(cursor)
}

/// Audit an exact caller-ordered tiling of `[origin, terminal)`.
pub fn audit_exact_tiling<I>(
    extents: I,
    origin: u64,
    terminal: u64,
) -> Result<(), OrderedExtentError>
where
    I: IntoIterator<Item = (usize, SourceRange)>,
{
    let actual = audit_ordered_contiguous_run(extents, origin)?;
    if actual != terminal {
        return Err(OrderedExtentError::TerminalMismatch {
            expected: terminal,
            actual,
        });
    }
    Ok(())
}

/// Validate strict starts and derive ranges ending at the successor or terminal.
///
/// This mechanic deliberately accepts an empty start list. Owners retain the
/// minimum member count, the source of each start, alignment, first-start,
/// terminal, and diagnostic policies.
pub fn strict_successor_ranges(
    starts: &[u64],
    terminal: u64,
) -> Result<Vec<SourceRange>, SuccessorRangesError> {
    for (index, &start) in starts.iter().enumerate() {
        if start >= terminal {
            return Err(SuccessorRangesError::OutsideTerminal {
                index,
                start,
                terminal,
            });
        }
        if index > 0 && start <= starts[index - 1] {
            return Err(SuccessorRangesError::NonIncreasing {
                index,
                previous: starts[index - 1],
                start,
            });
        }
    }
    Ok(starts
        .iter()
        .enumerate()
        .map(|(index, &start)| {
            let end = starts.get(index + 1).copied().unwrap_or(terminal);
            SourceRange::new(start, end - start)
        })
        .collect())
}

/// Validate nondecreasing starts and derive ranges ending at the successor or
/// terminal.
///
/// Equal starts are retained: the earlier start owns an empty range and the
/// later start owns the following positive range, if any. Starts equal to the
/// terminal produce empty ranges. Whether those shapes are legal members or a
/// terminal is a separate owner policy.
pub fn nondecreasing_successor_ranges(
    starts: &[u64],
    terminal: u64,
) -> Result<Vec<SourceRange>, NondecreasingSuccessorRangesError> {
    for (index, &start) in starts.iter().enumerate() {
        if start > terminal {
            return Err(NondecreasingSuccessorRangesError::OutsideTerminal {
                index,
                start,
                terminal,
            });
        }
        if index > 0 && start < starts[index - 1] {
            return Err(NondecreasingSuccessorRangesError::Decreasing {
                index,
                previous: starts[index - 1],
                start,
            });
        }
    }
    Ok(starts
        .iter()
        .enumerate()
        .map(|(index, &start)| {
            let end = starts.get(index + 1).copied().unwrap_or(terminal);
            SourceRange::new(start, end - start)
        })
        .collect())
}

/// Resolve a contiguous child range without assigning tree or sentinel policy.
///
/// An empty range at `total` is valid. Callers retain count conversion, graph
/// validation, traversal, and owner-specific diagnostics.
pub fn child_run(first: usize, count: usize, total: usize) -> Result<Range<usize>, ChildRunError> {
    let end = first.checked_add(count).ok_or(ChildRunError::Overflow)?;
    if end > total {
        return Err(ChildRunError::OutOfBounds);
    }
    Ok(first..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_alignment_matches_sector_formulas_and_rejects_invalid_inputs() {
        const SECTOR: u64 = 2_048;
        let largest = !(SECTOR - 1);
        for value in [
            0,
            1,
            SECTOR - 1,
            SECTOR,
            SECTOR + 1,
            u32::MAX as u64 + 1,
            largest,
        ] {
            let add = value.checked_add(SECTOR - 1).unwrap();
            let masked = add & !(SECTOR - 1);
            let divided = add / SECTOR * SECTOR;
            assert_eq!(masked, divided);
            assert_eq!(checked_align_up_u64(value, SECTOR), Some(masked));
        }
        for value in largest + 1..=u64::MAX {
            assert_eq!(checked_align_up_u64(value, SECTOR), None);
        }
        assert_eq!(checked_align_up_u64(u64::MAX, 1), Some(u64::MAX));
        assert_eq!(checked_align_up_u64(1, 0), None);
        assert_eq!(checked_align_up_u64(1, 3), None);
    }

    #[test]
    fn child_runs_distinguish_overflow_from_bounds() {
        assert_eq!(child_run(2, 3, 5), Ok(2..5));
        assert_eq!(child_run(5, 0, 5), Ok(5..5));
        assert_eq!(child_run(4, 2, 5), Err(ChildRunError::OutOfBounds));
        assert_eq!(
            child_run(usize::MAX, 1, usize::MAX),
            Err(ChildRunError::Overflow)
        );
    }

    #[test]
    fn strict_starts_derive_successor_and_terminal_ranges() {
        assert_eq!(
            strict_successor_ranges(&[8, 12, 20], 24),
            Ok(vec![
                SourceRange::new(8, 4),
                SourceRange::new(12, 8),
                SourceRange::new(20, 4),
            ])
        );
        assert_eq!(strict_successor_ranges(&[], 0), Ok(Vec::new()));
        assert_eq!(
            strict_successor_ranges(&[8, 8], 16),
            Err(SuccessorRangesError::NonIncreasing {
                index: 1,
                previous: 8,
                start: 8,
            })
        );
        assert_eq!(
            strict_successor_ranges(&[8, 16], 16),
            Err(SuccessorRangesError::OutsideTerminal {
                index: 1,
                start: 16,
                terminal: 16,
            })
        );
    }

    #[test]
    fn nondecreasing_starts_preserve_empty_members_and_terminal_starts() {
        assert_eq!(
            nondecreasing_successor_ranges(&[8, 8, 12, 16], 16),
            Ok(vec![
                SourceRange::new(8, 0),
                SourceRange::new(8, 4),
                SourceRange::new(12, 4),
                SourceRange::new(16, 0),
            ])
        );
        assert_eq!(nondecreasing_successor_ranges(&[], 0), Ok(Vec::new()));
        assert_eq!(
            nondecreasing_successor_ranges(&[8, 7], 16),
            Err(NondecreasingSuccessorRangesError::Decreasing {
                index: 1,
                previous: 8,
                start: 7,
            })
        );
        assert_eq!(
            nondecreasing_successor_ranges(&[17], 16),
            Err(NondecreasingSuccessorRangesError::OutsideTerminal {
                index: 0,
                start: 17,
                terminal: 16,
            })
        );
    }

    #[test]
    fn ordered_extent_audits_preserve_original_indices_and_relationships() {
        let gapped = [
            (7, SourceRange::new(10, 2)),
            (2, SourceRange::new(14, 0)),
            (9, SourceRange::new(14, 3)),
        ];
        assert_eq!(audit_ordered_non_overlapping(gapped), Ok(Some(17)));
        assert_eq!(
            audit_ordered_contiguous_run(gapped, 10),
            Err(OrderedExtentError::Discontiguous {
                index: 2,
                expected: 12,
                start: 14,
            })
        );

        let overlapping = [(11, SourceRange::new(4, 5)), (3, SourceRange::new(8, 1))];
        assert_eq!(
            audit_ordered_non_overlapping(overlapping),
            Err(OrderedExtentError::Overlap {
                previous_index: 11,
                previous_end: 9,
                index: 3,
                start: 8,
            })
        );
        assert_eq!(
            audit_ordered_non_overlapping([(5, SourceRange::new(u64::MAX, 1))]),
            Err(OrderedExtentError::EndOverflow {
                index: 5,
                start: u64::MAX,
                length: 1,
            })
        );
    }

    #[test]
    fn exact_tiling_distinguishes_run_and_terminal_mismatches() {
        let exact = [(4, SourceRange::new(8, 2)), (1, SourceRange::new(10, 3))];
        assert_eq!(audit_exact_tiling(exact, 8, 13), Ok(()));
        assert_eq!(audit_ordered_contiguous_run([], 7), Ok(7));
        assert_eq!(audit_exact_tiling([], 7, 7), Ok(()));
        assert_eq!(
            audit_exact_tiling(exact, 8, 14),
            Err(OrderedExtentError::TerminalMismatch {
                expected: 14,
                actual: 13,
            })
        );
    }

    proptest::proptest! {
        #[test]
        fn child_ranges_match_wide_arithmetic(first: usize, count: usize, total: usize) {
            let end = first as u128 + count as u128;
            let expected = if end > usize::MAX as u128 {
                Err(ChildRunError::Overflow)
            } else if end > total as u128 {
                Err(ChildRunError::OutOfBounds)
            } else {
                Ok(first..end as usize)
            };
            proptest::prop_assert_eq!(child_run(first, count, total), expected);
        }

        #[test]
        fn power_of_two_alignment_matches_wide_arithmetic(value: u64, shift in 0u32..64) {
            let alignment = 1u64 << shift;
            let expected = (value as u128 + alignment as u128 - 1)
                & !(alignment as u128 - 1);
            let expected = u64::try_from(expected).ok();
            proptest::prop_assert_eq!(checked_align_up_u64(value, alignment), expected);
        }
    }
}
