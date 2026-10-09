//! Checked aligned extents derived from an already-decoded size sequence.
//!
//! This module owns only the recurrence
//! `start[n + 1] = align_up(start[n] + size[n], alignment)`. Format owners
//! retain the size fields and their encoding, zero-size policy, source bounds,
//! padding contents, metadata overlap, final-tail policy, and diagnostics.

use crate::checked_align_up_u64;
use formatkit_core::SourceRange;

/// Failure while deriving an aligned size chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignedSizeError {
    /// Adding one decoded size overflowed the source coordinate.
    LogicalEndOverflow {
        /// Zero-based position of the size whose logical end overflowed.
        index: usize,
    },
    /// Aligning a logical end to obtain the following start overflowed.
    NextStartOverflow {
        /// Zero-based position of the size preceding the failed start.
        index: usize,
    },
}

/// The placement relationship for a sequence of decoded member sizes.
///
/// The first member begins at `first_offset`. Every later member begins at the
/// previous member's logical end rounded up to `alignment`. Alignment must be a
/// nonzero power of two; invalid constants are descriptor bugs and panic in
/// [`new`](Self::new).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlignedSizeChain {
    first_offset: u64,
    alignment: u64,
}

impl AlignedSizeChain {
    /// Configure the first member offset and inter-member alignment.
    #[must_use]
    pub const fn new(first_offset: u64, alignment: u64) -> Self {
        assert!(
            alignment.is_power_of_two(),
            "aligned-size-chain alignment must be a nonzero power of two"
        );
        Self {
            first_offset,
            alignment,
        }
    }

    /// Begin incremental derivation while preserving the owner's validation
    /// order and avoiding an intermediate size allocation.
    #[must_use]
    pub const fn cursor(self) -> AlignedSizeCursor {
        AlignedSizeCursor {
            first_offset: self.first_offset,
            alignment: self.alignment,
            previous_end: None,
            next_index: 0,
        }
    }

    /// Check all extent and alignment arithmetic and return a borrowed view.
    ///
    /// Empty and zero-size sequences are representable. This method does not
    /// compare any derived range with a carrier length and does not require the
    /// final logical end or its aligned successor to equal anything.
    pub fn derive<'a>(self, sizes: &'a [u64]) -> Result<DerivedAlignedSizes<'a>, AlignedSizeError> {
        let mut cursor = self.cursor();
        for &size in sizes {
            cursor.push(size)?;
        }
        Ok(DerivedAlignedSizes {
            sizes,
            first_offset: self.first_offset,
            alignment: self.alignment,
            final_end: cursor.final_end(),
        })
    }
}

/// Incremental state for an aligned size-derived chain.
///
/// Alignment is applied lazily before the next extent is requested. Therefore
/// finishing a chain never requires an unused aligned successor after its last
/// logical extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlignedSizeCursor {
    first_offset: u64,
    alignment: u64,
    previous_end: Option<u64>,
    next_index: usize,
}

impl AlignedSizeCursor {
    /// Derive one logical extent and advance the chain.
    pub fn push(&mut self, size: u64) -> Result<AlignedSizeExtent, AlignedSizeError> {
        let index = self.next_index;
        let start = match self.previous_end {
            Some(previous_end) => checked_align_up_u64(previous_end, self.alignment)
                .ok_or(AlignedSizeError::NextStartOverflow { index: index - 1 })?,
            None => self.first_offset,
        };
        let end = start
            .checked_add(size)
            .ok_or(AlignedSizeError::LogicalEndOverflow { index })?;
        self.previous_end = Some(end);
        self.next_index += 1;
        Ok(AlignedSizeExtent {
            index,
            size,
            range: SourceRange::new(start, size),
        })
    }

    /// The last derived logical end, or the configured first offset before any
    /// extent has been requested.
    #[must_use]
    pub const fn final_end(self) -> u64 {
        match self.previous_end {
            Some(end) => end,
            None => self.first_offset,
        }
    }
}

/// One logical extent in an aligned size-derived chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlignedSizeExtent {
    /// Zero-based position in the decoded size sequence.
    pub index: usize,
    /// Exact decoded logical size supplied by the owner.
    pub size: u64,
    /// Derived source-relative logical extent, excluding following padding.
    pub range: SourceRange,
}

/// A decoded size sequence whose complete placement arithmetic is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedAlignedSizes<'a> {
    sizes: &'a [u64],
    first_offset: u64,
    alignment: u64,
    final_end: u64,
}

impl DerivedAlignedSizes<'_> {
    /// Iterate exact logical extents without allocating.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = AlignedSizeExtent> + '_ {
        let mut cursor = self.first_offset;
        self.sizes.iter().enumerate().map(move |(index, &size)| {
            let range = SourceRange::new(cursor, size);
            if index + 1 < self.sizes.len() {
                cursor = checked_align_up_u64(range.end().unwrap(), self.alignment).unwrap();
            }
            AlignedSizeExtent { index, size, range }
        })
    }

    /// The final member's logical end, or the configured first offset when the
    /// sequence is empty.
    #[must_use]
    pub const fn final_end(&self) -> u64 {
        self.final_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn derives_inter_member_alignment_without_assigning_zero_or_tail_policy() {
        let derived = AlignedSizeChain::new(10, 4).derive(&[3, 0, 5]).unwrap();
        assert_eq!(
            derived.iter().collect::<Vec<_>>(),
            [
                AlignedSizeExtent {
                    index: 0,
                    size: 3,
                    range: SourceRange::new(10, 3),
                },
                AlignedSizeExtent {
                    index: 1,
                    size: 0,
                    range: SourceRange::new(16, 0),
                },
                AlignedSizeExtent {
                    index: 2,
                    size: 5,
                    range: SourceRange::new(16, 5),
                },
            ]
        );
        assert_eq!(derived.final_end(), 21);

        let empty = AlignedSizeChain::new(7, 1).derive(&[]).unwrap();
        assert_eq!(empty.iter().len(), 0);
        assert_eq!(empty.final_end(), 7);
    }

    #[test]
    fn final_extent_does_not_require_an_unused_aligned_successor() {
        let one = AlignedSizeChain::new(0, 8).derive(&[u64::MAX]).unwrap();
        assert_eq!(one.final_end(), u64::MAX);
        assert_eq!(
            one.iter().next().unwrap().range,
            SourceRange::new(0, u64::MAX)
        );

        assert_eq!(
            AlignedSizeChain::new(0, 8).derive(&[u64::MAX, 0]),
            Err(AlignedSizeError::NextStartOverflow { index: 0 })
        );
        assert_eq!(
            AlignedSizeChain::new(u64::MAX, 1).derive(&[1]),
            Err(AlignedSizeError::LogicalEndOverflow { index: 0 })
        );
    }

    #[test]
    fn incremental_cursor_matches_borrowed_derivation() {
        let layout = AlignedSizeChain::new(9, 8);
        let mut cursor = layout.cursor();
        let incremental = [7, 1, 0, 9]
            .into_iter()
            .map(|size| cursor.push(size).unwrap())
            .collect::<Vec<_>>();
        let borrowed = layout.derive(&[7, 1, 0, 9]).unwrap();
        assert_eq!(incremental, borrowed.iter().collect::<Vec<_>>());
        assert_eq!(cursor.final_end(), borrowed.final_end());
    }

    #[test]
    #[should_panic(expected = "aligned-size-chain alignment must be a nonzero power of two")]
    fn zero_alignment_is_an_invalid_descriptor() {
        let _ = AlignedSizeChain::new(0, 0);
    }

    #[test]
    #[should_panic(expected = "aligned-size-chain alignment must be a nonzero power of two")]
    fn non_power_of_two_alignment_is_an_invalid_descriptor() {
        let _ = AlignedSizeChain::new(0, 3);
    }

    proptest! {
        #[test]
        fn checked_chain_matches_independent_wide_arithmetic(
            first_offset in any::<u64>(),
            sizes in proptest::collection::vec(any::<u64>(), 0..24),
            shift in 0u32..64,
        ) {
            let alignment = 1u64 << shift;
            let mut cursor = u128::from(first_offset);
            let mut expected = Vec::with_capacity(sizes.len());
            let mut failed = false;
            for (index, &size) in sizes.iter().enumerate() {
                let end = cursor + u128::from(size);
                if end > u128::from(u64::MAX) {
                    failed = true;
                    break;
                }
                expected.push(SourceRange::new(cursor as u64, size));
                if index + 1 < sizes.len() {
                    let unit = u128::from(alignment);
                    cursor = (end + unit - 1) & !(unit - 1);
                    if cursor > u128::from(u64::MAX) {
                        failed = true;
                        break;
                    }
                } else {
                    cursor = end;
                }
            }

            match AlignedSizeChain::new(first_offset, alignment).derive(&sizes) {
                Ok(derived) => {
                    prop_assert!(!failed);
                    prop_assert_eq!(
                        derived.iter().map(|extent| extent.range).collect::<Vec<_>>(),
                        expected
                    );
                    prop_assert_eq!(u128::from(derived.final_end()), cursor);
                }
                Err(_) => prop_assert!(failed),
            }
        }
    }
}
