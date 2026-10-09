//! Count-prefixed, aligned terminal-boundary tables over resident metadata.
//!
//! Word zero is owned by the format and supplies the member count. The next
//! `count + 1` little-endian words are absolute byte boundaries. This helper
//! validates only their shared layout language: configured alignment, strict
//! increase, a bounded directory gap, and exact closure at carrier EOF. Gap
//! contents remain available for an owner to inspect without requiring the
//! complete carrier to be resident in this crate.

use formatkit_core::{Error, SourceRange};

const WORD_BYTES: usize = 4;

/// Failure while validating a counted terminal-boundary table.
#[derive(Debug, PartialEq, Eq)]
pub enum CountedBoundaryError {
    /// Computing `member_count + 1` overflowed the host index width.
    BoundaryCountOverflow,
    /// Computing the complete count-plus-boundaries extent overflowed.
    DirectoryExtentOverflow,
    /// A checked primitive read failed.
    Core(Error),
    /// Reserving storage for the validated boundary words failed.
    AllocationFailed {
        /// Number of boundary words requested.
        requested: usize,
    },
    /// A boundary was unaligned or beyond the resident carrier.
    InvalidBoundary {
        /// Zero-based position in the boundary list.
        index: usize,
        /// Exact decoded little-endian boundary word.
        value: u32,
    },
    /// The first boundary, directory gap, or terminal EOF closure was invalid.
    InvalidDirectoryClosure,
    /// A boundary did not strictly exceed its predecessor.
    NotStrictlyIncreasing {
        /// Zero-based position of the later boundary word.
        index: usize,
        /// Exact decoded little-endian boundary word.
        value: u32,
    },
}

impl From<Error> for CountedBoundaryError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

/// A little-endian count-plus-terminal-boundaries resident layout.
///
/// The owner reads and bounds the count before calling [`Self::validate`].
/// Count meaning, member types, names, resource limits, diagnostics, and any
/// retained allocation tail remain outside this primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedBoundaryTable {
    alignment: u32,
}

impl CountedBoundaryTable {
    /// Configure the required nonzero byte alignment of every boundary.
    #[must_use]
    pub const fn new(alignment: u32) -> Self {
        assert!(alignment != 0, "counted-boundary alignment must be nonzero");
        Self { alignment }
    }

    /// Validate the owner-bounded member count and its resident carrier.
    ///
    /// This compatibility entry point additionally enforces the historical
    /// zero-filled directory gap. Source-staged owners should call
    /// [`Self::validate_metadata`] and inspect the returned
    /// [`ValidatedCountedBoundaries::directory_gap`] through their own source.
    pub fn validate(
        self,
        carrier: &[u8],
        member_count: usize,
    ) -> Result<ValidatedCountedBoundaries, CountedBoundaryError> {
        let validated = self.decode_metadata(carrier, member_count, carrier.len() as u64)?;
        let gap = validated.directory_gap();
        let start = usize::try_from(gap.start)
            .map_err(|_| CountedBoundaryError::InvalidDirectoryClosure)?;
        let end = usize::try_from(
            gap.end()
                .map_err(|_| CountedBoundaryError::InvalidDirectoryClosure)?,
        )
        .map_err(|_| CountedBoundaryError::InvalidDirectoryClosure)?;
        if carrier
            .get(start..end)
            .is_none_or(|bytes| bytes.iter().any(|&byte| byte != 0))
        {
            return Err(CountedBoundaryError::InvalidDirectoryClosure);
        }
        require_strict_increase(&validated)?;
        Ok(validated)
    }

    /// Validate resident count/boundary metadata against a source length.
    ///
    /// Only the count word and `member_count + 1` boundary words must be
    /// resident. The returned directory-gap range lets the owner read and
    /// validate those bytes using its own source, budget, and diagnostics.
    /// This method performs no source I/O and assigns no gap-content policy.
    pub fn validate_metadata(
        self,
        metadata: &[u8],
        member_count: usize,
        source_len: u64,
    ) -> Result<ValidatedCountedBoundaries, CountedBoundaryError> {
        let validated = self.decode_metadata(metadata, member_count, source_len)?;
        require_strict_increase(&validated)?;
        Ok(validated)
    }

    fn decode_metadata(
        self,
        metadata: &[u8],
        member_count: usize,
        source_len: u64,
    ) -> Result<ValidatedCountedBoundaries, CountedBoundaryError> {
        let boundary_count = member_count
            .checked_add(1)
            .ok_or(CountedBoundaryError::BoundaryCountOverflow)?;
        let boundary_bytes = boundary_count
            .checked_mul(WORD_BYTES)
            .ok_or(CountedBoundaryError::DirectoryExtentOverflow)?;
        let directory_bytes = WORD_BYTES
            .checked_add(boundary_bytes)
            .ok_or(CountedBoundaryError::DirectoryExtentOverflow)?;
        formatkit_core::bytes_at(metadata, WORD_BYTES, boundary_bytes)?;

        let mut boundaries = Vec::new();
        boundaries.try_reserve_exact(boundary_count).map_err(|_| {
            CountedBoundaryError::AllocationFailed {
                requested: boundary_count,
            }
        })?;
        for index in 0..boundary_count {
            let value = formatkit_core::u32_at(metadata, WORD_BYTES + index * WORD_BYTES)?;
            if !value.is_multiple_of(self.alignment) || value as u64 > source_len {
                return Err(CountedBoundaryError::InvalidBoundary { index, value });
            }
            boundaries.push(u64::from(value));
        }

        if boundaries[0] < directory_bytes as u64 || boundaries.last().copied() != Some(source_len)
        {
            return Err(CountedBoundaryError::InvalidDirectoryClosure);
        }
        Ok(ValidatedCountedBoundaries {
            directory_bytes: directory_bytes as u64,
            boundaries,
        })
    }
}

fn require_strict_increase(
    validated: &ValidatedCountedBoundaries,
) -> Result<(), CountedBoundaryError> {
    for (prior_index, pair) in validated.boundaries.windows(2).enumerate() {
        if pair[1] <= pair[0] {
            return Err(CountedBoundaryError::NotStrictlyIncreasing {
                index: prior_index + 1,
                value: pair[1] as u32,
            });
        }
    }
    Ok(())
}

/// A validated counted-boundary layout without owner member semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCountedBoundaries {
    directory_bytes: u64,
    boundaries: Vec<u64>,
}

impl ValidatedCountedBoundaries {
    /// Return the count word plus all encoded boundary words in bytes.
    #[must_use]
    pub const fn directory_bytes(&self) -> u64 {
        self.directory_bytes
    }

    /// Return the exact first member boundary after any zero directory gap.
    #[must_use]
    pub fn first_boundary(&self) -> u64 {
        self.boundaries[0]
    }

    /// Return the owner-defined bytes between encoded metadata and child zero.
    ///
    /// The range may be empty. Its content policy is deliberately not part of
    /// the shared layout primitive.
    #[must_use]
    pub fn directory_gap(&self) -> SourceRange {
        SourceRange::new(
            self.directory_bytes,
            self.first_boundary() - self.directory_bytes,
        )
    }

    /// Return the validated raw absolute boundary words.
    #[must_use]
    pub fn boundaries(&self) -> &[u64] {
        &self.boundaries
    }

    /// Iterate the strictly positive ranges between adjacent boundaries.
    pub fn ranges(&self) -> impl ExactSizeIterator<Item = SourceRange> + '_ {
        self.boundaries
            .windows(2)
            .map(|pair| SourceRange::new(pair[0], pair[1] - pair[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: CountedBoundaryTable = CountedBoundaryTable::new(16);

    fn carrier(count: u32, boundaries: &[u32], len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        bytes[..4].copy_from_slice(&count.to_le_bytes());
        for (index, boundary) in boundaries.iter().enumerate() {
            let at = 4 + index * 4;
            if at + 4 <= bytes.len() {
                bytes[at..at + 4].copy_from_slice(&boundary.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn returns_layout_native_ranges_and_directory_facts() {
        let parsed = TABLE.validate(&carrier(2, &[16, 32, 48], 48), 2).unwrap();
        assert_eq!(parsed.directory_bytes(), 16);
        assert_eq!(parsed.first_boundary(), 16);
        assert_eq!(parsed.boundaries(), &[16, 32, 48]);
        assert_eq!(
            parsed.ranges().collect::<Vec<_>>(),
            [SourceRange::new(16, 16), SourceRange::new(32, 16)]
        );
    }

    #[test]
    fn zero_directory_gap_is_part_of_the_exact_language() {
        let parsed = TABLE.validate(&carrier(1, &[16, 32], 32), 1).unwrap();
        assert_eq!(parsed.directory_bytes(), 12);
        assert_eq!(parsed.first_boundary() - parsed.directory_bytes(), 4);
        assert_eq!(parsed.directory_gap(), SourceRange::new(12, 4));

        let mut dirty = carrier(1, &[16, 32], 32);
        dirty[12] = 1;
        assert_eq!(
            TABLE.validate(&dirty, 1),
            Err(CountedBoundaryError::InvalidDirectoryClosure)
        );
    }

    #[test]
    fn resident_gap_diagnostic_precedes_strict_order_but_staged_order_stays_strict() {
        let mut bytes = carrier(2, &[32, 32, 48], 48);
        bytes[16] = 1;
        assert_eq!(
            TABLE.validate(&bytes, 2),
            Err(CountedBoundaryError::InvalidDirectoryClosure)
        );
        assert_eq!(
            TABLE.validate_metadata(&bytes[..16], 2, 48),
            Err(CountedBoundaryError::NotStrictlyIncreasing {
                index: 1,
                value: 32,
            })
        );
    }

    #[test]
    fn source_staged_validation_needs_only_metadata_and_exposes_the_gap() {
        let mut bytes = carrier(1, &[16, 32], 32);
        bytes[12] = 0xa5;
        let parsed = TABLE.validate_metadata(&bytes[..12], 1, 32).unwrap();
        assert_eq!(parsed.boundaries(), &[16, 32]);
        assert_eq!(parsed.directory_gap(), SourceRange::new(12, 4));
        assert_eq!(
            TABLE.validate(&bytes, 1),
            Err(CountedBoundaryError::InvalidDirectoryClosure)
        );

        assert_eq!(
            TABLE.validate_metadata(&bytes[..11], 1, 32),
            Err(CountedBoundaryError::Core(Error::Truncated {
                offset: 4,
                needed: 8,
                available: 7,
            }))
        );
        assert_eq!(
            TABLE.validate_metadata(&bytes[..12], 1, 48),
            Err(CountedBoundaryError::InvalidDirectoryClosure)
        );
    }

    #[test]
    fn alignment_order_terminal_and_availability_are_distinct() {
        assert_eq!(
            TABLE.validate(&carrier(1, &[12, 32], 32), 1),
            Err(CountedBoundaryError::InvalidBoundary {
                index: 0,
                value: 12
            })
        );
        assert_eq!(
            TABLE.validate(&carrier(2, &[16, 16, 32], 32), 2),
            Err(CountedBoundaryError::NotStrictlyIncreasing {
                index: 1,
                value: 16
            })
        );
        assert_eq!(
            TABLE.validate(&carrier(1, &[16, 16], 32), 1),
            Err(CountedBoundaryError::InvalidDirectoryClosure)
        );
        assert_eq!(
            TABLE.validate(&[1, 0, 0, 0, 16], 1),
            Err(CountedBoundaryError::Core(Error::Truncated {
                offset: 4,
                needed: 8,
                available: 1
            }))
        );
    }

    #[test]
    fn looser_allocation_tail_language_is_not_absorbed() {
        let bytes = carrier(1, &[16, 24], 32);
        assert_eq!(
            TABLE.validate(&bytes, 1),
            Err(CountedBoundaryError::InvalidBoundary {
                index: 1,
                value: 24
            })
        );

        let byte_aligned = CountedBoundaryTable::new(1);
        assert_eq!(
            byte_aligned.validate(&bytes, 1),
            Err(CountedBoundaryError::InvalidDirectoryClosure)
        );
    }

    #[test]
    #[should_panic(expected = "counted-boundary alignment must be nonzero")]
    fn zero_alignment_definition_is_invalid() {
        let _ = CountedBoundaryTable::new(0);
    }

    fn frozen(
        carrier: &[u8],
        member_count: usize,
        alignment: u32,
    ) -> Result<(u64, Vec<u64>, Vec<SourceRange>), CountedBoundaryError> {
        let boundary_count = member_count
            .checked_add(1)
            .ok_or(CountedBoundaryError::BoundaryCountOverflow)?;
        let boundary_bytes = boundary_count
            .checked_mul(WORD_BYTES)
            .ok_or(CountedBoundaryError::DirectoryExtentOverflow)?;
        let directory_bytes = WORD_BYTES
            .checked_add(boundary_bytes)
            .ok_or(CountedBoundaryError::DirectoryExtentOverflow)?;
        let table = formatkit_core::bytes_at(carrier, WORD_BYTES, boundary_bytes)?;

        let mut boundaries = Vec::with_capacity(boundary_count);
        for (index, word) in table.chunks_exact(WORD_BYTES).enumerate() {
            let value = u32::from_le_bytes(word.try_into().unwrap());
            if !value.is_multiple_of(alignment) || value as u64 > carrier.len() as u64 {
                return Err(CountedBoundaryError::InvalidBoundary { index, value });
            }
            boundaries.push(u64::from(value));
        }
        let first_boundary = boundaries[0] as usize;
        if first_boundary < directory_bytes
            || boundaries.last().copied() != Some(carrier.len() as u64)
            || carrier[directory_bytes..first_boundary]
                .iter()
                .any(|&byte| byte != 0)
        {
            return Err(CountedBoundaryError::InvalidDirectoryClosure);
        }
        for (prior_index, pair) in boundaries.windows(2).enumerate() {
            if pair[1] <= pair[0] {
                return Err(CountedBoundaryError::NotStrictlyIncreasing {
                    index: prior_index + 1,
                    value: pair[1] as u32,
                });
            }
        }
        let ranges = boundaries
            .windows(2)
            .map(|pair| SourceRange::new(pair[0], pair[1] - pair[0]))
            .collect();
        Ok((directory_bytes as u64, boundaries, ranges))
    }

    proptest::proptest! {
        #[test]
        fn matches_frozen_mechanic_on_arbitrary_resident_input(
            carrier in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
            member_count in 0usize..64,
            alignment in 1u32..64,
        ) {
            let configured = CountedBoundaryTable::new(alignment)
                .validate(&carrier, member_count)
                .map(|validated| {
                    let ranges = validated.ranges().collect::<Vec<_>>();
                    (
                        validated.directory_bytes(),
                        validated.boundaries().to_vec(),
                        ranges,
                    )
                });
            proptest::prop_assert_eq!(
                configured,
                frozen(&carrier, member_count, alignment)
            );
        }
    }
}
