//! Checked positive-u32 size accumulation for already-bounded metadata.
//!
//! Owners retain headers, count limits, names, source reads, collision checks
//! and contextual child policy. This module only validates sizes and derives
//! consecutive source-relative extents that close exactly at EOF.

use formatkit_core::{Error, SourceRange};

const SIZE_BYTES: usize = 4;

/// Optional per-size divisibility policy for a positive-size list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeAlignment {
    /// Accept every positive `u32` size.
    Any,
    /// Require each size to be divisible by the nonzero supplied unit.
    MultipleOf(u32),
}

/// Failure while validating a positive-size list and its derived extents.
#[derive(Debug, PartialEq, Eq)]
pub enum PositiveSizeError {
    /// A checked primitive read failed.
    Core(Error),
    /// `count * 4` overflowed `usize`.
    TableExtentOverflow,
    /// A stored size was zero.
    Zero {
        /// Zero-based position of the invalid size word.
        index: usize,
    },
    /// A stored size violated the configured divisibility requirement.
    Unaligned {
        /// Zero-based position of the invalid size word.
        index: usize,
        /// Decoded size that violated the configured alignment.
        size: u32,
    },
    /// Adding a stored size overflowed the wide source coordinate.
    EndOverflow {
        /// Zero-based position of the size whose end overflowed.
        index: usize,
    },
    /// A derived extent ended after `source_len`.
    BeyondEof {
        /// Zero-based position of the extent that crossed EOF.
        index: usize,
    },
    /// The final derived extent ended before `source_len`.
    DoesNotClose,
}

impl From<Error> for PositiveSizeError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

/// A strict little-endian list of positive `u32` sizes.
///
/// Validation derives consecutive extents from an owner-supplied first offset
/// and requires the final extent to close exactly at EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositiveSizeList {
    alignment: SizeAlignment,
}

impl PositiveSizeList {
    /// Configure the optional per-size divisibility requirement.
    ///
    /// Panics for `SizeAlignment::MultipleOf(0)`.
    #[must_use]
    pub const fn new(alignment: SizeAlignment) -> Self {
        if let SizeAlignment::MultipleOf(unit) = alignment {
            assert!(unit != 0, "positive-size alignment must be nonzero");
        }
        Self { alignment }
    }

    /// Validate exactly `count` sizes and return a borrowed validated view.
    pub fn validate<'a>(
        self,
        table: &'a [u8],
        count: usize,
        first_offset: u64,
        source_len: u64,
    ) -> std::result::Result<ValidatedPositiveSizes<'a>, PositiveSizeError> {
        let table_bytes = count
            .checked_mul(SIZE_BYTES)
            .ok_or(PositiveSizeError::TableExtentOverflow)?;
        let table = formatkit_core::bytes_at(table, 0, table_bytes)?;
        let mut cursor = first_offset;
        for (index, raw) in table.chunks_exact(SIZE_BYTES).enumerate() {
            let size = formatkit_core::u32_at(raw, 0)?;
            if size == 0 {
                return Err(PositiveSizeError::Zero { index });
            }
            if let SizeAlignment::MultipleOf(unit) = self.alignment {
                if !size.is_multiple_of(unit) {
                    return Err(PositiveSizeError::Unaligned { index, size });
                }
            }
            cursor = cursor
                .checked_add(u64::from(size))
                .ok_or(PositiveSizeError::EndOverflow { index })?;
            if cursor > source_len {
                return Err(PositiveSizeError::BeyondEof { index });
            }
        }
        if cursor != source_len {
            return Err(PositiveSizeError::DoesNotClose);
        }
        Ok(ValidatedPositiveSizes {
            table,
            first_offset,
        })
    }
}

/// One consecutive extent derived from a validated positive size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositiveSizeExtent {
    /// Zero-based position in the size table.
    pub index: usize,
    /// The exact stored little-endian value.
    pub raw_size: u32,
    /// The derived source-relative byte extent.
    pub range: SourceRange,
}

/// A borrowed positive-size table whose full extent chain was validated.
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedPositiveSizes<'a> {
    table: &'a [u8],
    first_offset: u64,
}

impl ValidatedPositiveSizes<'_> {
    /// Iterate the already-validated consecutive extents without allocation.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = PositiveSizeExtent> + '_ {
        let mut cursor = self.first_offset;
        self.table
            .chunks_exact(SIZE_BYTES)
            .enumerate()
            .map(move |(index, raw)| {
                let raw_size = formatkit_core::u32_at(raw, 0).unwrap();
                let range = SourceRange::new(cursor, u64::from(raw_size));
                cursor = range.end().unwrap();
                PositiveSizeExtent {
                    index,
                    raw_size,
                    range,
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    #[test]
    fn alignment_is_an_explicit_owner_policy() {
        let table = words(&[3, 5]);
        let any = PositiveSizeList::new(SizeAlignment::Any)
            .validate(&table, 2, 12, 20)
            .unwrap();
        assert_eq!(
            any.iter().collect::<Vec<_>>(),
            [
                PositiveSizeExtent {
                    index: 0,
                    raw_size: 3,
                    range: SourceRange::new(12, 3),
                },
                PositiveSizeExtent {
                    index: 1,
                    raw_size: 5,
                    range: SourceRange::new(15, 5),
                }
            ]
        );
        assert_eq!(
            PositiveSizeList::new(SizeAlignment::MultipleOf(4)).validate(&table, 2, 12, 20),
            Err(PositiveSizeError::Unaligned { index: 0, size: 3 })
        );
    }

    #[test]
    fn zero_overrun_trailing_and_short_table_are_distinct() {
        let layout = PositiveSizeList::new(SizeAlignment::Any);
        assert_eq!(
            layout.validate(&words(&[0]), 1, 8, 8),
            Err(PositiveSizeError::Zero { index: 0 })
        );
        assert_eq!(
            layout.validate(&words(&[5]), 1, 8, 12),
            Err(PositiveSizeError::BeyondEof { index: 0 })
        );
        assert_eq!(
            layout.validate(&words(&[1]), 1, u64::MAX, u64::MAX),
            Err(PositiveSizeError::EndOverflow { index: 0 })
        );
        assert_eq!(
            layout.validate(&words(&[3]), 1, 8, 12),
            Err(PositiveSizeError::DoesNotClose)
        );
        assert!(matches!(
            layout.validate(&[1, 2, 3], 1, 8, 9),
            Err(PositiveSizeError::Core(Error::Truncated { .. }))
        ));
    }

    #[test]
    #[should_panic(expected = "positive-size alignment must be nonzero")]
    fn zero_alignment_definition_is_invalid() {
        let _ = PositiveSizeList::new(SizeAlignment::MultipleOf(0));
    }

    fn frozen(
        table: &[u8],
        count: usize,
        first_offset: u64,
        source_len: u64,
        alignment: SizeAlignment,
    ) -> std::result::Result<Vec<PositiveSizeExtent>, PositiveSizeError> {
        let table_bytes = count
            .checked_mul(SIZE_BYTES)
            .ok_or(PositiveSizeError::TableExtentOverflow)?;
        let table = formatkit_core::bytes_at(table, 0, table_bytes)?;
        let mut cursor = first_offset;
        let mut extents = Vec::new();
        for (index, raw) in table.chunks_exact(SIZE_BYTES).enumerate() {
            let raw_size = formatkit_core::u32_at(raw, 0)?;
            if raw_size == 0 {
                return Err(PositiveSizeError::Zero { index });
            }
            if let SizeAlignment::MultipleOf(unit) = alignment {
                if !raw_size.is_multiple_of(unit) {
                    return Err(PositiveSizeError::Unaligned {
                        index,
                        size: raw_size,
                    });
                }
            }
            let start = cursor;
            cursor = cursor
                .checked_add(u64::from(raw_size))
                .ok_or(PositiveSizeError::EndOverflow { index })?;
            if cursor > source_len {
                return Err(PositiveSizeError::BeyondEof { index });
            }
            extents.push(PositiveSizeExtent {
                index,
                raw_size,
                range: SourceRange::new(start, u64::from(raw_size)),
            });
        }
        if cursor != source_len {
            return Err(PositiveSizeError::DoesNotClose);
        }
        Ok(extents)
    }

    proptest::proptest! {
        #[test]
        fn validated_view_matches_independent_accumulation(
            table in proptest::collection::vec(proptest::num::u8::ANY, 0..128),
            count in 0usize..32,
            first_offset in proptest::num::u64::ANY,
            source_len in proptest::num::u64::ANY,
            aligned in proptest::bool::ANY,
        ) {
            let alignment = if aligned { SizeAlignment::MultipleOf(4) } else { SizeAlignment::Any };
            let layout = PositiveSizeList::new(alignment);
            let configured = layout
                .validate(&table, count, first_offset, source_len)
                .map(|validated| validated.iter().collect::<Vec<_>>());
            proptest::prop_assert_eq!(configured, frozen(&table, count, first_offset, source_len, alignment));
        }
    }
}
