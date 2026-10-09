//! Strict first-word offset tables producing layout-native ranges.
//!
//! The table describes byte ranges only. Owners retain carrier limits, child
//! validation, member names, source verification and writer capabilities.

use formatkit_core::{Error, SourceRange};

/// Failure while decoding the strict first-word offset-table language.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstWordOffsetError {
    /// A checked primitive read failed.
    Core(Error),
    /// The first word was not a positive, bounded multiple of four.
    InvalidTableLength,
    /// The declared table left no room for a nonempty first member.
    TableAtOrPastEof,
    /// The resident table slice does not contain its complete declaration.
    TableUnavailable {
        /// Complete encoded table length.
        needed: usize,
        /// Resident bytes supplied by the caller.
        available: usize,
    },
    /// An offset violated the first-offset, strict-order, or carrier bound.
    InvalidOffset {
        /// Zero-based position of the invalid offset word.
        index: usize,
    },
}

impl From<Error> for FirstWordOffsetError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

/// A strict little-endian table whose first word is also its byte length.
///
/// Every stored offset must be strictly increasing and before EOF. The first
/// offset must equal the table byte length, and the final derived range ends at
/// `source_len`. The owner supplies the table-size ceiling.
#[derive(Debug, Clone, Copy)]
pub struct FirstWordOffsetTable {
    max_table_bytes: u32,
}

impl FirstWordOffsetTable {
    /// Configure a nonzero, four-byte-aligned table-size ceiling.
    ///
    /// Panics when the ceiling is less than four, is not divisible by four, is
    /// not representable by the on-disk `u32`, or cannot address host memory.
    #[must_use]
    pub const fn new(max_table_bytes: u64) -> Self {
        assert!(
            max_table_bytes >= 4
                && max_table_bytes.is_multiple_of(4)
                && max_table_bytes <= u32::MAX as u64
                && max_table_bytes <= usize::MAX as u64
        );
        Self {
            max_table_bytes: max_table_bytes as u32,
        }
    }

    /// Validate and return the table byte length relative to a carrier.
    pub fn table_bytes(
        self,
        prefix: &[u8],
        source_len: u64,
    ) -> Result<usize, FirstWordOffsetError> {
        let bytes = self.declared_table_bytes(prefix)?;
        if bytes as u64 >= source_len {
            return Err(FirstWordOffsetError::TableAtOrPastEof);
        }
        Ok(bytes)
    }

    /// Validate the encoded table size without requiring it to precede EOF.
    ///
    /// Source adapters use this before issuing their owner-controlled read.
    pub fn declared_table_bytes(self, prefix: &[u8]) -> Result<usize, FirstWordOffsetError> {
        let bytes = u64::from(formatkit_core::u32_at(prefix, 0)?);
        if bytes < 4 || !bytes.is_multiple_of(4) || bytes > u64::from(self.max_table_bytes) {
            return Err(FirstWordOffsetError::InvalidTableLength);
        }
        Ok(bytes as usize)
    }

    /// Decode the complete table into strictly ordered carrier ranges.
    pub fn ranges(
        self,
        table: &[u8],
        source_len: u64,
    ) -> Result<Vec<SourceRange>, FirstWordOffsetError> {
        let bytes = self.table_bytes(table, source_len)?;
        if table.len() < bytes {
            return Err(FirstWordOffsetError::TableUnavailable {
                needed: bytes,
                available: table.len(),
            });
        }
        let count = bytes / 4;
        let mut ranges = Vec::with_capacity(count);
        let mut previous = bytes as u64;
        for index in 1..count {
            let offset = u64::from(formatkit_core::u32_at(table, index * 4)?);
            if offset <= previous || offset >= source_len {
                return Err(FirstWordOffsetError::InvalidOffset { index });
            }
            ranges.push(SourceRange::new(previous, offset - previous));
            previous = offset;
        }
        ranges.push(SourceRange::new(previous, source_len - previous));
        Ok(ranges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: FirstWordOffsetTable = FirstWordOffsetTable::new(16);

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn legacy_ranges(
        table: &[u8],
        source_len: u64,
    ) -> Result<Vec<SourceRange>, FirstWordOffsetError> {
        let bytes = u64::from(formatkit_core::u32_at(table, 0)?);
        if bytes < 4 || !bytes.is_multiple_of(4) || bytes > 16 {
            return Err(FirstWordOffsetError::InvalidTableLength);
        }
        if bytes >= source_len {
            return Err(FirstWordOffsetError::TableAtOrPastEof);
        }
        let bytes = bytes as usize;
        if table.len() < bytes {
            return Err(FirstWordOffsetError::TableUnavailable {
                needed: bytes,
                available: table.len(),
            });
        }
        let mut offsets = Vec::with_capacity(bytes / 4);
        for index in 0..bytes / 4 {
            let offset = u64::from(formatkit_core::u32_at(table, index * 4)?);
            if (index == 0 && offset != bytes as u64)
                || offsets.last().is_some_and(|&prior| offset <= prior)
                || offset >= source_len
            {
                return Err(FirstWordOffsetError::InvalidOffset { index });
            }
            offsets.push(offset);
        }
        Ok(offsets
            .iter()
            .enumerate()
            .map(|(index, &offset)| {
                let end = offsets.get(index + 1).copied().unwrap_or(source_len);
                SourceRange::new(offset, end - offset)
            })
            .collect())
    }

    #[test]
    fn one_and_multiple_members_end_at_eof_without_alignment_policy() {
        let one = TABLE.ranges(&words(&[4]), 5).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0], SourceRange::new(4, 1));
        assert_eq!(
            TABLE.ranges(&words(&[8, 11]), 14).unwrap(),
            [SourceRange::new(8, 3), SourceRange::new(11, 3)]
        );
    }

    #[test]
    fn table_length_and_availability_are_distinct() {
        assert_eq!(
            TABLE.table_bytes(&[], 12),
            Err(FirstWordOffsetError::Core(Error::Truncated {
                offset: 0,
                needed: 4,
                available: 0
            }))
        );
        for value in [0, 1, 3, 5, 20] {
            assert_eq!(
                TABLE.table_bytes(&words(&[value]), 21),
                Err(FirstWordOffsetError::InvalidTableLength)
            );
        }
        assert_eq!(
            TABLE.table_bytes(&words(&[12]), 12),
            Err(FirstWordOffsetError::TableAtOrPastEof)
        );
        assert_eq!(
            TABLE.ranges(&words(&[12, 16]), 20),
            Err(FirstWordOffsetError::TableUnavailable {
                needed: 12,
                available: 8
            })
        );
    }

    #[test]
    fn configuration_cannot_exceed_the_wire_table_length() {
        assert!(std::panic::catch_unwind(|| {
            FirstWordOffsetTable::new(u64::from(u32::MAX) + 1)
        })
        .is_err());
    }

    #[test]
    fn offsets_are_exactly_the_strict_family_contract() {
        for (values, bad_index) in [
            (vec![8, 8], 1),
            (vec![8, 7], 1),
            (vec![8, 4], 1),
            (vec![8, 20], 1),
        ] {
            assert_eq!(
                TABLE.ranges(&words(&values), 20),
                Err(FirstWordOffsetError::InvalidOffset { index: bad_index })
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn matches_frozen_mechanic_on_arbitrary_input(table in proptest::collection::vec(proptest::num::u8::ANY, 0..64), source_len in proptest::num::u64::ANY) {
            proptest::prop_assert_eq!(TABLE.ranges(&table, source_len), legacy_ranges(&table, source_len));
        }
    }
}
