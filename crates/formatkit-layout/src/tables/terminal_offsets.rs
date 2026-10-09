//! Nondecreasing terminal-offset tables producing layout-native ranges.
//!
//! The first word declares the complete table byte length and is also the
//! first data offset. The final word is a terminal offset equal to carrier
//! EOF, so adjacent equal offsets deliberately describe empty ranges.

use formatkit_core::{Error, SourceRange};

/// Failure while decoding the terminal-offset-table language.
#[derive(Debug, PartialEq, Eq)]
pub enum TerminalOffsetError {
    /// A checked primitive read failed.
    Core(Error),
    /// The first word was not a bounded complete table byte length.
    InvalidTableLength,
    /// The resident table slice does not contain its complete declaration.
    TableUnavailable {
        /// Offset at which the missing suffix would begin.
        offset: usize,
        /// Number of additional bytes required.
        needed: usize,
        /// Number of bytes available after `offset`.
        available: usize,
    },
    /// An offset was unaligned, descending, before the table, or after EOF.
    InvalidOffset {
        /// Zero-based position of the invalid offset word.
        index: usize,
    },
    /// The first offset did not equal the declared table byte length.
    FirstOffsetMismatch,
    /// The final offset did not equal carrier EOF.
    TerminalOffsetMismatch,
}

impl From<Error> for TerminalOffsetError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

/// A little-endian terminal-offset table with an owner-supplied slot ceiling.
///
/// Stored offsets must be four-byte aligned, nondecreasing, at or after the
/// table, and at or before EOF. Equal adjacent offsets are accepted. This type
/// performs no source I/O and attaches no archive semantics to its ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalOffsetTable {
    max_table_bytes: u32,
}

impl TerminalOffsetTable {
    /// Configure a positive logical-slot ceiling.
    ///
    /// Panics when the ceiling is zero or when its encoded table byte length
    /// does not fit the on-disk `u32`.
    #[must_use]
    pub const fn new(max_logical_slots: usize) -> Self {
        assert!(max_logical_slots != 0);
        let Some(word_count) = max_logical_slots.checked_add(1) else {
            panic!("terminal-offset slot ceiling overflows");
        };
        let Some(table_bytes) = word_count.checked_mul(4) else {
            panic!("terminal-offset table ceiling overflows");
        };
        assert!(
            table_bytes <= u32::MAX as usize,
            "terminal-offset table ceiling exceeds its wire representation"
        );
        Self {
            max_table_bytes: table_bytes as u32,
        }
    }

    /// Validate and return the encoded table byte length relative to a carrier.
    pub fn declared_table_bytes(
        self,
        prefix: &[u8],
        source_len: u64,
    ) -> Result<u64, TerminalOffsetError> {
        let table_bytes = u64::from(formatkit_core::u32_at(prefix, 0)?);
        if !(8..=u64::from(self.max_table_bytes)).contains(&table_bytes)
            || !table_bytes.is_multiple_of(4)
            || table_bytes > source_len
        {
            return Err(TerminalOffsetError::InvalidTableLength);
        }
        Ok(table_bytes)
    }

    /// Validate a complete resident table and return its carrier ranges.
    pub fn validate(
        self,
        table: &[u8],
        source_len: u64,
    ) -> Result<ValidatedTerminalOffsets, TerminalOffsetError> {
        let table_bytes = self.declared_table_bytes(table, source_len)?;
        let table_len = table_bytes as usize;
        if table.len() < table_len {
            return Err(TerminalOffsetError::TableUnavailable {
                offset: table.len(),
                needed: table_len - table.len(),
                available: 0,
            });
        }
        let word_count = table_len / 4;

        let mut ranges = Vec::with_capacity(word_count - 1);
        let mut previous = table_bytes;
        for index in 1..word_count {
            let offset = u64::from(formatkit_core::u32_at(table, index * 4)?);
            if !offset.is_multiple_of(4)
                || offset < table_bytes
                || offset > source_len
                || offset < previous
            {
                return Err(TerminalOffsetError::InvalidOffset { index });
            }
            ranges.push(SourceRange::new(previous, offset - previous));
            previous = offset;
        }
        if previous != source_len {
            return Err(TerminalOffsetError::TerminalOffsetMismatch);
        }
        Ok(ValidatedTerminalOffsets {
            table_bytes,
            ranges,
        })
    }
}

/// A validated terminal-offset table represented without owner vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTerminalOffsets {
    table_bytes: u64,
    ranges: Vec<SourceRange>,
}

impl ValidatedTerminalOffsets {
    /// Return the exact byte length occupied by the table.
    #[must_use]
    pub const fn table_bytes(&self) -> u64 {
        self.table_bytes
    }

    /// Return the validated ranges, including any empty logical slots.
    #[must_use]
    pub fn ranges(&self) -> &[SourceRange] {
        &self.ranges
    }

    /// Consume the validated table and return its ranges.
    #[must_use]
    pub fn into_ranges(self) -> Vec<SourceRange> {
        self.ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: TerminalOffsetTable = TerminalOffsetTable::new(4);

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn frozen(
        table: &[u8],
        source_len: u64,
    ) -> Result<(u64, Vec<SourceRange>), TerminalOffsetError> {
        let table_bytes = u64::from(formatkit_core::u32_at(table, 0)?);
        if !(8..=20).contains(&table_bytes)
            || !table_bytes.is_multiple_of(4)
            || table_bytes > source_len
        {
            return Err(TerminalOffsetError::InvalidTableLength);
        }
        let table_len = table_bytes as usize;
        if table.len() < table_len {
            return Err(TerminalOffsetError::TableUnavailable {
                offset: table.len(),
                needed: table_len - table.len(),
                available: 0,
            });
        }
        let word_count = table_len / 4;
        let mut offsets = Vec::with_capacity(word_count);
        for index in 0..word_count {
            let offset = u64::from(formatkit_core::u32_at(table, index * 4)?);
            if !offset.is_multiple_of(4)
                || offset < table_bytes
                || offset > source_len
                || offsets.last().is_some_and(|&prior| offset < prior)
            {
                return Err(TerminalOffsetError::InvalidOffset { index });
            }
            offsets.push(offset);
        }
        if offsets[0] != table_bytes {
            return Err(TerminalOffsetError::FirstOffsetMismatch);
        }
        if offsets[word_count - 1] != source_len {
            return Err(TerminalOffsetError::TerminalOffsetMismatch);
        }
        Ok((
            table_bytes,
            offsets
                .windows(2)
                .map(|pair| SourceRange::new(pair[0], pair[1] - pair[0]))
                .collect(),
        ))
    }

    #[test]
    fn adjacent_equal_offsets_are_retained_as_empty_ranges() {
        let validated = TABLE.validate(&words(&[16, 16, 20, 20]), 20).unwrap();
        assert_eq!(validated.table_bytes(), 16);
        assert_eq!(
            validated.ranges(),
            [
                SourceRange::new(16, 0),
                SourceRange::new(16, 4),
                SourceRange::new(20, 0),
            ]
        );
    }

    #[test]
    fn first_word_is_both_the_declaration_and_first_offset() {
        let validated = TABLE.validate(&words(&[12, 16, 20]), 20).unwrap();
        assert_eq!(validated.table_bytes(), 12);
        assert_eq!(validated.ranges()[0], SourceRange::new(12, 4));
    }

    #[test]
    fn distinct_closure_rules_remain_distinct() {
        assert_eq!(
            TABLE.validate(&words(&[8, 12]), 16),
            Err(TerminalOffsetError::TerminalOffsetMismatch)
        );
        assert_eq!(
            TABLE.validate(&words(&[8, 20]), 16),
            Err(TerminalOffsetError::InvalidOffset { index: 1 })
        );
        assert_eq!(
            TABLE.validate(&words(&[12, 16, 12]), 16),
            Err(TerminalOffsetError::InvalidOffset { index: 2 })
        );
    }

    #[test]
    fn table_declaration_and_resident_availability_are_distinct() {
        assert!(matches!(
            TABLE.declared_table_bytes(&[], 20),
            Err(TerminalOffsetError::Core(Error::Truncated { .. }))
        ));
        for value in [0, 4, 9, 24] {
            assert_eq!(
                TABLE.declared_table_bytes(&words(&[value]), 24),
                Err(TerminalOffsetError::InvalidTableLength)
            );
        }
        assert_eq!(
            TABLE.validate(&words(&[12, 16]), 20),
            Err(TerminalOffsetError::TableUnavailable {
                offset: 8,
                needed: 4,
                available: 0,
            })
        );
    }

    #[test]
    fn configuration_cannot_exceed_the_wire_table_length() {
        if usize::BITS > u32::BITS {
            let slots = u32::MAX as usize / 4 + 1;
            assert!(std::panic::catch_unwind(|| TerminalOffsetTable::new(slots)).is_err());
        }
    }

    proptest::proptest! {
        #[test]
        fn matches_frozen_mechanic_on_arbitrary_input(
            table in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
            source_len in proptest::num::u64::ANY,
        ) {
            let configured = TABLE
                .validate(&table, source_len)
                .map(|validated| (validated.table_bytes(), validated.into_ranges()));
            proptest::prop_assert_eq!(configured, frozen(&table, source_len));
        }
    }
}
