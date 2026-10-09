//! Fixed-stride rows containing unsigned offset and length fields.

use crate::{FixedRecords, U32Field};
use formatkit_core::{Endian, Result};

/// One decoded unsigned offset/length pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetLengthRow {
    /// The decoded offset, widened without assigning a coordinate system.
    pub offset: u64,
    /// The decoded length, widened without assigning extent policy.
    pub length: u64,
}

/// A statically configured fixed-stride `(offset, length)` row sequence.
///
/// This descriptor owns only row and field placement. It does not require
/// ordering, alignment, nonzero lengths, non-overlap, containment, or closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetLengthRows<const STRIDE: usize> {
    records: FixedRecords<STRIDE>,
    offset: U32Field,
    length: U32Field,
}

impl<const STRIDE: usize> OffsetLengthRows<STRIDE> {
    /// Configure the table start and two non-overlapping fields within a row.
    ///
    /// Panics if a four-byte field does not fit in `STRIDE` or the two fields
    /// overlap. These are static descriptor errors, not malformed input.
    #[must_use]
    pub const fn new(start: usize, offset_at: usize, length_at: usize, endian: Endian) -> Self {
        assert!(STRIDE >= 4, "offset/length row stride is too small");
        assert!(
            offset_at <= STRIDE - 4 && length_at <= STRIDE - 4,
            "offset/length field exceeds its row"
        );
        assert!(
            offset_at + 4 <= length_at || length_at + 4 <= offset_at,
            "offset/length fields overlap"
        );
        Self {
            records: FixedRecords::new(start),
            offset: U32Field::new(offset_at, endian),
            length: U32Field::new(length_at, endian),
        }
    }

    /// Bound and decode exactly `count` rows.
    pub fn iter<'a>(
        self,
        bytes: &'a [u8],
        count: usize,
    ) -> Result<impl ExactSizeIterator<Item = Result<OffsetLengthRow>> + 'a> {
        let offset = self.offset;
        let length = self.length;
        Ok(self.records.iter(bytes, count)?.map(move |record| {
            Ok(OffsetLengthRow {
                offset: u64::from(offset.read_record(record)),
                length: u64::from(length.read_record(record)),
            })
        }))
    }

    /// Write one precomputed offset/length pair.
    ///
    /// The complete record is bounded before either field changes, making a
    /// short-destination failure atomic. Owners retain narrowing, alignment,
    /// chaining, alias, and non-pair-field policy.
    pub fn write(self, bytes: &mut [u8], index: usize, offset: u32, length: u32) -> Result<()> {
        let record = self.records.record_array_mut(bytes, index)?;
        self.offset.write_record(record, offset);
        self.length.write_record(record, length);
        Ok(())
    }

    /// Update only the length field of a previously authorized row.
    pub fn write_length(self, bytes: &mut [u8], index: usize, length: u32) -> Result<()> {
        let record = self.records.record_array_mut(bytes, index)?;
        self.length.write_record(record, length);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use formatkit_core::Error;

    fn direct_rows(bytes: &[u8], start: usize, count: usize) -> Result<Vec<OffsetLengthRow>> {
        let width = count
            .checked_mul(8)
            .ok_or_else(|| Error::Malformed("record extent overflow".into()))?;
        let rows = formatkit_core::bytes_at(bytes, start, width)?;
        rows.chunks_exact(8)
            .map(|row| {
                Ok(OffsetLengthRow {
                    offset: u64::from(formatkit_core::u32_at(row, 0)?),
                    length: u64::from(formatkit_core::u32_at(row, 4)?),
                })
            })
            .collect()
    }

    #[test]
    fn configuration_supports_table_and_header_relative_rows() {
        let mut bytes = vec![0x55; 24];
        bytes[8..12].copy_from_slice(&16u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&24u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&5u32.to_le_bytes());
        let layout = OffsetLengthRows::<8>::new(8, 0, 4, Endian::Little);
        assert_eq!(
            layout
                .iter(&bytes, 2)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            [
                OffsetLengthRow {
                    offset: 16,
                    length: 3,
                },
                OffsetLengthRow {
                    offset: 24,
                    length: 5,
                },
            ]
        );
        assert_eq!(layout.iter(&bytes, 0).unwrap().len(), 0);
    }

    #[test]
    fn writes_support_prefixes_unaligned_fields_and_both_endians() {
        let mut little = [0xa5; 24];
        let rows = OffsetLengthRows::<9>::new(3, 1, 5, Endian::Little);
        rows.write(&mut little, 1, 0x1234_5678, 0x90ab_cdef)
            .unwrap();
        assert_eq!(&little[13..17], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&little[17..21], &0x90ab_cdefu32.to_le_bytes());
        assert!(little[..13].iter().all(|&byte| byte == 0xa5));
        assert!(little[21..].iter().all(|&byte| byte == 0xa5));

        let mut big = [0x5a; 12];
        OffsetLengthRows::<12>::new(0, 4, 8, Endian::Big)
            .write(&mut big, 0, 0x0123_4567, 0x89ab_cdef)
            .unwrap();
        assert_eq!(&big[4..8], &0x0123_4567u32.to_be_bytes());
        assert_eq!(&big[8..12], &0x89ab_cdefu32.to_be_bytes());
        assert_eq!(&big[..4], &[0x5a; 4]);
    }

    #[test]
    fn write_bounds_the_whole_record_before_mutating() {
        let rows = OffsetLengthRows::<14>::new(2, 6, 10, Endian::Little);
        let mut short = [0x55; 29];
        let before = short;
        assert_eq!(
            rows.write(&mut short, 1, 1, 2),
            Err(Error::Truncated {
                offset: 16,
                needed: 14,
                available: 13,
            })
        );
        assert_eq!(short, before);
        assert!(matches!(
            rows.write(&mut short, usize::MAX, 1, 2),
            Err(Error::Malformed(_))
        ));
        assert_eq!(short, before);
    }

    #[test]
    fn length_write_preserves_the_offset_field() {
        let rows = OffsetLengthRows::<8>::new(1, 0, 4, Endian::Little);
        let mut bytes = [0xa5; 10];
        bytes[1..5].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        rows.write_length(&mut bytes, 0, 0x90ab_cdef).unwrap();
        assert_eq!(&bytes[1..5], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&bytes[5..9], &0x90ab_cdefu32.to_le_bytes());
        assert_eq!(bytes[0], 0xa5);
        assert_eq!(bytes[9], 0xa5);
    }

    #[test]
    #[should_panic(expected = "offset/length fields overlap")]
    fn configuration_rejects_overlapping_fields() {
        let _ = OffsetLengthRows::<8>::new(0, 0, 2, Endian::Little);
    }

    #[test]
    fn configuration_rejects_short_rows_and_out_of_row_fields() {
        assert!(std::panic::catch_unwind(|| {
            OffsetLengthRows::<3>::new(0, 0, 0, Endian::Little)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            OffsetLengthRows::<8>::new(0, 0, 5, Endian::Little)
        })
        .is_err());
    }

    proptest::proptest! {
        #[test]
        fn configured_rows_match_independent_direct_reads(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..128),
            start in 0usize..32,
            count in 0usize..20,
        ) {
            let layout = OffsetLengthRows::<8>::new(start, 0, 4, Endian::Little);
            let configured = layout
                .iter(&bytes, count)
                .and_then(|rows| rows.collect::<Result<Vec<_>>>());
            proptest::prop_assert_eq!(configured, direct_rows(&bytes, start, count));
        }
    }
}
