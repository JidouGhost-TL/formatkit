//! Configured fixed-width regions within resident byte layouts.

use formatkit_core::{bytes_at, bytes_at_mut, Error, Result};

/// The arithmetic stage that overflowed while deriving a record-region end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOverflow {
    /// `count * WIDTH` overflowed.
    Count,
    /// Adding the configured region start overflowed.
    End,
}

/// A fixed-width record region.
///
/// This descriptor bounds and iterates records only. The format owner retains
/// the count source, count limits, record meaning, and trailing-byte policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRecords<const WIDTH: usize> {
    start: usize,
}

impl<const WIDTH: usize> FixedRecords<WIDTH> {
    /// Configure a record region beginning at `start`.
    ///
    /// Panics when `WIDTH` is zero. Since `WIDTH` is a const generic, that is a
    /// static descriptor error rather than malformed input.
    #[must_use]
    pub const fn new(start: usize) -> Self {
        assert!(WIDTH != 0, "record width must be nonzero");
        Self { start }
    }

    /// Return the exclusive end of `count` records.
    #[inline(always)]
    pub fn end(self, count: usize) -> std::result::Result<usize, RecordOverflow> {
        let size = count.checked_mul(WIDTH).ok_or(RecordOverflow::Count)?;
        self.start.checked_add(size).ok_or(RecordOverflow::End)
    }

    /// Bound and iterate exactly `count` records.
    #[inline(always)]
    pub fn iter(
        self,
        bytes: &[u8],
        count: usize,
    ) -> Result<impl ExactSizeIterator<Item = &[u8; WIDTH]>> {
        let end = self
            .end(count)
            .map_err(|_| Error::Malformed("record extent overflow".into()))?;
        let records = bytes_at(bytes, self.start, end - self.start)?;
        Ok(records.chunks_exact(WIDTH).map(|r| r.try_into().unwrap()))
    }

    /// Mutably bound and iterate exactly `count` records.
    ///
    /// The complete region is checked before the iterator is returned, so a
    /// bounds failure cannot expose a partial record run for mutation.
    #[inline(always)]
    pub fn iter_mut(
        self,
        bytes: &mut [u8],
        count: usize,
    ) -> Result<impl ExactSizeIterator<Item = &mut [u8; WIDTH]>> {
        let end = self
            .end(count)
            .map_err(|_| Error::Malformed("record extent overflow".into()))?;
        let records = bytes_at_mut(bytes, self.start, end - self.start)?;
        Ok(records
            .chunks_exact_mut(WIDTH)
            .map(|record| record.try_into().unwrap()))
    }

    /// Bound one record without imposing a logical record count.
    ///
    /// The owner must authorize `index` before calling when logical count is
    /// part of its public contract.
    #[inline(always)]
    pub fn record(self, bytes: &[u8], index: usize) -> Result<&[u8; WIDTH]> {
        let start = self
            .end(index)
            .map_err(|_| Error::Malformed("record offset overflow".into()))?;
        Ok(bytes_at(bytes, start, WIDTH)?.try_into().unwrap())
    }

    /// Mutably bound one record without imposing a logical record count.
    #[inline(always)]
    pub fn record_array_mut(self, bytes: &mut [u8], index: usize) -> Result<&mut [u8; WIDTH]> {
        let start = self
            .end(index)
            .map_err(|_| Error::Malformed("record offset overflow".into()))?;
        Ok(bytes_at_mut(bytes, start, WIDTH)?.try_into().unwrap())
    }

    /// Mutably bound one record as a byte slice.
    #[inline(always)]
    pub fn record_mut(self, bytes: &mut [u8], index: usize) -> Result<&mut [u8]> {
        Ok(self.record_array_mut(bytes, index)?.as_mut_slice())
    }

    /// Replace one complete record without changing surrounding bytes.
    ///
    /// The destination is bounded before it is mutated. The owner remains
    /// responsible for authorizing the index and validating record semantics.
    #[inline(always)]
    pub fn write_record(self, bytes: &mut [u8], index: usize, record: &[u8; WIDTH]) -> Result<()> {
        self.record_array_mut(bytes, index)?.copy_from_slice(record);
        Ok(())
    }

    /// Create one explicitly initialized record for owner-directed emission.
    ///
    /// This assigns no padding or reserved-byte meaning to `fill`; the format
    /// owner must select the value and populate all semantically required
    /// fields before writing the record.
    #[must_use]
    pub const fn initialized_record(self, fill: u8) -> [u8; WIDTH] {
        [fill; WIDTH]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_empty_regions_and_overflow_are_checked() {
        let layout = FixedRecords::<8>::new(4);
        assert_eq!(layout.end(0), Ok(4));
        assert_eq!(layout.end(2), Ok(20));
        assert_eq!(layout.end(usize::MAX), Err(RecordOverflow::Count));
        assert_eq!(
            FixedRecords::<1>::new(usize::MAX).end(1),
            Err(RecordOverflow::End)
        );
        assert!(layout.iter(&[0; 3], 0).is_err());
        assert_eq!(layout.iter(&[0; 4], 0).unwrap().len(), 0);
        assert!(layout.iter(&[0; 11], 1).is_err());
        assert_eq!(layout.iter(&[0; 12], 1).unwrap().len(), 1);
    }

    #[test]
    fn typed_record_lookups_cover_every_prefix_and_preserve_mutation() {
        const RECORDS: FixedRecords<8> = FixedRecords::new(3);
        let source: [u8; 27] = std::array::from_fn(|index| index as u8);
        for index in 0..=3 {
            let start = 3 + index * 8;
            for len in 0..=source.len() {
                let mut bytes = source[..len].to_vec();
                let mut slice_bytes = bytes.clone();
                if len < start + 8 {
                    let expected = Error::Truncated {
                        offset: start,
                        needed: 8,
                        available: len.saturating_sub(start),
                    };
                    assert_eq!(RECORDS.record(&bytes, index).unwrap_err(), expected);
                    assert_eq!(
                        RECORDS.record_array_mut(&mut bytes, index).unwrap_err(),
                        expected
                    );
                    assert_eq!(
                        RECORDS.record_mut(&mut slice_bytes, index).unwrap_err(),
                        expected
                    );
                    assert_eq!(bytes, source[..len]);
                    assert_eq!(slice_bytes, bytes);
                } else {
                    let record: &[u8; 8] = RECORDS.record(&bytes, index).unwrap();
                    assert_eq!(record.as_slice(), &source[start..start + 8]);
                    assert_eq!(record.as_ptr(), bytes[start..].as_ptr());
                    RECORDS
                        .record_array_mut(&mut bytes, index)
                        .unwrap()
                        .fill(0xa5);
                    RECORDS
                        .record_mut(&mut slice_bytes, index)
                        .unwrap()
                        .fill(0xa5);
                    assert_eq!(&bytes[..start], &source[..start]);
                    assert_eq!(&bytes[start..start + 8], &[0xa5; 8]);
                    assert_eq!(&bytes[start + 8..], &source[start + 8..len]);
                    assert_eq!(bytes, slice_bytes);
                }
            }
        }
    }

    #[test]
    fn mutable_iteration_bounds_the_whole_region_before_exposing_records() {
        const RECORDS: FixedRecords<3> = FixedRecords::new(2);
        let mut bytes = [0x55; 9];
        for (index, record) in RECORDS.iter_mut(&mut bytes, 2).unwrap().enumerate() {
            record.fill(index as u8 + 1);
        }
        assert_eq!(bytes, [0x55, 0x55, 1, 1, 1, 2, 2, 2, 0x55]);

        let mut short = [0x55; 7];
        let original = short;
        assert!(RECORDS.iter_mut(&mut short, 2).is_err());
        assert_eq!(short, original);
    }

    #[test]
    fn complete_record_writes_are_bounded_and_initialization_is_explicit() {
        const RECORDS: FixedRecords<4> = FixedRecords::new(1);
        const FILLED: [u8; 4] = RECORDS.initialized_record(0xa5);
        assert_eq!(FILLED, [0xa5; 4]);

        let mut bytes = [0x55; 6];
        RECORDS.write_record(&mut bytes, 0, b"ABCD").unwrap();
        assert_eq!(bytes, [0x55, b'A', b'B', b'C', b'D', 0x55]);

        let mut short = [0x55; 4];
        let original = short;
        assert!(RECORDS.write_record(&mut short, 0, &FILLED).is_err());
        assert_eq!(short, original);
        assert!(RECORDS
            .write_record(&mut bytes, usize::MAX, &FILLED)
            .is_err());
        assert_eq!(bytes, [0x55, b'A', b'B', b'C', b'D', 0x55]);
    }

    fn assert_record_lookup_error<const WIDTH: usize>(
        records: FixedRecords<WIDTH>,
        index: usize,
        expected: Error,
    ) {
        let mut bytes = [0x55; 9];
        assert_eq!(records.record(&bytes, index).unwrap_err(), expected);
        assert_eq!(
            records.record_array_mut(&mut bytes, index).unwrap_err(),
            expected
        );
        assert_eq!(records.record_mut(&mut bytes, index).unwrap_err(), expected);
        assert_eq!(bytes, [0x55; 9]);
    }

    #[test]
    fn lookup_keeps_arithmetic_and_bounds_failures_distinct() {
        assert_record_lookup_error(
            FixedRecords::<8>::new(3),
            usize::MAX,
            Error::Malformed("record offset overflow".into()),
        );
        assert_record_lookup_error(
            FixedRecords::<1>::new(usize::MAX),
            1,
            Error::Malformed("record offset overflow".into()),
        );
        assert_record_lookup_error(
            FixedRecords::<1>::new(0),
            usize::MAX,
            Error::Truncated {
                offset: usize::MAX,
                needed: 1,
                available: 0,
            },
        );
        assert_record_lookup_error(
            FixedRecords::<8>::new(usize::MAX - 3),
            0,
            Error::Truncated {
                offset: usize::MAX - 3,
                needed: 8,
                available: 0,
            },
        );
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_spans_match_independent_wide_arithmetic(
            start in proptest::num::usize::ANY,
            count in proptest::num::usize::ANY,
        ) {
            let expected = start as u128 + count as u128 * 48;
            let actual = FixedRecords::<48>::new(start).end(count);
            proptest::prop_assert_eq!(actual.ok(), usize::try_from(expected).ok());
        }
    }

    #[test]
    #[should_panic(expected = "record width must be nonzero")]
    fn zero_width_configuration_is_invalid() {
        let _ = FixedRecords::<0>::new(0);
    }
}
