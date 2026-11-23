//! Count-prefixed `u16` cumulative-boundary tables with configurable unit scaling.
//!
//! Word zero is a `u16` entry count, followed by `count + 1` nondecreasing
//! `u16` cumulative offsets expressed in units of `unit_scale` bytes (for
//! example `1` for byte offsets or `2048` for sector offsets). Adjacent equal
//! offsets are permitted and produce empty 0-byte [`SourceRange`] slots.

use formatkit_core::{Endian, Error, SourceRange};

const WORD_BYTES: usize = 2;

/// Failure while validating a counted `u16` cumulative-boundary table.
#[derive(Debug, PartialEq, Eq)]
pub enum CountedU16BoundaryError {
    /// A checked primitive read failed.
    Core(Error),
    /// Computing `entry_count + 1` overflowed the host index width.
    BoundaryCountOverflow,
    /// Computing the directory byte extent overflowed.
    DirectoryExtentOverflow,
    /// Reserving storage for the decoded boundaries failed.
    AllocationFailed {
        /// Number of boundary entries requested.
        requested: usize,
    },
    /// Scaling a `u16` offset by `unit_scale` overflowed `u64`.
    ScaledBoundaryOverflow {
        /// Zero-based position in the boundary list.
        index: usize,
        /// Exact decoded `u16` boundary value.
        raw_value: u16,
    },
    /// A scaled boundary exceeded the supplied source length.
    BoundaryOutOfBounds {
        /// Zero-based position in the boundary list.
        index: usize,
        /// Exact decoded `u16` boundary value.
        raw_value: u16,
        /// Scaled byte offset (`raw_value * unit_scale`).
        byte_offset: u64,
        /// Total source byte length.
        source_len: u64,
    },
    /// A boundary was smaller than its predecessor.
    DecreasingBoundary {
        /// Zero-based position of the out-of-order boundary.
        index: usize,
        /// Previous raw `u16` boundary value.
        previous: u16,
        /// Current raw `u16` boundary value.
        value: u16,
    },
}

impl From<Error> for CountedU16BoundaryError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

/// A count-prefixed `u16` cumulative-boundary layout with explicit endianness
/// and byte unit scaling.
///
/// Word zero stores the `u16` slot count `N`, followed by `N + 1` nondecreasing
/// `u16` offsets. Each offset is multiplied by `unit_scale` to yield a byte
/// boundary. Equal consecutive offsets are allowed and represent empty 0-byte
/// slots. This type performs no source I/O and attaches no format semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedU16BoundaryTable {
    endian: Endian,
    unit_scale: u64,
}

impl CountedU16BoundaryTable {
    /// Configure the wire byte order and nonzero byte unit scale.
    ///
    /// Panics if `unit_scale == 0`.
    #[must_use]
    pub const fn new(endian: Endian, unit_scale: u64) -> Self {
        assert!(
            unit_scale != 0,
            "counted u16 boundary unit_scale must be nonzero"
        );
        Self { endian, unit_scale }
    }

    /// Return the configured wire byte order.
    #[must_use]
    pub const fn endian(self) -> Endian {
        self.endian
    }

    /// Return the configured nonzero byte unit scale.
    #[must_use]
    pub const fn unit_scale(self) -> u64 {
        self.unit_scale
    }

    /// Read the leading `u16` count from `prefix` and return the total encoded
    /// directory size in bytes (`2 + (count + 1) * 2`).
    pub fn declared_directory_bytes(self, prefix: &[u8]) -> Result<u64, CountedU16BoundaryError> {
        let count = usize::from(formatkit_core::u16_at_endian(prefix, 0, self.endian)?);
        let boundary_count = count
            .checked_add(1)
            .ok_or(CountedU16BoundaryError::BoundaryCountOverflow)?;
        let boundary_bytes = boundary_count
            .checked_mul(WORD_BYTES)
            .ok_or(CountedU16BoundaryError::DirectoryExtentOverflow)?;
        let directory_bytes = WORD_BYTES
            .checked_add(boundary_bytes)
            .ok_or(CountedU16BoundaryError::DirectoryExtentOverflow)?;
        Ok(directory_bytes as u64)
    }

    /// Validate a complete resident carrier where `source_len == carrier.len()`.
    pub fn validate(
        self,
        carrier: &[u8],
    ) -> Result<ValidatedCountedU16Boundaries, CountedU16BoundaryError> {
        self.validate_metadata(carrier, carrier.len() as u64)
    }

    /// Validate resident count-plus-boundaries metadata against `source_len`.
    ///
    /// Only the 2-byte count and `count + 1` `u16` boundary words need to be
    /// resident in `metadata`.
    pub fn validate_metadata(
        self,
        metadata: &[u8],
        source_len: u64,
    ) -> Result<ValidatedCountedU16Boundaries, CountedU16BoundaryError> {
        let count = usize::from(formatkit_core::u16_at_endian(metadata, 0, self.endian)?);
        let boundary_count = count
            .checked_add(1)
            .ok_or(CountedU16BoundaryError::BoundaryCountOverflow)?;
        let boundary_bytes = boundary_count
            .checked_mul(WORD_BYTES)
            .ok_or(CountedU16BoundaryError::DirectoryExtentOverflow)?;
        let directory_bytes = WORD_BYTES
            .checked_add(boundary_bytes)
            .ok_or(CountedU16BoundaryError::DirectoryExtentOverflow)?;
        formatkit_core::bytes_at(metadata, WORD_BYTES, boundary_bytes)?;

        let mut raw_boundaries = Vec::new();
        raw_boundaries
            .try_reserve_exact(boundary_count)
            .map_err(|_| CountedU16BoundaryError::AllocationFailed {
                requested: boundary_count,
            })?;
        let mut boundaries = Vec::new();
        boundaries.try_reserve_exact(boundary_count).map_err(|_| {
            CountedU16BoundaryError::AllocationFailed {
                requested: boundary_count,
            }
        })?;

        let mut previous: Option<u16> = None;
        for index in 0..boundary_count {
            let raw_value = formatkit_core::u16_at_endian(
                metadata,
                WORD_BYTES + index * WORD_BYTES,
                self.endian,
            )?;
            if let Some(prev) = previous {
                if raw_value < prev {
                    return Err(CountedU16BoundaryError::DecreasingBoundary {
                        index,
                        previous: prev,
                        value: raw_value,
                    });
                }
            }
            let byte_offset = u64::from(raw_value)
                .checked_mul(self.unit_scale)
                .ok_or(CountedU16BoundaryError::ScaledBoundaryOverflow { index, raw_value })?;
            if byte_offset > source_len {
                return Err(CountedU16BoundaryError::BoundaryOutOfBounds {
                    index,
                    raw_value,
                    byte_offset,
                    source_len,
                });
            }
            raw_boundaries.push(raw_value);
            boundaries.push(byte_offset);
            previous = Some(raw_value);
        }

        Ok(ValidatedCountedU16Boundaries {
            directory_bytes: directory_bytes as u64,
            unit_scale: self.unit_scale,
            raw_boundaries,
            boundaries,
        })
    }
}

/// Validated `u16` counted cumulative boundaries and their scaled byte ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCountedU16Boundaries {
    directory_bytes: u64,
    unit_scale: u64,
    raw_boundaries: Vec<u16>,
    boundaries: Vec<u64>,
}

impl ValidatedCountedU16Boundaries {
    /// Return the number of logical slots (`boundaries.len() - 1`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.boundaries.len().saturating_sub(1)
    }

    /// Return the byte length of the count word plus all `u16` boundary words.
    #[must_use]
    pub const fn directory_bytes(&self) -> u64 {
        self.directory_bytes
    }

    /// Return the byte unit scale applied to each raw `u16` offset.
    #[must_use]
    pub const fn unit_scale(&self) -> u64 {
        self.unit_scale
    }

    /// Return the decoded unscaled `u16` boundary words.
    #[must_use]
    pub fn raw_boundaries(&self) -> &[u16] {
        &self.raw_boundaries
    }

    /// Return the validated byte-scaled boundaries (`raw * unit_scale`).
    #[must_use]
    pub fn boundaries(&self) -> &[u64] {
        &self.boundaries
    }

    /// Iterate the slot ranges between adjacent boundaries, preserving empty
    /// 0-byte slots where consecutive boundaries are equal.
    pub fn ranges(&self) -> impl ExactSizeIterator<Item = SourceRange> + '_ {
        self.boundaries
            .windows(2)
            .map(|pair| SourceRange::new(pair[0], pair[1] - pair[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_u16s(endian: Endian, words: &[u16]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 2);
        for &w in words {
            match endian {
                Endian::Little => out.extend_from_slice(&w.to_le_bytes()),
                Endian::Big => out.extend_from_slice(&w.to_be_bytes()),
            }
        }
        out
    }

    #[test]
    fn byte_scaled_little_endian_with_empty_slots() {
        let table = CountedU16BoundaryTable::new(Endian::Little, 1);
        // 3 slots: [10..20], [20..20] (empty), [20..36]
        let meta = encode_u16s(Endian::Little, &[3, 10, 20, 20, 36]);
        assert_eq!(table.declared_directory_bytes(&meta).unwrap(), 10);

        let parsed = table.validate_metadata(&meta, 36).unwrap();
        assert_eq!(parsed.count(), 3);
        assert_eq!(parsed.directory_bytes(), 10);
        assert_eq!(parsed.unit_scale(), 1);
        assert_eq!(parsed.raw_boundaries(), &[10, 20, 20, 36]);
        assert_eq!(parsed.boundaries(), &[10, 20, 20, 36]);
        assert_eq!(
            parsed.ranges().collect::<Vec<_>>(),
            vec![
                SourceRange::new(10, 10),
                SourceRange::new(20, 0),
                SourceRange::new(20, 16),
            ]
        );
    }

    #[test]
    fn sector_scaled_big_endian_and_zero_count() {
        let table = CountedU16BoundaryTable::new(Endian::Big, 2048);
        assert_eq!(table.endian(), Endian::Big);
        assert_eq!(table.unit_scale(), 2048);

        // 2 slots across 5 sectors (10240 bytes): [0..2048], [2048..10240]
        let meta = encode_u16s(Endian::Big, &[2, 0, 1, 5]);
        let parsed = table.validate_metadata(&meta, 10_240).unwrap();
        assert_eq!(parsed.count(), 2);
        assert_eq!(parsed.boundaries(), &[0, 2048, 10_240]);
        assert_eq!(
            parsed.ranges().collect::<Vec<_>>(),
            vec![SourceRange::new(0, 2048), SourceRange::new(2048, 8192)]
        );

        // 0 slots: 1 boundary word
        let empty = encode_u16s(Endian::Big, &[0, 0]);
        let parsed_empty = table.validate_metadata(&empty, 2048).unwrap();
        assert_eq!(parsed_empty.count(), 0);
        assert_eq!(parsed_empty.ranges().len(), 0);
    }

    #[test]
    fn rejects_decreasing_out_of_bounds_overflow_and_truncated() {
        let table = CountedU16BoundaryTable::new(Endian::Little, 2048);

        // Decreasing boundary
        let dec = encode_u16s(Endian::Little, &[2, 1, 3, 2]);
        assert_eq!(
            table.validate_metadata(&dec, 10_240),
            Err(CountedU16BoundaryError::DecreasingBoundary {
                index: 2,
                previous: 3,
                value: 2,
            })
        );

        // Out of bounds after unit scaling
        let oob = encode_u16s(Endian::Little, &[1, 0, 4]);
        assert_eq!(
            table.validate_metadata(&oob, 4096),
            Err(CountedU16BoundaryError::BoundaryOutOfBounds {
                index: 1,
                raw_value: 4,
                byte_offset: 8192,
                source_len: 4096,
            })
        );

        // Truncated metadata
        let short = encode_u16s(Endian::Little, &[2, 0, 1]);
        assert!(matches!(
            table.validate_metadata(&short, 10_240),
            Err(CountedU16BoundaryError::Core(Error::Truncated { .. }))
        ));

        // Scaled overflow
        let huge = CountedU16BoundaryTable::new(Endian::Little, u64::MAX);
        let overflow_meta = encode_u16s(Endian::Little, &[1, 0, 2]);
        assert_eq!(
            huge.validate_metadata(&overflow_meta, u64::MAX),
            Err(CountedU16BoundaryError::ScaledBoundaryOverflow {
                index: 1,
                raw_value: 2,
            })
        );
    }

    #[test]
    #[should_panic(expected = "counted u16 boundary unit_scale must be nonzero")]
    fn zero_unit_scale_panics() {
        let _ = CountedU16BoundaryTable::new(Endian::Little, 0);
    }
}
