//! Shared declarative field, offset-base, and error types for layout specs.

use core::fmt;

use formatkit_core::{Endian, Error as CoreError};

/// Unsigned integer bit width supported by declarative layout specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntWidth {
    /// 16-bit unsigned integer (2 bytes).
    U16,
    /// 24-bit unsigned integer (3 bytes).
    U24,
    /// 32-bit unsigned integer (4 bytes).
    U32,
}

impl IntWidth {
    /// Return the encoded byte length of this integer width.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::U16 => 2,
            Self::U24 => 3,
            Self::U32 => 4,
        }
    }
}

/// Declarative descriptor for an unsigned integer field inside a record or header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntFieldSpec {
    /// Byte offset of the field relative to the start of its record or header.
    pub offset: usize,
    /// Bit width of the unsigned integer.
    pub width: IntWidth,
    /// Byte order of the encoded integer.
    pub endian: Endian,
}

impl IntFieldSpec {
    /// Construct a new integer field descriptor.
    #[must_use]
    pub const fn new(offset: usize, width: IntWidth, endian: Endian) -> Self {
        Self {
            offset,
            width,
            endian,
        }
    }

    /// Construct a little-endian `u16` field descriptor at `offset`.
    #[must_use]
    pub const fn u16_le(offset: usize) -> Self {
        Self::new(offset, IntWidth::U16, Endian::Little)
    }

    /// Construct a big-endian `u16` field descriptor at `offset`.
    #[must_use]
    pub const fn u16_be(offset: usize) -> Self {
        Self::new(offset, IntWidth::U16, Endian::Big)
    }

    /// Construct a little-endian 24-bit unsigned field descriptor at `offset`.
    #[must_use]
    pub const fn u24_le(offset: usize) -> Self {
        Self::new(offset, IntWidth::U24, Endian::Little)
    }

    /// Construct a big-endian 24-bit unsigned field descriptor at `offset`.
    #[must_use]
    pub const fn u24_be(offset: usize) -> Self {
        Self::new(offset, IntWidth::U24, Endian::Big)
    }

    /// Construct a little-endian `u32` field descriptor at `offset`.
    #[must_use]
    pub const fn u32_le(offset: usize) -> Self {
        Self::new(offset, IntWidth::U32, Endian::Little)
    }

    /// Construct a big-endian `u32` field descriptor at `offset`.
    #[must_use]
    pub const fn u32_be(offset: usize) -> Self {
        Self::new(offset, IntWidth::U32, Endian::Big)
    }

    /// Return the exclusive end byte offset of this field, or `None` on overflow.
    #[must_use]
    pub const fn end_offset(self) -> Option<usize> {
        self.offset.checked_add(self.width.byte_len())
    }

    /// Decode this unsigned integer field from `bytes`.
    pub fn read(self, bytes: &[u8]) -> Result<u64, LayoutError> {
        read_int_at(bytes, self.offset, self.width, self.endian)
    }
}

/// Decode an unsigned integer of `width` and `endian` at `offset` in `bytes`.
pub(crate) fn read_int_at(
    bytes: &[u8],
    offset: usize,
    width: IntWidth,
    endian: Endian,
) -> Result<u64, LayoutError> {
    let needed = width.byte_len();
    let end = offset
        .checked_add(needed)
        .ok_or(LayoutError::Overflow { what: "field_end" })?;
    let Some(slice) = bytes.get(offset..end) else {
        return Err(LayoutError::Truncated {
            offset,
            needed,
            available: bytes.len().saturating_sub(offset),
        });
    };
    let value = match (width, endian) {
        (IntWidth::U16, Endian::Little) => u64::from(u16::from_le_bytes([slice[0], slice[1]])),
        (IntWidth::U16, Endian::Big) => u64::from(u16::from_be_bytes([slice[0], slice[1]])),
        (IntWidth::U24, Endian::Little) => {
            u64::from(slice[0]) | (u64::from(slice[1]) << 8) | (u64::from(slice[2]) << 16)
        }
        (IntWidth::U24, Endian::Big) => {
            (u64::from(slice[0]) << 16) | (u64::from(slice[1]) << 8) | u64::from(slice[2])
        }
        (IntWidth::U32, Endian::Little) => {
            u64::from(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        }
        (IntWidth::U32, Endian::Big) => {
            u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
        }
    };
    Ok(value)
}

/// Base coordinate added to scaled offsets in declarative table and array specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetBase {
    /// Offsets are absolute from byte 0 of the carrier.
    Absolute,
    /// Offsets are relative to the exclusive end of the table or offset array.
    TableEnd,
    /// Offsets are relative to a fixed base byte offset.
    Fixed(u64),
    /// Offsets are relative to the start of the record or array entry containing them.
    RecordStart,
}

impl OffsetBase {
    /// Resolve the base byte offset for a record at `record_offset` inside a
    /// table ending at `table_end`.
    pub(crate) fn resolve(self, table_end: u64, record_offset: usize) -> u64 {
        match self {
            Self::Absolute => 0,
            Self::TableEnd => table_end,
            Self::Fixed(base) => base,
            Self::RecordStart => record_offset as u64,
        }
    }
}

/// Structural and validation errors returned by declarative layout parsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// A static or caller-supplied spec parameter is invalid.
    InvalidSpec {
        /// Name of the invalid spec field.
        field: &'static str,
        /// Human-readable reason the parameter was rejected.
        reason: &'static str,
    },
    /// The input slice ended before a required table, record, array, or chunk header.
    Truncated {
        /// Byte offset where the read began.
        offset: usize,
        /// Number of bytes required.
        needed: usize,
        /// Number of bytes actually available from `offset`.
        available: usize,
    },
    /// Checked arithmetic overflowed while computing an extent, offset, or alignment.
    Overflow {
        /// Label identifying the overflowing computation.
        what: &'static str,
    },
    /// A derived payload or chunk range escaped the supplied input slice.
    OutOfBounds {
        /// Zero-based entry or chunk index.
        index: usize,
        /// Resolved byte offset.
        offset: u64,
        /// Resolved byte size.
        size: u64,
        /// Length of the supplied input slice.
        data_len: u64,
    },
    /// The input exceeded the spec's configured maximum entry or chunk limit.
    MaxEntriesExceeded {
        /// Maximum entries or chunks permitted by the spec.
        max: usize,
    },
    /// Offsets decreased when monotonic non-decreasing order was required.
    NonMonotonic {
        /// Zero-based index of the decreasing offset.
        index: usize,
        /// Previous resolved byte offset.
        previous: u64,
        /// Current resolved byte offset.
        current: u64,
    },
    /// A chunk stream step failed to strictly advance the cursor.
    ZeroAdvance {
        /// Zero-based chunk index.
        index: usize,
        /// Cursor byte offset where zero advance occurred.
        offset: usize,
    },
    /// A header-inclusive chunk declared a size smaller than `header_size`.
    SizeSmallerThanHeader {
        /// Zero-based chunk index.
        index: usize,
        /// Byte offset of the chunk header.
        offset: usize,
        /// Declared inclusive chunk size.
        declared: u64,
        /// Configured chunk header size.
        header_size: usize,
    },
    /// Trailing bytes remained when exact EOF closure was required.
    TrailingBytes {
        /// Cursor byte offset where scanning stopped.
        offset: usize,
        /// Number of unconsumed trailing bytes.
        remaining: usize,
    },
    /// Applying `count_adjust` to `count` produced a negative or unrepresentable count.
    InvalidCount {
        /// Unadjusted caller-supplied count.
        count: usize,
        /// Signed adjustment that failed.
        adjust: i32,
    },
    /// An entry name field failed its configured encoding validation.
    InvalidName {
        /// Zero-based entry index.
        index: usize,
    },
    /// Deriving table entry count from the first entry's offset failed.
    InvalidTableEnd {
        /// Resolved first-entry byte offset.
        first_offset: u64,
        /// Configured table start offset.
        table_offset: usize,
        /// Configured record stride.
        stride: usize,
    },
    /// Reserving output storage failed.
    AllocationFailed {
        /// Number of elements requested.
        requested: usize,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec { field, reason } => {
                write!(f, "invalid layout spec field `{field}`: {reason}")
            }
            Self::Truncated {
                offset,
                needed,
                available,
            } => write!(
                f,
                "truncated input at offset {offset}: needed {needed} bytes, {available} available"
            ),
            Self::Overflow { what } => write!(f, "arithmetic overflow computing {what}"),
            Self::OutOfBounds {
                index,
                offset,
                size,
                data_len,
            } => write!(
                f,
                "entry {index} range [{offset}..+{size}] exceeds data length {data_len}"
            ),
            Self::MaxEntriesExceeded { max } => {
                write!(f, "entry count exceeded configured maximum of {max}")
            }
            Self::NonMonotonic {
                index,
                previous,
                current,
            } => write!(
                f,
                "non-monotonic offset at entry {index}: {current} < {previous}"
            ),
            Self::ZeroAdvance { index, offset } => {
                write!(f, "chunk {index} at offset {offset} did not advance cursor")
            }
            Self::SizeSmallerThanHeader {
                index,
                offset,
                declared,
                header_size,
            } => write!(
                f,
                "chunk {index} at offset {offset} declared size {declared} < header size {header_size}"
            ),
            Self::TrailingBytes { offset, remaining } => {
                write!(f, "{remaining} trailing bytes remaining at offset {offset}")
            }
            Self::InvalidCount { count, adjust } => {
                write!(f, "invalid adjusted count: {count} + ({adjust})")
            }
            Self::InvalidName { index } => {
                write!(f, "invalid entry name at index {index}")
            }
            Self::InvalidTableEnd {
                first_offset,
                table_offset,
                stride,
            } => write!(
                f,
                "cannot derive record count from first offset {first_offset} with table_offset={table_offset}, stride={stride}"
            ),
            Self::AllocationFailed { requested } => {
                write!(f, "failed to reserve memory for {requested} entries")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

impl From<CoreError> for LayoutError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Truncated {
                offset,
                needed,
                available,
            } => Self::Truncated {
                offset,
                needed,
                available,
            },
            _ => Self::Overflow { what: "core_error" },
        }
    }
}
