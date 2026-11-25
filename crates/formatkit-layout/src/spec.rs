//! Shared declarative field, offset-base, pack-policy, and error types for layout specs.

use core::fmt;

use formatkit_core::{Endian, Error as CoreError};

/// Unsigned integer bit width supported by declarative layout specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntWidth {
    /// 8-bit unsigned integer (1 byte).
    U8,
    /// 16-bit unsigned integer (2 bytes).
    U16,
    /// 24-bit unsigned integer (3 bytes).
    U24,
    /// 32-bit unsigned integer (4 bytes).
    U32,
    /// 64-bit unsigned integer (8 bytes).
    U64,
}

impl IntWidth {
    /// Return the encoded byte length of this integer width.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 => 3,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }

    /// Return the maximum unsigned value representable by this integer width.
    #[must_use]
    pub const fn max_value(self) -> u64 {
        match self {
            Self::U8 => u8::MAX as u64,
            Self::U16 => u16::MAX as u64,
            Self::U24 => 0x00FF_FFFF,
            Self::U32 => u32::MAX as u64,
            Self::U64 => u64::MAX,
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

    /// Construct a single-byte `u8` field descriptor at `offset`.
    #[must_use]
    pub const fn u8(offset: usize) -> Self {
        Self::new(offset, IntWidth::U8, Endian::Little)
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

    /// Construct a little-endian `u64` field descriptor at `offset`.
    #[must_use]
    pub const fn u64_le(offset: usize) -> Self {
        Self::new(offset, IntWidth::U64, Endian::Little)
    }

    /// Construct a big-endian `u64` field descriptor at `offset`.
    #[must_use]
    pub const fn u64_be(offset: usize) -> Self {
        Self::new(offset, IntWidth::U64, Endian::Big)
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

    /// Encode `value` into `bytes` at this field's offset, validating that
    /// `value` fits in [`IntFieldSpec::width`].
    pub fn write(self, bytes: &mut [u8], value: u64) -> Result<(), LayoutError> {
        write_int_at(bytes, self.offset, self.width, self.endian, value)
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
        (IntWidth::U8, _) => u64::from(slice[0]),
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
        (IntWidth::U64, Endian::Little) => u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
        (IntWidth::U64, Endian::Big) => u64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
    };
    Ok(value)
}

/// Encode an unsigned integer of `width` and `endian` at `offset` in `bytes`.
pub(crate) fn write_int_at(
    bytes: &mut [u8],
    offset: usize,
    width: IntWidth,
    endian: Endian,
    value: u64,
) -> Result<(), LayoutError> {
    let max = width.max_value();
    if value > max {
        return Err(LayoutError::ValueOutOfRange { value, max });
    }
    let needed = width.byte_len();
    let end = offset
        .checked_add(needed)
        .ok_or(LayoutError::Overflow { what: "field_end" })?;
    let available = bytes.len().saturating_sub(offset);
    let Some(slice) = bytes.get_mut(offset..end) else {
        return Err(LayoutError::Truncated {
            offset,
            needed,
            available,
        });
    };
    match (width, endian) {
        (IntWidth::U8, _) => {
            slice[0] = value as u8;
        }
        (IntWidth::U16, Endian::Little) => {
            slice.copy_from_slice(&(value as u16).to_le_bytes());
        }
        (IntWidth::U16, Endian::Big) => {
            slice.copy_from_slice(&(value as u16).to_be_bytes());
        }
        (IntWidth::U24, Endian::Little) => {
            slice[0] = (value & 0xFF) as u8;
            slice[1] = ((value >> 8) & 0xFF) as u8;
            slice[2] = ((value >> 16) & 0xFF) as u8;
        }
        (IntWidth::U24, Endian::Big) => {
            slice[0] = ((value >> 16) & 0xFF) as u8;
            slice[1] = ((value >> 8) & 0xFF) as u8;
            slice[2] = (value & 0xFF) as u8;
        }
        (IntWidth::U32, Endian::Little) => {
            slice.copy_from_slice(&(value as u32).to_le_bytes());
        }
        (IntWidth::U32, Endian::Big) => {
            slice.copy_from_slice(&(value as u32).to_be_bytes());
        }
        (IntWidth::U64, Endian::Little) => {
            slice.copy_from_slice(&value.to_le_bytes());
        }
        (IntWidth::U64, Endian::Big) => {
            slice.copy_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
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

/// Serialization policy controlling alignment and fill bytes for declarative layout writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackPolicy {
    /// Byte alignment applied to payload starts (must be `>= 1`).
    pub data_alignment: usize,
    /// Byte value used to fill alignment gaps and trailing padding.
    pub pad_byte: u8,
    /// Byte value used to initialize newly allocated records or chunk headers when no template is supplied.
    pub record_fill_byte: u8,
    /// Whether to pad the final entry's end up to `data_alignment` (or chunk stream alignment).
    pub pad_final_entry: bool,
    /// Byte value used to pad `header_prefix` up to the table, array, or stream start offset.
    pub prefix_fill_byte: u8,
}

impl PackPolicy {
    /// Tight, unaligned packing with zero-filled gaps, records, and prefix padding.
    pub const TIGHT: Self = Self {
        data_alignment: 1,
        pad_byte: 0,
        record_fill_byte: 0,
        pad_final_entry: false,
        prefix_fill_byte: 0,
    };

    pub(crate) fn validate(&self) -> Result<(), LayoutError> {
        if self.data_alignment == 0 {
            return Err(LayoutError::InvalidSpec {
                field: "data_alignment",
                reason: "must be nonzero",
            });
        }
        Ok(())
    }
}

impl Default for PackPolicy {
    fn default() -> Self {
        Self::TIGHT
    }
}

/// Align `cursor` upward to satisfy both `data_alignment` (absolute) and
/// `(cursor - base) % offset_unit == 0` with `cursor >= base`.
pub(crate) fn align_payload_offset(
    cursor: u64,
    base: u64,
    data_alignment: usize,
    offset_unit: u64,
) -> Result<u64, LayoutError> {
    let align_u64 = data_alignment as u64;
    let mut pos = cursor.max(base);
    if align_u64 > 1 {
        let rem = pos % align_u64;
        if rem != 0 {
            pos = pos
                .checked_add(align_u64 - rem)
                .ok_or(LayoutError::Overflow {
                    what: "data_alignment",
                })?;
        }
    }
    if offset_unit > 1 {
        let rel = pos - base;
        let rem = rel % offset_unit;
        if rem != 0 {
            pos = pos
                .checked_add(offset_unit - rem)
                .ok_or(LayoutError::Overflow {
                    what: "offset_unit_alignment",
                })?;
        }
    }
    Ok(pos)
}

/// Structural and validation errors returned by declarative layout parsers and writers.
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
    /// A derived payload or chunk range escaped the supplied input slice or carrier length.
    OutOfBounds {
        /// Zero-based entry or chunk index.
        index: usize,
        /// Resolved byte offset.
        offset: u64,
        /// Resolved byte size.
        size: u64,
        /// Length of the supplied input slice or carrier.
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
    /// An entry name field failed its configured encoding or capacity validation.
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
    /// An encoded integer value exceeded the target [`IntWidth`] maximum.
    ValueOutOfRange {
        /// Value that could not be encoded.
        value: u64,
        /// Maximum representable value for the target integer width.
        max: u64,
    },
    /// A caller-supplied writer input violated the target layout spec.
    InvalidInput {
        /// Zero-based entry or chunk index associated with the failure.
        index: usize,
        /// Human-readable reason the input was rejected.
        reason: &'static str,
    },
    /// An underlying [`formatkit_core::Error`].
    Core(CoreError),
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
            Self::ValueOutOfRange { value, max } => {
                write!(f, "value {value} exceeds maximum representable value {max}")
            }
            Self::InvalidInput { index, reason } => {
                write!(f, "invalid writer input at index {index}: {reason}")
            }
            Self::Core(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl core::error::Error for LayoutError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Core(err) => Some(err),
            _ => None,
        }
    }
}

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
            other => Self::Core(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_field_spec_reads_and_writes_all_widths_and_rejects_out_of_range() {
        let mut buf = [0u8; 16];

        IntFieldSpec::u8(0).write(&mut buf, 0xAB).unwrap();
        assert_eq!(IntFieldSpec::u8(0).read(&buf).unwrap(), 0xAB);
        assert_eq!(
            IntFieldSpec::u8(0).write(&mut buf, 0x100),
            Err(LayoutError::ValueOutOfRange {
                value: 0x100,
                max: 0xFF
            })
        );

        IntFieldSpec::u16_le(1).write(&mut buf, 0x1234).unwrap();
        assert_eq!(IntFieldSpec::u16_le(1).read(&buf).unwrap(), 0x1234);
        IntFieldSpec::u16_be(1).write(&mut buf, 0x1234).unwrap();
        assert_eq!(IntFieldSpec::u16_be(1).read(&buf).unwrap(), 0x1234);

        IntFieldSpec::u24_le(3)
            .write(&mut buf, 0x00AB_CDEF)
            .unwrap();
        assert_eq!(IntFieldSpec::u24_le(3).read(&buf).unwrap(), 0x00AB_CDEF);
        IntFieldSpec::u24_be(3)
            .write(&mut buf, 0x00AB_CDEF)
            .unwrap();
        assert_eq!(IntFieldSpec::u24_be(3).read(&buf).unwrap(), 0x00AB_CDEF);
        assert_eq!(
            IntFieldSpec::u24_le(3).write(&mut buf, 0x0100_0000),
            Err(LayoutError::ValueOutOfRange {
                value: 0x0100_0000,
                max: 0x00FF_FFFF
            })
        );

        IntFieldSpec::u32_le(4)
            .write(&mut buf, 0xDEAD_BEEF)
            .unwrap();
        assert_eq!(IntFieldSpec::u32_le(4).read(&buf).unwrap(), 0xDEAD_BEEF);
        IntFieldSpec::u32_be(4)
            .write(&mut buf, 0xDEAD_BEEF)
            .unwrap();
        assert_eq!(IntFieldSpec::u32_be(4).read(&buf).unwrap(), 0xDEAD_BEEF);

        IntFieldSpec::u64_le(8)
            .write(&mut buf, 0x0123_4567_89AB_CDEF)
            .unwrap();
        assert_eq!(
            IntFieldSpec::u64_le(8).read(&buf).unwrap(),
            0x0123_4567_89AB_CDEF
        );
        IntFieldSpec::u64_be(8)
            .write(&mut buf, 0x0123_4567_89AB_CDEF)
            .unwrap();
        assert_eq!(
            IntFieldSpec::u64_be(8).read(&buf).unwrap(),
            0x0123_4567_89AB_CDEF
        );
    }

    #[test]
    fn from_core_error_preserves_detail() {
        let core_err = CoreError::BadMagic {
            offset: 4,
            expected: 0x1122_3344,
            found: 0x5566_7788,
        };
        let layout_err = LayoutError::from(core_err.clone());
        assert_eq!(layout_err, LayoutError::Core(core_err));
    }
}
