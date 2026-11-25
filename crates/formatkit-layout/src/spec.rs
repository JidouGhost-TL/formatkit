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

    /// Return the encoded bit length of this integer width.
    #[must_use]
    pub const fn bit_len(self) -> u8 {
        (self.byte_len() * 8) as u8
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

/// Declarative descriptor for an unsigned integer field (optionally bit-shifted
/// and bit-masked) inside a record or header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntFieldSpec {
    /// Byte offset of the field relative to the start of its record or header.
    pub offset: usize,
    /// Bit width of the unsigned integer.
    pub width: IntWidth,
    /// Byte order of the encoded integer.
    pub endian: Endian,
    /// Right-shift applied to the decoded integer before masking (default `0`).
    pub bit_shift: u8,
    /// Bit mask applied after shifting (default `u64::MAX`, meaning unmasked).
    pub bit_mask: u64,
}

impl IntFieldSpec {
    /// Construct a new unmasked integer field descriptor.
    #[must_use]
    pub const fn new(offset: usize, width: IntWidth, endian: Endian) -> Self {
        Self {
            offset,
            width,
            endian,
            bit_shift: 0,
            bit_mask: u64::MAX,
        }
    }

    /// Return a copy of this field descriptor with a bit-field right-shift and mask.
    ///
    /// Reading computes `(raw >> shift) & mask`. Writing validates that the value
    /// fits within both `mask` and the remaining bits of [`IntFieldSpec::width`]
    /// above `shift`, then performs a read-modify-write so unmasked bits in the
    /// underlying word are preserved.
    #[must_use]
    pub const fn masked(mut self, shift: u8, mask: u64) -> Self {
        self.bit_shift = shift;
        self.bit_mask = mask;
        self
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

    #[inline]
    const fn is_masked(self) -> bool {
        self.bit_shift != 0 || self.bit_mask != u64::MAX
    }

    pub(crate) fn validate(self) -> Result<(), LayoutError> {
        if self.bit_shift >= self.width.bit_len() {
            return Err(LayoutError::InvalidSpec {
                field: "bit_shift",
                reason: "must be less than integer bit width",
            });
        }
        if self.bit_mask == 0 {
            return Err(LayoutError::InvalidSpec {
                field: "bit_mask",
                reason: "must be nonzero",
            });
        }
        Ok(())
    }

    /// Decode this unsigned integer field from `bytes`, applying any configured
    /// [`IntFieldSpec::bit_shift`] and [`IntFieldSpec::bit_mask`].
    pub fn read(self, bytes: &[u8]) -> Result<u64, LayoutError> {
        self.validate()?;
        let raw = read_int_at(bytes, self.offset, self.width, self.endian)?;
        Ok((raw >> self.bit_shift) & self.bit_mask)
    }

    /// Encode `value` into `bytes` at this field's offset.
    ///
    /// Validates that `value` fits in [`IntFieldSpec::width`] and [`IntFieldSpec::bit_mask`]
    /// at [`IntFieldSpec::bit_shift`]. When masked or shifted, performs a read-modify-write
    /// so unmasked bits already present in `bytes` are preserved.
    pub fn write(self, bytes: &mut [u8], value: u64) -> Result<(), LayoutError> {
        self.validate()?;
        if !self.is_masked() {
            return write_int_at(bytes, self.offset, self.width, self.endian, value);
        }
        let max_in_width = self.width.max_value() >> self.bit_shift;
        let effective_max = self.bit_mask.min(max_in_width);
        if value > effective_max || (value & !self.bit_mask) != 0 {
            return Err(LayoutError::ValueOutOfRange {
                value,
                max: effective_max,
            });
        }
        let existing = read_int_at(bytes, self.offset, self.width, self.endian)?;
        let field_mask = (self.bit_mask & max_in_width) << self.bit_shift;
        let merged = (existing & !field_mask) | ((value & self.bit_mask) << self.bit_shift);
        write_int_at(bytes, self.offset, self.width, self.endian, merged)
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

/// Base coordinate applied to scaled offsets in declarative table and array specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetBase {
    /// Offsets are absolute from byte 0 of the carrier.
    Absolute,
    /// Offsets are relative to the start of the table (`table_offset`) or offset array (`array_offset`).
    TableStart,
    /// Offsets are relative to the exclusive end of the table or offset array.
    TableEnd,
    /// Offsets are relative to the exclusive end of the table or offset array plus a fixed byte bias.
    TableEndPlus(u64),
    /// Offsets are relative to a fixed base byte offset.
    Fixed(u64),
    /// Offsets are relative to the start of the record or array entry containing them.
    RecordStart,
    /// Offsets are bus/memory addresses relocated above a fixed base address;
    /// parsing subtracts this base (`checked_sub`), and packing adds it (`checked_add`).
    SubtractBase(u64),
}

impl OffsetBase {
    /// Apply this base coordinate to a scaled offset value.
    pub(crate) fn apply(
        self,
        scaled: u64,
        table_start: u64,
        table_end: u64,
        record_offset: usize,
    ) -> Result<u64, LayoutError> {
        match self {
            Self::Absolute => Ok(scaled),
            Self::TableStart => table_start
                .checked_add(scaled)
                .ok_or(LayoutError::Overflow { what: "offset" }),
            Self::TableEnd => table_end
                .checked_add(scaled)
                .ok_or(LayoutError::Overflow { what: "offset" }),
            Self::TableEndPlus(bias) => table_end
                .checked_add(bias)
                .and_then(|base| base.checked_add(scaled))
                .ok_or(LayoutError::Overflow { what: "offset" }),
            Self::Fixed(base) => base
                .checked_add(scaled)
                .ok_or(LayoutError::Overflow { what: "offset" }),
            Self::RecordStart => (record_offset as u64)
                .checked_add(scaled)
                .ok_or(LayoutError::Overflow { what: "offset" }),
            Self::SubtractBase(base) => scaled.checked_sub(base).ok_or(LayoutError::Overflow {
                what: "offset_subtract_base",
            }),
        }
    }

    /// Encode an exact physical byte offset into a raw unscaled field value.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encode_exact(
        self,
        physical_offset: u64,
        table_start: u64,
        table_end: u64,
        record_offset: usize,
        offset_unit: u64,
        index: usize,
        reason: &'static str,
    ) -> Result<u64, LayoutError> {
        let scaled = match self {
            Self::Absolute => physical_offset,
            Self::TableStart => physical_offset
                .checked_sub(table_start)
                .ok_or(LayoutError::InvalidInput { index, reason })?,
            Self::TableEnd => physical_offset
                .checked_sub(table_end)
                .ok_or(LayoutError::InvalidInput { index, reason })?,
            Self::TableEndPlus(bias) => {
                let base = table_end
                    .checked_add(bias)
                    .ok_or(LayoutError::Overflow { what: "offset" })?;
                physical_offset
                    .checked_sub(base)
                    .ok_or(LayoutError::InvalidInput { index, reason })?
            }
            Self::Fixed(base) => physical_offset
                .checked_sub(base)
                .ok_or(LayoutError::InvalidInput { index, reason })?,
            Self::RecordStart => physical_offset
                .checked_sub(record_offset as u64)
                .ok_or(LayoutError::InvalidInput { index, reason })?,
            Self::SubtractBase(base) => {
                physical_offset
                    .checked_add(base)
                    .ok_or(LayoutError::Overflow {
                        what: "offset_add_base",
                    })?
            }
        };
        if !scaled.is_multiple_of(offset_unit) {
            return Err(LayoutError::InvalidInput { index, reason });
        }
        Ok(scaled / offset_unit)
    }

    /// Align `cursor` upward to satisfy both `data_alignment` and encodability
    /// under this base and `offset_unit`, returning `(physical_offset, raw_offset)`.
    pub(crate) fn align_and_encode(
        self,
        cursor: u64,
        table_start: u64,
        table_end: u64,
        record_offset: usize,
        data_alignment: usize,
        offset_unit: u64,
    ) -> Result<(u64, u64), LayoutError> {
        match self {
            Self::Absolute
            | Self::TableStart
            | Self::TableEnd
            | Self::TableEndPlus(_)
            | Self::Fixed(_)
            | Self::RecordStart => {
                let base = match self {
                    Self::Absolute => 0,
                    Self::TableStart => table_start,
                    Self::TableEnd => table_end,
                    Self::TableEndPlus(bias) => table_end
                        .checked_add(bias)
                        .ok_or(LayoutError::Overflow { what: "offset" })?,
                    Self::Fixed(b) => b,
                    Self::RecordStart => record_offset as u64,
                    Self::SubtractBase(_) => unreachable!(),
                };
                let pos = align_payload_offset(cursor, base, data_alignment, offset_unit)?;
                Ok((pos, (pos - base) / offset_unit))
            }
            Self::SubtractBase(sub) => {
                let mut pos = align_payload_offset(cursor, 0, data_alignment, 1)?;
                let mut scaled = pos.checked_add(sub).ok_or(LayoutError::Overflow {
                    what: "offset_add_base",
                })?;
                if offset_unit > 1 {
                    let rem = scaled % offset_unit;
                    if rem != 0 {
                        let bump = offset_unit - rem;
                        pos = pos.checked_add(bump).ok_or(LayoutError::Overflow {
                            what: "offset_unit_alignment",
                        })?;
                        scaled = scaled.checked_add(bump).ok_or(LayoutError::Overflow {
                            what: "offset_add_base",
                        })?;
                    }
                }
                Ok((pos, scaled / offset_unit))
            }
        }
    }
}

/// Round `value` upward to the next multiple of `align` (which must be `>= 1`).
pub(crate) fn checked_align_up_multiple_u64(value: u64, align: u64) -> Option<u64> {
    if align == 0 {
        return None;
    }
    if align == 1 {
        return Some(value);
    }
    let rem = value % align;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(align - rem)
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
    fn int_field_spec_masked_read_modify_write_preserves_unmasked_bits() {
        // High 4-bit flags + 28-bit size in one u32le
        let size_field = IntFieldSpec::u32_le(0).masked(0, 0x0FFF_FFFF);
        let flag_field = IntFieldSpec::u32_le(0).masked(28, 0x0F);

        let mut word = 0xA000_0000u32.to_le_bytes();
        size_field.write(&mut word, 0x0123_4567).unwrap();
        assert_eq!(u32::from_le_bytes(word), 0xA123_4567);
        assert_eq!(size_field.read(&word).unwrap(), 0x0123_4567);
        assert_eq!(flag_field.read(&word).unwrap(), 0x0A);

        // Update flags without clobbering size
        flag_field.write(&mut word, 0x05).unwrap();
        assert_eq!(u32::from_le_bytes(word), 0x5123_4567);
        assert_eq!(size_field.read(&word).unwrap(), 0x0123_4567);
        assert_eq!(flag_field.read(&word).unwrap(), 0x05);

        // Packed 20-bit offset + 12-bit sector count in one u32le
        let off_field = IntFieldSpec::u32_le(0).masked(0, 0x000F_FFFF);
        let cnt_field = IntFieldSpec::u32_le(0).masked(20, 0x0FFF);
        let mut packed = [0u8; 4];
        off_field.write(&mut packed, 0x000A_BCDE).unwrap();
        cnt_field.write(&mut packed, 0x0321).unwrap();
        assert_eq!(off_field.read(&packed).unwrap(), 0x000A_BCDE);
        assert_eq!(cnt_field.read(&packed).unwrap(), 0x0321);

        // Reject values exceeding bit_mask or width
        assert_eq!(
            size_field.write(&mut word, 0x1000_0000),
            Err(LayoutError::ValueOutOfRange {
                value: 0x1000_0000,
                max: 0x0FFF_FFFF,
            })
        );
        assert_eq!(
            cnt_field.write(&mut packed, 0x1000),
            Err(LayoutError::ValueOutOfRange {
                value: 0x1000,
                max: 0x0FFF,
            })
        );

        // Reject invalid shift or zero mask
        assert!(matches!(
            IntFieldSpec::u32_le(0).masked(32, 1).read(&packed),
            Err(LayoutError::InvalidSpec {
                field: "bit_shift",
                ..
            })
        ));
        assert!(matches!(
            IntFieldSpec::u32_le(0).masked(0, 0).read(&packed),
            Err(LayoutError::InvalidSpec {
                field: "bit_mask",
                ..
            })
        ));
    }

    #[test]
    fn offset_base_subtract_base_round_trips_and_rejects_underflow() {
        let base = OffsetBase::SubtractBase(0x0800_0000);
        assert_eq!(base.apply(0x0800_0040, 0, 0, 0).unwrap(), 0x40);
        assert_eq!(
            base.apply(0x07FF_FFFF, 0, 0, 0),
            Err(LayoutError::Overflow {
                what: "offset_subtract_base"
            })
        );
        let (phys, raw) = base.align_and_encode(0x31, 0, 0, 0, 4, 1).unwrap();
        assert_eq!(phys, 0x34);
        assert_eq!(raw, 0x0800_0034);
        assert_eq!(base.apply(raw, 0, 0, 0).unwrap(), phys);
    }

    #[test]
    fn offset_base_table_start_and_table_end_plus_round_trip_and_overflow() {
        let ts = OffsetBase::TableStart;
        assert_eq!(ts.apply(0x20, 0x100, 0x140, 0x100).unwrap(), 0x120);
        let (phys, raw) = ts
            .align_and_encode(0x142, 0x100, 0x140, 0x100, 4, 2)
            .unwrap();
        assert_eq!(phys, 0x144);
        assert_eq!(raw, 0x22);
        assert_eq!(ts.apply(raw * 2, 0x100, 0x140, 0x100).unwrap(), phys);
        assert_eq!(
            ts.apply(u64::MAX, 1, 0, 0),
            Err(LayoutError::Overflow { what: "offset" })
        );

        let tep = OffsetBase::TableEndPlus(16);
        assert_eq!(tep.apply(8, 0x10, 0x40, 0x10).unwrap(), 0x58);
        let (phys2, raw2) = tep.align_and_encode(0x40, 0x10, 0x40, 0x10, 1, 1).unwrap();
        assert_eq!(phys2, 0x50);
        assert_eq!(raw2, 0);
        assert_eq!(tep.apply(raw2, 0x10, 0x40, 0x10).unwrap(), phys2);
        assert_eq!(
            OffsetBase::TableEndPlus(u64::MAX).apply(0, 0, 1, 0),
            Err(LayoutError::Overflow { what: "offset" })
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
