//! Declarative fixed-stride record table specification and checked parser.
//!
//! [`FixedRecordTableSpec`] describes fixed-stride directory tables with
//! configurable integer widths (`u16`/`u24`/`u32`), endianness, optional
//! embedded names, offset base/unit scaling, size derivation modes, and table
//! termination rules.

use crate::spec::{IntFieldSpec, LayoutError, OffsetBase};

/// How an embedded fixed-width name field is trimmed and validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameEncoding {
    /// Truncate at the first NUL byte (`0x00`), keeping the preceding raw bytes.
    NulTerminated,
    /// Truncate at the first NUL byte (`0x00`), then trim trailing ASCII spaces (`0x20`).
    NulOrSpacePadded,
    /// Truncate at the first NUL byte (`0x00`), trim trailing ASCII spaces (`0x20`),
    /// and require every remaining byte to be ASCII (`0x00..=0x7F`).
    Ascii,
}

/// Declarative descriptor for an embedded fixed-width name field inside each record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameFieldSpec {
    /// Byte offset of the name field within each record.
    pub offset: usize,
    /// Fixed byte length of the name field within each record.
    pub len: usize,
    /// Trimming and validation rule applied to the raw name bytes.
    pub encoding: NameEncoding,
}

impl NameFieldSpec {
    /// Construct a new embedded name field descriptor.
    #[must_use]
    pub const fn new(offset: usize, len: usize, encoding: NameEncoding) -> Self {
        Self {
            offset,
            len,
            encoding,
        }
    }

    /// Return the exclusive end byte offset of this field, or `None` on overflow.
    #[must_use]
    pub const fn end_offset(self) -> Option<usize> {
        self.offset.checked_add(self.len)
    }

    fn decode(self, record: &[u8], index: usize) -> Result<Vec<u8>, LayoutError> {
        let end = self
            .end_offset()
            .ok_or(LayoutError::Overflow { what: "name_end" })?;
        let slice = record.get(self.offset..end).ok_or(LayoutError::Truncated {
            offset: self.offset,
            needed: self.len,
            available: record.len().saturating_sub(self.offset),
        })?;
        let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        let mut trimmed = &slice[..nul_pos];
        match self.encoding {
            NameEncoding::NulTerminated => {}
            NameEncoding::NulOrSpacePadded => {
                while let Some(&last) = trimmed.last() {
                    if last == b' ' {
                        trimmed = &trimmed[..trimmed.len() - 1];
                    } else {
                        break;
                    }
                }
            }
            NameEncoding::Ascii => {
                while let Some(&last) = trimmed.last() {
                    if last == b' ' {
                        trimmed = &trimmed[..trimmed.len() - 1];
                    } else {
                        break;
                    }
                }
                if !trimmed.is_ascii() {
                    return Err(LayoutError::InvalidName { index });
                }
            }
        }
        Ok(trimmed.to_vec())
    }
}

/// Rule determining how each record's payload size is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMode {
    /// Each record stores an explicit size field (scaled by [`FixedRecordTableSpec::size_unit`]).
    Stored(IntFieldSpec),
    /// Entry `i` spans `[offset[i], offset[i + 1])` with the last entry ending at `data.len()`.
    /// Requires non-decreasing resolved offsets.
    NextOffset,
    /// Each record's `offset_field` stores a size (scaled by `offset_unit`), and
    /// entry offsets accumulate contiguously starting from the given byte offset.
    CumulativeFrom(u64),
    /// Every entry has a constant byte size. When `offset_field` is `None`,
    /// entry `i` starts at `base + i * slot_size`.
    FixedSlot(u64),
}

/// Rule determining where a fixed-stride record table terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableTermination {
    /// Table contains an explicit number of records.
    Counted(usize),
    /// Table terminates at the first record whose bytes are all `0x00`.
    ZeroRow,
    /// Table terminates at the first record whose first byte is `0x00`.
    FirstByteZero,
    /// Table length is derived from the first record's resolved byte offset:
    /// `count = (first_offset - table_offset) / stride`.
    FirstOffsetDerived,
    /// Table extends to the end of the input slice (complete records of `stride` bytes).
    Eof,
}

/// `const`-constructible declarative specification for a fixed-stride record table.
///
/// # Example
/// ```
/// use formatkit_core::Endian;
/// use formatkit_layout::{
///     parse_fixed_record_table, FixedRecordTableSpec, IntFieldSpec, NameEncoding, NameFieldSpec,
///     OffsetBase, SizeMode, TableTermination,
/// };
///
/// const SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
///     stride: 16,
///     table_offset: 0,
///     max_entries: 64,
///     name_field: Some(NameFieldSpec::new(0, 8, NameEncoding::Ascii)),
///     offset_field: Some(IntFieldSpec::u32_le(8)),
///     offset_base: OffsetBase::Absolute,
///     offset_unit: 1,
///     size_mode: SizeMode::Stored(IntFieldSpec::u32_le(12)),
///     size_unit: 1,
///     termination: TableTermination::Counted(1),
/// };
///
/// let mut data = Vec::new();
/// data.extend_from_slice(b"item0\0\0\0");
/// data.extend_from_slice(&16u32.to_le_bytes());
/// data.extend_from_slice(&4u32.to_le_bytes());
/// data.extend_from_slice(b"BODY");
///
/// let entries = parse_fixed_record_table(&data, &SPEC).unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].name_str(), Some("item0"));
/// assert_eq!(entries[0].offset, 16);
/// assert_eq!(entries[0].size, 4);
/// assert_eq!(entries[0].payload(&data), Some(&b"BODY"[..]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRecordTableSpec {
    /// Fixed byte stride of each record (must be `>= 1`).
    pub stride: usize,
    /// Byte offset where the first record begins in the carrier.
    pub table_offset: usize,
    /// Maximum number of entries accepted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_entries: usize,
    /// Optional embedded fixed-width name field inside each record.
    pub name_field: Option<NameFieldSpec>,
    /// Optional integer field carrying the entry offset (or size in [`SizeMode::CumulativeFrom`]).
    pub offset_field: Option<IntFieldSpec>,
    /// Base coordinate added to scaled offsets.
    pub offset_base: OffsetBase,
    /// Non-zero byte multiplier applied to decoded offset values (e.g. `1` or `2048`).
    pub offset_unit: u64,
    /// How each entry's payload size is determined.
    pub size_mode: SizeMode,
    /// Non-zero byte multiplier applied to [`SizeMode::Stored`] size values.
    pub size_unit: u64,
    /// How the number of records in the table is determined.
    pub termination: TableTermination,
}

/// One validated entry decoded from a [`FixedRecordTableSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedRecordEntry {
    /// Zero-based entry index in the table.
    pub index: usize,
    /// Byte offset of this entry's record within the carrier.
    pub record_offset: usize,
    /// Resolved byte offset of the payload within the carrier.
    pub offset: u64,
    /// Resolved byte size of the payload.
    pub size: u64,
    /// Decoded name bytes when [`FixedRecordTableSpec::name_field`] is configured.
    pub name: Option<Vec<u8>>,
}

impl FixedRecordEntry {
    /// Return the checked exclusive end offset of this entry's payload.
    #[must_use]
    pub fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }

    /// Borrow the decoded name as UTF-8, if present and valid UTF-8.
    #[must_use]
    pub fn name_str(&self) -> Option<&str> {
        self.name
            .as_deref()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
    }

    /// Slice this entry's payload out of `data`, if representable in `usize` and in bounds.
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = usize::try_from(self.end()?).ok()?;
        data.get(start..end)
    }
}

/// Zero-allocation iterator over validated entries of a [`FixedRecordTableSpec`].
#[derive(Debug, Clone)]
pub struct FixedRecordTableIter<'a> {
    data: &'a [u8],
    spec: FixedRecordTableSpec,
    count: usize,
    table_end: u64,
    next_index: usize,
    cumulative_cursor: u64,
    prev_offset: Option<u64>,
}

impl<'a> FixedRecordTableIter<'a> {
    /// Total number of records identified in the table.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.count
    }

    /// Exclusive byte offset immediately following the record table.
    #[must_use]
    pub const fn table_end(&self) -> u64 {
        self.table_end
    }

    fn record_slice(&self, index: usize) -> Result<(usize, &'a [u8]), LayoutError> {
        let rel = index
            .checked_mul(self.spec.stride)
            .ok_or(LayoutError::Overflow {
                what: "record_offset",
            })?;
        let record_offset =
            self.spec
                .table_offset
                .checked_add(rel)
                .ok_or(LayoutError::Overflow {
                    what: "record_offset",
                })?;
        let record_end = record_offset
            .checked_add(self.spec.stride)
            .ok_or(LayoutError::Overflow { what: "record_end" })?;
        let slice = self
            .data
            .get(record_offset..record_end)
            .ok_or(LayoutError::Truncated {
                offset: record_offset,
                needed: self.spec.stride,
                available: self.data.len().saturating_sub(record_offset),
            })?;
        Ok((record_offset, slice))
    }

    fn resolve_record_offset(
        &self,
        record: &[u8],
        record_offset: usize,
        field: IntFieldSpec,
    ) -> Result<u64, LayoutError> {
        let raw = field.read(record)?;
        let scaled = raw
            .checked_mul(self.spec.offset_unit)
            .ok_or(LayoutError::Overflow {
                what: "scaled_offset",
            })?;
        let base = self.spec.offset_base.resolve(self.table_end, record_offset);
        base.checked_add(scaled)
            .ok_or(LayoutError::Overflow { what: "offset" })
    }
}

impl Iterator for FixedRecordTableIter<'_> {
    type Item = Result<FixedRecordEntry, LayoutError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.count {
            return None;
        }
        let index = self.next_index;
        self.next_index += 1;
        Some(self.decode_entry(index))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.next_index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FixedRecordTableIter<'_> {}

impl FixedRecordTableIter<'_> {
    fn decode_entry(&mut self, index: usize) -> Result<FixedRecordEntry, LayoutError> {
        let (record_offset, record) = self.record_slice(index)?;
        let name = match self.spec.name_field {
            Some(name_spec) => Some(name_spec.decode(record, index)?),
            None => None,
        };
        let data_len = self.data.len() as u64;

        let (offset, size) = match self.spec.size_mode {
            SizeMode::Stored(size_field) => {
                let offset_field = self.spec.offset_field.ok_or(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for SizeMode::Stored",
                })?;
                let offset = self.resolve_record_offset(record, record_offset, offset_field)?;
                let raw_size = size_field.read(record)?;
                let size =
                    raw_size
                        .checked_mul(self.spec.size_unit)
                        .ok_or(LayoutError::Overflow {
                            what: "scaled_size",
                        })?;
                (offset, size)
            }
            SizeMode::NextOffset => {
                let offset_field = self.spec.offset_field.ok_or(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for SizeMode::NextOffset",
                })?;
                let offset = self.resolve_record_offset(record, record_offset, offset_field)?;
                if let Some(prev) = self.prev_offset {
                    if offset < prev {
                        return Err(LayoutError::NonMonotonic {
                            index,
                            previous: prev,
                            current: offset,
                        });
                    }
                }
                self.prev_offset = Some(offset);
                let next_offset = if index + 1 < self.count {
                    let (next_rec_off, next_rec) = self.record_slice(index + 1)?;
                    let next = self.resolve_record_offset(next_rec, next_rec_off, offset_field)?;
                    if next < offset {
                        return Err(LayoutError::NonMonotonic {
                            index: index + 1,
                            previous: offset,
                            current: next,
                        });
                    }
                    next
                } else {
                    data_len
                };
                if next_offset > data_len {
                    return Err(LayoutError::OutOfBounds {
                        index,
                        offset,
                        size: next_offset - offset,
                        data_len,
                    });
                }
                (offset, next_offset - offset)
            }
            SizeMode::CumulativeFrom(_) => {
                let size_field = self.spec.offset_field.ok_or(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required as size source for SizeMode::CumulativeFrom",
                })?;
                let raw_size = size_field.read(record)?;
                let size =
                    raw_size
                        .checked_mul(self.spec.offset_unit)
                        .ok_or(LayoutError::Overflow {
                            what: "cumulative_size",
                        })?;
                let offset = self.cumulative_cursor;
                let end = offset.checked_add(size).ok_or(LayoutError::Overflow {
                    what: "cumulative_end",
                })?;
                self.cumulative_cursor = end;
                (offset, size)
            }
            SizeMode::FixedSlot(slot_size) => {
                let offset = if let Some(offset_field) = self.spec.offset_field {
                    self.resolve_record_offset(record, record_offset, offset_field)?
                } else {
                    let base = self.spec.offset_base.resolve(self.table_end, record_offset);
                    let delta =
                        (index as u64)
                            .checked_mul(slot_size)
                            .ok_or(LayoutError::Overflow {
                                what: "fixed_slot_offset",
                            })?;
                    base.checked_add(delta).ok_or(LayoutError::Overflow {
                        what: "fixed_slot_offset",
                    })?
                };
                (offset, slot_size)
            }
        };

        let end = offset
            .checked_add(size)
            .ok_or(LayoutError::Overflow { what: "entry_end" })?;
        if end > data_len {
            return Err(LayoutError::OutOfBounds {
                index,
                offset,
                size,
                data_len,
            });
        }

        Ok(FixedRecordEntry {
            index,
            record_offset,
            offset,
            size,
            name,
        })
    }
}

fn validate_spec(spec: &FixedRecordTableSpec) -> Result<(), LayoutError> {
    if spec.stride == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "stride",
            reason: "must be nonzero",
        });
    }
    if spec.offset_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "offset_unit",
            reason: "must be nonzero",
        });
    }
    if spec.size_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "size_unit",
            reason: "must be nonzero",
        });
    }
    if let Some(name) = spec.name_field {
        let end = name.end_offset().ok_or(LayoutError::InvalidSpec {
            field: "name_field",
            reason: "offset + len overflows usize",
        })?;
        if end > spec.stride {
            return Err(LayoutError::InvalidSpec {
                field: "name_field",
                reason: "exceeds record stride",
            });
        }
    }
    if let Some(field) = spec.offset_field {
        let end = field.end_offset().ok_or(LayoutError::InvalidSpec {
            field: "offset_field",
            reason: "offset + width overflows usize",
        })?;
        if end > spec.stride {
            return Err(LayoutError::InvalidSpec {
                field: "offset_field",
                reason: "exceeds record stride",
            });
        }
    }
    match spec.size_mode {
        SizeMode::Stored(size_field) => {
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for SizeMode::Stored",
                });
            }
            let end = size_field.end_offset().ok_or(LayoutError::InvalidSpec {
                field: "size_mode",
                reason: "size field offset + width overflows usize",
            })?;
            if end > spec.stride {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "size field exceeds record stride",
                });
            }
        }
        SizeMode::NextOffset => {
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for SizeMode::NextOffset",
                });
            }
        }
        SizeMode::CumulativeFrom(_) => {
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required as size field for SizeMode::CumulativeFrom",
                });
            }
        }
        SizeMode::FixedSlot(_) => {}
    }
    if matches!(spec.termination, TableTermination::FirstOffsetDerived) {
        if spec.offset_field.is_none() {
            return Err(LayoutError::InvalidSpec {
                field: "offset_field",
                reason: "required for TableTermination::FirstOffsetDerived",
            });
        }
        if matches!(spec.offset_base, OffsetBase::TableEnd) {
            return Err(LayoutError::InvalidSpec {
                field: "offset_base",
                reason:
                    "OffsetBase::TableEnd is circular with TableTermination::FirstOffsetDerived",
            });
        }
    }
    Ok(())
}

/// Create a checked, zero-allocation iterator over a fixed-stride record table.
pub fn iter_fixed_record_table<'a>(
    data: &'a [u8],
    spec: &FixedRecordTableSpec,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    iter_fixed_record_table_bounded(data, spec, spec.max_entries)
}

fn iter_fixed_record_table_bounded<'a>(
    data: &'a [u8],
    spec: &FixedRecordTableSpec,
    max_entries: usize,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    validate_spec(spec)?;

    let effective_max = spec.max_entries.min(max_entries);
    if spec.table_offset > data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.table_offset,
            needed: 0,
            available: 0,
        });
    }

    let (count, table_end_usize) = match spec.termination {
        TableTermination::Counted(count) => {
            if count > effective_max {
                return Err(LayoutError::MaxEntriesExceeded { max: effective_max });
            }
            let bytes = count
                .checked_mul(spec.stride)
                .ok_or(LayoutError::Overflow {
                    what: "table_bytes",
                })?;
            let end = spec
                .table_offset
                .checked_add(bytes)
                .ok_or(LayoutError::Overflow { what: "table_end" })?;
            if end > data.len() {
                return Err(LayoutError::Truncated {
                    offset: spec.table_offset,
                    needed: bytes,
                    available: data.len().saturating_sub(spec.table_offset),
                });
            }
            (count, end)
        }
        TableTermination::ZeroRow | TableTermination::FirstByteZero => {
            let mut pos = spec.table_offset;
            let mut count = 0usize;
            let mut terminated = false;
            while let Some(end) = pos.checked_add(spec.stride) {
                if end > data.len() {
                    break;
                }
                let row = &data[pos..end];
                let is_sentinel = match spec.termination {
                    TableTermination::ZeroRow => row.iter().all(|&b| b == 0),
                    TableTermination::FirstByteZero => row[0] == 0,
                    _ => unreachable!(),
                };
                if is_sentinel {
                    pos = end;
                    terminated = true;
                    break;
                }
                if count >= effective_max {
                    return Err(LayoutError::MaxEntriesExceeded { max: effective_max });
                }
                count += 1;
                pos = end;
            }
            if !terminated && pos < data.len() && data.len() - pos < spec.stride {
                // Incomplete trailing record before any terminator.
                return Err(LayoutError::Truncated {
                    offset: pos,
                    needed: spec.stride,
                    available: data.len() - pos,
                });
            }
            (count, pos)
        }
        TableTermination::FirstOffsetDerived => {
            let first_end =
                spec.table_offset
                    .checked_add(spec.stride)
                    .ok_or(LayoutError::Overflow {
                        what: "first_record_end",
                    })?;
            let first_rec =
                data.get(spec.table_offset..first_end)
                    .ok_or(LayoutError::Truncated {
                        offset: spec.table_offset,
                        needed: spec.stride,
                        available: data.len().saturating_sub(spec.table_offset),
                    })?;
            let offset_field = spec.offset_field.expect("validated above");
            let raw = offset_field.read(first_rec)?;
            let scaled = raw
                .checked_mul(spec.offset_unit)
                .ok_or(LayoutError::Overflow {
                    what: "first_offset",
                })?;
            let base = spec.offset_base.resolve(0, spec.table_offset);
            let first_offset = base.checked_add(scaled).ok_or(LayoutError::Overflow {
                what: "first_offset",
            })?;
            let table_offset_u64 = spec.table_offset as u64;
            if first_offset < table_offset_u64 || first_offset > data.len() as u64 {
                return Err(LayoutError::InvalidTableEnd {
                    first_offset,
                    table_offset: spec.table_offset,
                    stride: spec.stride,
                });
            }
            let table_bytes = first_offset - table_offset_u64;
            if !table_bytes.is_multiple_of(spec.stride as u64) {
                return Err(LayoutError::InvalidTableEnd {
                    first_offset,
                    table_offset: spec.table_offset,
                    stride: spec.stride,
                });
            }
            let count = usize::try_from(table_bytes / (spec.stride as u64)).map_err(|_| {
                LayoutError::Overflow {
                    what: "derived_count",
                }
            })?;
            if count > effective_max {
                return Err(LayoutError::MaxEntriesExceeded { max: effective_max });
            }
            let end = usize::try_from(first_offset)
                .map_err(|_| LayoutError::Overflow { what: "table_end" })?;
            (count, end)
        }
        TableTermination::Eof => {
            let remaining = data.len() - spec.table_offset;
            let count = remaining / spec.stride;
            if count > effective_max {
                return Err(LayoutError::MaxEntriesExceeded { max: effective_max });
            }
            let end = spec.table_offset + count * spec.stride;
            (count, end)
        }
    };

    let cumulative_cursor = match spec.size_mode {
        SizeMode::CumulativeFrom(start) => start,
        _ => 0,
    };

    Ok(FixedRecordTableIter {
        data,
        spec: *spec,
        count,
        table_end: table_end_usize as u64,
        next_index: 0,
        cumulative_cursor,
        prev_offset: None,
    })
}

/// Parse a fixed-stride record table according to `spec`, validating every
/// `(offset, size)` range against `data.len()` with checked arithmetic.
pub fn parse_fixed_record_table(
    data: &[u8],
    spec: &FixedRecordTableSpec,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    parse_fixed_record_table_bounded(data, spec, spec.max_entries)
}

/// Parse a fixed-stride record table with an explicit caller entry bound
/// (enforcing `min(spec.max_entries, max_entries)`).
pub fn parse_fixed_record_table_bounded(
    data: &[u8],
    spec: &FixedRecordTableSpec,
    max_entries: usize,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    let iter = iter_fixed_record_table_bounded(data, spec, max_entries)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(iter.entry_count())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: iter.entry_count(),
        })?;
    for item in iter {
        entries.push(item?);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use formatkit_core::Endian;

    use super::*;
    use crate::spec::IntWidth;

    #[test]
    fn parses_counted_stored_be_u24_and_sector_units() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 16,
            table_offset: 0,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 8, NameEncoding::NulOrSpacePadded)),
            offset_field: Some(IntFieldSpec::new(8, IntWidth::U24, Endian::Big)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 2048,
            size_mode: SizeMode::Stored(IntFieldSpec::u32_be(12)),
            size_unit: 1,
            termination: TableTermination::Counted(2),
        };

        let mut data = vec![0u8; 2048 * 3];
        // Entry 0: name "alpha   ", offset = sector 1 (0x000001), size = 100
        data[0..8].copy_from_slice(b"alpha   ");
        data[8..11].copy_from_slice(&[0x00, 0x00, 0x01]);
        data[12..16].copy_from_slice(&100u32.to_be_bytes());
        // Entry 1: name "beta\0pad", offset = sector 2 (0x000002), size = 2048
        data[16..24].copy_from_slice(b"beta\0pad");
        data[24..27].copy_from_slice(&[0x00, 0x00, 0x02]);
        data[28..32].copy_from_slice(&2048u32.to_be_bytes());

        let entries = parse_fixed_record_table(&data, &SPEC).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name_str(), Some("alpha"));
        assert_eq!(entries[0].offset, 2048);
        assert_eq!(entries[0].size, 100);
        assert_eq!(entries[1].name_str(), Some("beta"));
        assert_eq!(entries[1].offset, 4096);
        assert_eq!(entries[1].size, 2048);
    }

    #[test]
    fn parses_first_offset_derived_and_next_offset() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 16,
            table_offset: 0,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 12, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u32_le(12)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::NextOffset,
            size_unit: 1,
            termination: TableTermination::FirstOffsetDerived,
        };

        // 2 records (32 bytes) + 10-byte payload0 + 6-byte payload1 = 48 bytes
        let mut data = Vec::new();
        data.extend_from_slice(b"first.bin\0\0\0");
        data.extend_from_slice(&32u32.to_le_bytes());
        data.extend_from_slice(b"second.bin\0\0");
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&[0xAA; 10]);
        data.extend_from_slice(&[0xBB; 6]);

        let entries = parse_fixed_record_table(&data, &SPEC).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name_str(), Some("first.bin"));
        assert_eq!(entries[0].offset, 32);
        assert_eq!(entries[0].size, 10);
        assert_eq!(entries[1].name_str(), Some("second.bin"));
        assert_eq!(entries[1].offset, 42);
        assert_eq!(entries[1].size, 6);
    }

    #[test]
    fn parses_zero_row_and_first_byte_zero_termination_with_table_end_base() {
        const ZERO_ROW_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 8,
            table_offset: 0,
            max_entries: 16,
            name_field: None,
            offset_field: Some(IntFieldSpec::u32_le(0)),
            offset_base: OffsetBase::TableEnd,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u32_le(4)),
            size_unit: 1,
            termination: TableTermination::ZeroRow,
        };

        let mut data = Vec::new();
        // Record 0: rel offset 0, size 4
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        // Record 1: rel offset 4, size 2
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        // Zero sentinel row (8 bytes) -> table_end = 24
        data.extend_from_slice(&[0u8; 8]);
        // Payloads
        data.extend_from_slice(b"ABCD");
        data.extend_from_slice(b"EF");

        let entries = parse_fixed_record_table(&data, &ZERO_ROW_SPEC).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 24);
        assert_eq!(entries[0].payload(&data), Some(&b"ABCD"[..]));
        assert_eq!(entries[1].offset, 28);
        assert_eq!(entries[1].payload(&data), Some(&b"EF"[..]));

        // FirstByteZero termination
        const FIRST_ZERO_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 12,
            table_offset: 0,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 4, NameEncoding::NulTerminated)),
            offset_field: Some(IntFieldSpec::u32_le(4)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u32_le(8)),
            size_unit: 1,
            termination: TableTermination::FirstByteZero,
        };
        let mut data2 = Vec::new();
        data2.extend_from_slice(b"A\0\0\0");
        data2.extend_from_slice(&24u32.to_le_bytes());
        data2.extend_from_slice(&3u32.to_le_bytes());
        // Sentinel row starts with 0x00, non-zero trailing bytes
        data2.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        data2.extend_from_slice(b"XYZ");
        let entries2 = parse_fixed_record_table(&data2, &FIRST_ZERO_SPEC).unwrap();
        assert_eq!(entries2.len(), 1);
        assert_eq!(entries2[0].name_str(), Some("A"));
        assert_eq!(entries2[0].payload(&data2), Some(&b"XYZ"[..]));
    }

    #[test]
    fn parses_cumulative_and_fixed_slot_and_record_start() {
        const CUMULATIVE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 4,
            table_offset: 0,
            max_entries: 16,
            name_field: None,
            offset_field: Some(IntFieldSpec::u32_le(0)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::CumulativeFrom(8),
            size_unit: 1,
            termination: TableTermination::Counted(2),
        };
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(b"12345678");
        let entries = parse_fixed_record_table(&data, &CUMULATIVE_SPEC).unwrap();
        assert_eq!(entries[0].offset, 8);
        assert_eq!(entries[0].size, 3);
        assert_eq!(entries[1].offset, 11);
        assert_eq!(entries[1].size, 5);

        const FIXED_SLOT_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 4,
            table_offset: 0,
            max_entries: 16,
            name_field: None,
            offset_field: None,
            offset_base: OffsetBase::Fixed(8),
            offset_unit: 1,
            size_mode: SizeMode::FixedSlot(4),
            size_unit: 1,
            termination: TableTermination::Counted(2),
        };
        let slot_data = [0u8; 16];
        let slot_entries = parse_fixed_record_table(&slot_data, &FIXED_SLOT_SPEC).unwrap();
        assert_eq!(slot_entries[0].offset, 8);
        assert_eq!(slot_entries[0].size, 4);
        assert_eq!(slot_entries[1].offset, 12);
        assert_eq!(slot_entries[1].size, 4);

        const REL_RECORD_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 4,
            table_offset: 0,
            max_entries: 16,
            name_field: None,
            offset_field: Some(IntFieldSpec::u16_le(0)),
            offset_base: OffsetBase::RecordStart,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u16_le(2)),
            size_unit: 1,
            termination: TableTermination::Counted(2),
        };
        let mut rel_data = Vec::new();
        // Record 0 at 0: +8 => 8, size 2
        rel_data.extend_from_slice(&8u16.to_le_bytes());
        rel_data.extend_from_slice(&2u16.to_le_bytes());
        // Record 1 at 4: +6 => 10, size 2
        rel_data.extend_from_slice(&6u16.to_le_bytes());
        rel_data.extend_from_slice(&2u16.to_le_bytes());
        rel_data.extend_from_slice(b"AABB");
        let rel_entries = parse_fixed_record_table(&rel_data, &REL_RECORD_SPEC).unwrap();
        assert_eq!(rel_entries[0].offset, 8);
        assert_eq!(rel_entries[1].offset, 10);
    }

    #[test]
    fn rejects_oob_overflow_non_monotonic_invalid_name_and_max_entries() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 12,
            table_offset: 0,
            max_entries: 4,
            name_field: Some(NameFieldSpec::new(0, 4, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u32_le(4)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u32_le(8)),
            size_unit: 1,
            termination: TableTermination::Counted(1),
        };

        // OOB payload
        let mut oob = Vec::new();
        oob.extend_from_slice(b"ok\0\0");
        oob.extend_from_slice(&12u32.to_le_bytes());
        oob.extend_from_slice(&5u32.to_le_bytes());
        oob.extend_from_slice(b"123");
        assert!(matches!(
            parse_fixed_record_table(&oob, &SPEC),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));

        // Invalid non-ASCII name
        let mut bad_name = Vec::new();
        bad_name.extend_from_slice(&[0xFF, b'a', 0, 0]);
        bad_name.extend_from_slice(&12u32.to_le_bytes());
        bad_name.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_fixed_record_table(&bad_name, &SPEC),
            Err(LayoutError::InvalidName { index: 0 })
        );

        // Overflow on offset scaling
        let overflow_spec = FixedRecordTableSpec {
            offset_unit: u64::MAX,
            ..SPEC
        };
        let mut ov = Vec::new();
        ov.extend_from_slice(b"ok\0\0");
        ov.extend_from_slice(&2u32.to_le_bytes());
        ov.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_fixed_record_table(&ov, &overflow_spec),
            Err(LayoutError::Overflow {
                what: "scaled_offset"
            })
        );

        // Bounded call rejects exceeding caller limit
        assert_eq!(
            parse_fixed_record_table_bounded(&oob, &SPEC, 0),
            Err(LayoutError::MaxEntriesExceeded { max: 0 })
        );

        // Non-monotonic NextOffset
        const NEXT_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 4,
            table_offset: 0,
            max_entries: 8,
            name_field: None,
            offset_field: Some(IntFieldSpec::u32_le(0)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::NextOffset,
            size_unit: 1,
            termination: TableTermination::Counted(2),
        };
        let mut non_mono = Vec::new();
        non_mono.extend_from_slice(&16u32.to_le_bytes());
        non_mono.extend_from_slice(&12u32.to_le_bytes());
        non_mono.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            parse_fixed_record_table(&non_mono, &NEXT_SPEC),
            Err(LayoutError::NonMonotonic {
                index: 1,
                previous: 16,
                current: 12,
            })
        );
    }
}
