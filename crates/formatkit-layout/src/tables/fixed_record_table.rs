//! Declarative fixed-stride record table specification, checked parser, and symmetric writer.
//!
//! [`FixedRecordTableSpec`] describes fixed-stride directory tables with
//! configurable integer widths (`u8`/`u16`/`u24`/`u32`/`u64`), endianness,
//! optional embedded names, offset base/unit scaling, size derivation modes,
//! and table termination rules.

use crate::spec::{align_payload_offset, IntFieldSpec, LayoutError, OffsetBase, PackPolicy};

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

    fn decode_borrowed(self, record: &[u8], index: usize) -> Result<&[u8], LayoutError> {
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
        Ok(trimmed)
    }

    fn encode(self, record: &mut [u8], name: &[u8], index: usize) -> Result<(), LayoutError> {
        if name.len() > self.len || name.contains(&0) {
            return Err(LayoutError::InvalidName { index });
        }
        if matches!(self.encoding, NameEncoding::Ascii) && !name.is_ascii() {
            return Err(LayoutError::InvalidName { index });
        }
        let end = self
            .end_offset()
            .ok_or(LayoutError::Overflow { what: "name_end" })?;
        let available = record.len().saturating_sub(self.offset);
        let slice = record
            .get_mut(self.offset..end)
            .ok_or(LayoutError::Truncated {
                offset: self.offset,
                needed: self.len,
                available,
            })?;
        slice.fill(0);
        slice[..name.len()].copy_from_slice(name);
        Ok(())
    }
}

/// Rule determining how each record's payload size is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMode {
    /// Each record stores an explicit size field (scaled by [`FixedRecordTableSpec::size_unit`]).
    Stored(IntFieldSpec),
    /// Entry `i` spans `[offset[i], offset[i + 1])` with the last entry ending at `carrier_len`.
    /// Requires non-decreasing resolved offsets.
    NextOffset,
    /// Each record's `offset_field` stores a size (scaled by [`FixedRecordTableSpec::size_unit`]),
    /// and entry offsets accumulate contiguously starting from the given byte offset.
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
    /// Non-zero byte multiplier applied to [`SizeMode::Stored`] and [`SizeMode::CumulativeFrom`] size values.
    pub size_unit: u64,
    /// How the number of records in the table is determined.
    pub termination: TableTermination,
}

/// Zero-allocation borrowed view of one validated entry decoded from a [`FixedRecordTableSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRecordView<'a> {
    /// Zero-based entry index in the table.
    pub index: usize,
    /// Byte offset of this entry's record within the table buffer.
    pub record_offset: usize,
    /// Resolved byte offset of the payload within the carrier.
    pub offset: u64,
    /// Resolved byte size of the payload.
    pub size: u64,
    /// Borrowed decoded name bytes when [`FixedRecordTableSpec::name_field`] is configured.
    pub name: Option<&'a [u8]>,
}

impl<'a> FixedRecordView<'a> {
    /// Return the checked exclusive end offset of this entry's payload.
    #[must_use]
    pub const fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }

    /// Borrow the decoded name as UTF-8, if present and valid UTF-8.
    #[must_use]
    pub fn name_str(&self) -> Option<&'a str> {
        self.name.and_then(|bytes| core::str::from_utf8(bytes).ok())
    }

    /// Slice this entry's payload out of `data`, if representable in `usize` and in bounds.
    #[must_use]
    pub fn payload<'d>(&self, data: &'d [u8]) -> Option<&'d [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = usize::try_from(self.end()?).ok()?;
        data.get(start..end)
    }

    /// Convert this borrowed view into an owned [`FixedRecordEntry`].
    #[must_use]
    pub fn to_owned_entry(&self) -> FixedRecordEntry {
        FixedRecordEntry {
            index: self.index,
            record_offset: self.record_offset,
            offset: self.offset,
            size: self.size,
            name: self.name.map(<[u8]>::to_vec),
        }
    }
}

impl From<FixedRecordView<'_>> for FixedRecordEntry {
    fn from(view: FixedRecordView<'_>) -> Self {
        view.to_owned_entry()
    }
}

/// One validated owned entry decoded from a [`FixedRecordTableSpec`].
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
    pub const fn end(&self) -> Option<u64> {
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
    carrier_len: u64,
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

    fn decode_entry(&mut self, index: usize) -> Result<FixedRecordView<'a>, LayoutError> {
        let (record_offset, record) = self.record_slice(index)?;
        let name = match self.spec.name_field {
            Some(name_spec) => Some(name_spec.decode_borrowed(record, index)?),
            None => None,
        };
        let data_len = self.carrier_len;

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
                if offset > data_len {
                    return Err(LayoutError::OutOfBounds {
                        index,
                        offset,
                        size: 0,
                        data_len,
                    });
                }
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
                        .checked_mul(self.spec.size_unit)
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

        Ok(FixedRecordView {
            index,
            record_offset,
            offset,
            size,
            name,
        })
    }
}

impl<'a> Iterator for FixedRecordTableIter<'a> {
    type Item = Result<FixedRecordView<'a>, LayoutError>;

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
        if matches!(spec.size_mode, SizeMode::CumulativeFrom(_)) {
            return Err(LayoutError::InvalidSpec {
                field: "size_mode",
                reason: "SizeMode::CumulativeFrom cannot be combined with TableTermination::FirstOffsetDerived",
            });
        }
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
    iter_fixed_record_table_inner(data, spec, spec.max_entries, data.len() as u64)
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`,
/// validating payload ranges against a full `carrier_len` without loading the carrier into RAM.
pub fn iter_fixed_record_table_metadata<'a>(
    table_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    iter_fixed_record_table_inner(table_data, spec, spec.max_entries, carrier_len)
}

/// Create a checked, zero-allocation iterator over a fixed-stride record table using a
/// runtime `count` (overriding [`FixedRecordTableSpec::termination`] with
/// [`TableTermination::Counted`]).
pub fn iter_fixed_record_table_counted<'a>(
    data: &'a [u8],
    spec: &FixedRecordTableSpec,
    count: usize,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    let counted_spec = FixedRecordTableSpec {
        termination: TableTermination::Counted(count),
        ..*spec
    };
    iter_fixed_record_table_inner(
        data,
        &counted_spec,
        counted_spec.max_entries,
        data.len() as u64,
    )
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`
/// with a runtime `count` and external `carrier_len`.
pub fn iter_fixed_record_table_counted_metadata<'a>(
    table_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    count: usize,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    let counted_spec = FixedRecordTableSpec {
        termination: TableTermination::Counted(count),
        ..*spec
    };
    iter_fixed_record_table_inner(
        table_data,
        &counted_spec,
        counted_spec.max_entries,
        carrier_len,
    )
}

fn iter_fixed_record_table_inner<'a>(
    table_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    max_entries: usize,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    validate_spec(spec)?;

    let effective_max = spec.max_entries.min(max_entries);
    if spec.table_offset > table_data.len() {
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
            if end > table_data.len() {
                return Err(LayoutError::Truncated {
                    offset: spec.table_offset,
                    needed: bytes,
                    available: table_data.len().saturating_sub(spec.table_offset),
                });
            }
            (count, end)
        }
        TableTermination::ZeroRow | TableTermination::FirstByteZero => {
            let mut pos = spec.table_offset;
            let mut count = 0usize;
            let mut terminated = false;
            while let Some(end) = pos.checked_add(spec.stride) {
                if end > table_data.len() {
                    break;
                }
                let row = &table_data[pos..end];
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
            if !terminated && pos < table_data.len() && table_data.len() - pos < spec.stride {
                return Err(LayoutError::Truncated {
                    offset: pos,
                    needed: spec.stride,
                    available: table_data.len() - pos,
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
                table_data
                    .get(spec.table_offset..first_end)
                    .ok_or(LayoutError::Truncated {
                        offset: spec.table_offset,
                        needed: spec.stride,
                        available: table_data.len().saturating_sub(spec.table_offset),
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
            if first_offset < table_offset_u64 || first_offset > carrier_len {
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
            if end > table_data.len() {
                return Err(LayoutError::Truncated {
                    offset: spec.table_offset,
                    needed: end - spec.table_offset,
                    available: table_data.len().saturating_sub(spec.table_offset),
                });
            }
            (count, end)
        }
        TableTermination::Eof => {
            let remaining = table_data.len() - spec.table_offset;
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
        data: table_data,
        carrier_len,
        spec: *spec,
        count,
        table_end: table_end_usize as u64,
        next_index: 0,
        cumulative_cursor,
        prev_offset: None,
    })
}

fn collect_entries(iter: FixedRecordTableIter<'_>) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(iter.entry_count())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: iter.entry_count(),
        })?;
    for item in iter {
        entries.push(item?.to_owned_entry());
    }
    Ok(entries)
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
    let iter = iter_fixed_record_table_inner(data, spec, max_entries, data.len() as u64)?;
    collect_entries(iter)
}

/// Parse staged directory bytes `table_data` against an external `carrier_len`
/// without loading the entire carrier into memory.
pub fn parse_fixed_record_table_metadata(
    table_data: &[u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    let iter = iter_fixed_record_table_metadata(table_data, spec, carrier_len)?;
    collect_entries(iter)
}

/// Parse a fixed-stride record table using a runtime `count`, without copying
/// a `const` [`FixedRecordTableSpec`] to patch [`TableTermination::Counted`].
pub fn parse_fixed_record_table_counted(
    data: &[u8],
    spec: &FixedRecordTableSpec,
    count: usize,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    let iter = iter_fixed_record_table_counted(data, spec, count)?;
    collect_entries(iter)
}

/// Parse staged directory bytes `table_data` using a runtime `count` and an
/// external `carrier_len`.
pub fn parse_fixed_record_table_counted_metadata(
    table_data: &[u8],
    spec: &FixedRecordTableSpec,
    count: usize,
    carrier_len: u64,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    let iter = iter_fixed_record_table_counted_metadata(table_data, spec, count, carrier_len)?;
    collect_entries(iter)
}

/// One entry supplied to [`pack_fixed_record_table`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRecordInput<'a> {
    /// Optional entry name bytes (written when [`FixedRecordTableSpec::name_field`] is configured).
    pub name: Option<&'a [u8]>,
    /// Payload bytes for this entry.
    pub payload: &'a [u8],
    /// Optional raw `stride`-byte record template copied before writing managed fields
    /// (preserving owner-specific flags, hashes, or auxiliary columns).
    pub record_template: Option<&'a [u8]>,
}

/// Serialize `entries` into a binary carrier conforming to `spec` and `policy`.
///
/// The resulting buffer begins with `header_prefix` (padded with
/// [`PackPolicy::prefix_fill_byte`] up to [`FixedRecordTableSpec::table_offset`]),
/// followed by the fixed-stride record table (plus any sentinel row required by
/// [`TableTermination::ZeroRow`] or [`TableTermination::FirstByteZero`]), and
/// then the aligned payloads.
pub fn pack_fixed_record_table(
    spec: &FixedRecordTableSpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    entries: &[FixedRecordInput<'_>],
) -> Result<Vec<u8>, LayoutError> {
    validate_spec(spec)?;
    policy.validate()?;

    if entries.len() > spec.max_entries {
        return Err(LayoutError::MaxEntriesExceeded {
            max: spec.max_entries,
        });
    }
    if header_prefix.len() > spec.table_offset {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "header_prefix exceeds table_offset",
        });
    }

    let sentinel_rows = match spec.termination {
        TableTermination::ZeroRow | TableTermination::FirstByteZero => 1usize,
        TableTermination::FirstOffsetDerived => {
            if entries.is_empty() {
                return Err(LayoutError::InvalidInput {
                    index: 0,
                    reason: "TableTermination::FirstOffsetDerived requires at least one entry",
                });
            }
            0usize
        }
        TableTermination::Eof => {
            if entries.iter().any(|e| !e.payload.is_empty()) {
                return Err(LayoutError::InvalidInput {
                    index: 0,
                    reason: "TableTermination::Eof cannot pack non-empty inline payloads",
                });
            }
            0usize
        }
        TableTermination::Counted(_) => 0usize,
    };

    let total_rows = entries
        .len()
        .checked_add(sentinel_rows)
        .ok_or(LayoutError::Overflow { what: "table_rows" })?;
    let table_bytes = total_rows
        .checked_mul(spec.stride)
        .ok_or(LayoutError::Overflow {
            what: "table_bytes",
        })?;
    let table_end = spec
        .table_offset
        .checked_add(table_bytes)
        .ok_or(LayoutError::Overflow { what: "table_end" })?;
    let table_end_u64 = table_end as u64;

    // Plan each entry's physical payload offset and encoded record values.
    struct PlannedEntry {
        payload_offset: usize,
        raw_offset: Option<u64>,
        raw_size: Option<u64>,
    }

    let mut planned = Vec::new();
    planned
        .try_reserve_exact(entries.len())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: entries.len(),
        })?;

    let mut cursor: u64 = match spec.size_mode {
        SizeMode::CumulativeFrom(start) => {
            if start < table_end_u64 {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "CumulativeFrom start offset overlaps record table",
                });
            }
            start
        }
        _ => table_end_u64,
    };

    for (index, entry) in entries.iter().enumerate() {
        let record_offset = spec.table_offset + index * spec.stride;
        let payload_len_u64 = entry.payload.len() as u64;

        match spec.size_mode {
            SizeMode::Stored(_) => {
                if !payload_len_u64.is_multiple_of(spec.size_unit) {
                    return Err(LayoutError::InvalidInput {
                        index,
                        reason: "payload size is not a multiple of size_unit",
                    });
                }
                let base = spec.offset_base.resolve(table_end_u64, record_offset);
                let offset_u64 = if index == 0
                    && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                {
                    if table_end_u64 < base
                        || !(table_end_u64 - base).is_multiple_of(spec.offset_unit)
                    {
                        return Err(LayoutError::InvalidInput {
                            index,
                            reason: "table_end cannot be encoded for FirstOffsetDerived",
                        });
                    }
                    table_end_u64
                } else {
                    align_payload_offset(cursor, base, policy.data_alignment, spec.offset_unit)?
                };
                let raw_offset = (offset_u64 - base) / spec.offset_unit;
                let raw_size = payload_len_u64 / spec.size_unit;
                let payload_offset =
                    usize::try_from(offset_u64).map_err(|_| LayoutError::Overflow {
                        what: "payload_offset",
                    })?;
                cursor = offset_u64
                    .checked_add(payload_len_u64)
                    .ok_or(LayoutError::Overflow { what: "entry_end" })?;
                planned.push(PlannedEntry {
                    payload_offset,
                    raw_offset: Some(raw_offset),
                    raw_size: Some(raw_size),
                });
            }
            SizeMode::NextOffset => {
                let base = spec.offset_base.resolve(table_end_u64, record_offset);
                let offset_u64 = if index == 0
                    && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                {
                    if table_end_u64 < base
                        || !(table_end_u64 - base).is_multiple_of(spec.offset_unit)
                    {
                        return Err(LayoutError::InvalidInput {
                            index,
                            reason: "table_end cannot be encoded for FirstOffsetDerived",
                        });
                    }
                    table_end_u64
                } else {
                    align_payload_offset(cursor, base, policy.data_alignment, spec.offset_unit)?
                };
                let raw_offset = (offset_u64 - base) / spec.offset_unit;
                let payload_offset =
                    usize::try_from(offset_u64).map_err(|_| LayoutError::Overflow {
                        what: "payload_offset",
                    })?;
                cursor = offset_u64
                    .checked_add(payload_len_u64)
                    .ok_or(LayoutError::Overflow { what: "entry_end" })?;
                planned.push(PlannedEntry {
                    payload_offset,
                    raw_offset: Some(raw_offset),
                    raw_size: None,
                });
            }
            SizeMode::CumulativeFrom(_) => {
                if !payload_len_u64.is_multiple_of(spec.size_unit) {
                    return Err(LayoutError::InvalidInput {
                        index,
                        reason: "payload size is not a multiple of size_unit",
                    });
                }
                let raw_size = payload_len_u64 / spec.size_unit;
                let payload_offset =
                    usize::try_from(cursor).map_err(|_| LayoutError::Overflow {
                        what: "payload_offset",
                    })?;
                cursor = cursor
                    .checked_add(payload_len_u64)
                    .ok_or(LayoutError::Overflow { what: "entry_end" })?;
                planned.push(PlannedEntry {
                    payload_offset,
                    raw_offset: Some(raw_size),
                    raw_size: None,
                });
            }
            SizeMode::FixedSlot(slot_size) => {
                if payload_len_u64 > slot_size {
                    return Err(LayoutError::InvalidInput {
                        index,
                        reason: "payload exceeds FixedSlot size",
                    });
                }
                let base = spec.offset_base.resolve(table_end_u64, record_offset);
                let (offset_u64, raw_offset) = if spec.offset_field.is_some() {
                    let off = if index == 0
                        && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                    {
                        if table_end_u64 < base
                            || !(table_end_u64 - base).is_multiple_of(spec.offset_unit)
                        {
                            return Err(LayoutError::InvalidInput {
                                index,
                                reason: "table_end cannot be encoded for FirstOffsetDerived",
                            });
                        }
                        table_end_u64
                    } else {
                        align_payload_offset(cursor, base, policy.data_alignment, spec.offset_unit)?
                    };
                    (off, Some((off - base) / spec.offset_unit))
                } else {
                    let delta =
                        (index as u64)
                            .checked_mul(slot_size)
                            .ok_or(LayoutError::Overflow {
                                what: "fixed_slot_offset",
                            })?;
                    let off = base.checked_add(delta).ok_or(LayoutError::Overflow {
                        what: "fixed_slot_offset",
                    })?;
                    if off < table_end_u64 {
                        return Err(LayoutError::InvalidInput {
                            index,
                            reason: "FixedSlot offset overlaps record table",
                        });
                    }
                    (off, None)
                };
                let payload_offset =
                    usize::try_from(offset_u64).map_err(|_| LayoutError::Overflow {
                        what: "payload_offset",
                    })?;
                let slot_end = offset_u64
                    .checked_add(slot_size)
                    .ok_or(LayoutError::Overflow { what: "entry_end" })?;
                cursor = cursor.max(slot_end);
                planned.push(PlannedEntry {
                    payload_offset,
                    raw_offset,
                    raw_size: None,
                });
            }
        }
    }

    if policy.pad_final_entry
        && policy.data_alignment > 1
        && !matches!(spec.termination, TableTermination::Eof)
    {
        cursor = align_payload_offset(cursor, 0, policy.data_alignment, 1)?;
    }

    let total_len =
        usize::try_from(cursor).map_err(|_| LayoutError::Overflow { what: "output_len" })?;
    let mut out = Vec::new();
    out.try_reserve_exact(total_len)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: total_len,
        })?;
    out.resize(total_len, policy.pad_byte);

    // Prefix region
    out[..header_prefix.len()].copy_from_slice(header_prefix);
    out[header_prefix.len()..spec.table_offset].fill(policy.prefix_fill_byte);

    // Table records
    for (index, (entry, plan)) in entries.iter().zip(planned.iter()).enumerate() {
        let record_offset = spec.table_offset + index * spec.stride;
        let rec = &mut out[record_offset..record_offset + spec.stride];
        if let Some(tmpl) = entry.record_template {
            if tmpl.len() != spec.stride {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "record_template length must equal stride",
                });
            }
            rec.copy_from_slice(tmpl);
        } else {
            rec.fill(policy.record_fill_byte);
        }

        if let Some(name_spec) = spec.name_field {
            if let Some(name_bytes) = entry.name {
                name_spec.encode(rec, name_bytes, index)?;
            } else if entry.record_template.is_none() {
                name_spec.encode(rec, &[], index)?;
            }
        }

        if let (Some(offset_field), Some(raw_off)) = (spec.offset_field, plan.raw_offset) {
            offset_field.write(rec, raw_off)?;
        }
        if let (SizeMode::Stored(size_field), Some(raw_size)) = (spec.size_mode, plan.raw_size) {
            size_field.write(rec, raw_size)?;
        }

        match spec.termination {
            TableTermination::ZeroRow if rec.iter().all(|&b| b == 0) => {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "encoded record is all-zero under TableTermination::ZeroRow",
                });
            }
            TableTermination::FirstByteZero if rec[0] == 0 => {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "encoded record starts with 0x00 under TableTermination::FirstByteZero",
                });
            }
            _ => {}
        }
    }

    // Sentinel row
    if sentinel_rows == 1 {
        let sentinel_start = spec.table_offset + entries.len() * spec.stride;
        out[sentinel_start..sentinel_start + spec.stride].fill(0);
    }

    // Payloads
    for (entry, plan) in entries.iter().zip(planned.iter()) {
        let end = plan.payload_offset + entry.payload.len();
        out[plan.payload_offset..end].copy_from_slice(entry.payload);
    }

    Ok(out)
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
        data[0..8].copy_from_slice(b"alpha   ");
        data[8..11].copy_from_slice(&[0x00, 0x00, 0x01]);
        data[12..16].copy_from_slice(&100u32.to_be_bytes());
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
    fn next_offset_final_entry_past_eof_returns_out_of_bounds_without_panic() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
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
        let mut data = Vec::new();
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&999u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]); // data.len() == 12 < 999

        assert_eq!(
            parse_fixed_record_table(&data, &SPEC),
            Err(LayoutError::OutOfBounds {
                index: 0,
                offset: 8,
                size: 991,
                data_len: 12,
            })
        );

        // Single entry whose offset exceeds data.len()
        const SINGLE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            termination: TableTermination::Counted(1),
            ..SPEC
        };
        let single = 999u32.to_le_bytes();
        assert_eq!(
            parse_fixed_record_table(&single, &SINGLE_SPEC),
            Err(LayoutError::OutOfBounds {
                index: 0,
                offset: 999,
                size: 0,
                data_len: 4,
            })
        );
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
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(b"ABCD");
        data.extend_from_slice(b"EF");

        let entries = parse_fixed_record_table(&data, &ZERO_ROW_SPEC).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 24);
        assert_eq!(entries[0].payload(&data), Some(&b"ABCD"[..]));
        assert_eq!(entries[1].offset, 28);
        assert_eq!(entries[1].payload(&data), Some(&b"EF"[..]));

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
        data2.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        data2.extend_from_slice(b"XYZ");
        let entries2 = parse_fixed_record_table(&data2, &FIRST_ZERO_SPEC).unwrap();
        assert_eq!(entries2.len(), 1);
        assert_eq!(entries2[0].name_str(), Some("A"));
        assert_eq!(entries2[0].payload(&data2), Some(&b"XYZ"[..]));
    }

    #[test]
    fn parses_cumulative_with_size_unit_and_rejects_first_offset_derived() {
        const CUMULATIVE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 4,
            table_offset: 0,
            max_entries: 16,
            name_field: None,
            offset_field: Some(IntFieldSpec::u32_le(0)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::CumulativeFrom(8),
            size_unit: 4,
            termination: TableTermination::Counted(2),
        };
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 * 4 = 4 bytes
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 * 4 = 8 bytes
        data.extend_from_slice(b"1234abcdefgh");
        let entries = parse_fixed_record_table(&data, &CUMULATIVE_SPEC).unwrap();
        assert_eq!(entries[0].offset, 8);
        assert_eq!(entries[0].size, 4);
        assert_eq!(entries[1].offset, 12);
        assert_eq!(entries[1].size, 8);

        let invalid_combo = FixedRecordTableSpec {
            termination: TableTermination::FirstOffsetDerived,
            ..CUMULATIVE_SPEC
        };
        assert!(matches!(
            parse_fixed_record_table(&data, &invalid_combo),
            Err(LayoutError::InvalidSpec {
                field: "size_mode",
                ..
            })
        ));
    }

    #[test]
    fn parses_fixed_slot_and_record_start_and_metadata_700mb() {
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

        // Source-staged metadata validation against a 700 MiB carrier using only 32 bytes of directory!
        const DISC_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 16,
            table_offset: 0,
            max_entries: 64,
            name_field: Some(NameFieldSpec::new(0, 8, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u32_le(8)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 2048,
            size_mode: SizeMode::Stored(IntFieldSpec::u32_le(12)),
            size_unit: 1,
            termination: TableTermination::Counted(0),
        };
        let mut dir_bytes = Vec::new();
        dir_bytes.extend_from_slice(b"big.bin\0");
        dir_bytes.extend_from_slice(&350_000u32.to_le_bytes()); // ~716 MB
        dir_bytes.extend_from_slice(&4096u32.to_le_bytes());
        let carrier_len: u64 = 750 * 1024 * 1024;
        let views: Vec<_> =
            iter_fixed_record_table_counted_metadata(&dir_bytes, &DISC_SPEC, 1, carrier_len)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].name_str(), Some("big.bin"));
        assert_eq!(views[0].offset, 350_000 * 2048);
        assert_eq!(views[0].size, 4096);

        let parsed =
            parse_fixed_record_table_counted_metadata(&dir_bytes, &DISC_SPEC, 1, carrier_len)
                .unwrap();
        assert_eq!(parsed[0].offset, 350_000 * 2048);
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

        let mut oob = Vec::new();
        oob.extend_from_slice(b"ok\0\0");
        oob.extend_from_slice(&12u32.to_le_bytes());
        oob.extend_from_slice(&5u32.to_le_bytes());
        oob.extend_from_slice(b"123");
        assert!(matches!(
            parse_fixed_record_table(&oob, &SPEC),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));

        let mut bad_name = Vec::new();
        bad_name.extend_from_slice(&[0xFF, b'a', 0, 0]);
        bad_name.extend_from_slice(&12u32.to_le_bytes());
        bad_name.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_fixed_record_table(&bad_name, &SPEC),
            Err(LayoutError::InvalidName { index: 0 })
        );

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

        assert_eq!(
            parse_fixed_record_table_bounded(&oob, &SPEC, 0),
            Err(LayoutError::MaxEntriesExceeded { max: 0 })
        );
    }

    #[test]
    fn pack_fixed_record_table_round_trips_all_modes_widths_and_templates() {
        // 1. Counted + Stored + U64 BE + alignment + record_template + header_prefix
        const STORED_U64_BE: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 28,
            table_offset: 8,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 8, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u64_be(8)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u64_be(16)),
            size_unit: 1,
            termination: TableTermination::Counted(0),
        };
        let mut tmpl0 = [0u8; 28];
        tmpl0[24..28].copy_from_slice(b"FLAG");
        let policy = PackPolicy {
            data_alignment: 16,
            pad_byte: 0xCC,
            record_fill_byte: 0x00,
            pad_final_entry: true,
            prefix_fill_byte: 0xEE,
        };
        let inputs = [
            FixedRecordInput {
                name: Some(b"alpha"),
                payload: b"hello",
                record_template: Some(&tmpl0),
            },
            FixedRecordInput {
                name: Some(b"beta"),
                payload: b"world!",
                record_template: None,
            },
        ];
        let packed = pack_fixed_record_table(&STORED_U64_BE, &policy, b"HDR!", &inputs).unwrap();
        assert_eq!(&packed[0..4], b"HDR!");
        assert_eq!(&packed[4..8], &[0xEE; 4]);
        assert_eq!(&packed[8 + 24..8 + 28], b"FLAG");
        assert_eq!(packed.len() % 16, 0);

        let parsed = parse_fixed_record_table_counted(&packed, &STORED_U64_BE, 2).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name_str(), Some("alpha"));
        assert_eq!(parsed[0].offset % 16, 0);
        assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
        assert_eq!(parsed[1].name_str(), Some("beta"));
        assert_eq!(parsed[1].offset % 16, 0);
        assert_eq!(parsed[1].payload(&packed), Some(&b"world!"[..]));

        // 2. Sector-scaled U24 BE + ZeroRow + TableEnd
        const SECTOR_ZERO_ROW: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 8,
            table_offset: 0,
            max_entries: 16,
            name_field: None,
            offset_field: Some(IntFieldSpec::u24_be(0)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 2048,
            size_mode: SizeMode::Stored(IntFieldSpec::u32_be(4)),
            size_unit: 1,
            termination: TableTermination::ZeroRow,
        };
        let sec_inputs = [
            FixedRecordInput {
                name: None,
                payload: b"sector-one",
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                payload: b"sector-two",
                record_template: None,
            },
        ];
        let sec_packed =
            pack_fixed_record_table(&SECTOR_ZERO_ROW, &PackPolicy::TIGHT, &[], &sec_inputs)
                .unwrap();
        let sec_parsed = parse_fixed_record_table(&sec_packed, &SECTOR_ZERO_ROW).unwrap();
        assert_eq!(sec_parsed.len(), 2);
        assert_eq!(sec_parsed[0].offset, 2048);
        assert_eq!(sec_parsed[0].payload(&sec_packed), Some(&b"sector-one"[..]));
        assert_eq!(sec_parsed[1].offset, 4096);
        assert_eq!(sec_parsed[1].payload(&sec_packed), Some(&b"sector-two"[..]));

        // 3. FirstOffsetDerived + NextOffset + U16 LE
        const FIRST_DERIVED: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 8,
            table_offset: 0,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 6, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u16_le(6)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::NextOffset,
            size_unit: 1,
            termination: TableTermination::FirstOffsetDerived,
        };
        let fd_inputs = [
            FixedRecordInput {
                name: Some(b"a.bin"),
                payload: b"1234",
                record_template: None,
            },
            FixedRecordInput {
                name: Some(b"b.bin"),
                payload: b"567890",
                record_template: None,
            },
        ];
        let fd_packed =
            pack_fixed_record_table(&FIRST_DERIVED, &PackPolicy::TIGHT, &[], &fd_inputs).unwrap();
        let fd_parsed = parse_fixed_record_table(&fd_packed, &FIRST_DERIVED).unwrap();
        assert_eq!(fd_parsed.len(), 2);
        assert_eq!(fd_parsed[0].payload(&fd_packed), Some(&b"1234"[..]));
        assert_eq!(fd_parsed[1].payload(&fd_packed), Some(&b"567890"[..]));

        // 4. FirstByteZero + U8 fields
        const FIRST_BYTE_U8: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 6,
            table_offset: 0,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 4, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u8(4)),
            offset_base: OffsetBase::TableEnd,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u8(5)),
            size_unit: 1,
            termination: TableTermination::FirstByteZero,
        };
        let u8_inputs = [FixedRecordInput {
            name: Some(b"item"),
            payload: b"tiny",
            record_template: None,
        }];
        let u8_packed =
            pack_fixed_record_table(&FIRST_BYTE_U8, &PackPolicy::TIGHT, &[], &u8_inputs).unwrap();
        let u8_parsed = parse_fixed_record_table(&u8_packed, &FIRST_BYTE_U8).unwrap();
        assert_eq!(u8_parsed.len(), 1);
        assert_eq!(u8_parsed[0].name_str(), Some("item"));
        assert_eq!(u8_parsed[0].payload(&u8_packed), Some(&b"tiny"[..]));

        // 5. Eof termination with empty payloads (detached directory)
        const EOF_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            stride: 8,
            table_offset: 0,
            max_entries: 16,
            name_field: Some(NameFieldSpec::new(0, 4, NameEncoding::Ascii)),
            offset_field: Some(IntFieldSpec::u16_le(4)),
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode: SizeMode::Stored(IntFieldSpec::u16_le(6)),
            size_unit: 1,
            termination: TableTermination::Eof,
        };
        let eof_inputs = [
            FixedRecordInput {
                name: Some(b"rec0"),
                payload: &[],
                record_template: None,
            },
            FixedRecordInput {
                name: Some(b"rec1"),
                payload: &[],
                record_template: None,
            },
        ];
        let eof_packed =
            pack_fixed_record_table(&EOF_SPEC, &PackPolicy::TIGHT, &[], &eof_inputs).unwrap();
        let eof_parsed = parse_fixed_record_table(&eof_packed, &EOF_SPEC).unwrap();
        assert_eq!(eof_parsed.len(), 2);
        assert_eq!(eof_parsed[0].name_str(), Some("rec0"));
        assert_eq!(eof_parsed[1].name_str(), Some("rec1"));

        // 6. Out-of-range U8 size rejection
        let too_big = [FixedRecordInput {
            name: Some(b"big"),
            payload: &[0u8; 300],
            record_template: None,
        }];
        assert_eq!(
            pack_fixed_record_table(&FIRST_BYTE_U8, &PackPolicy::TIGHT, &[], &too_big),
            Err(LayoutError::ValueOutOfRange {
                value: 300,
                max: 255
            })
        );
    }
}
