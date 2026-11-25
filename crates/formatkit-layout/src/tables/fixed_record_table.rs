//! Declarative fixed-stride record table specification, checked parser, and symmetric writer.
//!
//! [`FixedRecordTableSpec`] describes fixed-stride directory tables with
//! configurable integer widths (`u8`/`u16`/`u24`/`u32`/`u64`), endianness,
//! optional embedded names, offset base/unit scaling, size derivation modes,
//! and table termination rules.

use crate::spec::{
    align_payload_offset, checked_align_up_multiple_u64, IntFieldSpec, LayoutError, OffsetBase,
    PackPolicy,
};

/// How an embedded or pooled name field is trimmed and validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameEncoding {
    /// Truncate at the first NUL byte (`0x00`), keeping the preceding raw bytes.
    NulTerminated,
    /// Truncate at the first NUL byte (`0x00`), then trim trailing ASCII spaces (`0x20`).
    NulOrSpacePadded,
    /// Truncate at the first NUL byte (`0x00`), trim trailing ASCII spaces (`0x20`),
    /// and require every remaining byte to be ASCII (`0x00..=0x7F`).
    Ascii,
    /// Truncate at the first NUL byte (`0x00`), require every preceding byte to be
    /// printable ASCII (`0x20..=0x7E`, rejecting control bytes `0x01..=0x1F` and `0x7F`
    /// before trimming), then trim trailing ASCII spaces (`0x20`).
    PrintableAscii,
}

fn apply_name_encoding(
    raw: &[u8],
    encoding: NameEncoding,
    index: usize,
) -> Result<&[u8], LayoutError> {
    let mut trimmed = raw;
    match encoding {
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
        NameEncoding::PrintableAscii => {
            if !raw.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                return Err(LayoutError::InvalidName { index });
            }
            while let Some(&last) = trimmed.last() {
                if last == b' ' {
                    trimmed = &trimmed[..trimmed.len() - 1];
                } else {
                    break;
                }
            }
        }
    }
    Ok(trimmed)
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
        apply_name_encoding(&slice[..nul_pos], self.encoding, index)
    }

    fn encode(self, record: &mut [u8], name: &[u8], index: usize) -> Result<(), LayoutError> {
        if name.len() > self.len || name.contains(&0) {
            return Err(LayoutError::InvalidName { index });
        }
        match self.encoding {
            NameEncoding::NulTerminated | NameEncoding::NulOrSpacePadded => {}
            NameEncoding::Ascii => {
                if !name.is_ascii() {
                    return Err(LayoutError::InvalidName { index });
                }
            }
            NameEncoding::PrintableAscii => {
                if !name.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    return Err(LayoutError::InvalidName { index });
                }
            }
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

/// Declarative descriptor for resolving each record's name from a NUL-terminated
/// external or in-carrier string pool via an integer offset field in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamePoolSpec {
    /// Integer field inside each record carrying the byte offset into the string pool.
    pub offset_field: IntFieldSpec,
    /// Base coordinate applied to the decoded offset to locate the NUL-terminated name.
    pub pool_base: OffsetBase,
    /// Trimming and validation rule applied to the decoded name bytes.
    pub encoding: NameEncoding,
    /// Maximum number of name bytes permitted (excluding the terminating NUL).
    pub max_len: usize,
}

impl NamePoolSpec {
    /// Construct a new string-pool name descriptor.
    #[must_use]
    pub const fn new(
        offset_field: IntFieldSpec,
        pool_base: OffsetBase,
        encoding: NameEncoding,
        max_len: usize,
    ) -> Self {
        Self {
            offset_field,
            pool_base,
            encoding,
            max_len,
        }
    }

    fn decode_borrowed<'a>(
        self,
        pool_data: &'a [u8],
        table_start: u64,
        table_end: u64,
        record_offset: usize,
        record: &[u8],
        index: usize,
    ) -> Result<&'a [u8], LayoutError> {
        let raw_off = self.offset_field.read(record)?;
        let name_off_u64 = self
            .pool_base
            .apply(raw_off, table_start, table_end, record_offset)?;
        let name_off = usize::try_from(name_off_u64).map_err(|_| LayoutError::Overflow {
            what: "name_pool_offset",
        })?;
        if name_off >= pool_data.len() {
            return Err(LayoutError::OutOfBounds {
                index,
                offset: name_off_u64,
                size: 1,
                data_len: pool_data.len() as u64,
            });
        }
        let tail = &pool_data[name_off..];
        let scan_limit = tail.len().min(self.max_len.saturating_add(1));
        let Some(nul_pos) = tail[..scan_limit].iter().position(|&b| b == 0) else {
            return Err(LayoutError::InvalidName { index });
        };
        if nul_pos > self.max_len {
            return Err(LayoutError::InvalidName { index });
        }
        apply_name_encoding(&tail[..nul_pos], self.encoding, index)
    }

    fn validate_name_bytes(self, name: &[u8], index: usize) -> Result<(), LayoutError> {
        if name.len() > self.max_len || name.contains(&0) {
            return Err(LayoutError::InvalidName { index });
        }
        match self.encoding {
            NameEncoding::NulTerminated | NameEncoding::NulOrSpacePadded => {}
            NameEncoding::Ascii => {
                if !name.is_ascii() {
                    return Err(LayoutError::InvalidName { index });
                }
            }
            NameEncoding::PrintableAscii => {
                if !name.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    return Err(LayoutError::InvalidName { index });
                }
            }
        }
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
    /// Each record's `offset_field` stores a size (scaled by [`FixedRecordTableSpec::size_unit`]),
    /// and entry offsets start at `start` and advance by `align_up(size, align)` after each entry
    /// (with `align >= 1`).
    CumulativeAligned {
        /// Initial byte offset of the first entry.
        start: u64,
        /// Alignment multiple applied to each entry's byte size when advancing the cursor (`>= 1`).
        align: u64,
    },
    /// Each record's `offset_field` stores a size (scaled by [`FixedRecordTableSpec::size_unit`]),
    /// and entry offsets start at `table_end + bias` and advance by `align_up(size, align)` after
    /// each entry (with `align >= 1`).
    CumulativeFromTableEnd {
        /// Byte offset added to `table_end` to locate the first entry.
        bias: u64,
        /// Alignment multiple applied to each entry's byte size when advancing the cursor (`>= 1`).
        align: u64,
    },
    /// Each record stores an explicit exclusive end-offset field (scaled by
    /// [`FixedRecordTableSpec::offset_unit`] and [`FixedRecordTableSpec::offset_base`]),
    /// computing `size = end_offset - start_offset`.
    EndOffset(IntFieldSpec),
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
    /// Table terminates at the first record where `field.read(row) == value`.
    FieldEquals {
        /// Integer field inspected in each record.
        field: IntFieldSpec,
        /// Sentinel value that terminates the table when matched.
        value: u64,
    },
    /// Table terminates at the first record where `field.read(row) != value`.
    FieldNotEquals {
        /// Integer field inspected in each record.
        field: IntFieldSpec,
        /// Active value required for data rows; the first row where the field differs terminates the table.
        value: u64,
    },
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
///     name_pool: None,
///     key_field: None,
///     offset_field: Some(IntFieldSpec::u32_le(8)),
///     offset_base: OffsetBase::Absolute,
///     offset_unit: 1,
///     size_mode: SizeMode::Stored(IntFieldSpec::u32_le(12)),
///     size_unit: 1,
///     termination: TableTermination::Counted(1),
///     skip_empty_zero: false,
///     skip_field_equals: None,
///     sentinel_closes_next_offset: false,
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
    /// Optional external/in-carrier NUL-terminated string-pool name descriptor
    /// (mutually exclusive with [`FixedRecordTableSpec::name_field`]).
    pub name_pool: Option<NamePoolSpec>,
    /// Optional integer key or hash field decoded alongside each record.
    pub key_field: Option<IntFieldSpec>,
    /// Optional integer field carrying the entry offset (or size in cumulative modes).
    pub offset_field: Option<IntFieldSpec>,
    /// Base coordinate applied to scaled offsets.
    pub offset_base: OffsetBase,
    /// Non-zero byte multiplier applied to decoded offset values (e.g. `1` or `2048`).
    pub offset_unit: u64,
    /// How each entry's payload size is determined.
    pub size_mode: SizeMode,
    /// Non-zero byte multiplier applied to [`SizeMode::Stored`], [`SizeMode::CumulativeFrom`],
    /// [`SizeMode::CumulativeAligned`], and [`SizeMode::CumulativeFromTableEnd`] size values.
    pub size_unit: u64,
    /// How the number of records in the table is determined.
    pub termination: TableTermination,
    /// When `true`, skip all-zero or `(offset == 0, size/end == 0)` tombstone rows while
    /// preserving each surviving entry's physical slot `index`.
    pub skip_empty_zero: bool,
    /// Optional `(field, value)` predicate skipping interior tombstone/free slots where
    /// `field.read(row) == value` while preserving physical slot `index`.
    pub skip_field_equals: Option<(IntFieldSpec, u64)>,
    /// When `true` with [`SizeMode::NextOffset`] and a sentinel-based termination
    /// (`ZeroRow`, `FirstByteZero`, `FieldEquals`, or `FieldNotEquals`), use the terminating
    /// sentinel row's `offset_field` as the exclusive end offset for the final entry instead
    /// of `carrier_len`.
    pub sentinel_closes_next_offset: bool,
}

impl FixedRecordTableSpec {
    /// Construct a [`FixedRecordTableSpec`] with sensible defaults (`name_field: None`,
    /// `name_pool: None`, `key_field: None`, `offset_base: OffsetBase::Absolute`,
    /// `offset_unit: 1`, `size_unit: 1`, `skip_empty_zero: false`,
    /// `skip_field_equals: None`, `sentinel_closes_next_offset: false`).
    #[must_use]
    pub const fn new(
        stride: usize,
        table_offset: usize,
        max_entries: usize,
        offset_field: Option<IntFieldSpec>,
        size_mode: SizeMode,
        termination: TableTermination,
    ) -> Self {
        Self {
            stride,
            table_offset,
            max_entries,
            name_field: None,
            name_pool: None,
            key_field: None,
            offset_field,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            size_mode,
            size_unit: 1,
            termination,
            skip_empty_zero: false,
            skip_field_equals: None,
            sentinel_closes_next_offset: false,
        }
    }

    /// Attach an embedded fixed-width [`NameFieldSpec`].
    #[must_use]
    pub const fn with_name_field(mut self, name_field: NameFieldSpec) -> Self {
        self.name_field = Some(name_field);
        self
    }

    /// Attach a string-pool [`NamePoolSpec`].
    #[must_use]
    pub const fn with_name_pool(mut self, name_pool: NamePoolSpec) -> Self {
        self.name_pool = Some(name_pool);
        self
    }

    /// Attach an optional key/hash [`IntFieldSpec`].
    #[must_use]
    pub const fn with_key_field(mut self, key_field: IntFieldSpec) -> Self {
        self.key_field = Some(key_field);
        self
    }

    /// Set [`FixedRecordTableSpec::offset_base`].
    #[must_use]
    pub const fn with_offset_base(mut self, offset_base: OffsetBase) -> Self {
        self.offset_base = offset_base;
        self
    }

    /// Set [`FixedRecordTableSpec::offset_unit`].
    #[must_use]
    pub const fn with_offset_unit(mut self, offset_unit: u64) -> Self {
        self.offset_unit = offset_unit;
        self
    }

    /// Set [`FixedRecordTableSpec::size_unit`].
    #[must_use]
    pub const fn with_size_unit(mut self, size_unit: u64) -> Self {
        self.size_unit = size_unit;
        self
    }

    /// Enable or disable empty-zero tombstone row skipping.
    #[must_use]
    pub const fn with_skip_empty_zero(mut self, skip: bool) -> Self {
        self.skip_empty_zero = skip;
        self
    }

    /// Skip interior tombstone/free slots where `field.read(row) == value`.
    #[must_use]
    pub const fn with_skip_field_equals(mut self, field: IntFieldSpec, value: u64) -> Self {
        self.skip_field_equals = Some((field, value));
        self
    }

    /// Use the terminating sentinel row's `offset_field` as the exclusive end offset
    /// of the final entry under [`SizeMode::NextOffset`].
    #[must_use]
    pub const fn with_sentinel_closes_next_offset(mut self, enabled: bool) -> Self {
        self.sentinel_closes_next_offset = enabled;
        self
    }
}

/// Zero-allocation borrowed view of one validated entry decoded from a [`FixedRecordTableSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRecordView<'a> {
    /// Zero-based physical slot index in the table.
    pub index: usize,
    /// Byte offset of this entry's record within the table buffer.
    pub record_offset: usize,
    /// Resolved byte offset of the payload within the carrier.
    pub offset: u64,
    /// Resolved byte size of the payload.
    pub size: u64,
    /// Borrowed decoded name bytes when [`FixedRecordTableSpec::name_field`] or
    /// [`FixedRecordTableSpec::name_pool`] is configured.
    pub name: Option<&'a [u8]>,
    /// Decoded integer key or hash when [`FixedRecordTableSpec::key_field`] is configured.
    pub key: Option<u64>,
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
            key: self.key,
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
    /// Zero-based physical slot index in the table.
    pub index: usize,
    /// Byte offset of this entry's record within the carrier.
    pub record_offset: usize,
    /// Resolved byte offset of the payload within the carrier.
    pub offset: u64,
    /// Resolved byte size of the payload.
    pub size: u64,
    /// Decoded name bytes when [`FixedRecordTableSpec::name_field`] or
    /// [`FixedRecordTableSpec::name_pool`] is configured.
    pub name: Option<Vec<u8>>,
    /// Decoded integer key or hash when [`FixedRecordTableSpec::key_field`] is configured.
    pub key: Option<u64>,
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
    name_pool_data: &'a [u8],
    carrier_len: u64,
    next_offset_terminal: u64,
    spec: FixedRecordTableSpec,
    raw_count: usize,
    active_count: usize,
    remaining: usize,
    table_end: u64,
    next_index: usize,
    cumulative_cursor: u64,
    prev_offset: Option<u64>,
}

fn is_empty_zero_row(spec: &FixedRecordTableSpec, record: &[u8]) -> Result<bool, LayoutError> {
    if record.iter().all(|&b| b == 0) {
        return Ok(true);
    }
    match spec.size_mode {
        SizeMode::Stored(size_field) => {
            if let Some(offset_field) = spec.offset_field {
                return Ok(offset_field.read(record)? == 0 && size_field.read(record)? == 0);
            }
        }
        SizeMode::EndOffset(end_field) => {
            if let Some(offset_field) = spec.offset_field {
                return Ok(offset_field.read(record)? == 0 && end_field.read(record)? == 0);
            }
        }
        SizeMode::NextOffset
        | SizeMode::CumulativeFrom(_)
        | SizeMode::CumulativeAligned { .. }
        | SizeMode::CumulativeFromTableEnd { .. }
        | SizeMode::FixedSlot(_) => {}
    }
    Ok(false)
}

fn is_skipped_row(spec: &FixedRecordTableSpec, record: &[u8]) -> Result<bool, LayoutError> {
    if spec.skip_empty_zero && is_empty_zero_row(spec, record)? {
        return Ok(true);
    }
    if let Some((field, value)) = spec.skip_field_equals {
        if field.read(record)? == value {
            return Ok(true);
        }
    }
    Ok(false)
}

impl<'a> FixedRecordTableIter<'a> {
    /// Total number of non-skipped entries identified in the table.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.active_count
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
        self.spec.offset_base.apply(
            scaled,
            self.spec.table_offset as u64,
            self.table_end,
            record_offset,
        )
    }

    fn next_non_skipped_record(
        &self,
        start_index: usize,
    ) -> Result<Option<(usize, &'a [u8])>, LayoutError> {
        let mut idx = start_index;
        while idx < self.raw_count {
            let (rec_off, rec) = self.record_slice(idx)?;
            if is_skipped_row(&self.spec, rec)? {
                idx += 1;
                continue;
            }
            return Ok(Some((rec_off, rec)));
        }
        Ok(None)
    }

    fn decode_entry(&mut self, index: usize) -> Result<FixedRecordView<'a>, LayoutError> {
        let (record_offset, record) = self.record_slice(index)?;
        let name = if let Some(name_spec) = self.spec.name_field {
            Some(name_spec.decode_borrowed(record, index)?)
        } else if let Some(pool_spec) = self.spec.name_pool {
            Some(pool_spec.decode_borrowed(
                self.name_pool_data,
                self.spec.table_offset as u64,
                self.table_end,
                record_offset,
                record,
                index,
            )?)
        } else {
            None
        };
        let key = match self.spec.key_field {
            Some(kf) => Some(kf.read(record)?),
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
                let next_offset = if let Some((next_rec_off, next_rec)) =
                    self.next_non_skipped_record(index + 1)?
                {
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
                    if self.next_offset_terminal < offset {
                        return Err(LayoutError::NonMonotonic {
                            index: index + 1,
                            previous: offset,
                            current: self.next_offset_terminal,
                        });
                    }
                    self.next_offset_terminal
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
            SizeMode::CumulativeAligned { start: _, align }
            | SizeMode::CumulativeFromTableEnd { bias: _, align } => {
                let size_field = self.spec.offset_field.ok_or(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required as size source for cumulative aligned size mode",
                })?;
                let raw_size = size_field.read(record)?;
                let size =
                    raw_size
                        .checked_mul(self.spec.size_unit)
                        .ok_or(LayoutError::Overflow {
                            what: "cumulative_size",
                        })?;
                let offset = self.cumulative_cursor;
                let aligned_step =
                    checked_align_up_multiple_u64(size, align).ok_or(LayoutError::Overflow {
                        what: "cumulative_aligned_step",
                    })?;
                let next_cursor =
                    offset
                        .checked_add(aligned_step)
                        .ok_or(LayoutError::Overflow {
                            what: "cumulative_end",
                        })?;
                self.cumulative_cursor = next_cursor;
                (offset, size)
            }
            SizeMode::EndOffset(end_field) => {
                let offset_field = self.spec.offset_field.ok_or(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for SizeMode::EndOffset",
                })?;
                let offset = self.resolve_record_offset(record, record_offset, offset_field)?;
                let end_offset = self.resolve_record_offset(record, record_offset, end_field)?;
                if end_offset < offset {
                    return Err(LayoutError::NonMonotonic {
                        index,
                        previous: offset,
                        current: end_offset,
                    });
                }
                (offset, end_offset - offset)
            }
            SizeMode::FixedSlot(slot_size) => {
                let offset = if let Some(offset_field) = self.spec.offset_field {
                    self.resolve_record_offset(record, record_offset, offset_field)?
                } else {
                    let delta =
                        (index as u64)
                            .checked_mul(slot_size)
                            .ok_or(LayoutError::Overflow {
                                what: "fixed_slot_offset",
                            })?;
                    self.spec.offset_base.apply(
                        delta,
                        self.spec.table_offset as u64,
                        self.table_end,
                        record_offset,
                    )?
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
            key,
        })
    }
}

impl<'a> Iterator for FixedRecordTableIter<'a> {
    type Item = Result<FixedRecordView<'a>, LayoutError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_index < self.raw_count {
            let index = self.next_index;
            self.next_index += 1;
            if self.spec.skip_empty_zero || self.spec.skip_field_equals.is_some() {
                match self
                    .record_slice(index)
                    .and_then(|(_, rec)| is_skipped_row(&self.spec, rec))
                {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        self.remaining = self.remaining.saturating_sub(1);
                        return Some(Err(e));
                    }
                }
            }
            self.remaining = self.remaining.saturating_sub(1);
            return Some(self.decode_entry(index));
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for FixedRecordTableIter<'_> {}

fn validate_field_in_stride(
    field: IntFieldSpec,
    stride: usize,
    spec_field: &'static str,
) -> Result<(), LayoutError> {
    field.validate()?;
    let end = field.end_offset().ok_or(LayoutError::InvalidSpec {
        field: spec_field,
        reason: "offset + width overflows usize",
    })?;
    if end > stride {
        return Err(LayoutError::InvalidSpec {
            field: spec_field,
            reason: "exceeds record stride",
        });
    }
    Ok(())
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
    if spec.name_field.is_some() && spec.name_pool.is_some() {
        return Err(LayoutError::InvalidSpec {
            field: "name_pool",
            reason: "cannot specify both name_field and name_pool",
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
    if let Some(pool) = spec.name_pool {
        validate_field_in_stride(pool.offset_field, spec.stride, "name_pool")?;
        if pool.max_len == 0 {
            return Err(LayoutError::InvalidSpec {
                field: "name_pool",
                reason: "max_len must be nonzero",
            });
        }
    }
    if let Some(key_field) = spec.key_field {
        validate_field_in_stride(key_field, spec.stride, "key_field")?;
    }
    if let Some(field) = spec.offset_field {
        validate_field_in_stride(field, spec.stride, "offset_field")?;
    }
    if let Some((skip_field, _)) = spec.skip_field_equals {
        validate_field_in_stride(skip_field, spec.stride, "skip_field_equals")?;
    }
    if spec.sentinel_closes_next_offset {
        if !matches!(spec.size_mode, SizeMode::NextOffset) {
            return Err(LayoutError::InvalidSpec {
                field: "sentinel_closes_next_offset",
                reason: "requires SizeMode::NextOffset",
            });
        }
        if !matches!(
            spec.termination,
            TableTermination::ZeroRow
                | TableTermination::FirstByteZero
                | TableTermination::FieldEquals { .. }
                | TableTermination::FieldNotEquals { .. }
        ) {
            return Err(LayoutError::InvalidSpec {
                field: "sentinel_closes_next_offset",
                reason: "requires sentinel-based TableTermination",
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
            validate_field_in_stride(size_field, spec.stride, "size_mode")?;
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
        SizeMode::CumulativeAligned { align, .. }
        | SizeMode::CumulativeFromTableEnd { align, .. } => {
            if align == 0 {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "cumulative align must be nonzero",
                });
            }
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required as size field for cumulative aligned size mode",
                });
            }
        }
        SizeMode::EndOffset(end_field) => {
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for SizeMode::EndOffset",
                });
            }
            validate_field_in_stride(end_field, spec.stride, "size_mode")?;
        }
        SizeMode::FixedSlot(_) => {
            if spec.offset_field.is_none()
                && matches!(spec.offset_base, OffsetBase::SubtractBase(_))
            {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_base",
                    reason: "OffsetBase::SubtractBase requires offset_field",
                });
            }
        }
    }
    match spec.termination {
        TableTermination::FieldEquals { field, .. }
        | TableTermination::FieldNotEquals { field, .. } => {
            validate_field_in_stride(field, spec.stride, "termination")?;
        }
        TableTermination::FirstOffsetDerived => {
            if matches!(
                spec.size_mode,
                SizeMode::CumulativeFrom(_)
                    | SizeMode::CumulativeAligned { .. }
                    | SizeMode::CumulativeFromTableEnd { .. }
            ) {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "cumulative size modes cannot be combined with TableTermination::FirstOffsetDerived",
                });
            }
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required for TableTermination::FirstOffsetDerived",
                });
            }
            if matches!(
                spec.offset_base,
                OffsetBase::TableEnd | OffsetBase::TableEndPlus(_)
            ) {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_base",
                    reason:
                        "table-end-relative offset_base is circular with TableTermination::FirstOffsetDerived",
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// Create a checked, zero-allocation iterator over a fixed-stride record table.
pub fn iter_fixed_record_table<'a>(
    data: &'a [u8],
    spec: &FixedRecordTableSpec,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    iter_fixed_record_table_inner(data, data, spec, spec.max_entries, data.len() as u64)
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`,
/// validating payload ranges against a full `carrier_len` without loading the carrier into RAM.
pub fn iter_fixed_record_table_metadata<'a>(
    table_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    iter_fixed_record_table_inner(table_data, table_data, spec, spec.max_entries, carrier_len)
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`
/// with a separate `name_pool_data` slice and external `carrier_len`.
pub fn iter_fixed_record_table_with_name_pool<'a>(
    table_data: &'a [u8],
    name_pool_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    iter_fixed_record_table_inner(
        table_data,
        name_pool_data,
        spec,
        spec.max_entries,
        carrier_len,
    )
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
        table_data,
        &counted_spec,
        counted_spec.max_entries,
        carrier_len,
    )
}

fn iter_fixed_record_table_inner<'a>(
    table_data: &'a [u8],
    name_pool_data: &'a [u8],
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

    let (raw_count, table_end_usize, sentinel_record_offset) = match spec.termination {
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
            (count, end, None)
        }
        TableTermination::ZeroRow
        | TableTermination::FirstByteZero
        | TableTermination::FieldEquals { .. }
        | TableTermination::FieldNotEquals { .. } => {
            let mut pos = spec.table_offset;
            let mut count = 0usize;
            let mut sentinel_off = None;
            while let Some(end) = pos.checked_add(spec.stride) {
                if end > table_data.len() {
                    break;
                }
                let row = &table_data[pos..end];
                let is_sentinel = match spec.termination {
                    TableTermination::ZeroRow => row.iter().all(|&b| b == 0),
                    TableTermination::FirstByteZero => row[0] == 0,
                    TableTermination::FieldEquals { field, value } => field.read(row)? == value,
                    TableTermination::FieldNotEquals { field, value } => field.read(row)? != value,
                    _ => unreachable!(),
                };
                if is_sentinel {
                    sentinel_off = Some(pos);
                    pos = end;
                    break;
                }
                if count >= effective_max {
                    return Err(LayoutError::MaxEntriesExceeded { max: effective_max });
                }
                count += 1;
                pos = end;
            }
            if sentinel_off.is_none()
                && pos < table_data.len()
                && table_data.len() - pos < spec.stride
            {
                return Err(LayoutError::Truncated {
                    offset: pos,
                    needed: spec.stride,
                    available: table_data.len() - pos,
                });
            }
            (count, pos, sentinel_off)
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
            let first_offset =
                spec.offset_base
                    .apply(scaled, spec.table_offset as u64, 0, spec.table_offset)?;
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
            (count, end, None)
        }
        TableTermination::Eof => {
            let remaining = table_data.len() - spec.table_offset;
            let count = remaining / spec.stride;
            if count > effective_max {
                return Err(LayoutError::MaxEntriesExceeded { max: effective_max });
            }
            let end = spec.table_offset + count * spec.stride;
            (count, end, None)
        }
    };

    let active_count = if spec.skip_empty_zero || spec.skip_field_equals.is_some() {
        let mut active = 0usize;
        for idx in 0..raw_count {
            let start = spec.table_offset + idx * spec.stride;
            let row = &table_data[start..start + spec.stride];
            if !is_skipped_row(spec, row)? {
                active += 1;
            }
        }
        active
    } else {
        raw_count
    };

    let table_start = spec.table_offset as u64;
    let table_end = table_end_usize as u64;
    let next_offset_terminal = if spec.sentinel_closes_next_offset {
        if let Some(sent_off) = sentinel_record_offset {
            let sentinel_rec = &table_data[sent_off..sent_off + spec.stride];
            let offset_field = spec.offset_field.expect("validated above");
            let raw = offset_field.read(sentinel_rec)?;
            let scaled = raw
                .checked_mul(spec.offset_unit)
                .ok_or(LayoutError::Overflow {
                    what: "scaled_offset",
                })?;
            let end_off = spec
                .offset_base
                .apply(scaled, table_start, table_end, sent_off)?;
            if end_off > carrier_len {
                return Err(LayoutError::OutOfBounds {
                    index: raw_count,
                    offset: end_off,
                    size: 0,
                    data_len: carrier_len,
                });
            }
            end_off
        } else {
            carrier_len
        }
    } else {
        carrier_len
    };

    let cumulative_cursor = match spec.size_mode {
        SizeMode::CumulativeFrom(start) | SizeMode::CumulativeAligned { start, .. } => start,
        SizeMode::CumulativeFromTableEnd { bias, .. } => {
            table_end.checked_add(bias).ok_or(LayoutError::Overflow {
                what: "cumulative_start",
            })?
        }
        _ => 0,
    };

    Ok(FixedRecordTableIter {
        data: table_data,
        name_pool_data,
        carrier_len,
        next_offset_terminal,
        spec: *spec,
        raw_count,
        active_count,
        remaining: active_count,
        table_end,
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
    let iter = iter_fixed_record_table_inner(data, data, spec, max_entries, data.len() as u64)?;
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

/// Parse staged directory bytes `table_data` using a separate `name_pool_data` slice
/// and external `carrier_len`.
pub fn parse_fixed_record_table_with_name_pool(
    table_data: &[u8],
    name_pool_data: &[u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    let iter =
        iter_fixed_record_table_with_name_pool(table_data, name_pool_data, spec, carrier_len)?;
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
    /// Optional entry name bytes (written when [`FixedRecordTableSpec::name_field`] or
    /// [`FixedRecordTableSpec::name_pool`] is configured).
    pub name: Option<&'a [u8]>,
    /// Optional integer key or hash (written when [`FixedRecordTableSpec::key_field`] is configured).
    pub key: Option<u64>,
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
/// [`TableTermination::ZeroRow`], [`TableTermination::FirstByteZero`],
/// [`TableTermination::FieldEquals`], or [`TableTermination::FieldNotEquals`]),
/// an optional NUL-terminated string pool when [`FixedRecordTableSpec::name_pool`]
/// is configured, and then the aligned payloads.
pub fn pack_fixed_record_table(
    spec: &FixedRecordTableSpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    entries: &[FixedRecordInput<'_>],
) -> Result<Vec<u8>, LayoutError> {
    pack_fixed_record_table_with_post_table(spec, policy, header_prefix, &[], entries)
}

/// Serialize `entries` into a binary carrier conforming to `spec` and `policy`,
/// inserting `post_table` verbatim between the end of the record table (including
/// any sentinel row) and the string pool / first payload.
pub fn pack_fixed_record_table_with_post_table(
    spec: &FixedRecordTableSpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    post_table: &[u8],
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
        TableTermination::ZeroRow
        | TableTermination::FirstByteZero
        | TableTermination::FieldEquals { .. }
        | TableTermination::FieldNotEquals { .. } => 1usize,
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
            if !post_table.is_empty() {
                return Err(LayoutError::InvalidInput {
                    index: 0,
                    reason: "TableTermination::Eof cannot pack non-empty post_table",
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
    let table_start_u64 = spec.table_offset as u64;
    let table_end_u64 = table_end as u64;

    if !post_table.is_empty() && matches!(spec.termination, TableTermination::FirstOffsetDerived) {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "post_table cannot be placed before first payload under FirstOffsetDerived",
        });
    }
    let post_table_end_u64 =
        table_end_u64
            .checked_add(post_table.len() as u64)
            .ok_or(LayoutError::Overflow {
                what: "post_table_end",
            })?;

    // Optional string pool planning (K6)
    let mut pool_buf: Vec<u8> = Vec::new();
    let mut pool_start_u64 = post_table_end_u64;
    let mut raw_name_offsets: Vec<u64> = Vec::new();
    if let Some(pool) = spec.name_pool {
        match pool.pool_base {
            OffsetBase::Fixed(base) => {
                if base < post_table_end_u64 {
                    return Err(LayoutError::InvalidSpec {
                        field: "name_pool",
                        reason: "Fixed pool_base overlaps record table or post_table",
                    });
                }
                pool_start_u64 = base;
            }
            OffsetBase::TableEndPlus(bias) => {
                let biased = table_end_u64
                    .checked_add(bias)
                    .ok_or(LayoutError::Overflow {
                        what: "name_pool_start",
                    })?;
                if biased < post_table_end_u64 {
                    return Err(LayoutError::InvalidSpec {
                        field: "name_pool",
                        reason: "TableEndPlus pool_base overlaps post_table",
                    });
                }
                pool_start_u64 = biased;
            }
            _ => {}
        }
        raw_name_offsets
            .try_reserve_exact(entries.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: entries.len(),
            })?;
        for (index, entry) in entries.iter().enumerate() {
            let name_bytes = entry.name.unwrap_or(&[]);
            pool.validate_name_bytes(name_bytes, index)?;
            let rel = pool_buf.len() as u64;
            let abs_off = pool_start_u64
                .checked_add(rel)
                .ok_or(LayoutError::Overflow {
                    what: "name_pool_offset",
                })?;
            let record_offset = spec.table_offset + index * spec.stride;
            let raw_off = pool.pool_base.encode_exact(
                abs_off,
                table_start_u64,
                table_end_u64,
                record_offset,
                1,
                index,
                "name_pool offset cannot be encoded",
            )?;
            raw_name_offsets.push(raw_off);
            pool_buf.extend_from_slice(name_bytes);
            pool_buf.push(0);
        }
    }
    let pool_end_u64 =
        pool_start_u64
            .checked_add(pool_buf.len() as u64)
            .ok_or(LayoutError::Overflow {
                what: "name_pool_end",
            })?;
    if !pool_buf.is_empty() && matches!(spec.termination, TableTermination::FirstOffsetDerived) {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "name_pool cannot be placed before first payload under FirstOffsetDerived",
        });
    }
    let min_data_start = post_table_end_u64.max(pool_end_u64);

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
        SizeMode::CumulativeFrom(start) | SizeMode::CumulativeAligned { start, .. } => {
            if start < min_data_start {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason:
                        "cumulative start offset overlaps record table, post_table, or string pool",
                });
            }
            start
        }
        SizeMode::CumulativeFromTableEnd { bias, .. } => {
            let start = table_end_u64
                .checked_add(bias)
                .ok_or(LayoutError::Overflow {
                    what: "cumulative_start",
                })?;
            if start < min_data_start {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "cumulative start offset overlaps post_table or string pool",
                });
            }
            start
        }
        _ => min_data_start,
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
                let (offset_u64, raw_offset) = if index == 0
                    && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                {
                    let raw = spec.offset_base.encode_exact(
                        table_end_u64,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                        spec.offset_unit,
                        index,
                        "table_end cannot be encoded for FirstOffsetDerived",
                    )?;
                    (table_end_u64, raw)
                } else {
                    spec.offset_base.align_and_encode(
                        cursor,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                        policy.data_alignment,
                        spec.offset_unit,
                    )?
                };
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
                let (offset_u64, raw_offset) = if index == 0
                    && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                {
                    let raw = spec.offset_base.encode_exact(
                        table_end_u64,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                        spec.offset_unit,
                        index,
                        "table_end cannot be encoded for FirstOffsetDerived",
                    )?;
                    (table_end_u64, raw)
                } else {
                    spec.offset_base.align_and_encode(
                        cursor,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                        policy.data_alignment,
                        spec.offset_unit,
                    )?
                };
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
            SizeMode::CumulativeAligned { start: _, align }
            | SizeMode::CumulativeFromTableEnd { bias: _, align } => {
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
                let step = if index + 1 < entries.len() || policy.pad_final_entry {
                    checked_align_up_multiple_u64(payload_len_u64, align).ok_or(
                        LayoutError::Overflow {
                            what: "cumulative_aligned_step",
                        },
                    )?
                } else {
                    payload_len_u64
                };
                cursor = cursor
                    .checked_add(step)
                    .ok_or(LayoutError::Overflow { what: "entry_end" })?;
                planned.push(PlannedEntry {
                    payload_offset,
                    raw_offset: Some(raw_size),
                    raw_size: None,
                });
            }
            SizeMode::EndOffset(_) => {
                let (offset_u64, raw_offset) = if index == 0
                    && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                {
                    let raw = spec.offset_base.encode_exact(
                        table_end_u64,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                        spec.offset_unit,
                        index,
                        "table_end cannot be encoded for FirstOffsetDerived",
                    )?;
                    (table_end_u64, raw)
                } else {
                    spec.offset_base.align_and_encode(
                        cursor,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                        policy.data_alignment,
                        spec.offset_unit,
                    )?
                };
                let end_u64 = offset_u64
                    .checked_add(payload_len_u64)
                    .ok_or(LayoutError::Overflow { what: "entry_end" })?;
                let raw_end = spec.offset_base.encode_exact(
                    end_u64,
                    table_start_u64,
                    table_end_u64,
                    record_offset,
                    spec.offset_unit,
                    index,
                    "end offset is not representable with offset_base and offset_unit",
                )?;
                let payload_offset =
                    usize::try_from(offset_u64).map_err(|_| LayoutError::Overflow {
                        what: "payload_offset",
                    })?;
                cursor = end_u64;
                planned.push(PlannedEntry {
                    payload_offset,
                    raw_offset: Some(raw_offset),
                    raw_size: Some(raw_end),
                });
            }
            SizeMode::FixedSlot(slot_size) => {
                if payload_len_u64 > slot_size {
                    return Err(LayoutError::InvalidInput {
                        index,
                        reason: "payload exceeds FixedSlot size",
                    });
                }
                let (offset_u64, raw_offset) = if spec.offset_field.is_some() {
                    let (off, raw) = if index == 0
                        && matches!(spec.termination, TableTermination::FirstOffsetDerived)
                    {
                        let r = spec.offset_base.encode_exact(
                            table_end_u64,
                            table_start_u64,
                            table_end_u64,
                            record_offset,
                            spec.offset_unit,
                            index,
                            "table_end cannot be encoded for FirstOffsetDerived",
                        )?;
                        (table_end_u64, r)
                    } else {
                        spec.offset_base.align_and_encode(
                            cursor,
                            table_start_u64,
                            table_end_u64,
                            record_offset,
                            policy.data_alignment,
                            spec.offset_unit,
                        )?
                    };
                    (off, Some(raw))
                } else {
                    let delta =
                        (index as u64)
                            .checked_mul(slot_size)
                            .ok_or(LayoutError::Overflow {
                                what: "fixed_slot_offset",
                            })?;
                    let off = spec.offset_base.apply(
                        delta,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                    )?;
                    if off < min_data_start {
                        return Err(LayoutError::InvalidInput {
                            index,
                            reason:
                                "FixedSlot offset overlaps record table, post_table, or string pool",
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

    let sentinel_end_raw = if sentinel_rows == 1 && spec.sentinel_closes_next_offset {
        let sentinel_record_offset = spec.table_offset + entries.len() * spec.stride;
        let sentinel_align = if policy.pad_final_entry {
            policy.data_alignment
        } else {
            1
        };
        let (end_u64, raw_sentinel) = spec.offset_base.align_and_encode(
            cursor,
            table_start_u64,
            table_end_u64,
            sentinel_record_offset,
            sentinel_align,
            spec.offset_unit,
        )?;
        cursor = end_u64;
        Some(raw_sentinel)
    } else {
        if policy.pad_final_entry
            && policy.data_alignment > 1
            && !matches!(spec.termination, TableTermination::Eof)
        {
            cursor = align_payload_offset(cursor, 0, policy.data_alignment, 1)?;
        }
        None
    };

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
        if let Some(pool) = spec.name_pool {
            pool.offset_field.write(rec, raw_name_offsets[index])?;
        }
        if let Some(key_field) = spec.key_field {
            if let Some(key) = entry.key {
                key_field.write(rec, key)?;
            } else if entry.record_template.is_none() {
                key_field.write(rec, 0)?;
            }
        }

        if let (Some(offset_field), Some(raw_off)) = (spec.offset_field, plan.raw_offset) {
            offset_field.write(rec, raw_off)?;
        }
        if let (SizeMode::Stored(field) | SizeMode::EndOffset(field), Some(raw_val)) =
            (spec.size_mode, plan.raw_size)
        {
            field.write(rec, raw_val)?;
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
            TableTermination::FieldEquals { field, value } if field.read(rec)? == value => {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "encoded record matches TableTermination::FieldEquals sentinel",
                });
            }
            TableTermination::FieldNotEquals { field, value } if field.read(rec)? != value => {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "encoded record does not match TableTermination::FieldNotEquals active value",
                });
            }
            _ => {}
        }
        if let Some((skip_field, skip_value)) = spec.skip_field_equals {
            if skip_field.read(rec)? == skip_value {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "encoded record matches skip_field_equals tombstone",
                });
            }
        }
    }

    // Sentinel row
    if sentinel_rows == 1 {
        let sentinel_start = spec.table_offset + entries.len() * spec.stride;
        let sentinel_rec = &mut out[sentinel_start..sentinel_start + spec.stride];
        sentinel_rec.fill(0);
        if let Some(raw_end) = sentinel_end_raw {
            let offset_field = spec.offset_field.expect("validated above");
            offset_field.write(sentinel_rec, raw_end)?;
        }
        match spec.termination {
            TableTermination::FieldEquals { field, value } => {
                field.write(sentinel_rec, value)?;
            }
            TableTermination::FieldNotEquals { field, value } => {
                let sentinel_val = if value != 0 {
                    0
                } else {
                    1u64 << field.bit_mask.trailing_zeros()
                };
                field.write(sentinel_rec, sentinel_val)?;
            }
            _ => {}
        }
        // Verify sentinel row still satisfies the termination condition
        let valid_sentinel = match spec.termination {
            TableTermination::ZeroRow => sentinel_rec.iter().all(|&b| b == 0),
            TableTermination::FirstByteZero => sentinel_rec[0] == 0,
            TableTermination::FieldEquals { field, value } => field.read(sentinel_rec)? == value,
            TableTermination::FieldNotEquals { field, value } => field.read(sentinel_rec)? != value,
            _ => true,
        };
        if !valid_sentinel {
            return Err(LayoutError::InvalidInput {
                index: entries.len(),
                reason: "sentinel row offset_field conflicts with TableTermination sentinel",
            });
        }
    }

    // Post-table inter-section block
    if !post_table.is_empty() {
        out[table_end..table_end + post_table.len()].copy_from_slice(post_table);
    }

    // String pool
    if !pool_buf.is_empty() {
        let pool_start = usize::try_from(pool_start_u64).map_err(|_| LayoutError::Overflow {
            what: "name_pool_start",
        })?;
        out[pool_start..pool_start + pool_buf.len()].copy_from_slice(&pool_buf);
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
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            16,
            0,
            16,
            Some(IntFieldSpec::new(8, IntWidth::U24, Endian::Big)),
            SizeMode::Stored(IntFieldSpec::u32_be(12)),
            TableTermination::Counted(2),
        )
        .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::NulOrSpacePadded))
        .with_offset_unit(2048);

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
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            16,
            0,
            16,
            Some(IntFieldSpec::u32_le(12)),
            SizeMode::NextOffset,
            TableTermination::FirstOffsetDerived,
        )
        .with_name_field(NameFieldSpec::new(0, 12, NameEncoding::Ascii));

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
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            4,
            0,
            8,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::NextOffset,
            TableTermination::Counted(2),
        );
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
        const ZERO_ROW_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::Stored(IntFieldSpec::u32_le(4)),
            TableTermination::ZeroRow,
        )
        .with_offset_base(OffsetBase::TableEnd);

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

        const FIRST_ZERO_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            16,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::Stored(IntFieldSpec::u32_le(8)),
            TableTermination::FirstByteZero,
        )
        .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::NulTerminated));
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
        const CUMULATIVE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            4,
            0,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::CumulativeFrom(8),
            TableTermination::Counted(2),
        )
        .with_size_unit(4);
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
        const FIXED_SLOT_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            4,
            0,
            16,
            None,
            SizeMode::FixedSlot(4),
            TableTermination::Counted(2),
        )
        .with_offset_base(OffsetBase::Fixed(8));
        let slot_data = [0u8; 16];
        let slot_entries = parse_fixed_record_table(&slot_data, &FIXED_SLOT_SPEC).unwrap();
        assert_eq!(slot_entries[0].offset, 8);
        assert_eq!(slot_entries[0].size, 4);
        assert_eq!(slot_entries[1].offset, 12);
        assert_eq!(slot_entries[1].size, 4);

        // Source-staged metadata validation against a 700 MiB carrier using only 32 bytes of directory!
        const DISC_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            16,
            0,
            64,
            Some(IntFieldSpec::u32_le(8)),
            SizeMode::Stored(IntFieldSpec::u32_le(12)),
            TableTermination::Counted(0),
        )
        .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::Ascii))
        .with_offset_unit(2048);
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
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            4,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::Stored(IntFieldSpec::u32_le(8)),
            TableTermination::Counted(1),
        )
        .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii));

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
        const STORED_U64_BE: FixedRecordTableSpec = FixedRecordTableSpec::new(
            28,
            8,
            16,
            Some(IntFieldSpec::u64_be(8)),
            SizeMode::Stored(IntFieldSpec::u64_be(16)),
            TableTermination::Counted(0),
        )
        .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::Ascii));
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
                key: None,
                payload: b"hello",
                record_template: Some(&tmpl0),
            },
            FixedRecordInput {
                name: Some(b"beta"),
                key: None,
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
        const SECTOR_ZERO_ROW: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u24_be(0)),
            SizeMode::Stored(IntFieldSpec::u32_be(4)),
            TableTermination::ZeroRow,
        )
        .with_offset_unit(2048);
        let sec_inputs = [
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"sector-one",
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: None,
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
        const FIRST_DERIVED: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u16_le(6)),
            SizeMode::NextOffset,
            TableTermination::FirstOffsetDerived,
        )
        .with_name_field(NameFieldSpec::new(0, 6, NameEncoding::Ascii));
        let fd_inputs = [
            FixedRecordInput {
                name: Some(b"a.bin"),
                key: None,
                payload: b"1234",
                record_template: None,
            },
            FixedRecordInput {
                name: Some(b"b.bin"),
                key: None,
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
        const FIRST_BYTE_U8: FixedRecordTableSpec = FixedRecordTableSpec::new(
            6,
            0,
            16,
            Some(IntFieldSpec::u8(4)),
            SizeMode::Stored(IntFieldSpec::u8(5)),
            TableTermination::FirstByteZero,
        )
        .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii))
        .with_offset_base(OffsetBase::TableEnd);
        let u8_inputs = [FixedRecordInput {
            name: Some(b"item"),
            key: None,
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
        const EOF_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u16_le(4)),
            SizeMode::Stored(IntFieldSpec::u16_le(6)),
            TableTermination::Eof,
        )
        .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii));
        let eof_inputs = [
            FixedRecordInput {
                name: Some(b"rec0"),
                key: None,
                payload: &[],
                record_template: None,
            },
            FixedRecordInput {
                name: Some(b"rec1"),
                key: None,
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
            key: None,
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

    #[test]
    fn k2_masked_fields_preserve_template_flags_and_support_packed_words() {
        // Record layout: u32le at 0 packs 20-bit offset (bits 0..20) + 12-bit size (bits 20..32)
        // and u32le at 4 has high 4-bit flags in record_template preserved alongside a 28-bit key.
        const PACKED_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u32_le(0).masked(0, 0x000F_FFFF)),
            SizeMode::Stored(IntFieldSpec::u32_le(0).masked(20, 0x0FFF)),
            TableTermination::Counted(2),
        )
        .with_key_field(IntFieldSpec::u32_le(4).masked(0, 0x0FFF_FFFF));

        let mut tmpl0 = [0u8; 8];
        tmpl0[4..8].copy_from_slice(&0xB000_0000u32.to_le_bytes()); // flag nibble 0xB
        let mut tmpl1 = [0u8; 8];
        tmpl1[4..8].copy_from_slice(&0x7000_0000u32.to_le_bytes()); // flag nibble 0x7

        let inputs = [
            FixedRecordInput {
                name: None,
                key: Some(0x0123_4567),
                payload: b"hello",
                record_template: Some(&tmpl0),
            },
            FixedRecordInput {
                name: None,
                key: Some(0x00AB_CDEF),
                payload: b"world!!",
                record_template: Some(&tmpl1),
            },
        ];

        let packed =
            pack_fixed_record_table(&PACKED_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();

        // Verify template flag nibbles survived packing untouched
        assert_eq!(
            u32::from_le_bytes(packed[4..8].try_into().unwrap()) >> 28,
            0xB
        );
        assert_eq!(
            u32::from_le_bytes(packed[12..16].try_into().unwrap()) >> 28,
            0x7
        );

        let parsed = parse_fixed_record_table(&packed, &PACKED_SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].key, Some(0x0123_4567));
        assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
        assert_eq!(parsed[1].key, Some(0x00AB_CDEF));
        assert_eq!(parsed[1].payload(&packed), Some(&b"world!!"[..]));
    }

    #[test]
    fn k3_cumulative_aligned_parses_packs_and_validates() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            4,
            0,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::CumulativeAligned {
                start: 16,
                align: 16,
            },
            TableTermination::Counted(3),
        );
        let inputs = [
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"abc", // 3 bytes -> next at 16 + 16 = 32
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: None,
                payload: &[0x55; 16], // 16 bytes -> next at 32 + 16 = 48
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"tail!", // 5 bytes at 48
                record_template: None,
            },
        ];

        let packed_tight =
            pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        assert_eq!(packed_tight.len(), 53);
        let parsed = parse_fixed_record_table(&packed_tight, &SPEC).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!((parsed[0].offset, parsed[0].size), (16, 3));
        assert_eq!(parsed[0].payload(&packed_tight), Some(&b"abc"[..]));
        assert_eq!((parsed[1].offset, parsed[1].size), (32, 16));
        assert_eq!((parsed[2].offset, parsed[2].size), (48, 5));
        assert_eq!(parsed[2].payload(&packed_tight), Some(&b"tail!"[..]));

        // With pad_final_entry = true, final entry is padded to align = 16
        let pad_policy = PackPolicy {
            pad_final_entry: true,
            ..PackPolicy::TIGHT
        };
        let packed_padded = pack_fixed_record_table(&SPEC, &pad_policy, &[], &inputs).unwrap();
        assert_eq!(packed_padded.len(), 64);
        let parsed_padded = parse_fixed_record_table(&packed_padded, &SPEC).unwrap();
        assert_eq!(
            parsed_padded[2].payload(&packed_padded),
            Some(&b"tail!"[..])
        );

        // Metadata mode against external carrier_len
        let meta = parse_fixed_record_table_metadata(&packed_tight[..12], &SPEC, 53).unwrap();
        assert_eq!(meta.len(), 3);
        assert_eq!(meta[2].offset, 48);

        // Zero align rejected
        const BAD_ALIGN: FixedRecordTableSpec = FixedRecordTableSpec::new(
            4,
            0,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::CumulativeAligned { start: 8, align: 0 },
            TableTermination::Counted(1),
        );
        assert!(matches!(
            parse_fixed_record_table(&[0u8; 8], &BAD_ALIGN),
            Err(LayoutError::InvalidSpec {
                field: "size_mode",
                ..
            })
        ));
    }

    #[test]
    fn k4_end_offset_parses_packs_and_rejects_inverted_or_oob() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::EndOffset(IntFieldSpec::u32_le(4)),
            TableTermination::Counted(2),
        )
        .with_offset_base(OffsetBase::TableEnd);

        let inputs = [
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"alpha",
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"beta-payload",
                record_template: None,
            },
        ];
        let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].offset, 16);
        assert_eq!(parsed[0].size, 5);
        assert_eq!(parsed[0].payload(&packed), Some(&b"alpha"[..]));
        assert_eq!(parsed[1].offset, 21);
        assert_eq!(parsed[1].size, 12);
        assert_eq!(parsed[1].payload(&packed), Some(&b"beta-payload"[..]));

        // Reject end < start
        let mut inverted = Vec::new();
        inverted.extend_from_slice(&10u32.to_le_bytes());
        inverted.extend_from_slice(&4u32.to_le_bytes());
        inverted.extend_from_slice(&[0u8; 32]);
        const ONE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
            termination: TableTermination::Counted(1),
            ..SPEC
        };
        assert_eq!(
            parse_fixed_record_table(&inverted, &ONE_SPEC),
            Err(LayoutError::NonMonotonic {
                index: 0,
                previous: 18,
                current: 12,
            })
        );

        // Reject end > carrier_len
        let mut oob = Vec::new();
        oob.extend_from_slice(&0u32.to_le_bytes());
        oob.extend_from_slice(&100u32.to_le_bytes());
        assert!(matches!(
            parse_fixed_record_table_metadata(&oob, &ONE_SPEC, 20),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));
    }

    #[test]
    fn k5_field_equals_sentinel_and_skip_empty_zero() {
        // 1. FieldEquals sentinel 0xFFFF_FFFF round-trip
        const SENTINEL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::Stored(IntFieldSpec::u32_le(4)),
            TableTermination::FieldEquals {
                field: IntFieldSpec::u32_le(0),
                value: 0xFFFF_FFFF,
            },
        );
        let inputs = [
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"one",
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"two!",
                record_template: None,
            },
        ];
        let packed =
            pack_fixed_record_table(&SENTINEL_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        // Sentinel row at offset 16 must have field == 0xFFFF_FFFF
        assert_eq!(
            u32::from_le_bytes(packed[16..20].try_into().unwrap()),
            0xFFFF_FFFF
        );
        let parsed = parse_fixed_record_table(&packed, &SENTINEL_SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].payload(&packed), Some(&b"one"[..]));
        assert_eq!(parsed[1].payload(&packed), Some(&b"two!"[..]));

        // 2. skip_empty_zero skips both all-zero rows and (offset=0, size=0) tombstones
        //    while preserving physical slot indices and ExactSizeIterator::len().
        const SKIP_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            16,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::Stored(IntFieldSpec::u32_le(8)),
            TableTermination::Counted(4),
        )
        .with_key_field(IntFieldSpec::u32_le(0))
        .with_skip_empty_zero(true);

        let mut data = Vec::new();
        // Slot 0: valid (key=1, off=48, size=3)
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&48u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        // Slot 1: all-zero tombstone
        data.extend_from_slice(&[0u8; 12]);
        // Slot 2: non-zero key but (off=0, size=0) tombstone
        data.extend_from_slice(&99u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // Slot 3: valid (key=2, off=51, size=4)
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&51u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        // Payloads
        data.extend_from_slice(b"AAAbbbb");

        let iter = iter_fixed_record_table(&data, &SKIP_SPEC).unwrap();
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.entry_count(), 2);
        let views: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].index, 0);
        assert_eq!(views[0].key, Some(1));
        assert_eq!(views[0].payload(&data), Some(&b"AAA"[..]));
        assert_eq!(views[1].index, 3);
        assert_eq!(views[1].key, Some(2));
        assert_eq!(views[1].payload(&data), Some(&b"bbbb"[..]));
    }

    #[test]
    fn k6_name_pool_in_carrier_and_detached_round_trip_and_limits() {
        const POOL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            16,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::Stored(IntFieldSpec::u32_le(8)),
            TableTermination::Counted(2),
        )
        .with_name_pool(NamePoolSpec::new(
            IntFieldSpec::u32_le(0),
            OffsetBase::TableEnd,
            NameEncoding::Ascii,
            32,
        ));

        let inputs = [
            FixedRecordInput {
                name: Some(b"dir/first.bin"),
                key: None,
                payload: b"DATA0",
                record_template: None,
            },
            FixedRecordInput {
                name: Some(b"dir/second.bin"),
                key: None,
                payload: b"DATA1!",
                record_template: None,
            },
        ];
        let packed = pack_fixed_record_table(&POOL_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        let parsed = parse_fixed_record_table(&packed, &POOL_SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name_str(), Some("dir/first.bin"));
        assert_eq!(parsed[0].payload(&packed), Some(&b"DATA0"[..]));
        assert_eq!(parsed[1].name_str(), Some("dir/second.bin"));
        assert_eq!(parsed[1].payload(&packed), Some(&b"DATA1!"[..]));

        // Detached name pool slice with Absolute base inside pool_data
        const DETACHED_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            10,
            0,
            16,
            Some(IntFieldSpec::u32_le(2)),
            SizeMode::Stored(IntFieldSpec::u32_le(6)),
            TableTermination::Counted(2),
        )
        .with_name_pool(NamePoolSpec::new(
            IntFieldSpec::u16_le(0),
            OffsetBase::Absolute,
            NameEncoding::Ascii,
            8,
        ));
        let mut table = Vec::new();
        table.extend_from_slice(&0u16.to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes());
        table.extend_from_slice(&100u32.to_le_bytes());
        table.extend_from_slice(&6u16.to_le_bytes());
        table.extend_from_slice(&100u32.to_le_bytes());
        table.extend_from_slice(&50u32.to_le_bytes());
        let pool_slice = b"alpha\0beta\0";
        let detached =
            parse_fixed_record_table_with_name_pool(&table, pool_slice, &DETACHED_SPEC, 200)
                .unwrap();
        assert_eq!(detached.len(), 2);
        assert_eq!(detached[0].name_str(), Some("alpha"));
        assert_eq!(detached[1].name_str(), Some("beta"));

        // Reject name exceeding max_len
        let too_long_pool = b"0123456789\0";
        assert_eq!(
            parse_fixed_record_table_with_name_pool(&table, too_long_pool, &DETACHED_SPEC, 200),
            Err(LayoutError::InvalidName { index: 0 })
        );

        // Reject mutually exclusive name_field + name_pool
        let both = POOL_SPEC.with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii));
        assert!(matches!(
            parse_fixed_record_table(&packed, &both),
            Err(LayoutError::InvalidSpec {
                field: "name_pool",
                ..
            })
        ));
    }

    #[test]
    fn k7_key_field_u64_and_k8_subtract_base_round_trip_and_errors() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            16,
            0,
            16,
            Some(IntFieldSpec::u32_le(8)),
            SizeMode::Stored(IntFieldSpec::u32_le(12)),
            TableTermination::Counted(2),
        )
        .with_key_field(IntFieldSpec::u64_le(0))
        .with_offset_base(OffsetBase::SubtractBase(0x8001_0000));

        let inputs = [
            FixedRecordInput {
                name: None,
                key: Some(0xDEAD_BEEF_CAFE_BABE),
                payload: b"first",
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: Some(0x0123_4567_89AB_CDEF),
                payload: b"second",
                record_template: None,
            },
        ];
        let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        // Raw offset for record 0 must be 0x8001_0000 + 32 (2 * 16B records)
        assert_eq!(
            u32::from_le_bytes(packed[8..12].try_into().unwrap()),
            0x8001_0020
        );
        let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].key, Some(0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(parsed[0].offset, 32);
        assert_eq!(parsed[0].payload(&packed), Some(&b"first"[..]));
        assert_eq!(parsed[1].key, Some(0x0123_4567_89AB_CDEF));
        assert_eq!(parsed[1].offset, 37);
        assert_eq!(parsed[1].payload(&packed), Some(&b"second"[..]));

        // Reject raw address < SubtractBase
        let mut underflow = packed.clone();
        underflow[8..12].copy_from_slice(&0x8000_FFFFu32.to_le_bytes());
        assert_eq!(
            parse_fixed_record_table(&underflow, &SPEC),
            Err(LayoutError::Overflow {
                what: "offset_subtract_base"
            })
        );
    }

    #[test]
    fn knob1_field_not_equals_round_trip_and_validation() {
        // Active rows have tag == 1; terminator row has tag == 0
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            16,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::Stored(IntFieldSpec::u32_le(8)),
            TableTermination::FieldNotEquals {
                field: IntFieldSpec::u32_le(0),
                value: 1,
            },
        );
        let mut tmpl = [0u8; 12];
        tmpl[0..4].copy_from_slice(&1u32.to_le_bytes());
        let inputs = [
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"first",
                record_template: Some(&tmpl),
            },
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"second!",
                record_template: Some(&tmpl),
            },
        ];
        let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        // Sentinel row at offset 24 must have tag != 1 (written as 0)
        assert_eq!(u32::from_le_bytes(packed[24..28].try_into().unwrap()), 0);
        let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].payload(&packed), Some(&b"first"[..]));
        assert_eq!(parsed[1].payload(&packed), Some(&b"second!"[..]));

        // Metadata mode also respects FieldNotEquals
        let meta =
            parse_fixed_record_table_metadata(&packed[..36], &SPEC, packed.len() as u64).unwrap();
        assert_eq!(meta.len(), 2);

        // Packing a data row whose field != value is rejected
        let bad_inputs = [FixedRecordInput {
            name: None,
            key: None,
            payload: b"bad",
            record_template: None, // tag == 0 != 1
        }];
        assert!(matches!(
            pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &bad_inputs),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        // Active value == 0 emits sentinel value == 1
        const ZERO_ACTIVE: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            16,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::Stored(IntFieldSpec::u32_le(8)),
            TableTermination::FieldNotEquals {
                field: IntFieldSpec::u32_le(0),
                value: 0,
            },
        );
        let zero_packed = pack_fixed_record_table(
            &ZERO_ACTIVE,
            &PackPolicy::TIGHT,
            &[],
            &[FixedRecordInput {
                name: None,
                key: None,
                payload: b"ok",
                record_template: None,
            }],
        )
        .unwrap();
        assert_eq!(
            u32::from_le_bytes(zero_packed[12..16].try_into().unwrap()),
            1
        );
        let zero_parsed = parse_fixed_record_table(&zero_packed, &ZERO_ACTIVE).unwrap();
        assert_eq!(zero_parsed.len(), 1);
        assert_eq!(zero_parsed[0].payload(&zero_packed), Some(&b"ok"[..]));
    }

    #[test]
    fn knob2_skip_field_equals_preserves_index_next_offset_and_exact_len() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            0,
            16,
            Some(IntFieldSpec::u32_le(4)),
            SizeMode::NextOffset,
            TableTermination::Counted(4),
        )
        .with_key_field(IntFieldSpec::u32_le(0))
        .with_skip_field_equals(IntFieldSpec::u32_le(0), 0xFFFF_FFFF);

        let mut data = Vec::new();
        // Slot 0: active (key=10, off=32)
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&32u32.to_le_bytes());
        // Slot 1: tombstone (key=0xFFFF_FFFF, bogus offset 0)
        data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // Slot 2: active (key=20, off=36)
        data.extend_from_slice(&20u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());
        // Slot 3: tombstone
        data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // Payloads: 4 bytes + 5 bytes
        data.extend_from_slice(b"AAAAbbbbb");

        let iter = iter_fixed_record_table(&data, &SPEC).unwrap();
        assert_eq!(iter.len(), 2);
        let entries: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[0].key, Some(10));
        assert_eq!(entries[0].payload(&data), Some(&b"AAAA"[..]));
        assert_eq!(entries[1].index, 2);
        assert_eq!(entries[1].key, Some(20));
        assert_eq!(entries[1].payload(&data), Some(&b"bbbbb"[..]));
    }

    #[test]
    fn knob3_table_start_table_end_plus_and_cumulative_from_table_end() {
        // 1. OffsetBase::TableStart with runtime table_offset
        const TS_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            16,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::Stored(IntFieldSpec::u32_le(4)),
            TableTermination::Counted(2),
        )
        .with_offset_base(OffsetBase::TableStart);
        let inputs = [
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"hello",
                record_template: None,
            },
            FixedRecordInput {
                name: None,
                key: None,
                payload: b"world",
                record_template: None,
            },
        ];
        let packed =
            pack_fixed_record_table(&TS_SPEC, &PackPolicy::TIGHT, b"HDR!", &inputs).unwrap();
        // Raw offset 0 relative to table_offset=16 is 16 (2 * 8B records)
        assert_eq!(u32::from_le_bytes(packed[16..20].try_into().unwrap()), 16);
        let parsed = parse_fixed_record_table(&packed, &TS_SPEC).unwrap();
        assert_eq!(parsed[0].offset, 32);
        assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
        assert_eq!(parsed[1].offset, 37);
        assert_eq!(parsed[1].payload(&packed), Some(&b"world"[..]));

        // 2. OffsetBase::TableEndPlus(12)
        const TEP_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            8,
            4,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::Stored(IntFieldSpec::u32_le(4)),
            TableTermination::Counted(2),
        )
        .with_offset_base(OffsetBase::TableEndPlus(12));
        let tep_packed = pack_fixed_record_table_with_post_table(
            &TEP_SPEC,
            &PackPolicy::TIGHT,
            b"PFX!",
            b"INTER_SECTION",
            &inputs,
        );
        // post_table is 13 bytes, so cursor=table_end+13 > table_end+12 -> raw offset 0 is 1
        let tep_packed = tep_packed.unwrap();
        let tep_parsed = parse_fixed_record_table(&tep_packed, &TEP_SPEC).unwrap();
        assert_eq!(tep_parsed[0].payload(&tep_packed), Some(&b"hello"[..]));
        assert_eq!(tep_parsed[1].payload(&tep_packed), Some(&b"world"[..]));

        // 3. SizeMode::CumulativeFromTableEnd { bias: 8, align: 16 }
        const CUM_TE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            4,
            4,
            16,
            Some(IntFieldSpec::u32_le(0)),
            SizeMode::CumulativeFromTableEnd { bias: 8, align: 16 },
            TableTermination::Counted(2),
        );
        let cum_packed = pack_fixed_record_table_with_post_table(
            &CUM_TE_SPEC,
            &PackPolicy::TIGHT,
            b"HDR0",
            b"POST_BLK", // 8 bytes == bias
            &inputs,
        )
        .unwrap();
        // table_end = 4 + 8 = 12, + bias 8 = 20; entry 0 (5B) at 20, next at 20 + 16 = 36
        let cum_parsed = parse_fixed_record_table(&cum_packed, &CUM_TE_SPEC).unwrap();
        assert_eq!(cum_parsed.len(), 2);
        assert_eq!((cum_parsed[0].offset, cum_parsed[0].size), (20, 5));
        assert_eq!(cum_parsed[0].payload(&cum_packed), Some(&b"hello"[..]));
        assert_eq!((cum_parsed[1].offset, cum_parsed[1].size), (36, 5));
        assert_eq!(cum_parsed[1].payload(&cum_packed), Some(&b"world"[..]));
    }

    #[test]
    fn knob5_sentinel_closes_next_offset_round_trips_with_trailing_bytes() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            12,
            0,
            16,
            Some(IntFieldSpec::u32_le(8)),
            SizeMode::NextOffset,
            TableTermination::FirstByteZero,
        )
        .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::PrintableAscii))
        .with_sentinel_closes_next_offset(true);

        let inputs = [
            FixedRecordInput {
                name: Some(b"first"),
                key: None,
                payload: b"1234",
                record_template: None,
            },
            FixedRecordInput {
                name: Some(b"second"),
                key: None,
                payload: b"56789",
                record_template: None,
            },
        ];
        let mut packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
        // Append trailing carrier bytes after the sentinel's declared end offset
        packed.extend_from_slice(b"TRAILING_JUNK_OUTSIDE_SENTINEL");

        let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name_str(), Some("first"));
        assert_eq!(parsed[0].payload(&packed), Some(&b"1234"[..]));
        assert_eq!(parsed[1].name_str(), Some("second"));
        // Final entry closes at sentinel's offset, NOT at packed.len()!
        assert_eq!(parsed[1].payload(&packed), Some(&b"56789"[..]));
    }

    #[test]
    fn knob8_printable_ascii_and_post_table_bytes() {
        const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
            16,
            0,
            16,
            Some(IntFieldSpec::u32_le(8)),
            SizeMode::Stored(IntFieldSpec::u32_le(12)),
            TableTermination::Counted(1),
        )
        .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::PrintableAscii));

        let inputs = [FixedRecordInput {
            name: Some(b"ok_1.bin"),
            key: None,
            payload: b"PAYLOAD",
            record_template: None,
        }];
        let post = b"SORTED_INDEX_BLOCK";
        let packed =
            pack_fixed_record_table_with_post_table(&SPEC, &PackPolicy::TIGHT, &[], post, &inputs)
                .unwrap();
        assert_eq!(&packed[16..16 + post.len()], post);
        let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name_str(), Some("ok_1.bin"));
        assert_eq!(parsed[0].offset, (16 + post.len()) as u64);
        assert_eq!(parsed[0].payload(&packed), Some(&b"PAYLOAD"[..]));

        // Control byte 0x09 (tab) before trailing space is rejected on parse
        let mut bad_ctrl = packed.clone();
        bad_ctrl[0..8].copy_from_slice(b"ab\x09   \0\0");
        assert_eq!(
            parse_fixed_record_table(&bad_ctrl, &SPEC),
            Err(LayoutError::InvalidName { index: 0 })
        );

        // 0x7F (DEL) is rejected on parse and pack
        let mut bad_del = packed.clone();
        bad_del[0..8].copy_from_slice(b"ab\x7F\0\0\0\0\0");
        assert_eq!(
            parse_fixed_record_table(&bad_del, &SPEC),
            Err(LayoutError::InvalidName { index: 0 })
        );
        let bad_pack = [FixedRecordInput {
            name: Some(b"ab\x1F"),
            key: None,
            payload: b"X",
            record_template: None,
        }];
        assert_eq!(
            pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &bad_pack),
            Err(LayoutError::InvalidName { index: 0 })
        );
    }
}
