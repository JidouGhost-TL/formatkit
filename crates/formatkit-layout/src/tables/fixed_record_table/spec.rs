//! Declarative specification types, validation, and shared helpers for fixed-stride record tables.

use crate::prelude::*;

use formatkit_core::Endian;

use crate::spec::{read_int_at, write_int_at, IntFieldSpec, IntWidth, LayoutError, OffsetBase};

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

#[inline]
pub(super) fn trim_trailing_spaces(mut bytes: &[u8]) -> &[u8] {
    while let Some(&b' ') = bytes.last() {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub(super) fn apply_name_encoding(
    raw: &[u8],
    encoding: NameEncoding,
    index: usize,
) -> Result<&[u8], LayoutError> {
    match encoding {
        NameEncoding::NulTerminated => Ok(raw),
        NameEncoding::NulOrSpacePadded => Ok(trim_trailing_spaces(raw)),
        NameEncoding::Ascii => {
            let trimmed = trim_trailing_spaces(raw);
            if !trimmed.is_ascii() {
                return Err(LayoutError::InvalidName { index });
            }
            Ok(trimmed)
        }
        NameEncoding::PrintableAscii => {
            if !raw.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                return Err(LayoutError::InvalidName { index });
            }
            Ok(trim_trailing_spaces(raw))
        }
    }
}

pub(super) fn validate_name_bytes(
    name: &[u8],
    max_len: usize,
    encoding: NameEncoding,
    reject_nul: bool,
    index: usize,
) -> Result<(), LayoutError> {
    if name.len() > max_len || (reject_nul && name.contains(&0)) {
        return Err(LayoutError::InvalidName { index });
    }
    match encoding {
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

    pub(super) fn decode_borrowed(self, record: &[u8], index: usize) -> Result<&[u8], LayoutError> {
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

    pub(super) fn encode(
        self,
        record: &mut [u8],
        name: &[u8],
        index: usize,
    ) -> Result<(), LayoutError> {
        validate_name_bytes(name, self.len, self.encoding, true, index)?;
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

/// Wire format of entries stored in a string pool referenced by [`NamePoolSpec`].
///
/// # Example
/// ```
/// use formatkit_core::Endian;
/// use formatkit_layout::{
///     pack_fixed_record_table, parse_fixed_record_table, FixedRecordInput, FixedRecordTableSpec,
///     IntFieldSpec, IntWidth, NameEncoding, NamePoolFormat, NamePoolSpec, OffsetBase, PackPolicy,
///     SizeMode, TableTermination,
/// };
///
/// const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
///     12,
///     0,
///     16,
///     Some(IntFieldSpec::u32_le(4)),
///     SizeMode::Stored(IntFieldSpec::u32_le(8)),
///     TableTermination::Counted(1),
/// )
/// .with_name_pool(
///     NamePoolSpec::new(
///         IntFieldSpec::u32_le(0),
///         OffsetBase::TableEnd,
///         NameEncoding::Ascii,
///         32,
///     )
///     .with_format(NamePoolFormat::LengthPrefixed {
///         len_width: IntWidth::U8,
///         endian: Endian::Little,
///     }),
/// );
///
/// let inputs = [FixedRecordInput {
///     name: Some(b"alpha"),
///     key: None,
///     payload: b"DATA",
///     record_template: None,
/// }];
/// let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
/// let entries = parse_fixed_record_table(&packed, &SPEC).unwrap();
/// assert_eq!(entries[0].name_str(), Some("alpha"));
/// assert_eq!(entries[0].payload(&packed), Some(&b"DATA"[..]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamePoolFormat {
    /// NUL-terminated byte string (`bytes\0`, default).
    #[default]
    NulTerminated,
    /// Length-prefixed byte string (`len` integer followed immediately by `len` name bytes).
    LengthPrefixed {
        /// Bit width of the unsigned length prefix.
        len_width: IntWidth,
        /// Byte order of the unsigned length prefix.
        endian: Endian,
    },
}

/// Declarative descriptor for resolving each record's name from an external or
/// in-carrier string pool via an integer offset field in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamePoolSpec {
    /// Integer field inside each record carrying the byte offset into the string pool.
    pub offset_field: IntFieldSpec,
    /// Base coordinate applied to the decoded offset to locate the pooled name.
    pub pool_base: OffsetBase,
    /// Trimming and validation rule applied to the decoded name bytes.
    pub encoding: NameEncoding,
    /// Maximum number of name bytes permitted (excluding any NUL terminator or length prefix).
    pub max_len: usize,
    /// Wire format of each pooled string entry (default [`NamePoolFormat::NulTerminated`]).
    pub format: NamePoolFormat,
}

impl NamePoolSpec {
    /// Construct a new string-pool name descriptor with [`NamePoolFormat::NulTerminated`].
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
            format: NamePoolFormat::NulTerminated,
        }
    }

    /// Set [`NamePoolSpec::format`].
    #[must_use]
    pub const fn with_format(mut self, format: NamePoolFormat) -> Self {
        self.format = format;
        self
    }

    pub(super) fn decode_borrowed<'a>(
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
        match self.format {
            NamePoolFormat::NulTerminated => {
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
            NamePoolFormat::LengthPrefixed { len_width, endian } => {
                let prefix_len = len_width.byte_len();
                let str_start = name_off
                    .checked_add(prefix_len)
                    .ok_or(LayoutError::Overflow {
                        what: "name_pool_offset",
                    })?;
                if str_start > pool_data.len() {
                    return Err(LayoutError::OutOfBounds {
                        index,
                        offset: name_off_u64,
                        size: prefix_len as u64,
                        data_len: pool_data.len() as u64,
                    });
                }
                let len_u64 = read_int_at(pool_data, name_off, len_width, endian)?;
                let name_len = usize::try_from(len_u64).map_err(|_| LayoutError::Overflow {
                    what: "name_pool_len",
                })?;
                if name_len > self.max_len {
                    return Err(LayoutError::InvalidName { index });
                }
                let str_end = str_start
                    .checked_add(name_len)
                    .ok_or(LayoutError::Overflow {
                        what: "name_pool_end",
                    })?;
                if str_end > pool_data.len() {
                    return Err(LayoutError::OutOfBounds {
                        index,
                        offset: str_start as u64,
                        size: name_len as u64,
                        data_len: pool_data.len() as u64,
                    });
                }
                let raw = &pool_data[str_start..str_end];
                let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                apply_name_encoding(&raw[..nul_pos], self.encoding, index)
            }
        }
    }

    pub(super) fn append_encoded(
        self,
        pool_buf: &mut Vec<u8>,
        name: &[u8],
        index: usize,
    ) -> Result<(), LayoutError> {
        match self.format {
            NamePoolFormat::NulTerminated => {
                validate_name_bytes(name, self.max_len, self.encoding, true, index)?;
                pool_buf.extend_from_slice(name);
                pool_buf.push(0);
            }
            NamePoolFormat::LengthPrefixed { len_width, endian } => {
                validate_name_bytes(name, self.max_len, self.encoding, false, index)?;
                let mut len_buf = [0u8; 8];
                let prefix_len = len_width.byte_len();
                write_int_at(
                    &mut len_buf[..prefix_len],
                    0,
                    len_width,
                    endian,
                    name.len() as u64,
                )?;
                pool_buf.extend_from_slice(&len_buf[..prefix_len]);
                pool_buf.extend_from_slice(name);
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
    /// Entry `i` spans `[offset[i], offset[i + 1])` with the last entry ending at `carrier_len`
    /// (or the terminating sentinel's offset when [`FixedRecordTableSpec::sentinel_closes_next_offset`] is `true`).
    /// Requires non-decreasing resolved offsets.
    NextOffset,
    /// Each record's `offset_field` stores a size (scaled by [`FixedRecordTableSpec::size_unit`]),
    /// and entry offsets start at `start` (resolved with offset `0`) and advance by
    /// `align_up(size, align)` after each entry (with `align >= 1`).
    Cumulative {
        /// Base coordinate determining the initial byte offset of the first entry
        /// (supports `Absolute`, `TableStart`, `TableEnd`, `TableEndPlus`, and `Fixed`).
        start: OffsetBase,
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

impl SizeMode {
    /// Construct a contiguous (`align: 1`) cumulative size mode starting at `start`.
    #[must_use]
    pub const fn cumulative_from(start: OffsetBase) -> Self {
        Self::Cumulative { start, align: 1 }
    }

    /// Construct an aligned cumulative size mode starting at `start` with per-entry step `align`.
    #[must_use]
    pub const fn cumulative_aligned(start: OffsetBase, align: u64) -> Self {
        Self::Cumulative { start, align }
    }

    /// Construct an aligned cumulative size mode starting at `table_end + bias` with per-entry step `align`.
    #[must_use]
    pub const fn cumulative_from_table_end(bias: u64, align: u64) -> Self {
        Self::Cumulative {
            start: OffsetBase::TableEndPlus(bias),
            align,
        }
    }
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
    /// Table terminates at the first record where `field.read(row)` matches any value in `values`.
    ///
    /// During symmetric packing, `values[0]` is written into the terminating sentinel row.
    /// `values` must be non-empty.
    FieldIn {
        /// Integer field inspected in each record.
        field: IntFieldSpec,
        /// Non-empty set of sentinel values that terminate the table when matched.
        values: &'static [u64],
    },
    /// Table length is derived from the first record's resolved byte offset:
    /// `count = (first_offset - table_offset) / stride`.
    FirstOffsetDerived,
    /// Table extends to the end of the input slice (complete records of `stride` bytes).
    Eof,
}

/// Predicate matching interior tombstone/free rows based on an integer field value.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     parse_fixed_record_table, FixedRecordTableSpec, IntFieldSpec, RowFieldPredicate, SizeMode,
///     TableTermination,
/// };
///
/// const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
///     12,
///     0,
///     16,
///     Some(IntFieldSpec::u32_le(4)),
///     SizeMode::Stored(IntFieldSpec::u32_le(8)),
///     TableTermination::Counted(2),
/// )
/// .with_skip_predicate(RowFieldPredicate::Equals {
///     field: IntFieldSpec::u32_le(0),
///     value: 0,
/// });
///
/// let mut data = Vec::new();
/// // Row 0: tombstone (flag == 0)
/// data.extend_from_slice(&[0u8; 12]);
/// // Row 1: active entry (flag == 1)
/// data.extend_from_slice(&1u32.to_le_bytes());
/// data.extend_from_slice(&24u32.to_le_bytes());
/// data.extend_from_slice(&3u32.to_le_bytes());
/// data.extend_from_slice(b"XYZ");
///
/// let entries = parse_fixed_record_table(&data, &SPEC).unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].index, 1);
/// assert_eq!(entries[0].payload(&data), Some(&b"XYZ"[..]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowFieldPredicate {
    /// Skip rows where `field.read(row) == value`.
    Equals {
        /// Integer field inspected in each record.
        field: IntFieldSpec,
        /// Tombstone value that causes the row to be skipped.
        value: u64,
    },
    /// Skip rows where `field.read(row) != value`.
    NotEquals {
        /// Integer field inspected in each record.
        field: IntFieldSpec,
        /// Active value required for non-skipped rows; any other value causes the row to be skipped.
        value: u64,
    },
}

impl RowFieldPredicate {
    #[inline]
    pub(super) const fn field(self) -> IntFieldSpec {
        match self {
            Self::Equals { field, .. } | Self::NotEquals { field, .. } => field,
        }
    }

    #[inline]
    pub(super) fn matches(self, record: &[u8]) -> Result<bool, LayoutError> {
        match self {
            Self::Equals { field, value } => Ok(field.read(record)? == value),
            Self::NotEquals { field, value } => Ok(field.read(record)? != value),
        }
    }
}

/// Runtime overrides and detached buffers for [`FixedRecordTableSpec::parse_with`]
/// and [`FixedRecordTableSpec::iter_with`].
///
/// # Example
/// ```
/// use formatkit_layout::{
///     FixedRecordTableSpec, IntFieldSpec, SizeMode, TableParseOptions, TableTermination,
/// };
///
/// const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
///     8,
///     0,
///     64,
///     Some(IntFieldSpec::u32_le(0)),
///     SizeMode::Stored(IntFieldSpec::u32_le(4)),
///     TableTermination::Counted(0),
/// );
///
/// // Only the 8-byte directory row is staged in RAM; payload lives at offset 4096 in a 8192-byte carrier.
/// let mut table_bytes = Vec::new();
/// table_bytes.extend_from_slice(&4096u32.to_le_bytes());
/// table_bytes.extend_from_slice(&512u32.to_le_bytes());
///
/// let opts = TableParseOptions::new()
///     .with_count(1)
///     .with_carrier_len(8192);
/// let views: Vec<_> = SPEC
///     .iter_with(&table_bytes, opts)
///     .unwrap()
///     .collect::<Result<_, _>>()
///     .unwrap();
/// assert_eq!(views.len(), 1);
/// assert_eq!((views[0].offset, views[0].size), (4096, 512));
///
/// let entries = SPEC.parse_with(&table_bytes, opts).unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!((entries[0].offset, entries[0].size), (4096, 512));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TableParseOptions<'a> {
    /// Override [`FixedRecordTableSpec::termination`] with [`TableTermination::Counted`].
    pub count: Option<usize>,
    /// External carrier length for metadata-only parsing (defaults to `data.len() as u64`).
    pub carrier_len: Option<u64>,
    /// Detached string-pool byte slice (defaults to `data`).
    pub name_pool: Option<&'a [u8]>,
    /// Additional upper bound on entry count (`min(spec.max_entries, max_entries)`).
    pub max_entries: Option<usize>,
    /// Override [`FixedRecordTableSpec::table_offset`].
    pub table_offset: Option<usize>,
}

impl<'a> TableParseOptions<'a> {
    /// Construct default [`TableParseOptions`] with no overrides.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            count: None,
            carrier_len: None,
            name_pool: None,
            max_entries: None,
            table_offset: None,
        }
    }

    /// Override [`FixedRecordTableSpec::termination`] with [`TableTermination::Counted`].
    #[must_use]
    pub const fn with_count(mut self, count: usize) -> Self {
        self.count = Some(count);
        self
    }

    /// Set an external carrier length for metadata-only parsing.
    #[must_use]
    pub const fn with_carrier_len(mut self, carrier_len: u64) -> Self {
        self.carrier_len = Some(carrier_len);
        self
    }

    /// Supply a detached string-pool slice for [`FixedRecordTableSpec::name_pool`].
    #[must_use]
    pub const fn with_name_pool(mut self, name_pool: &'a [u8]) -> Self {
        self.name_pool = Some(name_pool);
        self
    }

    /// Cap the maximum entry count to `min(spec.max_entries, max_entries)`.
    #[must_use]
    pub const fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = Some(max_entries);
        self
    }

    /// Override [`FixedRecordTableSpec::table_offset`].
    #[must_use]
    pub const fn with_table_offset(mut self, table_offset: usize) -> Self {
        self.table_offset = Some(table_offset);
        self
    }
}

/// `const`-constructible declarative specification for a fixed-stride record table.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     parse_fixed_record_table, FixedRecordTableSpec, IntFieldSpec, NameEncoding, NameFieldSpec,
///     SizeMode, TableTermination,
/// };
///
/// const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
///     16,
///     0,
///     64,
///     Some(IntFieldSpec::u32_le(8)),
///     SizeMode::Stored(IntFieldSpec::u32_le(12)),
///     TableTermination::Counted(1),
/// )
/// .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::Ascii));
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
#[doc(alias = "directory table")]
#[doc(alias = "record table")]
#[doc(alias = "fixed stride table")]
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
    /// Optional external/in-carrier string-pool name descriptor
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
    /// Non-zero byte multiplier applied to [`SizeMode::Stored`] and [`SizeMode::Cumulative`] size values.
    pub size_unit: u64,
    /// How the number of records in the table is determined.
    pub termination: TableTermination,
    /// When `true`, skip all-zero or `(offset == 0, size/end == 0)` tombstone rows while
    /// preserving each surviving entry's physical slot `index`.
    pub skip_empty_zero: bool,
    /// Optional predicate skipping interior tombstone/free slots while preserving physical slot `index`.
    pub skip_predicate: Option<RowFieldPredicate>,
    /// When `true` with [`SizeMode::NextOffset`] and a sentinel-based termination
    /// (`ZeroRow`, `FirstByteZero`, `FieldEquals`, or `FieldNotEquals`), use the terminating
    /// sentinel row's `offset_field` as the exclusive end offset for the final entry instead
    /// of `carrier_len`.
    pub sentinel_closes_next_offset: bool,
    /// When `true` and a sentinel-based [`TableTermination`] matches (`ZeroRow`,
    /// `FirstByteZero`, `FieldEquals`, `FieldNotEquals`, or `FieldIn`), include the
    /// terminating sentinel record as the final emitted entry (default `false`).
    pub emit_terminator: bool,
}

impl FixedRecordTableSpec {
    /// Construct a [`FixedRecordTableSpec`] with sensible defaults (`name_field: None`,
    /// `name_pool: None`, `key_field: None`, `offset_base: OffsetBase::Absolute`,
    /// `offset_unit: 1`, `size_unit: 1`, `skip_empty_zero: false`,
    /// `skip_predicate: None`, `sentinel_closes_next_offset: false`,
    /// `emit_terminator: false`).
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
            skip_predicate: None,
            sentinel_closes_next_offset: false,
            emit_terminator: false,
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

    /// Set [`FixedRecordTableSpec::skip_predicate`].
    #[must_use]
    pub const fn with_skip_predicate(mut self, predicate: RowFieldPredicate) -> Self {
        self.skip_predicate = Some(predicate);
        self
    }

    /// Skip interior tombstone/free slots where `field.read(row) == value`.
    #[must_use]
    pub const fn with_skip_field_equals(mut self, field: IntFieldSpec, value: u64) -> Self {
        self.skip_predicate = Some(RowFieldPredicate::Equals { field, value });
        self
    }

    /// Skip interior tombstone/free slots where `field.read(row) != value`.
    #[must_use]
    pub const fn with_skip_field_not_equals(mut self, field: IntFieldSpec, value: u64) -> Self {
        self.skip_predicate = Some(RowFieldPredicate::NotEquals { field, value });
        self
    }

    /// Use the terminating sentinel row's `offset_field` as the exclusive end offset
    /// of the final entry under [`SizeMode::NextOffset`].
    #[must_use]
    pub const fn with_sentinel_closes_next_offset(mut self, enabled: bool) -> Self {
        self.sentinel_closes_next_offset = enabled;
        self
    }

    /// Set [`FixedRecordTableSpec::emit_terminator`].
    #[must_use]
    pub const fn with_emit_terminator(mut self, emit: bool) -> Self {
        self.emit_terminator = emit;
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

/// One entry supplied to [`super::pack_fixed_record_table`].
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

pub(super) fn matches_termination_sentinel(
    termination: TableTermination,
    row: &[u8],
) -> Result<bool, LayoutError> {
    match termination {
        TableTermination::ZeroRow => Ok(row.iter().all(|&b| b == 0)),
        TableTermination::FirstByteZero => Ok(row[0] == 0),
        TableTermination::FieldEquals { field, value } => Ok(field.read(row)? == value),
        TableTermination::FieldNotEquals { field, value } => Ok(field.read(row)? != value),
        TableTermination::FieldIn { field, values } => {
            let value = field.read(row)?;
            Ok(values.contains(&value))
        }
        TableTermination::Counted(_)
        | TableTermination::FirstOffsetDerived
        | TableTermination::Eof => Ok(false),
    }
}

pub(super) fn resolve_scaled_offset(
    spec: &FixedRecordTableSpec,
    record: &[u8],
    record_offset: usize,
    field: IntFieldSpec,
    table_end: u64,
    overflow_label: &'static str,
) -> Result<u64, LayoutError> {
    let raw = field.read(record)?;
    let scaled = raw
        .checked_mul(spec.offset_unit)
        .ok_or(LayoutError::Overflow {
            what: overflow_label,
        })?;
    spec.offset_base
        .apply(scaled, spec.table_offset as u64, table_end, record_offset)
}

pub(super) fn is_empty_zero_row(
    spec: &FixedRecordTableSpec,
    record: &[u8],
) -> Result<bool, LayoutError> {
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
        SizeMode::NextOffset | SizeMode::Cumulative { .. } | SizeMode::FixedSlot(_) => {}
    }
    Ok(false)
}

pub(super) fn is_skipped_row(
    spec: &FixedRecordTableSpec,
    record: &[u8],
) -> Result<bool, LayoutError> {
    if spec.skip_empty_zero && is_empty_zero_row(spec, record)? {
        return Ok(true);
    }
    if let Some(pred) = spec.skip_predicate {
        if pred.matches(record)? {
            return Ok(true);
        }
    }
    Ok(false)
}

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

pub(super) fn validate_spec(spec: &FixedRecordTableSpec) -> Result<(), LayoutError> {
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
    if let Some(pred) = spec.skip_predicate {
        validate_field_in_stride(pred.field(), spec.stride, "skip_predicate")?;
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
                | TableTermination::FieldIn { .. }
        ) {
            return Err(LayoutError::InvalidSpec {
                field: "sentinel_closes_next_offset",
                reason: "requires sentinel-based TableTermination",
            });
        }
    }
    if spec.emit_terminator {
        if !matches!(
            spec.termination,
            TableTermination::ZeroRow
                | TableTermination::FirstByteZero
                | TableTermination::FieldEquals { .. }
                | TableTermination::FieldNotEquals { .. }
                | TableTermination::FieldIn { .. }
        ) {
            return Err(LayoutError::InvalidSpec {
                field: "emit_terminator",
                reason: "requires sentinel-based TableTermination",
            });
        }
        if spec.sentinel_closes_next_offset {
            return Err(LayoutError::InvalidSpec {
                field: "emit_terminator",
                reason: "cannot be combined with sentinel_closes_next_offset",
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
        SizeMode::Cumulative { start, align } => {
            if align == 0 {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "cumulative align must be nonzero",
                });
            }
            if matches!(start, OffsetBase::RecordStart | OffsetBase::SubtractBase(_)) {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "cumulative start does not support RecordStart or SubtractBase",
                });
            }
            if spec.offset_field.is_none() {
                return Err(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required as size field for SizeMode::Cumulative",
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
        TableTermination::FieldIn { field, values } => {
            validate_field_in_stride(field, spec.stride, "termination")?;
            if values.is_empty() {
                return Err(LayoutError::InvalidSpec {
                    field: "termination",
                    reason: "FieldIn values must be non-empty",
                });
            }
        }
        TableTermination::FirstOffsetDerived => {
            if matches!(spec.size_mode, SizeMode::Cumulative { .. }) {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason: "cumulative size mode cannot be combined with TableTermination::FirstOffsetDerived",
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
