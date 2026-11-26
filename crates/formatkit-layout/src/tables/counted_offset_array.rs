//! Declarative counted offset/boundary array specification, checked parser, and symmetric writer.
//!
//! [`CountedOffsetArraySpec`] generalizes counted offset arrays
//! (`u8`/`u16`/`u24`/`u32`/`u64`, LE or BE, with optional bit-field masking,
//! signed count adjustment, optional trailing-zero trimming, optional interior
//! zero/sentinel skipping, optional EOF sentinel, offset base/unit scaling, and
//! [`OffsetOrderPolicy`]) into a single `const`-constructible descriptor.

use formatkit_core::Endian;

use crate::spec::{
    align_payload_offset, try_push, IntFieldSpec, IntWidth, LayoutError, OffsetBase, PackPolicy,
};

/// Ordering and deduplication policy applied to resolved offsets in a [`CountedOffsetArraySpec`].
///
/// # Example
/// ```
/// use formatkit_core::Endian;
/// use formatkit_layout::{
///     parse_counted_offset_array, CountedOffsetArraySpec, IntWidth, OffsetOrderPolicy,
/// };
///
/// const SPEC: CountedOffsetArraySpec =
///     CountedOffsetArraySpec::new(0, 3, IntWidth::U32, Endian::Little, 16)
///         .with_order_policy(OffsetOrderPolicy::AllowUnsorted);
///
/// // Offsets are stored out of physical order: slot 0 -> 16, slot 1 -> 12, slot 2 -> 20
/// let mut data = Vec::new();
/// data.extend_from_slice(&16u32.to_le_bytes());
/// data.extend_from_slice(&12u32.to_le_bytes());
/// data.extend_from_slice(&20u32.to_le_bytes());
/// data.extend_from_slice(b"BBBBAAAAcccc");
///
/// let spans = parse_counted_offset_array(&data, &SPEC).unwrap();
/// assert_eq!(spans[0].slice(&data), Some(&b"AAAA"[..]));
/// assert_eq!(spans[1].slice(&data), Some(&b"BBBB"[..]));
/// assert_eq!(spans[2].slice(&data), Some(&b"cccc"[..]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OffsetOrderPolicy {
    /// Require resolved offsets to be monotonically non-decreasing (default).
    #[default]
    RequireMonotonic,
    /// Allow unsorted offsets; derive each entry's end from the next physical offset
    /// in sorted order, returning spans in their original array order.
    AllowUnsorted,
    /// Sort and deduplicate unique resolved offsets before deriving `[off[i], off[i + 1])` spans.
    SortAndDeduplicate,
}

/// `const`-constructible declarative specification for a counted offset array.
///
/// # Example
/// ```
/// use formatkit_core::Endian;
/// use formatkit_layout::{
///     parse_counted_offset_array, CountedOffsetArraySpec, IntWidth,
/// };
///
/// const SPEC: CountedOffsetArraySpec =
///     CountedOffsetArraySpec::new(0, 2, IntWidth::U32, Endian::Little, 64)
///         .with_count_adjust(1) // N + 1 sentinel table
///         .with_has_eof_sentinel(true);
///
/// let mut data = Vec::new();
/// data.extend_from_slice(&12u32.to_le_bytes());
/// data.extend_from_slice(&16u32.to_le_bytes());
/// data.extend_from_slice(&22u32.to_le_bytes());
/// data.extend_from_slice(b"ABCD123456");
///
/// let spans = parse_counted_offset_array(&data, &SPEC).unwrap();
/// assert_eq!(spans.len(), 2);
/// assert_eq!(spans[0].offset, 12);
/// assert_eq!(spans[0].size, 4);
/// assert_eq!(spans[1].offset, 16);
/// assert_eq!(spans[1].size, 6);
/// ```
#[doc(alias = "offset table")]
#[doc(alias = "boundary array")]
#[doc(alias = "pointer table")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedOffsetArraySpec {
    /// Byte offset where the offset array begins.
    pub array_offset: usize,
    /// Unadjusted element count decoded by the format owner.
    pub count: usize,
    /// Signed adjustment applied to `count` (e.g. `0`, `-1`, `-2`, or `+1` for `N + 1` sentinels).
    pub count_adjust: i32,
    /// Bit width of each offset entry (`U8`, `U16`, `U24`, `U32`, or `U64`).
    pub entry_width: IntWidth,
    /// Byte order of each offset entry.
    pub endian: Endian,
    /// Right-shift applied to each decoded entry before masking (default `0`).
    pub bit_shift: u8,
    /// Bit mask applied to each decoded entry after shifting (default `u64::MAX`, meaning unmasked).
    pub bit_mask: u64,
    /// Base coordinate added to scaled offsets.
    pub offset_base: OffsetBase,
    /// Non-zero byte multiplier applied to decoded offsets (e.g. `1` or `2048`).
    pub offset_unit: u64,
    /// Trim trailing zero raw entries from the array before deriving spans.
    pub trailing_zero_trim: bool,
    /// Skip interior zero raw entries (or entries `< base` under [`OffsetBase::SubtractBase`])
    /// instead of only trimming trailing zeros.
    pub skip_zero_entries: bool,
    /// Optional raw (post-mask) sentinel value skipped for interior member slots (e.g. `0xFFFF_FFFF`).
    pub skip_sentinel: Option<u64>,
    /// When `true`, the final array element is an exclusive end sentinel rather than a member start.
    pub has_eof_sentinel: bool,
    /// Ordering and deduplication policy for resolved offsets.
    pub order_policy: OffsetOrderPolicy,
    /// When `true` and the unadjusted `count == 0`, treat any non-empty payload remaining
    /// after `array_offset` (`carrier_len > array_offset`) as a single implicit blob entry
    /// `(index: 0, offset: array_offset, size: carrier_len - array_offset)` instead of an
    /// empty table (default `false`).
    pub zero_count_implicit_blob: bool,
    /// Maximum number of adjusted offset elements permitted.
    pub max_entries: usize,
}

impl CountedOffsetArraySpec {
    /// Construct a [`CountedOffsetArraySpec`] with sensible defaults
    /// (`count_adjust: 0`, `bit_shift: 0`, `bit_mask: u64::MAX`,
    /// `offset_base: OffsetBase::Absolute`, `offset_unit: 1`,
    /// `trailing_zero_trim: false`, `skip_zero_entries: false`, `skip_sentinel: None`,
    /// `has_eof_sentinel: false`, `order_policy: OffsetOrderPolicy::RequireMonotonic`,
    /// `zero_count_implicit_blob: false`).
    #[must_use]
    pub const fn new(
        array_offset: usize,
        count: usize,
        entry_width: IntWidth,
        endian: Endian,
        max_entries: usize,
    ) -> Self {
        Self {
            array_offset,
            count,
            count_adjust: 0,
            entry_width,
            endian,
            bit_shift: 0,
            bit_mask: u64::MAX,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            trailing_zero_trim: false,
            skip_zero_entries: false,
            skip_sentinel: None,
            has_eof_sentinel: false,
            order_policy: OffsetOrderPolicy::RequireMonotonic,
            zero_count_implicit_blob: false,
            max_entries,
        }
    }

    /// Set [`CountedOffsetArraySpec::count_adjust`].
    #[must_use]
    pub const fn with_count_adjust(mut self, count_adjust: i32) -> Self {
        self.count_adjust = count_adjust;
        self
    }

    /// Set [`CountedOffsetArraySpec::bit_shift`] and [`CountedOffsetArraySpec::bit_mask`].
    #[must_use]
    pub const fn with_bit_mask(mut self, shift: u8, mask: u64) -> Self {
        self.bit_shift = shift;
        self.bit_mask = mask;
        self
    }

    /// Set [`CountedOffsetArraySpec::offset_base`].
    #[must_use]
    pub const fn with_offset_base(mut self, offset_base: OffsetBase) -> Self {
        self.offset_base = offset_base;
        self
    }

    /// Set [`CountedOffsetArraySpec::offset_unit`].
    #[must_use]
    pub const fn with_offset_unit(mut self, offset_unit: u64) -> Self {
        self.offset_unit = offset_unit;
        self
    }

    /// Set [`CountedOffsetArraySpec::trailing_zero_trim`].
    #[must_use]
    pub const fn with_trailing_zero_trim(mut self, trim: bool) -> Self {
        self.trailing_zero_trim = trim;
        self
    }

    /// Set [`CountedOffsetArraySpec::skip_zero_entries`].
    #[must_use]
    pub const fn with_skip_zero_entries(mut self, skip: bool) -> Self {
        self.skip_zero_entries = skip;
        self
    }

    /// Set [`CountedOffsetArraySpec::skip_sentinel`].
    #[must_use]
    pub const fn with_skip_sentinel(mut self, sentinel: u64) -> Self {
        self.skip_sentinel = Some(sentinel);
        self
    }

    /// Set [`CountedOffsetArraySpec::has_eof_sentinel`].
    #[must_use]
    pub const fn with_has_eof_sentinel(mut self, has_sentinel: bool) -> Self {
        self.has_eof_sentinel = has_sentinel;
        self
    }

    /// Set [`CountedOffsetArraySpec::order_policy`].
    #[must_use]
    pub const fn with_order_policy(mut self, policy: OffsetOrderPolicy) -> Self {
        self.order_policy = policy;
        self
    }

    /// Set [`CountedOffsetArraySpec::zero_count_implicit_blob`].
    #[must_use]
    pub const fn with_zero_count_implicit_blob(mut self, enabled: bool) -> Self {
        self.zero_count_implicit_blob = enabled;
        self
    }

    #[inline]
    const fn entry_field(&self, offset: usize) -> IntFieldSpec {
        IntFieldSpec::new(offset, self.entry_width, self.endian)
            .masked(self.bit_shift, self.bit_mask)
    }
}

/// One validated `(offset, size)` span derived from a [`CountedOffsetArraySpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetSpan {
    /// Zero-based logical index in the offset array.
    pub index: usize,
    /// Resolved byte offset within the carrier.
    pub offset: u64,
    /// Derived byte size of the span.
    pub size: u64,
}

impl OffsetSpan {
    /// Return the checked exclusive end offset of this span.
    #[must_use]
    pub const fn end(self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }

    /// Borrow this span's bytes from `data`, if representable in `usize` and in bounds.
    #[must_use]
    pub fn slice(self, data: &[u8]) -> Option<&[u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = usize::try_from(self.end()?).ok()?;
        data.get(start..end)
    }
}

fn validate_array_spec(spec: &CountedOffsetArraySpec) -> Result<(), LayoutError> {
    if spec.offset_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "offset_unit",
            reason: "must be nonzero",
        });
    }
    spec.entry_field(0).validate()?;
    Ok(())
}

/// Parse a counted offset array according to `spec` and derive checked `(offset, size)` spans.
pub fn parse_counted_offset_array(
    data: &[u8],
    spec: &CountedOffsetArraySpec,
) -> Result<Vec<OffsetSpan>, LayoutError> {
    parse_counted_offset_array_with_count_metadata(data, spec, spec.count, data.len() as u64)
}

/// Parse a counted offset array using a runtime `count`, without copying a
/// `const` [`CountedOffsetArraySpec`] to patch [`CountedOffsetArraySpec::count`].
pub fn parse_counted_offset_array_with_count(
    data: &[u8],
    spec: &CountedOffsetArraySpec,
    count: usize,
) -> Result<Vec<OffsetSpan>, LayoutError> {
    parse_counted_offset_array_with_count_metadata(data, spec, count, data.len() as u64)
}

/// Parse staged offset-array bytes `table_data` against an external `carrier_len`
/// without loading the entire carrier into memory.
pub fn parse_counted_offset_array_metadata(
    table_data: &[u8],
    spec: &CountedOffsetArraySpec,
    carrier_len: u64,
) -> Result<Vec<OffsetSpan>, LayoutError> {
    parse_counted_offset_array_with_count_metadata(table_data, spec, spec.count, carrier_len)
}

/// Parse staged offset-array bytes `table_data` using a runtime `count` and an
/// external `carrier_len`.
pub fn parse_counted_offset_array_with_count_metadata(
    table_data: &[u8],
    spec: &CountedOffsetArraySpec,
    count: usize,
    carrier_len: u64,
) -> Result<Vec<OffsetSpan>, LayoutError> {
    validate_array_spec(spec)?;

    if count == 0 && spec.zero_count_implicit_blob {
        if spec.array_offset > table_data.len() {
            return Err(LayoutError::Truncated {
                offset: spec.array_offset,
                needed: 0,
                available: 0,
            });
        }
        let start = spec.array_offset as u64;
        if start > carrier_len {
            return Err(LayoutError::Truncated {
                offset: spec.array_offset,
                needed: 0,
                available: 0,
            });
        }
        let remaining = carrier_len - start;
        if remaining == 0 {
            return Ok(Vec::new());
        }
        if spec.max_entries == 0 {
            return Err(LayoutError::MaxEntriesExceeded { max: 0 });
        }
        let mut spans = Vec::new();
        try_push(
            &mut spans,
            OffsetSpan {
                index: 0,
                offset: start,
                size: remaining,
            },
        )?;
        return Ok(spans);
    }

    let adjusted_i128 = (count as i128) + i128::from(spec.count_adjust);
    if adjusted_i128 < 0 {
        return Err(LayoutError::InvalidCount {
            count,
            adjust: spec.count_adjust,
        });
    }
    let effective_count =
        usize::try_from(adjusted_i128).map_err(|_| LayoutError::InvalidCount {
            count,
            adjust: spec.count_adjust,
        })?;
    if effective_count > spec.max_entries {
        return Err(LayoutError::MaxEntriesExceeded {
            max: spec.max_entries,
        });
    }

    let elem_bytes = spec.entry_width.byte_len();
    let array_bytes = effective_count
        .checked_mul(elem_bytes)
        .ok_or(LayoutError::Overflow {
            what: "array_bytes",
        })?;
    let array_end = spec
        .array_offset
        .checked_add(array_bytes)
        .ok_or(LayoutError::Overflow { what: "array_end" })?;
    if array_end > table_data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.array_offset,
            needed: array_bytes,
            available: table_data.len().saturating_sub(spec.array_offset),
        });
    }

    // Trim trailing zero raw entries in-place without allocating a scratch Vec.
    let mut trimmed_count = effective_count;
    if spec.trailing_zero_trim {
        while trimmed_count > 0 {
            let pos = spec.array_offset + (trimmed_count - 1) * elem_bytes;
            if spec.entry_field(pos).read(table_data)? == 0 {
                trimmed_count -= 1;
            } else {
                break;
            }
        }
    }

    if trimmed_count == 0 {
        return Ok(Vec::new());
    }

    let table_start = spec.array_offset as u64;
    let table_end = array_end as u64;
    let resolve_at = |index: usize| -> Result<u64, LayoutError> {
        let record_offset = spec.array_offset + index * elem_bytes;
        let raw_val = spec.entry_field(record_offset).read(table_data)?;
        let scaled = raw_val
            .checked_mul(spec.offset_unit)
            .ok_or(LayoutError::Overflow {
                what: "scaled_offset",
            })?;
        let offset = spec
            .offset_base
            .apply(scaled, table_start, table_end, record_offset)?;
        if offset > carrier_len {
            return Err(LayoutError::OutOfBounds {
                index,
                offset,
                size: 0,
                data_len: carrier_len,
            });
        }
        Ok(offset)
    };

    let resolve_member_opt = |index: usize| -> Result<Option<u64>, LayoutError> {
        let record_offset = spec.array_offset + index * elem_bytes;
        let raw_val = spec.entry_field(record_offset).read(table_data)?;
        if spec.skip_zero_entries && raw_val == 0 {
            return Ok(None);
        }
        if spec.skip_sentinel == Some(raw_val) {
            return Ok(None);
        }
        let scaled = raw_val
            .checked_mul(spec.offset_unit)
            .ok_or(LayoutError::Overflow {
                what: "scaled_offset",
            })?;
        if spec.skip_zero_entries {
            if let OffsetBase::SubtractBase(base) = spec.offset_base {
                if scaled < base {
                    return Ok(None);
                }
            }
        }
        let offset = spec
            .offset_base
            .apply(scaled, table_start, table_end, record_offset)?;
        if offset > carrier_len {
            return Err(LayoutError::OutOfBounds {
                index,
                offset,
                size: 0,
                data_len: carrier_len,
            });
        }
        Ok(Some(offset))
    };

    let member_count = if spec.has_eof_sentinel {
        trimmed_count - 1
    } else {
        trimmed_count
    };
    let may_skip = spec.skip_zero_entries || spec.skip_sentinel.is_some();

    match spec.order_policy {
        OffsetOrderPolicy::SortAndDeduplicate => {
            let terminal = if spec.has_eof_sentinel {
                resolve_at(trimmed_count - 1)?
            } else {
                carrier_len
            };
            if member_count == 0 {
                return Ok(Vec::new());
            }
            let mut unique: Vec<u64> = Vec::new();
            for index in 0..member_count {
                let Some(offset) = resolve_member_opt(index)? else {
                    continue;
                };
                if offset > terminal {
                    return Err(LayoutError::OutOfBounds {
                        index,
                        offset,
                        size: 0,
                        data_len: terminal,
                    });
                }
                try_push(&mut unique, offset)?;
            }
            if unique.is_empty() {
                return Ok(Vec::new());
            }
            unique.sort_unstable();
            unique.dedup();

            let mut spans = Vec::new();
            spans
                .try_reserve_exact(unique.len())
                .map_err(|_| LayoutError::AllocationFailed {
                    requested: unique.len(),
                })?;
            for (i, &offset) in unique.iter().enumerate() {
                let next = unique.get(i + 1).copied().unwrap_or(terminal);
                spans.push(OffsetSpan {
                    index: i,
                    offset,
                    size: next - offset,
                });
            }
            Ok(spans)
        }
        OffsetOrderPolicy::RequireMonotonic => {
            let terminal = if spec.has_eof_sentinel {
                Some(resolve_at(trimmed_count - 1)?)
            } else {
                None
            };
            let mut spans = Vec::new();
            if !may_skip {
                spans.try_reserve_exact(member_count).map_err(|_| {
                    LayoutError::AllocationFailed {
                        requested: member_count,
                    }
                })?;
            }
            let mut prev: Option<(usize, u64)> = None;
            for index in 0..member_count {
                let Some(current) = resolve_member_opt(index)? else {
                    continue;
                };
                if let Some((prev_idx, prev_off)) = prev {
                    if current < prev_off {
                        return Err(LayoutError::NonMonotonic {
                            index,
                            previous: prev_off,
                            current,
                        });
                    }
                    try_push(
                        &mut spans,
                        OffsetSpan {
                            index: prev_idx,
                            offset: prev_off,
                            size: current - prev_off,
                        },
                    )?;
                }
                prev = Some((index, current));
            }
            if let Some((last_idx, last_off)) = prev {
                let end_bound = if let Some(term) = terminal {
                    if term < last_off {
                        return Err(LayoutError::NonMonotonic {
                            index: trimmed_count - 1,
                            previous: last_off,
                            current: term,
                        });
                    }
                    term
                } else {
                    carrier_len
                };
                try_push(
                    &mut spans,
                    OffsetSpan {
                        index: last_idx,
                        offset: last_off,
                        size: end_bound - last_off,
                    },
                )?;
            }
            Ok(spans)
        }
        OffsetOrderPolicy::AllowUnsorted => {
            // Unsorted offsets: derive each entry's end from the next physical offset
            // in sorted order (bounded by `terminal`), then return in original order.
            let terminal = if spec.has_eof_sentinel {
                resolve_at(trimmed_count - 1)?
            } else {
                carrier_len
            };
            if member_count == 0 {
                return Ok(Vec::new());
            }

            let mut order: Vec<(u64, usize, usize)> = Vec::new();
            if !may_skip {
                order.try_reserve_exact(member_count).map_err(|_| {
                    LayoutError::AllocationFailed {
                        requested: member_count,
                    }
                })?;
            }
            for index in 0..member_count {
                let Some(offset) = resolve_member_opt(index)? else {
                    continue;
                };
                if offset > terminal {
                    return Err(LayoutError::OutOfBounds {
                        index,
                        offset,
                        size: 0,
                        data_len: terminal,
                    });
                }
                let out_pos = order.len();
                try_push(&mut order, (offset, index, out_pos))?;
            }
            if order.is_empty() {
                return Ok(Vec::new());
            }
            order.sort_unstable();

            let mut spans = Vec::new();
            spans
                .try_reserve_exact(order.len())
                .map_err(|_| LayoutError::AllocationFailed {
                    requested: order.len(),
                })?;
            spans.resize(
                order.len(),
                OffsetSpan {
                    index: 0,
                    offset: 0,
                    size: 0,
                },
            );
            for pos in 0..order.len() {
                let (offset, orig_index, out_pos) = order[pos];
                let next = order.get(pos + 1).map_or(terminal, |&(off, _, _)| off);
                spans[out_pos] = OffsetSpan {
                    index: orig_index,
                    offset,
                    size: next - offset,
                };
            }
            Ok(spans)
        }
    }
}

/// Serialize `payloads` into a binary carrier with a counted offset array
/// conforming to `spec` and `policy`.
///
/// The resulting buffer begins with `header_prefix` (padded with
/// [`PackPolicy::prefix_fill_byte`] up to [`CountedOffsetArraySpec::array_offset`]),
/// followed by the encoded offset array (initialized with
/// [`PackPolicy::record_fill_byte`] before writing any bit-masked entries, and
/// including the EOF sentinel when [`CountedOffsetArraySpec::has_eof_sentinel`] is `true`),
/// and then the aligned payloads.
///
/// # Round-trip invariants
///
/// To prevent silently dropping or merging entries on round-trip parsing, this writer rejects:
/// - Any entry whose encoded raw offset is `0` when [`CountedOffsetArraySpec::skip_zero_entries`] is `true`.
/// - Any entry whose encoded raw offset equals [`CountedOffsetArraySpec::skip_sentinel`].
/// - A trailing zero raw offset (either the EOF sentinel or the final entry) when
///   [`CountedOffsetArraySpec::trailing_zero_trim`] is `true`.
/// - Duplicate physical payload offsets (e.g. an empty payload followed by another entry
///   at the same byte offset) when [`CountedOffsetArraySpec::order_policy`] is
///   [`OffsetOrderPolicy::SortAndDeduplicate`].
///
/// # Example
/// ```
/// use formatkit_core::Endian;
/// use formatkit_layout::{
///     pack_counted_offset_array, parse_counted_offset_array_with_count, CountedOffsetArraySpec,
///     IntWidth, PackPolicy,
/// };
///
/// const SPEC: CountedOffsetArraySpec =
///     CountedOffsetArraySpec::new(0, 0, IntWidth::U32, Endian::Little, 16)
///         .with_count_adjust(1)
///         .with_has_eof_sentinel(true);
///
/// let payloads: &[&[u8]] = &[b"one", b"two!"];
/// let policy = PackPolicy::TIGHT.with_data_alignment(4);
/// let packed = pack_counted_offset_array(&SPEC, &policy, &[], payloads).unwrap();
/// let spans = parse_counted_offset_array_with_count(&packed, &SPEC, payloads.len()).unwrap();
/// assert_eq!(spans.len(), 2);
/// assert_eq!(spans[0].offset, 12);
/// assert_eq!(spans[1].slice(&packed), Some(&b"two!"[..]));
/// ```
pub fn pack_counted_offset_array(
    spec: &CountedOffsetArraySpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    payloads: &[&[u8]],
) -> Result<Vec<u8>, LayoutError> {
    validate_array_spec(spec)?;
    policy.validate()?;

    if header_prefix.len() > spec.array_offset {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "header_prefix exceeds array_offset",
        });
    }

    let array_elems = if spec.has_eof_sentinel {
        payloads.len().checked_add(1).ok_or(LayoutError::Overflow {
            what: "array_elems",
        })?
    } else {
        payloads.len()
    };
    if array_elems > spec.max_entries {
        return Err(LayoutError::MaxEntriesExceeded {
            max: spec.max_entries,
        });
    }

    let elem_bytes = spec.entry_width.byte_len();
    let array_bytes = array_elems
        .checked_mul(elem_bytes)
        .ok_or(LayoutError::Overflow {
            what: "array_bytes",
        })?;
    let array_end = spec
        .array_offset
        .checked_add(array_bytes)
        .ok_or(LayoutError::Overflow { what: "array_end" })?;
    let table_start = spec.array_offset as u64;
    let table_end = array_end as u64;

    let mut offsets: Vec<(usize, u64)> = Vec::new();
    offsets
        .try_reserve_exact(payloads.len())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: payloads.len(),
        })?;

    let mut cursor = table_end;
    let mut prev_physical: Option<u64> = None;
    for (index, payload) in payloads.iter().enumerate() {
        let record_offset = spec.array_offset + index * elem_bytes;
        let (offset_u64, raw_offset) = spec.offset_base.align_and_encode(
            cursor,
            table_start,
            table_end,
            record_offset,
            policy.data_alignment,
            spec.offset_unit,
        )?;
        if spec.skip_zero_entries && raw_offset == 0 {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "encoded offset would be skipped by skip_zero_entries",
            });
        }
        if spec.skip_sentinel == Some(raw_offset) {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "encoded offset collides with skip_sentinel",
            });
        }
        if spec.order_policy == OffsetOrderPolicy::SortAndDeduplicate
            && prev_physical == Some(offset_u64)
        {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "duplicate payload offset would be merged by SortAndDeduplicate",
            });
        }
        prev_physical = Some(offset_u64);
        let payload_offset = usize::try_from(offset_u64).map_err(|_| LayoutError::Overflow {
            what: "payload_offset",
        })?;
        offsets.push((payload_offset, raw_offset));
        cursor = offset_u64
            .checked_add(payload.len() as u64)
            .ok_or(LayoutError::Overflow {
                what: "payload_end",
            })?;
    }

    let sentinel_raw = if spec.has_eof_sentinel {
        let sentinel_record_offset = spec.array_offset + payloads.len() * elem_bytes;
        let sentinel_align = if policy.pad_final_entry {
            policy.data_alignment
        } else {
            1
        };
        let (end_u64, raw_sentinel) = spec.offset_base.align_and_encode(
            cursor,
            table_start,
            table_end,
            sentinel_record_offset,
            sentinel_align,
            spec.offset_unit,
        )?;
        cursor = end_u64;
        Some(raw_sentinel)
    } else {
        if policy.pad_final_entry && policy.data_alignment > 1 {
            cursor = align_payload_offset(cursor, 0, policy.data_alignment, 1)?;
        }
        None
    };

    if spec.trailing_zero_trim {
        if let Some(raw_sentinel) = sentinel_raw {
            if raw_sentinel == 0 {
                return Err(LayoutError::InvalidInput {
                    index: payloads.len(),
                    reason: "trailing zero sentinel would be trimmed by trailing_zero_trim",
                });
            }
        } else if let Some(&(_, last_raw)) = offsets.last() {
            if last_raw == 0 {
                return Err(LayoutError::InvalidInput {
                    index: payloads.len() - 1,
                    reason: "trailing zero offset would be trimmed by trailing_zero_trim",
                });
            }
        }
    }

    let total_len =
        usize::try_from(cursor).map_err(|_| LayoutError::Overflow { what: "output_len" })?;
    let mut out = Vec::new();
    out.try_reserve_exact(total_len)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: total_len,
        })?;
    out.resize(total_len, policy.pad_byte);

    out[..header_prefix.len()].copy_from_slice(header_prefix);
    out[header_prefix.len()..spec.array_offset].fill(policy.prefix_fill_byte);
    out[spec.array_offset..array_end].fill(policy.record_fill_byte);

    for (index, &(payload_offset, raw_offset)) in offsets.iter().enumerate() {
        let pos = spec.array_offset + index * elem_bytes;
        spec.entry_field(pos).write(&mut out, raw_offset)?;
        let payload = payloads[index];
        out[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    }

    if let Some(raw_sentinel) = sentinel_raw {
        let pos = spec.array_offset + payloads.len() * elem_bytes;
        spec.entry_field(pos).write(&mut out, raw_sentinel)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_u32_le_with_eof_sentinel_and_count_adjust() {
        const SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(4, 2, IntWidth::U32, Endian::Little, 16)
                .with_count_adjust(1)
                .with_has_eof_sentinel(true);
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&20u32.to_le_bytes());
        data.extend_from_slice(&26u32.to_le_bytes());
        data.extend_from_slice(b"1234abcdef");

        let spans = parse_counted_offset_array(&data, &SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].slice(&data), Some(&b"1234"[..]));
        assert_eq!(spans[1].slice(&data), Some(&b"abcdef"[..]));
    }

    #[test]
    fn parses_u16_be_sector_scaled_with_trailing_zero_trim_and_metadata_700mb() {
        const SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 4, IntWidth::U16, Endian::Big, 16)
                .with_offset_unit(2048)
                .with_trailing_zero_trim(true);
        let mut table_only = Vec::new();
        table_only.extend_from_slice(&1u16.to_be_bytes());
        table_only.extend_from_slice(&2u16.to_be_bytes());
        table_only.extend_from_slice(&0u16.to_be_bytes());
        table_only.extend_from_slice(&0u16.to_be_bytes());

        let carrier_len: u64 = 750 * 1024 * 1024;
        let spans = parse_counted_offset_array_metadata(&table_only, &SPEC, carrier_len).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].offset, 2048);
        assert_eq!(spans[0].size, 2048);
        assert_eq!(spans[1].offset, 4096);
        assert_eq!(spans[1].size, carrier_len - 4096);
    }

    #[test]
    fn parses_negative_count_adjust_and_table_end_base_with_runtime_count() {
        const SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 0, IntWidth::U32, Endian::Little, 16)
                .with_count_adjust(-2)
                .with_offset_base(OffsetBase::TableEnd);
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"abcXYZ");

        let spans = parse_counted_offset_array_with_count(&data, &SPEC, 4).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].slice(&data), Some(&b"abc"[..]));
        assert_eq!(spans[1].slice(&data), Some(&b"XYZ"[..]));
    }

    #[test]
    fn parses_non_monotonic_when_permitted_and_rejects_when_required() {
        let mut data = Vec::new();
        data.extend_from_slice(&12u32.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(b"BBBBAAAA");

        let strict_spec = CountedOffsetArraySpec::new(0, 2, IntWidth::U32, Endian::Little, 8);
        assert_eq!(
            parse_counted_offset_array(&data, &strict_spec),
            Err(LayoutError::NonMonotonic {
                index: 1,
                previous: 12,
                current: 8,
            })
        );

        let relaxed_spec = strict_spec.with_order_policy(OffsetOrderPolicy::AllowUnsorted);
        let spans = parse_counted_offset_array(&data, &relaxed_spec).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].offset, 12);
        assert_eq!(spans[0].size, 4);
        assert_eq!(spans[0].slice(&data), Some(&b"AAAA"[..]));
        assert_eq!(spans[1].offset, 8);
        assert_eq!(spans[1].size, 4);
        assert_eq!(spans[1].slice(&data), Some(&b"BBBB"[..]));
    }

    #[test]
    fn rejects_invalid_count_oob_overflow_and_max_entries() {
        let bad_adjust = CountedOffsetArraySpec::new(0, 1, IntWidth::U32, Endian::Little, 8)
            .with_count_adjust(-2);
        assert_eq!(
            parse_counted_offset_array(&[0u8; 8], &bad_adjust),
            Err(LayoutError::InvalidCount {
                count: 1,
                adjust: -2,
            })
        );

        let oob_spec = bad_adjust.with_count_adjust(0);
        let mut oob = Vec::new();
        oob.extend_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            parse_counted_offset_array(&oob, &oob_spec),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));

        let ov_spec = oob_spec.with_offset_unit(u64::MAX);
        assert_eq!(
            parse_counted_offset_array(&2u32.to_le_bytes(), &ov_spec),
            Err(LayoutError::Overflow {
                what: "scaled_offset"
            })
        );

        let cap_spec = CountedOffsetArraySpec {
            max_entries: 0,
            ..oob_spec
        };
        assert_eq!(
            parse_counted_offset_array(&oob, &cap_spec),
            Err(LayoutError::MaxEntriesExceeded { max: 0 })
        );
    }

    #[test]
    fn pack_counted_offset_array_round_trips_all_widths_sentinels_and_alignment() {
        // 1. U32 LE with EOF sentinel, header_prefix, and TableEnd base
        const SENTINEL_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(4, 0, IntWidth::U32, Endian::Little, 16)
                .with_count_adjust(1)
                .with_offset_base(OffsetBase::TableEnd)
                .with_has_eof_sentinel(true);
        let payloads: &[&[u8]] = &[b"alpha", b"beta!", b""];
        let packed = pack_counted_offset_array(
            &SENTINEL_SPEC,
            &PackPolicy::TIGHT,
            &3u32.to_le_bytes(),
            payloads,
        )
        .unwrap();
        let spans = parse_counted_offset_array_with_count(&packed, &SENTINEL_SPEC, 3).unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].slice(&packed), Some(&b"alpha"[..]));
        assert_eq!(spans[1].slice(&packed), Some(&b"beta!"[..]));
        assert_eq!(spans[2].slice(&packed), Some(&b""[..]));

        // 2. U24 BE sector-scaled without EOF sentinel
        const SECTOR_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 2, IntWidth::U24, Endian::Big, 16)
                .with_offset_unit(2048);
        let sec_payloads: &[&[u8]] = &[&[0x11; 2048], &[0x22; 100]];
        let sec_packed =
            pack_counted_offset_array(&SECTOR_SPEC, &PackPolicy::TIGHT, &[], sec_payloads).unwrap();
        let sec_spans = parse_counted_offset_array(&sec_packed, &SECTOR_SPEC).unwrap();
        assert_eq!(sec_spans.len(), 2);
        assert_eq!(sec_spans[0].offset, 2048);
        assert_eq!(sec_spans[0].size, 2048);
        assert_eq!(sec_spans[1].offset, 4096);
        assert_eq!(sec_spans[1].size, 100);

        // 3. U64 BE with alignment and pad_final_entry
        const U64_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(8, 2, IntWidth::U64, Endian::Big, 16);
        let policy = PackPolicy::TIGHT
            .with_data_alignment(8)
            .with_pad_byte(0xAA)
            .with_pad_final_entry(true)
            .with_prefix_fill_byte(0x55);
        let u64_packed =
            pack_counted_offset_array(&U64_SPEC, &policy, b"HEAD", &[b"123", b"4567"]).unwrap();
        assert_eq!(&u64_packed[0..4], b"HEAD");
        assert_eq!(&u64_packed[4..8], &[0x55; 4]);
        assert_eq!(u64_packed.len() % 8, 0);
        let u64_spans = parse_counted_offset_array(&u64_packed, &U64_SPEC).unwrap();
        assert_eq!(u64_spans[0].offset % 8, 0);
        assert_eq!(u64_spans[1].offset % 8, 0);

        // 4. U8 width out-of-range rejection
        const U8_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 2, IntWidth::U8, Endian::Little, 16);
        let huge = [0u8; 300];
        assert_eq!(
            pack_counted_offset_array(&U8_SPEC, &PackPolicy::TIGHT, &[], &[&huge, b"x"]),
            Err(LayoutError::ValueOutOfRange {
                value: 302,
                max: 255
            })
        );
    }

    #[test]
    fn subtract_base_round_trips_and_rejects_underflow() {
        const BUS_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 2, IntWidth::U32, Endian::Little, 16)
                .with_count_adjust(1)
                .with_offset_base(OffsetBase::SubtractBase(0x0800_0000))
                .with_has_eof_sentinel(true);
        let packed =
            pack_counted_offset_array(&BUS_SPEC, &PackPolicy::TIGHT, &[], &[b"ABCD", b"EF"])
                .unwrap();
        assert_eq!(
            u32::from_le_bytes(packed[0..4].try_into().unwrap()),
            0x0800_000C
        );
        let spans = parse_counted_offset_array(&packed, &BUS_SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].slice(&packed), Some(&b"ABCD"[..]));
        assert_eq!(spans[1].slice(&packed), Some(&b"EF"[..]));

        let bad = 0x07FF_FFFFu32.to_le_bytes();
        let bad_spec = CountedOffsetArraySpec {
            count: 1,
            count_adjust: 0,
            has_eof_sentinel: false,
            ..BUS_SPEC
        };
        assert_eq!(
            parse_counted_offset_array(&bad, &bad_spec),
            Err(LayoutError::Overflow {
                what: "offset_subtract_base"
            })
        );
    }

    #[test]
    fn skip_zero_entries_deduplicate_sorted_and_table_start_base() {
        const SKIP_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 4, IntWidth::U32, Endian::Little, 16)
                .with_skip_zero_entries(true);
        let mut data = Vec::new();
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&20u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(b"AAAABBBBBB");

        let spans = parse_counted_offset_array(&data, &SKIP_SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].index, 0);
        assert_eq!(spans[0].slice(&data), Some(&b"AAAA"[..]));
        assert_eq!(spans[1].index, 2);
        assert_eq!(spans[1].slice(&data), Some(&b"BBBBBB"[..]));

        const BUS_SKIP: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 3, IntWidth::U32, Endian::Little, 16)
                .with_offset_base(OffsetBase::SubtractBase(0x8000_0000))
                .with_skip_zero_entries(true);
        let mut bus_data = Vec::new();
        bus_data.extend_from_slice(&0x8000_000Cu32.to_le_bytes());
        bus_data.extend_from_slice(&0x0000_0000u32.to_le_bytes());
        bus_data.extend_from_slice(&0x8000_0010u32.to_le_bytes());
        bus_data.extend_from_slice(b"12345678");
        let bus_spans = parse_counted_offset_array(&bus_data, &BUS_SKIP).unwrap();
        assert_eq!(bus_spans.len(), 2);
        assert_eq!(bus_spans[0].index, 0);
        assert_eq!(bus_spans[0].slice(&bus_data), Some(&b"1234"[..]));
        assert_eq!(bus_spans[1].index, 2);
        assert_eq!(bus_spans[1].slice(&bus_data), Some(&b"5678"[..]));

        const DEDUP_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 5, IntWidth::U32, Endian::Little, 16)
                .with_skip_zero_entries(true)
                .with_order_policy(OffsetOrderPolicy::SortAndDeduplicate);
        let mut dup_data = Vec::new();
        dup_data.extend_from_slice(&24u32.to_le_bytes());
        dup_data.extend_from_slice(&20u32.to_le_bytes());
        dup_data.extend_from_slice(&0u32.to_le_bytes());
        dup_data.extend_from_slice(&24u32.to_le_bytes());
        dup_data.extend_from_slice(&20u32.to_le_bytes());
        dup_data.extend_from_slice(b"XXXXYYYYYY");
        let dedup_spans = parse_counted_offset_array(&dup_data, &DEDUP_SPEC).unwrap();
        assert_eq!(dedup_spans.len(), 2);
        assert_eq!(dedup_spans[0].index, 0);
        assert_eq!(dedup_spans[0].offset, 20);
        assert_eq!(dedup_spans[0].slice(&dup_data), Some(&b"XXXX"[..]));
        assert_eq!(dedup_spans[1].index, 1);
        assert_eq!(dedup_spans[1].offset, 24);
        assert_eq!(dedup_spans[1].slice(&dup_data), Some(&b"YYYYYY"[..]));

        const TABLE_START_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(8, 2, IntWidth::U32, Endian::Little, 16)
                .with_offset_base(OffsetBase::TableStart);
        let ts_packed = pack_counted_offset_array(
            &TABLE_START_SPEC,
            &PackPolicy::TIGHT,
            b"HEAD",
            &[b"hi", b"yo!"],
        )
        .unwrap();
        assert_eq!(u32::from_le_bytes(ts_packed[8..12].try_into().unwrap()), 8);
        let ts_spans = parse_counted_offset_array(&ts_packed, &TABLE_START_SPEC).unwrap();
        assert_eq!(ts_spans[0].slice(&ts_packed), Some(&b"hi"[..]));
        assert_eq!(ts_spans[1].slice(&ts_packed), Some(&b"yo!"[..]));

        const TABLE_END_PLUS_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(4, 2, IntWidth::U32, Endian::Little, 16)
                .with_offset_base(OffsetBase::TableEndPlus(16));
        let tep_packed = pack_counted_offset_array(
            &TABLE_END_PLUS_SPEC,
            &PackPolicy::TIGHT,
            b"HDR!",
            &[b"AA", b"BBB"],
        )
        .unwrap();
        let tep_spans = parse_counted_offset_array(&tep_packed, &TABLE_END_PLUS_SPEC).unwrap();
        assert_eq!(tep_spans[0].offset, 4 + 8 + 16);
        assert_eq!(tep_spans[0].slice(&tep_packed), Some(&b"AA"[..]));
        assert_eq!(tep_spans[1].slice(&tep_packed), Some(&b"BBB"[..]));
    }

    #[test]
    fn skip_sentinel_bit_mask_and_pack_round_trip_guards() {
        // 1. Entry bit-masking (e.g. high flag nibble ignored, low 28-bit offset)
        const MASKED_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 2, IntWidth::U32, Endian::Little, 16)
                .with_bit_mask(0, 0x0FFF_FFFF);
        let packed =
            pack_counted_offset_array(&MASKED_SPEC, &PackPolicy::TIGHT, &[], &[b"ABCD", b"EF"])
                .unwrap();
        // Inject high flag bits into raw entries and verify parse still extracts offsets cleanly
        let mut flagged = packed.clone();
        flagged[3] |= 0xA0;
        flagged[7] |= 0x50;
        let spans = parse_counted_offset_array(&flagged, &MASKED_SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].slice(&flagged), Some(&b"ABCD"[..]));
        assert_eq!(spans[1].slice(&flagged), Some(&b"EF"[..]));

        // Shifted bit-mask pack + parse round-trip
        const SHIFTED_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 2, IntWidth::U32, Endian::Little, 16)
                .with_bit_mask(4, 0x0FFF_FFFF);
        let shifted_packed =
            pack_counted_offset_array(&SHIFTED_SPEC, &PackPolicy::TIGHT, &[], &[b"123", b"4567"])
                .unwrap();
        let shifted_spans = parse_counted_offset_array(&shifted_packed, &SHIFTED_SPEC).unwrap();
        assert_eq!(shifted_spans[0].slice(&shifted_packed), Some(&b"123"[..]));
        assert_eq!(shifted_spans[1].slice(&shifted_packed), Some(&b"4567"[..]));

        // 2. skip_sentinel skips 0xFFFF_FFFF interior entries while preserving physical index
        const SENTINEL_SKIP: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 3, IntWidth::U32, Endian::Little, 16)
                .with_skip_sentinel(0xFFFF_FFFF);
        let mut sdata = Vec::new();
        sdata.extend_from_slice(&12u32.to_le_bytes());
        sdata.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        sdata.extend_from_slice(&16u32.to_le_bytes());
        sdata.extend_from_slice(b"AAAAbbbb");
        let sspans = parse_counted_offset_array(&sdata, &SENTINEL_SKIP).unwrap();
        assert_eq!(sspans.len(), 2);
        assert_eq!(sspans[0].index, 0);
        assert_eq!(sspans[0].slice(&sdata), Some(&b"AAAA"[..]));
        assert_eq!(sspans[1].index, 2);
        assert_eq!(sspans[1].slice(&sdata), Some(&b"bbbb"[..]));

        // 3. Pack guards reject silent round-trip loss
        // (a) skip_zero_entries with TableEnd (entry 0 encodes raw_offset == 0)
        const ZERO_GUARD: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 1, IntWidth::U32, Endian::Little, 16)
                .with_offset_base(OffsetBase::TableEnd)
                .with_skip_zero_entries(true);
        assert!(matches!(
            pack_counted_offset_array(&ZERO_GUARD, &PackPolicy::TIGHT, &[], &[b"abc"]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        // (b) trailing_zero_trim with TableEnd and 1 entry (raw_offset == 0)
        const TRIM_GUARD: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 1, IntWidth::U32, Endian::Little, 16)
                .with_offset_base(OffsetBase::TableEnd)
                .with_trailing_zero_trim(true);
        assert!(matches!(
            pack_counted_offset_array(&TRIM_GUARD, &PackPolicy::TIGHT, &[], &[b"abc"]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        // (c) SortAndDeduplicate with empty payload followed by another entry at same offset
        const DEDUP_GUARD: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 2, IntWidth::U32, Endian::Little, 16)
                .with_order_policy(OffsetOrderPolicy::SortAndDeduplicate);
        assert!(matches!(
            pack_counted_offset_array(&DEDUP_GUARD, &PackPolicy::TIGHT, &[], &[b"", b"abc"]),
            Err(LayoutError::InvalidInput { index: 1, .. })
        ));

        // (d) skip_sentinel collision on pack
        const COLLIDE_GUARD: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(0, 1, IntWidth::U32, Endian::Little, 16)
                .with_skip_sentinel(4);
        assert!(matches!(
            pack_counted_offset_array(&COLLIDE_GUARD, &PackPolicy::TIGHT, &[], &[b"abc"]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));
    }

    #[test]
    fn zero_count_implicit_blob_emits_single_span_when_payload_present() {
        const SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(8, 0, IntWidth::U32, Endian::Little, 16)
                .with_zero_count_implicit_blob(true);

        // Header (8 bytes) + non-empty implicit blob (6 bytes)
        let data = b"HDR\0\0\0\0\0BLOB!!";
        let spans = parse_counted_offset_array(data, &SPEC).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].index, 0);
        assert_eq!(spans[0].offset, 8);
        assert_eq!(spans[0].size, 6);
        assert_eq!(spans[0].slice(data), Some(&b"BLOB!!"[..]));

        // Default (false) returns empty Vec for count == 0
        const DEFAULT_SPEC: CountedOffsetArraySpec =
            CountedOffsetArraySpec::new(8, 0, IntWidth::U32, Endian::Little, 16);
        assert!(parse_counted_offset_array(data, &DEFAULT_SPEC)
            .unwrap()
            .is_empty());

        // Header only (no remaining payload) returns empty Vec even when enabled
        assert!(parse_counted_offset_array(b"HDR\0\0\0\0\0", &SPEC)
            .unwrap()
            .is_empty());

        // Truncated header (< array_offset) returns Truncated
        assert!(matches!(
            parse_counted_offset_array(b"HDR", &SPEC),
            Err(LayoutError::Truncated { offset: 8, .. })
        ));

        // Non-zero count behaves identically to normal counted offset array
        let mut two = Vec::new();
        two.extend_from_slice(b"HDR\0\x02\0\0\0");
        two.extend_from_slice(&16u32.to_le_bytes());
        two.extend_from_slice(&20u32.to_le_bytes());
        two.extend_from_slice(b"ABCDxy");
        let normal = parse_counted_offset_array_with_count(&two, &SPEC, 2).unwrap();
        assert_eq!(normal.len(), 2);
        assert_eq!(normal[0].slice(&two), Some(&b"ABCD"[..]));
        assert_eq!(normal[1].slice(&two), Some(&b"xy"[..]));
    }
}
