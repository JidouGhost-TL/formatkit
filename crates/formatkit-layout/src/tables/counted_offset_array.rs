//! Declarative counted offset/boundary array specification, checked parser, and symmetric writer.
//!
//! [`CountedOffsetArraySpec`] generalizes counted offset arrays
//! (`u8`/`u16`/`u24`/`u32`/`u64`, LE or BE, with signed count adjustment,
//! optional trailing-zero trimming, optional EOF sentinel, offset base/unit
//! scaling, and monotonicity policy) into a single `const`-constructible
//! descriptor.

use formatkit_core::Endian;

use crate::spec::{
    align_payload_offset, read_int_at, write_int_at, IntWidth, LayoutError, OffsetBase, PackPolicy,
};

/// `const`-constructible declarative specification for a counted offset array.
///
/// # Example
/// ```
/// use formatkit_core::Endian;
/// use formatkit_layout::{
///     parse_counted_offset_array, CountedOffsetArraySpec, IntWidth, OffsetBase,
/// };
///
/// const SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
///     array_offset: 0,
///     count: 2,
///     count_adjust: 1, // N + 1 sentinel table
///     entry_width: IntWidth::U32,
///     endian: Endian::Little,
///     offset_base: OffsetBase::Absolute,
///     offset_unit: 1,
///     trailing_zero_trim: false,
///     has_eof_sentinel: true,
///     require_monotonic: true,
///     max_entries: 64,
/// };
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
    /// Base coordinate added to scaled offsets.
    pub offset_base: OffsetBase,
    /// Non-zero byte multiplier applied to decoded offsets (e.g. `1` or `2048`).
    pub offset_unit: u64,
    /// Trim trailing zero raw entries from the array before deriving spans.
    pub trailing_zero_trim: bool,
    /// When `true`, the final array element is an exclusive end sentinel rather than a member start.
    pub has_eof_sentinel: bool,
    /// When `true`, resolved offsets must be monotonically non-decreasing.
    pub require_monotonic: bool,
    /// Maximum number of adjusted offset elements permitted.
    pub max_entries: usize,
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
    if spec.offset_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "offset_unit",
            reason: "must be nonzero",
        });
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
            if read_int_at(table_data, pos, spec.entry_width, spec.endian)? == 0 {
                trimmed_count -= 1;
            } else {
                break;
            }
        }
    }

    if trimmed_count == 0 {
        return Ok(Vec::new());
    }

    let table_end = array_end as u64;
    let resolve_at = |index: usize| -> Result<u64, LayoutError> {
        let record_offset = spec.array_offset + index * elem_bytes;
        let raw_val = read_int_at(table_data, record_offset, spec.entry_width, spec.endian)?;
        let scaled = raw_val
            .checked_mul(spec.offset_unit)
            .ok_or(LayoutError::Overflow {
                what: "scaled_offset",
            })?;
        let offset = spec.offset_base.apply(scaled, table_end, record_offset)?;
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

    let member_count = if spec.has_eof_sentinel {
        trimmed_count - 1
    } else {
        trimmed_count
    };

    if spec.require_monotonic {
        // Single-pass, single-allocation path for monotonic offset arrays.
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(member_count)
            .map_err(|_| LayoutError::AllocationFailed {
                requested: member_count,
            })?;
        let mut prev = resolve_at(0)?;
        for index in 1..trimmed_count {
            let current = resolve_at(index)?;
            if current < prev {
                return Err(LayoutError::NonMonotonic {
                    index,
                    previous: prev,
                    current,
                });
            }
            spans.push(OffsetSpan {
                index: index - 1,
                offset: prev,
                size: current - prev,
            });
            prev = current;
        }
        if !spec.has_eof_sentinel {
            spans.push(OffsetSpan {
                index: trimmed_count - 1,
                offset: prev,
                size: carrier_len - prev,
            });
        }
        Ok(spans)
    } else {
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

        let mut order: Vec<(u64, usize)> = Vec::new();
        order
            .try_reserve_exact(member_count)
            .map_err(|_| LayoutError::AllocationFailed {
                requested: member_count,
            })?;
        for index in 0..member_count {
            let offset = resolve_at(index)?;
            if offset > terminal {
                return Err(LayoutError::OutOfBounds {
                    index,
                    offset,
                    size: 0,
                    data_len: terminal,
                });
            }
            order.push((offset, index));
        }
        order.sort_unstable();

        let mut spans = Vec::new();
        spans
            .try_reserve_exact(member_count)
            .map_err(|_| LayoutError::AllocationFailed {
                requested: member_count,
            })?;
        spans.resize(
            member_count,
            OffsetSpan {
                index: 0,
                offset: 0,
                size: 0,
            },
        );
        for pos in 0..order.len() {
            let (offset, orig_index) = order[pos];
            let next = order.get(pos + 1).map_or(terminal, |&(off, _)| off);
            spans[orig_index] = OffsetSpan {
                index: orig_index,
                offset,
                size: next - offset,
            };
        }
        Ok(spans)
    }
}

/// Serialize `payloads` into a binary carrier with a counted offset array
/// conforming to `spec` and `policy`.
///
/// The resulting buffer begins with `header_prefix` (padded with
/// [`PackPolicy::prefix_fill_byte`] up to [`CountedOffsetArraySpec::array_offset`]),
/// followed by the encoded offset array (including the EOF sentinel when
/// [`CountedOffsetArraySpec::has_eof_sentinel`] is `true`), and then the aligned
/// payloads.
pub fn pack_counted_offset_array(
    spec: &CountedOffsetArraySpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    payloads: &[&[u8]],
) -> Result<Vec<u8>, LayoutError> {
    if spec.offset_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "offset_unit",
            reason: "must be nonzero",
        });
    }
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
    let table_end = array_end as u64;

    let mut offsets: Vec<(usize, u64)> = Vec::new();
    offsets
        .try_reserve_exact(payloads.len())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: payloads.len(),
        })?;

    let mut cursor = table_end;
    for (index, payload) in payloads.iter().enumerate() {
        let record_offset = spec.array_offset + index * elem_bytes;
        let (offset_u64, raw_offset) = spec.offset_base.align_and_encode(
            cursor,
            table_end,
            record_offset,
            policy.data_alignment,
            spec.offset_unit,
        )?;
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

    for (index, &(payload_offset, raw_offset)) in offsets.iter().enumerate() {
        let pos = spec.array_offset + index * elem_bytes;
        write_int_at(&mut out, pos, spec.entry_width, spec.endian, raw_offset)?;
        let payload = payloads[index];
        out[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    }

    if let Some(raw_sentinel) = sentinel_raw {
        let pos = spec.array_offset + payloads.len() * elem_bytes;
        write_int_at(&mut out, pos, spec.entry_width, spec.endian, raw_sentinel)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_u32_le_with_eof_sentinel_and_count_adjust() {
        const SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 4,
            count: 2,
            count_adjust: 1,
            entry_width: IntWidth::U32,
            endian: Endian::Little,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: true,
            require_monotonic: true,
            max_entries: 16,
        };
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
        const SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 4,
            count_adjust: 0,
            entry_width: IntWidth::U16,
            endian: Endian::Big,
            offset_base: OffsetBase::Absolute,
            offset_unit: 2048,
            trailing_zero_trim: true,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 16,
        };
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
        const SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 0,
            count_adjust: -2,
            entry_width: IntWidth::U32,
            endian: Endian::Little,
            offset_base: OffsetBase::TableEnd,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 16,
        };
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

        let strict_spec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 2,
            count_adjust: 0,
            entry_width: IntWidth::U32,
            endian: Endian::Little,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 8,
        };
        assert_eq!(
            parse_counted_offset_array(&data, &strict_spec),
            Err(LayoutError::NonMonotonic {
                index: 1,
                previous: 12,
                current: 8,
            })
        );

        let relaxed_spec = CountedOffsetArraySpec {
            require_monotonic: false,
            ..strict_spec
        };
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
        let bad_adjust = CountedOffsetArraySpec {
            array_offset: 0,
            count: 1,
            count_adjust: -2,
            entry_width: IntWidth::U32,
            endian: Endian::Little,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 8,
        };
        assert_eq!(
            parse_counted_offset_array(&[0u8; 8], &bad_adjust),
            Err(LayoutError::InvalidCount {
                count: 1,
                adjust: -2,
            })
        );

        let oob_spec = CountedOffsetArraySpec {
            count_adjust: 0,
            ..bad_adjust
        };
        let mut oob = Vec::new();
        oob.extend_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            parse_counted_offset_array(&oob, &oob_spec),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));

        let ov_spec = CountedOffsetArraySpec {
            offset_unit: u64::MAX,
            ..oob_spec
        };
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
        const SENTINEL_SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 4,
            count: 0,
            count_adjust: 1,
            entry_width: IntWidth::U32,
            endian: Endian::Little,
            offset_base: OffsetBase::TableEnd,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: true,
            require_monotonic: true,
            max_entries: 16,
        };
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
        const SECTOR_SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 2,
            count_adjust: 0,
            entry_width: IntWidth::U24,
            endian: Endian::Big,
            offset_base: OffsetBase::Absolute,
            offset_unit: 2048,
            trailing_zero_trim: false,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 16,
        };
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
        const U64_SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 8,
            count: 2,
            count_adjust: 0,
            entry_width: IntWidth::U64,
            endian: Endian::Big,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 16,
        };
        let policy = PackPolicy {
            data_alignment: 8,
            pad_byte: 0xAA,
            record_fill_byte: 0,
            pad_final_entry: true,
            prefix_fill_byte: 0x55,
        };
        let u64_packed =
            pack_counted_offset_array(&U64_SPEC, &policy, b"HEAD", &[b"123", b"4567"]).unwrap();
        assert_eq!(&u64_packed[0..4], b"HEAD");
        assert_eq!(&u64_packed[4..8], &[0x55; 4]);
        assert_eq!(u64_packed.len() % 8, 0);
        let u64_spans = parse_counted_offset_array(&u64_packed, &U64_SPEC).unwrap();
        assert_eq!(u64_spans[0].offset % 8, 0);
        assert_eq!(u64_spans[1].offset % 8, 0);

        // 4. U8 width out-of-range rejection
        const U8_SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 2,
            count_adjust: 0,
            entry_width: IntWidth::U8,
            endian: Endian::Little,
            offset_base: OffsetBase::Absolute,
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: false,
            require_monotonic: true,
            max_entries: 16,
        };
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
        const BUS_SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 2,
            count_adjust: 1,
            entry_width: IntWidth::U32,
            endian: Endian::Little,
            offset_base: OffsetBase::SubtractBase(0x0800_0000),
            offset_unit: 1,
            trailing_zero_trim: false,
            has_eof_sentinel: true,
            require_monotonic: true,
            max_entries: 16,
        };
        let packed =
            pack_counted_offset_array(&BUS_SPEC, &PackPolicy::TIGHT, &[], &[b"ABCD", b"EF"])
                .unwrap();
        // Raw first offset must equal 0x0800_0000 + 12 (3 u32s)
        assert_eq!(
            u32::from_le_bytes(packed[0..4].try_into().unwrap()),
            0x0800_000C
        );
        let spans = parse_counted_offset_array(&packed, &BUS_SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].slice(&packed), Some(&b"ABCD"[..]));
        assert_eq!(spans[1].slice(&packed), Some(&b"EF"[..]));

        // Underflow when raw address < base
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
}
