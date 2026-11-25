//! Declarative counted offset/boundary array specification and checked parser.
//!
//! [`CountedOffsetArraySpec`] generalizes counted offset arrays (`u16`/`u24`/`u32`,
//! LE or BE, with signed count adjustment, optional trailing-zero trimming,
//! optional EOF sentinel, offset base/unit scaling, and monotonicity policy)
//! into a single `const`-constructible descriptor.

use formatkit_core::Endian;

use crate::spec::{read_int_at, IntWidth, LayoutError, OffsetBase};

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
    /// Bit width of each offset entry (`U16`, `U24`, or `U32`).
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
    if spec.offset_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "offset_unit",
            reason: "must be nonzero",
        });
    }

    let adjusted_i128 = (spec.count as i128) + i128::from(spec.count_adjust);
    if adjusted_i128 < 0 {
        return Err(LayoutError::InvalidCount {
            count: spec.count,
            adjust: spec.count_adjust,
        });
    }
    let effective_count =
        usize::try_from(adjusted_i128).map_err(|_| LayoutError::InvalidCount {
            count: spec.count,
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
    if array_end > data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.array_offset,
            needed: array_bytes,
            available: data.len().saturating_sub(spec.array_offset),
        });
    }

    let mut raw = Vec::new();
    raw.try_reserve_exact(effective_count)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: effective_count,
        })?;
    for index in 0..effective_count {
        let pos = spec.array_offset + index * elem_bytes;
        raw.push(read_int_at(data, pos, spec.entry_width, spec.endian)?);
    }

    if spec.trailing_zero_trim {
        while raw.last().copied() == Some(0) {
            raw.pop();
        }
    }

    let data_len = data.len() as u64;
    let table_end = array_end as u64;
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(raw.len())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: raw.len(),
        })?;
    for (index, raw_val) in raw.into_iter().enumerate() {
        let scaled = raw_val
            .checked_mul(spec.offset_unit)
            .ok_or(LayoutError::Overflow {
                what: "scaled_offset",
            })?;
        let record_offset = spec.array_offset + index * elem_bytes;
        let base = spec.offset_base.resolve(table_end, record_offset);
        let offset = base
            .checked_add(scaled)
            .ok_or(LayoutError::Overflow { what: "offset" })?;
        if offset > data_len {
            return Err(LayoutError::OutOfBounds {
                index,
                offset,
                size: 0,
                data_len,
            });
        }
        resolved.push(offset);
    }

    if spec.require_monotonic {
        for index in 1..resolved.len() {
            if resolved[index] < resolved[index - 1] {
                return Err(LayoutError::NonMonotonic {
                    index,
                    previous: resolved[index - 1],
                    current: resolved[index],
                });
            }
        }
    }

    let (starts, terminal) = if spec.has_eof_sentinel {
        let Some((&last, prefix)) = resolved.split_last() else {
            return Ok(Vec::new());
        };
        (prefix, last)
    } else {
        (resolved.as_slice(), data_len)
    };

    if starts.is_empty() {
        return Ok(Vec::new());
    }

    if spec.require_monotonic {
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(starts.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: starts.len(),
            })?;
        for (index, &offset) in starts.iter().enumerate() {
            let next = starts.get(index + 1).copied().unwrap_or(terminal);
            // Monotonicity guarantees next >= offset and next <= data_len.
            spans.push(OffsetSpan {
                index,
                offset,
                size: next - offset,
            });
        }
        Ok(spans)
    } else {
        // Unsorted offsets: derive each entry's end from the next physical offset
        // in sorted order (bounded by `terminal`), then return in original order.
        for (index, &offset) in starts.iter().enumerate() {
            if offset > terminal {
                return Err(LayoutError::OutOfBounds {
                    index,
                    offset,
                    size: 0,
                    data_len: terminal,
                });
            }
        }
        let mut order: Vec<(u64, usize)> = Vec::new();
        order
            .try_reserve_exact(starts.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: starts.len(),
            })?;
        for (index, &offset) in starts.iter().enumerate() {
            order.push((offset, index));
        }
        order.sort_unstable();

        let mut spans = vec![
            OffsetSpan {
                index: 0,
                offset: 0,
                size: 0,
            };
            starts.len()
        ];
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
        data.extend_from_slice(&2u32.to_le_bytes()); // owner header
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
    fn parses_u16_be_sector_scaled_with_trailing_zero_trim() {
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
        let mut data = vec![0u8; 2048 * 3];
        data[0..2].copy_from_slice(&1u16.to_be_bytes());
        data[2..4].copy_from_slice(&2u16.to_be_bytes());
        data[4..6].copy_from_slice(&0u16.to_be_bytes());
        data[6..8].copy_from_slice(&0u16.to_be_bytes());

        let spans = parse_counted_offset_array(&data, &SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].offset, 2048);
        assert_eq!(spans[0].size, 2048);
        assert_eq!(spans[1].offset, 4096);
        assert_eq!(spans[1].size, 2048);
    }

    #[test]
    fn parses_negative_count_adjust_and_table_end_base() {
        const SPEC: CountedOffsetArraySpec = CountedOffsetArraySpec {
            array_offset: 0,
            count: 4,
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

        let spans = parse_counted_offset_array(&data, &SPEC).unwrap();
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
}
