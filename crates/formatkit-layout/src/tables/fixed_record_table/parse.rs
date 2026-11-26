//! Checked zero-allocation iterator and parsers for fixed-stride record tables.

use crate::spec::{checked_align_up_multiple_u64, IntFieldSpec, LayoutError};

use super::spec::{
    is_skipped_row, matches_termination_sentinel, resolve_scaled_offset, validate_spec,
    FixedRecordEntry, FixedRecordTableSpec, FixedRecordView, SizeMode, TableParseOptions,
    TableTermination,
};

type NextRecord<'a> = (usize, usize, &'a [u8]);

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
        resolve_scaled_offset(
            &self.spec,
            record,
            record_offset,
            field,
            self.table_end,
            "scaled_offset",
        )
    }

    fn next_non_skipped_record(
        &self,
        start_index: usize,
    ) -> Result<Option<NextRecord<'a>>, LayoutError> {
        let mut idx = start_index;
        while idx < self.raw_count {
            let (rec_off, rec) = self.record_slice(idx)?;
            if is_skipped_row(&self.spec, rec)? {
                idx += 1;
                continue;
            }
            return Ok(Some((idx, rec_off, rec)));
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
                let next_offset = if let Some((next_idx, next_rec_off, next_rec)) =
                    self.next_non_skipped_record(index + 1)?
                {
                    let next = self.resolve_record_offset(next_rec, next_rec_off, offset_field)?;
                    if next < offset {
                        return Err(LayoutError::NonMonotonic {
                            index: next_idx,
                            previous: offset,
                            current: next,
                        });
                    }
                    next
                } else {
                    if self.next_offset_terminal < offset {
                        return Err(LayoutError::NonMonotonic {
                            index: self.raw_count,
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
            SizeMode::Cumulative { start: _, align } => {
                let size_field = self.spec.offset_field.ok_or(LayoutError::InvalidSpec {
                    field: "offset_field",
                    reason: "required as size source for SizeMode::Cumulative",
                })?;
                let raw_size = size_field.read(record)?;
                let size =
                    raw_size
                        .checked_mul(self.spec.size_unit)
                        .ok_or(LayoutError::Overflow {
                            what: "cumulative_size",
                        })?;
                let offset = self.cumulative_cursor;
                let step = if align <= 1 {
                    size
                } else {
                    checked_align_up_multiple_u64(size, align).ok_or(LayoutError::Overflow {
                        what: "cumulative_aligned_step",
                    })?
                };
                let next_cursor = offset.checked_add(step).ok_or(LayoutError::Overflow {
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
            if self.spec.skip_empty_zero || self.spec.skip_predicate.is_some() {
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

impl FixedRecordTableSpec {
    /// Create a checked, zero-allocation iterator over `data` using runtime [`TableParseOptions`].
    pub fn iter_with<'a>(
        &self,
        data: &'a [u8],
        opts: TableParseOptions<'a>,
    ) -> Result<FixedRecordTableIter<'a>, LayoutError> {
        let mut effective_spec = *self;
        if let Some(count) = opts.count {
            effective_spec.termination = TableTermination::Counted(count);
        }
        if let Some(table_offset) = opts.table_offset {
            effective_spec.table_offset = table_offset;
        }
        let max_entries = opts.max_entries.unwrap_or(effective_spec.max_entries);
        let carrier_len = opts.carrier_len.unwrap_or(data.len() as u64);
        let name_pool_data = opts.name_pool.unwrap_or(data);
        iter_fixed_record_table_inner(
            data,
            name_pool_data,
            &effective_spec,
            max_entries,
            carrier_len,
        )
    }

    /// Parse all entries from `data` using runtime [`TableParseOptions`].
    pub fn parse_with<'a>(
        &self,
        data: &'a [u8],
        opts: TableParseOptions<'a>,
    ) -> Result<Vec<FixedRecordEntry>, LayoutError> {
        collect_entries(self.iter_with(data, opts)?)
    }
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
        | TableTermination::FieldNotEquals { .. }
        | TableTermination::FieldIn { .. } => {
            let mut pos = spec.table_offset;
            let mut count = 0usize;
            let mut sentinel_off = None;
            while let Some(end) = pos.checked_add(spec.stride) {
                if end > table_data.len() {
                    break;
                }
                let row = &table_data[pos..end];
                if matches_termination_sentinel(spec.termination, row)? {
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
            let first_offset = resolve_scaled_offset(
                spec,
                first_rec,
                spec.table_offset,
                offset_field,
                0,
                "first_offset",
            )?;
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

    let active_count = if spec.skip_empty_zero || spec.skip_predicate.is_some() {
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
            let end_off = resolve_scaled_offset(
                spec,
                sentinel_rec,
                sent_off,
                offset_field,
                table_end,
                "scaled_offset",
            )?;
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
        SizeMode::Cumulative { start, .. } => {
            start.apply(0, table_start, table_end, spec.table_offset)?
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

/// Create a checked, zero-allocation iterator over a fixed-stride record table.
pub fn iter_fixed_record_table<'a>(
    data: &'a [u8],
    spec: &FixedRecordTableSpec,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    spec.iter_with(data, TableParseOptions::new())
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`,
/// validating payload ranges against a full `carrier_len` without loading the carrier into RAM.
pub fn iter_fixed_record_table_metadata<'a>(
    table_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    spec.iter_with(
        table_data,
        TableParseOptions::new().with_carrier_len(carrier_len),
    )
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`
/// with a separate `name_pool_data` slice and external `carrier_len`.
pub fn iter_fixed_record_table_with_name_pool<'a>(
    table_data: &'a [u8],
    name_pool_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    spec.iter_with(
        table_data,
        TableParseOptions::new()
            .with_name_pool(name_pool_data)
            .with_carrier_len(carrier_len),
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
    spec.iter_with(data, TableParseOptions::new().with_count(count))
}

/// Create a checked, zero-allocation iterator over staged directory bytes `table_data`
/// with a runtime `count` and external `carrier_len`.
pub fn iter_fixed_record_table_counted_metadata<'a>(
    table_data: &'a [u8],
    spec: &FixedRecordTableSpec,
    count: usize,
    carrier_len: u64,
) -> Result<FixedRecordTableIter<'a>, LayoutError> {
    spec.iter_with(
        table_data,
        TableParseOptions::new()
            .with_count(count)
            .with_carrier_len(carrier_len),
    )
}

/// Parse a fixed-stride record table according to `spec`, validating every
/// `(offset, size)` range against `data.len()` with checked arithmetic.
pub fn parse_fixed_record_table(
    data: &[u8],
    spec: &FixedRecordTableSpec,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    spec.parse_with(data, TableParseOptions::new())
}

/// Parse a fixed-stride record table with an explicit caller entry bound
/// (enforcing `min(spec.max_entries, max_entries)`).
pub fn parse_fixed_record_table_bounded(
    data: &[u8],
    spec: &FixedRecordTableSpec,
    max_entries: usize,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    spec.parse_with(data, TableParseOptions::new().with_max_entries(max_entries))
}

/// Parse staged directory bytes `table_data` against an external `carrier_len`
/// without loading the entire carrier into memory.
pub fn parse_fixed_record_table_metadata(
    table_data: &[u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    spec.parse_with(
        table_data,
        TableParseOptions::new().with_carrier_len(carrier_len),
    )
}

/// Parse staged directory bytes `table_data` using a separate `name_pool_data` slice
/// and external `carrier_len`.
pub fn parse_fixed_record_table_with_name_pool(
    table_data: &[u8],
    name_pool_data: &[u8],
    spec: &FixedRecordTableSpec,
    carrier_len: u64,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    spec.parse_with(
        table_data,
        TableParseOptions::new()
            .with_name_pool(name_pool_data)
            .with_carrier_len(carrier_len),
    )
}

/// Parse a fixed-stride record table using a runtime `count`, without copying
/// a `const` [`FixedRecordTableSpec`] to patch [`TableTermination::Counted`].
pub fn parse_fixed_record_table_counted(
    data: &[u8],
    spec: &FixedRecordTableSpec,
    count: usize,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    spec.parse_with(data, TableParseOptions::new().with_count(count))
}

/// Parse staged directory bytes `table_data` using a runtime `count` and an
/// external `carrier_len`.
pub fn parse_fixed_record_table_counted_metadata(
    table_data: &[u8],
    spec: &FixedRecordTableSpec,
    count: usize,
    carrier_len: u64,
) -> Result<Vec<FixedRecordEntry>, LayoutError> {
    spec.parse_with(
        table_data,
        TableParseOptions::new()
            .with_count(count)
            .with_carrier_len(carrier_len),
    )
}
