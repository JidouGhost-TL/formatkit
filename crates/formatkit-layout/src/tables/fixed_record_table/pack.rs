//! Symmetric checked serializer for fixed-stride record tables.

use crate::spec::{
    align_payload_offset, checked_align_up_multiple_u64, LayoutError, OffsetBase, PackPolicy,
};

use super::spec::{
    is_empty_zero_row, matches_termination_sentinel, validate_spec, FixedRecordInput,
    FixedRecordTableSpec, SizeMode, TableTermination,
};

#[allow(clippy::too_many_arguments)]
fn plan_offset(
    spec: &FixedRecordTableSpec,
    policy: &PackPolicy,
    index: usize,
    cursor: u64,
    table_start_u64: u64,
    table_end_u64: u64,
    record_offset: usize,
) -> Result<(u64, u64), LayoutError> {
    if index == 0 && matches!(spec.termination, TableTermination::FirstOffsetDerived) {
        let raw = spec.offset_base.encode_exact(
            table_end_u64,
            table_start_u64,
            table_end_u64,
            record_offset,
            spec.offset_unit,
            index,
            "table_end cannot be encoded for FirstOffsetDerived",
        )?;
        Ok((table_end_u64, raw))
    } else {
        spec.offset_base.align_and_encode(
            cursor,
            table_start_u64,
            table_end_u64,
            record_offset,
            policy.data_alignment,
            spec.offset_unit,
        )
    }
}

/// Serialize `entries` into a binary carrier conforming to `spec` and `policy`.
///
/// The resulting buffer begins with `header_prefix` (padded with
/// [`PackPolicy::prefix_fill_byte`] up to [`FixedRecordTableSpec::table_offset`]),
/// followed by the fixed-stride record table (plus any sentinel row required by
/// [`TableTermination::ZeroRow`], [`TableTermination::FirstByteZero`],
/// [`TableTermination::FieldEquals`], or [`TableTermination::FieldNotEquals`]),
/// an optional string pool when [`FixedRecordTableSpec::name_pool`]
/// is configured, and then the aligned payloads.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     pack_fixed_record_table, parse_fixed_record_table_counted, FixedRecordInput,
///     FixedRecordTableSpec, IntFieldSpec, PackPolicy, SizeMode, TableTermination,
/// };
///
/// const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
///     8,
///     0,
///     16,
///     Some(IntFieldSpec::u32_le(0)),
///     SizeMode::Stored(IntFieldSpec::u32_le(4)),
///     TableTermination::Counted(0),
/// );
///
/// let inputs = [
///     FixedRecordInput { name: None, key: None, payload: b"abc", record_template: None },
///     FixedRecordInput { name: None, key: None, payload: b"WXYZ", record_template: None },
/// ];
/// let policy = PackPolicy::TIGHT.with_data_alignment(8);
/// let packed = pack_fixed_record_table(&SPEC, &policy, &[], &inputs).unwrap();
/// let entries = parse_fixed_record_table_counted(&packed, &SPEC, inputs.len()).unwrap();
/// assert_eq!(entries[0].offset, 16);
/// assert_eq!(entries[1].offset, 24);
/// assert_eq!(entries[1].payload(&packed), Some(&b"WXYZ"[..]));
/// ```
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

    // Optional string pool planning
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
            pool.append_encoded(&mut pool_buf, name_bytes, index)?;
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
    if !pool_buf.is_empty() && matches!(spec.termination, TableTermination::Eof) {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "TableTermination::Eof cannot pack non-empty name_pool",
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
        SizeMode::Cumulative { start, .. } => {
            let resolved = start.apply(0, table_start_u64, table_end_u64, spec.table_offset)?;
            if resolved < min_data_start {
                return Err(LayoutError::InvalidSpec {
                    field: "size_mode",
                    reason:
                        "cumulative start offset overlaps record table, post_table, or string pool",
                });
            }
            resolved
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
                let (offset_u64, raw_offset) = plan_offset(
                    spec,
                    policy,
                    index,
                    cursor,
                    table_start_u64,
                    table_end_u64,
                    record_offset,
                )?;
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
                let (offset_u64, raw_offset) = plan_offset(
                    spec,
                    policy,
                    index,
                    cursor,
                    table_start_u64,
                    table_end_u64,
                    record_offset,
                )?;
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
            SizeMode::Cumulative { start: _, align } => {
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
                let step = if align > 1 && (index + 1 < entries.len() || policy.pad_final_entry) {
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
                let (offset_u64, raw_offset) = plan_offset(
                    spec,
                    policy,
                    index,
                    cursor,
                    table_start_u64,
                    table_end_u64,
                    record_offset,
                )?;
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
                    let (off, raw) = plan_offset(
                        spec,
                        policy,
                        index,
                        cursor,
                        table_start_u64,
                        table_end_u64,
                        record_offset,
                    )?;
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

    if matches!(spec.termination, TableTermination::Eof) && cursor > table_end_u64 {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "TableTermination::Eof cannot place data past table_end",
        });
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

        if matches_termination_sentinel(spec.termination, rec)? {
            let reason = match spec.termination {
                TableTermination::ZeroRow => {
                    "encoded record is all-zero under TableTermination::ZeroRow"
                }
                TableTermination::FirstByteZero => {
                    "encoded record starts with 0x00 under TableTermination::FirstByteZero"
                }
                TableTermination::FieldEquals { .. } => {
                    "encoded record matches TableTermination::FieldEquals sentinel"
                }
                TableTermination::FieldNotEquals { .. } => {
                    "encoded record does not match TableTermination::FieldNotEquals active value"
                }
                _ => unreachable!(),
            };
            return Err(LayoutError::InvalidInput { index, reason });
        }
        if spec.skip_empty_zero && is_empty_zero_row(spec, rec)? {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "encoded record would be skipped by skip_empty_zero",
            });
        }
        if let Some(pred) = spec.skip_predicate {
            if pred.matches(rec)? {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "encoded record matches skip_predicate tombstone",
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
        if !matches_termination_sentinel(spec.termination, sentinel_rec)? {
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
