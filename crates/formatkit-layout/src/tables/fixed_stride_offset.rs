//! Fixed-stride offset tables producing validated [`NamespaceEntry`] rows.

use formatkit_core::{u32_at, Error, NamespaceEntry, Result};

/// How each entry's byte size is determined in a [`FixedStrideOffsetTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableSizeMode {
    /// Each entry carries an explicit little-endian `u32` size field at
    /// `field_offset` bytes within the entry, scaled by `unit`.
    ExplicitU32 {
        /// Byte offset of the little-endian `u32` size field within each entry.
        field_offset: usize,
        /// Non-zero byte multiplier applied to each decoded size value.
        unit: u64,
    },
    /// Entry sizes are derived from consecutive non-decreasing offsets:
    /// entry `i` spans `[offset[i], offset[i + 1])`, and the final entry spans
    /// `[offset[n - 1], end)` where `end` is `sentinel_end.unwrap_or(data_size)`.
    SequentialUntil {
        /// Optional explicit terminal offset for the final entry. Defaults to
        /// `data_size` when `None`.
        sentinel_end: Option<u64>,
    },
}

/// Configured descriptor for a fixed-stride table of little-endian `u32`
/// offsets that maps directly to [`NamespaceEntry`] rows.
///
/// The descriptor owns record placement, unit scaling, bounds checking,
/// overflow checking, and sequential monotonicity validation. Format identity,
/// header framing, and semantic policies remain with the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedStrideOffsetTable {
    /// Number of entries in the table.
    pub entry_count: usize,
    /// Stride in bytes of each table entry (must be at least 4).
    pub entry_stride: usize,
    /// Byte offset of the little-endian `u32` offset field within each entry.
    pub offset_field: usize,
    /// Non-zero byte multiplier applied to each decoded offset value.
    pub offset_unit: u64,
    /// Rule used to compute each entry's byte size.
    pub size_mode: TableSizeMode,
    /// Prefix for synthesized entry names. When empty, entries have `name: None`.
    /// When non-empty, names are formatted as `"{prefix}_{index:04}"` (or
    /// `"{prefix}{index:04}"` if `prefix` already ends with `_`, `-`, or `/`).
    pub name_prefix: &'static str,
}

impl FixedStrideOffsetTable {
    /// Parse `table_bytes` into validated [`NamespaceEntry`] rows bounded by
    /// `data_size`.
    ///
    /// Rejects invalid descriptor parameters, truncated table bytes, arithmetic
    /// overflows, out-of-bounds entry ranges, and (in
    /// [`TableSizeMode::SequentialUntil`] mode) non-monotonic offsets.
    pub fn parse_entries(&self, table_bytes: &[u8], data_size: u64) -> Result<Vec<NamespaceEntry>> {
        self.validate_descriptor(data_size)?;

        let required_bytes = self
            .entry_count
            .checked_mul(self.entry_stride)
            .ok_or_else(|| Error::Malformed("offset table byte length overflow".into()))?;
        if table_bytes.len() < required_bytes {
            return Err(Error::Truncated {
                offset: 0,
                needed: required_bytes,
                available: table_bytes.len(),
            });
        }

        if self.entry_count == 0 {
            return Ok(Vec::new());
        }

        match self.size_mode {
            TableSizeMode::ExplicitU32 { field_offset, unit } => {
                self.parse_explicit(table_bytes, data_size, field_offset, unit)
            }
            TableSizeMode::SequentialUntil { sentinel_end } => {
                self.parse_sequential(table_bytes, data_size, sentinel_end.unwrap_or(data_size))
            }
        }
    }

    fn validate_descriptor(&self, data_size: u64) -> Result<()> {
        if self.entry_stride < 4 {
            return Err(Error::InvalidField {
                what: "entry_stride",
                value: self.entry_stride as u64,
            });
        }
        let offset_end = self
            .offset_field
            .checked_add(4)
            .ok_or(Error::InvalidField {
                what: "offset_field",
                value: self.offset_field as u64,
            })?;
        if offset_end > self.entry_stride {
            return Err(Error::InvalidField {
                what: "offset_field",
                value: self.offset_field as u64,
            });
        }
        if self.offset_unit == 0 {
            return Err(Error::InvalidField {
                what: "offset_unit",
                value: 0,
            });
        }
        match self.size_mode {
            TableSizeMode::ExplicitU32 { field_offset, unit } => {
                let size_end = field_offset.checked_add(4).ok_or(Error::InvalidField {
                    what: "size_field",
                    value: field_offset as u64,
                })?;
                if size_end > self.entry_stride {
                    return Err(Error::InvalidField {
                        what: "size_field",
                        value: field_offset as u64,
                    });
                }
                if unit == 0 {
                    return Err(Error::InvalidField {
                        what: "size_unit",
                        value: 0,
                    });
                }
            }
            TableSizeMode::SequentialUntil {
                sentinel_end: Some(end),
            } => {
                if end > data_size {
                    return Err(Error::SourceRangeOutside {
                        offset: 0,
                        length: end,
                        source_size: data_size,
                    });
                }
            }
            TableSizeMode::SequentialUntil { sentinel_end: None } => {}
        }
        Ok(())
    }

    fn format_name(&self, index: usize) -> Option<String> {
        if self.name_prefix.is_empty() {
            None
        } else if self.name_prefix.ends_with(['_', '-', '/']) {
            Some(format!("{}{index:04}", self.name_prefix))
        } else {
            Some(format!("{}_{index:04}", self.name_prefix))
        }
    }

    fn parse_explicit(
        &self,
        table_bytes: &[u8],
        data_size: u64,
        field_offset: usize,
        unit: u64,
    ) -> Result<Vec<NamespaceEntry>> {
        let mut entries = Vec::with_capacity(self.entry_count);
        for index in 0..self.entry_count {
            let row_start = index * self.entry_stride;
            let row = &table_bytes[row_start..row_start + self.entry_stride];
            let raw_offset = u32_at(row, self.offset_field)?;
            let offset = u64::from(raw_offset)
                .checked_mul(self.offset_unit)
                .ok_or_else(|| {
                    Error::Malformed(format!("entry {index} offset scaling overflow"))
                })?;
            let raw_size = u32_at(row, field_offset)?;
            let size = u64::from(raw_size)
                .checked_mul(unit)
                .ok_or_else(|| Error::Malformed(format!("entry {index} size scaling overflow")))?;
            let end = offset
                .checked_add(size)
                .ok_or_else(|| Error::Malformed(format!("entry {index} offset + size overflow")))?;
            if end > data_size {
                return Err(Error::SourceRangeOutside {
                    offset,
                    length: size,
                    source_size: data_size,
                });
            }
            entries.push(NamespaceEntry {
                name: self.format_name(index),
                offset,
                size,
            });
        }
        Ok(entries)
    }

    fn parse_sequential(
        &self,
        table_bytes: &[u8],
        data_size: u64,
        end_bound: u64,
    ) -> Result<Vec<NamespaceEntry>> {
        let mut offsets = Vec::with_capacity(self.entry_count);
        for index in 0..self.entry_count {
            let row_start = index * self.entry_stride;
            let row = &table_bytes[row_start..row_start + self.entry_stride];
            let raw_offset = u32_at(row, self.offset_field)?;
            let offset = u64::from(raw_offset)
                .checked_mul(self.offset_unit)
                .ok_or_else(|| {
                    Error::Malformed(format!("entry {index} offset scaling overflow"))
                })?;
            if offset > end_bound {
                return Err(Error::SourceRangeOutside {
                    offset,
                    length: 0,
                    source_size: data_size,
                });
            }
            if let Some(&prev) = offsets.last() {
                if offset < prev {
                    return Err(Error::Malformed(format!(
                        "non-monotonic offset at entry {index}: {offset:#x} < {prev:#x}"
                    )));
                }
            }
            offsets.push(offset);
        }

        let mut entries = Vec::with_capacity(self.entry_count);
        for (index, &offset) in offsets.iter().enumerate() {
            let next = offsets.get(index + 1).copied().unwrap_or(end_bound);
            entries.push(NamespaceEntry {
                name: self.format_name(index),
                offset,
                size: next - offset,
            });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_u32_rows(rows: &[&[u32]]) -> Vec<u8> {
        let mut out = Vec::new();
        for row in rows {
            for &word in *row {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
        out
    }

    #[test]
    fn parses_explicit_u32_table_with_scaling_and_names() {
        let table_bytes = encode_u32_rows(&[&[1, 2, 0], &[3, 4, 0]]);
        let table = FixedStrideOffsetTable {
            entry_count: 2,
            entry_stride: 12,
            offset_field: 0,
            offset_unit: 2048,
            size_mode: TableSizeMode::ExplicitU32 {
                field_offset: 4,
                unit: 512,
            },
            name_prefix: "entry",
        };
        let entries = table.parse_entries(&table_bytes, 16384).unwrap();
        assert_eq!(
            entries,
            vec![
                NamespaceEntry {
                    name: Some("entry_0000".into()),
                    offset: 2048,
                    size: 1024,
                },
                NamespaceEntry {
                    name: Some("entry_0001".into()),
                    offset: 6144,
                    size: 2048,
                },
            ]
        );
    }

    #[test]
    fn parses_sequential_until_data_size_and_sentinel() {
        let table_bytes = encode_u32_rows(&[&[16], &[64], &[64], &[128]]);
        let table = FixedStrideOffsetTable {
            entry_count: 4,
            entry_stride: 4,
            offset_field: 0,
            offset_unit: 1,
            size_mode: TableSizeMode::SequentialUntil { sentinel_end: None },
            name_prefix: "",
        };
        let entries = table.parse_entries(&table_bytes, 256).unwrap();
        assert_eq!(
            entries,
            vec![
                NamespaceEntry {
                    name: None,
                    offset: 16,
                    size: 48,
                },
                NamespaceEntry {
                    name: None,
                    offset: 64,
                    size: 0,
                },
                NamespaceEntry {
                    name: None,
                    offset: 64,
                    size: 64,
                },
                NamespaceEntry {
                    name: None,
                    offset: 128,
                    size: 128,
                },
            ]
        );

        let bounded = FixedStrideOffsetTable {
            size_mode: TableSizeMode::SequentialUntil {
                sentinel_end: Some(192),
            },
            name_prefix: "item_",
            ..table
        };
        let bounded_entries = bounded.parse_entries(&table_bytes, 256).unwrap();
        assert_eq!(bounded_entries[3].size, 64);
        assert_eq!(bounded_entries[3].name.as_deref(), Some("item_0003"));
    }

    #[test]
    fn rejects_non_monotonic_sequential_offsets() {
        let table_bytes = encode_u32_rows(&[&[100], &[80]]);
        let table = FixedStrideOffsetTable {
            entry_count: 2,
            entry_stride: 4,
            offset_field: 0,
            offset_unit: 1,
            size_mode: TableSizeMode::SequentialUntil { sentinel_end: None },
            name_prefix: "row",
        };
        let err = table.parse_entries(&table_bytes, 512).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn rejects_out_of_bounds_and_overflow_and_truncation() {
        // Explicit range exceeding data_size.
        let oob_bytes = encode_u32_rows(&[&[100, 50]]);
        let explicit = FixedStrideOffsetTable {
            entry_count: 1,
            entry_stride: 8,
            offset_field: 0,
            offset_unit: 1,
            size_mode: TableSizeMode::ExplicitU32 {
                field_offset: 4,
                unit: 1,
            },
            name_prefix: "x",
        };
        assert!(matches!(
            explicit.parse_entries(&oob_bytes, 149),
            Err(Error::SourceRangeOutside { .. })
        ));

        // Offset scaling overflow.
        let overflow_bytes = encode_u32_rows(&[&[u32::MAX, 1]]);
        let scaled = FixedStrideOffsetTable {
            offset_unit: u64::MAX / 2,
            ..explicit
        };
        assert!(matches!(
            scaled.parse_entries(&overflow_bytes, u64::MAX),
            Err(Error::Malformed(_))
        ));

        // Truncated table.
        assert!(matches!(
            explicit.parse_entries(&oob_bytes[..4], 1024),
            Err(Error::Truncated {
                offset: 0,
                needed: 8,
                available: 4
            })
        ));

        // Sentinel beyond data_size.
        let seq = FixedStrideOffsetTable {
            entry_count: 1,
            entry_stride: 4,
            offset_field: 0,
            offset_unit: 1,
            size_mode: TableSizeMode::SequentialUntil {
                sentinel_end: Some(500),
            },
            name_prefix: "",
        };
        assert!(matches!(
            seq.parse_entries(&encode_u32_rows(&[&[0]]), 400),
            Err(Error::SourceRangeOutside { .. })
        ));
    }

    #[test]
    fn rejects_invalid_descriptors_and_handles_empty_table() {
        let base = FixedStrideOffsetTable {
            entry_count: 0,
            entry_stride: 8,
            offset_field: 0,
            offset_unit: 1,
            size_mode: TableSizeMode::ExplicitU32 {
                field_offset: 4,
                unit: 1,
            },
            name_prefix: "empty",
        };
        assert_eq!(base.parse_entries(&[], 0).unwrap(), Vec::new());

        let bad_stride = FixedStrideOffsetTable {
            entry_stride: 2,
            ..base
        };
        assert!(matches!(
            bad_stride.parse_entries(&[], 0),
            Err(Error::InvalidField {
                what: "entry_stride",
                ..
            })
        ));

        let bad_unit = FixedStrideOffsetTable {
            offset_unit: 0,
            ..base
        };
        assert!(matches!(
            bad_unit.parse_entries(&[], 0),
            Err(Error::InvalidField {
                what: "offset_unit",
                ..
            })
        ));

        let bad_size_field = FixedStrideOffsetTable {
            size_mode: TableSizeMode::ExplicitU32 {
                field_offset: 6,
                unit: 1,
            },
            ..base
        };
        assert!(matches!(
            bad_size_field.parse_entries(&[], 0),
            Err(Error::InvalidField {
                what: "size_field",
                ..
            })
        ));
    }
}
