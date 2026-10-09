//! Exact, caller-buffered metadata reads over [`RangeSource`](crate::RangeSource).
//!
//! This is deliberately a small read adapter, not a parser or cache. The caller
//! owns the output buffers, source-stability cadence, metadata limits, parsing,
//! and owner error vocabulary. An optional already-authenticated source window
//! can be reused without reading or charging those bytes again.

use crate::{
    Error, ExactReadRoute, RangeSource, ResidentBuffer, Result, RevalidatedExactSliceErrorPolicy,
    WorkBudget,
};

/// One previously read source window available for exact metadata reuse.
#[derive(Debug, Clone, Copy)]
pub struct SourceMetadataWindow<'a> {
    offset: u64,
    bytes: &'a [u8],
}

impl<'a> SourceMetadataWindow<'a> {
    /// Describe bytes previously read from `offset` in the same source.
    #[must_use]
    pub const fn new(offset: u64, bytes: &'a [u8]) -> Self {
        Self { offset, bytes }
    }

    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Exact source metadata reader using caller-owned buffers and a cumulative
/// [`WorkBudget`].
pub struct SourceMetadataReader<'a, P = ()> {
    source: &'a dyn RangeSource,
    budget: &'a mut WorkBudget,
    window: Option<SourceMetadataWindow<'a>>,
    policy: P,
}

impl<'a> SourceMetadataReader<'a, ()> {
    /// Construct a reader with core error vocabulary and no reusable window.
    pub fn new(source: &'a dyn RangeSource, budget: &'a mut WorkBudget) -> Self {
        Self {
            source,
            budget,
            window: None,
            policy: (),
        }
    }
}

impl<'a, P: RevalidatedExactSliceErrorPolicy> SourceMetadataReader<'a, P> {
    /// Construct a reader retaining an owner's source-read error vocabulary.
    pub fn with_policy(source: &'a dyn RangeSource, budget: &'a mut WorkBudget, policy: P) -> Self {
        Self {
            source,
            budget,
            window: None,
            policy,
        }
    }

    /// Reuse a previously read source window. The complete window must lie in
    /// this source; malformed caller metadata is rejected before later reads.
    pub fn with_window(mut self, window: SourceMetadataWindow<'a>) -> Result<Self> {
        checked_source_range(self.source.size(), window.offset, window.bytes.len() as u64)
            .map_err(|error| self.policy.map_read_error(ExactReadRoute::Owned, error))?;
        self.window = Some(window);
        Ok(self)
    }

    /// Read one exact fixed-size metadata value without allocating.
    pub fn read_array<const N: usize>(&mut self, offset: u64) -> Result<[u8; N]> {
        let mut output = [0; N];
        self.read_exact_into(offset, &mut output)?;
        Ok(output)
    }

    /// Materialize one exact source range into capacity-accounted resident
    /// storage. Bounds and representability are validated before allocation;
    /// the returned buffer keeps its resident permit until it is dropped.
    pub fn read_resident(&mut self, offset: u64, length: u64) -> Result<ResidentBuffer> {
        checked_source_range(self.source.size(), offset, length)
            .map_err(|error| self.policy.map_read_error(ExactReadRoute::Owned, error))?;
        let length = usize::try_from(length).map_err(|_| Error::ResourceLimit {
            resource: "resident metadata bytes",
            requested: length,
            limit: usize::MAX as u64,
        })?;
        let mut output = ResidentBuffer::zeroed(self.budget, length)?;
        self.read_exact_into(offset, output.as_mut_slice())?;
        Ok(output)
    }

    /// Fill a caller-owned buffer from one exact source range.
    ///
    /// Bytes covered by the configured window are copied from it. Any prefix or
    /// suffix outside the window is read directly into the corresponding output
    /// region and charged through the supplied `WorkBudget`.
    pub fn read_exact_into(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        let length = output.len() as u64;
        let end = checked_source_range(self.source.size(), offset, length)
            .map_err(|error| self.policy.map_read_error(ExactReadRoute::Owned, error))?;
        let Some(window) = self.window else {
            return self.read_source(offset, output);
        };
        let window_end = window
            .offset
            .checked_add(window.bytes.len() as u64)
            .expect("validated metadata window end");
        let overlap_start = offset.max(window.offset);
        let overlap_end = end.min(window_end);
        if overlap_start >= overlap_end {
            return self.read_source(offset, output);
        }

        let before = usize::try_from(overlap_start - offset).expect("output-bounded prefix");
        if before != 0 {
            self.read_source(offset, &mut output[..before])?;
        }

        let window_start =
            usize::try_from(overlap_start - window.offset).expect("window-bounded start");
        let overlap_len = usize::try_from(overlap_end - overlap_start).expect("bounded overlap");
        output[before..before + overlap_len]
            .copy_from_slice(&window.bytes[window_start..window_start + overlap_len]);

        let after_start = before + overlap_len;
        if after_start != output.len() {
            self.read_source(overlap_end, &mut output[after_start..])?;
        }
        Ok(())
    }

    fn read_source(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        self.source
            .read_exact_into(offset, output, self.budget)
            .map_err(|error| self.policy.map_read_error(ExactReadRoute::Owned, error))
    }
}

fn checked_source_range(size: u64, offset: u64, length: u64) -> Result<u64> {
    let Some(end) = offset.checked_add(length) else {
        return Err(Error::SourceRangeOutside {
            offset,
            length,
            source_size: size,
        });
    };
    if end > size {
        return Err(Error::SourceRangeOutside {
            offset,
            length,
            source_size: size,
        });
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorContext, InjectedError, MemoryRangeSource, RangeSourceTestDouble, ReadFault,
        WorkLimits, WorkResource,
    };

    #[derive(Clone, Copy)]
    struct Policy;

    impl RevalidatedExactSliceErrorPolicy for Policy {
        fn map_read_error(&self, route: ExactReadRoute, error: Error) -> Error {
            assert_eq!(route, ExactReadRoute::Owned);
            error.context(ErrorContext::Component("metadata fixture"))
        }
    }

    fn budget(logical: u64) -> WorkBudget {
        WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, logical))
    }

    #[test]
    fn exact_arrays_and_caller_buffers_use_one_budget() {
        let source = MemoryRangeSource::new((0u8..32).collect::<Vec<_>>(), "metadata");
        let mut work = budget(7);
        let mut reader = SourceMetadataReader::new(&source, &mut work);
        assert_eq!(reader.read_array::<4>(3).unwrap(), [3, 4, 5, 6]);
        let mut tail = [0; 3];
        reader.read_exact_into(20, &mut tail).unwrap();
        assert_eq!(tail, [20, 21, 22]);
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 7);
    }

    #[test]
    fn a_window_reuses_full_and_partial_ranges_without_double_reads() {
        let source = MemoryRangeSource::new((0u8..32).collect::<Vec<_>>(), "metadata");
        let cached = [8, 9, 10, 11, 12, 13, 14, 15];
        let mut work = budget(4);
        let mut reader = SourceMetadataReader::new(&source, &mut work)
            .with_window(SourceMetadataWindow::new(8, &cached))
            .unwrap();

        assert_eq!(reader.read_array::<4>(10).unwrap(), [10, 11, 12, 13]);
        let mut crossing = [0; 8];
        reader.read_exact_into(6, &mut crossing).unwrap();
        assert_eq!(crossing, [6, 7, 8, 9, 10, 11, 12, 13]);
        let mut suffix = [0; 2];
        reader.read_exact_into(15, &mut suffix).unwrap();
        assert_eq!(suffix, [15, 16]);
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 3);
    }

    #[test]
    fn wide_bounds_and_owner_mapping_remain_typed() {
        let source = MemoryRangeSource::new(vec![0; 4], "metadata");
        let mut work = budget(4);
        let mut reader = SourceMetadataReader::with_policy(&source, &mut work, Policy);
        let error = reader.read_array::<4>(2).unwrap_err();
        assert!(matches!(
            error.leaf(),
            Error::SourceRangeOutside {
                offset: 2,
                length: 4,
                source_size: 4,
            }
        ));
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![&ErrorContext::Component("metadata fixture")]
        );

        let mut work = budget(0);
        let error = SourceMetadataReader::with_policy(&source, &mut work, Policy)
            .with_window(SourceMetadataWindow::new(u64::MAX, &[0, 1]))
            .err()
            .expect("overflowing window must fail");
        assert!(matches!(
            error.leaf(),
            Error::SourceRangeOutside {
                offset: u64::MAX,
                length: 2,
                source_size: 4,
            }
        ));
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![&ErrorContext::Component("metadata fixture")]
        );
    }

    #[test]
    fn resident_reads_account_storage_and_release_it_on_drop() {
        let source = MemoryRangeSource::new((0u8..16).collect::<Vec<_>>(), "metadata");
        let mut work = WorkBudget::new(
            WorkLimits::unlimited()
                .with(WorkResource::LogicalReadBytes, 5)
                .with(WorkResource::MaterializedBytes, 5)
                .with_resident_bytes(5),
        );
        let mut reader = SourceMetadataReader::new(&source, &mut work);
        let bytes = reader.read_resident(4, 5).unwrap();
        assert_eq!(bytes.as_slice(), &[4, 5, 6, 7, 8]);
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 5);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 5);
        assert_eq!(work.usage().resident_bytes(), bytes.capacity_bytes());
        drop(bytes);
        assert_eq!(work.usage().resident_bytes(), 0);
    }

    #[test]
    fn resident_reads_validate_before_allocation_and_release_on_read_failure() {
        let source = RangeSourceTestDouble::resident(vec![0; 8], "metadata").with_read_fault(
            ReadFault::Always(InjectedError::Unsupported("injected metadata read")),
        );
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let mut reader = SourceMetadataReader::new(&source, &mut work);
        assert!(matches!(
            reader.read_resident(7, 2),
            Err(Error::SourceRangeOutside { .. })
        ));
        assert_eq!(source.read_calls(), 0);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 0);
        assert_eq!(work.usage().resident_bytes(), 0);

        let mut reader = SourceMetadataReader::new(&source, &mut work);
        assert_eq!(
            reader.read_resident(2, 3).unwrap_err(),
            Error::Unsupported("injected metadata read".into())
        );
        assert_eq!(source.read_calls(), 1);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 3);
        assert_eq!(work.usage().resident_bytes(), 0);
    }

    #[test]
    fn resident_reads_reuse_windows_and_zero_length_is_well_defined() {
        let source = MemoryRangeSource::new((0u8..16).collect::<Vec<_>>(), "metadata");
        let cached = [4, 5, 6, 7];
        let mut work = WorkBudget::new(
            WorkLimits::unlimited()
                .with(WorkResource::LogicalReadBytes, 2)
                .with(WorkResource::MaterializedBytes, 6)
                .with_resident_bytes(6),
        );
        let mut reader = SourceMetadataReader::new(&source, &mut work)
            .with_window(SourceMetadataWindow::new(4, &cached))
            .unwrap();
        let bytes = reader.read_resident(3, 6).unwrap();
        assert_eq!(bytes.as_slice(), &[3, 4, 5, 6, 7, 8]);
        let empty = reader.read_resident(16, 0).unwrap();
        assert!(empty.as_slice().is_empty());
        assert_eq!(empty.capacity_bytes(), 0);
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 2);
        drop(bytes);
    }
}
