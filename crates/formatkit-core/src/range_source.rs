//! Bounded, random-access byte sources for disc-scale forensic work.
//!
//! A source is opened once, reads are charged before allocation or I/O, and
//! every range check is overflow-safe. File sources retain their descriptor
//! and can prove that both the held inode and its path still name the snapshot
//! observed at open time.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use crate::{Error, Result, WorkBudget, WorkLimits, WorkResource};

/// An immutable byte range retaining shared ownership of its backing storage.
///
/// Unlike `Vec<u8>`, taking a subrange does not copy its bytes. Sources that
/// are already resident can therefore pass nested container/member ranges
/// through an arbitrary number of readers while retaining one allocation.
#[derive(Clone)]
pub struct SharedBytes {
    storage: Arc<[u8]>,
    start: usize,
    end: usize,
}

impl std::fmt::Debug for SharedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedBytes")
            .field("range", &(self.start..self.end))
            .field("storage_len", &self.storage.len())
            .finish()
    }
}

impl SharedBytes {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let storage: Arc<[u8]> = bytes.into();
        let end = storage.len();
        Self {
            storage,
            start: 0,
            end,
        }
    }

    pub fn from_arc(storage: Arc<[u8]>) -> Self {
        let end = storage.len();
        Self {
            storage,
            start: 0,
            end,
        }
    }

    pub fn from_arc_range(storage: Arc<[u8]>, range: std::ops::Range<usize>) -> Result<Self> {
        if range.start > range.end || range.end > storage.len() {
            return Err(Error::Truncated {
                offset: range.start,
                needed: range.end.saturating_sub(range.start),
                available: storage.len().saturating_sub(range.start),
            });
        }
        Ok(Self {
            storage,
            start: range.start,
            end: range.end,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    /// Retain this view as one immutable allocation.
    ///
    /// A full-storage view is returned without copying. A proper subrange is
    /// copied because `Arc<[u8]>` cannot itself carry range bounds.
    pub fn into_arc(self) -> Arc<[u8]> {
        if self.start == 0 && self.end == self.storage.len() {
            self.storage
        } else {
            Arc::from(&self.storage[self.start..self.end])
        }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn slice(&self, range: std::ops::Range<usize>) -> Result<Self> {
        if range.start > range.end || range.end > self.len() {
            return Err(Error::Truncated {
                offset: range.start,
                needed: range.end.saturating_sub(range.start),
                available: self.len().saturating_sub(range.start),
            });
        }
        Ok(Self {
            storage: self.storage.clone(),
            start: self.start + range.start,
            end: self.start + range.end,
        })
    }

    /// Whether two views retain the same allocation.
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.storage, &other.storage)
    }
}

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::ops::Deref for SharedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl RangeSource for SharedBytes {
    fn size(&self) -> u64 {
        self.len() as u64
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        self.read_shared_at(offset, length, budget)
            .map(|bytes| bytes.as_slice().to_vec())
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        let length = checked_read(self.size(), offset, length, budget)?;
        let start = usize::try_from(offset)
            .map_err(|_| Error::Malformed("shared byte offset exceeds usize".into()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::Malformed("shared byte range overflows usize".into()))?;
        self.slice(start..end)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        CoordinateSpaceDescription::bytes("shared-range", "resident shared bytes", self.size())
    }
}

/// A half-open range in a named coordinate space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRange {
    pub start: u64,
    pub length: u64,
}

impl SourceRange {
    pub const fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    pub fn end(self) -> Result<u64> {
        self.start
            .checked_add(self.length)
            .ok_or_else(|| Error::Malformed("range end overflows u64".into()))
    }
}

/// The coordinate system used by offsets returned from a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinateSpaceDescription {
    pub kind: String,
    pub unit: String,
    pub name: String,
    pub size_units: u64,
}

impl CoordinateSpaceDescription {
    pub fn bytes(kind: impl Into<String>, name: impl Into<String>, size: u64) -> Self {
        Self {
            kind: kind.into(),
            unit: "byte".into(),
            name: name.into(),
            size_units: size,
        }
    }
}

/// Precision of a mapping from this source's logical bytes to its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingPrecision {
    ExactAffine,
    ExactTable,
    Parametric,
    CoarseDependency,
    Unknown,
}

impl MappingPrecision {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactAffine => "exact-affine",
            Self::ExactTable => "exact-table",
            Self::Parametric => "parametric",
            Self::CoarseDependency => "coarse-dependency",
            Self::Unknown => "unknown",
        }
    }
}

/// A compact, provenance-preserving coordinate translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinateMappingDescription {
    pub from: SourceRange,
    pub to_space: CoordinateSpaceDescription,
    pub to: SourceRange,
    pub kind: String,
    pub precision: MappingPrecision,
    pub recipe_identity: Option<String>,
}

/// Where a bounded materialization may be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializationPolicy {
    Memory { max_bytes: u64 },
    NewFile { path: PathBuf, max_bytes: u64 },
}

/// A materialized snapshot and the digest that verifies its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializedContent {
    Memory {
        bytes: Arc<[u8]>,
        sha256: String,
    },
    File {
        path: PathBuf,
        size: u64,
        sha256: String,
    },
}

impl MaterializedContent {
    pub fn size(&self) -> u64 {
        match self {
            Self::Memory { bytes, .. } => bytes.len() as u64,
            Self::File { size, .. } => *size,
        }
    }

    pub fn sha256(&self) -> &str {
        match self {
            Self::Memory { sha256, .. } | Self::File { sha256, .. } => sha256,
        }
    }
}

/// Per-job accounting for bytes requested from range sources.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadBudget {
    limit: Option<u64>,
    spent: u64,
    bridge_identity: Option<std::sync::Arc<()>>,
}

impl Clone for ReadBudget {
    fn clone(&self) -> Self {
        // A clone is an observational copy, never another handle to a private
        // WorkBudget compatibility bridge. Restoring it into an active bridge
        // is therefore detected at the callback boundary.
        Self {
            limit: self.limit,
            spent: self.spent,
            bridge_identity: None,
        }
    }
}

impl ReadBudget {
    pub const fn limited(limit: u64) -> Self {
        Self {
            limit: Some(limit),
            spent: 0,
            bridge_identity: None,
        }
    }

    pub const fn unlimited() -> Self {
        Self {
            limit: None,
            spent: 0,
            bridge_identity: None,
        }
    }

    pub(crate) fn bridged(limit: u64, identity: std::sync::Arc<()>) -> Self {
        Self {
            limit: Some(limit),
            spent: 0,
            bridge_identity: Some(identity),
        }
    }

    pub(crate) fn has_bridge_identity(&self, identity: &std::sync::Arc<()>) -> bool {
        self.bridge_identity
            .as_ref()
            .is_some_and(|current| std::sync::Arc::ptr_eq(current, identity))
    }

    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub const fn spent(&self) -> u64 {
        self.spent
    }

    pub fn remaining(&self) -> Option<u64> {
        self.limit.map(|limit| limit.saturating_sub(self.spent))
    }

    /// Account for bytes consumed by an adapter which had to carry an owned
    /// sub-budget across an API that cannot borrow this value directly.
    pub fn charge(&mut self, amount: u64) -> Result<()> {
        let requested = self
            .spent
            .checked_add(amount)
            .ok_or_else(|| Error::Malformed("byte-read budget overflows u64".into()))?;
        if let Some(limit) = self.limit {
            if requested > limit {
                return Err(Error::ResourceLimit {
                    resource: "range-source bytes",
                    requested,
                    limit,
                });
            }
        }
        self.spent = requested;
        Ok(())
    }

    /// Run one logical-read operation through a [`WorkBudget`] while retaining
    /// this legacy budget's cumulative accounting and diagnostics.
    ///
    /// The temporary work budget starts at zero so operation-local consumers
    /// can continue to inspect `LogicalReadBytes` as a delta. Its ceiling is
    /// this budget's remaining capacity. Admitted logical bytes are transferred
    /// back after the closure returns, including when it returns an error.
    /// Bridge-limit errors regain the legacy `range-source bytes` label and
    /// absolute `requested` / `limit` values without discarding context frames.
    /// Other work dimensions are intentionally unlimited and are not retained.
    pub fn with_logical_read_work_budget<T>(
        &mut self,
        operation: impl FnOnce(&mut WorkBudget) -> Result<T>,
    ) -> Result<T> {
        let base_spent = self.spent;
        // Even an unlimited ReadBudget is bounded by its cumulative u64
        // counter. Making that capacity explicit admits work before I/O and
        // lets the bridge restore the legacy overflow error afterward.
        let additional_limit = self
            .remaining()
            .unwrap_or_else(|| u64::MAX.saturating_sub(base_spent));
        let limits = WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, additional_limit);
        let mut work = WorkBudget::new(limits);
        let result = operation(&mut work);
        let admitted = work.spent(WorkResource::LogicalReadBytes);
        // `admitted <= additional_limit`, so this transfer cannot exceed a
        // finite parent limit or overflow an unlimited parent's counter.
        self.charge(admitted)?;
        result.map_err(|error| map_work_read_error(error, base_spent, self.limit, additional_limit))
    }
}

fn map_work_read_error(
    error: Error,
    base_spent: u64,
    legacy_limit: Option<u64>,
    bridge_limit: u64,
) -> Error {
    match error {
        Error::Context { frame, source } => Error::Context {
            frame,
            source: Box::new(map_work_read_error(
                *source,
                base_spent,
                legacy_limit,
                bridge_limit,
            )),
        },
        Error::ResourceLimit {
            resource: "logical source bytes",
            requested,
            limit,
        } if limit == bridge_limit => match (legacy_limit, base_spent.checked_add(requested)) {
            (_, None) => Error::Malformed("byte-read budget overflows u64".into()),
            (Some(limit), Some(requested)) => Error::ResourceLimit {
                resource: "range-source bytes",
                requested,
                limit,
            },
            (None, Some(_)) => Error::ResourceLimit {
                resource: "logical source bytes",
                requested,
                limit,
            },
        },
        Error::Malformed(message) if message == "logical source bytes accounting overflow" => {
            Error::Malformed("byte-read budget overflows u64".into())
        }
        error => error,
    }
}

/// One immutable random-access byte view.
pub trait RangeSource: Send + Sync {
    fn size(&self) -> u64;

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>>;

    /// Read exactly into a reusable initialized buffer. On error the buffer
    /// may be partially changed. The compatibility route allocates and cannot
    /// enforce underlying I/O limits; adopted sources override it.
    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        budget.mark_uninstrumented_io()?;
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let mut legacy = ReadBudget::limited(output.len() as u64);
        let bytes = self.read_at(offset, output.len() as u64, &mut legacy)?;
        validate_exact_read_length(
            ExactReadRoute::Owned,
            offset,
            output.len() as u64,
            bytes.len(),
        )
        .map_err(ExactReadLengthMismatch::into_default_error)?;
        output.copy_from_slice(&bytes);
        Ok(())
    }

    /// Whether [`Self::read_exact_into`] reports every underlying read attempt
    /// through the supplied [`WorkBudget`]. Sources which retain the default
    /// compatibility implementation must leave this false.
    ///
    /// This is a capability statement, not an estimate of how many calls or
    /// requested bytes one exact logical read will require.
    fn supports_complete_io_accounting(&self) -> bool {
        false
    }

    /// Read exactly while the caller owns the source-stability cadence.
    ///
    /// The caller must invoke [`Self::verify_unchanged`] before the operation
    /// and again afterward, including after a read error. The default retains
    /// the source's ordinary per-read checks. Descriptor-pinned file sources
    /// override this method to avoid reopening and restatting the pathname for
    /// every small read inside an explicitly bracketed scan.
    fn read_exact_into_assuming_unchanged(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        self.read_exact_into(offset, output, budget)
    }

    /// Read an immutable shared range. The default materializes exactly the
    /// requested bytes; resident and sliced sources override this to share
    /// their existing allocation.
    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        self.read_at(offset, length, budget)
            .map(SharedBytes::from_vec)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription;

    /// Describe translations from this logical view into parent coordinates.
    fn coordinate_mappings(&self) -> Vec<CoordinateMappingDescription> {
        Vec::new()
    }

    /// Recheck any external identity held by this source.
    fn verify_unchanged(&self) -> Result<()> {
        Ok(())
    }

    fn iter_ranges(&self, ranges: &[SourceRange], budget: &mut ReadBudget) -> Result<Vec<Vec<u8>>> {
        ranges
            .iter()
            .map(|range| self.read_at(range.start, range.length, budget))
            .collect()
    }

    /// Materialize this exact snapshot under an explicit size policy.
    ///
    /// File targets use `create_new`, so an existing path is never replaced.
    /// The source is revalidated before and after the copy and the returned
    /// SHA-256 covers the exact materialized bytes.
    fn materialize(
        &self,
        policy: &MaterializationPolicy,
        budget: &mut ReadBudget,
    ) -> Result<MaterializedContent> {
        let limit = match policy {
            MaterializationPolicy::Memory { max_bytes }
            | MaterializationPolicy::NewFile { max_bytes, .. } => *max_bytes,
        };
        if self.size() > limit {
            return Err(Error::ResourceLimit {
                resource: "range-source materialization",
                requested: self.size(),
                limit,
            });
        }
        self.verify_unchanged()?;
        match policy {
            MaterializationPolicy::Memory { .. } => {
                let bytes = self.read_at(0, self.size(), budget)?;
                self.verify_unchanged()?;
                let sha256 = format!("{:x}", Sha256::digest(&bytes));
                Ok(MaterializedContent::Memory {
                    bytes: bytes.into(),
                    sha256,
                })
            }
            MaterializationPolicy::NewFile { path, .. } => {
                let mut output = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(path)
                    .map_err(|error| {
                        Error::Malformed(format!("create materialized range source: {error}"))
                    })?;
                let result = (|| {
                    let mut digest = Sha256::new();
                    let mut offset = 0u64;
                    while offset < self.size() {
                        let length = (self.size() - offset).min(1024 * 1024);
                        let bytes = self.read_at(offset, length, budget)?;
                        output.write_all(&bytes).map_err(|error| {
                            Error::Malformed(format!("write materialized range source: {error}"))
                        })?;
                        digest.update(&bytes);
                        offset = offset.checked_add(length).ok_or_else(|| {
                            Error::Malformed("materialization offset overflows u64".into())
                        })?;
                    }
                    output.sync_all().map_err(|error| {
                        Error::Malformed(format!("sync materialized range source: {error}"))
                    })?;
                    self.verify_unchanged()?;
                    Ok(MaterializedContent::File {
                        path: path.clone(),
                        size: self.size(),
                        sha256: format!("{:x}", digest.finalize()),
                    })
                })();
                if result.is_err() {
                    drop(output);
                    let _ = std::fs::remove_file(path);
                }
                result
            }
        }
    }
}

/// The `RangeSource` route used for an exact read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactReadRoute {
    /// The owned `Vec<u8>` route, [`RangeSource::read_at`].
    Owned,
    /// The storage-sharing route, [`RangeSource::read_shared_at`].
    Shared,
}

/// Whether an exact read returned fewer or more bytes than requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactReadLengthMismatchKind {
    /// The source returned fewer bytes than requested.
    Short,
    /// The source returned more bytes than requested.
    Overlong,
}

/// Typed exact-length failure data, before any owner-specific [`Error`] is built.
///
/// Owners can use the route as well as the slice-local offset, requested length,
/// and actual returned length to preserve their established leaf and display
/// vocabulary exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactReadLengthMismatch {
    /// The owned or storage-sharing read route.
    pub route: ExactReadRoute,
    /// The requested offset in the source on which the read was made.
    pub offset: u64,
    /// The exact number of bytes requested.
    pub requested: u64,
    /// The number of bytes actually returned by the source.
    pub actual: usize,
}

impl ExactReadLengthMismatch {
    /// Classify this mismatch without narrowing either length.
    pub fn kind(self) -> ExactReadLengthMismatchKind {
        if (self.actual as u128) < u128::from(self.requested) {
            ExactReadLengthMismatchKind::Short
        } else {
            ExactReadLengthMismatchKind::Overlong
        }
    }

    /// Convert the mismatch to the core's default exact-read error vocabulary.
    pub fn into_default_error(self) -> Error {
        match self.kind() {
            ExactReadLengthMismatchKind::Short => Error::Truncated {
                offset: usize::try_from(self.offset).unwrap_or(usize::MAX),
                needed: usize::try_from(self.requested).unwrap_or(usize::MAX),
                available: self.actual,
            },
            ExactReadLengthMismatchKind::Overlong => Error::Malformed(format!(
                "source returned {} bytes for an exact {}-byte read",
                self.actual, self.requested
            )),
        }
    }
}

/// Report whether a source returned exactly the requested length.
///
/// Unlike an error-producing validator, this exposes all mismatch data before
/// constructing an [`Error`], allowing each format owner to retain its exact
/// malformed prefix, structured contexts, and owned/shared wording.
pub fn validate_exact_read_length(
    route: ExactReadRoute,
    offset: u64,
    requested: u64,
    actual: usize,
) -> std::result::Result<(), ExactReadLengthMismatch> {
    if (actual as u128) == u128::from(requested) {
        Ok(())
    } else {
        Err(ExactReadLengthMismatch {
            route,
            offset,
            requested,
            actual,
        })
    }
}

/// Owner policy for errors raised by exact and revalidated source reads.
///
/// Each error path is independent. In particular, construction errors from
/// [`SliceRangeSource::new`] are not treated as read or stability errors, and
/// exact-length failures arrive as typed data before an owner leaf is built.
/// Default methods preserve the original error and use the core exact-length
/// vocabulary, so an owner only needs to override the paths it customizes.
pub trait RevalidatedExactSliceErrorPolicy: Send + Sync {
    /// Map an underlying owned or shared read error.
    fn map_read_error(&self, _route: ExactReadRoute, error: Error) -> Error {
        error
    }

    /// Build the owner error for a short or overlong returned buffer.
    fn map_length_mismatch(&self, mismatch: ExactReadLengthMismatch) -> Error {
        mismatch.into_default_error()
    }

    /// Map a parent identity-verification error.
    fn map_stability_error(&self, error: Error) -> Error {
        error
    }

    /// Map the parent identity failure checked before slice construction.
    ///
    /// Most owners use the same vocabulary for construction-time and later
    /// read-time stability failures. Owners whose factory check is deliberately
    /// bare can override this independently without wrapping the parent source
    /// or changing the one-check construction cadence.
    fn map_initial_stability_error(&self, error: Error) -> Error {
        self.map_stability_error(error)
    }

    /// Map an error from constructing the bounded [`SliceRangeSource`].
    fn map_construction_error(&self, error: Error) -> Error {
        error
    }
}

impl RevalidatedExactSliceErrorPolicy for () {}

/// Read one exact owned range using an owner's error policy.
///
/// This helper deliberately does not call [`RangeSource::verify_unchanged`].
/// Owners which bracket a multi-read metadata parse with one pair of identity
/// checks can therefore share exact-read enforcement without changing their
/// verification counts.
pub fn read_exact_at<P: RevalidatedExactSliceErrorPolicy + ?Sized>(
    source: &dyn RangeSource,
    offset: u64,
    length: u64,
    budget: &mut ReadBudget,
    policy: &P,
) -> Result<Vec<u8>> {
    let route = ExactReadRoute::Owned;
    let bytes = source
        .read_at(offset, length, budget)
        .map_err(|error| policy.map_read_error(route, error))?;
    validate_exact_read_length(route, offset, length, bytes.len())
        .map_err(|mismatch| policy.map_length_mismatch(mismatch))?;
    Ok(bytes)
}

/// Read one exact storage-sharing range using an owner's error policy.
///
/// Like [`read_exact_at`], this helper leaves identity-verification cadence to
/// its caller.
pub fn read_shared_exact_at<P: RevalidatedExactSliceErrorPolicy + ?Sized>(
    source: &dyn RangeSource,
    offset: u64,
    length: u64,
    budget: &mut ReadBudget,
    policy: &P,
) -> Result<SharedBytes> {
    let route = ExactReadRoute::Shared;
    let bytes = source
        .read_shared_at(offset, length, budget)
        .map_err(|error| policy.map_read_error(route, error))?;
    validate_exact_read_length(route, offset, length, bytes.len())
        .map_err(|mismatch| policy.map_length_mismatch(mismatch))?;
    Ok(bytes)
}

fn checked_read(size: u64, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<usize> {
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
    let allocation = usize::try_from(length).map_err(|_| Error::ResourceLimit {
        resource: "range-source allocation",
        requested: length,
        limit: usize::MAX as u64,
    })?;
    budget.charge(length)?;
    Ok(allocation)
}

fn checked_work_read(size: u64, offset: u64, length: usize, budget: &mut WorkBudget) -> Result<()> {
    // Reuse legacy bounds/error ordering without charging nested physical views.
    checked_read(size, offset, length as u64, &mut ReadBudget::unlimited())?;
    budget.logical_read(length as u64)
}

/// An immutable resident source, useful for small members and fixtures.
#[derive(Debug, Clone)]
pub struct MemoryRangeSource {
    bytes: Arc<[u8]>,
    coordinate_space: CoordinateSpaceDescription,
}

impl MemoryRangeSource {
    pub fn new(bytes: impl Into<Vec<u8>>, name: impl Into<String>) -> Self {
        let bytes: Arc<[u8]> = bytes.into().into();
        let coordinate_space =
            CoordinateSpaceDescription::bytes("artifact-local", name, bytes.len() as u64);
        Self {
            bytes,
            coordinate_space,
        }
    }

    pub fn from_arc(bytes: Arc<[u8]>, name: impl Into<String>) -> Self {
        let coordinate_space =
            CoordinateSpaceDescription::bytes("artifact-local", name, bytes.len() as u64);
        Self {
            bytes,
            coordinate_space,
        }
    }
}

impl RangeSource for MemoryRangeSource {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let start = offset as usize;
        output.copy_from_slice(&self.bytes[start..start + output.len()]);
        Ok(())
    }

    fn supports_complete_io_accounting(&self) -> bool {
        true
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        let length_usize = checked_read(self.size(), offset, length, budget)?;
        let start = usize::try_from(offset)
            .map_err(|_| Error::Malformed("memory source offset exceeds usize".into()))?;
        let end = start
            .checked_add(length_usize)
            .ok_or_else(|| Error::Malformed("memory source range overflows usize".into()))?;
        Ok(self.bytes[start..end].to_vec())
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        let length = checked_read(self.size(), offset, length, budget)?;
        let start = usize::try_from(offset)
            .map_err(|_| Error::Malformed("memory source offset exceeds usize".into()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::Malformed("memory source range overflows usize".into()))?;
        SharedBytes::from_arc_range(self.bytes.clone(), start..end)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.coordinate_space.clone()
    }
}

/// A bounded resident transform output which retains the stored source and
/// the stable recipe that produced it. Decoded offsets generally do not map
/// byte-for-byte to compressed or encrypted input, so the mapping is an
/// honest coarse dependency rather than a fabricated affine translation.
#[derive(Clone)]
pub struct TransformedRangeSource {
    bytes: Arc<[u8]>,
    parent: Arc<dyn RangeSource>,
    parent_dependency: SourceRange,
    coordinate_space: CoordinateSpaceDescription,
    transform: String,
    recipe_identity: String,
}

impl std::fmt::Debug for TransformedRangeSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransformedRangeSource")
            .field("size", &self.bytes.len())
            .field("parent_size", &self.parent.size())
            .field("transform", &self.transform)
            .field("recipe_identity", &self.recipe_identity)
            .finish()
    }
}

impl TransformedRangeSource {
    pub fn new(
        bytes: Arc<[u8]>,
        parent: Arc<dyn RangeSource>,
        transform: impl Into<String>,
        name: impl Into<String>,
        recipe_identity: impl Into<String>,
    ) -> Self {
        let dependency = SourceRange::new(0, parent.size());
        Self::new_with_dependency(bytes, parent, dependency, transform, name, recipe_identity)
    }

    /// Construct a transformed address space whose output depends on one
    /// bounded range of the parent rather than the complete parent carrier.
    pub fn new_with_dependency(
        bytes: Arc<[u8]>,
        parent: Arc<dyn RangeSource>,
        parent_dependency: SourceRange,
        transform: impl Into<String>,
        name: impl Into<String>,
        recipe_identity: impl Into<String>,
    ) -> Self {
        let transform = transform.into();
        let coordinate_space =
            CoordinateSpaceDescription::bytes("transformed", name, bytes.len() as u64);
        Self {
            bytes,
            parent,
            parent_dependency,
            coordinate_space,
            transform,
            recipe_identity: recipe_identity.into(),
        }
    }

    pub fn from_vec(
        bytes: Vec<u8>,
        parent: Arc<dyn RangeSource>,
        transform: impl Into<String>,
        name: impl Into<String>,
        recipe_identity: impl Into<String>,
    ) -> Self {
        Self::new(bytes.into(), parent, transform, name, recipe_identity)
    }

    pub fn from_vec_with_dependency(
        bytes: Vec<u8>,
        parent: Arc<dyn RangeSource>,
        parent_dependency: SourceRange,
        transform: impl Into<String>,
        name: impl Into<String>,
        recipe_identity: impl Into<String>,
    ) -> Self {
        Self::new_with_dependency(
            bytes.into(),
            parent,
            parent_dependency,
            transform,
            name,
            recipe_identity,
        )
    }
}

impl RangeSource for TransformedRangeSource {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        self.verify_unchanged()?;
        let start = offset as usize;
        output.copy_from_slice(&self.bytes[start..start + output.len()]);
        self.verify_unchanged()
    }

    fn supports_complete_io_accounting(&self) -> bool {
        true
    }

    fn read_exact_into_assuming_unchanged(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let start = offset as usize;
        output.copy_from_slice(&self.bytes[start..start + output.len()]);
        Ok(())
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        let length = checked_read(self.size(), offset, length, budget)?;
        let start = usize::try_from(offset)
            .map_err(|_| Error::Malformed("transformed offset exceeds usize".into()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::Malformed("transformed range overflows usize".into()))?;
        Ok(self.bytes[start..end].to_vec())
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        let length = checked_read(self.size(), offset, length, budget)?;
        let start = usize::try_from(offset)
            .map_err(|_| Error::Malformed("transformed offset exceeds usize".into()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::Malformed("transformed range overflows usize".into()))?;
        SharedBytes::from_arc_range(self.bytes.clone(), start..end)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.coordinate_space.clone()
    }

    fn coordinate_mappings(&self) -> Vec<CoordinateMappingDescription> {
        let mut mappings = vec![CoordinateMappingDescription {
            from: SourceRange::new(0, self.size()),
            to_space: self.parent.describe_coordinate_space(),
            to: self.parent_dependency,
            kind: self.transform.clone(),
            precision: MappingPrecision::CoarseDependency,
            recipe_identity: Some(self.recipe_identity.clone()),
        }];
        mappings.extend(
            self.parent
                .coordinate_mappings()
                .into_iter()
                .map(|mapping| CoordinateMappingDescription {
                    from: SourceRange::new(0, self.size()),
                    to_space: mapping.to_space,
                    to: mapping.to,
                    kind: self.transform.clone(),
                    precision: MappingPrecision::CoarseDependency,
                    recipe_identity: Some(self.recipe_identity.clone()),
                }),
        );
        mappings
    }

    fn verify_unchanged(&self) -> Result<()> {
        self.parent.verify_unchanged()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSignature {
    len: u64,
    modified_nanos: Option<u128>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    mtime_nanos: i128,
    #[cfg(unix)]
    ctime_nanos: i128,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}

// The only unsafe platform boundary is the audited Win32 identity query.
#[cfg(windows)]
#[allow(unsafe_code)]
#[path = "windows_backing_identity.rs"]
mod windows_backing_identity;

fn file_signature(file: &File, metadata: &Metadata) -> Result<FileSignature> {
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = file;
        Ok(FileSignature {
            len: metadata.len(),
            modified_nanos,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            mtime_nanos: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            ctime_nanos: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        })
    }
    #[cfg(windows)]
    {
        let (volume_serial_number, file_index) =
            windows_backing_identity::query(file).map_err(|error| {
                Error::Malformed(format!("query range-source backing identity: {error}"))
            })?;
        Ok(FileSignature {
            len: metadata.len(),
            modified_nanos,
            volume_serial_number,
            file_index,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(FileSignature {
            len: metadata.len(),
            modified_nanos,
        })
    }
}

/// One descriptor-pinned external file with path/inode revalidation.
#[derive(Debug)]
pub struct FileRangeSource {
    path: PathBuf,
    file: Mutex<File>,
    signature: FileSignature,
    coordinate_space: CoordinateSpaceDescription,
}

impl FileRangeSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)
            .map_err(|error| Error::Malformed(format!("open range source: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| Error::Malformed(format!("stat range source: {error}")))?;
        if !metadata.is_file() {
            return Err(Error::Malformed(
                "range source is not a regular file".into(),
            ));
        }
        let signature = file_signature(&file, &metadata)?;
        let coordinate_space =
            CoordinateSpaceDescription::bytes("source-file", path.to_string_lossy(), signature.len);
        Ok(Self {
            path,
            file: Mutex::new(file),
            signature,
            coordinate_space,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compare the backing identity captured from each already-open file
    /// descriptor. Pathnames are deliberately not consulted, so a rename or
    /// rebinding cannot change this answer after either source is opened.
    pub fn shares_file_backing(&self, other: &Self) -> Result<bool> {
        #[cfg(unix)]
        {
            Ok(self.signature.device == other.signature.device
                && self.signature.inode == other.signature.inode)
        }
        #[cfg(windows)]
        {
            Ok(
                self.signature.volume_serial_number == other.signature.volume_serial_number
                    && self.signature.file_index == other.signature.file_index,
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = other;
            Err(Error::Unsupported(
                "reliable opened-file backing identity is unavailable on this platform".into(),
            ))
        }
    }
}

fn read_exact_instrumented(
    reader: &mut impl Read,
    mut output: &mut [u8],
    budget: &mut WorkBudget,
) -> Result<()> {
    while !output.is_empty() {
        budget.io_attempt(output.len() as u64)?;
        match reader.read(output) {
            Ok(0) => {
                return Err(Error::Malformed(
                    "unexpected EOF reading range source".into(),
                ))
            }
            Ok(size) => {
                budget.io_completed(size as u64);
                output = &mut output[size..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Malformed(format!("read range source: {error}"))),
        }
    }
    Ok(())
}

impl RangeSource for FileRangeSource {
    fn size(&self) -> u64 {
        self.signature.len
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        self.verify_unchanged()?;
        let result = (|| {
            let mut file = self
                .file
                .lock()
                .map_err(|_| Error::Malformed("range-source file lock is poisoned".into()))?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|error| Error::Malformed(format!("seek range source: {error}")))?;
            read_exact_instrumented(&mut *file, output, budget)
        })();
        self.verify_unchanged()?;
        result
    }

    fn supports_complete_io_accounting(&self) -> bool {
        true
    }

    fn read_exact_into_assuming_unchanged(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| Error::Malformed("range-source file lock is poisoned".into()))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| Error::Malformed(format!("seek range source: {error}")))?;
        read_exact_instrumented(&mut *file, output, budget)
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        let allocation = checked_read(self.size(), offset, length, budget)?;
        self.verify_unchanged()?;
        let mut output = vec![0u8; allocation];
        let mut file = self
            .file
            .lock()
            .map_err(|_| Error::Malformed("range-source file lock is poisoned".into()))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| Error::Malformed(format!("seek range source: {error}")))?;
        file.read_exact(&mut output)
            .map_err(|error| Error::Malformed(format!("read range source: {error}")))?;
        drop(file);
        self.verify_unchanged()?;
        Ok(output)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.coordinate_space.clone()
    }

    fn verify_unchanged(&self) -> Result<()> {
        let held_file = self
            .file
            .lock()
            .map_err(|_| Error::Malformed("range-source file lock is poisoned".into()))?;
        let held = held_file
            .metadata()
            .map_err(|error| Error::Malformed(format!("stat held range source: {error}")))?;
        let current_file = File::open(&self.path)
            .map_err(|error| Error::Malformed(format!("open range-source path: {error}")))?;
        let current = current_file
            .metadata()
            .map_err(|error| Error::Malformed(format!("stat range-source path: {error}")))?;
        if file_signature(&held_file, &held)? != self.signature
            || file_signature(&current_file, &current)? != self.signature
        {
            return Err(Error::SourceIdentityChanged {
                identity: self.path.to_string_lossy().into_owned(),
            });
        }
        Ok(())
    }
}

/// A bounded view into another source. Its offsets are artifact-local.
#[derive(Clone)]
pub struct SliceRangeSource {
    source: Arc<dyn RangeSource>,
    source_start: u64,
    length: u64,
    coordinate_space: CoordinateSpaceDescription,
}

impl std::fmt::Debug for SliceRangeSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SliceRangeSource")
            .field("source_start", &self.source_start)
            .field("length", &self.length)
            .field("coordinate_space", &self.coordinate_space)
            .finish_non_exhaustive()
    }
}

impl SliceRangeSource {
    pub fn new(
        source: Arc<dyn RangeSource>,
        source_start: u64,
        length: u64,
        name: impl Into<String>,
    ) -> Result<Self> {
        let Some(end) = source_start.checked_add(length) else {
            return Err(Error::SourceRangeOutside {
                offset: source_start,
                length,
                source_size: source.size(),
            });
        };
        if end > source.size() {
            return Err(Error::SourceRangeOutside {
                offset: source_start,
                length,
                source_size: source.size(),
            });
        }
        Ok(Self {
            source,
            source_start,
            length,
            coordinate_space: CoordinateSpaceDescription::bytes("artifact-local", name, length),
        })
    }
}

impl RangeSource for SliceRangeSource {
    fn size(&self) -> u64 {
        self.length
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let absolute = self
            .source_start
            .checked_add(offset)
            .ok_or_else(|| Error::Malformed("slice read offset overflows u64".into()))?;
        budget.forward(|budget| self.source.read_exact_into(absolute, output, budget))
    }

    fn supports_complete_io_accounting(&self) -> bool {
        self.source.supports_complete_io_accounting()
    }

    fn read_exact_into_assuming_unchanged(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let absolute = self
            .source_start
            .checked_add(offset)
            .ok_or_else(|| Error::Malformed("slice read offset overflows u64".into()))?;
        budget.forward(|budget| {
            self.source
                .read_exact_into_assuming_unchanged(absolute, output, budget)
        })
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        checked_read(self.length, offset, length, budget)?;
        let absolute = self
            .source_start
            .checked_add(offset)
            .ok_or_else(|| Error::Malformed("slice read offset overflows u64".into()))?;
        let mut child_budget = ReadBudget::unlimited();
        self.source.read_at(absolute, length, &mut child_budget)
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        checked_read(self.length, offset, length, budget)?;
        let absolute = self
            .source_start
            .checked_add(offset)
            .ok_or_else(|| Error::Malformed("slice read offset overflows u64".into()))?;
        let mut child_budget = ReadBudget::unlimited();
        self.source
            .read_shared_at(absolute, length, &mut child_budget)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.coordinate_space.clone()
    }

    fn coordinate_mappings(&self) -> Vec<CoordinateMappingDescription> {
        let mut mappings = vec![CoordinateMappingDescription {
            from: SourceRange::new(0, self.length),
            to_space: self.source.describe_coordinate_space(),
            to: SourceRange::new(self.source_start, self.length),
            kind: "slice".into(),
            precision: MappingPrecision::ExactAffine,
            recipe_identity: None,
        }];
        let Some(slice_end) = self.source_start.checked_add(self.length) else {
            return mappings;
        };
        for parent in self.source.coordinate_mappings() {
            let Some(parent_from_end) = parent.from.start.checked_add(parent.from.length) else {
                continue;
            };
            if parent.from.start > self.source_start || slice_end > parent_from_end {
                continue;
            }
            let (to, precision) = if parent.precision == MappingPrecision::ExactAffine
                && parent.from.length == parent.to.length
            {
                let delta = self.source_start - parent.from.start;
                let Some(start) = parent.to.start.checked_add(delta) else {
                    continue;
                };
                (
                    SourceRange::new(start, self.length),
                    MappingPrecision::ExactAffine,
                )
            } else {
                (parent.to, MappingPrecision::CoarseDependency)
            };
            mappings.push(CoordinateMappingDescription {
                from: SourceRange::new(0, self.length),
                to_space: parent.to_space,
                to,
                kind: parent.kind,
                precision,
                recipe_identity: parent.recipe_identity,
            });
        }
        mappings
    }

    fn verify_unchanged(&self) -> Result<()> {
        self.source.verify_unchanged()
    }
}

/// A bounded source view whose reads are exact and bracketed by parent
/// identity checks.
///
/// The caller supplies an inline policy so a format owner can retain its public
/// error vocabulary without an allocation for callbacks. The coordinate name
/// is forwarded to the underlying [`SliceRangeSource`]. Read budgets are
/// charged there exactly once; this wrapper performs no additional charging.
/// Construction verifies the parent before validating the slice coordinates,
/// matching owner factories which must fail closed on an unstable source.
#[derive(Clone)]
pub struct RevalidatedExactSliceSource<P = ()> {
    owner: Arc<dyn RangeSource>,
    slice: SliceRangeSource,
    policy: P,
}

impl<P> std::fmt::Debug for RevalidatedExactSliceSource<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevalidatedExactSliceSource")
            .field("slice", &self.slice)
            .field("policy", &std::any::type_name::<P>())
            .finish_non_exhaustive()
    }
}

impl RevalidatedExactSliceSource<()> {
    /// Construct a source with the default identity/core-error policy.
    pub fn new(
        owner: Arc<dyn RangeSource>,
        source_start: u64,
        length: u64,
        coordinate_name: impl Into<String>,
    ) -> Result<Self> {
        Self::with_policy(owner, source_start, length, coordinate_name, ())
    }
}

impl<P: RevalidatedExactSliceErrorPolicy> RevalidatedExactSliceSource<P> {
    /// Construct a source with an owner-defined error policy.
    pub fn with_policy(
        owner: Arc<dyn RangeSource>,
        source_start: u64,
        length: u64,
        coordinate_name: impl Into<String>,
        policy: P,
    ) -> Result<Self> {
        owner
            .verify_unchanged()
            .map_err(|error| policy.map_initial_stability_error(error))?;
        let slice =
            SliceRangeSource::new(Arc::clone(&owner), source_start, length, coordinate_name)
                .map_err(|error| policy.map_construction_error(error))?;
        Ok(Self {
            owner,
            slice,
            policy,
        })
    }

    fn verify_parent(&self) -> Result<()> {
        self.owner
            .verify_unchanged()
            .map_err(|error| self.policy.map_stability_error(error))
    }
}

impl<P: RevalidatedExactSliceErrorPolicy> RangeSource for RevalidatedExactSliceSource<P> {
    fn size(&self) -> u64 {
        self.slice.size()
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        self.verify_parent()?;
        let result = self.slice.read_exact_into(offset, output, budget);
        self.verify_parent()?;
        result.map_err(|error| self.policy.map_read_error(ExactReadRoute::Owned, error))
    }

    fn supports_complete_io_accounting(&self) -> bool {
        self.slice.supports_complete_io_accounting()
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        let route = ExactReadRoute::Owned;
        self.verify_parent()?;
        let read = self.slice.read_at(offset, length, budget);
        self.verify_parent()?;
        let bytes = read.map_err(|error| self.policy.map_read_error(route, error))?;
        validate_exact_read_length(route, offset, length, bytes.len())
            .map_err(|mismatch| self.policy.map_length_mismatch(mismatch))?;
        Ok(bytes)
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        let route = ExactReadRoute::Shared;
        self.verify_parent()?;
        let read = self.slice.read_shared_at(offset, length, budget);
        self.verify_parent()?;
        let bytes = read.map_err(|error| self.policy.map_read_error(route, error))?;
        validate_exact_read_length(route, offset, length, bytes.len())
            .map_err(|mismatch| self.policy.map_length_mismatch(mismatch))?;
        Ok(bytes)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.slice.describe_coordinate_space()
    }

    fn coordinate_mappings(&self) -> Vec<CoordinateMappingDescription> {
        self.slice.coordinate_mappings()
    }

    fn verify_unchanged(&self) -> Result<()> {
        self.verify_parent()
    }
}

/// One logical segment in a concatenated or sparse source.
#[derive(Clone)]
pub struct CompositeSegment {
    source: Option<Arc<dyn RangeSource>>,
    source_start: u64,
    length: u64,
}

impl std::fmt::Debug for CompositeSegment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeSegment")
            .field("mapped", &self.source.is_some())
            .field("source_start", &self.source_start)
            .field("length", &self.length)
            .finish()
    }
}

impl CompositeSegment {
    pub fn mapped(source: Arc<dyn RangeSource>, source_start: u64, length: u64) -> Result<Self> {
        let Some(end) = source_start.checked_add(length) else {
            return Err(Error::SourceRangeOutside {
                offset: source_start,
                length,
                source_size: source.size(),
            });
        };
        if end > source.size() {
            return Err(Error::SourceRangeOutside {
                offset: source_start,
                length,
                source_size: source.size(),
            });
        }
        Ok(Self {
            source: Some(source),
            source_start,
            length,
        })
    }

    /// A logical hole that reads as zero and has no parent mapping.
    pub const fn zero_filled(length: u64) -> Self {
        Self {
            source: None,
            source_start: 0,
            length,
        }
    }

    pub const fn length(&self) -> u64 {
        self.length
    }
}

/// A concatenation of mapped ranges and optional zero-filled sparse holes.
#[derive(Clone)]
pub struct CompositeRangeSource {
    segments: Vec<CompositeSegment>,
    segment_ends: Vec<u64>,
    size: u64,
    coordinate_space: CoordinateSpaceDescription,
}

impl std::fmt::Debug for CompositeRangeSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeRangeSource")
            .field("segments", &self.segments)
            .field("size", &self.size)
            .field("coordinate_space", &self.coordinate_space)
            .finish()
    }
}

impl CompositeRangeSource {
    pub fn new(segments: Vec<CompositeSegment>, name: impl Into<String>) -> Result<Self> {
        let mut size = 0u64;
        let mut segment_ends = Vec::new();
        segment_ends
            .try_reserve_exact(segments.len())
            .map_err(|_| Error::Malformed("allocate composite segment index".into()))?;
        for segment in &segments {
            size = size
                .checked_add(segment.length)
                .ok_or_else(|| Error::Malformed("composite size overflows u64".into()))?;
            segment_ends.push(size);
        }
        Ok(Self {
            segments,
            segment_ends,
            size,
            coordinate_space: CoordinateSpaceDescription::bytes("artifact-local", name, size),
        })
    }

    pub fn segments(&self) -> &[CompositeSegment] {
        &self.segments
    }
}

impl RangeSource for CompositeRangeSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let mut index = self.segment_ends.partition_point(|end| *end <= offset);
        let mut logical = offset;
        let mut remaining = output;
        while !remaining.is_empty() {
            let start = if index == 0 {
                0
            } else {
                self.segment_ends[index - 1]
            };
            let segment = &self.segments[index];
            let length = (self.segment_ends[index] - logical).min(remaining.len() as u64) as usize;
            if length == 0 {
                index += 1;
                continue;
            }
            let (current, tail) = remaining.split_at_mut(length);
            if let Some(source) = &segment.source {
                let absolute = segment.source_start + (logical - start);
                budget.forward(|budget| source.read_exact_into(absolute, current, budget))?;
            } else {
                current.fill(0);
            }
            remaining = tail;
            logical += length as u64;
            index += 1;
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        let allocation = checked_read(self.size, offset, length, budget)?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::Malformed("composite read range overflows u64".into()))?;
        let mut output = vec![0u8; allocation];
        let mut logical_start = 0u64;
        for segment in &self.segments {
            let logical_end = logical_start
                .checked_add(segment.length)
                .ok_or_else(|| Error::Malformed("composite segment end overflows u64".into()))?;
            let overlap_start = offset.max(logical_start);
            let overlap_end = end.min(logical_end);
            if overlap_start < overlap_end {
                if let Some(source) = &segment.source {
                    let within_segment = overlap_start - logical_start;
                    let source_offset = segment
                        .source_start
                        .checked_add(within_segment)
                        .ok_or_else(|| {
                            Error::Malformed("composite source offset overflows u64".into())
                        })?;
                    let overlap_length = overlap_end - overlap_start;
                    let mut child_budget = ReadBudget::unlimited();
                    let bytes = source.read_at(source_offset, overlap_length, &mut child_budget)?;
                    let output_start = usize::try_from(overlap_start - offset)
                        .map_err(|_| Error::Malformed("composite offset exceeds usize".into()))?;
                    let output_end = output_start.checked_add(bytes.len()).ok_or_else(|| {
                        Error::Malformed("composite output range overflows usize".into())
                    })?;
                    output[output_start..output_end].copy_from_slice(&bytes);
                }
            }
            logical_start = logical_end;
            if logical_start >= end {
                break;
            }
        }
        Ok(output)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.coordinate_space.clone()
    }

    fn coordinate_mappings(&self) -> Vec<CoordinateMappingDescription> {
        let mut logical_start = 0u64;
        self.segments
            .iter()
            .filter_map(|segment| {
                let from = SourceRange::new(logical_start, segment.length);
                logical_start += segment.length;
                segment
                    .source
                    .as_ref()
                    .map(|source| CoordinateMappingDescription {
                        from,
                        to_space: source.describe_coordinate_space(),
                        to: SourceRange::new(segment.source_start, segment.length),
                        kind: "concatenated-slice".into(),
                        precision: MappingPrecision::ExactTable,
                        recipe_identity: None,
                    })
            })
            .collect()
    }

    fn verify_unchanged(&self) -> Result<()> {
        for segment in &self.segments {
            if let Some(source) = &segment.source {
                source.verify_unchanged()?;
            }
        }
        Ok(())
    }
}

/// A regular payload view over fixed-stride records such as cooked CD sectors.
#[derive(Clone)]
pub struct StridedRangeSource {
    source: Arc<dyn RangeSource>,
    source_start: u64,
    input_stride: u64,
    payload_offset: u64,
    payload_length: u64,
    record_count: u64,
    size: u64,
    coordinate_space: CoordinateSpaceDescription,
    recipe_identity: String,
}

impl std::fmt::Debug for StridedRangeSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StridedRangeSource")
            .field("source_start", &self.source_start)
            .field("input_stride", &self.input_stride)
            .field("payload_offset", &self.payload_offset)
            .field("payload_length", &self.payload_length)
            .field("record_count", &self.record_count)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl StridedRangeSource {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: Arc<dyn RangeSource>,
        source_start: u64,
        input_stride: u64,
        payload_offset: u64,
        payload_length: u64,
        record_count: u64,
        kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self> {
        if input_stride == 0 || payload_length == 0 {
            return Err(Error::Malformed(
                "strided source requires non-zero stride and payload".into(),
            ));
        }
        let payload_end = payload_offset
            .checked_add(payload_length)
            .ok_or_else(|| Error::Malformed("strided payload range overflows u64".into()))?;
        if payload_end > input_stride {
            return Err(Error::Malformed(
                "strided payload extends beyond its input record".into(),
            ));
        }
        let input_length = input_stride
            .checked_mul(record_count)
            .ok_or_else(|| Error::Malformed("strided input size overflows u64".into()))?;
        let Some(input_end) = source_start.checked_add(input_length) else {
            return Err(Error::SourceRangeOutside {
                offset: source_start,
                length: input_length,
                source_size: source.size(),
            });
        };
        if input_end > source.size() {
            return Err(Error::SourceRangeOutside {
                offset: source_start,
                length: input_length,
                source_size: source.size(),
            });
        }
        let size = payload_length
            .checked_mul(record_count)
            .ok_or_else(|| Error::Malformed("strided output size overflows u64".into()))?;
        let kind = kind.into();
        let recipe_identity = format!(
            "strided-v1:{source_start}:{input_stride}:{payload_offset}:{payload_length}:{record_count}"
        );
        Ok(Self {
            source,
            source_start,
            input_stride,
            payload_offset,
            payload_length,
            record_count,
            size,
            coordinate_space: CoordinateSpaceDescription::bytes(kind, name, size),
            recipe_identity,
        })
    }

    pub const fn record_count(&self) -> u64 {
        self.record_count
    }
}

impl RangeSource for StridedRangeSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        checked_work_read(self.size(), offset, output.len(), budget)?;
        let mut logical = offset;
        let mut remaining = output;
        while !remaining.is_empty() {
            let record = logical / self.payload_length;
            let within = logical % self.payload_length;
            let length = if self.payload_length == self.input_stride {
                remaining.len()
            } else {
                (self.payload_length - within).min(remaining.len() as u64) as usize
            };
            let physical =
                self.source_start + record * self.input_stride + self.payload_offset + within;
            let (current, tail) = remaining.split_at_mut(length);
            budget.forward(|budget| self.source.read_exact_into(physical, current, budget))?;
            remaining = tail;
            logical += length as u64;
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        let allocation = checked_read(self.size, offset, length, budget)?;
        let mut output = Vec::with_capacity(allocation);
        let mut logical = offset;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::Malformed("strided read range overflows u64".into()))?;
        while logical < end {
            let record = logical / self.payload_length;
            let within = logical % self.payload_length;
            let take = (self.payload_length - within).min(end - logical);
            let physical_record = record
                .checked_mul(self.input_stride)
                .ok_or_else(|| Error::Malformed("strided record offset overflows u64".into()))?;
            let physical = self
                .source_start
                .checked_add(physical_record)
                .and_then(|value| value.checked_add(self.payload_offset))
                .and_then(|value| value.checked_add(within))
                .ok_or_else(|| Error::Malformed("strided source offset overflows u64".into()))?;
            let mut child_budget = ReadBudget::unlimited();
            output.extend_from_slice(&self.source.read_at(physical, take, &mut child_budget)?);
            logical = logical
                .checked_add(take)
                .ok_or_else(|| Error::Malformed("strided logical offset overflows u64".into()))?;
        }
        Ok(output)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.coordinate_space.clone()
    }

    fn coordinate_mappings(&self) -> Vec<CoordinateMappingDescription> {
        vec![CoordinateMappingDescription {
            from: SourceRange::new(0, self.size),
            to_space: self.source.describe_coordinate_space(),
            to: SourceRange::new(self.source_start, self.input_stride * self.record_count),
            kind: "strided-payload-view".into(),
            precision: MappingPrecision::Parametric,
            recipe_identity: Some(self.recipe_identity.clone()),
        }]
    }

    fn verify_unchanged(&self) -> Result<()> {
        self.source.verify_unchanged()
    }
}

/// Stored archive members and object-pack blobs are exact slices of a source.
pub type ArchiveMemberRangeSource = SliceRangeSource;
pub type ObjectPackRangeSource = SliceRangeSource;

#[cfg(test)]
#[path = "range_source_work_tests.rs"]
mod work_tests;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::ErrorContext;

    #[derive(Debug, Clone, Copy)]
    enum ExactReadBehavior {
        Exact,
        Short,
        Overlong,
        Fail(&'static str),
    }

    struct AdversarialExactSource {
        bytes: Arc<[u8]>,
        owned: ExactReadBehavior,
        shared: ExactReadBehavior,
        fail_verification_at: Option<(u64, &'static str)>,
        owned_calls: AtomicU64,
        shared_calls: AtomicU64,
        requested_bytes: AtomicU64,
        verification_calls: AtomicU64,
    }

    impl AdversarialExactSource {
        fn new(
            owned: ExactReadBehavior,
            shared: ExactReadBehavior,
            fail_verification_at: Option<(u64, &'static str)>,
        ) -> Self {
            Self {
                bytes: Arc::from(&b"0123456789ab"[..]),
                owned,
                shared,
                fail_verification_at,
                owned_calls: AtomicU64::new(0),
                shared_calls: AtomicU64::new(0),
                requested_bytes: AtomicU64::new(0),
                verification_calls: AtomicU64::new(0),
            }
        }

        fn returned_length(behavior: ExactReadBehavior, requested: u64) -> Result<u64> {
            match behavior {
                ExactReadBehavior::Exact => Ok(requested),
                ExactReadBehavior::Short => requested
                    .checked_sub(1)
                    .ok_or_else(|| Error::Malformed("cannot inject a short zero-byte read".into())),
                ExactReadBehavior::Overlong => requested
                    .checked_add(1)
                    .ok_or_else(|| Error::Malformed("injected read length overflows u64".into())),
                ExactReadBehavior::Fail(message) => Err(Error::Unsupported(message.into())),
            }
        }

        fn range(
            &self,
            offset: u64,
            requested: u64,
            behavior: ExactReadBehavior,
            budget: &mut ReadBudget,
        ) -> Result<std::ops::Range<usize>> {
            self.requested_bytes.fetch_add(requested, Ordering::SeqCst);
            budget.charge(requested)?;
            let returned = Self::returned_length(behavior, requested)?;
            let start = usize::try_from(offset)
                .map_err(|_| Error::Malformed("test source offset exceeds usize".into()))?;
            let returned = usize::try_from(returned).map_err(|_| Error::ResourceLimit {
                resource: "test source allocation",
                requested: returned,
                limit: usize::MAX as u64,
            })?;
            let end = start
                .checked_add(returned)
                .ok_or_else(|| Error::Malformed("test source range overflows usize".into()))?;
            if end > self.bytes.len() {
                return Err(Error::Truncated {
                    offset: start,
                    needed: returned,
                    available: self.bytes.len().saturating_sub(start),
                });
            }
            Ok(start..end)
        }
    }

    impl RangeSource for AdversarialExactSource {
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
            self.owned_calls.fetch_add(1, Ordering::SeqCst);
            let range = self.range(offset, length, self.owned, budget)?;
            Ok(self.bytes[range].to_vec())
        }

        fn read_shared_at(
            &self,
            offset: u64,
            length: u64,
            budget: &mut ReadBudget,
        ) -> Result<SharedBytes> {
            self.shared_calls.fetch_add(1, Ordering::SeqCst);
            let range = self.range(offset, length, self.shared, budget)?;
            SharedBytes::from_arc_range(Arc::clone(&self.bytes), range)
        }

        fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
            CoordinateSpaceDescription::bytes(
                "synthetic-id-1c18a5ddb64b",
                "carrier.bin",
                self.size(),
            )
        }

        fn verify_unchanged(&self) -> Result<()> {
            let call = self.verification_calls.fetch_add(1, Ordering::SeqCst);
            if let Some((failure_call, message)) = self.fail_verification_at {
                if call == failure_call {
                    return Err(Error::Malformed(message.into()));
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct ContextPolicy {
        read: &'static str,
        stability: &'static str,
        initial_stability: &'static str,
        construction: &'static str,
    }

    impl RevalidatedExactSliceErrorPolicy for ContextPolicy {
        fn map_read_error(&self, _route: ExactReadRoute, error: Error) -> Error {
            error.context(ErrorContext::Component(self.read))
        }

        fn map_length_mismatch(&self, mismatch: ExactReadLengthMismatch) -> Error {
            mismatch
                .into_default_error()
                .context(ErrorContext::Component(self.read))
        }

        fn map_stability_error(&self, error: Error) -> Error {
            error.context(ErrorContext::Component(self.stability))
        }

        fn map_initial_stability_error(&self, error: Error) -> Error {
            error.context(ErrorContext::Component(self.initial_stability))
        }

        fn map_construction_error(&self, error: Error) -> Error {
            error.context(ErrorContext::Component(self.construction))
        }
    }

    const TEST_POLICY: ContextPolicy = ContextPolicy {
        read: "owner stored read",
        stability: "owner stability",
        initial_stability: "owner initial stability",
        construction: "owner construction",
    };

    fn exact_slice(
        owner: &Arc<AdversarialExactSource>,
    ) -> RevalidatedExactSliceSource<ContextPolicy> {
        let source: Arc<dyn RangeSource> = owner.clone();
        RevalidatedExactSliceSource::with_policy(source, 2, 8, "payload.bin", TEST_POLICY).unwrap()
    }

    #[test]
    fn memory_reads_are_bounded_and_charged() {
        let source = MemoryRangeSource::new(b"0123456789".to_vec(), "fixture");
        let mut budget = ReadBudget::limited(5);
        assert_eq!(source.read_at(2, 4, &mut budget).unwrap(), b"2345");
        assert_eq!(budget.spent(), 4);
        assert!(matches!(
            source.read_at(0, 2, &mut budget),
            Err(Error::ResourceLimit {
                resource: "range-source bytes",
                requested: 6,
                limit: 5,
            })
        ));
        assert_eq!(budget.spent(), 4);
    }

    #[test]
    fn work_bridge_transfers_success_and_error_spend() {
        let mut budget = ReadBudget::limited(20);
        budget.charge(3).unwrap();
        let local_spent = budget
            .with_logical_read_work_budget(|work| {
                work.charge(WorkResource::LogicalReadBytes, 5)?;
                Ok(work.spent(WorkResource::LogicalReadBytes))
            })
            .unwrap();
        assert_eq!(local_spent, 5);
        assert_eq!(budget.spent(), 8);

        let error = budget
            .with_logical_read_work_budget::<()>(|work| {
                work.charge(WorkResource::LogicalReadBytes, 4)?;
                Err(Error::Unsupported("injected after admission".into()))
            })
            .unwrap_err();
        assert_eq!(error, Error::Unsupported("injected after admission".into()));
        assert_eq!(budget.spent(), 12);
    }

    #[test]
    fn work_bridge_restores_absolute_legacy_limit_diagnostics() {
        let mut budget = ReadBudget::limited(100);
        budget.charge(20).unwrap();
        let error = budget
            .with_logical_read_work_budget::<()>(|work| {
                work.charge(WorkResource::LogicalReadBytes, 60)?;
                work.charge(WorkResource::LogicalReadBytes, 30)?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: "range-source bytes",
                requested: 110,
                limit: 100,
            }
        );
        // The rejected charge is excluded, while prior admitted work survives.
        assert_eq!(budget.spent(), 80);
    }

    #[test]
    fn work_bridge_rewrites_nested_limit_leaf_without_losing_context() {
        let mut budget = ReadBudget::limited(12);
        budget.charge(4).unwrap();
        let error = budget
            .with_logical_read_work_budget::<()>(|work| {
                work.charge(WorkResource::LogicalReadBytes, 5)?;
                work.charge(WorkResource::LogicalReadBytes, 4)
                    .map_err(|error| {
                        error
                            .context(ErrorContext::Component("inner source"))
                            .context(ErrorContext::Format("outer owner"))
                    })?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            error.leaf(),
            Error::ResourceLimit {
                resource: "range-source bytes",
                requested: 13,
                limit: 12,
            }
        ));
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![
                &ErrorContext::Format("outer owner"),
                &ErrorContext::Component("inner source"),
            ]
        );
        assert_eq!(budget.spent(), 9);
    }

    #[test]
    fn work_bridge_rewrites_a_revalidated_source_limit_in_place() {
        let owner = Arc::new(AdversarialExactSource::new(
            ExactReadBehavior::Exact,
            ExactReadBehavior::Exact,
            None,
        ));
        let source = exact_slice(&owner);
        let mut budget = ReadBudget::limited(4);
        budget.charge(1).unwrap();
        let error = budget
            .with_logical_read_work_budget::<()>(|work| {
                let mut output = [0; 4];
                source.read_exact_into(0, &mut output, work)?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            error.leaf(),
            Error::ResourceLimit {
                resource: "range-source bytes",
                requested: 5,
                limit: 4,
            }
        ));
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![&ErrorContext::Component(TEST_POLICY.read)]
        );
        assert_eq!(budget.spent(), 1);
        assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn work_bridge_preserves_unrelated_limits_and_child_scopes() {
        let mut budget = ReadBudget::limited(20);
        let owner_limit = Error::ResourceLimit {
            resource: "format members",
            requested: 3,
            limit: 2,
        }
        .context(ErrorContext::Component("owner policy"));
        let error = budget
            .with_logical_read_work_budget::<()>(|_| Err(owner_limit))
            .unwrap_err();
        assert!(matches!(
            error.leaf(),
            Error::ResourceLimit {
                resource: "format members",
                requested: 3,
                limit: 2,
            }
        ));

        let error = budget
            .with_logical_read_work_budget::<()>(|work| {
                let mut child =
                    work.scope(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 2))?;
                child.charge(WorkResource::LogicalReadBytes, 3)?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 3,
                limit: 2,
            }
        );
        assert_eq!(budget.spent(), 0);
    }

    #[test]
    fn work_bridge_preserves_legacy_unlimited_counter_overflow() {
        let mut budget = ReadBudget {
            limit: None,
            spent: u64::MAX - 2,
            bridge_identity: None,
        };
        let error = budget
            .with_logical_read_work_budget::<()>(|work| {
                work.charge(WorkResource::LogicalReadBytes, 3)?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::Malformed("byte-read budget overflows u64".into())
        );
        assert_eq!(budget.spent(), u64::MAX - 2);
    }

    #[test]
    fn work_bridge_preserves_fabricated_limit_under_unlimited_parent() {
        let mut budget = ReadBudget {
            limit: None,
            spent: 7,
            bridge_identity: None,
        };
        let bridge_limit = u64::MAX - 7;
        let error = budget
            .with_logical_read_work_budget::<()>(|_| {
                Err(Error::ResourceLimit {
                    resource: "logical source bytes",
                    requested: 11,
                    limit: bridge_limit,
                }
                .context(ErrorContext::Component("fabricated owner error")))
            })
            .unwrap_err();
        assert!(matches!(
            error.leaf(),
            Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 11,
                limit,
            } if *limit == bridge_limit
        ));
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![&ErrorContext::Component("fabricated owner error")]
        );
        assert_eq!(budget.spent(), 7);
    }

    #[test]
    fn resident_shared_reads_and_nested_slices_keep_one_allocation() {
        let storage: Arc<[u8]> = Arc::from(&b"HEADleafTAIL"[..]);
        let root: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::from_arc(storage, "fixture"));
        let child = SliceRangeSource::new(root.clone(), 4, 4, "member").unwrap();
        let mut budget = ReadBudget::limited(16);
        let root_view = root.read_shared_at(0, 12, &mut budget).unwrap();
        let child_view = child.read_shared_at(0, 4, &mut budget).unwrap();
        assert_eq!(child_view.as_slice(), b"leaf");
        assert!(root_view.shares_storage_with(&child_view));
        assert_eq!(budget.spent(), 16);
    }

    #[test]
    fn overflow_and_out_of_bounds_fail_before_charging() {
        let source = MemoryRangeSource::new(vec![0; 8], "fixture");
        let mut budget = ReadBudget::limited(100);
        assert!(matches!(
            source.read_at(u64::MAX, 2, &mut budget),
            Err(Error::SourceRangeOutside {
                offset: u64::MAX,
                length: 2,
                source_size: 8,
            })
        ));
        assert!(matches!(
            source.read_at(7, 2, &mut budget),
            Err(Error::SourceRangeOutside {
                offset: 7,
                length: 2,
                source_size: 8,
            })
        ));
        assert_eq!(budget.spent(), 0);
    }

    #[test]
    fn slice_cannot_escape_parent_and_charges_once() {
        let parent: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"headerPAYLOADtail".to_vec(),
            "parent",
        ));
        let source = SliceRangeSource::new(parent, 6, 7, "member").unwrap();
        let mut budget = ReadBudget::limited(7);
        assert_eq!(source.read_at(0, 7, &mut budget).unwrap(), b"PAYLOAD");
        assert_eq!(budget.spent(), 7);
        assert!(matches!(
            source.read_at(7, 1, &mut ReadBudget::unlimited()),
            Err(Error::SourceRangeOutside {
                offset: 7,
                length: 1,
                source_size: 7,
            })
        ));
    }

    #[test]
    fn revalidated_exact_slice_preserves_owned_shared_coordinates_and_budget() {
        let owner = Arc::new(AdversarialExactSource::new(
            ExactReadBehavior::Exact,
            ExactReadBehavior::Exact,
            None,
        ));
        let source = exact_slice(&owner);
        let mut budget = ReadBudget::limited(7);

        assert_eq!(source.read_at(1, 4, &mut budget).unwrap(), b"3456");
        let shared = source.read_shared_at(2, 3, &mut budget).unwrap();
        assert_eq!(shared.as_slice(), b"456");
        assert!(SharedBytes::from_arc(Arc::clone(&owner.bytes)).shares_storage_with(&shared));
        assert_eq!(budget.spent(), 7);
        assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.shared_calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.requested_bytes.load(Ordering::SeqCst), 7);
        assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 5);

        assert_eq!(
            source.describe_coordinate_space(),
            CoordinateSpaceDescription::bytes("artifact-local", "payload.bin", 8)
        );
        assert_eq!(
            source.coordinate_mappings(),
            vec![CoordinateMappingDescription {
                from: SourceRange::new(0, 8),
                to_space: CoordinateSpaceDescription::bytes(
                    "synthetic-id-1c18a5ddb64b",
                    "carrier.bin",
                    12,
                ),
                to: SourceRange::new(2, 8),
                kind: "slice".into(),
                precision: MappingPrecision::ExactAffine,
                recipe_identity: None,
            }]
        );
    }

    #[test]
    fn exact_source_read_is_contextual_strict_budgeted_and_zero_length_safe() {
        for behavior in [
            ExactReadBehavior::Exact,
            ExactReadBehavior::Short,
            ExactReadBehavior::Overlong,
            ExactReadBehavior::Fail("metadata I/O failed"),
        ] {
            let owner = AdversarialExactSource::new(behavior, ExactReadBehavior::Exact, None);
            let mut budget = ReadBudget::limited(4);
            let result = read_exact_at(
                &owner,
                2,
                4,
                &mut budget,
                &ContextPolicy {
                    read: "owner metadata read",
                    ..TEST_POLICY
                },
            );
            if matches!(behavior, ExactReadBehavior::Exact) {
                assert_eq!(result.unwrap(), b"2345");
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.contexts().collect::<Vec<_>>(),
                    vec![&ErrorContext::Component("owner metadata read")]
                );
                match behavior {
                    ExactReadBehavior::Short => assert!(matches!(
                        error.leaf(),
                        Error::Truncated {
                            offset: 2,
                            needed: 4,
                            available: 3,
                        }
                    )),
                    ExactReadBehavior::Overlong => assert!(
                        matches!(error.leaf(), Error::Malformed(message) if message.contains("returned 5 bytes for an exact 4-byte read"))
                    ),
                    ExactReadBehavior::Fail(message) => assert!(
                        matches!(error.leaf(), Error::Unsupported(actual) if actual == message)
                    ),
                    ExactReadBehavior::Exact => unreachable!(),
                }
            }
            assert_eq!(budget.spent(), 4);
            assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 1);
            assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 0);
        }

        let owner =
            AdversarialExactSource::new(ExactReadBehavior::Exact, ExactReadBehavior::Exact, None);
        let mut budget = ReadBudget::limited(0);
        assert!(read_exact_at(&owner, owner.size(), 0, &mut budget, &())
            .unwrap()
            .is_empty());
        assert_eq!(budget.spent(), 0);
    }

    #[test]
    fn exact_mismatch_is_typed_before_owner_error_construction() {
        let mismatch = validate_exact_read_length(ExactReadRoute::Shared, 9, 4, 3).unwrap_err();
        assert_eq!(
            mismatch,
            ExactReadLengthMismatch {
                route: ExactReadRoute::Shared,
                offset: 9,
                requested: 4,
                actual: 3,
            }
        );
        assert_eq!(mismatch.kind(), ExactReadLengthMismatchKind::Short);
        assert!(matches!(
            mismatch.into_default_error(),
            Error::Truncated {
                offset: 9,
                needed: 4,
                available: 3,
            }
        ));

        let overlong = validate_exact_read_length(ExactReadRoute::Owned, 7, 4, 5).unwrap_err();
        assert_eq!(overlong.kind(), ExactReadLengthMismatchKind::Overlong);
    }

    #[test]
    fn exact_read_helpers_apply_policy_to_both_routes() {
        let policy = ContextPolicy {
            read: "route-aware read",
            ..TEST_POLICY
        };
        let owner = AdversarialExactSource::new(
            ExactReadBehavior::Fail("owned failure"),
            ExactReadBehavior::Overlong,
            None,
        );

        let owned = read_exact_at(&owner, 1, 4, &mut ReadBudget::limited(4), &policy).unwrap_err();
        assert_eq!(
            owned.to_string(),
            "route-aware read: unsupported: owned failure"
        );
        let shared =
            read_shared_exact_at(&owner, 1, 4, &mut ReadBudget::limited(4), &policy).unwrap_err();
        assert_eq!(
            shared.to_string(),
            "route-aware read: source returned 5 bytes for an exact 4-byte read"
        );
        assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.shared_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn revalidated_exact_slice_zero_length_reads_are_still_revalidated() {
        let owner = Arc::new(AdversarialExactSource::new(
            ExactReadBehavior::Exact,
            ExactReadBehavior::Exact,
            None,
        ));
        let source = exact_slice(&owner);
        let mut budget = ReadBudget::limited(0);

        assert!(source
            .read_at(source.size(), 0, &mut budget)
            .unwrap()
            .is_empty());
        assert!(source
            .read_shared_at(source.size(), 0, &mut budget)
            .unwrap()
            .is_empty());
        assert_eq!(budget.spent(), 0);
        assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.shared_calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.requested_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn revalidated_exact_slice_rejects_short_overlong_and_failed_reads_on_both_routes() {
        for behavior in [
            ExactReadBehavior::Short,
            ExactReadBehavior::Overlong,
            ExactReadBehavior::Fail("injected read failure"),
        ] {
            for shared in [false, true] {
                let owner = Arc::new(AdversarialExactSource::new(
                    if shared {
                        ExactReadBehavior::Exact
                    } else {
                        behavior
                    },
                    if shared {
                        behavior
                    } else {
                        ExactReadBehavior::Exact
                    },
                    None,
                ));
                let source = exact_slice(&owner);
                let mut budget = ReadBudget::limited(4);
                let error = if shared {
                    source.read_shared_at(1, 4, &mut budget).unwrap_err()
                } else {
                    source.read_at(1, 4, &mut budget).unwrap_err()
                };

                match behavior {
                    ExactReadBehavior::Short => assert!(matches!(
                        error.leaf(),
                        Error::Truncated {
                            offset: 1,
                            needed: 4,
                            available: 3,
                        }
                    )),
                    ExactReadBehavior::Overlong => {
                        assert!(
                            matches!(error.leaf(), Error::Malformed(message) if message.contains("returned 5 bytes for an exact 4-byte read"))
                        )
                    }
                    ExactReadBehavior::Fail(message) => {
                        assert!(
                            matches!(error.leaf(), Error::Unsupported(actual) if actual == message)
                        )
                    }
                    ExactReadBehavior::Exact => unreachable!(),
                }
                assert_eq!(
                    error.contexts().collect::<Vec<_>>(),
                    vec![&ErrorContext::Component("owner stored read")]
                );
                assert_eq!(budget.spent(), 4);
                assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 3);
                assert_eq!(owner.owned_calls.load(Ordering::SeqCst), u64::from(!shared));
                assert_eq!(owner.shared_calls.load(Ordering::SeqCst), u64::from(shared));
            }
        }
    }

    #[test]
    fn revalidated_exact_slice_initial_failure_skips_read_and_charge() {
        for shared in [false, true] {
            let owner = Arc::new(AdversarialExactSource::new(
                ExactReadBehavior::Exact,
                ExactReadBehavior::Exact,
                Some((1, "changed before read")),
            ));
            let source = exact_slice(&owner);
            let mut budget = ReadBudget::limited(4);
            let error = if shared {
                source.read_shared_at(0, 4, &mut budget).unwrap_err()
            } else {
                source.read_at(0, 4, &mut budget).unwrap_err()
            };

            assert!(
                matches!(error.leaf(), Error::Malformed(message) if message == "changed before read")
            );
            assert_eq!(
                error.contexts().collect::<Vec<_>>(),
                vec![&ErrorContext::Component("owner stability")]
            );
            assert_eq!(budget.spent(), 0);
            assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 0);
            assert_eq!(owner.shared_calls.load(Ordering::SeqCst), 0);
            assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn revalidated_exact_slice_constructor_verifies_before_slice_validation() {
        let owner = Arc::new(AdversarialExactSource::new(
            ExactReadBehavior::Exact,
            ExactReadBehavior::Exact,
            Some((0, "changed before slice construction")),
        ));
        let owner_as_source: Arc<dyn RangeSource> = owner.clone();
        let error = RevalidatedExactSliceSource::with_policy(
            owner_as_source,
            u64::MAX,
            2,
            "invalid slice",
            TEST_POLICY,
        )
        .unwrap_err();

        assert!(
            matches!(error.leaf(), Error::Malformed(message) if message == "changed before slice construction")
        );
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![&ErrorContext::Component("owner initial stability")]
        );
        assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.shared_calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn revalidated_exact_slice_trailing_stability_failure_wins() {
        for behavior in [
            ExactReadBehavior::Exact,
            ExactReadBehavior::Short,
            ExactReadBehavior::Overlong,
            ExactReadBehavior::Fail("read also failed"),
        ] {
            for shared in [false, true] {
                let owner = Arc::new(AdversarialExactSource::new(
                    if shared {
                        ExactReadBehavior::Exact
                    } else {
                        behavior
                    },
                    if shared {
                        behavior
                    } else {
                        ExactReadBehavior::Exact
                    },
                    Some((2, "changed after read")),
                ));
                let source = exact_slice(&owner);
                let mut budget = ReadBudget::limited(4);
                let error = if shared {
                    source.read_shared_at(0, 4, &mut budget).unwrap_err()
                } else {
                    source.read_at(0, 4, &mut budget).unwrap_err()
                };

                assert!(
                    matches!(error.leaf(), Error::Malformed(message) if message == "changed after read")
                );
                assert_eq!(
                    error.contexts().collect::<Vec<_>>(),
                    vec![&ErrorContext::Component("owner stability")]
                );
                assert_eq!(budget.spent(), 4);
                assert_eq!(owner.owned_calls.load(Ordering::SeqCst), u64::from(!shared));
                assert_eq!(owner.shared_calls.load(Ordering::SeqCst), u64::from(shared));
                assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 3);
            }
        }
    }

    #[test]
    fn revalidated_exact_slice_invalid_ranges_are_checked_without_panics_or_reads() {
        let owner = Arc::new(AdversarialExactSource::new(
            ExactReadBehavior::Exact,
            ExactReadBehavior::Exact,
            None,
        ));
        let source = exact_slice(&owner);
        let mut budget = ReadBudget::limited(4);
        let error = source.read_at(u64::MAX, 2, &mut budget).unwrap_err();
        assert!(matches!(
            error.leaf(),
            Error::SourceRangeOutside {
                offset: u64::MAX,
                length: 2,
                source_size: 8,
            }
        ));
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![&ErrorContext::Component("owner stored read")]
        );
        assert_eq!(budget.spent(), 0);
        assert_eq!(owner.owned_calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 3);

        let owner_as_source: Arc<dyn RangeSource> = owner.clone();
        assert!(matches!(
            RevalidatedExactSliceSource::with_policy(
                owner_as_source,
                u64::MAX,
                2,
                "overflow",
                TEST_POLICY,
            ),
            Err(Error::Context { .. })
        ));
        assert_eq!(owner.verification_calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn transformed_slices_retain_recipe_and_root_dependency() {
        let root: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"HEADERcompressedTAIL".to_vec(),
            "carrier",
        ));
        let stored: Arc<dyn RangeSource> =
            Arc::new(SliceRangeSource::new(root, 6, 10, "member.bin").unwrap());
        let decoded: Arc<dyn RangeSource> = Arc::new(TransformedRangeSource::from_vec(
            b"decoded-leaf".to_vec(),
            stored,
            "example-codec",
            "decoded member.bin",
            "example-codec-v1",
        ));
        let leaf = SliceRangeSource::new(decoded, 8, 4, "leaf").unwrap();
        let mappings = leaf.coordinate_mappings();

        assert_eq!(mappings[0].precision, MappingPrecision::ExactAffine);
        assert_eq!(mappings[0].to, SourceRange::new(8, 4));
        assert!(mappings.iter().any(|mapping| {
            mapping.to_space.name == "member.bin"
                && mapping.precision == MappingPrecision::CoarseDependency
                && mapping.recipe_identity.as_deref() == Some("example-codec-v1")
        }));
        assert!(mappings.iter().any(|mapping| {
            mapping.to_space.name == "carrier"
                && mapping.to == SourceRange::new(6, 10)
                && mapping.precision == MappingPrecision::CoarseDependency
                && mapping.recipe_identity.as_deref() == Some("example-codec-v1")
        }));
    }

    #[test]
    fn transformed_source_can_name_one_bounded_parent_dependency() {
        let root: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"HEADcompressedTAIL".to_vec(),
            "carrier",
        ));
        let decoded = TransformedRangeSource::from_vec_with_dependency(
            b"decoded".to_vec(),
            root,
            SourceRange::new(4, 10),
            "codec",
            "decoded",
            "codec-v2",
        );
        assert_eq!(
            decoded.coordinate_mappings(),
            vec![CoordinateMappingDescription {
                from: SourceRange::new(0, 7),
                to_space: CoordinateSpaceDescription::bytes("artifact-local", "carrier", 18),
                to: SourceRange::new(4, 10),
                kind: "codec".into(),
                precision: MappingPrecision::CoarseDependency,
                recipe_identity: Some("codec-v2".into()),
            }]
        );
    }

    #[test]
    fn file_source_detects_path_replacement() {
        let directory = std::env::temp_dir().join(format!(
            "formatkit-core-range-source-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("source.bin");
        fs::write(&path, b"stable bytes").unwrap();
        let source = FileRangeSource::open(&path).unwrap();
        let mut budget = ReadBudget::limited(6);
        assert_eq!(source.read_at(0, 6, &mut budget).unwrap(), b"stable");

        let replacement = directory.join("replacement.bin");
        fs::write(&replacement, b"other bytes!").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(matches!(
            source.verify_unchanged(),
            Err(Error::SourceIdentityChanged { .. })
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn caller_bracketed_file_reads_skip_only_the_per_read_identity_check() {
        let directory = std::env::temp_dir().join(format!(
            "formatkit-core-bracketed-range-source-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("source.bin");
        fs::write(&path, b"stable bytes").unwrap();
        let source = FileRangeSource::open(&path).unwrap();
        assert!(source.supports_complete_io_accounting());
        source.verify_unchanged().unwrap();

        let replacement = directory.join("replacement.bin");
        fs::write(&replacement, b"other bytes!").unwrap();
        fs::rename(&replacement, &path).unwrap();

        let mut output = [0u8; 6];
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        source
            .read_exact_into_assuming_unchanged(0, &mut output, &mut budget)
            .unwrap();
        assert_eq!(&output, b"stable");
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 6);
        assert_eq!(budget.spent(WorkResource::IoReadCalls), 1);
        assert_eq!(budget.spent(WorkResource::IoRequestedBytes), 6);
        assert!(matches!(
            source.verify_unchanged(),
            Err(Error::SourceIdentityChanged { .. })
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_backing_identity_is_captured_from_open_descriptors() {
        let directory = std::env::temp_dir().join(format!(
            "formatkit-core-file-identity-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let primary_path = directory.join("primary.bin");
        let alias_path = directory.join("alias.bin");
        let other_path = directory.join("other.bin");
        fs::write(&primary_path, b"primary").unwrap();
        fs::write(&other_path, b"other!!").unwrap();
        fs::hard_link(&primary_path, &alias_path).unwrap();

        let primary = FileRangeSource::open(&primary_path).unwrap();
        let alias = FileRangeSource::open(&alias_path).unwrap();
        let other = FileRangeSource::open(&other_path).unwrap();
        assert!(primary.shares_file_backing(&alias).unwrap());
        assert!(!primary.shares_file_backing(&other).unwrap());

        // Rebind the primary pathname after all handles are open. Identity is
        // still the identity of the descriptors, not a fresh pathname stat.
        let parked_path = directory.join("parked.bin");
        fs::rename(&primary_path, &parked_path).unwrap();
        fs::rename(&other_path, &primary_path).unwrap();
        assert!(primary.shares_file_backing(&alias).unwrap());
        assert!(!primary.shares_file_backing(&other).unwrap());

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn file_backing_identity_uses_windows_open_handle_ids() {
        let directory = std::env::temp_dir().join(format!(
            "formatkit-core-file-identity-windows-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let primary_path = directory.join("primary.bin");
        let alias_path = directory.join("alias.bin");
        let other_path = directory.join("other.bin");
        fs::write(&primary_path, b"primary").unwrap();
        fs::hard_link(&primary_path, &alias_path).unwrap();
        fs::write(&other_path, b"other!!").unwrap();
        let primary = FileRangeSource::open(&primary_path).unwrap();
        let alias = FileRangeSource::open(&alias_path).unwrap();
        let other = FileRangeSource::open(&other_path).unwrap();
        assert!(primary.shares_file_backing(&alias).unwrap());
        assert!(!primary.shares_file_backing(&other).unwrap());
        drop((primary, alias, other));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn iter_ranges_uses_one_aggregate_budget() {
        let source = MemoryRangeSource::new(b"abcdefgh".to_vec(), "fixture");
        let mut budget = ReadBudget::limited(4);
        let values = source
            .iter_ranges(
                &[SourceRange::new(0, 2), SourceRange::new(6, 2)],
                &mut budget,
            )
            .unwrap();
        assert_eq!(values, vec![b"ab".to_vec(), b"gh".to_vec()]);
        assert_eq!(budget.spent(), 4);
    }

    #[test]
    fn composite_reads_across_mapped_ranges_and_sparse_holes() {
        let left: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(b"LEFT".to_vec(), "left"));
        let right: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"right".to_vec(), "right"));
        let source = CompositeRangeSource::new(
            vec![
                CompositeSegment::mapped(left, 1, 3).unwrap(),
                CompositeSegment::zero_filled(2),
                CompositeSegment::mapped(right, 0, 5).unwrap(),
            ],
            "carved",
        )
        .unwrap();
        let mut budget = ReadBudget::limited(8);

        assert_eq!(source.read_at(1, 8, &mut budget).unwrap(), b"FT\0\0righ");
        assert_eq!(budget.spent(), 8);
        assert_eq!(source.coordinate_mappings().len(), 2);
        assert_eq!(source.coordinate_mappings()[1].from, SourceRange::new(5, 5));
    }

    #[test]
    fn strided_source_maps_cooked_payloads_without_padding() {
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"__abcd--__efgh--".to_vec(),
            "raw-sectors",
        ));
        let cooked =
            StridedRangeSource::new(source, 0, 8, 2, 4, 2, "cooked-track", "track 1").unwrap();
        let mut budget = ReadBudget::limited(6);

        assert_eq!(cooked.read_at(2, 6, &mut budget).unwrap(), b"cdefgh");
        assert_eq!(cooked.size(), 8);
        let mapping = &cooked.coordinate_mappings()[0];
        assert_eq!(mapping.precision, MappingPrecision::Parametric);
        assert_eq!(mapping.to, SourceRange::new(0, 16));
    }

    #[test]
    fn materialization_is_bounded_hashed_and_never_overwrites() {
        let source = MemoryRangeSource::new(b"abc".to_vec(), "fixture");
        let mut budget = ReadBudget::limited(3);
        let memory = source
            .materialize(&MaterializationPolicy::Memory { max_bytes: 3 }, &mut budget)
            .unwrap();
        assert_eq!(
            memory.sha256(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(memory.size(), 3);

        let directory = std::env::temp_dir().join(format!(
            "formatkit-core-materialize-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("snapshot.bin");
        let file = source
            .materialize(
                &MaterializationPolicy::NewFile {
                    path: path.clone(),
                    max_bytes: 3,
                },
                &mut ReadBudget::limited(3),
            )
            .unwrap();
        assert_eq!(file.sha256(), memory.sha256());
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        assert!(source
            .materialize(
                &MaterializationPolicy::NewFile {
                    path: path.clone(),
                    max_bytes: 3,
                },
                &mut ReadBudget::limited(3),
            )
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn materialization_limit_fails_before_spending_budget() {
        let source = MemoryRangeSource::new(b"abcd".to_vec(), "fixture");
        let mut budget = ReadBudget::limited(100);
        assert!(matches!(
            source.materialize(&MaterializationPolicy::Memory { max_bytes: 3 }, &mut budget,),
            Err(Error::ResourceLimit {
                resource: "range-source materialization",
                requested: 4,
                limit: 3,
            })
        ));
        assert_eq!(budget.spent(), 0);
    }
}
