//! Accounting for a sequential operation and its nested scopes.
//!
//! Cumulative work survives errors and scope exit. Depth and resident bytes are
//! active observations which fall when their guards leave scope; their peaks
//! remain global to the whole budget. Owned retained permits extend the same
//! active resident total past the call which admitted them and release on
//! drop. Resident bytes are nominal, owner-declared retained-allocation
//! reservations, not allocator-observed heap usage, capacity, process memory,
//! or hidden codec work.
//!
//! Heterogeneous transform effort is deliberately not a shared dimension.
//! Owner-specific units cannot be summed or capped truthfully across unrelated
//! codecs. A future finite transform budget requires explicit owner-local scope
//! identity; until then, owners must keep such limits in their typed contracts.
//!
//! This is cooperative accounting for trusted in-process owners. Completeness
//! means participating APIs kept using the shared ledger and no persistent
//! replacement was detected; it is not a sandbox or proof against intentionally
//! dishonest code, uninstrumented side effects, or a transient swap restored
//! before a checked call returns.

use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::{Error, ReadBudget, Result};

/// Independently bounded cumulative dimensions.
///
/// Active resident bytes are deliberately not a `WorkResource`: cumulative
/// resources only increase, while a resident reservation is released on drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum WorkResource {
    LogicalReadBytes,
    IoRequestedBytes,
    IoReadCalls,
    MaterializedBytes,
    OutputBytes,
    Nodes,
    Members,
}

/// Cheap clonable signal for cooperative cancellation of trusted in-process
/// work.
///
/// Cancellation is sticky. Owners decide where to call
/// [`WorkBudget::check_cancelled`]; charging work does not implicitly check the
/// token. This is not thread or process isolation, and code which never checks
/// the token will continue running.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. The request cannot be cleared.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl WorkResource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LogicalReadBytes => "logical source bytes",
            Self::IoRequestedBytes => "underlying requested I/O bytes",
            Self::IoReadCalls => "underlying read calls",
            Self::MaterializedBytes => "materialized bytes",
            Self::OutputBytes => "output bytes",
            Self::Nodes => "nodes",
            Self::Members => "members",
        }
    }
}

const DIMENSIONS: usize = 7;

/// An explicit limit policy. `None` means that dimension is not limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkLimits {
    values: [Option<u64>; DIMENSIONS],
    depth: Option<u64>,
    resident_bytes: Option<u64>,
}

impl WorkLimits {
    /// No shared ceiling. Product entry points should normally add explicit
    /// limits for every resource they promise to bound.
    pub const fn unlimited() -> Self {
        Self {
            values: [None; DIMENSIONS],
            depth: None,
            resident_bytes: None,
        }
    }

    pub const fn with(mut self, resource: WorkResource, limit: u64) -> Self {
        self.values[resource as usize] = Some(limit);
        self
    }

    pub const fn with_depth(mut self, limit: u64) -> Self {
        self.depth = Some(limit);
        self
    }

    /// Set the ceiling for simultaneously active, nominal owner-declared
    /// retained-allocation bytes.
    pub const fn with_resident_bytes(mut self, limit: u64) -> Self {
        self.resident_bytes = Some(limit);
        self
    }

    /// The configured cumulative ceiling for one resource.
    pub const fn limit(self, resource: WorkResource) -> Option<u64> {
        self.values[resource as usize]
    }

    /// The configured active nesting ceiling.
    pub const fn depth_limit(self) -> Option<u64> {
        self.depth
    }

    /// The configured ceiling for simultaneously active nominal retained bytes.
    pub const fn resident_bytes_limit(self) -> Option<u64> {
        self.resident_bytes
    }
}

/// Point-in-time, allocation-free copy of one [`WorkBudget`]'s observations.
///
/// Cumulative resource values describe admitted work, including work admitted
/// before a later operation failure. `io_completed_bytes` counts only bytes
/// returned by successful underlying reads. Active depth can fall after a
/// snapshot while peak depth is retained. Resident-byte values describe active,
/// nominal owner-declared retained-allocation reservations. They are not
/// allocator-observed heap usage or capacity, and do not establish an exact
/// process-memory bound. Peaks are global observations retained across child
/// scopes and guard drops. This value does not claim to measure hidden codec
/// work or wall-clock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkUsage {
    limits: WorkLimits,
    spent: [u64; DIMENSIONS],
    active_depth: u64,
    peak_depth: u64,
    resident_bytes: u64,
    peak_resident_bytes: u64,
    io_completed_bytes: u64,
    complete_logical_read_accounting: bool,
    complete_io_accounting: bool,
    complete_resident_accounting: bool,
    cancellation_requested: bool,
    cancellation_observed: bool,
}

impl WorkUsage {
    /// The complete limit policy in effect when the snapshot was taken.
    pub const fn limits(self) -> WorkLimits {
        self.limits
    }

    /// The configured cumulative ceiling for one resource.
    pub const fn limit(self, resource: WorkResource) -> Option<u64> {
        self.limits.limit(resource)
    }

    /// Cumulative admitted work for one resource.
    pub const fn spent(self, resource: WorkResource) -> u64 {
        self.spent[resource as usize]
    }

    /// Remaining cumulative allowance, or `None` when the resource is
    /// unlimited. This value saturates at zero for defensive reporting.
    pub const fn remaining(self, resource: WorkResource) -> Option<u64> {
        match self.limit(resource) {
            Some(limit) => Some(limit.saturating_sub(self.spent(resource))),
            None => None,
        }
    }

    /// The configured active nesting ceiling.
    pub const fn depth_limit(self) -> Option<u64> {
        self.limits.depth_limit()
    }

    /// Active nesting when the snapshot was taken.
    pub const fn active_depth(self) -> u64 {
        self.active_depth
    }

    /// Highest active nesting observed by the budget.
    pub const fn peak_depth(self) -> u64 {
        self.peak_depth
    }

    /// The configured ceiling for simultaneously active nominal retained bytes.
    pub const fn resident_bytes_limit(self) -> Option<u64> {
        self.limits.resident_bytes_limit()
    }

    /// Nominal owner-declared retained-allocation bytes active when the snapshot
    /// was taken. This is not allocator-observed heap usage or capacity.
    pub const fn resident_bytes(self) -> u64 {
        self.resident_bytes
    }

    /// Remaining nominal retained-allocation allowance, or `None` when
    /// unlimited.
    pub const fn remaining_resident_bytes(self) -> Option<u64> {
        match self.resident_bytes_limit() {
            Some(limit) => Some(limit.saturating_sub(self.resident_bytes)),
            None => None,
        }
    }

    /// Highest simultaneous nominal retained-allocation reservation observed
    /// globally by the budget, including reservations made inside child scopes.
    pub const fn peak_resident_bytes(self) -> u64 {
        self.peak_resident_bytes
    }

    /// Bytes actually returned by instrumented underlying reads.
    pub const fn io_completed_bytes(self) -> u64 {
        self.io_completed_bytes
    }

    /// Whether every underlying read taken so far was instrumented.
    pub const fn complete_io_accounting(self) -> bool {
        self.complete_io_accounting
    }

    /// Whether every legacy read-budget bridge retained its private continuity
    /// identity through the callback boundary.
    pub const fn complete_logical_read_accounting(self) -> bool {
        self.complete_logical_read_accounting
    }

    /// Whether cooperating resident guards have preserved their private ledger
    /// identity.
    ///
    /// This becomes false when a guard detects that mutable budget access
    /// replaced the entire [`WorkBudget`]. Such replacement is unsupported: it
    /// severs the guard from the state against which its allowance was admitted.
    /// A false value is sticky for that replacement budget and means resident
    /// observations are incomplete. Matching public counters cannot forge the
    /// private identity of a persistently replaced ledger.
    ///
    /// `true` is a cooperative-accounting observation, not a security proof.
    /// Trusted in-process code can ignore instrumentation or transiently swap
    /// and restore a ledger within one callback; preventing deliberate evasion
    /// would require an isolation boundary outside this API.
    pub const fn complete_resident_accounting(self) -> bool {
        self.complete_resident_accounting
    }

    /// Whether the attached cooperative token had been cancelled when this
    /// snapshot was taken.
    pub const fn cancellation_requested(self) -> bool {
        self.cancellation_requested
    }

    /// Whether this budget has returned a typed cancellation error from an
    /// explicit check. This observation is sticky even if later work ignores
    /// the request.
    pub const fn cancellation_observed(self) -> bool {
        self.cancellation_observed
    }
}

/// A non-clonable cooperative budget shared by sequential child operations.
///
/// Owners and callbacks are trusted to route relevant work through this ledger.
/// It detects accidental limit violations and persistent ledger replacement;
/// it does not sandbox intentionally dishonest in-process code or account for
/// side effects which participating APIs choose not to report.
#[derive(Debug)]
pub struct WorkBudget {
    limits: WorkLimits,
    spent: [u64; DIMENSIONS],
    depth: u64,
    peak_depth: u64,
    resident_bytes: u64,
    peak_resident_bytes: u64,
    forwarded_read: bool,
    io_completed_bytes: u64,
    complete_logical_read_accounting: bool,
    complete_io_accounting: bool,
    active_resident_reservations: u64,
    complete_resident_accounting: bool,
    ledger_identity: Option<Arc<()>>,
    retained_resident: Option<Arc<SharedRetainedResident>>,
    cancellation: Option<CancellationToken>,
    cancellation_observed: bool,
}

/// Live total of owned retained-resident permits issued by one ledger.
///
/// Borrowed [`ResidentReservation`] guards release back into their ledger
/// through exclusive access. Owned [`RetainedResidentPermit`] values cannot
/// borrow the ledger they outlive, so they share only this counter: the
/// ledger observes it on every resident admission and observation, and each
/// permit releases its amount when dropped. Permits are order-free and never
/// participate in the guard stack's LIFO discipline.
#[derive(Debug, Default)]
struct SharedRetainedResident {
    outstanding: AtomicU64,
}

impl WorkBudget {
    pub const fn new(limits: WorkLimits) -> Self {
        Self {
            limits,
            spent: [0; DIMENSIONS],
            depth: 0,
            peak_depth: 0,
            resident_bytes: 0,
            peak_resident_bytes: 0,
            forwarded_read: false,
            io_completed_bytes: 0,
            complete_logical_read_accounting: true,
            complete_io_accounting: true,
            active_resident_reservations: 0,
            complete_resident_accounting: true,
            ledger_identity: None,
            retained_resident: None,
            cancellation: None,
            cancellation_observed: false,
        }
    }

    /// Attach one cooperative cancellation signal to this sequential ledger.
    /// Child scopes, resident guards, and compatibility bridges continue to use
    /// the same budget and therefore observe the same token.
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Whether the attached token currently requests cancellation.
    pub fn cancellation_requested(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    }

    /// Whether an explicit check on this budget has observed cancellation.
    pub const fn cancellation_observed(&self) -> bool {
        self.cancellation_observed
    }

    /// Observe the cooperative token at an owner-selected interruption point.
    ///
    /// This method performs only an `Option` branch when no token is attached.
    /// Cancellation is sticky and returns [`Error::Cancelled`]. Work charging
    /// deliberately does not call this method implicitly.
    pub fn check_cancelled(&mut self) -> Result<()> {
        if self.cancellation_requested() {
            self.cancellation_observed = true;
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn spent(&self, resource: WorkResource) -> u64 {
        self.spent[resource as usize]
    }
    pub fn remaining(&self, resource: WorkResource) -> Option<u64> {
        self.limits.values[resource as usize]
            .map(|limit| limit.saturating_sub(self.spent(resource)))
    }

    /// Whether the caller selected a finite ceiling for one resource.
    ///
    /// Compatibility adapters use this to refuse work whose underlying
    /// implementation cannot honestly account a requested dimension.
    pub const fn is_limited(&self, resource: WorkResource) -> bool {
        self.limits.values[resource as usize].is_some()
    }
    pub fn depth(&self) -> u64 {
        self.depth
    }
    pub fn peak_depth(&self) -> u64 {
        self.peak_depth
    }
    pub fn io_completed_bytes(&self) -> u64 {
        self.io_completed_bytes
    }
    pub fn complete_io_accounting(&self) -> bool {
        self.complete_io_accounting
    }

    /// Nominal retained-allocation bytes currently held by owned permits.
    ///
    /// This is the live [`RetainedResidentPermit`] total only; borrowed guard
    /// bytes are reported separately by [`WorkUsage::resident_bytes`], which
    /// sums both holdings.
    pub fn retained_resident_bytes(&self) -> u64 {
        self.retained_outstanding()
    }

    fn retained_outstanding(&self) -> u64 {
        self.retained_resident
            .as_ref()
            .map_or(0, |shared| shared.outstanding.load(Ordering::Acquire))
    }

    /// Total active nominal retained bytes: borrowed guards plus live owned
    /// permits. Admission uses the checked form and reports overflow; this
    /// saturating form is for defensive observation only.
    fn total_resident_bytes(&self) -> u64 {
        self.resident_bytes
            .saturating_add(self.retained_outstanding())
    }

    fn checked_total_resident_bytes(&self, additional: u64) -> Result<u64> {
        self.resident_bytes
            .checked_add(self.retained_outstanding())
            .and_then(|current| current.checked_add(additional))
            .ok_or_else(|| Error::Malformed("resident byte accounting overflow".into()))
    }

    /// Remaining nominal retained-allocation allowance, or `None` when
    /// unlimited. Live owned permits consume the same allowance as guards.
    pub fn remaining_resident_bytes(&self) -> Option<u64> {
        self.limits
            .resident_bytes
            .map(|limit| limit.saturating_sub(self.total_resident_bytes()))
    }

    /// Copy the current limits and observations without resetting the budget.
    ///
    /// The returned value owns no allowance and cannot be used to charge work.
    /// Later changes to this budget do not modify an earlier snapshot.
    pub fn usage(&self) -> WorkUsage {
        WorkUsage {
            limits: self.limits,
            spent: self.spent,
            active_depth: self.depth,
            peak_depth: self.peak_depth,
            resident_bytes: self.total_resident_bytes(),
            peak_resident_bytes: self.peak_resident_bytes,
            io_completed_bytes: self.io_completed_bytes,
            complete_logical_read_accounting: self.complete_logical_read_accounting,
            complete_io_accounting: self.complete_io_accounting,
            complete_resident_accounting: self.complete_resident_accounting,
            cancellation_requested: self.cancellation_requested(),
            cancellation_observed: self.cancellation_observed,
        }
    }

    pub fn check(&self, resource: WorkResource, amount: u64) -> Result<u64> {
        let requested = self
            .spent(resource)
            .checked_add(amount)
            .ok_or_else(|| Error::Malformed(format!("{} accounting overflow", resource.label())))?;
        if let Some(limit) = self.limits.values[resource as usize] {
            if requested > limit {
                return Err(Error::ResourceLimit {
                    resource: resource.label(),
                    requested,
                    limit,
                });
            }
        }
        Ok(requested)
    }

    pub fn charge(&mut self, resource: WorkResource, amount: u64) -> Result<()> {
        self.spent[resource as usize] = self.check(resource, amount)?;
        Ok(())
    }

    /// Admit a known stage's cumulative work atomically, checking cancellation
    /// first. Repeated dimensions are summed with checked arithmetic. A denied
    /// stage spends nothing; earlier successful stages remain charged.
    ///
    /// This does not predict data-dependent work or reserve resident storage.
    /// Callers must not charge these same units again when executing the stage.
    pub fn charge_batch(&mut self, charges: &[(WorkResource, u64)]) -> Result<()> {
        self.check_cancelled()?;
        let mut next = self.spent;
        for &(resource, amount) in charges {
            let requested =
                next[resource as usize]
                    .checked_add(amount)
                    .ok_or(Error::ResourceLimit {
                        resource: resource.label(),
                        requested: u64::MAX,
                        limit: self.limits.limit(resource).unwrap_or(u64::MAX),
                    })?;
            if let Some(limit) = self.limits.limit(resource) {
                if requested > limit {
                    return Err(Error::ResourceLimit {
                        resource: resource.label(),
                        requested,
                        limit,
                    });
                }
            }
            next[resource as usize] = requested;
        }
        self.spent = next;
        Ok(())
    }

    /// Run one legacy logical-read operation against this ledger.
    ///
    /// This compatibility bridge lends an operation-local [`ReadBudget`] capped
    /// at the parent's remaining logical-byte allowance. Its admitted spend is
    /// transferred back on success and error, so legacy and native operations
    /// consume one cumulative allowance. The exclusive borrow prevents the
    /// parent from being charged simultaneously. Bridge-limit errors regain the
    /// parent's `logical source bytes` label and absolute diagnostics while
    /// preserving structured context frames.
    ///
    /// The temporary value is an adapter, not a second independent allowance.
    /// Other work dimensions are unavailable to the legacy operation. In
    /// particular, entering this bridge marks physical-I/O accounting
    /// incomplete and rejects a parent with finite physical-I/O ceilings before
    /// invoking the callback. The parent cancellation token is checked before
    /// and after the callback. An
    /// operation error retains precedence over cancellation requested during
    /// that operation, while admitted bytes are transferred in either case.
    /// A private continuity identity rejects a fresh budget which remains in
    /// place at the callback boundary and marks logical-read accounting
    /// incomplete. As with the parent ledger, this is cooperative misuse
    /// detection rather than a sandbox against deliberate swap-and-restore.
    pub fn with_read_budget<T>(
        &mut self,
        operation: impl FnOnce(&mut ReadBudget) -> Result<T>,
    ) -> Result<T> {
        self.check_cancelled()?;
        // ReadBudget observes logical admission only. Any physical reads made
        // by the legacy callback are therefore outside this ledger's I/O-call
        // and requested-byte observations. Finite physical-I/O policy cannot
        // be promised across this compatibility boundary.
        self.mark_uninstrumented_io()?;
        let base_spent = self.spent(WorkResource::LogicalReadBytes);
        let parent_limit = self.limits.limit(WorkResource::LogicalReadBytes);
        // An unlimited parent still has a finite u64 counter. Exposing exactly
        // that remaining numeric domain makes overflow fail before transfer.
        let additional_limit = self
            .remaining(WorkResource::LogicalReadBytes)
            .unwrap_or_else(|| u64::MAX.saturating_sub(base_spent));
        let bridge_identity = Arc::new(());
        let mut legacy = ReadBudget::bridged(additional_limit, Arc::clone(&bridge_identity));
        let result = operation(&mut legacy);
        if !legacy.has_bridge_identity(&bridge_identity) {
            self.complete_logical_read_accounting = false;
            // Observation remains sticky even though continuity failure has
            // diagnostic precedence over concurrent cancellation.
            let _ = self.check_cancelled();
            return Err(Error::Malformed(
                "legacy read-budget bridge was replaced".into(),
            ));
        }
        let admitted = legacy.spent();
        // Honest ReadBudget operations cannot exceed the temporary ceiling, so
        // this transfer retains the callback's result and cannot partially fail.
        self.charge(WorkResource::LogicalReadBytes, admitted)?;
        let result = result.map_err(|error| {
            map_legacy_read_error(error, base_spent, parent_limit, additional_limit)
        });
        let cancellation = self.check_cancelled();
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                cancellation?;
                Ok(value)
            }
        }
    }

    /// Import work already admitted by a standalone legacy [`ReadBudget`].
    ///
    /// This compatibility path retains the logical spend but cannot reconstruct
    /// physical read calls or requested/completed byte observations. It marks
    /// physical-I/O accounting incomplete even when importing the logical spend
    /// subsequently fails. A parent with finite physical-I/O ceilings is
    /// rejected because those ceilings could not have been enforced before the
    /// legacy work occurred.
    pub fn absorb_read_budget(&mut self, reads: ReadBudget) -> Result<()> {
        self.complete_io_accounting = false;
        self.charge(WorkResource::LogicalReadBytes, reads.spent())?;
        if self.limits.values[WorkResource::IoReadCalls as usize].is_some()
            || self.limits.values[WorkResource::IoRequestedBytes as usize].is_some()
        {
            return Err(Error::Unsupported(
                "legacy reads cannot satisfy finite physical-I/O limits".into(),
            ));
        }
        Ok(())
    }

    /// Restrict a child to additional work without resetting parent totals.
    /// Dropping the guard restores ceilings on success, error, or unwinding.
    pub fn scope(&mut self, local: WorkLimits) -> Result<WorkScope<'_>> {
        let previous = self.limits;
        let mut next = previous;
        for (index, local_limit) in local.values.iter().enumerate() {
            if let Some(amount) = local_limit {
                let end = self.spent[index]
                    .checked_add(*amount)
                    .ok_or_else(|| Error::Malformed("child work ceiling overflow".into()))?;
                next.values[index] =
                    Some(previous.values[index].map_or(end, |limit| limit.min(end)));
            }
        }
        if let Some(additional) = local.depth {
            let end = self
                .depth
                .checked_add(additional)
                .ok_or_else(|| Error::Malformed("child depth ceiling overflow".into()))?;
            next.depth = Some(previous.depth.map_or(end, |limit| limit.min(end)));
        }
        if let Some(additional) = local.resident_bytes {
            // A child scope grants additional bytes above the live total:
            // borrowed guards plus outstanding owned permits. Deriving from
            // the borrowed total alone would spuriously deny valid scoped
            // admissions while a permit is live.
            let end = self
                .checked_total_resident_bytes(additional)
                .map_err(|_| Error::Malformed("child resident byte ceiling overflow".into()))?;
            next.resident_bytes = Some(previous.resident_bytes.map_or(end, |limit| limit.min(end)));
        }
        self.limits = next;
        Ok(WorkScope {
            budget: self,
            previous,
        })
    }

    pub fn enter_depth(&mut self) -> Result<DepthScope<'_>> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or_else(|| Error::Malformed("work depth overflow".into()))?;
        if let Some(limit) = self.limits.depth {
            if next > limit {
                return Err(Error::ResourceLimit {
                    resource: "work depth",
                    requested: next,
                    limit,
                });
            }
        }
        self.depth = next;
        self.peak_depth = self.peak_depth.max(next);
        Ok(DepthScope { budget: self })
    }

    /// Reserve nominal owner-declared retained-allocation bytes which remain
    /// active for the returned guard's lifetime.
    ///
    /// Allocate only after this succeeds, keep the guard until the allocation
    /// is released, and perform subsequent work through its proxy methods or
    /// checked [`ResidentReservation::with_budget`] bridge. Reads, nested scopes,
    /// and nested resident reservations continue to consume one ledger.
    /// The guard may be grown or partially released as the corresponding live
    /// allocation changes. Dropping it releases its remaining current resident
    /// bytes while peak usage remains visible.
    ///
    /// No raw mutable budget reference can escape the guard. For cooperative
    /// callers, the checked bridge detects a whole-budget replacement that
    /// remains at the call boundary using private per-ledger identity, avoids
    /// subtracting from unrelated state, and marks resident accounting
    /// incomplete. This is accidental-misuse hardening, not a sandbox against a
    /// callback which deliberately evades accounting.
    pub fn reserve_resident(&mut self, amount: u64) -> Result<ResidentReservation<'_>> {
        let requested = self.checked_total_resident_bytes(amount)?;
        let reservation_depth = self
            .active_resident_reservations
            .checked_add(1)
            .ok_or_else(|| Error::Malformed("resident reservation depth overflow".into()))?;
        if let Some(limit) = self.limits.resident_bytes {
            if requested > limit {
                return Err(Error::ResourceLimit {
                    resource: "resident bytes",
                    requested,
                    limit,
                });
            }
        }
        self.resident_bytes = self
            .resident_bytes
            .checked_add(amount)
            .ok_or_else(|| Error::Malformed("resident byte accounting overflow".into()))?;
        self.peak_resident_bytes = self.peak_resident_bytes.max(requested);
        self.active_resident_reservations = reservation_depth;
        let ledger_identity = Arc::clone(self.ledger_identity.get_or_insert_with(|| Arc::new(())));
        Ok(ResidentReservation {
            budget: self,
            amount,
            reservation_depth,
            ledger_identity,
        })
    }

    /// Admit nominal owner-declared retained-allocation bytes as an owned
    /// permit which outlives this call.
    ///
    /// Borrowed [`ResidentReservation`] guards cannot be stored in a returned
    /// namespace or any other owned value: they mutably borrow this ledger.
    /// A permit instead shares only a live counter with the ledger. It
    /// consumes the same resident ceiling as guards (admission observes both
    /// holdings), contributes to the same global peak, and releases its
    /// amount when dropped. Permits are order-free: they never join the guard
    /// stack and need no LIFO discipline.
    ///
    /// Keep the permit alive exactly as long as the corresponding allocation.
    /// Dropping it early under-reports live residency; leaking it
    /// over-reports. A permit which outlives its ledger keeps only its own
    /// counter alive and releases harmlessly. Like every ledger API this is
    /// cooperative accounting, not a sandbox against dishonest code.
    ///
    /// The shared counter uses a safe standard `Arc` allocated once on first
    /// use. Its fixed bookkeeping overhead is excluded from payload accounting;
    /// this API does not promise recovery from process-wide allocator exhaustion.
    pub fn retain_resident(&mut self, amount: u64) -> Result<RetainedResidentPermit> {
        self.check_cancelled()?;
        let requested = self.checked_total_resident_bytes(amount)?;
        if let Some(limit) = self.limits.resident_bytes {
            if requested > limit {
                return Err(Error::ResourceLimit {
                    resource: "resident bytes",
                    requested,
                    limit,
                });
            }
        }
        self.peak_resident_bytes = self.peak_resident_bytes.max(requested);
        let shared = self
            .retained_resident
            .get_or_insert_with(|| Arc::new(SharedRetainedResident::default()));
        shared.outstanding.fetch_add(amount, Ordering::AcqRel);
        Ok(RetainedResidentPermit {
            shared: Arc::clone(shared),
            amount,
        })
    }

    /// Fill an existing buffer from an external sequential reader while
    /// retaining this ledger's physical-I/O and cancellation accounting.
    ///
    /// Each underlying attempt atomically admits one call and all bytes passed
    /// to `Read::read` before invoking the reader. Successfully returned bytes
    /// are recorded even when a later attempt fails. Cancellation is checked
    /// before each admission; a resource denial therefore happens before the
    /// corresponding I/O, while an admitted reader error retains its typed
    /// operation context. Interrupted attempts remain admitted attempts and
    /// are retried. This method neither allocates nor charges logical reads:
    /// the caller owns the meaning and resident storage of `output`.
    pub fn read_external_exact_into(
        &mut self,
        reader: &mut impl Read,
        mut output: &mut [u8],
    ) -> Result<()> {
        while !output.is_empty() {
            self.check_cancelled()?;
            self.io_attempt(output.len() as u64)?;
            match reader.read(output) {
                Ok(0) => {
                    return Err(Error::Malformed(
                        "unexpected EOF reading external input".into(),
                    ))
                }
                Ok(size) if size <= output.len() => {
                    self.io_completed(size as u64);
                    output = &mut output[size..];
                }
                Ok(size) => {
                    return Err(Error::Malformed(format!(
                        "external reader returned {size} bytes for a {}-byte buffer",
                        output.len()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(Error::Malformed(format!("read external input: {error}")))
                }
            }
        }
        Ok(())
    }

    pub(crate) fn logical_read(&mut self, length: u64) -> Result<()> {
        if self.forwarded_read {
            Ok(())
        } else {
            self.charge(WorkResource::LogicalReadBytes, length)
        }
    }

    pub(crate) fn forward<T>(&mut self, read: impl FnOnce(&mut Self) -> T) -> T {
        struct Forward<'a> {
            budget: &'a mut WorkBudget,
            previous: bool,
        }
        impl Drop for Forward<'_> {
            fn drop(&mut self) {
                self.budget.forwarded_read = self.previous;
            }
        }
        let previous = self.forwarded_read;
        self.forwarded_read = true;
        let guard = Forward {
            budget: self,
            previous,
        };
        read(guard.budget)
    }

    /// Execute one transformed logical read while charging its requested
    /// output exactly once. Reads performed by `operation` are forwarded: they
    /// retain physical-I/O accounting but do not charge their encoded bytes as
    /// additional logical output.
    ///
    /// Transforming [`RangeSource`](crate::RangeSource) implementations should
    /// validate their logical bounds before calling this helper. The logical
    /// charge is admitted before any encoded input is read or decoded.
    pub fn with_transformed_read<T>(
        &mut self,
        logical_length: u64,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.check_cancelled()?;
        self.logical_read(logical_length)?;
        let result = self.forward(operation);
        let cancellation = self.check_cancelled();
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                cancellation?;
                Ok(value)
            }
        }
    }

    /// Admit both dimensions atomically before one underlying read attempt.
    pub(crate) fn io_attempt(&mut self, length: u64) -> Result<()> {
        let calls = self.check(WorkResource::IoReadCalls, 1)?;
        let bytes = self.check(WorkResource::IoRequestedBytes, length)?;
        self.spent[WorkResource::IoReadCalls as usize] = calls;
        self.spent[WorkResource::IoRequestedBytes as usize] = bytes;
        Ok(())
    }

    pub(crate) fn io_completed(&mut self, length: u64) {
        // Completed bytes cannot exceed the previously admitted requested bytes.
        self.io_completed_bytes += length;
    }

    pub(crate) fn mark_uninstrumented_io(&mut self) -> Result<()> {
        if self.limits.values[WorkResource::IoReadCalls as usize].is_some()
            || self.limits.values[WorkResource::IoRequestedBytes as usize].is_some()
        {
            return Err(Error::Unsupported(
                "source does not expose underlying I/O accounting".into(),
            ));
        }
        self.complete_io_accounting = false;
        Ok(())
    }
}

fn map_legacy_read_error(
    error: Error,
    base_spent: u64,
    parent_limit: Option<u64>,
    bridge_limit: u64,
) -> Error {
    match error {
        Error::Context { frame, source } => Error::Context {
            frame,
            source: Box::new(map_legacy_read_error(
                *source,
                base_spent,
                parent_limit,
                bridge_limit,
            )),
        },
        Error::ResourceLimit {
            resource: "range-source bytes",
            requested,
            limit,
        } if limit == bridge_limit => match (parent_limit, base_spent.checked_add(requested)) {
            (_, None) => Error::Malformed("logical source bytes accounting overflow".into()),
            (Some(limit), Some(requested)) => Error::ResourceLimit {
                resource: WorkResource::LogicalReadBytes.label(),
                requested,
                limit,
            },
            (None, Some(_)) => Error::ResourceLimit {
                resource: WorkResource::LogicalReadBytes.label(),
                requested,
                limit,
            },
        },
        Error::Malformed(message) if message == "byte-read budget overflows u64" => {
            Error::Malformed("logical source bytes accounting overflow".into())
        }
        error => error,
    }
}

#[must_use = "the work scope restores its parent limits when dropped"]
pub struct WorkScope<'a> {
    budget: &'a mut WorkBudget,
    previous: WorkLimits,
}
impl Deref for WorkScope<'_> {
    type Target = WorkBudget;
    fn deref(&self) -> &WorkBudget {
        self.budget
    }
}
impl DerefMut for WorkScope<'_> {
    fn deref_mut(&mut self) -> &mut WorkBudget {
        self.budget
    }
}
impl Drop for WorkScope<'_> {
    fn drop(&mut self) {
        self.budget.limits = self.previous;
    }
}

#[must_use = "the depth scope releases active nesting when dropped"]
pub struct DepthScope<'a> {
    budget: &'a mut WorkBudget,
}
impl Deref for DepthScope<'_> {
    type Target = WorkBudget;
    fn deref(&self) -> &WorkBudget {
        self.budget
    }
}
impl DerefMut for DepthScope<'_> {
    fn deref_mut(&mut self) -> &mut WorkBudget {
        self.budget
    }
}
impl Drop for DepthScope<'_> {
    fn drop(&mut self) {
        self.budget.depth -= 1;
    }
}

/// Live nominal retained-allocation reservation over one sequential
/// [`WorkBudget`].
///
/// Continue using the budget through this guard while the corresponding memory
/// is retained. Owners declare the nominal byte amount; it is not observed from
/// an allocator and need not equal heap capacity. Nested guards reserve against
/// the same current and global peak totals. In this sequential v1 API,
/// exclusive borrowing enforces stack/LIFO release. In-place resizing of one
/// guard is supported through growth and partial release. Already-admitted
/// bytes may transfer to an owned permit without a release/re-admission gap;
/// the remaining borrowed guard must still follow stack discipline.
#[must_use = "dropping the reservation immediately releases its resident-byte allowance"]
pub struct ResidentReservation<'a> {
    budget: &'a mut WorkBudget,
    amount: u64,
    reservation_depth: u64,
    ledger_identity: Arc<()>,
}

impl ResidentReservation<'_> {
    fn verify_ledger(&mut self) -> Result<()> {
        if self
            .budget
            .ledger_identity
            .as_ref()
            .is_none_or(|identity| !Arc::ptr_eq(identity, &self.ledger_identity))
            || self.budget.active_resident_reservations != self.reservation_depth
            || self.budget.resident_bytes < self.amount
        {
            self.budget.complete_resident_accounting = false;
            return Err(Error::Malformed(
                "resident reservation ledger was replaced".into(),
            ));
        }
        Ok(())
    }

    /// Run an API which requires the underlying sequential budget without
    /// allowing that mutable reference to escape this checked call.
    ///
    /// Replacing the complete budget inside `operation` is unsupported and a
    /// replacement still present at the call boundary returns a typed error.
    /// The private ledger identity is not reproducible through safe public APIs,
    /// even when replacement state has matching counters. Replacement detection
    /// takes precedence over the callback result. Unwinding is checked by this
    /// guard's `Drop`.
    ///
    /// This bridge assumes a cooperative, trusted in-process operation. It does
    /// not prove that the callback reported every side effect, nor detect a
    /// deliberate transient swap which is restored before returning. Enforcing
    /// that threat model requires isolation rather than a Rust proxy.
    pub fn with_budget<T>(
        &mut self,
        operation: impl for<'budget> FnOnce(&'budget mut WorkBudget) -> Result<T>,
    ) -> Result<T> {
        self.verify_ledger()?;
        let result = operation(self.budget);
        self.verify_ledger()?;
        result
    }

    /// Typed-error variant of [`Self::with_budget`] for executors which must
    /// retain an operation-specific error enum (for example a source-copy
    /// write or cancellation error). Ledger failures are converted into `E`;
    /// a replacement detected after the callback retains guard precedence.
    pub fn with_budget_typed<T, E>(
        &mut self,
        operation: impl for<'budget> FnOnce(&'budget mut WorkBudget) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.verify_ledger().map_err(E::from)?;
        let result = operation(self.budget);
        self.verify_ledger().map_err(E::from)?;
        result
    }

    /// Charge cumulative work to the same sequential ledger.
    pub fn charge(&mut self, resource: WorkResource, amount: u64) -> Result<()> {
        self.verify_ledger()?;
        self.budget.charge(resource, amount)
    }

    /// Check the cooperative cancellation token on the same sequential ledger.
    pub fn check_cancelled(&mut self) -> Result<()> {
        self.verify_ledger()?;
        self.budget.check_cancelled()
    }

    /// Reserve another nominal retained allocation on the same ledger.
    pub fn reserve_resident(&mut self, amount: u64) -> Result<ResidentReservation<'_>> {
        self.verify_ledger()?;
        self.budget.reserve_resident(amount)
    }

    /// Add `additional` active bytes to this reservation.
    ///
    /// The configured resident ceiling and arithmetic bounds are checked before
    /// either this guard or its budget is changed. A denied growth is atomic:
    /// current and peak usage remain unchanged.
    pub fn try_grow(&mut self, additional: u64) -> Result<()> {
        self.verify_ledger()?;
        let requested = self.budget.checked_total_resident_bytes(additional)?;
        let amount = self
            .amount
            .checked_add(additional)
            .ok_or_else(|| Error::Malformed("resident reservation accounting overflow".into()))?;
        if let Some(limit) = self.budget.limits.resident_bytes {
            if requested > limit {
                return Err(Error::ResourceLimit {
                    resource: "resident bytes",
                    requested,
                    limit,
                });
            }
        }
        self.budget.resident_bytes = self
            .budget
            .resident_bytes
            .checked_add(additional)
            .ok_or_else(|| Error::Malformed("resident byte accounting overflow".into()))?;
        self.budget.peak_resident_bytes = self.budget.peak_resident_bytes.max(requested);
        self.amount = amount;
        Ok(())
    }

    /// Move already-admitted bytes into an owned permit without releasing them
    /// or spending work again. The total and historical peak do not change.
    ///
    /// Useful when a construction guard returns owned output. Cancellation or
    /// an invalid amount leaves this guard's complete allowance intact. Only
    /// this guard's own bytes can move, never other live permits' allowances.
    pub fn transfer_retained(&mut self, amount: u64) -> Result<RetainedResidentPermit> {
        self.verify_ledger()?;
        self.budget.check_cancelled()?;
        if amount > self.amount {
            return Err(Error::ResourceLimit {
                resource: "resident reservation transfer bytes",
                requested: amount,
                limit: self.amount,
            });
        }
        let shared = self
            .budget
            .retained_resident
            .get_or_insert_with(|| Arc::new(SharedRetainedResident::default()));
        // The ledger is exclusively borrowed and the combined total already
        // admitted these bytes. Other threads may only drop owned permits.
        shared.outstanding.fetch_add(amount, Ordering::AcqRel);
        self.budget.resident_bytes -= amount;
        self.amount -= amount;
        Ok(RetainedResidentPermit {
            shared: Arc::clone(shared),
            amount,
        })
    }

    /// Release `amount` active bytes from this reservation before it is dropped.
    ///
    /// Releasing more than this guard currently owns is rejected atomically.
    /// Peak usage is historical and therefore does not decrease.
    pub fn release(&mut self, amount: u64) -> Result<()> {
        self.verify_ledger()?;
        if amount > self.amount {
            return Err(Error::ResourceLimit {
                resource: "resident reservation release bytes",
                requested: amount,
                limit: self.amount,
            });
        }
        self.amount -= amount;
        self.budget.resident_bytes -= amount;
        Ok(())
    }
}

impl Deref for ResidentReservation<'_> {
    type Target = WorkBudget;
    fn deref(&self) -> &WorkBudget {
        self.budget
    }
}
impl Drop for ResidentReservation<'_> {
    fn drop(&mut self) {
        if self
            .budget
            .ledger_identity
            .as_ref()
            .is_none_or(|identity| !Arc::ptr_eq(identity, &self.ledger_identity))
            || self.budget.active_resident_reservations != self.reservation_depth
            || self.budget.resident_bytes < self.amount
        {
            // The checked bridge may have been used to replace the ledger.
            // Cleanup must never underflow or subtract from replacement state.
            self.budget.complete_resident_accounting = false;
            return;
        }
        self.budget.resident_bytes -= self.amount;
        self.budget.active_resident_reservations -= 1;
    }
}

/// Owned nominal retained-allocation bytes admitted by [`WorkBudget::retain_resident`].
///
/// Unlike [`ResidentReservation`], a permit owns no borrow: it shares only a
/// live counter with its ledger, so it can travel inside a returned namespace
/// or any other owned value and keep reporting residency for exactly as long
/// as the corresponding allocation lives. Dropping the permit releases its
/// amount; the ledger peak is historical and never decreases.
#[must_use = "dropping the permit immediately releases its resident-byte allowance"]
#[derive(Debug)]
pub struct RetainedResidentPermit {
    shared: Arc<SharedRetainedResident>,
    amount: u64,
}

impl RetainedResidentPermit {
    /// Nominal retained bytes this permit holds live.
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Reconcile a measured capacity with this permit on its issuing ledger.
    /// Growth is admitted before updating the permit. Shrinking releases only
    /// residency, never cumulative work. A different ledger cannot adopt it.
    pub fn resize(&mut self, budget: &mut WorkBudget, amount: u64) -> Result<()> {
        if !budget
            .retained_resident
            .as_ref()
            .is_some_and(|shared| Arc::ptr_eq(shared, &self.shared))
        {
            return Err(Error::Malformed(
                "retained permit belongs to another ledger".into(),
            ));
        }
        if amount > self.amount {
            let additional = budget.retain_resident(amount - self.amount)?;
            // Transfer the newly admitted amount without releasing it. Zeroing
            // the donor makes its normal Drop harmless; no allocation is leaked.
            let mut additional = additional;
            self.amount = amount;
            additional.amount = 0;
        } else {
            self.shared
                .outstanding
                .fetch_sub(self.amount - amount, Ordering::AcqRel);
            self.amount = amount;
        }
        Ok(())
    }
}

impl Drop for RetainedResidentPermit {
    fn drop(&mut self) {
        // Permits are only issued through the checked admission above, so the
        // shared total always covers this amount. Saturate defensively: cleanup
        // must never wrap the counter even under misuse.
        let _ = self.shared.outstanding.fetch_update(
            Ordering::AcqRel,
            Ordering::Relaxed,
            |outstanding| Some(outstanding.saturating_sub(self.amount)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_to_owned_transfer_preserves_total_at_exact_limit() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let earlier = budget.retain_resident(3).unwrap();
        let later = {
            let mut guard = budget.reserve_resident(7).unwrap();
            assert!(guard.transfer_retained(8).is_err());
            assert_eq!(guard.usage().resident_bytes(), 10);
            let later = guard.transfer_retained(5).unwrap();
            assert_eq!(guard.usage().resident_bytes(), 10);
            assert_eq!(guard.usage().peak_resident_bytes(), 10);
            assert!(guard.try_grow(1).is_err());
            later
        };
        assert_eq!(budget.usage().resident_bytes(), 8);
        drop(earlier);
        assert_eq!(budget.usage().resident_bytes(), 5);
        drop(later);
        assert_eq!(budget.usage().resident_bytes(), 0);
    }

    #[test]
    fn cancelled_transfer_leaves_construction_storage_reserved() {
        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        let mut guard = budget.reserve_resident(7).unwrap();
        token.cancel();
        assert!(matches!(guard.transfer_retained(7), Err(Error::Cancelled)));
        assert_eq!(guard.usage().resident_bytes(), 7);
        drop(guard);
        assert_eq!(budget.usage().resident_bytes(), 0);
    }

    #[test]
    fn stage_admission_is_atomic_and_sums_duplicate_dimensions() {
        use WorkResource::{Nodes, OutputBytes};
        let mut budget =
            WorkBudget::new(WorkLimits::unlimited().with(Nodes, 4).with(OutputBytes, 5));
        budget.charge(Nodes, 1).unwrap();
        assert!(budget
            .charge_batch(&[(Nodes, 2), (OutputBytes, 6)])
            .is_err());
        assert_eq!(budget.spent(Nodes), 1);
        assert_eq!(budget.spent(OutputBytes), 0);
        assert!(budget.charge_batch(&[(Nodes, 2), (Nodes, 2)]).is_err());
        assert_eq!(budget.spent(Nodes), 1);
        budget
            .charge_batch(&[(Nodes, 1), (Nodes, 2), (OutputBytes, 5)])
            .unwrap();
        assert_eq!(budget.spent(Nodes), 4);
        assert_eq!(budget.spent(OutputBytes), 5);
    }

    #[test]
    fn stage_admission_overflow_and_cancel_do_not_spend() {
        use WorkResource::{Nodes, OutputBytes};
        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        budget.charge(Nodes, u64::MAX).unwrap();
        assert!(budget
            .charge_batch(&[(OutputBytes, 1), (Nodes, 1)])
            .is_err());
        assert_eq!(budget.spent(OutputBytes), 0);
        token.cancel();
        assert_eq!(
            budget.charge_batch(&[(OutputBytes, 1)]),
            Err(Error::Cancelled)
        );
        assert!(matches!(budget.retain_resident(1), Err(Error::Cancelled)));
        assert_eq!(budget.spent(OutputBytes), 0);
        assert_eq!(budget.usage().resident_bytes(), 0);
    }
    use WorkResource::*;

    #[test]
    fn legacy_read_bridge_shares_exact_parent_allowance_across_mixed_routes() {
        let mut budget =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 7));
        budget.charge(WorkResource::LogicalReadBytes, 2).unwrap();
        budget
            .with_read_budget(|reads| {
                assert_eq!(reads.limit(), Some(5));
                reads.charge(3)?;
                Ok(())
            })
            .unwrap();
        budget.charge(WorkResource::LogicalReadBytes, 2).unwrap();
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 7);
        assert!(!budget.complete_io_accounting());

        assert_eq!(
            budget.with_read_budget(|reads| reads.charge(1)),
            Err(Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 8,
                limit: 7,
            })
        );
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 7);
    }

    #[test]
    fn legacy_read_bridge_rejects_finite_physical_io_before_callback() {
        let mut budget = WorkBudget::new(
            WorkLimits::unlimited()
                .with(LogicalReadBytes, 8)
                .with(IoRequestedBytes, 8)
                .with(IoReadCalls, 1),
        );
        let invoked = std::cell::Cell::new(false);
        let error = budget
            .with_read_budget(|_| {
                invoked.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(!invoked.get());
        assert_eq!(
            error,
            Error::Unsupported("source does not expose underlying I/O accounting".into())
        );
        assert!(budget.complete_io_accounting());
    }

    #[test]
    fn absorbed_legacy_reads_retain_spend_and_mark_physical_io_incomplete() {
        let mut reads = ReadBudget::limited(4);
        reads.charge(4).unwrap();
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with(LogicalReadBytes, 4));
        budget.absorb_read_budget(reads).unwrap();
        assert_eq!(budget.spent(LogicalReadBytes), 4);
        assert!(!budget.complete_io_accounting());

        let mut reads = ReadBudget::limited(4);
        reads.charge(4).unwrap();
        let mut finite_io = WorkBudget::new(
            WorkLimits::unlimited()
                .with(LogicalReadBytes, 4)
                .with(IoReadCalls, 1),
        );
        assert_eq!(
            finite_io.absorb_read_budget(reads),
            Err(Error::Unsupported(
                "legacy reads cannot satisfy finite physical-I/O limits".into()
            ))
        );
        assert_eq!(finite_io.spent(LogicalReadBytes), 4);
        assert!(!finite_io.complete_io_accounting());

        let mut reads = ReadBudget::limited(5);
        reads.charge(5).unwrap();
        let mut one_short = WorkBudget::new(WorkLimits::unlimited().with(LogicalReadBytes, 4));
        assert!(matches!(
            one_short.absorb_read_budget(reads),
            Err(Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 5,
                limit: 4,
            })
        ));
        assert_eq!(one_short.spent(LogicalReadBytes), 0);
        assert!(!one_short.complete_io_accounting());
    }

    #[test]
    fn legacy_read_bridge_rejects_fresh_replacement_and_marks_incomplete() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with(LogicalReadBytes, 8));
        let error = budget
            .with_read_budget(|reads| {
                reads.charge(3)?;
                *reads = ReadBudget::limited(8);
                reads.charge(7)
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::Malformed("legacy read-budget bridge was replaced".into())
        );
        assert_eq!(budget.spent(LogicalReadBytes), 0);
        assert!(!budget.usage().complete_logical_read_accounting());
    }

    #[test]
    fn legacy_read_bridge_matching_replacement_cannot_forge_continuity() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with(LogicalReadBytes, 5));
        let error = budget
            .with_read_budget(|reads| {
                *reads = ReadBudget::limited(5);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::Malformed("legacy read-budget bridge was replaced".into())
        );
        assert!(!budget.usage().complete_logical_read_accounting());
    }

    #[test]
    fn legacy_read_bridge_clone_cannot_reset_spend_and_preserve_continuity() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with(LogicalReadBytes, 8));
        let error = budget
            .with_read_budget(|reads| {
                let saved = reads.clone();
                reads.charge(6)?;
                *reads = saved;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::Malformed("legacy read-budget bridge was replaced".into())
        );
        assert_eq!(budget.spent(LogicalReadBytes), 0);
        assert!(!budget.usage().complete_logical_read_accounting());
    }

    #[test]
    fn bridge_replacement_precedes_but_still_observes_cancellation() {
        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        let error = budget
            .with_read_budget(|reads| {
                *reads = ReadBudget::limited(0);
                token.cancel();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::Malformed("legacy read-budget bridge was replaced".into())
        );
        assert!(budget.cancellation_requested());
        assert!(budget.cancellation_observed());
        assert!(!budget.usage().complete_logical_read_accounting());
    }

    #[test]
    fn public_budget_constructors_remain_const_compatible() {
        const READS: ReadBudget = ReadBudget::limited(4);
        const WORK: WorkBudget = WorkBudget::new(WorkLimits::unlimited());
        assert_eq!(READS.remaining(), Some(4));
        assert_eq!(WORK.spent[LogicalReadBytes as usize], 0);
    }

    #[test]
    fn legacy_read_bridge_transfers_admitted_spend_on_error_and_preserves_context() {
        let mut budget =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 5));
        budget.charge(WorkResource::LogicalReadBytes, 2).unwrap();
        let frame = crate::ErrorContext::Component("legacy reader");
        let error = budget
            .with_read_budget(|reads| {
                reads.charge(2)?;
                Err::<(), _>(
                    Error::ResourceLimit {
                        resource: "range-source bytes",
                        requested: 4,
                        limit: 3,
                    }
                    .context(frame.clone()),
                )
            })
            .unwrap_err();
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 6,
                limit: 5,
            }
            .context(frame)
        );
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 4);
    }

    #[test]
    fn legacy_read_bridge_honors_nested_scope_and_restores_parent_ceiling() {
        let mut budget =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 10));
        budget.charge(WorkResource::LogicalReadBytes, 2).unwrap();
        {
            let mut child = budget
                .scope(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 3))
                .unwrap();
            child
                .with_read_budget(|reads| {
                    assert_eq!(reads.limit(), Some(3));
                    reads.charge(3)
                })
                .unwrap();
            assert_eq!(
                child.with_read_budget(|reads| reads.charge(1)),
                Err(Error::ResourceLimit {
                    resource: "logical source bytes",
                    requested: 6,
                    limit: 5,
                })
            );
        }
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 5);
        assert_eq!(budget.remaining(WorkResource::LogicalReadBytes), Some(5));
        budget
            .with_read_budget(|reads| {
                assert_eq!(reads.limit(), Some(5));
                reads.charge(5)
            })
            .unwrap();
    }

    #[test]
    fn legacy_read_bridge_maps_unlimited_counter_overflow() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        budget
            .charge(WorkResource::LogicalReadBytes, u64::MAX)
            .unwrap();
        assert_eq!(
            budget.with_read_budget(|reads| reads.charge(1)),
            Err(Error::Malformed(
                "logical source bytes accounting overflow".into()
            ))
        );
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), u64::MAX);
    }

    #[test]
    fn cancellation_is_shared_by_scopes_and_legacy_bridge_boundaries() {
        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        assert!(!budget.cancellation_requested());
        assert!(!budget.cancellation_observed());

        let error = budget
            .with_read_budget(|reads| {
                reads.charge(2)?;
                token.cancel();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, Error::Cancelled);
        assert_eq!(budget.spent(LogicalReadBytes), 2);
        assert!(budget.cancellation_requested());
        assert!(budget.cancellation_observed());
        let usage = budget.usage();
        assert!(usage.cancellation_requested());
        assert!(usage.cancellation_observed());

        let mut called = false;
        assert_eq!(
            budget.with_read_budget(|_| {
                called = true;
                Ok(())
            }),
            Err(Error::Cancelled)
        );
        assert!(!called, "pre-cancelled bridge must not invoke legacy work");

        let mut child = budget.scope(WorkLimits::unlimited()).unwrap();
        assert_eq!(child.check_cancelled(), Err(Error::Cancelled));
        drop(child);
        let mut resident = budget.reserve_resident(0).unwrap();
        assert_eq!(resident.check_cancelled(), Err(Error::Cancelled));
    }

    #[test]
    fn legacy_operation_error_precedes_concurrent_cooperative_cancellation() {
        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        let error = budget
            .with_read_budget(|reads| {
                reads.charge(1)?;
                token.cancel();
                Err::<(), _>(Error::Malformed("legacy operation failed".into()))
            })
            .unwrap_err();
        assert_eq!(error, Error::Malformed("legacy operation failed".into()));
        assert_eq!(budget.spent(LogicalReadBytes), 1);
        assert!(budget.cancellation_observed());
    }

    #[test]
    fn every_cumulative_dimension_accepts_exact_and_rejects_one_short_without_spending_denial() {
        for resource in [
            LogicalReadBytes,
            IoRequestedBytes,
            IoReadCalls,
            MaterializedBytes,
            OutputBytes,
            Nodes,
        ] {
            let mut budget = WorkBudget::new(WorkLimits::unlimited().with(resource, 2));
            budget.charge(resource, 2).unwrap();
            assert_eq!(
                budget.spent(resource),
                2,
                "{} exact spend",
                resource.label()
            );
            assert_eq!(
                budget.remaining(resource),
                Some(0),
                "{} exact remainder",
                resource.label()
            );

            assert_eq!(
                budget.charge(resource, 1),
                Err(Error::ResourceLimit {
                    resource: resource.label(),
                    requested: 3,
                    limit: 2,
                }),
                "{} one-short error",
                resource.label()
            );
            assert_eq!(
                budget.spent(resource),
                2,
                "{} denied charge must not be spent",
                resource.label()
            );
        }
    }

    #[test]
    fn depth_exact_one_short_and_unwind_restore_active_but_keep_peak() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_depth(2));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut first = budget.enter_depth().unwrap();
            assert_eq!(first.depth(), 1);
            assert_eq!(first.peak_depth(), 1);

            let mut second = first.enter_depth().unwrap();
            assert_eq!(second.depth(), 2);
            assert_eq!(second.peak_depth(), 2);
            match second.enter_depth() {
                Err(error) => assert_eq!(
                    error,
                    Error::ResourceLimit {
                        resource: "work depth",
                        requested: 3,
                        limit: 2,
                    }
                ),
                Ok(_) => panic!("one-short depth entry unexpectedly succeeded"),
            }
            assert_eq!(second.depth(), 2, "denied entry must not change depth");
            assert_eq!(second.peak_depth(), 2, "denied entry must not change peak");
            panic!("exercise depth guard unwinding");
        }));

        assert!(unwind.is_err());
        assert_eq!(budget.depth(), 0, "unwinding must release active depth");
        assert_eq!(budget.peak_depth(), 2, "unwinding must retain peak depth");
    }

    #[test]
    fn resident_exact_one_short_releases_current_and_retains_peak() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(5));
        assert_eq!(budget.remaining_resident_bytes(), Some(5));
        {
            let mut exact = budget.reserve_resident(5).unwrap();
            let usage = exact.usage();
            assert_eq!(usage.resident_bytes_limit(), Some(5));
            assert_eq!(usage.resident_bytes(), 5);
            assert_eq!(usage.remaining_resident_bytes(), Some(0));
            assert_eq!(exact.remaining_resident_bytes(), Some(0));
            assert_eq!(usage.peak_resident_bytes(), 5);

            match exact.reserve_resident(1) {
                Err(error) => assert_eq!(
                    error,
                    Error::ResourceLimit {
                        resource: "resident bytes",
                        requested: 6,
                        limit: 5,
                    }
                ),
                Ok(_) => panic!("one-short resident reservation unexpectedly succeeded"),
            }
            assert_eq!(exact.usage().resident_bytes(), 5);
            assert_eq!(exact.usage().peak_resident_bytes(), 5);
        }
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().remaining_resident_bytes(), Some(5));
        assert_eq!(budget.remaining_resident_bytes(), Some(5));
        assert_eq!(budget.usage().peak_resident_bytes(), 5);
    }

    #[test]
    fn resident_growth_accepts_exact_and_rejects_one_short_atomically() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        {
            let mut reservation = budget.reserve_resident(4).unwrap();
            reservation.try_grow(6).unwrap();
            assert_eq!(reservation.usage().resident_bytes(), 10);
            assert_eq!(reservation.usage().remaining_resident_bytes(), Some(0));
            assert_eq!(reservation.usage().peak_resident_bytes(), 10);

            assert_eq!(
                reservation.try_grow(1),
                Err(Error::ResourceLimit {
                    resource: "resident bytes",
                    requested: 11,
                    limit: 10,
                })
            );
            assert_eq!(reservation.usage().resident_bytes(), 10);
            assert_eq!(reservation.usage().peak_resident_bytes(), 10);
        }
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), 10);
    }

    #[test]
    fn resident_partial_release_is_guard_local_and_drop_releases_the_remainder() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        {
            let mut reservation = budget.reserve_resident(6).unwrap();
            reservation.release(2).unwrap();
            assert_eq!(reservation.usage().resident_bytes(), 4);
            assert_eq!(reservation.usage().remaining_resident_bytes(), Some(6));
            assert_eq!(reservation.usage().peak_resident_bytes(), 6);

            assert_eq!(
                reservation.release(5),
                Err(Error::ResourceLimit {
                    resource: "resident reservation release bytes",
                    requested: 5,
                    limit: 4,
                })
            );
            assert_eq!(reservation.usage().resident_bytes(), 4);
            assert_eq!(reservation.usage().peak_resident_bytes(), 6);
        }
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), 6);
    }

    #[test]
    fn resident_adjustment_unwind_releases_only_the_remaining_amount() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut reservation = budget.reserve_resident(3).unwrap();
            reservation.try_grow(4).unwrap();
            reservation.release(2).unwrap();
            assert_eq!(reservation.usage().resident_bytes(), 5);
            assert_eq!(reservation.usage().peak_resident_bytes(), 7);
            panic!("exercise adjusted resident guard unwinding");
        }));

        assert!(unwind.is_err());
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), 7);
    }

    #[test]
    fn replacing_budget_through_resident_guard_is_detected_without_drop_corruption() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut reservation = budget.reserve_resident(6).unwrap();
            let mut replacement = WorkBudget::new(
                WorkLimits::unlimited()
                    .with(Nodes, 3)
                    .with_resident_bytes(20),
            );
            replacement.charge(Nodes, 3).unwrap();
            assert_eq!(
                reservation.with_budget(|budget| {
                    *budget = replacement;
                    Ok(())
                }),
                Err(Error::Malformed(
                    "resident reservation ledger was replaced".into()
                ))
            );
            assert!(!reservation.usage().complete_resident_accounting());
        }));

        assert!(
            outcome.is_ok(),
            "guard drop must not panic after replacement"
        );
        let usage = budget.usage();
        assert_eq!(usage.spent(Nodes), 3, "drop must not corrupt replacement");
        assert_eq!(usage.resident_bytes(), 0);
        assert_eq!(usage.peak_resident_bytes(), 0);
        assert!(!usage.complete_resident_accounting());
    }

    #[test]
    fn matching_replacement_counters_cannot_forge_private_ledger_identity() {
        let mut replacement = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let leaked = replacement.reserve_resident(6).unwrap();
        std::mem::forget(leaked);
        assert_eq!(replacement.usage().resident_bytes(), 6);

        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        {
            let mut reservation = budget.reserve_resident(6).unwrap();
            assert_eq!(
                reservation.with_budget(|target| {
                    *target = replacement;
                    Ok(())
                }),
                Err(Error::Malformed(
                    "resident reservation ledger was replaced".into()
                ))
            );
            assert_eq!(reservation.usage().resident_bytes(), 6);
            assert!(!reservation.usage().complete_resident_accounting());
        }

        assert_eq!(budget.usage().resident_bytes(), 6);
        assert!(!budget.usage().complete_resident_accounting());
    }

    #[test]
    fn replacement_during_callback_unwind_is_detected_by_drop() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut reservation = budget.reserve_resident(6).unwrap();
            let _ = reservation.with_budget::<()>(|target| {
                *target = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(20));
                panic!("exercise replacement during callback unwind");
            });
        }));

        assert!(unwind.is_err());
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert!(!budget.usage().complete_resident_accounting());
    }

    #[test]
    fn resident_growth_honors_child_ceiling_and_restores_parent_truth() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let mut outer = budget.reserve_resident(4).unwrap();
        outer
            .with_budget(|budget| {
                let mut child = budget
                    .scope(WorkLimits::unlimited().with_resident_bytes(3))
                    .unwrap();
                let mut reservation = child.reserve_resident(1).unwrap();
                reservation.try_grow(2).unwrap();
                assert_eq!(reservation.usage().resident_bytes_limit(), Some(7));
                assert_eq!(reservation.usage().resident_bytes(), 7);
                assert_eq!(reservation.usage().peak_resident_bytes(), 7);
                assert_eq!(
                    reservation.try_grow(1),
                    Err(Error::ResourceLimit {
                        resource: "resident bytes",
                        requested: 8,
                        limit: 7,
                    })
                );
                assert_eq!(reservation.usage().resident_bytes(), 7);
                assert_eq!(reservation.usage().peak_resident_bytes(), 7);
                Ok(())
            })
            .unwrap();
        assert_eq!(outer.usage().resident_bytes_limit(), Some(10));
        assert_eq!(outer.usage().resident_bytes(), 4);
        assert_eq!(outer.usage().remaining_resident_bytes(), Some(6));
        assert_eq!(outer.usage().peak_resident_bytes(), 7);
    }

    #[test]
    fn resident_reservation_releases_on_early_error() {
        fn fail_after_reserving(budget: &mut WorkBudget) -> Result<()> {
            let reservation = budget.reserve_resident(4)?;
            assert_eq!(reservation.usage().resident_bytes(), 4);
            Err(Error::Malformed("stop after reservation".into()))
        }

        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(5));
        assert_eq!(
            fail_after_reserving(&mut budget),
            Err(Error::Malformed("stop after reservation".into()))
        );
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), 4);
        assert_eq!(budget.remaining_resident_bytes(), Some(5));
    }

    #[test]
    fn resident_overflow_is_rejected_without_changing_active_or_peak() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        {
            let mut maximum = budget.reserve_resident(u64::MAX).unwrap();
            assert_eq!(
                maximum.try_grow(1),
                Err(Error::Malformed("resident byte accounting overflow".into()))
            );
            assert_eq!(maximum.usage().resident_bytes(), u64::MAX);
            assert_eq!(maximum.usage().peak_resident_bytes(), u64::MAX);
            assert_eq!(maximum.usage().remaining_resident_bytes(), None);
        }
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), u64::MAX);
    }

    #[test]
    fn resident_guards_keep_the_same_budget_usable_and_honor_child_limits() {
        let mut budget = WorkBudget::new(
            WorkLimits::unlimited()
                .with(LogicalReadBytes, 4)
                .with(Nodes, 2)
                .with_resident_bytes(10),
        );
        let mut outer = budget.reserve_resident(4).unwrap();
        outer.charge(Nodes, 1).unwrap();
        {
            let mut nested = outer.reserve_resident(3).unwrap();
            nested.charge(LogicalReadBytes, 2).unwrap();
            assert_eq!(nested.usage().resident_bytes(), 7);
            assert_eq!(nested.usage().peak_resident_bytes(), 7);
            assert_eq!(nested.usage().spent(LogicalReadBytes), 2);
            assert_eq!(nested.usage().spent(Nodes), 1);
        }
        assert_eq!(outer.usage().resident_bytes(), 4);
        assert_eq!(outer.usage().peak_resident_bytes(), 7);

        outer
            .with_budget(|budget| {
                let mut child = budget
                    .scope(WorkLimits::unlimited().with_resident_bytes(2))
                    .unwrap();
                let mut exact = child.reserve_resident(2).unwrap();
                match exact.reserve_resident(1) {
                    Err(Error::ResourceLimit {
                        resource: "resident bytes",
                        requested: 7,
                        limit: 6,
                    }) => {}
                    Err(error) => panic!("unexpected child resident error: {error}"),
                    Ok(_) => panic!("child resident ceiling unexpectedly relaxed"),
                };
                Ok(())
            })
            .unwrap();
        assert_eq!(outer.usage().resident_bytes_limit(), Some(10));
        assert_eq!(outer.usage().resident_bytes(), 4);
        assert_eq!(outer.usage().peak_resident_bytes(), 7);
    }

    #[test]
    fn resident_unwind_releases_nested_current_and_retains_peak() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut outer = budget.reserve_resident(4).unwrap();
            let nested = outer.reserve_resident(3).unwrap();
            assert_eq!(nested.usage().resident_bytes(), 7);
            panic!("exercise resident guard unwinding");
        }));

        assert!(unwind.is_err());
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), 7);
    }

    #[test]
    fn child_scope_restores_resident_limit_after_error_and_unwind() {
        fn fail_in_child(budget: &mut WorkBudget) -> Result<()> {
            let mut child = budget.scope(WorkLimits::unlimited().with_resident_bytes(2))?;
            let reservation = child.reserve_resident(2)?;
            assert_eq!(reservation.usage().resident_bytes_limit(), Some(6));
            assert_eq!(reservation.usage().remaining_resident_bytes(), Some(0));
            Err(Error::Malformed("stop inside child".into()))
        }

        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(10));
        let mut outer = budget.reserve_resident(4).unwrap();
        assert_eq!(
            outer.with_budget(fail_in_child),
            Err(Error::Malformed("stop inside child".into()))
        );
        assert_eq!(outer.usage().resident_bytes_limit(), Some(10));
        assert_eq!(outer.usage().resident_bytes(), 4);
        assert_eq!(outer.usage().peak_resident_bytes(), 6);
        assert_eq!(outer.remaining_resident_bytes(), Some(6));

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = outer.with_budget::<()>(|budget| {
                let mut child = budget
                    .scope(WorkLimits::unlimited().with_resident_bytes(1))
                    .unwrap();
                let reservation = child.reserve_resident(1).unwrap();
                assert_eq!(reservation.usage().resident_bytes_limit(), Some(5));
                panic!("exercise child resident-scope unwinding");
            });
        }));
        assert!(unwind.is_err());
        assert_eq!(outer.usage().resident_bytes_limit(), Some(10));
        assert_eq!(outer.usage().resident_bytes(), 4);
        assert_eq!(outer.usage().peak_resident_bytes(), 6);
        assert_eq!(outer.remaining_resident_bytes(), Some(6));

        let exact = outer.reserve_resident(6).unwrap();
        assert_eq!(exact.usage().resident_bytes(), 10);
        assert_eq!(exact.usage().remaining_resident_bytes(), Some(0));
    }

    #[test]
    fn usage_snapshot_copies_limits_and_all_current_observations() {
        let limits = WorkLimits::unlimited()
            .with(LogicalReadBytes, 10)
            .with(IoRequestedBytes, 20)
            .with(IoReadCalls, 2)
            .with(MaterializedBytes, 30)
            .with(OutputBytes, 40)
            .with(Nodes, 50)
            .with_resident_bytes(70)
            .with_depth(2);
        let mut budget = WorkBudget::new(limits);
        budget.charge(LogicalReadBytes, 1).unwrap();
        budget.io_attempt(4).unwrap();
        budget.io_completed(3);
        budget.charge(MaterializedBytes, 2).unwrap();
        budget.charge(OutputBytes, 3).unwrap();
        budget.charge(Nodes, 4).unwrap();

        {
            let mut resident = budget.reserve_resident(5).unwrap();
            let active = resident
                .with_budget(|budget| {
                    let mut first = budget.enter_depth()?;
                    let second = first.enter_depth()?;
                    Ok(second.usage())
                })
                .unwrap();
            assert_eq!(active.limits(), limits);
            assert_eq!(active.limit(LogicalReadBytes), Some(10));
            assert_eq!(active.spent(LogicalReadBytes), 1);
            assert_eq!(active.remaining(LogicalReadBytes), Some(9));
            assert_eq!(active.spent(IoRequestedBytes), 4);
            assert_eq!(active.spent(IoReadCalls), 1);
            assert_eq!(active.spent(MaterializedBytes), 2);
            assert_eq!(active.spent(OutputBytes), 3);
            assert_eq!(active.spent(Nodes), 4);
            assert_eq!(active.depth_limit(), Some(2));
            assert_eq!(active.active_depth(), 2);
            assert_eq!(active.peak_depth(), 2);
            assert_eq!(active.resident_bytes_limit(), Some(70));
            assert_eq!(active.resident_bytes(), 5);
            assert_eq!(active.remaining_resident_bytes(), Some(65));
            assert_eq!(active.peak_resident_bytes(), 5);
            assert_eq!(active.io_completed_bytes(), 3);
            assert!(active.complete_io_accounting());
            assert!(active.complete_resident_accounting());
            assert!(!active.cancellation_requested());
            assert!(!active.cancellation_observed());
        }

        let settled = budget.usage();
        assert_eq!(settled.active_depth(), 0);
        assert_eq!(settled.peak_depth(), 2);
        assert_eq!(settled.resident_bytes(), 0);
        assert_eq!(settled.peak_resident_bytes(), 5);
        assert!(settled.complete_resident_accounting());
        budget.charge(LogicalReadBytes, 1).unwrap();
        assert_eq!(settled.spent(LogicalReadBytes), 1);
        assert_eq!(budget.usage().spent(LogicalReadBytes), 2);
    }

    #[test]
    fn usage_snapshot_reports_unlimited_and_incomplete_io_honestly() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        budget.mark_uninstrumented_io().unwrap();
        let usage = budget.usage();

        for resource in [
            LogicalReadBytes,
            IoRequestedBytes,
            IoReadCalls,
            MaterializedBytes,
            OutputBytes,
            Nodes,
        ] {
            assert_eq!(usage.limit(resource), None);
            assert_eq!(usage.remaining(resource), None);
            assert_eq!(usage.spent(resource), 0);
        }
        assert_eq!(usage.depth_limit(), None);
        assert_eq!(usage.active_depth(), 0);
        assert_eq!(usage.peak_depth(), 0);
        assert_eq!(usage.resident_bytes_limit(), None);
        assert_eq!(usage.resident_bytes(), 0);
        assert_eq!(usage.remaining_resident_bytes(), None);
        assert_eq!(budget.remaining_resident_bytes(), None);
        assert_eq!(usage.peak_resident_bytes(), 0);
        assert_eq!(usage.io_completed_bytes(), 0);
        assert!(!usage.complete_io_accounting());
        assert!(usage.complete_resident_accounting());
        assert!(!usage.cancellation_requested());
        assert!(!usage.cancellation_observed());
    }

    #[test]
    fn scopes_restore_limits_but_never_consumed_work_even_when_unwinding() {
        let mut job = WorkBudget::new(WorkLimits::unlimited().with(Nodes, 5).with_depth(2));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut child = job.scope(WorkLimits::unlimited().with(Nodes, 2)).unwrap();
            child.charge(Nodes, 2).unwrap();
            assert!(child.charge(Nodes, 1).is_err());
            let mut depth = child.enter_depth().unwrap();
            {
                let mut nested = depth.enter_depth().unwrap();
                assert!(nested.enter_depth().is_err());
            }
            panic!("operation interrupted");
        }));
        assert_eq!(job.depth(), 0);
        assert_eq!(job.peak_depth(), 2);
        assert_eq!(job.spent(Nodes), 2);
        job.charge(Nodes, 3).unwrap();
        assert!(job.charge(Nodes, 1).is_err());
    }

    #[test]
    fn parent_limits_and_overflow_are_not_relaxed_by_children() {
        let mut job = WorkBudget::new(WorkLimits::unlimited().with(OutputBytes, 4));
        job.charge(OutputBytes, 3).unwrap();
        let mut child = job
            .scope(WorkLimits::unlimited().with(OutputBytes, 100))
            .unwrap();
        assert!(child.charge(OutputBytes, 2).is_err());
        child.charge(OutputBytes, 1).unwrap();
        assert!(child
            .scope(WorkLimits::unlimited().with(OutputBytes, u64::MAX))
            .is_err());
    }

    #[test]
    fn underlying_admission_is_atomic_and_fallback_is_honest() {
        let mut job = WorkBudget::new(WorkLimits::unlimited().with(IoRequestedBytes, 2));
        assert!(job.io_attempt(3).is_err());
        assert_eq!(job.spent(IoReadCalls), 0);
        assert!(job.mark_uninstrumented_io().is_err());
        assert!(job.complete_io_accounting());
        let mut job = WorkBudget::new(WorkLimits::unlimited());
        job.mark_uninstrumented_io().unwrap();
        assert!(!job.complete_io_accounting());
    }

    #[test]
    fn external_exact_read_admits_before_io_and_tracks_partial_attempts() {
        struct Chunks {
            bytes: &'static [u8],
            position: usize,
            chunk: usize,
        }
        impl std::io::Read for Chunks {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                let length = output
                    .len()
                    .min(self.chunk)
                    .min(self.bytes.len() - self.position);
                output[..length]
                    .copy_from_slice(&self.bytes[self.position..self.position + length]);
                self.position += length;
                Ok(length)
            }
        }

        let limits = WorkLimits::unlimited()
            .with(IoReadCalls, 2)
            .with(IoRequestedBytes, 6);
        let mut budget = WorkBudget::new(limits);
        let mut reader = Chunks {
            bytes: b"data",
            position: 0,
            chunk: 2,
        };
        let mut output = [0u8; 4];
        budget
            .read_external_exact_into(&mut reader, &mut output)
            .unwrap();
        assert_eq!(&output, b"data");
        assert_eq!(budget.spent(IoReadCalls), 2);
        assert_eq!(budget.spent(IoRequestedBytes), 6);
        assert_eq!(budget.io_completed_bytes(), 4);
        assert!(budget.complete_io_accounting());

        let mut denied = WorkBudget::new(
            WorkLimits::unlimited()
                .with(IoReadCalls, 1)
                .with(IoRequestedBytes, 3),
        );
        let mut reader = std::io::Cursor::new(b"data");
        assert!(matches!(
            denied.read_external_exact_into(&mut reader, &mut output),
            Err(Error::ResourceLimit {
                resource: "underlying requested I/O bytes",
                requested: 4,
                limit: 3,
            })
        ));
        assert_eq!(reader.position(), 0, "one-short denial must precede I/O");
        assert_eq!(denied.spent(IoReadCalls), 0, "atomic two-axis admission");
        assert_eq!(denied.io_completed_bytes(), 0);
    }

    #[test]
    fn external_exact_read_retains_completed_work_and_cancellation_precedence() {
        struct CancelAfterFirst {
            token: CancellationToken,
            first: bool,
        }
        impl std::io::Read for CancelAfterFirst {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.first {
                    return Err(std::io::Error::other("unexpected second read"));
                }
                self.first = true;
                output[..2].copy_from_slice(b"ab");
                self.token.cancel();
                Ok(2)
            }
        }

        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(
            WorkLimits::unlimited()
                .with(IoReadCalls, 2)
                .with(IoRequestedBytes, 6),
        )
        .with_cancellation(token.clone());
        let mut reader = CancelAfterFirst {
            token,
            first: false,
        };
        let mut output = [0u8; 4];
        assert_eq!(
            budget.read_external_exact_into(&mut reader, &mut output),
            Err(Error::Cancelled)
        );
        assert_eq!(budget.spent(IoReadCalls), 1);
        assert_eq!(budget.spent(IoRequestedBytes), 4);
        assert_eq!(budget.io_completed_bytes(), 2);
        assert!(budget.cancellation_observed());

        struct FailAfterFirst(bool);
        impl std::io::Read for FailAfterFirst {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Err(std::io::Error::other("injected external read fault"));
                }
                self.0 = true;
                output[..2].copy_from_slice(b"ab");
                Ok(2)
            }
        }
        let mut budget = WorkBudget::new(
            WorkLimits::unlimited()
                .with(IoReadCalls, 2)
                .with(IoRequestedBytes, 6),
        );
        let error = budget
            .read_external_exact_into(&mut FailAfterFirst(false), &mut output)
            .unwrap_err();
        assert!(matches!(error, Error::Malformed(message) if message.contains("injected")));
        assert_eq!(budget.spent(IoReadCalls), 2);
        assert_eq!(budget.spent(IoRequestedBytes), 6);
        assert_eq!(budget.io_completed_bytes(), 2);
    }

    #[test]
    fn retained_permits_extend_live_residency_and_release_on_drop() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(100));
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.retained_resident_bytes(), 0);

        let first = budget.retain_resident(30).unwrap();
        assert_eq!(first.amount(), 30);
        assert_eq!(budget.usage().resident_bytes(), 30);
        assert_eq!(budget.retained_resident_bytes(), 30);
        assert_eq!(budget.usage().peak_resident_bytes(), 30);
        assert_eq!(budget.remaining_resident_bytes(), Some(70));

        let second = budget.retain_resident(20).unwrap();
        assert_eq!(budget.usage().resident_bytes(), 50);
        assert_eq!(budget.retained_resident_bytes(), 50);
        assert_eq!(budget.usage().peak_resident_bytes(), 50);

        drop(first);
        assert_eq!(budget.usage().resident_bytes(), 20);
        assert_eq!(budget.retained_resident_bytes(), 20);
        assert_eq!(budget.usage().peak_resident_bytes(), 50);

        drop(second);
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.retained_resident_bytes(), 0);
        assert_eq!(budget.usage().peak_resident_bytes(), 50);
        assert!(budget.usage().complete_resident_accounting());
    }

    #[test]
    fn retained_permits_share_one_ceiling_with_borrowed_guards() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(100));
        let permit = budget.retain_resident(60).unwrap();

        {
            let mut guard = budget.reserve_resident(40).unwrap();
            assert_eq!(guard.usage().resident_bytes(), 100);
            assert!(matches!(
                guard.reserve_resident(1),
                Err(Error::ResourceLimit { .. })
            ));
            assert!(guard.try_grow(1).is_err());
        }
        assert_eq!(budget.usage().resident_bytes(), 60);

        {
            let guard = budget.reserve_resident(30).unwrap();
            assert_eq!(guard.usage().remaining_resident_bytes(), Some(10));
        }
        assert!(matches!(
            budget.retain_resident(41),
            Err(Error::ResourceLimit { .. })
        ));
        let tight = budget.retain_resident(40).unwrap();
        assert_eq!(budget.usage().resident_bytes(), 100);
        assert_eq!(budget.usage().peak_resident_bytes(), 100);
        drop(tight);
        assert_eq!(budget.usage().resident_bytes(), 60);
        drop(permit);
        assert_eq!(budget.usage().resident_bytes(), 0);
    }

    #[test]
    fn retained_permit_limits_are_exact_and_zero_is_denied() {
        let mut exact = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(16));
        let permit = exact.retain_resident(16).unwrap();
        assert_eq!(exact.usage().resident_bytes(), 16);
        assert!(matches!(
            exact.retain_resident(1),
            Err(Error::ResourceLimit { .. })
        ));
        drop(permit);

        let mut one_short = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(15));
        assert!(matches!(
            one_short.retain_resident(16),
            Err(Error::ResourceLimit { .. })
        ));
        assert_eq!(one_short.usage().resident_bytes(), 0);
        assert_eq!(one_short.usage().peak_resident_bytes(), 0);

        let mut zero = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(0));
        assert!(matches!(
            zero.retain_resident(1),
            Err(Error::ResourceLimit { .. })
        ));
        let vacuous = zero.retain_resident(0).unwrap();
        assert_eq!(vacuous.amount(), 0);
        assert_eq!(zero.usage().resident_bytes(), 0);
        drop(vacuous);
    }

    #[test]
    fn retained_permit_outliving_its_ledger_releases_harmlessly() {
        let permit = {
            let mut budget = WorkBudget::new(WorkLimits::unlimited());
            let permit = budget.retain_resident(12).unwrap();
            assert_eq!(budget.usage().resident_bytes(), 12);
            permit
        };
        assert_eq!(permit.amount(), 12);
        drop(permit);
    }

    #[test]
    fn child_resident_scope_counts_live_permits_for_exact_and_one_over() {
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(100));
        let live = budget.retain_resident(60).unwrap();
        assert_eq!(budget.usage().resident_bytes(), 60);

        {
            let mut scope = budget
                .scope(WorkLimits::unlimited().with_resident_bytes(30))
                .unwrap();
            assert_eq!(scope.usage().resident_bytes(), 60);
            let mut guard = scope.reserve_resident(30).unwrap();
            assert_eq!(guard.usage().resident_bytes(), 90);
            assert!(matches!(
                guard.reserve_resident(1),
                Err(Error::ResourceLimit {
                    requested: 91,
                    limit: 90,
                    ..
                })
            ));
        }
        assert_eq!(budget.usage().resident_bytes(), 60);

        {
            let mut scope = budget
                .scope(WorkLimits::unlimited().with_resident_bytes(40))
                .unwrap();
            let mut guard = scope.reserve_resident(40).unwrap();
            assert_eq!(guard.usage().resident_bytes(), 100);
            let denied = guard.with_budget(|budget| budget.retain_resident(1));
            assert!(matches!(denied, Err(Error::ResourceLimit { .. })));
        }

        let mut one_over = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(100));
        let live_over = one_over.retain_resident(60).unwrap();
        {
            let mut scope = one_over
                .scope(WorkLimits::unlimited().with_resident_bytes(39))
                .unwrap();
            assert!(matches!(
                scope.reserve_resident(40),
                Err(Error::ResourceLimit {
                    requested: 100,
                    limit: 99,
                    ..
                })
            ));
            assert_eq!(scope.usage().peak_resident_bytes(), 60);
        }
        drop(live_over);
        drop(live);
        assert_eq!(budget.usage().resident_bytes(), 0);
    }

    #[test]
    fn child_scope_and_permit_release_in_both_drop_orders() {
        // Order 1: scope drops before its inner permit.
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(100));
        let outer = budget.retain_resident(50).unwrap();
        let inner = {
            let mut scope = budget
                .scope(WorkLimits::unlimited().with_resident_bytes(40))
                .unwrap();
            let inner = scope.retain_resident(40).unwrap();
            assert_eq!(scope.usage().resident_bytes(), 90);
            inner
        };
        assert_eq!(budget.usage().resident_bytes(), 90);
        assert_eq!(budget.usage().peak_resident_bytes(), 90);
        drop(inner);
        assert_eq!(budget.usage().resident_bytes(), 50);
        drop(outer);
        assert_eq!(budget.usage().resident_bytes(), 0);

        // Order 2: inner permit drops before its scope.
        let mut budget = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(100));
        let outer = budget.retain_resident(50).unwrap();
        {
            let mut scope = budget
                .scope(WorkLimits::unlimited().with_resident_bytes(40))
                .unwrap();
            {
                let guard = scope.reserve_resident(40).unwrap();
                assert_eq!(guard.usage().resident_bytes(), 90);
            }
            assert_eq!(scope.usage().resident_bytes(), 50);
        }
        assert_eq!(budget.usage().resident_bytes(), 50);
        drop(outer);
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert!(budget.usage().complete_resident_accounting());
    }

    #[test]
    fn transformed_read_charges_logical_output_once_and_forwards_nested_reads() {
        let mut budget = WorkBudget::new(
            WorkLimits::unlimited()
                .with(LogicalReadBytes, 8)
                .with(IoReadCalls, 1)
                .with(IoRequestedBytes, 3),
        );
        let mut reader = std::io::Cursor::new(b"abc");
        let mut encoded = [0; 3];
        budget
            .with_transformed_read(8, |budget| {
                // A transformed source normally reaches this through a
                // nested FileRangeSource read. The explicit external read is
                // the smallest test of the same physical-I/O ledger.
                budget.read_external_exact_into(&mut reader, &mut encoded)
            })
            .unwrap();
        assert_eq!(budget.spent(LogicalReadBytes), 8);
        assert_eq!(budget.spent(IoReadCalls), 1);
        assert_eq!(budget.spent(IoRequestedBytes), 3);

        let before = reader.position();
        assert!(matches!(
            budget.with_transformed_read(1, |_| Ok(())),
            Err(Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 9,
                limit: 8,
            })
        ));
        assert_eq!(reader.position(), before, "denial precedes transform work");
    }

    #[test]
    fn transformed_read_observes_cancellation_at_both_boundaries() {
        let token = CancellationToken::new();
        token.cancel();
        let mut precancelled = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        let mut called = false;
        assert_eq!(
            precancelled.with_transformed_read(8, |_| {
                called = true;
                Ok(())
            }),
            Err(Error::Cancelled)
        );
        assert!(!called);
        assert_eq!(precancelled.spent(LogicalReadBytes), 0);
        assert!(precancelled.cancellation_observed());

        let token = CancellationToken::new();
        let mut during = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        assert_eq!(
            during.with_transformed_read(1, |_| {
                token.cancel();
                Ok(())
            }),
            Err(Error::Cancelled)
        );
        assert_eq!(during.spent(LogicalReadBytes), 1);
        assert!(during.cancellation_observed());
    }
}
