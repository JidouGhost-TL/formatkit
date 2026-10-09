//! Capacity-accounted payload storage; allocator metadata and fixed wrappers
//! are outside the nominal resident model. Allocators may over-reserve, so
//! capacity is reconciled after allocation and before storage is published.

use crate::{Error, Result, RetainedResidentPermit, WorkBudget, WorkResource};

/// An initialized fixed-length byte buffer owning its resident reservation.
/// It has no operation that grows storage or detaches the bytes from the permit.
#[derive(Debug)]
pub struct ResidentBuffer {
    bytes: Vec<u8>,
    // Field order releases storage before releasing its permit.
    resident: RetainedResidentPermit,
}

impl ResidentBuffer {
    /// Admit payload storage and materialization, allocate fallibly, reconcile
    /// capacity, then initialize. If an allocator returns extra capacity beyond
    /// the limit, drop it and fail before returning the buffer. This does not
    /// promise a strict bound on the transient allocator allocation itself.
    pub fn zeroed(budget: &mut WorkBudget, length: usize) -> Result<Self> {
        let requested = u64::try_from(length)
            .map_err(|_| Error::Malformed("payload length exceeds accounting range".into()))?;
        let mut resident = budget.retain_resident(requested)?;
        budget.charge_batch(&[(WorkResource::MaterializedBytes, requested)])?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::ResourceLimit {
                resource: "payload allocation bytes",
                requested,
                limit: requested,
            })?;
        resident.resize(budget, bytes.capacity() as u64)?;
        // Initialize in chunks so a large admitted allocation stays cancellable.
        while bytes.len() < length {
            budget.check_cancelled()?;
            bytes.resize(length.min(bytes.len().saturating_add(64 * 1024)), 0);
        }
        Ok(Self { bytes, resident })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    pub fn capacity_bytes(&self) -> u64 {
        self.resident.amount()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, WorkLimits};

    #[test]
    fn two_payloads_share_ceiling_and_release_independently() {
        let mut work = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(96));
        let mut first = ResidentBuffer::zeroed(&mut work, 32).unwrap();
        first.as_mut_slice()[0] = 7;
        let second = ResidentBuffer::zeroed(&mut work, 64).unwrap();
        assert_eq!(first.as_slice()[0], 7);
        assert_eq!(
            work.usage().resident_bytes(),
            first.capacity_bytes() + second.capacity_bytes()
        );
        assert!(ResidentBuffer::zeroed(&mut work, 1).is_err());
        drop(first);
        assert_eq!(work.usage().resident_bytes(), second.capacity_bytes());
        drop(second);
        assert_eq!(work.usage().resident_bytes(), 0);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 96);
    }

    #[test]
    fn denial_and_cancellation_release_residency() {
        let mut work =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::MaterializedBytes, 3));
        assert!(ResidentBuffer::zeroed(&mut work, 4).is_err());
        assert_eq!(work.usage().resident_bytes(), 0);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 0);
        let token = CancellationToken::new();
        token.cancel();
        let mut work = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert!(matches!(
            ResidentBuffer::zeroed(&mut work, 4),
            Err(Error::Cancelled)
        ));
        assert_eq!(work.usage().resident_bytes(), 0);
    }

    #[test]
    fn permit_reconciliation_requires_issuing_ledger_and_checks_growth() {
        let mut work = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(8));
        let mut other = WorkBudget::new(WorkLimits::unlimited());
        let mut permit = work.retain_resident(4).unwrap();
        assert!(permit.resize(&mut other, 5).is_err());
        assert!(permit.resize(&mut work, 9).is_err());
        assert_eq!(work.usage().resident_bytes(), 4);
        permit.resize(&mut work, 8).unwrap();
        permit.resize(&mut work, 2).unwrap();
        assert_eq!(work.usage().resident_bytes(), 2);
        assert_eq!(work.usage().peak_resident_bytes(), 8);
        drop(permit);
        assert_eq!(work.usage().resident_bytes(), 0);
    }

    #[test]
    fn impossible_allocation_releases_residency_but_not_admitted_work() {
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        // Vec rejects capacities beyond isize::MAX before touching the allocator.
        assert!(matches!(
            ResidentBuffer::zeroed(&mut work, usize::MAX),
            Err(Error::ResourceLimit { .. })
        ));
        assert_eq!(work.usage().resident_bytes(), 0);
        assert_eq!(
            work.spent(WorkResource::MaterializedBytes),
            usize::MAX as u64
        );
    }

    #[test]
    fn payload_can_release_on_another_thread_without_refunding_work() {
        let mut work = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(64));
        let bytes = ResidentBuffer::zeroed(&mut work, 64).unwrap();
        std::thread::spawn(move || drop(bytes)).join().unwrap();
        assert_eq!(work.usage().resident_bytes(), 0);
        assert_eq!(work.usage().peak_resident_bytes(), 64);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 64);
    }
}
