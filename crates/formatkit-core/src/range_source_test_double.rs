//! Deterministic `RangeSource` instrumentation shared by owner tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::{CoordinateSpaceDescription, Error, RangeSource, ReadBudget, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedError {
    Malformed(&'static str),
    Unsupported(&'static str),
    TruncatedOne { offset: u64 },
    TruncatedOneCast { offset: u64 },
}

impl InjectedError {
    fn make(self) -> Error {
        match self {
            Self::Malformed(message) => Error::Malformed(message.into()),
            Self::Unsupported(message) => Error::Unsupported(message.into()),
            Self::TruncatedOne { offset } => Error::Truncated {
                offset: usize::try_from(offset).expect("test fault offset fits usize"),
                needed: 1,
                available: 0,
            },
            Self::TruncatedOneCast { offset } => Error::Truncated {
                offset: offset as usize,
                needed: 1,
                available: 0,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFault {
    Never,
    Always(InjectedError),
    ExactOffset { offset: u64, error: InjectedError },
    AtOrAfter { offset: u64, error: InjectedError },
    ContainsOffset { offset: u64, error: InjectedError },
    EndAfter { boundary: u64, error: InjectedError },
}

impl ReadFault {
    fn error(self, offset: u64, length: u64) -> Option<Error> {
        match self {
            Self::Never => None,
            Self::Always(error) => Some(error.make()),
            Self::ExactOffset { offset: at, error } if offset == at => Some(error.make()),
            Self::AtOrAfter { offset: at, error } if offset >= at => Some(error.make()),
            Self::ContainsOffset { offset: at, error }
                if offset <= at && at < offset.saturating_add(length) =>
            {
                Some(error.make())
            }
            Self::EndAfter { boundary, error }
                if offset.checked_add(length).is_none_or(|end| end > boundary) =>
            {
                Some(error.make())
            }
            Self::ExactOffset { .. }
            | Self::AtOrAfter { .. }
            | Self::ContainsOffset { .. }
            | Self::EndAfter { .. } => None,
        }
    }
}

enum Backing {
    Source(Arc<dyn RangeSource>),
    SizeOnly { size: u64, name: &'static str },
}

/// Test-only range source with literal faults and attempted-read counters.
pub struct RangeSourceTestDouble {
    backing: Backing,
    read_fault: ReadFault,
    verification_fault: Option<(u64, InjectedError)>,
    read_calls: AtomicU64,
    read_bytes: AtomicU64,
    verification_calls: AtomicU64,
}

impl RangeSourceTestDouble {
    pub fn wrapping(source: Arc<dyn RangeSource>) -> Self {
        Self {
            backing: Backing::Source(source),
            read_fault: ReadFault::Never,
            verification_fault: None,
            read_calls: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            verification_calls: AtomicU64::new(0),
        }
    }

    pub fn resident(bytes: Vec<u8>, name: &'static str) -> Self {
        Self::wrapping(Arc::new(crate::MemoryRangeSource::new(bytes, name)))
    }

    pub fn from_memory(source: crate::MemoryRangeSource) -> Self {
        Self::wrapping(Arc::new(source))
    }

    /// Declares a size without allocating corresponding storage.
    pub fn size_only(size: u64, name: &'static str) -> Self {
        Self {
            backing: Backing::SizeOnly { size, name },
            read_fault: ReadFault::Never,
            verification_fault: None,
            read_calls: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            verification_calls: AtomicU64::new(0),
        }
    }

    pub fn with_read_fault(mut self, fault: ReadFault) -> Self {
        self.read_fault = fault;
        self
    }

    /// Fails after exactly `stable_calls` successful verification calls.
    pub fn with_verification_fault(mut self, stable_calls: u64, error: InjectedError) -> Self {
        self.verification_fault = Some((stable_calls, error));
        self
    }

    pub fn read_calls(&self) -> u64 {
        self.read_calls.load(Ordering::SeqCst)
    }

    pub fn read_bytes(&self) -> u64 {
        self.read_bytes.load(Ordering::SeqCst)
    }

    pub fn verification_calls(&self) -> u64 {
        self.verification_calls.load(Ordering::SeqCst)
    }
}

impl RangeSource for RangeSourceTestDouble {
    fn size(&self) -> u64 {
        match &self.backing {
            Backing::Source(source) => source.size(),
            Backing::SizeOnly { size, .. } => *size,
        }
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        self.read_bytes.fetch_add(length, Ordering::SeqCst);
        if let Some(error) = self.read_fault.error(offset, length) {
            return Err(error);
        }
        match &self.backing {
            Backing::Source(source) => source.read_at(offset, length, budget),
            Backing::SizeOnly { .. } => Err(Error::Unsupported(
                "size-only test source has no readable backing".into(),
            )),
        }
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        match &self.backing {
            Backing::Source(source) => source.describe_coordinate_space(),
            Backing::SizeOnly { size, name } => {
                CoordinateSpaceDescription::bytes("test", *name, *size)
            }
        }
    }

    fn verify_unchanged(&self) -> Result<()> {
        let call = self.verification_calls.fetch_add(1, Ordering::SeqCst);
        if let Some((stable_calls, error)) = self.verification_fault {
            if call >= stable_calls {
                return Err(error.make());
            }
        }
        match &self.backing {
            Backing::Source(source) => source.verify_unchanged(),
            Backing::SizeOnly { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_threshold_faults_pin_offsets_attempts_and_budget_timing() {
        let exact = RangeSourceTestDouble::resident(vec![0; 16], "exact").with_read_fault(
            ReadFault::ExactOffset {
                offset: 8,
                error: InjectedError::Malformed("exact"),
            },
        );
        let mut budget = ReadBudget::limited(16);
        assert_eq!(exact.read_at(7, 2, &mut budget).unwrap(), vec![0; 2]);
        assert_eq!(
            exact.read_at(8, 0, &mut budget),
            Err(Error::Malformed("exact".into()))
        );
        assert_eq!(exact.read_at(9, 1, &mut budget).unwrap(), vec![0]);
        assert_eq!(
            (exact.read_calls(), exact.read_bytes(), budget.spent()),
            (3, 3, 3)
        );

        let threshold = RangeSourceTestDouble::resident(vec![0; 16], "threshold").with_read_fault(
            ReadFault::AtOrAfter {
                offset: 8,
                error: InjectedError::Unsupported("threshold"),
            },
        );
        let mut budget = ReadBudget::unlimited();
        assert_eq!(threshold.read_at(7, 2, &mut budget).unwrap(), vec![0; 2]);
        assert_eq!(
            threshold.read_at(8, 1, &mut budget),
            Err(Error::Unsupported("threshold".into()))
        );
        assert_eq!(
            threshold.read_at(u64::MAX, 1, &mut budget),
            Err(Error::Unsupported("threshold".into()))
        );

        let crossing = RangeSourceTestDouble::resident(vec![0; 16], "crossing").with_read_fault(
            ReadFault::ContainsOffset {
                offset: 8,
                error: InjectedError::TruncatedOne { offset: 8 },
            },
        );
        assert!(crossing.read_at(7, 1, &mut budget).is_ok());
        assert!(crossing.read_at(7, 2, &mut budget).is_err());
        assert!(crossing.read_at(8, 0, &mut budget).is_ok());
        assert!(crossing.read_at(8, 1, &mut budget).is_err());
        let overflow = RangeSourceTestDouble::resident(vec![0; 1], "overflow").with_read_fault(
            ReadFault::ContainsOffset {
                offset: u64::MAX,
                error: InjectedError::Unsupported("overflow"),
            },
        );
        assert!(overflow
            .read_at(u64::MAX - 1, u64::MAX, &mut budget)
            .is_err());

        let end = RangeSourceTestDouble::resident(vec![0; 16], "end").with_read_fault(
            ReadFault::EndAfter {
                boundary: 8,
                error: InjectedError::Unsupported("end"),
            },
        );
        assert!(end.read_at(7, 1, &mut budget).is_ok());
        assert!(end.read_at(8, 0, &mut budget).is_ok());
        assert!(end.read_at(8, 1, &mut budget).is_err());
        assert!(end.read_at(u64::MAX, 2, &mut budget).is_err());

        let counted_budget_failure = RangeSourceTestDouble::resident(vec![0; 4], "budget");
        let mut empty_budget = ReadBudget::limited(0);
        assert!(matches!(
            counted_budget_failure.read_at(0, 1, &mut empty_budget),
            Err(Error::ResourceLimit { .. })
        ));
        assert_eq!(
            (
                counted_budget_failure.read_calls(),
                counted_budget_failure.read_bytes(),
                empty_budget.spent(),
            ),
            (1, 1, 0)
        );
    }

    #[test]
    fn always_fail_is_sparse_uses_default_shared_read_and_pins_stability_schedule() {
        let source = RangeSourceTestDouble::size_only(u64::MAX, "huge")
            .with_read_fault(ReadFault::Always(InjectedError::Unsupported("read")))
            .with_verification_fault(1, InjectedError::Malformed("changed"));
        let mut budget = ReadBudget::limited(0);
        assert_eq!(
            source.read_at(0, 0, &mut budget),
            Err(Error::Unsupported("read".into()))
        );
        assert!(matches!(
            source.read_shared_at(3, 4, &mut budget),
            Err(Error::Unsupported(message)) if message == "read"
        ));
        assert_eq!(
            (source.read_calls(), source.read_bytes(), budget.spent()),
            (2, 4, 0)
        );
        assert_eq!(source.verify_unchanged(), Ok(()));
        assert_eq!(
            source.verify_unchanged(),
            Err(Error::Malformed("changed".into()))
        );
        assert_eq!(source.verification_calls(), 2);

        let inner: Arc<dyn RangeSource> = Arc::new(
            RangeSourceTestDouble::size_only(0, "inner")
                .with_verification_fault(0, InjectedError::Malformed("inner changed")),
        );
        let forwarding = RangeSourceTestDouble::wrapping(inner);
        assert_eq!(
            forwarding.verify_unchanged(),
            Err(Error::Malformed("inner changed".into()))
        );
        assert_eq!(forwarding.verification_calls(), 1);
    }
}
