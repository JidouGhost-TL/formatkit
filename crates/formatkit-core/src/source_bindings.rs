//! Operation-local source identities. Handles are not durable evidence or authorization.

use std::sync::Arc;

use crate::{Error, RangeSource, Result, SliceRangeSource};

#[derive(Debug)]
struct OperationIdentity;

/// Identity of a registered backing source in one operation.
/// Equal bytes and equal pathnames never merge registrations.
#[derive(Debug, Clone)]
pub struct SourceHandle {
    operation: Arc<OperationIdentity>,
    index: usize,
}

impl PartialEq for SourceHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.operation, &other.operation) && self.index == other.index
    }
}
impl Eq for SourceHandle {}

/// Identity of a coordinate view of a registered backing source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceViewHandle {
    backing: SourceHandle,
    index: usize,
}

impl SourceViewHandle {
    pub fn backing(&self) -> &SourceHandle {
        &self.backing
    }
}

/// Retains sources opened for one operation; there is no pathname rebinding.
///
/// Registration is explicit. Reuse a handle to declare an alias. Registering
/// the same `Arc` twice creates two distinct identities. Views can only be
/// derived from existing handles, so their ancestry cannot contain cycles.
/// The registry does not authenticate content or infer filesystem aliases.
pub struct SourceBindings {
    operation: Arc<OperationIdentity>,
    backing_count: usize,
    views: Vec<(SourceHandle, Arc<dyn RangeSource>)>,
}

impl Default for SourceBindings {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceBindings {
    pub fn new() -> Self {
        Self {
            operation: Arc::new(OperationIdentity),
            backing_count: 0,
            views: Vec::new(),
        }
    }

    /// Fallibly reserve registry slots before [`Self::register`].
    ///
    /// Callers with a work ledger charge the slot bytes first, then call this
    /// to make the subsequent infallible pushes unable to reallocate. Each
    /// slot retains one [`SourceHandle`] plus one source [`Arc`].
    pub fn try_reserve_views(&mut self, additional: usize) -> Result<()> {
        self.views
            .try_reserve(additional)
            .map_err(|_| Error::ResourceLimit {
                resource: "source binding registry slots",
                requested: additional as u64,
                limit: usize::MAX as u64,
            })
    }

    pub fn register(&mut self, source: Arc<dyn RangeSource>) -> SourceViewHandle {
        let backing = SourceHandle {
            operation: self.operation.clone(),
            index: self.backing_count,
        };
        self.backing_count += 1;
        let handle = SourceViewHandle {
            backing: backing.clone(),
            index: self.views.len(),
        };
        self.views.push((backing, source));
        handle
    }

    pub fn source(&self, handle: &SourceViewHandle) -> Result<&Arc<dyn RangeSource>> {
        if !Arc::ptr_eq(&self.operation, &handle.backing.operation) {
            return Err(Error::Unsupported(
                "source handle belongs to another operation".into(),
            ));
        }
        let (backing, source) = self.views.get(handle.index).ok_or_else(|| {
            Error::Unsupported("source view is not registered in this operation".into())
        })?;
        if backing != &handle.backing {
            return Err(Error::Unsupported(
                "source view has a different backing source".into(),
            ));
        }
        Ok(source)
    }

    /// Register a checked subview. It retains the backing identity while
    /// receiving its own coordinate identity, including for identical ranges.
    pub fn slice(
        &mut self,
        parent: &SourceViewHandle,
        offset: u64,
        length: u64,
        label: impl Into<String>,
    ) -> Result<SourceViewHandle> {
        let source = Arc::new(SliceRangeSource::new(
            self.source(parent)?.clone(),
            offset,
            length,
            label,
        )?);
        let handle = SourceViewHandle {
            backing: parent.backing.clone(),
            index: self.views.len(),
        };
        self.views.push((parent.backing.clone(), source));
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryRangeSource, ReadBudget};

    #[test]
    fn handles_distinguish_operations_backings_and_coordinates() {
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(vec![1, 2, 3], "same"));
        let mut first = SourceBindings::new();
        let root = first.register(source.clone());
        let same_arc = first.register(source.clone());
        assert_ne!(root.backing(), same_arc.backing());
        let slice = first.slice(&root, 1, 2, "slice").unwrap();
        let nested = first.slice(&slice, 1, 1, "nested").unwrap();
        assert_eq!(root.backing(), nested.backing());
        assert_ne!(slice, nested);
        assert_eq!(
            first
                .source(&nested)
                .unwrap()
                .read_at(0, 1, &mut ReadBudget::unlimited())
                .unwrap(),
            [3]
        );
        let mut other = SourceBindings::new();
        let foreign = other.register(source);
        assert!(first.source(&foreign).is_err());
        assert!(other.source(&root).is_err());
        assert!(first.slice(&foreign, 0, 0, "foreign").is_err());
        assert!(first.slice(&root, u64::MAX, 2, "overflow").is_err());
        // Growing the registry does not invalidate the original identity.
        assert_eq!(first.source(&root).unwrap().size(), 3);
    }

    #[test]
    fn try_reserve_views_covers_registrations_without_reallocation() {
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(vec![9], "reserve"));
        let mut bindings = SourceBindings::new();
        bindings.try_reserve_views(2).unwrap();
        let before = bindings.views.capacity();
        let first = bindings.register(source.clone());
        let second = bindings.register(source);
        assert!(bindings.views.capacity() >= before);
        assert_eq!(bindings.source(&first).unwrap().size(), 1);
        assert_eq!(bindings.source(&second).unwrap().size(), 1);
        assert!(bindings.try_reserve_views(usize::MAX).is_err());
    }
}
