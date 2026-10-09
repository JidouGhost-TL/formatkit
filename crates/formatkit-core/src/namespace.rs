//! Mounted, random-access namespaces shared by discs, archives, and object packs.

use std::any::Any;
use std::sync::Arc;

use crate::{Error, RangeSource, Result};

/// One logical child in an indexed namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceEntry {
    pub name: Option<String>,
    /// Offset in the namespace's logical coordinate space.
    pub offset: u64,
    /// Exact stored extent in logical bytes.
    pub size: u64,
}

/// A transform between a member's stored extent and its usable content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberTransform {
    Stored,
    Codec {
        id: &'static str,
    },
    Encrypted {
        id: &'static str,
    },
    Framed {
        id: &'static str,
    },
    Composite {
        id: &'static str,
    },
    /// Compatibility adapters use this until the concrete container publishes
    /// an exact per-member transform.
    LegacyUnknown,
}

/// Broad class of a bounded member transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformKind {
    Codec,
    Encrypted,
    Framed,
    Composite,
}

/// Stable identity shared by transformation accounting and provenance.
///
/// `id` is the user-facing transform label. `recipe_identity` identifies the
/// exact, versioned recipe which produced transformed bytes. Keeping these in
/// one value prevents a mounted namespace and its resulting range source from
/// silently describing different operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransformRecipe {
    pub kind: TransformKind,
    pub id: &'static str,
    pub recipe_identity: &'static str,
}

impl TransformRecipe {
    pub const fn new(kind: TransformKind, id: &'static str, recipe_identity: &'static str) -> Self {
        Self {
            kind,
            id,
            recipe_identity,
        }
    }

    pub const fn member_transform(self) -> MemberTransform {
        match self.kind {
            TransformKind::Codec => MemberTransform::Codec { id: self.id },
            TransformKind::Encrypted => MemberTransform::Encrypted { id: self.id },
            TransformKind::Framed => MemberTransform::Framed { id: self.id },
            TransformKind::Composite => MemberTransform::Composite { id: self.id },
        }
    }
}

impl MemberTransform {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Codec { id }
            | Self::Encrypted { id }
            | Self::Framed { id }
            | Self::Composite { id } => id,
            Self::LegacyUnknown => "legacy-unknown",
        }
    }
}

/// How a usable member source was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAccessMode {
    /// Exact view of an existing source; no member bytes were copied.
    SharedRange,
    /// This member's transform produced a bounded resident snapshot.
    TransformedMaterialization,
    /// A legacy owning parser forced a compatibility materialization.
    LegacyMaterialization,
}

/// Cheap, allocation-free description of how a member can be accessed.
///
/// Walkers consult this before requesting content so shared ranges are not
/// accidentally subjected to decoded-output limits, while transforms can be
/// rejected before they allocate their output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberLayout {
    pub stored_size: u64,
    pub content_size: Option<u64>,
    pub transform: MemberTransform,
    pub access: MemberAccessMode,
}

impl MemberAccessMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SharedRange => "shared-range",
            Self::TransformedMaterialization => "transformed-materialization",
            Self::LegacyMaterialization => "legacy-materialization",
        }
    }
}

/// Usable content plus an honest account of its storage transformation.
#[derive(Clone)]
pub struct MemberContentSource {
    pub source: Arc<dyn RangeSource>,
    pub transform: MemberTransform,
    pub access: MemberAccessMode,
    /// Bytes materialized specifically to produce this content source. This
    /// may exceed `source.size()` when a member is a slice of a decoded group.
    pub materialized_bytes: u64,
}

impl std::fmt::Debug for MemberContentSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemberContentSource")
            .field("size", &self.source.size())
            .field("transform", &self.transform)
            .field("access", &self.access)
            .field("materialized_bytes", &self.materialized_bytes)
            .finish()
    }
}

/// An optional logical interpretation of one stored namespace member.
///
/// The primary namespace entry and [`IndexedNamespace::stored_source`] remain
/// the lossless stored extent. Consumers which want semantic classification
/// may request this separately, so framed subranges and composite views do not
/// erase producer padding, tails, or sibling allocations.
#[derive(Clone)]
pub struct MemberSemanticView {
    pub format: &'static str,
    pub content: MemberContentSource,
}

impl std::fmt::Debug for MemberSemanticView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemberSemanticView")
            .field("format", &self.format)
            .field("content", &self.content)
            .finish()
    }
}

/// A child namespace whose identity is proven by its authenticated parent
/// context and the child's own bounded grammar.
pub struct ContextualMemberNamespace {
    pub format: &'static str,
    pub namespace: Box<dyn IndexedNamespace>,
}

/// Opaque owner capability carried by a trusted traversal. Owners keep token
/// construction private and validate both the token type and receiving parent.
/// This is not a serialized proof or an automatic sibling resolver.
pub type NamespaceTraversalContext = Arc<dyn std::any::Any + Send + Sync>;

impl std::fmt::Debug for ContextualMemberNamespace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContextualMemberNamespace")
            .field("format", &self.format)
            .field("member_count", &self.namespace.len())
            .finish_non_exhaustive()
    }
}

/// A mounted indexed namespace.
///
/// Implementations expose child sources rather than extracted paths. Concrete
/// format handlers may downcast the parent through [`Self::as_any`] to build a
/// typed address-space context, while generic walkers remain format-neutral.
pub trait IndexedNamespace: Send + Sync {
    fn entries(&self) -> &[NamespaceEntry];

    /// Whether this implementation overrides the aggregate-work member-open
    /// path with complete accounting for its reads and materialization.
    fn supports_work_budget_member_open(&self) -> bool {
        false
    }

    /// Contribute owner context at this namespace boundary. The default
    /// preserves inherited context; the caller must scope it to descendants.
    fn traversal_context(
        &self,
        inherited: Option<&NamespaceTraversalContext>,
    ) -> Option<NamespaceTraversalContext> {
        inherited.cloned()
    }

    /// Whether this owner can supply a semantic operation's required context.
    /// The operation must validate the token again before using its sources.
    fn has_contextual_member_format(
        &self,
        _format: &str,
        _context: Option<&NamespaceTraversalContext>,
    ) -> bool {
        false
    }

    fn raw_name_bytes(&self, _index: usize) -> Option<&[u8]> {
        None
    }

    /// Optional byte-declared semantic role supplied by the owning namespace.
    /// This qualifies generic content detection without turning a weak child
    /// signature into an owner-level semantic claim.
    fn declared_member_role(&self, _index: usize) -> Option<&'static str> {
        None
    }

    /// Lazily validate and expose an optional semantic view without changing
    /// the member's stored/content extraction contract. The default has no
    /// alternate view. Implementations must propagate source and resource
    /// failures; `Ok(None)` means the stored bytes have no proven view.
    fn semantic_member_view(
        &self,
        _index: usize,
        _budget: &mut crate::ReadBudget,
    ) -> Result<Option<MemberSemanticView>> {
        Ok(None)
    }

    /// Optionally mount a child through authenticated parent context before a
    /// generic walker reads a large classification prefix. Implementations
    /// must still validate the complete child grammar and propagate source or
    /// resource failures; `Ok(None)` is only an ordinary contextual miss.
    fn contextual_member_namespace(
        &self,
        _index: usize,
        _budget: &mut crate::ReadBudget,
    ) -> Result<Option<ContextualMemberNamespace>> {
        Ok(None)
    }

    fn member_layout(&self, index: usize) -> Result<MemberLayout> {
        let entry = self.entries().get(index).ok_or(Error::InvalidField {
            what: "namespace member index",
            value: index as u64,
        })?;
        Ok(MemberLayout {
            stored_size: entry.size,
            content_size: Some(entry.size),
            transform: MemberTransform::Stored,
            access: MemberAccessMode::SharedRange,
        })
    }

    /// Validate integrity metadata required before claiming that a semantic
    /// opener consumed trustworthy content. `max_output_len` bounds any
    /// decoded materialization validation requires. The default has no extra
    /// checksum contract beyond a valid member layout.
    fn validate_member(
        &self,
        index: usize,
        _max_output_len: u64,
        _budget: &mut crate::ReadBudget,
    ) -> Result<()> {
        self.member_layout(index).map(|_| ())
    }

    /// Exact stored member extent in the namespace's coordinate space.
    fn stored_source(&self, index: usize) -> Result<Arc<dyn RangeSource>>;

    /// Usable member content. Stored members normally inherit the default;
    /// transformed members override it and enforce their decoded-size policy.
    fn content_source(
        &self,
        index: usize,
        _max_output_len: u64,
        _budget: &mut crate::ReadBudget,
    ) -> Result<MemberContentSource> {
        Ok(MemberContentSource {
            source: self.stored_source(index)?,
            transform: MemberTransform::Stored,
            access: MemberAccessMode::SharedRange,
            materialized_bytes: 0,
        })
    }

    /// Validate integrity metadata and return usable content as one operation.
    ///
    /// The default preserves the separate validation/opening contract. Formats
    /// whose validation necessarily performs the content transform can
    /// override this method to avoid decoding the same member twice.
    fn validated_content_source(
        &self,
        index: usize,
        max_output_len: u64,
        budget: &mut crate::ReadBudget,
    ) -> Result<MemberContentSource> {
        self.validate_member(index, max_output_len, budget)?;
        self.content_source(index, max_output_len, budget)
    }

    /// Validate and open a member under the aggregate execution budget.
    ///
    /// This additive operation leaves the legacy [`crate::ReadBudget`] API
    /// intact. Its default compatibility route can account logical source
    /// requests, but cannot enforce physical-I/O or pre-allocation
    /// materialization ceilings. It therefore refuses those finite policies
    /// instead of silently claiming they were enforced. Adopted namespaces
    /// override this method and charge work before I/O or allocation.
    fn validated_content_source_with_work(
        &self,
        index: usize,
        max_output_len: u64,
        budget: &mut crate::WorkBudget,
    ) -> Result<MemberContentSource> {
        use crate::WorkResource;

        if budget.is_limited(WorkResource::IoRequestedBytes)
            || budget.is_limited(WorkResource::IoReadCalls)
        {
            return Err(Error::Unsupported(
                "legacy namespace member opening cannot account physical I/O".into(),
            ));
        }
        if budget.is_limited(WorkResource::MaterializedBytes) {
            return Err(Error::Unsupported(
                "legacy namespace member opening cannot reserve materialized output".into(),
            ));
        }
        budget.mark_uninstrumented_io()?;
        let mut reads = match budget.remaining(WorkResource::LogicalReadBytes) {
            Some(remaining) => crate::ReadBudget::limited(remaining),
            None => crate::ReadBudget::unlimited(),
        };
        let result = self.validated_content_source(index, max_output_len, &mut reads);
        // The compatibility reader admits requests before access, so failed
        // work remains spent just like native WorkBudget reads.
        budget.charge(WorkResource::LogicalReadBytes, reads.spent())?;
        if let Ok(content) = &result {
            budget.charge(WorkResource::MaterializedBytes, content.materialized_bytes)?;
        }
        result
    }

    fn as_any(&self) -> Option<&dyn Any> {
        None
    }

    fn len(&self) -> usize {
        self.entries().len()
    }

    fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.entries()
            .iter()
            .position(|entry| entry.name.as_deref() == Some(name))
    }
}

/// Explicit safety limits for a [`StoredRangeNamespace`].
///
/// Format parsers normally enforce tighter grammar-specific bounds while
/// reading their directory. Requiring limits again at the shared namespace
/// boundary prevents an adapter from accidentally turning an unbounded table
/// into a large collection of retained names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredRangeNamespaceLimits {
    pub max_entries: usize,
    pub max_name_bytes: usize,
    pub max_total_name_bytes: usize,
}

/// When a [`StoredRangeNamespace`] revalidates its immutable source identity.
///
/// The default constructors use [`Self::OnMemberOpen`]. `MountOnly` exists for
/// compatibility adapters whose owner contract already authenticates a paired
/// source before and after parsing and historically did not add another check
/// while creating a member view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredRangeRevalidation {
    OnMemberOpen,
    MountOnly,
}

/// A namespace whose members are exact shared ranges of one immutable source.
///
/// The type deliberately imposes no filesystem-like assumptions: aliases,
/// overlaps, nested extents, duplicate names, unnamed entries, and zero-length
/// members are all valid container semantics. It performs no parsing,
/// decompression, name normalization, or writer inference.
pub struct StoredRangeNamespace {
    source: Arc<dyn RangeSource>,
    entries: Vec<NamespaceEntry>,
    raw_names: Option<Vec<Option<Vec<u8>>>>,
    revalidation: StoredRangeRevalidation,
}

impl std::fmt::Debug for StoredRangeNamespace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRangeNamespace")
            .field("source_size", &self.source.size())
            .field("entries", &self.entries)
            .field("raw_names", &self.raw_names)
            .finish()
    }
}

impl StoredRangeNamespace {
    pub fn new(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        raw_names: Vec<Option<Vec<u8>>>,
        limits: StoredRangeNamespaceLimits,
    ) -> Result<Self> {
        Self::new_with_revalidation(
            source,
            entries,
            raw_names,
            limits,
            StoredRangeRevalidation::OnMemberOpen,
        )
    }

    pub fn new_with_revalidation(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        raw_names: Vec<Option<Vec<u8>>>,
        limits: StoredRangeNamespaceLimits,
        revalidation: StoredRangeRevalidation,
    ) -> Result<Self> {
        Self::new_inner(source, entries, Some(raw_names), limits, revalidation, None)
    }

    /// Budget-aware constructor with the same admission policy as [`Self::new`].
    ///
    /// Cancellation is checked before each entry. Every entry whose
    /// verification starts charges one node for that work; every entry whose
    /// extent and name checks pass then charges one member for the admitted
    /// child. The O(1) entry-count and total-name-bytes ceiling checks carry
    /// no per-entry charge, and the trailing source-stability recheck is
    /// preserved.
    pub fn new_with_budget(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        raw_names: Vec<Option<Vec<u8>>>,
        limits: StoredRangeNamespaceLimits,
        budget: &mut crate::WorkBudget,
    ) -> Result<Self> {
        Self::new_inner_with_budget(
            source,
            entries,
            Some(raw_names),
            limits,
            StoredRangeRevalidation::OnMemberOpen,
            Some(budget),
            true,
        )
    }

    /// Validate and retain named entries while observing cooperative
    /// cancellation, without charging work already admitted by the owner.
    pub fn new_with_work(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        raw_names: Vec<Option<Vec<u8>>>,
        limits: StoredRangeNamespaceLimits,
        budget: &mut crate::WorkBudget,
    ) -> Result<Self> {
        Self::new_inner(
            source,
            entries,
            Some(raw_names),
            limits,
            StoredRangeRevalidation::OnMemberOpen,
            Some(budget),
        )
    }

    fn new_inner(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        raw_names: Option<Vec<Option<Vec<u8>>>>,
        limits: StoredRangeNamespaceLimits,
        revalidation: StoredRangeRevalidation,
        budget: Option<&mut crate::WorkBudget>,
    ) -> Result<Self> {
        Self::new_inner_with_budget(
            source,
            entries,
            raw_names,
            limits,
            revalidation,
            budget,
            false,
        )
    }

    fn new_inner_with_budget(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        raw_names: Option<Vec<Option<Vec<u8>>>>,
        limits: StoredRangeNamespaceLimits,
        revalidation: StoredRangeRevalidation,
        budget: Option<&mut crate::WorkBudget>,
        charge_work: bool,
    ) -> Result<Self> {
        use crate::WorkResource;
        if entries.len() > limits.max_entries {
            return Err(Error::ResourceLimit {
                resource: "namespace entries",
                requested: entries.len() as u64,
                limit: limits.max_entries as u64,
            });
        }
        if raw_names
            .as_ref()
            .is_some_and(|names| names.len() != entries.len())
        {
            return Err(Error::Malformed(format!(
                "namespace raw-name count {} does not match entry count {}",
                raw_names.as_ref().map_or(0, Vec::len),
                entries.len()
            )));
        }

        let mut budget = budget;
        if let Some(budget) = budget.as_mut() {
            budget.check_cancelled()?;
        }
        let mut total_name_bytes = 0usize;
        for (index, entry) in entries.iter().enumerate() {
            if let Some(budget) = budget.as_deref_mut() {
                budget.check_cancelled()?;
                if charge_work {
                    budget.charge(WorkResource::Nodes, 1)?;
                }
            }
            let end = entry.offset.checked_add(entry.size).ok_or_else(|| {
                Error::Malformed(format!("namespace member {index} extent overflows u64"))
            })?;
            if end > source.size() {
                return Err(Error::Malformed(format!(
                    "namespace member {index} extent {:#x}..{end:#x} exceeds source size {:#x}",
                    entry.offset,
                    source.size()
                )));
            }
            let display_len = entry.name.as_ref().map_or(0, String::len);
            let raw_len = raw_names
                .as_ref()
                .and_then(|names| names[index].as_ref())
                .map_or(0, Vec::len);
            let largest = display_len.max(raw_len);
            if largest > limits.max_name_bytes {
                return Err(Error::ResourceLimit {
                    resource: "namespace member name bytes",
                    requested: largest as u64,
                    limit: limits.max_name_bytes as u64,
                });
            }
            total_name_bytes = total_name_bytes
                .checked_add(display_len)
                .and_then(|total| total.checked_add(raw_len))
                .ok_or_else(|| Error::Malformed("namespace name byte count overflows".into()))?;
            if total_name_bytes > limits.max_total_name_bytes {
                return Err(Error::ResourceLimit {
                    resource: "namespace total name bytes",
                    requested: total_name_bytes as u64,
                    limit: limits.max_total_name_bytes as u64,
                });
            }
            if charge_work {
                let budget = budget
                    .as_deref_mut()
                    .expect("charged namespace construction requires a work budget");
                budget.charge(WorkResource::Members, 1)?;
            }
        }
        source.verify_unchanged()?;
        Ok(Self {
            source,
            entries,
            raw_names,
            revalidation,
        })
    }

    pub fn without_raw_names(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        limits: StoredRangeNamespaceLimits,
    ) -> Result<Self> {
        Self::new_inner(
            source,
            entries,
            None,
            limits,
            StoredRangeRevalidation::OnMemberOpen,
            None,
        )
    }

    /// Budget-aware constructor with the same admission policy as
    /// [`Self::without_raw_names`].
    ///
    /// Cancellation is checked before each entry. Each validation attempt
    /// charges one node before inspecting the extent or name, then charges one
    /// member only after that entry passes validation. This is the canonical
    /// path for owners which have not already admitted their namespace rows.
    pub fn without_raw_names_with_budget(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        limits: StoredRangeNamespaceLimits,
        budget: &mut crate::WorkBudget,
    ) -> Result<Self> {
        Self::new_inner_with_budget(
            source,
            entries,
            None,
            limits,
            StoredRangeRevalidation::OnMemberOpen,
            Some(budget),
            true,
        )
    }

    /// Validate and retain `entries` exactly like
    /// [`Self::without_raw_names`], observing the operation's cooperative
    /// cancellation token before validating each entry.
    ///
    /// This constructor charges no additional work: owners admit member nodes
    /// and retained bytes before materializing `entries`, so per-entry charges
    /// here would double-count. Cancellation is checked first in every
    /// iteration, so a request raised mid-validation stops before any later
    /// entry is examined.
    pub fn without_raw_names_with_work(
        source: Arc<dyn RangeSource>,
        entries: Vec<NamespaceEntry>,
        limits: StoredRangeNamespaceLimits,
        budget: &mut crate::WorkBudget,
    ) -> Result<Self> {
        Self::new_inner_with_budget(
            source,
            entries,
            None,
            limits,
            StoredRangeRevalidation::OnMemberOpen,
            Some(budget),
            false,
        )
    }
}

impl IndexedNamespace for StoredRangeNamespace {
    fn entries(&self) -> &[NamespaceEntry] {
        &self.entries
    }

    fn supports_work_budget_member_open(&self) -> bool {
        true
    }

    fn raw_name_bytes(&self, index: usize) -> Option<&[u8]> {
        self.raw_names
            .as_ref()
            .and_then(|names| names.get(index))
            .and_then(Option::as_deref)
    }

    fn stored_source(&self, index: usize) -> Result<Arc<dyn RangeSource>> {
        let entry = self.entries.get(index).ok_or(Error::InvalidField {
            what: "namespace member index",
            value: index as u64,
        })?;
        if self.revalidation == StoredRangeRevalidation::OnMemberOpen {
            self.source.verify_unchanged()?;
        }
        Ok(Arc::new(crate::SliceRangeSource::new(
            self.source.clone(),
            entry.offset,
            entry.size,
            entry.name.clone().unwrap_or_else(|| format!("#{index}")),
        )?))
    }

    fn validated_content_source_with_work(
        &self,
        index: usize,
        _max_output_len: u64,
        budget: &mut crate::WorkBudget,
    ) -> Result<MemberContentSource> {
        budget.check_cancelled()?;
        // A stored member is only a retained source view: no member bytes are
        // read and no transformed output is allocated while opening it.
        Ok(MemberContentSource {
            source: self.stored_source(index)?,
            transform: MemberTransform::Stored,
            access: MemberAccessMode::SharedRange,
            materialized_bytes: 0,
        })
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// A child mounted in, and still linked to, its parent namespace.
#[derive(Clone, Copy)]
pub struct MountedMember<'a> {
    namespace: &'a dyn IndexedNamespace,
    index: usize,
}

impl<'a> MountedMember<'a> {
    pub fn mount(namespace: &'a dyn IndexedNamespace, index: usize) -> Result<Self> {
        namespace.entries().get(index).ok_or(Error::InvalidField {
            what: "namespace member index",
            value: index as u64,
        })?;
        Ok(Self { namespace, index })
    }

    pub fn namespace(self) -> &'a dyn IndexedNamespace {
        self.namespace
    }

    pub fn index(self) -> usize {
        self.index
    }

    pub fn entry(self) -> &'a NamespaceEntry {
        &self.namespace.entries()[self.index]
    }

    pub fn raw_name_bytes(self) -> Option<&'a [u8]> {
        self.namespace.raw_name_bytes(self.index)
    }

    pub fn stored_source(self) -> Result<Arc<dyn RangeSource>> {
        self.namespace.stored_source(self.index)
    }

    pub fn layout(self) -> Result<MemberLayout> {
        self.namespace.member_layout(self.index)
    }

    pub fn validate(self, max_output_len: u64, budget: &mut crate::ReadBudget) -> Result<()> {
        self.namespace
            .validate_member(self.index, max_output_len, budget)
    }

    pub fn content_source(
        self,
        max_output_len: u64,
        budget: &mut crate::ReadBudget,
    ) -> Result<MemberContentSource> {
        self.namespace
            .content_source(self.index, max_output_len, budget)
    }

    pub fn validated_content_source(
        self,
        max_output_len: u64,
        budget: &mut crate::ReadBudget,
    ) -> Result<MemberContentSource> {
        self.namespace
            .validated_content_source(self.index, max_output_len, budget)
    }

    pub fn sibling(self, index: usize) -> Result<Self> {
        Self::mount(self.namespace, index)
    }

    pub fn sibling_named(self, name: &str) -> Option<Self> {
        self.namespace.find(name).map(|index| Self {
            namespace: self.namespace,
            index,
        })
    }
}

pub struct MountedMembers<'a> {
    namespace: &'a dyn IndexedNamespace,
    next: usize,
}

impl<'a> MountedMembers<'a> {
    pub fn new(namespace: &'a dyn IndexedNamespace) -> Self {
        Self { namespace, next: 0 }
    }
}

impl<'a> Iterator for MountedMembers<'a> {
    type Item = MountedMember<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        if index >= self.namespace.len() {
            return None;
        }
        self.next += 1;
        Some(MountedMember {
            namespace: self.namespace,
            index,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.namespace.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for MountedMembers<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryRangeSource, ReadBudget, SharedBytes, SliceRangeSource, WorkBudget, WorkLimits,
        WorkResource,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FixtureNamespace {
        entries: Vec<NamespaceEntry>,
        source: Arc<dyn RangeSource>,
    }

    impl IndexedNamespace for FixtureNamespace {
        fn entries(&self) -> &[NamespaceEntry] {
            &self.entries
        }

        fn stored_source(&self, index: usize) -> Result<Arc<dyn RangeSource>> {
            let entry = self.entries.get(index).ok_or(Error::InvalidField {
                what: "fixture index",
                value: index as u64,
            })?;
            Ok(Arc::new(SliceRangeSource::new(
                self.source.clone(),
                entry.offset,
                entry.size,
                entry.name.clone().unwrap_or_else(|| format!("#{index}")),
            )?))
        }

        fn as_any(&self) -> Option<&dyn Any> {
            Some(self)
        }
    }

    #[test]
    fn mounted_member_retains_parent_and_shared_storage() {
        let root_bytes = SharedBytes::from_vec(b"HEADleafTAIL".to_vec());
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::from_arc(
            Arc::from(root_bytes.as_slice()),
            "fixture",
        ));
        let namespace = FixtureNamespace {
            entries: vec![NamespaceEntry {
                name: Some("asset.bin".into()),
                offset: 4,
                size: 4,
            }],
            source,
        };
        let member = MountedMember::mount(&namespace, 0).unwrap();
        assert_eq!(member.entry().name.as_deref(), Some("asset.bin"));
        assert!(member
            .namespace()
            .as_any()
            .is_some_and(|namespace| namespace.is::<FixtureNamespace>()));
        let mut budget = ReadBudget::limited(4);
        let bytes = member
            .stored_source()
            .unwrap()
            .read_shared_at(0, 4, &mut budget)
            .unwrap();
        assert_eq!(bytes.as_slice(), b"leaf");
        assert_eq!(budget.spent(), 4);
    }

    #[test]
    fn stored_namespace_work_open_uses_no_read_or_materialization_allowance() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"stored".to_vec(), "fixture"));
        let namespace = StoredRangeNamespace::without_raw_names(
            source,
            vec![NamespaceEntry {
                name: Some("member.bin".into()),
                offset: 0,
                size: 6,
            }],
            StoredRangeNamespaceLimits {
                max_entries: 1,
                max_name_bytes: 16,
                max_total_name_bytes: 16,
            },
        )
        .unwrap();
        let mut work = WorkBudget::new(
            WorkLimits::unlimited()
                .with(WorkResource::LogicalReadBytes, 0)
                .with(WorkResource::IoRequestedBytes, 0)
                .with(WorkResource::IoReadCalls, 0)
                .with(WorkResource::MaterializedBytes, 0),
        );
        let content = namespace
            .validated_content_source_with_work(0, 0, &mut work)
            .unwrap();
        assert_eq!(content.access, MemberAccessMode::SharedRange);
        assert_eq!(content.source.size(), 6);
        for resource in [
            WorkResource::LogicalReadBytes,
            WorkResource::IoRequestedBytes,
            WorkResource::IoReadCalls,
            WorkResource::MaterializedBytes,
        ] {
            assert_eq!(work.spent(resource), 0);
        }
    }

    #[test]
    fn stored_namespace_work_open_checks_cancellation_before_verification() {
        let source = Arc::new(crate::RangeSourceTestDouble::resident(
            b"stored".to_vec(),
            "fixture",
        ));
        let namespace = StoredRangeNamespace::without_raw_names(
            source.clone(),
            vec![NamespaceEntry {
                name: Some("member.bin".into()),
                offset: 0,
                size: 6,
            }],
            STORED_LIMITS,
        )
        .unwrap();
        let verified_at_mount = source.verification_calls();

        let token = crate::CancellationToken::new();
        token.cancel();
        let mut cancelled = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert!(matches!(
            namespace.validated_content_source_with_work(0, 6, &mut cancelled),
            Err(Error::Cancelled)
        ));
        assert!(cancelled.cancellation_observed());
        assert_eq!(source.verification_calls(), verified_at_mount);
        assert_eq!(source.read_calls(), 0);
        assert_eq!(source.read_bytes(), 0);
        for resource in [
            WorkResource::LogicalReadBytes,
            WorkResource::IoRequestedBytes,
            WorkResource::IoReadCalls,
            WorkResource::MaterializedBytes,
            WorkResource::OutputBytes,
            WorkResource::Nodes,
            WorkResource::Members,
        ] {
            assert_eq!(cancelled.spent(resource), 0);
        }

        let mut live = WorkBudget::new(WorkLimits::unlimited());
        let content = namespace
            .validated_content_source_with_work(0, 6, &mut live)
            .unwrap();
        assert_eq!(content.access, MemberAccessMode::SharedRange);
        assert_eq!(content.source.size(), 6);
        assert_eq!(source.verification_calls(), verified_at_mount + 1);
        assert_eq!(source.read_calls(), 0);
        assert_eq!(live.spent(WorkResource::MaterializedBytes), 0);
    }

    #[test]
    fn legacy_work_open_refuses_unaccountable_finite_materialization() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"stored".to_vec(), "fixture"));
        let namespace = FixtureNamespace {
            entries: vec![NamespaceEntry {
                name: None,
                offset: 0,
                size: 6,
            }],
            source,
        };
        let mut work =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::MaterializedBytes, 6));
        assert!(matches!(
            namespace.validated_content_source_with_work(0, 6, &mut work),
            Err(Error::Unsupported(message)) if message.contains("materialized")
        ));

        let mut work = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::IoReadCalls, 1));
        assert!(matches!(
            namespace.validated_content_source_with_work(0, 6, &mut work),
            Err(Error::Unsupported(message)) if message.contains("physical I/O")
        ));
    }

    #[test]
    fn semantic_view_is_optional_and_does_not_replace_primary_content() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"stored".to_vec(), "fixture"));
        let namespace = FixtureNamespace {
            entries: vec![NamespaceEntry {
                name: Some("member.bin".into()),
                offset: 0,
                size: 6,
            }],
            source,
        };
        let mut budget = ReadBudget::limited(6);
        assert!(namespace
            .semantic_member_view(0, &mut budget)
            .unwrap()
            .is_none());
        assert_eq!(budget.spent(), 0);
        let content = namespace.content_source(0, 6, &mut budget).unwrap();
        assert_eq!(content.transform, MemberTransform::Stored);
        assert_eq!(
            content.source.read_at(0, 6, &mut budget).unwrap(),
            b"stored"
        );
    }

    #[test]
    fn sibling_lookup_and_invalid_mount_are_explicit() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"ab".to_vec(), "fixture"));
        let namespace = FixtureNamespace {
            entries: vec![
                NamespaceEntry {
                    name: Some("a".into()),
                    offset: 0,
                    size: 1,
                },
                NamespaceEntry {
                    name: Some("b".into()),
                    offset: 1,
                    size: 1,
                },
            ],
            source,
        };
        let first = MountedMember::mount(&namespace, 0).unwrap();
        assert_eq!(first.sibling_named("b").unwrap().index(), 1);
        assert!(MountedMember::mount(&namespace, 2).is_err());
    }

    const STORED_LIMITS: StoredRangeNamespaceLimits = StoredRangeNamespaceLimits {
        max_entries: 8,
        max_name_bytes: 32,
        max_total_name_bytes: 128,
    };

    #[test]
    fn stored_ranges_preserve_aliases_overlaps_zero_lengths_and_raw_names() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"0123456789".to_vec(), "fixture"));
        let namespace = StoredRangeNamespace::new(
            source,
            vec![
                NamespaceEntry {
                    name: Some("alias-a".into()),
                    offset: 2,
                    size: 4,
                },
                NamespaceEntry {
                    name: Some("alias-b".into()),
                    offset: 2,
                    size: 4,
                },
                NamespaceEntry {
                    name: None,
                    offset: 4,
                    size: 0,
                },
            ],
            vec![Some(b"raw-a".to_vec()), Some(b"raw-b".to_vec()), None],
            STORED_LIMITS,
        )
        .unwrap();

        assert_eq!(namespace.raw_name_bytes(0), Some(b"raw-a".as_slice()));
        assert_eq!(namespace.member_layout(2).unwrap().stored_size, 0);
        let mut budget = ReadBudget::limited(8);
        for index in 0..2 {
            assert_eq!(
                namespace
                    .stored_source(index)
                    .unwrap()
                    .read_at(0, 4, &mut budget)
                    .unwrap(),
                b"2345"
            );
        }
        assert_eq!(budget.spent(), 8);
    }

    #[test]
    fn stored_ranges_reject_bad_extents_name_shapes_and_limits() {
        let source =
            || -> Arc<dyn RangeSource> { Arc::new(MemoryRangeSource::new(vec![0; 8], "fixture")) };
        let entry = NamespaceEntry {
            name: Some("member".into()),
            offset: 7,
            size: 2,
        };
        assert!(matches!(
            StoredRangeNamespace::new(source(), vec![entry], vec![None], STORED_LIMITS),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            StoredRangeNamespace::new(source(), vec![], vec![None], STORED_LIMITS),
            Err(Error::Malformed(_))
        ));
        let tiny = StoredRangeNamespaceLimits {
            max_entries: 0,
            ..STORED_LIMITS
        };
        assert!(matches!(
            StoredRangeNamespace::without_raw_names(
                source(),
                vec![NamespaceEntry {
                    name: None,
                    offset: 0,
                    size: 0,
                }],
                tiny,
            ),
            Err(Error::ResourceLimit {
                resource: "namespace entries",
                ..
            })
        ));
    }

    fn budgeted_entries() -> (Vec<NamespaceEntry>, Vec<Option<Vec<u8>>>) {
        (
            vec![
                NamespaceEntry {
                    name: Some("a".into()),
                    offset: 0,
                    size: 4,
                },
                NamespaceEntry {
                    name: Some("b".into()),
                    offset: 4,
                    size: 4,
                },
            ],
            vec![None, None],
        )
    }

    #[test]
    fn stored_ranges_budgeted_construction_charges_nodes_members_and_cancellation() {
        let source =
            || -> Arc<dyn RangeSource> { Arc::new(MemoryRangeSource::new(vec![0; 8], "fixture")) };
        // Exact admission charges one node and one member per entry.
        let (entries, raw) = budgeted_entries();
        let mut exact = WorkBudget::new(
            WorkLimits::unlimited()
                .with(WorkResource::Nodes, 2)
                .with(WorkResource::Members, 2),
        );
        StoredRangeNamespace::new_with_budget(source(), entries, raw, STORED_LIMITS, &mut exact)
            .unwrap();
        assert_eq!(exact.spent(WorkResource::Nodes), 2);
        assert_eq!(exact.spent(WorkResource::Members), 2);

        // One node short fails before the trailing member is admitted.
        let (entries, raw) = budgeted_entries();
        let mut nodes_short = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::Nodes, 1));
        assert!(matches!(
            StoredRangeNamespace::new_with_budget(
                source(),
                entries,
                raw,
                STORED_LIMITS,
                &mut nodes_short
            ),
            Err(Error::ResourceLimit { .. })
        ));
        assert_eq!(nodes_short.spent(WorkResource::Nodes), 1);
        assert_eq!(nodes_short.spent(WorkResource::Members), 1);

        // One member short fails after the trailing node work is charged.
        let (entries, raw) = budgeted_entries();
        let mut members_short =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::Members, 1));
        assert!(matches!(
            StoredRangeNamespace::new_with_budget(
                source(),
                entries,
                raw,
                STORED_LIMITS,
                &mut members_short
            ),
            Err(Error::ResourceLimit { .. })
        ));
        assert_eq!(members_short.spent(WorkResource::Nodes), 2);
        assert_eq!(members_short.spent(WorkResource::Members), 1);

        // A cancelled ledger fails before any entry is admitted.
        let (entries, raw) = budgeted_entries();
        let token = crate::CancellationToken::new();
        token.cancel();
        let mut cancelled = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert!(matches!(
            StoredRangeNamespace::new_with_budget(
                source(),
                entries,
                raw,
                STORED_LIMITS,
                &mut cancelled
            ),
            Err(Error::Cancelled)
        ));
        assert_eq!(cancelled.spent(WorkResource::Nodes), 0);
        assert_eq!(cancelled.spent(WorkResource::Members), 0);
    }

    #[test]
    fn stored_ranges_without_raw_names_keep_no_parallel_allocation() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"abc".to_vec(), "fixture"));
        let namespace = StoredRangeNamespace::without_raw_names(
            source,
            vec![NamespaceEntry {
                name: Some("member".into()),
                offset: 0,
                size: 3,
            }],
            STORED_LIMITS,
        )
        .unwrap();

        assert!(namespace.raw_names.is_none());
        assert_eq!(namespace.raw_name_bytes(0), None);
    }

    struct MutableFixtureSource {
        changed: AtomicBool,
    }

    impl RangeSource for MutableFixtureSource {
        fn size(&self) -> u64 {
            1
        }

        fn read_at(&self, _: u64, _: u64, _: &mut ReadBudget) -> Result<Vec<u8>> {
            Ok(vec![0])
        }

        fn describe_coordinate_space(&self) -> crate::CoordinateSpaceDescription {
            crate::CoordinateSpaceDescription::bytes("fixture", "mutable", 1)
        }

        fn verify_unchanged(&self) -> Result<()> {
            if self.changed.load(Ordering::Relaxed) {
                Err(Error::Malformed("fixture source changed".into()))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn stored_ranges_validate_source_stability_at_mount_and_open() {
        let source = Arc::new(MutableFixtureSource {
            changed: AtomicBool::new(false),
        });
        let namespace = StoredRangeNamespace::without_raw_names(
            source.clone(),
            vec![NamespaceEntry {
                name: None,
                offset: 0,
                size: 1,
            }],
            STORED_LIMITS,
        )
        .unwrap();
        source.changed.store(true, Ordering::Relaxed);
        assert!(matches!(
            namespace.stored_source(0),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn work_aware_no_raw_name_construction_matches_plain_construction() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"0123456789".to_vec(), "fixture"));
        let entries = vec![
            NamespaceEntry {
                name: Some("alias-a".into()),
                offset: 2,
                size: 4,
            },
            NamespaceEntry {
                name: None,
                offset: 4,
                size: 0,
            },
        ];
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let namespace = StoredRangeNamespace::without_raw_names_with_work(
            source,
            entries.clone(),
            STORED_LIMITS,
            &mut work,
        )
        .unwrap();
        assert_eq!(namespace.entries(), entries.as_slice());
        assert!(namespace.raw_name_bytes(0).is_none());
        for resource in [
            WorkResource::LogicalReadBytes,
            WorkResource::IoRequestedBytes,
            WorkResource::IoReadCalls,
            WorkResource::MaterializedBytes,
            WorkResource::OutputBytes,
            WorkResource::Nodes,
        ] {
            assert_eq!(work.spent(resource), 0);
        }
        assert!(!work.cancellation_observed());
        assert_eq!(work.usage().peak_resident_bytes(), 0);
    }

    #[test]
    fn work_aware_no_raw_name_construction_observes_pre_cancellation() {
        let source: Arc<dyn RangeSource> =
            Arc::new(MemoryRangeSource::new(b"0123456789".to_vec(), "fixture"));
        let token = crate::CancellationToken::new();
        token.cancel();
        let mut work = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        // Cancellation precedes validation: even a structurally invalid entry
        // list reports Cancelled rather than Malformed.
        let invalid = vec![NamespaceEntry {
            name: None,
            offset: 9,
            size: 2,
        }];
        assert_eq!(
            StoredRangeNamespace::without_raw_names_with_work(
                source,
                invalid,
                STORED_LIMITS,
                &mut work,
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
        assert!(work.cancellation_observed());
    }

    /// Cancels its token while serving the `cancel_after`-th `size` query, so
    /// cancellation is requested mid-validation and must be observed at the
    /// next entry's interruption point.
    struct CancelsOnSizeQuery {
        inner: MemoryRangeSource,
        token: crate::CancellationToken,
        cancel_after: usize,
        queries: std::sync::atomic::AtomicUsize,
    }

    impl RangeSource for CancelsOnSizeQuery {
        fn size(&self) -> u64 {
            let queries = self.queries.fetch_add(1, Ordering::SeqCst) + 1;
            if queries == self.cancel_after {
                self.token.cancel();
            }
            self.inner.size()
        }

        fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
            self.inner.read_at(offset, length, budget)
        }

        fn describe_coordinate_space(&self) -> crate::CoordinateSpaceDescription {
            self.inner.describe_coordinate_space()
        }
    }

    #[test]
    fn work_aware_no_raw_name_construction_cancels_mid_loop_without_later_work() {
        use std::sync::atomic::AtomicUsize;
        const COMPLETED: usize = 3;
        let source = Arc::new(CancelsOnSizeQuery {
            inner: MemoryRangeSource::new(b"0123456789".to_vec(), "cancelling fixture"),
            token: crate::CancellationToken::new(),
            cancel_after: COMPLETED,
            queries: AtomicUsize::new(0),
        });
        // The trailing entry is structurally invalid, so any validation past
        // the cancellation point would surface Malformed instead of Cancelled.
        let entries = vec![
            NamespaceEntry {
                name: Some("a".into()),
                offset: 0,
                size: 2,
            },
            NamespaceEntry {
                name: Some("b".into()),
                offset: 2,
                size: 2,
            },
            NamespaceEntry {
                name: Some("c".into()),
                offset: 4,
                size: 2,
            },
            NamespaceEntry {
                name: Some("d".into()),
                offset: 6,
                size: 2,
            },
            NamespaceEntry {
                name: Some("poison".into()),
                offset: 9,
                size: 2,
            },
        ];
        let token = source.token.clone();
        let mut work = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert_eq!(
            StoredRangeNamespace::without_raw_names_with_work(
                source.clone(),
                entries,
                STORED_LIMITS,
                &mut work,
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
        assert!(work.cancellation_observed());
        assert_eq!(source.queries.load(Ordering::SeqCst), COMPLETED);
    }

    #[test]
    fn stored_ranges_can_preserve_mount_only_revalidation_policy() {
        let source = Arc::new(MutableFixtureSource {
            changed: AtomicBool::new(false),
        });
        let namespace = StoredRangeNamespace::new_with_revalidation(
            source.clone(),
            vec![NamespaceEntry {
                name: Some("member".into()),
                offset: 0,
                size: 1,
            }],
            vec![Some(b"member".to_vec())],
            STORED_LIMITS,
            StoredRangeRevalidation::MountOnly,
        )
        .unwrap();
        source.changed.store(true, Ordering::Relaxed);
        assert!(namespace.stored_source(0).is_ok());
    }

    #[test]
    fn budget_aware_construction_matches_plain_validation_exactly() {
        fn build(budget: Option<&mut WorkBudget>) -> Result<StoredRangeNamespace> {
            let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
                b"0123456789abcdef".to_vec(),
                "fixture",
            ));
            let entries = vec![
                NamespaceEntry {
                    name: Some("a.bin".into()),
                    offset: 0,
                    size: 8,
                },
                NamespaceEntry {
                    name: Some("b.bin".into()),
                    offset: 8,
                    size: 8,
                },
            ];
            match budget {
                Some(budget) => StoredRangeNamespace::without_raw_names_with_budget(
                    source,
                    entries,
                    STORED_LIMITS,
                    budget,
                ),
                None => StoredRangeNamespace::without_raw_names(source, entries, STORED_LIMITS),
            }
        }

        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let plain = build(None).unwrap();
        let aware = build(Some(&mut budget)).unwrap();
        assert_eq!(aware.entries(), plain.entries());
        for resource in [
            WorkResource::LogicalReadBytes,
            WorkResource::MaterializedBytes,
            WorkResource::OutputBytes,
        ] {
            assert_eq!(budget.spent(resource), 0);
        }
        assert_eq!(budget.spent(WorkResource::Nodes), 2);
        assert_eq!(budget.spent(WorkResource::Members), 2);
        assert_eq!(budget.usage().peak_resident_bytes(), 0);

        let exact_entries = vec![
            NamespaceEntry {
                name: Some("a.bin".into()),
                offset: 0,
                size: 8,
            },
            NamespaceEntry {
                name: Some("b.bin".into()),
                offset: 8,
                size: 8,
            },
        ];
        for (resource, limit, expected_other) in [
            (WorkResource::Nodes, 1, (1, 1)),
            (WorkResource::Members, 1, (2, 1)),
        ] {
            let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
                b"0123456789abcdef".to_vec(),
                "fixture",
            ));
            let mut one_short = WorkBudget::new(WorkLimits::unlimited().with(resource, limit));
            assert!(matches!(
                StoredRangeNamespace::without_raw_names_with_budget(
                    source,
                    exact_entries.clone(),
                    STORED_LIMITS,
                    &mut one_short,
                ),
                Err(Error::ResourceLimit { .. })
            ));
            assert_eq!(one_short.spent(WorkResource::Nodes), expected_other.0);
            assert_eq!(one_short.spent(WorkResource::Members), expected_other.1);
        }

        // Every validation failure keeps its exact identity across both paths.
        let failures: Vec<(Vec<NamespaceEntry>, StoredRangeNamespaceLimits)> = vec![
            (
                vec![NamespaceEntry {
                    name: None,
                    offset: u64::MAX,
                    size: 1,
                }],
                STORED_LIMITS,
            ),
            (
                vec![NamespaceEntry {
                    name: None,
                    offset: 15,
                    size: 2,
                }],
                STORED_LIMITS,
            ),
            (
                vec![NamespaceEntry {
                    name: Some("n".repeat(33)),
                    offset: 0,
                    size: 1,
                }],
                STORED_LIMITS,
            ),
            (
                (0..8)
                    .map(|index| NamespaceEntry {
                        name: Some(format!("member-{index:02}-payload.bin")),
                        offset: index,
                        size: 1,
                    })
                    .collect(),
                STORED_LIMITS,
            ),
            (
                (0..9)
                    .map(|_| NamespaceEntry {
                        name: None,
                        offset: 0,
                        size: 1,
                    })
                    .collect(),
                STORED_LIMITS,
            ),
        ];
        for (entries, limits) in failures {
            let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
                b"0123456789abcdef".to_vec(),
                "fixture",
            ));
            let plain =
                StoredRangeNamespace::without_raw_names(source.clone(), entries.clone(), limits)
                    .unwrap_err();
            let mut budget = WorkBudget::new(WorkLimits::unlimited());
            let aware = StoredRangeNamespace::without_raw_names_with_budget(
                source,
                entries,
                limits,
                &mut budget,
            )
            .unwrap_err();
            assert_eq!(
                format!("{aware:?}"),
                format!("{plain:?}"),
                "budget-aware validation must keep plain error identity"
            );
        }

        // The charged constructor fails closed on invalid extents and names;
        // no invalid row is admitted as a member.
        for invalid in [
            NamespaceEntry {
                name: Some("extent".into()),
                offset: 15,
                size: 2,
            },
            NamespaceEntry {
                name: Some("n".repeat(STORED_LIMITS.max_name_bytes + 1)),
                offset: 0,
                size: 1,
            },
        ] {
            let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
                b"0123456789abcdef".to_vec(),
                "fixture",
            ));
            let mut budget = WorkBudget::new(WorkLimits::unlimited());
            assert!(StoredRangeNamespace::without_raw_names_with_budget(
                source,
                vec![invalid],
                STORED_LIMITS,
                &mut budget,
            )
            .is_err());
            assert_eq!(budget.spent(WorkResource::Nodes), 1);
            assert_eq!(budget.spent(WorkResource::Members), 0);
        }

        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"0123456789abcdef".to_vec(),
            "fixture",
        ));
        let aggregate_limits = StoredRangeNamespaceLimits {
            max_entries: 2,
            max_name_bytes: 2,
            max_total_name_bytes: 3,
        };
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        assert!(matches!(
            StoredRangeNamespace::without_raw_names_with_budget(
                source,
                vec![
                    NamespaceEntry {
                        name: Some("aa".into()),
                        offset: 0,
                        size: 1,
                    },
                    NamespaceEntry {
                        name: Some("bb".into()),
                        offset: 1,
                        size: 1,
                    },
                ],
                aggregate_limits,
                &mut budget,
            ),
            Err(Error::ResourceLimit {
                resource: "namespace total name bytes",
                ..
            })
        ));
        assert_eq!(budget.spent(WorkResource::Nodes), 2);
        assert_eq!(budget.spent(WorkResource::Members), 1);
    }

    /// Resident source cancelling a shared token on a fixed `size()` call, so
    /// mid-traversal cancellation of the namespace validation pass is
    /// deterministic: the pass reads `size()` once per entry.
    struct CancellingSizeSource {
        inner: MemoryRangeSource,
        token: crate::CancellationToken,
        calls: std::sync::atomic::AtomicUsize,
        trip_call: usize,
    }

    impl RangeSource for CancellingSizeSource {
        fn size(&self) -> u64 {
            let calls = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if calls == self.trip_call {
                self.token.cancel();
            }
            self.inner.size()
        }

        fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
            self.inner.read_at(offset, length, budget)
        }

        fn describe_coordinate_space(&self) -> crate::CoordinateSpaceDescription {
            self.inner.describe_coordinate_space()
        }
    }

    #[test]
    fn budget_aware_construction_checks_cancellation_per_entry() {
        let entries = || {
            vec![
                NamespaceEntry {
                    name: Some("a.bin".into()),
                    offset: 0,
                    size: 4,
                },
                NamespaceEntry {
                    name: Some("b.bin".into()),
                    offset: 4,
                    size: 4,
                },
                NamespaceEntry {
                    name: Some("c.bin".into()),
                    offset: 8,
                    size: 8,
                },
            ]
        };

        // A pre-cancelled budget fails before the first entry.
        let token = crate::CancellationToken::new();
        token.cancel();
        let mut cancelled = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"0123456789abcdef".to_vec(),
            "fixture",
        ));
        assert_eq!(
            StoredRangeNamespace::without_raw_names_with_budget(
                source,
                entries(),
                STORED_LIMITS,
                &mut cancelled,
            )
            .unwrap_err(),
            Error::Cancelled
        );
        assert!(cancelled.usage().cancellation_observed());

        // Cancellation requested during the second entry's extent check is
        // observed at the third entry's check, proving every iteration checks.
        let token = crate::CancellationToken::new();
        let source: Arc<dyn RangeSource> = Arc::new(CancellingSizeSource {
            inner: MemoryRangeSource::new(b"0123456789abcdef".to_vec(), "fixture"),
            token: token.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            trip_call: 2,
        });
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert_eq!(
            StoredRangeNamespace::without_raw_names_with_budget(
                source,
                entries(),
                STORED_LIMITS,
                &mut budget,
            )
            .unwrap_err(),
            Error::Cancelled
        );
        assert!(budget.usage().cancellation_observed());

        // The same entries mount when nothing requests cancellation.
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
            b"0123456789abcdef".to_vec(),
            "fixture",
        ));
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let namespace = StoredRangeNamespace::without_raw_names_with_budget(
            source,
            entries(),
            STORED_LIMITS,
            &mut budget,
        )
        .unwrap();
        assert_eq!(namespace.len(), 3);
    }
}
