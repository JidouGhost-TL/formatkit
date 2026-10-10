//! Runtime composition kernel for format-owned static contributions.
//!
//! Each [`FormatModule`] is exactly one [`FormatId`] ownership row. Decoder
//! families export slices of rows; family aggregation is product policy outside
//! the row. Existing `formatkit-catalog` declarations remain the typed payloads.
//!
//! Operations have an open, owner-chosen static name and purpose. The temporary
//! [`ExistingExecutableOperation`] enum only adapts today's namespace and leaf
//! payloads; it is not operation identity. Role-bound namespace callbacks live
//! on [`ModuleOperation`] while legacy single/pair callbacks remain projected.
//! Writer contracts remain the proof authority. Strict resident writer
//! operations select one exact contract operation and provide a callable;
//! selectors do not duplicate proof-oracle metadata.
//! Cargo proof selectors are syntax-checked here; exact selector resolution is
//! a workspace build/audit gate required before a row is activated as strict.
//!
//! `archive-owner::ArchiveFormat` is deliberately absent: adapting that type here
//! would reverse the dependency boundary. Its owner can project registrations
//! into per-format rows during shadow composition.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::io::Write;

use formatkit_catalog::catalog::{
    BoundInputs, CatalogError, EditMode, EmbeddedFormatSupport, FormatCatalog, FormatDescriptor,
    InputCardinality, InputForm, InputSchema, LeafOperationCatalog, LeafOperationCatalogError,
    LeafOperationProvider, NamespaceMountContract, NamespaceMountInput, NamespaceProvider,
    NamespaceSemantics, OperationScope, RoleBoundNamespaceContract, RoleBoundNamespaceInput,
    RoleBoundNamespaceProvider, SourceProbeOutcome, SupportCatalog, SupportCatalogError,
    WorkMountedNamespace, WorkRunnerOp, WorkRunnerUser, WriterContract,
};
use formatkit_catalog::FormatId;

pub type BoundNamespaceAdapter = fn(
    &formatkit_core::SourceBindings,
    &BoundInputs,
    &[u8],
    &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<
    SourceProbeOutcome<Box<dyn formatkit_core::IndexedNamespace>>,
>;

/// Role-bound namespace runner: mounts without type erasure on the caller's
/// ledger, then invokes the scoped user once with the live mount. The caller
/// declares `op` so the runner preflights the complete mount-plus-operation
/// plan before mounting. Nothing heap-allocated escapes except through the
/// user's own captured delivery values.
pub type BoundRunnerNamespaceAdapter = for<'user> fn(
    &formatkit_core::SourceBindings,
    &BoundInputs,
    &[u8],
    &mut formatkit_core::WorkBudget,
    WorkRunnerOp,
    &'user mut WorkRunnerUser<'user>,
) -> formatkit_core::Result<()>;

/// Work-native role-bound namespace adapter. Unlike [`BoundNamespaceAdapter`],
/// the prepared match keeps its covering resident reservation as a disjoint
/// sibling borrowing the caller's ledger, so live accounting releases exactly
/// when the returned storage drops. The adapter validates its cited evidence
/// before constructing the borrowed mount.
pub type BoundNamespaceWorkAdapter = for<'budget> fn(
    &formatkit_core::SourceBindings,
    &BoundInputs,
    &[u8],
    &'budget mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<
    SourceProbeOutcome<WorkMountedNamespace<'budget>>,
>;

/// Exact selection of one operation already declared by a [`WriterContract`].
///
/// Proof oracles deliberately do not appear here: composition resolves this
/// selector against the contract and the contract remains their sole authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriterProofSelector {
    Reproduction {
        scope: OperationScope,
    },
    Edit {
        mode: EditMode,
        scope: OperationScope,
    },
    Authoring {
        scope: OperationScope,
    },
}

impl WriterProofSelector {
    const fn capabilities(self) -> OperationCapabilities {
        match self {
            Self::Reproduction { .. } => OperationCapabilities::ROUND_TRIP,
            Self::Edit { .. } => OperationCapabilities::EDIT,
            Self::Authoring { .. } => OperationCapabilities::WRITE,
        }
    }

    fn is_declared_by(self, contract: &WriterContract) -> bool {
        match self {
            Self::Reproduction { scope } => contract
                .reproduction
                .is_some_and(|operation| operation.scope == scope),
            Self::Edit { mode, scope } => contract
                .edits
                .iter()
                .any(|operation| operation.mode == mode && operation.scope == scope),
            Self::Authoring { scope } => contract
                .authoring
                .is_some_and(|operation| operation.output_scope == scope),
        }
    }
}

/// HRTB resident-writer callback. The returned allocation cannot outlive the
/// one sequential work ledger which admitted and retains it.
pub type ResidentWriterCallback =
    for<'budget> fn(
        &formatkit_core::SourceBindings,
        &BoundInputs,
        &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<ResidentWriteOutput<'budget>>;

/// Callable resident writer and its exact existing proof selection.
#[derive(Clone, Copy)]
pub struct ResidentWriterProvider {
    pub id: FormatId,
    pub owner: &'static str,
    pub proof: WriterProofSelector,
    pub write: ResidentWriterCallback,
}

impl fmt::Debug for ResidentWriterProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentWriterProvider")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .field("proof", &self.proof)
            .finish_non_exhaustive()
    }
}

/// Resident writer result whose nominal allocation remains reserved until the
/// value is dropped.
///
/// Owners construct an output with [`Self::build`], which admits resident,
/// materialized, and node work before allocating. The byte allocation
/// has no consuming escape; publication or hashing must use the checked
/// [`Self::with_output_and_budget`] bridge while it remains tied to the ledger.
#[must_use = "dropping the output releases its resident-byte reservation"]
pub struct ResidentWriteOutput<'budget> {
    bytes: Vec<u8>,
    resident: formatkit_core::ResidentReservation<'budget>,
}

/// Failure while publishing a resident writer result.
#[derive(Debug)]
pub enum ResidentWriteError {
    Work(formatkit_core::Error),
    Write(std::io::Error),
}

impl fmt::Display for ResidentWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Work(error) => error.fmt(formatter),
            Self::Write(error) => write!(formatter, "write resident output: {error}"),
        }
    }
}

impl std::error::Error for ResidentWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Work(error) => Some(error),
            Self::Write(error) => Some(error),
        }
    }
}

impl From<formatkit_core::Error> for ResidentWriteError {
    fn from(error: formatkit_core::Error) -> Self {
        Self::Work(error)
    }
}

impl fmt::Debug for ResidentWriteOutput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentWriteOutput")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl<'budget> ResidentWriteOutput<'budget> {
    /// Admit and allocate an exact-length output, then let the owner fill it.
    ///
    /// Resident/materialized admissions remain observable if allocation or
    /// construction later fails. `operation` is trusted cooperative code and
    /// must charge source reads or additional work. Output bytes are not charged
    /// until [`Self::write_to`] successfully writes them to a destination.
    pub fn build(
        budget: &'budget mut formatkit_core::WorkBudget,
        length: usize,
        operation: impl for<'operation> FnOnce(
            &'operation mut [u8],
            &'operation mut formatkit_core::WorkBudget,
        ) -> formatkit_core::Result<()>,
    ) -> formatkit_core::Result<Self> {
        budget.check_cancelled()?;
        let amount = u64::try_from(length).map_err(|_| formatkit_core::Error::ResourceLimit {
            resource: "resident writer output bytes",
            requested: u64::MAX,
            limit: u64::MAX,
        })?;
        let mut resident = budget.reserve_resident(amount)?;
        resident.charge(formatkit_core::WorkResource::MaterializedBytes, amount)?;
        resident.charge(formatkit_core::WorkResource::Nodes, 1)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| formatkit_core::Error::ResourceLimit {
                resource: "resident writer output bytes",
                requested: amount,
                limit: usize::MAX as u64,
            })?;
        bytes.resize(length, 0);
        let operation = resident.with_budget(|budget| operation(&mut bytes, budget));
        let cancellation = resident.check_cancelled();
        match operation {
            Err(error) => return Err(error),
            Ok(()) => cancellation?,
        }
        Ok(Self { bytes, resident })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Publish the complete resident output to a sequential destination.
    ///
    /// The full remaining length is admitted before the first destination I/O.
    /// Each successful `Write::write` return is then charged exactly; an error
    /// can therefore leave both a partial destination and the same exact partial
    /// cumulative output spend. Interrupted writes are retried. This method does
    /// not flush, sync, hash, or otherwise publish the destination atomically.
    pub fn write_to(
        &mut self,
        output: &mut impl Write,
    ) -> std::result::Result<(), ResidentWriteError> {
        self.resident.with_budget_typed(|budget| {
            budget.check_cancelled()?;
            let amount = self.bytes.len() as u64;
            budget.check(formatkit_core::WorkResource::OutputBytes, amount)?;
            let mut remaining = self.bytes.as_slice();
            while !remaining.is_empty() {
                budget.check_cancelled()?;
                match output.write(remaining) {
                    Ok(0) => {
                        let _ = budget.check_cancelled();
                        return Err(ResidentWriteError::Write(
                            std::io::ErrorKind::WriteZero.into(),
                        ));
                    }
                    Ok(written) if written <= remaining.len() => {
                        budget.charge(formatkit_core::WorkResource::OutputBytes, written as u64)?;
                        remaining = &remaining[written..];
                    }
                    Ok(_) => {
                        let _ = budget.check_cancelled();
                        return Err(ResidentWriteError::Write(std::io::Error::other(
                            "writer returned oversized count",
                        )));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = budget.check_cancelled();
                        return Err(ResidentWriteError::Write(error));
                    }
                }
            }
            budget.check_cancelled()?;
            Ok(())
        })
    }

    /// Use the immutable output together with its checked owning ledger.
    ///
    /// The higher-ranked callback cannot return a borrow of either value.
    /// Persistent whole-ledger replacement is rejected with guard precedence;
    /// this remains cooperative accounting, not an in-process security sandbox.
    pub fn with_output_and_budget<T, E>(
        &mut self,
        operation: impl for<'operation> FnOnce(
            &'operation [u8],
            &'operation mut formatkit_core::WorkBudget,
        ) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<formatkit_core::Error>,
    {
        self.resident
            .with_budget_typed(|budget| operation(&self.bytes, budget))
    }
}

/// Execute one role-bound namespace adapter after revalidating its canonical
/// schema. Shadow pilots use this explicitly while their legacy module rows
/// remain excluded from normal executable lookup.
pub fn invoke_bound_namespace_adapter(
    operation: &ModuleOperation,
    sources: &formatkit_core::SourceBindings,
    bound: &BoundInputs,
    prefix: &[u8],
    budget: &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<SourceProbeOutcome<Box<dyn formatkit_core::IndexedNamespace>>> {
    operation.input_schema.validate_bound(sources, bound)?;
    let ExistingExecutableOperation::Namespace { contract, provider } = operation.executable else {
        return Err(formatkit_core::Error::Unsupported(
            "bound namespace adapter is attached to a non-namespace operation".into(),
        ));
    };
    if contract.id != provider.id
        || contract.input != provider.input
        || contract.strategy != provider.strategy
    {
        return Err(formatkit_core::Error::Unsupported(
            "namespace compatibility contract disagrees with its provider".into(),
        ));
    }
    if !schema_has_exact_namespace_topology(operation.input_schema, contract.input) {
        return Err(formatkit_core::Error::Unsupported(
            "input schema does not exactly project namespace role topology".into(),
        ));
    }
    let invoke = operation.bound_namespace.ok_or_else(|| {
        formatkit_core::Error::Unsupported("operation has no bound namespace adapter".into())
    })?;
    invoke(sources, bound, prefix, budget)?.validate(sources, bound, budget)
}

/// Execute one role-bound namespace runner after revalidating its canonical
/// schema. The runner mounts on the caller's ledger without type erasure and
/// invokes the scoped user once; mount, traversal, and extraction share that
/// one ledger, and the mount is dropped when the user returns.
pub fn invoke_bound_runner_namespace_adapter(
    operation: &ModuleOperation,
    sources: &formatkit_core::SourceBindings,
    bound: &BoundInputs,
    prefix: &[u8],
    budget: &mut formatkit_core::WorkBudget,
    op: WorkRunnerOp,
    user: &mut WorkRunnerUser<'_>,
) -> formatkit_core::Result<()> {
    operation.input_schema.validate_bound(sources, bound)?;
    let ExistingExecutableOperation::RunnerNamespace {
        contract,
        provider,
        runner,
    } = operation.executable
    else {
        return Err(formatkit_core::Error::Unsupported(
            "runner namespace adapter is attached to a non-runner-namespace operation".into(),
        ));
    };
    if contract.id != provider.id
        || contract.input != provider.input
        || contract.strategy != provider.strategy
    {
        return Err(formatkit_core::Error::Unsupported(
            "namespace compatibility contract disagrees with its provider".into(),
        ));
    }
    if !schema_has_exact_namespace_topology(operation.input_schema, contract.input) {
        return Err(formatkit_core::Error::Unsupported(
            "input schema does not exactly project namespace role topology".into(),
        ));
    }
    runner(sources, bound, prefix, budget, op, user)
}

/// Execute one work-native role-bound namespace adapter after revalidating its
/// canonical schema. The adapter is supplied by the owner beside its module
/// row; schema, contract/provider agreement, and topology are still enforced
/// here from the composed operation, and the provider must be a work-single
/// shape. Evidence is validated by the adapter before its borrowed mount is
/// constructed: the borrowed outcome cannot re-borrow the ledger for a
/// post-return check.
pub fn invoke_bound_namespace_work_adapter<'budget>(
    operation: &ModuleOperation,
    adapter: BoundNamespaceWorkAdapter,
    sources: &formatkit_core::SourceBindings,
    bound: &BoundInputs,
    prefix: &[u8],
    budget: &'budget mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<SourceProbeOutcome<WorkMountedNamespace<'budget>>> {
    operation.input_schema.validate_bound(sources, bound)?;
    let ExistingExecutableOperation::Namespace { contract, provider } = operation.executable else {
        return Err(formatkit_core::Error::Unsupported(
            "bound namespace adapter is attached to a non-namespace operation".into(),
        ));
    };
    if contract.id != provider.id
        || contract.input != provider.input
        || contract.strategy != provider.strategy
    {
        return Err(formatkit_core::Error::Unsupported(
            "namespace compatibility contract disagrees with its provider".into(),
        ));
    }
    if !schema_has_exact_namespace_topology(operation.input_schema, contract.input) {
        return Err(formatkit_core::Error::Unsupported(
            "input schema does not exactly project namespace role topology".into(),
        ));
    }
    if !provider.supports_work_single() {
        return Err(formatkit_core::Error::Unsupported(
            "work namespace adapter requires a work-single provider".into(),
        ));
    }
    adapter(sources, bound, prefix, budget)
}

/// Execute one finite role-bound namespace probe after revalidating its
/// canonical schema. The adapter is supplied by the owner beside its module
/// row; schema, contract/provider agreement, and exact role projection are
/// still enforced here from the composed operation. There is no legacy
/// `ReadBudget` fallback: the probe runs on the caller's one `WorkBudget`.
/// Evidence is validated by the adapter before its borrowed mount is
/// constructed: the borrowed outcome cannot re-borrow the ledger for a
/// post-return check.
pub fn invoke_role_bound_namespace_work_adapter<'budget>(
    operation: &ModuleOperation,
    adapter: BoundNamespaceWorkAdapter,
    sources: &formatkit_core::SourceBindings,
    bound: &BoundInputs,
    prefix: &[u8],
    budget: &'budget mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<SourceProbeOutcome<WorkMountedNamespace<'budget>>> {
    operation.input_schema.validate_bound(sources, bound)?;
    let ExistingExecutableOperation::RoleBoundNamespace { contract, provider } =
        operation.executable
    else {
        return Err(formatkit_core::Error::Unsupported(
            "role-bound namespace adapter is attached to a non-role-bound operation".into(),
        ));
    };
    if contract.id != provider.id
        || contract.input != provider.input
        || contract.strategy != provider.strategy
    {
        return Err(formatkit_core::Error::Unsupported(
            "role-bound contract disagrees with its provider".into(),
        ));
    }
    if !schema_has_exact_role_bound_topology(operation.input_schema, &contract.input) {
        return Err(formatkit_core::Error::Unsupported(
            "input schema does not exactly project role-bound topology".into(),
        ));
    }
    if !provider.mount_matches_input() {
        return Err(formatkit_core::Error::Unsupported(
            "role-bound provider mount does not match its declared input".into(),
        ));
    }
    adapter(sources, bound, prefix, budget)
}

/// Transitional authority state for one per-format row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleState {
    /// Preserves old executable compatibility projections while contributing no
    /// operation to the new strict lookup. These rows remain counted migration
    /// debt, not a second long-term dispatch authority.
    Legacy,
    /// Owner-authorized row whose named operations have typed callbacks and
    /// syntax-valid proof selectors. Exact Cargo proof resolution is an external
    /// strict-activation/build audit.
    Strict,
}

/// Stable, extensible identity for one owner-named operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId {
    pub format: FormatId,
    pub name: &'static str,
}

/// Product capability axes discharged by one executable operation.
///
/// This deliberately excludes corpus evidence, bindings, and confidence: those
/// describe support/evidence rather than callable behavior. Namespace/leaf
/// adapters discharge parse/decode; resident writer providers discharge the
/// exact writer axis selected from their contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationCapabilities(u8);

impl OperationCapabilities {
    pub const NONE: Self = Self(0);
    pub const PARSE: Self = Self(1 << 0);
    pub const DECODE: Self = Self(1 << 1);
    pub const EDIT: Self = Self(1 << 2);
    pub const WRITE: Self = Self(1 << 3);
    pub const ROUND_TRIP: Self = Self(1 << 4);

    const READER_ADAPTERS: Self = Self(Self::PARSE.0 | Self::DECODE.0);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    const fn is_nonempty(self) -> bool {
        self.0 != 0
    }

    const fn supported_by_reader_adapters(self) -> bool {
        self.is_nonempty() && self.0 & !Self::READER_ADAPTERS.0 == 0
    }
}

impl Ord for OperationId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.format
            .as_str()
            .cmp(other.format.as_str())
            .then_with(|| self.name.cmp(other.name))
    }
}

impl PartialOrd for OperationId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Today's contract/provider payloads, retained without inventing a universal
/// operation callback or AST. This adapter is not the operation namespace.
#[derive(Clone, Copy, Debug)]
pub enum ExistingExecutableOperation {
    Namespace {
        contract: &'static NamespaceMountContract,
        provider: &'static NamespaceProvider,
    },
    /// Namespace mount without type erasure: the runner mounts on the caller's
    /// ledger and invokes a scoped user once. The runner lives in the variant
    /// (rather than the operation's legacy adapter slot) so existing rows keep
    /// their exact shape; the provider remains the callback authority and the
    /// runner must delegate to the same strict mount.
    RunnerNamespace {
        contract: &'static NamespaceMountContract,
        provider: &'static NamespaceProvider,
        runner: BoundRunnerNamespaceAdapter,
    },
    /// Finite role-bound namespace mount on the caller's work ledger. There
    /// is no legacy `ReadBudget` shape: the work adapter travels beside the
    /// row like [`Self::Namespace`] work-single mounts, and the provider
    /// remains the callback authority.
    RoleBoundNamespace {
        contract: &'static RoleBoundNamespaceContract,
        provider: &'static RoleBoundNamespaceProvider,
    },
    Leaf(&'static LeafOperationProvider),
    ResidentWriter(&'static ResidentWriterProvider),
}

impl ExistingExecutableOperation {
    const fn format(self) -> FormatId {
        match self {
            Self::Namespace { contract, .. } => contract.id,
            Self::RunnerNamespace { contract, .. } => contract.id,
            Self::RoleBoundNamespace { contract, .. } => contract.id,
            Self::Leaf(provider) => provider.contract.id,
            Self::ResidentWriter(provider) => provider.id,
        }
    }
}

/// One named operation contribution attached to its owner row.
#[derive(Clone, Copy, Debug)]
pub struct ModuleOperation {
    pub name: &'static str,
    pub purpose: &'static str,
    /// Static owner attribution checked against the enclosing module. For leaf
    /// providers this is an asserted attribution, not compiler provenance.
    pub owner: &'static str,
    pub capabilities: OperationCapabilities,
    /// Canonical role/selector contract checked at composition and again before
    /// a bound namespace callback can perform owner I/O.
    pub input_schema: &'static InputSchema<'static>,
    /// General role-bound namespace path. `None` retains today's legacy
    /// single/pair provider adapter during shadow migration.
    pub bound_namespace: Option<BoundNamespaceAdapter>,
    pub executable: ExistingExecutableOperation,
}

/// One format identity and its complete current module contribution.
#[derive(Clone, Copy)]
pub struct FormatModule {
    pub format: FormatId,
    pub owner: &'static str,
    pub state: ModuleState,
    pub descriptor: Option<&'static FormatDescriptor>,
    pub embedded_support: Option<&'static EmbeddedFormatSupport>,
    /// Sole proof authority for writer operations. Legacy rows retain it as a
    /// compatibility projection; strict writer operations select it through a
    /// callable [`ResidentWriterProvider`].
    pub writer_contract: Option<&'static WriterContract>,
    pub namespace_semantics: Option<&'static NamespaceSemantics>,
    pub operations: &'static [ModuleOperation],
}

impl fmt::Debug for FormatModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FormatModule")
            .field("format", &self.format)
            .field("owner", &self.owner)
            .field("state", &self.state)
            .field("has_descriptor", &self.descriptor.is_some())
            .field("embedded_support", &self.embedded_support)
            .field("writer_contract", &self.writer_contract)
            .field("namespace_semantics", &self.namespace_semantics)
            .field("operations", &self.operations)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleCatalogError {
    InvalidFormatId(FormatId),
    InvalidOwner {
        format: FormatId,
        owner: &'static str,
    },
    DuplicateModule(FormatId),
    MissingSupportIdentity(FormatId),
    InvalidOperationName {
        format: FormatId,
        name: &'static str,
    },
    InvalidInputSchema(OperationId),
    InputSchemaTopologyDisagreement(OperationId),
    InvalidBoundNamespaceAdapter(OperationId),
    DuplicateOperation(OperationId),
    /// The selected legacy namespace default does not name a contributed operation.
    UnknownNamespaceProjection(OperationId),
    /// Only ordinary or runner namespaces have a legacy provider projection.
    InvalidNamespaceProjection(OperationId),
    /// A legacy support view can expose at most one namespace default per format.
    DuplicateNamespaceProjection(FormatId),
    UnsupportedOperationCapabilities(OperationId),
    IdentityDisagreement {
        module: FormatId,
        contributed: FormatId,
    },
    OwnerDisagreement {
        format: FormatId,
        module_owner: &'static str,
        declared_owner: &'static str,
    },
    CapabilityDisagreement(FormatId),
    ContractProviderDisagreement(FormatId),
    MissingWriterContract(OperationId),
    WriterProofDisagreement(OperationId),
    DuplicateWriterProof {
        format: FormatId,
        proof: WriterProofSelector,
    },
    MissingWriterProvider {
        format: FormatId,
        proof: WriterProofSelector,
    },
    StrictCapabilityDisagreement(FormatId),
    InvalidFormatCatalog,
    InvalidSupportCatalog,
    InvalidLeafCatalog,
}

impl fmt::Display for ModuleCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormatId(format) => {
                write!(formatter, "invalid module format identity: {format:?}")
            }
            Self::InvalidOwner { format, owner } => {
                write!(formatter, "invalid owner {owner:?} for {format}")
            }
            Self::DuplicateModule(format) => write!(formatter, "duplicate module row for {format}"),
            Self::MissingSupportIdentity(format) => {
                write!(
                    formatter,
                    "module row for {format} has no descriptor or embedded support"
                )
            }
            Self::InvalidOperationName { format, name } => {
                write!(formatter, "invalid operation name {name:?} for {format}")
            }
            Self::InvalidInputSchema(id) => write!(formatter, "invalid input schema: {id:?}"),
            Self::InputSchemaTopologyDisagreement(id) => {
                write!(
                    formatter,
                    "input schema does not exactly project namespace role topology: {id:?}"
                )
            }
            Self::InvalidBoundNamespaceAdapter(id) => {
                write!(formatter, "invalid bound namespace adapter: {id:?}")
            }
            Self::DuplicateOperation(id) => write!(formatter, "duplicate operation: {id:?}"),
            Self::UnknownNamespaceProjection(id) => {
                write!(formatter, "unknown namespace projection operation: {id:?}")
            }
            Self::InvalidNamespaceProjection(id) => {
                write!(
                    formatter,
                    "operation has no legacy namespace projection: {id:?}"
                )
            }
            Self::DuplicateNamespaceProjection(format) => {
                write!(formatter, "duplicate namespace projection for {format}")
            }
            Self::UnsupportedOperationCapabilities(id) => {
                write!(
                    formatter,
                    "operation uses unsupported capability axes: {id:?}"
                )
            }
            Self::IdentityDisagreement {
                module,
                contributed,
            } => write!(
                formatter,
                "module {module} contains contribution for {contributed}"
            ),
            Self::OwnerDisagreement {
                format,
                module_owner,
                declared_owner,
            } => write!(
                formatter,
                "module owner {module_owner:?} disagrees with {declared_owner:?} for {format}"
            ),
            Self::CapabilityDisagreement(format) => {
                write!(
                    formatter,
                    "descriptor and embedded capabilities disagree for {format}"
                )
            }
            Self::ContractProviderDisagreement(format) => {
                write!(
                    formatter,
                    "namespace contract/provider disagreement for {format}"
                )
            }
            Self::MissingWriterContract(id) => {
                write!(formatter, "resident writer has no writer contract: {id:?}")
            }
            Self::WriterProofDisagreement(id) => write!(
                formatter,
                "resident writer proof selector disagrees with its contract: {id:?}"
            ),
            Self::DuplicateWriterProof { format, proof } => {
                write!(
                    formatter,
                    "duplicate resident writer proof for {format}: {proof:?}"
                )
            }
            Self::MissingWriterProvider { format, proof } => {
                write!(
                    formatter,
                    "missing resident writer provider for {format}: {proof:?}"
                )
            }
            Self::StrictCapabilityDisagreement(format) => write!(
                formatter,
                "strict {format} row capability claims do not exactly match its operations"
            ),
            Self::InvalidFormatCatalog => formatter.write_str("invalid composed format catalog"),
            Self::InvalidSupportCatalog => formatter.write_str("invalid composed support catalog"),
            Self::InvalidLeafCatalog => formatter.write_str("invalid composed leaf catalog"),
        }
    }
}

impl std::error::Error for ModuleCatalogError {}

impl From<CatalogError> for ModuleCatalogError {
    fn from(_: CatalogError) -> Self {
        Self::InvalidFormatCatalog
    }
}

impl From<SupportCatalogError> for ModuleCatalogError {
    fn from(_: SupportCatalogError) -> Self {
        Self::InvalidSupportCatalog
    }
}

impl From<LeafOperationCatalogError> for ModuleCatalogError {
    fn from(_: LeafOperationCatalogError) -> Self {
        Self::InvalidLeafCatalog
    }
}

/// Validated legacy projections plus indexed strict module dispatch metadata.
pub struct ModuleCatalog {
    modules: Vec<&'static FormatModule>,
    formats: FormatCatalog,
    support: SupportCatalog,
    leaf: LeafOperationCatalog,
    strict_operations: Vec<(OperationId, &'static ModuleOperation)>,
    legacy_module_count: usize,
    legacy_operation_count: usize,
}

impl ModuleCatalog {
    pub fn new(
        modules: impl IntoIterator<Item = &'static FormatModule>,
    ) -> Result<Self, ModuleCatalogError> {
        Self::build(modules, None)
    }

    /// Compose every strict named operation while explicitly selecting the
    /// namespace defaults visible through the legacy support catalog.
    ///
    /// At most one [`ExistingExecutableOperation::Namespace`] or
    /// [`ExistingExecutableOperation::RunnerNamespace`] may be selected per
    /// format. Unselected operations retain their canonical schemas and remain
    /// available through [`Self::operation`] when contributed by strict rows.
    /// An empty selection exposes no legacy namespace default. Role-bound
    /// namespaces have no legacy projection and cannot be selected here.
    ///
    /// All module rows and operations are validated before projection; excluding
    /// a default does not suppress invalid contracts or capabilities. Unlike
    /// [`Self::new`], this constructor permits multiple named namespace
    /// operations for one format without implicitly choosing between them.
    pub fn with_namespace_projection(
        modules: impl IntoIterator<Item = &'static FormatModule>,
        selected: impl IntoIterator<Item = OperationId>,
    ) -> Result<Self, ModuleCatalogError> {
        Self::build(modules, Some(selected.into_iter().collect()))
    }

    fn build(
        modules: impl IntoIterator<Item = &'static FormatModule>,
        selected: Option<Vec<OperationId>>,
    ) -> Result<Self, ModuleCatalogError> {
        let mut modules = modules.into_iter().collect::<Vec<_>>();
        validate_rows(&modules)?;
        modules.sort_by_key(|module| module.format.as_str());
        let selected = selected
            .map(|selected| validate_namespace_projection(&modules, selected))
            .transpose()?;

        let descriptors = modules
            .iter()
            .filter_map(|module| module.descriptor)
            .copied()
            .collect::<Vec<_>>();
        let embedded = modules
            .iter()
            .filter_map(|module| module.embedded_support)
            .copied()
            .collect::<Vec<_>>();
        let semantics = modules
            .iter()
            .filter_map(|module| module.namespace_semantics)
            .copied()
            .collect::<Vec<_>>();
        let mut writers = Vec::new();
        let mut leaves = Vec::new();
        let mut strict_operations = Vec::new();
        let mut all_namespaces = Vec::new();
        let mut role_bound_namespaces = Vec::new();
        let mut projected_namespace_indices = Vec::new();
        let mut legacy_operation_count = 0;
        for module in &modules {
            for operation in module.operations {
                let id = OperationId {
                    format: module.format,
                    name: operation.name,
                };
                let project_namespace = selected
                    .as_ref()
                    .is_none_or(|selected| selected.contains(&id));
                if let ExistingExecutableOperation::Namespace { contract, provider }
                | ExistingExecutableOperation::RunnerNamespace {
                    contract, provider, ..
                } = operation.executable
                {
                    if project_namespace {
                        projected_namespace_indices.push(all_namespaces.len());
                    }
                    all_namespaces.push((contract, provider));
                }
                match operation.executable {
                    ExistingExecutableOperation::Namespace { .. }
                    | ExistingExecutableOperation::RunnerNamespace { .. } => {}
                    ExistingExecutableOperation::RoleBoundNamespace { contract, provider } => {
                        // Role-bound rows have no legacy support projection;
                        // even legacy debt rows must validate their metadata.
                        role_bound_namespaces.push((contract, provider));
                    }
                    ExistingExecutableOperation::Leaf(provider) => leaves.push(*provider),
                    ExistingExecutableOperation::ResidentWriter(_) => {}
                }
                match module.state {
                    ModuleState::Strict => strict_operations.push((id, operation)),
                    ModuleState::Legacy => legacy_operation_count += 1,
                }
            }
        }
        writers.extend(
            modules
                .iter()
                .filter_map(|module| module.writer_contract)
                .copied(),
        );
        strict_operations.sort_by_key(|(id, _)| *id);

        let available_decoders = descriptors
            .iter()
            .filter_map(|descriptor| descriptor.decoder)
            .collect::<HashSet<_>>();
        let formats = FormatCatalog::builder()
            .add_family(descriptors.iter().copied())
            .available_decoders(available_decoders)
            .build()?;
        let support = SupportCatalog::with_namespace_support(
            descriptors,
            embedded,
            writers,
            semantics,
            [],
            [],
        )?
        .with_namespace_operation_projection_with_role_bound(
            all_namespaces,
            role_bound_namespaces,
            projected_namespace_indices,
        )?;
        let leaf = LeafOperationCatalog::new(leaves)?;
        let legacy_module_count = modules
            .iter()
            .filter(|module| module.state == ModuleState::Legacy)
            .count();

        Ok(Self {
            modules,
            formats,
            support,
            leaf,
            strict_operations,
            legacy_module_count,
            legacy_operation_count,
        })
    }

    pub fn modules(&self) -> &[&'static FormatModule] {
        &self.modules
    }

    pub fn module(&self, format: FormatId) -> Option<&'static FormatModule> {
        self.modules
            .binary_search_by_key(&format.as_str(), |module| module.format.as_str())
            .ok()
            .map(|index| self.modules[index])
    }

    pub const fn formats(&self) -> &FormatCatalog {
        &self.formats
    }

    pub const fn support(&self) -> &SupportCatalog {
        &self.support
    }

    pub const fn leaf_operations(&self) -> &LeafOperationCatalog {
        &self.leaf
    }

    /// Only strict rows participate in executable module dispatch.
    pub fn operations(&self) -> impl ExactSizeIterator<Item = (OperationId, &ModuleOperation)> {
        self.strict_operations
            .iter()
            .map(|(id, operation)| (*id, *operation))
    }

    pub fn operation(&self, id: OperationId) -> Option<&ModuleOperation> {
        self.strict_operations
            .binary_search_by_key(&id, |(candidate, _)| *candidate)
            .ok()
            .map(|index| self.strict_operations[index].1)
    }

    /// Invoke a strict role-bound namespace operation without changing product
    /// routing. Schema/relationship checks precede owner I/O and successful
    /// evidence is confined to the bound roles before returning.
    pub fn invoke_bound_namespace(
        &self,
        id: OperationId,
        sources: &formatkit_core::SourceBindings,
        bound: &BoundInputs,
        prefix: &[u8],
        budget: &mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<Option<SourceProbeOutcome<Box<dyn formatkit_core::IndexedNamespace>>>>
    {
        let Some(operation) = self.operation(id) else {
            return Ok(None);
        };
        if operation.bound_namespace.is_none() {
            return Ok(None);
        }
        invoke_bound_namespace_adapter(operation, sources, bound, prefix, budget).map(Some)
    }

    /// Invoke a strict runner-namespace operation without changing product
    /// routing. Unknown or non-runner-namespace operation IDs return `Ok(None)`.
    /// The runner mounts on the caller's ledger and invokes the scoped user
    /// once; the mount is dropped when the user returns.
    #[allow(clippy::too_many_arguments)]
    pub fn invoke_runner_namespace(
        &self,
        id: OperationId,
        sources: &formatkit_core::SourceBindings,
        bound: &BoundInputs,
        prefix: &[u8],
        budget: &mut formatkit_core::WorkBudget,
        op: WorkRunnerOp,
        user: &mut WorkRunnerUser<'_>,
    ) -> formatkit_core::Result<Option<()>> {
        let Some(operation) = self.operation(id) else {
            return Ok(None);
        };
        if !matches!(
            operation.executable,
            ExistingExecutableOperation::RunnerNamespace { .. }
        ) {
            return Ok(None);
        }
        invoke_bound_runner_namespace_adapter(operation, sources, bound, prefix, budget, op, user)
            .map(Some)
    }

    /// Invoke a strict work-native role-bound namespace operation without
    /// changing product routing. The owner supplies its work adapter beside
    /// the composed operation; operations with a legacy adapter serve the
    /// `'static` path instead and return `Ok(None)` here.
    pub fn invoke_bound_namespace_work<'budget>(
        &self,
        id: OperationId,
        adapter: BoundNamespaceWorkAdapter,
        sources: &formatkit_core::SourceBindings,
        bound: &BoundInputs,
        prefix: &[u8],
        budget: &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<Option<SourceProbeOutcome<WorkMountedNamespace<'budget>>>> {
        let Some(operation) = self.operation(id) else {
            return Ok(None);
        };
        if operation.bound_namespace.is_some() {
            return Ok(None);
        }
        if matches!(
            operation.executable,
            ExistingExecutableOperation::RoleBoundNamespace { .. }
        ) {
            return Ok(None);
        }
        invoke_bound_namespace_work_adapter(operation, adapter, sources, bound, prefix, budget)
            .map(Some)
    }

    /// Invoke a strict finite role-bound namespace operation without changing
    /// product routing. The owner supplies its work adapter beside the
    /// composed operation. Unknown or non-role-bound operation IDs return
    /// `Ok(None)`.
    pub fn invoke_role_bound_namespace_work<'budget>(
        &self,
        id: OperationId,
        adapter: BoundNamespaceWorkAdapter,
        sources: &formatkit_core::SourceBindings,
        bound: &BoundInputs,
        prefix: &[u8],
        budget: &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<Option<SourceProbeOutcome<WorkMountedNamespace<'budget>>>> {
        let Some(operation) = self.operation(id) else {
            return Ok(None);
        };
        if !matches!(
            operation.executable,
            ExistingExecutableOperation::RoleBoundNamespace { .. }
        ) {
            return Ok(None);
        }
        if operation.bound_namespace.is_some() {
            return Ok(None);
        }
        invoke_role_bound_namespace_work_adapter(operation, adapter, sources, bound, prefix, budget)
            .map(Some)
    }

    /// Invoke one strict resident writer after revalidating its canonical input
    /// binding. Unknown or non-writer operation IDs return `Ok(None)`.
    pub fn invoke_resident_writer<'budget>(
        &self,
        id: OperationId,
        sources: &formatkit_core::SourceBindings,
        bound: &BoundInputs,
        budget: &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<Option<ResidentWriteOutput<'budget>>> {
        let Some(operation) = self.operation(id) else {
            return Ok(None);
        };
        let ExistingExecutableOperation::ResidentWriter(provider) = operation.executable else {
            return Ok(None);
        };
        operation.input_schema.validate_bound(sources, bound)?;
        (provider.write)(sources, bound, budget).map(Some)
    }

    pub const fn legacy_module_count(&self) -> usize {
        self.legacy_module_count
    }

    pub const fn legacy_operation_count(&self) -> usize {
        self.legacy_operation_count
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn form_projects(
    form: &InputForm<'_>,
    byte_roles: &[&str],
    required_selector: Option<&str>,
) -> bool {
    form.bytes.len() == byte_roles.len()
        && byte_roles.iter().all(|expected| {
            form.bytes
                .iter()
                .any(|role| role.name == *expected && role.cardinality == InputCardinality::One)
        })
        && form.selectors.len() == usize::from(required_selector.is_some())
        && match required_selector {
            Some(expected) => form
                .selectors
                .first()
                .is_some_and(|role| role.name == expected && role.required),
            None => form.selectors.is_empty(),
        }
}

/// Whether one role-bound form projects exactly the declared roles. Every
/// declared byte role must occur once with `One` cardinality and every
/// declared selector must occur once as required; `Optional`/`Many` shapes
/// never project, and extra roles never project.
fn role_bound_form_projects(form: &InputForm<'_>, input: &RoleBoundNamespaceInput) -> bool {
    form.bytes.len() == input.byte_roles.len()
        && input.byte_roles.iter().all(|expected| {
            form.bytes
                .iter()
                .filter(|role| role.name == *expected)
                .count()
                == 1
                && form
                    .bytes
                    .iter()
                    .any(|role| role.name == *expected && role.cardinality == InputCardinality::One)
        })
        && form.selectors.len() == input.selector_roles.len()
        && input.selector_roles.iter().all(|expected| {
            form.selectors
                .iter()
                .filter(|role| role.name == *expected)
                .count()
                == 1
                && form
                    .selectors
                    .iter()
                    .any(|role| role.name == *expected && role.required)
        })
}

/// Relationships are deliberately excluded: they may strengthen owner policy,
/// while forms, role cardinality, and required selectors must project exactly.
/// Role-bound topologies require exactly one form; ambiguous multi-form
/// schemas never project.
fn schema_has_exact_role_bound_topology(
    schema: &InputSchema<'_>,
    input: &RoleBoundNamespaceInput,
) -> bool {
    input.validate().is_ok()
        && schema.forms.len() == 1
        && schema
            .forms
            .first()
            .is_some_and(|form| role_bound_form_projects(form, input))
}

/// Relationships are deliberately excluded: they may strengthen owner policy,
/// while forms, role cardinality, and required selectors must project exactly.
fn schema_has_exact_namespace_topology(
    schema: &InputSchema<'_>,
    input: NamespaceMountInput,
) -> bool {
    let accepts_exactly = |expected: &[(&[&str], Option<&str>)]| {
        schema.forms.len() == expected.len()
            && schema.forms.iter().all(|form| {
                expected
                    .iter()
                    .filter(|(roles, selector)| form_projects(form, roles, *selector))
                    .count()
                    == 1
            })
            && expected.iter().all(|(roles, selector)| {
                schema
                    .forms
                    .iter()
                    .filter(|form| form_projects(form, roles, *selector))
                    .count()
                    == 1
            })
    };
    match input {
        NamespaceMountInput::SingleSource { role } => accepts_exactly(&[(&[role], None)]),
        NamespaceMountInput::PairedSources {
            directory_role,
            content_role,
        } => accepts_exactly(&[(&[directory_role, content_role], None)]),
        NamespaceMountInput::SelectedPairedSources {
            directory_role,
            content_role,
            selector_role,
        } => accepts_exactly(&[(&[directory_role, content_role], Some(selector_role))]),
        NamespaceMountInput::SingleOrSelectedPairedSources {
            single_role,
            directory_role,
            content_role,
            selector_role,
        } => accepts_exactly(&[
            (&[single_role], None),
            (&[directory_role, content_role], Some(selector_role)),
        ]),
        NamespaceMountInput::SelectedSingleSource {
            role,
            selector_role,
        } => accepts_exactly(&[(&[role], Some(selector_role))]),
    }
}

fn validate_namespace_projection(
    modules: &[&FormatModule],
    selected: Vec<OperationId>,
) -> Result<HashSet<OperationId>, ModuleCatalogError> {
    let mut formats = HashSet::new();
    let mut operations = HashSet::new();
    for id in selected {
        let operation = modules
            .iter()
            .find(|module| module.format == id.format)
            .and_then(|module| {
                module
                    .operations
                    .iter()
                    .find(|operation| operation.name == id.name)
            })
            .ok_or(ModuleCatalogError::UnknownNamespaceProjection(id))?;
        if !matches!(
            operation.executable,
            ExistingExecutableOperation::Namespace { .. }
                | ExistingExecutableOperation::RunnerNamespace { .. }
        ) {
            return Err(ModuleCatalogError::InvalidNamespaceProjection(id));
        }
        if !formats.insert(id.format) {
            return Err(ModuleCatalogError::DuplicateNamespaceProjection(id.format));
        }
        operations.insert(id);
    }
    Ok(operations)
}

fn validate_rows(modules: &[&FormatModule]) -> Result<(), ModuleCatalogError> {
    let mut module_ids = HashSet::new();
    let mut operation_ids = HashSet::new();
    let mut writer_proofs = HashSet::new();
    for module in modules {
        if !module.format.is_valid() {
            return Err(ModuleCatalogError::InvalidFormatId(module.format));
        }
        if !valid_component(module.owner) {
            return Err(ModuleCatalogError::InvalidOwner {
                format: module.format,
                owner: module.owner,
            });
        }
        if !module_ids.insert(module.format) {
            return Err(ModuleCatalogError::DuplicateModule(module.format));
        }
        if module.descriptor.is_none() && module.embedded_support.is_none() {
            return Err(ModuleCatalogError::MissingSupportIdentity(module.format));
        }
        validate_identity(module, module.descriptor.map(|value| value.id))?;
        validate_identity(module, module.embedded_support.map(|value| value.id))?;
        validate_identity(
            module,
            module
                .embedded_support
                .and_then(|value| value.detectable_carrier),
        )?;
        validate_identity(module, module.writer_contract.map(|value| value.id))?;
        validate_identity(module, module.namespace_semantics.map(|value| value.id))?;
        if let Some(descriptor) = module.descriptor {
            if let Some(owner) = descriptor.decoder {
                validate_owner(module, owner)?;
            }
        }
        if let Some(support) = module.embedded_support {
            validate_owner(module, support.decoder)?;
        }

        if let (Some(descriptor), Some(support)) = (module.descriptor, module.embedded_support) {
            if descriptor.capabilities != support.capabilities {
                return Err(ModuleCatalogError::CapabilityDisagreement(module.format));
            }
        }

        let mut operation_capabilities = OperationCapabilities::NONE;
        for operation in module.operations {
            if !valid_component(operation.name) || operation.purpose.trim().is_empty() {
                return Err(ModuleCatalogError::InvalidOperationName {
                    format: module.format,
                    name: operation.name,
                });
            }
            let id = OperationId {
                format: module.format,
                name: operation.name,
            };
            if operation.input_schema.validate().is_err() {
                return Err(ModuleCatalogError::InvalidInputSchema(id));
            }
            if !operation_ids.insert(id) {
                return Err(ModuleCatalogError::DuplicateOperation(id));
            }
            validate_owner(module, operation.owner)?;
            let writer_executable = matches!(
                operation.executable,
                ExistingExecutableOperation::ResidentWriter(_)
            );
            if !operation.capabilities.is_nonempty()
                || (!writer_executable && !operation.capabilities.supported_by_reader_adapters())
            {
                return Err(ModuleCatalogError::UnsupportedOperationCapabilities(id));
            }
            operation_capabilities = operation_capabilities.union(operation.capabilities);
            validate_identity(module, Some(operation.executable.format()))?;
            let work_native = matches!(
                operation.executable,
                ExistingExecutableOperation::Namespace { provider, .. }
                    if provider.supports_work_single()
            ) || matches!(
                operation.executable,
                ExistingExecutableOperation::RoleBoundNamespace { .. }
            );
            // Legacy static namespace rows use the operation-level bound slot.
            // Runner rows carry their callback in the executable variant and
            // work-single/role-bound rows receive their borrowing adapter at
            // invocation.
            let wants_legacy_bound = matches!(
                operation.executable,
                ExistingExecutableOperation::Namespace { .. }
            ) && !work_native;
            if operation.bound_namespace.is_some() != wants_legacy_bound
                && (operation.bound_namespace.is_some() || module.state == ModuleState::Strict)
            {
                return Err(ModuleCatalogError::InvalidBoundNamespaceAdapter(id));
            }
            match operation.executable {
                ExistingExecutableOperation::Namespace { contract, provider } => {
                    let topology_checked = operation.bound_namespace.is_some()
                        || (module.state == ModuleState::Strict && work_native);
                    if topology_checked
                        && !schema_has_exact_namespace_topology(
                            operation.input_schema,
                            contract.input,
                        )
                    {
                        return Err(ModuleCatalogError::InputSchemaTopologyDisagreement(id));
                    }
                    validate_identity(module, Some(contract.id))?;
                    validate_identity(module, Some(provider.id))?;
                    if contract.id != provider.id
                        || contract.input != provider.input
                        || contract.strategy != provider.strategy
                    {
                        return Err(ModuleCatalogError::ContractProviderDisagreement(
                            module.format,
                        ));
                    }
                    validate_owner(module, provider.owner)?;
                }
                ExistingExecutableOperation::RunnerNamespace {
                    contract, provider, ..
                } => {
                    if !schema_has_exact_namespace_topology(operation.input_schema, contract.input)
                    {
                        return Err(ModuleCatalogError::InputSchemaTopologyDisagreement(id));
                    }
                    validate_identity(module, Some(contract.id))?;
                    validate_identity(module, Some(provider.id))?;
                    if contract.id != provider.id
                        || contract.input != provider.input
                        || contract.strategy != provider.strategy
                    {
                        return Err(ModuleCatalogError::ContractProviderDisagreement(
                            module.format,
                        ));
                    }
                    validate_owner(module, provider.owner)?;
                }
                ExistingExecutableOperation::RoleBoundNamespace { contract, provider } => {
                    // Work-native rows receive their adapter at invocation;
                    // strict rows must project exactly, legacy rows (which
                    // should not exist for new topologies) retain topology debt.
                    // Canonical metadata validation still covers every row.
                    let topology_checked = operation.bound_namespace.is_some()
                        || (module.state == ModuleState::Strict && work_native);
                    if topology_checked
                        && !schema_has_exact_role_bound_topology(
                            operation.input_schema,
                            &contract.input,
                        )
                    {
                        return Err(ModuleCatalogError::InputSchemaTopologyDisagreement(id));
                    }
                    if contract.input.validate().is_err() || !provider.mount_matches_input() {
                        return Err(ModuleCatalogError::InputSchemaTopologyDisagreement(id));
                    }
                    validate_identity(module, Some(contract.id))?;
                    validate_identity(module, Some(provider.id))?;
                    if contract.id != provider.id
                        || contract.input != provider.input
                        || contract.strategy != provider.strategy
                    {
                        return Err(ModuleCatalogError::ContractProviderDisagreement(
                            module.format,
                        ));
                    }
                    validate_owner(module, provider.owner)?;
                }
                ExistingExecutableOperation::Leaf(_) => {}
                ExistingExecutableOperation::ResidentWriter(provider) => {
                    validate_identity(module, Some(provider.id))?;
                    validate_owner(module, provider.owner)?;
                    if operation.capabilities != provider.proof.capabilities() {
                        return Err(ModuleCatalogError::UnsupportedOperationCapabilities(id));
                    }
                    let contract = module
                        .writer_contract
                        .ok_or(ModuleCatalogError::MissingWriterContract(id))?;
                    if !provider.proof.is_declared_by(contract) {
                        return Err(ModuleCatalogError::WriterProofDisagreement(id));
                    }
                    if !writer_proofs.insert((module.format, provider.proof)) {
                        return Err(ModuleCatalogError::DuplicateWriterProof {
                            format: module.format,
                            proof: provider.proof,
                        });
                    }
                }
            }
        }

        if module.state == ModuleState::Strict {
            if let Some(contract) = module.writer_contract {
                let reproduction =
                    contract
                        .reproduction
                        .map(|operation| WriterProofSelector::Reproduction {
                            scope: operation.scope,
                        });
                let edits = contract
                    .edits
                    .iter()
                    .map(|operation| WriterProofSelector::Edit {
                        mode: operation.mode,
                        scope: operation.scope,
                    });
                let authoring =
                    contract
                        .authoring
                        .map(|operation| WriterProofSelector::Authoring {
                            scope: operation.output_scope,
                        });
                for proof in reproduction.into_iter().chain(edits).chain(authoring) {
                    if !writer_proofs.contains(&(module.format, proof)) {
                        return Err(ModuleCatalogError::MissingWriterProvider {
                            format: module.format,
                            proof,
                        });
                    }
                }
            }
            let capabilities = module
                .embedded_support
                .map(|support| support.capabilities)
                .or_else(|| module.descriptor.map(|descriptor| descriptor.capabilities))
                .expect("validated module has a support identity");
            let claimed = format_operation_capabilities(capabilities);
            if claimed != operation_capabilities {
                return Err(ModuleCatalogError::StrictCapabilityDisagreement(
                    module.format,
                ));
            }
        }
    }
    Ok(())
}

const fn format_operation_capabilities(
    capabilities: formatkit_catalog::catalog::FormatCapabilities,
) -> OperationCapabilities {
    let mut bits = 0;
    if capabilities.parse {
        bits |= OperationCapabilities::PARSE.0;
    }
    if capabilities.decode {
        bits |= OperationCapabilities::DECODE.0;
    }
    if capabilities.edit {
        bits |= OperationCapabilities::EDIT.0;
    }
    if capabilities.write {
        bits |= OperationCapabilities::WRITE.0;
    }
    if capabilities.round_trip {
        bits |= OperationCapabilities::ROUND_TRIP.0;
    }
    OperationCapabilities(bits)
}

fn validate_identity(
    module: &FormatModule,
    contributed: Option<FormatId>,
) -> Result<(), ModuleCatalogError> {
    if let Some(contributed) = contributed {
        if !contributed.is_valid() {
            return Err(ModuleCatalogError::InvalidFormatId(contributed));
        }
        if contributed != module.format {
            return Err(ModuleCatalogError::IdentityDisagreement {
                module: module.format,
                contributed,
            });
        }
    }
    Ok(())
}

fn validate_owner(
    module: &FormatModule,
    declared_owner: &'static str,
) -> Result<(), ModuleCatalogError> {
    if declared_owner != module.owner {
        return Err(ModuleCatalogError::OwnerDisagreement {
            format: module.format,
            module_owner: module.owner,
            declared_owner,
        });
    }
    Ok(())
}

#[cfg(test)]
mod role_bound_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod synthetic;
