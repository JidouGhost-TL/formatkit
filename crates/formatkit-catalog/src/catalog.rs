//! Explicitly composed format identification catalogs.
//!
//! A decoder crate owns its [`FormatDescriptor`]; a product or application
//! chooses which descriptors to compose. The catalog resolves content matches
//! deterministically and uses path context only to break a genuine tie.

mod descriptor;
pub use descriptor::{
    Confidence, ContextRequirement, CorpusEvidence, DecoderRequirement, FormatCapabilities,
    FormatDescriptor, FormatFamilyId, Probe, GZIP_FORMAT, MIDI_FORMAT, PNG_FORMAT, XML_FORMAT,
};

mod writer;
pub use writer::{
    AuthoringContract, CargoTestOracle, CargoTestTarget, DialectId, EditContract, EditMode,
    EditPrecondition, OperationScope, OutputLengthGuarantee, RelocationObligation,
    ReproductionContract, WriterContract,
};

mod leaf;
pub use leaf::{
    BudgetedLeafOutput, LeafDecodeHandlerBudgeted, LeafDecodeHandlerBudgetedFile,
    LeafDecodeHandlerBudgetedSource, LeafDecodeLimits, LeafDecodeRequest, LeafDecoded,
    LeafInputContract, LeafOperationCatalog, LeafOperationCatalogError, LeafOperationContract,
    LeafOperationProvider, LeafOutput, LeafOutputContract, LeafOutputKind, LeafOutputMultiplicity,
    LeafSelection, LeafSelectionContract, LeafSelector,
};

mod inputs;
mod namespace;
pub use inputs::{
    BoundInputs, ByteInput, ByteRole, InputCardinality, InputForm, InputRelationship, InputSchema,
    RetainedSourceEvidence, SelectorInput, SelectorRole, SourceEvidenceRange, SourceProbeOutcome,
    MAX_SOURCE_EVIDENCE_RANGES,
};

pub use namespace::{
    early_namespace_probe_len, identify_and_mount_namespace_source,
    identify_and_mount_namespace_source_early, identify_and_mount_namespace_source_early_work,
    identify_and_mount_namespace_source_work, IdentifiedNamespace, NamespaceAddressing,
    NamespaceCollisionContract, NamespaceCollisionKind, NamespaceExecution, NamespaceKind,
    NamespaceMountContract, NamespaceMountInput, NamespaceMountStrategy, NamespaceProvider,
    NamespaceProviderMount, NamespaceSemantics, NamespaceSourceProbe, PairedNamespaceMounter,
    PairedNamespaceSources, RoleBoundNamespaceContract, RoleBoundNamespaceInput,
    RoleBoundNamespaceProvider, RoleBoundWorkMounter, SelectedSingleNamespaceMounter,
    SingleNamespaceMounter, WorkMountedNamespace, WorkNamespaceSourceProbe, WorkRunnerOp,
    WorkRunnerUser, WorkSingleNamespaceMounter, WorkSourceRunner, MAX_EARLY_NAMESPACE_PROBE_BYTES,
    MAX_ROLE_BOUND_BYTE_ROLES, MAX_ROLE_BOUND_SELECTOR_ROLES,
};

mod support;
pub use support::{EmbeddedFormatSupport, FormatSupportView, SupportCatalog, SupportCatalogError};

mod resolver;
pub use resolver::{
    Candidate, CatalogDiagnostic, CatalogError, DetectionContext, Evidence, FormatCatalog,
    FormatCatalogBuilder, Resolution,
};

#[cfg(test)]
mod tests;
