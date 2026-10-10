//! Source topology, evidence contracts, and executable providers for indexed namespaces.

use std::fmt;

use super::writer::valid_cargo_test_oracle;
use super::{CargoTestOracle, DecoderRequirement, FormatCapabilities};
use crate::FormatId;

/// The logical relationship between a format and the children it exposes.
///
/// This is deliberately independent of [`crate::Category`]. `Archive` is a
/// detection/display category, while this declaration says whether treating
/// the decoded object as a folder-like namespace is semantically sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKind {
    /// A storage carrier whose members are independently addressable assets.
    Carrier,
    /// A structured object exposed as children for useful semantic traversal.
    SemanticView,
    /// A terminal value which must not be presented as a directory.
    NonNamespace,
}

impl NamespaceKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Carrier => "carrier",
            Self::SemanticView => "semantic-view",
            Self::NonNamespace => "non-namespace",
        }
    }
}

/// How namespace member extents relate to the physical inputs.
///
/// This describes the namespace address space, not an individual member's
/// [`formatkit_core::MemberTransform`]. A selectively transformed namespace may,
/// for example, still contain both stored and compressed members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceAddressing {
    /// Member extents are direct ranges of one of the mounted inputs.
    DirectRanges,
    /// Only the regions needed to expose members are transformed.
    SelectiveTransform,
    /// Directory offsets address a bounded, reconstructed logical space.
    ReconstructedAddressSpace,
}

impl NamespaceAddressing {
    pub const fn label(self) -> &'static str {
        match self {
            Self::DirectRanges => "direct-ranges",
            Self::SelectiveTransform => "selective-transform",
            Self::ReconstructedAddressSpace => "reconstructed-address-space",
        }
    }
}

/// Product execution prerequisite for exposing a declared namespace.
///
/// This is separate from addressing: a carrier can have well-understood
/// selective transforms while still requiring a licensed transform service
/// that the ordinary static provider callback cannot supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceExecution {
    /// No external transform prerequisite is known. Provider availability is
    /// tracked separately by the support catalog.
    Native,
    /// Materializing members requires an explicitly injected external
    /// transform service.
    ExternalTransformRequired,
}

impl NamespaceExecution {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::ExternalTransformRequired => "external-transform-required",
        }
    }
}

/// An owner-authored declaration of whether and how a format is a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceSemantics {
    pub id: FormatId,
    pub kind: NamespaceKind,
    pub addressing: Option<NamespaceAddressing>,
    pub execution: NamespaceExecution,
}

impl NamespaceSemantics {
    pub const fn carrier(id: FormatId, addressing: NamespaceAddressing) -> Self {
        Self {
            id,
            kind: NamespaceKind::Carrier,
            addressing: Some(addressing),
            execution: NamespaceExecution::Native,
        }
    }

    pub const fn external_transform_carrier(id: FormatId, addressing: NamespaceAddressing) -> Self {
        Self {
            id,
            kind: NamespaceKind::Carrier,
            addressing: Some(addressing),
            execution: NamespaceExecution::ExternalTransformRequired,
        }
    }

    pub const fn semantic_view(id: FormatId, addressing: NamespaceAddressing) -> Self {
        Self {
            id,
            kind: NamespaceKind::SemanticView,
            addressing: Some(addressing),
            execution: NamespaceExecution::Native,
        }
    }

    pub const fn non_namespace(id: FormatId) -> Self {
        Self {
            id,
            kind: NamespaceKind::NonNamespace,
            addressing: None,
            execution: NamespaceExecution::Native,
        }
    }

    pub const fn is_valid(self) -> bool {
        matches!(
            (self.kind, self.addressing, self.execution),
            (
                NamespaceKind::Carrier | NamespaceKind::SemanticView,
                Some(_),
                NamespaceExecution::Native
            ) | (
                NamespaceKind::Carrier | NamespaceKind::SemanticView,
                Some(
                    NamespaceAddressing::SelectiveTransform
                        | NamespaceAddressing::ReconstructedAddressSpace
                ),
                NamespaceExecution::ExternalTransformRequired
            ) | (
                NamespaceKind::NonNamespace,
                None,
                NamespaceExecution::Native
            )
        )
    }
}

/// The physical source set required to expose one format as a random-access
/// namespace. This is deliberately product-wide: archives, disc images, and
/// paired index/data stores all present the same lookup contract to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceMountInput {
    /// One carrier contains both directory metadata and member bodies.
    SingleSource { role: &'static str },
    /// One carrier plus an explicit semantic selector required to interpret
    /// it. The selector is data, not a filename-derived hint.
    SelectedSingleSource {
        role: &'static str,
        selector_role: &'static str,
    },
    /// A directory carrier addresses one unambiguous content carrier.
    PairedSources {
        directory_role: &'static str,
        content_role: &'static str,
    },
    /// A directory carrier addresses several possible content carriers and
    /// requires an explicit semantic selector to interpret the chosen one.
    /// The selector is data, not a filename-derived hint.
    SelectedPairedSources {
        directory_role: &'static str,
        content_role: &'static str,
        selector_role: &'static str,
    },
    /// The ordinary carrier is self-contained, but a union directory may
    /// address the same format through one explicitly selected physical
    /// carrier. Both topologies share one semantic namespace identity.
    SingleOrSelectedPairedSources {
        single_role: &'static str,
        directory_role: &'static str,
        content_role: &'static str,
        selector_role: &'static str,
    },
}

impl NamespaceMountInput {
    /// Bind the legacy topology through an equivalent finite schema. Schema
    /// success does not replace the owner's paired-source relationship checks.
    pub fn bind(
        self,
        sources: &formatkit_core::SourceBindings,
        bytes: &[super::ByteInput<'_>],
        selectors: &[super::SelectorInput<'_>],
    ) -> formatkit_core::Result<super::BoundInputs> {
        use super::{ByteRole, InputForm, InputSchema, SelectorRole};
        let single = [ByteRole::one(self.single_role().unwrap_or("unused"))];
        let (directory, content) = self.roles();
        let paired = [
            ByteRole::one(directory),
            ByteRole::one(content.unwrap_or("unused")),
        ];
        let selected = [SelectorRole {
            name: self.selector_role().unwrap_or("unused"),
            required: true,
        }];
        let single_form = InputForm {
            name: "single",
            bytes: &single,
            selectors: &[],
        };
        let selected_single_form = InputForm {
            name: "single",
            bytes: &single,
            selectors: &selected,
        };
        let pair_form = InputForm {
            name: "paired",
            bytes: &paired,
            selectors: if self.selector_role().is_some() {
                &selected
            } else {
                &[]
            },
        };
        let forms = match self {
            Self::SingleSource { .. } => [single_form, single_form],
            Self::SelectedSingleSource { .. } => [selected_single_form, selected_single_form],
            Self::PairedSources { .. } | Self::SelectedPairedSources { .. } => {
                [pair_form, pair_form]
            }
            Self::SingleOrSelectedPairedSources { .. } => [single_form, pair_form],
        };
        let count = if matches!(self, Self::SingleOrSelectedPairedSources { .. }) {
            2
        } else {
            1
        };
        InputSchema {
            forms: &forms[..count],
            relationships: &[],
        }
        .bind(sources, bytes, selectors)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::SingleSource { .. } => "single-source",
            Self::SelectedSingleSource { .. } => "selected-single-source",
            Self::PairedSources { .. } => "paired-sources",
            Self::SelectedPairedSources { .. } => "selected-paired-sources",
            Self::SingleOrSelectedPairedSources { .. } => "single-or-selected-paired-sources",
        }
    }

    pub const fn roles(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::SingleSource { role } | Self::SelectedSingleSource { role, .. } => (role, None),
            Self::PairedSources {
                directory_role,
                content_role,
            } => (directory_role, Some(content_role)),
            Self::SelectedPairedSources {
                directory_role,
                content_role,
                ..
            } => (directory_role, Some(content_role)),
            Self::SingleOrSelectedPairedSources {
                directory_role,
                content_role,
                ..
            } => (directory_role, Some(content_role)),
        }
    }

    pub const fn single_role(self) -> Option<&'static str> {
        match self {
            Self::SingleSource { role } | Self::SelectedSingleSource { role, .. } => Some(role),
            Self::SingleOrSelectedPairedSources { single_role, .. } => Some(single_role),
            Self::PairedSources { .. } | Self::SelectedPairedSources { .. } => None,
        }
    }

    pub const fn selector_role(self) -> Option<&'static str> {
        match self {
            Self::SelectedSingleSource { selector_role, .. }
            | Self::SelectedPairedSources { selector_role, .. }
            | Self::SingleOrSelectedPairedSources { selector_role, .. } => Some(selector_role),
            Self::SingleSource { .. } | Self::PairedSources { .. } => None,
        }
    }
}

/// Observable cost class of constructing an indexed namespace.
///
/// This is intentionally separate from source cardinality: a single-source
/// mount can still materialize an entire carrier, while a paired mount can read
/// only its compact index and leave the data source lazy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceMountStrategy {
    /// Reads bounded directory/validation metadata and leaves all member
    /// payloads attached to their source ranges.
    MetadataOnly,
    /// Builds a bounded transformed address space needed for random access,
    /// while leaving unrelated source regions untouched.
    SelectiveTransform,
    /// Reads or transforms the complete carrier while constructing the mount.
    WholeCarrier,
}

impl NamespaceMountStrategy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata-only",
            Self::SelectiveTransform => "selective-transform",
            Self::WholeCarrier => "whole-carrier",
        }
    }

    /// Whether this policy ceiling admits a provider with `required` mount
    /// cost. Products can thereby permit metadata-only or selective mounts
    /// without accidentally opting into whole-carrier materialization.
    pub const fn permits(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::MetadataOnly, Self::MetadataOnly)
                | (
                    Self::SelectiveTransform,
                    Self::MetadataOnly | Self::SelectiveTransform
                )
                | (Self::WholeCarrier, _)
        )
    }
}

/// The kind of collision evidence carried by a namespace contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceCollisionKind {
    /// Every namespace owner participating in the named ambiguity declares the
    /// same group. Composition requires at least two owners.
    SharedNamespaceGroup,
    /// The namespace is checked against a non-namespace owner, a malformed
    /// weak head, or another peer that cannot carry a namespace contract.
    PeerBoundary,
}

/// Evidence that a namespace collision boundary is resolved deliberately
/// rather than by registration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceCollisionContract {
    pub kind: NamespaceCollisionKind,
    pub group: &'static str,
    pub ambiguity_oracle: CargoTestOracle,
}

/// Executable proof obligations for one source-native namespace mount.
///
/// A parser may expose a mount before acquiring this contract. Once attached,
/// the catalog requires parity with the owning parser, independently checked
/// layout, bounded and stable range access, typed dispatch failures, malformed
/// input rejection, CLI integration, collision handling where applicable, and
/// corpus evidence whenever that capability is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceMountContract {
    pub id: FormatId,
    pub input: NamespaceMountInput,
    pub strategy: NamespaceMountStrategy,
    pub parser_parity_oracle: CargoTestOracle,
    pub independent_layout_oracle: CargoTestOracle,
    pub budget_oracle: CargoTestOracle,
    pub stability_oracle: CargoTestOracle,
    pub dispatch_oracle: CargoTestOracle,
    pub malformed_oracle: CargoTestOracle,
    pub collision: Option<NamespaceCollisionContract>,
    pub cli_oracle: CargoTestOracle,
    pub corpus_oracle: Option<CargoTestOracle>,
}

impl NamespaceMountContract {
    pub fn oracles(self) -> impl Iterator<Item = CargoTestOracle> {
        [
            self.parser_parity_oracle,
            self.independent_layout_oracle,
            self.budget_oracle,
            self.stability_oracle,
            self.dispatch_oracle,
            self.malformed_oracle,
            self.cli_oracle,
        ]
        .into_iter()
        .chain(self.collision.map(|contract| contract.ambiguity_oracle))
        .chain(self.corpus_oracle)
    }
}

pub type SingleNamespaceMounter =
    fn(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>>;
pub type SelectedSingleNamespaceMounter =
    fn(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        &str,
        &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>>;
pub type NamespaceSourceProbe =
    fn(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        &[u8],
        &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Option<Box<dyn formatkit_core::IndexedNamespace>>>;
pub type WorkNamespaceSourceProbe =
    fn(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        &[u8],
        &mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<Option<Box<dyn formatkit_core::IndexedNamespace>>>;
/// What scoped work a work-runner mount must admit before mounting.
///
/// The caller declares its operation class so the runner can preflight the
/// complete mount-plus-operation allocation plan (mount structures plus the
/// caller's report or extraction buffers) before any read, work, or retained
/// allocation. Bounds travel as plain data; the runner derives exact totals
/// from the member count once the minimum derivation read lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkRunnerOp {
    /// Flat listing: the caller builds one report row per member inside the
    /// runner scope. Carries the caller's nominal per-row retained bytes for
    /// that row class, whether member heads are identified, and the head-read
    /// cap the caller honors.
    List {
        row_materialized_nominal: u64,
        row_resident_nominal: u64,
        identify: bool,
        head_cap: u64,
    },
    /// Single-member extraction: the caller resolves one member and streams
    /// its bounded bytes inside the runner scope. Carries the caller's
    /// nominal retained bytes for its stream buffer plus report assembly; the
    /// runner preflights the worst-case member decode itself.
    Extract {
        caller_materialized_nominal: u64,
        caller_resident_nominal: u64,
    },
}

/// Scoped user of a work-runner mount: invoked once with the live mount and
/// the ledger guard covering its retained graph. All traversal, report, and
/// extraction allocation happens here, under the same ledger, before the
/// mount is dropped and its resident permit released.
pub type WorkRunnerUser<'user> = dyn FnMut(
        &dyn formatkit_core::IndexedNamespace,
        &mut formatkit_core::ResidentReservation,
    ) -> formatkit_core::Result<()>
    + 'user;

/// Work-ledger-native single-source mount without type erasure. The mount
/// lives on the runner's stack frame, owns no heap beyond its fallibly
/// admitted containers, and is dropped (releasing its resident permit) when
/// the scoped user returns. The caller declares `op` so the runner preflights
/// the complete plan before mounting.
pub type WorkSourceRunner = for<'budget, 'user> fn(
    std::sync::Arc<dyn formatkit_core::RangeSource>,
    &'budget mut formatkit_core::WorkBudget,
    WorkRunnerOp,
    &'user mut WorkRunnerUser<'user>,
) -> formatkit_core::Result<()>;

/// A format identity and the namespace whose successful source probe proved it.
pub struct IdentifiedNamespace {
    pub format_id: FormatId,
    pub namespace: Box<dyn formatkit_core::IndexedNamespace>,
}

impl fmt::Debug for IdentifiedNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentifiedNamespace")
            .field("format_id", &self.format_id)
            .field("member_count", &self.namespace.len())
            .finish_non_exhaustive()
    }
}

/// Named sources for a two-file namespace, optionally carrying the explicit
/// selector required by [`NamespaceMountInput::SelectedPairedSources`].
///
/// Keeping the directory and content roles attached to their sources prevents
/// generic dispatch from silently reversing two type-identical `Arc`s. The
/// format callback must claim the exact role names it understands before it
/// can access either source.
#[derive(Clone)]
pub struct PairedNamespaceSources {
    directory_role: &'static str,
    directory: std::sync::Arc<dyn formatkit_core::RangeSource>,
    content_role: &'static str,
    content: std::sync::Arc<dyn formatkit_core::RangeSource>,
    selector: Option<(&'static str, String)>,
}

impl fmt::Debug for PairedNamespaceSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedNamespaceSources")
            .field("directory_role", &self.directory_role)
            .field("directory_size", &self.directory.size())
            .field("content_role", &self.content_role)
            .field("content_size", &self.content.size())
            .field("selector", &self.selector)
            .finish()
    }
}

impl PairedNamespaceSources {
    /// Bind callers' physical sources to the declared topology, including an
    /// optional semantic selector. Products should use this entry point rather
    /// than matching [`NamespaceMountInput`] variants themselves.
    pub fn for_input_with_selector(
        input: NamespaceMountInput,
        directory: std::sync::Arc<dyn formatkit_core::RangeSource>,
        content: std::sync::Arc<dyn formatkit_core::RangeSource>,
        selector: Option<&str>,
    ) -> formatkit_core::Result<Self> {
        match (input, selector) {
            (NamespaceMountInput::PairedSources { .. }, None) => {
                Self::for_input(input, directory, content)
            }
            (
                NamespaceMountInput::SelectedPairedSources { .. }
                | NamespaceMountInput::SingleOrSelectedPairedSources { .. },
                Some(selector),
            ) => Self::for_selected_input(input, directory, content, selector),
            (
                NamespaceMountInput::SelectedPairedSources { selector_role, .. }
                | NamespaceMountInput::SingleOrSelectedPairedSources { selector_role, .. },
                None,
            ) => Err(formatkit_core::Error::Unsupported(format!(
                "paired namespace input {} requires selector {selector_role:?}",
                input.label()
            ))),
            (NamespaceMountInput::PairedSources { .. }, Some(_)) => {
                Err(formatkit_core::Error::Unsupported(format!(
                    "paired namespace input {} does not accept a selector",
                    input.label()
                )))
            }
            (
                NamespaceMountInput::SingleSource { .. }
                | NamespaceMountInput::SelectedSingleSource { .. },
                _,
            ) => Self::for_input(input, directory, content),
        }
    }

    pub fn for_input(
        input: NamespaceMountInput,
        directory: std::sync::Arc<dyn formatkit_core::RangeSource>,
        content: std::sync::Arc<dyn formatkit_core::RangeSource>,
    ) -> formatkit_core::Result<Self> {
        let NamespaceMountInput::PairedSources {
            directory_role,
            content_role,
        } = input
        else {
            return Err(formatkit_core::Error::Unsupported(format!(
                "namespace input {} is not paired",
                input.label()
            )));
        };
        Ok(Self {
            directory_role,
            directory,
            content_role,
            content,
            selector: None,
        })
    }

    pub fn for_selected_input(
        input: NamespaceMountInput,
        directory: std::sync::Arc<dyn formatkit_core::RangeSource>,
        content: std::sync::Arc<dyn formatkit_core::RangeSource>,
        selector: impl Into<String>,
    ) -> formatkit_core::Result<Self> {
        let (directory_role, content_role, selector_role) = match input {
            NamespaceMountInput::SelectedPairedSources {
                directory_role,
                content_role,
                selector_role,
            }
            | NamespaceMountInput::SingleOrSelectedPairedSources {
                directory_role,
                content_role,
                selector_role,
                ..
            } => (directory_role, content_role, selector_role),
            _ => {
                return Err(formatkit_core::Error::Unsupported(format!(
                    "namespace input {} does not accept a selector",
                    input.label()
                )));
            }
        };
        let selector = selector.into();
        if selector.is_empty() {
            return Err(formatkit_core::Error::Unsupported(format!(
                "paired namespace selector {selector_role:?} is empty"
            )));
        }
        Ok(Self {
            directory_role,
            directory,
            content_role,
            content,
            selector: Some((selector_role, selector)),
        })
    }

    pub const fn roles(&self) -> (&'static str, &'static str) {
        (self.directory_role, self.content_role)
    }

    pub fn selector(&self) -> Option<(&'static str, &str)> {
        self.selector
            .as_ref()
            .map(|(role, value)| (*role, value.as_str()))
    }

    pub fn into_roles(
        self,
        directory_role: &'static str,
        content_role: &'static str,
    ) -> formatkit_core::Result<(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        std::sync::Arc<dyn formatkit_core::RangeSource>,
    )> {
        if self.roles() != (directory_role, content_role) || self.selector.is_some() {
            return Err(formatkit_core::Error::Unsupported(format!(
                "paired namespace roles {:?} do not match required roles ({directory_role:?}, {content_role:?})",
                self.roles()
            )));
        }
        Ok((self.directory, self.content))
    }

    #[allow(clippy::type_complexity)]
    pub fn into_selected_roles(
        self,
        directory_role: &'static str,
        content_role: &'static str,
        selector_role: &'static str,
    ) -> formatkit_core::Result<(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        String,
    )> {
        if self.roles() != (directory_role, content_role)
            || self.selector().map(|(role, _)| role) != Some(selector_role)
        {
            return Err(formatkit_core::Error::Unsupported(format!(
                "selected paired namespace roles {:?} and selector {:?} do not match required roles ({directory_role:?}, {content_role:?}, {selector_role:?})",
                self.roles(),
                self.selector()
            )));
        }
        let (_, selector) = self.selector.expect("selected role checked above");
        Ok((self.directory, self.content, selector))
    }
}

pub type PairedNamespaceMounter =
    fn(
        PairedNamespaceSources,
        &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>>;
/// Work-native single-source mount: the mounted namespace plus the resident
/// reservation covering its retained bytes. Both live and drop together
/// (fields drop in declaration order, so the permit releases only after its
/// storage is gone); the caller keeps the borrowed ledger alive across use.
/// The two fields are disjoint, so products may walk the namespace while
/// charging traversal through the reservation on the same ledger.
pub struct WorkMountedNamespace<'budget> {
    pub namespace: Box<dyn formatkit_core::IndexedNamespace + 'budget>,
    pub resident: formatkit_core::ResidentReservation<'budget>,
}

/// Single-source mount on the caller's native work ledger.
pub type WorkSingleNamespaceMounter =
    for<'budget> fn(
        std::sync::Arc<dyn formatkit_core::RangeSource>,
        &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<WorkMountedNamespace<'budget>>;

/// Callable runtime half of a [`NamespaceMountContract`]. Products compose
/// providers from every decoder crate they ship; the support catalog accepts a
/// namespace capability only when its evidence, source roles, owning decoder,
/// and executable callback agree exactly.
#[derive(Clone, Copy)]
pub enum NamespaceProviderMount {
    Single(SingleNamespaceMounter),
    SelectedSingle(SelectedSingleNamespaceMounter),
    Paired(PairedNamespaceMounter),
    SingleOrPaired {
        single: SingleNamespaceMounter,
        paired: PairedNamespaceMounter,
    },
    WorkRunner(WorkSourceRunner),
    /// Work-native single-source mount. This is single-capable but has no
    /// legacy `ReadBudget` callback: products must mount through
    /// [`NamespaceProvider::mount_single_work`] with the caller's own ledger.
    WorkSingle(WorkSingleNamespaceMounter),
}

impl fmt::Debug for NamespaceProviderMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Single(_) => "Single(..)",
            Self::SelectedSingle(_) => "SelectedSingle(..)",
            Self::Paired(_) => "Paired(..)",
            Self::SingleOrPaired { .. } => "SingleOrPaired(..)",
            Self::WorkRunner(_) => "WorkRunner(..)",
            Self::WorkSingle(_) => "WorkSingle(..)",
        })
    }
}

impl NamespaceProviderMount {
    const fn supports_single(self) -> bool {
        matches!(
            self,
            Self::Single(_)
                | Self::SingleOrPaired { .. }
                | Self::WorkRunner(_)
                | Self::WorkSingle(_)
        )
    }

    const fn supports_work_single(self) -> bool {
        matches!(self, Self::WorkSingle(_))
    }

    const fn supports_work_runner(self) -> bool {
        matches!(self, Self::WorkRunner(_))
    }

    const fn supports_selected_single(self) -> bool {
        matches!(self, Self::SelectedSingle(_))
    }

    const fn supports_pair(self) -> bool {
        matches!(self, Self::Paired(_) | Self::SingleOrPaired { .. })
    }

    const fn matches_input(self, input: NamespaceMountInput) -> bool {
        matches!(
            (input, self),
            (NamespaceMountInput::SingleSource { .. }, Self::Single(_))
                | (
                    NamespaceMountInput::SingleSource { .. },
                    Self::WorkRunner(_)
                )
                | (
                    NamespaceMountInput::SingleSource { .. },
                    Self::WorkSingle(_)
                )
                | (
                    NamespaceMountInput::SelectedSingleSource { .. },
                    Self::SelectedSingle(_)
                )
                | (
                    NamespaceMountInput::PairedSources { .. }
                        | NamespaceMountInput::SelectedPairedSources { .. },
                    Self::Paired(_)
                )
                | (
                    NamespaceMountInput::SingleOrSelectedPairedSources { .. },
                    Self::SingleOrPaired { .. }
                )
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NamespaceProvider {
    pub id: FormatId,
    pub owner: &'static str,
    pub input: NamespaceMountInput,
    pub strategy: NamespaceMountStrategy,
    pub mount: NamespaceProviderMount,
    /// Optional structural probe for formats whose complete directory cannot
    /// be authenticated from the generic detector prefix alone.
    pub source_probe: Option<NamespaceSourceProbe>,
    /// Source-native probe which participates in one complete work ledger.
    pub work_source_probe: Option<WorkNamespaceSourceProbe>,
    /// Optional exact byte prefix that allows a product to schedule this
    /// source probe before its ordinary broad classification read. The probe
    /// still owns complete recognition; this is only a cheap discriminator.
    pub early_probe_prefix: Option<&'static [u8]>,
}

pub fn identify_and_mount_namespace_source_work(
    providers: impl IntoIterator<Item = NamespaceProvider>,
    source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    prefix: &[u8],
    budget: &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<Option<IdentifiedNamespace>> {
    let mut selected: Option<IdentifiedNamespace> = None;
    for provider in providers {
        let probe = match (provider.work_source_probe, provider.source_probe) {
            (Some(probe), _) => probe,
            (None, Some(_)) => {
                return Err(formatkit_core::Error::Unsupported(format!(
                    "source-native candidate {} has no WorkBudget probe",
                    provider.id
                )))
            }
            (None, None) => continue,
        };
        let Some(namespace) = probe(source.clone(), prefix, budget)? else {
            continue;
        };
        if let Some(previous) = selected.as_ref() {
            return Err(formatkit_core::Error::Malformed(format!(
                "source-native identification is ambiguous between {} and {}",
                previous.format_id, provider.id
            )));
        }
        selected = Some(IdentifiedNamespace {
            format_id: provider.id,
            namespace,
        });
    }
    source.verify_unchanged()?;
    Ok(selected)
}

pub fn identify_and_mount_namespace_source_early_work(
    providers: impl IntoIterator<Item = NamespaceProvider>,
    source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    prefix: &[u8],
    budget: &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<Option<IdentifiedNamespace>> {
    identify_and_mount_namespace_source_work(
        providers.into_iter().filter(|provider| {
            provider
                .early_probe_prefix
                .is_some_and(|discriminator| prefix.starts_with(discriminator))
        }),
        source,
        prefix,
        budget,
    )
}

/// Product dispatch may stage this many cheap discriminator bytes before its
/// ordinary bounded identification prefix. This is a scheduling ceiling, not
/// a format metadata or source-read budget.
pub const MAX_EARLY_NAMESPACE_PROBE_BYTES: usize = 64;

/// Longest discriminator a validated provider set needs staged. Products use
/// this to size one shared early read before extending the same prefix.
pub fn early_namespace_probe_len(providers: impl IntoIterator<Item = NamespaceProvider>) -> usize {
    providers
        .into_iter()
        .filter_map(|provider| provider.early_probe_prefix.map(<[u8]>::len))
        .max()
        .unwrap_or(0)
}

/// Resolve source-aware structural candidates without reading a successful
/// directory twice. Candidate budgets are isolated and charged to one
/// aggregate caller budget; multiple complete parses remain an ambiguity.
pub fn identify_and_mount_namespace_source(
    providers: impl IntoIterator<Item = NamespaceProvider>,
    source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    prefix: &[u8],
    budget: &mut formatkit_core::ReadBudget,
) -> formatkit_core::Result<Option<IdentifiedNamespace>> {
    let mut selected: Option<IdentifiedNamespace> = None;
    for provider in providers {
        let Some(probe) = provider.source_probe else {
            continue;
        };
        let mut candidate_budget = budget.remaining().map_or_else(
            formatkit_core::ReadBudget::unlimited,
            formatkit_core::ReadBudget::limited,
        );
        let outcome = probe(source.clone(), prefix, &mut candidate_budget);
        budget.charge(candidate_budget.spent())?;
        let Some(namespace) = outcome? else {
            continue;
        };
        if let Some(previous) = selected.as_ref() {
            return Err(formatkit_core::Error::Malformed(format!(
                "source-native identification is ambiguous between {} and {}",
                previous.format_id, provider.id
            )));
        }
        selected = Some(IdentifiedNamespace {
            format_id: provider.id,
            namespace,
        });
    }
    source.verify_unchanged()?;
    Ok(selected)
}

/// Resolve only source-aware providers whose declared cheap discriminator
/// matches an already-read prefix. Matching is scheduling, not precedence:
/// all matching probes run through the ordinary ambiguity and error rules.
pub fn identify_and_mount_namespace_source_early(
    providers: impl IntoIterator<Item = NamespaceProvider>,
    source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    prefix: &[u8],
    budget: &mut formatkit_core::ReadBudget,
) -> formatkit_core::Result<Option<IdentifiedNamespace>> {
    identify_and_mount_namespace_source(
        providers.into_iter().filter(|provider| {
            provider
                .early_probe_prefix
                .is_some_and(|discriminator| prefix.starts_with(discriminator))
        }),
        source,
        prefix,
        budget,
    )
}

impl NamespaceProvider {
    /// Validate named inputs once, then dispatch through the established owner
    /// callback. Existing single/paired APIs and their diagnostics stay intact.
    pub fn mount_inputs(
        self,
        sources: &formatkit_core::SourceBindings,
        bytes: &[super::ByteInput<'_>],
        selectors: &[super::SelectorInput<'_>],
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        let bound = self.input.bind(sources, bytes, selectors)?;
        if bound.form() == "single" {
            let role = self.input.single_role().expect("bound single form");
            let source = sources.source(bound.single_source(role)?)?.clone();
            if let NamespaceMountInput::SelectedSingleSource { selector_role, .. } = self.input {
                let selector = bound.selector(selector_role).ok_or_else(|| {
                    formatkit_core::Error::Unsupported(format!(
                        "namespace {} requires selector {selector_role:?}",
                        self.id
                    ))
                })?;
                return self.mount_selected_single(source, selector, budget);
            }
            self.mount_single(source, budget)
        } else {
            let (directory, content) = self.input.roles();
            let content = content.expect("bound paired form");
            let pair = PairedNamespaceSources::for_input_with_selector(
                self.input,
                sources.source(bound.single_source(directory)?)?.clone(),
                sources.source(bound.single_source(content)?)?.clone(),
                self.input
                    .selector_role()
                    .and_then(|role| bound.selector(role)),
            )?;
            self.mount_pair(pair, budget)
        }
    }

    /// Whether this provider accepts the format's self-contained source shape.
    pub const fn supports_single(self) -> bool {
        self.mount.supports_single()
    }

    /// Whether this provider mounts one source through the native work ledger.
    pub const fn supports_work_runner(self) -> bool {
        self.mount.supports_work_runner()
    }

    /// Whether this provider mounts only on the caller's native work ledger.
    pub const fn supports_work_single(self) -> bool {
        self.mount.supports_work_single()
    }

    /// Whether this provider accepts one source plus its required selector.
    pub const fn supports_selected_single(self) -> bool {
        self.mount.supports_selected_single()
    }

    /// Whether this provider accepts the format's paired source shape.
    pub const fn supports_pair(self) -> bool {
        self.mount.supports_pair()
    }

    /// Whether the executable callback shape agrees with the declared source
    /// topology. Catalog validation uses this rather than duplicating topology
    /// matching in every product.
    pub const fn mount_matches_input(self) -> bool {
        self.mount.matches_input(self.input)
    }

    pub fn enforce_strategy(self, maximum: NamespaceMountStrategy) -> formatkit_core::Result<Self> {
        if maximum.permits(self.strategy) {
            Ok(self)
        } else {
            Err(formatkit_core::Error::Unsupported(format!(
                "namespace {} requires {} mounting but product policy permits at most {}",
                self.id,
                self.strategy.label(),
                maximum.label()
            )))
        }
    }

    pub fn mount_single(
        self,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        match self.mount {
            NamespaceProviderMount::Single(mount)
            | NamespaceProviderMount::SingleOrPaired { single: mount, .. } => mount(source, budget),
            NamespaceProviderMount::WorkRunner(_) => {
                Err(formatkit_core::Error::Unsupported(format!(
                    "namespace {} mounts only through the native work ledger",
                    self.id,
                )))
            }
            NamespaceProviderMount::SelectedSingle(_) => {
                Err(formatkit_core::Error::Unsupported(format!(
                    "namespace {} requires selector {:?} with its single role {:?}",
                    self.id,
                    self.input.selector_role().unwrap_or("selector"),
                    self.input.single_role().unwrap_or("source"),
                )))
            }
            NamespaceProviderMount::WorkSingle(_) => {
                Err(formatkit_core::Error::Unsupported(format!(
                    "namespace {id} mounts only through its WorkBudget-native single-source route",
                    id = self.id,
                )))
            }
            NamespaceProviderMount::Paired(_) => Err(formatkit_core::Error::Unsupported(format!(
                "namespace {} requires paired roles {:?}",
                self.id,
                self.input.roles()
            ))),
        }
    }

    pub fn mount_work_runner(
        self,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        budget: &mut formatkit_core::WorkBudget,
        op: WorkRunnerOp,
        user: &mut WorkRunnerUser<'_>,
    ) -> formatkit_core::Result<()> {
        match self.mount {
            NamespaceProviderMount::WorkRunner(runner) => runner(source, budget, op, user),
            _ => Err(formatkit_core::Error::Unsupported(format!(
                "namespace {id} has no native work-ledger single-source runner",
                id = self.id,
            ))),
        }
    }

    /// Mount one single-source namespace on the caller's own work ledger.
    /// Only [`NamespaceProviderMount::WorkSingle`] providers serve this route;
    /// every other shape keeps its established legacy callback.
    pub fn mount_single_work<'budget>(
        self,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        budget: &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<WorkMountedNamespace<'budget>> {
        match self.mount {
            NamespaceProviderMount::WorkSingle(mount) => mount(source, budget),
            _ => Err(formatkit_core::Error::Unsupported(format!(
                "namespace {id} has no WorkBudget-native single-source mount",
                id = self.id,
            ))),
        }
    }

    pub fn mount_selected_single(
        self,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        selector: &str,
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        match self.mount {
            NamespaceProviderMount::SelectedSingle(mount) => mount(source, selector, budget),
            _ => Err(formatkit_core::Error::Unsupported(format!(
                "namespace {} has no selected single-source mount for selector role {:?}",
                self.id,
                self.input.selector_role(),
            ))),
        }
    }

    pub fn mount_pair(
        self,
        sources: PairedNamespaceSources,
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        match self.mount {
            NamespaceProviderMount::Paired(mount)
            | NamespaceProviderMount::SingleOrPaired { paired: mount, .. } => {
                let expected = self.input.roles();
                let expected_selector = self.input.selector_role();
                if sources.roles() != (expected.0, expected.1.expect("paired provider role"))
                    || sources.selector().map(|(role, _)| role) != expected_selector
                {
                    return Err(formatkit_core::Error::Unsupported(format!(
                        "namespace {} received paired roles {:?} selector {:?}, expected {:?} selector {:?}",
                        self.id,
                        sources.roles(),
                        sources.selector(),
                        expected,
                        expected_selector,
                    )));
                }
                mount(sources, budget)
            }
            NamespaceProviderMount::Single(_)
            | NamespaceProviderMount::SelectedSingle(_)
            | NamespaceProviderMount::WorkRunner(_)
            | NamespaceProviderMount::WorkSingle(_) => {
                Err(formatkit_core::Error::Unsupported(format!(
                    "namespace {} requires the single role {:?}",
                    self.id,
                    self.input.single_role().unwrap_or(self.input.roles().0)
                )))
            }
        }
    }
}

pub(super) enum NamespaceCompositionError {
    Contract(FormatId),
    Provider(FormatId),
}

type NamespaceCollisionGroups = std::collections::HashMap<
    &'static str,
    (NamespaceCollisionKind, std::collections::HashSet<FormatId>),
>;

fn valid_namespace_contract(
    contract: NamespaceMountContract,
    caps: FormatCapabilities,
    requirement: Option<DecoderRequirement>,
    embedded_context: Option<super::ContextRequirement>,
) -> bool {
    let valid_role = |role: &str| {
        !role.is_empty()
            && role.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
    };
    let (first_role, second_role) = contract.input.roles();
    let roles_ok = valid_role(first_role)
        && second_role.is_none_or(|role| valid_role(role) && role != first_role)
        && contract
            .input
            .selector_role()
            .is_none_or(|role| valid_role(role) && role != first_role && Some(role) != second_role)
        && contract.input.single_role().is_none_or(|role| {
            valid_role(role)
                && match contract.input {
                    NamespaceMountInput::SingleOrSelectedPairedSources { .. } => {
                        role != first_role && Some(role) != second_role
                    }
                    _ => true,
                }
        });
    let input_matches = requirement.map_or_else(
        || {
            matches!(
                (embedded_context, contract.input),
                (
                    Some(super::ContextRequirement::ExplicitSelection),
                    NamespaceMountInput::SingleSource { .. }
                        | NamespaceMountInput::SelectedSingleSource { .. }
                ) | (
                    Some(super::ContextRequirement::PairedData { .. }),
                    NamespaceMountInput::PairedSources { .. }
                        | NamespaceMountInput::SelectedPairedSources { .. }
                ) | (
                    Some(
                        super::ContextRequirement::ParentAddressSpace { .. }
                            | super::ContextRequirement::ParentAndSiblings { .. }
                            | super::ContextRequirement::AuthenticatedCarrierMember { .. }
                    ),
                    NamespaceMountInput::SingleSource { .. }
                )
            )
        },
        |requirement| match contract.input {
            NamespaceMountInput::SingleSource { .. }
            | NamespaceMountInput::SelectedSingleSource { .. }
            | NamespaceMountInput::SingleOrSelectedPairedSources { .. } => {
                requirement == DecoderRequirement::None
            }
            NamespaceMountInput::PairedSources { .. }
            | NamespaceMountInput::SelectedPairedSources { .. } => {
                requirement == DecoderRequirement::PairedData
            }
        },
    );
    let collision_ok = valid_namespace_collision(contract.collision);
    caps.parse
        && caps.corpus == contract.corpus_oracle.is_some()
        && roles_ok
        && input_matches
        && collision_ok
        && contract.oracles().all(valid_cargo_test_oracle)
}

fn valid_namespace_collision(collision: Option<NamespaceCollisionContract>) -> bool {
    collision.is_none_or(|collision| {
        !collision.group.trim().is_empty()
            && collision
                .group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && valid_cargo_test_oracle(collision.ambiguity_oracle)
    })
}

fn valid_namespace_provider(
    provider: NamespaceProvider,
    contract: NamespaceMountContract,
    decoder: Option<&str>,
) -> bool {
    provider.id == contract.id
        && provider.input == contract.input
        && provider.strategy == contract.strategy
        && provider.mount_matches_input()
        && ((provider.source_probe.is_none() && provider.work_source_probe.is_none())
            || provider.supports_single())
        && provider.early_probe_prefix.is_none_or(|prefix| {
            !prefix.is_empty()
                && prefix.len() <= MAX_EARLY_NAMESPACE_PROBE_BYTES
                && (provider.source_probe.is_some() || provider.work_source_probe.is_some())
        })
        && decoder == Some(provider.owner)
}

fn register_namespace_collision(
    id: FormatId,
    collision: Option<NamespaceCollisionContract>,
    groups: &mut NamespaceCollisionGroups,
) -> Result<(), NamespaceCompositionError> {
    if let Some(collision) = collision {
        let entry = groups
            .entry(collision.group)
            .or_insert_with(|| (collision.kind, Default::default()));
        if entry.0 != collision.kind {
            return Err(NamespaceCompositionError::Contract(id));
        }
        entry.1.insert(id);
    }
    Ok(())
}

fn validate_namespace_collision_groups(
    groups: NamespaceCollisionGroups,
) -> Result<(), NamespaceCompositionError> {
    for (kind, ids) in groups.into_values() {
        if kind == NamespaceCollisionKind::SharedNamespaceGroup && ids.len() < 2 {
            return Err(NamespaceCompositionError::Contract(
                *ids.iter().next().expect("registered group has a format"),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_named_namespace_operations<'a>(
    support: &super::SupportCatalog,
    operations: impl IntoIterator<Item = (&'a NamespaceMountContract, &'a NamespaceProvider)>,
    role_bound: impl IntoIterator<
        Item = (
            &'a RoleBoundNamespaceContract,
            &'a RoleBoundNamespaceProvider,
        ),
    >,
) -> Result<(), super::SupportCatalogError> {
    let mut groups = NamespaceCollisionGroups::new();
    for (&contract, &provider) in operations {
        let view = support.get(contract.id).ok_or(
            super::SupportCatalogError::InvalidNamespaceMountContract(contract.id),
        )?;
        if !valid_namespace_contract(
            contract,
            view.capabilities(),
            view.detectable.map(|descriptor| descriptor.requirement),
            view.embedded.map(|support| support.context),
        ) {
            return Err(super::SupportCatalogError::InvalidNamespaceMountContract(
                contract.id,
            ));
        }
        if !valid_namespace_provider(provider, contract, view.decoder()) {
            return Err(super::SupportCatalogError::InvalidNamespaceProvider(
                provider.id,
            ));
        }
        let semantics = view.namespace_semantics.ok_or(
            super::SupportCatalogError::MissingNamespaceSemantics(contract.id),
        )?;
        if semantics.kind == NamespaceKind::NonNamespace
            || semantics.execution == NamespaceExecution::ExternalTransformRequired
        {
            return Err(super::SupportCatalogError::InvalidNamespaceSemantics(
                contract.id,
            ));
        }
        register_namespace_collision(contract.id, contract.collision, &mut groups)
            .map_err(|_| super::SupportCatalogError::InvalidNamespaceMountContract(contract.id))?;
    }
    for (&contract, &provider) in role_bound {
        let view = support.get(contract.id).ok_or(
            super::SupportCatalogError::InvalidNamespaceMountContract(contract.id),
        )?;
        let caps = view.capabilities();
        if !caps.parse
            || caps.corpus != contract.corpus_oracle.is_some()
            || contract.input.validate().is_err()
            || !valid_namespace_collision(contract.collision)
            || !contract.oracles().all(valid_cargo_test_oracle)
        {
            return Err(super::SupportCatalogError::InvalidNamespaceMountContract(
                contract.id,
            ));
        }
        if provider.id != contract.id
            || provider.input != contract.input
            || provider.strategy != contract.strategy
            || !provider.mount_matches_input()
            || view.decoder() != Some(provider.owner)
        {
            return Err(super::SupportCatalogError::InvalidNamespaceProvider(
                provider.id,
            ));
        }
        let semantics = view.namespace_semantics.ok_or(
            super::SupportCatalogError::MissingNamespaceSemantics(contract.id),
        )?;
        if semantics.kind == NamespaceKind::NonNamespace
            || semantics.execution == NamespaceExecution::ExternalTransformRequired
        {
            return Err(super::SupportCatalogError::InvalidNamespaceSemantics(
                contract.id,
            ));
        }
        register_namespace_collision(contract.id, contract.collision, &mut groups)
            .map_err(|_| super::SupportCatalogError::InvalidNamespaceMountContract(contract.id))?;
    }
    validate_namespace_collision_groups(groups).map_err(|error| match error {
        NamespaceCompositionError::Contract(id) => {
            super::SupportCatalogError::InvalidNamespaceMountContract(id)
        }
        NamespaceCompositionError::Provider(id) => {
            super::SupportCatalogError::InvalidNamespaceProvider(id)
        }
    })
}

pub(super) fn validate_namespace_composition(
    contracts: impl IntoIterator<Item = NamespaceMountContract>,
    providers: impl IntoIterator<Item = NamespaceProvider>,
    capabilities: &std::collections::HashMap<FormatId, FormatCapabilities>,
    detectable_requirements: &std::collections::HashMap<FormatId, DecoderRequirement>,
    detectable_decoders: &std::collections::HashMap<FormatId, Option<&'static str>>,
    embedded_contexts: &std::collections::HashMap<FormatId, super::ContextRequirement>,
) -> Result<(Vec<NamespaceMountContract>, Vec<NamespaceProvider>), NamespaceCompositionError> {
    use std::collections::{HashMap, HashSet};

    let mut namespace_ids = HashSet::new();
    let mut collision_groups = NamespaceCollisionGroups::new();
    let mut validated_contracts = Vec::new();
    for contract in contracts {
        let Some(caps) = capabilities.get(&contract.id) else {
            return Err(NamespaceCompositionError::Contract(contract.id));
        };
        if !namespace_ids.insert(contract.id)
            || !valid_namespace_contract(
                contract,
                *caps,
                detectable_requirements.get(&contract.id).copied(),
                embedded_contexts.get(&contract.id).copied(),
            )
        {
            return Err(NamespaceCompositionError::Contract(contract.id));
        }
        register_namespace_collision(contract.id, contract.collision, &mut collision_groups)?;
        validated_contracts.push(contract);
    }
    validate_namespace_collision_groups(collision_groups)?;
    validated_contracts.sort_by_key(|contract| contract.id.as_str());

    let contract_inputs = validated_contracts
        .iter()
        .map(|contract| (contract.id, contract))
        .collect::<HashMap<_, _>>();
    let mut provider_ids = HashSet::new();
    let mut validated_providers = Vec::new();
    for provider in providers {
        if !provider_ids.insert(provider.id)
            || contract_inputs.get(&provider.id).is_none_or(|contract| {
                !valid_namespace_provider(
                    provider,
                    **contract,
                    detectable_decoders.get(&provider.id).copied().flatten(),
                )
            })
        {
            return Err(NamespaceCompositionError::Provider(provider.id));
        }
        validated_providers.push(provider);
    }
    if let Some(contract) = validated_contracts
        .iter()
        .find(|contract| !provider_ids.contains(&contract.id))
    {
        return Err(NamespaceCompositionError::Provider(contract.id));
    }
    validated_providers.sort_by_key(|provider| provider.id.as_str());
    Ok((validated_contracts, validated_providers))
}

/// Maximum byte roles in one finite role-bound namespace topology. Three
/// covers the reviewed trio blocker and four proves the mechanism is not
/// trio-specific; eight leaves headroom without inviting unbounded inputs.
pub const MAX_ROLE_BOUND_BYTE_ROLES: usize = 8;
/// Maximum required selector roles in one role-bound topology. Selectors are
/// explicit semantic data, never filename-derived hints.
pub const MAX_ROLE_BOUND_SELECTOR_ROLES: usize = 4;

/// A finite declared set of required single-occurrence byte roles plus
/// required selectors. This is intentionally separate from
/// [`NamespaceMountInput`]: legacy single/pair topologies keep their exact
/// APIs and precedence, while role-bound mounts project their declared roles
/// against an owner [`super::InputSchema`] without pretending a third role
/// does not exist. Owner relationships such as `DistinctBacking` stay in the
/// schema; this topology only declares which roles must occur exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleBoundNamespaceInput {
    pub byte_roles: &'static [&'static str],
    pub selector_roles: &'static [&'static str],
}

impl RoleBoundNamespaceInput {
    pub const fn label(self) -> &'static str {
        "role-bound-sources"
    }

    /// Validate immutable declarations without binding or reading any source.
    /// Byte roles must be one to eight distinct valid names; selector roles
    /// must be zero to four distinct valid names disjoint from the bytes.
    pub fn validate(self) -> formatkit_core::Result<()> {
        fn valid_name(name: &str) -> bool {
            !name.is_empty()
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        }
        if self.byte_roles.is_empty() || self.byte_roles.len() > MAX_ROLE_BOUND_BYTE_ROLES {
            return Err(formatkit_core::Error::Unsupported(format!(
                "role-bound input has {} byte roles, expected 1..={}",
                self.byte_roles.len(),
                MAX_ROLE_BOUND_BYTE_ROLES
            )));
        }
        if self.selector_roles.len() > MAX_ROLE_BOUND_SELECTOR_ROLES {
            return Err(formatkit_core::Error::Unsupported(format!(
                "role-bound input has {} selector roles, expected 0..={}",
                self.selector_roles.len(),
                MAX_ROLE_BOUND_SELECTOR_ROLES
            )));
        }
        for (index, role) in self.byte_roles.iter().enumerate() {
            if !valid_name(role) || self.byte_roles[..index].contains(role) {
                return Err(formatkit_core::Error::Unsupported(format!(
                    "role-bound input has an invalid or duplicate byte role {role:?}"
                )));
            }
        }
        for (index, role) in self.selector_roles.iter().enumerate() {
            if !valid_name(role)
                || self.selector_roles[..index].contains(role)
                || self.byte_roles.contains(role)
            {
                return Err(formatkit_core::Error::Unsupported(format!(
                    "role-bound input has an invalid or duplicate selector role {role:?}"
                )));
            }
        }
        Ok(())
    }
}

/// Work-native role-bound mount: the mounted namespace plus the resident
/// reservation covering its retained bytes. Both live and drop together; the
/// caller keeps the borrowed ledger alive across use. The mount receives
/// already-bound role handles and must not rebind paths, guess filenames, or
/// admit a second ledger.
pub type RoleBoundWorkMounter =
    for<'budget> fn(
        &formatkit_core::SourceBindings,
        &super::BoundInputs,
        &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<WorkMountedNamespace<'budget>>;

/// Executable proof obligations for one role-bound namespace mount. This
/// mirrors [`NamespaceMountContract`] without reusing its fixed-arity input:
/// parser parity, independent layout, budget, stability, dispatch,
/// malformed rejection, CLI integration, collision handling where applicable,
/// and corpus evidence whenever that capability is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleBoundNamespaceContract {
    pub id: FormatId,
    pub input: RoleBoundNamespaceInput,
    pub strategy: NamespaceMountStrategy,
    pub parser_parity_oracle: super::CargoTestOracle,
    pub independent_layout_oracle: super::CargoTestOracle,
    pub budget_oracle: super::CargoTestOracle,
    pub stability_oracle: super::CargoTestOracle,
    pub dispatch_oracle: super::CargoTestOracle,
    pub malformed_oracle: super::CargoTestOracle,
    pub collision: Option<NamespaceCollisionContract>,
    pub cli_oracle: super::CargoTestOracle,
    pub corpus_oracle: Option<super::CargoTestOracle>,
}

impl RoleBoundNamespaceContract {
    pub fn oracles(self) -> impl Iterator<Item = super::CargoTestOracle> {
        [
            self.parser_parity_oracle,
            self.independent_layout_oracle,
            self.budget_oracle,
            self.stability_oracle,
            self.dispatch_oracle,
            self.malformed_oracle,
            self.cli_oracle,
        ]
        .into_iter()
        .chain(self.collision.map(|contract| contract.ambiguity_oracle))
        .chain(self.corpus_oracle)
    }
}

/// Callable work-native half of a [`RoleBoundNamespaceContract`]. There is no
/// legacy `ReadBudget` callback: products mount through
/// [`RoleBoundNamespaceProvider::mount_work`] on their own ledger.
#[derive(Clone, Copy)]
pub struct RoleBoundNamespaceProvider {
    pub id: FormatId,
    pub owner: &'static str,
    pub input: RoleBoundNamespaceInput,
    pub strategy: NamespaceMountStrategy,
    pub mount: RoleBoundWorkMounter,
}

impl fmt::Debug for RoleBoundNamespaceProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleBoundNamespaceProvider")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .field("input", &self.input)
            .field("strategy", &self.strategy)
            .finish_non_exhaustive()
    }
}

impl RoleBoundNamespaceProvider {
    pub fn enforce_strategy(self, maximum: NamespaceMountStrategy) -> formatkit_core::Result<Self> {
        if maximum.permits(self.strategy) {
            Ok(self)
        } else {
            Err(formatkit_core::Error::Unsupported(format!(
                "namespace {} requires {} mounting but product policy permits at most {}",
                self.id,
                self.strategy.label(),
                maximum.label()
            )))
        }
    }

    /// Whether the executable callback shape agrees with the declared source
    /// topology. Role-bound mounts have exactly one work-native shape.
    pub fn mount_matches_input(self) -> bool {
        self.input.validate().is_ok()
    }

    /// Mount already-bound roles on the caller's native work ledger. The
    /// caller binds through the operation's canonical [`super::InputSchema`]
    /// (which enforces `DistinctBacking` and other owner relationships); this
    /// entry point additionally requires exactly the declared byte roles with
    /// exactly one source each, exactly the declared selectors, and no extra
    /// roles, before the owner callback can perform I/O.
    pub fn mount_work<'budget>(
        self,
        sources: &formatkit_core::SourceBindings,
        bound: &super::BoundInputs,
        budget: &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<WorkMountedNamespace<'budget>> {
        self.input.validate()?;
        if bound.byte_len() != self.input.byte_roles.len()
            || bound.selector_len() != self.input.selector_roles.len()
        {
            return Err(formatkit_core::Error::Unsupported(format!(
                "namespace {} role-bound mount has {} byte and {} selector bindings, expected {} and {}",
                self.id,
                bound.byte_len(),
                bound.selector_len(),
                self.input.byte_roles.len(),
                self.input.selector_roles.len()
            )));
        }
        for role in self.input.byte_roles {
            bound.single_source(role).map_err(|_| {
                formatkit_core::Error::Unsupported(format!(
                    "namespace {} role-bound mount is missing byte role {role:?}",
                    self.id
                ))
            })?;
            sources.source(bound.single_source(role).expect("checked above"))?;
        }
        for role in self.input.selector_roles {
            if bound.selector(role).is_none_or(str::is_empty) {
                return Err(formatkit_core::Error::Unsupported(format!(
                    "namespace {} role-bound mount is missing selector {role:?}",
                    self.id
                )));
            }
        }
        (self.mount)(sources, bound, budget)
    }
}
