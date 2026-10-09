use std::fmt::{self, Write as _};

use super::namespace::{validate_namespace_composition, NamespaceCompositionError};
use super::{
    CargoTestOracle, ContextRequirement, CorpusEvidence, DecoderRequirement, FormatCapabilities,
    FormatDescriptor, FormatFamilyId, NamespaceExecution, NamespaceKind, NamespaceMountContract,
    NamespaceMountInput, NamespaceMountStrategy, NamespaceProvider, NamespaceSemantics,
    PairedNamespaceSources, WorkMountedNamespace, WorkRunnerOp, WorkRunnerUser, WriterContract,
};
use crate::{Category, FormatId};

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Support metadata for a semantic format that deliberately has no global
/// content probe. This complements [`FormatDescriptor`]; it must never be fed
/// to content detection with a fabricated weak signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedFormatSupport {
    pub id: FormatId,
    /// `Some(id)` overlays context/family/evidence on a detectable metadata
    /// descriptor with the same identity. `None` is a purely embedded leaf.
    pub detectable_carrier: Option<FormatId>,
    pub family: FormatFamilyId,
    pub decoder: &'static str,
    pub context: ContextRequirement,
    /// A family-local discriminator (magic, object class, or authenticated
    /// carrier role). Equal discriminators require an explicit dialect group.
    pub local_discriminator: &'static str,
    pub dialect_group: Option<&'static str>,
    /// True when the public parser accepts the typed context described above,
    /// rather than an unqualified detached byte slice.
    pub typed_context: bool,
    pub capabilities: FormatCapabilities,
    pub corpus_evidence: Option<CorpusEvidence>,
}

/// A validated view of detectable and context-only format support.
#[derive(Clone)]
pub struct SupportCatalog {
    detectable: Vec<FormatDescriptor>,
    embedded: Vec<EmbeddedFormatSupport>,
    writer_contracts: Vec<WriterContract>,
    namespace_semantics: Vec<NamespaceSemantics>,
    namespace_mount_contracts: Vec<NamespaceMountContract>,
    namespace_providers: Vec<NamespaceProvider>,
}

impl fmt::Debug for SupportCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupportCatalog")
            .field(
                "detectable",
                &self
                    .detectable
                    .iter()
                    .map(|descriptor| descriptor.id)
                    .collect::<Vec<_>>(),
            )
            .field("embedded", &self.embedded)
            .field("writer_contracts", &self.writer_contracts)
            .field("namespace_semantics", &self.namespace_semantics)
            .field("namespace_mount_contracts", &self.namespace_mount_contracts)
            .field("namespace_providers", &self.namespace_providers)
            .finish()
    }
}

/// One normalized support lookup. Detectable metadata and a context overlay
/// may coexist for the same identity; callers no longer need to search two
/// inventories and guess which capabilities apply.
#[derive(Clone, Copy)]
pub struct FormatSupportView<'a> {
    pub id: FormatId,
    pub detectable: Option<&'a FormatDescriptor>,
    pub embedded: Option<&'a EmbeddedFormatSupport>,
    pub writer: Option<&'a WriterContract>,
    pub namespace_semantics: Option<&'a NamespaceSemantics>,
    pub namespace_mount: Option<&'a NamespaceMountContract>,
    pub namespace_provider: Option<&'a NamespaceProvider>,
}

impl FormatSupportView<'_> {
    /// Product-facing category label. Purely embedded identities deliberately
    /// have no fabricated global category or content probe.
    pub fn category_label(self) -> &'static str {
        self.detectable
            .map_or("context-only", |descriptor| descriptor.category.label())
    }

    pub fn capabilities(self) -> FormatCapabilities {
        self.embedded
            .map(|support| support.capabilities)
            .or_else(|| self.detectable.map(|descriptor| descriptor.capabilities))
            .expect("a support view always has detectable or embedded metadata")
    }

    pub fn family(self) -> Option<FormatFamilyId> {
        self.embedded.map(|support| support.family)
    }

    pub fn context(self) -> Option<ContextRequirement> {
        self.embedded.map(|support| support.context)
    }

    pub fn decoder(self) -> Option<&'static str> {
        self.embedded
            .map(|support| support.decoder)
            .or_else(|| self.detectable.and_then(|descriptor| descriptor.decoder))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportCatalogError {
    InvalidFormatId(FormatId),
    DuplicateId(FormatId),
    InvalidFamily(FormatId),
    InvalidContext(FormatId),
    InvalidCapabilities(FormatId),
    MissingCorpusEvidence(FormatId),
    DuplicateLocalDiscriminator { first: FormatId, second: FormatId },
    InvalidWriterContract(FormatId),
    DuplicateNamespaceSemantics(FormatId),
    MissingNamespaceSemantics(FormatId),
    InvalidNamespaceSemantics(FormatId),
    InvalidNamespaceMountContract(FormatId),
    InvalidNamespaceProvider(FormatId),
}

impl fmt::Display for SupportCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormatId(id) => write!(f, "invalid support identity: {id:?}"),
            Self::DuplicateId(id) => write!(f, "duplicate support identity: {id}"),
            Self::InvalidFamily(id) => write!(f, "invalid embedded format family: {id}"),
            Self::InvalidContext(id) => write!(f, "invalid embedded format context: {id}"),
            Self::InvalidCapabilities(id) => {
                write!(f, "invalid embedded format capabilities: {id}")
            }
            Self::MissingCorpusEvidence(id) => {
                write!(f, "missing embedded corpus evidence: {id}")
            }
            Self::DuplicateLocalDiscriminator { first, second } => write!(
                f,
                "undeclared embedded discriminator collision: {first} and {second}"
            ),
            Self::InvalidWriterContract(id) => write!(f, "invalid writer contract: {id}"),
            Self::DuplicateNamespaceSemantics(id) => {
                write!(f, "duplicate namespace semantics: {id}")
            }
            Self::MissingNamespaceSemantics(id) => {
                write!(f, "missing namespace semantics: {id}")
            }
            Self::InvalidNamespaceSemantics(id) => {
                write!(f, "invalid namespace semantics: {id}")
            }
            Self::InvalidNamespaceMountContract(id) => {
                write!(f, "invalid namespace mount contract: {id}")
            }
            Self::InvalidNamespaceProvider(id) => {
                write!(f, "invalid namespace provider: {id}")
            }
        }
    }
}

impl std::error::Error for SupportCatalogError {}

impl SupportCatalog {
    pub fn new(
        detectable: impl IntoIterator<Item = FormatDescriptor>,
        embedded: impl IntoIterator<Item = EmbeddedFormatSupport>,
    ) -> Result<Self, SupportCatalogError> {
        Self::with_contracts(detectable, embedded, [], [], [])
    }

    pub fn with_writer_contracts(
        detectable: impl IntoIterator<Item = FormatDescriptor>,
        embedded: impl IntoIterator<Item = EmbeddedFormatSupport>,
        writer_contracts: impl IntoIterator<Item = WriterContract>,
    ) -> Result<Self, SupportCatalogError> {
        Self::with_contracts(detectable, embedded, writer_contracts, [], [])
    }

    pub fn with_contracts(
        detectable: impl IntoIterator<Item = FormatDescriptor>,
        embedded: impl IntoIterator<Item = EmbeddedFormatSupport>,
        writer_contracts: impl IntoIterator<Item = WriterContract>,
        namespace_mount_contracts: impl IntoIterator<Item = NamespaceMountContract>,
        namespace_providers: impl IntoIterator<Item = NamespaceProvider>,
    ) -> Result<Self, SupportCatalogError> {
        Self::compose(
            detectable,
            embedded,
            writer_contracts,
            [],
            namespace_mount_contracts,
            namespace_providers,
            false,
        )
    }

    /// Compose a product catalog whose archive-class descriptors must all
    /// declare their namespace semantics explicitly. Namespace-capable formats
    /// in other categories (for example disc images) may opt in as well.
    pub fn with_namespace_support(
        detectable: impl IntoIterator<Item = FormatDescriptor>,
        embedded: impl IntoIterator<Item = EmbeddedFormatSupport>,
        writer_contracts: impl IntoIterator<Item = WriterContract>,
        namespace_semantics: impl IntoIterator<Item = NamespaceSemantics>,
        namespace_mount_contracts: impl IntoIterator<Item = NamespaceMountContract>,
        namespace_providers: impl IntoIterator<Item = NamespaceProvider>,
    ) -> Result<Self, SupportCatalogError> {
        Self::compose(
            detectable,
            embedded,
            writer_contracts,
            namespace_semantics,
            namespace_mount_contracts,
            namespace_providers,
            true,
        )
    }

    fn compose(
        detectable: impl IntoIterator<Item = FormatDescriptor>,
        embedded: impl IntoIterator<Item = EmbeddedFormatSupport>,
        writer_contracts: impl IntoIterator<Item = WriterContract>,
        namespace_semantics: impl IntoIterator<Item = NamespaceSemantics>,
        namespace_mount_contracts: impl IntoIterator<Item = NamespaceMountContract>,
        namespace_providers: impl IntoIterator<Item = NamespaceProvider>,
        require_archive_semantics: bool,
    ) -> Result<Self, SupportCatalogError> {
        use std::collections::{HashMap, HashSet};

        let writer_contracts = writer_contracts.into_iter().collect::<Vec<_>>();
        let namespace_semantics = namespace_semantics.into_iter().collect::<Vec<_>>();
        let namespace_mount_contracts = namespace_mount_contracts.into_iter().collect::<Vec<_>>();
        let namespace_providers = namespace_providers.into_iter().collect::<Vec<_>>();
        for id in writer_contracts
            .iter()
            .map(|contract| contract.id)
            .chain(namespace_semantics.iter().map(|declaration| declaration.id))
            .chain(namespace_mount_contracts.iter().map(|contract| contract.id))
            .chain(namespace_providers.iter().map(|provider| provider.id))
        {
            if !id.is_valid() {
                return Err(SupportCatalogError::InvalidFormatId(id));
            }
        }

        let mut identities = HashSet::new();
        let mut detectable_requirements = HashMap::new();
        let mut detectable_decoders = HashMap::new();
        let mut detectable_categories = HashMap::new();
        let mut capabilities = HashMap::new();
        let mut detectable = detectable.into_iter().collect::<Vec<_>>();
        for descriptor in &detectable {
            if !descriptor.id.is_valid() {
                return Err(SupportCatalogError::InvalidFormatId(descriptor.id));
            }
            if !identities.insert(descriptor.id) {
                return Err(SupportCatalogError::DuplicateId(descriptor.id));
            }
            detectable_requirements.insert(descriptor.id, descriptor.requirement);
            detectable_decoders.insert(descriptor.id, descriptor.decoder);
            detectable_categories.insert(descriptor.id, descriptor.category);
            capabilities.insert(descriptor.id, descriptor.capabilities);
        }
        detectable.sort_by_key(|descriptor| descriptor.id.as_str());
        let mut discriminators: HashMap<
            (FormatFamilyId, &'static str),
            (FormatId, Option<&'static str>),
        > = HashMap::new();
        let mut validated = Vec::new();
        for support in embedded {
            if !support.id.is_valid() {
                return Err(SupportCatalogError::InvalidFormatId(support.id));
            }
            if let Some(carrier) = support
                .detectable_carrier
                .filter(|carrier| !carrier.is_valid())
            {
                return Err(SupportCatalogError::InvalidFormatId(carrier));
            }
            if !identities.insert(support.id) {
                if support.detectable_carrier != Some(support.id) {
                    return Err(SupportCatalogError::DuplicateId(support.id));
                }
                let expected = match support.context {
                    ContextRequirement::ExplicitSelection => DecoderRequirement::None,
                    ContextRequirement::PairedData { .. } => DecoderRequirement::PairedData,
                    ContextRequirement::ParentAddressSpace { .. } => {
                        DecoderRequirement::ParentAddressSpace
                    }
                    ContextRequirement::ParentAndSiblings { .. } => {
                        DecoderRequirement::ParentAndSiblings
                    }
                    ContextRequirement::AuthenticatedCarrierMember { .. } => {
                        DecoderRequirement::AuthenticatedCarrierMember
                    }
                };
                if detectable_requirements.get(&support.id) != Some(&expected) {
                    return Err(SupportCatalogError::InvalidContext(support.id));
                }
                if detectable_decoders.get(&support.id).copied().flatten() != Some(support.decoder)
                    || capabilities.get(&support.id) != Some(&support.capabilities)
                {
                    return Err(SupportCatalogError::InvalidCapabilities(support.id));
                }
            } else if support.detectable_carrier.is_some() {
                return Err(SupportCatalogError::InvalidContext(support.id));
            }
            if !support.family.is_valid()
                || support.decoder.is_empty()
                || support.local_discriminator.is_empty()
            {
                return Err(SupportCatalogError::InvalidFamily(support.id));
            }
            if !support.typed_context
                || support
                    .context
                    .family()
                    .is_some_and(|family| family != support.family)
                || matches!(support.context, ContextRequirement::PairedData { role: "" })
            {
                return Err(SupportCatalogError::InvalidContext(support.id));
            }
            let caps = support.capabilities;
            if ((!caps.parse) && (caps.decode || caps.edit || caps.write || caps.round_trip))
                || (caps.round_trip && (!caps.write || !caps.edit))
            {
                return Err(SupportCatalogError::InvalidCapabilities(support.id));
            }
            match (caps.corpus, support.corpus_evidence) {
                (true, Some(evidence))
                    if !evidence.handler.is_empty() && evidence.sample_floor > 0 => {}
                (false, None) => {}
                _ => return Err(SupportCatalogError::MissingCorpusEvidence(support.id)),
            }
            let key = (support.family, support.local_discriminator);
            if let Some(&(other, group)) = discriminators.get(&key) {
                if support.dialect_group.is_none() || support.dialect_group != group {
                    return Err(SupportCatalogError::DuplicateLocalDiscriminator {
                        first: other,
                        second: support.id,
                    });
                }
            } else {
                discriminators.insert(key, (support.id, support.dialect_group));
            }
            validated.push(support);
        }
        validated.sort_by_key(|support| support.id.as_str());
        capabilities.extend(
            validated
                .iter()
                .map(|support| (support.id, support.capabilities)),
        );
        // Purely context-only formats still own typed decoder identities used
        // to validate namespace providers. Their semantic context remains
        // separate from physical mount topology and global detection.
        for support in &validated {
            detectable_decoders
                .entry(support.id)
                .or_insert(Some(support.decoder));
        }
        let embedded_contexts = validated
            .iter()
            .map(|support| (support.id, support.context))
            .collect::<HashMap<_, _>>();
        let mut contract_ids = HashSet::new();
        let mut contracts = Vec::new();
        for contract in writer_contracts {
            let Some(caps) = capabilities.get(&contract.id) else {
                return Err(SupportCatalogError::InvalidWriterContract(contract.id));
            };
            if !contract_ids.insert(contract.id) || !contract.valid_for(*caps) {
                return Err(SupportCatalogError::InvalidWriterContract(contract.id));
            }
            contracts.push(contract);
        }
        contracts.sort_by_key(|contract| contract.id.as_str());
        let mut semantics_ids = HashSet::new();
        let mut semantics = Vec::new();
        for declaration in namespace_semantics {
            if !semantics_ids.insert(declaration.id) {
                return Err(SupportCatalogError::DuplicateNamespaceSemantics(
                    declaration.id,
                ));
            }
            if !capabilities.contains_key(&declaration.id) || !declaration.is_valid() {
                return Err(SupportCatalogError::InvalidNamespaceSemantics(
                    declaration.id,
                ));
            }
            semantics.push(declaration);
        }
        if require_archive_semantics {
            if let Some((&id, _)) = detectable_categories.iter().find(|(id, category)| {
                **category == Category::Archive && !semantics_ids.contains(id)
            }) {
                return Err(SupportCatalogError::MissingNamespaceSemantics(id));
            }
        }
        semantics.sort_by_key(|declaration| declaration.id.as_str());
        let (namespace_contracts, providers) = validate_namespace_composition(
            namespace_mount_contracts,
            namespace_providers,
            &capabilities,
            &detectable_requirements,
            &detectable_decoders,
            &embedded_contexts,
        )
        .map_err(|error| match error {
            NamespaceCompositionError::Contract(id) => {
                SupportCatalogError::InvalidNamespaceMountContract(id)
            }
            NamespaceCompositionError::Provider(id) => {
                SupportCatalogError::InvalidNamespaceProvider(id)
            }
        })?;
        if let Some(contract) = namespace_contracts.iter().find(|contract| {
            semantics
                .iter()
                .find(|declaration| declaration.id == contract.id)
                .is_some_and(|declaration| {
                    declaration.kind == NamespaceKind::NonNamespace
                        || declaration.execution == NamespaceExecution::ExternalTransformRequired
                })
        }) {
            return Err(SupportCatalogError::InvalidNamespaceSemantics(contract.id));
        }
        if require_archive_semantics {
            if let Some(contract) = namespace_contracts
                .iter()
                .find(|contract| !semantics_ids.contains(&contract.id))
            {
                return Err(SupportCatalogError::MissingNamespaceSemantics(contract.id));
            }
        }
        Ok(Self {
            detectable,
            embedded: validated,
            writer_contracts: contracts,
            namespace_semantics: semantics,
            namespace_mount_contracts: namespace_contracts,
            namespace_providers: providers,
        })
    }

    pub fn detectable(&self) -> &[FormatDescriptor] {
        &self.detectable
    }

    pub fn embedded(&self) -> &[EmbeddedFormatSupport] {
        &self.embedded
    }

    pub fn writer_contracts(&self) -> &[WriterContract] {
        &self.writer_contracts
    }

    pub fn namespace_semantics(&self) -> &[NamespaceSemantics] {
        &self.namespace_semantics
    }

    pub fn namespace_semantics_for(&self, id: FormatId) -> Option<&NamespaceSemantics> {
        self.namespace_semantics
            .binary_search_by_key(&id.as_str(), |declaration| declaration.id.as_str())
            .ok()
            .map(|index| &self.namespace_semantics[index])
    }

    pub fn namespace_mount_contracts(&self) -> &[NamespaceMountContract] {
        &self.namespace_mount_contracts
    }

    pub fn namespace_providers(&self) -> &[NamespaceProvider] {
        &self.namespace_providers
    }

    pub fn namespace_provider(&self, id: FormatId) -> Option<&NamespaceProvider> {
        self.namespace_providers
            .binary_search_by_key(&id.as_str(), |provider| provider.id.as_str())
            .ok()
            .map(|index| &self.namespace_providers[index])
    }

    pub fn mount_namespace_single(
        &self,
        id: FormatId,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        maximum_strategy: NamespaceMountStrategy,
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        self.namespace_provider(id)
            .copied()
            .ok_or_else(|| {
                formatkit_core::Error::Unsupported(format!(
                    "no composed single-source namespace provider for {id}"
                ))
            })?
            .enforce_strategy(maximum_strategy)?
            .mount_single(source, budget)
    }

    pub fn mount_namespace_single_work_runner(
        &self,
        id: FormatId,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        maximum_strategy: NamespaceMountStrategy,
        budget: &mut formatkit_core::WorkBudget,
        op: WorkRunnerOp,
        user: &mut WorkRunnerUser<'_>,
    ) -> formatkit_core::Result<()> {
        self.namespace_provider(id)
            .copied()
            .ok_or_else(|| {
                formatkit_core::Error::Unsupported(format!("no namespace provider for format {id}"))
            })?
            .enforce_strategy(maximum_strategy)?
            .mount_work_runner(source, budget, op, user)
    }

    /// Mount a work-native single-source namespace on the caller's own ledger.
    /// Strategy enforcement matches [`Self::mount_namespace_single`]; the
    /// provider must be a work-single shape.
    pub fn mount_namespace_single_work<'budget>(
        &self,
        id: FormatId,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        maximum_strategy: NamespaceMountStrategy,
        budget: &'budget mut formatkit_core::WorkBudget,
    ) -> formatkit_core::Result<WorkMountedNamespace<'budget>> {
        self.namespace_provider(id)
            .copied()
            .ok_or_else(|| {
                formatkit_core::Error::Unsupported(format!(
                    "no composed single-source namespace provider for {id}"
                ))
            })?
            .enforce_strategy(maximum_strategy)?
            .mount_single_work(source, budget)
    }

    pub fn mount_namespace_selected_single(
        &self,
        id: FormatId,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        selector: &str,
        maximum_strategy: NamespaceMountStrategy,
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        self.namespace_provider(id)
            .copied()
            .ok_or_else(|| {
                formatkit_core::Error::Unsupported(format!(
                    "no composed selected single-source namespace provider for {id}"
                ))
            })?
            .enforce_strategy(maximum_strategy)?
            .mount_selected_single(source, selector, budget)
    }

    pub fn mount_namespace_pair(
        &self,
        id: FormatId,
        sources: PairedNamespaceSources,
        maximum_strategy: NamespaceMountStrategy,
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
        self.namespace_provider(id)
            .copied()
            .ok_or_else(|| {
                formatkit_core::Error::Unsupported(format!(
                    "no composed paired namespace provider for {id}"
                ))
            })?
            .enforce_strategy(maximum_strategy)?
            .mount_pair(sources, budget)
    }

    pub fn identify_and_mount_namespace_source(
        &self,
        source: std::sync::Arc<dyn formatkit_core::RangeSource>,
        prefix: &[u8],
        budget: &mut formatkit_core::ReadBudget,
    ) -> formatkit_core::Result<Option<super::IdentifiedNamespace>> {
        super::identify_and_mount_namespace_source(
            self.namespace_providers.iter().copied(),
            source,
            prefix,
            budget,
        )
    }

    /// Every distinct executable oracle referenced by the composed contracts,
    /// in deterministic contract/operation order.
    pub fn writer_oracles(&self) -> Vec<CargoTestOracle> {
        let mut seen = std::collections::HashSet::new();
        self.writer_contracts
            .iter()
            .flat_map(|contract| contract.oracles())
            .filter(|oracle| seen.insert(*oracle))
            .collect()
    }

    pub fn namespace_mount_oracles(&self) -> Vec<CargoTestOracle> {
        let mut seen = std::collections::HashSet::new();
        self.namespace_mount_contracts
            .iter()
            .flat_map(|contract| contract.oracles())
            .filter(|oracle| seen.insert(*oracle))
            .collect()
    }

    /// Corpus-backed namespace proofs. These selectors are inventoried by the
    /// ordinary product audit, but must execute only under the serialized,
    /// required-corpus runner.
    pub fn namespace_corpus_oracles(&self) -> Vec<CargoTestOracle> {
        let mut seen = std::collections::HashSet::new();
        self.namespace_mount_contracts
            .iter()
            .filter_map(|contract| contract.corpus_oracle)
            .filter(|oracle| seen.insert(*oracle))
            .collect()
    }

    /// Self-contained proof selectors which are safe to execute without an
    /// external corpus. Corpus selectors remain part of [`Self::contract_oracles`]
    /// so their package, target, and exact name are still validated.
    pub fn self_contained_contract_oracles(&self) -> Vec<CargoTestOracle> {
        let corpus = self
            .namespace_corpus_oracles()
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        self.contract_oracles()
            .into_iter()
            .filter(|oracle| !corpus.contains(oracle))
            .collect()
    }

    /// Every distinct proof oracle named by either operation or namespace
    /// contracts in deterministic catalog order.
    pub fn contract_oracles(&self) -> Vec<CargoTestOracle> {
        let mut seen = std::collections::HashSet::new();
        self.writer_contracts
            .iter()
            .flat_map(|contract| contract.oracles())
            .chain(
                self.namespace_mount_contracts
                    .iter()
                    .flat_map(|contract| contract.oracles()),
            )
            .filter(|oracle| seen.insert(*oracle))
            .collect()
    }

    pub fn get(&self, id: FormatId) -> Option<FormatSupportView<'_>> {
        let detectable = self
            .detectable
            .binary_search_by_key(&id.as_str(), |descriptor| descriptor.id.as_str())
            .ok()
            .map(|index| &self.detectable[index]);
        let embedded = self
            .embedded
            .binary_search_by_key(&id.as_str(), |support| support.id.as_str())
            .ok()
            .map(|index| &self.embedded[index]);
        if detectable.is_none() && embedded.is_none() {
            return None;
        }
        let writer = self
            .writer_contracts
            .binary_search_by_key(&id.as_str(), |contract| contract.id.as_str())
            .ok()
            .map(|index| &self.writer_contracts[index]);
        let namespace_semantics = self.namespace_semantics_for(id);
        let namespace_mount = self
            .namespace_mount_contracts
            .binary_search_by_key(&id.as_str(), |contract| contract.id.as_str())
            .ok()
            .map(|index| &self.namespace_mount_contracts[index]);
        let namespace_provider = self.namespace_provider(id);
        Some(FormatSupportView {
            id,
            detectable,
            embedded,
            writer,
            namespace_semantics,
            namespace_mount,
            namespace_provider,
        })
    }

    pub fn capability_markdown(&self) -> String {
        let mut out = String::from(
            "| Format | Detection | Family | Context | Decoder | Namespace mount | Reproduce | Edit modes | Edit scope | Edit preconditions | Edit length | Edit relocation | Author | Parse | Decode | Edit | Write | Round-trip | Corpus | Bindings | Confidence |\n\
             |---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|\n",
        );
        let mut ids = self
            .detectable
            .iter()
            .map(|descriptor| descriptor.id)
            .chain(self.embedded.iter().map(|support| support.id))
            .collect::<Vec<_>>();
        ids.sort_by_key(|id| id.as_str());
        ids.dedup();
        for id in ids {
            let support = self
                .get(id)
                .expect("catalog identity came from one support input");
            let capabilities = support.capabilities();
            let detection = match (support.detectable, support.embedded) {
                (Some(_), Some(_)) => "global+context",
                (Some(_), None) => "global",
                (None, Some(_)) => "context-only",
                (None, None) => unreachable!("support view has at least one input"),
            };
            let family = support.family().map_or("—", FormatFamilyId::as_str);
            let context = support.context().map_or_else(
                || {
                    support
                        .detectable
                        .map_or("—", |descriptor| descriptor.requirement.label())
                },
                ContextRequirement::label,
            );
            let namespace_mount = support.namespace_mount.map_or_else(
                || "—".to_owned(),
                |contract| match contract.input {
                    NamespaceMountInput::SingleSource { role } => format!(
                        "verified@single-source({role});{}",
                        contract.strategy.label()
                    ),
                    NamespaceMountInput::SelectedSingleSource { role, selector_role } => format!(
                        "verified@selected-single-source({role};{selector_role});{}",
                        contract.strategy.label()
                    ),
                    NamespaceMountInput::PairedSources {
                        directory_role,
                        content_role,
                    } => format!(
                        "verified@paired-sources({directory_role},{content_role});{}",
                        contract.strategy.label()
                    ),
                    NamespaceMountInput::SelectedPairedSources {
                        directory_role,
                        content_role,
                        selector_role,
                    } => format!(
                        "verified@selected-paired-sources({directory_role},{content_role};{selector_role});{}",
                        contract.strategy.label()
                    ),
                    NamespaceMountInput::SingleOrSelectedPairedSources {
                        single_role,
                        directory_role,
                        content_role,
                        selector_role,
                    } => format!(
                        "verified@single-or-selected-paired-sources({single_role}|{directory_role},{content_role};{selector_role});{}",
                        contract.strategy.label()
                    ),
                },
            );
            let (
                reproduce,
                edit_modes,
                edit_scopes,
                edit_preconditions,
                edit_lengths,
                edit_relocation,
                author,
            ) = support.writer.map_or_else(
                || {
                    let writer = capabilities.edit || capabilities.write;
                    let edit = capabilities.edit;
                    (
                        if writer { "unclassified" } else { "—" }.to_owned(),
                        if edit { "unclassified" } else { "—" }.to_owned(),
                        if edit { "unclassified" } else { "—" }.to_owned(),
                        if edit { "unclassified" } else { "—" }.to_owned(),
                        if edit { "unclassified" } else { "—" }.to_owned(),
                        if edit { "unclassified" } else { "—" }.to_owned(),
                        if capabilities.write {
                            "unclassified"
                        } else {
                            "—"
                        }
                        .to_owned(),
                    )
                },
                |contract| {
                    let join = |values: Vec<&str>| {
                        if values.is_empty() {
                            "—".to_owned()
                        } else {
                            values.join("+")
                        }
                    };
                    (
                        contract.reproduction.map_or_else(
                            || "—".to_owned(),
                            |operation| format!("verified@{}", operation.scope.label()),
                        ),
                        join(
                            contract
                                .edits
                                .iter()
                                .map(|edit| edit.mode.label())
                                .collect(),
                        ),
                        join(
                            contract
                                .edits
                                .iter()
                                .map(|edit| edit.scope.label())
                                .collect(),
                        ),
                        join(
                            contract
                                .edits
                                .iter()
                                .map(|edit| edit.precondition.label())
                                .collect(),
                        ),
                        join(
                            contract
                                .edits
                                .iter()
                                .map(|edit| edit.output_length.label())
                                .collect(),
                        ),
                        join(
                            contract
                                .edits
                                .iter()
                                .map(|edit| edit.relocation.label())
                                .collect(),
                        ),
                        contract.authoring.map_or_else(
                            || "—".to_owned(),
                            |operation| format!("verified@{}", operation.output_scope.label()),
                        ),
                    )
                },
            );
            let _ =
                writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                support.id,
                detection,
                family,
                context,
                support.decoder().unwrap_or("—"),
                namespace_mount,
                reproduce,
                edit_modes,
                edit_scopes,
                edit_preconditions,
                edit_lengths,
                edit_relocation,
                author,
                yes_no(capabilities.parse),
                yes_no(capabilities.decode),
                yes_no(capabilities.edit),
                yes_no(capabilities.write),
                yes_no(capabilities.round_trip),
                yes_no(capabilities.corpus),
                yes_no(capabilities.bindings),
                capabilities.confidence.label(),
            );
        }
        out
    }
}
