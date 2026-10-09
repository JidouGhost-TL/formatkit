use super::super::*;
use crate::{Category, FormatId};

pub(super) fn rejecting_source_mounter(
    _source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    _budget: &mut formatkit_core::ReadBudget,
) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
    Err(formatkit_core::Error::Unsupported("test provider".into()))
}

pub(super) fn rejecting_source_probe(
    _source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    _prefix: &[u8],
    _budget: &mut formatkit_core::ReadBudget,
) -> formatkit_core::Result<Option<Box<dyn formatkit_core::IndexedNamespace>>> {
    Ok(None)
}

pub(super) fn rejecting_pair_mounter(
    _sources: PairedNamespaceSources,
    _budget: &mut formatkit_core::ReadBudget,
) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
    Err(formatkit_core::Error::Unsupported("test provider".into()))
}

pub(super) fn rejecting_selected_single_mounter(
    _source: std::sync::Arc<dyn formatkit_core::RangeSource>,
    _selector: &str,
    _budget: &mut formatkit_core::ReadBudget,
) -> formatkit_core::Result<Box<dyn formatkit_core::IndexedNamespace>> {
    Err(formatkit_core::Error::Unsupported("test provider".into()))
}

pub(super) fn namespace_provider(id: FormatId, input: NamespaceMountInput) -> NamespaceProvider {
    let mount = match input {
        NamespaceMountInput::SingleSource { .. } => {
            NamespaceProviderMount::Single(rejecting_source_mounter)
        }
        NamespaceMountInput::SelectedSingleSource { .. } => {
            NamespaceProviderMount::SelectedSingle(rejecting_selected_single_mounter)
        }
        NamespaceMountInput::PairedSources { .. } => {
            NamespaceProviderMount::Paired(rejecting_pair_mounter)
        }
        NamespaceMountInput::SelectedPairedSources { .. } => {
            NamespaceProviderMount::Paired(rejecting_pair_mounter)
        }
        NamespaceMountInput::SingleOrSelectedPairedSources { .. } => {
            NamespaceProviderMount::SingleOrPaired {
                single: rejecting_source_mounter,
                paired: rejecting_pair_mounter,
            }
        }
    };
    NamespaceProvider {
        id,
        owner: "test",
        input,
        strategy: NamespaceMountStrategy::MetadataOnly,
        mount,
        source_probe: None,
        work_source_probe: None,
        early_probe_prefix: None,
    }
}

pub(super) fn starts_with_ten(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x10)
}

pub(super) const MAGIC: &[Probe] = &[Probe::Magic {
    offset: 0,
    bytes: b"TEST",
}];
pub(super) const STRUCTURAL: &[Probe] = &[Probe::Structural {
    name: "leading-10",
    check: starts_with_ten,
}];

pub(super) fn descriptor(
    id: FormatId,
    precedence: u16,
    probes: &'static [Probe],
    hints: &'static [&'static str],
) -> FormatDescriptor {
    FormatDescriptor {
        id,
        category: Category::Unknown,
        decoder: None,
        precedence,
        probes,
        extension_hints: hints,
        requirement: DecoderRequirement::None,
        ambiguity_group: None,
        capabilities: FormatCapabilities {
            parse: false,
            decode: false,
            edit: false,
            write: false,
            round_trip: false,
            corpus: false,
            bindings: false,
            confidence: Confidence::Structural,
        },
    }
}

pub(super) fn embedded(id: FormatId) -> EmbeddedFormatSupport {
    EmbeddedFormatSupport {
        id,
        detectable_carrier: None,
        family: FormatFamilyId::new("synthetic-family-0"),
        decoder: "image-owner",
        context: ContextRequirement::AuthenticatedCarrierMember {
            family: FormatFamilyId::new("synthetic-family-0"),
        },
        local_discriminator: "image-body",
        dialect_group: None,
        typed_context: true,
        capabilities: FormatCapabilities {
            parse: true,
            decode: true,
            edit: false,
            write: false,
            round_trip: false,
            corpus: false,
            bindings: false,
            confidence: Confidence::CorpusBacked,
        },
        corpus_evidence: None,
    }
}
