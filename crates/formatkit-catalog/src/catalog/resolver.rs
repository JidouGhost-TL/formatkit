use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::path::Path;

use super::{Confidence, DecoderRequirement, FormatDescriptor, Probe};
use crate::{FormatId, Id, Method};

impl Probe {
    fn match_evidence(self, context: DetectionContext<'_>) -> Option<Evidence> {
        match self {
            Probe::Magic { offset, bytes } => {
                let end = offset.checked_add(bytes.len())?;
                (context.bytes.get(offset..end) == Some(bytes)).then_some(Evidence::Magic {
                    offset,
                    length: bytes.len(),
                })
            }
            Probe::Structural { name, check } => {
                check(context.bytes).then_some(Evidence::Structural { name })
            }
            Probe::ContextualStructural {
                name,
                extension,
                parent_suffix,
                check,
            } => (context
                .extension
                .is_some_and(|actual| actual.eq_ignore_ascii_case(extension))
                && context.path.and_then(Path::parent).is_some_and(|parent| {
                    let mut components = parent.components().rev();
                    parent_suffix.rsplit('/').all(|expected| {
                        components
                            .next()
                            .and_then(|component| component.as_os_str().to_str())
                            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                    })
                })
                && check(context.bytes))
            .then_some(Evidence::Structural { name }),
        }
    }
}

/// Optional context which may disambiguate content-matched candidates or
/// admit an explicitly contextual structural probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetectionContext<'a> {
    pub bytes: &'a [u8],
    pub extension: Option<&'a str>,
    pub path: Option<&'a Path>,
    pub has_paired_data: bool,
    pub has_parent_address_space: bool,
    pub has_parent_siblings: bool,
    pub authenticated_carrier_member: bool,
}

impl<'a> DetectionContext<'a> {
    pub const fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            extension: None,
            path: None,
            has_paired_data: false,
            has_parent_address_space: false,
            has_parent_siblings: false,
            authenticated_carrier_member: false,
        }
    }

    pub fn with_extension(mut self, extension: &'a str) -> Self {
        self.extension = Some(extension.trim_start_matches('.'));
        self
    }

    /// Attach a path and derive its extension for role-scoped probes.
    pub fn with_path(mut self, path: &'a Path) -> Self {
        self.path = Some(path);
        self.extension = path.extension().and_then(|extension| extension.to_str());
        self
    }

    pub const fn with_paired_data(mut self, present: bool) -> Self {
        self.has_paired_data = present;
        self
    }

    pub const fn with_parent_address_space(mut self, present: bool) -> Self {
        self.has_parent_address_space = present;
        self
    }

    pub const fn with_parent_siblings(mut self, present: bool) -> Self {
        self.has_parent_siblings = present;
        self
    }

    pub const fn with_authenticated_carrier_member(mut self, present: bool) -> Self {
        self.authenticated_carrier_member = present;
        self
    }
}

/// Why a descriptor matched the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    Magic { offset: usize, length: usize },
    Structural { name: &'static str },
}

impl Evidence {
    pub const fn method(self) -> Method {
        match self {
            Evidence::Magic { .. } => Method::Magic,
            Evidence::Structural { .. } => Method::Structural,
        }
    }

    fn specificity(self) -> usize {
        match self {
            Evidence::Magic { length, .. } => length,
            Evidence::Structural { .. } => 0,
        }
    }
}

/// One content-matched descriptor.
#[derive(Clone, Copy)]
pub struct Candidate<'a> {
    pub descriptor: &'a FormatDescriptor,
    pub evidence: Evidence,
    pub extension_hint: bool,
    decoder_ready: bool,
}

impl Candidate<'_> {
    /// Whether all non-content inputs needed by the decoder are available.
    pub const fn decoder_ready(self) -> bool {
        self.decoder_ready
    }
}

/// The deterministic result of resolving a composed catalog.
pub struct Resolution<'a> {
    /// The selected candidate. `None` means unknown or ambiguous.
    pub selected: Option<Candidate<'a>>,
    /// Highest-precedence contenders. Empty means nothing matched.
    pub contenders: Vec<Candidate<'a>>,
}

impl Resolution<'_> {
    pub fn is_unknown(&self) -> bool {
        self.contenders.is_empty()
    }

    pub fn is_ambiguous(&self) -> bool {
        self.selected.is_none() && !self.contenders.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogError {
    InvalidFormatId(FormatId),
    DuplicateId(FormatId),
    NoProbes(FormatId),
    ZeroPrecedence(FormatId),
    InvalidExtensionHint(FormatId),
    InvalidAmbiguityGroup(FormatId),
    MissingAmbiguityGroup(FormatId),
    InvalidCapabilities(FormatId),
    UndeclaredProbeConflict {
        first: FormatId,
        second: FormatId,
    },
    MissingDecoder {
        format: FormatId,
        decoder: &'static str,
    },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogError::InvalidFormatId(id) => write!(f, "invalid format identity: {id:?}"),
            CatalogError::DuplicateId(id) => write!(f, "duplicate format descriptor: {id}"),
            CatalogError::NoProbes(id) => write!(f, "format descriptor has no probes: {id}"),
            CatalogError::ZeroPrecedence(id) => {
                write!(f, "format descriptor has zero precedence: {id}")
            }
            CatalogError::InvalidExtensionHint(id) => {
                write!(f, "format descriptor has an invalid extension hint: {id}")
            }
            CatalogError::InvalidAmbiguityGroup(id) => {
                write!(f, "format descriptor has an invalid ambiguity group: {id}")
            }
            CatalogError::MissingAmbiguityGroup(id) => {
                write!(
                    f,
                    "ambiguous format descriptor has no ambiguity group: {id}"
                )
            }
            CatalogError::InvalidCapabilities(id) => {
                write!(f, "format descriptor has inconsistent capabilities: {id}")
            }
            CatalogError::UndeclaredProbeConflict { first, second } => {
                write!(
                    f,
                    "equal-ranked format descriptors share a probe without a common ambiguity group: {first}, {second}"
                )
            }
            CatalogError::MissingDecoder { format, decoder } => {
                write!(f, "format {format} names unavailable decoder {decoder}")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

/// A validated, explicitly composed set of format descriptors.
pub struct FormatCatalog {
    descriptors: Vec<FormatDescriptor>,
    diagnostics: Vec<CatalogDiagnostic>,
}

/// A non-fatal property of a valid catalog composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogDiagnostic {
    SharedExtension {
        extension: &'static str,
        formats: Vec<FormatId>,
    },
}

/// Composes descriptor families and validates product decoder availability.
#[derive(Default)]
pub struct FormatCatalogBuilder {
    descriptors: Vec<FormatDescriptor>,
    available_decoders: Option<Vec<&'static str>>,
}

impl FormatCatalogBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_descriptor(mut self, descriptor: FormatDescriptor) -> Self {
        self.descriptors.push(descriptor);
        self
    }

    pub fn add_family(mut self, descriptors: impl IntoIterator<Item = FormatDescriptor>) -> Self {
        self.descriptors.extend(descriptors);
        self
    }

    pub fn available_decoders(mut self, decoders: impl IntoIterator<Item = &'static str>) -> Self {
        self.available_decoders = Some(decoders.into_iter().collect());
        self
    }

    pub fn build(self) -> Result<FormatCatalog, CatalogError> {
        FormatCatalog::build(self.descriptors, self.available_decoders.as_deref())
    }
}

impl FormatCatalog {
    pub fn builder() -> FormatCatalogBuilder {
        FormatCatalogBuilder::new()
    }

    pub fn new(
        descriptors: impl IntoIterator<Item = FormatDescriptor>,
    ) -> Result<Self, CatalogError> {
        Self::build(descriptors.into_iter().collect(), None)
    }

    fn build(
        mut descriptors: Vec<FormatDescriptor>,
        available_decoders: Option<&[&str]>,
    ) -> Result<Self, CatalogError> {
        let mut conflict_index = ProbeConflictIndex::default();
        let mut identities = HashSet::with_capacity(descriptors.len());
        for (index, descriptor) in descriptors.iter().enumerate() {
            if !descriptor.id.is_valid() {
                return Err(CatalogError::InvalidFormatId(descriptor.id));
            }
            if descriptor.probes.is_empty() {
                return Err(CatalogError::NoProbes(descriptor.id));
            }
            if descriptor.precedence == 0 {
                return Err(CatalogError::ZeroPrecedence(descriptor.id));
            }
            if descriptor.extension_hints.iter().any(|hint| {
                hint.is_empty()
                    || hint.starts_with('.')
                    || hint.bytes().any(|byte| byte.is_ascii_uppercase())
            }) {
                return Err(CatalogError::InvalidExtensionHint(descriptor.id));
            }
            if descriptor.ambiguity_group.is_some_and(|group| {
                group.is_empty()
                    || group.starts_with('-')
                    || group.ends_with('-')
                    || group.bytes().any(|byte| {
                        !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                    })
            }) {
                return Err(CatalogError::InvalidAmbiguityGroup(descriptor.id));
            }
            if descriptor.capabilities.confidence == Confidence::Ambiguous
                && descriptor.ambiguity_group.is_none()
            {
                return Err(CatalogError::MissingAmbiguityGroup(descriptor.id));
            }
            // Every operation below consumes the parsed structure.  Reject
            // impossible capability rows here, where all product catalogs pass,
            // instead of relying on each descriptor author to remember the
            // implication chain.  `edit` and `write` remain independent: an
            // in-place editor need not be a general authoring implementation.
            let capabilities = descriptor.capabilities;
            if ((!capabilities.parse)
                && (capabilities.decode
                    || capabilities.edit
                    || capabilities.write
                    || capabilities.round_trip))
                || (capabilities.round_trip && (!capabilities.write || !capabilities.edit))
            {
                return Err(CatalogError::InvalidCapabilities(descriptor.id));
            }
            if !identities.insert(descriptor.id) {
                return Err(CatalogError::DuplicateId(descriptor.id));
            }
            if let Some(first) = conflict_index.first_conflict(descriptor, &descriptors[..index]) {
                return Err(CatalogError::UndeclaredProbeConflict {
                    first,
                    second: descriptor.id,
                });
            }
            if let (Some(decoder), Some(available)) = (descriptor.decoder, available_decoders) {
                if !available.contains(&decoder) {
                    return Err(CatalogError::MissingDecoder {
                        format: descriptor.id,
                        decoder,
                    });
                }
            }
        }

        descriptors.sort_by_key(|descriptor| descriptor.id.as_str());
        let diagnostics = shared_extension_diagnostics(&descriptors);
        Ok(Self {
            descriptors,
            diagnostics,
        })
    }

    pub fn descriptors(&self) -> &[FormatDescriptor] {
        &self.descriptors
    }

    pub fn diagnostics(&self) -> &[CatalogDiagnostic] {
        &self.diagnostics
    }

    /// Generate a deterministic Markdown capability matrix directly from the
    /// composed descriptors, avoiding a second handwritten inventory.
    pub fn capability_markdown(&self) -> String {
        self.capability_markdown_with_decoder_display(|_, decoder| decoder)
    }

    /// Render the capability matrix with a caller-selected decoder-cell label.
    ///
    /// The callback affects presentation only. Canonical descriptors, decoder
    /// validation, detection and contextual readiness remain unchanged. Display
    /// labels must not be used as registration or operation-routing authority.
    pub fn capability_markdown_with_decoder_display(
        &self,
        mut display_decoder: impl FnMut(FormatId, Option<&'static str>) -> Option<&'static str>,
    ) -> String {
        let mut descriptors: Vec<_> = self.descriptors.iter().collect();
        descriptors.sort_by_key(|descriptor| descriptor.id.as_str());
        let mut output = String::from(
            "| Format | Category | Decoder | Parse | Decode | Edit | Write | Round-trip | Corpus | Bindings | Confidence | Requirement |\n\
             |---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|\n",
        );
        for descriptor in descriptors {
            let capability = descriptor.capabilities;
            writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                descriptor.id,
                descriptor.category.label(),
                display_decoder(descriptor.id, descriptor.decoder).unwrap_or("—"),
                yes_no(capability.parse),
                yes_no(capability.decode),
                yes_no(capability.edit),
                yes_no(capability.write),
                yes_no(capability.round_trip),
                yes_no(capability.corpus),
                yes_no(capability.bindings),
                capability.confidence.label(),
                descriptor.requirement.label(),
            )
            .expect("writing to String cannot fail");
        }
        output
    }

    /// Ensure every descriptor which names a decoder can be serviced by the
    /// composing product. Recognized-but-unsupported descriptors use `None`.
    pub fn validate_decoders(&self, available: &[&str]) -> Result<(), CatalogError> {
        for descriptor in &self.descriptors {
            if let Some(decoder) = descriptor.decoder {
                if !available.contains(&decoder) {
                    return Err(CatalogError::MissingDecoder {
                        format: descriptor.id,
                        decoder,
                    });
                }
            }
        }
        Ok(())
    }

    /// Resolve only candidates whose probes match. For content-only probes, an
    /// extension hint can break an equal-ranked tie but cannot create a match.
    /// A contextual probe separately requires its declared extension, parent
    /// role, and structural bytes; no single hint admits it by itself.
    pub fn resolve<'a>(&'a self, context: DetectionContext<'_>) -> Resolution<'a> {
        let mut matches = Vec::new();
        for descriptor in &self.descriptors {
            let evidence = descriptor
                .probes
                .iter()
                .filter_map(|probe| probe.match_evidence(context))
                .max_by_key(|evidence| {
                    (evidence.method() == Method::Magic, evidence.specificity())
                });
            let Some(evidence) = evidence else {
                continue;
            };
            let extension_hint = context.extension.is_some_and(|extension| {
                descriptor
                    .extension_hints
                    .iter()
                    .any(|hint| extension.eq_ignore_ascii_case(hint))
            });
            matches.push(Candidate {
                descriptor,
                evidence,
                extension_hint,
                decoder_ready: descriptor.decoder.is_some()
                    && match descriptor.requirement {
                        DecoderRequirement::None => true,
                        DecoderRequirement::PairedData => context.has_paired_data,
                        DecoderRequirement::ParentAddressSpace => context.has_parent_address_space,
                        DecoderRequirement::ParentAndSiblings => {
                            context.has_parent_address_space && context.has_parent_siblings
                        }
                        DecoderRequirement::AuthenticatedCarrierMember => {
                            context.authenticated_carrier_member
                        }
                    },
            });
        }

        let Some(highest) = matches
            .iter()
            .map(|candidate| candidate.descriptor.precedence)
            .max()
        else {
            return Resolution {
                selected: None,
                contenders: Vec::new(),
            };
        };
        matches.retain(|candidate| candidate.descriptor.precedence == highest);

        let selected = if matches.len() == 1 {
            Some(matches[0])
        } else {
            let mut hinted = matches
                .iter()
                .copied()
                .filter(|candidate| candidate.extension_hint);
            match (hinted.next(), hinted.next()) {
                (Some(candidate), None) => Some(candidate),
                _ => None,
            }
        };
        Resolution {
            selected,
            contenders: matches,
        }
    }

    /// Identify content through this catalog, returning `None` for unknown or
    /// ambiguous input.
    pub fn identify(&self, context: DetectionContext<'_>) -> Option<Id> {
        let candidate = self.resolve(context).selected?;
        Some(Id {
            category: candidate.descriptor.category,
            format: candidate.descriptor.id.as_str(),
            method: candidate.evidence.method(),
            opener: candidate
                .decoder_ready
                .then_some(candidate.descriptor.decoder)
                .flatten(),
        })
    }
}

#[derive(Default)]
struct ProbeConflictIndex {
    by_precedence: HashMap<u16, ProbeConflictGroup>,
}

enum ProbeConflictGroup {
    /// The common format-catalog shape: one exact magic probe at the same
    /// offset and width. Equal spans overlap iff their complete bytes match, so
    /// validation is linear-after-hashing instead of a prior-prefix scan.
    SimpleMagic {
        offset: usize,
        length: usize,
        signatures: HashMap<&'static [u8], (FormatId, Option<&'static str>)>,
    },
    /// Mixed probe shapes retain the established pairwise oracle. Product
    /// catalogs are small here; this branch preserves exact overlap semantics
    /// and first-prior error precedence without weakening structural probes.
    Mixed,
}

impl ProbeConflictIndex {
    fn first_conflict(
        &mut self,
        descriptor: &FormatDescriptor,
        prior: &[FormatDescriptor],
    ) -> Option<FormatId> {
        let simple_magic = match descriptor.probes {
            [Probe::Magic { offset, bytes }] => Some((*offset, *bytes)),
            _ => None,
        };
        match self.by_precedence.entry(descriptor.precedence) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(match simple_magic {
                    Some((offset, bytes)) => {
                        let mut signatures = HashMap::new();
                        signatures.insert(bytes, (descriptor.id, descriptor.ambiguity_group));
                        ProbeConflictGroup::SimpleMagic {
                            offset,
                            length: bytes.len(),
                            signatures,
                        }
                    }
                    None => ProbeConflictGroup::Mixed,
                });
                None
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                ProbeConflictGroup::SimpleMagic {
                    offset,
                    length,
                    signatures,
                } if simple_magic.is_some_and(|(candidate_offset, bytes)| {
                    candidate_offset == *offset && bytes.len() == *length
                }) =>
                {
                    let (_, bytes) = simple_magic.expect("simple magic checked above");
                    if let Some((first, group)) = signatures.get(bytes).copied() {
                        if group.is_none() || group != descriptor.ambiguity_group {
                            return Some(first);
                        }
                    } else {
                        signatures.insert(bytes, (descriptor.id, descriptor.ambiguity_group));
                    }
                    None
                }
                group => {
                    *group = ProbeConflictGroup::Mixed;
                    prior.iter().find_map(|candidate| {
                        (candidate.precedence == descriptor.precedence
                            && probes_overlap(candidate.probes, descriptor.probes)
                            && (candidate.ambiguity_group.is_none()
                                || candidate.ambiguity_group != descriptor.ambiguity_group))
                            .then_some(candidate.id)
                    })
                }
            },
        }
    }
}

fn probes_overlap(left: &[Probe], right: &[Probe]) -> bool {
    left.iter().any(|left_probe| {
        right
            .iter()
            .any(|right_probe| match (*left_probe, *right_probe) {
                (
                    Probe::Magic {
                        offset: left_offset,
                        bytes: left_bytes,
                    },
                    Probe::Magic {
                        offset: right_offset,
                        bytes: right_bytes,
                    },
                ) => {
                    let left_end = left_offset + left_bytes.len();
                    let right_end = right_offset + right_bytes.len();
                    let overlap_start = left_offset.max(right_offset);
                    let overlap_end = left_end.min(right_end);
                    if overlap_start >= overlap_end {
                        return false;
                    }
                    let left_slice =
                        &left_bytes[overlap_start - left_offset..overlap_end - left_offset];
                    let right_slice =
                        &right_bytes[overlap_start - right_offset..overlap_end - right_offset];
                    left_slice == right_slice
                }
                (
                    Probe::Structural {
                        name: left_name, ..
                    },
                    Probe::Structural {
                        name: right_name, ..
                    },
                ) => left_name == right_name,
                (
                    Probe::ContextualStructural {
                        name: left_name,
                        extension: left_extension,
                        parent_suffix: left_parent,
                        ..
                    },
                    Probe::ContextualStructural {
                        name: right_name,
                        extension: right_extension,
                        parent_suffix: right_parent,
                        ..
                    },
                ) => {
                    left_name == right_name
                        && left_extension.eq_ignore_ascii_case(right_extension)
                        && left_parent.eq_ignore_ascii_case(right_parent)
                }
                (
                    Probe::Structural {
                        name: left_name, ..
                    },
                    Probe::ContextualStructural {
                        name: right_name, ..
                    },
                )
                | (
                    Probe::ContextualStructural {
                        name: left_name, ..
                    },
                    Probe::Structural {
                        name: right_name, ..
                    },
                ) => left_name == right_name,
                _ => false,
            })
    })
}

fn shared_extension_diagnostics(descriptors: &[FormatDescriptor]) -> Vec<CatalogDiagnostic> {
    let mut extensions: Vec<_> = descriptors
        .iter()
        .flat_map(|descriptor| {
            descriptor
                .extension_hints
                .iter()
                .map(move |extension| (*extension, descriptor.id))
        })
        .collect();
    extensions.sort_unstable_by_key(|(extension, id)| (*extension, id.as_str()));

    let mut diagnostics = Vec::new();
    let mut start = 0;
    while start < extensions.len() {
        let extension = extensions[start].0;
        let mut end = start + 1;
        while end < extensions.len() && extensions[end].0 == extension {
            end += 1;
        }
        if end - start > 1 {
            diagnostics.push(CatalogDiagnostic::SharedExtension {
                extension,
                formats: extensions[start..end]
                    .iter()
                    .map(|(_, format)| *format)
                    .collect(),
            });
        }
        start = end;
    }
    diagnostics
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
