use crate::{Category, FormatId};

/// How strongly a descriptor's interpretation is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Exact, format-specific content magic.
    ExactMagic,
    /// Structural recognition backed by parser/corpus agreement.
    CorpusBacked,
    /// A bounded structural interpretation without an independent oracle.
    Structural,
    /// Content identifies a family but requires context to select a member.
    Ambiguous,
}

impl Confidence {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactMagic => "exact-magic",
            Self::CorpusBacked => "corpus-backed",
            Self::Structural => "structural",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// Product-relevant behavior implemented for one identified format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatCapabilities {
    pub parse: bool,
    pub decode: bool,
    /// A supported mutation path exists. This can be true without general
    /// authoring (`write`) for constrained, source-preserving editors.
    pub edit: bool,
    pub write: bool,
    pub round_trip: bool,
    pub corpus: bool,
    pub bindings: bool,
    pub confidence: Confidence,
}

/// An identification probe. Most probes are content-only; contextual probes
/// additionally require a caller-supplied path whose parent has a known role.
#[derive(Clone, Copy)]
pub enum Probe {
    /// Match exact bytes at a fixed offset.
    Magic { offset: usize, bytes: &'static [u8] },
    /// Run a bounded structural predicate supplied by the owning format crate.
    Structural {
        name: &'static str,
        check: fn(&[u8]) -> bool,
    },
    /// Match a structural predicate only in a specific parent-directory role.
    /// The suffix is a path, not a substring; an absent path never matches.
    ContextualStructural {
        name: &'static str,
        extension: &'static str,
        parent_suffix: &'static str,
        check: fn(&[u8]) -> bool,
    },
}

/// Extra input a decoder requires after identification has succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderRequirement {
    None,
    /// The format is an index whose payload lives in a separate data file.
    PairedData,
    /// Payload offsets address an enclosing allocation rather than this slice.
    ParentAddressSpace,
    /// Full semantics also require sibling objects owned by the same parent.
    ParentAndSiblings,
    /// Headerless/structural bytes are meaningful only in a known carrier role.
    AuthenticatedCarrierMember,
}

impl DecoderRequirement {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PairedData => "paired-data",
            Self::ParentAddressSpace => "parent-address-space",
            Self::ParentAndSiblings => "parent-and-siblings",
            Self::AuthenticatedCarrierMember => "authenticated-carrier-member",
        }
    }
}

/// Identification metadata owned by a format implementation.
#[derive(Clone, Copy)]
pub struct FormatDescriptor {
    pub id: FormatId,
    pub category: Category,
    pub decoder: Option<&'static str>,
    /// Higher precedence wins. Path hints only break ties at equal precedence.
    pub precedence: u16,
    pub probes: &'static [Probe],
    /// Lowercase extensions without a leading dot.
    pub extension_hints: &'static [&'static str],
    pub requirement: DecoderRequirement,
    /// Formats in the same group may intentionally share equal-ranked probes.
    pub ambiguity_group: Option<&'static str>,
    pub capabilities: FormatCapabilities,
}

/// Identity of a runtime/container family shared by related leaf formats.
///
/// A family is an ownership and context boundary, not a format identity: it is
/// never returned by content detection and never substitutes for [`FormatId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FormatFamilyId(&'static str);

impl FormatFamilyId {
    /// Declare an owner-defined static format-family identity.
    ///
    /// Construction is allocation-free and intentionally const. Catalog
    /// composition validates the lexical domain, just as it does for
    /// owner-defined [`FormatId`] values.
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// Whether this is a composable family identity.
    ///
    /// Family identities use the same lowercase, separator-delimited lexical
    /// domain as [`FormatId`]. Keeping validation at catalog composition lets
    /// owner crates declare constants without extending a central registry.
    pub const fn is_valid(self) -> bool {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let mut index = 0;
        let mut previous_was_separator = true;
        while index < bytes.len() {
            let byte = bytes[index];
            let separator = byte == b'-' || byte == b'.';
            if separator {
                if previous_was_separator {
                    return false;
                }
            } else if !((byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9')) {
                return false;
            }
            previous_was_separator = separator;
            index += 1;
        }
        !previous_was_separator
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Extra, typed input required to open a semantic leaf which cannot safely be
/// selected by a global content probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRequirement {
    /// The format has no safe detached identity and is opened only by an
    /// explicit typed selection supplied by the caller.
    ExplicitSelection,
    PairedData {
        role: &'static str,
    },
    ParentAddressSpace {
        family: FormatFamilyId,
    },
    ParentAndSiblings {
        family: FormatFamilyId,
    },
    AuthenticatedCarrierMember {
        family: FormatFamilyId,
    },
}

impl ContextRequirement {
    pub const fn family(self) -> Option<FormatFamilyId> {
        match self {
            Self::ExplicitSelection | Self::PairedData { .. } => None,
            Self::ParentAddressSpace { family }
            | Self::ParentAndSiblings { family }
            | Self::AuthenticatedCarrierMember { family } => Some(family),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ExplicitSelection => "explicit-selection",
            Self::PairedData { .. } => "paired-data",
            Self::ParentAddressSpace { .. } => "parent-address-space",
            Self::ParentAndSiblings { .. } => "parent-and-siblings",
            Self::AuthenticatedCarrierMember { .. } => "authenticated-carrier-member",
        }
    }
}

/// Concrete evidence behind a context-only format's corpus capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusEvidence {
    pub handler: &'static str,
    pub sample_floor: usize,
}
