use crate::catalog::Probe;
use crate::{Category, FormatId, Method};

/// Owner-declared content evidence for a caller-composed compatibility
/// recognition profile.
///
/// This value only describes a possible report. It does not grant execution,
/// native admission, decoding, or dispatch authority. The optional guard is
/// called by a consumer over the complete byte slice supplied to that
/// consumer; this type does not define truncation or prefix behavior.
#[derive(Clone, Copy)]
pub struct CompatibilityRecognitionRule {
    /// Owner-declared identity for this recognition result.
    pub id: FormatId,
    /// Broad category reported for the recognized bytes.
    pub category: Category,
    /// Recognition method corresponding to `probe`.
    pub method: Method,
    /// Content evidence supplied by the owner.
    pub probe: Probe,
    /// Optional owner-supplied check over the consumer's complete input.
    pub guard: Option<fn(&[u8]) -> bool>,
    /// Optional historical label for a compatibility report; not a dispatch key.
    pub historical_opener: Option<&'static str>,
}

/// Owner-declared recognition evidence with a compatibility report label that
/// may differ from the rule's canonical identity.
///
/// The label is descriptive data only; it does not authorize execution,
/// native admission, or dispatch.
#[derive(Clone, Copy)]
pub struct CompatibilityRecognitionContribution {
    /// Recognition evidence supplied by the owner.
    pub rule: CompatibilityRecognitionRule,
    /// Historical label for compatibility reporting.
    pub historical_report_format: &'static str,
}
