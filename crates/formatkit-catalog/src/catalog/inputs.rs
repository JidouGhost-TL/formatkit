//! Finite input forms. Binding proves shape and operation identity, not owner semantics.

use formatkit_core::{
    Error, Result, RetainedResidentPermit, SourceBindings, SourceViewHandle, WorkBudget,
    WorkResource,
};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputCardinality {
    One,
    Optional,
    Many { min: usize, max: usize },
}

impl InputCardinality {
    fn accepts(self, count: usize) -> bool {
        match self {
            Self::One => count == 1,
            Self::Optional => count <= 1,
            Self::Many { min, max } => min <= count && count <= max,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ByteRole {
    pub name: &'static str,
    pub cardinality: InputCardinality,
}

impl ByteRole {
    pub const fn one(name: &'static str) -> Self {
        Self {
            name,
            cardinality: InputCardinality::One,
        }
    }
}

/// A selector is explicit semantic input. Products must not infer it from a path.
#[derive(Debug, Clone, Copy)]
pub struct SelectorRole {
    pub name: &'static str,
    pub required: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct InputForm<'a> {
    pub name: &'static str,
    pub bytes: &'a [ByteRole],
    pub selectors: &'a [SelectorRole],
}

/// A relationship declared by an owner for generic input adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputRelationship {
    /// Every source bound to either role must have a different registered
    /// backing identity from every source bound to the other role.
    DistinctBacking {
        left_role: &'static str,
        right_role: &'static str,
    },
    /// Physical path inputs for both roles must carry the same file stem.
    /// Source-only adapters cannot prove this relationship and leave it to
    /// path-aware product binding before owner I/O.
    SameStem {
        left_role: &'static str,
        right_role: &'static str,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct InputSchema<'a> {
    pub forms: &'a [InputForm<'a>],
    /// Empty means aliases are allowed. Relationships are opt-in because equal
    /// paths, bytes, or `Arc`s do not establish source identity.
    pub relationships: &'a [InputRelationship],
}

#[derive(Debug, Clone, Copy)]
pub struct ByteInput<'a> {
    pub role: &'a str,
    pub source: &'a SourceViewHandle,
}

#[derive(Debug, Clone, Copy)]
pub struct SelectorInput<'a> {
    pub role: &'a str,
    pub value: &'a str,
}

/// Validated input shape with stable role names and operation-local source handles.
/// Owner semantics beyond relationships declared in the generic schema remain
/// the owner's responsibility before consuming source bytes.
#[derive(Debug)]
pub struct BoundInputs {
    form: &'static str,
    bytes: Vec<(&'static str, SourceViewHandle)>,
    selectors: Vec<(&'static str, String)>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Unsupported(message.into())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

impl InputSchema<'_> {
    /// Validate immutable declarations without binding or reading any source.
    pub fn validate(&self) -> Result<()> {
        if self.forms.is_empty() {
            return Err(invalid("input schema has no forms"));
        }
        for (index, form) in self.forms.iter().enumerate() {
            if !valid_name(form.name) || self.forms[..index].iter().any(|f| f.name == form.name) {
                return Err(invalid("input schema has invalid or duplicate form names"));
            }
            for (i, role) in form.bytes.iter().enumerate() {
                if !valid_name(role.name)
                    || form.bytes[..i].iter().any(|r| r.name == role.name)
                    || matches!(role.cardinality, InputCardinality::Many { min, max } if min > max || max == 0)
                {
                    return Err(invalid("input schema has invalid or duplicate byte roles"));
                }
            }
            for (i, role) in form.selectors.iter().enumerate() {
                if !valid_name(role.name)
                    || form.selectors[..i].iter().any(|r| r.name == role.name)
                    || form.bytes.iter().any(|r| r.name == role.name)
                {
                    return Err(invalid(
                        "input schema has invalid or duplicate selector roles",
                    ));
                }
            }
        }
        for (index, relationship) in self.relationships.iter().enumerate() {
            let (left_role, right_role) = match *relationship {
                InputRelationship::DistinctBacking {
                    left_role,
                    right_role,
                }
                | InputRelationship::SameStem {
                    left_role,
                    right_role,
                } => (left_role, right_role),
            };
            if left_role == right_role
                || !valid_name(left_role)
                || !valid_name(right_role)
                || !self.forms.iter().any(|form| {
                    form.bytes.iter().any(|role| role.name == left_role)
                        && form.bytes.iter().any(|role| role.name == right_role)
                })
                || self.relationships[..index]
                    .iter()
                    .any(|prior| match (*relationship, *prior) {
                        (
                            InputRelationship::DistinctBacking { .. },
                            InputRelationship::DistinctBacking {
                                left_role: prior_left,
                                right_role: prior_right,
                            },
                        )
                        | (
                            InputRelationship::SameStem { .. },
                            InputRelationship::SameStem {
                                left_role: prior_left,
                                right_role: prior_right,
                            },
                        ) => {
                            (prior_left, prior_right) == (left_role, right_role)
                                || (prior_left, prior_right) == (right_role, left_role)
                        }
                        _ => false,
                    })
            {
                return Err(invalid(
                    "input schema has an invalid or duplicate relationship",
                ));
            }
        }
        Ok(())
    }

    pub fn bind(
        &self,
        sources: &SourceBindings,
        bytes: &[ByteInput<'_>],
        selectors: &[SelectorInput<'_>],
    ) -> Result<BoundInputs> {
        self.validate()?;
        if bytes.len() > MAX_BOUND_BYTE_INPUTS {
            return Err(invalid("input binding exceeds the byte-input limit"));
        }
        if selectors.len() > MAX_BOUND_SELECTORS {
            return Err(invalid("input binding exceeds the selector-count limit"));
        }
        let selector_bytes = selectors.iter().try_fold(0usize, |total, selector| {
            total
                .checked_add(selector.value.len())
                .ok_or_else(|| invalid("input binding selector-byte count overflows usize"))
        })?;
        if selector_bytes > MAX_BOUND_SELECTOR_BYTES {
            return Err(invalid("input binding exceeds the selector-byte limit"));
        }
        for byte in bytes {
            sources.source(byte.source)?;
        }
        if selectors.iter().enumerate().any(|(i, value)| {
            value.value.is_empty() || selectors[..i].iter().any(|s| s.role == value.role)
        }) {
            return Err(invalid("input selectors are empty or duplicated"));
        }
        let mut matches = self.forms.iter().filter(|form| {
            bytes
                .iter()
                .all(|b| form.bytes.iter().any(|r| r.name == b.role))
                && form.bytes.iter().all(|r| {
                    r.cardinality
                        .accepts(bytes.iter().filter(|b| b.role == r.name).count())
                })
                && selectors
                    .iter()
                    .all(|s| form.selectors.iter().any(|r| r.name == s.role))
                && form
                    .selectors
                    .iter()
                    .all(|r| !r.required || selectors.iter().any(|s| s.role == r.name))
        });
        let form = matches.next().ok_or_else(|| {
            invalid("inputs do not match an accepted form (unknown, missing, or duplicate roles)")
        })?;
        if matches.next().is_some() {
            return Err(invalid("inputs match multiple accepted forms"));
        }
        let mut bound_bytes = Vec::new();
        bound_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| invalid("cannot reserve bound byte inputs"))?;
        for role in form.bytes {
            bound_bytes.extend(
                bytes
                    .iter()
                    .filter(|input| input.role == role.name)
                    .map(|input| (role.name, input.source.clone())),
            );
        }
        let mut bound_selectors = Vec::new();
        bound_selectors
            .try_reserve_exact(selectors.len())
            .map_err(|_| invalid("cannot reserve bound selectors"))?;
        for role in form.selectors {
            if let Some(selector) = selectors.iter().find(|input| input.role == role.name) {
                let mut value = String::new();
                value
                    .try_reserve_exact(selector.value.len())
                    .map_err(|_| invalid("cannot reserve bound selector value"))?;
                value.push_str(selector.value);
                bound_selectors.push((role.name, value));
            }
        }
        let bound = BoundInputs {
            form: form.name,
            bytes: bound_bytes,
            selectors: bound_selectors,
        };
        self.validate_bound(sources, &bound)?;
        Ok(bound)
    }

    /// Revalidate a bound value against this canonical schema before an owner
    /// callback can perform I/O. This also permits safe shadow adapters to
    /// receive `BoundInputs` produced outside their immediate call site.
    pub fn validate_bound(&self, sources: &SourceBindings, bound: &BoundInputs) -> Result<()> {
        self.validate()?;
        let form = self
            .forms
            .iter()
            .find(|form| form.name == bound.form)
            .ok_or_else(|| invalid("bound inputs name an unknown form"))?;
        for (_, source) in &bound.bytes {
            sources.source(source)?;
        }
        if !bound
            .bytes
            .iter()
            .all(|(name, _)| form.bytes.iter().any(|role| role.name == *name))
            || !form.bytes.iter().all(|role| {
                role.cardinality.accepts(
                    bound
                        .bytes
                        .iter()
                        .filter(|(name, _)| *name == role.name)
                        .count(),
                )
            })
            || !bound.selectors.iter().all(|(name, value)| {
                !value.is_empty() && form.selectors.iter().any(|r| r.name == *name)
            })
            || !form.selectors.iter().all(|role| {
                !role.required || bound.selectors.iter().any(|(name, _)| *name == role.name)
            })
        {
            return Err(invalid("bound inputs do not satisfy their declared form"));
        }
        for relationship in self.relationships {
            let InputRelationship::DistinctBacking {
                left_role,
                right_role,
            } = *relationship
            else {
                continue;
            };
            for left in bound.sources(left_role) {
                for right in bound.sources(right_role) {
                    if left.backing() == right.backing() {
                        return Err(invalid(format!(
                            "input roles {left_role:?} and {right_role:?} require distinct backing sources"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether a path-aware adapter must enforce equal file stems for these
    /// two roles. Role order is immaterial.
    pub fn requires_same_stem(self, left_role: &str, right_role: &str) -> bool {
        self.relationships.iter().any(|relationship| {
            matches!(
                *relationship,
                InputRelationship::SameStem {
                    left_role: declared_left,
                    right_role: declared_right,
                } if (declared_left, declared_right) == (left_role, right_role)
                    || (declared_left, declared_right) == (right_role, left_role)
            )
        })
    }
}

/// Patch-1 admission ceiling for byte-role bindings. This bounds the generic
/// `Many` path before handle validation, role matching, or result allocation.
pub const MAX_BOUND_BYTE_INPUTS: usize = 1_024;
/// Patch-1 admission ceiling for explicit selector values.
pub const MAX_BOUND_SELECTORS: usize = 256;
/// Patch-1 aggregate UTF-8 byte ceiling for copied selector values.
pub const MAX_BOUND_SELECTOR_BYTES: usize = 1024 * 1024;

impl BoundInputs {
    pub const fn form(&self) -> &'static str {
        self.form
    }

    /// Number of bound byte sources across all roles. Role-bound providers
    /// compare this against their declared role count to reject smuggled
    /// extra sources without enumerating role names.
    pub const fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Number of bound selectors across all roles.
    pub const fn selector_len(&self) -> usize {
        self.selectors.len()
    }

    pub fn sources<'a>(&'a self, role: &'a str) -> impl Iterator<Item = &'a SourceViewHandle> + 'a {
        self.bytes
            .iter()
            .filter(move |(name, _)| *name == role)
            .map(|(_, source)| source)
    }

    pub fn single_source(&self, role: &str) -> Result<&SourceViewHandle> {
        let mut sources = self
            .bytes
            .iter()
            .filter(|(name, _)| *name == role)
            .map(|(_, source)| source);
        let source = sources
            .next()
            .ok_or_else(|| invalid(format!("missing byte role {role:?}")))?;
        if sources.next().is_some() {
            return Err(invalid(format!("byte role {role:?} has multiple sources")));
        }
        Ok(source)
    }

    pub fn selector(&self, role: &str) -> Option<&str> {
        self.selectors
            .iter()
            .find(|(name, _)| *name == role)
            .map(|(_, value)| value.as_str())
    }

    fn contains_source(&self, role: &str, source: &SourceViewHandle) -> bool {
        self.bytes
            .iter()
            .any(|(name, candidate)| *name == role && candidate == source)
    }

    fn source_position(&self, role: &str, source: &SourceViewHandle) -> Option<usize> {
        self.bytes
            .iter()
            .filter(|(name, _)| *name == role)
            .position(|(_, candidate)| candidate == source)
    }
}

pub const MAX_SOURCE_EVIDENCE_RANGES: usize = 64;

/// One cited source witness which contributed to a successful source probe.
///
/// Evidence is deliberately non-exhaustive: the prepared owner value remains
/// the authority for complete structural authentication. These ranges explain
/// stable, bounded bytes supporting the match; they do not claim that reading
/// only the cited ranges reproduces the owner's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEvidenceRange {
    pub role: &'static str,
    pub source: SourceViewHandle,
    pub range: Range<u64>,
}

/// Match evidence whose backing allocation remains coupled to its residency
/// permit. The fields are private and no consuming Vec accessor is exposed,
/// so callers cannot detach the evidence allocation from its ledger lifetime.
#[derive(Debug)]
pub struct RetainedSourceEvidence {
    evidence: Vec<SourceEvidenceRange>,
    resident: RetainedResidentPermit,
}

impl RetainedSourceEvidence {
    /// Couple a completed evidence vector to an exact capacity-sized permit.
    pub fn new(
        evidence: Vec<SourceEvidenceRange>,
        resident: RetainedResidentPermit,
    ) -> Result<Self> {
        let capacity_bytes = (evidence.capacity() as u64)
            .checked_mul(std::mem::size_of::<SourceEvidenceRange>() as u64)
            .ok_or_else(|| invalid("source evidence capacity overflows"))?;
        if resident.amount() != capacity_bytes {
            return Err(invalid(
                "source evidence permit does not match vector capacity",
            ));
        }
        Ok(Self { evidence, resident })
    }

    pub fn as_slice(&self) -> &[SourceEvidenceRange] {
        &self.evidence
    }

    pub fn resident_bytes(&self) -> u64 {
        self.resident.amount()
    }
}

impl std::ops::Deref for RetainedSourceEvidence {
    type Target = [SourceEvidenceRange];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// A source probe is a structural mismatch, or a prepared match with explicit,
/// non-exhaustive cited witnesses. Operational failures remain the outer
/// [`Result`].
///
/// `MatchRetained` is the residency-strict match shape: the prepared value
/// and the cited evidence each own the caller-ledger permit covering their
/// retained storage, so either may drop first while the survivor keeps
/// reporting its live nominal. Owners whose evidence heap is covered
/// elsewhere keep returning the plain `Match` shape.
#[derive(Debug)]
pub enum SourceProbeOutcome<T> {
    Mismatch,
    Match {
        prepared: T,
        evidence: Vec<SourceEvidenceRange>,
    },
    MatchRetained {
        prepared: T,
        evidence: RetainedSourceEvidence,
    },
}

impl<T> SourceProbeOutcome<T> {
    /// Validate match evidence against the operation's role binding and source
    /// sizes. `Mismatch` returns without allocating evidence storage. Both
    /// match shapes share one validation gate and one node charge.
    pub fn validate(
        self,
        sources: &SourceBindings,
        bound: &BoundInputs,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let evidence: &[SourceEvidenceRange] = match &self {
            Self::Mismatch => return Ok(self),
            Self::Match { evidence, .. } => evidence,
            Self::MatchRetained { evidence, .. } => evidence.as_slice(),
        };
        Self::validate_evidence(sources, bound, evidence, budget)?;
        Ok(self)
    }

    /// Validate cited evidence ranges without consuming an outcome.
    /// Work-native adapters call this before constructing their borrowed
    /// mount: the borrowed outcome cannot re-borrow the same ledger for a
    /// post-return validation, so the evidence node is charged here, ahead of
    /// the downstream mount it witnesses.
    pub fn validate_evidence(
        sources: &SourceBindings,
        bound: &BoundInputs,
        evidence: &[SourceEvidenceRange],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        if evidence.is_empty() || evidence.len() > MAX_SOURCE_EVIDENCE_RANGES {
            return Err(invalid("source probe match has an invalid evidence count"));
        }
        budget.charge(WorkResource::Nodes, evidence.len() as u64)?;
        let mut previous: Option<(&str, usize, &Range<u64>)> = None;
        for item in evidence {
            let source = sources.source(&item.source)?;
            let position = bound.source_position(item.role, &item.source);
            if !bound.contains_source(item.role, &item.source)
                || item.range.start >= item.range.end
                || item.range.end > source.size()
            {
                return Err(invalid("source probe evidence is outside its bound role"));
            }
            let position = position.expect("contains_source established the position");
            if let Some((prior_role, prior_position, prior_range)) = previous {
                if (item.role, position, item.range.start)
                    <= (prior_role, prior_position, prior_range.start)
                    || (item.role == prior_role
                        && position == prior_position
                        && item.range.start < prior_range.end)
                {
                    return Err(invalid(
                        "source probe evidence is unordered or overlaps on one source",
                    ));
                }
            }
            previous = Some((item.role, position, &item.range));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn alternatives_reject_mixtures_ambiguity_and_foreign_handles() {
        let mut sources = SourceBindings::new();
        let handle = sources.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![1],
            "input",
        )));
        let single = [ByteRole::one("synthetic-id-2e6a2810b7c3")];
        let pair = [ByteRole::one("index"), ByteRole::one("data")];
        let selector = [SelectorRole {
            name: "selection",
            required: true,
        }];
        let forms = [
            InputForm {
                name: "single",
                bytes: &single,
                selectors: &[],
            },
            InputForm {
                name: "pair",
                bytes: &pair,
                selectors: &selector,
            },
        ];
        let schema = InputSchema {
            forms: &forms,
            relationships: &[],
        };
        let bytes = [
            ByteInput {
                role: "index",
                source: &handle,
            },
            ByteInput {
                role: "data",
                source: &handle,
            },
        ];
        let selectors = [SelectorInput {
            role: "selection",
            value: "explicit",
        }];
        let bound = schema.bind(&sources, &bytes, &selectors).unwrap();
        assert_eq!(bound.form(), "pair");
        assert_eq!(
            bound.single_source("index").unwrap(),
            bound.single_source("data").unwrap()
        );
        assert!(schema.bind(&sources, &bytes, &[]).is_err());
        assert!(schema
            .bind(&sources, &[bytes[0], bytes[0]], &selectors)
            .is_err());
        assert!(schema
            .bind(
                &sources,
                &[
                    bytes[0],
                    ByteInput {
                        role: "synthetic-id-2e6a2810b7c3",
                        source: &handle
                    }
                ],
                &selectors
            )
            .is_err());
        assert!(schema
            .bind(&SourceBindings::new(), &bytes, &selectors)
            .is_err());
        let ambiguous = [
            forms[0],
            InputForm {
                name: "also-single",
                ..forms[0]
            },
        ];
        assert!(InputSchema {
            forms: &ambiguous,
            relationships: &[],
        }
        .bind(
            &sources,
            &[ByteInput {
                role: "synthetic-id-2e6a2810b7c3",
                source: &handle
            }],
            &[]
        )
        .unwrap_err()
        .to_string()
        .contains("multiple"));
    }

    #[test]
    fn many_is_bounded_and_selectors_are_not_byte_roles() {
        let mut sources = SourceBindings::new();
        let handle = sources.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![],
            "input",
        )));
        let roles = [
            ByteRole {
                name: "body",
                cardinality: InputCardinality::Many { min: 1, max: 2 },
            },
            ByteRole {
                name: "palette",
                cardinality: InputCardinality::Optional,
            },
        ];
        let forms = [InputForm {
            name: "bank",
            bytes: &roles,
            selectors: &[],
        }];
        let schema = InputSchema {
            forms: &forms,
            relationships: &[],
        };
        let value = ByteInput {
            role: "body",
            source: &handle,
        };
        assert!(schema.bind(&sources, &[value, value], &[]).is_ok());
        assert!(schema.bind(&sources, &[value, value, value], &[]).is_err());
        assert!(schema.bind(&sources, &[], &[]).is_err());
        assert!(schema
            .bind(
                &sources,
                &[value],
                &[SelectorInput {
                    role: "body",
                    value: "fake"
                }]
            )
            .is_err());
    }

    #[test]
    fn distinct_backing_is_opt_in_and_evidence_is_role_confined() {
        let mut sources = SourceBindings::new();
        let root = sources.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![1, 2, 3, 4],
            "root",
        )));
        let alias = sources.slice(&root, 0, 4, "alias").unwrap();
        let independent = sources.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![5, 6, 7, 8],
            "independent",
        )));
        let roles = [ByteRole::one("index"), ByteRole::one("image")];
        let forms = [InputForm {
            name: "paired",
            bytes: &roles,
            selectors: &[],
        }];
        let permissive = InputSchema {
            forms: &forms,
            relationships: &[],
        };
        let aliased = [
            ByteInput {
                role: "index",
                source: &root,
            },
            ByteInput {
                role: "image",
                source: &alias,
            },
        ];
        assert!(permissive.bind(&sources, &aliased, &[]).is_ok());

        let relationships = [InputRelationship::DistinctBacking {
            left_role: "index",
            right_role: "image",
        }];
        let distinct = InputSchema {
            forms: &forms,
            relationships: &relationships,
        };
        assert!(distinct.bind(&sources, &aliased, &[]).is_err());
        let separated = [
            aliased[0],
            ByteInput {
                role: "image",
                source: &independent,
            },
        ];
        let bound = distinct.bind(&sources, &separated, &[]).unwrap();
        assert!(matches!(
            SourceProbeOutcome::<()>::Mismatch
                .validate(
                    &sources,
                    &bound,
                    &mut WorkBudget::new(formatkit_core::WorkLimits::unlimited()),
                )
                .unwrap(),
            SourceProbeOutcome::Mismatch
        ));
        assert!(SourceProbeOutcome::Match {
            prepared: (),
            evidence: vec![SourceEvidenceRange {
                role: "index",
                source: root.clone(),
                range: 0..4,
            }],
        }
        .validate(
            &sources,
            &bound,
            &mut WorkBudget::new(formatkit_core::WorkLimits::unlimited()),
        )
        .is_ok());
        assert!(SourceProbeOutcome::Match {
            prepared: (),
            evidence: vec![SourceEvidenceRange {
                role: "image",
                source: root.clone(),
                range: 0..4,
            }],
        }
        .validate(
            &sources,
            &bound,
            &mut WorkBudget::new(formatkit_core::WorkLimits::unlimited()),
        )
        .is_err());

        let invalid_ranges = |ranges: [Range<u64>; 2]| SourceProbeOutcome::Match {
            prepared: (),
            evidence: ranges
                .into_iter()
                .map(|range| SourceEvidenceRange {
                    role: "index",
                    source: separated[0].source.clone(),
                    range,
                })
                .collect(),
        };
        for ranges in [[2..4, 0..1], [0..3, 2..4]] {
            assert!(invalid_ranges(ranges)
                .validate(
                    &sources,
                    &bound,
                    &mut WorkBudget::new(formatkit_core::WorkLimits::unlimited()),
                )
                .is_err());
        }

        let mut no_evidence_nodes =
            WorkBudget::new(formatkit_core::WorkLimits::unlimited().with(WorkResource::Nodes, 0));
        assert!(SourceProbeOutcome::Match {
            prepared: (),
            evidence: vec![SourceEvidenceRange {
                role: "index",
                source: separated[0].source.clone(),
                range: 0..1,
            }],
        }
        .validate(&sources, &bound, &mut no_evidence_nodes)
        .is_err());
        assert_eq!(no_evidence_nodes.spent(WorkResource::Nodes), 0);

        let many_roles = [ByteRole {
            name: "body",
            cardinality: InputCardinality::Many { min: 2, max: 2 },
        }];
        let many_forms = [InputForm {
            name: "many",
            bytes: &many_roles,
            selectors: &[],
        }];
        let many_schema = InputSchema {
            forms: &many_forms,
            relationships: &[],
        };
        let many_bound = many_schema
            .bind(
                &sources,
                &[
                    ByteInput {
                        role: "body",
                        source: separated[0].source,
                    },
                    ByteInput {
                        role: "body",
                        source: separated[1].source,
                    },
                ],
                &[],
            )
            .unwrap();
        assert!(SourceProbeOutcome::Match {
            prepared: (),
            evidence: vec![
                SourceEvidenceRange {
                    role: "body",
                    source: separated[0].source.clone(),
                    range: 0..2,
                },
                SourceEvidenceRange {
                    role: "body",
                    source: separated[1].source.clone(),
                    range: 0..2,
                },
            ],
        }
        .validate(
            &sources,
            &many_bound,
            &mut WorkBudget::new(formatkit_core::WorkLimits::unlimited()),
        )
        .is_ok());

        let too_many = (0..=MAX_SOURCE_EVIDENCE_RANGES)
            .map(|_| SourceEvidenceRange {
                role: "index",
                source: separated[0].source.clone(),
                range: 0..1,
            })
            .collect();
        assert!(SourceProbeOutcome::Match {
            prepared: (),
            evidence: too_many,
        }
        .validate(
            &sources,
            &bound,
            &mut WorkBudget::new(formatkit_core::WorkLimits::unlimited()),
        )
        .is_err());
    }

    #[test]
    fn same_stem_is_declared_for_path_adapters_without_weakening_source_binding() {
        let mut sources = SourceBindings::new();
        let index = sources.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![1],
            "index",
        )));
        let data = sources.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![2],
            "data",
        )));
        let roles = [ByteRole::one("index"), ByteRole::one("data")];
        let forms = [InputForm {
            name: "paired",
            bytes: &roles,
            selectors: &[],
        }];
        let relationships = [InputRelationship::SameStem {
            left_role: "index",
            right_role: "data",
        }];
        let schema = InputSchema {
            forms: &forms,
            relationships: &relationships,
        };
        assert!(schema.requires_same_stem("index", "data"));
        assert!(schema.requires_same_stem("data", "index"));
        assert!(!schema.requires_same_stem("index", "other"));
        assert!(schema
            .bind(
                &sources,
                &[
                    ByteInput {
                        role: "index",
                        source: &index,
                    },
                    ByteInput {
                        role: "data",
                        source: &data,
                    },
                ],
                &[],
            )
            .is_ok());
    }

    #[test]
    fn binder_caps_many_and_selectors_before_handle_resolution_or_allocation() {
        let roles = [ByteRole {
            name: "body",
            cardinality: InputCardinality::Many {
                min: 1,
                max: MAX_BOUND_BYTE_INPUTS + 1,
            },
        }];
        let selector_roles = [SelectorRole {
            name: "choice",
            required: false,
        }];
        let forms = [InputForm {
            name: "bounded",
            bytes: &roles,
            selectors: &selector_roles,
        }];
        let schema = InputSchema {
            forms: &forms,
            relationships: &[],
        };

        // A foreign handle would fail normal lookup. Hitting the static count
        // gate first locks denial before SourceBindings resolution/owner I/O.
        let sources = SourceBindings::new();
        let mut foreign = SourceBindings::new();
        let foreign_handle = foreign.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![0],
            "foreign",
        )));
        let too_many = (0..=MAX_BOUND_BYTE_INPUTS)
            .map(|_| ByteInput {
                role: "body",
                source: &foreign_handle,
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            schema.bind(&sources, &too_many, &[]),
            Err(Error::Unsupported(message)) if message == "input binding exceeds the byte-input limit"
        ));

        let mut local = SourceBindings::new();
        let local_handle = local.register(Arc::new(formatkit_core::MemoryRangeSource::new(
            vec![0],
            "local",
        )));
        let bytes = [ByteInput {
            role: "body",
            source: &local_handle,
        }];
        let oversized_value = "x".repeat(MAX_BOUND_SELECTOR_BYTES + 1);
        let selectors = [SelectorInput {
            role: "choice",
            value: &oversized_value,
        }];
        assert!(matches!(
            schema.bind(&local, &bytes, &selectors),
            Err(Error::Unsupported(message)) if message == "input binding exceeds the selector-byte limit"
        ));

        let too_many_selectors = (0..=MAX_BOUND_SELECTORS)
            .map(|_| SelectorInput {
                role: "choice",
                value: "x",
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            schema.bind(&local, &bytes, &too_many_selectors),
            Err(Error::Unsupported(message)) if message == "input binding exceeds the selector-count limit"
        ));
    }
}
