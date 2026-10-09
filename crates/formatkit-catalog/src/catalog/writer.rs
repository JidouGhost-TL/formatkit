//! Writer operation contracts and executable proof-oracle identities.

use super::FormatCapabilities;
use crate::FormatId;

/// One concrete mutation strategy exposed by a writer API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditMode {
    ConfinedEdit,
    SameSizeEdit,
    AllocationFittingEdit,
    Rebuild,
}

impl EditMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConfinedEdit => "confined-edit",
            Self::SameSizeEdit => "same-size-edit",
            Self::AllocationFittingEdit => "allocation-fitting-edit",
            Self::Rebuild => "rebuild",
        }
    }

    pub(super) const fn order(self) -> u8 {
        match self {
            Self::ConfinedEdit => 0,
            Self::SameSizeEdit => 1,
            Self::AllocationFittingEdit => 2,
            Self::Rebuild => 3,
        }
    }
}

/// A format-owned dialect identity. Including the owning format prevents a
/// parser dialect from being reused accidentally by an unrelated contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DialectId {
    format: FormatId,
    name: &'static str,
}

impl DialectId {
    pub const fn new(format: FormatId, name: &'static str) -> Self {
        Self { format, name }
    }

    pub const fn format(self) -> FormatId {
        self.format
    }

    pub const fn name(self) -> &'static str {
        self.name
    }
}

/// Input/output dialect surface to which one operation applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationScope {
    Format,
    Dialect(DialectId),
}

impl OperationScope {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Dialect(dialect) => dialect.name(),
        }
    }
}

/// Condition under which an edit mode is selected. These describe semantic
/// writer decisions; they are not inferred from the resulting byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditPrecondition {
    SemanticFieldsOnly,
    ReplacementLengthsUnchanged,
    FitsExistingAllocation,
    ExistingLayoutCannotBePreserved,
    AnyMutation,
}

impl EditPrecondition {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SemanticFieldsOnly => "semantic-fields-only",
            Self::ReplacementLengthsUnchanged => "replacement-lengths-unchanged",
            Self::FitsExistingAllocation => "fits-existing-allocation",
            Self::ExistingLayoutCannotBePreserved => "layout-cannot-be-preserved",
            Self::AnyMutation => "any-mutation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputLengthGuarantee {
    Preserved,
    MayChange,
}

impl OutputLengthGuarantee {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Preserved => "preserved",
            Self::MayChange => "may-change",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationObligation {
    /// The rebuilt format has no internal offsets or pointers to relocate.
    NotApplicable,
    PreserveExistingOffsets,
    RecomputeDirectoryOffsets,
    ValidatedPointerRelocationPlan,
}

impl RelocationObligation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotApplicable => "n/a",
            Self::PreserveExistingOffsets => "preserve-offsets",
            Self::RecomputeDirectoryOffsets => "recompute-directory-offsets",
            Self::ValidatedPointerRelocationPlan => "validated-pointer-plan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReproductionContract {
    pub scope: OperationScope,
    pub oracle: CargoTestOracle,
}

/// A selector for a concrete Cargo test intended to discharge one writer proof
/// obligation.
///
/// Keeping the package, target, and exact test selector together makes an
/// oracle machine-addressable. [`super::SupportCatalog`] validates selector syntax;
/// the composing workspace must separately list its Cargo test inventories and
/// require each production selector to resolve exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CargoTestOracle {
    pub package: &'static str,
    pub target: CargoTestTarget,
    pub test: &'static str,
}

impl CargoTestOracle {
    pub const fn lib(package: &'static str, test: &'static str) -> Self {
        Self {
            package,
            target: CargoTestTarget::Lib,
            test,
        }
    }

    pub const fn integration(
        package: &'static str,
        target: &'static str,
        test: &'static str,
    ) -> Self {
        Self {
            package,
            target: CargoTestTarget::Integration(target),
            test,
        }
    }

    pub const fn bin(package: &'static str, target: &'static str, test: &'static str) -> Self {
        Self {
            package,
            target: CargoTestTarget::Bin(target),
            test,
        }
    }

    /// Exact arguments accepted by Cargo from a workspace root.
    pub fn cargo_args(self) -> Vec<&'static str> {
        let mut args = vec!["test", "-p", self.package];
        match self.target {
            CargoTestTarget::Lib => args.push("--lib"),
            CargoTestTarget::Bin(target) => {
                args.extend(["--bin", target]);
            }
            CargoTestTarget::Integration(target) => {
                args.extend(["--test", target]);
            }
        }
        args.extend([self.test, "--", "--exact"]);
        args
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CargoTestTarget {
    Lib,
    Bin(&'static str),
    Integration(&'static str),
}

pub(super) fn valid_cargo_test_oracle(oracle: CargoTestOracle) -> bool {
    let component = |value: &str| {
        !value.trim().is_empty()
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    component(oracle.package)
        && match oracle.target {
            CargoTestTarget::Lib => true,
            CargoTestTarget::Bin(target) | CargoTestTarget::Integration(target) => {
                component(target)
            }
        }
        && !oracle.test.trim().is_empty()
        && !oracle.test.starts_with('-')
        && oracle
            .test
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditContract {
    pub mode: EditMode,
    pub scope: OperationScope,
    pub precondition: EditPrecondition,
    pub output_length: OutputLengthGuarantee,
    pub relocation: RelocationObligation,
    pub mutation_oracle: CargoTestOracle,
    pub parse_after_write_oracle: CargoTestOracle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoringContract {
    pub output_scope: OperationScope,
    pub parse_after_write_oracle: CargoTestOracle,
    pub semantic_oracle: CargoTestOracle,
    pub independent_extent_oracle: CargoTestOracle,
}

/// Machine-readable proof obligations for the independent writer operations
/// exposed for one format. Reproduction, mutation modes, and fresh authoring
/// are deliberately orthogonal: a builder does not erase the stricter
/// guarantees of a same-size editor, and a parser may recognize dialects to
/// which only some operations apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterContract {
    pub id: FormatId,
    pub reproduction: Option<ReproductionContract>,
    pub edits: &'static [EditContract],
    pub authoring: Option<AuthoringContract>,
}

impl WriterContract {
    pub fn oracles(self) -> impl Iterator<Item = CargoTestOracle> {
        self.reproduction
            .into_iter()
            .map(|operation| operation.oracle)
            .chain(self.edits.iter().flat_map(|operation| {
                [
                    operation.mutation_oracle,
                    operation.parse_after_write_oracle,
                ]
            }))
            .chain(self.authoring.into_iter().flat_map(|operation| {
                [
                    operation.parse_after_write_oracle,
                    operation.semantic_oracle,
                    operation.independent_extent_oracle,
                ]
            }))
    }

    pub(super) fn valid_for(self, capabilities: FormatCapabilities) -> bool {
        let nonempty = |value: &str| !value.trim().is_empty();
        let valid_scope = |scope: OperationScope| match scope {
            OperationScope::Format => true,
            OperationScope::Dialect(dialect) => {
                dialect.format() == self.id
                    && nonempty(dialect.name())
                    && dialect.name().bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            }
        };
        let reproduction_ok = self.reproduction.is_none_or(|operation| {
            valid_scope(operation.scope) && valid_cargo_test_oracle(operation.oracle)
        });
        let mut edit_operations = std::collections::HashSet::new();
        let mut previous_operation = None;
        let edits_ok = self.edits.iter().all(|operation| {
            let scope_order = match operation.scope {
                OperationScope::Format => (0, ""),
                OperationScope::Dialect(dialect) => (1, dialect.name()),
            };
            let operation_order = (operation.mode.order(), scope_order);
            let ordered = previous_operation.is_none_or(|prior| prior < operation_order);
            previous_operation = Some(operation_order);
            ordered
                && edit_operations.insert((operation.mode, operation.scope))
                && valid_scope(operation.scope)
                && valid_cargo_test_oracle(operation.mutation_oracle)
                && valid_cargo_test_oracle(operation.parse_after_write_oracle)
                && operation.valid_mode_contract()
        });
        let authoring_ok = self.authoring.is_none_or(|operation| {
            valid_scope(operation.output_scope)
                && valid_cargo_test_oracle(operation.parse_after_write_oracle)
                && valid_cargo_test_oracle(operation.semantic_oracle)
                && valid_cargo_test_oracle(operation.independent_extent_oracle)
        });
        let operations_match_capabilities = capabilities.edit != self.edits.is_empty()
            && capabilities.write == self.authoring.is_some()
            && (self.reproduction.is_some() || !self.edits.is_empty() || self.authoring.is_some());
        reproduction_ok && edits_ok && authoring_ok && operations_match_capabilities
    }
}

impl EditContract {
    fn valid_mode_contract(self) -> bool {
        match self.mode {
            EditMode::ConfinedEdit => {
                self.precondition == EditPrecondition::SemanticFieldsOnly
                    && self.output_length == OutputLengthGuarantee::Preserved
                    && !matches!(
                        self.relocation,
                        RelocationObligation::RecomputeDirectoryOffsets
                            | RelocationObligation::ValidatedPointerRelocationPlan
                    )
            }
            EditMode::SameSizeEdit => {
                self.precondition == EditPrecondition::ReplacementLengthsUnchanged
                    && self.output_length == OutputLengthGuarantee::Preserved
                    && self.relocation == RelocationObligation::PreserveExistingOffsets
            }
            EditMode::AllocationFittingEdit => {
                self.precondition == EditPrecondition::FitsExistingAllocation
                    && self.output_length == OutputLengthGuarantee::Preserved
                    && self.relocation == RelocationObligation::PreserveExistingOffsets
            }
            EditMode::Rebuild => {
                matches!(
                    self.precondition,
                    EditPrecondition::ExistingLayoutCannotBePreserved
                        | EditPrecondition::AnyMutation
                ) && self.output_length == OutputLengthGuarantee::MayChange
                    && matches!(
                        self.relocation,
                        RelocationObligation::NotApplicable
                            | RelocationObligation::RecomputeDirectoryOffsets
                            | RelocationObligation::ValidatedPointerRelocationPlan
                    )
            }
        }
    }
}
