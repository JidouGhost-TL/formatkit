use super::super::*;
use super::fixtures::*;
use crate::FormatId;

#[test]
fn writer_contract_enforces_operation_specific_obligations() {
    let mut item = embedded(crate::synthetic::ID_B38504826C7B);
    item.capabilities.edit = true;
    const MUTATION: CargoTestOracle = CargoTestOracle::lib("formatkit-catalog", "tests::mutation");
    const REPARSE: CargoTestOracle = CargoTestOracle::lib("formatkit-catalog", "tests::reparse");
    const VALID_EDIT: EditContract = EditContract {
        mode: EditMode::SameSizeEdit,
        scope: OperationScope::Format,
        precondition: EditPrecondition::ReplacementLengthsUnchanged,
        output_length: OutputLengthGuarantee::Preserved,
        relocation: RelocationObligation::PreserveExistingOffsets,
        mutation_oracle: MUTATION,
        parse_after_write_oracle: REPARSE,
    };
    let valid = WriterContract {
        id: crate::synthetic::ID_B38504826C7B,
        reproduction: None,
        edits: &[VALID_EDIT],
        authoring: None,
    };
    let invalid_identity = WriterContract {
        id: FormatId::new("writer_bad"),
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [], [invalid_identity]).unwrap_err(),
        SupportCatalogError::InvalidFormatId(FormatId::new("writer_bad"))
    );
    let catalog = SupportCatalog::with_writer_contracts([], [item], [valid]).unwrap();
    assert_eq!(catalog.writer_contracts(), &[valid]);
    assert_eq!(catalog.writer_oracles(), [MUTATION, REPARSE]);
    assert_eq!(
        MUTATION.cargo_args(),
        [
            "test",
            "-p",
            "formatkit-catalog",
            "--lib",
            "tests::mutation",
            "--",
            "--exact",
        ]
    );
    assert_eq!(
        CargoTestOracle::integration("archive-owner", "reemit_oracle", "faithful_reproduction")
            .cargo_args(),
        [
            "test",
            "-p",
            "archive-owner",
            "--test",
            "reemit_oracle",
            "faithful_reproduction",
            "--",
            "--exact",
        ]
    );

    let invalid = WriterContract {
        edits: &[EditContract {
            mode: EditMode::SameSizeEdit,
            scope: OperationScope::Format,
            precondition: EditPrecondition::ReplacementLengthsUnchanged,
            output_length: OutputLengthGuarantee::MayChange,
            relocation: RelocationObligation::PreserveExistingOffsets,
            mutation_oracle: MUTATION,
            parse_after_write_oracle: REPARSE,
        }],
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [invalid]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    const INVALID_SCOPE: EditContract = EditContract {
        scope: OperationScope::Dialect(DialectId::new(
            crate::synthetic::ID_B38504826C7B,
            "bad|scope",
        )),
        ..VALID_EDIT
    };
    let invalid_scope = WriterContract {
        edits: &[INVALID_SCOPE],
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [invalid_scope]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    const WRONG_OWNER_SCOPE: EditContract = EditContract {
        scope: OperationScope::Dialect(DialectId::new(FormatId::PNG, "canonical")),
        ..VALID_EDIT
    };
    let wrong_owner_scope = WriterContract {
        edits: &[WRONG_OWNER_SCOPE],
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [wrong_owner_scope]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    const DIALECT_ALPHA: EditContract = EditContract {
        scope: OperationScope::Dialect(DialectId::new(crate::synthetic::ID_B38504826C7B, "alpha")),
        ..VALID_EDIT
    };
    const DIALECT_BETA: EditContract = EditContract {
        scope: OperationScope::Dialect(DialectId::new(crate::synthetic::ID_B38504826C7B, "beta")),
        ..VALID_EDIT
    };
    let same_mode_for_distinct_dialects = WriterContract {
        edits: &[DIALECT_ALPHA, DIALECT_BETA],
        ..valid
    };
    assert!(
        SupportCatalog::with_writer_contracts([], [item], [same_mode_for_distinct_dialects])
            .is_ok()
    );

    const EMPTY_EVIDENCE: EditContract = EditContract {
        mutation_oracle: CargoTestOracle::lib("formatkit-catalog", "  "),
        ..VALID_EDIT
    };
    let empty_evidence = WriterContract {
        edits: &[EMPTY_EVIDENCE],
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [empty_evidence]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    const UNRESOLVABLE_EVIDENCE: EditContract = EditContract {
        mutation_oracle: CargoTestOracle::lib("--package", "tests::mutation"),
        ..VALID_EDIT
    };
    let unresolvable_evidence = WriterContract {
        edits: &[UNRESOLVABLE_EVIDENCE],
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [unresolvable_evidence]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    const CONFINED: EditContract = EditContract {
        mode: EditMode::ConfinedEdit,
        scope: OperationScope::Format,
        precondition: EditPrecondition::SemanticFieldsOnly,
        output_length: OutputLengthGuarantee::Preserved,
        relocation: RelocationObligation::NotApplicable,
        mutation_oracle: MUTATION,
        parse_after_write_oracle: REPARSE,
    };
    const REBUILD: EditContract = EditContract {
        mode: EditMode::Rebuild,
        scope: OperationScope::Format,
        precondition: EditPrecondition::AnyMutation,
        output_length: OutputLengthGuarantee::MayChange,
        relocation: RelocationObligation::RecomputeDirectoryOffsets,
        mutation_oracle: MUTATION,
        parse_after_write_oracle: REPARSE,
    };
    let reversed_modes = WriterContract {
        edits: &[REBUILD, CONFINED],
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [reversed_modes]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    let zero_operations = WriterContract {
        reproduction: None,
        edits: &[],
        authoring: None,
        ..valid
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([], [item], [zero_operations]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut detectable = descriptor(FormatId::PNG, 10, MAGIC, &[]);
    detectable.capabilities.parse = true;
    detectable.capabilities.edit = true;
    let detectable_contract = WriterContract {
        id: FormatId::PNG,
        reproduction: None,
        edits: &[EditContract {
            mode: EditMode::ConfinedEdit,
            scope: OperationScope::Format,
            precondition: EditPrecondition::SemanticFieldsOnly,
            output_length: OutputLengthGuarantee::Preserved,
            relocation: RelocationObligation::NotApplicable,
            mutation_oracle: MUTATION,
            parse_after_write_oracle: REPARSE,
        }],
        authoring: None,
    };
    let catalog =
        SupportCatalog::with_writer_contracts([detectable], [], [detectable_contract]).unwrap();
    assert_eq!(catalog.writer_contracts(), &[detectable_contract]);
    assert!(catalog.capability_markdown().contains(
        "| png | global | — | none | — | — | — | confined-edit | format | semantic-fields-only | preserved | n/a | — |"
    ));

    let mut authored = descriptor(FormatId::PNG, 10, MAGIC, &[]);
    authored.capabilities.parse = true;
    authored.capabilities.edit = true;
    authored.capabilities.write = true;
    let valid_authoring = WriterContract {
        id: FormatId::PNG,
        reproduction: Some(ReproductionContract {
            scope: OperationScope::Format,
            oracle: CargoTestOracle::integration("formatkit-catalog", "writer_oracle", "source"),
        }),
        edits: detectable_contract.edits,
        authoring: Some(AuthoringContract {
            output_scope: OperationScope::Format,
            parse_after_write_oracle: REPARSE,
            semantic_oracle: CargoTestOracle::lib("formatkit-catalog", "tests::semantic"),
            independent_extent_oracle: CargoTestOracle::lib("formatkit-catalog", "tests::extent"),
        }),
    };
    assert!(SupportCatalog::with_writer_contracts([authored], [], [valid_authoring]).is_ok());

    let mut author_only = authored;
    author_only.capabilities.edit = false;
    let author_only_contract = WriterContract {
        reproduction: None,
        edits: &[],
        ..valid_authoring
    };
    assert!(
        SupportCatalog::with_writer_contracts([author_only], [], [author_only_contract]).is_ok()
    );

    let empty_oracle = WriterContract {
        authoring: Some(AuthoringContract {
            independent_extent_oracle: CargoTestOracle::lib("formatkit-catalog", ""),
            ..valid_authoring.authoring.unwrap()
        }),
        ..valid_authoring
    };
    assert_eq!(
        SupportCatalog::with_writer_contracts([authored], [], [empty_oracle]).unwrap_err(),
        SupportCatalogError::InvalidWriterContract(FormatId::PNG)
    );
}
