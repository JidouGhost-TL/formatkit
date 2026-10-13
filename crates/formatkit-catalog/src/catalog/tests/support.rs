use super::super::*;
use super::fixtures::*;
use crate::FormatId;
use std::sync::atomic::{AtomicUsize, Ordering};

static LOCAL_PROBE_CALLS: AtomicUsize = AtomicUsize::new(0);

fn local_probe(bytes: &[u8]) -> bool {
    LOCAL_PROBE_CALLS.fetch_add(1, Ordering::SeqCst);
    bytes.starts_with(b"TEST")
}

static LOCAL_PROBES: &[Probe] = &[Probe::Structural {
    name: "synthetic-local-structure",
    check: local_probe,
}];

#[test]
fn support_catalog_rejects_invalid_detectable_and_embedded_ids() {
    const INVALID: FormatId = FormatId::new("owner_bad");
    assert_eq!(
        SupportCatalog::new([descriptor(INVALID, 10, MAGIC, &[])], []).unwrap_err(),
        SupportCatalogError::InvalidFormatId(INVALID)
    );

    assert_eq!(
        SupportCatalog::new([], [embedded(INVALID)]).unwrap_err(),
        SupportCatalogError::InvalidFormatId(INVALID)
    );

    let mut invalid_carrier = embedded(crate::synthetic::ID_B38504826C7B);
    invalid_carrier.detectable_carrier = Some(INVALID);
    assert_eq!(
        SupportCatalog::new([], [invalid_carrier]).unwrap_err(),
        SupportCatalogError::InvalidFormatId(INVALID)
    );
}

#[test]
fn support_catalog_rejects_detectable_and_embedded_duplicate_ids() {
    let mut detectable = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    detectable.decoder = Some("image-owner");
    detectable.capabilities = embedded(crate::synthetic::ID_B38504826C7B).capabilities;
    assert_eq!(
        SupportCatalog::new([detectable], [embedded(crate::synthetic::ID_B38504826C7B)])
            .unwrap_err(),
        SupportCatalogError::DuplicateId(crate::synthetic::ID_B38504826C7B)
    );

    let mut overlay = embedded(crate::synthetic::ID_B38504826C7B);
    overlay.detectable_carrier = Some(crate::synthetic::ID_B38504826C7B);
    assert_eq!(
        SupportCatalog::new([detectable], [overlay]).unwrap_err(),
        SupportCatalogError::InvalidContext(crate::synthetic::ID_B38504826C7B),
        "an overlay must agree with the detectable descriptor's requirement"
    );
    let mut contextual = detectable;
    contextual.requirement = DecoderRequirement::AuthenticatedCarrierMember;
    assert!(SupportCatalog::new([contextual], [overlay]).is_ok());
}

#[test]
fn support_catalog_rejects_overlay_decoder_or_capability_drift() {
    let mut detectable = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    detectable.decoder = Some("image-owner");
    detectable.requirement = DecoderRequirement::AuthenticatedCarrierMember;
    detectable.capabilities = embedded(crate::synthetic::ID_B38504826C7B).capabilities;

    let mut overlay = embedded(crate::synthetic::ID_B38504826C7B);
    overlay.detectable_carrier = Some(crate::synthetic::ID_B38504826C7B);
    overlay.decoder = "other-decoder";
    assert_eq!(
        SupportCatalog::new([detectable], [overlay]).unwrap_err(),
        SupportCatalogError::InvalidCapabilities(crate::synthetic::ID_B38504826C7B)
    );

    overlay.decoder = "image-owner";
    overlay.capabilities.decode = false;
    assert_eq!(
        SupportCatalog::new([detectable], [overlay]).unwrap_err(),
        SupportCatalogError::InvalidCapabilities(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn support_catalog_rejects_duplicate_detectable_inputs() {
    let detectable = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    assert_eq!(
        SupportCatalog::new([detectable, detectable], []).unwrap_err(),
        SupportCatalogError::DuplicateId(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn operation_local_descriptors_stay_out_of_global_detection() {
    let id = crate::synthetic::ID_B38504826C7B;
    let mut local = descriptor(id, 10, LOCAL_PROBES, &["local"]);
    local.decoder = Some("synthetic-local-decoder");
    local.capabilities.parse = true;

    LOCAL_PROBE_CALLS.store(0, Ordering::SeqCst);
    let catalog =
        SupportCatalog::with_operation_local_descriptors([], [local], [], [], [], []).unwrap();
    assert!(catalog.detectable().is_empty());
    assert_eq!(catalog.operation_local_descriptors().len(), 1);
    assert_eq!(catalog.operation_local_descriptors()[0].id, id);
    assert_eq!(
        catalog.operation_local_descriptor(id).map(|row| row.id),
        Some(id)
    );
    assert!(std::ptr::eq(
        catalog.operation_local_descriptor(id).unwrap().probes,
        LOCAL_PROBES,
    ));
    assert_eq!(
        catalog.operation_local_descriptor(id).unwrap().decoder,
        local.decoder
    );
    assert!(
        catalog.get(id).is_none(),
        "legacy global/context lookup changed"
    );
    assert!(catalog.embedded().is_empty());
    let global = FormatCatalog::new(catalog.detectable().iter().copied()).unwrap();
    assert!(global.descriptors().is_empty());
    assert!(global
        .identify(DetectionContext::from_bytes(b"TEST"))
        .is_none());
    let markdown = catalog.capability_markdown();
    assert!(markdown.contains("| synthetic-id-b38504826c7b | explicit-only |"));
    assert!(!markdown.contains("| synthetic-id-b38504826c7b | global |"));
    assert!(markdown.contains("| synthetic-local-decoder |"));
    assert_eq!(
        LOCAL_PROBE_CALLS.load(Ordering::SeqCst),
        0,
        "support composition, lookup, global identification, or rendering invoked the local probe"
    );
}

#[test]
fn operation_local_descriptors_reject_identity_collisions() {
    let id = crate::synthetic::ID_B38504826C7B;
    let local = descriptor(id, 10, &[], &[]);

    assert_eq!(
        SupportCatalog::with_operation_local_descriptors([], [local, local], [], [], [], [],)
            .unwrap_err(),
        SupportCatalogError::DuplicateId(id),
    );
    assert_eq!(
        SupportCatalog::with_operation_local_descriptors(
            [descriptor(id, 10, MAGIC, &[])],
            [local],
            [],
            [],
            [],
            [],
        )
        .unwrap_err(),
        SupportCatalogError::DuplicateId(id),
        "a local descriptor must not shadow a global descriptor",
    );
    assert_eq!(
        SupportCatalog::with_operation_local_descriptors([], [local], [embedded(id)], [], [], [],)
            .unwrap_err(),
        SupportCatalogError::DuplicateId(id),
        "a local descriptor must not impersonate an embedded overlay",
    );
}

#[test]
fn operation_local_descriptors_enforce_capability_implications() {
    let id = crate::synthetic::ID_B38504826C7B;
    let mut impossible = descriptor(id, 10, &[], &[]);
    impossible.capabilities.decode = true;
    assert_eq!(
        SupportCatalog::with_operation_local_descriptors([], [impossible], [], [], [], [])
            .unwrap_err(),
        SupportCatalogError::InvalidCapabilities(id),
    );

    impossible.capabilities.parse = true;
    impossible.capabilities.round_trip = true;
    impossible.capabilities.write = true;
    assert_eq!(
        SupportCatalog::with_operation_local_descriptors([], [impossible], [], [], [], [])
            .unwrap_err(),
        SupportCatalogError::InvalidCapabilities(id),
    );
}

#[test]
fn operation_local_and_unrelated_embedded_metadata_coexist_without_fabrication() {
    let local_id = crate::synthetic::ID_B38504826C7B;
    let embedded_id = crate::synthetic::ID_44895F217E35;
    let local = descriptor(local_id, 10, &[], &[]);
    let mut context = embedded(embedded_id);
    context.local_discriminator = "second-image-body";
    let catalog =
        SupportCatalog::with_operation_local_descriptors([], [local], [context], [], [], [])
            .unwrap();

    assert!(catalog.get(local_id).is_none());
    let embedded_view = catalog.get(embedded_id).unwrap();
    assert!(embedded_view.detectable.is_none());
    assert_eq!(embedded_view.embedded, Some(&context));
    assert_eq!(
        catalog
            .operation_local_descriptor(local_id)
            .map(|row| row.id),
        Some(local_id)
    );
}

#[test]
fn support_catalog_rejects_invalid_family_and_context_contracts() {
    for family in [
        FormatFamilyId::new(""),
        FormatFamilyId::new("Uppercase"),
        FormatFamilyId::new("-leading"),
        FormatFamilyId::new("trailing-"),
        FormatFamilyId::new("double..dot"),
        FormatFamilyId::new("under_score"),
    ] {
        let mut invalid = embedded(crate::synthetic::ID_B38504826C7B);
        invalid.family = family;
        invalid.context = ContextRequirement::AuthenticatedCarrierMember { family };
        assert_eq!(
            SupportCatalog::new([], [invalid]).unwrap_err(),
            SupportCatalogError::InvalidFamily(crate::synthetic::ID_B38504826C7B)
        );
    }

    const OWNER_FAMILY: FormatFamilyId = FormatFamilyId::new("owner.chunk-db-v1");
    assert!(OWNER_FAMILY.is_valid());
    let mut owner = embedded(crate::synthetic::ID_B38504826C7B);
    owner.family = OWNER_FAMILY;
    owner.context = ContextRequirement::AuthenticatedCarrierMember {
        family: OWNER_FAMILY,
    };
    assert!(SupportCatalog::new([], [owner]).is_ok());

    let mut wrong_family = embedded(crate::synthetic::ID_B38504826C7B);
    wrong_family.context = ContextRequirement::ParentAddressSpace {
        family: FormatFamilyId::new("synthetic-family-4"),
    };
    assert_eq!(
        SupportCatalog::new([], [wrong_family]).unwrap_err(),
        SupportCatalogError::InvalidContext(crate::synthetic::ID_B38504826C7B)
    );

    let mut detached = embedded(crate::synthetic::ID_B38504826C7B);
    detached.typed_context = false;
    assert_eq!(
        SupportCatalog::new([], [detached]).unwrap_err(),
        SupportCatalogError::InvalidContext(crate::synthetic::ID_B38504826C7B)
    );

    let mut empty_role = embedded(crate::synthetic::ID_B38504826C7B);
    empty_role.family = FormatFamilyId::new("synthetic-family-1");
    empty_role.context = ContextRequirement::PairedData { role: "" };
    assert_eq!(
        SupportCatalog::new([], [empty_role]).unwrap_err(),
        SupportCatalogError::InvalidContext(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn support_catalog_enforces_capabilities_and_corpus_evidence() {
    let mut impossible = embedded(crate::synthetic::ID_B38504826C7B);
    impossible.capabilities.parse = false;
    assert_eq!(
        SupportCatalog::new([], [impossible]).unwrap_err(),
        SupportCatalogError::InvalidCapabilities(crate::synthetic::ID_B38504826C7B)
    );

    let mut corpus = embedded(crate::synthetic::ID_B38504826C7B);
    corpus.capabilities.corpus = true;
    assert_eq!(
        SupportCatalog::new([], [corpus]).unwrap_err(),
        SupportCatalogError::MissingCorpusEvidence(crate::synthetic::ID_B38504826C7B)
    );
    corpus.corpus_evidence = Some(CorpusEvidence {
        handler: "image-owner-image",
        sample_floor: 1,
    });
    assert!(SupportCatalog::new([], [corpus]).is_ok());

    let mut editor = embedded(crate::synthetic::ID_B38504826C7B);
    editor.capabilities.edit = true;
    let support = SupportCatalog::new([], [editor]).unwrap();
    assert!(support.capability_markdown().contains(
        "| synthetic-id-b38504826c7b | context-only | synthetic-family-0 | authenticated-carrier-member | image-owner | — | unclassified | unclassified |"
    ));

    let mut writer = editor;
    writer.capabilities.write = true;
    let support = SupportCatalog::new([], [writer]).unwrap();
    assert!(support
        .capability_markdown()
        .contains("| unclassified | yes | yes | yes | yes |"));
}

#[test]
fn support_catalog_requires_explicit_groups_for_local_collisions() {
    let first = embedded(crate::synthetic::ID_B38504826C7B);
    let second = embedded(crate::synthetic::ID_44895F217E35);
    assert_eq!(
        SupportCatalog::new([], [first, second]).unwrap_err(),
        SupportCatalogError::DuplicateLocalDiscriminator {
            first: crate::synthetic::ID_B38504826C7B,
            second: crate::synthetic::ID_44895F217E35,
        }
    );
    let mut first = first;
    let mut second = second;
    first.dialect_group = Some("image-owner-image-body");
    second.dialect_group = Some("image-owner-image-body");
    assert!(SupportCatalog::new([], [first, second]).is_ok());
}

#[test]
fn support_catalog_is_sorted_and_retains_context() {
    let mut tim = embedded(crate::synthetic::ID_B38504826C7B);
    tim.local_discriminator = "synthetic-id-b38504826c7b";
    let mut second = embedded(crate::synthetic::ID_44895F217E35);
    second.local_discriminator = "synthetic-id-44895f217e35";
    let support = SupportCatalog::new([], [tim, second]).unwrap();
    assert_eq!(
        support
            .embedded()
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        [
            crate::synthetic::ID_44895F217E35,
            crate::synthetic::ID_B38504826C7B
        ]
    );
    let matrix = support.capability_markdown();
    assert!(
        matrix
            .find("| synthetic-id-44895f217e35 | context-only |")
            .unwrap()
            < matrix
                .find("| synthetic-id-b38504826c7b | context-only |")
                .unwrap()
    );
    assert!(matrix.contains(
        "| synthetic-id-44895f217e35 | context-only | synthetic-family-0 | authenticated-carrier-member | image-owner | — | — | — | — | — | — | — |"
    ));
    assert_eq!(
        support
            .get(crate::synthetic::ID_44895F217E35)
            .unwrap()
            .category_label(),
        "context-only"
    );
}

#[test]
fn support_lookup_merges_detectable_context_and_writer_metadata() {
    let mut detectable = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    detectable.decoder = Some("image-owner");
    detectable.requirement = DecoderRequirement::AuthenticatedCarrierMember;
    let mut overlay = embedded(crate::synthetic::ID_B38504826C7B);
    overlay.detectable_carrier = Some(crate::synthetic::ID_B38504826C7B);
    overlay.capabilities.edit = true;
    detectable.capabilities = overlay.capabilities;
    const WRITER_EDIT: EditContract = EditContract {
        mode: EditMode::ConfinedEdit,
        scope: OperationScope::Format,
        precondition: EditPrecondition::SemanticFieldsOnly,
        output_length: OutputLengthGuarantee::Preserved,
        relocation: RelocationObligation::NotApplicable,
        mutation_oracle: CargoTestOracle::lib("formatkit-catalog", "tests::mutation"),
        parse_after_write_oracle: CargoTestOracle::lib("formatkit-catalog", "tests::reparse"),
    };
    let writer = WriterContract {
        id: crate::synthetic::ID_B38504826C7B,
        reproduction: None,
        edits: &[WRITER_EDIT],
        authoring: None,
    };
    let support = SupportCatalog::with_writer_contracts([detectable], [overlay], [writer]).unwrap();
    let merged = support.get(crate::synthetic::ID_B38504826C7B).unwrap();
    assert!(merged.detectable.is_some());
    assert!(merged.embedded.is_some());
    assert_eq!(
        merged.family(),
        Some(FormatFamilyId::new("synthetic-family-0"))
    );
    assert_eq!(
        merged.context(),
        Some(ContextRequirement::AuthenticatedCarrierMember {
            family: FormatFamilyId::new("synthetic-family-0")
        })
    );
    assert_eq!(merged.writer, Some(&writer));
    assert!(merged.capabilities().edit);
    assert_eq!(merged.decoder(), Some("image-owner"));
    assert!(support.get(crate::synthetic::ID_44895F217E35).is_none());
}

#[test]
fn product_namespace_support_requires_explicit_valid_archive_semantics() {
    let mut archive = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    archive.category = crate::Category::Archive;
    archive.decoder = Some("test");
    archive.capabilities.parse = true;

    assert_eq!(
        SupportCatalog::with_namespace_support([archive], [], [], [], [], []).unwrap_err(),
        SupportCatalogError::MissingNamespaceSemantics(crate::synthetic::ID_B38504826C7B)
    );

    let invalid = NamespaceSemantics {
        id: crate::synthetic::ID_B38504826C7B,
        kind: NamespaceKind::Carrier,
        addressing: None,
        execution: NamespaceExecution::Native,
    };
    assert_eq!(
        SupportCatalog::with_namespace_support([archive], [], [], [invalid], [], []).unwrap_err(),
        SupportCatalogError::InvalidNamespaceSemantics(crate::synthetic::ID_B38504826C7B)
    );

    let terminal = NamespaceSemantics::non_namespace(crate::synthetic::ID_B38504826C7B);
    let support =
        SupportCatalog::with_namespace_support([archive], [], [], [terminal], [], []).unwrap();
    assert_eq!(support.namespace_semantics(), [terminal]);
    assert_eq!(
        support
            .get(crate::synthetic::ID_B38504826C7B)
            .and_then(|view| view.namespace_semantics),
        Some(&terminal)
    );
}

#[test]
fn non_namespace_declarations_cannot_acquire_mount_contracts() {
    const ORACLE: CargoTestOracle =
        CargoTestOracle::lib("formatkit-catalog", "tests::namespace_oracle");
    let mut archive = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    archive.category = crate::Category::Archive;
    archive.decoder = Some("test");
    archive.capabilities.parse = true;
    let contract = NamespaceMountContract {
        id: crate::synthetic::ID_B38504826C7B,
        input: NamespaceMountInput::SingleSource { role: "archive" },
        strategy: NamespaceMountStrategy::MetadataOnly,
        parser_parity_oracle: ORACLE,
        independent_layout_oracle: ORACLE,
        budget_oracle: ORACLE,
        stability_oracle: ORACLE,
        dispatch_oracle: ORACLE,
        malformed_oracle: ORACLE,
        collision: None,
        cli_oracle: ORACLE,
        corpus_oracle: None,
    };
    assert_eq!(
        SupportCatalog::with_namespace_support(
            [archive],
            [],
            [],
            [NamespaceSemantics::non_namespace(
                crate::synthetic::ID_B38504826C7B
            )],
            [contract],
            [namespace_provider(
                crate::synthetic::ID_B38504826C7B,
                contract.input
            )],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceSemantics(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn context_only_namespace_topology_is_validated_without_global_detection() {
    const ORACLE: CargoTestOracle =
        CargoTestOracle::lib("formatkit-catalog", "tests::namespace_oracle");
    let paired_input = NamespaceMountInput::PairedSources {
        directory_role: "index",
        content_role: "body",
    };
    let contract = NamespaceMountContract {
        id: crate::synthetic::ID_B38504826C7B,
        input: paired_input,
        strategy: NamespaceMountStrategy::MetadataOnly,
        parser_parity_oracle: ORACLE,
        independent_layout_oracle: ORACLE,
        budget_oracle: ORACLE,
        stability_oracle: ORACLE,
        dispatch_oracle: ORACLE,
        malformed_oracle: ORACLE,
        collision: None,
        cli_oracle: ORACLE,
        corpus_oracle: None,
    };
    let mut support = embedded(crate::synthetic::ID_B38504826C7B);
    support.context = ContextRequirement::PairedData { role: "body" };
    let mut provider = namespace_provider(crate::synthetic::ID_B38504826C7B, paired_input);
    provider.owner = support.decoder;
    let catalog = SupportCatalog::with_namespace_support(
        [],
        [support],
        [],
        [NamespaceSemantics::carrier(
            crate::synthetic::ID_B38504826C7B,
            NamespaceAddressing::DirectRanges,
        )],
        [contract],
        [provider],
    )
    .unwrap();
    assert!(catalog.detectable().is_empty());
    assert_eq!(catalog.embedded(), [support]);
    assert!(catalog
        .namespace_provider(crate::synthetic::ID_B38504826C7B)
        .is_some());

    let single_input = NamespaceMountInput::SingleSource { role: "carrier" };
    let single_contract = NamespaceMountContract {
        input: single_input,
        ..contract
    };
    let mut explicit = embedded(crate::synthetic::ID_B38504826C7B);
    explicit.context = ContextRequirement::ExplicitSelection;
    let mut single_provider = namespace_provider(crate::synthetic::ID_B38504826C7B, single_input);
    single_provider.owner = explicit.decoder;
    let explicit_catalog = SupportCatalog::with_namespace_support(
        [],
        [explicit],
        [],
        [NamespaceSemantics::carrier(
            crate::synthetic::ID_B38504826C7B,
            NamespaceAddressing::DirectRanges,
        )],
        [single_contract],
        [single_provider],
    )
    .unwrap();
    assert!(explicit_catalog.detectable().is_empty());
    assert_eq!(explicit_catalog.embedded(), [explicit]);
    assert!(explicit_catalog
        .namespace_provider(crate::synthetic::ID_B38504826C7B)
        .is_some());
    assert_eq!(
        SupportCatalog::with_namespace_support(
            [],
            [explicit],
            [],
            [NamespaceSemantics::carrier(
                crate::synthetic::ID_B38504826C7B,
                NamespaceAddressing::DirectRanges,
            )],
            [contract],
            [provider],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    assert_eq!(
        SupportCatalog::with_namespace_support(
            [],
            [],
            [],
            [NamespaceSemantics::carrier(
                crate::synthetic::ID_B38504826C7B,
                NamespaceAddressing::DirectRanges,
            )],
            [contract],
            [provider],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceSemantics(crate::synthetic::ID_B38504826C7B)
    );

    let mut authenticated = embedded(crate::synthetic::ID_B38504826C7B);
    authenticated.context = ContextRequirement::AuthenticatedCarrierMember {
        family: authenticated.family,
    };
    assert_eq!(
        SupportCatalog::with_namespace_support(
            [],
            [authenticated],
            [],
            [NamespaceSemantics::carrier(
                crate::synthetic::ID_B38504826C7B,
                NamespaceAddressing::DirectRanges,
            )],
            [contract],
            [provider],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut wrong_owner = provider;
    wrong_owner.owner = "wrong";
    assert_eq!(
        SupportCatalog::with_namespace_support(
            [],
            [support],
            [],
            [NamespaceSemantics::carrier(
                crate::synthetic::ID_B38504826C7B,
                NamespaceAddressing::DirectRanges,
            )],
            [contract],
            [wrong_owner],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn support_catalog_rejects_invalid_early_probe_prefix_contracts() {
    const ORACLE: CargoTestOracle =
        CargoTestOracle::lib("formatkit-catalog", "tests::namespace_oracle");
    let mut archive = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    archive.category = crate::Category::Archive;
    archive.decoder = Some("test");
    archive.capabilities.parse = true;
    let contract = NamespaceMountContract {
        id: crate::synthetic::ID_B38504826C7B,
        input: NamespaceMountInput::SingleSource { role: "archive" },
        strategy: NamespaceMountStrategy::MetadataOnly,
        parser_parity_oracle: ORACLE,
        independent_layout_oracle: ORACLE,
        budget_oracle: ORACLE,
        stability_oracle: ORACLE,
        dispatch_oracle: ORACLE,
        malformed_oracle: ORACLE,
        collision: None,
        cli_oracle: ORACLE,
        corpus_oracle: None,
    };
    for prefix in [b"".as_slice(), &[0; MAX_EARLY_NAMESPACE_PROBE_BYTES + 1]] {
        let mut provider = namespace_provider(crate::synthetic::ID_B38504826C7B, contract.input);
        provider.source_probe = Some(rejecting_source_probe);
        provider.early_probe_prefix = Some(prefix);
        assert_eq!(
            SupportCatalog::with_contracts([archive], [], [], [contract], [provider]).unwrap_err(),
            SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
        );
    }

    let mut provider = namespace_provider(crate::synthetic::ID_B38504826C7B, contract.input);
    provider.early_probe_prefix = Some(b"TEST");
    assert_eq!(
        SupportCatalog::with_contracts([archive], [], [], [contract], [provider]).unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn external_transform_namespaces_are_explicit_and_cannot_claim_static_providers() {
    const ORACLE: CargoTestOracle =
        CargoTestOracle::lib("formatkit-catalog", "tests::namespace_oracle");
    let mut archive = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    archive.category = crate::Category::Archive;
    archive.decoder = Some("test");
    archive.capabilities.parse = true;
    let declaration = NamespaceSemantics::external_transform_carrier(
        crate::synthetic::ID_B38504826C7B,
        NamespaceAddressing::SelectiveTransform,
    );
    let support =
        SupportCatalog::with_namespace_support([archive], [], [], [declaration], [], []).unwrap();
    assert_eq!(support.namespace_semantics(), [declaration]);

    let contract = NamespaceMountContract {
        id: crate::synthetic::ID_B38504826C7B,
        input: NamespaceMountInput::SingleSource { role: "archive" },
        strategy: NamespaceMountStrategy::MetadataOnly,
        parser_parity_oracle: ORACLE,
        independent_layout_oracle: ORACLE,
        budget_oracle: ORACLE,
        stability_oracle: ORACLE,
        dispatch_oracle: ORACLE,
        malformed_oracle: ORACLE,
        collision: None,
        cli_oracle: ORACLE,
        corpus_oracle: None,
    };
    assert_eq!(
        SupportCatalog::with_namespace_support(
            [archive],
            [],
            [],
            [declaration],
            [contract],
            [namespace_provider(
                crate::synthetic::ID_B38504826C7B,
                contract.input
            )],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceSemantics(crate::synthetic::ID_B38504826C7B)
    );
}
