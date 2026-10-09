use super::super::*;
use super::fixtures::*;
use crate::FormatId;

#[test]
fn namespace_contracts_enforce_source_shape_and_executable_collision_evidence() {
    const ORACLE: CargoTestOracle =
        CargoTestOracle::lib("formatkit-catalog", "tests::namespace_oracle");
    let contract = |id| NamespaceMountContract {
        id,
        input: NamespaceMountInput::SingleSource { role: "archive" },
        strategy: NamespaceMountStrategy::MetadataOnly,
        parser_parity_oracle: ORACLE,
        independent_layout_oracle: ORACLE,
        budget_oracle: ORACLE,
        stability_oracle: ORACLE,
        dispatch_oracle: ORACLE,
        malformed_oracle: ORACLE,
        collision: Some(NamespaceCollisionContract {
            kind: NamespaceCollisionKind::SharedNamespaceGroup,
            group: "shared-prefix",
            ambiguity_oracle: ORACLE,
        }),
        cli_oracle: ORACLE,
        corpus_oracle: None,
    };
    let invalid_id = FormatId::new("namespace_bad");
    assert_eq!(
        SupportCatalog::with_contracts([], [], [], [contract(invalid_id)], []).unwrap_err(),
        SupportCatalogError::InvalidFormatId(invalid_id)
    );
    assert_eq!(
        SupportCatalog::with_contracts(
            [],
            [],
            [],
            [],
            [namespace_provider(
                invalid_id,
                NamespaceMountInput::SingleSource { role: "archive" },
            )],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidFormatId(invalid_id)
    );
    let mut first = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    first.capabilities.parse = true;
    first.decoder = Some("test");
    let mut second = descriptor(FormatId::PNG, 10, STRUCTURAL, &[]);
    second.capabilities.parse = true;
    second.decoder = Some("test");

    let catalog = SupportCatalog::with_contracts(
        [first, second],
        [],
        [],
        [
            contract(crate::synthetic::ID_B38504826C7B),
            contract(FormatId::PNG),
        ],
        [
            namespace_provider(
                crate::synthetic::ID_B38504826C7B,
                contract(crate::synthetic::ID_B38504826C7B).input,
            ),
            namespace_provider(FormatId::PNG, contract(FormatId::PNG).input),
        ],
    )
    .unwrap();
    assert_eq!(catalog.namespace_mount_contracts().len(), 2);
    assert_eq!(catalog.namespace_providers().len(), 2);
    assert_eq!(catalog.namespace_mount_oracles(), [ORACLE]);
    assert_eq!(catalog.contract_oracles(), [ORACLE]);
    assert_eq!(
        catalog
            .get(crate::synthetic::ID_B38504826C7B)
            .and_then(|view| view.namespace_mount)
            .map(|mount| mount.input),
        Some(NamespaceMountInput::SingleSource { role: "archive" })
    );
    assert!(catalog.capability_markdown().contains(
        "| synthetic-id-b38504826c7b | global | — | none | test | verified@single-source(archive);metadata-only |"
    ));

    let singleton = SupportCatalog::with_contracts(
        [first],
        [],
        [],
        [contract(crate::synthetic::ID_B38504826C7B)],
        [namespace_provider(
            crate::synthetic::ID_B38504826C7B,
            contract(crate::synthetic::ID_B38504826C7B).input,
        )],
    );
    assert_eq!(
        singleton.unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut peer_contract = contract(crate::synthetic::ID_B38504826C7B);
    peer_contract.collision.as_mut().unwrap().kind = NamespaceCollisionKind::PeerBoundary;
    let peer_catalog = SupportCatalog::with_contracts(
        [first],
        [],
        [],
        [peer_contract],
        [namespace_provider(
            crate::synthetic::ID_B38504826C7B,
            peer_contract.input,
        )],
    )
    .unwrap();
    assert_eq!(peer_catalog.namespace_mount_contracts().len(), 1);

    let mut mixed_kind = contract(FormatId::PNG);
    mixed_kind.collision.as_mut().unwrap().kind = NamespaceCollisionKind::PeerBoundary;
    let mixed_group = SupportCatalog::with_contracts(
        [first, second],
        [],
        [],
        [contract(crate::synthetic::ID_B38504826C7B), mixed_kind],
        [
            namespace_provider(
                crate::synthetic::ID_B38504826C7B,
                contract(crate::synthetic::ID_B38504826C7B).input,
            ),
            namespace_provider(FormatId::PNG, mixed_kind.input),
        ],
    );
    assert_eq!(
        mixed_group.unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(FormatId::PNG)
    );

    let mut wrong_input = contract(crate::synthetic::ID_B38504826C7B);
    wrong_input.input = NamespaceMountInput::PairedSources {
        directory_role: "index",
        content_role: "image",
    };
    assert_eq!(
        SupportCatalog::with_contracts([first], [], [], [wrong_input], []).unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut paired = first;
    paired.requirement = DecoderRequirement::PairedData;
    let mut paired_contract = contract(crate::synthetic::ID_B38504826C7B);
    paired_contract.input = NamespaceMountInput::PairedSources {
        directory_role: "index",
        content_role: "image",
    };
    paired_contract.collision = None;
    let paired_catalog = SupportCatalog::with_contracts(
        [paired],
        [],
        [],
        [paired_contract],
        [namespace_provider(
            crate::synthetic::ID_B38504826C7B,
            paired_contract.input,
        )],
    )
    .unwrap();
    assert_eq!(
        paired_catalog
            .namespace_provider(crate::synthetic::ID_B38504826C7B)
            .unwrap()
            .strategy,
        NamespaceMountStrategy::MetadataOnly
    );
    let directory: std::sync::Arc<dyn formatkit_core::RangeSource> = std::sync::Arc::new(
        formatkit_core::MemoryRangeSource::new(Vec::new(), "directory"),
    );
    let content: std::sync::Arc<dyn formatkit_core::RangeSource> = std::sync::Arc::new(
        formatkit_core::MemoryRangeSource::new(Vec::new(), "content"),
    );
    let reversed = PairedNamespaceSources::for_input(
        NamespaceMountInput::PairedSources {
            directory_role: "image",
            content_role: "index",
        },
        directory,
        content,
    )
    .unwrap();
    let error = paired_catalog
        .mount_namespace_pair(
            crate::synthetic::ID_B38504826C7B,
            reversed,
            NamespaceMountStrategy::MetadataOnly,
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .err()
        .expect("reversed named roles unexpectedly reached the provider callback");
    assert!(error.to_string().contains("expected"));

    let mut selected_contract = paired_contract;
    selected_contract.input = NamespaceMountInput::SelectedPairedSources {
        directory_role: "index",
        content_role: "pack",
        selector_role: "pack-path",
    };
    let selected_catalog = SupportCatalog::with_contracts(
        [paired],
        [],
        [],
        [selected_contract],
        [namespace_provider(
            crate::synthetic::ID_B38504826C7B,
            selected_contract.input,
        )],
    )
    .unwrap();
    assert!(selected_catalog
        .capability_markdown()
        .contains("verified@selected-paired-sources(index,pack;pack-path);metadata-only"));
    let directory = std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        Vec::new(),
        "directory",
    ));
    let content = std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        Vec::new(),
        "content",
    ));
    assert!(PairedNamespaceSources::for_input(
        selected_contract.input,
        directory.clone(),
        content.clone(),
    )
    .is_err());
    assert!(PairedNamespaceSources::for_selected_input(
        paired_contract.input,
        directory.clone(),
        content.clone(),
        "data/pack/main.dat",
    )
    .is_err());
    assert!(PairedNamespaceSources::for_selected_input(
        selected_contract.input,
        directory.clone(),
        content.clone(),
        "",
    )
    .is_err());
    assert!(PairedNamespaceSources::for_input_with_selector(
        selected_contract.input,
        directory.clone(),
        content.clone(),
        None,
    )
    .is_err());
    assert!(PairedNamespaceSources::for_input_with_selector(
        paired_contract.input,
        directory.clone(),
        content.clone(),
        Some("unexpected"),
    )
    .is_err());
    let selected = PairedNamespaceSources::for_input_with_selector(
        selected_contract.input,
        directory,
        content,
        Some("data/pack/main.dat"),
    )
    .unwrap();
    assert_eq!(
        selected.selector(),
        Some(("pack-path", "data/pack/main.dat"))
    );
    let error = selected_catalog
        .mount_namespace_pair(
            crate::synthetic::ID_B38504826C7B,
            selected,
            NamespaceMountStrategy::MetadataOnly,
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .err()
        .expect("selected sources unexpectedly succeeded through rejecting provider");
    assert!(error.to_string().contains("test provider"));

    let mut hybrid_contract = contract(crate::synthetic::ID_B38504826C7B);
    hybrid_contract.input = NamespaceMountInput::SingleOrSelectedPairedSources {
        single_role: "pack",
        directory_role: "index",
        content_role: "physical-pack",
        selector_role: "pack-path",
    };
    hybrid_contract.collision = None;
    let hybrid_catalog = SupportCatalog::with_contracts(
        [first],
        [],
        [],
        [hybrid_contract],
        [namespace_provider(
            crate::synthetic::ID_B38504826C7B,
            hybrid_contract.input,
        )],
    )
    .unwrap();
    assert!(hybrid_catalog.capability_markdown().contains(
        "verified@single-or-selected-paired-sources(pack|index,physical-pack;pack-path);metadata-only"
    ));
    let source = std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        Vec::new(),
        "synthetic-id-2e6a2810b7c3",
    ));
    assert!(hybrid_catalog
        .mount_namespace_single(
            crate::synthetic::ID_B38504826C7B,
            source,
            NamespaceMountStrategy::MetadataOnly,
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .err()
        .expect("hybrid single source unexpectedly succeeded")
        .to_string()
        .contains("test provider"));
    let directory = std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        Vec::new(),
        "directory",
    ));
    let content = std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        Vec::new(),
        "content",
    ));
    let hybrid_sources = PairedNamespaceSources::for_input_with_selector(
        hybrid_contract.input,
        directory,
        content,
        Some("data/pack/main.apk"),
    )
    .unwrap();
    assert!(hybrid_catalog
        .mount_namespace_pair(
            crate::synthetic::ID_B38504826C7B,
            hybrid_sources,
            NamespaceMountStrategy::MetadataOnly,
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .err()
        .expect("hybrid selected pair unexpectedly succeeded")
        .to_string()
        .contains("test provider"));

    let mut colliding_hybrid_role = hybrid_contract;
    colliding_hybrid_role.input = NamespaceMountInput::SingleOrSelectedPairedSources {
        single_role: "index",
        directory_role: "index",
        content_role: "physical-pack",
        selector_role: "pack-path",
    };
    assert_eq!(
        SupportCatalog::with_contracts([first], [], [], [colliding_hybrid_role], []).unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut duplicate_selector_role = selected_contract;
    duplicate_selector_role.input = NamespaceMountInput::SelectedPairedSources {
        directory_role: "index",
        content_role: "synthetic-id-2e6a2810b7c3",
        selector_role: "synthetic-id-2e6a2810b7c3",
    };
    assert_eq!(
        SupportCatalog::with_contracts([paired], [], [], [duplicate_selector_role], [])
            .unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut duplicate_roles = paired_contract;
    duplicate_roles.input = NamespaceMountInput::PairedSources {
        directory_role: "image",
        content_role: "image",
    };
    assert_eq!(
        SupportCatalog::with_contracts([paired], [], [], [duplicate_roles], []).unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let mut invalid_oracle = contract(crate::synthetic::ID_B38504826C7B);
    invalid_oracle.collision = None;
    invalid_oracle.malformed_oracle = CargoTestOracle::lib("formatkit-catalog", " ");
    assert_eq!(
        SupportCatalog::with_contracts([first], [], [], [invalid_oracle], []).unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );

    let no_provider = SupportCatalog::with_contracts(
        [first],
        [],
        [],
        [NamespaceMountContract {
            collision: None,
            ..contract(crate::synthetic::ID_B38504826C7B)
        }],
        [],
    );
    assert_eq!(
        no_provider.unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );

    let mut wrong_owner = namespace_provider(
        crate::synthetic::ID_B38504826C7B,
        contract(crate::synthetic::ID_B38504826C7B).input,
    );
    wrong_owner.owner = "somewhere-else";
    assert_eq!(
        SupportCatalog::with_contracts(
            [first],
            [],
            [],
            [NamespaceMountContract {
                collision: None,
                ..contract(crate::synthetic::ID_B38504826C7B)
            }],
            [wrong_owner],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );

    let mut wrong_strategy = namespace_provider(
        crate::synthetic::ID_B38504826C7B,
        contract(crate::synthetic::ID_B38504826C7B).input,
    );
    wrong_strategy.strategy = NamespaceMountStrategy::WholeCarrier;
    assert_eq!(
        SupportCatalog::with_contracts(
            [first],
            [],
            [],
            [NamespaceMountContract {
                collision: None,
                ..contract(crate::synthetic::ID_B38504826C7B)
            }],
            [wrong_strategy],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );

    let wrong_shape = NamespaceProvider {
        mount: NamespaceProviderMount::Paired(rejecting_pair_mounter),
        ..namespace_provider(
            crate::synthetic::ID_B38504826C7B,
            contract(crate::synthetic::ID_B38504826C7B).input,
        )
    };
    assert_eq!(
        SupportCatalog::with_contracts(
            [first],
            [],
            [],
            [NamespaceMountContract {
                collision: None,
                ..contract(crate::synthetic::ID_B38504826C7B)
            }],
            [wrong_shape],
        )
        .unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn selected_single_source_requires_its_selector_on_every_mount_route() {
    const ORACLE: CargoTestOracle =
        CargoTestOracle::lib("formatkit-catalog", "tests::namespace_oracle");
    let input = NamespaceMountInput::SelectedSingleSource {
        role: "carrier",
        selector_role: "expected-id",
    };
    let contract = NamespaceMountContract {
        id: crate::synthetic::ID_B38504826C7B,
        input,
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
    let mut detected = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    detected.capabilities.parse = true;
    detected.decoder = Some("test");
    let provider = namespace_provider(crate::synthetic::ID_B38504826C7B, input);
    assert!(provider.supports_selected_single());
    assert!(!provider.supports_single());
    assert!(!provider.supports_pair());
    assert!(provider.mount_matches_input());
    let catalog =
        SupportCatalog::with_contracts([detected], [], [], [contract], [provider]).unwrap();
    assert!(catalog
        .capability_markdown()
        .contains("verified@selected-single-source(carrier;expected-id);metadata-only"));

    let mut explicit = embedded(crate::synthetic::ID_B38504826C7B);
    explicit.context = ContextRequirement::ExplicitSelection;
    let mut explicit_provider = namespace_provider(crate::synthetic::ID_B38504826C7B, input);
    explicit_provider.owner = explicit.decoder;
    let explicit_catalog = SupportCatalog::with_namespace_support(
        [],
        [explicit],
        [],
        [NamespaceSemantics::carrier(
            crate::synthetic::ID_B38504826C7B,
            NamespaceAddressing::DirectRanges,
        )],
        [contract],
        [explicit_provider],
    )
    .unwrap();
    assert!(explicit_catalog.detectable().is_empty());
    assert!(explicit_catalog
        .namespace_provider(crate::synthetic::ID_B38504826C7B)
        .is_some());

    let mut duplicate_selector = contract;
    duplicate_selector.input = NamespaceMountInput::SelectedSingleSource {
        role: "carrier",
        selector_role: "carrier",
    };
    assert_eq!(
        SupportCatalog::with_contracts([detected], [], [], [duplicate_selector], []).unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );
    let mut paired_descriptor = detected;
    paired_descriptor.requirement = DecoderRequirement::PairedData;
    assert_eq!(
        SupportCatalog::with_contracts([paired_descriptor], [], [], [contract], [provider])
            .unwrap_err(),
        SupportCatalogError::InvalidNamespaceMountContract(crate::synthetic::ID_B38504826C7B)
    );
    let weak_shape = NamespaceProvider {
        mount: NamespaceProviderMount::Single(rejecting_source_mounter),
        ..provider
    };
    assert_eq!(
        SupportCatalog::with_contracts([detected], [], [], [contract], [weak_shape],).unwrap_err(),
        SupportCatalogError::InvalidNamespaceProvider(crate::synthetic::ID_B38504826C7B)
    );

    let mut sources = formatkit_core::SourceBindings::new();
    let handle = sources.register(std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        vec![0u8; 4],
        "carrier",
    )));
    let bytes = [ByteInput {
        role: "carrier",
        source: &handle,
    }];
    assert!(input.bind(&sources, &bytes, &[]).is_err());
    assert!(input
        .bind(
            &sources,
            &bytes,
            &[SelectorInput {
                role: "wrong",
                value: "6",
            }],
        )
        .is_err());
    let bound = input
        .bind(
            &sources,
            &bytes,
            &[SelectorInput {
                role: "expected-id",
                value: "6",
            }],
        )
        .unwrap();
    assert_eq!(bound.form(), "single");
    assert_eq!(bound.selector("expected-id"), Some("6"));

    let source = sources.source(&handle).unwrap().clone();
    assert!(provider
        .mount_single(source.clone(), &mut formatkit_core::ReadBudget::unlimited())
        .err()
        .expect("selector-less single mount unexpectedly succeeded")
        .to_string()
        .contains("expected-id"));
    assert!(provider
        .mount_selected_single(
            source.clone(),
            "6",
            &mut formatkit_core::ReadBudget::unlimited()
        )
        .err()
        .expect("selected mount unexpectedly succeeded")
        .to_string()
        .contains("test provider"));
    assert!(catalog
        .mount_namespace_selected_single(
            crate::synthetic::ID_B38504826C7B,
            source.clone(),
            "6",
            NamespaceMountStrategy::MetadataOnly,
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .err()
        .expect("catalog selected mount unexpectedly succeeded")
        .to_string()
        .contains("test provider"));
    assert!(catalog
        .mount_namespace_single(
            crate::synthetic::ID_B38504826C7B,
            source.clone(),
            NamespaceMountStrategy::WholeCarrier,
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .is_err());
    assert!(provider
        .mount_inputs(
            &sources,
            &bytes,
            &[SelectorInput {
                role: "expected-id",
                value: "6",
            }],
            &mut formatkit_core::ReadBudget::unlimited(),
        )
        .err()
        .expect("bound selected mount unexpectedly succeeded")
        .to_string()
        .contains("test provider"));
    assert!(provider
        .mount_inputs(
            &sources,
            &bytes,
            &[],
            &mut formatkit_core::ReadBudget::unlimited()
        )
        .is_err());
    let directory: std::sync::Arc<dyn formatkit_core::RangeSource> = std::sync::Arc::new(
        formatkit_core::MemoryRangeSource::new(Vec::new(), "directory"),
    );
    let content: std::sync::Arc<dyn formatkit_core::RangeSource> = std::sync::Arc::new(
        formatkit_core::MemoryRangeSource::new(Vec::new(), "content"),
    );
    assert!(
        PairedNamespaceSources::for_input_with_selector(input, directory, content, Some("6"))
            .is_err()
    );
}

#[test]
fn namespace_mount_strategy_is_an_enforceable_policy_ceiling() {
    assert!(NamespaceMountStrategy::MetadataOnly.permits(NamespaceMountStrategy::MetadataOnly));
    assert!(
        !NamespaceMountStrategy::MetadataOnly.permits(NamespaceMountStrategy::SelectiveTransform)
    );
    assert!(
        NamespaceMountStrategy::SelectiveTransform.permits(NamespaceMountStrategy::MetadataOnly)
    );
    assert!(
        !NamespaceMountStrategy::SelectiveTransform.permits(NamespaceMountStrategy::WholeCarrier)
    );
    assert!(NamespaceMountStrategy::WholeCarrier.permits(NamespaceMountStrategy::WholeCarrier));

    let mut provider = namespace_provider(
        crate::synthetic::ID_B38504826C7B,
        NamespaceMountInput::SingleSource { role: "archive" },
    );
    provider.strategy = NamespaceMountStrategy::WholeCarrier;
    let error = provider
        .enforce_strategy(NamespaceMountStrategy::SelectiveTransform)
        .unwrap_err();
    assert!(error.to_string().contains("whole-carrier"));
    assert!(error.to_string().contains("selective-transform"));
}
