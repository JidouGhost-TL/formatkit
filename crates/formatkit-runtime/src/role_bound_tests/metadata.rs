use super::*;
use formatkit_catalog::{
    NamespaceCollisionContract, NamespaceCollisionKind, NamespaceExecution, NamespaceMountContract,
    NamespaceMountInput, NamespaceMountStrategy, NamespaceProvider, NamespaceProviderMount,
};

fn module(
    contract: RoleBoundNamespaceContract,
    semantics: Option<NamespaceSemantics>,
) -> &'static FormatModule {
    let contract = Box::leak(Box::new(contract));
    let provider = Box::leak(Box::new(RoleBoundNamespaceProvider {
        strategy: contract.strategy,
        ..THREE_PROVIDER
    }));
    let operations = Box::leak(
        vec![ModuleOperation {
            executable: ExistingExecutableOperation::RoleBoundNamespace { contract, provider },
            ..THREE_OPERATION
        }]
        .into_boxed_slice(),
    );
    Box::leak(Box::new(FormatModule {
        operations,
        namespace_semantics: semantics.map(|value| &*Box::leak(Box::new(value))),
        ..THREE_MODULE
    }))
}

fn rejects_metadata(module: &'static FormatModule) {
    for result in [
        ModuleCatalog::new([module]),
        ModuleCatalog::with_namespace_projection([module], []),
    ] {
        assert_eq!(
            result.err().unwrap(),
            ModuleCatalogError::InvalidSupportCatalog
        );
    }
}

#[test]
fn omitted_role_bound_operations_validate_every_oracle_and_corpus_presence() {
    let invalid = CargoTestOracle::lib("formatkit-runtime", "");
    for contract in [
        RoleBoundNamespaceContract {
            parser_parity_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            independent_layout_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            budget_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            stability_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            dispatch_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            malformed_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            cli_oracle: invalid,
            ..THREE_CONTRACT
        },
        RoleBoundNamespaceContract {
            corpus_oracle: Some(ORACLE),
            ..THREE_CONTRACT
        },
    ] {
        rejects_metadata(module(contract, Some(SEMANTICS)));
    }
    static CORPUS_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
        capabilities: FormatCapabilities {
            corpus: true,
            ..PARSE_DESCRIPTOR.capabilities
        },
        ..PARSE_DESCRIPTOR
    };
    let missing = Box::leak(Box::new(FormatModule {
        descriptor: Some(&CORPUS_DESCRIPTOR),
        ..*module(THREE_CONTRACT, Some(SEMANTICS))
    }));
    rejects_metadata(missing);
    let bad_corpus = Box::leak(Box::new(FormatModule {
        descriptor: Some(&CORPUS_DESCRIPTOR),
        ..*module(
            RoleBoundNamespaceContract {
                corpus_oracle: Some(invalid),
                ..THREE_CONTRACT
            },
            Some(SEMANTICS),
        )
    }));
    rejects_metadata(bad_corpus);
    let valid: &'static FormatModule = Box::leak(Box::new(FormatModule {
        descriptor: Some(&CORPUS_DESCRIPTOR),
        ..*module(
            RoleBoundNamespaceContract {
                corpus_oracle: Some(ORACLE),
                ..THREE_CONTRACT
            },
            Some(SEMANTICS),
        )
    }));
    ModuleCatalog::with_namespace_projection([valid], []).unwrap();
}

#[test]
fn role_bound_execution_requires_declared_executable_namespace_semantics() {
    for semantics in [
        None,
        Some(NamespaceSemantics::non_namespace(THREE_MODULE.format)),
        Some(NamespaceSemantics {
            execution: NamespaceExecution::ExternalTransformRequired,
            ..SEMANTICS
        }),
    ] {
        rejects_metadata(module(THREE_CONTRACT, semantics));
    }
    let valid = module(
        RoleBoundNamespaceContract {
            strategy: NamespaceMountStrategy::WholeCarrier,
            ..THREE_CONTRACT
        },
        Some(SEMANTICS),
    );
    let catalog = ModuleCatalog::with_namespace_projection([valid], []).unwrap();
    let id = OperationId {
        format: valid.format,
        name: THREE_OPERATION.name,
    };
    let ExistingExecutableOperation::RoleBoundNamespace { provider, .. } =
        catalog.operation(id).unwrap().executable
    else {
        panic!("role-bound operation must survive")
    };
    assert!(provider
        .enforce_strategy(NamespaceMountStrategy::MetadataOnly)
        .is_err());
    assert!(provider
        .enforce_strategy(NamespaceMountStrategy::WholeCarrier)
        .is_ok());
    assert!(catalog.support().namespace_provider(valid.format).is_none());
    let mismatched_provider = Box::leak(Box::new(RoleBoundNamespaceProvider {
        strategy: NamespaceMountStrategy::MetadataOnly,
        ..*provider
    }));
    let mismatched_operations = Box::leak(
        vec![ModuleOperation {
            executable: ExistingExecutableOperation::RoleBoundNamespace {
                contract: match catalog.operation(id).unwrap().executable {
                    ExistingExecutableOperation::RoleBoundNamespace { contract, .. } => contract,
                    _ => unreachable!(),
                },
                provider: mismatched_provider,
            },
            ..THREE_OPERATION
        }]
        .into_boxed_slice(),
    );
    let mismatched: &'static FormatModule = Box::leak(Box::new(FormatModule {
        operations: mismatched_operations,
        ..*valid
    }));
    assert_eq!(
        ModuleCatalog::with_namespace_projection([mismatched], [])
            .err()
            .unwrap(),
        ModuleCatalogError::ContractProviderDisagreement(valid.format),
    );
}

const COLLISION: NamespaceCollisionContract = NamespaceCollisionContract {
    kind: NamespaceCollisionKind::SharedNamespaceGroup,
    group: "synthetic-role-group",
    ambiguity_oracle: ORACLE,
};

#[test]
fn role_bound_collision_metadata_and_distinct_format_count_are_validated() {
    for collision in [
        NamespaceCollisionContract {
            group: "",
            ..COLLISION
        },
        NamespaceCollisionContract {
            ambiguity_oracle: CargoTestOracle::lib("formatkit-runtime", ""),
            ..COLLISION
        },
        COLLISION,
    ] {
        rejects_metadata(module(
            RoleBoundNamespaceContract {
                collision: Some(collision),
                ..THREE_CONTRACT
            },
            Some(SEMANTICS),
        ));
    }
    let one = module(
        RoleBoundNamespaceContract {
            collision: Some(COLLISION),
            ..THREE_CONTRACT
        },
        Some(SEMANTICS),
    );
    let second = ModuleOperation {
        name: "second",
        ..one.operations[0]
    };
    let twice = Box::leak(Box::new(FormatModule {
        operations: Box::leak(vec![one.operations[0], second].into_boxed_slice()),
        ..*one
    }));
    rejects_metadata(twice);
    let peer = module(
        RoleBoundNamespaceContract {
            collision: Some(NamespaceCollisionContract {
                kind: NamespaceCollisionKind::PeerBoundary,
                ..COLLISION
            }),
            ..THREE_CONTRACT
        },
        Some(SEMANTICS),
    );
    ModuleCatalog::new([peer]).unwrap();
    let legacy = Box::leak(Box::new(FormatModule {
        state: ModuleState::Legacy,
        ..*one
    }));
    rejects_metadata(legacy);
}

const PEER_ID: FormatId = FormatId::new("synthetic-role-peer");
const PEER_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: PEER_ID,
    probes: &[formatkit_catalog::Probe::Structural {
        name: "synthetic role peer",
        check: |_| false,
    }],
    extension_hints: &[],
    ..PARSE_DESCRIPTOR
};
const PEER_CONTRACT: NamespaceMountContract = NamespaceMountContract {
    id: PEER_ID,
    input: NamespaceMountInput::SingleSource { role: "carrier" },
    strategy: NamespaceMountStrategy::MetadataOnly,
    parser_parity_oracle: ORACLE,
    independent_layout_oracle: ORACLE,
    budget_oracle: ORACLE,
    stability_oracle: ORACLE,
    dispatch_oracle: ORACLE,
    malformed_oracle: ORACLE,
    collision: Some(COLLISION),
    cli_oracle: ORACLE,
    corpus_oracle: None,
};
fn peer_mount(
    source: Arc<dyn RangeSource>,
    _: &mut formatkit_core::ReadBudget,
) -> Result<Box<dyn IndexedNamespace>> {
    Ok(Box::new(StoredRangeNamespace::without_raw_names(
        source,
        vec![],
        StoredRangeNamespaceLimits {
            max_entries: 1,
            max_name_bytes: 1,
            max_total_name_bytes: 1,
        },
    )?))
}
const PEER_PROVIDER: NamespaceProvider = NamespaceProvider {
    id: PEER_ID,
    owner: OWNER,
    input: PEER_CONTRACT.input,
    strategy: PEER_CONTRACT.strategy,
    mount: NamespaceProviderMount::Single(peer_mount),
    source_probe: None,
    work_source_probe: None,
    early_probe_prefix: None,
};
const PEER_SCHEMA: InputSchema<'static> = InputSchema {
    forms: &[InputForm {
        name: "single",
        bytes: &[ByteRole::one("carrier")],
        selectors: &[],
    }],
    relationships: &[],
};
const PEER_OPERATION: ModuleOperation = ModuleOperation {
    name: "mount-peer",
    input_schema: &PEER_SCHEMA,
    executable: ExistingExecutableOperation::Namespace {
        contract: &PEER_CONTRACT,
        provider: &PEER_PROVIDER,
    },
    ..THREE_OPERATION
};
static PEER_MODULE: FormatModule = FormatModule {
    format: PEER_ID,
    state: ModuleState::Legacy,
    descriptor: Some(&PEER_DESCRIPTOR),
    namespace_semantics: Some(&NamespaceSemantics::carrier(
        PEER_ID,
        NamespaceAddressing::DirectRanges,
    )),
    operations: &[PEER_OPERATION],
    ..THREE_MODULE
};

#[test]
fn collision_groups_include_ordinary_and_role_bound_owners_without_fake_defaults() {
    let role = module(
        RoleBoundNamespaceContract {
            collision: Some(COLLISION),
            ..THREE_CONTRACT
        },
        Some(SEMANTICS),
    );
    let peer_id = OperationId {
        format: PEER_ID,
        name: PEER_OPERATION.name,
    };
    for modules in [[role, &PEER_MODULE], [&PEER_MODULE, role]] {
        ModuleCatalog::new(modules).unwrap();
        for selected in [vec![], vec![peer_id]] {
            let catalog =
                ModuleCatalog::with_namespace_projection(modules, selected.clone()).unwrap();
            assert!(catalog
                .operation(OperationId {
                    format: role.format,
                    name: THREE_OPERATION.name
                })
                .is_some());
            assert_eq!(
                catalog.support().namespace_provider(PEER_ID).is_some(),
                !selected.is_empty()
            );
            assert!(catalog.support().namespace_provider(role.format).is_none());
        }
    }
    let conflict = module(
        RoleBoundNamespaceContract {
            collision: Some(NamespaceCollisionContract {
                kind: NamespaceCollisionKind::PeerBoundary,
                ..COLLISION
            }),
            ..THREE_CONTRACT
        },
        Some(SEMANTICS),
    );
    assert_eq!(
        ModuleCatalog::with_namespace_projection([conflict, &PEER_MODULE], [])
            .err()
            .unwrap(),
        ModuleCatalogError::InvalidSupportCatalog,
    );
}
