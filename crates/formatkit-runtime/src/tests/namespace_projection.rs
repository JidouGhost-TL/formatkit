use std::sync::Arc;

use formatkit_catalog::{ByteInput, SourceEvidenceRange, SourceProbeOutcome};
use formatkit_catalog::{NamespaceCollisionContract, NamespaceCollisionKind};
use formatkit_core::{
    MemoryRangeSource, NamespaceEntry, SourceBindings, StoredRangeNamespace,
    StoredRangeNamespaceLimits, WorkBudget, WorkLimits,
};

use super::*;

const PROJECTION_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    category: Category::Data,
    probes: &[Probe::Structural {
        name: "synthetic projection-left",
        check: |_| false,
    }],
    extension_hints: &[],
    ..PARSE_NAMESPACE_DESCRIPTOR
};
static PROJECTION_BASE: FormatModule = FormatModule {
    descriptor: Some(&PROJECTION_DESCRIPTOR),
    ..PARSE_NAMESPACE_MODULE
};

const LEFT_ID: OperationId = OperationId {
    format: crate::synthetic::ID_B38504826C7B,
    name: "left",
};
const RIGHT_ID: OperationId = OperationId {
    format: crate::synthetic::ID_B38504826C7B,
    name: "right",
};
const RIGHT_SCHEMA: InputSchema<'static> = InputSchema {
    forms: &[InputForm {
        name: "right",
        bytes: NAMESPACE_ROLES,
        selectors: &[],
    }],
    relationships: &[],
};

fn mount_named(name: &str, source: Arc<dyn RangeSource>) -> Result<Box<dyn IndexedNamespace>> {
    let size = source.size();
    Ok(Box::new(StoredRangeNamespace::without_raw_names(
        source,
        vec![NamespaceEntry {
            name: Some(name.into()),
            offset: 0,
            size,
        }],
        StoredRangeNamespaceLimits {
            max_entries: 1,
            max_name_bytes: 5,
            max_total_name_bytes: 5,
        },
    )?))
}
fn mount_left(
    source: Arc<dyn RangeSource>,
    _: &mut ReadBudget,
) -> Result<Box<dyn IndexedNamespace>> {
    mount_named("left", source)
}
fn mount_right(
    source: Arc<dyn RangeSource>,
    _: &mut ReadBudget,
) -> Result<Box<dyn IndexedNamespace>> {
    mount_named("right", source)
}

fn bound_named(
    name: &str,
    sources: &SourceBindings,
    bound: &BoundInputs,
) -> Result<SourceProbeOutcome<Box<dyn IndexedNamespace>>> {
    let handle = bound.single_source("carrier")?;
    let source = sources.source(handle)?.clone();
    let size = source.size();
    Ok(SourceProbeOutcome::Match {
        prepared: mount_named(name, source)?,
        evidence: vec![SourceEvidenceRange {
            role: "carrier",
            source: handle.clone(),
            range: 0..size,
        }],
    })
}
fn bound_left(
    sources: &SourceBindings,
    bound: &BoundInputs,
    _: &[u8],
    _: &mut WorkBudget,
) -> Result<SourceProbeOutcome<Box<dyn IndexedNamespace>>> {
    bound_named("left", sources, bound)
}
fn bound_right(
    sources: &SourceBindings,
    bound: &BoundInputs,
    _: &[u8],
    _: &mut WorkBudget,
) -> Result<SourceProbeOutcome<Box<dyn IndexedNamespace>>> {
    bound_named("right", sources, bound)
}

const LEFT_PROVIDER: NamespaceProvider = NamespaceProvider {
    mount: NamespaceProviderMount::Single(mount_left),
    ..MATCHED_PROVIDER
};
const RIGHT_PROVIDER: NamespaceProvider = NamespaceProvider {
    strategy: NamespaceMountStrategy::WholeCarrier,
    mount: NamespaceProviderMount::Single(mount_right),
    ..MATCHED_PROVIDER
};
const RIGHT_CONTRACT: NamespaceMountContract = NamespaceMountContract {
    strategy: NamespaceMountStrategy::WholeCarrier,
    ..NAMESPACE_CONTRACT
};
const LEFT: ModuleOperation = ModuleOperation {
    name: "left",
    bound_namespace: Some(bound_left),
    executable: ExistingExecutableOperation::Namespace {
        contract: &NAMESPACE_CONTRACT,
        provider: &LEFT_PROVIDER,
    },
    ..MATCHED_NAMESPACE
};
const RIGHT: ModuleOperation = ModuleOperation {
    name: "right",
    input_schema: &RIGHT_SCHEMA,
    bound_namespace: Some(bound_right),
    executable: ExistingExecutableOperation::Namespace {
        contract: &RIGHT_CONTRACT,
        provider: &RIGHT_PROVIDER,
    },
    ..MATCHED_NAMESPACE
};
static FORWARD: FormatModule = FormatModule {
    operations: &[LEFT, RIGHT],
    ..PROJECTION_BASE
};
static REVERSE: FormatModule = FormatModule {
    operations: &[RIGHT, LEFT],
    ..PROJECTION_BASE
};

fn source() -> Arc<dyn RangeSource> {
    Arc::new(MemoryRangeSource::new(
        b"abcd".to_vec(),
        "synthetic projection source",
    ))
}

#[test]
fn embedded_only_work_namespace_has_the_same_owner_for_selected_and_empty_projection() {
    const EMBEDDED: EmbeddedFormatSupport = EmbeddedFormatSupport {
        id: LEFT_ID.format,
        detectable_carrier: None,
        family: FormatFamilyId::new("synthetic-projection-family"),
        decoder: "owner-a",
        context: ContextRequirement::ExplicitSelection,
        local_discriminator: "synthetic-projection-context",
        dialect_group: None,
        typed_context: true,
        capabilities: PROJECTION_DESCRIPTOR.capabilities,
        corpus_evidence: None,
    };
    fn mount_work<'budget>(
        source: Arc<dyn RangeSource>,
        budget: &'budget mut WorkBudget,
    ) -> Result<formatkit_catalog::WorkMountedNamespace<'budget>> {
        Ok(formatkit_catalog::WorkMountedNamespace {
            namespace: mount_named("left", source)?,
            resident: budget.reserve_resident(0)?,
        })
    }
    const PROVIDER: NamespaceProvider = NamespaceProvider {
        mount: NamespaceProviderMount::WorkSingle(mount_work),
        ..LEFT_PROVIDER
    };
    const OPERATION: ModuleOperation = ModuleOperation {
        bound_namespace: None,
        executable: ExistingExecutableOperation::Namespace {
            contract: &NAMESPACE_CONTRACT,
            provider: &PROVIDER,
        },
        ..LEFT
    };
    static MODULE: FormatModule = FormatModule {
        descriptor: None,
        embedded_support: Some(&EMBEDDED),
        operations: &[OPERATION],
        ..PROJECTION_BASE
    };
    ModuleCatalog::new([&MODULE]).unwrap();
    for selected in [vec![LEFT_ID], vec![]] {
        let catalog =
            ModuleCatalog::with_namespace_projection([&MODULE], selected.clone()).unwrap();
        let view = catalog.support().get(LEFT_ID.format).unwrap();
        assert!(view.detectable.is_none());
        assert_eq!(view.decoder(), Some("owner-a"));
        assert!(catalog.operation(LEFT_ID).is_some());
        assert_eq!(view.namespace_provider.is_some(), !selected.is_empty());
        if !selected.is_empty() {
            let mut budget = WorkBudget::new(WorkLimits::unlimited());
            let mounted = view
                .namespace_provider
                .unwrap()
                .mount_single_work(source(), &mut budget)
                .unwrap();
            assert_eq!(mounted.namespace.entries()[0].name.as_deref(), Some("left"));
        }
    }
}

#[test]
fn canonical_projection_indices_reject_out_of_range_and_duplicate_format_defaults() {
    let support = || {
        ModuleCatalog::with_namespace_projection([&FORWARD], [])
            .unwrap()
            .support()
            .clone()
    };
    let pairs = [
        (&NAMESPACE_CONTRACT, &LEFT_PROVIDER),
        (&RIGHT_CONTRACT, &RIGHT_PROVIDER),
    ];
    assert!(matches!(
        support().with_namespace_operation_projection(pairs, [2]),
        Err(formatkit_catalog::SupportCatalogError::InvalidNamespaceProjectionIndex(2))
    ));
    for indices in [[0, 0], [0, 1]] {
        assert!(
            matches!(support().with_namespace_operation_projection(pairs, indices), Err(formatkit_catalog::SupportCatalogError::InvalidNamespaceMountContract(id)) if id == LEFT_ID.format)
        );
    }
    let projected = support()
        .with_namespace_operation_projection(pairs, [1])
        .unwrap();
    assert_eq!(
        projected
            .get(LEFT_ID.format)
            .unwrap()
            .namespace_mount
            .unwrap()
            .strategy,
        RIGHT_CONTRACT.strategy
    );
}

#[test]
fn explicit_default_preserves_both_named_mounts_and_their_schemas_in_either_order() {
    for module in [&FORWARD, &REVERSE] {
        for (default, name) in [(LEFT_ID, "left"), (RIGHT_ID, "right")] {
            let catalog = ModuleCatalog::with_namespace_projection([module], [default]).unwrap();
            assert_eq!(
                catalog.operations().map(|(id, _)| id).collect::<Vec<_>>(),
                [LEFT_ID, RIGHT_ID]
            );
            assert!(std::ptr::eq(
                catalog.operation(LEFT_ID).unwrap().input_schema,
                &NAMESPACE_SCHEMA
            ));
            assert!(std::ptr::eq(
                catalog.operation(RIGHT_ID).unwrap().input_schema,
                &RIGHT_SCHEMA
            ));
            let mounted = catalog
                .support()
                .mount_namespace_single(
                    default.format,
                    source(),
                    NamespaceMountStrategy::WholeCarrier,
                    &mut ReadBudget::unlimited(),
                )
                .unwrap();
            assert_eq!(mounted.entries()[0].name.as_deref(), Some(name));
            let mut sources = SourceBindings::new();
            let handle = sources.register(source());
            for (id, name) in [(LEFT_ID, "left"), (RIGHT_ID, "right")] {
                let operation = catalog.operation(id).unwrap();
                let bound = operation
                    .input_schema
                    .bind(
                        &sources,
                        &[ByteInput {
                            role: "carrier",
                            source: &handle,
                        }],
                        &[],
                    )
                    .unwrap();
                let mut budget = WorkBudget::new(WorkLimits::unlimited());
                let outcome = catalog
                    .invoke_bound_namespace(id, &sources, &bound, b"abcd", &mut budget)
                    .unwrap()
                    .unwrap();
                let SourceProbeOutcome::Match { prepared, .. } = outcome else {
                    panic!("synthetic match must remain callable")
                };
                assert_eq!(prepared.entries()[0].name.as_deref(), Some(name));
            }
        }
    }
}

#[test]
fn empty_projection_excludes_all_legacy_defaults_without_hiding_operations() {
    let catalog = ModuleCatalog::with_namespace_projection([&FORWARD], []).unwrap();
    assert!(catalog
        .support()
        .namespace_provider(LEFT_ID.format)
        .is_none());
    assert!(catalog.support().namespace_mount_contracts().is_empty());
    assert!(catalog.operation(LEFT_ID).is_some());
    assert!(catalog.operation(RIGHT_ID).is_some());
    assert!(catalog
        .support()
        .mount_namespace_single(
            LEFT_ID.format,
            source(),
            NamespaceMountStrategy::MetadataOnly,
            &mut ReadBudget::unlimited()
        )
        .is_err());
    assert_eq!(
        ModuleCatalog::new([&FORWARD]).err().unwrap(),
        ModuleCatalogError::InvalidSupportCatalog
    );
}

#[test]
fn projection_rejects_unknown_nonnamespace_and_duplicate_format_selections() {
    for id in [
        OperationId {
            name: "absent",
            ..LEFT_ID
        },
        OperationId {
            format: FormatId::new("synthetic-absent"),
            ..LEFT_ID
        },
    ] {
        assert_eq!(
            ModuleCatalog::with_namespace_projection([&FORWARD], [id])
                .err()
                .unwrap(),
            ModuleCatalogError::UnknownNamespaceProjection(id)
        );
    }
    let leaf = OperationId {
        format: MODULE_A.format,
        name: LEAF_OPERATION.name,
    };
    assert_eq!(
        ModuleCatalog::with_namespace_projection([&MODULE_A], [leaf])
            .err()
            .unwrap(),
        ModuleCatalogError::InvalidNamespaceProjection(leaf)
    );
    for selected in [[LEFT_ID, RIGHT_ID], [RIGHT_ID, LEFT_ID], [LEFT_ID, LEFT_ID]] {
        assert_eq!(
            ModuleCatalog::with_namespace_projection([&FORWARD], selected)
                .err()
                .unwrap(),
            ModuleCatalogError::DuplicateNamespaceProjection(LEFT_ID.format)
        );
    }
}

#[test]
fn excluding_a_default_does_not_skip_contract_or_schema_validation() {
    assert_eq!(
        ModuleCatalog::with_namespace_projection([&MISMATCHED_MODULE], [])
            .err()
            .unwrap(),
        ModuleCatalogError::ContractProviderDisagreement(MISMATCHED_MODULE.format)
    );
    const BAD_SCHEMA: InputSchema<'static> = InputSchema {
        forms: &[],
        relationships: &[],
    };
    const BAD: ModuleOperation = ModuleOperation {
        input_schema: &BAD_SCHEMA,
        ..RIGHT
    };
    static BAD_MODULE: FormatModule = FormatModule {
        operations: &[LEFT, BAD],
        ..PROJECTION_BASE
    };
    assert_eq!(
        ModuleCatalog::with_namespace_projection([&BAD_MODULE], [LEFT_ID])
            .err()
            .unwrap(),
        ModuleCatalogError::InvalidInputSchema(RIGHT_ID)
    );
}

#[test]
fn unselected_proofs_and_probe_policies_use_canonical_validation() {
    const NO_PROOF: NamespaceMountContract = NamespaceMountContract {
        budget_oracle: CargoTestOracle::lib("formatkit-runtime", ""),
        ..RIGHT_CONTRACT
    };
    const UNPROVED: ModuleOperation = ModuleOperation {
        executable: ExistingExecutableOperation::Namespace {
            contract: &NO_PROOF,
            provider: &RIGHT_PROVIDER,
        },
        ..RIGHT
    };
    static UNPROVED_MODULE: FormatModule = FormatModule {
        operations: &[LEFT, UNPROVED],
        ..PROJECTION_BASE
    };
    const BAD_PROBE: NamespaceProvider = NamespaceProvider {
        early_probe_prefix: Some(b"x"),
        ..RIGHT_PROVIDER
    };
    const BAD_PROBE_OPERATION: ModuleOperation = ModuleOperation {
        executable: ExistingExecutableOperation::Namespace {
            contract: &RIGHT_CONTRACT,
            provider: &BAD_PROBE,
        },
        ..RIGHT
    };
    static BAD_PROBE_MODULE: FormatModule = FormatModule {
        operations: &[LEFT, BAD_PROBE_OPERATION],
        ..PROJECTION_BASE
    };
    for module in [&UNPROVED_MODULE, &BAD_PROBE_MODULE] {
        for projection in [vec![LEFT_ID], vec![]] {
            assert_eq!(
                ModuleCatalog::with_namespace_projection([module], projection)
                    .err()
                    .unwrap(),
                ModuleCatalogError::InvalidSupportCatalog
            );
        }
    }
}

const SHARED_COLLISION: NamespaceCollisionContract = NamespaceCollisionContract {
    kind: NamespaceCollisionKind::SharedNamespaceGroup,
    group: "synthetic-shared-group",
    ambiguity_oracle: ORACLE,
};
const LEFT_SHARED_CONTRACT: NamespaceMountContract = NamespaceMountContract {
    collision: Some(SHARED_COLLISION),
    ..NAMESPACE_CONTRACT
};
const RIGHT_SHARED_CONTRACT: NamespaceMountContract = NamespaceMountContract {
    collision: Some(SHARED_COLLISION),
    ..RIGHT_CONTRACT
};
const LEFT_SHARED: ModuleOperation = ModuleOperation {
    executable: ExistingExecutableOperation::Namespace {
        contract: &LEFT_SHARED_CONTRACT,
        provider: &LEFT_PROVIDER,
    },
    ..LEFT
};
const RIGHT_SHARED: ModuleOperation = ModuleOperation {
    executable: ExistingExecutableOperation::Namespace {
        contract: &RIGHT_SHARED_CONTRACT,
        provider: &RIGHT_PROVIDER,
    },
    ..RIGHT
};
static SHARED_MODULE: FormatModule = FormatModule {
    operations: &[LEFT_SHARED, RIGHT_SHARED],
    ..PROJECTION_BASE
};

const SECOND_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: MODULE_B.format,
    decoder: Some("owner-b"),
    probes: &[Probe::Structural {
        name: "synthetic projection-right",
        check: |_| false,
    }],
    extension_hints: &[],
    ..PROJECTION_DESCRIPTOR
};
const SECOND_CONTRACT: NamespaceMountContract = NamespaceMountContract {
    id: MODULE_B.format,
    ..LEFT_SHARED_CONTRACT
};
const SECOND_PROVIDER: NamespaceProvider = NamespaceProvider {
    id: MODULE_B.format,
    owner: "owner-b",
    ..LEFT_PROVIDER
};
const SECOND_OPERATION: ModuleOperation = ModuleOperation {
    owner: "owner-b",
    executable: ExistingExecutableOperation::Namespace {
        contract: &SECOND_CONTRACT,
        provider: &SECOND_PROVIDER,
    },
    ..LEFT
};
const SECOND_SEMANTICS: NamespaceSemantics =
    NamespaceSemantics::carrier(MODULE_B.format, NamespaceAddressing::DirectRanges);
static SECOND_MODULE: FormatModule = FormatModule {
    format: MODULE_B.format,
    owner: "owner-b",
    descriptor: Some(&SECOND_DESCRIPTOR),
    namespace_semantics: Some(&SECOND_SEMANTICS),
    operations: &[SECOND_OPERATION],
    ..PROJECTION_BASE
};

#[test]
fn shared_collision_groups_count_formats_and_do_not_hide_unselected_conflicts() {
    assert_eq!(
        ModuleCatalog::with_namespace_projection([&SHARED_MODULE], [])
            .err()
            .unwrap(),
        ModuleCatalogError::InvalidSupportCatalog
    );
    let second_id = OperationId {
        format: SECOND_MODULE.format,
        name: SECOND_OPERATION.name,
    };
    for modules in [
        [&SHARED_MODULE, &SECOND_MODULE],
        [&SECOND_MODULE, &SHARED_MODULE],
    ] {
        for projection in [
            vec![],
            vec![LEFT_ID],
            vec![second_id],
            vec![LEFT_ID, second_id],
        ] {
            let catalog =
                ModuleCatalog::with_namespace_projection(modules, projection.clone()).unwrap();
            assert!(catalog.operation(LEFT_ID).is_some());
            assert!(catalog.operation(RIGHT_ID).is_some());
            assert!(catalog.operation(second_id).is_some());
            for id in &projection {
                assert_eq!(
                    catalog
                        .support()
                        .get(id.format)
                        .unwrap()
                        .namespace_mount
                        .unwrap()
                        .collision,
                    Some(SHARED_COLLISION)
                );
            }
        }
    }
    const CONFLICT_CONTRACT: NamespaceMountContract = NamespaceMountContract {
        collision: Some(NamespaceCollisionContract {
            kind: NamespaceCollisionKind::PeerBoundary,
            ..SHARED_COLLISION
        }),
        ..RIGHT_CONTRACT
    };
    const CONFLICT_OPERATION: ModuleOperation = ModuleOperation {
        executable: ExistingExecutableOperation::Namespace {
            contract: &CONFLICT_CONTRACT,
            provider: &RIGHT_PROVIDER,
        },
        ..RIGHT
    };
    static CONFLICT_MODULE: FormatModule = FormatModule {
        operations: &[LEFT_SHARED, CONFLICT_OPERATION],
        ..PROJECTION_BASE
    };
    assert_eq!(
        ModuleCatalog::with_namespace_projection(
            [&CONFLICT_MODULE, &SECOND_MODULE],
            [LEFT_ID, second_id]
        )
        .err()
        .unwrap(),
        ModuleCatalogError::InvalidSupportCatalog
    );
}

#[test]
fn explicit_legacy_projection_does_not_promote_legacy_operations_to_strict_dispatch() {
    static LEGACY: FormatModule = FormatModule {
        state: ModuleState::Legacy,
        ..FORWARD
    };
    let catalog = ModuleCatalog::with_namespace_projection([&LEGACY], [RIGHT_ID]).unwrap();
    assert!(catalog.operation(LEFT_ID).is_none());
    assert!(catalog.operation(RIGHT_ID).is_none());
    assert_eq!(catalog.legacy_module_count(), 1);
    assert_eq!(catalog.legacy_operation_count(), 2);
    assert!(catalog
        .support()
        .namespace_provider(RIGHT_ID.format)
        .is_some());
}

fn runner<'user>(
    _: &SourceBindings,
    _: &BoundInputs,
    _: &[u8],
    _: &mut WorkBudget,
    _: WorkRunnerOp,
    _: &'user mut WorkRunnerUser<'user>,
) -> Result<()> {
    Err(Error::Unsupported("synthetic runner invocation".into()))
}
const RUNNER: ModuleOperation = ModuleOperation {
    bound_namespace: None,
    executable: ExistingExecutableOperation::RunnerNamespace {
        contract: &RIGHT_CONTRACT,
        provider: &RIGHT_PROVIDER,
        runner,
    },
    ..RIGHT
};
static WITH_RUNNER: FormatModule = FormatModule {
    operations: &[LEFT, RUNNER],
    ..PROJECTION_BASE
};

#[test]
fn runner_namespace_can_be_an_explicit_default_without_erasing_its_callback() {
    let catalog = ModuleCatalog::with_namespace_projection([&WITH_RUNNER], [RIGHT_ID]).unwrap();
    assert!(matches!(
        catalog.operation(RIGHT_ID).unwrap().executable,
        ExistingExecutableOperation::RunnerNamespace { .. }
    ));
    assert!(catalog.operation(LEFT_ID).is_some());
    let mounted = catalog
        .support()
        .mount_namespace_single(
            RIGHT_ID.format,
            source(),
            NamespaceMountStrategy::WholeCarrier,
            &mut ReadBudget::unlimited(),
        )
        .unwrap();
    assert_eq!(mounted.entries()[0].name.as_deref(), Some("right"));
}
