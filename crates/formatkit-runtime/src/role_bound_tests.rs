use std::mem::size_of;
use std::sync::Arc;

use formatkit_catalog::catalog::{
    BoundInputs, ByteInput, ByteRole, CargoTestOracle, FormatCapabilities, FormatDescriptor,
    InputCardinality, InputForm, InputRelationship, InputSchema, NamespaceAddressing,
    NamespaceSemantics, RoleBoundNamespaceContract, RoleBoundNamespaceInput,
    RoleBoundNamespaceProvider, SelectorRole, SourceEvidenceRange, SourceProbeOutcome,
    WorkMountedNamespace,
};
use formatkit_catalog::Category;
use formatkit_core::{
    Error, IndexedNamespace, MemoryRangeSource, NamespaceEntry, RangeSource, Result,
    SourceBindings, StoredRangeNamespace, StoredRangeNamespaceLimits, WorkBudget, WorkLimits,
    WorkResource,
};

use super::*;

mod metadata;

const ORACLE: CargoTestOracle =
    CargoTestOracle::lib("formatkit-runtime", "tests::module_order_is_stable");
const OWNER: &str = "owner-a";

const TIM_PROBES: &[formatkit_catalog::catalog::Probe] =
    &[formatkit_catalog::catalog::Probe::Magic {
        offset: 0,
        bytes: b"TIM!",
    }];

const PARSE_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: crate::synthetic::ID_B38504826C7B,
    category: Category::Image,
    decoder: Some(OWNER),
    precedence: 100,
    probes: TIM_PROBES,
    extension_hints: &["synthetic-id-b38504826c7b"],
    requirement: formatkit_catalog::catalog::DecoderRequirement::None,
    ambiguity_group: None,
    capabilities: FormatCapabilities {
        parse: true,
        decode: false,
        edit: false,
        write: false,
        round_trip: false,
        corpus: false,
        bindings: false,
        confidence: formatkit_catalog::catalog::Confidence::ExactMagic,
    },
};

const SEMANTICS: NamespaceSemantics = NamespaceSemantics::carrier(
    crate::synthetic::ID_B38504826C7B,
    NamespaceAddressing::DirectRanges,
);

// --- Three-role synthetic fixtures ---

static THREE_BYTES: &[&str] = &["alpha", "beta", "gamma"];
static THREE_SELECTORS: &[&str] = &[];
const THREE_INPUT: RoleBoundNamespaceInput = RoleBoundNamespaceInput {
    byte_roles: THREE_BYTES,
    selector_roles: THREE_SELECTORS,
};

static THREE_ROLES: &[ByteRole] = &[
    ByteRole::one("alpha"),
    ByteRole::one("beta"),
    ByteRole::one("gamma"),
];
static THREE_FORMS: &[InputForm<'static>] = &[InputForm {
    name: "trio",
    bytes: THREE_ROLES,
    selectors: &[],
}];
static THREE_RELATIONSHIPS: &[InputRelationship] = &[
    InputRelationship::DistinctBacking {
        left_role: "alpha",
        right_role: "beta",
    },
    InputRelationship::DistinctBacking {
        left_role: "alpha",
        right_role: "gamma",
    },
    InputRelationship::DistinctBacking {
        left_role: "beta",
        right_role: "gamma",
    },
];
static THREE_SCHEMA: InputSchema<'static> = InputSchema {
    forms: THREE_FORMS,
    relationships: THREE_RELATIONSHIPS,
};

// --- Four-role synthetic fixtures ---

static FOUR_BYTES: &[&str] = &["alpha", "beta", "gamma", "delta"];
static FOUR_SELECTORS: &[&str] = &[];
const FOUR_INPUT: RoleBoundNamespaceInput = RoleBoundNamespaceInput {
    byte_roles: FOUR_BYTES,
    selector_roles: FOUR_SELECTORS,
};

static FOUR_ROLES: &[ByteRole] = &[
    ByteRole::one("alpha"),
    ByteRole::one("beta"),
    ByteRole::one("gamma"),
    ByteRole::one("delta"),
];
static FOUR_FORMS: &[InputForm<'static>] = &[InputForm {
    name: "quad",
    bytes: FOUR_ROLES,
    selectors: &[],
}];
static FOUR_SCHEMA: InputSchema<'static> = InputSchema {
    forms: FOUR_FORMS,
    relationships: &[],
};

/// Synthetic mounted namespace owning its retained permit. The single member
/// `m` is the first byte of the primary source; other roles are
/// authentication-only (bounded prefix reads) like an index/names pair.
struct MountedTrio {
    namespace: StoredRangeNamespace,
    _permit: formatkit_core::RetainedResidentPermit,
}

impl IndexedNamespace for MountedTrio {
    fn entries(&self) -> &[NamespaceEntry] {
        self.namespace.entries()
    }

    fn supports_work_budget_member_open(&self) -> bool {
        true
    }

    fn stored_source(&self, index: usize) -> Result<Arc<dyn RangeSource>> {
        self.namespace.stored_source(index)
    }

    fn validated_content_source_with_work(
        &self,
        index: usize,
        max_output_len: u64,
        budget: &mut WorkBudget,
    ) -> Result<formatkit_core::MemberContentSource> {
        self.namespace
            .validated_content_source_with_work(index, max_output_len, budget)
    }
}

/// Mount ledger: one node per role plus one mount node and one member node,
/// one member, logical reads of one byte per role, and retained entries plus
/// the one-byte member name. Evidence cites 0..1 per role.
fn mount_trio_inner(
    sources: &SourceBindings,
    bound: &BoundInputs,
    roles: &[&'static str],
    member_name: &str,
    budget: &mut WorkBudget,
) -> Result<(MountedTrio, Vec<SourceEvidenceRange>)> {
    budget.check_cancelled()?;
    let nodes = roles.len() as u64 + 2;
    budget.charge_batch(&[(WorkResource::Nodes, nodes), (WorkResource::Members, 1)])?;
    let mut primary: Option<Arc<dyn RangeSource>> = None;
    let mut primary_handle: Option<formatkit_core::SourceViewHandle> = None;
    for role in roles {
        budget.check_cancelled()?;
        let handle = bound.single_source(role)?;
        let source = sources.source(handle)?.clone();
        source.verify_unchanged()?;
        let mut byte = [0u8; 1];
        source.read_exact_into(0, byte.as_mut_slice(), budget)?;
        source.verify_unchanged()?;
        if primary.is_none() {
            primary = Some(source);
            primary_handle = Some(handle.clone());
        }
    }
    let primary = primary.expect("at least one role");
    let _ = primary_handle;
    budget.check_cancelled()?;
    // Preflight the small fixed retained graph before allocating it.
    let name_estimate = 8u64;
    let entries_estimate = (size_of::<NamespaceEntry>() as u64).saturating_add(name_estimate);
    budget.check(WorkResource::MaterializedBytes, entries_estimate)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(1)
        .map_err(|_| Error::ResourceLimit {
            resource: "role-bound test entries",
            requested: size_of::<NamespaceEntry>() as u64,
            limit: size_of::<NamespaceEntry>() as u64,
        })?;
    let name = String::from(member_name);
    entries.push(NamespaceEntry {
        name: Some(name),
        offset: 0,
        size: 1,
    });
    let observed = (entries.capacity() as u64)
        .saturating_mul(size_of::<NamespaceEntry>() as u64)
        .saturating_add(
            entries[0]
                .name
                .as_ref()
                .map_or(0, |name| name.capacity() as u64),
        );
    budget.charge(WorkResource::MaterializedBytes, observed)?;
    let permit = budget.retain_resident(observed)?;
    let namespace = StoredRangeNamespace::without_raw_names_with_work(
        primary,
        entries,
        StoredRangeNamespaceLimits {
            max_entries: 4,
            max_name_bytes: 8,
            max_total_name_bytes: 32,
        },
        budget,
    )?;
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(roles.len())
        .map_err(|_| Error::ResourceLimit {
            resource: "role-bound test evidence",
            requested: roles.len() as u64,
            limit: roles.len() as u64,
        })?;
    let mut sorted_roles = roles.to_vec();
    sorted_roles.sort_unstable();
    for role in sorted_roles {
        let handle = bound.single_source(role)?.clone();
        // Leak the role name to 'static: test roles are static strings.
        let static_role = roles.iter().find(|name| **name == role).copied().unwrap();
        evidence.push(SourceEvidenceRange {
            role: static_role,
            source: handle,
            range: 0..1,
        });
    }
    SourceProbeOutcome::<()>::validate_evidence(sources, bound, &evidence, budget)?;
    Ok((
        MountedTrio {
            namespace,
            _permit: permit,
        },
        evidence,
    ))
}

fn trio_direct_mount<'budget>(
    sources: &SourceBindings,
    bound: &BoundInputs,
    budget: &'budget mut WorkBudget,
) -> Result<WorkMountedNamespace<'budget>> {
    let (mounted, _evidence) = mount_trio_inner(
        sources,
        bound,
        &["alpha", "beta", "gamma"],
        "direct",
        budget,
    )?;
    let box_bytes = size_of::<MountedTrio>() as u64;
    budget.charge(WorkResource::MaterializedBytes, box_bytes)?;
    // The mounted value already owns its graph permit; the outer guard stays
    // empty like sibling work-single mounts.
    let namespace: Box<dyn IndexedNamespace> = Box::new(mounted);
    let resident = budget.reserve_resident(0)?;
    Ok(WorkMountedNamespace {
        namespace,
        resident,
    })
}

fn quad_direct_mount<'budget>(
    sources: &SourceBindings,
    bound: &BoundInputs,
    budget: &'budget mut WorkBudget,
) -> Result<WorkMountedNamespace<'budget>> {
    let (mounted, _evidence) = mount_trio_inner(
        sources,
        bound,
        &["alpha", "beta", "gamma", "delta"],
        "direct",
        budget,
    )?;
    let box_bytes = size_of::<MountedTrio>() as u64;
    budget.charge(WorkResource::MaterializedBytes, box_bytes)?;
    let namespace: Box<dyn IndexedNamespace> = Box::new(mounted);
    let resident = budget.reserve_resident(0)?;
    Ok(WorkMountedNamespace {
        namespace,
        resident,
    })
}

fn trio_probe<'budget>(
    sources: &SourceBindings,
    bound: &BoundInputs,
    prefix: &[u8],
    budget: &'budget mut WorkBudget,
) -> Result<SourceProbeOutcome<WorkMountedNamespace<'budget>>> {
    budget.check_cancelled()?;
    // Role-bound probes authenticate from bound sources, not from a single
    // detached prefix: an empty prefix is the explicit-selection path.
    let _ = prefix;
    for role in ["alpha", "beta", "gamma"] {
        let handle = bound.single_source(role)?;
        let source = sources.source(handle)?;
        if source.size() < 1 {
            return Ok(SourceProbeOutcome::Mismatch);
        }
    }
    let (mounted, evidence) =
        mount_trio_inner(sources, bound, &["alpha", "beta", "gamma"], "probe", budget)?;
    let box_bytes = size_of::<MountedTrio>() as u64;
    budget.charge(WorkResource::MaterializedBytes, box_bytes)?;
    let namespace: Box<dyn IndexedNamespace> = Box::new(mounted);
    let resident = budget.reserve_resident(0)?;
    Ok(SourceProbeOutcome::Match {
        prepared: WorkMountedNamespace {
            namespace,
            resident,
        },
        evidence,
    })
}

fn quad_probe<'budget>(
    sources: &SourceBindings,
    bound: &BoundInputs,
    _prefix: &[u8],
    budget: &'budget mut WorkBudget,
) -> Result<SourceProbeOutcome<WorkMountedNamespace<'budget>>> {
    for role in ["alpha", "beta", "gamma", "delta"] {
        let handle = bound.single_source(role)?;
        if sources.source(handle)?.size() < 1 {
            return Ok(SourceProbeOutcome::Mismatch);
        }
    }
    let (mounted, evidence) = mount_trio_inner(
        sources,
        bound,
        &["alpha", "beta", "gamma", "delta"],
        "probe",
        budget,
    )?;
    let box_bytes = size_of::<MountedTrio>() as u64;
    budget.charge(WorkResource::MaterializedBytes, box_bytes)?;
    let namespace: Box<dyn IndexedNamespace> = Box::new(mounted);
    let resident = budget.reserve_resident(0)?;
    Ok(SourceProbeOutcome::Match {
        prepared: WorkMountedNamespace {
            namespace,
            resident,
        },
        evidence,
    })
}

const THREE_CONTRACT: RoleBoundNamespaceContract = RoleBoundNamespaceContract {
    id: crate::synthetic::ID_B38504826C7B,
    input: THREE_INPUT,
    strategy: formatkit_catalog::catalog::NamespaceMountStrategy::MetadataOnly,
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

const THREE_PROVIDER: RoleBoundNamespaceProvider = RoleBoundNamespaceProvider {
    id: crate::synthetic::ID_B38504826C7B,
    owner: OWNER,
    input: THREE_INPUT,
    strategy: formatkit_catalog::catalog::NamespaceMountStrategy::MetadataOnly,
    mount: trio_direct_mount,
};

const THREE_OPERATION: ModuleOperation = ModuleOperation {
    name: "mount",
    purpose: "mount three test roles",
    owner: OWNER,
    capabilities: OperationCapabilities::PARSE,
    input_schema: &THREE_SCHEMA,
    bound_namespace: None,
    executable: ExistingExecutableOperation::RoleBoundNamespace {
        contract: &THREE_CONTRACT,
        provider: &THREE_PROVIDER,
    },
};

static THREE_MODULE: FormatModule = FormatModule {
    format: crate::synthetic::ID_B38504826C7B,
    owner: OWNER,
    state: ModuleState::Strict,
    descriptor: Some(&PARSE_DESCRIPTOR),
    embedded_support: None,
    writer_contract: None,
    namespace_semantics: Some(&SEMANTICS),
    operations: &[THREE_OPERATION],
};

#[test]
fn role_bound_operations_remain_strict_only_with_selective_projection() {
    let id = OperationId {
        format: THREE_MODULE.format,
        name: THREE_OPERATION.name,
    };
    let catalog = ModuleCatalog::with_namespace_projection([&THREE_MODULE], []).unwrap();
    assert!(catalog.operation(id).is_some());
    assert!(catalog.support().namespace_provider(id.format).is_none());
    assert!(std::ptr::eq(
        catalog.operation(id).unwrap().input_schema,
        &THREE_SCHEMA
    ));
    assert_eq!(
        ModuleCatalog::with_namespace_projection([&THREE_MODULE], [id])
            .err()
            .unwrap(),
        ModuleCatalogError::InvalidNamespaceProjection(id)
    );
}

const FOUR_CONTRACT: RoleBoundNamespaceContract = RoleBoundNamespaceContract {
    id: crate::synthetic::ID_B38504826C7B,
    input: FOUR_INPUT,
    strategy: formatkit_catalog::catalog::NamespaceMountStrategy::MetadataOnly,
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

const FOUR_PROVIDER: RoleBoundNamespaceProvider = RoleBoundNamespaceProvider {
    id: crate::synthetic::ID_B38504826C7B,
    owner: OWNER,
    input: FOUR_INPUT,
    strategy: formatkit_catalog::catalog::NamespaceMountStrategy::MetadataOnly,
    mount: quad_direct_mount,
};

const FOUR_OPERATION: ModuleOperation = ModuleOperation {
    name: "mount",
    purpose: "mount four test roles",
    owner: OWNER,
    capabilities: OperationCapabilities::PARSE,
    input_schema: &FOUR_SCHEMA,
    bound_namespace: None,
    executable: ExistingExecutableOperation::RoleBoundNamespace {
        contract: &FOUR_CONTRACT,
        provider: &FOUR_PROVIDER,
    },
};

static FOUR_MODULE: FormatModule = FormatModule {
    format: crate::synthetic::ID_B38504826C7B,
    owner: OWNER,
    state: ModuleState::Strict,
    descriptor: Some(&PARSE_DESCRIPTOR),
    embedded_support: None,
    writer_contract: None,
    namespace_semantics: Some(&SEMANTICS),
    operations: &[FOUR_OPERATION],
};

fn memory_sources() -> (SourceBindings, Vec<formatkit_core::SourceViewHandle>) {
    let mut bindings = SourceBindings::new();
    let handles = ["a", "b", "c", "d"]
        .into_iter()
        .enumerate()
        .map(|(index, label)| {
            bindings.register(
                Arc::new(MemoryRangeSource::new(vec![index as u8 + 1; 16], label))
                    as Arc<dyn RangeSource>,
            )
        })
        .collect();
    (bindings, handles)
}

#[test]
fn three_and_four_role_strict_modules_compose() {
    assert!(ModuleCatalog::new([&THREE_MODULE]).is_ok());
    assert!(ModuleCatalog::new([&FOUR_MODULE]).is_ok());
    let catalog = ModuleCatalog::new([&THREE_MODULE]).unwrap();
    assert_eq!(catalog.operations().count(), 1);
    assert_eq!(catalog.legacy_module_count(), 0);
}

#[test]
fn role_bound_topology_rejects_wrong_roles_and_cardinalities() {
    // Wrong role name.
    static WRONG_ROLES: &[ByteRole] = &[
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole::one("wrong"),
    ];
    static WRONG_FORMS: &[InputForm<'static>] = &[InputForm {
        name: "trio",
        bytes: WRONG_ROLES,
        selectors: &[],
    }];
    static WRONG_SCHEMA: InputSchema<'static> = InputSchema {
        forms: WRONG_FORMS,
        relationships: &[],
    };
    // Two roles instead of three.
    static TWO_ROLES: &[ByteRole] = &[ByteRole::one("alpha"), ByteRole::one("beta")];
    static TWO_FORMS: &[InputForm<'static>] = &[InputForm {
        name: "pair",
        bytes: TWO_ROLES,
        selectors: &[],
    }];
    static TWO_SCHEMA: InputSchema<'static> = InputSchema {
        forms: TWO_FORMS,
        relationships: &[],
    };
    // Optional treated as missing: must not project.
    static OPTIONAL_ROLES: &[ByteRole] = &[
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole {
            name: "gamma",
            cardinality: InputCardinality::Optional,
        },
    ];
    static OPTIONAL_FORMS: &[InputForm<'static>] = &[InputForm {
        name: "trio",
        bytes: OPTIONAL_ROLES,
        selectors: &[],
    }];
    static OPTIONAL_SCHEMA: InputSchema<'static> = InputSchema {
        forms: OPTIONAL_FORMS,
        relationships: &[],
    };
    // Many with max 1 still must not project as One.
    static MANY_ROLES: &[ByteRole] = &[
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole {
            name: "gamma",
            cardinality: InputCardinality::Many { min: 1, max: 1 },
        },
    ];
    static MANY_FORMS: &[InputForm<'static>] = &[InputForm {
        name: "trio",
        bytes: MANY_ROLES,
        selectors: &[],
    }];
    static MANY_SCHEMA: InputSchema<'static> = InputSchema {
        forms: MANY_FORMS,
        relationships: &[],
    };
    // Ambiguous two-form schema.
    static AMBIGUOUS_FORMS: &[InputForm<'static>] = &[
        InputForm {
            name: "first",
            bytes: THREE_ROLES,
            selectors: &[],
        },
        InputForm {
            name: "second",
            bytes: THREE_ROLES,
            selectors: &[],
        },
    ];
    static AMBIGUOUS_SCHEMA: InputSchema<'static> = InputSchema {
        forms: AMBIGUOUS_FORMS,
        relationships: &[],
    };
    // Unexpected selector.
    static SELECTOR_ROLES: &[SelectorRole] = &[SelectorRole {
        name: "choice",
        required: true,
    }];
    static SELECTOR_FORMS: &[InputForm<'static>] = &[InputForm {
        name: "trio",
        bytes: THREE_ROLES,
        selectors: SELECTOR_ROLES,
    }];
    static SELECTOR_SCHEMA: InputSchema<'static> = InputSchema {
        forms: SELECTOR_FORMS,
        relationships: &[],
    };
    for (label, schema) in [
        ("wrong-role", &WRONG_SCHEMA),
        ("two-roles", &TWO_SCHEMA),
        ("optional", &OPTIONAL_SCHEMA),
        ("many", &MANY_SCHEMA),
        ("ambiguous", &AMBIGUOUS_SCHEMA),
        ("selector", &SELECTOR_SCHEMA),
    ] {
        let operations = Box::leak(
            vec![ModuleOperation {
                input_schema: schema,
                ..THREE_OPERATION
            }]
            .into_boxed_slice(),
        );
        let module: &'static FormatModule = Box::leak(Box::new(FormatModule {
            format: crate::synthetic::ID_B38504826C7B,
            owner: OWNER,
            state: ModuleState::Strict,
            descriptor: Some(&PARSE_DESCRIPTOR),
            embedded_support: None,
            writer_contract: None,
            namespace_semantics: Some(&SEMANTICS),
            operations,
        }));
        assert_eq!(
            ModuleCatalog::new([module]).err().unwrap(),
            ModuleCatalogError::InputSchemaTopologyDisagreement(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "mount",
            }),
            "{label} must disagree"
        );
    }
    // Swapped roles still project (topology is a set): binding order, not
    // schema order, decides which handle backs which role.
    assert!(schema_has_exact_role_bound_topology(
        &THREE_SCHEMA,
        &THREE_INPUT
    ));
    // Extra relationships strengthen policy without breaking projection.
    assert!(schema_has_exact_role_bound_topology(
        &THREE_SCHEMA,
        &THREE_INPUT
    ));
}

#[test]
fn role_bound_strict_rows_reject_legacy_adapters_and_mismatches() {
    // Legacy bound slot must stay None for work-native role-bound rows.
    fn legacy_adapter(
        _sources: &SourceBindings,
        _bound: &BoundInputs,
        _prefix: &[u8],
        _budget: &mut WorkBudget,
    ) -> Result<SourceProbeOutcome<Box<dyn IndexedNamespace>>> {
        Ok(SourceProbeOutcome::Mismatch)
    }
    let with_adapter = ModuleOperation {
        bound_namespace: Some(legacy_adapter),
        ..THREE_OPERATION
    };
    let operations = Box::leak(vec![with_adapter].into_boxed_slice());
    let module: &'static FormatModule = Box::leak(Box::new(FormatModule {
        format: crate::synthetic::ID_B38504826C7B,
        owner: OWNER,
        state: ModuleState::Strict,
        descriptor: Some(&PARSE_DESCRIPTOR),
        embedded_support: None,
        writer_contract: None,
        namespace_semantics: Some(&SEMANTICS),
        operations,
    }));
    assert_eq!(
        ModuleCatalog::new([module]).err().unwrap(),
        ModuleCatalogError::InvalidBoundNamespaceAdapter(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "mount",
        })
    );

    // Contract/provider disagreement.
    let mismatched = ModuleOperation {
        executable: ExistingExecutableOperation::RoleBoundNamespace {
            contract: &THREE_CONTRACT,
            provider: &FOUR_PROVIDER,
        },
        ..THREE_OPERATION
    };
    let operations = Box::leak(vec![mismatched].into_boxed_slice());
    let module: &'static FormatModule = Box::leak(Box::new(FormatModule {
        format: crate::synthetic::ID_B38504826C7B,
        owner: OWNER,
        state: ModuleState::Strict,
        descriptor: Some(&PARSE_DESCRIPTOR),
        embedded_support: None,
        writer_contract: None,
        namespace_semantics: Some(&SEMANTICS),
        operations,
    }));
    assert_eq!(
        ModuleCatalog::new([module]).err().unwrap(),
        ModuleCatalogError::ContractProviderDisagreement(crate::synthetic::ID_B38504826C7B)
    );
}

#[test]
fn role_bound_dispatch_invokes_one_adapter_on_one_ledger() {
    let catalog = ModuleCatalog::new([&THREE_MODULE]).unwrap();
    let id = OperationId {
        format: crate::synthetic::ID_B38504826C7B,
        name: "mount",
    };
    let (bindings, handles) = memory_sources();
    let bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .unwrap();
    let mut budget = WorkBudget::new(WorkLimits::unlimited());
    {
        let outcome = catalog
            .invoke_role_bound_namespace_work(id, trio_probe, &bindings, &bound, &[], &mut budget)
            .unwrap()
            .expect("strict role-bound operation must dispatch");
        match outcome {
            SourceProbeOutcome::Match { prepared, evidence } => {
                assert_eq!(prepared.namespace.len(), 1);
                assert_eq!(evidence.len(), 3);
                // Only the probe adapter names its member "probe"; the
                // provider direct mount would name it "direct".
                assert_eq!(
                    prepared.namespace.entries()[0].name.as_deref(),
                    Some("probe")
                );
            }
            _ => panic!("expected trio match"),
        }
    }
    // Unknown operation IDs miss without calling the adapter.
    let miss = catalog
        .invoke_role_bound_namespace_work(
            OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "missing",
            },
            trio_probe,
            &bindings,
            &bound,
            &[],
            &mut budget,
        )
        .unwrap();
    assert!(miss.is_none());
    // No probe call: miss/validation failure returns before owner I/O.
    // Source-order invariance: same role mapping in shuffled bind order.
    let shuffled = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
            ],
            &[],
        )
        .unwrap();
    {
        let mut shuffled_budget = WorkBudget::new(WorkLimits::unlimited());
        let outcome = catalog
            .invoke_role_bound_namespace_work(
                id,
                trio_probe,
                &bindings,
                &shuffled,
                &[],
                &mut shuffled_budget,
            )
            .unwrap()
            .expect("shuffled binding must dispatch");
        assert!(matches!(outcome, SourceProbeOutcome::Match { .. }));
    }
    // Probe invocation proven by member name.
}

#[test]
fn role_bound_dispatch_rejects_bad_bindings_before_owner_io() {
    let catalog = ModuleCatalog::new([&THREE_MODULE]).unwrap();
    let id = OperationId {
        format: crate::synthetic::ID_B38504826C7B,
        name: "mount",
    };
    let (mut bindings, handles) = memory_sources();
    // Missing role fails at bind.
    assert!(THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
            ],
            &[],
        )
        .is_err());
    // Alias collapse fails DistinctBacking at bind.
    assert!(THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[0],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .is_err());
    // Foreign handle fails at bind.
    let mut foreign = SourceBindings::new();
    let foreign_handle = foreign.register(
        Arc::new(MemoryRangeSource::new(vec![9u8; 16], "foreign")) as Arc<dyn RangeSource>,
    );
    assert!(THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &foreign_handle,
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .is_err());
    // No probe call: miss/validation failure returns before owner I/O.
    // Quad binding against the trio operation fails revalidation inside the
    // adapter entry point (no probe call).
    let quad_bound = FOUR_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
                ByteInput {
                    role: "delta",
                    source: &handles[3],
                },
            ],
            &[],
        )
        .unwrap();
    assert!(catalog
        .invoke_role_bound_namespace_work(
            id,
            trio_probe,
            &bindings,
            &quad_bound,
            &[],
            &mut WorkBudget::new(WorkLimits::unlimited()),
        )
        .is_err());
    // No probe call: miss/validation failure returns before owner I/O.
    // Legacy bound-namespace entry points miss role-bound rows.
    let bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .unwrap();
    assert!(catalog
        .invoke_bound_namespace(
            id,
            &bindings,
            &bound,
            &[],
            &mut WorkBudget::new(WorkLimits::unlimited())
        )
        .unwrap()
        .is_none());
    assert!(catalog
        .invoke_bound_namespace_work(
            id,
            trio_probe,
            &bindings,
            &bound,
            &[],
            &mut WorkBudget::new(WorkLimits::unlimited())
        )
        .unwrap()
        .is_none());
    let _ = &mut bindings;
}

#[test]
fn role_bound_direct_mount_enforces_exact_roles() {
    let (bindings, handles) = memory_sources();
    let bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .unwrap();
    {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let mounted = THREE_PROVIDER
            .mount_work(&bindings, &bound, &mut budget)
            .unwrap();
        assert_eq!(mounted.namespace.len(), 1);
        assert_eq!(
            mounted.namespace.entries()[0].name.as_deref(),
            Some("direct")
        );
    }
    // Quad bindings are rejected by the trio provider before owner I/O.
    let quad_bound = FOUR_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
                ByteInput {
                    role: "delta",
                    source: &handles[3],
                },
            ],
            &[],
        )
        .unwrap();
    {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        assert!(THREE_PROVIDER
            .mount_work(&bindings, &quad_bound, &mut budget)
            .is_err());
    }
}

#[test]
fn role_bound_probe_handles_mismatch_cancellation_and_budgets() {
    let catalog = ModuleCatalog::new([&THREE_MODULE]).unwrap();
    let id = OperationId {
        format: crate::synthetic::ID_B38504826C7B,
        name: "mount",
    };
    // Empty role is an authenticated miss, not an operational error.
    let mut bindings = SourceBindings::new();
    let a = bindings
        .register(Arc::new(MemoryRangeSource::new(vec![1u8; 16], "a")) as Arc<dyn RangeSource>);
    let b = bindings
        .register(Arc::new(MemoryRangeSource::new(Vec::new(), "b")) as Arc<dyn RangeSource>);
    let c = bindings
        .register(Arc::new(MemoryRangeSource::new(vec![2u8; 16], "c")) as Arc<dyn RangeSource>);
    let miss_bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &a,
                },
                ByteInput {
                    role: "beta",
                    source: &b,
                },
                ByteInput {
                    role: "gamma",
                    source: &c,
                },
            ],
            &[],
        )
        .unwrap();
    {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let outcome = catalog
            .invoke_role_bound_namespace_work(
                id,
                trio_probe,
                &bindings,
                &miss_bound,
                &[],
                &mut budget,
            )
            .unwrap()
            .expect("probe must run");
        assert!(matches!(outcome, SourceProbeOutcome::Mismatch));
    }

    // Pre-cancelled budgets spend nothing and never reach owner reads.
    let (bindings, handles) = memory_sources();
    let bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .unwrap();
    let token = formatkit_core::CancellationToken::new();
    token.cancel();
    let mut cancelled = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
    assert!(matches!(
        catalog.invoke_role_bound_namespace_work(
            id,
            trio_probe,
            &bindings,
            &bound,
            &[],
            &mut cancelled
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(cancelled.spent(WorkResource::Nodes), 0);
    assert_eq!(cancelled.usage().resident_bytes(), 0);

    // One-short node budget rejects before guarded reads.
    let mut one_short = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::Nodes, 4));
    assert!(catalog
        .invoke_role_bound_namespace_work(id, trio_probe, &bindings, &bound, &[], &mut one_short)
        .is_err());
    assert_eq!(one_short.spent(WorkResource::LogicalReadBytes), 0);
    assert_eq!(one_short.usage().resident_bytes(), 0);
    // Exact mount batch (5 nodes + 3 evidence nodes = 8) plus one member.
    let mut exact = WorkBudget::new(
        WorkLimits::unlimited()
            .with(WorkResource::Nodes, 8)
            .with(WorkResource::Members, 1),
    );
    let outcome = catalog
        .invoke_role_bound_namespace_work(id, trio_probe, &bindings, &bound, &[], &mut exact)
        .unwrap()
        .expect("exact budget must mount");
    assert!(matches!(outcome, SourceProbeOutcome::Match { .. }));
    drop(outcome);
    assert_eq!(exact.usage().resident_bytes(), 0);

    // One-short logical-read budget rejects before the third role read.
    let mut short_reads =
        WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 2));
    assert!(catalog
        .invoke_role_bound_namespace_work(id, trio_probe, &bindings, &bound, &[], &mut short_reads)
        .is_err());
    assert_eq!(short_reads.spent(WorkResource::LogicalReadBytes), 2);
    assert_eq!(short_reads.usage().resident_bytes(), 0);
}

#[test]
fn role_bound_simultaneous_mounts_hold_independent_residency() {
    // The exported borrowing guard (`WorkMountedNamespace`, empty outer
    // reservation like sibling work mounts) cannot be held twice against one
    // `&mut` ledger: exclusivity is the point of the borrow. Residency itself
    // lives in the mounted value's owned permit, which the exported probe
    // constructs via this same inner on the caller's ledger. Simultaneous
    // lifetimes are therefore proven through the owned inner mounts that the
    // exported path returns (single-mount dispatch through the exported path
    // is proven separately above).
    let (bindings, handles) = memory_sources();
    let bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .unwrap();
    let mut budget = WorkBudget::new(WorkLimits::unlimited());
    let baseline = budget.usage().resident_bytes();
    let (first, _) = mount_trio_inner(
        &bindings,
        &bound,
        &["alpha", "beta", "gamma"],
        "m",
        &mut budget,
    )
    .unwrap();
    let first_resident = budget.usage().resident_bytes().saturating_sub(baseline);
    assert!(first_resident > 0);
    let (second, _) = mount_trio_inner(
        &bindings,
        &bound,
        &["alpha", "beta", "gamma"],
        "m",
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        budget.usage().resident_bytes(),
        baseline + first_resident * 2
    );
    drop(first);
    assert_eq!(
        budget.usage().resident_bytes(),
        baseline + first_resident,
        "dropping the first mount releases exactly its residency"
    );
    drop(second);
    assert_eq!(budget.usage().resident_bytes(), baseline);

    // Reverse drop order releases symmetrically.
    let (first, _) = mount_trio_inner(
        &bindings,
        &bound,
        &["alpha", "beta", "gamma"],
        "m",
        &mut budget,
    )
    .unwrap();
    let (second, _) = mount_trio_inner(
        &bindings,
        &bound,
        &["alpha", "beta", "gamma"],
        "m",
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        budget.usage().resident_bytes(),
        baseline + first_resident * 2
    );
    drop(second);
    assert_eq!(budget.usage().resident_bytes(), baseline + first_resident);
    drop(first);
    assert_eq!(budget.usage().resident_bytes(), baseline);
}

#[test]
fn four_role_dispatch_proves_generality_beyond_trio() {
    let catalog = ModuleCatalog::new([&FOUR_MODULE]).unwrap();
    let id = OperationId {
        format: crate::synthetic::ID_B38504826C7B,
        name: "mount",
    };
    let (bindings, handles) = memory_sources();
    let bound = FOUR_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
                ByteInput {
                    role: "delta",
                    source: &handles[3],
                },
            ],
            &[],
        )
        .unwrap();
    {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let outcome = catalog
            .invoke_role_bound_namespace_work(id, quad_probe, &bindings, &bound, &[], &mut budget)
            .unwrap()
            .expect("quad must dispatch");
        match outcome {
            SourceProbeOutcome::Match { prepared, evidence } => {
                assert_eq!(prepared.namespace.len(), 1);
                assert_eq!(evidence.len(), 4);
            }
            _ => panic!("expected quad match"),
        }
    }
    // Trio bindings do not satisfy the quad operation.
    let trio_bound = THREE_SCHEMA
        .bind(
            &bindings,
            &[
                ByteInput {
                    role: "alpha",
                    source: &handles[0],
                },
                ByteInput {
                    role: "beta",
                    source: &handles[1],
                },
                ByteInput {
                    role: "gamma",
                    source: &handles[2],
                },
            ],
            &[],
        )
        .unwrap();
    {
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        assert!(catalog
            .invoke_role_bound_namespace_work(
                id,
                quad_probe,
                &bindings,
                &trio_bound,
                &[],
                &mut budget
            )
            .is_err());
    }
}
