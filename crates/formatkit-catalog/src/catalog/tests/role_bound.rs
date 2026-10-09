// The mounted/registry `Ok` types below do not implement `Debug`, so
// `expect_err` is unavailable; `.err().expect(..)` is the precise assertion.
#![allow(clippy::err_expect)]

use super::super::*;

fn empty_mount<'budget>(
    sources: &formatkit_core::SourceBindings,
    bound: &BoundInputs,
    budget: &'budget mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<WorkMountedNamespace<'budget>> {
    budget.check_cancelled()?;
    for role in ["alpha", "beta", "gamma", "delta"] {
        if let Ok(handle) = bound.single_source(role) {
            sources.source(handle)?.verify_unchanged()?;
        }
    }
    for index in 0..bound.byte_len() {
        let _ = index;
        budget.check_cancelled()?;
    }
    let namespace: Box<dyn formatkit_core::IndexedNamespace> =
        Box::new(formatkit_core::StoredRangeNamespace::without_raw_names(
            sources
                .source(bound.single_source("alpha").unwrap_or_else(|_| {
                    bound
                        .single_source(bound_single_first_role(bound))
                        .expect("test mount has at least one role")
                }))?
                .clone(),
            Vec::new(),
            formatkit_core::StoredRangeNamespaceLimits {
                max_entries: 0,
                max_name_bytes: 0,
                max_total_name_bytes: 0,
            },
        )?);
    let resident = budget.reserve_resident(0)?;
    Ok(WorkMountedNamespace {
        namespace,
        resident,
    })
}

fn bound_single_first_role(bound: &BoundInputs) -> &str {
    // Test-only helper: the empty mount retains no names, so any single
    // bound role supplies the (unused) backing source for zero members.
    // Callers always bind at least one role; provider validation rejects
    // empty bindings before this mount runs.
    for role in [
        "alpha", "beta", "gamma", "delta", "first", "second", "third",
    ] {
        if bound.single_source(role).is_ok() {
            return match role {
                "alpha" => "alpha",
                "beta" => "beta",
                "gamma" => "gamma",
                "delta" => "delta",
                "first" => "first",
                "second" => "second",
                _ => "third",
            };
        }
    }
    "alpha"
}

fn rejecting_mount<'budget>(
    _sources: &formatkit_core::SourceBindings,
    _bound: &BoundInputs,
    _budget: &'budget mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<WorkMountedNamespace<'budget>> {
    Err(formatkit_core::Error::Unsupported(
        "test role-bound mount".into(),
    ))
}

fn three_input() -> RoleBoundNamespaceInput {
    static BYTES: &[&str] = &["alpha", "beta", "gamma"];
    static SELECTORS: &[&str] = &[];
    RoleBoundNamespaceInput {
        byte_roles: BYTES,
        selector_roles: SELECTORS,
    }
}

fn four_input() -> RoleBoundNamespaceInput {
    static BYTES: &[&str] = &["alpha", "beta", "gamma", "delta"];
    static SELECTORS: &[&str] = &[];
    RoleBoundNamespaceInput {
        byte_roles: BYTES,
        selector_roles: SELECTORS,
    }
}

fn three_provider() -> RoleBoundNamespaceProvider {
    RoleBoundNamespaceProvider {
        id: crate::synthetic::ID_B38504826C7B,
        owner: "test",
        input: three_input(),
        strategy: NamespaceMountStrategy::MetadataOnly,
        mount: empty_mount,
    }
}

fn memory_source(byte: u8) -> std::sync::Arc<dyn formatkit_core::RangeSource> {
    std::sync::Arc::new(formatkit_core::MemoryRangeSource::new(
        vec![byte; 16],
        "role",
    ))
}

#[test]
fn role_bound_input_validates_finite_roles() {
    assert!(three_input().validate().is_ok());
    assert!(four_input().validate().is_ok());
    assert_eq!(three_input().label(), "role-bound-sources");

    static ONE: &[&str] = &["only"];
    static NONE_SELECTOR: &[&str] = &[];
    assert!(RoleBoundNamespaceInput {
        byte_roles: ONE,
        selector_roles: NONE_SELECTOR,
    }
    .validate()
    .is_ok());

    static EMPTY: &[&str] = &[];
    assert!(RoleBoundNamespaceInput {
        byte_roles: EMPTY,
        selector_roles: NONE_SELECTOR,
    }
    .validate()
    .is_err());

    static NINE: &[&str] = &["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    assert!(RoleBoundNamespaceInput {
        byte_roles: NINE,
        selector_roles: NONE_SELECTOR,
    }
    .validate()
    .is_err());

    static DUP: &[&str] = &["alpha", "beta", "alpha"];
    assert!(RoleBoundNamespaceInput {
        byte_roles: DUP,
        selector_roles: NONE_SELECTOR,
    }
    .validate()
    .is_err());

    static BAD: &[&str] = &["Alpha"];
    assert!(RoleBoundNamespaceInput {
        byte_roles: BAD,
        selector_roles: NONE_SELECTOR,
    }
    .validate()
    .is_err());

    static SELECTORS: &[&str] = &["choice"];
    assert!(RoleBoundNamespaceInput {
        byte_roles: ONE,
        selector_roles: SELECTORS,
    }
    .validate()
    .is_ok());
    static OVERLAP: &[&str] = &["only"];
    assert!(RoleBoundNamespaceInput {
        byte_roles: ONE,
        selector_roles: OVERLAP,
    }
    .validate()
    .is_err());
    static FIVE_SELECTORS: &[&str] = &["a", "b", "c", "d", "e"];
    assert!(RoleBoundNamespaceInput {
        byte_roles: ONE,
        selector_roles: FIVE_SELECTORS,
    }
    .validate()
    .is_err());
}

#[test]
fn role_bound_mount_requires_exact_roles_before_owner_io() {
    let provider = RoleBoundNamespaceProvider {
        mount: rejecting_mount,
        ..three_provider()
    };
    assert!(provider.mount_matches_input());
    assert!(provider
        .enforce_strategy(NamespaceMountStrategy::MetadataOnly)
        .is_ok());
    assert!(provider
        .enforce_strategy(NamespaceMountStrategy::MetadataOnly)
        .is_ok());

    let roles = [
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole::one("gamma"),
    ];
    let forms = [InputForm {
        name: "trio",
        bytes: &roles,
        selectors: &[],
    }];
    let schema = InputSchema {
        forms: &forms,
        relationships: &[],
    };
    let mut sources = formatkit_core::SourceBindings::new();
    let alpha = sources.register(memory_source(1));
    let beta = sources.register(memory_source(2));
    let gamma = sources.register(memory_source(3));
    let bound = schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
            ],
            &[],
        )
        .unwrap();
    assert_eq!(bound.byte_len(), 3);
    assert_eq!(bound.selector_len(), 0);
    // Exact roles reach the owner callback (which rejects here to prove
    // validation passed before I/O).
    assert!(provider
        .mount_work(
            &sources,
            &bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .err()
        .expect("expected error")
        .to_string()
        .contains("test role-bound mount"));

    // Missing role fails at schema bind, before the provider runs.
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
            ],
            &[],
        )
        .is_err());
    // Duplicate role fails at schema bind (One cardinality).
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "alpha",
                    source: &beta,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
            ],
            &[],
        )
        .is_err());
    // Unknown role fails at schema bind.
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "unknown",
                    source: &gamma,
                },
            ],
            &[],
        )
        .is_err());

    // Extra bindings smuggled through a wider schema are rejected by the
    // provider's exact-count gate before owner I/O.
    let wide_roles = [
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole::one("gamma"),
        ByteRole::one("delta"),
    ];
    let wide_forms = [InputForm {
        name: "quad",
        bytes: &wide_roles,
        selectors: &[],
    }];
    let wide_schema = InputSchema {
        forms: &wide_forms,
        relationships: &[],
    };
    let delta = sources.register(memory_source(4));
    let wide_bound = wide_schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
                ByteInput {
                    role: "delta",
                    source: &delta,
                },
            ],
            &[],
        )
        .unwrap();
    assert!(provider
        .mount_work(
            &sources,
            &wide_bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .err()
        .expect("expected error")
        .to_string()
        .contains("expected 3"));

    // Four-role provider accepts four and rejects three.
    let four_roles = [
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole::one("gamma"),
        ByteRole::one("delta"),
    ];
    let four_forms = [InputForm {
        name: "quad",
        bytes: &four_roles,
        selectors: &[],
    }];
    let four_schema = InputSchema {
        forms: &four_forms,
        relationships: &[],
    };
    let four_bound = four_schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
                ByteInput {
                    role: "delta",
                    source: &delta,
                },
            ],
            &[],
        )
        .unwrap();
    let four_provider = RoleBoundNamespaceProvider {
        input: four_input(),
        mount: rejecting_mount,
        ..three_provider()
    };
    assert!(four_provider
        .mount_work(
            &sources,
            &four_bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .err()
        .expect("expected error")
        .to_string()
        .contains("test role-bound mount"));
    assert!(four_provider
        .mount_work(
            &sources,
            &bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .is_err());
}

#[test]
fn role_bound_distinct_backing_enforces_aliases_for_three_roles() {
    let roles = [
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole::one("gamma"),
    ];
    let forms = [InputForm {
        name: "trio",
        bytes: &roles,
        selectors: &[],
    }];
    let relationships = [
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
    let schema = InputSchema {
        forms: &forms,
        relationships: &relationships,
    };
    // Distinct files with identical contents remain distinct sources.
    let mut sources = formatkit_core::SourceBindings::new();
    let first = sources.register(memory_source(7));
    let second = sources.register(memory_source(7));
    let third = sources.register(memory_source(7));
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &first,
                },
                ByteInput {
                    role: "beta",
                    source: &second,
                },
                ByteInput {
                    role: "gamma",
                    source: &third,
                },
            ],
            &[],
        )
        .is_ok());
    // Reusing one handle for two roles collapses to one backing and fails.
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &first,
                },
                ByteInput {
                    role: "beta",
                    source: &first,
                },
                ByteInput {
                    role: "gamma",
                    source: &third,
                },
            ],
            &[],
        )
        .err()
        .expect("expected error")
        .to_string()
        .contains("distinct backing"));
    // A slice view shares its parent backing and also fails.
    let alias = sources.slice(&first, 0, 16, "alias").unwrap();
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &first,
                },
                ByteInput {
                    role: "beta",
                    source: &second,
                },
                ByteInput {
                    role: "gamma",
                    source: &alias,
                },
            ],
            &[],
        )
        .is_err());
}

#[test]
fn role_bound_provider_rejects_optional_many_counts_before_owner_io() {
    let provider = RoleBoundNamespaceProvider {
        mount: rejecting_mount,
        ..three_provider()
    };
    let mut sources = formatkit_core::SourceBindings::new();
    let alpha = sources.register(memory_source(1));
    let beta = sources.register(memory_source(2));
    let gamma = sources.register(memory_source(3));

    // Optional with zero bindings: schema bind succeeds (Optional allows 0)
    // but the provider requires exactly three byte bindings.
    let optional_roles = [
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole {
            name: "gamma",
            cardinality: InputCardinality::Optional,
        },
    ];
    let optional_forms = [InputForm {
        name: "trio",
        bytes: &optional_roles,
        selectors: &[],
    }];
    let optional_schema = InputSchema {
        forms: &optional_forms,
        relationships: &[],
    };
    let optional_bound = optional_schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
            ],
            &[],
        )
        .unwrap();
    assert!(provider
        .mount_work(
            &sources,
            &optional_bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .is_err());

    // Many with two bindings: schema bind succeeds but the provider rejects
    // the extra source instead of treating the role as One.
    let many_roles = [
        ByteRole::one("alpha"),
        ByteRole {
            name: "beta",
            cardinality: InputCardinality::Many { min: 1, max: 2 },
        },
        ByteRole::one("gamma"),
    ];
    let many_forms = [InputForm {
        name: "trio",
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
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "beta",
                    source: &gamma,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
            ],
            &[],
        )
        .unwrap();
    assert!(provider
        .mount_work(
            &sources,
            &many_bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .is_err());
}

#[test]
fn role_bound_selectors_require_exact_values() {
    static BYTES: &[&str] = &["alpha", "beta", "gamma"];
    static SELECTORS: &[&str] = &["choice"];
    let input = RoleBoundNamespaceInput {
        byte_roles: BYTES,
        selector_roles: SELECTORS,
    };
    assert!(input.validate().is_ok());
    let provider = RoleBoundNamespaceProvider {
        input,
        mount: rejecting_mount,
        ..three_provider()
    };
    let roles = [
        ByteRole::one("alpha"),
        ByteRole::one("beta"),
        ByteRole::one("gamma"),
    ];
    let selector_roles = [SelectorRole {
        name: "choice",
        required: true,
    }];
    let forms = [InputForm {
        name: "trio",
        bytes: &roles,
        selectors: &selector_roles,
    }];
    let schema = InputSchema {
        forms: &forms,
        relationships: &[],
    };
    let mut sources = formatkit_core::SourceBindings::new();
    let alpha = sources.register(memory_source(1));
    let beta = sources.register(memory_source(2));
    let gamma = sources.register(memory_source(3));
    let bound = schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
            ],
            &[SelectorInput {
                role: "choice",
                value: "explicit",
            }],
        )
        .unwrap();
    assert!(provider
        .mount_work(
            &sources,
            &bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .err()
        .expect("expected error")
        .to_string()
        .contains("test role-bound mount"));
    // Missing required selector fails at schema bind.
    assert!(schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
            ],
            &[],
        )
        .is_err());
    // Selector-less bindings smuggled through a selector-less schema are
    // rejected by the provider's exact-count gate.
    let plain_forms = [InputForm {
        name: "trio",
        bytes: &roles,
        selectors: &[],
    }];
    let plain_schema = InputSchema {
        forms: &plain_forms,
        relationships: &[],
    };
    let plain_bound = plain_schema
        .bind(
            &sources,
            &[
                ByteInput {
                    role: "alpha",
                    source: &alpha,
                },
                ByteInput {
                    role: "beta",
                    source: &beta,
                },
                ByteInput {
                    role: "gamma",
                    source: &gamma,
                },
            ],
            &[],
        )
        .unwrap();
    assert!(provider
        .mount_work(
            &sources,
            &plain_bound,
            &mut formatkit_core::WorkBudget::new(formatkit_core::WorkLimits::unlimited())
        )
        .is_err());
}
