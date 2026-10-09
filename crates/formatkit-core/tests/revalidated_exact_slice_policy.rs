use std::sync::Arc;

use formatkit_core::{
    Error, ErrorContext, ExactReadLengthMismatch, ExactReadLengthMismatchKind, ExactReadRoute,
    MemoryRangeSource, RangeSource, RevalidatedExactSliceErrorPolicy, RevalidatedExactSliceSource,
};

#[derive(Clone)]
struct OwnerPolicy {
    malformed_prefix: String,
    read_context: &'static str,
    stability_context: Option<&'static str>,
    construction_context: Option<&'static str>,
    route_specific_wording: bool,
}

impl OwnerPolicy {
    fn contextualize(error: Error, context: Option<&'static str>) -> Error {
        match context {
            Some(context) => error.context(ErrorContext::Component(context)),
            None => error,
        }
    }
}

impl RevalidatedExactSliceErrorPolicy for OwnerPolicy {
    fn map_read_error(&self, _route: ExactReadRoute, error: Error) -> Error {
        Self::contextualize(error, Some(self.read_context))
    }

    fn map_length_mismatch(&self, mismatch: ExactReadLengthMismatch) -> Error {
        let leaf = match mismatch.kind() {
            ExactReadLengthMismatchKind::Short => Error::Truncated {
                offset: usize::try_from(mismatch.offset).unwrap_or(usize::MAX),
                needed: usize::try_from(mismatch.requested).unwrap_or(usize::MAX),
                available: mismatch.actual,
            },
            ExactReadLengthMismatchKind::Overlong if self.route_specific_wording => {
                let route = match mismatch.route {
                    ExactReadRoute::Owned => "read",
                    ExactReadRoute::Shared => "shared read",
                };
                Error::Malformed(format!(
                    "{}: stored range returned {} bytes for an exact {}-byte {route}",
                    self.malformed_prefix, mismatch.actual, mismatch.requested
                ))
            }
            ExactReadLengthMismatchKind::Overlong => Error::Malformed(format!(
                "{}: source returned {} bytes for an exact {}-byte read",
                self.malformed_prefix, mismatch.actual, mismatch.requested
            )),
        };
        Self::contextualize(leaf, Some(self.read_context))
    }

    fn map_stability_error(&self, error: Error) -> Error {
        Self::contextualize(error, self.stability_context)
    }

    fn map_construction_error(&self, error: Error) -> Error {
        Self::contextualize(error, self.construction_context)
    }
}

#[test]
fn public_policy_surface_represents_contextual_policy_combinations() {
    let runtime_dialect = String::from("dynamic");
    let fixtures = [
        (
            "synthetic-policy-b45090a97232".to_owned(),
            "synthetic-policy-56287ead4400",
            Some("synthetic-policy-9d4bbadbfee4"),
            None,
            false,
        ),
        (
            "synthetic-policy-5a9c7229275c".to_owned(),
            "synthetic-policy-b67b275faffe",
            Some("synthetic-policy-b67b275faffe"),
            None,
            false,
        ),
        (
            "synthetic owner".to_owned(),
            "synthetic deferred range read",
            Some("synthetic source stability"),
            None,
            false,
        ),
        (
            "synthetic-policy-465fa7a326c3".to_owned(),
            "synthetic-policy-c58f933a6dc4",
            None,
            None,
            false,
        ),
        (
            "synthetic-policy-604f687eb6ad".to_owned(),
            "synthetic-policy-ddd7802a246e",
            Some("synthetic-policy-ddd7802a246e"),
            None,
            false,
        ),
        (
            "synthetic-policy-8dafa849b928".to_owned(),
            "synthetic-policy-16a5fc92ec94",
            Some("synthetic-policy-56ab73156a2c"),
            None,
            true,
        ),
        (
            "synthetic-policy-1802335953b0".to_owned(),
            "synthetic-policy-b73385f0f0c8",
            None,
            None,
            false,
        ),
        (
            format!("synthetic-policy-{runtime_dialect}"),
            "synthetic-policy-18442e60a8cb",
            None,
            None,
            false,
        ),
        (
            "synthetic-policy-775cd6e4b0a3".to_owned(),
            "synthetic-policy-a1bfc5adc23a",
            None,
            None,
            false,
        ),
        (
            "synthetic-policy-ffe94852b36b".to_owned(),
            "synthetic-policy-4edf2ddedd26",
            Some("synthetic-policy-67c802312a1e"),
            Some("synthetic-policy-4edf2ddedd26"),
            false,
        ),
    ];

    for (prefix, read, stability, construction, route_specific) in fixtures {
        let policy = OwnerPolicy {
            malformed_prefix: prefix.clone(),
            read_context: read,
            stability_context: stability,
            construction_context: construction,
            route_specific_wording: route_specific,
        };
        for route in [ExactReadRoute::Owned, ExactReadRoute::Shared] {
            let error = policy.map_length_mismatch(ExactReadLengthMismatch {
                route,
                offset: 11,
                requested: 4,
                actual: 5,
            });
            let operation = if route_specific && route == ExactReadRoute::Shared {
                "stored range returned 5 bytes for an exact 4-byte shared read"
            } else if route_specific {
                "stored range returned 5 bytes for an exact 4-byte read"
            } else {
                "source returned 5 bytes for an exact 4-byte read"
            };
            let leaf = format!("{prefix}: {operation}");
            assert_eq!(error.to_string(), format!("{read}: {leaf}"));
            assert!(matches!(error.leaf(), Error::Malformed(message) if message == &leaf));
            assert_eq!(
                error.contexts().collect::<Vec<_>>(),
                vec![&ErrorContext::Component(read)]
            );
        }
    }
}

#[test]
fn public_policy_surface_keeps_construction_mapping_independent_and_cloneable() {
    let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
        b"01234567".to_vec(),
        "synthetic-policy-9d9a2805b833",
    ));
    let policy = OwnerPolicy {
        malformed_prefix: "synthetic-policy-ffe94852b36b".into(),
        read_context: "synthetic-policy-4edf2ddedd26",
        stability_context: Some("synthetic-policy-67c802312a1e"),
        construction_context: Some("synthetic-policy-4edf2ddedd26"),
        route_specific_wording: false,
    };
    let error = RevalidatedExactSliceSource::with_policy(
        source,
        u64::MAX,
        2,
        "synthetic-policy-781adabbd955",
        policy,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "synthetic-policy-4edf2ddedd26: source range 0xffffffffffffffff+0x2 lies outside source size 0x8");
    assert!(matches!(
        error.leaf(),
        Error::SourceRangeOutside {
            offset: u64::MAX,
            length: 2,
            source_size: 8,
        }
    ));
    assert_eq!(
        error.contexts().collect::<Vec<_>>(),
        vec![&ErrorContext::Component("synthetic-policy-4edf2ddedd26")]
    );

    let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
        b"01234567".to_vec(),
        "clone fixture",
    ));
    let wrapped = RevalidatedExactSliceSource::new(source, 2, 4, "payload").unwrap();
    let _clone = wrapped.clone();
}
