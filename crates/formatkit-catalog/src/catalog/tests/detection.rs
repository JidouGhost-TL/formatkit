use super::super::*;
use super::fixtures::*;
use crate::{Category, FormatId, Method};
use std::path::Path;

#[test]
fn decoder_owned_format_ids_preserve_the_existing_lexical_domain() {
    const OWNER_ID: FormatId = FormatId::new("owner.icon.sys-v2");
    assert!(OWNER_ID.is_valid());
    assert_eq!(OWNER_ID.as_str(), "owner.icon.sys-v2");
    assert!(FormatCatalog::new([descriptor(OWNER_ID, 10, MAGIC, &[])]).is_ok());

    for malformed in [
        FormatId::UNKNOWN,
        FormatId::new("Uppercase"),
        FormatId::new("-leading"),
        FormatId::new("trailing-"),
        FormatId::new("double..dot"),
        FormatId::new("mixed.-separator"),
        FormatId::new("under_score"),
    ] {
        assert!(!malformed.is_valid(), "{:?}", malformed.as_str());
        assert_eq!(
            FormatCatalog::new([descriptor(malformed, 10, MAGIC, &[])])
                .err()
                .unwrap(),
            CatalogError::InvalidFormatId(malformed)
        );
    }
}

#[test]
fn content_is_required_even_when_extension_matches() {
    let catalog = FormatCatalog::new([descriptor(
        crate::synthetic::ID_B38504826C7B,
        10,
        MAGIC,
        &["synthetic-id-b38504826c7b"],
    )])
    .unwrap();
    let result = catalog
        .resolve(DetectionContext::from_bytes(b"nope").with_extension("synthetic-id-b38504826c7b"));
    assert!(result.is_unknown());
}

#[test]
fn contextual_structural_probe_requires_full_parent_role_and_content() {
    const ROLE_PROBES: &[Probe] = &[Probe::ContextualStructural {
        name: "contextual-test",
        extension: "dtb",
        parent_suffix: "cclm/battle2",
        check: starts_with_ten,
    }];
    let catalog = FormatCatalog::new([descriptor(
        crate::synthetic::ID_B38504826C7B,
        10,
        ROLE_PROBES,
        &["dtb"],
    )])
    .unwrap();
    let bytes = [0x10, 0x00];
    assert!(catalog
        .identify(DetectionContext::from_bytes(&bytes))
        .is_none());
    assert!(catalog
        .identify(DetectionContext::from_bytes(&bytes).with_extension("dtb"))
        .is_none());
    for path in [
        "other/battle2/table.dtb",
        "cclm/map4/table.dtb",
        "cclm/battle2/table.bin",
    ] {
        assert!(
            catalog
                .identify(DetectionContext::from_bytes(&bytes).with_path(Path::new(path)))
                .is_none(),
            "{path}"
        );
    }
    let path = Path::new("ROOT/ASSETS/data/CCLM/BATTLE2/table.DTB");
    let context = DetectionContext::from_bytes(&bytes).with_path(path);
    assert_eq!(
        catalog.identify(context).unwrap().format_id(),
        crate::synthetic::ID_B38504826C7B
    );
    assert!(catalog
        .identify(DetectionContext::from_bytes(&[0x00]).with_path(path))
        .is_none());
}

#[test]
fn identify_returns_the_shared_id_shape() {
    let mut decoded = descriptor(
        crate::synthetic::ID_B38504826C7B,
        10,
        MAGIC,
        &["synthetic-id-b38504826c7b"],
    );
    decoded.category = Category::Image;
    decoded.decoder = Some("image-owner");
    let catalog = FormatCatalog::new([decoded]).unwrap();
    let id = catalog
        .identify(DetectionContext::from_bytes(b"TEST"))
        .unwrap();
    assert_eq!(id.format_id(), crate::synthetic::ID_B38504826C7B);
    assert_eq!(id.category, Category::Image);
    assert_eq!(id.method, Method::Magic);
    assert_eq!(id.opener, Some("image-owner"));
    assert!(catalog
        .identify(DetectionContext::from_bytes(b"nope"))
        .is_none());
}

#[test]
fn extension_breaks_only_an_equal_precedence_tie() {
    let mut seq = descriptor(
        crate::synthetic::ID_7EEC5564AF8B,
        10,
        MAGIC,
        &["synthetic-id-7eec5564af8b"],
    );
    seq.ambiguity_group = Some("sequence");
    seq.capabilities.confidence = Confidence::Ambiguous;
    let mut sep = descriptor(
        crate::synthetic::ID_FF823BEFE290,
        10,
        MAGIC,
        &["synthetic-id-ff823befe290"],
    );
    sep.ambiguity_group = Some("sequence");
    sep.capabilities.confidence = Confidence::Ambiguous;
    let catalog = FormatCatalog::new([seq, sep]).unwrap();
    assert!(catalog
        .resolve(DetectionContext::from_bytes(b"TEST"))
        .is_ambiguous());
    let resolved = catalog.resolve(
        DetectionContext::from_bytes(b"TEST").with_extension(".SYNTHETIC-ID-FF823BEFE290"),
    );
    assert_eq!(
        resolved.selected.unwrap().descriptor.id,
        crate::synthetic::ID_FF823BEFE290
    );
}

#[test]
fn higher_precedence_content_match_beats_an_extension_hint() {
    let catalog = FormatCatalog::new([
        descriptor(crate::synthetic::ID_B38504826C7B, 20, STRUCTURAL, &[]),
        descriptor(FormatId::PNG, 10, STRUCTURAL, &["png"]),
    ])
    .unwrap();
    let resolved = catalog.resolve(DetectionContext::from_bytes(&[0x10]).with_extension("png"));
    assert_eq!(
        resolved.selected.unwrap().descriptor.id,
        crate::synthetic::ID_B38504826C7B
    );
}

#[test]
fn parent_context_requirement_identifies_metadata_but_gates_decoder_readiness() {
    let mut contextual = descriptor(crate::synthetic::ID_B38504826C7B, 20, MAGIC, &[]);
    contextual.decoder = Some("context-decoder");
    contextual.requirement = DecoderRequirement::ParentAndSiblings;
    let catalog = FormatCatalog::new([contextual]).unwrap();

    let detached = catalog.resolve(DetectionContext::from_bytes(b"TEST"));
    assert_eq!(
        detached.selected.unwrap().descriptor.id,
        crate::synthetic::ID_B38504826C7B
    );
    assert!(!detached.selected.unwrap().decoder_ready());

    let parent_only =
        catalog.resolve(DetectionContext::from_bytes(b"TEST").with_parent_address_space(true));
    assert!(!parent_only.selected.unwrap().decoder_ready());

    let complete = catalog.resolve(
        DetectionContext::from_bytes(b"TEST")
            .with_parent_address_space(true)
            .with_parent_siblings(true),
    );
    assert!(complete.selected.unwrap().decoder_ready());
}

#[test]
fn catalog_validation_rejects_duplicate_ids_and_missing_decoders() {
    assert!(matches!(
        FormatCatalog::new([
            descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]),
            descriptor(crate::synthetic::ID_B38504826C7B, 20, STRUCTURAL, &[]),
        ]),
        Err(CatalogError::DuplicateId(crate::synthetic::ID_B38504826C7B))
    ));

    let mut decoded = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    decoded.decoder = Some("image-owner");
    let catalog = FormatCatalog::new([decoded]).unwrap();
    assert!(catalog.validate_decoders(&[]).is_err());
    assert!(catalog.validate_decoders(&["image-owner"]).is_ok());
}

#[test]
fn catalog_rejects_round_trip_without_write_and_edit_support() {
    let mut missing_edit = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    missing_edit.capabilities.parse = true;
    missing_edit.capabilities.write = true;
    missing_edit.capabilities.round_trip = true;
    assert!(matches!(
        FormatCatalog::new([missing_edit]),
        Err(CatalogError::InvalidCapabilities(
            crate::synthetic::ID_B38504826C7B
        ))
    ));

    let mut missing_write = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    missing_write.capabilities.parse = true;
    missing_write.capabilities.edit = true;
    missing_write.capabilities.round_trip = true;
    assert!(matches!(
        FormatCatalog::new([missing_write]),
        Err(CatalogError::InvalidCapabilities(
            crate::synthetic::ID_B38504826C7B
        ))
    ));
}

#[test]
fn catalog_rejects_operations_without_parse_support() {
    for enable in [
        |caps: &mut FormatCapabilities| caps.decode = true,
        |caps: &mut FormatCapabilities| caps.edit = true,
        |caps: &mut FormatCapabilities| caps.write = true,
    ] {
        let mut impossible = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
        enable(&mut impossible.capabilities);
        assert!(matches!(
            FormatCatalog::new([impossible]),
            Err(CatalogError::InvalidCapabilities(
                crate::synthetic::ID_B38504826C7B
            ))
        ));
    }
}

#[test]
fn builder_rejects_undeclared_probe_conflicts() {
    assert!(matches!(
        FormatCatalog::builder()
            .add_descriptor(descriptor(
                crate::synthetic::ID_7EEC5564AF8B,
                10,
                MAGIC,
                &["synthetic-id-7eec5564af8b"]
            ))
            .add_descriptor(descriptor(
                crate::synthetic::ID_FF823BEFE290,
                10,
                MAGIC,
                &["synthetic-id-ff823befe290"]
            ))
            .build(),
        Err(CatalogError::UndeclaredProbeConflict {
            first: crate::synthetic::ID_7EEC5564AF8B,
            second: crate::synthetic::ID_FF823BEFE290,
        })
    ));
}

#[test]
fn optimized_conflict_index_preserves_validation_and_first_prior_precedence() {
    let first = descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]);
    let mut invalid_duplicate = descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]);
    invalid_duplicate.probes = &[];
    assert_eq!(
        FormatCatalog::new([first, invalid_duplicate])
            .err()
            .unwrap(),
        CatalogError::NoProbes(crate::synthetic::ID_7EEC5564AF8B)
    );

    assert_eq!(
        FormatCatalog::new([
            descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]),
            descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]),
        ])
        .err()
        .unwrap(),
        CatalogError::DuplicateId(crate::synthetic::ID_7EEC5564AF8B)
    );

    let mut unavailable = descriptor(crate::synthetic::ID_FF823BEFE290, 10, MAGIC, &[]);
    unavailable.decoder = Some("missing-decoder");
    assert_eq!(
        FormatCatalog::builder()
            .add_family([
                descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]),
                unavailable
            ])
            .available_decoders([])
            .build()
            .err()
            .unwrap(),
        CatalogError::UndeclaredProbeConflict {
            first: crate::synthetic::ID_7EEC5564AF8B,
            second: crate::synthetic::ID_FF823BEFE290,
        }
    );

    let mut left = descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]);
    left.ambiguity_group = Some("sequence");
    left.capabilities.confidence = Confidence::Ambiguous;
    let mut middle = descriptor(crate::synthetic::ID_FF823BEFE290, 10, MAGIC, &[]);
    middle.ambiguity_group = Some("sequence");
    middle.capabilities.confidence = Confidence::Ambiguous;
    assert_eq!(
        FormatCatalog::new([
            left,
            middle,
            descriptor(crate::synthetic::ID_71C0E0E93923, 10, MAGIC, &[]),
        ])
        .err()
        .unwrap(),
        CatalogError::UndeclaredProbeConflict {
            first: crate::synthetic::ID_7EEC5564AF8B,
            second: crate::synthetic::ID_71C0E0E93923,
        }
    );

    let mut missing_first = descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, STRUCTURAL, &[]);
    missing_first.decoder = Some("missing-decoder");
    let mut invalid_later = descriptor(crate::synthetic::ID_FF823BEFE290, 10, MAGIC, &[]);
    invalid_later.precedence = 0;
    assert_eq!(
        FormatCatalog::builder()
            .add_family([missing_first, invalid_later])
            .available_decoders([])
            .build()
            .err()
            .unwrap(),
        CatalogError::MissingDecoder {
            format: crate::synthetic::ID_7EEC5564AF8B,
            decoder: "missing-decoder",
        }
    );
}

#[test]
fn mixed_conflict_fallback_preserves_overlap_and_first_prior_semantics() {
    const SHORT_MAGIC: &[Probe] = &[Probe::Magic {
        offset: 0,
        bytes: b"TE",
    }];
    const DISTINCT_MAGIC: &[Probe] = &[Probe::Magic {
        offset: 0,
        bytes: b"NO",
    }];
    const INNER_MAGIC: &[Probe] = &[Probe::Magic {
        offset: 1,
        bytes: b"ES",
    }];

    // A different magic width forces SimpleMagic -> Mixed. The fallback must
    // still reject a real byte-range overlap.
    assert_eq!(
        FormatCatalog::new([
            descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]),
            descriptor(crate::synthetic::ID_FF823BEFE290, 10, SHORT_MAGIC, &[]),
        ])
        .err()
        .unwrap(),
        CatalogError::UndeclaredProbeConflict {
            first: crate::synthetic::ID_7EEC5564AF8B,
            second: crate::synthetic::ID_FF823BEFE290,
        }
    );

    // Transitioning to Mixed is not itself a conflict.
    assert!(FormatCatalog::new([
        descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]),
        descriptor(crate::synthetic::ID_FF823BEFE290, 10, DISTINCT_MAGIC, &[]),
    ])
    .is_ok());

    // Two intentionally grouped overlapping priors establish a Mixed group.
    // An ungrouped third descriptor overlaps both; preserve the original
    // prefix scan's first-prior diagnostic.
    let mut first = descriptor(crate::synthetic::ID_7EEC5564AF8B, 10, MAGIC, &[]);
    first.ambiguity_group = Some("sequence");
    let mut second = descriptor(crate::synthetic::ID_FF823BEFE290, 10, SHORT_MAGIC, &[]);
    second.ambiguity_group = Some("sequence");
    assert_eq!(
        FormatCatalog::new([
            first,
            second,
            descriptor(crate::synthetic::ID_71C0E0E93923, 10, INNER_MAGIC, &[]),
        ])
        .err()
        .unwrap(),
        CatalogError::UndeclaredProbeConflict {
            first: crate::synthetic::ID_7EEC5564AF8B,
            second: crate::synthetic::ID_71C0E0E93923,
        }
    );
}

#[test]
fn invalid_identity_precedes_other_errors_on_the_same_descriptor() {
    let invalid = FormatId::new("INVALID_ID");
    let mut descriptor = descriptor(invalid, 0, &[], &[".BAD"]);
    descriptor.capabilities.decode = true;
    assert_eq!(
        FormatCatalog::new([descriptor]).err().unwrap(),
        CatalogError::InvalidFormatId(invalid)
    );
}

#[test]
fn builder_validates_decoders_during_composition() {
    let mut decoded = descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]);
    decoded.decoder = Some("image-owner");
    assert!(matches!(
        FormatCatalog::builder()
            .add_descriptor(decoded)
            .available_decoders([])
            .build(),
        Err(CatalogError::MissingDecoder {
            format: crate::synthetic::ID_B38504826C7B,
            decoder: "image-owner",
        })
    ));
    assert!(FormatCatalog::builder()
        .add_descriptor(decoded)
        .available_decoders(["image-owner"])
        .build()
        .is_ok());
}

#[test]
fn composition_order_does_not_change_descriptor_or_contender_order() {
    let mut seq = descriptor(
        crate::synthetic::ID_7EEC5564AF8B,
        10,
        MAGIC,
        &["synthetic-id-7eec5564af8b"],
    );
    seq.ambiguity_group = Some("sequence");
    seq.capabilities.confidence = Confidence::Ambiguous;
    let mut sep = descriptor(
        crate::synthetic::ID_FF823BEFE290,
        10,
        MAGIC,
        &["synthetic-id-ff823befe290"],
    );
    sep.ambiguity_group = Some("sequence");
    sep.capabilities.confidence = Confidence::Ambiguous;

    let forward = FormatCatalog::new([seq, sep]).unwrap();
    let reverse = FormatCatalog::new([sep, seq]).unwrap();
    let ids = |catalog: &FormatCatalog| {
        catalog
            .descriptors()
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<Vec<_>>()
    };
    let contenders = |catalog: &FormatCatalog| {
        catalog
            .resolve(DetectionContext::from_bytes(b"TEST"))
            .contenders
            .iter()
            .map(|candidate| candidate.descriptor.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&forward), ids(&reverse));
    assert_eq!(contenders(&forward), contenders(&reverse));
}

#[test]
fn shared_extensions_are_reported_without_rejecting_the_catalog() {
    let catalog = FormatCatalog::new([
        descriptor(crate::synthetic::ID_B38504826C7B, 20, MAGIC, &["bin"]),
        descriptor(FormatId::PNG, 10, STRUCTURAL, &["bin"]),
    ])
    .unwrap();
    assert_eq!(
        catalog.diagnostics(),
        [CatalogDiagnostic::SharedExtension {
            extension: "bin",
            formats: vec![FormatId::PNG, crate::synthetic::ID_B38504826C7B],
        }]
    );
}

#[test]
fn capability_matrix_is_sorted_and_descriptor_driven() {
    let catalog = FormatCatalog::new([
        descriptor(crate::synthetic::ID_B38504826C7B, 10, MAGIC, &[]),
        PNG_FORMAT,
    ])
    .unwrap();
    let matrix = catalog.capability_markdown();
    assert!(
        matrix.find("| png |").unwrap() < matrix.find("| synthetic-id-b38504826c7b |").unwrap()
    );
    assert!(matrix
        .contains("| png | image | — | no | no | no | no | no | no | no | exact-magic | none |"));
}
