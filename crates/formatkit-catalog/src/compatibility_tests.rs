use crate::catalog::Probe;
use crate::{Category, CompatibilityRecognitionContribution, CompatibilityRecognitionRule};
use crate::{FormatId, Method};

const OWNER_ID: FormatId = FormatId::new("synthetic-compatibility-owner");
const OTHER_OWNER_ID: FormatId = FormatId::new("synthetic-compatibility-peer");

fn accepts_complete_synthetic_input(bytes: &[u8]) -> bool {
    bytes == b"SYNTHETIC-COMPATIBILITY"
}

fn starts_with_synthetic_structure(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SYN") && bytes.len() >= 7
}

#[test]
fn owner_rule_retains_neutral_magic_guard_and_report_fields() {
    let rule = CompatibilityRecognitionRule {
        id: OWNER_ID,
        category: Category::Data,
        method: Method::Magic,
        probe: Probe::Magic {
            offset: 2,
            bytes: b"COMPAT",
        },
        guard: Some(accepts_complete_synthetic_input),
        historical_opener: Some("synthetic-owner-label"),
    };
    let copied = rule;
    assert_eq!(copied.id, OWNER_ID);
    let Probe::Magic { offset, bytes } = copied.probe else {
        panic!("magic evidence retained")
    };
    assert_eq!(offset, 2);
    assert_eq!(bytes, &b"COMPAT"[..]);
    assert_eq!(copied.method, Method::Magic);
    assert_eq!(copied.category, Category::Data);
    let guard = copied.guard.expect("owner guard retained");
    let input = b"SYNTHETIC-COMPATIBILITY";
    assert!(guard(input));
    assert!(!guard(&input[..input.len() - 1]));
    assert_eq!(copied.historical_opener, Some("synthetic-owner-label"));
}

#[test]
fn owner_contribution_keeps_structural_callback_and_separate_report_label() {
    let contribution = CompatibilityRecognitionContribution {
        rule: CompatibilityRecognitionRule {
            id: OTHER_OWNER_ID,
            category: Category::Data,
            method: Method::Structural,
            probe: Probe::Structural {
                name: "synthetic-structure",
                check: starts_with_synthetic_structure,
            },
            guard: None,
            historical_opener: None,
        },
        historical_report_format: "synthetic-compatibility-report",
    };
    let copied = contribution;
    assert_eq!(copied.rule.id, OTHER_OWNER_ID);
    assert_eq!(copied.rule.method, Method::Structural);
    assert!(copied.rule.guard.is_none());
    assert!(copied.rule.historical_opener.is_none());
    assert_eq!(
        copied.historical_report_format,
        "synthetic-compatibility-report"
    );
    let Probe::Structural { check, .. } = copied.rule.probe else {
        panic!("structural callback retained")
    };
    let input = b"SYNTHETIC-STRUCTURE";
    assert!(check(input));
    assert!(!check(b"SYN"));
}
