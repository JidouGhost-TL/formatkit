use formatkit_corpus_test::{archive_digest, extend_digest_object};
use serde_json::{json, Value};

fn legacy<const N: usize>(mut digest: Value, fields: [(&'static str, Value); N]) -> Value {
    for (key, value) in fields {
        digest[key] = value;
    }
    digest
}

fn assert_legacy_parity<const N: usize>(
    names: &[&str],
    sizes: &[u64],
    fields: [(&'static str, Value); N],
) {
    let expected = legacy(archive_digest(names, sizes), fields.clone());
    let actual = extend_digest_object(archive_digest(names, sizes), fields).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}

#[test]
fn empty_and_nonempty_archive_extensions_match_legacy_assignment_exactly() {
    assert_legacy_parity(
        &[],
        &[],
        [("archive_type", json!(1)), ("subtype", json!(0))],
    );
    assert_legacy_parity(
        &["one", "two"],
        &[3, 5],
        [
            ("raw_names_hash", json!("raw")),
            ("contents_hash", json!("contents")),
            ("mount_directory_bytes", json!(72)),
            ("attr_offset", Value::Null),
            ("attr_size", json!(0)),
        ],
    );
    assert_legacy_parity(
        &["named"],
        &[7],
        [
            ("coverage", json!(["kind:container"])),
            ("kind", json!("container")),
            ("raw_names_hash", json!("raw")),
            ("placements_hash", json!("placements")),
            ("stored_bodies_hash", json!("stored")),
            ("directory_bytes", json!(32)),
            ("directory_hash", json!("directory")),
            ("directory_padding_bytes", json!(0)),
            ("directory_padding_hash", json!("padding")),
            ("has_terminator", json!(true)),
            ("trailing_bytes", json!(0)),
            ("trailing_hash", json!("trailing")),
            ("all_names_printable", json!(true)),
            ("all_sizes_nonzero", json!(true)),
            ("identity_exact", json!(true)),
            ("same_size_edit_byte_local", json!(true)),
            ("resize_edit_semantic", json!(true)),
            ("semantic_build", json!(true)),
        ],
    );
}
