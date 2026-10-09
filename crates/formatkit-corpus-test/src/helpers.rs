//! Digest primitives shared across format handlers.

use sha2::{Digest as _, Sha256};

const FILE_HASH_KEY: &str = "file_hash";

/// Incremental form of [`hash_bytes`] for large canonical digests.
///
/// Feeding the same byte slices in order produces exactly the SHA-256 returned
/// by `hash_bytes` over their concatenation, without materializing that
/// concatenation in memory.
pub struct HashStream(Sha256);

impl HashStream {
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish(self) -> String {
        self.0
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

impl Default for HashStream {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex sha256 of `bytes` — the canonical content hash for decoded
/// output.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Run an owner's byte reproduction once and compare it with the authenticated
/// source bytes.
///
/// The closure keeps the owner's concrete error type and allocation policy;
/// this helper only centralizes the error-propagating equality operation used
/// by corpus digests.
pub fn roundtrip_ok<E>(
    source: &[u8],
    reproduce: impl FnOnce() -> Result<Vec<u8>, E>,
) -> Result<bool, E> {
    reproduce().map(|bytes| bytes.as_slice() == source)
}

/// Attach the canonical hash of the original file bytes to a digest object.
///
/// This helper only transforms an already-built JSON value. It performs no
/// file I/O and does not parse or decode the supplied bytes. The owner remains
/// responsible for choosing the exact original byte slice and for constructing
/// every semantic field and early-return value before calling this function.
///
/// Non-object values and objects which already contain the reserved
/// `file_hash` key are rejected rather than wrapped or overwritten.
pub fn with_file_hash(
    mut digest: serde_json::Value,
    bytes: &[u8],
) -> formatkit_core::Result<serde_json::Value> {
    let object = digest.as_object_mut().ok_or_else(|| {
        formatkit_core::Error::Malformed("file-hash sidecar requires a JSON object".into())
    })?;
    if object.contains_key(FILE_HASH_KEY) {
        return Err(formatkit_core::Error::Malformed(
            "file-hash sidecar refuses reserved key file_hash".into(),
        ));
    }
    object.insert(
        FILE_HASH_KEY.to_owned(),
        serde_json::Value::String(hash_bytes(bytes)),
    );
    Ok(digest)
}

/// Canonical archive digest reused by every archive format: entry count plus
/// order-sensitive hashes of the entries' names and sizes. `names` and
/// `sizes` must be in the same (enumeration) order, and that order is part
/// of the digest — a reordering of same-content entries changes it.
pub fn archive_digest(names: &[&str], sizes: &[u64]) -> serde_json::Value {
    let names_hash = hash_bytes(names.join("\n").as_bytes());
    let mut size_bytes = Vec::with_capacity(sizes.len() * 8);
    for s in sizes {
        size_bytes.extend_from_slice(&s.to_le_bytes());
    }
    serde_json::json!({
        "entries": names.len(),
        "names_hash": names_hash,
        "sizes_hash": hash_bytes(&size_bytes),
    })
}

/// Extend an already-computed digest object with a bounded set of owner fields.
///
/// This is deliberately only a JSON assembly primitive: it performs no file
/// I/O, parsing, decoding, hashing, or owner-policy work. Callers compute the
/// base digest and every extension value first, preserving their existing
/// failure order, then hand those values here. Non-object bases and collisions
/// with either base or earlier extension keys fail closed instead of wrapping
/// or overwriting data.
pub fn extend_digest_object<const N: usize>(
    mut digest: serde_json::Value,
    fields: [(&'static str, serde_json::Value); N],
) -> formatkit_core::Result<serde_json::Value> {
    let object = digest.as_object_mut().ok_or_else(|| {
        formatkit_core::Error::Malformed("digest extension requires a JSON object".into())
    })?;
    for (key, value) in fields {
        if object.contains_key(key) {
            return Err(formatkit_core::Error::Malformed(format!(
                "digest extension refuses duplicate key {key}"
            )));
        }
        object.insert(key.to_owned(), value);
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::{
        archive_digest, extend_digest_object, hash_bytes, roundtrip_ok, with_file_hash, HashStream,
    };
    use serde_json::json;

    #[test]
    fn hash_bytes_matches_a_known_sha256_vector() {
        assert_eq!(
            hash_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_bytes_is_stable() {
        assert_eq!(hash_bytes(b"same input"), hash_bytes(b"same input"));
        assert_ne!(hash_bytes(b"a"), hash_bytes(b"b"));
    }

    #[test]
    fn roundtrip_comparison_preserves_success_mismatch_and_owner_error() {
        assert_eq!(
            roundtrip_ok(b"same", || Ok::<_, &str>(b"same".to_vec())),
            Ok(true)
        );
        assert_eq!(
            roundtrip_ok(b"same", || Ok::<_, &str>(b"other".to_vec())),
            Ok(false)
        );
        assert_eq!(
            roundtrip_ok(b"same", || Err::<Vec<u8>, _>("owner error")),
            Err("owner error")
        );
    }

    #[test]
    fn file_hash_sidecar_preserves_complete_legacy_values() {
        let empty = with_file_hash(json!({"coverage": ["sample:empty"]}), b"").unwrap();
        assert_eq!(
            empty,
            json!({
                "coverage": ["sample:empty"],
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            })
        );

        let ordinary = with_file_hash(
            json!({"coverage": ["parsed"], "nested": {"value": 7}}),
            b"abc",
        )
        .unwrap();
        assert_eq!(
            ordinary,
            json!({
                "coverage": ["parsed"],
                "file_hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "nested": {"value": 7},
            })
        );
    }

    #[test]
    fn file_hash_sidecar_rejects_non_objects_and_reserved_key_collisions() {
        for value in [
            serde_json::Value::Null,
            json!(false),
            json!(3),
            json!("object"),
            json!([]),
        ] {
            assert_eq!(
                with_file_hash(value, b"bytes").unwrap_err(),
                formatkit_core::Error::Malformed("file-hash sidecar requires a JSON object".into())
            );
        }

        assert_eq!(
            with_file_hash(json!({"file_hash": null, "semantic": 1}), b"bytes").unwrap_err(),
            formatkit_core::Error::Malformed(
                "file-hash sidecar refuses reserved key file_hash".into()
            )
        );
        assert!(with_file_hash(json!({"nested": {"file_hash": "owner-field"}}), b"bytes").is_ok());
    }

    #[test]
    fn hash_stream_matches_concatenated_bytes() {
        let mut stream = HashStream::new();
        stream.update(b"same ");
        stream.update(b"input");
        assert_eq!(stream.finish(), hash_bytes(b"same input"));
    }

    #[test]
    fn archive_digest_reports_entry_count() {
        let d = archive_digest(&["a", "b", "c"], &[1, 2, 3]);
        assert_eq!(d["entries"], json!(3));
    }

    #[test]
    fn archive_digest_is_stable_for_the_same_input() {
        let names = ["one", "two"];
        let sizes = [10u64, 20u64];
        assert_eq!(
            archive_digest(&names, &sizes),
            archive_digest(&names, &sizes)
        );
    }

    #[test]
    fn archive_digest_is_order_sensitive_on_names() {
        let a = archive_digest(&["a", "b"], &[1, 1]);
        let b = archive_digest(&["b", "a"], &[1, 1]);
        assert_ne!(
            a["names_hash"], b["names_hash"],
            "swapping names must change names_hash"
        );
    }

    #[test]
    fn archive_digest_is_sensitive_to_sizes() {
        let a = archive_digest(&["a"], &[1]);
        let b = archive_digest(&["a"], &[2]);
        assert_ne!(a["sizes_hash"], b["sizes_hash"]);
    }

    #[test]
    fn digest_extension_rejects_non_objects_and_duplicate_keys_in_order() {
        assert_eq!(
            extend_digest_object(serde_json::Value::Null, [("owner", json!(1))]).unwrap_err(),
            formatkit_core::Error::Malformed("digest extension requires a JSON object".into())
        );
        assert_eq!(
            extend_digest_object(json!({"entries": 0}), [("entries", json!(1))]).unwrap_err(),
            formatkit_core::Error::Malformed(
                "digest extension refuses duplicate key entries".into()
            )
        );
        assert_eq!(
            extend_digest_object(
                json!({"entries": 0}),
                [("owner", json!(1)), ("owner", json!(2))],
            )
            .unwrap_err(),
            formatkit_core::Error::Malformed("digest extension refuses duplicate key owner".into())
        );
    }
}
