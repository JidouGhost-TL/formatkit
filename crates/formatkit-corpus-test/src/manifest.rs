//! Manifest-based corpus validation — the second corpus layout this harness
//! understands, alongside the per-subdir [`spec.json`](crate::Spec) form.
//!
//! A manifest corpus is a set of `<format>/<file>` samples under
//! `$FORMATKIT_CORPUS_DIR`, indexed by a single root **`manifest.json`**:
//!
//! ```json
//! { "version": 1, "entries": [
//!   { "id": "afs/foo.afs", "format": "afs", "roundtrip": true,
//!     "decode": false, "decode_sha256": null, "props": { ... } }
//! ] }
//! ```
//!
//! Each entry is a golden digest in a fixed shape: whether the sample
//! round-trips, an optional content hash of its decoded output, and a
//! format-specific `props` object. A format supplies a [`ManifestSubject`] that
//! recomputes those three from the raw bytes; [`run_manifest`] compares them to
//! the stored entry (or, with `FORMATKIT_CORPUS_WRITE=1`, regenerates the entries for
//! that format from the files actually present).

use std::path::Path;

use crate::hash_bytes;

/// What a [`ManifestSubject`] recomputes for one sample — the comparable half
/// of a manifest entry.
#[derive(Debug, Clone)]
pub struct Evaluated {
    /// Whether the sample round-trips (its exact meaning is the format's — a
    /// byte-identical re-emit for a leaf format, a semantic member round-trip
    /// for an archive).
    pub roundtrip: bool,
    /// Content hash of decoded output, or `None` for a format that does not
    /// decode to a single media blob (e.g. an archive).
    pub decode_sha256: Option<String>,
    /// Salient parsed fields — must be provenance-clean (no sample names, no
    /// source identifiers).
    pub props: serde_json::Value,
}

impl Evaluated {
    /// Hash `decoded` into `decode_sha256`.
    pub fn decoded(props: serde_json::Value, roundtrip: bool, decoded: &[u8]) -> Self {
        Self {
            roundtrip,
            decode_sha256: Some(hash_bytes(decoded)),
            props,
        }
    }
    /// A non-decoding sample (archives, containers).
    pub fn structural(props: serde_json::Value, roundtrip: bool) -> Self {
        Self {
            roundtrip,
            decode_sha256: None,
            props,
        }
    }
}

/// Recomputes one format's golden fields from a sample's raw bytes.
pub trait ManifestSubject {
    fn evaluate(&self, bytes: &[u8]) -> formatkit_core::Result<Evaluated>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Entry {
    id: String,
    format: String,
    #[serde(default)]
    roundtrip: bool,
    #[serde(default)]
    decode: bool,
    #[serde(default)]
    decode_sha256: Option<String>,
    #[serde(default)]
    props: serde_json::Value,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Manifest {
    version: u32,
    entries: Vec<Entry>,
}

fn required_mode() -> bool {
    std::env::var_os("FORMATKIT_CORPUS_REQUIRED").as_deref() == Some(std::ffi::OsStr::new("1"))
}
fn write_mode() -> bool {
    std::env::var_os("FORMATKIT_CORPUS_WRITE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Validate every root-`manifest.json` entry of `format` against `subject`, or
/// (with `FORMATKIT_CORPUS_WRITE=1`) regenerate those entries from the files present
/// in `$FORMATKIT_CORPUS_DIR/<format>/`. Returns the number of samples inspected;
/// 0 when the corpus or its manifest is absent — the clean-skip path. Panics
/// with a readable diff on any mismatch (this is a test helper).
pub fn run_manifest(format: &str, subject: &dyn ManifestSubject) -> usize {
    let Some(base) = formatkit_corpus::dir() else {
        assert!(
            !required_mode(),
            "FORMATKIT_CORPUS_REQUIRED=1 but FORMATKIT_CORPUS_DIR is unset"
        );
        return 0;
    };
    let manifest_path = base.join("manifest.json");
    if !manifest_path.is_file() {
        assert!(
            !required_mode(),
            "FORMATKIT_CORPUS_REQUIRED=1 but {} is absent",
            manifest_path.display()
        );
        return 0;
    }
    let text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("{}: {e}", manifest_path.display()));
    let mut manifest: Manifest =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", manifest_path.display()));

    if write_mode() {
        regenerate(&base, format, subject, &mut manifest, &manifest_path)
    } else {
        verify(&base, format, subject, &manifest)
    }
}

fn verify(base: &Path, format: &str, subject: &dyn ManifestSubject, manifest: &Manifest) -> usize {
    let mut inspected = 0usize;
    for e in manifest.entries.iter().filter(|e| e.format == format) {
        let path = base.join(&e.id);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("{}: sample unreadable: {err}", path.display()));
        let got = subject
            .evaluate(&bytes)
            .unwrap_or_else(|err| panic!("{}: evaluate failed: {err}", path.display()));
        assert_eq!(
            got.roundtrip, e.roundtrip,
            "{}: roundtrip mismatch (got {}, manifest {})",
            e.id, got.roundtrip, e.roundtrip
        );
        assert_eq!(
            got.decode_sha256, e.decode_sha256,
            "{}: decode_sha256 mismatch",
            e.id
        );
        if got.props != e.props {
            panic!(
                "{}: props mismatch\n--- manifest ---\n{}\n--- got ---\n{}",
                e.id,
                serde_json::to_string_pretty(&e.props).unwrap(),
                serde_json::to_string_pretty(&got.props).unwrap(),
            );
        }
        inspected += 1;
    }
    assert!(
        !required_mode() || inspected > 0,
        "FORMATKIT_CORPUS_REQUIRED=1 but manifest format {format:?} inspected no samples"
    );
    inspected
}

fn regenerate(
    base: &Path,
    format: &str,
    subject: &dyn ManifestSubject,
    manifest: &mut Manifest,
    manifest_path: &Path,
) -> usize {
    let dir = base.join(format);
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(formatkit_corpus::is_sample_name)
        })
        .collect();
    files.sort();

    let listed: std::collections::HashSet<&str> = manifest
        .entries
        .iter()
        .filter(|entry| entry.format == format)
        .map(|entry| entry.id.as_str())
        .collect();

    let mut regenerated = Vec::with_capacity(files.len());
    let mut rejected = Vec::new();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let ev = match subject.evaluate(&bytes) {
            Ok(ev) => ev,
            // An entry already in the manifest is a contract, so a failure there
            // is a regression. A file not yet listed is only a candidate — a
            // format directory often holds sidecars of a different format — so
            // name it and move on rather than blocking the regeneration.
            Err(e) if !listed.contains(format!("{format}/{name}").as_str()) => {
                rejected.push(format!("{name}: {e}"));
                continue;
            }
            Err(e) => panic!("{}: evaluate failed: {e}", path.display()),
        };
        regenerated.push(Entry {
            id: format!("{format}/{name}"),
            format: format.to_string(),
            roundtrip: ev.roundtrip,
            decode: ev.decode_sha256.is_some(),
            decode_sha256: ev.decode_sha256,
            props: ev.props,
        });
    }
    if !rejected.is_empty() {
        eprintln!(
            "{}: {} file(s) not enrolled as {format} samples:\n  {}",
            dir.display(),
            rejected.len(),
            rejected.join("\n  ")
        );
    }
    let count = regenerated.len();
    manifest.entries.retain(|e| e.format != format);
    manifest.entries.extend(regenerated);
    manifest.entries.sort_by(|a, b| a.id.cmp(&b.id));
    let out = serde_json::to_string_pretty(manifest).unwrap();
    std::fs::write(manifest_path, out)
        .unwrap_or_else(|e| panic!("{}: {e}", manifest_path.display()));
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A trivial subject: props record the byte length, roundtrip is "even".
    struct LenSubject;
    impl ManifestSubject for LenSubject {
        fn evaluate(&self, bytes: &[u8]) -> formatkit_core::Result<Evaluated> {
            Ok(Evaluated::structural(
                json!({ "len": bytes.len() }),
                bytes.len().is_multiple_of(2),
            ))
        }
    }

    fn seed(base: &Path) {
        std::fs::create_dir(base.join("blob")).unwrap();
        std::fs::write(base.join("blob/a.bin"), b"abcd").unwrap(); // len 4 -> even
        std::fs::write(base.join("blob/b.bin"), b"xyz").unwrap(); // len 3 -> odd
    }

    #[test]
    fn regenerate_then_verify_round_trips_and_preserves_other_formats() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        seed(base);
        let mp = base.join("manifest.json");
        // a pre-existing entry of another format must survive regeneration
        let mut manifest = Manifest {
            version: 1,
            entries: vec![Entry {
                id: "other/keep.bin".into(),
                format: "other".into(),
                roundtrip: true,
                decode: false,
                decode_sha256: None,
                props: json!({ "keep": 1 }),
            }],
        };
        assert_eq!(regenerate(base, "blob", &LenSubject, &mut manifest, &mp), 2);

        let reloaded: Manifest =
            serde_json::from_str(&std::fs::read_to_string(&mp).unwrap()).unwrap();
        assert_eq!(reloaded.entries.len(), 3); // 1 other + 2 blob
        assert!(reloaded.entries.iter().any(|e| e.format == "other"));
        assert_eq!(verify(base, "blob", &LenSubject, &reloaded), 2);
    }

    /// Rejects odd-length files, so a directory can hold both samples of this
    /// format and sidecars of another.
    struct EvenSubject;
    impl ManifestSubject for EvenSubject {
        fn evaluate(&self, bytes: &[u8]) -> formatkit_core::Result<Evaluated> {
            if bytes.len().is_multiple_of(2) {
                Ok(Evaluated::structural(json!({ "len": bytes.len() }), true))
            } else {
                Err(formatkit_core::Error::Malformed("odd length".into()))
            }
        }
    }

    #[test]
    fn regenerate_skips_an_unlisted_file_the_subject_cannot_evaluate() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        seed(base); // a.bin is even, b.bin is odd
        let mut manifest = Manifest {
            version: 1,
            entries: vec![],
        };
        // b.bin is a sidecar this format cannot read; it must not block the
        // regeneration of the sample that can.
        assert_eq!(
            regenerate(
                base,
                "blob",
                &EvenSubject,
                &mut manifest,
                &base.join("manifest.json")
            ),
            1
        );
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].id, "blob/a.bin");
    }

    /// A file already in the manifest is a contract, so a regeneration that
    /// can no longer evaluate it fails rather than dropping it.
    #[test]
    #[should_panic(expected = "b.bin")]
    fn regenerate_will_not_drop_a_listed_entry_that_stops_evaluating() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        seed(base);
        let mut manifest = Manifest {
            version: 1,
            entries: vec![Entry {
                id: "blob/b.bin".into(),
                format: "blob".into(),
                roundtrip: false,
                decode: false,
                decode_sha256: None,
                props: json!({ "len": 3 }),
            }],
        };
        regenerate(
            base,
            "blob",
            &EvenSubject,
            &mut manifest,
            &base.join("manifest.json"),
        );
    }

    #[test]
    #[should_panic(expected = "props mismatch")]
    fn verify_detects_a_changed_sample() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        seed(base);
        let mp = base.join("manifest.json");
        let mut manifest = Manifest {
            version: 1,
            entries: vec![],
        };
        regenerate(base, "blob", &LenSubject, &mut manifest, &mp);
        let reloaded: Manifest =
            serde_json::from_str(&std::fs::read_to_string(&mp).unwrap()).unwrap();
        // Mutating a sample changes its digest -> verify must catch it.
        std::fs::write(base.join("blob/a.bin"), b"abcdef").unwrap();
        verify(base, "blob", &LenSubject, &reloaded);
    }
}
