use formatkit_core::Error;
use std::collections::BTreeMap;
use std::path::Path;

/// The pass/fail truth for one corpus subdirectory, loaded from its
/// `spec.json`. `format` defaults to the directory name when absent.
/// [`BTreeMap`] keeps sample keys in stable order, so a regenerated spec's
/// diff is limited to actual value changes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Spec {
    #[serde(default)]
    pub format: Option<String>,
    pub samples: BTreeMap<String, Sample>,
    /// Files present in the directory that this directory's handler does not
    /// cover, each mapped to the error that excluded it.
    ///
    /// Exclusion is relative to the handler, not a verdict on the file. A
    /// directory picks up sidecars of other formats and the odd helper script,
    /// and a handler may also take a narrower view than the format — a
    /// VRAM-placement check covers only the images that declare a placement it
    /// can reason about. Either way the file must be distinguishable from a
    /// sample the harness forgot, so recording it here makes the exclusion
    /// explicit and reviewable, and lets the runner insist that every file
    /// present is accounted for one way or the other. An excluded entry that
    /// starts digesting is promoted back to a sample on the next regeneration.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub excluded: BTreeMap<String, String>,
    /// Candidates excluded from the full source survey. These files are not
    /// copied into a curated selection, but their disposition remains part of
    /// the reviewable provenance for that selection.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_excluded: BTreeMap<String, String>,
}

/// One sample's decode args and expected digest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Sample {
    #[serde(default)]
    pub args: serde_json::Map<String, serde_json::Value>,
    pub expect: serde_json::Value,
}

impl Spec {
    /// Read and parse `path`. Any I/O or JSON error becomes
    /// [`Error::Malformed`] naming `path`.
    pub fn load(path: &Path) -> formatkit_core::Result<Spec> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Malformed(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&text)
            .map_err(|e| Error::Malformed(format!("{}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::Spec;
    use serde_json::json;
    use std::io::Write;

    fn write_spec(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
        let path = dir.join("spec.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_a_spec_with_no_format_override() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_spec(
            tmp.path(),
            r#"{ "samples": { "a.bin": { "expect": { "len": 4 } } } }"#,
        );
        let spec = Spec::load(&path).unwrap();
        assert_eq!(spec.format, None);
        assert_eq!(spec.samples.len(), 1);
        assert_eq!(spec.samples["a.bin"].expect, json!({ "len": 4 }));
        assert!(spec.samples["a.bin"].args.is_empty());
    }

    #[test]
    fn loads_a_spec_with_a_format_override_and_args() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_spec(
            tmp.path(),
            r#"{ "format": "gs-psmct32",
                "samples": { "a.bin": { "args": { "width": 640 }, "expect": { "len": 4 } } } }"#,
        );
        let spec = Spec::load(&path).unwrap();
        assert_eq!(spec.format.as_deref(), Some("gs-psmct32"));
        assert_eq!(spec.samples["a.bin"].args.get("width"), Some(&json!(640)));
    }

    #[test]
    fn loads_source_exclusions_from_a_curated_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_spec(
            tmp.path(),
            r#"{ "samples": { "a.bin": { "expect": { "len": 4 } } },
                "source_excluded": { "bad.bin": "invalid layout" } }"#,
        );
        let spec = Spec::load(&path).unwrap();
        assert_eq!(
            spec.source_excluded.get("bad.bin").map(String::as_str),
            Some("invalid layout")
        );
    }

    #[test]
    fn missing_file_is_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        let err = Spec::load(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&path.display().to_string()),
            "error should name the path: {msg}"
        );
    }

    #[test]
    fn invalid_json_is_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_spec(tmp.path(), "not json");
        let err = Spec::load(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&path.display().to_string()),
            "error should name the path: {msg}"
        );
    }
}
