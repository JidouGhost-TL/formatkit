use crate::{Args, Digest, Spec};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Maps a format name (`spec.json`'s `format`, or a directory name) to the
/// [`Digest`] handler that validates it.
#[derive(Default)]
pub struct Registry(HashMap<&'static str, Box<dyn Digest>>);

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, format: &'static str, handler: Box<dyn Digest>) -> &mut Self {
        self.0.insert(format, handler);
        self
    }

    pub fn get(&self, format: &str) -> Option<&dyn Digest> {
        self.0.get(format).map(|b| b.as_ref())
    }
}

/// `$FORMATKIT_CORPUS_WRITE=1` switches every runner call from asserting to
/// regenerating `spec.json` from the freshly computed digests.
fn write_mode() -> bool {
    std::env::var_os("FORMATKIT_CORPUS_WRITE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Opt-in required-run guard: configured corpus runs must inspect real samples instead
/// of silently taking the normal developer-machine skip path.
pub fn required_mode() -> bool {
    std::env::var_os("FORMATKIT_CORPUS_REQUIRED").as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// The corpus root for a test that reads samples **directly** rather than
/// through [`run_dir`]'s `spec.json` machinery, honouring `FORMATKIT_CORPUS_REQUIRED`.
///
/// This exists because the gate used to live only inside `run_dir`. Oracles that
/// walk the corpus themselves called [`formatkit_corpus::dir`] and returned early on
/// `None`, which put them on the far side of the guard: with no corpus they
/// printed a skip line and reported success, so the suites carrying the entire
/// real-data proof were exactly the ones the no-vacuous-pass switch could not
/// reach. Anything sweeping the corpus by hand must come through here.
///
/// `what` names the check, so a required-mode failure says which one went vacuous.
pub fn corpus_root(what: &str) -> Option<std::path::PathBuf> {
    match formatkit_corpus::dir() {
        Some(base) => Some(base),
        None => {
            assert!(
                !required_mode(),
                "FORMATKIT_CORPUS_REQUIRED=1 but FORMATKIT_CORPUS_DIR is unset — {what} would pass vacuously"
            );
            eprintln!("no corpus configured; skipping {what}");
            None
        }
    }
}

/// Verify that every JSON-owned sample in `dir` has a matching root
/// `versions.json` entry. `digest_field` names the sample's expected SHA-256
/// field; `required_fields` names non-null ledger metadata required by the
/// format's curation contract.
///
/// Keeping this traversal in the shared harness prevents format tests from
/// acquiring sample paths or cardinality outside [`run_dir`]'s JSON contract.
pub fn verify_versioned_samples(
    dir: &str,
    digest_field: &str,
    expected_format: &str,
    required_fields: &[&str],
) -> usize {
    let Some(base) = corpus_root(&format!("{dir} version ledger")) else {
        return 0;
    };
    let subdir = base.join(dir);
    let spec_path = subdir.join("spec.json");
    if !spec_path.is_file() {
        assert!(
            !required_mode(),
            "FORMATKIT_CORPUS_REQUIRED=1 but {} is absent",
            spec_path.display()
        );
        eprintln!("{} is absent; skipping version ledger", spec_path.display());
        return 0;
    }
    let spec =
        Spec::load(&spec_path).unwrap_or_else(|error| panic!("{}: {error}", spec_path.display()));
    assert!(
        !spec.samples.is_empty(),
        "{} has no samples",
        spec_path.display()
    );
    let versions_path = base.join("versions.json");
    let versions: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&versions_path)
            .unwrap_or_else(|error| panic!("{}: {error}", versions_path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", versions_path.display()));

    for (relative, sample) in &spec.samples {
        let digest = sample.expect[digest_field].as_str().unwrap_or_else(|| {
            panic!(
                "{}: sample {relative:?} lacks string digest field {digest_field:?}",
                spec_path.display()
            )
        });
        assert!(
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{}: sample {relative:?} has invalid SHA-256 {digest:?}",
            spec_path.display()
        );
        let bytes = std::fs::read(subdir.join(relative)).unwrap_or_else(|error| {
            panic!(
                "{}: sample {relative:?} is unreadable: {error}",
                spec_path.display()
            )
        });
        assert_eq!(
            crate::hash_bytes(&bytes),
            digest,
            "{}: sample {relative:?} digest differs from {digest_field:?}",
            spec_path.display()
        );
        let row = versions.get(digest).unwrap_or_else(|| {
            panic!(
                "{} lacks sample {relative:?} digest {digest}",
                versions_path.display()
            )
        });
        assert_eq!(
            row["format"],
            expected_format,
            "{}: sample {relative:?} has the wrong format ledger value",
            versions_path.display()
        );
        if let Some(size) = row.get("size") {
            assert_eq!(
                size.as_u64(),
                Some(bytes.len() as u64),
                "{}: sample {relative:?} has the wrong ledger size",
                versions_path.display()
            );
        }
        for field in required_fields {
            let value = row.get(*field).unwrap_or_else(|| {
                panic!(
                    "{}: sample {relative:?} lacks ledger field {field:?}",
                    versions_path.display()
                )
            });
            assert!(
                match value {
                    serde_json::Value::Null => false,
                    serde_json::Value::String(value) => !value.is_empty(),
                    serde_json::Value::Array(value) => !value.is_empty(),
                    serde_json::Value::Object(value) => !value.is_empty(),
                    _ => true,
                },
                "{}: sample {relative:?} has an empty ledger field {field:?}",
                versions_path.display()
            );
        }
    }
    spec.samples.len()
}

/// Run every sample in an already-loaded `spec` against `handler`, either
/// asserting each digest against `expect` (`write = false`) or overwriting
/// `expect` with the computed digest and persisting `spec_path` (`write =
/// true`). Panics naming `dir/filename` on a missing file or a mismatch.
///
/// `candidates` names entries this run added speculatively from the directory
/// listing. They are the only entries a failure can *demote*: everything else
/// in the spec is a standing contract, so a failure there is a regression and
/// panics even under `write`.
fn run_spec(
    subdir: &Path,
    spec_path: &Path,
    mut spec: Spec,
    handler: &dyn Digest,
    write: bool,
    candidates: &std::collections::BTreeSet<String>,
) -> usize {
    assert!(
        !spec.samples.is_empty(),
        "{}: spec present but lists no samples",
        spec_path.display()
    );
    let mut inspected = 0usize;
    let mut demoted: Vec<(String, String)> = Vec::new();
    for (filename, sample) in spec.samples.iter_mut() {
        let file_path = subdir.join(filename);
        let speculative = write && candidates.contains(filename);
        let bytes = match std::fs::read(&file_path) {
            Ok(bytes) => bytes,
            Err(e) if speculative => {
                demoted.push((filename.clone(), format!("unreadable: {e}")));
                continue;
            }
            Err(e) => panic!("{}: sample file unreadable: {e}", file_path.display()),
        };
        let args = Args(sample.args.clone());
        let got = match handler.digest(&bytes, &args) {
            Ok(got) => got,
            Err(e) if speculative => {
                demoted.push((filename.clone(), e.to_string()));
                continue;
            }
            Err(e) => panic!("{}: digest failed: {e}", file_path.display()),
        };
        if write {
            sample.expect = got;
        } else if got != sample.expect {
            panic!(
                "{}/{filename}: digest mismatch\n--- expected ---\n{}\n--- got ---\n{}",
                subdir.display(),
                serde_json::to_string_pretty(&sample.expect).unwrap(),
                serde_json::to_string_pretty(&got).unwrap(),
            );
        }
        inspected += 1;
    }

    for (name, why) in &demoted {
        spec.samples.remove(name);
        spec.excluded.insert(name.clone(), why.clone());
    }
    if !demoted.is_empty() {
        eprintln!(
            "{}: {} file(s) recorded as excluded — this handler does not cover them. Each is a \
             sample needing `args` by hand, a file outside this handler's view, or a file that \
             does not belong in the corpus:\n  {}",
            subdir.display(),
            demoted.len(),
            demoted
                .iter()
                .map(|(name, why)| format!("{name}: {why}"))
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    if write {
        if spec.samples.is_empty() {
            eprintln!(
                "{}: nothing enrolled; leaving the directory without a spec",
                subdir.display()
            );
            return 0;
        }
        let text = serde_json::to_string_pretty(&spec).unwrap();
        std::fs::write(spec_path, text)
            .unwrap_or_else(|e| panic!("{}: spec unwritable: {e}", spec_path.display()));
    }
    inspected
}

/// The sample files sitting in a corpus subdirectory, per
/// [`formatkit_corpus::is_sample_name`] — the one definition every sweep shares.
fn sample_files(subdir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(subdir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| formatkit_corpus::is_sample_name(name))
        .collect();
    names.sort();
    names
}

/// Files present in a directory that the spec accounts for in neither
/// direction: not a sample to check, not a declared exclusion to explain.
fn unlisted_files<'a>(present: &'a [String], spec: &Spec) -> Vec<&'a str> {
    present
        .iter()
        .filter(|name| !spec.samples.contains_key(*name) && !spec.excluded.contains_key(*name))
        .map(|name| name.as_str())
        .collect()
}

fn run_dir_at(base: &Path, dir: &str, handler: &dyn Digest, write: bool) -> usize {
    let subdir = base.join(dir);
    if !subdir.is_dir() {
        return 0;
    }
    let spec_path = subdir.join("spec.json");
    let mut spec = match (spec_path.is_file(), write) {
        (true, _) => Spec::load(&spec_path).unwrap_or_else(|e| panic!("{e}")),
        // Write mode provisions a subdirectory that has samples but no spec —
        // otherwise a newly added format stays invisible until someone
        // hand-writes a file listing, and an invisible format is one whose
        // test reports success having read nothing.
        (false, true) => Spec {
            format: None,
            samples: Default::default(),
            excluded: Default::default(),
            source_excluded: Default::default(),
        },
        (false, false) => return 0,
    };

    let present = sample_files(&subdir);
    let mut candidates = std::collections::BTreeSet::new();
    if write {
        // Every unlisted file becomes a speculative sample. `run_spec` digests
        // it once and either keeps it or records why it is not a sample, so a
        // directory is classified in a single pass rather than digested twice.
        // Previously rejected files are re-offered, so one that starts parsing
        // is promoted back.
        spec.excluded.clear();
        for name in &present {
            if spec.samples.contains_key(name) {
                continue;
            }
            candidates.insert(name.clone());
            spec.samples.insert(
                name.clone(),
                crate::Sample {
                    args: Default::default(),
                    expect: serde_json::Value::Null,
                },
            );
        }
    } else {
        // A file nobody listed — neither as a sample nor as a declared
        // exclusion — is a file nobody checks and nobody decided about. Report
        // it always; required mode makes it a failure, matching how the corpus
        // gate treats every other way of quietly inspecting nothing.
        let unlisted = unlisted_files(&present, &spec);
        if !unlisted.is_empty() {
            let message = format!(
                "{}: {} file(s) present but in neither `samples` nor `excluded`, so nothing \
                 checks them and nothing says why: {}\nRe-run with FORMATKIT_CORPUS_WRITE=1 to classify.",
                subdir.display(),
                unlisted.len(),
                unlisted.join(", ")
            );
            assert!(!required_mode(), "{message}");
            eprintln!("{message}");
        }
    }

    run_spec(&subdir, &spec_path, spec, handler, write, &candidates)
}

/// Run one corpus subdir `<FORMATKIT_CORPUS_DIR>/<dir>` against `handler`, using
/// its `spec.json`. Returns the number of sample files inspected (0 if the
/// corpus, the subdir, or its spec is absent — a clean skip). Panics with a
/// readable JSON diff on any mismatch (this is a test helper).
pub fn run_dir(dir: &str, handler: &dyn Digest) -> usize {
    let base = formatkit_corpus::dir().unwrap_or_else(|| {
        assert!(
            !required_mode(),
            "FORMATKIT_CORPUS_REQUIRED=1 but FORMATKIT_CORPUS_DIR is unset"
        );
        PathBuf::new()
    });
    if base.as_os_str().is_empty() {
        return 0;
    }
    let inspected = run_dir_at(&base, dir, handler, write_mode());
    assert!(
        !required_mode() || inspected > 0,
        "FORMATKIT_CORPUS_REQUIRED=1 but corpus format {dir:?} inspected no samples"
    );
    inspected
}

/// Run the `spec.json` located directly at `$FORMATKIT_CORPUS_DIR`.
///
/// This is for an umbrella corpus whose samples span several format families;
/// ordinary one-format suites should continue to use [`run_dir`]. Required
/// mode has the same non-vacuous semantics as [`run_dir`].
fn run_root_at(base: &Path, handler: &dyn Digest, write: bool) -> usize {
    let spec_path = base.join("spec.json");
    if !spec_path.is_file() {
        return 0;
    }
    let spec = Spec::load(&spec_path).unwrap_or_else(|e| panic!("{e}"));
    run_spec(base, &spec_path, spec, handler, write, &Default::default())
}

pub fn run_root(handler: &dyn Digest) -> usize {
    let base = formatkit_corpus::dir().unwrap_or_else(|| {
        assert!(
            !required_mode(),
            "FORMATKIT_CORPUS_REQUIRED=1 but FORMATKIT_CORPUS_DIR is unset"
        );
        PathBuf::new()
    });
    if base.as_os_str().is_empty() {
        return 0;
    }
    let inspected = run_root_at(&base, handler, write_mode());
    assert!(
        !required_mode() || inspected > 0,
        "FORMATKIT_CORPUS_REQUIRED=1 but the corpus-root spec inspected no samples"
    );
    inspected
}

fn run_all_at(base: &Path, registry: &Registry, write: bool) -> usize {
    let Ok(entries) = std::fs::read_dir(base) else {
        return 0;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    let mut subdirs_with_spec = 0usize;
    let mut inspected = 0usize;
    for subdir in dirs {
        let spec_path = subdir.join("spec.json");
        if !spec_path.is_file() {
            continue;
        }
        subdirs_with_spec += 1;
        let spec = Spec::load(&spec_path).unwrap_or_else(|e| panic!("{e}"));
        let dir_name = subdir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let format = spec.format.clone().unwrap_or_else(|| dir_name.clone());
        let handler = registry.get(&format).unwrap_or_else(|| {
            panic!("no handler registered for format {format:?} (dir {dir_name:?})")
        });
        inspected += run_spec(
            &subdir,
            &spec_path,
            spec,
            handler,
            write,
            &Default::default(),
        );
    }
    assert!(
        subdirs_with_spec == 0 || inspected > 0,
        "non-vacuous guard: {subdirs_with_spec} spec'd subdir(s) present but 0 files inspected"
    );
    inspected
}

/// Iterate every subdir of the corpus that has a `spec.json`, dispatch each
/// by `spec.format ?? dir_name` through `registry`, and run it. Returns total
/// files inspected. Non-vacuous: if >=1 subdir with a `spec.json` is
/// present, asserts total inspected > 0.
pub fn run_all(registry: &Registry) -> usize {
    let base = formatkit_corpus::dir().unwrap_or_else(|| {
        assert!(
            !required_mode(),
            "FORMATKIT_CORPUS_REQUIRED=1 but FORMATKIT_CORPUS_DIR is unset"
        );
        PathBuf::new()
    });
    if base.as_os_str().is_empty() {
        return 0;
    }
    let inspected = run_all_at(&base, registry, write_mode());
    assert!(
        !required_mode() || inspected > 0,
        "FORMATKIT_CORPUS_REQUIRED=1 but the corpus inspected no samples"
    );
    inspected
}

#[cfg(test)]
mod tests {
    use super::{run_all_at, run_dir_at, run_root_at, Registry};
    use crate::{Args, Digest};
    use serde_json::json;
    use std::path::Path;

    struct Len;

    impl Digest for Len {
        fn digest(&self, bytes: &[u8], _args: &Args) -> formatkit_core::Result<serde_json::Value> {
            Ok(json!({ "len": bytes.len() }))
        }
    }

    fn write_spec(dir: &Path, contents: &str) {
        std::fs::write(dir.join("spec.json"), contents).unwrap();
    }

    #[test]
    fn run_dir_at_skips_a_missing_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let n = run_dir_at(tmp.path(), "does-not-exist", &Len, false);
        assert_eq!(n, 0);
    }

    #[test]
    fn run_dir_at_skips_a_subdir_with_no_spec() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let n = run_dir_at(tmp.path(), "sub", &Len, false);
        assert_eq!(n, 0);
    }

    #[test]
    fn run_dir_at_happy_path_returns_inspected_count() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        write_spec(
            &sub,
            r#"{ "samples": { "a.bin": { "expect": { "len": 4 } } } }"#,
        );
        let n = run_dir_at(tmp.path(), "sub", &Len, false);
        assert_eq!(n, 1);
    }

    #[test]
    fn run_root_at_reads_a_spec_directly_from_the_base() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.bin"), b"abcd").unwrap();
        write_spec(
            tmp.path(),
            r#"{ "samples": { "a.bin": { "expect": { "len": 4 } } } }"#,
        );
        assert_eq!(run_root_at(tmp.path(), &Len, false), 1);
    }

    #[test]
    #[should_panic(expected = "a.bin")]
    fn run_dir_at_panics_on_mismatch_naming_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        write_spec(
            &sub,
            r#"{ "samples": { "a.bin": { "expect": { "len": 999 } } } }"#,
        );
        run_dir_at(tmp.path(), "sub", &Len, false);
    }

    #[test]
    #[should_panic]
    fn run_dir_at_panics_on_a_spec_with_no_samples() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        write_spec(&sub, r#"{ "samples": {} }"#);
        run_dir_at(tmp.path(), "sub", &Len, false);
    }

    #[test]
    fn run_dir_at_missing_sample_file_panics_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        write_spec(
            &sub,
            r#"{ "samples": { "absent.dat": { "expect": { "len": 4 } } } }"#,
        );
        let result = std::panic::catch_unwind(|| run_dir_at(tmp.path(), "sub", &Len, false));
        let err = result.unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s: &&str| s.to_string()))
            .unwrap_or_default();
        assert!(msg.contains("absent.dat"), "message was: {msg}");
    }

    #[test]
    fn run_dir_at_regen_rewrites_expect_and_a_rerun_then_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        write_spec(&sub, r#"{ "samples": { "a.bin": { "expect": null } } }"#);

        let n = run_dir_at(tmp.path(), "sub", &Len, true);
        assert_eq!(n, 1);

        let rewritten = std::fs::read_to_string(sub.join("spec.json")).unwrap();
        assert!(
            rewritten.contains("\"len\""),
            "spec.json was not rewritten: {rewritten}"
        );

        // A subsequent read-mode run against the regenerated spec must pass.
        let n2 = run_dir_at(tmp.path(), "sub", &Len, false);
        assert_eq!(n2, 1);
    }

    /// A `Digest` that only accepts even-length files, so a directory can hold
    /// both enrollable samples and files that are not samples of this format.
    struct EvenLen;

    impl Digest for EvenLen {
        fn digest(&self, bytes: &[u8], _args: &Args) -> formatkit_core::Result<serde_json::Value> {
            if bytes.len().is_multiple_of(2) {
                Ok(json!({ "len": bytes.len() }))
            } else {
                Err(formatkit_core::Error::Malformed("odd length".into()))
            }
        }
    }

    fn load(sub: &Path) -> crate::Spec {
        crate::Spec::load(&sub.join("spec.json")).unwrap()
    }

    #[test]
    fn write_mode_provisions_a_spec_for_a_directory_that_has_none() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        std::fs::write(sub.join("b.bin"), b"ef").unwrap();

        assert_eq!(run_dir_at(tmp.path(), "sub", &Len, true), 2);
        let spec = load(&sub);
        assert_eq!(spec.samples.len(), 2);
        assert_eq!(spec.samples["a.bin"].expect, json!({ "len": 4 }));
        // And the provisioned spec is immediately usable in read mode.
        assert_eq!(run_dir_at(tmp.path(), "sub", &Len, false), 2);
    }

    #[test]
    fn write_mode_enrolls_new_files_into_an_existing_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        write_spec(
            &sub,
            r#"{ "samples": { "a.bin": { "expect": { "len": 4 } } } }"#,
        );
        std::fs::write(sub.join("new.bin"), b"xy").unwrap();

        assert_eq!(run_dir_at(tmp.path(), "sub", &Len, true), 2);
        assert_eq!(load(&sub).samples["new.bin"].expect, json!({ "len": 2 }));
    }

    #[test]
    fn a_candidate_that_does_not_digest_is_recorded_as_not_a_sample() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("good.bin"), b"abcd").unwrap();
        std::fs::write(sub.join("sidecar.txt"), b"xyz").unwrap();

        assert_eq!(run_dir_at(tmp.path(), "sub", &EvenLen, true), 1);
        let spec = load(&sub);
        assert_eq!(spec.samples.len(), 1);
        assert!(spec.excluded["sidecar.txt"].contains("odd length"));

        // Read mode accepts the directory: every file is accounted for, one as
        // a sample and one as a declared non-sample.
        assert_eq!(run_dir_at(tmp.path(), "sub", &EvenLen, false), 1);
    }

    /// A file listed as a sample is a contract: it must keep digesting, and a
    /// regeneration that hits an error there fails rather than demoting it.
    #[test]
    #[should_panic(expected = "was.bin")]
    fn write_mode_does_not_demote_a_listed_sample_that_stops_digesting() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("was.bin"), b"xyz").unwrap();
        write_spec(
            &sub,
            r#"{ "samples": { "was.bin": { "expect": { "len": 3 } } } }"#,
        );
        run_dir_at(tmp.path(), "sub", &EvenLen, true);
    }

    #[test]
    fn a_rejected_file_is_promoted_back_once_it_digests() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        std::fs::write(sub.join("later.bin"), b"xyz").unwrap();
        assert_eq!(run_dir_at(tmp.path(), "sub", &EvenLen, true), 1);
        assert!(load(&sub).excluded.contains_key("later.bin"));

        std::fs::write(sub.join("later.bin"), b"xyzw").unwrap();
        assert_eq!(run_dir_at(tmp.path(), "sub", &EvenLen, true), 2);
        let spec = load(&sub);
        assert!(spec.excluded.is_empty());
        assert_eq!(spec.samples["later.bin"].expect, json!({ "len": 4 }));
    }

    #[test]
    fn a_file_the_spec_does_not_account_for_is_reported_as_unlisted() {
        let spec: crate::Spec = serde_json::from_str(
            r#"{ "samples": { "a.bin": { "expect": null } },
                 "excluded": { "b.txt": "not this format" } }"#,
        )
        .unwrap();
        let present = ["a.bin", "b.txt", "stray.bin"].map(String::from);
        assert_eq!(super::unlisted_files(&present, &spec), ["stray.bin"]);

        // Everything accounted for, in either direction, leaves nothing to report.
        let present = ["a.bin", "b.txt"].map(String::from);
        assert!(super::unlisted_files(&present, &spec).is_empty());
    }

    #[test]
    fn the_spec_itself_is_never_treated_as_a_sample() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        std::fs::write(sub.join("manifest.json"), b"{}").unwrap();

        assert_eq!(run_dir_at(tmp.path(), "sub", &Len, true), 1);
        let spec = load(&sub);
        assert_eq!(spec.samples.keys().collect::<Vec<_>>(), ["a.bin"]);
        assert!(spec.excluded.is_empty());
    }

    #[test]
    fn run_all_at_is_non_vacuous_with_a_present_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        write_spec(
            &sub,
            r#"{ "samples": { "a.bin": { "expect": { "len": 4 } } } }"#,
        );
        let mut registry = Registry::new();
        registry.register("sub", Box::new(Len));

        let n = run_all_at(tmp.path(), &registry, false);
        assert!(n > 0);
    }

    #[test]
    fn run_all_at_dispatches_by_format_override_not_dir_name() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.bin"), b"abcd").unwrap();
        write_spec(
            &sub,
            r#"{ "format": "len-format",
                "samples": { "a.bin": { "expect": { "len": 4 } } } }"#,
        );
        let mut registry = Registry::new();
        registry.register("len-format", Box::new(Len));

        let n = run_all_at(tmp.path(), &registry, false);
        assert_eq!(n, 1);
    }

    #[test]
    fn run_all_at_returns_zero_with_no_specd_subdirs_and_does_not_panic() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("empty")).unwrap();
        let registry = Registry::new();
        let n = run_all_at(tmp.path(), &registry, false);
        assert_eq!(n, 0);
    }

    #[test]
    fn run_all_at_skips_cleanly_when_base_is_absent() {
        let n = run_all_at(
            Path::new("/nonexistent/does-not-exist"),
            &Registry::new(),
            false,
        );
        assert_eq!(n, 0);
    }

    #[test]
    fn registry_get_returns_none_for_unregistered_format() {
        let registry = Registry::new();
        assert!(registry.get("nope").is_none());
    }
}
