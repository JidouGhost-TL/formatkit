//! **`formatkit-corpus`** — shared explicit-root corpus discovery.
//!
//! Every opt-in "round-trip against a real file" test reads its samples from one
//! root: the `FORMATKIT_CORPUS_DIR` environment variable. There is exactly one
//! environment variable, and there are **no fallbacks** — no home-directory
//! probe, no baked-in default path. When `FORMATKIT_CORPUS_DIR` is unset (or empty)
//! every helper returns `None`/empty and the calling test skips.
//!
//! Layout convention: a sample lives under a per-format subdirectory of the
//! root, e.g. `$FORMATKIT_CORPUS_DIR/image/…`, `$FORMATKIT_CORPUS_DIR/archive/…`. Tests
//! address samples through [`subdir`], [`file()`], [`samples`], or [`first`].
//!
//! A configured corpus is intentionally available only under
//! `tools/run-corpus-safe.sh`. The runner serializes expensive corpus jobs and
//! marks its locked child process with `FORMATKIT_CORPUS_RUNNER_LOCKED=1`; direct
//! `cargo test` invocations with `FORMATKIT_CORPUS_DIR` set fail closed.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// The corpus root from `$FORMATKIT_CORPUS_DIR`, or `None` when it is unset or
/// empty. No fallback: an unset variable means "no corpus configured", never a
/// guessed path.
pub fn dir() -> Option<PathBuf> {
    match std::env::var_os("FORMATKIT_CORPUS_DIR") {
        Some(v) if !v.is_empty() => {
            assert_eq!(
                std::env::var_os("FORMATKIT_CORPUS_RUNNER_LOCKED").as_deref(),
                Some(std::ffi::OsStr::new("1")),
                "FORMATKIT_CORPUS_DIR is configured outside tools/run-corpus-safe.sh; \
                 refuse an unbounded or overlapping real-corpus run"
            );
            Some(PathBuf::from(v))
        }
        _ => None,
    }
}

/// Filenames the harness owns inside a corpus directory: the per-directory
/// golden `spec.json`, the root manifest layout's `manifest.json`, and the
/// `versions.json` provenance record. They describe samples; they are not
/// samples, and a sweep that treats one as a sample of its directory's format
/// is testing the harness's own bookkeeping.
pub const RESERVED_NAMES: &[&str] = &["spec.json", "manifest.json", "versions.json"];

/// Whether a filename denotes a corpus sample rather than harness bookkeeping
/// or a hidden file. The single definition — every sweep, whether it goes
/// through `spec.json` or walks the directory itself, must agree on what a
/// sample is.
pub fn is_sample_name(name: &str) -> bool {
    !RESERVED_NAMES.contains(&name) && !name.starts_with('.')
}

fn is_sample_path(path: &std::path::Path) -> bool {
    path.is_file()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_sample_name)
}

/// `<corpus>/<sub>` when it is an existing directory, else `None`.
pub fn subdir(sub: &str) -> Option<PathBuf> {
    let p = dir()?.join(sub);
    p.is_dir().then_some(p)
}

/// `<corpus>/<rel>` when it is an existing file, else `None`.
pub fn file(rel: &str) -> Option<PathBuf> {
    let p = dir()?.join(rel);
    p.is_file().then_some(p)
}

/// Every file directly inside `<corpus>/<sub>` whose extension matches `ext`
/// (case-insensitive), sorted. Empty when the corpus or subdirectory is absent —
/// for round-trip sweeps over all samples of a format.
pub fn samples(sub: &str, ext: &str) -> Vec<PathBuf> {
    let Some(d) = subdir(sub) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_sample_path(p) && p.extension().is_some_and(|x| x.eq_ignore_ascii_case(ext)))
        .collect();
    v.sort();
    v
}

/// Every regular file directly inside `<corpus>/<sub>`, sorted, with **no**
/// extension filter. Empty when the corpus or subdirectory is absent. Use this
/// for sweeps that must see all real files — an empty-`ext` call to [`samples`]
/// matches nothing, because a file's extension never equals `""`.
pub fn samples_all(sub: &str) -> Vec<PathBuf> {
    let Some(d) = subdir(sub) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_sample_path(p))
        .collect();
    v.sort();
    v
}

/// The first file (sorted) directly inside `<corpus>/<sub>`, or `None` — for a
/// test that just needs one real sample of a format.
pub fn first(sub: &str) -> Option<PathBuf> {
    let d = subdir(sub)?;
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_sample_path(p))
        .collect();
    v.sort();
    v.into_iter().next()
}

#[cfg(test)]
mod tests {
    #[test]
    fn configured_corpus_access_requires_safe_runner_marker() {
        if std::env::var_os("FORMATKIT_CORPUS_DIR").is_some_and(|value| !value.is_empty()) {
            assert!(super::dir().is_some());
        }
    }
}
