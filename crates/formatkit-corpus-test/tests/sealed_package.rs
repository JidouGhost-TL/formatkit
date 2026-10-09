#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

//! Neutral admission matrix for [`formatkit_corpus_test::sealed_package`].
//!
//! Every fixture is synthetic and built at runtime under a private
//! temporary directory: no fixed bytes, counts, hashes, or names from any
//! external package appear here. Each test drives admission through the
//! public entry points and asserts the exact [`SealedErrorKind`].

use formatkit_corpus_test::{
    curated_v1_cases, decode_sha256, expected_digest_from_env, parse_expected_digest,
    AdmissionProbe, SealedBounds, SealedError, SealedErrorKind, SealedPackage, UnverifiedCase,
    MANIFEST_SHA256_ENV_VAR,
};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

const PACKAGE: &str = "fixture-v1";
const MANIFEST: &str = "spec.json";

fn bounds() -> SealedBounds {
    SealedBounds::new(8192, 16, 2048, 4096, 256, 8)
}

fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn write_tree(root: &Path, files: &[(&str, &[u8])]) {
    for (relative, bytes) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
    }
}

/// A synthetic package on disk plus the digest of its exact manifest bytes.
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    package: String,
    manifest: String,
    manifest_bytes: Vec<u8>,
    expected: [u8; 32],
}

impl Fixture {
    fn open(&self) -> Result<SealedPackage, SealedError> {
        self.open_with(bounds(), &self.expected)
    }

    fn open_with(
        &self,
        bounds: SealedBounds,
        expected: &[u8; 32],
    ) -> Result<SealedPackage, SealedError> {
        SealedPackage::open(&self.root, &self.package, &self.manifest, expected, bounds)
    }

    fn open_probed(
        &self,
        bounds: SealedBounds,
        probe: &mut dyn AdmissionProbe,
    ) -> Result<SealedPackage, SealedError> {
        SealedPackage::open_with_probe(
            &self.root,
            &self.package,
            &self.manifest,
            &self.expected,
            bounds,
            probe,
        )
    }
}

fn manifest_for(cases: &[(&str, &[u8])]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = cases
        .iter()
        .map(|(path, bytes)| {
            serde_json::json!({
                "path": path,
                "sha256": sha_hex(bytes),
                "size": bytes.len(),
                "role": "positive",
                "outcome": "accept",
            })
        })
        .collect();
    serde_json::json!({
        "schema": "formatkit.curated-corpus-package.v1",
        "format": "neutral-fixture",
        "package": PACKAGE,
        "cases": entries,
    })
    .to_string()
    .into_bytes()
}

/// Build a valid package: `files` are written verbatim and the manifest is
/// generated from `cases` (which usually match `files` exactly).
fn seal_with(package: &str, manifest: &str, files: &[(&str, &[u8])]) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(package);
    std::fs::create_dir_all(&directory).unwrap();
    write_tree(&directory, files);
    let manifest_bytes = manifest_for(files);
    std::fs::write(directory.join(manifest), &manifest_bytes).unwrap();
    let expected = sha_bytes(&manifest_bytes);
    Fixture {
        _temp: temp,
        root,
        package: package.to_owned(),
        manifest: manifest.to_owned(),
        manifest_bytes,
        expected,
    }
}

fn seal(files: &[(&str, &[u8])]) -> Fixture {
    seal_with(PACKAGE, MANIFEST, files)
}

/// Build a package with caller-supplied raw manifest bytes (for malformed,
/// duplicate-key, or schema-violation envelopes). `expected` defaults to
/// the digest of those exact bytes.
fn seal_raw_with(
    package: &str,
    manifest: &str,
    files: &[(&str, &[u8])],
    manifest_bytes: &[u8],
) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(package);
    std::fs::create_dir_all(&directory).unwrap();
    write_tree(&directory, files);
    let manifest_path = directory.join(manifest);
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&manifest_path, manifest_bytes).unwrap();
    let expected = sha_bytes(manifest_bytes);
    Fixture {
        _temp: temp,
        root,
        package: package.to_owned(),
        manifest: manifest.to_owned(),
        manifest_bytes: manifest_bytes.to_vec(),
        expected,
    }
}

fn seal_raw(files: &[(&str, &[u8])], manifest_bytes: &[u8]) -> Fixture {
    seal_raw_with(PACKAGE, MANIFEST, files, manifest_bytes)
}

/// Assert admission rejects with the exact kind. The simulated parser only
/// runs inside the success branch, so a rejection structurally yields no
/// parser input; any success panics with the invocation count attached.
fn assert_rejects(result: Result<SealedPackage, SealedError>, kind: SealedErrorKind, label: &str) {
    let mut parser_invocations = 0usize;
    match result {
        Ok(package) => {
            for case in package.cases() {
                parser_invocations += 1;
                std::hint::black_box(case.bytes());
            }
            panic!("{label}: admission succeeded; parser would run {parser_invocations} times");
        }
        Err(error) => {
            assert_eq!(
                parser_invocations, 0,
                "{label}: parser ran without a package"
            );
            assert_eq!(
                error.kind(),
                kind,
                "{label}: wrong rejection kind ({error})"
            );
        }
    }
}

#[test]
fn valid_nested_package_admits_with_exact_bytes() {
    let files: &[(&str, &[u8])] = &[
        ("top.bin", b"top-level bytes"),
        ("nested/middle.bin", b"nested bytes"),
        ("nested/deep/leaf.bin", b"leaf"),
        ("empty.bin", b""),
    ];
    let fixture = seal(files);
    let package = fixture.open().unwrap();
    assert_eq!(package.manifest_bytes(), fixture.manifest_bytes.as_slice());
    assert_eq!(package.cases().len(), files.len());
    for ((path, bytes), case) in files.iter().zip(package.cases().iter()) {
        assert_eq!(case.path(), *path);
        assert_eq!(case.bytes(), *bytes);
        assert_eq!(case.size(), bytes.len() as u64);
        assert_eq!(case.sha256_hex(), sha_hex(bytes));
        assert_eq!(case.raw()["role"], serde_json::json!("positive"));
        let looked_up = package.case(path).expect("case lookup");
        assert_eq!(looked_up.bytes(), *bytes);
    }
    assert!(package.case("missing.bin").is_none());
    assert_eq!(
        package.manifest()["format"],
        serde_json::json!("neutral-fixture")
    );
}

#[test]
fn wrong_expected_pin_rejects_before_parsing() {
    let fixture = seal(&[("a.bin", b"bytes")]);
    let mut wrong = fixture.expected;
    wrong[0] ^= 0x01;
    assert_rejects(
        fixture.open_with(bounds(), &wrong),
        SealedErrorKind::ManifestSeal,
        "wrong pin",
    );

    // A wrong pin beats even a malformed manifest: authentication precedes
    // parsing, so the failure kind cannot leak envelope shape.
    let malformed = seal_raw(&[], b"not json{{{");
    assert_rejects(
        malformed.open_with(bounds(), &wrong),
        SealedErrorKind::ManifestSeal,
        "wrong pin with malformed envelope",
    );

    // And a right pin over a malformed envelope fails at parsing instead.
    assert_rejects(
        malformed.open(),
        SealedErrorKind::ManifestParse,
        "right pin with malformed envelope",
    );
}

#[test]
fn env_pin_round_trip_through_the_shared_carrier() {
    // This is the only test touching the process environment, so parallel
    // execution cannot race it; the previous value is always restored.
    let saved = std::env::var_os(MANIFEST_SHA256_ENV_VAR);
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var(MANIFEST_SHA256_ENV_VAR, value),
                None => std::env::remove_var(MANIFEST_SHA256_ENV_VAR),
            }
        }
    }
    let _restore = Restore(saved);

    std::env::remove_var(MANIFEST_SHA256_ENV_VAR);
    assert_eq!(
        expected_digest_from_env().unwrap_err().kind(),
        SealedErrorKind::ExpectedDigest
    );
    for malformed in ["", "xyz", &"ab".repeat(31)] {
        std::env::set_var(MANIFEST_SHA256_ENV_VAR, malformed);
        assert_eq!(
            expected_digest_from_env().unwrap_err().kind(),
            SealedErrorKind::ExpectedDigest,
            "pin {malformed:?} must be rejected"
        );
    }
    let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    std::env::set_var(MANIFEST_SHA256_ENV_VAR, digest);
    assert_eq!(
        expected_digest_from_env().unwrap(),
        parse_expected_digest(digest).unwrap()
    );
}

#[test]
fn malformed_manifest_rejects() {
    for (label, bytes) in [
        ("empty", b"".as_slice()),
        ("text", b"not json".as_slice()),
        ("truncated", b"{\"cases\": [".as_slice()),
        ("trailing", b"{\"cases\": []} trailing".as_slice()),
    ] {
        let fixture = seal_raw(&[], bytes);
        assert_rejects(fixture.open(), SealedErrorKind::ManifestParse, label);
    }
}

#[test]
fn duplicate_manifest_keys_reject() {
    for (label, bytes) in [
        ("top level", r#"{"cases": [], "cases": []}"#),
        ("nested", r#"{"cases": [{"path": "a", "path": "b"}]}"#),
        (
            "decoded escapes",
            "{\"cases\": [{\"A\": 1, \"\\u0041\": 2}]}",
        ),
    ] {
        let fixture = seal_raw(&[], bytes.as_bytes());
        assert_rejects(
            fixture.open(),
            SealedErrorKind::ManifestDuplicateKeys,
            label,
        );
    }
}

#[test]
fn schema_violations_reject() {
    let good_sha = sha_hex(b"");
    let envelopes = [
        ("non-object", serde_json::json!([1])),
        ("missing cases", serde_json::json!({"schema": "x"})),
        ("non-array cases", serde_json::json!({"cases": {}})),
        ("non-object case", serde_json::json!({"cases": ["a.bin"]})),
        (
            "missing path",
            serde_json::json!({"cases": [{"sha256": good_sha, "size": 0}]}),
        ),
        (
            "non-string path",
            serde_json::json!({"cases": [{"path": 1, "sha256": good_sha, "size": 0}]}),
        ),
        (
            "missing sha",
            serde_json::json!({"cases": [{"path": "a.bin", "size": 0}]}),
        ),
        (
            "malformed sha",
            serde_json::json!({"cases": [{"path": "a.bin", "sha256": "zz", "size": 0}]}),
        ),
        (
            "missing size",
            serde_json::json!({"cases": [{"path": "a.bin", "sha256": good_sha}]}),
        ),
        (
            "string size",
            serde_json::json!({"cases": [{"path": "a.bin", "sha256": good_sha, "size": "0"}]}),
        ),
    ];
    for (label, envelope) in &envelopes {
        let fixture = seal_raw(&[], envelope.to_string().as_bytes());
        assert_rejects(fixture.open(), SealedErrorKind::ManifestSchema, label);
    }
    // An envelope with no cases is neutrally admitted; consumers decide
    // whether an empty selection satisfies them.
    let empty = seal_raw(&[], br#"{"cases": []}"#);
    assert!(empty.open().unwrap().cases().is_empty());
}

#[test]
fn duplicate_declared_paths_reject() {
    let sha = sha_hex(b"bytes");
    let envelope = serde_json::json!({
        "cases": [
            {"path": "dup.bin", "sha256": sha, "size": 5},
            {"path": "dup.bin", "sha256": sha, "size": 5},
        ],
    });
    let fixture = seal_raw(&[("dup.bin", b"bytes")], envelope.to_string().as_bytes());
    assert_rejects(
        fixture.open(),
        SealedErrorKind::Inventory,
        "duplicate paths",
    );
}

#[test]
fn prefix_conflicts_reject() {
    let sha = sha_hex(b"bytes");
    let file_case = |path: &str| serde_json::json!({"path": path, "sha256": sha, "size": 5});
    // A declared file cannot also be an implied directory. Only the
    // first path can exist on disk; admission must still reject on the
    // declaration conflict before reading anything.
    let envelope = serde_json::json!({"cases": [file_case("dir"), file_case("dir/file.bin")]});
    let fixture = seal_raw(&[("dir", b"bytes")], envelope.to_string().as_bytes());
    assert_rejects(
        fixture.open(),
        SealedErrorKind::Inventory,
        "file/dir conflict",
    );

    // A declared case cannot nest under the manifest path either.
    let nested = seal_raw_with(
        PACKAGE,
        "sub/manifest.json",
        &[],
        serde_json::json!({"cases": [file_case("sub")]})
            .to_string()
            .as_bytes(),
    );
    assert_rejects(
        nested.open(),
        SealedErrorKind::Inventory,
        "manifest nesting",
    );

    // Nor collide with it exactly.
    let collision = seal_raw(
        &[],
        serde_json::json!({"cases": [file_case("spec.json")]})
            .to_string()
            .as_bytes(),
    );
    assert_rejects(
        collision.open(),
        SealedErrorKind::Inventory,
        "manifest collision",
    );
}

#[test]
fn missing_undeclared_and_unexplained_entries_reject() {
    // Declared but absent.
    let missing = seal_raw(
        &[],
        serde_json::json!({"cases": [{
            "path": "ghost.bin",
            "sha256": sha_hex(b""),
            "size": 0,
        }]})
        .to_string()
        .as_bytes(),
    );
    assert_rejects(missing.open(), SealedErrorKind::Inventory, "missing case");

    // Present but undeclared, flat and nested.
    let fixture = seal(&[("a.bin", b"a")]);
    std::fs::write(fixture.root.join(PACKAGE).join("extra.bin"), b"extra").unwrap();
    assert_rejects(
        fixture.open(),
        SealedErrorKind::Inventory,
        "undeclared file",
    );
    let nested = seal(&[("a.bin", b"a")]);
    write_tree(
        &nested.root.join(PACKAGE),
        &[("deep/nested/extra.bin", b"extra")],
    );
    assert_rejects(
        nested.open(),
        SealedErrorKind::Inventory,
        "undeclared nested file",
    );

    // An unexplained directory (even empty) is not silently skipped.
    let bare = seal(&[("a.bin", b"a")]);
    std::fs::create_dir_all(bare.root.join(PACKAGE).join("stray")).unwrap();
    assert_rejects(
        bare.open(),
        SealedErrorKind::Inventory,
        "unexplained directory",
    );
}

#[test]
fn unsafe_declared_paths_reject() {
    let sha = sha_hex(b"");
    for (label, path) in [
        ("absolute", "/etc/hostname"),
        ("dot-dot", "sub/../../escape.bin"),
        ("dot", "sub/./case.bin"),
        ("drive", "C:/case.bin"),
        ("backslash", "sub\\case.bin"),
        ("nul", "sub/\0case.bin"),
        ("empty component", "sub//case.bin"),
    ] {
        let envelope = serde_json::json!({"cases": [{
            "path": path,
            "sha256": sha,
            "size": 0,
        }]});
        let fixture = seal_raw(&[], envelope.to_string().as_bytes());
        assert_rejects(fixture.open(), SealedErrorKind::Path, label);
    }
}

#[test]
fn unsafe_package_and_manifest_selectors_reject_before_io() {
    // Lexical validation precedes even the root open: point at a root
    // that does not exist and the failure must still be lexical.
    let temp = tempfile::tempdir().unwrap();
    let absent = temp.path().join("no-such-root");
    for (label, package, manifest) in [
        ("package escape", "../escape", MANIFEST),
        ("package absolute", "/abs", MANIFEST),
        ("manifest escape", PACKAGE, "../escape.json"),
        ("manifest absolute", PACKAGE, "/abs.json"),
        ("manifest dot", PACKAGE, "sub/./manifest.json"),
    ] {
        let result = SealedPackage::open(&absent, package, manifest, &[0u8; 32], bounds());
        assert_rejects(result, SealedErrorKind::Path, label);
    }
}

#[test]
fn root_symlink_and_root_file_reject() {
    use std::os::unix::fs::symlink;

    let target = seal(&[("a.bin", b"a")]);
    let temp = tempfile::tempdir().unwrap();
    let link = temp.path().join("linked-root");
    symlink(&target.root, &link).unwrap();
    assert_rejects(
        SealedPackage::open(&link, PACKAGE, MANIFEST, &target.expected, bounds()),
        SealedErrorKind::Symlink,
        "root symlink",
    );

    let file = temp.path().join("file-root");
    std::fs::write(&file, b"not a directory").unwrap();
    assert_rejects(
        SealedPackage::open(&file, PACKAGE, MANIFEST, &[0u8; 32], bounds()),
        SealedErrorKind::FileType,
        "root file",
    );
}

/// Write a minimal valid package (`a.bin` plus its manifest) under an
/// arbitrary already-created root directory; returns the expected digest.
fn write_valid_package(root: &Path) -> [u8; 32] {
    let directory = root.join(PACKAGE);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("a.bin"), b"a").unwrap();
    let manifest_bytes = manifest_for(&[("a.bin", b"a")]);
    std::fs::write(directory.join(MANIFEST), &manifest_bytes).unwrap();
    sha_bytes(&manifest_bytes)
}

#[test]
fn root_ancestor_symlink_rejects() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();

    // A symlink at the parent of the root: the final root is a genuine
    // directory, but reaching it traverses a link.
    let real_parent = temp.path().join("real-parent");
    let root = real_parent.join("corpus");
    std::fs::create_dir_all(&root).unwrap();
    let expected = write_valid_package(&root);
    SealedPackage::open(&root, PACKAGE, MANIFEST, &expected, bounds()).unwrap();
    symlink(&real_parent, temp.path().join("alias-parent")).unwrap();
    assert_rejects(
        SealedPackage::open(
            &temp.path().join("alias-parent").join("corpus"),
            PACKAGE,
            MANIFEST,
            &expected,
            bounds(),
        ),
        SealedErrorKind::Symlink,
        "symlinked parent of root",
    );

    // A symlink at the grandparent of the root: no-follow applies at every
    // depth, not just the final component and its parent.
    let real_grand = temp.path().join("real-grand");
    let deep = real_grand.join("mid").join("corpus");
    std::fs::create_dir_all(&deep).unwrap();
    let deep_expected = write_valid_package(&deep);
    SealedPackage::open(&deep, PACKAGE, MANIFEST, &deep_expected, bounds()).unwrap();
    symlink(&real_grand, temp.path().join("alias-grand")).unwrap();
    assert_rejects(
        SealedPackage::open(
            &temp.path().join("alias-grand").join("mid").join("corpus"),
            PACKAGE,
            MANIFEST,
            &deep_expected,
            bounds(),
        ),
        SealedErrorKind::Symlink,
        "symlinked grandparent of root",
    );
}

#[test]
fn root_ancestor_file_rejects() {
    // A regular file above the root is a type failure on that component,
    // matching intermediate package components.
    let temp = tempfile::tempdir().unwrap();
    let blocker = temp.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    assert_rejects(
        SealedPackage::open(
            &blocker.join("corpus"),
            PACKAGE,
            MANIFEST,
            &[0u8; 32],
            bounds(),
        ),
        SealedErrorKind::FileType,
        "file as root ancestor",
    );
}

#[test]
fn relative_root_spelling_admits() {
    use std::path::Component;

    let fixture = seal(&[("a.bin", b"a")]);
    // Spell the absolute fixture root relatively from the process working
    // directory without mutating global state.
    let current = std::env::current_dir().unwrap();
    let mut leading = current.components().peekable();
    let mut trailing = fixture.root.components().peekable();
    loop {
        match (leading.peek(), trailing.peek()) {
            (Some(first), Some(second)) if first == second => {
                leading.next();
                trailing.next();
            }
            _ => break,
        }
    }
    let mut relative = PathBuf::new();
    for _ in leading {
        relative.push("..");
    }
    for component in trailing {
        match component {
            Component::Normal(name) => relative.push(name),
            _ => panic!("fixture root carries a non-normal component"),
        }
    }
    assert!(relative.is_relative());
    let package =
        SealedPackage::open(&relative, PACKAGE, MANIFEST, &fixture.expected, bounds()).unwrap();
    assert_eq!(package.case("a.bin").unwrap().bytes(), b"a");

    // A deterministic parent round-trip through a held directory also
    // resolves: descend into the package, then step back up to the root.
    let round_trip = relative.join(PACKAGE).join("..");
    let package =
        SealedPackage::open(&round_trip, PACKAGE, MANIFEST, &fixture.expected, bounds()).unwrap();
    assert_eq!(package.case("a.bin").unwrap().bytes(), b"a");
}

#[test]
fn manifest_symlink_rejects() {
    use std::os::unix::fs::symlink;

    let fixture = seal(&[("a.bin", b"a")]);
    let directory = fixture.root.join(PACKAGE);
    let real = directory.join("real-manifest.json");
    std::fs::rename(directory.join(MANIFEST), &real).unwrap();
    symlink("real-manifest.json", directory.join(MANIFEST)).unwrap();
    assert_rejects(fixture.open(), SealedErrorKind::Symlink, "manifest symlink");
}

#[test]
fn intermediate_symlink_rejects() {
    use std::os::unix::fs::symlink;

    // Declared nested case whose intermediate directory is a symlink.
    // The on-disk tree holds the link plus a shadow target; admission
    // must fail on the link, never follow it.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(PACKAGE);
    std::fs::create_dir_all(directory.join("shadow")).unwrap();
    std::fs::write(directory.join("shadow/case.bin"), b"shadowed").unwrap();
    symlink("shadow", directory.join("sub")).unwrap();
    let envelope = serde_json::json!({"cases": [{
        "path": "sub/case.bin",
        "sha256": sha_hex(b"shadowed"),
        "size": 8,
    }]});
    let manifest_bytes = envelope.to_string().into_bytes();
    std::fs::write(directory.join(MANIFEST), &manifest_bytes).unwrap();
    let expected = sha_bytes(&manifest_bytes);
    // Enumeration sees the link first and rejects before any case opens.
    assert_rejects(
        SealedPackage::open(&root, PACKAGE, MANIFEST, &expected, bounds()),
        SealedErrorKind::Symlink,
        "intermediate symlink",
    );
}

#[test]
fn leaf_symlink_rejects() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(PACKAGE);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("target.bin"), b"target").unwrap();
    symlink("target.bin", directory.join("link.bin")).unwrap();
    let envelope = serde_json::json!({"cases": [{
        "path": "link.bin",
        "sha256": sha_hex(b"target"),
        "size": 6,
    }]});
    let manifest_bytes = envelope.to_string().into_bytes();
    std::fs::write(directory.join(MANIFEST), &manifest_bytes).unwrap();
    let expected = sha_bytes(&manifest_bytes);
    // Entry classification precedes inventory comparison structurally,
    // so the link rejects as a symlink even though the undeclared target
    // would also fail on its own.
    assert_rejects(
        SealedPackage::open(&root, PACKAGE, MANIFEST, &expected, bounds()),
        SealedErrorKind::Symlink,
        "leaf symlink",
    );
}

#[test]
fn package_component_symlink_rejects() {
    use std::os::unix::fs::symlink;

    // A two-component package selector whose first component is a link.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let real = root.join("real");
    let inner = real.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    let manifest_bytes = manifest_for(&[]);
    std::fs::write(inner.join(MANIFEST), &manifest_bytes).unwrap();
    symlink("real", root.join("outer")).unwrap();
    assert_rejects(
        SealedPackage::open(
            &root,
            "outer/inner",
            MANIFEST,
            &sha_bytes(&manifest_bytes),
            bounds(),
        ),
        SealedErrorKind::Symlink,
        "package component symlink",
    );
}

#[test]
fn special_files_reject_without_blocking() {
    // A FIFO entry must fail admission without any thread blocking in a
    // FIFO open: completion of this test is the non-blocking proof.
    let fixture = seal(&[("a.bin", b"a")]);
    let directory = fixture.root.join(PACKAGE);
    let dir_fd = rustix::fs::open(
        &directory,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::fs::mkfifoat(
        &dir_fd,
        "pipe.bin",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    assert_rejects(fixture.open(), SealedErrorKind::FileType, "fifo entry");

    // A socket entry rejects the same way through content-free typing.
    let socketed = seal(&[("a.bin", b"a")]);
    let path = socketed.root.join(PACKAGE).join("socket.bin");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    assert_rejects(socketed.open(), SealedErrorKind::FileType, "socket entry");
}

#[test]
fn hash_and_size_mismatches_reject() {
    // Right size, wrong bytes.
    let wrong = seal_raw(
        &[("a.bin", b"tampered")],
        serde_json::json!({"cases": [{
            "path": "a.bin",
            "sha256": sha_hex(b"original"),
            "size": 8,
        }]})
        .to_string()
        .as_bytes(),
    );
    assert_rejects(wrong.open(), SealedErrorKind::HashMismatch, "wrong bytes");

    // Short read.
    let short = seal_raw(
        &[("a.bin", b"tiny")],
        serde_json::json!({"cases": [{
            "path": "a.bin",
            "sha256": sha_hex(b"tiny"),
            "size": 64,
        }]})
        .to_string()
        .as_bytes(),
    );
    assert_rejects(short.open(), SealedErrorKind::SizeMismatch, "short read");

    // Long read (declared digest matches the prefix to isolate the size
    // check from the hash check).
    let long = seal_raw(
        &[("a.bin", b"tiny plus trailing bytes")],
        serde_json::json!({"cases": [{
            "path": "a.bin",
            "sha256": sha_hex(b"tiny"),
            "size": 4,
        }]})
        .to_string()
        .as_bytes(),
    );
    assert_rejects(long.open(), SealedErrorKind::SizeMismatch, "long read");
}

#[test]
fn exact_and_one_short_bounds() {
    // Tight, non-vacuous ceilings: one short on any ceiling rejects while
    // the exact ceiling admits. Short package/manifest selectors isolate
    // each boundary from the other validated names.
    let files: &[(&str, &[u8])] = &[("d1/d2/leaf.bin", b"0123456789")];
    let package = "p";
    let manifest = "m";
    let fixture = seal_with(package, manifest, files);
    let manifest_len = fixture.manifest_bytes.len() as u64;
    let path_len = "d1/d2/leaf.bin".len() as u64;
    assert_eq!(path_len, 14);

    let exact = SealedBounds::new(manifest_len, 1, 10, 10, path_len, 3);
    SealedPackage::open(&fixture.root, package, manifest, &fixture.expected, exact).unwrap();

    // One short on each ceiling in turn.
    let cases: &[(SealedBounds, &str)] = &[
        (
            SealedBounds::new(manifest_len - 1, 1, 10, 10, path_len, 3),
            "manifest bytes",
        ),
        (
            SealedBounds::new(manifest_len, 0, 10, 10, path_len, 3),
            "file count",
        ),
        (
            SealedBounds::new(manifest_len, 1, 9, 10, path_len, 3),
            "per-file bytes",
        ),
        (
            SealedBounds::new(manifest_len, 1, 10, 9, path_len, 3),
            "total bytes",
        ),
        (
            SealedBounds::new(manifest_len, 1, 10, 10, path_len - 1, 3),
            "path bytes",
        ),
        (
            SealedBounds::new(manifest_len, 1, 10, 10, path_len, 2),
            "depth",
        ),
    ];
    for (short, label) in cases {
        assert_rejects(
            SealedPackage::open(&fixture.root, package, manifest, &fixture.expected, *short),
            SealedErrorKind::Bounds,
            label,
        );
    }

    // Zero file ceiling admits nothing, not even an empty selection.
    let empty = seal_with("p", "m", &[]);
    let zero = SealedBounds::new(8192, 0, 2048, 4096, 256, 8);
    assert!(
        SealedPackage::open(&empty.root, "p", "m", &empty.expected, zero)
            .unwrap()
            .cases()
            .is_empty()
    );
    let one = seal_with("p", "m", &[("a.bin", b"a")]);
    assert_rejects(
        SealedPackage::open(&one.root, "p", "m", &one.expected, zero),
        SealedErrorKind::Bounds,
        "zero file ceiling with one case",
    );
}

/// A scripted deterministic race: exactly one filesystem action at exactly
/// one admission seam, with no threads or sleeps.
struct ScriptedProbe {
    fire_on: ProbePoint,
    action: ProbeAction,
    fired: usize,
}

/// Each variant names the [`AdmissionProbe`] seam it fires on, hence the
/// shared prefix.
#[derive(PartialEq, Eq, Debug)]
#[allow(clippy::enum_variant_names)]
enum ProbePoint {
    AfterRootOpen,
    AfterManifestOpen,
    AfterManifestSealed,
    AfterInventory,
    AfterCaseOpen(String),
    AfterAllCases,
}

enum ProbeAction {
    WriteFile(PathBuf, Vec<u8>),
    Rename(PathBuf, PathBuf),
    RemoveFile(PathBuf),
    RemoveDir(PathBuf),
    MakeDir(PathBuf),
}

impl ScriptedProbe {
    fn new(fire_on: ProbePoint, action: ProbeAction) -> Self {
        Self {
            fire_on,
            action,
            fired: 0,
        }
    }

    fn fire(&mut self) {
        self.fired += 1;
        match &self.action {
            ProbeAction::WriteFile(path, bytes) => std::fs::write(path, bytes).unwrap(),
            ProbeAction::Rename(from, to) => std::fs::rename(from, to).unwrap(),
            ProbeAction::RemoveFile(path) => std::fs::remove_file(path).unwrap(),
            ProbeAction::RemoveDir(path) => std::fs::remove_dir_all(path).unwrap(),
            ProbeAction::MakeDir(path) => std::fs::create_dir_all(path).unwrap(),
        }
    }

    fn finished(self, label: &str) {
        assert_eq!(self.fired, 1, "{label}: probe must fire exactly once");
    }
}

impl AdmissionProbe for ScriptedProbe {
    fn after_root_open(&mut self) {
        if self.fire_on == ProbePoint::AfterRootOpen {
            self.fire();
        }
    }

    fn after_manifest_open(&mut self) {
        if self.fire_on == ProbePoint::AfterManifestOpen {
            self.fire();
        }
    }

    fn after_manifest_sealed(&mut self) {
        if self.fire_on == ProbePoint::AfterManifestSealed {
            self.fire();
        }
    }

    fn after_inventory(&mut self) {
        if self.fire_on == ProbePoint::AfterInventory {
            self.fire();
        }
    }

    fn after_case_open(&mut self, path: &str) {
        if self.fire_on == ProbePoint::AfterCaseOpen(path.to_owned()) {
            self.fire();
        }
    }

    fn after_all_cases(&mut self) {
        if self.fire_on == ProbePoint::AfterAllCases {
            self.fire();
        }
    }
}

#[test]
fn manifest_mutation_at_open_seam_fails_the_seal() {
    let fixture = seal(&[("a.bin", b"a")]);
    let manifest_path = fixture.root.join(PACKAGE).join(MANIFEST);
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterManifestOpen,
        ProbeAction::WriteFile(manifest_path, b"{\"cases\": []}".to_vec()),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::ManifestSeal,
        "manifest rewritten after open",
    );
    probe.finished("manifest rewritten after open");
}

#[test]
fn manifest_swap_at_open_seam_fails_final_verification() {
    // The path is swapped after the manifest handle is held: admission
    // reads the original bytes (the seal passes) but final verification
    // observes the replacement and fails.
    let fixture = seal(&[("a.bin", b"a")]);
    let directory = fixture.root.join(PACKAGE);
    let spare = directory.join("spare.json");
    std::fs::write(&spare, b"{\"cases\": []}").unwrap();
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterManifestOpen,
        ProbeAction::Rename(spare, directory.join(MANIFEST)),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::Replaced,
        "manifest swapped after open",
    );
    probe.finished("manifest swapped after open");
}

#[test]
fn case_mutation_at_open_seam_fails_the_hash() {
    let fixture = seal(&[("a.bin", b"original")]);
    let case_path = fixture.root.join(PACKAGE).join("a.bin");
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterCaseOpen("a.bin".to_owned()),
        ProbeAction::WriteFile(case_path, b"mutated!".to_vec()),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::HashMismatch,
        "case rewritten after open",
    );
    probe.finished("case rewritten after open");
}

#[test]
fn case_swap_at_open_seam_fails_final_verification() {
    // Same-size swap: the held handle still yields the original bytes
    // (hash passes), but final verification observes the new object. The
    // spare waits outside the package so the first enumeration stays
    // clean; the rename carries it in at the seam.
    let fixture = seal(&[("a.bin", b"original")]);
    let directory = fixture.root.join(PACKAGE);
    let spare = fixture.root.join("spare.bin");
    std::fs::write(&spare, b"swapped!").unwrap();
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterCaseOpen("a.bin".to_owned()),
        ProbeAction::Rename(spare, directory.join("a.bin")),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::Replaced,
        "case swapped after open",
    );
    probe.finished("case swapped after open");
}

#[test]
fn inventory_insertion_and_removal_during_admission_fail() {
    let fixture = seal(&[("a.bin", b"a")]);
    let directory = fixture.root.join(PACKAGE);
    let mut insert = ScriptedProbe::new(
        ProbePoint::AfterAllCases,
        ProbeAction::WriteFile(directory.join("inserted.bin"), b"inserted".to_vec()),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut insert),
        SealedErrorKind::Replaced,
        "inserted file",
    );
    insert.finished("inserted file");

    let removed = seal(&[("a.bin", b"a")]);
    let mut remove = ScriptedProbe::new(
        ProbePoint::AfterAllCases,
        ProbeAction::RemoveFile(removed.root.join(PACKAGE).join("a.bin")),
    );
    assert_rejects(
        removed.open_probed(bounds(), &mut remove),
        SealedErrorKind::Replaced,
        "removed file",
    );
    remove.finished("removed file");
}

#[test]
fn late_case_mutation_fails_final_verification() {
    let fixture = seal(&[("a.bin", b"original")]);
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterAllCases,
        ProbeAction::WriteFile(
            fixture.root.join(PACKAGE).join("a.bin"),
            b"mutated!".to_vec(),
        ),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::Replaced,
        "case rewritten after verification",
    );
    probe.finished("case rewritten after verification");
}

#[test]
fn package_swap_during_admission_fails() {
    // The whole package directory is exchanged after the seal: every
    // mid-admission step still uses held handles (and would pass), but
    // final verification re-walks the package path and observes the swap.
    let fixture = seal(&[("a.bin", b"a")]);
    let root = fixture.root.clone();
    let staged = root.join("staged");
    let staged_package = staged.join(PACKAGE);
    std::fs::create_dir_all(&staged_package).unwrap();
    std::fs::write(staged_package.join(MANIFEST), &fixture.manifest_bytes).unwrap();
    std::fs::write(staged_package.join("a.bin"), b"a").unwrap();
    let parked = root.join("parked");
    struct SwapPackage {
        root: PathBuf,
        staged: PathBuf,
        parked: PathBuf,
        fired: usize,
    }
    impl AdmissionProbe for SwapPackage {
        fn after_all_cases(&mut self) {
            self.fired += 1;
            std::fs::rename(self.root.join(PACKAGE), &self.parked).unwrap();
            std::fs::rename(self.staged.join(PACKAGE), self.root.join(PACKAGE)).unwrap();
        }
    }
    let mut probe = SwapPackage {
        root,
        staged,
        parked,
        fired: 0,
    };
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::Replaced,
        "package directory swapped",
    );
    assert_eq!(probe.fired, 1);
}

#[test]
fn root_swap_during_admission_fails() {
    // Two complete roots exchange paths after admission starts: the held
    // root handle is unaffected, but final verification re-opens the
    // root path and observes the exchange.
    let first = seal(&[("a.bin", b"a")]);
    let second = seal(&[("a.bin", b"a")]);
    struct SwapRoots {
        first: PathBuf,
        second: PathBuf,
        fired: usize,
    }
    impl AdmissionProbe for SwapRoots {
        fn after_all_cases(&mut self) {
            self.fired += 1;
            let parked = self.first.parent().unwrap().join("parked-root");
            std::fs::rename(&self.first, &parked).unwrap();
            std::fs::rename(&self.second, &self.first).unwrap();
            std::fs::rename(&parked, &self.second).unwrap();
        }
    }
    // Both roots live under distinct temporary directories; exchange the
    // whole trees by path. The temporary directories clean up whichever
    // tree ends up under them.
    let mut probe = SwapRoots {
        first: first.root.clone(),
        second: second.root.clone(),
        fired: 0,
    };
    assert_rejects(
        first.open_probed(bounds(), &mut probe),
        SealedErrorKind::Replaced,
        "root swapped",
    );
    assert_eq!(probe.fired, 1);
}

#[test]
fn root_ancestor_swap_during_admission_fails() {
    // Two byte-identical trees under sibling anchors; after admission
    // starts, the anchors exchange names. Held handles still serve the
    // original bytes, but final verification re-walks the root path and
    // observes a different object.
    let temp = tempfile::tempdir().unwrap();
    let anchor_first = temp.path().join("first");
    let anchor_second = temp.path().join("second");
    let root = anchor_first.join("corpus");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(anchor_second.join("corpus")).unwrap();
    let expected = write_valid_package(&root);
    assert_eq!(write_valid_package(&anchor_second.join("corpus")), expected);
    struct SwapAnchors {
        first: PathBuf,
        second: PathBuf,
        fired: usize,
    }
    impl AdmissionProbe for SwapAnchors {
        fn after_all_cases(&mut self) {
            self.fired += 1;
            let parked = self.first.parent().unwrap().join("parked-anchor");
            std::fs::rename(&self.first, &parked).unwrap();
            std::fs::rename(&self.second, &self.first).unwrap();
            std::fs::rename(&parked, &self.second).unwrap();
        }
    }
    let mut probe = SwapAnchors {
        first: anchor_first,
        second: anchor_second,
        fired: 0,
    };
    assert_rejects(
        SealedPackage::open_with_probe(&root, PACKAGE, MANIFEST, &expected, bounds(), &mut probe),
        SealedErrorKind::Replaced,
        "root ancestor swapped",
    );
    assert_eq!(probe.fired, 1);
}

#[test]
fn root_ancestor_symlink_planted_during_admission_fails() {
    // After admission completes, the anchor moves aside and a symlink takes
    // its name pointing at the original location: the bytes are unchanged,
    // but the ancestry now traverses a link, so re-verification fails.
    let temp = tempfile::tempdir().unwrap();
    let anchor = temp.path().join("anchor");
    let root = anchor.join("corpus");
    std::fs::create_dir_all(&root).unwrap();
    let expected = write_valid_package(&root);
    struct PlantAncestorLink {
        anchor: PathBuf,
        fired: usize,
    }
    impl AdmissionProbe for PlantAncestorLink {
        fn after_all_cases(&mut self) {
            self.fired += 1;
            let parked = self.anchor.parent().unwrap().join("parked-anchor");
            std::fs::rename(&self.anchor, &parked).unwrap();
            std::os::unix::fs::symlink(&parked, &self.anchor).unwrap();
        }
    }
    let mut probe = PlantAncestorLink { anchor, fired: 0 };
    assert_rejects(
        SealedPackage::open_with_probe(&root, PACKAGE, MANIFEST, &expected, bounds(), &mut probe),
        SealedErrorKind::Symlink,
        "ancestor replaced by symlink",
    );
    assert_eq!(probe.fired, 1);
}

#[test]
fn package_removed_at_root_seam_fails_closed() {
    let fixture = seal(&[("a.bin", b"a")]);
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterRootOpen,
        ProbeAction::RemoveDir(fixture.root.join(PACKAGE)),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::Io,
        "package removed after root open",
    );
    probe.finished("package removed after root open");
}

#[test]
fn directory_created_at_seal_seam_fails_inventory() {
    let fixture = seal(&[("a.bin", b"a")]);
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterManifestSealed,
        ProbeAction::MakeDir(fixture.root.join(PACKAGE).join("late-dir")),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::Inventory,
        "directory created after seal",
    );
    probe.finished("directory created after seal");
}

#[test]
fn case_swap_at_inventory_seam_fails_the_hash() {
    // The swap lands after enumeration but before case opens: the first
    // inventory still matches (same names), the case opens read the new
    // object, and its bytes fail the declared digest immediately.
    let fixture = seal(&[("a.bin", b"original")]);
    let spare = fixture.root.join("spare.bin");
    std::fs::write(&spare, b"swapped!").unwrap();
    let mut probe = ScriptedProbe::new(
        ProbePoint::AfterInventory,
        ProbeAction::Rename(spare, fixture.root.join(PACKAGE).join("a.bin")),
    );
    assert_rejects(
        fixture.open_probed(bounds(), &mut probe),
        SealedErrorKind::HashMismatch,
        "case swapped after inventory",
    );
    probe.finished("case swapped after inventory");
}

#[test]
fn post_admission_swap_and_delete_keep_verified_bytes() {
    let files: &[(&str, &[u8])] = &[("a.bin", b"original-a"), ("sub/b.bin", b"original-b")];
    let fixture = seal(files);
    let package = fixture.open().unwrap();

    // Delete the entire tree after admission: the verified view survives.
    std::fs::remove_dir_all(&fixture.root).unwrap();
    assert_eq!(package.manifest_bytes(), fixture.manifest_bytes.as_slice());
    for (path, bytes) in files {
        assert_eq!(package.case(path).unwrap().bytes(), *bytes);
    }

    // Recreate the tree with different bytes at the same names: the
    // verified view still carries the admitted bytes, never the new ones.
    let revived = seal(files);
    let held = revived.open().unwrap();
    std::fs::write(revived.root.join(PACKAGE).join("a.bin"), b"changed!!").unwrap();
    std::fs::write(revived.root.join(PACKAGE).join("sub/b.bin"), b"changed!!-b").unwrap();
    assert_eq!(held.case("a.bin").unwrap().bytes(), b"original-a");
    assert_eq!(held.case("sub/b.bin").unwrap().bytes(), b"original-b");
}

#[test]
fn hardlinked_cases_share_bytes() {
    // Distinct declared paths may share one object; identity is by bytes,
    // with no inode-uniqueness policy either way.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(PACKAGE);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("first.bin"), b"shared").unwrap();
    std::fs::hard_link(directory.join("first.bin"), directory.join("second.bin")).unwrap();
    let sha = sha_hex(b"shared");
    let envelope = serde_json::json!({"cases": [
        {"path": "first.bin", "sha256": sha, "size": 6},
        {"path": "second.bin", "sha256": sha, "size": 6},
    ]});
    let manifest_bytes = envelope.to_string().into_bytes();
    std::fs::write(directory.join(MANIFEST), &manifest_bytes).unwrap();
    let package = SealedPackage::open(
        &root,
        PACKAGE,
        MANIFEST,
        &sha_bytes(&manifest_bytes),
        bounds(),
    )
    .unwrap();
    assert_eq!(package.case("first.bin").unwrap().bytes(), b"shared");
    assert_eq!(package.case("second.bin").unwrap().bytes(), b"shared");
}

#[test]
fn directory_as_manifest_and_file_as_directory_reject() {
    // The manifest path exists as a directory: classification fails with
    // the file-type kind before any content is read (the expected digest
    // is never consulted).
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(PACKAGE);
    std::fs::create_dir_all(directory.join("subdir")).unwrap();
    assert_rejects(
        SealedPackage::open(&root, PACKAGE, "subdir", &[0u8; 32], bounds()),
        SealedErrorKind::FileType,
        "directory as manifest",
    );

    // A package intermediate exists as a regular file.
    let blocked = tempfile::tempdir().unwrap();
    std::fs::write(blocked.path().join("outer"), b"blocker").unwrap();
    assert_rejects(
        SealedPackage::open(
            blocked.path(),
            "outer/inner",
            MANIFEST,
            &[0u8; 32],
            bounds(),
        ),
        SealedErrorKind::FileType,
        "file as package directory",
    );
}

#[test]
fn custom_extractor_adapter_works() {
    // Envelopes with a different schema keep their shape: a small caller
    // adapter maps them onto case records while the sealed pass stays put.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let directory = root.join(PACKAGE);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("a.bin"), b"payload").unwrap();
    let envelope = serde_json::json!({
        "kind": "legacy-listing",
        "files": [{"name": "a.bin", "digest": sha_hex(b"payload"), "len": 7}],
    });
    let manifest_bytes = envelope.to_string().into_bytes();
    std::fs::write(directory.join(MANIFEST), &manifest_bytes).unwrap();
    let expected = sha_bytes(&manifest_bytes);
    let mut probe = formatkit_corpus_test::NoProbe;
    let package = SealedPackage::open_with_extractor(
        &root,
        PACKAGE,
        MANIFEST,
        &expected,
        bounds(),
        &mut probe,
        |manifest| {
            let mut out = Vec::new();
            for file in manifest["files"].as_array().cloned().unwrap_or_default() {
                out.push(UnverifiedCase {
                    path: file["name"].as_str().unwrap().to_owned(),
                    sha256: decode_sha256(file["digest"].as_str().unwrap())?,
                    size: file["len"].as_u64().unwrap(),
                    raw: file.clone(),
                });
            }
            Ok(out)
        },
    )
    .unwrap();
    assert_eq!(package.case("a.bin").unwrap().bytes(), b"payload");

    // The default extractor still rejects the foreign envelope shape.
    assert_rejects(
        SealedPackage::open(&root, PACKAGE, MANIFEST, &expected, bounds()),
        SealedErrorKind::ManifestSchema,
        "foreign envelope under default extractor",
    );

    // And the curated extractor stays available as a plain function.
    let parsed: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert!(curated_v1_cases(&parsed).is_err());
}

#[test]
fn failed_admission_produces_no_parser_input() {
    // Representative corrupt package with an explicitly counting parser:
    // the counter documents that rejection yields nothing to consume.
    let fixture = seal_raw(
        &[("a.bin", b"tampered")],
        serde_json::json!({"cases": [{
            "path": "a.bin",
            "sha256": sha_hex(b"original"),
            "size": 8,
        }]})
        .to_string()
        .as_bytes(),
    );
    let mut parser_invocations = 0usize;
    let result = fixture.open();
    if let Ok(package) = &result {
        for case in package.cases() {
            parser_invocations += 1;
            std::hint::black_box(case.bytes());
        }
    }
    assert_eq!(parser_invocations, 0);
    assert_eq!(result.unwrap_err().kind(), SealedErrorKind::HashMismatch);
}
