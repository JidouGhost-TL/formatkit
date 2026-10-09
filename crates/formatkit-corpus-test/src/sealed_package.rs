#![forbid(unsafe_code)]

//! Sealed canonical-package admission for corpus selectors.
//!
//! A corpus selector must treat its package directory as untrusted input:
//! authenticating the manifest and then reopening carriers by path leaves a
//! check/open/read race, and a plain directory walk follows symlinks. This
//! module closes that gap with one bounded admission pass:
//!
//! 1. The caller supplies the expected full-manifest SHA-256 out of band
//!    (never derived from the bytes being opened) plus explicit finite
//!    operational ceilings ([`SealedBounds`]).
//! 2. The manifest is opened through held component-relative no-follow
//!    handles, read within its bound, and authenticated byte-for-byte
//!    against the expected digest *before* JSON parsing.
//! 3. The authenticated manifest is parsed with duplicate object keys
//!    rejected at every nesting level, and its declared relative inventory
//!    is validated lexically (no absolute, drive, empty, dot, dot-dot,
//!    NUL, or backslash components) with duplicates and file/directory
//!    prefix conflicts rejected.
//! 4. The complete package tree is enumerated through the same held
//!    handles. Only the authenticated manifest plus exactly the declared
//!    regular case files may exist; symlinks, special files, missing or
//!    undeclared entries, and unexplained directories all fail admission.
//! 5. Every declared case is opened through its held handle and its exact
//!    read bytes are checked against the declared size and SHA-256. Reads
//!    use fallible reservation within the per-file and total ceilings.
//! 6. A final re-verification pass re-opens the root by path, re-walks the
//!    package, re-enumerates the inventory, and re-reads every admitted
//!    file, requiring identical handles, inventory, and bytes. Observed
//!    replacement or mutation fails admission.
//!
//! On success the caller receives [`SealedPackage`]: immutable verified
//! bytes plus the opaque parsed manifest. No format parser runs until
//! admission succeeds, and the guarantee covers exactly those returned
//! buffers — never a later path read. Callers that must hand bytes to a
//! child process stage the returned buffers into private scratch instead
//! of reopening the original carrier paths.
//!
//! This is finite test-harness admission, not a production streaming route
//! and not an atomic filesystem snapshot: it cannot protect an inode that
//! changes after verification. What it guarantees is that the delivered
//! buffers are exactly bytes that were inventoried through held handles
//! and matched the sealed manifest, and that any replacement or mutation
//! observed during admission fails the whole package.
//!
//! The handle-bound implementation requires POSIX-style descriptor-relative
//! opening (`openat` with `O_NOFOLLOW`) and fails closed with
//! [`SealedErrorKind::UnsupportedPlatform`] elsewhere. The corpus root is
//! opened by walking every ancestry component from a trusted anchor (`/`
//! for absolute roots, `.` for relative ones) with `O_NOFOLLOW |
//! O_DIRECTORY` at each step, so a static symlink anywhere in the ancestry
//! fails admission — not just a symlink at the final component. Every
//! later step is relative to held handles, so a later ancestor swap cannot
//! redirect reads; the final pass additionally re-walks the root path and
//! fails when its identity changed or an ancestor became a link.

use serde::de::Error as _;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// Environment carrier for the externally supplied expected full-manifest
/// SHA-256 (64 lowercase or uppercase hex digits). Read only through
/// [`expected_digest_from_env`]; the admission entry points take the digest
/// as an explicit argument so consumers without environment state pass it
/// directly.
pub const MANIFEST_SHA256_ENV_VAR: &str = "FORMATKIT_CORPUS_MANIFEST_SHA256";

/// Machine-readable admission failure classes. Tests assert on
/// [`SealedError::kind`]; the human-readable detail lives in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedErrorKind {
    /// No handle-bound implementation for this platform.
    UnsupportedPlatform,
    /// The externally supplied expected digest is missing or malformed.
    ExpectedDigest,
    /// A package, manifest, or case path is lexically unsafe.
    Path,
    /// A caller-supplied operational ceiling was exceeded.
    Bounds,
    /// Authenticated manifest bytes differ from the expected digest.
    ManifestSeal,
    /// Authenticated manifest bytes are not well-formed JSON.
    ManifestParse,
    /// The manifest envelope lacks the required cases shape.
    ManifestSchema,
    /// The manifest repeats an object key (ambiguous inventory).
    ManifestDuplicateKeys,
    /// Declared and observed inventories differ, or declarations collide.
    Inventory,
    /// A symlink was observed in the root ancestry or on the admitted tree.
    Symlink,
    /// A directory, FIFO, socket, device, or other non-regular file
    /// appeared where a regular case file or directory was required.
    FileType,
    /// Read bytes differ in length from the declared size.
    SizeMismatch,
    /// Read bytes differ in SHA-256 from the declared digest.
    HashMismatch,
    /// An object observed during admission changed before it completed.
    Replaced,
    /// Any other input/output failure.
    Io,
}

/// Admission failure: a [`SealedErrorKind`] plus a neutral detail message
/// that names paths and bounds but never donor or source identity.
#[derive(Debug, Clone)]
pub struct SealedError {
    kind: SealedErrorKind,
    message: String,
}

impl SealedError {
    fn new(kind: SealedErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The machine-readable failure class.
    pub fn kind(&self) -> SealedErrorKind {
        self.kind
    }
}

impl fmt::Display for SealedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sealed package {:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for SealedError {}

/// Explicit finite operational ceilings for one admission pass. Every
/// ceiling is caller-supplied; there are no built-in defaults because a
/// default would silently decide how much untrusted input is acceptable.
/// ceilings are operational policy, not grammar: admission rejects input
/// above them without claiming the input is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedBounds {
    /// Largest accepted manifest file in bytes.
    pub max_manifest_bytes: u64,
    /// Largest accepted count of declared case files (excluding the manifest).
    pub max_files: u64,
    /// Largest accepted single case file in bytes.
    pub max_file_bytes: u64,
    /// Largest accepted sum of verified case bytes (excluding the manifest).
    pub max_total_bytes: u64,
    /// Largest accepted declared relative path in bytes.
    pub max_path_bytes: u64,
    /// Largest accepted component count of one declared relative path and
    /// traversal depth of the package tree.
    pub max_depth: u64,
}

impl SealedBounds {
    /// Build an explicit ceiling set. Positional so call sites stay visibly
    /// complete; see the field documentation for each parameter in order.
    pub const fn new(
        max_manifest_bytes: u64,
        max_files: u64,
        max_file_bytes: u64,
        max_total_bytes: u64,
        max_path_bytes: u64,
        max_depth: u64,
    ) -> Self {
        Self {
            max_manifest_bytes,
            max_files,
            max_file_bytes,
            max_total_bytes,
            max_path_bytes,
            max_depth,
        }
    }
}

/// One manifest-declared case before admission: validated descriptor plus
/// the opaque original JSON object for format-specific fields.
#[derive(Debug, Clone)]
pub struct UnverifiedCase {
    /// Declared relative path exactly as written in the manifest.
    pub path: String,
    /// Decoded declared SHA-256.
    pub sha256: [u8; 32],
    /// Declared byte size.
    pub size: u64,
    /// The opaque original case JSON object.
    pub raw: serde_json::Value,
}

/// Deterministic admission seams for race tests. Every method runs
/// synchronously inside [`SealedPackage::open_with_probe`] at the named
/// boundary; tests mutate the package tree from these hooks without
/// sleeping. Production consumers pass [`NoProbe`].
pub trait AdmissionProbe {
    /// After the corpus root handle is admitted, before package traversal.
    fn after_root_open(&mut self) {}
    /// After the manifest handle is opened and type-checked, before its
    /// bytes are read.
    fn after_manifest_open(&mut self) {}
    /// After the manifest is sealed, parsed, and schema-checked, before
    /// the package inventory is enumerated.
    fn after_manifest_sealed(&mut self) {}
    /// After the first inventory enumeration, before any case is opened.
    fn after_inventory(&mut self) {}
    /// After one case handle is opened and type-checked, before its bytes
    /// are read. Receives the normalized manifest-relative path.
    fn after_case_open(&mut self, _path: &str) {}
    /// After every case is verified, before final re-verification.
    fn after_all_cases(&mut self) {}
}

/// No-op [`AdmissionProbe`] for production admission.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProbe;

impl AdmissionProbe for NoProbe {}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Decode a manifest-declared SHA-256 (64 hex digits, either case) for
/// custom manifest extractors. Failures are [`SealedErrorKind::ManifestSchema`].
pub fn decode_sha256(hex: &str) -> Result<[u8; 32], SealedError> {
    decode_hex_32(hex).ok_or_else(|| {
        SealedError::new(
            SealedErrorKind::ManifestSchema,
            format!("declared sha256 is not 64 hex digits: {hex:?}"),
        )
    })
}

/// Decode the externally supplied expected full-manifest digest.
/// Failures are [`SealedErrorKind::ExpectedDigest`].
pub fn parse_expected_digest(hex: &str) -> Result<[u8; 32], SealedError> {
    decode_hex_32(hex.trim()).ok_or_else(|| {
        SealedError::new(
            SealedErrorKind::ExpectedDigest,
            "expected manifest digest is not 64 hex digits",
        )
    })
}

/// Read the externally supplied expected full-manifest digest from
/// [`MANIFEST_SHA256_ENV_VAR`]. A missing or malformed pin is
/// [`SealedErrorKind::ExpectedDigest`]: callers treat a configured package
/// without a valid pin as an error, never a skip.
pub fn expected_digest_from_env() -> Result<[u8; 32], SealedError> {
    let raw = std::env::var("FORMATKIT_CORPUS_MANIFEST_SHA256").map_err(|_| {
        SealedError::new(
            SealedErrorKind::ExpectedDigest,
            format!("{MANIFEST_SHA256_ENV_VAR} is not set"),
        )
    })?;
    parse_expected_digest(&raw)
}

/// Validate one manifest-relative path lexically: non-empty, within
/// `max_path_bytes` bytes, without NUL, backslash, absolute, drive, empty,
/// dot, or dot-dot components, and within `max_depth` components.
/// Returns the path components on success.
pub fn validate_relative_path(
    path: &str,
    bounds: SealedBounds,
) -> Result<Vec<String>, SealedError> {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return Err(SealedError::new(
            SealedErrorKind::Path,
            "declared path is empty",
        ));
    }
    if bytes.len() as u64 > bounds.max_path_bytes {
        return Err(SealedError::new(
            SealedErrorKind::Bounds,
            format!(
                "declared path exceeds {} bytes: {path:?}",
                bounds.max_path_bytes
            ),
        ));
    }
    if bytes.contains(&0) {
        return Err(SealedError::new(
            SealedErrorKind::Path,
            format!("declared path contains NUL: {path:?}"),
        ));
    }
    if bytes.contains(&b'\\') {
        return Err(SealedError::new(
            SealedErrorKind::Path,
            format!("declared path contains a backslash: {path:?}"),
        ));
    }
    if bytes.starts_with(b"/") {
        return Err(SealedError::new(
            SealedErrorKind::Path,
            format!("declared path is absolute: {path:?}"),
        ));
    }
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(SealedError::new(
            SealedErrorKind::Path,
            format!("declared path has a drive prefix: {path:?}"),
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() {
            return Err(SealedError::new(
                SealedErrorKind::Path,
                format!("declared path has an empty component: {path:?}"),
            ));
        }
        if component == "." || component == ".." {
            return Err(SealedError::new(
                SealedErrorKind::Path,
                format!("declared path escapes its root: {path:?}"),
            ));
        }
        components.push(component.to_owned());
    }
    if components.len() as u64 > bounds.max_depth {
        return Err(SealedError::new(
            SealedErrorKind::Bounds,
            format!(
                "declared path exceeds {} components: {path:?}",
                bounds.max_depth
            ),
        ));
    }
    Ok(components)
}

/// Join validated components into the normalized manifest-relative form.
fn normalize_components(components: &[String]) -> String {
    components.join("/")
}

/// Marker prefix for duplicate-key failures raised inside strict parsing.
/// Matched by prefix so the error kind stays stable regardless of how the
/// JSON backend renders positions.
const DUPLICATE_KEY_MARKER: &str = "sealed-package duplicate object key";

/// A JSON value parsed with duplicate object keys rejected at every
/// nesting level. A sealed envelope describing two inventories for one key
/// would let admission and consumption disagree, so any repetition fails.
struct StrictValue(serde_json::Value);

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Bool(v)))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(v.into())))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(v.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(
            serde_json::Number::from_f64(v).ok_or_else(|| E::custom("non-finite number"))?,
        )))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::String(v.to_owned())))
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        self.visit_str(v)
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::String(v)))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<StrictValue>()? {
            items.push(item.0);
        }
        Ok(StrictValue(serde_json::Value::Array(items)))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom(format!("{DUPLICATE_KEY_MARKER}: {key:?}")));
            }
            let value: StrictValue = map.next_value()?;
            object.insert(key, value.0);
        }
        Ok(StrictValue(serde_json::Value::Object(object)))
    }
}

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parse authenticated manifest bytes, rejecting malformed JSON and any
/// duplicate object key. Escape handling is delegated to the JSON backend,
/// so keys that differ only in spelling still collide after decoding.
fn parse_manifest(bytes: &[u8]) -> Result<serde_json::Value, SealedError> {
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|strict| strict.0)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains(DUPLICATE_KEY_MARKER) {
                SealedError::new(SealedErrorKind::ManifestDuplicateKeys, message)
            } else {
                SealedError::new(SealedErrorKind::ManifestParse, message)
            }
        })
}

/// Extract declared cases from a versioned curated-case
/// envelope: the manifest must be an object carrying a `cases` array, and
/// every case must be an object with string `path`, string `sha256`, and
/// unsigned integer `size` fields. All other fields stay opaque inside
/// [`UnverifiedCase::raw`].
pub fn curated_v1_cases(manifest: &serde_json::Value) -> Result<Vec<UnverifiedCase>, SealedError> {
    let schema =
        |detail: &str| SealedError::new(SealedErrorKind::ManifestSchema, detail.to_owned());
    let object = manifest
        .as_object()
        .ok_or_else(|| schema("manifest envelope is not an object"))?;
    let cases = object
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| schema("manifest envelope lacks a cases array"))?;
    let mut out = Vec::with_capacity(cases.len().min(1024));
    for (index, case) in cases.iter().enumerate() {
        let label = format!("case {index}");
        let object = case
            .as_object()
            .ok_or_else(|| schema(&format!("{label} is not an object")))?;
        let path = object
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| schema(&format!("{label} lacks a string path")))?;
        let sha_hex = object
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| schema(&format!("{label} lacks a string sha256")))?;
        let size = object
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| schema(&format!("{label} lacks an unsigned size")))?;
        out.push(UnverifiedCase {
            path: path.to_owned(),
            sha256: decode_sha256(sha_hex)
                .map_err(|_| schema(&format!("{label} sha256 is not 64 hex digits")))?,
            size,
            raw: case.clone(),
        });
    }
    Ok(out)
}

/// One admitted case: the normalized manifest-relative path, the declared
/// identity it was verified against, the immutable verified bytes, and the
/// opaque original case JSON for format-specific fields.
#[derive(Debug, Clone)]
pub struct SealedCase {
    path: String,
    sha256: [u8; 32],
    size: u64,
    bytes: Vec<u8>,
    raw: serde_json::Value,
}

impl SealedCase {
    /// Normalized manifest-relative path (`/`-joined validated components).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Declared SHA-256 the bytes were verified against.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// [`SealedCase::sha256`] rendered as lowercase hex.
    pub fn sha256_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in &self.sha256 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    /// Declared byte size (equal to [`SealedCase::bytes`] length).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Immutable verified bytes. The only parser input this admission
    /// vouches for.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Opaque original case JSON for format-specific fields.
    pub fn raw(&self) -> &serde_json::Value {
        &self.raw
    }
}

/// A fully admitted package: the exact authenticated manifest bytes, the
/// parsed manifest, and every declared case in manifest order with its
/// verified bytes.
#[derive(Debug, Clone)]
pub struct SealedPackage {
    manifest_bytes: Vec<u8>,
    manifest: serde_json::Value,
    cases: Vec<SealedCase>,
    index: BTreeMap<String, usize>,
}

impl SealedPackage {
    /// Admit the package `package` (relative to `root`) whose manifest file
    /// is `manifest` (relative to the package), authenticating the manifest
    /// against `expected` within `bounds`. See the module documentation for
    /// the admission pass and its guarantees.
    pub fn open(
        root: &Path,
        package: &str,
        manifest: &str,
        expected: &[u8; 32],
        bounds: SealedBounds,
    ) -> Result<Self, SealedError> {
        Self::open_with_probe(root, package, manifest, expected, bounds, &mut NoProbe)
    }

    /// [`SealedPackage::open`] with deterministic [`AdmissionProbe`] seams
    /// for race tests.
    pub fn open_with_probe(
        root: &Path,
        package: &str,
        manifest: &str,
        expected: &[u8; 32],
        bounds: SealedBounds,
        probe: &mut dyn AdmissionProbe,
    ) -> Result<Self, SealedError> {
        Self::open_with_extractor(
            root,
            package,
            manifest,
            expected,
            bounds,
            probe,
            curated_v1_cases,
        )
    }

    /// [`SealedPackage::open`] with a caller-supplied case extractor over
    /// the authenticated parsed manifest, so envelopes with a different
    /// schema keep their own shape while reusing the sealed admission
    /// pass. The extractor runs after the manifest seal and strict parse;
    /// every record it returns is still validated lexically and admitted
    /// within `bounds` before any case opens.
    pub fn open_with_extractor(
        root: &Path,
        package: &str,
        manifest: &str,
        expected: &[u8; 32],
        bounds: SealedBounds,
        probe: &mut dyn AdmissionProbe,
        extract: impl FnOnce(&serde_json::Value) -> Result<Vec<UnverifiedCase>, SealedError>,
    ) -> Result<Self, SealedError> {
        imp::admit(root, package, manifest, expected, bounds, probe, extract)
    }

    /// Exact manifest bytes the digest authenticated (before parsing).
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Parsed authenticated manifest.
    pub fn manifest(&self) -> &serde_json::Value {
        &self.manifest
    }

    /// Admitted cases in manifest order.
    pub fn cases(&self) -> &[SealedCase] {
        &self.cases
    }

    /// Look up one admitted case by normalized manifest-relative path.
    pub fn case(&self, path: &str) -> Option<&SealedCase> {
        self.index.get(path).map(|ordinal| &self.cases[*ordinal])
    }
}

/// Handle-bound admission. Implemented on Linux, where `openat` with
/// `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK`, and `O_PATH` provides the
/// required component-relative no-follow semantics; every other platform
/// fails closed (see below).
#[cfg(target_os = "linux")]
mod imp {
    use super::{
        normalize_components, parse_manifest, validate_relative_path, AdmissionProbe, SealedBounds,
        SealedCase, SealedError, SealedErrorKind, SealedPackage, UnverifiedCase,
    };
    use rustix::fs::{Dir, Mode, OFlags};
    use rustix::io::Errno;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::OwnedFd;
    use std::path::Path;

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn file_flags() -> OFlags {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
    }

    fn path_flags() -> OFlags {
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn errno_error(error: Errno, what: &str) -> SealedError {
        if error == Errno::LOOP {
            SealedError::new(
                SealedErrorKind::Symlink,
                format!("{what}: symlink encountered"),
            )
        } else {
            SealedError::new(SealedErrorKind::Io, format!("{what}: {error}"))
        }
    }

    fn io_error(error: std::io::Error, what: &str) -> SealedError {
        SealedError::new(SealedErrorKind::Io, format!("{what}: {error}"))
    }

    fn lossy(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Open a trusted walk anchor (`/` or `.`): neither spelling can
    /// traverse a symlink, so a plain strict directory open suffices.
    /// Failure kinds match [`open_root`]'s historical mapping.
    fn open_anchor(anchor: &Path, what: &str) -> Result<OwnedFd, SealedError> {
        rustix::fs::open(anchor, dir_flags(), Mode::empty()).map_err(|error| {
            if error == Errno::LOOP {
                SealedError::new(SealedErrorKind::Symlink, format!("{what} is a symlink"))
            } else if error == Errno::NOTDIR {
                SealedError::new(
                    SealedErrorKind::FileType,
                    format!("{what} is not a directory"),
                )
            } else {
                SealedError::new(SealedErrorKind::Io, format!("cannot open {what}: {error}"))
            }
        })
    }

    /// Open the corpus root enforcing no-follow on every ancestry
    /// component, not just the final one. The walk starts from a trusted
    /// anchor (`/` for absolute roots, `.` for relative ones) and opens
    /// each component with the same classify-then-open directory
    /// discipline used below the root, so a static symlink anywhere in
    /// the ancestry fails admission. `.` components are no-ops; `..`
    /// steps through the held handle, which no symlink can redirect.
    /// The final component keeps its exact historical kinds: a symlink
    /// is [`SealedErrorKind::Symlink`], a non-directory is
    /// [`SealedErrorKind::FileType`].
    fn open_root(root: &Path) -> Result<OwnedFd, SealedError> {
        use std::path::Component;
        let what = format!("corpus root {}", root.display());
        let mut components = root.components().peekable();
        let mut current = match components.peek() {
            None => {
                return Err(SealedError::new(
                    SealedErrorKind::Io,
                    format!("cannot open {what}: path is empty"),
                ));
            }
            Some(Component::Prefix(_)) => {
                return Err(SealedError::new(
                    SealedErrorKind::Path,
                    format!("{what}: path prefix is not supported"),
                ));
            }
            Some(Component::RootDir) => {
                components.next();
                open_anchor(Path::new("/"), &what)?
            }
            _ => open_anchor(Path::new("."), &what)?,
        };
        for component in components {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    return Err(SealedError::new(
                        SealedErrorKind::Path,
                        format!("{what}: repeated root is not supported"),
                    ));
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    current = open_child_dir_path(&current, Path::new(".."), &what)?;
                }
                Component::Normal(name) => {
                    current = open_child_dir_path(&current, Path::new(name), &what)?;
                }
            }
        }
        Ok(current)
    }

    /// Identity of a held directory: device plus inode. Re-opened through
    /// `"."` so the caller's handle stays usable for traversal.
    fn dir_identity(fd: &OwnedFd, what: &str) -> Result<(u64, u64), SealedError> {
        let dup = rustix::fs::openat(fd, ".", dir_flags(), Mode::empty())
            .map_err(|error| errno_error(error, what))?;
        let meta = File::from(dup)
            .metadata()
            .map_err(|error| io_error(error, what))?;
        Ok((meta.dev(), meta.ino()))
    }

    /// Open one child directory after classifying it: symlinks, files,
    /// and special entries fail with exact kinds before the strict
    /// directory open, which then only rechecks against swaps.
    fn open_child_dir(
        parent: &OwnedFd,
        component: &str,
        what: &str,
    ) -> Result<OwnedFd, SealedError> {
        open_child_dir_path(parent, Path::new(component), what)
    }

    /// [`open_child_dir`] over a raw path component. The corpus-root walk
    /// spells components as caller-supplied bytes (possibly non-UTF-8),
    /// unlike validated manifest components; classification, failure
    /// kinds, and diagnostics otherwise match exactly.
    fn open_child_dir_path(
        parent: &OwnedFd,
        name: &Path,
        what: &str,
    ) -> Result<OwnedFd, SealedError> {
        let label = format!("{what}: component {name:?}");
        match classify_at(parent, name, &label)? {
            EntryKind::Dir => {}
            EntryKind::File => {
                return Err(SealedError::new(
                    SealedErrorKind::FileType,
                    format!("{label} is not a directory"),
                ));
            }
        }
        rustix::fs::openat(parent, name, dir_flags(), Mode::empty()).map_err(|error| {
            if error == Errno::LOOP {
                SealedError::new(SealedErrorKind::Symlink, format!("{label} is a symlink"))
            } else if error == Errno::NOTDIR {
                SealedError::new(
                    SealedErrorKind::FileType,
                    format!("{label} is not a directory"),
                )
            } else {
                SealedError::new(SealedErrorKind::Io, format!("cannot open {label}: {error}"))
            }
        })
    }

    /// Walk validated components to a subdirectory, enforcing directory
    /// type and no-follow on every component.
    fn walk_dirs(
        parent: &OwnedFd,
        components: &[String],
        what: &str,
    ) -> Result<OwnedFd, SealedError> {
        let mut current = rustix::fs::openat(parent, ".", dir_flags(), Mode::empty())
            .map_err(|error| errno_error(error, what))?;
        for component in components {
            current = open_child_dir(&current, component, what)?;
        }
        Ok(current)
    }

    enum EntryKind {
        Dir,
        File,
    }

    /// Classify one directory entry without opening it for content:
    /// `O_PATH` never touches FIFOs, devices, or sockets. Symlinks are
    /// detected explicitly from the handle's own type rather than from
    /// error ordering, which varies by flag combination. Anything other
    /// than a directory or a regular file fails here, before any content
    /// handle exists.
    fn classify_at(parent: &OwnedFd, name: &Path, what: &str) -> Result<EntryKind, SealedError> {
        let fd =
            rustix::fs::openat(parent, name, path_flags(), Mode::empty()).map_err(|error| {
                if error == Errno::LOOP {
                    SealedError::new(SealedErrorKind::Symlink, format!("{what}: symlink entry"))
                } else {
                    SealedError::new(SealedErrorKind::Io, format!("{what}: {error}"))
                }
            })?;
        let meta = File::from(fd)
            .metadata()
            .map_err(|error| io_error(error, what))?;
        entry_kind_from_meta(&meta, what)
    }

    fn entry_kind_from_meta(
        meta: &std::fs::Metadata,
        what: &str,
    ) -> Result<EntryKind, SealedError> {
        if meta.file_type().is_symlink() {
            Err(SealedError::new(
                SealedErrorKind::Symlink,
                format!("{what}: symlink entry"),
            ))
        } else if meta.is_dir() {
            Ok(EntryKind::Dir)
        } else if meta.is_file() {
            Ok(EntryKind::File)
        } else {
            Err(SealedError::new(
                SealedErrorKind::FileType,
                format!("{what}: not a regular file or directory"),
            ))
        }
    }

    /// Open one validated relative file for content: walk intermediates as
    /// directories, classify the leaf without content access, then reopen
    /// it strictly and recheck regular type so a swap between classification
    /// and reopening still fails. Returns the content handle plus the
    /// leaf's device/inode identity. `O_NONBLOCK` keeps the strict open
    /// from blocking on a FIFO that won the race after classification.
    fn open_strict_file(
        package_fd: &OwnedFd,
        components: &[String],
        what: &str,
    ) -> Result<(File, (u64, u64)), SealedError> {
        let Some((leaf, intermediates)) = components.split_last() else {
            return Err(SealedError::new(
                SealedErrorKind::Path,
                format!("{what}: path has no components"),
            ));
        };
        let mut dir_fd = rustix::fs::openat(package_fd, ".", dir_flags(), Mode::empty())
            .map_err(|error| errno_error(error, what))?;
        for component in intermediates {
            dir_fd = open_child_dir(&dir_fd, component, what)?;
        }
        match classify_at(&dir_fd, Path::new(leaf), what)? {
            EntryKind::Dir => Err(SealedError::new(
                SealedErrorKind::FileType,
                format!("{what}: {leaf:?} is a directory"),
            )),
            EntryKind::File => {
                let fd = rustix::fs::openat(&dir_fd, Path::new(leaf), file_flags(), Mode::empty())
                    .map_err(|error| {
                        if error == Errno::LOOP {
                            SealedError::new(
                                SealedErrorKind::Symlink,
                                format!("{what}: {leaf:?} became a symlink"),
                            )
                        } else {
                            SealedError::new(
                                SealedErrorKind::Io,
                                format!("{what}: cannot open {leaf:?}: {error}"),
                            )
                        }
                    })?;
                let file = File::from(fd);
                let meta = file.metadata().map_err(|error| io_error(error, what))?;
                if !meta.is_file() {
                    return Err(SealedError::new(
                        SealedErrorKind::FileType,
                        format!("{what}: {leaf:?} is not a regular file"),
                    ));
                }
                Ok((file, (meta.dev(), meta.ino())))
            }
        }
    }

    /// Read a held handle to EOF with fallible growth, accepting at most
    /// `max_bytes`. Content beyond the ceiling fails instead of truncating.
    fn read_bounded(file: &mut File, max_bytes: u64, what: &str) -> Result<Vec<u8>, SealedError> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let have = buf.len() as u64;
            if have > max_bytes {
                return Err(SealedError::new(
                    SealedErrorKind::Bounds,
                    format!("{what}: exceeds {max_bytes} bytes"),
                ));
            }
            let want = max_bytes.saturating_add(1).saturating_sub(have).min(8192);
            buf.try_reserve_exact(want as usize).map_err(|_| {
                SealedError::new(
                    SealedErrorKind::Bounds,
                    format!("{what}: cannot reserve {want} bytes"),
                )
            })?;
            let base = buf.len();
            buf.resize(base + want as usize, 0);
            match file.read(&mut buf[base..]) {
                Err(error) => return Err(io_error(error, what)),
                Ok(0) => {
                    buf.truncate(base);
                    return Ok(buf);
                }
                Ok(read) => buf.truncate(base + read),
            }
        }
    }

    struct AdmittedRecord {
        normalized: String,
        components: Vec<String>,
        sha256: [u8; 32],
        size: u64,
        raw: serde_json::Value,
    }

    fn is_strict_prefix(shorter: &[String], longer: &[String]) -> bool {
        shorter.len() < longer.len() && longer.starts_with(shorter)
    }

    /// Validate every extracted record before any case opens: per-file and
    /// total admission, lexical paths, duplicates, and file/directory
    /// prefix conflicts (including against the manifest path).
    fn validate_records(
        records: &[UnverifiedCase],
        manifest_components: &[String],
        bounds: SealedBounds,
    ) -> Result<Vec<AdmittedRecord>, SealedError> {
        if records.len() as u64 > bounds.max_files {
            return Err(SealedError::new(
                SealedErrorKind::Bounds,
                format!(
                    "manifest declares {} cases, exceeding {}",
                    records.len(),
                    bounds.max_files
                ),
            ));
        }
        let mut total: u64 = 0;
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            if record.size > bounds.max_file_bytes {
                return Err(SealedError::new(
                    SealedErrorKind::Bounds,
                    format!(
                        "declared case {:?} size {} exceeds {}",
                        record.path, record.size, bounds.max_file_bytes
                    ),
                ));
            }
            total = total.checked_add(record.size).ok_or_else(|| {
                SealedError::new(
                    SealedErrorKind::Bounds,
                    "declared total case bytes overflow",
                )
            })?;
            if total > bounds.max_total_bytes {
                return Err(SealedError::new(
                    SealedErrorKind::Bounds,
                    format!(
                        "declared total case bytes exceed {}",
                        bounds.max_total_bytes
                    ),
                ));
            }
            let components = validate_relative_path(&record.path, bounds)?;
            let normalized = normalize_components(&components);
            if !seen.insert(normalized.clone()) {
                return Err(SealedError::new(
                    SealedErrorKind::Inventory,
                    format!("manifest declares {normalized:?} twice"),
                ));
            }
            out.push(AdmittedRecord {
                normalized,
                components,
                sha256: record.sha256,
                size: record.size,
                raw: record.raw.clone(),
            });
        }
        let manifest_rel = normalize_components(manifest_components);
        for record in &out {
            if record.normalized == manifest_rel {
                return Err(SealedError::new(
                    SealedErrorKind::Inventory,
                    format!("manifest path collides with declared case {manifest_rel:?}"),
                ));
            }
            if is_strict_prefix(&record.components, manifest_components)
                || is_strict_prefix(manifest_components, &record.components)
            {
                return Err(SealedError::new(
                    SealedErrorKind::Inventory,
                    format!(
                        "manifest path {:?} conflicts with declared case {:?}",
                        manifest_rel, record.normalized
                    ),
                ));
            }
        }
        for (index, left) in out.iter().enumerate() {
            for right in &out[index + 1..] {
                if is_strict_prefix(&left.components, &right.components)
                    || is_strict_prefix(&right.components, &left.components)
                {
                    return Err(SealedError::new(
                        SealedErrorKind::Inventory,
                        format!(
                            "declared cases {:?} and {:?} conflict",
                            left.normalized, right.normalized
                        ),
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Observed package inventory as raw byte paths (directory entries are
    /// arbitrary bytes; only exact byte equality with a declaration admits
    /// a file).
    struct Inventory {
        files: BTreeSet<Vec<u8>>,
        dirs: BTreeSet<Vec<u8>>,
    }

    /// Enumerate the package tree through held handles, classifying every
    /// entry without opening content. Bounded in entries, depth, and
    /// allocation before traversal.
    fn enumerate(package_fd: &OwnedFd, bounds: SealedBounds) -> Result<Inventory, SealedError> {
        let visit_bound = bounds
            .max_files
            .saturating_add(1)
            .saturating_mul(bounds.max_depth.saturating_add(1));
        let mut visited: u64 = 0;
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        let top = rustix::fs::openat(package_fd, ".", dir_flags(), Mode::empty())
            .map_err(|error| errno_error(error, "package enumeration"))?;
        let mut stack: Vec<(OwnedFd, Vec<u8>, u64)> = vec![(top, Vec::new(), 0)];
        while let Some((fd, prefix, depth)) = stack.pop() {
            let dir =
                Dir::read_from(&fd).map_err(|error| errno_error(error, "package enumeration"))?;
            for entry in dir {
                let entry = entry.map_err(|error| errno_error(error, "package enumeration"))?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                visited = visited.saturating_add(1);
                if visited > visit_bound {
                    return Err(SealedError::new(
                        SealedErrorKind::Bounds,
                        "package entry count exceeds its ceiling",
                    ));
                }
                let child_depth = depth + 1;
                if child_depth > bounds.max_depth {
                    return Err(SealedError::new(
                        SealedErrorKind::Bounds,
                        "package depth exceeds its ceiling",
                    ));
                }
                let mut relative = prefix.clone();
                if !relative.is_empty() {
                    relative.push(b'/');
                }
                relative.extend_from_slice(name);
                let what = format!("package entry {:?}", lossy(&relative));
                let name_path = Path::new(OsStr::from_bytes(name));
                match classify_at(&fd, name_path, &what)? {
                    EntryKind::Dir => {
                        let child = rustix::fs::openat(&fd, name_path, dir_flags(), Mode::empty())
                            .map_err(|error| {
                                if error == Errno::LOOP {
                                    SealedError::new(
                                        SealedErrorKind::Symlink,
                                        format!("{what}: symlink entry"),
                                    )
                                } else if error == Errno::NOTDIR {
                                    SealedError::new(
                                        SealedErrorKind::FileType,
                                        format!("{what}: not a directory"),
                                    )
                                } else {
                                    SealedError::new(
                                        SealedErrorKind::Io,
                                        format!("{what}: {error}"),
                                    )
                                }
                            })?;
                        dirs.insert(relative.clone());
                        stack.push((child, relative, child_depth));
                    }
                    EntryKind::File => {
                        files.insert(relative);
                    }
                }
            }
        }
        Ok(Inventory { files, dirs })
    }

    /// Require the observed inventory to equal exactly the manifest plus
    /// the declared cases, and every observed directory to be an implied
    /// prefix of a declared file.
    fn check_inventory(
        found: &Inventory,
        admitted: &[AdmittedRecord],
        manifest_rel: &str,
    ) -> Result<(), SealedError> {
        let mut declared = BTreeSet::new();
        declared.insert(manifest_rel.as_bytes().to_vec());
        for record in admitted {
            declared.insert(record.normalized.as_bytes().to_vec());
        }
        if let Some(missing) = declared.difference(&found.files).next() {
            return Err(SealedError::new(
                SealedErrorKind::Inventory,
                format!("declared file {:?} is missing", lossy(missing)),
            ));
        }
        if let Some(extra) = found.files.difference(&declared).next() {
            return Err(SealedError::new(
                SealedErrorKind::Inventory,
                format!("undeclared package file {:?}", lossy(extra)),
            ));
        }
        let mut implied = BTreeSet::new();
        for path in &declared {
            let mut start = 0;
            while let Some(slash) = path[start..].iter().position(|byte| *byte == b'/') {
                implied.insert(path[..start + slash].to_vec());
                start += slash + 1;
            }
        }
        for dir in &found.dirs {
            if !implied.contains(dir) {
                return Err(SealedError::new(
                    SealedErrorKind::Inventory,
                    format!("unexplained package directory {:?}", lossy(dir)),
                ));
            }
        }
        Ok(())
    }

    struct VerifiedFile {
        components: Vec<String>,
        identity: (u64, u64),
        bytes: Vec<u8>,
    }

    struct FinalCheck<'a> {
        package_components: &'a [String],
        manifest_components: &'a [String],
        root_identity: (u64, u64),
        package_identity: (u64, u64),
        manifest_identity: (u64, u64),
        manifest_bytes: &'a [u8],
        files: &'a [VerifiedFile],
        first_files: &'a BTreeSet<Vec<u8>>,
        first_dirs: &'a BTreeSet<Vec<u8>>,
    }

    /// Re-verify through fresh handles: the root path still resolves to the
    /// held root, the package path still resolves to the held package, the
    /// inventory is unchanged, and every admitted file still carries the
    /// identical object with identical bytes.
    fn final_verify(
        root: &Path,
        root_fd: &OwnedFd,
        bounds: SealedBounds,
        check: &FinalCheck<'_>,
    ) -> Result<(), SealedError> {
        let replaced = |detail: String| SealedError::new(SealedErrorKind::Replaced, detail);
        let fresh_root = open_root(root)?;
        let fresh_identity = dir_identity(&fresh_root, "corpus root")?;
        if fresh_identity != check.root_identity {
            return Err(replaced(
                "corpus root was replaced during admission".to_owned(),
            ));
        }
        let fresh_package = walk_dirs(root_fd, check.package_components, "package")?;
        let fresh_package_identity = dir_identity(&fresh_package, "package")?;
        if fresh_package_identity != check.package_identity {
            return Err(replaced(
                "package directory was replaced during admission".to_owned(),
            ));
        }
        let second = enumerate(&fresh_package, bounds)?;
        if second.files != *check.first_files || second.dirs != *check.first_dirs {
            return Err(replaced(
                "package inventory changed during admission".to_owned(),
            ));
        }
        let (mut manifest_file, manifest_identity) =
            open_strict_file(&fresh_package, check.manifest_components, "manifest")?;
        if manifest_identity != check.manifest_identity {
            return Err(replaced(
                "manifest was replaced during admission".to_owned(),
            ));
        }
        let manifest_bytes = read_bounded(
            &mut manifest_file,
            check.manifest_bytes.len() as u64,
            "manifest",
        )
        .map_err(|error| {
            if error.kind() == SealedErrorKind::Bounds {
                replaced("manifest bytes changed during admission".to_owned())
            } else {
                error
            }
        })?;
        if manifest_bytes != check.manifest_bytes {
            return Err(replaced(
                "manifest bytes changed during admission".to_owned(),
            ));
        }
        for file in check.files {
            let what = format!("declared case {:?}", normalize_components(&file.components));
            let (mut handle, identity) = open_strict_file(&fresh_package, &file.components, &what)?;
            if identity != file.identity {
                return Err(replaced(format!("{what} was replaced during admission")));
            }
            let bytes =
                read_bounded(&mut handle, file.bytes.len() as u64, &what).map_err(|error| {
                    if error.kind() == SealedErrorKind::Bounds {
                        replaced(format!("{what} bytes changed during admission"))
                    } else {
                        error
                    }
                })?;
            if bytes != file.bytes {
                return Err(replaced(format!("{what} bytes changed during admission")));
            }
        }
        Ok(())
    }

    /// Run the full admission pass described in the module documentation.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit(
        root: &Path,
        package: &str,
        manifest_name: &str,
        expected: &[u8; 32],
        bounds: SealedBounds,
        probe: &mut dyn AdmissionProbe,
        extract: impl FnOnce(&serde_json::Value) -> Result<Vec<UnverifiedCase>, SealedError>,
    ) -> Result<SealedPackage, SealedError> {
        let package_components = validate_relative_path(package, bounds)?;
        let manifest_components = validate_relative_path(manifest_name, bounds)?;
        let manifest_rel = normalize_components(&manifest_components);

        let root_fd = open_root(root)?;
        let root_identity = dir_identity(&root_fd, "corpus root")?;
        probe.after_root_open();

        let package_fd = walk_dirs(&root_fd, &package_components, "package")?;
        let package_identity = dir_identity(&package_fd, "package")?;

        let (mut manifest_file, manifest_identity) =
            open_strict_file(&package_fd, &manifest_components, "manifest")?;
        probe.after_manifest_open();
        let manifest_bytes =
            read_bounded(&mut manifest_file, bounds.max_manifest_bytes, "manifest")?;
        drop(manifest_file);
        if sha256_of(&manifest_bytes) != *expected {
            return Err(SealedError::new(
                SealedErrorKind::ManifestSeal,
                "manifest bytes differ from the expected digest",
            ));
        }
        let manifest_value = parse_manifest(&manifest_bytes)?;
        let records = extract(&manifest_value)?;
        let admitted = validate_records(&records, &manifest_components, bounds)?;
        probe.after_manifest_sealed();

        let first = enumerate(&package_fd, bounds)?;
        check_inventory(&first, &admitted, &manifest_rel)?;
        probe.after_inventory();

        let mut cases = Vec::with_capacity(admitted.len());
        let mut verified = Vec::with_capacity(admitted.len());
        let mut index = std::collections::BTreeMap::new();
        for record in &admitted {
            let what = format!("declared case {:?}", record.normalized);
            let (mut file, identity) = open_strict_file(&package_fd, &record.components, &what)?;
            probe.after_case_open(&record.normalized);
            let bytes = read_bounded(&mut file, record.size, &what).map_err(|error| {
                if error.kind() == SealedErrorKind::Bounds {
                    SealedError::new(
                        SealedErrorKind::SizeMismatch,
                        format!("{what}: exceeds declared size {}", record.size),
                    )
                } else {
                    error
                }
            })?;
            drop(file);
            if bytes.len() as u64 != record.size {
                return Err(SealedError::new(
                    SealedErrorKind::SizeMismatch,
                    format!(
                        "{what}: read {} bytes, declared {}",
                        bytes.len(),
                        record.size
                    ),
                ));
            }
            if sha256_of(&bytes) != record.sha256 {
                return Err(SealedError::new(
                    SealedErrorKind::HashMismatch,
                    format!("{what}: bytes differ from the declared digest"),
                ));
            }
            index.insert(record.normalized.clone(), cases.len());
            verified.push(VerifiedFile {
                components: record.components.clone(),
                identity,
                bytes: bytes.clone(),
            });
            cases.push(SealedCase {
                path: record.normalized.clone(),
                sha256: record.sha256,
                size: record.size,
                bytes,
                raw: record.raw.clone(),
            });
        }
        probe.after_all_cases();

        final_verify(
            root,
            &root_fd,
            bounds,
            &FinalCheck {
                package_components: &package_components,
                manifest_components: &manifest_components,
                root_identity,
                package_identity,
                manifest_identity,
                manifest_bytes: &manifest_bytes,
                files: &verified,
                first_files: &first.files,
                first_dirs: &first.dirs,
            },
        )?;

        Ok(SealedPackage {
            manifest_bytes,
            manifest: manifest_value,
            cases,
            index,
        })
    }
}

/// Fail-closed admission outside Linux: without equivalent handle-bound
/// semantics the helper reports unsupported rather than claiming safety
/// it cannot provide.
#[cfg(not(target_os = "linux"))]
mod imp {
    use super::UnverifiedCase;
    use super::{AdmissionProbe, SealedBounds, SealedError, SealedErrorKind, SealedPackage};
    use std::path::Path;

    pub(super) fn admit(
        _root: &Path,
        _package: &str,
        _manifest: &str,
        _expected: &[u8; 32],
        _bounds: SealedBounds,
        _probe: &mut dyn AdmissionProbe,
        _extract: impl FnOnce(&serde_json::Value) -> Result<Vec<UnverifiedCase>, SealedError>,
    ) -> Result<SealedPackage, SealedError> {
        Err(SealedError::new(
            SealedErrorKind::UnsupportedPlatform,
            "sealed package admission requires Linux openat/O_NOFOLLOW/O_PATH handle semantics",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        curated_v1_cases, decode_sha256, parse_expected_digest, parse_manifest,
        validate_relative_path, SealedBounds, SealedErrorKind,
    };
    use serde_json::json;

    const BOUNDS: SealedBounds = SealedBounds::new(1024, 8, 512, 1024, 64, 4);

    #[test]
    fn relative_paths_accept_nested_components() {
        assert_eq!(
            validate_relative_path("nested/case/file.bin", BOUNDS).unwrap(),
            vec!["nested", "case", "file.bin"]
        );
        assert_eq!(
            validate_relative_path("top.bin", BOUNDS).unwrap(),
            vec!["top.bin"]
        );
    }

    #[test]
    fn relative_paths_reject_escapes_and_ambiguity() {
        for rejected in [
            "",
            "/absolute.bin",
            "/",
            "C:/drive.bin",
            "C:relative.bin",
            "back\\slash.bin",
            "nested//empty.bin",
            "trailing/",
            ".",
            "..",
            "nested/./dot.bin",
            "nested/../escape.bin",
            "../escape.bin",
            "nested/../../escape.bin",
            "with\0nul.bin",
        ] {
            assert_eq!(
                validate_relative_path(rejected, BOUNDS).unwrap_err().kind(),
                SealedErrorKind::Path,
                "path {rejected:?} must be rejected"
            );
        }
    }

    #[test]
    fn relative_paths_enforce_byte_and_depth_ceilings() {
        let exact = "a".repeat(64 - 4) + ".bin";
        assert_eq!(exact.len(), 64);
        validate_relative_path(&exact, BOUNDS).unwrap();
        let overlong = "a".repeat(65 - 4) + ".bin";
        assert_eq!(
            validate_relative_path(&overlong, BOUNDS)
                .unwrap_err()
                .kind(),
            SealedErrorKind::Bounds
        );
        validate_relative_path("a/b/c/d.bin", BOUNDS).unwrap();
        assert_eq!(
            validate_relative_path("a/b/c/d/e.bin", BOUNDS)
                .unwrap_err()
                .kind(),
            SealedErrorKind::Bounds
        );
        assert_eq!(
            validate_relative_path("top.bin", SealedBounds::new(1024, 8, 512, 1024, 64, 0))
                .unwrap_err()
                .kind(),
            SealedErrorKind::Bounds
        );
    }

    #[test]
    fn digests_accept_either_hex_case_and_reject_malformed() {
        let lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let mixed = "e3B0c44298Fc1c149afBF4c8996fb92427Ae41e4649b934cA495991b7852B855";
        let decoded = decode_sha256(lower).unwrap();
        assert_eq!(decode_sha256(upper).unwrap(), decoded);
        assert_eq!(decode_sha256(mixed).unwrap(), decoded);
        assert_eq!(decoded[0], 0xe3);
        assert_eq!(decoded[31], 0x55);
        for malformed in [
            "",
            "xyz",
            &"ab".repeat(31),
            &"ab".repeat(33),
            &"zz".repeat(32),
        ] {
            assert_eq!(
                decode_sha256(malformed).unwrap_err().kind(),
                SealedErrorKind::ManifestSchema,
                "digest {malformed:?} must be rejected"
            );
        }
        assert_eq!(
            parse_expected_digest(" not hex ").unwrap_err().kind(),
            SealedErrorKind::ExpectedDigest
        );
        assert_eq!(
            parse_expected_digest(&format!("  {lower}\n")).unwrap(),
            decoded
        );
    }

    #[test]
    fn strict_parse_accepts_plain_manifests() {
        let value =
            parse_manifest(br#"{"cases": [{"path": "a.bin", "n": 1}], "flag": true}"#).unwrap();
        assert_eq!(value["cases"][0]["path"], json!("a.bin"));
    }

    #[test]
    fn strict_parse_rejects_duplicate_keys_at_every_level() {
        for (label, document) in [
            ("top level", r#"{"a": 1, "a": 2}"#),
            ("nested object", r#"{"outer": {"a": 1, "a": 2}}"#),
            (
                "array element",
                r#"{"cases": [{"path": "a"}, {"path": "b", "path": "c"}]}"#,
            ),
            ("identical values", r#"{"a": 1, "a": 1}"#),
            ("decoded escapes", "{\"A\": 1, \"\\u0041\": 2}"),
            ("decoded slash", "{\"a/b\": 1, \"a\\/b\": 2}"),
        ] {
            assert_eq!(
                parse_manifest(document.as_bytes()).unwrap_err().kind(),
                SealedErrorKind::ManifestDuplicateKeys,
                "{label} duplicates must be rejected"
            );
        }
    }

    #[test]
    fn strict_parse_rejects_malformed_documents() {
        for document in ["not json", "{unclosed", "", "\u{feff}{\"a\": 1}"] {
            assert_eq!(
                parse_manifest(document.as_bytes()).unwrap_err().kind(),
                SealedErrorKind::ManifestParse,
                "document {document:?} must be rejected"
            );
        }
    }

    #[test]
    fn v1_extractor_keeps_opaque_fields_and_validates_descriptor_types() {
        let manifest = json!({
            "schema": "synthetic.cases.v1",
            "format": "neutral-fixture",
            "package": "fixture-v1",
            "cases": [
                {
                    "path": "a.bin",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "size": 0,
                    "role": "positive",
                    "custom": {"nested": [1, 2]},
                }
            ],
        });
        let cases = curated_v1_cases(&manifest).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].path, "a.bin");
        assert_eq!(cases[0].size, 0);
        assert_eq!(cases[0].raw["role"], json!("positive"));
        assert_eq!(cases[0].raw["custom"]["nested"], json!([1, 2]));

        for manifest in [
            json!([1, 2]),
            json!({"cases": {}}),
            json!({"cases": ["a.bin"]}),
            json!({"cases": [{}]}),
            json!({"cases": [{"path": 1, "sha256": "ab", "size": 0}]}),
            json!({"cases": [{"path": "a", "sha256": 1, "size": 0}]}),
            json!({"cases": [{"path": "a", "sha256": "zz", "size": 0}]}),
            json!({"cases": [{"path": "a", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": -1}]}),
            json!({"cases": [{"path": "a", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 1.5}]}),
            json!({"cases": [{"path": "a", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": "0"}]}),
        ] {
            assert_eq!(
                curated_v1_cases(&manifest).unwrap_err().kind(),
                SealedErrorKind::ManifestSchema,
                "envelope {manifest} must be rejected"
            );
        }
        assert!(curated_v1_cases(&json!({"cases": []})).unwrap().is_empty());
    }

    #[test]
    fn error_display_names_kind_and_detail() {
        let error = decode_sha256("nope").unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("ManifestSchema"), "{rendered}");
        assert!(rendered.contains("nope"), "{rendered}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platforms_fail_closed() {
        let mut probe = super::NoProbe;
        let error = super::SealedPackage::open(
            std::path::Path::new("."),
            "package",
            "spec.json",
            &[0u8; 32],
            BOUNDS,
        );
        // open_with_probe form keeps the same fail-closed contract.
        let probe_error = super::SealedPackage::open_with_probe(
            std::path::Path::new("."),
            "package",
            "spec.json",
            &[0u8; 32],
            BOUNDS,
            &mut probe,
        );
        for result in [error, probe_error] {
            assert_eq!(
                result.unwrap_err().kind(),
                SealedErrorKind::UnsupportedPlatform
            );
        }
    }
}
