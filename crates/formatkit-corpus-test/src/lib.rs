//! **`formatkit-corpus-test`** — the generic corpus-spec test harness.
//!
//! Every format's opt-in "round-trip over sample files" test collapses to
//! the same shape: read bytes, produce a canonical [`Digest`], compare it to
//! a golden value. This crate is the runner: it walks `$FORMATKIT_CORPUS_DIR`
//! (via [`formatkit_corpus`]) for subdirectories carrying a `spec.json`, dispatches
//! each to a registered [`Digest`] handler by directory name, and asserts the
//! computed digest matches the spec's `expect`. A format crate depends on
//! this one (dev-only) to implement `Digest` for its own types and register a
//! test that calls [`run_dir`] or [`run_all`].
//!
//! Set `FORMATKIT_CORPUS_REQUIRED=1` for a deliberate corpus validation run to turn
//! every missing or empty corpus selection into a failure. Ordinary test runs
//! retain the clean-skip behavior when no corpus is configured.
//!
//! Kept separate from `formatkit-corpus` so that crate stays dependency-light (no
//! serde) and so format crates can implement [`Digest`] here without a
//! dependency cycle back through `formatkit-corpus`.

#![forbid(unsafe_code)]

mod args;
pub mod compress_oracle;
mod digest;
pub mod helpers;
pub mod manifest;
pub mod namespace;
mod registry;
pub mod sealed_package;
mod spec;

pub use args::Args;
pub use compress_oracle::{diff, load_pairs, run, run_from_corpus, Ledger, Outcome, Pair};
pub use digest::Digest;
pub use helpers::{
    archive_digest, extend_digest_object, hash_bytes, roundtrip_ok, with_file_hash, HashStream,
};
pub use manifest::{run_manifest, Evaluated, ManifestSubject};
pub use registry::{
    corpus_root, required_mode, run_all, run_dir, run_root, verify_versioned_samples, Registry,
};
pub use sealed_package::{
    curated_v1_cases, decode_sha256, expected_digest_from_env, parse_expected_digest,
    validate_relative_path, AdmissionProbe, NoProbe, SealedBounds, SealedCase, SealedError,
    SealedErrorKind, SealedPackage, UnverifiedCase, MANIFEST_SHA256_ENV_VAR,
};
pub use spec::{Sample, Spec};
