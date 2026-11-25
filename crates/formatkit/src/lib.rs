//! Umbrella re-export crate for the Formatkit binary data toolkit.
//!
//! With `default = []`, the umbrella re-exports the core foundation crates:
//! - [`core`] (`formatkit-core`): checked bytes/bits, sources, budgets, checksums, and shared values
//! - [`layout`] (`formatkit-layout`): fields, records, declarative table/chunk/marker specs, symmetric `pack_*` writers, offset-graph rewrites, IFF/RIFF, charmaps, and edits
//! - [`catalog`] (`formatkit-catalog`): open format identities, detection, and operation contracts
//! - [`runtime`] (`formatkit-runtime`): explicit owner-module composition and dispatch
//!
//! Optional crates are gated behind Cargo features:
//! - `archive` → `archive` (`formatkit-archive`)
//! - `pixel` → `pixel` (`formatkit-pixel`)
//! - `codec` → `codec` (`formatkit-codec`)
//! - `patch` → `patch` (`formatkit-patch`)
//! - `gltf` → `gltf` (`formatkit-gltf`)
//! - `corpus` → `corpus` (`formatkit-corpus`) and `corpus_test` (`formatkit-corpus-test`)
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#[cfg(feature = "archive")]
pub use formatkit_archive as archive;
pub use formatkit_catalog as catalog;
#[cfg(feature = "codec")]
pub use formatkit_codec as codec;
pub use formatkit_core as core;
#[cfg(feature = "corpus")]
pub use formatkit_corpus as corpus;
#[cfg(feature = "corpus")]
pub use formatkit_corpus_test as corpus_test;
#[cfg(feature = "gltf")]
pub use formatkit_gltf as gltf;
pub use formatkit_layout as layout;
#[cfg(feature = "pixel")]
pub use formatkit_pixel as pixel;
pub use formatkit_runtime as runtime;

#[cfg(feature = "patch")]
pub use formatkit_patch as patch;
