//! Platform-neutral format identities, descriptors, contracts, and catalog resolution.
//!
//! # Overview
//! - **Identity types**: [`FormatId`], [`Id`], [`Category`], and [`Method`] define open,
//!   platform-neutral format identifiers without hard-coding a registry.
//! - **[`catalog`]**: descriptors, probe outcomes, namespace/leaf/writer contracts, input schemas,
//!   and support catalogs.
//! - **Compatibility**: [`CompatibilityRecognitionContribution`] and [`CompatibilityRecognitionRule`]
//!   support incremental migration while format owners transition `Legacy` rows to `Strict`
//!   owner-authorized module rows in `formatkit-runtime`.
#![forbid(unsafe_code)]
mod identity;
pub use identity::{Category, FormatId, Id, Method};
/// Format descriptors, probe outcomes, input schemas, and executable operation contracts.
pub mod catalog;
pub use catalog::*;
mod compatibility;
pub use compatibility::{CompatibilityRecognitionContribution, CompatibilityRecognitionRule};

#[cfg(test)]
mod compatibility_tests;
#[cfg(test)]
mod synthetic;
