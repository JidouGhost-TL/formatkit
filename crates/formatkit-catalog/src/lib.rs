//! Platform-neutral identities, descriptors, contracts and catalog resolution.
#![forbid(unsafe_code)]
mod identity;
pub use identity::{Category, FormatId, Id, Method};
pub mod catalog;
pub use catalog::*;
mod compatibility;
pub use compatibility::{CompatibilityRecognitionContribution, CompatibilityRecognitionRule};

#[cfg(test)]
mod compatibility_tests;
#[cfg(test)]
mod synthetic;
