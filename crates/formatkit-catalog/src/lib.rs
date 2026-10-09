//! Platform-neutral identities, descriptors, contracts and catalog resolution.
#![forbid(unsafe_code)]
mod identity;
pub use identity::{Category, FormatId, Id, Method};
pub mod catalog;
pub use catalog::*;

#[cfg(test)]
mod synthetic;
