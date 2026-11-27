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
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

/// `alloc` types the `std` prelude would otherwise supply, so module code reads
/// the same with and without the `std` feature.
#[allow(unused_imports)]
mod prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec::Vec;
    pub(crate) use alloc::{format, vec};
}

/// Hash collections with `std`; ordered `alloc` collections without it, so the
/// crate needs no hashing dependency. Iteration order is never relied upon.
#[allow(unused_imports)]
mod collections {
    #[cfg(not(feature = "std"))]
    pub(crate) use alloc::collections::{
        btree_map as hash_map, BTreeMap as HashMap, BTreeSet as HashSet,
    };
    #[cfg(feature = "std")]
    pub(crate) use std::collections::{hash_map, HashMap, HashSet};

    /// `HashMap::with_capacity`, or an empty ordered map without `std`.
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pub(crate) fn map_with_capacity<K, V>(capacity: usize) -> HashMap<K, V> {
        HashMap::with_capacity(capacity)
    }

    #[cfg(not(feature = "std"))]
    #[allow(dead_code)]
    pub(crate) fn map_with_capacity<K, V>(_capacity: usize) -> HashMap<K, V> {
        HashMap::new()
    }

    /// `HashSet::with_capacity`, or an empty ordered set without `std`.
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pub(crate) fn set_with_capacity<T>(capacity: usize) -> HashSet<T> {
        HashSet::with_capacity(capacity)
    }

    #[cfg(not(feature = "std"))]
    #[allow(dead_code)]
    pub(crate) fn set_with_capacity<T>(_capacity: usize) -> HashSet<T> {
        HashSet::new()
    }
}
mod identity;
pub use identity::{Category, FormatId, Id, Method};

/// Host path of the path-aware detection and file-backed decode entry points.
///
/// With the `std` feature this is [`std::path::Path`]. Without it, it is an
/// uninhabited stand-in: those fields keep their shape (so struct literals
/// compile the same either way) but can only hold `None`.
#[cfg(feature = "std")]
pub type HostPath = std::path::Path;

/// Host path of the path-aware detection and file-backed decode entry points.
///
/// With the `std` feature this is `std::path::Path`. Without it, it is this
/// uninhabited stand-in: those fields keep their shape (so struct literals
/// compile the same either way) but can only hold `None`.
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostPath {}
/// Format descriptors, probe outcomes, input schemas, and executable operation contracts.
pub mod catalog;
pub use catalog::*;
mod compatibility;
pub use compatibility::{CompatibilityRecognitionContribution, CompatibilityRecognitionRule};

#[cfg(test)]
mod compatibility_tests;
#[cfg(test)]
mod synthetic;
