//! Small topology iterators used while exporting triangle primitives.
//!
//! These helpers preserve the caller's index values and emit every triangle,
//! including degenerates. Format owners remain responsible for filtering,
//! primitive-restart handling, and any format-specific winding conversion.

pub use formatkit_core::topology::{triangle_fan, triangle_strip};
