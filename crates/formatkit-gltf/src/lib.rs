//! Dependency-free glTF 2.0 binary (`.glb`) and split (`.gltf` + `.bin`)
//! writer, strict GLB container reader/writer, and transform helpers.
//!
//! [`gltf::GltfBuilder`] accumulates a glTF 2.0 document and its binary buffer
//! from neutral geometry ([`gltf::Prim`]: positions, normals, optional
//! UVs/colours/skinning, indices), PBR and `KHR_materials_unlit` materials,
//! embedded PNG or external images, samplers, skins, morph targets, a node
//! tree, and animation channels, then serializes either a single self-contained
//! `.glb` ([`GltfBuilder::try_finish_glb`] / [`GltfBuilder::finish_glb`]) or a
//! split `.gltf` + `.bin` + textures bundle ([`GltfBuilder::finish_split`]).
//!
//! [`glb::read_glb`] and [`glb::write_glb`] provide strict, checked GLB 2.0
//! container framing without external JSON dependencies.
//!
//! # Example
//! ```
//! use formatkit_gltf::{read_glb, GltfBuilder};
//!
//! let mut builder = GltfBuilder::new();
//! let root = builder.add_node(Some("root".into()), None, None);
//! let glb = builder.try_finish_glb(vec![root]).unwrap();
//! let (json, _bin) = read_glb(&glb).unwrap();
//! assert!(core::str::from_utf8(json).unwrap().contains("\"version\":\"2.0\""));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Strict GLB 2.0 binary container reader and writer.
pub mod glb;
/// glTF 2.0 scene, mesh, material, skin, and animation document builder.
pub mod gltf;
/// Compact, dependency-free JSON value tree and serializer.
pub mod json;
/// Triangle strip and triangle fan topology iterators.
pub mod topology;
/// Basis-column normalization and quaternion extraction helpers.
pub mod transform;

pub use glb::{read_glb, write_glb};
pub use gltf::{
    AlphaMode, GltfBuilder, GltfError, GltfSplitOutput, MaterialOptions, MorphTarget, Prim,
    PrimExtras,
};
pub use topology::{triangle_fan, triangle_strip};
pub use transform::{
    normalize_basis_columns, shepperd_quaternion_unnormalized, DegenerateColumnScale,
};
