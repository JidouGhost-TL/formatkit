//! A small glTF 2.0 document builder that emits a binary `.glb` container or
//! split `.gltf` + `.bin` + texture files.
//!
//! The builder accumulates one binary buffer (accessor data plus optional
//! embedded image payloads) and the JSON arrays that index into it — buffer
//! views, accessors, meshes, materials, textures, images, samplers, skins,
//! nodes, and animations. [`GltfBuilder::finish_glb`] wraps the JSON and the
//! buffer into the two-chunk GLB layout; [`GltfBuilder::finish_split`] emits
//! external `.bin` and image files.
//!
//! All accessor data is 4-byte-scalar (`f32` / `u32`, or packed `u16x4`) and
//! every buffer view starts at a 4-byte-aligned buffer offset, so accessor
//! component alignment is satisfied without per-accessor offset math.

mod accessor;
mod animation;
mod material;
mod mesh;
mod scene;
mod serialize;

pub use animation::push_animation_channel;
pub use serialize::GltfSplitOutput;

use crate::json::Json;
use std::collections::HashMap;
use std::fmt;

const FLOAT: u64 = 5126;
const UNSIGNED_INT: u64 = 5125;
const UNSIGNED_SHORT: u64 = 5123;

/// The glTF default node transform; emitting it is discouraged by the spec.
const IDENTITY_MATRIX: [f32; 16] = [
    1.0, 0.0, 0.0, 0.0, //
    0.0, 1.0, 0.0, 0.0, //
    0.0, 0.0, 1.0, 0.0, //
    0.0, 0.0, 0.0, 1.0,
];
const ARRAY_BUFFER: u64 = 34962;
const ELEMENT_ARRAY_BUFFER: u64 = 34963;

/// One mesh primitive to emit: a material plus per-vertex attribute arrays and
/// a triangle index list. `normals` may be empty if omitted; `uvs`, `colors`,
/// `joints`, and `weights` are optional.
pub struct Prim {
    /// Material index in [`GltfBuilder`].
    pub material: usize,
    /// Per-vertex 3D positions (`POSITION`).
    pub positions: Vec<[f32; 3]>,
    /// Per-vertex normals (`NORMAL`); omitted when empty.
    pub normals: Vec<[f32; 3]>,
    /// Optional per-vertex UV coordinates (`TEXCOORD_0`).
    pub uvs: Option<Vec<[f32; 2]>>,
    /// Optional per-vertex RGBA colors (`COLOR_0`).
    pub colors: Option<Vec<[f32; 4]>>,
    /// Skin joint indices per vertex (`JOINTS_0`), 4 per vertex.
    pub joints: Option<Vec<[u16; 4]>>,
    /// Skin weights per vertex (`WEIGHTS_0`), aligned with `joints`.
    pub weights: Option<Vec<[f32; 4]>>,
    /// Triangle vertex indices (`mode = 4`, `TRIANGLES`).
    pub indices: Vec<u32>,
}

/// Additional glTF attributes passed via [`GltfBuilder::add_mesh_with_extras`].
#[derive(Debug, Default)]
pub struct PrimExtras {
    /// Skin joint indices five through eight (`JOINTS_1`).
    pub joints_1: Option<Vec<[u16; 4]>>,
    /// Skin weights five through eight (`WEIGHTS_1`).
    pub weights_1: Option<Vec<[f32; 4]>>,
    /// Per-primitive morph targets. Values are deltas, as required by glTF.
    pub morph_targets: Vec<MorphTarget>,
}

/// One glTF morph target. At least one of `positions` or `normals` must be
/// present, and each present array must match the primitive's vertex count.
#[derive(Debug, Default)]
pub struct MorphTarget {
    /// Per-vertex position deltas (`POSITION`).
    pub positions: Option<Vec<[f32; 3]>>,
    /// Per-vertex normal deltas (`NORMAL`).
    pub normals: Option<Vec<[f32; 3]>>,
}

/// The alpha behavior of a glTF material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlphaMode {
    /// Fully opaque (`"OPAQUE"`).
    Opaque,
    /// Alpha-tested cutout (`"MASK"`), using [`MaterialOptions::alpha_cutoff`].
    Mask,
    /// Alpha-blended translucency (`"BLEND"`).
    Blend,
}

impl AlphaMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Opaque => "OPAQUE",
            Self::Mask => "MASK",
            Self::Blend => "BLEND",
        }
    }
}

/// Render state which has a direct glTF material representation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MaterialOptions {
    /// Disable back-face culling when true.
    pub double_sided: bool,
    /// Alpha mode (`OPAQUE`, `MASK`, or `BLEND`).
    pub alpha_mode: AlphaMode,
    /// Alpha threshold for [`AlphaMode::Mask`]. Ignored for other modes.
    pub alpha_cutoff: f32,
    /// Emit `KHR_materials_unlit` on this material when true.
    pub unlit: bool,
}

impl Default for MaterialOptions {
    fn default() -> Self {
        Self {
            double_sided: false,
            alpha_mode: AlphaMode::Opaque,
            alpha_cutoff: 0.5,
            unlit: false,
        }
    }
}

/// A checked-builder error identifying data-shape issues that would otherwise
/// produce a glTF document rejected by validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GltfError {
    /// An accessor that glTF requires to be non-empty had zero elements.
    EmptyAccessor(&'static str),
    /// A floating-point attribute or parameter contained `NaN` or infinity.
    NonFinite(&'static str),
    /// Animation keyframe times were not strictly increasing.
    NonIncreasingTimes,
    /// An attribute array length did not match the expected vertex/keyframe count.
    AttributeLength {
        /// Attribute or track name.
        attribute: &'static str,
        /// Expected element count.
        expected: usize,
        /// Actual element count provided.
        actual: usize,
    },
    /// One half of a required attribute pair (e.g. `JOINTS_0`/`WEIGHTS_0`) was missing.
    MissingPairedAttribute(&'static str),
    /// `JOINTS_1`/`WEIGHTS_1` were supplied without `JOINTS_0`/`WEIGHTS_0`.
    MissingBaseSkinAttributes,
    /// A morph target had neither `positions` nor `normals`.
    EmptyMorphTarget,
    /// Primitives in the same mesh had differing morph-target counts.
    MorphTargetCount {
        /// Target count of the first primitive in the mesh.
        expected: usize,
        /// Target count of the mismatched primitive.
        actual: usize,
    },
    /// A triangle index referenced a vertex past the end of `positions`.
    IndexOutOfBounds {
        /// Offending index value.
        index: u32,
        /// Number of vertices in the primitive.
        vertex_count: usize,
    },
    /// An animation channel targeted a node index that does not exist.
    NodeOutOfBounds(usize),
    /// An animation channel targeted a node that uses a non-identity `matrix`.
    AnimatedNodeHasMatrix(usize),
    /// A rotation quaternion was not unit length.
    NonUnitQuaternion,
    /// Encoding an embedded image (e.g. PNG) failed.
    ImageEncode(String),
}

impl fmt::Display for GltfError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAccessor(name) => write!(out, "{name} accessor is empty"),
            Self::NonFinite(name) => write!(out, "{name} contains a non-finite value"),
            Self::NonIncreasingTimes => write!(out, "animation times are not strictly increasing"),
            Self::AttributeLength {
                attribute,
                expected,
                actual,
            } => write!(
                out,
                "{attribute} has {actual} values but the primitive has {expected} vertices"
            ),
            Self::MissingPairedAttribute(name) => {
                write!(out, "{name} must be provided with its paired attribute")
            }
            Self::MissingBaseSkinAttributes => {
                write!(out, "JOINTS_1/WEIGHTS_1 require JOINTS_0/WEIGHTS_0")
            }
            Self::EmptyMorphTarget => write!(out, "morph target has no attributes"),
            Self::MorphTargetCount { expected, actual } => write!(
                out,
                "primitive has {actual} morph targets but the mesh expects {expected}"
            ),
            Self::IndexOutOfBounds {
                index,
                vertex_count,
            } => write!(
                out,
                "index {index} is outside the primitive's {vertex_count} vertices"
            ),
            Self::NodeOutOfBounds(node) => write!(out, "animation node {node} does not exist"),
            Self::AnimatedNodeHasMatrix(node) => {
                write!(out, "animation node {node} has a non-TRS matrix transform")
            }
            Self::NonUnitQuaternion => write!(out, "rotation contains a non-unit quaternion"),
            Self::ImageEncode(msg) => write!(out, "image encoding failed: {msg}"),
        }
    }
}

impl std::error::Error for GltfError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrsPath {
    Translation,
    Rotation,
    Scale,
}

impl TrsPath {
    fn as_str(self) -> &'static str {
        match self {
            Self::Translation => "translation",
            Self::Rotation => "rotation",
            Self::Scale => "scale",
        }
    }
}

struct NodeData {
    name: Option<String>,
    matrix: Option<[f32; 16]>,
    translation: Option<[f32; 3]>,
    rotation: Option<[f32; 4]>,
    scale: Option<[f32; 3]>,
    mesh: Option<usize>,
    skin: Option<usize>,
    children: Vec<usize>,
}

enum ImageRecord {
    Embedded {
        offset: usize,
        len: usize,
        mime_type: String,
    },
    External {
        uri: String,
        mime_type: Option<String>,
    },
}

/// Accumulates a glTF 2.0 document and its binary buffer.
#[derive(Default)]
pub struct GltfBuilder {
    generator: Option<String>,
    buffer: Vec<u8>,
    buffer_views: Vec<Json>,
    accessors: Vec<Json>,
    meshes: Vec<Json>,
    materials: Vec<Json>,
    images: Vec<Json>,
    image_records: Vec<ImageRecord>,
    textures: Vec<Json>,
    samplers: Vec<Json>,
    nodes: Vec<NodeData>,
    animations: Vec<Json>,
    skins: Vec<Json>,
    uses_unlit: bool,
    solid_material: Option<usize>,
    #[cfg(feature = "png")]
    texture_material: HashMap<(u16, u16), usize>,
    configured_solid_material: HashMap<MaterialKey, usize>,
    #[cfg(feature = "png")]
    configured_texture_material: HashMap<(u16, u16, MaterialKey), usize>,
    #[cfg(feature = "png")]
    sampler: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MaterialKey {
    double_sided: bool,
    alpha_mode: AlphaMode,
    alpha_cutoff_bits: u32,
    unlit: bool,
}

impl From<MaterialOptions> for MaterialKey {
    fn from(options: MaterialOptions) -> Self {
        Self {
            double_sided: options.double_sided,
            alpha_mode: options.alpha_mode,
            alpha_cutoff_bits: options.alpha_cutoff.to_bits(),
            unlit: options.unlit,
        }
    }
}

impl GltfBuilder {
    /// Create an empty glTF 2.0 builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the `asset.generator` string (defaults to `"formatkit-gltf"`).
    pub fn set_generator(&mut self, generator: impl Into<String>) {
        self.generator = Some(generator.into());
    }
}

fn f(x: f32) -> Json {
    Json::Num(x as f64)
}

#[cfg(test)]
mod tests;
