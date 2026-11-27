use crate::prelude::*;

use super::{animation, GltfBuilder, GltfError, NodeData};
use crate::json::Json;

impl GltfBuilder {
    /// Add a skin: `joint_nodes` are node indices (in joint order) and
    /// `inverse_bind` are their column-major inverse-bind matrices. Returns the
    /// skin index to assign to a mesh node with [`GltfBuilder::set_node_skin`].
    pub fn add_skin(&mut self, joint_nodes: &[usize], inverse_bind: &[[f32; 16]]) -> usize {
        let ibm = self.add_mat4(inverse_bind);
        self.skins.push(Json::Obj(vec![
            ("inverseBindMatrices", Json::UInt(ibm as u64)),
            (
                "joints",
                Json::Arr(joint_nodes.iter().map(|&n| Json::UInt(n as u64)).collect()),
            ),
        ]));
        self.skins.len() - 1
    }

    /// Bind a skin to a node (the node whose mesh is skinned).
    pub fn set_node_skin(&mut self, node: usize, skin: usize) {
        if let Some(n) = self.nodes.get_mut(node) {
            n.skin = Some(skin);
        }
    }

    /// Add a node with an optional local matrix (column-major 4×4), an optional
    /// mesh, and an optional name. Children are attached later with
    /// [`GltfBuilder::add_child`].
    pub fn add_node(
        &mut self,
        name: Option<String>,
        matrix: Option<[f32; 16]>,
        mesh: Option<usize>,
    ) -> usize {
        self.nodes.push(NodeData {
            name,
            matrix,
            translation: None,
            rotation: None,
            scale: None,
            mesh,
            skin: None,
            children: Vec::new(),
        });
        self.nodes.len() - 1
    }

    /// Add a node with a decomposed translation / rotation (quaternion `[x,y,z,w]`)
    /// / scale transform instead of a matrix. glTF requires TRS (not `matrix`) on
    /// any node targeted by an animation channel, so animated nodes use this.
    pub fn add_node_trs(
        &mut self,
        name: Option<String>,
        translation: [f32; 3],
        rotation: [f32; 4],
        scale: [f32; 3],
        mesh: Option<usize>,
    ) -> usize {
        self.nodes.push(NodeData {
            name,
            matrix: None,
            translation: Some(translation),
            rotation: Some(rotation),
            scale: Some(scale),
            mesh,
            skin: None,
            children: Vec::new(),
        });
        self.nodes.len() - 1
    }

    /// Checked form of [`GltfBuilder::add_node_trs`]. This rejects values that
    /// cannot legally be serialized as glTF TRS rather than silently replacing
    /// non-finite components in JSON.
    pub fn try_add_node_trs(
        &mut self,
        name: Option<String>,
        translation: [f32; 3],
        rotation: [f32; 4],
        scale: [f32; 3],
        mesh: Option<usize>,
    ) -> Result<usize, GltfError> {
        animation::validate_finite_vec3(&translation, "node translation")?;
        animation::validate_quaternion(&rotation)?;
        animation::validate_finite_vec3(&scale, "node scale")?;
        Ok(self.add_node_trs(name, translation, rotation, scale, mesh))
    }

    /// Attach `child` under `parent`. Out-of-range indices are ignored.
    pub fn add_child(&mut self, parent: usize, child: usize) {
        if let Some(n) = self.nodes.get_mut(parent) {
            n.children.push(child);
        }
    }
}
