use super::{GltfBuilder, GltfError, Prim, PrimExtras, ARRAY_BUFFER};
use crate::json::Json;

impl GltfBuilder {
    /// Emit a mesh from its primitives, returning its index. A primitive with
    /// no positions is skipped; a mesh with no usable primitive is still
    /// emitted (empty) so node wiring stays stable.
    pub fn add_mesh(&mut self, prims: Vec<Prim>) -> usize {
        self.emit_mesh(
            prims
                .into_iter()
                .map(|prim| (prim, PrimExtras::default()))
                .collect(),
        )
    }

    /// Emit a mesh with optional second skin-weight sets and morph targets.
    ///
    /// Every attribute is checked before the builder is mutated. This prevents
    /// mismatched arrays, unpaired skin attributes, inconsistent target counts,
    /// and out-of-range indices from becoming validator-invalid glTF.
    pub fn add_mesh_with_extras(
        &mut self,
        prims: Vec<(Prim, PrimExtras)>,
    ) -> Result<usize, GltfError> {
        let mut mesh_target_count = None;
        for (prim, extras) in &prims {
            if prim.positions.is_empty() || prim.indices.is_empty() {
                continue;
            }
            validate_prim(prim, extras)?;
            if let Some(expected) = mesh_target_count {
                if extras.morph_targets.len() != expected {
                    return Err(GltfError::MorphTargetCount {
                        expected,
                        actual: extras.morph_targets.len(),
                    });
                }
            } else {
                mesh_target_count = Some(extras.morph_targets.len());
            }
        }
        Ok(self.emit_mesh(prims))
    }

    fn emit_mesh(&mut self, prims: Vec<(Prim, PrimExtras)>) -> usize {
        let mut json_prims = Vec::new();
        for (p, extras) in prims {
            if p.positions.is_empty() || p.indices.is_empty() {
                continue;
            }
            let pos = self.add_positions(&p.positions);
            let mut attrs = vec![("POSITION", Json::UInt(pos as u64))];
            if !p.normals.is_empty() {
                let nrm = self.add_vec3(&p.normals, Some(ARRAY_BUFFER));
                attrs.push(("NORMAL", Json::UInt(nrm as u64)));
            }
            if let Some(uv) = &p.uvs {
                let a = self.add_vec2(uv, Some(ARRAY_BUFFER));
                attrs.push(("TEXCOORD_0", Json::UInt(a as u64)));
            }
            if let Some(col) = &p.colors {
                let a = self.add_vec4(col, Some(ARRAY_BUFFER));
                attrs.push(("COLOR_0", Json::UInt(a as u64)));
            }
            if let Some(j) = &p.joints {
                let a = self.add_u16x4(j);
                attrs.push(("JOINTS_0", Json::UInt(a as u64)));
            }
            if let Some(wts) = &p.weights {
                let a = self.add_vec4(wts, Some(ARRAY_BUFFER));
                attrs.push(("WEIGHTS_0", Json::UInt(a as u64)));
            }
            if let Some(joints) = &extras.joints_1 {
                let accessor = self.add_u16x4(joints);
                attrs.push(("JOINTS_1", Json::UInt(accessor as u64)));
            }
            if let Some(weights) = &extras.weights_1 {
                let accessor = self.add_vec4(weights, Some(ARRAY_BUFFER));
                attrs.push(("WEIGHTS_1", Json::UInt(accessor as u64)));
            }
            let idx = self.add_indices(&p.indices);
            let mut fields = vec![
                ("attributes", Json::Obj(attrs)),
                ("indices", Json::UInt(idx as u64)),
                ("material", Json::UInt(p.material as u64)),
                ("mode", Json::UInt(4)),
            ];
            if !extras.morph_targets.is_empty() {
                let mut targets = Vec::with_capacity(extras.morph_targets.len());
                for target in extras.morph_targets {
                    let mut attributes = Vec::new();
                    if let Some(positions) = target.positions {
                        let accessor = self.add_vec3(&positions, Some(ARRAY_BUFFER));
                        attributes.push(("POSITION", Json::UInt(accessor as u64)));
                    }
                    if let Some(normals) = target.normals {
                        let accessor = self.add_vec3(&normals, Some(ARRAY_BUFFER));
                        attributes.push(("NORMAL", Json::UInt(accessor as u64)));
                    }
                    targets.push(Json::Obj(attributes));
                }
                fields.push(("targets", Json::Arr(targets)));
            }
            json_prims.push(Json::Obj(fields));
        }
        self.meshes
            .push(Json::Obj(vec![("primitives", Json::Arr(json_prims))]));
        self.meshes.len() - 1
    }
}

fn validate_attribute_len<T>(
    values: Option<&[T]>,
    vertex_count: usize,
    attribute: &'static str,
) -> Result<(), GltfError> {
    if let Some(values) = values {
        if values.len() != vertex_count {
            return Err(GltfError::AttributeLength {
                attribute,
                expected: vertex_count,
                actual: values.len(),
            });
        }
    }
    Ok(())
}

fn validate_prim(prim: &Prim, extras: &PrimExtras) -> Result<(), GltfError> {
    let vertex_count = prim.positions.len();
    if prim
        .positions
        .iter()
        .flatten()
        .any(|component| !component.is_finite())
    {
        return Err(GltfError::NonFinite("POSITION"));
    }
    validate_attribute_len(
        (!prim.normals.is_empty()).then_some(prim.normals.as_slice()),
        vertex_count,
        "NORMAL",
    )?;
    validate_attribute_len(prim.uvs.as_deref(), vertex_count, "TEXCOORD_0")?;
    validate_attribute_len(prim.colors.as_deref(), vertex_count, "COLOR_0")?;
    validate_attribute_len(prim.joints.as_deref(), vertex_count, "JOINTS_0")?;
    validate_attribute_len(prim.weights.as_deref(), vertex_count, "WEIGHTS_0")?;
    validate_attribute_len(extras.joints_1.as_deref(), vertex_count, "JOINTS_1")?;
    validate_attribute_len(extras.weights_1.as_deref(), vertex_count, "WEIGHTS_1")?;

    if prim.joints.is_some() != prim.weights.is_some() {
        return Err(GltfError::MissingPairedAttribute("JOINTS_0/WEIGHTS_0"));
    }
    if extras.joints_1.is_some() != extras.weights_1.is_some() {
        return Err(GltfError::MissingPairedAttribute("JOINTS_1/WEIGHTS_1"));
    }
    if extras.joints_1.is_some() && prim.joints.is_none() {
        return Err(GltfError::MissingBaseSkinAttributes);
    }

    if let Some(index) = prim
        .indices
        .iter()
        .copied()
        .find(|&index| index as usize >= vertex_count)
    {
        return Err(GltfError::IndexOutOfBounds {
            index,
            vertex_count,
        });
    }

    for values in prim
        .normals
        .iter()
        .flatten()
        .chain(prim.uvs.iter().flatten().flatten())
        .chain(prim.colors.iter().flatten().flatten())
        .chain(prim.weights.iter().flatten().flatten())
        .chain(extras.weights_1.iter().flatten().flatten())
    {
        if !values.is_finite() {
            return Err(GltfError::NonFinite("vertex attribute"));
        }
    }

    for target in &extras.morph_targets {
        if target.positions.is_none() && target.normals.is_none() {
            return Err(GltfError::EmptyMorphTarget);
        }
        validate_attribute_len(target.positions.as_deref(), vertex_count, "morph POSITION")?;
        validate_attribute_len(target.normals.as_deref(), vertex_count, "morph NORMAL")?;
        let finite = target
            .positions
            .iter()
            .flatten()
            .flatten()
            .chain(target.normals.iter().flatten().flatten())
            .all(|component| component.is_finite());
        if !finite {
            return Err(GltfError::NonFinite("morph target"));
        }
    }
    Ok(())
}
