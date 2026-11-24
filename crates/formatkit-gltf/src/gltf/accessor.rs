use super::{
    f, GltfBuilder, GltfError, ARRAY_BUFFER, ELEMENT_ARRAY_BUFFER, FLOAT, UNSIGNED_INT,
    UNSIGNED_SHORT,
};
use crate::json::Json;

impl GltfBuilder {
    /// Append `data` at the next 4-byte-aligned offset and record a buffer
    /// view over it. `target` is set for vertex/index data (`ARRAY_BUFFER` /
    /// `ELEMENT_ARRAY_BUFFER`) and omitted for image and animation data.
    /// Returns the view index.
    pub(super) fn add_view(&mut self, data: &[u8], target: Option<u64>) -> usize {
        while !self.buffer.len().is_multiple_of(4) {
            self.buffer.push(0);
        }
        let offset = self.buffer.len();
        self.buffer.extend_from_slice(data);
        let mut fields = vec![
            ("buffer", Json::UInt(0)),
            ("byteOffset", Json::UInt(offset as u64)),
            ("byteLength", Json::UInt(data.len() as u64)),
        ];
        if let Some(t) = target {
            fields.push(("target", Json::UInt(t)));
        }
        self.buffer_views.push(Json::Obj(fields));
        self.buffer_views.len() - 1
    }

    fn add_accessor(
        &mut self,
        view: usize,
        component_type: u64,
        count: usize,
        ty: &'static str,
        min_max: Option<(Vec<f32>, Vec<f32>)>,
    ) -> usize {
        debug_assert!(count > 0, "glTF accessor.count must be >= 1");
        let mut fields = vec![
            ("bufferView", Json::UInt(view as u64)),
            ("componentType", Json::UInt(component_type)),
            ("count", Json::UInt(count as u64)),
            ("type", Json::Str(ty.to_string())),
        ];
        if let Some((min, max)) = min_max {
            fields.push(("min", Json::Arr(min.into_iter().map(f).collect())));
            fields.push(("max", Json::Arr(max.into_iter().map(f).collect())));
        }
        self.accessors.push(Json::Obj(fields));
        self.accessors.len() - 1
    }

    /// A `VEC3` float POSITION accessor, with the glTF-required `min`/`max`.
    pub(super) fn add_positions(&mut self, data: &[[f32; 3]]) -> usize {
        let view = self.add_view(&flatten3(data), Some(ARRAY_BUFFER));
        let (min, max) = bounds3(data);
        self.add_accessor(view, FLOAT, data.len(), "VEC3", Some((min, max)))
    }

    pub(super) fn add_vec3(&mut self, data: &[[f32; 3]], target: Option<u64>) -> usize {
        let view = self.add_view(&flatten3(data), target);
        self.add_accessor(view, FLOAT, data.len(), "VEC3", None)
    }

    pub(super) fn add_vec2(&mut self, data: &[[f32; 2]], target: Option<u64>) -> usize {
        let mut bytes = Vec::with_capacity(data.len() * 8);
        for v in data {
            for c in v {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        let view = self.add_view(&bytes, target);
        self.add_accessor(view, FLOAT, data.len(), "VEC2", None)
    }

    pub(super) fn add_vec4(&mut self, data: &[[f32; 4]], target: Option<u64>) -> usize {
        let mut bytes = Vec::with_capacity(data.len() * 16);
        for v in data {
            for c in v {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        let view = self.add_view(&bytes, target);
        self.add_accessor(view, FLOAT, data.len(), "VEC4", None)
    }

    pub(super) fn add_indices(&mut self, data: &[u32]) -> usize {
        let mut bytes = Vec::with_capacity(data.len() * 4);
        for &i in data {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        let view = self.add_view(&bytes, Some(ELEMENT_ARRAY_BUFFER));
        self.add_accessor(view, UNSIGNED_INT, data.len(), "SCALAR", None)
    }

    /// A `SCALAR` float accessor with `min`/`max` — the shape an animation
    /// sampler input (keyframe times) requires.
    pub fn add_scalar_times(&mut self, times: &[f32]) -> usize {
        self.try_add_scalar_times(times)
            .expect("animation times must be finite, non-empty, and increasing")
    }

    /// Checked form of [`GltfBuilder::add_scalar_times`]. Values are copied as
    /// their original `f32` bit patterns; no frame-rate conversion or endpoint
    /// rounding is applied.
    pub fn try_add_scalar_times(&mut self, times: &[f32]) -> Result<usize, GltfError> {
        super::animation::validate_times(times)?;
        let mut bytes = Vec::with_capacity(times.len() * 4);
        for &t in times {
            bytes.extend_from_slice(&t.to_le_bytes());
        }
        let view = self.add_view(&bytes, None);
        let min = times.iter().cloned().fold(f32::INFINITY, f32::min);
        let max = times.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        Ok(self.add_accessor(
            view,
            FLOAT,
            times.len(),
            "SCALAR",
            Some((vec![min], vec![max])),
        ))
    }

    /// A `VEC3` float accessor for animation sampler output (translation/scale).
    pub fn add_anim_vec3(&mut self, data: &[[f32; 3]]) -> usize {
        self.add_vec3(data, None)
    }

    /// A `VEC4` float accessor for animation sampler output (rotation quats).
    pub fn add_anim_vec4(&mut self, data: &[[f32; 4]]) -> usize {
        self.add_vec4(data, None)
    }

    /// An unsigned-short `VEC4` accessor (`JOINTS_0` skin joint indices).
    pub(super) fn add_u16x4(&mut self, data: &[[u16; 4]]) -> usize {
        let mut bytes = Vec::with_capacity(data.len() * 8);
        for v in data {
            for c in v {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        let view = self.add_view(&bytes, Some(ARRAY_BUFFER));
        self.add_accessor(view, UNSIGNED_SHORT, data.len(), "VEC4", None)
    }

    /// A float `MAT4` accessor (skin inverse-bind matrices), column-major.
    pub(super) fn add_mat4(&mut self, data: &[[f32; 16]]) -> usize {
        let mut bytes = Vec::with_capacity(data.len() * 64);
        for m in data {
            for c in m {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        let view = self.add_view(&bytes, None);
        self.add_accessor(view, FLOAT, data.len(), "MAT4", None)
    }
}

fn flatten3(data: &[[f32; 3]]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(data.len() * 12);
    for v in data {
        for c in v {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
    }
    bytes
}

fn bounds3(data: &[[f32; 3]]) -> (Vec<f32>, Vec<f32>) {
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for v in data {
        for k in 0..3 {
            min[k] = min[k].min(v[k]);
            max[k] = max[k].max(v[k]);
        }
    }
    for k in 0..3 {
        if !min[k].is_finite() {
            min[k] = 0.0;
        }
        if !max[k].is_finite() {
            max[k] = 0.0;
        }
    }
    (min.to_vec(), max.to_vec())
}
