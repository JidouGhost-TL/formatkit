use crate::prelude::*;

use super::{GltfBuilder, GltfError, TrsPath, IDENTITY_MATRIX};
use crate::json::Json;

impl GltfBuilder {
    /// Add an animation from pre-built channels and samplers (JSON objects).
    pub fn add_animation(&mut self, name: &str, channels: Vec<Json>, samplers: Vec<Json>) {
        self.animations.push(Json::Obj(vec![
            ("name", Json::Str(name.to_string())),
            ("channels", Json::Arr(channels)),
            ("samplers", Json::Arr(samplers)),
        ]));
    }

    /// Append an exact-time translation track targeting a TRS node.
    pub fn push_translation_channel(
        &mut self,
        channels: &mut Vec<Json>,
        samplers: &mut Vec<Json>,
        node: usize,
        times: &[f32],
        values: &[[f32; 3]],
    ) -> Result<(), GltfError> {
        self.push_vec3_channel(
            channels,
            samplers,
            node,
            times,
            values,
            TrsPath::Translation,
        )
    }

    /// Append an exact-time scale track targeting a TRS node.
    pub fn push_scale_channel(
        &mut self,
        channels: &mut Vec<Json>,
        samplers: &mut Vec<Json>,
        node: usize,
        times: &[f32],
        values: &[[f32; 3]],
    ) -> Result<(), GltfError> {
        self.push_vec3_channel(channels, samplers, node, times, values, TrsPath::Scale)
    }

    /// Append an exact-time quaternion rotation track targeting a TRS node.
    pub fn push_rotation_channel(
        &mut self,
        channels: &mut Vec<Json>,
        samplers: &mut Vec<Json>,
        node: usize,
        times: &[f32],
        values: &[[f32; 4]],
    ) -> Result<(), GltfError> {
        self.validate_animation_track(node, times, values.len())?;
        for value in values {
            validate_quaternion(value)?;
        }
        let input = self.try_add_scalar_times(times)?;
        let output = self.add_anim_vec4(values);
        push_animation_channel(
            channels,
            samplers,
            input,
            node,
            TrsPath::Rotation.as_str(),
            output,
        );
        Ok(())
    }

    /// Append an exact-time quaternion `CUBICSPLINE` track targeting a TRS node.
    ///
    /// `values` uses the glTF triplet layout
    /// `[in tangent, value, out tangent]` for every input time. Tangents must
    /// be finite; the center value of every triplet must be a unit quaternion.
    pub fn push_rotation_cubic_spline_channel(
        &mut self,
        channels: &mut Vec<Json>,
        samplers: &mut Vec<Json>,
        node: usize,
        times: &[f32],
        values: &[[f32; 4]],
    ) -> Result<(), GltfError> {
        self.validate_animation_track(node, times, times.len())?;
        let expected = times
            .len()
            .checked_mul(3)
            .ok_or(GltfError::AttributeLength {
                attribute: "CUBICSPLINE animation output",
                expected: usize::MAX,
                actual: values.len(),
            })?;
        if values.len() != expected {
            return Err(GltfError::AttributeLength {
                attribute: "CUBICSPLINE animation output",
                expected,
                actual: values.len(),
            });
        }
        for (index, value) in values.iter().enumerate() {
            if index % 3 == 1 {
                validate_quaternion(value)?;
            } else if value.iter().any(|component| !component.is_finite()) {
                return Err(GltfError::NonFinite("rotation tangent"));
            }
        }
        let input = self.try_add_scalar_times(times)?;
        let output = self.add_anim_vec4(values);
        let sampler = samplers.len();
        samplers.push(Json::Obj(vec![
            ("input", Json::UInt(input as u64)),
            ("output", Json::UInt(output as u64)),
            ("interpolation", Json::Str("CUBICSPLINE".to_string())),
        ]));
        channels.push(Json::Obj(vec![
            ("sampler", Json::UInt(sampler as u64)),
            (
                "target",
                Json::Obj(vec![
                    ("node", Json::UInt(node as u64)),
                    ("path", Json::Str("rotation".to_string())),
                ]),
            ),
        ]));
        Ok(())
    }

    fn push_vec3_channel(
        &mut self,
        channels: &mut Vec<Json>,
        samplers: &mut Vec<Json>,
        node: usize,
        times: &[f32],
        values: &[[f32; 3]],
        path: TrsPath,
    ) -> Result<(), GltfError> {
        self.validate_animation_track(node, times, values.len())?;
        let value_name = path.as_str();
        for value in values {
            validate_finite_vec3(value, value_name)?;
        }
        let input = self.try_add_scalar_times(times)?;
        let output = self.add_anim_vec3(values);
        push_animation_channel(channels, samplers, input, node, path.as_str(), output);
        Ok(())
    }

    fn validate_animation_track(
        &self,
        node: usize,
        times: &[f32],
        value_count: usize,
    ) -> Result<(), GltfError> {
        let node_data = self
            .nodes
            .get(node)
            .ok_or(GltfError::NodeOutOfBounds(node))?;
        if node_data
            .matrix
            .is_some_and(|matrix| matrix != IDENTITY_MATRIX)
        {
            return Err(GltfError::AnimatedNodeHasMatrix(node));
        }
        validate_times(times)?;
        if value_count != times.len() {
            return Err(GltfError::AttributeLength {
                attribute: "animation output",
                expected: times.len(),
                actual: value_count,
            });
        }
        Ok(())
    }
}

pub(super) fn validate_times(times: &[f32]) -> Result<(), GltfError> {
    if times.is_empty() {
        return Err(GltfError::EmptyAccessor("animation input"));
    }
    if times.iter().any(|time| !time.is_finite()) {
        return Err(GltfError::NonFinite("animation input"));
    }
    if times.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(GltfError::NonIncreasingTimes);
    }
    Ok(())
}

pub(super) fn validate_finite_vec3(values: &[f32; 3], name: &'static str) -> Result<(), GltfError> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(GltfError::NonFinite(name));
    }
    Ok(())
}

pub(super) fn validate_quaternion(value: &[f32; 4]) -> Result<(), GltfError> {
    if value.iter().any(|component| !component.is_finite()) {
        return Err(GltfError::NonFinite("rotation"));
    }
    let length_squared = value
        .iter()
        .map(|component| component * component)
        .sum::<f32>();
    if (length_squared - 1.0).abs() > 1.0e-3 {
        return Err(GltfError::NonUnitQuaternion);
    }
    Ok(())
}

/// Append one LINEAR animation sampler (over `input`/`output` accessor
/// indices) and its channel (targeting `node`'s `path` property), keeping the
/// new sampler's index in `samplers` in agreement with the channel that
/// references it.
pub fn push_animation_channel(
    channels: &mut Vec<Json>,
    samplers: &mut Vec<Json>,
    input: usize,
    node: usize,
    path: &'static str,
    output: usize,
) {
    let sidx = samplers.len();
    samplers.push(Json::Obj(vec![
        ("input", Json::UInt(input as u64)),
        ("output", Json::UInt(output as u64)),
        ("interpolation", Json::Str("LINEAR".to_string())),
    ]));
    channels.push(Json::Obj(vec![
        ("sampler", Json::UInt(sidx as u64)),
        (
            "target",
            Json::Obj(vec![
                ("node", Json::UInt(node as u64)),
                ("path", Json::Str(path.to_string())),
            ]),
        ),
    ]));
}
