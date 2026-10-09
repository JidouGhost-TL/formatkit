//! Fixed-point 3-D transform math shared by the model coordinate hierarchy and
//! animation evaluation.
//!
//! The console's geometry unit represents a transform as a 3×3 rotation/scale
//! matrix whose elements are fixed-point with `4096 == 1.0`, plus an integer
//! translation. Products of two such matrices (and of a matrix by a vector)
//! carry an extra `4096` factor that is removed with an arithmetic `>> 12`
//! shift — the convention every consumer here follows. All arithmetic is done
//! in `i64` intermediates and the shift is a floor-toward-negative-infinity
//! arithmetic shift, matching the hardware's `sra`.

/// Fixed-point scale where `ONE == 1.0`.
pub const ONE: i32 = 4096;

/// Binary-point shift for signed Q12 values (`4096 == 1.0`).
///
/// This is public so integer-domain evaluators can remove one multiplied Q12
/// factor without duplicating the representation constant.
pub const Q12_SHIFT: u32 = 12;

/// Convert a signed 16-bit Q12 scalar to `f32` without changing the owner's
/// rounding policy: conversion happens before division by the exactly
/// representable power-of-two scale.
#[inline]
pub fn q12_i16_to_f32(value: i16) -> f32 {
    value as f32 / ONE as f32
}

/// A fixed-point rigid/scale transform: a 3×3 rotation-scale matrix `m` (each
/// element `4096 == 1.0`, row-major) and an integer translation `t`.
///
/// The fixed-point convention is: `m` composes with the `>> 12`
/// fixed-point convention and `t` is an integer world offset applied after the
/// matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matrix {
    /// Row-major 3×3 rotation/scale, `4096 == 1.0`.
    pub m: [[i16; 3]; 3],
    /// Integer translation, applied after `m`.
    pub t: [i32; 3],
}

impl Default for Matrix {
    fn default() -> Self {
        Self::IDENTITY
    }
}

/// Saturating narrow of an `i64` to `i16` (the matrix element type). A composed
/// rotation stays within `±ONE`, but a scaled or crafted transform can exceed
/// the range; saturating (rather than wrapping or panicking) keeps a malformed
/// input bounded.
pub fn saturating_i16(v: i64) -> i16 {
    v.clamp(i16::MIN as i64, i16::MAX as i64) as i16
}

/// How an IEEE-754 binary16 NaN is represented after widening to `f32`.
///
/// Both policies preserve every finite value, signed zero, and infinity bit
/// exactly. The choice exists because some format owners historically retain
/// the stored NaN sign/payload while others deliberately canonicalize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary16Nan {
    /// Retain the binary16 sign and payload in the corresponding `f32` lanes.
    PreservePayload,
    /// Return Rust's canonical positive quiet NaN.
    Canonical,
}

/// Widen one IEEE-754 binary16 bit pattern to `f32` under an explicit NaN
/// policy.
///
/// This is a scalar conversion only: byte order and format-level acceptance of
/// non-finite values remain with the caller.
pub fn binary16_to_f32(value: u16, nan: Binary16Nan) -> f32 {
    let sign = (u32::from(value) & 0x8000) << 16;
    let exponent = (value >> 10) & 0x1f;
    let fraction = value & 0x03ff;
    let bits = match exponent {
        0 if fraction == 0 => sign,
        0 => {
            let leading = 15 - fraction.leading_zeros() as i32;
            let exponent = leading - 24 + 127;
            let mantissa = (u32::from(fraction) << (23 - leading)) & 0x7f_ffff;
            sign | ((exponent as u32) << 23) | mantissa
        }
        0x1f if fraction != 0 && nan == Binary16Nan::Canonical => f32::NAN.to_bits(),
        0x1f => sign | 0x7f80_0000 | (u32::from(fraction) << 13),
        _ => sign | ((u32::from(exponent) + 112) << 23) | (u32::from(fraction) << 13),
    };
    f32::from_bits(bits)
}

/// Saturating narrow of an `i64` to `i32` (the translation/world-coordinate
/// type).
fn sat_i32(v: i64) -> i32 {
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

impl Matrix {
    /// The identity transform: `m` is the `4096`-scaled 3×3 identity, `t` is
    /// zero.
    pub const IDENTITY: Matrix = Matrix {
        m: [[ONE as i16, 0, 0], [0, ONE as i16, 0], [0, 0, ONE as i16]],
        t: [0, 0, 0],
    };

    /// Builds a translation-only transform (identity rotation).
    pub fn from_translation(t: [i32; 3]) -> Matrix {
        Matrix {
            m: Matrix::IDENTITY.m,
            t,
        }
    }

    /// Composes `parent ∘ local`: the result maps a vector from `local`'s space
    /// all the way out through `parent`'s space. Rotation is `parent.m · local.m`
    /// (`>> 12`); translation is `parent.m · local.t` (`>> 12`) offset by
    /// `parent.t` — i.e. `local`'s origin expressed in `parent`'s parent space.
    #[allow(clippy::needless_range_loop)] // `k` indexes both operands' arrays.
    pub fn compose(parent: &Matrix, local: &Matrix) -> Matrix {
        let mut m = [[0i16; 3]; 3];
        for (i, row) in m.iter_mut().enumerate() {
            for (j, out) in row.iter_mut().enumerate() {
                let mut acc = 0i64;
                for k in 0..3 {
                    acc += parent.m[i][k] as i64 * local.m[k][j] as i64;
                }
                *out = saturating_i16(acc >> Q12_SHIFT);
            }
        }
        let mut t = [0i32; 3];
        for (i, out) in t.iter_mut().enumerate() {
            let mut acc = 0i64;
            for k in 0..3 {
                acc += parent.m[i][k] as i64 * local.t[k] as i64;
            }
            *out = sat_i32((acc >> Q12_SHIFT) + parent.t[i] as i64);
        }
        Matrix { m, t }
    }

    /// Applies this transform to a 16-bit vector, returning full-range 32-bit
    /// world coordinates: `v' = (m · v) >> 12 + t`.
    #[allow(clippy::needless_range_loop)] // `k` indexes both the row and `v`.
    pub fn apply(&self, v: [i16; 3]) -> [i32; 3] {
        let mut out = [0i32; 3];
        for (i, o) in out.iter_mut().enumerate() {
            let mut acc = 0i64;
            for k in 0..3 {
                acc += self.m[i][k] as i64 * v[k] as i64;
            }
            *o = sat_i32((acc >> Q12_SHIFT) + self.t[i] as i64);
        }
        out
    }

    /// Applies this transform to a 16-bit vector and saturates the result back
    /// to 16-bit — the console vertex type. Matches the geometry unit's own
    /// `i16` clamp on transformed vertices; use [`Matrix::apply`] when the full
    /// 32-bit range must be preserved.
    pub fn apply_i16(&self, v: [i16; 3]) -> [i16; 3] {
        let w = self.apply(v);
        [
            saturating_i16(w[0] as i64),
            saturating_i16(w[1] as i64),
            saturating_i16(w[2] as i64),
        ]
    }

    /// Builds a local transform from an animation object's translation/rotation/
    /// scale triple. `rot` is Euler angles in the console convention where
    /// `4096 == one full turn` per axis; `scale` is fixed-point (`4096 == 1.0`);
    /// `trans` is integer.
    ///
    /// The rotation is `Rz · Ry · Rx` (X applied first), matching the geometry
    /// unit's `RotMatrix` ordering, and each axis rotation is scaled in-place by
    /// the corresponding scale factor. The rotation entries are computed from a
    /// floating sine and rounded to the `4096` fixed-point grid — exact for the
    /// axis-aligned angles the golden tests assert (0°, 90°) and a close
    /// approximation elsewhere; translation and scale are exact integers.
    #[allow(clippy::needless_range_loop)] // fixed-size matrix index math
    pub fn from_trs(rot: [i32; 3], scale: [i16; 3], trans: [i32; 3]) -> Matrix {
        let (sx, cx) = fixed_turn_sin_cos(rot[0]);
        let (sy, cy) = fixed_turn_sin_cos(rot[1]);
        let (sz, cz) = fixed_turn_sin_cos(rot[2]);

        // Rz · Ry · Rx in fixed point (each factor 4096 = 1.0), products >> 12.
        let mul = |a: i32, b: i32| -> i32 { ((a as i64 * b as i64) >> Q12_SHIFT) as i32 };
        // Ry · Rx first.
        let r = [
            [cy, mul(sy, sx), mul(sy, cx)],
            [0, cx, -sx],
            [-sy, mul(cy, sx), mul(cy, cx)],
        ];
        // Rz · (Ry·Rx).
        let mut rot_m = [[0i32; 3]; 3];
        let rz = [[cz, -sz, 0], [sz, cz, 0], [0, 0, ONE]];
        for i in 0..3 {
            for j in 0..3 {
                let mut acc = 0i64;
                for k in 0..3 {
                    acc += rz[i][k] as i64 * r[k][j] as i64;
                }
                rot_m[i][j] = (acc >> Q12_SHIFT) as i32;
            }
        }
        // Scale each column by its axis scale factor.
        let mut m = [[0i16; 3]; 3];
        for (i, row) in m.iter_mut().enumerate() {
            for (j, out) in row.iter_mut().enumerate() {
                let scaled = (rot_m[i][j] as i64 * scale[j] as i64) >> Q12_SHIFT;
                *out = saturating_i16(scaled);
            }
        }
        Matrix { m, t: trans }
    }
}

/// Fixed-point sine/cosine for an angle where `4096 == one full turn`, returned
/// scaled by `4096`.
///
/// Evaluation remains in `f64` and each component is rounded independently to
/// the fixed grid. This is the shared console-animation convention, not a
/// general radians API or a lookup-table approximation.
pub fn fixed_turn_sin_cos(angle: i32) -> (i32, i32) {
    let turns = angle as f64 / ONE as f64;
    let rad = turns * core::f64::consts::TAU;
    let s = (rad.sin() * ONE as f64).round() as i32;
    let c = (rad.cos() * ONE as f64).round() as i32;
    (s, c)
}

/// Hamilton product of two floating-point quaternions in `[x, y, z, w]`
/// component order.
///
/// This operation does not normalize either operand or the result. Hemisphere,
/// normalization thresholds and interpolation policy remain with the caller.
pub fn quaternion_multiply(left: [f32; 4], right: [f32; 4]) -> [f32; 4] {
    let [left_x, left_y, left_z, left_w] = left;
    let [right_x, right_y, right_z, right_w] = right;
    [
        left_w * right_x + left_x * right_w + left_y * right_z - left_z * right_y,
        left_w * right_y - left_x * right_z + left_y * right_w + left_z * right_x,
        left_w * right_z + left_x * right_y - left_y * right_x + left_z * right_w,
        left_w * right_w - left_x * right_x - left_y * right_y - left_z * right_z,
    ]
}

/// Normalize an `[x, y, z, w]` quaternion using an owner-selected minimum
/// length and fallback.
///
/// The threshold is deliberately data, not policy hidden in this helper:
/// console runtimes disagree on whether tiny but nonzero quaternions survive.
/// Non-finite lengths take the fallback because the comparison is false,
/// matching both adopted owners.
pub fn normalize_quaternion(
    quaternion: [f32; 4],
    minimum_length: f32,
    fallback: [f32; 4],
) -> [f32; 4] {
    let length = (quaternion[0] * quaternion[0]
        + quaternion[1] * quaternion[1]
        + quaternion[2] * quaternion[2]
        + quaternion[3] * quaternion[3])
        .sqrt();
    if length > minimum_length {
        [
            quaternion[0] / length,
            quaternion[1] / length,
            quaternion[2] / length,
            quaternion[3] / length,
        ]
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q12_i16_float_conversion_matches_the_owner_expression_exhaustively() {
        for value in i16::MIN..=i16::MAX {
            assert_eq!(
                q12_i16_to_f32(value).to_bits(),
                (value as f32 / 4096.0).to_bits(),
                "Q12 value {value}"
            );
        }
        assert_eq!(Q12_SHIFT, 12);
    }

    #[test]
    fn binary16_widening_matches_both_legacy_owner_policies_exhaustively() {
        fn legacy_canonical(value: u16) -> f32 {
            let sign = if value & 0x8000 != 0 { -1.0 } else { 1.0 };
            let exponent = (value >> 10) & 0x1f;
            let fraction = (value & 0x03ff) as f32;
            match exponent {
                0 => sign * fraction * 2.0f32.powi(-24),
                0x1f if fraction == 0.0 => sign * f32::INFINITY,
                0x1f => f32::NAN,
                _ => sign * (1024.0 + fraction) * 2.0f32.powi(exponent as i32 - 25),
            }
        }

        fn legacy_preserved(value: u16) -> f32 {
            let sign = (u32::from(value) & 0x8000) << 16;
            let exponent = (value >> 10) & 0x1f;
            let fraction = value & 0x03ff;
            let bits = match exponent {
                0 if fraction == 0 => sign,
                0 => {
                    let leading = 15 - fraction.leading_zeros() as i32;
                    let exponent = leading - 24 + 127;
                    let mantissa = (u32::from(fraction) << (23 - leading)) & 0x7f_ffff;
                    sign | ((exponent as u32) << 23) | mantissa
                }
                0x1f => sign | 0x7f80_0000 | (u32::from(fraction) << 13),
                _ => sign | ((u32::from(exponent) + 112) << 23) | (u32::from(fraction) << 13),
            };
            f32::from_bits(bits)
        }

        for value in 0..=u16::MAX {
            assert_eq!(
                binary16_to_f32(value, Binary16Nan::Canonical).to_bits(),
                legacy_canonical(value).to_bits(),
                "canonical binary16 {value:#06x}"
            );
            assert_eq!(
                binary16_to_f32(value, Binary16Nan::PreservePayload).to_bits(),
                legacy_preserved(value).to_bits(),
                "payload-preserving binary16 {value:#06x}"
            );
        }
    }

    #[test]
    fn saturating_i16_pins_boundaries_and_full_i32_input_domain_shape() {
        for value in [
            i32::MIN,
            i16::MIN as i32 - 1,
            i16::MIN as i32,
            -1,
            0,
            1,
            i16::MAX as i32,
            i16::MAX as i32 + 1,
            i32::MAX,
        ] {
            assert_eq!(
                saturating_i16(i64::from(value)),
                value.clamp(i16::MIN as i32, i16::MAX as i32) as i16
            );
        }
        assert_eq!(saturating_i16(i64::MIN), i16::MIN);
        assert_eq!(saturating_i16(i64::MAX), i16::MAX);
    }

    #[test]
    fn fixed_turn_sine_cosine_pins_axes_turns_and_integer_extremes() {
        assert_eq!(fixed_turn_sin_cos(0), (0, ONE));
        assert_eq!(fixed_turn_sin_cos(ONE / 4), (ONE, 0));
        assert_eq!(fixed_turn_sin_cos(-(ONE / 4)), (-ONE, 0));
        assert_eq!(fixed_turn_sin_cos(ONE / 2), (0, -ONE));
        assert_eq!(fixed_turn_sin_cos(ONE), (0, ONE));
        assert_eq!(fixed_turn_sin_cos(ONE * 9), (0, ONE));
        assert_eq!(fixed_turn_sin_cos(-ONE * 7), (0, ONE));

        for angle in [i32::MIN, i32::MIN + 1, i32::MAX - 1, i32::MAX] {
            let (sin, cos) = fixed_turn_sin_cos(angle);
            assert!((-ONE..=ONE).contains(&sin), "sine at {angle}");
            assert!((-ONE..=ONE).contains(&cos), "cosine at {angle}");
        }
    }

    #[test]
    fn quaternion_product_preserves_order_and_does_not_normalize() {
        let x = [1.0, 0.0, 0.0, 0.0];
        let y = [0.0, 1.0, 0.0, 0.0];
        assert_eq!(quaternion_multiply(x, y), [0.0, 0.0, 1.0, 0.0]);
        assert_eq!(quaternion_multiply(y, x), [0.0, 0.0, -1.0, 0.0]);
        assert_eq!(
            quaternion_multiply([2.0, 0.0, 0.0, 0.0], y),
            [0.0, 0.0, 2.0, 0.0]
        );
    }

    #[test]
    fn quaternion_normalization_keeps_threshold_and_fallback_as_owner_policy() {
        let fallback = [0.0, 0.0, 0.0, 1.0];
        assert_eq!(
            normalize_quaternion([f32::EPSILON, 0.0, 0.0, 0.0], f32::EPSILON, fallback),
            fallback
        );
        assert_eq!(
            normalize_quaternion([5.0e-7, 0.0, 0.0, 0.0], f32::EPSILON, fallback),
            [1.0, 0.0, 0.0, 0.0]
        );
        assert_eq!(
            normalize_quaternion([5.0e-7, 0.0, 0.0, 0.0], 1.0e-6, fallback),
            fallback
        );
        assert_eq!(
            normalize_quaternion([f32::NAN, 1.0, 0.0, 0.0], 0.0, fallback),
            fallback
        );
    }

    #[test]
    fn identity_compose_is_identity() {
        let i = Matrix::IDENTITY;
        assert_eq!(Matrix::compose(&i, &i), i);
    }

    #[test]
    fn identity_apply_is_passthrough() {
        let i = Matrix::IDENTITY;
        assert_eq!(i.apply([10, -20, 300]), [10, -20, 300]);
    }

    #[test]
    fn compose_places_child_translation_in_parent_space() {
        // Parent: identity rotation, translated by (0,0,-300); child: identity
        // rotation at its own origin. Composed origin = (0,0,-300).
        let parent = Matrix::from_translation([0, 0, -300]);
        let child = Matrix::IDENTITY;
        let world = Matrix::compose(&parent, &child);
        assert_eq!(world.t, [0, 0, -300]);
        assert_eq!(world.m, Matrix::IDENTITY.m);
    }

    #[test]
    fn compose_rotates_child_translation_by_parent() {
        // Parent = +quarter-turn about Z (maps +X -> +Y): m = [[0,-1,0],
        // [1,0,0],[0,0,1]] scaled by 4096. Child translated +100 on X.
        let parent = Matrix {
            m: [
                [0, -(ONE as i16), 0],
                [ONE as i16, 0, 0],
                [0, 0, ONE as i16],
            ],
            t: [0, 0, 0],
        };
        let child = Matrix::from_translation([100, 0, 0]);
        let world = Matrix::compose(&parent, &child);
        // parent.m · (100,0,0) >> 12 = (0, 100, 0).
        assert_eq!(world.t, [0, 100, 0]);
    }

    #[test]
    fn apply_uses_floor_shift_on_negative() {
        // m row 0 = (1, 0, 0) scaled: 4096 * v >> 12 == v. A fractional-scale
        // row exercises the arithmetic (floor) shift on a negative product.
        let m = Matrix {
            m: [[2048, 0, 0], [0, ONE as i16, 0], [0, 0, ONE as i16]],
            t: [0, 0, 0],
        };
        // 2048 * -3 = -6144; -6144 >> 12 = -2 (floor), not -1 (truncation).
        assert_eq!(m.apply([-3, 0, 0])[0], -2);
    }

    #[test]
    fn from_trs_identity_rotation_is_scale_translation() {
        let m = Matrix::from_trs([0, 0, 0], [ONE as i16, ONE as i16, ONE as i16], [7, 8, 9]);
        assert_eq!(m.m, Matrix::IDENTITY.m);
        assert_eq!(m.t, [7, 8, 9]);
    }

    #[test]
    fn from_trs_quarter_turn_z_is_exact() {
        // +quarter turn about Z = angle 1024 (4096 == full turn), unit scale.
        let m = Matrix::from_trs(
            [0, 0, 1024],
            [ONE as i16, ONE as i16, ONE as i16],
            [0, 0, 0],
        );
        // Rz(+90°): [[0,-1,0],[1,0,0],[0,0,1]] * 4096.
        assert_eq!(
            m.m,
            [
                [0, -(ONE as i16), 0],
                [ONE as i16, 0, 0],
                [0, 0, ONE as i16]
            ]
        );
    }

    #[test]
    fn apply_i16_saturates() {
        let m = Matrix::from_translation([40000, 0, 0]);
        // 100 + 40000 = 40100 -> clamped to i16::MAX.
        assert_eq!(m.apply_i16([100, 0, 0])[0], i16::MAX);
    }
}
