//! Transform decomposition kernels shared by glTF exporters.

/// Caller policy for a zero or tiny basis-column length during TRS
/// decomposition.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DegenerateColumnScale {
    /// Preserve the measured scale and substitute a unit divisor only for an
    /// exact zero. `NaN` remains a divisor.
    PreserveExactZero,
    /// Substitute unit scale and unit divisor at or below the given threshold.
    /// `NaN` is preserved as output scale and uses a unit divisor.
    UnitAtOrBelow(f32),
}

/// Measure and normalize the three columns of a 3×3 basis.
///
/// The input is `columns[column][row]`; the returned rotation is conventional
/// `rotation[row][column]`. Translation extraction, matrix storage convention,
/// quaternion conversion, and reflection/shear policy stay with the caller.
#[must_use]
pub fn normalize_basis_columns(
    columns: [[f32; 3]; 3],
    policy: DegenerateColumnScale,
) -> ([[f32; 3]; 3], [f32; 3]) {
    let mut scale = [0.0f32; 3];
    let mut rotation = [[0.0f32; 3]; 3];
    for column in 0..3 {
        let length = (columns[column][0] * columns[column][0]
            + columns[column][1] * columns[column][1]
            + columns[column][2] * columns[column][2])
            .sqrt();
        let (divisor, output_scale) = match policy {
            DegenerateColumnScale::PreserveExactZero => {
                (if length == 0.0 { 1.0 } else { length }, length)
            }
            DegenerateColumnScale::UnitAtOrBelow(threshold) => (
                if length > threshold { length } else { 1.0 },
                if length <= threshold { 1.0 } else { length },
            ),
        };
        scale[column] = output_scale;
        for row in 0..3 {
            rotation[row][column] = columns[column][row] / divisor;
        }
    }
    (rotation, scale)
}

/// Compute Shepperd's numerically stable quaternion candidate for a normalized
/// rotation matrix, using row/column indexing and glTF `[x, y, z, w]` order.
///
/// The result is intentionally not normalized so callers can apply their own
/// policy for zero, tiny, or non-finite inputs.
#[must_use]
pub fn shepperd_quaternion_unnormalized(matrix: &[[f32; 3]; 3]) -> [f32; 4] {
    let trace = matrix[0][0] + matrix[1][1] + matrix[2][2];
    if trace > 0.0 {
        let scale = 0.5 / (trace + 1.0).sqrt();
        [
            (matrix[2][1] - matrix[1][2]) * scale,
            (matrix[0][2] - matrix[2][0]) * scale,
            (matrix[1][0] - matrix[0][1]) * scale,
            0.25 / scale,
        ]
    } else if matrix[0][0] > matrix[1][1] && matrix[0][0] > matrix[2][2] {
        let scale = 2.0 * (1.0 + matrix[0][0] - matrix[1][1] - matrix[2][2]).sqrt();
        [
            0.25 * scale,
            (matrix[0][1] + matrix[1][0]) / scale,
            (matrix[0][2] + matrix[2][0]) / scale,
            (matrix[2][1] - matrix[1][2]) / scale,
        ]
    } else if matrix[1][1] > matrix[2][2] {
        let scale = 2.0 * (1.0 + matrix[1][1] - matrix[0][0] - matrix[2][2]).sqrt();
        [
            (matrix[0][1] + matrix[1][0]) / scale,
            0.25 * scale,
            (matrix[1][2] + matrix[2][1]) / scale,
            (matrix[0][2] - matrix[2][0]) / scale,
        ]
    } else {
        let scale = 2.0 * (1.0 + matrix[2][2] - matrix[0][0] - matrix[1][1]).sqrt();
        [
            (matrix[0][2] + matrix[2][0]) / scale,
            (matrix[1][2] + matrix[2][1]) / scale,
            0.25 * scale,
            (matrix[1][0] - matrix[0][1]) / scale,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rotation_matrix(quaternion: [f32; 4]) -> [[f32; 3]; 3] {
        let [x, y, z, w] = quaternion;
        [
            [
                1.0 - 2.0 * (y * y + z * z),
                2.0 * (x * y - z * w),
                2.0 * (x * z + y * w),
            ],
            [
                2.0 * (x * y + z * w),
                1.0 - 2.0 * (x * x + z * z),
                2.0 * (y * z - x * w),
            ],
            [
                2.0 * (x * z - y * w),
                2.0 * (y * z + x * w),
                1.0 - 2.0 * (x * x + y * y),
            ],
        ]
    }

    #[test]
    fn identity_and_half_turns_select_every_stable_branch() {
        assert_eq!(
            shepperd_quaternion_unnormalized(&[[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]),
            [0.0, 0.0, 0.0, 1.0]
        );
        assert_eq!(
            shepperd_quaternion_unnormalized(&[
                [1.0, 0.0, 0.0],
                [0.0, -1.0, 0.0],
                [0.0, 0.0, -1.0],
            ]),
            [1.0, 0.0, 0.0, 0.0]
        );
        assert_eq!(
            shepperd_quaternion_unnormalized(&[
                [-1.0, 0.0, 0.0],
                [0.0, 1.0, 0.0],
                [0.0, 0.0, -1.0],
            ]),
            [0.0, 1.0, 0.0, 0.0]
        );
        assert_eq!(
            shepperd_quaternion_unnormalized(&[
                [-1.0, 0.0, 0.0],
                [0.0, -1.0, 0.0],
                [0.0, 0.0, 1.0],
            ]),
            [0.0, 0.0, 1.0, 0.0]
        );
    }

    #[test]
    fn non_finite_input_is_left_for_caller_normalization_policy() {
        let quaternion = shepperd_quaternion_unnormalized(&[
            [f32::NAN, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, 1.0],
        ]);
        assert!(quaternion.iter().any(|lane| lane.is_nan()));
    }

    #[test]
    fn off_axis_rotations_cover_signs_in_each_diagonal_branch() {
        let half_angle = 85.0_f32.to_radians();
        let (sin, cos) = half_angle.sin_cos();
        for axis in [[0.8_f32, 0.3, 0.5], [0.3, 0.8, 0.5], [0.3, 0.5, 0.8]] {
            let length = axis.iter().map(|lane| lane * lane).sum::<f32>().sqrt();
            let expected = [
                axis[0] / length * sin,
                axis[1] / length * sin,
                axis[2] / length * sin,
                cos,
            ];
            let actual = shepperd_quaternion_unnormalized(&rotation_matrix(expected));
            for lane in 0..4 {
                assert!(
                    (actual[lane] - expected[lane]).abs() < 2e-6,
                    "axis {axis:?}, lane {lane}: {actual:?} != {expected:?}"
                );
            }
        }
    }

    #[test]
    fn column_normalization_keeps_both_degenerate_policies() {
        let columns = [[0.0, 0.0, 0.0], [5.0e-7, 0.0, 0.0], [f32::NAN, 1.0, 0.0]];
        let (preserved_rotation, preserved_scale) =
            normalize_basis_columns(columns, DegenerateColumnScale::PreserveExactZero);
        assert_eq!(preserved_scale[0].to_bits(), 0.0f32.to_bits());
        assert_eq!(preserved_rotation[0][0].to_bits(), 0.0f32.to_bits());
        assert_eq!(preserved_scale[1].to_bits(), 5.0e-7f32.to_bits());
        assert_eq!(preserved_rotation[0][1].to_bits(), 1.0f32.to_bits());
        assert!(preserved_rotation[0][2].is_nan());

        let (unit_rotation, unit_scale) =
            normalize_basis_columns(columns, DegenerateColumnScale::UnitAtOrBelow(1.0e-6));
        assert_eq!(unit_scale[0].to_bits(), 1.0f32.to_bits());
        assert_eq!(unit_scale[1].to_bits(), 1.0f32.to_bits());
        assert_eq!(unit_rotation[0][1].to_bits(), 5.0e-7f32.to_bits());
        assert!(unit_scale[2].is_nan());
        assert!(unit_rotation[0][2].is_nan());
    }
}
