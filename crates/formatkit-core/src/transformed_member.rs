//! Bounded execution of one resident member transformation.

use std::sync::Arc;

use crate::{
    Error, MemberAccessMode, MemberContentSource, RangeSource, Result, SourceRange,
    TransformRecipe, TransformedRangeSource, WorkBudget, WorkResource,
};

/// Complete input and output contract for one transformed member.
#[derive(Clone)]
pub struct TransformMaterialization {
    /// Source containing the exact stored dependency.
    pub source: Arc<dyn RangeSource>,
    /// Exact stored bytes consumed by the recipe.
    pub dependency: SourceRange,
    /// Exact transformed output size.
    pub output_size: u64,
    /// Independent caller ceiling for this member.
    pub max_output_size: u64,
    /// Stable transform and recipe identity.
    pub recipe: TransformRecipe,
    /// Human-readable coordinate-space name for the transformed bytes.
    pub coordinate_name: String,
}

impl std::fmt::Debug for TransformMaterialization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransformMaterialization")
            .field("dependency", &self.dependency)
            .field("output_size", &self.output_size)
            .field("max_output_size", &self.max_output_size)
            .field("recipe", &self.recipe)
            .field("coordinate_name", &self.coordinate_name)
            .finish_non_exhaustive()
    }
}

/// Read, transform, and publish one bounded resident member.
///
/// Output work is charged before stored input is read or decoder allocation is
/// possible. The source is checked before and after the complete operation,
/// and the decoder must return exactly `output_size` bytes. The callback gets
/// the already-validated output length as `usize`; it remains responsible for
/// codec-specific integrity and scratch-space policy.
pub fn materialize_transformed_member(
    request: TransformMaterialization,
    budget: &mut WorkBudget,
    decode: impl FnOnce(Vec<u8>, usize) -> Result<Vec<u8>>,
) -> Result<MemberContentSource> {
    if request.output_size > request.max_output_size {
        return Err(Error::ResourceLimit {
            resource: "transformed member output bytes",
            requested: request.output_size,
            limit: request.max_output_size,
        });
    }
    let output_size = usize::try_from(request.output_size).map_err(|_| Error::ResourceLimit {
        resource: "transformed member output allocation",
        requested: request.output_size,
        limit: usize::MAX as u64,
    })?;
    let input_size =
        usize::try_from(request.dependency.length).map_err(|_| Error::ResourceLimit {
            resource: "transformed member input allocation",
            requested: request.dependency.length,
            limit: usize::MAX as u64,
        })?;
    if request.dependency.end()? > request.source.size() {
        return Err(Error::Malformed(
            "transformed member dependency exceeds its source".into(),
        ));
    }

    // Admit both cumulative dimensions atomically before charging either one.
    // A job which cannot read this dependency must not consume output budget,
    // and a job which cannot materialize the output must not consume reads.
    budget.check(WorkResource::MaterializedBytes, request.output_size)?;
    budget.check(WorkResource::LogicalReadBytes, request.dependency.length)?;
    budget.charge(WorkResource::MaterializedBytes, request.output_size)?;
    request.source.verify_unchanged()?;
    let mut encoded = vec![0; input_size];
    request
        .source
        .read_exact_into(request.dependency.start, &mut encoded, budget)?;
    let decoded = decode(encoded, output_size);
    // A changing external source wins even when the codec also rejects the
    // bytes: the caller must not treat an unstable snapshot as a durable
    // malformed-input conclusion.
    request.source.verify_unchanged()?;
    let decoded = decoded?;
    if decoded.len() != output_size {
        return Err(Error::Malformed(format!(
            "transform {} produced {} bytes, expected {}",
            request.recipe.recipe_identity,
            decoded.len(),
            request.output_size
        )));
    }
    let source = Arc::new(TransformedRangeSource::from_vec_with_dependency(
        decoded,
        request.source,
        request.dependency,
        request.recipe.id,
        request.coordinate_name,
        request.recipe.recipe_identity,
    ));
    Ok(MemberContentSource {
        source,
        transform: request.recipe.member_transform(),
        access: MemberAccessMode::TransformedMaterialization,
        materialized_bytes: request.output_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryRangeSource, WorkLimits};

    const RECIPE: TransformRecipe = TransformRecipe::new(
        crate::TransformKind::Codec,
        "synthetic-id-95cc5f2c5792",
        "synthetic-id-cc9000ce2b5f",
    );

    fn request() -> TransformMaterialization {
        TransformMaterialization {
            source: Arc::new(MemoryRangeSource::new(b"encoded".to_vec(), "input")),
            dependency: SourceRange::new(0, 7),
            output_size: 4,
            max_output_size: 4,
            recipe: RECIPE,
            coordinate_name: "decoded".into(),
        }
    }

    #[test]
    fn charges_before_decode_and_builds_typed_source() {
        let mut work = WorkBudget::new(
            WorkLimits::unlimited()
                .with(WorkResource::LogicalReadBytes, 7)
                .with(WorkResource::MaterializedBytes, 4),
        );
        let content = materialize_transformed_member(request(), &mut work, |encoded, want| {
            assert_eq!(encoded, b"encoded");
            assert_eq!(want, 4);
            Ok(b"plain"[..want].to_vec())
        })
        .unwrap();
        assert_eq!(content.transform, RECIPE.member_transform());
        assert_eq!(content.materialized_bytes, 4);
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 7);
    }

    #[test]
    fn denied_output_prevents_read_and_decode() {
        let mut work =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::MaterializedBytes, 3));
        let called = std::cell::Cell::new(false);
        assert!(
            materialize_transformed_member(request(), &mut work, |_, _| {
                called.set(true);
                Ok(Vec::new())
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 0);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 0);
    }

    #[test]
    fn denied_input_leaves_both_dimensions_unspent() {
        let mut work = WorkBudget::new(
            WorkLimits::unlimited()
                .with(WorkResource::LogicalReadBytes, 6)
                .with(WorkResource::MaterializedBytes, 4),
        );
        let called = std::cell::Cell::new(false);
        assert!(matches!(
            materialize_transformed_member(request(), &mut work, |_, _| {
                called.set(true);
                Ok(Vec::new())
            }),
            Err(Error::ResourceLimit {
                resource: "logical source bytes",
                requested: 7,
                limit: 6,
            })
        ));
        assert!(!called.get());
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 0);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 0);
    }

    #[test]
    fn exact_output_length_is_required_and_failed_work_stays_spent() {
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        assert!(
            materialize_transformed_member(request(), &mut work, |_, _| Ok(vec![0; 3])).is_err()
        );
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 7);
        assert_eq!(work.spent(WorkResource::MaterializedBytes), 4);
    }
}
