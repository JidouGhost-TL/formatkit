//! Reusable evidence helpers for source-native namespace contract tests.
//!
//! Format tests still own their independent layout oracle and malformed corpus:
//! those encode the actual grammar. This module centralizes the mechanical
//! proof that a single-source mount consumes its declared metadata budget,
//! exposes stored members as shared ranges, and rejects a source whose identity
//! changes while the mount is being constructed.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use formatkit_core::{
    Error, IndexedNamespace, MemoryRangeSource, NamespaceEntry, RangeSource, ReadBudget, Result,
    SharedBytes, SourceRange,
};

/// The common callable shape of a single-source namespace mount.
pub type SingleSourceMount =
    fn(Arc<dyn RangeSource>, &mut ReadBudget) -> Result<Box<dyn IndexedNamespace>>;

struct RecordingSource {
    inner: MemoryRangeSource,
    reads: Mutex<Vec<SourceRange>>,
    verifications: AtomicUsize,
}

impl RangeSource for RecordingSource {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        self.reads
            .lock()
            .expect("recording-source read log is not poisoned")
            .push(SourceRange::new(offset, length));
        self.inner.read_at(offset, length, budget)
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        self.reads
            .lock()
            .expect("recording-source read log is not poisoned")
            .push(SourceRange::new(offset, length));
        self.inner.read_shared_at(offset, length, budget)
    }

    fn describe_coordinate_space(&self) -> formatkit_core::CoordinateSpaceDescription {
        self.inner.describe_coordinate_space()
    }

    fn coordinate_mappings(&self) -> Vec<formatkit_core::CoordinateMappingDescription> {
        self.inner.coordinate_mappings()
    }

    fn verify_unchanged(&self) -> Result<()> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        self.inner.verify_unchanged()
    }
}

/// Mount one resident fixture through exactly the expected metadata ranges and
/// source-identity checks. A budget one byte smaller must fail before the
/// provider can silently read more.
pub fn mount_with_expected_reads(
    mount: SingleSourceMount,
    bytes: Arc<[u8]>,
    expected_reads: &[SourceRange],
    expected_verifications: usize,
    name: &str,
) -> Box<dyn IndexedNamespace> {
    let metadata_bytes = expected_reads.iter().fold(0u64, |total, range| {
        total
            .checked_add(range.length)
            .expect("expected metadata byte count fits u64")
    });
    let recorded = Arc::new(RecordingSource {
        inner: MemoryRangeSource::from_arc(bytes.clone(), format!("{name} recorded fixture")),
        reads: Mutex::new(Vec::new()),
        verifications: AtomicUsize::new(0),
    });
    let source: Arc<dyn RangeSource> = recorded.clone();
    let mut exact = ReadBudget::limited(metadata_bytes);
    let namespace = mount(source, &mut exact)
        .unwrap_or_else(|error| panic!("{name} exact-budget mount failed: {error}"));
    assert_eq!(
        exact.spent(),
        metadata_bytes,
        "{name} mount did not consume its declared metadata bytes"
    );
    assert_eq!(
        *recorded
            .reads
            .lock()
            .expect("recording-source read log is not poisoned"),
        expected_reads,
        "{name} mount read outside its declared metadata ranges"
    );
    assert_eq!(
        recorded.verifications.load(Ordering::SeqCst),
        expected_verifications,
        "{name} mount performed an unexpected number of identity checks"
    );

    if metadata_bytes != 0 {
        let source: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::from_arc(
            bytes,
            format!("{name} one-short fixture"),
        ));
        let error = mount(source, &mut ReadBudget::limited(metadata_bytes - 1))
            .err()
            .unwrap_or_else(|| panic!("{name} mounted with a one-short metadata budget"));
        assert!(
            matches!(error.leaf(), Error::ResourceLimit { .. }),
            "{name} one-short budget returned {error:?}"
        );
    }
    namespace
}

/// Compare the mounted directory with independently expected entries and read
/// every stored child through its own bounded shared-range source.
pub fn assert_stored_ranges(
    namespace: &dyn IndexedNamespace,
    expected_entries: &[NamespaceEntry],
    expected_raw_names: &[Option<&[u8]>],
    carrier: &Arc<[u8]>,
) {
    assert_eq!(namespace.entries(), expected_entries);
    assert_eq!(expected_raw_names.len(), expected_entries.len());
    let root_source = MemoryRangeSource::from_arc(carrier.clone(), "contract root allocation");
    let root = root_source
        .read_shared_at(0, root_source.size(), &mut ReadBudget::unlimited())
        .expect("resident fixture root is readable");

    for (index, entry) in expected_entries.iter().enumerate() {
        assert_eq!(namespace.raw_name_bytes(index), expected_raw_names[index]);
        let layout = namespace
            .member_layout(index)
            .unwrap_or_else(|error| panic!("member {index} layout failed: {error}"));
        assert_eq!(layout.stored_size, entry.size, "member {index}");
        assert_eq!(layout.content_size, Some(entry.size), "member {index}");
        assert_eq!(
            layout.transform,
            formatkit_core::MemberTransform::Stored,
            "member {index}"
        );
        assert_eq!(
            layout.access,
            formatkit_core::MemberAccessMode::SharedRange,
            "member {index}"
        );

        let child = namespace
            .stored_source(index)
            .unwrap_or_else(|error| panic!("member {index} source failed: {error}"));
        assert_eq!(child.size(), entry.size, "member {index}");
        let mut budget = ReadBudget::limited(entry.size);
        let body = child
            .read_shared_at(0, child.size(), &mut budget)
            .unwrap_or_else(|error| panic!("member {index} read failed: {error}"));
        assert_eq!(budget.spent(), entry.size, "member {index}");
        assert!(
            root.shares_storage_with(&body),
            "member {index} does not share the carrier allocation"
        );
        let start = usize::try_from(entry.offset).expect("fixture offset fits usize");
        let size = usize::try_from(entry.size).expect("fixture size fits usize");
        let end = start
            .checked_add(size)
            .expect("fixture range does not overflow");
        assert_eq!(body.as_ref(), &carrier[start..end], "member {index}");

        for validated in [false, true] {
            let mut open_budget = ReadBudget::limited(0);
            let content = if validated {
                namespace.validated_content_source(index, entry.size, &mut open_budget)
            } else {
                namespace.content_source(index, entry.size, &mut open_budget)
            }
            .unwrap_or_else(|error| panic!("member {index} content source failed: {error}"));
            assert_eq!(open_budget.spent(), 0, "member {index}");
            assert_eq!(content.transform, formatkit_core::MemberTransform::Stored);
            assert_eq!(
                content.access,
                formatkit_core::MemberAccessMode::SharedRange
            );
            assert_eq!(content.materialized_bytes, 0);
            assert_eq!(content.source.size(), entry.size);
            let mut content_budget = ReadBudget::limited(entry.size);
            let content_bytes = content
                .source
                .read_shared_at(0, entry.size, &mut content_budget)
                .unwrap_or_else(|error| panic!("member {index} content read failed: {error}"));
            assert_eq!(content_budget.spent(), entry.size, "member {index}");
            assert!(
                root.shares_storage_with(&content_bytes),
                "member {index} content does not share the carrier allocation"
            );
            assert_eq!(
                content_bytes.as_ref(),
                &carrier[start..end],
                "member {index}"
            );
        }
    }
}

/// Expected storage and usable content for one member in a namespace that
/// selectively transforms only some children.
pub struct ExpectedSelectiveMember<'a> {
    pub entry: NamespaceEntry,
    pub raw_name: Option<&'a [u8]>,
    pub content: &'a [u8],
    pub transform: formatkit_core::MemberTransform,
    /// Stable transform recipe recorded in coarse provenance mappings, or
    /// `None` for a stored member.
    pub recipe_identity: Option<&'a str>,
    /// Source bytes consumed while opening usable content. Stored members use
    /// zero because their shared child source is lazy.
    pub open_read_bytes: u64,
}

/// Prove mixed stored/transformed member behavior without encoding a container
/// grammar. Format tests remain responsible for deriving entries, stored
/// ranges, transform identities, and read budgets independently.
pub fn assert_selective_transforms(
    namespace: &dyn IndexedNamespace,
    expected: &[ExpectedSelectiveMember<'_>],
    carrier: &Arc<[u8]>,
) {
    assert_eq!(namespace.entries().len(), expected.len());
    let root_source = MemoryRangeSource::from_arc(carrier.clone(), "selective contract root");
    let root = root_source
        .read_shared_at(0, root_source.size(), &mut ReadBudget::unlimited())
        .expect("resident selective fixture root is readable");

    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(
            &namespace.entries()[index],
            &expected.entry,
            "member {index}"
        );
        assert_eq!(
            namespace.raw_name_bytes(index),
            expected.raw_name,
            "member {index}"
        );
        let layout = namespace
            .member_layout(index)
            .unwrap_or_else(|error| panic!("member {index} layout failed: {error}"));
        assert_eq!(layout.stored_size, expected.entry.size, "member {index}");
        assert_eq!(layout.transform, expected.transform, "member {index}");

        let stored = namespace
            .stored_source(index)
            .unwrap_or_else(|error| panic!("member {index} stored source failed: {error}"));
        let mut stored_budget = ReadBudget::limited(expected.entry.size);
        let stored_bytes = stored
            .read_shared_at(0, stored.size(), &mut stored_budget)
            .unwrap_or_else(|error| panic!("member {index} stored read failed: {error}"));
        assert_eq!(stored_budget.spent(), expected.entry.size, "member {index}");
        assert!(
            root.shares_storage_with(&stored_bytes),
            "member {index} stored source does not share the carrier allocation"
        );
        let start = usize::try_from(expected.entry.offset).expect("fixture offset fits usize");
        let size = usize::try_from(expected.entry.size).expect("fixture size fits usize");
        let end = start
            .checked_add(size)
            .expect("fixture range does not overflow");
        assert_eq!(
            stored_bytes.as_ref(),
            &carrier[start..end],
            "member {index}"
        );

        let mut open_budget = ReadBudget::limited(expected.open_read_bytes);
        let content = namespace
            .validated_content_source(index, expected.content.len() as u64, &mut open_budget)
            .unwrap_or_else(|error| panic!("member {index} content open failed: {error}"));
        assert_eq!(
            open_budget.spent(),
            expected.open_read_bytes,
            "member {index}"
        );
        assert_eq!(content.transform, expected.transform, "member {index}");
        if matches!(expected.transform, formatkit_core::MemberTransform::Stored) {
            assert_eq!(expected.recipe_identity, None, "member {index}");
            assert_eq!(
                layout.content_size,
                Some(expected.entry.size),
                "member {index}"
            );
            assert_eq!(layout.access, formatkit_core::MemberAccessMode::SharedRange);
            assert_eq!(
                content.access,
                formatkit_core::MemberAccessMode::SharedRange
            );
            assert_eq!(content.materialized_bytes, 0);
        } else {
            let recipe = expected
                .recipe_identity
                .unwrap_or_else(|| panic!("member {index} transformed without a recipe"));
            assert_eq!(
                layout.access,
                formatkit_core::MemberAccessMode::TransformedMaterialization
            );
            assert_eq!(
                content.access,
                formatkit_core::MemberAccessMode::TransformedMaterialization
            );
            assert_eq!(content.materialized_bytes, expected.content.len() as u64);
            assert!(
                content.source.coordinate_mappings().iter().any(|mapping| {
                    mapping.precision == formatkit_core::MappingPrecision::CoarseDependency
                        && mapping.recipe_identity.as_deref() == Some(recipe)
                        && mapping.to
                            == SourceRange::new(expected.entry.offset, expected.entry.size)
                }),
                "member {index} transformed provenance does not retain its stored dependency"
            );
        }
        let mut content_budget = ReadBudget::limited(expected.content.len() as u64);
        let content_bytes = content
            .source
            .read_shared_at(0, content.source.size(), &mut content_budget)
            .unwrap_or_else(|error| panic!("member {index} content read failed: {error}"));
        assert_eq!(
            content_budget.spent(),
            expected.content.len() as u64,
            "member {index}"
        );
        assert_eq!(
            root.shares_storage_with(&content_bytes),
            matches!(expected.transform, formatkit_core::MemberTransform::Stored),
            "member {index} content storage mode"
        );
        assert_eq!(content_bytes.as_ref(), expected.content, "member {index}");
    }
}

/// A resident range source which succeeds for a fixed number of identity
/// checks and then reports a typed source-change error.
struct ChangesAfterVerifications {
    inner: MemoryRangeSource,
    name: String,
    verifications: AtomicUsize,
    successful_verifications: usize,
}

impl RangeSource for ChangesAfterVerifications {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        self.inner.read_at(offset, length, budget)
    }

    fn read_shared_at(
        &self,
        offset: u64,
        length: u64,
        budget: &mut ReadBudget,
    ) -> Result<SharedBytes> {
        self.inner.read_shared_at(offset, length, budget)
    }

    fn describe_coordinate_space(&self) -> formatkit_core::CoordinateSpaceDescription {
        self.inner.describe_coordinate_space()
    }

    fn verify_unchanged(&self) -> Result<()> {
        if self.verifications.fetch_add(1, Ordering::SeqCst) < self.successful_verifications {
            Ok(())
        } else {
            Err(Error::Malformed(format!(
                "test source {} changed during mount",
                self.name
            )))
        }
    }
}

/// Construct a source used to prove both pre-read and post-read stability
/// checks. `successful_verifications = 1` changes after the mount's first
/// identity check.
pub fn changes_after_mount(bytes: Vec<u8>, name: impl Into<String>) -> Arc<dyn RangeSource> {
    changes_after_verifications(bytes, name, 1)
}

/// Construct a source that changes after an explicit number of successful
/// identity checks.
pub fn changes_after_verifications(
    bytes: Vec<u8>,
    name: impl Into<String>,
    successful_verifications: usize,
) -> Arc<dyn RangeSource> {
    let name = name.into();
    Arc::new(ChangesAfterVerifications {
        inner: MemoryRangeSource::new(bytes, name.clone()),
        name,
        verifications: AtomicUsize::new(0),
        successful_verifications,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_mount(
        source: Arc<dyn RangeSource>,
        budget: &mut ReadBudget,
    ) -> Result<Box<dyn IndexedNamespace>> {
        source.verify_unchanged()?;
        source.read_at(0, 2, budget)?;
        Ok(Box::new(
            formatkit_core::StoredRangeNamespace::without_raw_names(
                source,
                vec![NamespaceEntry {
                    name: Some("body".into()),
                    offset: 2,
                    size: 2,
                }],
                formatkit_core::StoredRangeNamespaceLimits {
                    max_entries: 1,
                    max_name_bytes: 4,
                    max_total_name_bytes: 4,
                },
            )?,
        ))
    }

    #[test]
    fn exact_budget_and_stored_range_helpers_cover_the_common_contract() {
        let bytes: Arc<[u8]> = Arc::from(&b"HHOK"[..]);
        let mounted = mount_with_expected_reads(
            stored_mount,
            bytes.clone(),
            &[SourceRange::new(0, 2)],
            2,
            "helper",
        );
        let entries = [NamespaceEntry {
            name: Some("body".into()),
            offset: 2,
            size: 2,
        }];
        assert_stored_ranges(mounted.as_ref(), &entries, &[None], &bytes);
    }

    #[test]
    fn changing_source_fails_the_post_read_identity_check() {
        let source = changes_after_mount(b"HHOK".to_vec(), "unstable");
        let error = stored_mount(source, &mut ReadBudget::limited(2))
            .err()
            .expect("unstable source must fail");
        assert_eq!(
            error,
            Error::Malformed("test source unstable changed during mount".into())
        );
    }
}
