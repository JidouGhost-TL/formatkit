use std::io::Write;
use std::sync::Arc;

use formatkit_archive::*;
use formatkit_catalog::Resolution as CatalogResolution;
use formatkit_core::*;

fn namespace(names: &[Option<&str>]) -> StoredRangeNamespace {
    StoredRangeNamespace::new(
        Arc::new(MemoryRangeSource::new(b"abcd".to_vec(), "synthetic source")),
        names
            .iter()
            .map(|name| NamespaceEntry {
                name: name.map(str::to_owned),
                offset: 0,
                size: 4,
            })
            .collect(),
        names.iter().map(|_| Some(vec![0xff])).collect(),
        StoredRangeNamespaceLimits {
            max_entries: 16,
            max_name_bytes: 16,
            max_total_name_bytes: 128,
        },
    )
    .unwrap()
}

#[test]
fn selection_preserves_duplicates_empty_and_raw_names() {
    let ns = namespace(&[Some("same"), None, Some(""), Some("same")]);
    assert_eq!(
        select_name(&ns, "same"),
        Err(SelectionError::AmbiguousName {
            first: 0,
            second: 3
        })
    );
    assert_eq!(select_name(&ns, ""), Ok(2));
    assert_eq!(select_name(&ns, "absent"), Err(SelectionError::NameMissing));
    assert_eq!(select_index(&ns, 3), Ok(3));
    assert_eq!(select_index(&ns, 4), Err(SelectionError::IndexOutside(4)));
    assert_eq!(MountedMembers::new(&ns).count(), 4);
    assert_eq!(
        MountedMember::mount(&ns, 1).unwrap().raw_name_bytes(),
        Some(&[0xff][..])
    );
}

struct ReverseNamespace {
    inner: StoredRangeNamespace,
}

struct AccountedSource {
    source: Arc<dyn RangeSource>,
    _resident: RetainedResidentPermit,
}

impl RangeSource for AccountedSource {
    fn size(&self) -> u64 {
        self.source.size()
    }
    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.source.describe_coordinate_space()
    }
    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        self.source.read_at(offset, length, budget)
    }
    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        self.source.read_exact_into(offset, output, budget)
    }
    fn supports_complete_io_accounting(&self) -> bool {
        self.source.supports_complete_io_accounting()
    }
    fn verify_unchanged(&self) -> Result<()> {
        self.source.verify_unchanged()
    }
}

impl IndexedNamespace for ReverseNamespace {
    fn entries(&self) -> &[NamespaceEntry] {
        self.inner.entries()
    }
    fn stored_source(&self, index: usize) -> Result<Arc<dyn RangeSource>> {
        self.inner.stored_source(index)
    }
    fn supports_work_budget_member_open(&self) -> bool {
        true
    }
    fn member_layout(&self, index: usize) -> Result<MemberLayout> {
        let mut layout = self.inner.member_layout(index)?;
        layout.transform = MemberTransform::Composite {
            id: "synthetic reverse",
        };
        layout.access = MemberAccessMode::TransformedMaterialization;
        Ok(layout)
    }
    fn validated_content_source_with_work(
        &self,
        index: usize,
        max: u64,
        work: &mut WorkBudget,
    ) -> Result<MemberContentSource> {
        let resident = work.retain_resident(4)?;
        let mut content = materialize_transformed_member(
            TransformMaterialization {
                source: self.stored_source(index)?,
                dependency: SourceRange::new(0, 4),
                output_size: 4,
                max_output_size: max,
                recipe: TransformRecipe::new(
                    TransformKind::Composite,
                    "synthetic reverse",
                    "synthetic reverse v1",
                ),
                coordinate_name: "synthetic transformed bytes".into(),
            },
            work,
            |mut bytes, _| {
                bytes.reverse();
                Ok(bytes)
            },
        )?;
        content.source = Arc::new(AccountedSource {
            source: content.source,
            _resident: resident,
        });
        Ok(content)
    }
    fn traversal_context(
        &self,
        _: Option<&NamespaceTraversalContext>,
    ) -> Option<NamespaceTraversalContext> {
        Some(Arc::new(17_u32))
    }
}

#[test]
fn stored_content_choice_and_output_admission_are_explicit() {
    let ns = ReverseNamespace {
        inner: namespace(&[Some("leaf")]),
    };
    let member = MountedMember::mount(&ns, 0).unwrap();
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut stored = Vec::new();
    let receipt = extract(
        member,
        ExtractionMode::Stored,
        &mut stored,
        &mut [0; 2],
        &mut work,
    )
    .unwrap();
    assert_eq!(receipt.bytes_written, 4);
    assert_eq!(stored, b"abcd");
    assert_eq!(work.spent(WorkResource::MaterializedBytes), 0);
    let mut content = Vec::new();
    extract(
        member,
        ExtractionMode::Content { max_output_len: 4 },
        &mut content,
        &mut [0; 3],
        &mut work,
    )
    .unwrap();
    assert_eq!(content, b"dcba");
    assert_eq!(work.spent(WorkResource::MaterializedBytes), 4);
    assert_eq!(work.spent(WorkResource::OutputBytes), 8);
    assert_eq!(work.spent(WorkResource::LogicalReadBytes), 12);
    let mut work =
        WorkBudget::new(WorkLimits::unlimited().with(WorkResource::MaterializedBytes, 3));
    assert!(extract(
        member,
        ExtractionMode::Content { max_output_len: 4 },
        &mut Vec::new(),
        &mut [0; 2],
        &mut work
    )
    .is_err());
    assert_eq!(work.spent(WorkResource::LogicalReadBytes), 0);
    let mut work = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::OutputBytes, 3));
    assert!(extract(
        member,
        ExtractionMode::Content { max_output_len: 4 },
        &mut Vec::new(),
        &mut [0; 2],
        &mut work
    )
    .is_err());
    assert_eq!(work.spent(WorkResource::LogicalReadBytes), 0);
    assert_eq!(work.spent(WorkResource::MaterializedBytes), 0);
}

#[test]
fn retained_transformed_content_holds_its_permit_on_the_original_ledger() {
    let ns = ReverseNamespace {
        inner: namespace(&[Some("leaf")]),
    };
    let mut work = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(4));
    let content = ns
        .validated_content_source_with_work(0, 4, &mut work)
        .unwrap();
    assert_eq!(work.usage().resident_bytes(), 4);
    let retained = content.clone();
    drop(content);
    assert_eq!(work.usage().resident_bytes(), 4);
    assert!(work.retain_resident(1).is_err());
    drop(retained);
    assert_eq!(work.usage().resident_bytes(), 0);
    assert_eq!(work.spent(WorkResource::MaterializedBytes), 4);
}

struct FailingSink {
    bytes: Vec<u8>,
}
impl Write for FailingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() == 3 {
            return Err(std::io::Error::other("synthetic sink failure"));
        }
        self.bytes.push(bytes[0]);
        Ok(1)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        panic!("extraction must not flush")
    }
}

#[test]
fn partial_sink_failure_keeps_exact_progress_on_the_same_ledger() {
    let ns = namespace(&[None]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut sink = FailingSink { bytes: Vec::new() };
    assert!(matches!(
        extract(
            MountedMember::mount(&ns, 0).unwrap(),
            ExtractionMode::Stored,
            &mut sink,
            &mut [0; 2],
            &mut work
        ),
        Err(SourceCopyError::Write(_))
    ));
    assert_eq!(sink.bytes, b"abc");
    assert_eq!(work.spent(WorkResource::OutputBytes), 3);
    assert_eq!(work.spent(WorkResource::LogicalReadBytes), 4);
}

struct BorrowedNamespace<'a> {
    entries: &'a [NamespaceEntry],
    source: Arc<dyn RangeSource>,
}
impl IndexedNamespace for BorrowedNamespace<'_> {
    fn entries(&self) -> &[NamespaceEntry] {
        self.entries
    }
    fn stored_source(&self, _: usize) -> Result<Arc<dyn RangeSource>> {
        Ok(self.source.clone())
    }
    fn traversal_context(
        &self,
        _: Option<&NamespaceTraversalContext>,
    ) -> Option<NamespaceTraversalContext> {
        Some(Arc::new(17_u32))
    }
}

struct ScopedResolver {
    borrowed: bool,
}
impl Resolver for ScopedResolver {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        context: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        if member.entry().name.as_deref() == Some("nested") {
            if self.borrowed {
                let mut reservation = budget.reserve_resident(96)?;
                let entries = [NamespaceEntry {
                    name: Some("leaf".into()),
                    offset: 0,
                    size: 4,
                }];
                let child = BorrowedNamespace {
                    entries: &entries,
                    source: member.stored_source()?,
                };
                reservation.with_budget(|budget| {
                    assert_eq!(budget.usage().resident_bytes(), 96);
                    visit(
                        Resolution::Mounted {
                            namespace: &child,
                            ancestor_key: Some("synthetic borrowed view"),
                        },
                        None,
                        budget,
                    )
                })
            } else {
                let permit = budget.retain_resident(96)?;
                let child: Box<dyn IndexedNamespace> = Box::new(ReverseNamespace {
                    inner: namespace(&[Some("leaf")]),
                });
                assert_eq!(budget.usage().resident_bytes(), 96);
                let result = visit(
                    Resolution::Mounted {
                        namespace: child.as_ref(),
                        ancestor_key: Some("synthetic owned view"),
                    },
                    None,
                    budget,
                );
                drop(child);
                drop(permit);
                result
            }
        } else {
            assert_eq!(
                context.and_then(|c| c.downcast_ref::<u32>()).copied(),
                Some(17)
            );
            assert_eq!(budget.usage().resident_bytes(), 96);
            if !self.borrowed {
                let content = member.namespace().validated_content_source_with_work(
                    member.index(),
                    4,
                    budget,
                )?;
                assert_eq!(content.transform.label(), "synthetic reverse");
            }
            visit(Resolution::Miss, None, budget)
        }
    }
}

#[test]
fn borrowed_and_owned_mounts_keep_residency_while_nested_work_uses_one_ledger() {
    for borrowed in [true, false] {
        let ns = namespace(&[Some("nested")]);
        let mut work = WorkBudget::new(
            WorkLimits::unlimited()
                .with_resident_bytes(100)
                .with_depth(2),
        );
        work.charge(WorkResource::OutputBytes, 7).unwrap();
        let mut namespaces = 0;
        assert_eq!(
            walk(
                &ns,
                &ScopedResolver { borrowed },
                None,
                &mut work,
                WalkOptions::default(),
                |event| {
                    if let WalkEvent::Namespace { .. } = event {
                        namespaces += 1;
                    }
                    WalkControl::Continue
                }
            )
            .unwrap(),
            WalkControl::Continue
        );
        assert_eq!(namespaces, 2);
        assert_eq!(work.spent(WorkResource::Nodes), 2);
        assert_eq!(work.spent(WorkResource::Members), 2);
        assert_eq!(work.spent(WorkResource::OutputBytes), 7);
        assert_eq!(
            work.spent(WorkResource::MaterializedBytes),
            if borrowed { 0 } else { 4 }
        );
        assert_eq!(
            work.usage().peak_resident_bytes(),
            if borrowed { 96 } else { 100 }
        );
        assert_eq!(work.usage().resident_bytes(), 0);
        assert_eq!(work.depth(), 0);
        assert_eq!(work.peak_depth(), 2);
    }
}

#[test]
fn callback_stop_releases_borrowed_child_and_does_not_resolve_its_members() {
    let ns = namespace(&[Some("nested")]);
    let mut work = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(96));
    assert_eq!(
        walk(
            &ns,
            &ScopedResolver { borrowed: true },
            None,
            &mut work,
            WalkOptions::default(),
            |event| {
                if matches!(event, WalkEvent::Namespace { depth: 2, .. }) {
                    WalkControl::Stop
                } else {
                    WalkControl::Continue
                }
            }
        )
        .unwrap(),
        WalkControl::Stop
    );
    assert_eq!(work.usage().resident_bytes(), 0);
    assert_eq!(work.depth(), 0);
    assert_eq!(work.spent(WorkResource::Members), 1);
}

#[test]
fn nested_depth_and_member_limits_do_not_reset_at_resolver_boundaries() {
    let ns = namespace(&[Some("nested")]);
    for limits in [
        WorkLimits::unlimited().with_depth(1),
        WorkLimits::unlimited().with(WorkResource::Members, 1),
    ] {
        let mut work = WorkBudget::new(limits);
        assert!(matches!(
            walk(
                &ns,
                &ScopedResolver { borrowed: true },
                None,
                &mut work,
                WalkOptions::default(),
                |_| WalkControl::Continue
            ),
            Err(Error::ResourceLimit { .. })
        ));
        assert_eq!(work.usage().resident_bytes(), 0);
        assert_eq!(work.depth(), 0);
        assert_eq!(work.spent(WorkResource::Members), 1);
    }
}

struct Outcomes;
impl Resolver for Outcomes {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        visit(
            match member.index() {
                0 => Resolution::Miss,
                1 => Resolution::Unsupported,
                2 => Resolution::RecognitionOnly,
                3 => Resolution::RequiresInputs,
                _ => Resolution::Ambiguous,
            },
            None,
            budget,
        )
    }
}

#[test]
fn ordinary_outcomes_remain_distinct_and_filtering_avoids_resolution() {
    let ns = namespace(&[None; 5]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut outcomes = [false; 5];
    walk(
        &ns,
        &Outcomes,
        None,
        &mut work,
        WalkOptions::default(),
        |event| {
            if let WalkEvent::Resolution {
                member, resolution, ..
            } = event
            {
                outcomes[member.index()] = matches!(
                    (member.index(), resolution),
                    (0, Resolution::Miss)
                        | (1, Resolution::Unsupported)
                        | (2, Resolution::RecognitionOnly)
                        | (3, Resolution::RequiresInputs)
                        | (4, Resolution::Ambiguous)
                );
            }
            WalkControl::Continue
        },
    )
    .unwrap();
    assert_eq!(outcomes, [true; 5]);
    let mut resolved = false;
    walk(
        &ns,
        &Outcomes,
        None,
        &mut work,
        WalkOptions::default(),
        |event| match event {
            WalkEvent::Member { .. } => WalkControl::Skip,
            WalkEvent::Resolution { .. } => {
                resolved = true;
                WalkControl::Continue
            }
            _ => WalkControl::Continue,
        },
    )
    .unwrap();
    assert!(!resolved);
}

struct Fails(Error);
struct Corrupt;
impl Resolver for Corrupt {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        visit(
            Resolution::InvalidContent {
                error: Error::Malformed("synthetic invalid content".into()),
            },
            None,
            budget,
        )
    }
}
impl Resolver for Fails {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        _: &mut WorkBudget,
        _: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        Err(match &self.0 {
            Error::Cancelled => Error::Cancelled,
            Error::SourceIdentityChanged { identity } => Error::SourceIdentityChanged {
                identity: identity.clone(),
            },
            Error::SourceRangeOutside {
                offset,
                length,
                source_size,
            } => Error::SourceRangeOutside {
                offset: *offset,
                length: *length,
                source_size: *source_size,
            },
            _ => Error::Malformed("synthetic child failure".into()),
        })
    }
}

#[test]
fn recovery_is_opted_in_and_never_hides_cancellation_or_source_changes() {
    let ns = namespace(&[None, None]);
    let options = WalkOptions {
        continue_on_malformed: true,
        ..WalkOptions::default()
    };
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut failures = 0;
    walk(&ns, &Corrupt, None, &mut work, options, |event| {
        if matches!(event, WalkEvent::Failure { .. }) {
            failures += 1;
        }
        WalkControl::Continue
    })
    .unwrap();
    assert_eq!(failures, 2);
    for error in [
        Error::Malformed("synthetic arbitrary failure".into()),
        Error::Cancelled,
        Error::SourceIdentityChanged {
            identity: "synthetic source".into(),
        },
        Error::SourceRangeOutside {
            offset: 4,
            length: 1,
            source_size: 4,
        },
    ] {
        assert!(walk(&ns, &Fails(error), None, &mut work, options, |_| {
            WalkControl::Continue
        })
        .is_err());
    }
    assert!(walk(
        &ns,
        &Corrupt,
        None,
        &mut work,
        WalkOptions::default(),
        |_| WalkControl::Continue
    )
    .is_err());
}

#[test]
fn cancellation_and_output_limits_stop_before_reads_or_writes() {
    let ns = namespace(&[None]);
    let member = MountedMember::mount(&ns, 0).unwrap();
    let token = CancellationToken::new();
    token.cancel();
    let mut work = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
    assert!(matches!(
        walk(
            &ns,
            &Outcomes,
            None,
            &mut work,
            WalkOptions::default(),
            |_| panic!("cancelled before events")
        ),
        Err(Error::Cancelled)
    ));
    let mut output = Vec::new();
    assert!(extract(
        member,
        ExtractionMode::Stored,
        &mut output,
        &mut [0; 2],
        &mut work
    )
    .is_err());
    assert!(output.is_empty());
    let mut work = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::OutputBytes, 3));
    assert!(extract(
        member,
        ExtractionMode::Stored,
        &mut output,
        &mut [0; 2],
        &mut work
    )
    .is_err());
    assert_eq!(work.spent(WorkResource::LogicalReadBytes), 0);
    assert!(output.is_empty());
}

struct Looping;
impl Resolver for Looping {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        visit(
            Resolution::Mounted {
                namespace: member.namespace(),
                ancestor_key: Some("synthetic validated view and operation"),
            },
            None,
            budget,
        )
    }
}

#[test]
fn authenticated_ancestor_keys_bound_cycles_without_equating_names() {
    let ns = namespace(&[None]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut cycles = 0;
    walk(
        &ns,
        &Looping,
        None,
        &mut work,
        WalkOptions::default(),
        |event| {
            if matches!(event, WalkEvent::Cycle { .. }) {
                cycles += 1;
            }
            WalkControl::Continue
        },
    )
    .unwrap();
    assert_eq!(cycles, 1);
    assert_eq!(work.spent(WorkResource::Nodes), 2);
    assert_eq!(work.peak_depth(), 2);
}

struct WrongLedger;
impl Resolver for WrongLedger {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        _: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        visit(
            Resolution::Miss,
            None,
            &mut WorkBudget::new(WorkLimits::unlimited()),
        )
    }
}

#[test]
fn unrelated_continuation_ledger_is_rejected_before_delivering_resolution() {
    let ns = namespace(&[None]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut resolutions = 0;
    assert!(walk(
        &ns,
        &WrongLedger,
        None,
        &mut work,
        WalkOptions::default(),
        |event| {
            if matches!(event, WalkEvent::Resolution { .. }) {
                resolutions += 1;
            }
            WalkControl::Continue
        }
    )
    .is_err());
    assert_eq!(resolutions, 0);
    assert_eq!(work.spent(WorkResource::Members), 1);
    assert_eq!(work.depth(), 0);
}

struct ShortSource;
impl RangeSource for ShortSource {
    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        CoordinateSpaceDescription::bytes("synthetic", "short source", self.size())
    }
    fn size(&self) -> u64 {
        4
    }
    fn read_at(&self, _: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        budget.charge(length)?;
        Ok(vec![0; length.saturating_sub(1) as usize])
    }
}

struct ChangingSource {
    reads: std::sync::atomic::AtomicBool,
}
impl RangeSource for ChangingSource {
    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        CoordinateSpaceDescription::bytes("synthetic", "changing source", self.size())
    }
    fn size(&self) -> u64 {
        4
    }
    fn read_at(&self, _: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        budget.charge(length)?;
        self.reads.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(vec![0; length as usize])
    }
    fn verify_unchanged(&self) -> Result<()> {
        if self.reads.load(std::sync::atomic::Ordering::Relaxed) {
            Err(Error::SourceIdentityChanged {
                identity: "synthetic changing source".into(),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn short_reads_and_changed_sources_keep_typed_errors_and_admitted_work() {
    let entries = [NamespaceEntry {
        name: None,
        offset: 0,
        size: 4,
    }];
    for (source, changes) in [
        (Arc::new(ShortSource) as Arc<dyn RangeSource>, false),
        (
            Arc::new(ChangingSource {
                reads: false.into(),
            }) as Arc<dyn RangeSource>,
            true,
        ),
    ] {
        let ns = BorrowedNamespace {
            entries: &entries,
            source,
        };
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let mut output = Vec::new();
        let error = extract(
            MountedMember::mount(&ns, 0).unwrap(),
            ExtractionMode::Stored,
            &mut output,
            &mut [0; 4],
            &mut work,
        )
        .unwrap_err();
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 4);
        if changes {
            assert!(matches!(
                error,
                SourceCopyError::Source(Error::SourceIdentityChanged { .. })
            ));
            assert_eq!(output.len(), 4);
            assert_eq!(work.spent(WorkResource::OutputBytes), 4);
        } else {
            assert!(matches!(error, SourceCopyError::Source(_)));
            assert!(output.is_empty());
            assert_eq!(work.spent(WorkResource::OutputBytes), 0);
        }
    }
}

#[test]
fn explicit_walk_depth_limit_is_reported_and_releases_residency() {
    let ns = namespace(&[Some("nested")]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut limits = 0;
    assert!(matches!(
        walk(
            &ns,
            &ScopedResolver { borrowed: true },
            None,
            &mut work,
            WalkOptions {
                max_depth: 1,
                ..WalkOptions::default()
            },
            |event| {
                if matches!(event, WalkEvent::Limit { .. }) {
                    limits += 1;
                }
                WalkControl::Continue
            }
        ),
        Err(Error::ResourceLimit { .. })
    ));
    assert_eq!(limits, 1);
    assert_eq!(work.usage().resident_bytes(), 0);
    assert_eq!(work.depth(), 0);
}

fn synthetic_descriptor(id: formatkit_catalog::FormatId) -> formatkit_catalog::FormatDescriptor {
    use formatkit_catalog::*;
    FormatDescriptor {
        id,
        category: Category::Data,
        decoder: None,
        precedence: 1,
        probes: &[Probe::Structural {
            name: "synthetic supplied classification",
            check: |_| true,
        }],
        extension_hints: &[],
        requirement: DecoderRequirement::PairedData,
        ambiguity_group: Some("synthetic-ambiguity"),
        capabilities: FormatCapabilities {
            parse: false,
            decode: false,
            edit: false,
            write: false,
            round_trip: false,
            corpus: false,
            bindings: false,
            confidence: Confidence::Structural,
        },
    }
}

struct MetadataResolver<'a> {
    selected: CatalogResolution<'a>,
    ambiguous: CatalogResolution<'a>,
    child: StoredRangeNamespace,
}
impl Resolver for MetadataResolver<'_> {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        match member.index() {
            0 => visit(Resolution::RecognitionOnly, Some(&self.selected), budget),
            1 => visit(Resolution::RequiresInputs, Some(&self.selected), budget),
            2 => visit(Resolution::Ambiguous, Some(&self.ambiguous), budget),
            _ => visit(
                Resolution::Mounted {
                    namespace: &self.child,
                    ancestor_key: None,
                },
                Some(&self.selected),
                budget,
            ),
        }
    }
}

#[test]
fn canonical_identification_is_delivered_losslessly_for_all_resolution_modes() {
    use formatkit_catalog::{DetectionContext, Evidence, FormatCatalog, FormatId};
    let left = FormatId::new("synthetic-left");
    let right = FormatId::new("synthetic-right");
    let single = FormatCatalog::new([synthetic_descriptor(left)]).unwrap();
    let both =
        FormatCatalog::new([synthetic_descriptor(left), synthetic_descriptor(right)]).unwrap();
    let resolver = MetadataResolver {
        selected: single.resolve(DetectionContext::from_bytes(&[])),
        ambiguous: both.resolve(DetectionContext::from_bytes(&[])),
        child: namespace(&[]),
    };
    let ns = namespace(&[None; 4]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut identifications = 0;
    let mut outcomes = 0;
    walk(
        &ns,
        &resolver,
        None,
        &mut work,
        WalkOptions::default(),
        |event| {
            let metadata = match event {
                WalkEvent::Identification {
                    member,
                    identification,
                    ..
                } => {
                    identifications += 1;
                    Some((member.index(), identification))
                }
                WalkEvent::Resolution {
                    member,
                    identification: Some(identification),
                    ..
                } => {
                    outcomes += 1;
                    Some((member.index(), identification))
                }
                _ => None,
            };
            if let Some((index, identification)) = metadata {
                if index == 2 {
                    assert!(std::ptr::eq(identification, &resolver.ambiguous));
                    assert!(identification.is_ambiguous());
                    assert_eq!(
                        identification
                            .contenders
                            .iter()
                            .map(|c| c.descriptor.id)
                            .collect::<Vec<_>>(),
                        [left, right]
                    );
                } else {
                    assert!(std::ptr::eq(identification, &resolver.selected));
                    let selected = identification.selected.unwrap();
                    assert_eq!(selected.descriptor.id, left);
                    assert!(!selected.decoder_ready());
                    assert_eq!(
                        selected.evidence,
                        Evidence::Structural {
                            name: "synthetic supplied classification"
                        }
                    );
                    assert_eq!(identification.contenders.len(), 1);
                }
            }
            WalkControl::Continue
        },
    )
    .unwrap();
    assert_eq!(identifications, 4);
    assert_eq!(outcomes, 4);
}

struct ReplacesContinuationError {
    replace: bool,
    cancellation: Option<CancellationToken>,
}
impl Resolver for ReplacesContinuationError {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        if let Some(token) = &self.cancellation {
            token.cancel();
        }
        let _swallowed = visit(
            Resolution::Mounted {
                namespace: member.namespace(),
                ancestor_key: None,
            },
            None,
            budget,
        );
        if self.replace {
            Err(Error::Malformed("synthetic replacement error".into()))
        } else {
            Ok(WalkControl::Continue)
        }
    }
}

#[test]
fn original_budget_and_cancellation_causes_survive_swallowed_or_replaced_errors() {
    let ns = namespace(&[None]);
    for replace in [false, true] {
        for cancelled in [false, true] {
            let token = CancellationToken::new();
            let mut work = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::Nodes, 1))
                .with_cancellation(token.clone());
            let resolver = ReplacesContinuationError {
                replace,
                cancellation: cancelled.then_some(token),
            };
            let error = walk(
                &ns,
                &resolver,
                None,
                &mut work,
                WalkOptions {
                    continue_on_malformed: true,
                    ..WalkOptions::default()
                },
                |_| WalkControl::Continue,
            )
            .unwrap_err();
            if cancelled {
                assert_eq!(error, Error::Cancelled);
            } else {
                assert!(matches!(
                    error,
                    Error::ResourceLimit {
                        resource: "nodes",
                        ..
                    }
                ));
            }
            assert_eq!(work.depth(), 0);
        }
    }
}

struct DeletedFileResolver {
    source: FileRangeSource,
}
impl Resolver for DeletedFileResolver {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        self.source.verify_unchanged()?;
        visit(Resolution::Miss, None, budget)
    }
}

#[test]
fn deleted_file_verification_is_terminal_even_with_content_recovery_enabled() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-input");
    std::fs::write(&path, b"abcd").unwrap();
    let resolver = DeletedFileResolver {
        source: FileRangeSource::open(&path).unwrap(),
    };
    std::fs::remove_file(&path).unwrap();
    let ns = namespace(&[None, None]);
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut failures = 0;
    let error = walk(
        &ns,
        &resolver,
        None,
        &mut work,
        WalkOptions {
            continue_on_malformed: true,
            ..WalkOptions::default()
        },
        |event| {
            if matches!(event, WalkEvent::Failure { .. }) {
                failures += 1;
            }
            assert!(!matches!(event, WalkEvent::Resolution { .. }));
            WalkControl::Continue
        },
    )
    .unwrap_err();
    // File reopening I/O failures currently use the canonical Malformed leaf.
    // Recovery must never infer content corruption from that variant alone.
    assert!(matches!(error, Error::Malformed(_)));
    assert_eq!(failures, 1);
    assert_eq!(work.spent(WorkResource::Members), 1);
    assert_eq!(work.depth(), 0);
}

struct CallbackProtocol {
    twice: bool,
}
impl Resolver for CallbackProtocol {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        if self.twice {
            let _first = visit(Resolution::Miss, None, budget);
            let _second = visit(Resolution::Miss, None, budget);
        }
        Ok(WalkControl::Continue)
    }
}

#[test]
fn missing_or_duplicate_continuation_delivery_is_terminal() {
    let ns = namespace(&[None]);
    for twice in [false, true] {
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let mut resolutions = 0;
        assert!(walk(
            &ns,
            &CallbackProtocol { twice },
            None,
            &mut work,
            WalkOptions {
                continue_on_malformed: true,
                ..WalkOptions::default()
            },
            |event| {
                if matches!(event, WalkEvent::Resolution { .. }) {
                    resolutions += 1;
                }
                WalkControl::Continue
            }
        )
        .is_err());
        assert_eq!(resolutions, usize::from(twice));
        assert_eq!(work.depth(), 0);
    }
}

struct ContextResolver;
impl Resolver for ContextResolver {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        context: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        let outcome = if context.and_then(|c| c.downcast_ref::<u32>()).copied() == Some(17) {
            Resolution::Miss
        } else {
            Resolution::RequiresInputs
        };
        visit(outcome, None, budget)
    }
}

#[test]
fn missing_owner_context_stays_requires_inputs_without_source_reads() {
    let ns = namespace(&[None]);
    let context: NamespaceTraversalContext = Arc::new(17_u32);
    for supplied in [None, Some(&context)] {
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let mut received = false;
        walk(
            &ns,
            &ContextResolver,
            supplied,
            &mut work,
            WalkOptions::default(),
            |event| {
                if let WalkEvent::Resolution { resolution, .. } = event {
                    received = if supplied.is_none() {
                        matches!(resolution, Resolution::RequiresInputs)
                    } else {
                        matches!(resolution, Resolution::Miss)
                    };
                }
                WalkControl::Continue
            },
        )
        .unwrap();
        assert!(received);
        assert_eq!(work.spent(WorkResource::LogicalReadBytes), 0);
    }
}

struct DistinctViews {
    children: [StoredRangeNamespace; 2],
}
impl Resolver for DistinctViews {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        if member.namespace().len() == 2 {
            visit(
                Resolution::Mounted {
                    namespace: &self.children[member.index()],
                    ancestor_key: Some(if member.index() == 0 {
                        "synthetic logical left"
                    } else {
                        "synthetic logical right"
                    }),
                },
                None,
                budget,
            )
        } else {
            visit(Resolution::Miss, None, budget)
        }
    }
}

#[test]
fn identical_names_and_offsets_do_not_collapse_distinct_logical_views() {
    let ns = namespace(&[Some("same"), Some("same")]);
    let resolver = DistinctViews {
        children: [namespace(&[Some("same")]), namespace(&[Some("same")])],
    };
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut cycles = 0;
    walk(
        &ns,
        &resolver,
        None,
        &mut work,
        WalkOptions::default(),
        |event| {
            if matches!(event, WalkEvent::Cycle { .. }) {
                cycles += 1;
            }
            WalkControl::Continue
        },
    )
    .unwrap();
    assert_eq!(cycles, 0);
    assert_eq!(work.spent(WorkResource::Nodes), 3);
    assert_eq!(work.spent(WorkResource::Members), 4);
}

struct NestedViews {
    child: StoredRangeNamespace,
    grandchild: StoredRangeNamespace,
    same_key: bool,
}
impl Resolver for NestedViews {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        let is_child = std::ptr::eq(member.namespace(), &self.child as &dyn IndexedNamespace);
        let namespace = if is_child {
            &self.grandchild
        } else {
            &self.child
        };
        let key = if is_child && !self.same_key {
            "synthetic nested view right"
        } else {
            "synthetic nested view left"
        };
        visit(
            Resolution::Mounted {
                namespace,
                ancestor_key: Some(key),
            },
            None,
            budget,
        )
    }
}

#[test]
fn nested_identical_names_only_cycle_when_authenticated_view_keys_match() {
    let ns = namespace(&[Some("same")]);
    for same_key in [false, true] {
        let resolver = NestedViews {
            child: namespace(&[Some("same")]),
            grandchild: namespace(&[]),
            same_key,
        };
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let mut cycles = 0;
        walk(
            &ns,
            &resolver,
            None,
            &mut work,
            WalkOptions::default(),
            |event| {
                if matches!(event, WalkEvent::Cycle { .. }) {
                    cycles += 1;
                }
                WalkControl::Continue
            },
        )
        .unwrap();
        assert_eq!(cycles, usize::from(same_key));
        assert_eq!(
            work.spent(WorkResource::Nodes),
            if same_key { 2 } else { 3 }
        );
        assert_eq!(work.spent(WorkResource::Members), 2);
    }
}

struct MisclassifiedFailure {
    kind: usize,
    wrapped: bool,
}
impl MisclassifiedFailure {
    fn error(&self) -> Error {
        let error = match self.kind {
            0 => Error::Cancelled,
            1 => Error::ResourceLimit {
                resource: "synthetic resource",
                requested: 2,
                limit: 1,
            },
            2 => Error::SourceIdentityChanged {
                identity: "synthetic source".into(),
            },
            3 => Error::SourceRangeOutside {
                offset: 4,
                length: 1,
                source_size: 4,
            },
            4 => Error::Unsupported("synthetic unsupported operation".into()),
            _ => Error::UnsupportedDialect {
                family: "synthetic family",
                dialect: "synthetic dialect",
            },
        };
        if self.wrapped {
            error.context(ErrorContext::Component("synthetic failure"))
        } else {
            error
        }
    }
}
impl Resolver for MisclassifiedFailure {
    fn resolve(
        &self,
        _: MountedMember<'_>,
        _: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl> {
        visit(
            Resolution::InvalidContent {
                error: self.error(),
            },
            None,
            budget,
        )
    }
}

#[test]
fn typed_resource_and_source_failures_cannot_be_hidden_in_recoverable_outcomes() {
    let ns = namespace(&[None, None]);
    for (kind, wrapped, control) in (0..6).flat_map(|kind| {
        [false, true].into_iter().flat_map(move |wrapped| {
            [WalkControl::Continue, WalkControl::Skip, WalkControl::Stop]
                .into_iter()
                .map(move |control| (kind, wrapped, control))
        })
    }) {
        let resolver = MisclassifiedFailure { kind, wrapped };
        let mut work = WorkBudget::new(WorkLimits::unlimited());
        let error = walk(
            &ns,
            &resolver,
            None,
            &mut work,
            WalkOptions {
                continue_on_malformed: true,
                ..WalkOptions::default()
            },
            |event| {
                if matches!(
                    event,
                    WalkEvent::Resolution { .. }
                        | WalkEvent::Failure { .. }
                        | WalkEvent::Limit { .. }
                ) {
                    control
                } else {
                    WalkControl::Continue
                }
            },
        )
        .unwrap_err();
        assert_eq!(error, resolver.error());
        assert_eq!(work.spent(WorkResource::Members), 1);
        assert_eq!(work.depth(), 0);
    }
}
