use super::*;
use crate::{WorkLimits, WorkResource};
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

fn job() -> WorkBudget {
    WorkBudget::new(WorkLimits::unlimited())
}

enum ReadStep {
    Interrupted,
    Bytes(usize),
}

struct ScriptedReader {
    bytes: &'static [u8],
    position: usize,
    steps: VecDeque<ReadStep>,
}

impl io::Read for ScriptedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self.steps.pop_front().expect("scripted read step") {
            ReadStep::Interrupted => Err(io::ErrorKind::Interrupted.into()),
            ReadStep::Bytes(limit) => {
                let length = limit
                    .min(output.len())
                    .min(self.bytes.len() - self.position);
                output[..length]
                    .copy_from_slice(&self.bytes[self.position..self.position + length]);
                self.position += length;
                Ok(length)
            }
        }
    }
}

#[test]
fn instrumented_exact_read_retries_eintr_and_short_reads_with_honest_attempt_counts() {
    let mut reader = ScriptedReader {
        bytes: b"abcde",
        position: 0,
        steps: VecDeque::from([
            ReadStep::Interrupted,
            ReadStep::Bytes(2),
            ReadStep::Bytes(1),
            ReadStep::Bytes(2),
        ]),
    };
    let mut output = [0; 5];
    let mut budget = job();
    read_exact_instrumented(&mut reader, &mut output, &mut budget).unwrap();
    assert_eq!(&output, b"abcde");
    assert_eq!(budget.spent(WorkResource::IoReadCalls), 4);
    assert_eq!(budget.spent(WorkResource::IoRequestedBytes), 15);
    assert_eq!(budget.io_completed_bytes(), 5);
}

struct TestFile {
    path: PathBuf,
}
impl TestFile {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "formatkit-work-io-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self { path }
    }
}
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
use std::time::SystemTime;

#[test]
fn all_subranges_match_old_sources_and_charge_logical_bytes_once() {
    let resident: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(
        (0..36).collect::<Vec<_>>(),
        "fixture",
    ));
    let slice: Arc<dyn RangeSource> =
        Arc::new(SliceRangeSource::new(resident.clone(), 2, 24, "slice").unwrap());
    let nested = SliceRangeSource::new(slice, 2, 18, "nested").unwrap();
    let composite = CompositeRangeSource::new(
        vec![
            CompositeSegment::zero_filled(0),
            CompositeSegment::mapped(resident.clone(), 3, 7).unwrap(),
            CompositeSegment::zero_filled(4),
            CompositeSegment::zero_filled(0),
            CompositeSegment::mapped(resident.clone(), 19, 8).unwrap(),
        ],
        "composite",
    )
    .unwrap();
    let stride =
        StridedRangeSource::new(resident.clone(), 0, 6, 1, 3, 6, "strided", "fixture").unwrap();
    let exact = RevalidatedExactSliceSource::new(resident.clone(), 2, 20, "exact").unwrap();
    for source in [resident.as_ref(), &nested, &composite, &stride, &exact] {
        for offset in 0..=source.size() + 1 {
            for length in 0..=source.size() + 1 {
                let old = source.read_at(offset, length, &mut ReadBudget::unlimited());
                let mut new = vec![0xff; length as usize];
                let mut budget = job();
                let result = source.read_exact_into(offset, &mut new, &mut budget);
                match old {
                    Ok(bytes) => {
                        result.unwrap();
                        assert_eq!(bytes, new);
                        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), length);
                        assert_eq!(budget.spent(WorkResource::IoReadCalls), 0);
                    }
                    Err(error) => {
                        assert_eq!(result.unwrap_err(), error);
                        assert!(new.iter().all(|byte| *byte == 0xff));
                        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 0);
                    }
                }
            }
        }
    }
}

#[test]
fn file_stride_reports_physical_fanout_and_stops_before_exceeding_limit() {
    let fixture = TestFile::new(b"_ab_cd_ef_gh");
    let file: Arc<dyn RangeSource> = Arc::new(FileRangeSource::open(&fixture.path).unwrap());
    let stride = StridedRangeSource::new(file, 0, 3, 1, 2, 3, "payload", "fixture").unwrap();
    let mut output = [0xff; 6];
    let mut budget = WorkBudget::new(
        WorkLimits::unlimited()
            .with(WorkResource::LogicalReadBytes, 6)
            .with(WorkResource::IoReadCalls, 2),
    );
    assert!(matches!(
        stride.read_exact_into(0, &mut output, &mut budget),
        Err(Error::ResourceLimit { .. })
    ));
    assert_eq!(&output, b"abcd\xff\xff");
    assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 6);
    assert_eq!(budget.spent(WorkResource::IoReadCalls), 2);
    assert_eq!(budget.io_completed_bytes(), 4);
    let mut budget = WorkBudget::new(
        WorkLimits::unlimited()
            .with(WorkResource::IoReadCalls, 3)
            .with(WorkResource::IoRequestedBytes, 6),
    );
    stride.read_exact_into(0, &mut output, &mut budget).unwrap();
    assert_eq!(&output, b"abcdef");
    assert_eq!(budget.spent(WorkResource::IoRequestedBytes), 6);
    assert!(budget.complete_io_accounting());
}

#[test]
fn fallback_preserves_single_logical_charge_and_reports_missing_io_accounting() {
    let source: Arc<dyn RangeSource> = Arc::new(crate::RangeSourceTestDouble::resident(
        vec![1, 2, 3],
        "fallback",
    ));
    let slice = SliceRangeSource::new(source, 0, 3, "slice").unwrap();
    let mut output = [0; 3];
    let mut budget =
        WorkBudget::new(WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, 3));
    slice.read_exact_into(0, &mut output, &mut budget).unwrap();
    assert_eq!(output, [1, 2, 3]);
    assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 3);
    assert!(!budget.complete_io_accounting());
    let mut physical = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::IoReadCalls, 5));
    assert!(matches!(
        slice.read_exact_into(0, &mut output, &mut physical),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn stale_source_and_overflow_fail_before_io() {
    let fixture = TestFile::new(b"abcd");
    let source = FileRangeSource::open(&fixture.path).unwrap();
    let mut budget = job();
    assert!(source
        .read_exact_into(u64::MAX, &mut [0; 2], &mut budget)
        .is_err());
    assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 0);
    std::fs::write(&fixture.path, b"changed-size").unwrap();
    assert!(source.read_exact_into(0, &mut [0; 1], &mut budget).is_err());
    assert_eq!(budget.spent(WorkResource::IoReadCalls), 0);
    assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 1);
}

#[test]
fn empty_mapped_segments_never_invoke_their_source() {
    let bytes: Arc<dyn RangeSource> = Arc::new(MemoryRangeSource::new(vec![1, 2], "bytes"));
    let unused = Arc::new(
        crate::RangeSourceTestDouble::resident(vec![], "empty").with_read_fault(
            crate::ReadFault::Always(crate::InjectedError::Malformed("must not read")),
        ),
    );
    let composite = CompositeRangeSource::new(
        vec![
            CompositeSegment::mapped(bytes.clone(), 0, 1).unwrap(),
            CompositeSegment::mapped(unused.clone(), 0, 0).unwrap(),
            CompositeSegment::mapped(bytes, 1, 1).unwrap(),
        ],
        "composite",
    )
    .unwrap();
    let mut budget = WorkBudget::new(WorkLimits::unlimited().with(WorkResource::IoReadCalls, 0));
    let mut output = [0; 2];
    composite
        .read_exact_into(0, &mut output, &mut budget)
        .unwrap();
    assert_eq!(output, [1, 2]);
    assert_eq!(unused.read_calls(), 0);
    assert!(budget.complete_io_accounting());
}

#[test]
fn revalidated_view_keeps_late_stability_error_precedence() {
    let source = Arc::new(
        crate::RangeSourceTestDouble::resident(vec![1, 2], "unstable")
            .with_verification_fault(2, crate::InjectedError::Malformed("changed")),
    );
    let view = RevalidatedExactSliceSource::new(source, 0, 2, "view").unwrap();
    let mut budget = job();
    let mut output = [0; 2];
    assert_eq!(
        view.read_exact_into(0, &mut output, &mut budget),
        Err(Error::Malformed("changed".into()))
    );
    assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 2);
}
