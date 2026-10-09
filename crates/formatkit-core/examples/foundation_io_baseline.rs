//! Synthetic foundation I/O benchmark. Run with `cargo run --release -p
//! formatkit-core --example foundation_io_baseline -- 11`. No corpus inputs are used.
//!
//! The frozen composite/strided loops preserve the allocating traversal shape
//! at the preserved baseline. They are performance controls, not production parsers.
//! Leaf request counters measure source API calls, not operating-system calls.
//! Setup is measured separately from reads. Allocation instrumentation is
//! process-global; this executable deliberately performs single-threaded work.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Instant;

use formatkit_core::{
    CompositeRangeSource, CompositeSegment, CoordinateSpaceDescription, FileRangeSource,
    MemoryRangeSource, RangeSource, ReadBudget, Result, SliceRangeSource, StridedRangeSource,
    WorkBudget, WorkLimits, WorkResource,
};

struct Allocator;
static ENABLED: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

fn allocated(size: usize) {
    if ENABLED.load(Relaxed) {
        CALLS.fetch_add(1, Relaxed);
        BYTES.fetch_add(size as u64, Relaxed);
        let live = LIVE.fetch_add(size as u64, Relaxed) + size as u64;
        PEAK.fetch_max(live, Relaxed);
    }
}

// SAFETY: all allocations are forwarded with unchanged layouts to System.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ENABLED.load(Relaxed) {
            LIVE.fetch_sub(layout.size() as u64, Relaxed);
        }
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(pointer, layout, size) };
        if !new.is_null() && ENABLED.load(Relaxed) {
            LIVE.fetch_sub(layout.size() as u64, Relaxed);
            allocated(size);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn begin() {
    CALLS.store(0, Relaxed);
    BYTES.store(0, Relaxed);
    LIVE.store(0, Relaxed);
    PEAK.store(0, Relaxed);
    ENABLED.store(true, Relaxed);
}

fn finish() -> (u64, u64, u64) {
    ENABLED.store(false, Relaxed);
    (CALLS.load(Relaxed), BYTES.load(Relaxed), PEAK.load(Relaxed))
}

#[derive(Default)]
struct Requests {
    calls: AtomicU64,
    bytes: AtomicU64,
    visits: AtomicU64,
}

struct Leaf {
    source: Arc<dyn RangeSource>,
    requests: Arc<Requests>,
}

impl RangeSource for Leaf {
    fn size(&self) -> u64 {
        self.source.size()
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        self.requests.calls.fetch_add(1, Relaxed);
        self.requests.bytes.fetch_add(length, Relaxed);
        self.source.read_at(offset, length, budget)
    }

    fn read_exact_into(
        &self,
        offset: u64,
        output: &mut [u8],
        budget: &mut WorkBudget,
    ) -> Result<()> {
        self.requests.calls.fetch_add(1, Relaxed);
        self.requests.bytes.fetch_add(output.len() as u64, Relaxed);
        self.source.read_exact_into(offset, output, budget)
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        self.source.describe_coordinate_space()
    }

    fn verify_unchanged(&self) -> Result<()> {
        self.source.verify_unchanged()
    }
}

enum Frozen {
    Composite {
        leaf: Arc<dyn RangeSource>,
        segments: usize,
        width: u64,
        requests: Arc<Requests>,
    },
    Strided {
        leaf: Arc<dyn RangeSource>,
        records: u64,
    },
}

impl RangeSource for Frozen {
    fn size(&self) -> u64 {
        match self {
            Self::Composite {
                segments, width, ..
            } => *segments as u64 * width,
            Self::Strided { records, .. } => records * 2048,
        }
    }

    fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
        assert!(offset <= self.size() && length <= self.size() - offset);
        budget.charge(length)?;
        let end = offset + length;
        match self {
            Self::Composite {
                leaf,
                segments,
                width,
                requests,
            } => {
                let mut output = vec![0; length as usize];
                let mut start = 0;
                let mut visits = 0;
                for _ in 0..*segments {
                    visits += 1;
                    let next = start + width;
                    let from = offset.max(start);
                    let to = end.min(next);
                    if from < to {
                        let bytes = leaf.read_at(from, to - from, &mut ReadBudget::unlimited())?;
                        output[(from - offset) as usize..(to - offset) as usize]
                            .copy_from_slice(&bytes);
                    }
                    start = next;
                    if start >= end {
                        break;
                    }
                }
                requests.visits.fetch_add(visits, Relaxed);
                Ok(output)
            }
            Self::Strided { leaf, .. } => {
                let mut output = Vec::with_capacity(length as usize);
                let mut logical = offset;
                while logical < end {
                    let within = logical % 2048;
                    let take = (2048 - within).min(end - logical);
                    let physical = logical / 2048 * 2352 + 24 + within;
                    output.extend_from_slice(&leaf.read_at(
                        physical,
                        take,
                        &mut ReadBudget::unlimited(),
                    )?);
                    logical += take;
                }
                Ok(output)
            }
        }
    }

    fn describe_coordinate_space(&self) -> CoordinateSpaceDescription {
        CoordinateSpaceDescription::bytes("synthetic", "frozen benchmark", self.size())
    }
}

fn measure(
    name: &str,
    route: &str,
    round: usize,
    source: &dyn RangeSource,
    requests: &Requests,
    chunk: u64,
) -> Result<u64> {
    requests.calls.store(0, Relaxed);
    requests.bytes.store(0, Relaxed);
    requests.visits.store(0, Relaxed);
    let mut budget = ReadBudget::limited(source.size());
    let mut checksum = 0u64;
    begin();
    let started = Instant::now();
    let mut offset = 0;
    while offset < source.size() {
        let length = chunk.min(source.size() - offset);
        let bytes = source.read_at(offset, length, &mut budget)?;
        checksum = checksum.wrapping_add(bytes.iter().map(|value| u64::from(*value)).sum::<u64>());
        black_box(&bytes);
        offset += length;
    }
    let elapsed = started.elapsed().as_nanos();
    let (calls, allocated, peak) = finish();
    println!("{{\"case\":\"{name}\",\"route\":\"{route}\",\"round\":{round},\"elapsed_ns\":{elapsed},\"allocation_calls\":{calls},\"allocated_bytes\":{allocated},\"peak_live_bytes\":{peak},\"logical_bytes\":{},\"leaf_requests\":{},\"leaf_requested_bytes\":{},\"frozen_segment_visits\":{},\"checksum\":{checksum}}}", budget.spent(), requests.calls.load(Relaxed), requests.bytes.load(Relaxed), requests.visits.load(Relaxed));
    Ok(checksum)
}

fn measure_into(
    name: &str,
    round: usize,
    source: &dyn RangeSource,
    requests: &Requests,
    chunk: u64,
) -> Result<u64> {
    requests.calls.store(0, Relaxed);
    requests.bytes.store(0, Relaxed);
    let mut budget = WorkBudget::new(
        WorkLimits::unlimited().with(WorkResource::LogicalReadBytes, source.size()),
    );
    let mut checksum = 0u64;
    begin();
    let started = Instant::now();
    let mut buffer = vec![0; chunk as usize];
    let mut offset = 0;
    while offset < source.size() {
        let length = chunk.min(source.size() - offset);
        let bytes = &mut buffer[..length as usize];
        source.read_exact_into(offset, bytes, &mut budget)?;
        checksum = checksum.wrapping_add(bytes.iter().map(|value| u64::from(*value)).sum::<u64>());
        black_box(&bytes);
        offset += length;
    }
    drop(buffer);
    let elapsed = started.elapsed().as_nanos();
    let (calls, allocated, peak) = finish();
    println!("{{\"case\":\"{name}\",\"route\":\"read_exact_into\",\"round\":{round},\"elapsed_ns\":{elapsed},\"allocation_calls\":{calls},\"allocated_bytes\":{allocated},\"peak_live_bytes\":{peak},\"logical_bytes\":{},\"leaf_requests\":{},\"leaf_requested_bytes\":{},\"io_accounting_complete\":{},\"io_requested_bytes\":{},\"io_read_calls\":{},\"io_completed_bytes\":{},\"checksum\":{checksum}}}", budget.spent(WorkResource::LogicalReadBytes), requests.calls.load(Relaxed), requests.bytes.load(Relaxed), budget.complete_io_accounting(), budget.spent(WorkResource::IoRequestedBytes), budget.spent(WorkResource::IoReadCalls), budget.io_completed_bytes());
    Ok(checksum)
}

fn measure_pair(
    name: &str,
    round: usize,
    source: &dyn RangeSource,
    requests: &Requests,
    chunk: u64,
) -> Result<u64> {
    let (owned, reused) = if round.is_multiple_of(2) {
        (
            measure(name, "read_at", round, source, requests, chunk)?,
            measure_into(name, round, source, requests, chunk)?,
        )
    } else {
        let reused = measure_into(name, round, source, requests, chunk)?;
        (
            measure(name, "read_at", round, source, requests, chunk)?,
            reused,
        )
    };
    assert_eq!(owned, reused, "{name} byte checksum differs");
    Ok(owned)
}

fn verify_bytes(expected: &dyn RangeSource, actual: &dyn RangeSource, chunk: u64) -> Result<()> {
    assert_eq!(expected.size(), actual.size());
    let mut old = ReadBudget::limited(expected.size());
    let mut work = WorkBudget::new(WorkLimits::unlimited());
    let mut buffer = vec![0; chunk as usize];
    let mut offset = 0;
    while offset < expected.size() {
        let length = chunk.min(expected.size() - offset);
        let bytes = expected.read_at(offset, length, &mut old)?;
        let output = &mut buffer[..length as usize];
        actual.read_exact_into(offset, output, &mut work)?;
        assert_eq!(bytes, output, "exact byte mismatch at {offset}");
        offset += length;
    }
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let rounds = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(11);
    println!("{{\"schema\":1,\"baseline_algorithm_commit\":\"2e984b6\",\"old_physical_syscalls_measured\":false,\"new_io_from_work_budget\":true,\"note\":\"single-threaded synthetic; alternating paired route order; composite setup separate; checksums include every byte\"}}");
    let payload = (0..2352 * 2048)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let requests = Arc::new(Requests::default());
    let memory: Arc<dyn RangeSource> = Arc::new(Leaf {
        source: Arc::new(MemoryRangeSource::new(payload.clone(), "synthetic")),
        requests: requests.clone(),
    });
    let mut nested = memory.clone();
    for _ in 0..12 {
        nested = Arc::new(SliceRangeSource::new(
            nested.clone(),
            0,
            nested.size(),
            "nested",
        )?);
    }
    let old_composite = Frozen::Composite {
        leaf: memory.clone(),
        segments: 8192,
        width: 128,
        requests: requests.clone(),
    };
    begin();
    let composite = CompositeRangeSource::new(
        (0..8192)
            .map(|index| CompositeSegment::mapped(memory.clone(), index * 128, 128))
            .collect::<Result<Vec<_>>>()?,
        "many-segments",
    )?;
    let (calls, bytes, peak) = finish();
    println!("{{\"case\":\"composite\",\"route\":\"construction\",\"allocation_calls\":{calls},\"allocated_bytes\":{bytes},\"peak_live_bytes\":{peak}}}");
    let old_strided = Frozen::Strided {
        leaf: memory.clone(),
        records: 2048,
    };
    let strided = StridedRangeSource::new(
        memory.clone(),
        0,
        2352,
        24,
        2048,
        2048,
        "synthetic",
        "strided",
    )?;
    let path = std::env::temp_dir().join(format!(
        "formatkit-foundation-io-{}.bin",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::io::Write::write_all(&mut file, &payload)?;
    drop(file);
    let source = Arc::new(FileRangeSource::open(&path)?);
    let file_strided = StridedRangeSource::new(
        source.clone(),
        0,
        2352,
        24,
        2048,
        2048,
        "synthetic",
        "file-strided",
    )?;
    // Exact byte comparisons happen outside timing. The cheap timed checksum
    // keeps data consumption observable without claiming cryptographic identity.
    verify_bytes(nested.as_ref(), nested.as_ref(), 65536)?;
    verify_bytes(&old_composite, &composite, 4096)?;
    verify_bytes(&old_strided, &strided, 65536)?;
    verify_bytes(source.as_ref(), source.as_ref(), 65536)?;
    verify_bytes(&file_strided, &file_strided, 65536)?;
    println!("{{\"exact_byte_parity\":true,\"timed_checksum\":\"additive-byte-sum\"}}");
    for round in 0..rounds {
        measure_pair("nested-12", round, nested.as_ref(), &requests, 65536)?;
        let expected = measure(
            "composite",
            "frozen",
            round,
            &old_composite,
            &requests,
            4096,
        )?;
        assert_eq!(
            expected,
            measure_pair("composite", round, &composite, &requests, 4096)?
        );
        let expected = measure("strided", "frozen", round, &old_strided, &requests, 65536)?;
        assert_eq!(
            expected,
            measure_pair("strided", round, &strided, &requests, 65536)?
        );
        measure_pair("file", round, source.as_ref(), &requests, 65536)?;
        measure_pair("file-strided", round, &file_strided, &requests, 65536)?;
    }
    drop(file_strided);
    drop(source);
    std::fs::remove_file(&path)?;
    Ok(())
}
