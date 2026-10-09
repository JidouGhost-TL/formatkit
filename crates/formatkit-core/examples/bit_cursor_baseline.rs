//! Alternating release benchmark for the shared LSB bit cursor and the frozen
//! pre-migration DEFLATE accumulator. No corpus inputs are used.
//!
//! Run with:
//! `cargo run --release -p formatkit-core --example bit_cursor_baseline -- 31`

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

use formatkit_core::LsbBitCursor;

struct CountingAllocator;
static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every operation delegates to the system allocator with the original
// pointer and layout. The counters are observational only.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && COUNT_ALLOCATIONS.load(Relaxed) {
            ALLOCATION_CALLS.fetch_add(1, Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && COUNT_ALLOCATIONS.load(Relaxed) {
            ALLOCATION_CALLS.fetch_add(1, Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(pointer, layout, size) };
        if !new.is_null() && COUNT_ALLOCATIONS.load(Relaxed) {
            ALLOCATION_CALLS.fetch_add(1, Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Exact pre-migration accumulator from `formatkit-codec::inflate`, retained only
/// as an independent performance oracle.
struct FrozenBits<'a> {
    src: &'a [u8],
    pos: usize,
    bit: u32,
    acc: u32,
}

impl<'a> FrozenBits<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            bit: 0,
            acc: 0,
        }
    }

    fn read(&mut self, width: u32) -> Option<u32> {
        while self.bit < width {
            let byte = *self.src.get(self.pos)?;
            self.pos += 1;
            self.acc |= u32::from(byte) << self.bit;
            self.bit += 8;
        }
        let value = self.acc & ((1u32 << width) - 1);
        self.acc >>= width;
        self.bit -= width;
        Some(value)
    }
}

const WIDTHS: [u32; 8] = [1, 3, 7, 15, 2, 8, 16, 5];

fn frozen_checksum(bytes: &[u8], cycles: usize) -> u64 {
    let mut cursor = FrozenBits::new(bytes);
    let mut checksum = 0u64;
    for _ in 0..cycles {
        for width in WIDTHS {
            checksum = checksum.rotate_left(5) ^ u64::from(cursor.read(width).unwrap());
        }
    }
    checksum
}

fn shared_checksum(bytes: &[u8], cycles: usize) -> u64 {
    let mut cursor = LsbBitCursor::new(bytes);
    let mut checksum = 0u64;
    for _ in 0..cycles {
        for width in WIDTHS {
            checksum = checksum.rotate_left(5) ^ u64::from(cursor.read(width).unwrap());
        }
    }
    checksum
}

fn measure(route: &str, round: usize, run: impl FnOnce() -> u64) -> u64 {
    ALLOCATION_CALLS.store(0, Relaxed);
    COUNT_ALLOCATIONS.store(true, Relaxed);
    let started = Instant::now();
    let checksum = black_box(run());
    let elapsed_ns = started.elapsed().as_nanos();
    COUNT_ALLOCATIONS.store(false, Relaxed);
    let allocation_calls = ALLOCATION_CALLS.load(Relaxed);
    println!(
        "{{\"kind\":\"observation\",\"route\":\"{route}\",\"round\":{round},\"elapsed_ns\":{elapsed_ns},\"allocation_calls\":{allocation_calls},\"checksum\":{checksum}}}"
    );
    checksum
}

fn main() {
    let rounds = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>().expect("rounds must be an integer"))
        .unwrap_or(31);
    assert!(rounds >= 3, "at least three rounds are required");

    let bytes: Vec<u8> = (0..1024 * 1024)
        .map(|index| ((index * 73 + index / 11 + 0x5a) & 0xff) as u8)
        .collect();
    let bits_per_cycle: usize = WIDTHS.iter().map(|width| *width as usize).sum();
    let cycles = bytes.len() * 8 / bits_per_cycle;
    let expected = frozen_checksum(&bytes, cycles);
    assert_eq!(shared_checksum(&bytes, cycles), expected);
    println!(
        "{{\"kind\":\"metadata\",\"rounds\":{rounds},\"input_bytes\":{},\"cycles_per_round\":{cycles},\"scalar_reads_per_round\":{},\"widths\":\"1,3,7,15,2,8,16,5\",\"checksum\":{expected}}}",
        bytes.len(),
        cycles * WIDTHS.len()
    );

    for round in 0..rounds {
        let (frozen, shared) = if round.is_multiple_of(2) {
            (
                measure("frozen", round, || frozen_checksum(&bytes, cycles)),
                measure("shared", round, || shared_checksum(&bytes, cycles)),
            )
        } else {
            let shared = measure("shared", round, || shared_checksum(&bytes, cycles));
            let frozen = measure("frozen", round, || frozen_checksum(&bytes, cycles));
            (frozen, shared)
        };
        assert_eq!(frozen, expected);
        assert_eq!(shared, expected);
    }
}
