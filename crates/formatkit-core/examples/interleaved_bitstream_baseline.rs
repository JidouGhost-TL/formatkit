//! Alternating release benchmark for the shared MSB interleaved bit/raw-byte
//! stream and frozen pre-migration reader/writer mechanics. No corpus is used.
//!
//! Run with:
//! `cargo run --release -p formatkit-core --example interleaved_bitstream_baseline -- 11`

use formatkit_core::{MsbInterleavedBitReader, MsbInterleavedBitWriter};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

struct CountingAllocator;
static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every operation delegates to the system allocator with the original
// pointer and layout. The counter is observational only.
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
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        if !pointer.is_null() && COUNT_ALLOCATIONS.load(Relaxed) {
            ALLOCATION_CALLS.fetch_add(1, Relaxed);
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct FrozenReader<'a> {
    bytes: &'a [u8],
    position: usize,
    control: u8,
    mask: u8,
}

impl<'a> FrozenReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            control: 0,
            mask: 0,
        }
    }

    fn bit(&mut self) -> bool {
        if self.mask == 0 {
            self.control = self.bytes[self.position];
            self.position += 1;
            self.mask = 0x80;
        }
        let bit = self.control & self.mask != 0;
        self.mask >>= 1;
        bit
    }

    fn byte(&mut self) -> u8 {
        let byte = self.bytes[self.position];
        self.position += 1;
        byte
    }
}

struct FrozenWriter {
    bytes: Vec<u8>,
    control_position: usize,
    mask: u8,
}

impl FrozenWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            control_position: 0,
            mask: 0,
        }
    }

    fn bit(&mut self, bit: bool) {
        if self.mask == 0 {
            self.control_position = self.bytes.len();
            self.bytes.push(0);
            self.mask = 0x80;
        }
        if bit {
            self.bytes[self.control_position] |= self.mask;
        }
        self.mask >>= 1;
    }

    fn byte(&mut self, byte: u8) {
        self.bytes.push(byte);
    }
}

fn frozen_read(bytes: &[u8], groups: usize) -> u64 {
    let mut reader = FrozenReader::new(bytes);
    let mut checksum = 0u64;
    for _ in 0..groups {
        for index in 0..8usize {
            checksum = checksum.rotate_left(3) ^ u64::from(reader.bit());
            if index.is_multiple_of(2) {
                checksum = checksum.rotate_left(5) ^ u64::from(reader.byte());
            }
        }
    }
    black_box(reader.position);
    checksum
}

fn shared_read(bytes: &[u8], groups: usize) -> u64 {
    let mut reader = MsbInterleavedBitReader::new(bytes);
    let mut checksum = 0u64;
    for _ in 0..groups {
        for index in 0..8usize {
            checksum = checksum.rotate_left(3) ^ u64::from(reader.read_bit().unwrap());
            if index.is_multiple_of(2) {
                checksum = checksum.rotate_left(5) ^ u64::from(reader.read_byte().unwrap());
            }
        }
    }
    black_box(reader.position());
    checksum
}

fn frozen_write(source: &[u8], groups: usize) -> u64 {
    let mut writer = FrozenWriter::with_capacity(groups * 5);
    let mut source_position = 0usize;
    for _ in 0..groups {
        for index in 0..8usize {
            let byte = source[source_position];
            source_position += 1;
            writer.bit(byte & 1 != 0);
            if index.is_multiple_of(2) {
                writer.byte(byte.rotate_left(3));
            }
        }
    }
    writer
        .bytes
        .iter()
        .fold(0u64, |sum, &byte| sum.rotate_left(5) ^ u64::from(byte))
}

fn shared_write(source: &[u8], groups: usize) -> u64 {
    let mut writer = MsbInterleavedBitWriter::with_capacity(groups * 5);
    let mut source_position = 0usize;
    for _ in 0..groups {
        for index in 0..8usize {
            let byte = source[source_position];
            source_position += 1;
            writer.write_bit(byte & 1 != 0);
            if index.is_multiple_of(2) {
                writer.write_byte(byte.rotate_left(3));
            }
        }
    }
    writer
        .as_bytes()
        .iter()
        .fold(0u64, |sum, &byte| sum.rotate_left(5) ^ u64::from(byte))
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
        "{{\"route\":\"{route}\",\"round\":{round},\"elapsed_ns\":{elapsed_ns},\"allocation_calls\":{allocation_calls},\"checksum\":{checksum}}}"
    );
    checksum
}

fn main() {
    let rounds = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>().expect("rounds must be an integer"))
        .unwrap_or(11);
    assert!(rounds >= 3, "at least three rounds are required");
    let groups = 1 << 17;
    let source: Vec<u8> = (0..groups * 8)
        .map(|index| ((index * 73 + index / 11 + 0x5a) & 0xff) as u8)
        .collect();
    let encoded = {
        let mut writer = MsbInterleavedBitWriter::with_capacity(groups * 5);
        let mut source_position = 0usize;
        for _ in 0..groups {
            for index in 0..8usize {
                let byte = source[source_position];
                source_position += 1;
                writer.write_bit(byte & 1 != 0);
                if index.is_multiple_of(2) {
                    writer.write_byte(byte.rotate_left(3));
                }
            }
        }
        writer.into_bytes()
    };
    let read_expected = frozen_read(&encoded, groups);
    let write_expected = frozen_write(&source, groups);
    assert_eq!(shared_read(&encoded, groups), read_expected);
    assert_eq!(shared_write(&source, groups), write_expected);

    for round in 0..rounds {
        let routes: [(&str, &dyn Fn() -> u64); 4] = if round.is_multiple_of(2) {
            [
                ("reader-frozen", &|| frozen_read(&encoded, groups)),
                ("reader-shared", &|| shared_read(&encoded, groups)),
                ("writer-frozen", &|| frozen_write(&source, groups)),
                ("writer-shared", &|| shared_write(&source, groups)),
            ]
        } else {
            [
                ("writer-shared", &|| shared_write(&source, groups)),
                ("writer-frozen", &|| frozen_write(&source, groups)),
                ("reader-shared", &|| shared_read(&encoded, groups)),
                ("reader-frozen", &|| frozen_read(&encoded, groups)),
            ]
        };
        for (route, run) in routes {
            let checksum = measure(route, round, run);
            assert_eq!(
                checksum,
                if route.starts_with("reader") {
                    read_expected
                } else {
                    write_expected
                }
            );
        }
    }
}
