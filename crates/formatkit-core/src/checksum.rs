//! Common checksum state machines.
//!
//! This module owns only the byte arithmetic. Formats remain responsible for
//! deciding which bytes are covered, how checksums are stored, and whether a
//! mismatch is fatal.

/// Parameters for a 16-bit CRC with matching input/output bit orientation.
///
/// Reflected algorithms supply the reflected polynomial (for example 0x8408),
/// while MSB-first algorithms supply the normal polynomial (for example 0x8005).
/// Byte swapping is final presentation only, never applied between updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc16Params {
    pub polynomial: u16,
    pub seed: u16,
    pub xor_out: u16,
    pub reflected: bool,
    pub swap_bytes: bool,
}

impl Crc16Params {
    pub const ARC: Self = Self {
        polynomial: 0xa001,
        seed: 0,
        xor_out: 0,
        reflected: true,
        swap_bytes: false,
    };
    pub const KERMIT: Self = Self {
        polynomial: 0x8408,
        seed: 0,
        xor_out: 0,
        reflected: true,
        swap_bytes: false,
    };
    pub const X25: Self = Self {
        polynomial: 0x8408,
        seed: 0xffff,
        xor_out: 0xffff,
        reflected: true,
        swap_bytes: false,
    };
    pub const BUYPASS: Self = Self {
        polynomial: 0x8005,
        seed: 0,
        xor_out: 0,
        reflected: false,
        swap_bytes: false,
    };
    pub const XMODEM: Self = Self {
        polynomial: 0x1021,
        seed: 0,
        xor_out: 0,
        reflected: false,
        swap_bytes: false,
    };
    pub const CCITT_FALSE: Self = Self {
        polynomial: 0x1021,
        seed: 0xffff,
        xor_out: 0,
        reflected: false,
        swap_bytes: false,
    };
    pub const MODBUS: Self = Self {
        polynomial: 0xa001,
        seed: 0xffff,
        xor_out: 0,
        reflected: true,
        swap_bytes: false,
    };

    pub fn compute(self, bytes: &[u8]) -> u16 {
        let mut state = Crc16::new(self);
        state.update(bytes);
        state.finish()
    }

    /// Compute the finalized CRC-16 over `bytes` with `zero_range` treated as zero bytes.
    ///
    /// Validates `zero_range.start <= zero_range.end && zero_range.end <= bytes.len()`
    /// without allocating a temporary copy of `bytes`.
    pub fn compute_with_zeroed_range(
        self,
        bytes: &[u8],
        zero_range: core::ops::Range<usize>,
    ) -> crate::Result<u16> {
        if zero_range.start > zero_range.end {
            return Err(crate::Error::InvalidField {
                what: "checksum zero range start",
                value: zero_range.start as u64,
            });
        }
        if zero_range.end > bytes.len() {
            return Err(crate::Error::InvalidField {
                what: "checksum zero range end",
                value: zero_range.end as u64,
            });
        }
        let mut state = Crc16::new(self);
        state.update(&bytes[..zero_range.start]);
        let zeros = [0u8; 64];
        let mut remaining = zero_range.len();
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            state.update(&zeros[..chunk]);
            remaining -= chunk;
        }
        state.update(&bytes[zero_range.end..]);
        Ok(state.finish())
    }
}

/// Incremental CRC-16 arithmetic. Coverage and stored-byte order are owner policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc16 {
    params: Crc16Params,
    state: u16,
}

impl Crc16 {
    pub const fn new(params: Crc16Params) -> Self {
        Self {
            state: params.seed,
            params,
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.params.reflected {
                self.state ^= u16::from(byte);
                for _ in 0..8 {
                    let mask = (self.state & 1).wrapping_neg();
                    self.state = (self.state >> 1) ^ (self.params.polynomial & mask);
                }
            } else {
                self.state ^= u16::from(byte) << 8;
                for _ in 0..8 {
                    let mask = (self.state >> 15).wrapping_neg();
                    self.state = (self.state << 1) ^ (self.params.polynomial & mask);
                }
            }
        }
    }
    /// Unfinalized shift-register state, useful for explicit chained records.
    pub const fn raw_state(self) -> u16 {
        self.state
    }
    pub const fn finish(self) -> u16 {
        let value = self.state ^ self.params.xor_out;
        if self.params.swap_bytes {
            value.swap_bytes()
        } else {
            value
        }
    }
}

const CRC32_ISO_HDLC_POLYNOMIAL: u32 = 0xEDB8_8320;
const CRC32_MPEG2_POLYNOMIAL: u32 = 0x04C1_1DB7;
const CRC32C_POLYNOMIAL: u32 = 0x82F6_3B78;
const ADLER32_MODULUS: u32 = 65_521;

/// Parameters for a 32-bit CRC with matching input/output bit orientation.
///
/// Reflected algorithms supply the reflected polynomial (for example
/// `0xEDB8_8320`), while MSB-first algorithms supply the normal polynomial
/// (for example `0x04C1_1DB7`). Byte swapping is final presentation only,
/// never applied between updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32Params {
    /// Normal (when `reflected == false`) or reflected (when `reflected == true`) polynomial.
    pub polynomial: u32,
    /// Initial shift-register value.
    pub seed: u32,
    /// Final XOR mask applied on completion.
    pub xor_out: u32,
    /// Whether input bytes and shift-register state are processed LSB first.
    pub reflected: bool,
    /// Whether the finalized 32-bit value has its byte order reversed.
    pub swap_bytes: bool,
}

impl Crc32Params {
    /// CRC-32/ISO-HDLC (Ethernet, PKZIP, PNG, gzip). Check value: `0xCBF4_3926`.
    pub const ISO_HDLC: Self = Self {
        polynomial: CRC32_ISO_HDLC_POLYNOMIAL,
        seed: 0xFFFF_FFFF,
        xor_out: 0xFFFF_FFFF,
        reflected: true,
        swap_bytes: false,
    };

    /// CRC-32/JAMCRC (reflected ISO-HDLC without final complement). Check value: `0x340B_C6D9`.
    pub const JAMCRC: Self = Self {
        polynomial: CRC32_ISO_HDLC_POLYNOMIAL,
        seed: 0xFFFF_FFFF,
        xor_out: 0x0000_0000,
        reflected: true,
        swap_bytes: false,
    };

    /// CRC-32/MPEG-2 (MSB-first, no final XOR). Check value: `0x0376_E6E7`.
    pub const MPEG2: Self = Self {
        polynomial: CRC32_MPEG2_POLYNOMIAL,
        seed: 0xFFFF_FFFF,
        xor_out: 0x0000_0000,
        reflected: false,
        swap_bytes: false,
    };

    /// CRC-32/BZIP2 (MSB-first with final complement). Check value: `0xFC89_1918`.
    pub const BZIP2: Self = Self {
        polynomial: CRC32_MPEG2_POLYNOMIAL,
        seed: 0xFFFF_FFFF,
        xor_out: 0xFFFF_FFFF,
        reflected: false,
        swap_bytes: false,
    };

    /// CRC-32/ISCSI (Castagnoli / CRC-32C). Check value: `0xE306_9283`.
    pub const CRC32C: Self = Self {
        polynomial: CRC32C_POLYNOMIAL,
        seed: 0xFFFF_FFFF,
        xor_out: 0xFFFF_FFFF,
        reflected: true,
        swap_bytes: false,
    };

    /// Compute the finalized CRC-32 over `bytes`.
    pub fn compute(self, bytes: &[u8]) -> u32 {
        let mut state = Crc32::new(self);
        state.update(bytes);
        state.finalize()
    }

    /// Compute the finalized CRC-32 over `bytes` with `zero_range` treated as zero bytes.
    ///
    /// Validates `zero_range.start <= zero_range.end && zero_range.end <= bytes.len()`
    /// without allocating a temporary copy of `bytes`.
    pub fn compute_with_zeroed_range(
        self,
        bytes: &[u8],
        zero_range: std::ops::Range<usize>,
    ) -> crate::Result<u32> {
        if zero_range.start > zero_range.end {
            return Err(crate::Error::InvalidField {
                what: "checksum zero range start",
                value: zero_range.start as u64,
            });
        }
        if zero_range.end > bytes.len() {
            return Err(crate::Error::InvalidField {
                what: "checksum zero range end",
                value: zero_range.end as u64,
            });
        }
        let mut state = Crc32::new(self);
        state.update(&bytes[..zero_range.start]);
        let zeros = [0u8; 64];
        let mut remaining = zero_range.len();
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            state.update(&zeros[..chunk]);
            remaining -= chunk;
        }
        state.update(&bytes[zero_range.end..]);
        Ok(state.finalize())
    }
}

/// Incremental CRC-32 arithmetic. Coverage and stored-byte order are owner policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32 {
    params: Crc32Params,
    state: u32,
}

impl Crc32 {
    /// Start an incremental CRC-32 calculation with `params`.
    pub const fn new(params: Crc32Params) -> Self {
        Self {
            state: params.seed,
            params,
        }
    }

    /// Incorporate another byte sequence into the running CRC-32 state.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.params.reflected {
                self.state ^= u32::from(byte);
                for _ in 0..8 {
                    let mask = (self.state & 1).wrapping_neg();
                    self.state = (self.state >> 1) ^ (self.params.polynomial & mask);
                }
            } else {
                self.state ^= u32::from(byte) << 24;
                for _ in 0..8 {
                    let mask = (self.state >> 31).wrapping_neg();
                    self.state = (self.state << 1) ^ (self.params.polynomial & mask);
                }
            }
        }
    }

    /// Unfinalized shift-register state, useful for explicit chained records.
    pub const fn raw_state(self) -> u32 {
        self.state
    }

    /// Finalize the CRC-32 by applying `xor_out` and optional byte swap.
    pub const fn finalize(self) -> u32 {
        let value = self.state ^ self.params.xor_out;
        if self.params.swap_bytes {
            value.swap_bytes()
        } else {
            value
        }
    }

    /// Alias for [`Self::finalize`], symmetric with [`Crc16::finish`].
    pub const fn finish(self) -> u32 {
        self.finalize()
    }
}

/// Streaming reflected CRC-32/ISO-HDLC state.
///
/// The conventional checksum uses an all-ones initial state and complements
/// the state returned by [`Self::raw_state`]. Some identifier hashes use that
/// raw state directly, so both outcomes are exposed explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32IsoHdlc {
    inner: Crc32,
}

impl Crc32IsoHdlc {
    /// Start a CRC-32/ISO-HDLC calculation.
    pub const fn new() -> Self {
        Self {
            inner: Crc32::new(Crc32Params::ISO_HDLC),
        }
    }

    /// Incorporate another byte sequence.
    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Return the conventional complemented CRC-32/ISO-HDLC checksum.
    pub const fn finish(self) -> u32 {
        self.inner.finalize()
    }

    /// Return the uncomplemented shift-register state.
    pub const fn raw_state(self) -> u32 {
        self.inner.raw_state()
    }
}

impl Default for Crc32IsoHdlc {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the conventional reflected CRC-32/ISO-HDLC checksum.
pub fn crc32_iso_hdlc(bytes: &[u8]) -> u32 {
    let mut checksum = Crc32IsoHdlc::new();
    checksum.update(bytes);
    checksum.finish()
}

/// Streaming CRC-32/MPEG-2 state.
///
/// This variant is non-reflected, starts from all ones, and has no final XOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32Mpeg2 {
    inner: Crc32,
}

impl Crc32Mpeg2 {
    /// Start a CRC-32/MPEG-2 calculation.
    pub const fn new() -> Self {
        Self {
            inner: Crc32::new(Crc32Params::MPEG2),
        }
    }

    /// Incorporate another byte sequence.
    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Return the current CRC-32/MPEG-2 checksum.
    pub const fn finish(self) -> u32 {
        self.inner.finalize()
    }
}

impl Default for Crc32Mpeg2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a CRC-32/MPEG-2 checksum.
pub fn crc32_mpeg2(bytes: &[u8]) -> u32 {
    let mut checksum = Crc32Mpeg2::new();
    checksum.update(bytes);
    checksum.finish()
}

/// Streaming Adler-32 state used by RFC 1950 zlib streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Adler32 {
    /// Start an Adler-32 calculation.
    pub const fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    /// Incorporate another byte sequence.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.a = (self.a + u32::from(byte)) % ADLER32_MODULUS;
            self.b = (self.b + self.a) % ADLER32_MODULUS;
        }
    }

    /// Return the current Adler-32 checksum.
    pub const fn finish(self) -> u32 {
        (self.b << 16) | self.a
    }
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the Adler-32 checksum used by RFC 1950 zlib streams.
pub fn adler32(bytes: &[u8]) -> u32 {
    let mut checksum = Adler32::new();
    checksum.update(bytes);
    checksum.finish()
}

/// Wrapping 8-bit sum of bytes starting from `seed`.
pub fn sum_bytes_u8(bytes: &[u8], seed: u8) -> u8 {
    bytes.iter().fold(seed, |acc, &b| acc.wrapping_add(b))
}

/// Wrapping 16-bit sum of individual bytes starting from `seed`.
pub fn sum_bytes_u16(bytes: &[u8], seed: u16) -> u16 {
    bytes
        .iter()
        .fold(seed, |acc, &b| acc.wrapping_add(u16::from(b)))
}

/// Wrapping 32-bit sum of individual bytes starting from `seed`.
pub fn sum_bytes_u32(bytes: &[u8], seed: u32) -> u32 {
    bytes
        .iter()
        .fold(seed, |acc, &b| acc.wrapping_add(u32::from(b)))
}

/// Wrapping 16-bit sum of little-endian `u16` words (ignoring any trailing odd byte).
pub fn sum_u16_le_words(bytes: &[u8], seed: u16) -> u16 {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc.wrapping_add(u16::from_le_bytes(w)))
}

/// Wrapping 16-bit sum of big-endian `u16` words (ignoring any trailing odd byte).
pub fn sum_u16_be_words(bytes: &[u8], seed: u16) -> u16 {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc.wrapping_add(u16::from_be_bytes(w)))
}

/// Wrapping 32-bit sum of little-endian `u32` words (ignoring any trailing `< 4` bytes).
pub fn sum_u32_le_words(bytes: &[u8], seed: u32) -> u32 {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc.wrapping_add(u32::from_le_bytes(w)))
}

/// Wrapping 32-bit sum of big-endian `u32` words (ignoring any trailing `< 4` bytes).
pub fn sum_u32_be_words(bytes: &[u8], seed: u32) -> u32 {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc.wrapping_add(u32::from_be_bytes(w)))
}

/// Bitwise XOR of bytes starting from `seed`.
pub fn xor_bytes_u8(bytes: &[u8], seed: u8) -> u8 {
    bytes.iter().fold(seed, |acc, &b| acc ^ b)
}

/// Bitwise XOR of all bytes starting from `0`.
pub fn xor_bytes(bytes: &[u8]) -> u8 {
    xor_bytes_u8(bytes, 0)
}

/// Bitwise XOR of little-endian `u16` words starting from `seed` (ignoring any trailing odd byte).
pub fn xor_u16_le_words(bytes: &[u8], seed: u16) -> u16 {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc ^ u16::from_le_bytes(w))
}

/// Bitwise XOR of big-endian `u16` words starting from `seed` (ignoring any trailing odd byte).
pub fn xor_u16_be_words(bytes: &[u8], seed: u16) -> u16 {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc ^ u16::from_be_bytes(w))
}

/// Bitwise XOR of little-endian `u32` words starting from `seed` (ignoring any trailing `< 4` bytes).
pub fn xor_u32_le_words(bytes: &[u8], seed: u32) -> u32 {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc ^ u32::from_le_bytes(w))
}

/// Bitwise XOR of big-endian `u32` words starting from `seed` (ignoring any trailing `< 4` bytes).
pub fn xor_u32_be_words(bytes: &[u8], seed: u32) -> u32 {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc ^ u32::from_be_bytes(w))
}

/// Input unit width and byte order for [`FoldChecksum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldUnit {
    /// Single unsigned bytes (`1` byte per step).
    Byte,
    /// Unsigned 16-bit words (`2` bytes per step) in the given byte order.
    U16(crate::Endian),
    /// Unsigned 32-bit words (`4` bytes per step) in the given byte order.
    U32(crate::Endian),
    /// Unsigned 64-bit words (`8` bytes per step) in the given byte order.
    U64(crate::Endian),
}

impl FoldUnit {
    const fn byte_len(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::U16(_) => 2,
            Self::U32(_) => 4,
            Self::U64(_) => 8,
        }
    }
}

/// Accumulation step applied to each decoded unit in [`FoldChecksum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldOp {
    /// Wrapping addition: `acc = (acc + unit) & mask`.
    Sum,
    /// Bitwise exclusive-or: `acc = (acc ^ unit) & mask`.
    Xor,
    /// Rotate accumulator left within `bits`, then add: `acc = (rotl(acc, shift) + unit) & mask`.
    RotateLeftThenSum(u32),
    /// Add, then rotate accumulator left within `bits`: `acc = rotl((acc + unit) & mask, shift)`.
    SumThenRotateLeft(u32),
    /// Rotate accumulator left within `bits`, then XOR: `acc = (rotl(acc, shift) ^ unit) & mask`.
    RotateLeftThenXor(u32),
    /// XOR, then rotate accumulator left within `bits`: `acc = rotl((acc ^ unit) & mask, shift)`.
    XorThenRotateLeft(u32),
    /// Wrapping weighted sum by 0-based unit index: `acc = (acc + unit * (base + index)) & mask`.
    WeightedOffset { base: u64 },
    /// Wrapping weighted sum by 0-based byte offset: `acc = (acc + unit * (base + byte_offset)) & mask`.
    WeightedByteOffset { base: u64 },
}

/// Configurable arithmetic or bitwise fold checksum over fixed-width units.
///
/// The accumulator is masked to `bits` (`1..=64`) at initialization, after each
/// step, and after applying `xor_out`. Input length must be an exact multiple
/// of the selected [`FoldUnit`] width.
#[doc(alias = "additive")]
#[doc(alias = "rolling")]
#[doc(alias = "xor")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldChecksum {
    pub unit: FoldUnit,
    pub op: FoldOp,
    pub bits: u8,
    pub seed: u64,
    pub xor_out: u64,
}

#[inline]
fn rotate_left_bits(value: u64, shift: u32, bits: u8, mask: u64) -> u64 {
    let width = u32::from(bits);
    let r = shift % width;
    let v = value & mask;
    if r == 0 {
        v
    } else {
        ((v << r) | (v >> (width - r))) & mask
    }
}

impl FoldChecksum {
    /// Compute the fold checksum over `bytes`.
    pub fn compute(&self, bytes: &[u8]) -> crate::Result<u64> {
        self.compute_masked(bytes, 0..0)
    }

    /// Compute the fold checksum over `bytes` with `zero_range` treated as zero bytes.
    ///
    /// Validates `zero_range.start <= zero_range.end && zero_range.end <= bytes.len()`
    /// without allocating a temporary copy of `bytes`.
    pub fn compute_with_zeroed_range(
        &self,
        bytes: &[u8],
        zero_range: core::ops::Range<usize>,
    ) -> crate::Result<u64> {
        if zero_range.start > zero_range.end {
            return Err(crate::Error::InvalidField {
                what: "checksum zero range start",
                value: zero_range.start as u64,
            });
        }
        if zero_range.end > bytes.len() {
            return Err(crate::Error::InvalidField {
                what: "checksum zero range end",
                value: zero_range.end as u64,
            });
        }
        self.compute_masked(bytes, zero_range)
    }

    fn compute_masked(
        &self,
        bytes: &[u8],
        zero_range: core::ops::Range<usize>,
    ) -> crate::Result<u64> {
        if self.bits == 0 || self.bits > 64 {
            return Err(crate::Error::InvalidField {
                what: "checksum bit width",
                value: u64::from(self.bits),
            });
        }
        let unit_size = self.unit.byte_len();
        if !bytes.len().is_multiple_of(unit_size) {
            return Err(crate::Error::InvalidField {
                what: "checksum input length",
                value: bytes.len() as u64,
            });
        }

        let mask = if self.bits == 64 {
            u64::MAX
        } else {
            (1u64 << self.bits) - 1
        };
        let mut acc = self.seed & mask;

        let step = |acc: u64, val: u64, idx: u64| -> u64 {
            match self.op {
                FoldOp::Sum => acc.wrapping_add(val) & mask,
                FoldOp::Xor => (acc ^ val) & mask,
                FoldOp::RotateLeftThenSum(shift) => {
                    rotate_left_bits(acc, shift, self.bits, mask).wrapping_add(val) & mask
                }
                FoldOp::SumThenRotateLeft(shift) => {
                    rotate_left_bits(acc.wrapping_add(val) & mask, shift, self.bits, mask)
                }
                FoldOp::RotateLeftThenXor(shift) => {
                    (rotate_left_bits(acc, shift, self.bits, mask) ^ val) & mask
                }
                FoldOp::XorThenRotateLeft(shift) => {
                    rotate_left_bits((acc ^ val) & mask, shift, self.bits, mask)
                }
                FoldOp::WeightedOffset { base } => {
                    let weight = base.wrapping_add(idx);
                    acc.wrapping_add(val.wrapping_mul(weight)) & mask
                }
                FoldOp::WeightedByteOffset { base } => {
                    let byte_offset = idx.wrapping_mul(unit_size as u64);
                    let weight = base.wrapping_add(byte_offset);
                    acc.wrapping_add(val.wrapping_mul(weight)) & mask
                }
            }
        };

        let read_byte = |pos: usize| -> u8 {
            if zero_range.contains(&pos) {
                0
            } else {
                bytes[pos]
            }
        };

        match self.unit {
            FoldUnit::Byte => {
                for idx in 0..bytes.len() {
                    acc = step(acc, u64::from(read_byte(idx)), idx as u64);
                }
            }
            FoldUnit::U16(endian) => {
                for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
                    let base = idx * 2;
                    let raw = if base + 2 <= zero_range.start || base >= zero_range.end {
                        [chunk[0], chunk[1]]
                    } else {
                        [read_byte(base), read_byte(base + 1)]
                    };
                    let val = match endian {
                        crate::Endian::Little => u16::from_le_bytes(raw),
                        crate::Endian::Big => u16::from_be_bytes(raw),
                    };
                    acc = step(acc, u64::from(val), idx as u64);
                }
            }
            FoldUnit::U32(endian) => {
                for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
                    let base = idx * 4;
                    let raw = if base + 4 <= zero_range.start || base >= zero_range.end {
                        [chunk[0], chunk[1], chunk[2], chunk[3]]
                    } else {
                        [
                            read_byte(base),
                            read_byte(base + 1),
                            read_byte(base + 2),
                            read_byte(base + 3),
                        ]
                    };
                    let val = match endian {
                        crate::Endian::Little => u32::from_le_bytes(raw),
                        crate::Endian::Big => u32::from_be_bytes(raw),
                    };
                    acc = step(acc, u64::from(val), idx as u64);
                }
            }
            FoldUnit::U64(endian) => {
                for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
                    let base = idx * 8;
                    let raw = if base + 8 <= zero_range.start || base >= zero_range.end {
                        [
                            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                            chunk[7],
                        ]
                    } else {
                        [
                            read_byte(base),
                            read_byte(base + 1),
                            read_byte(base + 2),
                            read_byte(base + 3),
                            read_byte(base + 4),
                            read_byte(base + 5),
                            read_byte(base + 6),
                            read_byte(base + 7),
                        ]
                    };
                    let val = match endian {
                        crate::Endian::Little => u64::from_le_bytes(raw),
                        crate::Endian::Big => u64::from_be_bytes(raw),
                    };
                    acc = step(acc, val, idx as u64);
                }
            }
        }

        Ok((acc ^ self.xor_out) & mask)
    }
}

/// Compute a checksum or digest over `bytes` with `zero_range` treated as zero bytes.
///
/// Validates that `zero_range.start <= zero_range.end && zero_range.end <= bytes.len()`.
/// When `zero_range` is empty, `f` is invoked directly on `bytes` without allocating;
/// otherwise `f` is invoked on a temporary copy with `zero_range` filled with `0x00`.
pub fn compute_with_zeroed_range<T, F>(
    bytes: &[u8],
    zero_range: std::ops::Range<usize>,
    f: F,
) -> crate::Result<T>
where
    F: FnOnce(&[u8]) -> crate::Result<T>,
{
    if zero_range.start > zero_range.end {
        return Err(crate::Error::InvalidField {
            what: "checksum zero range start",
            value: zero_range.start as u64,
        });
    }
    if zero_range.end > bytes.len() {
        return Err(crate::Error::InvalidField {
            what: "checksum zero range end",
            value: zero_range.end as u64,
        });
    }
    if zero_range.is_empty() {
        return f(bytes);
    }
    let mut copy = bytes.to_vec();
    copy[zero_range].fill(0);
    f(&copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_published_check_values() {
        assert_eq!(crc32_iso_hdlc(b""), 0);
        assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_raw_state_is_the_uncomplemented_result() {
        let mut checksum = Crc32IsoHdlc::new();
        checksum.update(b"123456789");
        assert_eq!(checksum.raw_state(), !0xCBF4_3926);
        assert_eq!(checksum.finish(), 0xCBF4_3926);
    }

    #[test]
    fn crc32_updates_are_incremental() {
        let mut checksum = Crc32IsoHdlc::new();
        checksum.update(b"123");
        checksum.update(b"456");
        checksum.update(b"789");
        assert_eq!(checksum.finish(), crc32_iso_hdlc(b"123456789"));
    }

    #[test]
    fn crc32_mpeg2_matches_published_check_value() {
        assert_eq!(crc32_mpeg2(b"123456789"), 0x0376_E6E7);
    }

    #[test]
    fn crc32_mpeg2_updates_are_incremental() {
        let mut checksum = Crc32Mpeg2::new();
        checksum.update(b"123");
        checksum.update(b"456");
        checksum.update(b"789");
        assert_eq!(checksum.finish(), crc32_mpeg2(b"123456789"));
    }

    #[test]
    fn adler32_matches_published_check_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"123456789"), 0x091E_01DE);
    }

    #[test]
    fn adler32_updates_are_incremental() {
        let mut checksum = Adler32::new();
        checksum.update(b"123");
        checksum.update(b"456789");
        assert_eq!(checksum.finish(), adler32(b"123456789"));
    }
}

#[cfg(test)]
mod crc16_tests {
    use super::*;
    #[test]
    fn standard_check_values_and_streaming() {
        for (params, check) in [
            (Crc16Params::ARC, 0xbb3d),
            (Crc16Params::KERMIT, 0x2189),
            (Crc16Params::X25, 0x906e),
            (Crc16Params::BUYPASS, 0xfee8),
            (Crc16Params::XMODEM, 0x31c3),
            (Crc16Params::CCITT_FALSE, 0x29b1),
            (Crc16Params::MODBUS, 0x4b37),
        ] {
            assert_eq!(params.compute(b"123456789"), check);
            for split in 0..=9 {
                let mut state = Crc16::new(params);
                state.update(&b"123456789"[..split]);
                state.update(&[]);
                state.update(&b"123456789"[split..]);
                assert_eq!(state.finish(), check);
                assert_eq!(state.raw_state() ^ params.xor_out, check);
            }
        }
    }
    #[test]
    fn custom_seed_polynomial_finalization_and_swap() {
        let params = Crc16Params {
            seed: 0x1234,
            xor_out: 0x4567,
            polynomial: 0x8408,
            reflected: true,
            swap_bytes: true,
        };
        assert_eq!(params.compute(b""), (0x1234u16 ^ 0x4567).swap_bytes());
        let mut crc = Crc16::new(params);
        crc.update(b"abc");
        let raw = crc.raw_state();
        assert_eq!(crc.finish(), (raw ^ params.xor_out).swap_bytes());
        let chained = Crc16Params {
            seed: raw,
            ..params
        }
        .compute(b"def");
        crc.update(b"def");
        assert_eq!(crc.finish(), chained);
        assert_eq!(crc.finish(), params.compute(b"abcdef"));
    }

    #[test]
    fn crc32_presets_streaming_and_zeroed_range() {
        for (params, check) in [
            (Crc32Params::ISO_HDLC, 0xCBF4_3926),
            (Crc32Params::JAMCRC, 0x340B_C6D9),
            (Crc32Params::MPEG2, 0x0376_E6E7),
            (Crc32Params::BZIP2, 0xFC89_1918),
            (Crc32Params::CRC32C, 0xE306_9283),
        ] {
            assert_eq!(params.compute(b"123456789"), check);
            for split in 0..=9 {
                let mut state = Crc32::new(params);
                state.update(&b"123456789"[..split]);
                state.update(&[]);
                state.update(&b"123456789"[split..]);
                assert_eq!(state.finalize(), check);
                assert_eq!(state.finish(), check);
                assert_eq!(state.raw_state() ^ params.xor_out, check);
            }
        }

        let buf = [1u8, 2, 0xAA, 0xBB, 0xCC, 0xDD, 7, 8];
        let mut expected = buf;
        expected[2..6].fill(0);
        assert_eq!(
            Crc32Params::ISO_HDLC
                .compute_with_zeroed_range(&buf, 2..6)
                .unwrap(),
            Crc32Params::ISO_HDLC.compute(&expected)
        );
        assert_eq!(
            Crc32Params::CRC32C
                .compute_with_zeroed_range(&buf, 4..4)
                .unwrap(),
            Crc32Params::CRC32C.compute(&buf)
        );
        assert!(Crc32Params::ISO_HDLC
            .compute_with_zeroed_range(&buf, std::ops::Range { start: 5, end: 3 })
            .is_err());
        assert!(Crc32Params::ISO_HDLC
            .compute_with_zeroed_range(&buf, 0..9)
            .is_err());

        let swapped = Crc32Params {
            swap_bytes: true,
            ..Crc32Params::ISO_HDLC
        };
        assert_eq!(swapped.compute(b"123456789"), 0xCBF4_3926u32.swap_bytes());
    }

    #[test]
    fn crc16_compute_with_zeroed_range_matches_zeroed_copy_and_validates_bounds() {
        let buf = [0x11u8, 0x22, 0xAA, 0xBB, 0xCC, 0xDD, 0x77, 0x88];
        let mut expected = buf;
        expected[2..6].fill(0);
        assert_eq!(
            Crc16Params::CCITT_FALSE
                .compute_with_zeroed_range(&buf, 2..6)
                .unwrap(),
            Crc16Params::CCITT_FALSE.compute(&expected)
        );
        assert_eq!(
            Crc16Params::MODBUS
                .compute_with_zeroed_range(&buf, 4..4)
                .unwrap(),
            Crc16Params::MODBUS.compute(&buf)
        );

        let large = [0x5Au8; 100];
        let mut large_expected = large;
        large_expected[10..90].fill(0);
        assert_eq!(
            Crc16Params::X25
                .compute_with_zeroed_range(&large, 10..90)
                .unwrap(),
            Crc16Params::X25.compute(&large_expected)
        );

        assert!(Crc16Params::ARC
            .compute_with_zeroed_range(&buf, core::ops::Range { start: 5, end: 3 })
            .is_err());
        assert!(Crc16Params::ARC
            .compute_with_zeroed_range(&buf, 0..9)
            .is_err());
    }
}

#[cfg(test)]
mod arithmetic_checksum_tests {
    use super::*;
    use crate::{Endian, Error};

    #[test]
    fn wrapping_sums_and_xors() {
        let data = [0x01, 0x02, 0x03, 0x04, 0xFF];
        assert_eq!(sum_bytes_u8(&data, 0), 0x09);
        assert_eq!(sum_bytes_u16(&data, 1), 0x010A);
        assert_eq!(sum_bytes_u32(&data, 0), 0x0109);
        assert_eq!(sum_u16_le_words(&data, 0), 0x0201u16.wrapping_add(0x0403));
        assert_eq!(sum_u16_be_words(&data, 0), 0x0102u16.wrapping_add(0x0304));
        assert_eq!(sum_u32_le_words(&data, 0), 0x0403_0201);
        assert_eq!(sum_u32_be_words(&data, 0), 0x0102_0304);
        assert_eq!(xor_bytes_u8(&data, 0), 0xFB);
        assert_eq!(xor_bytes(&data), 0xFB);
        assert_eq!(xor_u16_le_words(&data, 0), 0x0201 ^ 0x0403);
        assert_eq!(xor_u16_be_words(&data, 0), 0x0102 ^ 0x0304);
        assert_eq!(
            xor_u32_le_words(&data, 0x1111_1111),
            0x1111_1111 ^ 0x0403_0201
        );
        assert_eq!(
            xor_u32_be_words(&data, 0x1111_1111),
            0x1111_1111 ^ 0x0102_0304
        );

        let u64_fold_le = FoldChecksum {
            unit: FoldUnit::U64(Endian::Little),
            op: FoldOp::Sum,
            bits: 64,
            seed: 1,
            xor_out: 0,
        };
        let u64_data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        ];
        assert_eq!(
            u64_fold_le.compute(&u64_data).unwrap(),
            1u64.wrapping_add(0x0807_0605_0403_0201)
                .wrapping_add(0x8070_6050_4030_2010)
        );
        let u64_fold_be = FoldChecksum {
            unit: FoldUnit::U64(Endian::Big),
            op: FoldOp::Xor,
            bits: 64,
            seed: 0,
            xor_out: 0,
        };
        assert_eq!(
            u64_fold_be.compute(&u64_data).unwrap(),
            0x0102_0304_0506_0708 ^ 0x1020_3040_5060_7080
        );
        assert!(u64_fold_be.compute(&u64_data[..7]).is_err());
    }

    #[test]
    fn fold_checksum_covers_units_ops_and_masks() {
        let data = [0x01, 0x02, 0x03, 0x04];

        let sum_u16_le = FoldChecksum {
            unit: FoldUnit::U16(Endian::Little),
            op: FoldOp::Sum,
            bits: 16,
            seed: 0x0010,
            xor_out: 0xFFFF,
        };
        assert_eq!(
            sum_u16_le.compute(&data).unwrap(),
            (0x0010u16.wrapping_add(0x0201).wrapping_add(0x0403) ^ 0xFFFF) as u64
        );

        let xor_u32_be = FoldChecksum {
            unit: FoldUnit::U32(Endian::Big),
            op: FoldOp::Xor,
            bits: 32,
            seed: 0xA5A5_5A5A,
            xor_out: 0,
        };
        assert_eq!(
            xor_u32_be.compute(&data).unwrap(),
            u64::from(0xA5A5_5A5Au32 ^ 0x0102_0304)
        );

        let rot_then_sum = FoldChecksum {
            unit: FoldUnit::Byte,
            op: FoldOp::RotateLeftThenSum(1),
            bits: 16,
            seed: 0x8000,
            xor_out: 0,
        };
        // Step 0: rotl16(0x8000, 1) + 1 = 0x0001 + 1 = 0x0002
        // Step 1: rotl16(0x0002, 1) + 2 = 0x0004 + 2 = 0x0006
        assert_eq!(rot_then_sum.compute(&[1, 2]).unwrap(), 0x0006);

        let sum_then_rot = FoldChecksum {
            unit: FoldUnit::Byte,
            op: FoldOp::SumThenRotateLeft(1),
            bits: 8,
            seed: 0x80,
            xor_out: 0,
        };
        // Step 0: rotl8((0x80 + 1) & 0xFF, 1) = rotl8(0x81, 1) = 0x03
        assert_eq!(sum_then_rot.compute(&[1]).unwrap(), 0x03);

        let rot_then_xor = FoldChecksum {
            unit: FoldUnit::Byte,
            op: FoldOp::RotateLeftThenXor(1),
            bits: 16,
            seed: 0x8000,
            xor_out: 0,
        };
        // Step 0: rotl16(0x8000, 1) ^ 0x03 = 0x0001 ^ 0x03 = 0x0002
        // Step 1: rotl16(0x0002, 1) ^ 0x05 = 0x0004 ^ 0x05 = 0x0001
        assert_eq!(rot_then_xor.compute(&[0x03, 0x05]).unwrap(), 0x0001);

        let xor_then_rot = FoldChecksum {
            unit: FoldUnit::Byte,
            op: FoldOp::XorThenRotateLeft(1),
            bits: 8,
            seed: 0x80,
            xor_out: 0,
        };
        // Step 0: rotl8((0x80 ^ 0x01) & 0xFF, 1) = rotl8(0x81, 1) = 0x03
        // Step 1: rotl8((0x03 ^ 0x02) & 0xFF, 1) = rotl8(0x01, 1) = 0x02
        assert_eq!(xor_then_rot.compute(&[0x01, 0x02]).unwrap(), 0x02);

        let rot_xor_12bit = FoldChecksum {
            unit: FoldUnit::U16(Endian::Big),
            op: FoldOp::RotateLeftThenXor(13), // 13 % 12 == 1
            bits: 12,
            seed: 0x0800,
            xor_out: 0,
        };
        // Step 0: (rotl12(0x800, 1) ^ 0xF005) & 0xFFF = (0x001 ^ 0x005) = 0x004
        assert_eq!(rot_xor_12bit.compute(&[0xF0, 0x05]).unwrap(), 0x004);

        let weighted = FoldChecksum {
            unit: FoldUnit::Byte,
            op: FoldOp::WeightedOffset { base: 1 },
            bits: 64,
            seed: 0,
            xor_out: 0,
        };
        // 1*1 + 2*2 + 3*3 + 4*4 = 30
        assert_eq!(weighted.compute(&data).unwrap(), 30);

        let weighted_byte_offset_u16 = FoldChecksum {
            unit: FoldUnit::U16(Endian::Little),
            op: FoldOp::WeightedByteOffset { base: 1 },
            bits: 64,
            seed: 0,
            xor_out: 0,
        };
        // Unit 0 at byte offset 0: 0x0201 * (1 + 0)
        // Unit 1 at byte offset 2: 0x0403 * (1 + 2)
        assert_eq!(
            weighted_byte_offset_u16.compute(&data).unwrap(),
            0x0201u64 + 0x0403u64 * 3
        );

        let weighted_byte_offset_u32 = FoldChecksum {
            unit: FoldUnit::U32(Endian::Big),
            op: FoldOp::WeightedByteOffset { base: 10 },
            bits: 64,
            seed: 0,
            xor_out: 0,
        };
        let eight = [0, 0, 0, 2, 0, 0, 0, 5];
        // Unit 0 at byte offset 0: 2 * 10 = 20
        // Unit 1 at byte offset 4: 5 * 14 = 70
        assert_eq!(weighted_byte_offset_u32.compute(&eight).unwrap(), 90);
    }

    #[test]
    fn fold_checksum_rejects_invalid_bits_and_unaligned_input() {
        let bad_zero = FoldChecksum {
            unit: FoldUnit::Byte,
            op: FoldOp::Sum,
            bits: 0,
            seed: 0,
            xor_out: 0,
        };
        assert!(matches!(
            bad_zero.compute(&[]),
            Err(Error::InvalidField {
                what: "checksum bit width",
                value: 0
            })
        ));

        let bad_wide = FoldChecksum {
            bits: 65,
            ..bad_zero
        };
        assert!(matches!(
            bad_wide.compute(&[]),
            Err(Error::InvalidField {
                what: "checksum bit width",
                value: 65
            })
        ));

        let u32_fold = FoldChecksum {
            unit: FoldUnit::U32(Endian::Little),
            op: FoldOp::Sum,
            bits: 32,
            seed: 0,
            xor_out: 0,
        };
        assert!(matches!(
            u32_fold.compute(&[1, 2, 3]),
            Err(Error::InvalidField {
                what: "checksum input length",
                value: 3
            })
        ));
    }

    #[test]
    fn compute_with_zeroed_range_masks_field_and_validates_bounds() {
        let data = [0x10, 0x20, 0xAA, 0xBB, 0x30, 0x40];
        let masked_sum =
            compute_with_zeroed_range(&data, 2..4, |slice| Ok(sum_bytes_u16(slice, 0))).unwrap();
        assert_eq!(masked_sum, 0x10 + 0x20 + 0x30 + 0x40);
        // Original slice is untouched.
        assert_eq!(data[2..4], [0xAA, 0xBB]);

        // Empty in-bounds range passes the original slice directly without allocating.
        let orig_ptr = data.as_ptr();
        let passed_ptr =
            compute_with_zeroed_range(&data, 2..2, |slice| Ok(slice.as_ptr())).unwrap();
        assert_eq!(passed_ptr, orig_ptr);

        // Reversed range is rejected.
        assert!(matches!(
            compute_with_zeroed_range(&data, std::ops::Range { start: 4, end: 2 }, |_| Ok(())),
            Err(Error::InvalidField {
                what: "checksum zero range start",
                value: 4
            })
        ));

        // Out-of-bounds range is rejected even when empty.
        assert!(matches!(
            compute_with_zeroed_range(&data, 7..7, |_| Ok(())),
            Err(Error::InvalidField {
                what: "checksum zero range end",
                value: 7
            })
        ));
        assert!(matches!(
            compute_with_zeroed_range(&data, 4..7, |_| Ok(())),
            Err(Error::InvalidField {
                what: "checksum zero range end",
                value: 7
            })
        ));
    }

    #[test]
    fn fold_checksum_compute_with_zeroed_range_matches_zeroed_copy_and_validates_bounds() {
        let data = [
            0x01, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x07, 0x08, //
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        // Unaligned range straddling U16/U32/U64 boundaries.
        let range = 3..9;
        let mut expected = data;
        expected[range.clone()].fill(0);

        for unit in [
            FoldUnit::Byte,
            FoldUnit::U16(Endian::Little),
            FoldUnit::U16(Endian::Big),
            FoldUnit::U32(Endian::Little),
            FoldUnit::U32(Endian::Big),
            FoldUnit::U64(Endian::Little),
            FoldUnit::U64(Endian::Big),
        ] {
            let fold = FoldChecksum {
                unit,
                op: FoldOp::XorThenRotateLeft(3),
                bits: 32,
                seed: 0x1234_5678,
                xor_out: 0x00FF_00FF,
            };
            assert_eq!(
                fold.compute_with_zeroed_range(&data, range.clone())
                    .unwrap(),
                fold.compute(&expected).unwrap()
            );
            assert_eq!(
                fold.compute_with_zeroed_range(&data, 4..4).unwrap(),
                fold.compute(&data).unwrap()
            );
        }

        let fold = FoldChecksum {
            unit: FoldUnit::U32(Endian::Little),
            op: FoldOp::Sum,
            bits: 32,
            seed: 0,
            xor_out: 0,
        };
        assert!(matches!(
            fold.compute_with_zeroed_range(&data, core::ops::Range { start: 6, end: 2 }),
            Err(Error::InvalidField {
                what: "checksum zero range start",
                value: 6
            })
        ));
        assert!(matches!(
            fold.compute_with_zeroed_range(&data, 0..17),
            Err(Error::InvalidField {
                what: "checksum zero range end",
                value: 17
            })
        ));
    }
}
