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

    pub fn compute(self, bytes: &[u8]) -> u16 {
        let mut state = Crc16::new(self);
        state.update(bytes);
        state.finish()
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
const ADLER32_MODULUS: u32 = 65_521;

/// Streaming reflected CRC-32/ISO-HDLC state.
///
/// The conventional checksum uses an all-ones initial state and complements
/// the state returned by [`Self::raw_state`]. Some identifier hashes use that
/// raw state directly, so both outcomes are exposed explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32IsoHdlc {
    state: u32,
}

impl Crc32IsoHdlc {
    /// Start a CRC-32/ISO-HDLC calculation.
    pub const fn new() -> Self {
        Self { state: u32::MAX }
    }

    /// Incorporate another byte sequence.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (self.state & 1).wrapping_neg();
                self.state = (self.state >> 1) ^ (CRC32_ISO_HDLC_POLYNOMIAL & mask);
            }
        }
    }

    /// Return the conventional complemented CRC-32/ISO-HDLC checksum.
    pub const fn finish(self) -> u32 {
        !self.state
    }

    /// Return the uncomplemented shift-register state.
    pub const fn raw_state(self) -> u32 {
        self.state
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
    state: u32,
}

impl Crc32Mpeg2 {
    /// Start a CRC-32/MPEG-2 calculation.
    pub const fn new() -> Self {
        Self { state: u32::MAX }
    }

    /// Incorporate another byte sequence.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= u32::from(byte) << 24;
            for _ in 0..8 {
                let top_bit = (self.state >> 31).wrapping_neg();
                self.state = (self.state << 1) ^ (CRC32_MPEG2_POLYNOMIAL & top_bit);
            }
        }
    }

    /// Return the current CRC-32/MPEG-2 checksum.
    pub const fn finish(self) -> u32 {
        self.state
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

/// Bitwise XOR of bytes starting from `seed`.
pub fn xor_bytes_u8(bytes: &[u8], seed: u8) -> u8 {
    bytes.iter().fold(seed, |acc, &b| acc ^ b)
}

/// Bitwise XOR of little-endian `u16` words starting from `seed` (ignoring any trailing odd byte).
pub fn xor_u16_le_words(bytes: &[u8], seed: u16) -> u16 {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .fold(seed, |acc, &w| acc ^ u16::from_le_bytes(w))
}

#[cfg(test)]
mod arithmetic_checksum_tests {
    use super::*;

    #[test]
    fn wrapping_sums_and_xors() {
        let data = [0x01, 0x02, 0x03, 0x04, 0xFF];
        assert_eq!(sum_bytes_u8(&data, 0), 0x09);
        assert_eq!(sum_bytes_u16(&data, 1), 0x010A);
        assert_eq!(sum_bytes_u32(&data, 0), 0x0109);
        assert_eq!(sum_u16_le_words(&data, 0), 0x0201u16.wrapping_add(0x0403));
        assert_eq!(sum_u16_be_words(&data, 0), 0x0102u16.wrapping_add(0x0304));
        assert_eq!(sum_u32_le_words(&data, 0), 0x0403_0201);
        assert_eq!(xor_bytes_u8(&data, 0), 0xFB);
        assert_eq!(xor_u16_le_words(&data, 0), 0x0201 ^ 0x0403);
    }
}
