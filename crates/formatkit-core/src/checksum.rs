//! Common checksum state machines.
//!
//! This module owns only the byte arithmetic. Formats remain responsible for
//! deciding which bytes are covered, how checksums are stored, and whether a
//! mismatch is fatal.

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
