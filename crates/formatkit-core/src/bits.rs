//! Position-independent mechanics for packed integer fields.
//!
//! These descriptors operate after byte order has been decoded. They assign no
//! meaning to a bit or range and do not decide which combinations are legal.

/// A value that does not fit in a configured bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("value {value:#x} does not fit in {width} bits")]
pub struct BitValueTooWide {
    /// The rejected unsigned value.
    pub value: u64,
    /// The configured range width.
    pub width: u32,
}

/// One bit within a decoded unsigned integer.
///
/// Replacing a bit preserves every other bit in the word. Using a descriptor
/// with a word type too narrow for its index panics as a static descriptor
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bit {
    index: u32,
}

impl Bit {
    /// Configure a bit numbered from the least-significant bit.
    ///
    /// Panics when `index` is outside a `u64`, the widest supported word.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        assert!(index < u64::BITS, "bit index exceeds u64");
        Self { index }
    }

    /// Test this bit in a `u8`.
    #[must_use]
    #[inline(always)]
    pub const fn test_u8(self, word: u8) -> bool {
        self.assert_fits(u8::BITS);
        word & (1u8 << self.index) != 0
    }

    /// Set or clear this bit in a `u8`, preserving all other bits.
    #[must_use]
    #[inline(always)]
    pub const fn replace_u8(self, word: u8, value: bool) -> u8 {
        self.assert_fits(u8::BITS);
        replace_bit_u64(word as u64, self.index, value) as u8
    }

    /// Test this bit in a `u16`.
    #[must_use]
    #[inline(always)]
    pub const fn test_u16(self, word: u16) -> bool {
        self.assert_fits(u16::BITS);
        word & (1u16 << self.index) != 0
    }

    /// Set or clear this bit in a `u16`, preserving all other bits.
    #[must_use]
    #[inline(always)]
    pub const fn replace_u16(self, word: u16, value: bool) -> u16 {
        self.assert_fits(u16::BITS);
        replace_bit_u64(word as u64, self.index, value) as u16
    }

    /// Test this bit in a `u32`.
    #[must_use]
    #[inline(always)]
    pub const fn test_u32(self, word: u32) -> bool {
        self.assert_fits(u32::BITS);
        word & (1u32 << self.index) != 0
    }

    /// Set or clear this bit in a `u32`, preserving all other bits.
    #[must_use]
    #[inline(always)]
    pub const fn replace_u32(self, word: u32, value: bool) -> u32 {
        self.assert_fits(u32::BITS);
        replace_bit_u64(word as u64, self.index, value) as u32
    }

    /// Test this bit in a `u64`.
    #[must_use]
    #[inline(always)]
    pub const fn test_u64(self, word: u64) -> bool {
        word & (1u64 << self.index) != 0
    }

    /// Set or clear this bit in a `u64`, preserving all other bits.
    #[must_use]
    #[inline(always)]
    pub const fn replace_u64(self, word: u64, value: bool) -> u64 {
        replace_bit_u64(word, self.index, value)
    }

    const fn assert_fits(self, bits: u32) {
        assert!(self.index < bits, "bit exceeds word");
    }
}

const fn replace_bit_u64(word: u64, index: u32, value: bool) -> u64 {
    let mask = 1u64 << index;
    if value {
        word | mask
    } else {
        word & !mask
    }
}

/// A contiguous bit range within a decoded unsigned integer.
///
/// Extraction shifts the range to bit zero. Replacement checks that the new
/// value fits and preserves every bit outside the range. A descriptor used
/// with a word type narrower than its range panics as a static descriptor
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitRange {
    lsb: u32,
    width: u32,
}

impl BitRange {
    /// Configure a nonempty range by least-significant bit and width.
    ///
    /// Panics when the range does not fit in a `u64`, the widest supported
    /// word.
    #[must_use]
    pub const fn new(lsb: u32, width: u32) -> Self {
        assert!(width != 0, "bit range width must be nonzero");
        assert!(lsb < u64::BITS, "bit range start exceeds u64");
        assert!(width <= u64::BITS - lsb, "bit range exceeds u64");
        Self { lsb, width }
    }

    /// Extract this range from a `u8`.
    #[must_use]
    #[inline(always)]
    pub const fn extract_u8(self, word: u8) -> u8 {
        self.assert_fits(u8::BITS);
        self.extract_u64_inner(word as u64) as u8
    }

    /// Replace this range in a `u8`, preserving every other bit.
    #[inline(always)]
    pub const fn replace_u8(self, word: u8, value: u8) -> Result<u8, BitValueTooWide> {
        self.assert_fits(u8::BITS);
        match self.replace_u64_inner(word as u64, value as u64) {
            Ok(replaced) => Ok(replaced as u8),
            Err(error) => Err(error),
        }
    }

    /// Extract this range from a `u16`.
    #[must_use]
    #[inline(always)]
    pub const fn extract_u16(self, word: u16) -> u16 {
        self.assert_fits(u16::BITS);
        self.extract_u64_inner(word as u64) as u16
    }

    /// Replace this range in a `u16`, preserving every other bit.
    #[inline(always)]
    pub const fn replace_u16(self, word: u16, value: u16) -> Result<u16, BitValueTooWide> {
        self.assert_fits(u16::BITS);
        match self.replace_u64_inner(word as u64, value as u64) {
            Ok(replaced) => Ok(replaced as u16),
            Err(error) => Err(error),
        }
    }

    /// Extract this range from a `u32`.
    #[must_use]
    #[inline(always)]
    pub const fn extract_u32(self, word: u32) -> u32 {
        self.assert_fits(u32::BITS);
        self.extract_u64_inner(word as u64) as u32
    }

    /// Replace this range in a `u32`, preserving every other bit.
    #[inline(always)]
    pub const fn replace_u32(self, word: u32, value: u32) -> Result<u32, BitValueTooWide> {
        self.assert_fits(u32::BITS);
        match self.replace_u64_inner(word as u64, value as u64) {
            Ok(replaced) => Ok(replaced as u32),
            Err(error) => Err(error),
        }
    }

    /// Extract this range from a `u64`.
    #[must_use]
    #[inline(always)]
    pub const fn extract_u64(self, word: u64) -> u64 {
        self.extract_u64_inner(word)
    }

    /// Replace this range in a `u64`, preserving every other bit.
    #[inline(always)]
    pub const fn replace_u64(self, word: u64, value: u64) -> Result<u64, BitValueTooWide> {
        self.replace_u64_inner(word, value)
    }

    const fn assert_fits(self, bits: u32) {
        assert!(self.lsb + self.width <= bits, "bit range exceeds word");
    }

    const fn value_mask(self) -> u64 {
        if self.width == u64::BITS {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        }
    }

    const fn extract_u64_inner(self, word: u64) -> u64 {
        (word >> self.lsb) & self.value_mask()
    }

    const fn replace_u64_inner(self, word: u64, value: u64) -> Result<u64, BitValueTooWide> {
        let value_mask = self.value_mask();
        if value & !value_mask != 0 {
            return Err(BitValueTooWide {
                value,
                width: self.width,
            });
        }
        let field_mask = value_mask << self.lsb;
        Ok((word & !field_mask) | (value << self.lsb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_test_and_replace_every_position_without_touching_neighbors() {
        for index in 0..u64::BITS {
            let bit = Bit::new(index);
            let mask = 1u64 << index;
            assert!(!bit.test_u64(0));
            assert!(bit.test_u64(mask));
            assert_eq!(bit.replace_u64(u64::MAX, false), u64::MAX ^ mask);
            assert_eq!(bit.replace_u64(0, true), mask);
        }
        assert_eq!(Bit::new(7).replace_u8(0x55, true), 0xd5);
        assert_eq!(Bit::new(15).replace_u16(0xffff, false), 0x7fff);
        assert_eq!(Bit::new(31).replace_u32(0, true), 0x8000_0000);
    }

    #[test]
    fn ranges_extract_and_replace_edges_and_whole_words() {
        let nibble = BitRange::new(4, 4);
        assert_eq!(nibble.extract_u8(0xab), 0x0a);
        assert_eq!(nibble.replace_u8(0xab, 5), Ok(0x5b));
        assert_eq!(nibble.replace_u8(0xab, 0x10).unwrap_err().width, 4);

        let high = BitRange::new(60, 4);
        assert_eq!(high.extract_u64(0xa123_4567_89ab_cdef), 0xa);
        assert_eq!(
            high.replace_u64(0x0123_4567_89ab_cdef, 0xf),
            Ok(0xf123_4567_89ab_cdef)
        );

        let whole = BitRange::new(0, 64);
        assert_eq!(whole.extract_u64(u64::MAX), u64::MAX);
        assert_eq!(whole.replace_u64(0, u64::MAX), Ok(u64::MAX));
    }

    #[test]
    fn static_descriptor_errors_panic_instead_of_becoming_input_errors() {
        assert!(std::panic::catch_unwind(|| Bit::new(64)).is_err());
        assert!(std::panic::catch_unwind(|| Bit::new(8).test_u8(0)).is_err());
        assert!(std::panic::catch_unwind(|| BitRange::new(0, 0)).is_err());
        assert!(std::panic::catch_unwind(|| BitRange::new(63, 2)).is_err());
        assert!(std::panic::catch_unwind(|| BitRange::new(7, 2).extract_u8(0)).is_err());
    }
}
