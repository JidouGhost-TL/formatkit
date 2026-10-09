//! Allocation-free cursors for contiguous byte-wise bitstreams.

/// A byte-loaded, least-significant-bit-first cursor.
///
/// Reads are checked and transactional on exhaustion. Widths through 32 bits
/// are supported, including zero. The accumulator keeps scalar reads fast
/// across byte boundaries without allocation or dynamic dispatch.
#[derive(Debug, Clone)]
pub struct LsbBitCursor<'a> {
    bytes: &'a [u8],
    next_byte: usize,
    accumulator: u64,
    buffered_bits: u32,
    consumed_bits: u64,
}

impl<'a> LsbBitCursor<'a> {
    /// Start at bit zero of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            next_byte: 0,
            accumulator: 0,
            buffered_bits: 0,
            consumed_bits: 0,
        }
    }

    /// Read `width` bits LSB first. Returns `None` without changing the cursor
    /// when `width > 32` or the complete value is unavailable.
    pub fn read(&mut self, width: u32) -> Option<u32> {
        if width > 32 || u64::from(width) > self.remaining_bits() {
            return None;
        }
        while self.buffered_bits < width {
            let byte = self.bytes[self.next_byte];
            self.next_byte += 1;
            self.accumulator |= u64::from(byte) << self.buffered_bits;
            self.buffered_bits += 8;
        }
        let mask = if width == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << width) - 1
        };
        let value = (self.accumulator & mask) as u32;
        self.accumulator >>= width;
        self.buffered_bits -= width;
        self.consumed_bits += u64::from(width);
        Some(value)
    }

    /// Number of bits consumed, including explicit alignment skips.
    #[must_use]
    pub const fn position_bits(&self) -> u64 {
        self.consumed_bits
    }

    /// Number of bits still available from the current position.
    #[must_use]
    pub fn remaining_bits(&self) -> u64 {
        (self.bytes.len() as u64)
            .saturating_mul(8)
            .saturating_sub(self.consumed_bits)
    }

    /// Discard the remainder of the current byte. Scalar reads load only as
    /// many bytes as needed, so fewer than eight bits are discarded.
    pub fn align_to_byte(&mut self) {
        self.consumed_bits += u64::from(self.buffered_bits);
        self.accumulator = 0;
        self.buffered_bits = 0;
    }

    /// Read an exact byte slice at an aligned cursor and advance past it.
    /// Returns `None` without changing the cursor when unaligned, overflowing,
    /// or exhausted.
    pub fn read_aligned_bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        if self.buffered_bits != 0 {
            return None;
        }
        let end = self.next_byte.checked_add(length)?;
        let bytes = self.bytes.get(self.next_byte..end)?;
        let added_bits = u64::try_from(length).ok()?.checked_mul(8)?;
        self.next_byte = end;
        self.consumed_bits = self.consumed_bits.checked_add(added_bits)?;
        Some(bytes)
    }

    /// Byte extent touched by scalar reads or consumed by aligned reads. A
    /// partially consumed final byte counts in full.
    #[must_use]
    pub const fn byte_extent(&self) -> usize {
        self.next_byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(bytes: &[u8], start: u32, width: u32) -> u32 {
        let mut value = 0u32;
        for bit in 0..width {
            let position = start + bit;
            value |= u32::from((bytes[(position / 8) as usize] >> (position % 8)) & 1) << bit;
        }
        value
    }

    #[test]
    fn scalar_reads_match_a_per_bit_oracle_across_every_boundary() {
        let bytes = [0x81, 0x72, 0x4c, 0xe3, 0x19, 0xa5];
        for prefix in 0..8u32 {
            for width in 0..=32u32 {
                if prefix + width > bytes.len() as u32 * 8 {
                    continue;
                }
                let mut cursor = LsbBitCursor::new(&bytes);
                assert_eq!(cursor.read(prefix), Some(reference(&bytes, 0, prefix)));
                assert_eq!(cursor.read(width), Some(reference(&bytes, prefix, width)));
                assert_eq!(cursor.position_bits(), u64::from(prefix + width));
            }
        }
    }

    #[test]
    fn exhaustion_and_invalid_width_are_transactional() {
        let mut cursor = LsbBitCursor::new(&[0xaa]);
        assert_eq!(cursor.read(5), Some(0x0a));
        let position = cursor.position_bits();
        let extent = cursor.byte_extent();
        assert_eq!(cursor.read(4), None);
        assert_eq!(cursor.read(33), None);
        assert_eq!(
            (cursor.position_bits(), cursor.byte_extent()),
            (position, extent)
        );
        assert_eq!(cursor.remaining_bits(), 3);
    }

    #[test]
    fn alignment_and_aligned_reads_preserve_byte_extent() {
        let bytes = [0x07, 0x34, 0x12, 0xcb, 0xaa];
        let mut cursor = LsbBitCursor::new(&bytes);
        assert_eq!(cursor.read(3), Some(7));
        assert!(cursor.read_aligned_bytes(1).is_none());
        cursor.align_to_byte();
        assert_eq!(cursor.position_bits(), 8);
        assert_eq!(cursor.read_aligned_bytes(2), Some(&bytes[1..3]));
        assert_eq!(cursor.byte_extent(), 3);
        assert_eq!(cursor.read(4), Some(0x0b));
        cursor.align_to_byte();
        assert_eq!(cursor.read_aligned_bytes(1), Some(&bytes[4..5]));
        assert_eq!(cursor.remaining_bits(), 0);
    }
}
