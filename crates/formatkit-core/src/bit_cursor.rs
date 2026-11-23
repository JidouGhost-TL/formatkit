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

/// A byte-loaded, most-significant-bit-first cursor.
///
/// Mirror of [`LsbBitCursor`]: reads are checked and transactional on
/// exhaustion, supporting widths `0..=32` without allocation or dynamic
/// dispatch.
#[derive(Debug, Clone)]
pub struct MsbBitCursor<'a> {
    bytes: &'a [u8],
    next_byte: usize,
    accumulator: u64,
    buffered_bits: u32,
    consumed_bits: u64,
}

impl<'a> MsbBitCursor<'a> {
    /// Start at bit zero (most significant bit of byte zero) of `bytes`.
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

    /// Read `width` bits MSB first. Returns `None` without changing the cursor
    /// when `width > 32` or the complete value is unavailable.
    pub fn read(&mut self, width: u32) -> Option<u32> {
        if width > 32 || u64::from(width) > self.remaining_bits() {
            return None;
        }
        if width == 0 {
            return Some(0);
        }
        while self.buffered_bits < width {
            let byte = self.bytes[self.next_byte];
            self.next_byte += 1;
            self.accumulator = (self.accumulator << 8) | u64::from(byte);
            self.buffered_bits += 8;
        }
        let remaining = self.buffered_bits - width;
        let mask = if width == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << width) - 1
        };
        let value = ((self.accumulator >> remaining) & mask) as u32;
        self.buffered_bits = remaining;
        self.accumulator &= if remaining == 0 {
            0
        } else {
            (1u64 << remaining) - 1
        };
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

/// A contiguous, least-significant-bit-first bitstream writer.
///
/// Mirror of [`LsbBitCursor`]: bits are packed into each byte from bit 0
/// upward. Widths `0..=32` are supported. Any partial final byte is
/// zero-padded when [`Self::align_zero`] or [`Self::finish`] is called.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LsbBitWriter {
    bytes: Vec<u8>,
    accumulator: u64,
    buffered_bits: u32,
    written_bits: u64,
}

impl LsbBitWriter {
    /// Create an empty LSB-first bitstream writer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            accumulator: 0,
            buffered_bits: 0,
            written_bits: 0,
        }
    }

    /// Create an empty writer pre-allocated for at least `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            accumulator: 0,
            buffered_bits: 0,
            written_bits: 0,
        }
    }

    /// Append a single bit (`false` = `0`, `true` = `1`).
    pub fn write_bit(&mut self, bit: bool) {
        if bit {
            self.accumulator |= 1u64 << self.buffered_bits;
        }
        self.buffered_bits += 1;
        self.written_bits += 1;
        if self.buffered_bits == 8 {
            self.bytes.push((self.accumulator & 0xff) as u8);
            self.accumulator = 0;
            self.buffered_bits = 0;
        }
    }

    /// Append the lowest `width` bits of `value` LSB first.
    ///
    /// Returns [`crate::Error::InvalidField`] without mutating the writer when
    /// `width > 32`.
    pub fn write_bits(&mut self, value: u32, width: u32) -> crate::Result<()> {
        if width > 32 {
            return Err(crate::Error::InvalidField {
                what: "bit width",
                value: u64::from(width),
            });
        }
        if width == 0 {
            return Ok(());
        }
        let mask = if width == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << width) - 1
        };
        self.accumulator |= (u64::from(value) & mask) << self.buffered_bits;
        self.buffered_bits += width;
        self.written_bits += u64::from(width);
        while self.buffered_bits >= 8 {
            self.bytes.push((self.accumulator & 0xff) as u8);
            self.accumulator >>= 8;
            self.buffered_bits -= 8;
        }
        Ok(())
    }

    /// Zero-pad the current partial byte to a byte boundary.
    ///
    /// Does nothing if the writer is already byte-aligned.
    pub fn align_zero(&mut self) {
        if self.buffered_bits > 0 {
            let pad = 8 - self.buffered_bits;
            self.bytes.push((self.accumulator & 0xff) as u8);
            self.accumulator = 0;
            self.buffered_bits = 0;
            self.written_bits += u64::from(pad);
        }
    }

    /// Total number of bits written so far, including any explicit alignment padding.
    #[must_use]
    pub const fn bit_len(&self) -> u64 {
        self.written_bits
    }

    /// Flush any partial final byte with zero padding and return the encoded bytes.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.align_zero();
        self.bytes
    }
}

/// A contiguous, most-significant-bit-first bitstream writer.
///
/// Mirror of [`MsbBitCursor`]: bits are packed into each byte from bit 7
/// downward. Widths `0..=32` are supported. Any partial final byte is
/// zero-padded in its low bits when [`Self::align_zero`] or [`Self::finish`] is
/// called.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsbBitWriter {
    bytes: Vec<u8>,
    accumulator: u64,
    buffered_bits: u32,
    written_bits: u64,
}

impl MsbBitWriter {
    /// Create an empty MSB-first bitstream writer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            accumulator: 0,
            buffered_bits: 0,
            written_bits: 0,
        }
    }

    /// Create an empty writer pre-allocated for at least `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            accumulator: 0,
            buffered_bits: 0,
            written_bits: 0,
        }
    }

    /// Append a single bit (`false` = `0`, `true` = `1`).
    pub fn write_bit(&mut self, bit: bool) {
        self.accumulator = (self.accumulator << 1) | u64::from(bit);
        self.buffered_bits += 1;
        self.written_bits += 1;
        if self.buffered_bits == 8 {
            self.bytes.push((self.accumulator & 0xff) as u8);
            self.accumulator = 0;
            self.buffered_bits = 0;
        }
    }

    /// Append the lowest `width` bits of `value` MSB first (bit `width - 1` down to bit `0`).
    ///
    /// Returns [`crate::Error::InvalidField`] without mutating the writer when
    /// `width > 32`.
    pub fn write_bits(&mut self, value: u32, width: u32) -> crate::Result<()> {
        if width > 32 {
            return Err(crate::Error::InvalidField {
                what: "bit width",
                value: u64::from(width),
            });
        }
        if width == 0 {
            return Ok(());
        }
        let mask = if width == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << width) - 1
        };
        self.accumulator = (self.accumulator << width) | (u64::from(value) & mask);
        self.buffered_bits += width;
        self.written_bits += u64::from(width);
        while self.buffered_bits >= 8 {
            self.buffered_bits -= 8;
            self.bytes
                .push(((self.accumulator >> self.buffered_bits) & 0xff) as u8);
        }
        self.accumulator &= if self.buffered_bits == 0 {
            0
        } else {
            (1u64 << self.buffered_bits) - 1
        };
        Ok(())
    }

    /// Zero-pad the current partial byte to a byte boundary.
    ///
    /// Does nothing if the writer is already byte-aligned.
    pub fn align_zero(&mut self) {
        if self.buffered_bits > 0 {
            let pad = 8 - self.buffered_bits;
            self.bytes.push(((self.accumulator << pad) & 0xff) as u8);
            self.accumulator = 0;
            self.buffered_bits = 0;
            self.written_bits += u64::from(pad);
        }
    }

    /// Total number of bits written so far, including any explicit alignment padding.
    #[must_use]
    pub const fn bit_len(&self) -> u64 {
        self.written_bits
    }

    /// Flush any partial final byte with zero padding and return the encoded bytes.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.align_zero();
        self.bytes
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

    fn reference_msb(bytes: &[u8], start: u32, width: u32) -> u32 {
        let mut value = 0u32;
        for bit in 0..width {
            let position = start + bit;
            let shift = 7 - (position % 8);
            value = (value << 1) | u32::from((bytes[(position / 8) as usize] >> shift) & 1);
        }
        value
    }

    #[test]
    fn msb_scalar_reads_match_a_per_bit_oracle_across_every_boundary() {
        let bytes = [0x81, 0x72, 0x4c, 0xe3, 0x19, 0xa5];
        for prefix in 0..8u32 {
            for width in 0..=32u32 {
                if prefix + width > bytes.len() as u32 * 8 {
                    continue;
                }
                let mut cursor = MsbBitCursor::new(&bytes);
                assert_eq!(cursor.read(prefix), Some(reference_msb(&bytes, 0, prefix)));
                assert_eq!(
                    cursor.read(width),
                    Some(reference_msb(&bytes, prefix, width))
                );
                assert_eq!(cursor.position_bits(), u64::from(prefix + width));
            }
        }
    }

    #[test]
    fn msb_exhaustion_alignment_and_aligned_reads_preserve_byte_extent() {
        let bytes = [0b1110_0000, 0x34, 0x12, 0xcb, 0xaa];
        let mut cursor = MsbBitCursor::new(&bytes);
        assert_eq!(cursor.read(3), Some(0b111));
        assert!(cursor.read_aligned_bytes(1).is_none());
        assert_eq!(cursor.read(33), None);
        assert_eq!(cursor.position_bits(), 3);
        cursor.align_to_byte();
        assert_eq!(cursor.position_bits(), 8);
        assert_eq!(cursor.read_aligned_bytes(2), Some(&bytes[1..3]));
        assert_eq!(cursor.byte_extent(), 3);
        assert_eq!(cursor.read(4), Some(0x0c));
        assert_eq!(cursor.read(13), None);
        assert_eq!(cursor.remaining_bits(), 12);
        cursor.align_to_byte();
        assert_eq!(cursor.read_aligned_bytes(1), Some(&bytes[4..5]));
        assert_eq!(cursor.remaining_bits(), 0);
    }

    #[test]
    fn lsb_writer_round_trips_with_cursor_across_widths_and_alignment() {
        let mut w = LsbBitWriter::new();
        assert_eq!(w.bit_len(), 0);
        w.write_bits(0, 0).unwrap();
        assert_eq!(w.bit_len(), 0);
        assert!(w.write_bits(1, 33).is_err());
        assert_eq!(w.bit_len(), 0);

        w.write_bit(true);
        w.write_bit(false);
        w.write_bit(true);
        assert_eq!(w.bit_len(), 3);
        w.write_bits(0xDEAD_BEEF, 32).unwrap();
        assert_eq!(w.bit_len(), 35);
        w.align_zero();
        assert_eq!(w.bit_len(), 40);
        w.align_zero();
        assert_eq!(w.bit_len(), 40);
        w.write_bits(0b1_0110, 5).unwrap();
        assert_eq!(w.bit_len(), 45);
        let bytes = w.finish();
        assert_eq!(bytes.len(), 6);

        let mut c = LsbBitCursor::new(&bytes);
        assert_eq!(c.read(1), Some(1));
        assert_eq!(c.read(1), Some(0));
        assert_eq!(c.read(1), Some(1));
        assert_eq!(c.read(32), Some(0xDEAD_BEEF));
        assert_eq!(c.read(5), Some(0));
        assert_eq!(c.read(5), Some(0b1_0110));
        assert_eq!(c.read(3), Some(0));
        assert_eq!(c.remaining_bits(), 0);
    }

    #[test]
    fn msb_writer_round_trips_with_cursor_across_widths_and_alignment() {
        let mut w = MsbBitWriter::with_capacity(8);
        assert_eq!(w.bit_len(), 0);
        w.write_bits(0, 0).unwrap();
        assert!(w.write_bits(1, 33).is_err());
        assert_eq!(w.bit_len(), 0);

        w.write_bit(true);
        w.write_bit(false);
        w.write_bit(true);
        w.write_bits(0xCAFE_BABE, 32).unwrap();
        assert_eq!(w.bit_len(), 35);
        w.align_zero();
        assert_eq!(w.bit_len(), 40);
        w.write_bits(0b1_0110, 5).unwrap();
        assert_eq!(w.bit_len(), 45);
        let bytes = w.finish();
        assert_eq!(bytes.len(), 6);

        let mut c = MsbBitCursor::new(&bytes);
        assert_eq!(c.read(1), Some(1));
        assert_eq!(c.read(1), Some(0));
        assert_eq!(c.read(1), Some(1));
        assert_eq!(c.read(32), Some(0xCAFE_BABE));
        assert_eq!(c.read(5), Some(0));
        assert_eq!(c.read(5), Some(0b1_0110));
        assert_eq!(c.read(3), Some(0));
        assert_eq!(c.remaining_bits(), 0);
    }
}
