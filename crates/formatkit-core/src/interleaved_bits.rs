//! Control-bit streams whose operand bytes share the control-byte cursor.
//!
//! These cursors are deliberately separate from [`crate::LsbBitCursor`]. A
//! raw byte may be consumed while control bits from an earlier byte remain
//! buffered; the next control byte is fetched from the then-current stream
//! position only after that buffered group is exhausted.

/// Reader for an interleaved control-bit/raw-byte stream.
///
/// `MSB_FIRST` selects the order of bits within each control byte. Reads are
/// allocation-free. Exhausted control and raw-byte reads leave the cursor
/// unchanged.
#[derive(Debug, Clone)]
pub struct InterleavedBitReader<'a, const MSB_FIRST: bool> {
    bytes: &'a [u8],
    origin: usize,
    next_byte: usize,
    control: u8,
    control_bits_left: u8,
}

/// MSB-first interleaved stream reader.
pub type MsbInterleavedBitReader<'a> = InterleavedBitReader<'a, true>;
/// LSB-first interleaved stream reader.
pub type LsbInterleavedBitReader<'a> = InterleavedBitReader<'a, false>;

impl<'a, const MSB_FIRST: bool> InterleavedBitReader<'a, MSB_FIRST> {
    /// Start at byte zero. The first control byte is loaded lazily.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            origin: 0,
            next_byte: 0,
            control: 0,
            control_bits_left: 0,
        }
    }

    /// Start at an absolute byte position, returning `None` when it lies past
    /// the input. A position exactly at EOF is valid but cannot yield data.
    #[must_use]
    pub fn at(bytes: &'a [u8], position: usize) -> Option<Self> {
        (position <= bytes.len()).then_some(Self {
            bytes,
            origin: position,
            next_byte: position,
            control: 0,
            control_bits_left: 0,
        })
    }

    /// Consume one control bit, loading a new control byte only when the prior
    /// one has no bits left.
    pub fn read_bit(&mut self) -> Option<bool> {
        if self.control_bits_left == 0 {
            let control = *self.bytes.get(self.next_byte)?;
            self.control = control;
            self.next_byte += 1;
            self.control_bits_left = 8;
        }
        let shift = if MSB_FIRST {
            self.control_bits_left - 1
        } else {
            8 - self.control_bits_left
        };
        let bit = self.control & (1 << shift) != 0;
        self.control_bits_left -= 1;
        Some(bit)
    }

    /// Consume the next raw byte without discarding buffered control bits.
    pub fn read_byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.next_byte)?;
        self.next_byte += 1;
        Some(byte)
    }

    /// Consume an exact raw-byte slice without discarding buffered control
    /// bits. Overflow or exhaustion leaves the cursor unchanged.
    pub fn read_bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.next_byte.checked_add(length)?;
        let bytes = self.bytes.get(self.next_byte..end)?;
        self.next_byte = end;
        Some(bytes)
    }

    /// Absolute position of the next control or raw byte in the source.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.next_byte
    }

    /// Number of source bytes consumed since construction.
    #[must_use]
    pub const fn byte_extent(&self) -> usize {
        self.next_byte - self.origin
    }

    /// Control bits still buffered from the last loaded control byte.
    #[must_use]
    pub const fn buffered_control_bits(&self) -> u8 {
        self.control_bits_left
    }
}

/// Writer for an interleaved control-bit/raw-byte stream.
///
/// A control-byte slot is reserved at the current stream end when its first bit
/// is written. Raw bytes are then appended while that slot continues to fill.
/// `MSB_FIRST` selects the order of bits within each control byte.
#[derive(Debug, Clone, Default)]
pub struct InterleavedBitWriter<const MSB_FIRST: bool> {
    bytes: Vec<u8>,
    control_position: usize,
    control_mask: u8,
}

/// MSB-first interleaved stream writer.
pub type MsbInterleavedBitWriter = InterleavedBitWriter<true>;
/// LSB-first interleaved stream writer.
pub type LsbInterleavedBitWriter = InterleavedBitWriter<false>;

impl<const MSB_FIRST: bool> InterleavedBitWriter<MSB_FIRST> {
    /// Create an empty stream.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            control_position: 0,
            control_mask: 0,
        }
    }

    /// Create an empty stream with storage for at least `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            control_position: 0,
            control_mask: 0,
        }
    }

    /// Reserve exact additional byte capacity, forwarding `Vec`'s allocation
    /// failure without changing the stream.
    pub fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> std::result::Result<(), std::collections::TryReserveError> {
        self.bytes.try_reserve_exact(additional)
    }

    /// Append one control bit.
    pub fn write_bit(&mut self, bit: bool) {
        if self.control_mask == 0 {
            self.control_position = self.bytes.len();
            self.bytes.push(0);
            self.control_mask = if MSB_FIRST { 0x80 } else { 0x01 };
        }
        if bit {
            self.bytes[self.control_position] |= self.control_mask;
        }
        if MSB_FIRST {
            self.control_mask >>= 1;
        } else {
            self.control_mask <<= 1;
        }
    }

    /// Append one raw byte while retaining the current control group.
    pub fn write_byte(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    /// Append raw bytes while retaining the current control group.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Current encoded byte extent.
    #[must_use]
    pub const fn byte_extent(&self) -> usize {
        self.bytes.len()
    }

    /// Control bits already written into the current control byte.
    #[must_use]
    pub const fn buffered_control_bits(&self) -> u8 {
        if self.control_mask == 0 {
            0
        } else if MSB_FIRST {
            7 - self.control_mask.trailing_zeros() as u8
        } else {
            self.control_mask.trailing_zeros() as u8
        }
    }

    /// Borrow the complete stream. Partially filled control bytes are already
    /// patched and unused bits are zero.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Finish and return the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct FrozenReader<'a, const MSB_FIRST: bool> {
        bytes: &'a [u8],
        position: usize,
        control: u8,
        bits_left: u8,
    }

    impl<'a, const MSB_FIRST: bool> FrozenReader<'a, MSB_FIRST> {
        fn new(bytes: &'a [u8], position: usize) -> Self {
            Self {
                bytes,
                position,
                control: 0,
                bits_left: 0,
            }
        }

        fn bit(&mut self) -> Option<bool> {
            if self.bits_left == 0 {
                self.control = *self.bytes.get(self.position)?;
                self.position += 1;
                self.bits_left = 8;
            }
            let shift = if MSB_FIRST {
                self.bits_left - 1
            } else {
                8 - self.bits_left
            };
            let bit = self.control & (1 << shift) != 0;
            self.bits_left -= 1;
            Some(bit)
        }

        fn byte(&mut self) -> Option<u8> {
            let byte = *self.bytes.get(self.position)?;
            self.position += 1;
            Some(byte)
        }
    }

    fn reference<const MSB_FIRST: bool>(steps: &[(bool, u8)]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut control_position = None;
        let mut used = 0u8;
        for &(is_bit, value) in steps {
            if is_bit {
                let position = match control_position {
                    Some(position) if used < 8 => position,
                    _ => {
                        let position = output.len();
                        output.push(0);
                        control_position = Some(position);
                        used = 0;
                        position
                    }
                };
                if value != 0 {
                    let shift = if MSB_FIRST { 7 - used } else { used };
                    output[position] |= 1 << shift;
                }
                used += 1;
            } else {
                output.push(value);
            }
        }
        output
    }

    fn writer_matches_frozen_oracle<const MSB_FIRST: bool>() {
        let mut state = 0x1357_2468u32;
        for length in 0..256usize {
            let mut steps = Vec::new();
            let mut writer = InterleavedBitWriter::<MSB_FIRST>::new();
            for index in 0..length {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if index % 3 == 0 || state & 3 == 0 {
                    let bit = (state >> 31) != 0;
                    steps.push((true, u8::from(bit)));
                    writer.write_bit(bit);
                } else {
                    let byte = (state >> 16) as u8;
                    steps.push((false, byte));
                    writer.write_byte(byte);
                }
            }
            assert_eq!(writer.as_bytes(), reference::<MSB_FIRST>(&steps));
            assert_eq!(writer.byte_extent(), writer.as_bytes().len());
        }
    }

    fn reader_matches_frozen_oracle<const MSB_FIRST: bool>() {
        let mut source = [0u8; 96];
        let mut state = 0xc001_d00du32;
        for byte in &mut source {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *byte = (state >> 16) as u8;
        }
        for origin in 0..=source.len() {
            let mut shared = InterleavedBitReader::<MSB_FIRST>::at(&source, origin).unwrap();
            let mut frozen = FrozenReader::<MSB_FIRST>::new(&source, origin);
            for step in 0..320u32 {
                state = state.rotate_left(5) ^ step.wrapping_mul(0x9e37_79b9);
                if state & 3 == 0 {
                    assert_eq!(shared.read_byte(), frozen.byte());
                } else {
                    assert_eq!(shared.read_bit(), frozen.bit());
                }
                assert_eq!(shared.position(), frozen.position);
                assert_eq!(shared.byte_extent(), frozen.position - origin);
                assert_eq!(shared.buffered_control_bits(), frozen.bits_left);
            }
        }
    }

    #[test]
    fn both_writer_orders_match_frozen_oracles() {
        writer_matches_frozen_oracle::<true>();
        writer_matches_frozen_oracle::<false>();
    }

    #[test]
    fn both_reader_orders_match_frozen_oracles() {
        reader_matches_frozen_oracle::<true>();
        reader_matches_frozen_oracle::<false>();
    }

    #[test]
    fn readers_preserve_control_bits_across_raw_bytes() {
        let bytes = [0xa5, 0x11, 0x22, 0x3c, 0x33];
        let mut msb = MsbInterleavedBitReader::new(&bytes);
        assert_eq!(msb.read_bit(), Some(true));
        assert_eq!(msb.read_bytes(2), Some(&bytes[1..3]));
        assert_eq!(
            (0..7).map(|_| msb.read_bit()).collect::<Vec<_>>(),
            [
                Some(false),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
                Some(false),
                Some(true)
            ]
        );
        assert_eq!(msb.read_bit(), Some(false));
        assert_eq!(msb.read_byte(), Some(0x33));
        assert_eq!(msb.byte_extent(), bytes.len());

        let mut lsb = LsbInterleavedBitReader::new(&bytes);
        assert_eq!(
            (0..4).map(|_| lsb.read_bit()).collect::<Vec<_>>(),
            [Some(true), Some(false), Some(true), Some(false)]
        );
        assert_eq!(lsb.read_byte(), Some(0x11));
        assert_eq!(lsb.position(), 2);
        assert_eq!(lsb.buffered_control_bits(), 4);
    }

    #[test]
    fn exhaustion_and_overflow_are_transactional() {
        let bytes = [0x80, 0x00];
        let mut reader = MsbInterleavedBitReader::at(&bytes, 1).unwrap();
        assert_eq!(reader.read_bit(), Some(false));
        let before = (
            reader.position(),
            reader.byte_extent(),
            reader.buffered_control_bits(),
        );
        assert_eq!(reader.read_bytes(usize::MAX), None);
        assert_eq!(reader.read_byte(), None);
        assert_eq!(
            (
                reader.position(),
                reader.byte_extent(),
                reader.buffered_control_bits(),
            ),
            before
        );
        for _ in 0..7 {
            assert_eq!(reader.read_bit(), Some(false));
        }
        let before = (reader.position(), reader.buffered_control_bits());
        assert_eq!(reader.read_bit(), None);
        assert_eq!((reader.position(), reader.buffered_control_bits()), before);
        assert!(MsbInterleavedBitReader::at(&bytes, bytes.len() + 1).is_none());
    }

    #[test]
    fn partial_control_bytes_are_visible_without_finish_work() {
        let mut writer = LsbInterleavedBitWriter::with_capacity(4);
        writer.write_bit(true);
        writer.write_byte(0x55);
        writer.write_bit(true);
        writer.write_bytes(&[0xaa, 0xbb]);
        assert_eq!(writer.as_bytes(), [0x03, 0x55, 0xaa, 0xbb]);
        assert_eq!(writer.buffered_control_bits(), 2);
        assert_eq!(writer.into_bytes(), [0x03, 0x55, 0xaa, 0xbb]);
    }
}
