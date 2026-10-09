//! Configured fields within resident byte layouts.

use formatkit_core::{bytes_at, bytes_at_mut, u32_at_endian, u64_at_endian, Endian, Error, Result};

/// A configured unsigned byte field.
///
/// The descriptor owns only the field's byte offset. Its format owner remains
/// responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U8Field {
    offset: usize,
}

impl U8Field {
    /// Configure the byte offset of the field.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<u8> {
        Ok(bytes_at(bytes, self.offset, 1)?[0])
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> u8 {
        assert!(self.offset < WIDTH, "u8 field exceeds record");
        bytes[self.offset]
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: u8) -> Result<()> {
        bytes_at_mut(bytes, self.offset, 1)?[0] = value;
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: u8) {
        assert!(self.offset < WIDTH, "u8 field exceeds record");
        bytes[self.offset] = value;
    }
}

/// A configured signed byte field.
///
/// The descriptor owns only the field's byte offset. Its format owner remains
/// responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I8Field {
    offset: usize,
}

impl I8Field {
    /// Configure the byte offset of the field.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<i8> {
        Ok(bytes_at(bytes, self.offset, 1)?[0] as i8)
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> i8 {
        assert!(self.offset < WIDTH, "i8 field exceeds record");
        bytes[self.offset] as i8
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: i8) -> Result<()> {
        bytes_at_mut(bytes, self.offset, 1)?[0] = value as u8;
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: i8) {
        assert!(self.offset < WIDTH, "i8 field exceeds record");
        bytes[self.offset] = value as u8;
    }
}

/// A configured 16-bit unsigned field.
///
/// The descriptor owns only the field's byte offset and encoding. Its format
/// owner remains responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16Field {
    offset: usize,
    endian: Endian,
}

impl U16Field {
    /// Configure the byte offset and byte order of the field.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<u16> {
        let encoded = bytes_at(bytes, self.offset, 2)?.try_into().unwrap();
        Ok(self.decode(encoded))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> u16 {
        assert!(
            self.offset.checked_add(2).is_some_and(|end| end <= WIDTH),
            "u16 field exceeds record"
        );
        self.decode(bytes[self.offset..self.offset + 2].try_into().unwrap())
    }

    #[inline(always)]
    fn decode(self, encoded: [u8; 2]) -> u16 {
        match self.endian {
            Endian::Little => u16::from_le_bytes(encoded),
            Endian::Big => u16::from_be_bytes(encoded),
        }
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: u16) -> Result<()> {
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes_at_mut(bytes, self.offset, 2)?.copy_from_slice(&encoded);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: u16) {
        assert!(
            self.offset.checked_add(2).is_some_and(|end| end <= WIDTH),
            "u16 field exceeds record"
        );
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes[self.offset..self.offset + 2].copy_from_slice(&encoded);
    }
}

/// A configured 16-bit signed field.
///
/// The descriptor owns only the field's byte offset and encoding. Its format
/// owner remains responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I16Field {
    offset: usize,
    endian: Endian,
}

impl I16Field {
    /// Configure the byte offset and byte order of the field.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<i16> {
        let encoded = bytes_at(bytes, self.offset, 2)?.try_into().unwrap();
        Ok(self.decode(encoded))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> i16 {
        assert!(
            self.offset.checked_add(2).is_some_and(|end| end <= WIDTH),
            "i16 field exceeds record"
        );
        self.decode(bytes[self.offset..self.offset + 2].try_into().unwrap())
    }

    #[inline(always)]
    fn decode(self, encoded: [u8; 2]) -> i16 {
        match self.endian {
            Endian::Little => i16::from_le_bytes(encoded),
            Endian::Big => i16::from_be_bytes(encoded),
        }
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: i16) -> Result<()> {
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes_at_mut(bytes, self.offset, 2)?.copy_from_slice(&encoded);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: i16) {
        assert!(
            self.offset.checked_add(2).is_some_and(|end| end <= WIDTH),
            "i16 field exceeds record"
        );
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes[self.offset..self.offset + 2].copy_from_slice(&encoded);
    }
}

/// A configured 32-bit unsigned field.
///
/// The descriptor owns only the field's byte offset and encoding. Its format
/// owner remains responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32Field {
    offset: usize,
    endian: Endian,
}

impl U32Field {
    /// Configure the byte offset and byte order of the field.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<u32> {
        u32_at_endian(bytes, self.offset, self.endian)
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> u32 {
        assert!(
            self.offset.checked_add(4).is_some_and(|end| end <= WIDTH),
            "u32 field exceeds record"
        );
        u32_at_endian(bytes, self.offset, self.endian).expect("validated u32 record field")
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: u32) -> Result<()> {
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes_at_mut(bytes, self.offset, 4)?.copy_from_slice(&encoded);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the destination bytes.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: u32) {
        assert!(
            self.offset.checked_add(4).is_some_and(|end| end <= WIDTH),
            "u32 field exceeds record"
        );
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes[self.offset..self.offset + 4].copy_from_slice(&encoded);
    }
}

/// A configured `u32` field whose stored value counts fixed-size byte units.
///
/// This descriptor owns only the exact, reversible relationship
/// `byte_value = stored_value * unit`. It assigns no base address, sentinel,
/// alignment, ordering, containment, or extent policy to the decoded value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaledU32Field {
    raw: U32Field,
    unit: u64,
}

impl ScaledU32Field {
    /// Configure the field position, byte order, and nonzero byte unit.
    ///
    /// A zero unit is a static descriptor error and panics.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian, unit: u64) -> Self {
        assert!(unit != 0, "scaled u32 field unit must be nonzero");
        Self {
            raw: U32Field::new(offset, endian),
            unit,
        }
    }

    /// Read and scale the stored word from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<u64> {
        self.scale(self.raw.read(bytes)?)
    }

    /// Read and scale after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. Scaling overflow is
    /// reported as malformed input.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> Result<u64> {
        self.scale(self.raw.read_record(bytes))
    }

    /// Read, scale, and add an owner-supplied absolute base.
    #[inline]
    pub fn read_relative(self, bytes: &[u8], base: u64) -> Result<u64> {
        self.add_base(self.read(bytes)?, base)
    }

    /// Read, scale, and add an owner-supplied base after bounding a record.
    #[inline(always)]
    pub fn read_record_relative<const WIDTH: usize>(
        self,
        bytes: &[u8; WIDTH],
        base: u64,
    ) -> Result<u64> {
        self.add_base(self.read_record(bytes)?, base)
    }

    /// Encode and write an exact byte value without changing surrounding bytes.
    ///
    /// Values that are not an integral number of units or whose quotient does
    /// not fit the stored `u32` are rejected before the destination is changed.
    #[inline]
    pub fn write(self, bytes: &mut [u8], byte_value: u64) -> Result<()> {
        self.raw.write(bytes, self.unscale(byte_value)?)
    }

    /// Encode and write after the enclosing record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. Non-integral or
    /// unrepresentable byte values are returned as errors without mutation.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(
        self,
        bytes: &mut [u8; WIDTH],
        byte_value: u64,
    ) -> Result<()> {
        let raw = self.unscale(byte_value)?;
        self.raw.write_record(bytes, raw);
        Ok(())
    }

    /// Subtract an owner-supplied base and encode the remaining exact scaled
    /// value. Underflow, unit mismatch, and representation overflow are
    /// rejected before the destination is changed.
    #[inline]
    pub fn write_relative(self, bytes: &mut [u8], base: u64, absolute: u64) -> Result<()> {
        self.write(bytes, self.subtract_base(base, absolute)?)
    }

    /// Base-relative counterpart to [`Self::write_record`].
    #[inline(always)]
    pub fn write_record_relative<const WIDTH: usize>(
        self,
        bytes: &mut [u8; WIDTH],
        base: u64,
        absolute: u64,
    ) -> Result<()> {
        self.write_record(bytes, self.subtract_base(base, absolute)?)
    }

    #[inline(always)]
    fn add_base(self, relative: u64, base: u64) -> Result<u64> {
        base.checked_add(relative).ok_or(Error::InvalidField {
            what: "base-relative scaled u32 addition",
            value: relative,
        })
    }

    #[inline(always)]
    fn subtract_base(self, base: u64, absolute: u64) -> Result<u64> {
        absolute.checked_sub(base).ok_or(Error::InvalidField {
            what: "base-relative scaled u32 absolute value",
            value: absolute,
        })
    }

    #[inline(always)]
    fn scale(self, raw: u32) -> Result<u64> {
        u64::from(raw)
            .checked_mul(self.unit)
            .ok_or(Error::InvalidField {
                what: "scaled u32 multiplication",
                value: u64::from(raw),
            })
    }

    #[inline(always)]
    fn unscale(self, byte_value: u64) -> Result<u32> {
        if !byte_value.is_multiple_of(self.unit) {
            return Err(Error::InvalidField {
                what: "scaled u32 exact byte value",
                value: byte_value,
            });
        }
        u32::try_from(byte_value / self.unit).map_err(|_| Error::InvalidField {
            what: "scaled u32 stored value",
            value: byte_value,
        })
    }
}

/// A configured 32-bit signed field.
///
/// The descriptor owns only the field's byte offset and encoding. Its format
/// owner remains responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I32Field {
    offset: usize,
    endian: Endian,
}

impl I32Field {
    /// Configure the byte offset and byte order of the field.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<i32> {
        Ok(u32_at_endian(bytes, self.offset, self.endian)? as i32)
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> i32 {
        assert!(
            self.offset.checked_add(4).is_some_and(|end| end <= WIDTH),
            "i32 field exceeds record"
        );
        u32_at_endian(bytes, self.offset, self.endian).expect("validated i32 record field") as i32
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: i32) -> Result<()> {
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes_at_mut(bytes, self.offset, 4)?.copy_from_slice(&encoded);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: i32) {
        assert!(
            self.offset.checked_add(4).is_some_and(|end| end <= WIDTH),
            "i32 field exceeds record"
        );
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes[self.offset..self.offset + 4].copy_from_slice(&encoded);
    }
}

/// A configured 64-bit unsigned field.
///
/// The descriptor owns only the field's byte offset and encoding. Its format
/// owner remains responsible for assigning meaning and validating the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U64Field {
    offset: usize,
    endian: Endian,
}

impl U64Field {
    /// Configure the byte offset and byte order of the field.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<u64> {
        u64_at_endian(bytes, self.offset, self.endian)
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> u64 {
        assert!(
            self.offset.checked_add(8).is_some_and(|end| end <= WIDTH),
            "u64 field exceeds record"
        );
        u64_at_endian(bytes, self.offset, self.endian).expect("validated u64 record field")
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: u64) -> Result<()> {
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes_at_mut(bytes, self.offset, 8)?.copy_from_slice(&encoded);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: u64) {
        assert!(
            self.offset.checked_add(8).is_some_and(|end| end <= WIDTH),
            "u64 field exceeds record"
        );
        let encoded = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        bytes[self.offset..self.offset + 8].copy_from_slice(&encoded);
    }
}

/// A configured raw IEEE-754 single-precision field.
///
/// The descriptor assigns no finite-value, coordinate, or numeric policy. All
/// bit patterns, including signed zero and NaN payloads, round-trip unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F32Field {
    offset: usize,
    endian: Endian,
}

impl F32Field {
    /// Configure the byte offset and byte order of the field.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    /// Read the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<f32> {
        Ok(f32::from_bits(u32_at_endian(
            bytes,
            self.offset,
            self.endian,
        )?))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> f32 {
        assert!(
            self.offset.checked_add(4).is_some_and(|end| end <= WIDTH),
            "f32 field exceeds record"
        );
        f32::from_bits(
            u32_at_endian(bytes, self.offset, self.endian).expect("validated f32 record field"),
        )
    }

    /// Write the field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: f32) -> Result<()> {
        let encoded = match self.endian {
            Endian::Little => value.to_bits().to_le_bytes(),
            Endian::Big => value.to_bits().to_be_bytes(),
        };
        bytes_at_mut(bytes, self.offset, 4)?.copy_from_slice(&encoded);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: f32) {
        assert!(
            self.offset.checked_add(4).is_some_and(|end| end <= WIDTH),
            "f32 field exceeds record"
        );
        let encoded = match self.endian {
            Endian::Little => value.to_bits().to_le_bytes(),
            Endian::Big => value.to_bits().to_be_bytes(),
        };
        bytes[self.offset..self.offset + 4].copy_from_slice(&encoded);
    }
}

/// A configured fixed-width byte field.
///
/// This descriptor provides placement only. String encoding, termination,
/// padding, masks, and all other meaning remain format-owner policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytesField<const N: usize> {
    offset: usize,
}

impl<const N: usize> BytesField<N> {
    /// Configure the byte offset of the fixed-width field.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Borrow the field from an arbitrary resident carrier.
    #[inline]
    pub fn read(self, bytes: &[u8]) -> Result<&[u8; N]> {
        Ok(bytes_at(bytes, self.offset, N)?.try_into().unwrap())
    }

    /// Borrow after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`. That is a static
    /// descriptor error, rather than a property of the input bytes.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> &[u8; N] {
        let end = self.offset.checked_add(N).expect("byte field end overflow");
        assert!(end <= WIDTH, "byte field exceeds record");
        bytes[self.offset..end].try_into().unwrap()
    }

    /// Write the exact field without changing any surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], value: &[u8; N]) -> Result<()> {
        bytes_at_mut(bytes, self.offset, N)?.copy_from_slice(value);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured field exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], value: &[u8; N]) {
        let end = self.offset.checked_add(N).expect("byte field end overflow");
        assert!(end <= WIDTH, "byte field exceeds record");
        bytes[self.offset..end].copy_from_slice(value);
    }
}

/// A configured contiguous array of 16-bit unsigned fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16ArrayField<const N: usize> {
    offset: usize,
    endian: Endian,
}

impl<const N: usize> U16ArrayField<N> {
    /// Configure the byte offset and byte order of the array.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    fn width(self) -> Result<usize> {
        N.checked_mul(2).ok_or(Error::InvalidField {
            what: "u16 array width",
            value: N as u64,
        })
    }

    /// Read the array from an arbitrary resident carrier.
    pub fn read(self, bytes: &[u8]) -> Result<[u16; N]> {
        let field = bytes_at(bytes, self.offset, self.width()?)?;
        Ok(std::array::from_fn(|index| {
            let encoded = field[index * 2..index * 2 + 2].try_into().unwrap();
            match self.endian {
                Endian::Little => u16::from_le_bytes(encoded),
                Endian::Big => u16::from_be_bytes(encoded),
            }
        }))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH` or its static width
    /// overflows `usize`.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> [u16; N] {
        let width = N.checked_mul(2).expect("u16 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("u16 array end overflow");
        assert!(end <= WIDTH, "u16 array field exceeds record");
        std::array::from_fn(|index| {
            let offset = self.offset + index * 2;
            let encoded = bytes[offset..offset + 2].try_into().unwrap();
            match self.endian {
                Endian::Little => u16::from_le_bytes(encoded),
                Endian::Big => u16::from_be_bytes(encoded),
            }
        })
    }

    /// Write every array element without changing surrounding bytes.
    pub fn write(self, bytes: &mut [u8], values: [u16; N]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, self.width()?)?;
        self.write_bounded(field, values);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], values: [u16; N]) {
        let width = N.checked_mul(2).expect("u16 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("u16 array end overflow");
        assert!(end <= WIDTH, "u16 array field exceeds record");
        self.write_bounded(&mut bytes[self.offset..end], values);
    }

    #[inline(always)]
    fn write_bounded(self, field: &mut [u8], values: [u16; N]) {
        for (slot, value) in field.chunks_exact_mut(2).zip(values) {
            let encoded = match self.endian {
                Endian::Little => value.to_le_bytes(),
                Endian::Big => value.to_be_bytes(),
            };
            slot.copy_from_slice(&encoded);
        }
    }
}

/// A configured contiguous array of 16-bit signed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I16ArrayField<const N: usize> {
    offset: usize,
    endian: Endian,
}

impl<const N: usize> I16ArrayField<N> {
    /// Configure the byte offset and byte order of the array.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    fn width(self) -> Result<usize> {
        N.checked_mul(2).ok_or(Error::InvalidField {
            what: "i16 array width",
            value: N as u64,
        })
    }

    /// Read the array from an arbitrary resident carrier.
    pub fn read(self, bytes: &[u8]) -> Result<[i16; N]> {
        let field = bytes_at(bytes, self.offset, self.width()?)?;
        Ok(std::array::from_fn(|index| {
            let encoded = field[index * 2..index * 2 + 2].try_into().unwrap();
            match self.endian {
                Endian::Little => i16::from_le_bytes(encoded),
                Endian::Big => i16::from_be_bytes(encoded),
            }
        }))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH` or its static width
    /// overflows `usize`.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> [i16; N] {
        let width = N.checked_mul(2).expect("i16 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("i16 array end overflow");
        assert!(end <= WIDTH, "i16 array field exceeds record");
        std::array::from_fn(|index| {
            let offset = self.offset + index * 2;
            let encoded = bytes[offset..offset + 2].try_into().unwrap();
            match self.endian {
                Endian::Little => i16::from_le_bytes(encoded),
                Endian::Big => i16::from_be_bytes(encoded),
            }
        })
    }

    /// Write every array element without changing surrounding bytes.
    pub fn write(self, bytes: &mut [u8], values: [i16; N]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, self.width()?)?;
        self.write_bounded(field, values);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], values: [i16; N]) {
        let width = N.checked_mul(2).expect("i16 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("i16 array end overflow");
        assert!(end <= WIDTH, "i16 array field exceeds record");
        self.write_bounded(&mut bytes[self.offset..end], values);
    }

    #[inline(always)]
    fn write_bounded(self, field: &mut [u8], values: [i16; N]) {
        for (slot, value) in field.chunks_exact_mut(2).zip(values) {
            let encoded = match self.endian {
                Endian::Little => value.to_le_bytes(),
                Endian::Big => value.to_be_bytes(),
            };
            slot.copy_from_slice(&encoded);
        }
    }
}

/// A configured contiguous array of 32-bit unsigned fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32ArrayField<const N: usize> {
    offset: usize,
    endian: Endian,
}

impl<const N: usize> U32ArrayField<N> {
    /// Configure the byte offset and byte order of the array.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    fn width(self) -> Result<usize> {
        N.checked_mul(4).ok_or(Error::InvalidField {
            what: "u32 array width",
            value: N as u64,
        })
    }

    /// Read the array from an arbitrary resident carrier.
    pub fn read(self, bytes: &[u8]) -> Result<[u32; N]> {
        let field = bytes_at(bytes, self.offset, self.width()?)?;
        Ok(std::array::from_fn(|index| {
            let encoded = field[index * 4..index * 4 + 4].try_into().unwrap();
            match self.endian {
                Endian::Little => u32::from_le_bytes(encoded),
                Endian::Big => u32::from_be_bytes(encoded),
            }
        }))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH` or its static width
    /// overflows `usize`.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> [u32; N] {
        let width = N.checked_mul(4).expect("u32 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("u32 array end overflow");
        assert!(end <= WIDTH, "u32 array field exceeds record");
        std::array::from_fn(|index| {
            let offset = self.offset + index * 4;
            let encoded = bytes[offset..offset + 4].try_into().unwrap();
            match self.endian {
                Endian::Little => u32::from_le_bytes(encoded),
                Endian::Big => u32::from_be_bytes(encoded),
            }
        })
    }

    /// Write every array element without changing surrounding bytes.
    pub fn write(self, bytes: &mut [u8], values: [u32; N]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, self.width()?)?;
        self.write_bounded(field, values);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], values: [u32; N]) {
        let width = N.checked_mul(4).expect("u32 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("u32 array end overflow");
        assert!(end <= WIDTH, "u32 array field exceeds record");
        self.write_bounded(&mut bytes[self.offset..end], values);
    }

    #[inline(always)]
    fn write_bounded(self, field: &mut [u8], values: [u32; N]) {
        for (slot, value) in field.chunks_exact_mut(4).zip(values) {
            let encoded = match self.endian {
                Endian::Little => value.to_le_bytes(),
                Endian::Big => value.to_be_bytes(),
            };
            slot.copy_from_slice(&encoded);
        }
    }
}

/// A configured contiguous array of 32-bit signed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I32ArrayField<const N: usize> {
    offset: usize,
    endian: Endian,
}

impl<const N: usize> I32ArrayField<N> {
    /// Configure the byte offset and byte order of the array.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    fn width(self) -> Result<usize> {
        N.checked_mul(4).ok_or(Error::InvalidField {
            what: "i32 array width",
            value: N as u64,
        })
    }

    /// Read the array from an arbitrary resident carrier.
    pub fn read(self, bytes: &[u8]) -> Result<[i32; N]> {
        let field = bytes_at(bytes, self.offset, self.width()?)?;
        Ok(std::array::from_fn(|index| {
            let encoded = field[index * 4..index * 4 + 4].try_into().unwrap();
            match self.endian {
                Endian::Little => i32::from_le_bytes(encoded),
                Endian::Big => i32::from_be_bytes(encoded),
            }
        }))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH` or its static width
    /// overflows `usize`.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> [i32; N] {
        let width = N.checked_mul(4).expect("i32 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("i32 array end overflow");
        assert!(end <= WIDTH, "i32 array field exceeds record");
        std::array::from_fn(|index| {
            let offset = self.offset + index * 4;
            let encoded = bytes[offset..offset + 4].try_into().unwrap();
            match self.endian {
                Endian::Little => i32::from_le_bytes(encoded),
                Endian::Big => i32::from_be_bytes(encoded),
            }
        })
    }

    /// Write every array element without changing surrounding bytes.
    pub fn write(self, bytes: &mut [u8], values: [i32; N]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, self.width()?)?;
        self.write_bounded(field, values);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], values: [i32; N]) {
        let width = N.checked_mul(4).expect("i32 array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("i32 array end overflow");
        assert!(end <= WIDTH, "i32 array field exceeds record");
        self.write_bounded(&mut bytes[self.offset..end], values);
    }

    #[inline(always)]
    fn write_bounded(self, field: &mut [u8], values: [i32; N]) {
        for (slot, value) in field.chunks_exact_mut(4).zip(values) {
            let encoded = match self.endian {
                Endian::Little => value.to_le_bytes(),
                Endian::Big => value.to_be_bytes(),
            };
            slot.copy_from_slice(&encoded);
        }
    }
}

/// A configured contiguous array of raw IEEE-754 single-precision fields.
///
/// The descriptor deliberately assigns no finite-value, vector, matrix, or
/// coordinate semantics. All bit patterns round-trip unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F32ArrayField<const N: usize> {
    offset: usize,
    endian: Endian,
}

impl<const N: usize> F32ArrayField<N> {
    /// Configure the byte offset and byte order of the contiguous array.
    #[must_use]
    pub const fn new(offset: usize, endian: Endian) -> Self {
        Self { offset, endian }
    }

    fn width(self) -> Result<usize> {
        N.checked_mul(4).ok_or(Error::InvalidField {
            what: "float array width",
            value: N as u64,
        })
    }

    /// Read the array from an arbitrary resident carrier.
    pub fn read(self, bytes: &[u8]) -> Result<[f32; N]> {
        let field = bytes_at(bytes, self.offset, self.width()?)?;
        Ok(std::array::from_fn(|index| {
            let encoded = field[index * 4..index * 4 + 4].try_into().unwrap();
            match self.endian {
                Endian::Little => f32::from_le_bytes(encoded),
                Endian::Big => f32::from_be_bytes(encoded),
            }
        }))
    }

    /// Read after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH` or its static width
    /// overflows `usize`.
    #[inline(always)]
    pub fn read_record<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> [f32; N] {
        let width = N.checked_mul(4).expect("float array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("float array end overflow");
        assert!(end <= WIDTH, "float array field exceeds record");
        std::array::from_fn(|index| {
            let offset = self.offset + index * 4;
            let encoded = bytes[offset..offset + 4].try_into().unwrap();
            match self.endian {
                Endian::Little => f32::from_le_bytes(encoded),
                Endian::Big => f32::from_be_bytes(encoded),
            }
        })
    }

    /// Write every array element without changing surrounding bytes.
    #[inline]
    pub fn write(self, bytes: &mut [u8], values: [f32; N]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, self.width()?)?;
        self.write_bounded(field, values);
        Ok(())
    }

    /// Write after the enclosing fixed-width record has been bounded.
    ///
    /// Panics when the configured array exceeds `WIDTH`.
    #[inline(always)]
    pub fn write_record<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH], values: [f32; N]) {
        let width = N.checked_mul(4).expect("float array width overflow");
        let end = self
            .offset
            .checked_add(width)
            .expect("float array end overflow");
        assert!(end <= WIDTH, "float array field exceeds record");
        self.write_bounded(&mut bytes[self.offset..end], values);
    }

    #[inline(always)]
    fn write_bounded(self, field: &mut [u8], values: [f32; N]) {
        for (slot, value) in field.chunks_exact_mut(4).zip(values) {
            let encoded = match self.endian {
                Endian::Little => value.to_bits().to_le_bytes(),
                Endian::Big => value.to_bits().to_be_bytes(),
            };
            slot.copy_from_slice(&encoded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_fields_preserve_every_bit_pattern_and_touch_only_the_field() {
        let unsigned = U8Field::new(1);
        let signed = I8Field::new(1);
        for raw in 0..=u8::MAX {
            let mut unsigned_bytes = [0x55; 3];
            unsigned.write(&mut unsigned_bytes, raw).unwrap();
            assert_eq!(unsigned.read(&unsigned_bytes).unwrap(), raw);
            assert_eq!(unsigned.read_record(&unsigned_bytes), raw);

            let mut unsigned_record = [0x55; 3];
            unsigned.write_record(&mut unsigned_record, raw);
            assert_eq!(unsigned_record, unsigned_bytes);

            let value = raw as i8;
            let mut signed_bytes = [0x55; 3];
            signed.write(&mut signed_bytes, value).unwrap();
            assert_eq!(signed.read(&signed_bytes).unwrap(), value);
            assert_eq!(signed.read_record(&signed_bytes), value);

            let mut signed_record = [0x55; 3];
            signed.write_record(&mut signed_record, value);
            assert_eq!(signed_record, signed_bytes);
        }
    }

    #[test]
    fn u16_fields_preserve_every_value_in_both_endians_and_touch_only_the_field() {
        for endian in [Endian::Little, Endian::Big] {
            let field = U16Field::new(1, endian);
            for value in 0..=u16::MAX {
                let mut bytes = [0x55; 4];
                field.write(&mut bytes, value).unwrap();
                let encoded = match endian {
                    Endian::Little => value.to_le_bytes(),
                    Endian::Big => value.to_be_bytes(),
                };
                assert_eq!(bytes, [0x55, encoded[0], encoded[1], 0x55]);
                assert_eq!(field.read(&bytes).unwrap(), value);
                assert_eq!(field.read_record(&bytes), value);

                let mut record = [0x55; 4];
                field.write_record(&mut record, value);
                assert_eq!(record, bytes);
            }
        }
        const AT_ZERO: U16Field = U16Field::new(0, Endian::Little);
        assert_eq!(AT_ZERO.read_record(&[0x34, 0x12]), 0x1234);
        assert_eq!(AT_ZERO.read(&[0x34, 0x12]).unwrap(), 0x1234);
    }

    #[test]
    fn u16_short_and_overflowing_ranges_keep_exact_errors_and_bytes() {
        for endian in [Endian::Little, Endian::Big] {
            for offset in [0, 1, 3, usize::MAX - 1, usize::MAX] {
                let field = U16Field::new(offset, endian);
                for len in 0usize..=6 {
                    let mut bytes = vec![0x55; len];
                    if offset.checked_add(2).is_some_and(|end| end <= len) {
                        assert_eq!(field.read(&bytes).unwrap(), 0x5555);
                        continue;
                    }
                    let expected = Error::Truncated {
                        offset,
                        needed: 2,
                        available: len.saturating_sub(offset),
                    };
                    assert_eq!(field.read(&bytes).unwrap_err(), expected);
                    assert_eq!(field.write(&mut bytes, 0).unwrap_err(), expected);
                    assert_eq!(bytes, vec![0x55; len]);
                }
            }
        }
    }

    #[test]
    fn scalar_and_float_fields_preserve_bits_in_both_byte_orders() {
        for endian in [Endian::Little, Endian::Big] {
            let field = U32Field::new(1, endian);
            for value in [0, 1, u32::MAX, 0x8000_0000, 0x1234_5678] {
                let mut bytes = [0x55; 6];
                field.write(&mut bytes, value).unwrap();
                assert_eq!(field.read(&bytes).unwrap(), value);
                assert_eq!((bytes[0], bytes[5]), (0x55, 0x55));

                let mut record = [0x55; 6];
                field.write_record(&mut record, value);
                assert_eq!(record, bytes);
            }

            let xyz = F32ArrayField::<3>::new(2, endian);
            let values = [
                f32::from_bits(0x8000_0000),
                f32::from_bits(0x7fc0_1234),
                f32::INFINITY,
            ];
            let mut bytes = [0x55; 16];
            xyz.write(&mut bytes, values).unwrap();
            assert_eq!(
                xyz.read_record(&bytes).map(f32::to_bits),
                values.map(f32::to_bits)
            );
            assert_eq!(&bytes[..2], &[0x55; 2]);
            assert_eq!(&bytes[14..], &[0x55; 2]);
        }
    }

    #[test]
    fn signed_wide_and_scalar_float_fields_preserve_bits_in_both_byte_orders() {
        for endian in [Endian::Little, Endian::Big] {
            for value in [i16::MIN, -1, 0, 1, i16::MAX] {
                let field = I16Field::new(1, endian);
                let mut bytes = [0x55; 4];
                field.write(&mut bytes, value).unwrap();
                assert_eq!(field.read(&bytes).unwrap(), value);
                assert_eq!(field.read_record(&bytes), value);
                assert_eq!((bytes[0], bytes[3]), (0x55, 0x55));

                let mut record = [0x55; 4];
                field.write_record(&mut record, value);
                assert_eq!(record, bytes);
            }

            for value in [i32::MIN, -1, 0, 1, i32::MAX] {
                let field = I32Field::new(1, endian);
                let mut bytes = [0x55; 6];
                field.write(&mut bytes, value).unwrap();
                assert_eq!(field.read(&bytes).unwrap(), value);
                assert_eq!(field.read_record(&bytes), value);
                assert_eq!((bytes[0], bytes[5]), (0x55, 0x55));

                let mut record = [0x55; 6];
                field.write_record(&mut record, value);
                assert_eq!(record, bytes);
            }

            for value in [0, 1, u64::MAX, 0x8000_0000_0000_0000, 0x0123_4567_89ab_cdef] {
                let field = U64Field::new(1, endian);
                let mut bytes = [0x55; 10];
                field.write(&mut bytes, value).unwrap();
                assert_eq!(field.read(&bytes).unwrap(), value);
                assert_eq!(field.read_record(&bytes), value);
                assert_eq!((bytes[0], bytes[9]), (0x55, 0x55));

                let mut record = [0x55; 10];
                field.write_record(&mut record, value);
                assert_eq!(record, bytes);
            }

            for bits in [0, 0x8000_0000, 0x7fc0_1234, 0x7f80_0000, 0x3f80_0000] {
                let field = F32Field::new(1, endian);
                let mut bytes = [0x55; 6];
                field.write(&mut bytes, f32::from_bits(bits)).unwrap();
                assert_eq!(field.read(&bytes).unwrap().to_bits(), bits);
                assert_eq!(field.read_record(&bytes).to_bits(), bits);
                assert_eq!((bytes[0], bytes[5]), (0x55, 0x55));

                let mut record = [0x55; 6];
                field.write_record(&mut record, f32::from_bits(bits));
                assert_eq!(record, bytes);
            }
        }
    }

    #[test]
    fn scaled_u32_fields_are_exact_symmetric_and_nonmutating_on_error() {
        for endian in [Endian::Little, Endian::Big] {
            let field = ScaledU32Field::new(1, endian, 2_048);
            let mut bytes = [0x55; 6];
            field.write(&mut bytes, 3 * 2_048).unwrap();
            assert_eq!(field.read(&bytes).unwrap(), 3 * 2_048);
            assert_eq!(field.read_record(&bytes).unwrap(), 3 * 2_048);
            assert_eq!((bytes[0], bytes[5]), (0x55, 0x55));

            let before = bytes;
            assert!(field.write(&mut bytes, 2_049).is_err());
            assert_eq!(bytes, before);

            field
                .write_relative(&mut bytes, 0x4000, 0x4000 + 4 * 2_048)
                .unwrap();
            assert_eq!(field.read_relative(&bytes, 0x4000).unwrap(), 0x6000);

            let before = bytes;
            assert!(field.write_relative(&mut bytes, 0x4000, 0x3fff).is_err());
            assert_eq!(bytes, before);
            assert!(field
                .write(&mut bytes, (u64::from(u32::MAX) + 1) * 2_048)
                .is_err());
            assert_eq!(bytes, before);

            let mut record = [0x55; 6];
            field
                .write_record(&mut record, u64::from(u32::MAX) * 2_048)
                .unwrap();
            assert_eq!(
                field.read_record(&record).unwrap(),
                u64::from(u32::MAX) * 2_048
            );

            let mut relative_record = [0x55; 6];
            field
                .write_record_relative(&mut relative_record, 7, 7 + 5 * 2_048)
                .unwrap();
            assert_eq!(
                field.read_record_relative(&relative_record, 7).unwrap(),
                7 + 5 * 2_048
            );
        }

        let overflowing = ScaledU32Field::new(0, Endian::Little, u64::MAX);
        assert!(overflowing.read(&2u32.to_le_bytes()).is_err());
        let unit = ScaledU32Field::new(0, Endian::Little, 1);
        assert!(unit
            .read_relative(&u32::MAX.to_le_bytes(), u64::MAX)
            .is_err());
    }

    #[test]
    #[should_panic(expected = "scaled u32 field unit must be nonzero")]
    fn scaled_u32_zero_unit_is_a_descriptor_error() {
        let _ = ScaledU32Field::new(0, Endian::Little, 0);
    }

    #[test]
    fn integer_arrays_and_fixed_bytes_round_trip_without_touching_neighbors() {
        for endian in [Endian::Little, Endian::Big] {
            let unsigned = U16ArrayField::<4>::new(2, endian);
            let unsigned_values = [0, 1, 0x8000, u16::MAX];
            let mut unsigned_bytes = [0x55; 12];
            unsigned
                .write(&mut unsigned_bytes, unsigned_values)
                .unwrap();
            assert_eq!(unsigned.read(&unsigned_bytes).unwrap(), unsigned_values);
            assert_eq!(unsigned.read_record(&unsigned_bytes), unsigned_values);
            let mut unsigned_record = [0x55; 12];
            unsigned.write_record(&mut unsigned_record, unsigned_values);
            assert_eq!(unsigned_record, unsigned_bytes);

            let signed = I16ArrayField::<4>::new(2, endian);
            let signed_values = [i16::MIN, -1, 0x1234, i16::MAX];
            let mut signed_bytes = [0x55; 12];
            signed.write(&mut signed_bytes, signed_values).unwrap();
            assert_eq!(signed.read(&signed_bytes).unwrap(), signed_values);
            assert_eq!(signed.read_record(&signed_bytes), signed_values);
            assert_eq!(&signed_bytes[..2], &[0x55; 2]);
            assert_eq!(&signed_bytes[10..], &[0x55; 2]);
            let mut signed_record = [0x55; 12];
            signed.write_record(&mut signed_record, signed_values);
            assert_eq!(signed_record, signed_bytes);

            let words = U32ArrayField::<3>::new(1, endian);
            let word_values = [0, 0x8000_0000, 0x1234_5678];
            let mut word_bytes = [0x55; 14];
            words.write(&mut word_bytes, word_values).unwrap();
            assert_eq!(words.read(&word_bytes).unwrap(), word_values);
            assert_eq!(words.read_record(&word_bytes), word_values);
            assert_eq!((word_bytes[0], word_bytes[13]), (0x55, 0x55));
            let mut word_record = [0x55; 14];
            words.write_record(&mut word_record, word_values);
            assert_eq!(word_record, word_bytes);

            let signed_words = I32ArrayField::<3>::new(1, endian);
            let signed_word_values = [i32::MIN, -1, i32::MAX];
            let mut signed_word_bytes = [0x55; 14];
            signed_words
                .write(&mut signed_word_bytes, signed_word_values)
                .unwrap();
            assert_eq!(
                signed_words.read(&signed_word_bytes).unwrap(),
                signed_word_values
            );
            assert_eq!(
                signed_words.read_record(&signed_word_bytes),
                signed_word_values
            );
            assert_eq!((signed_word_bytes[0], signed_word_bytes[13]), (0x55, 0x55));
            let mut signed_word_record = [0x55; 14];
            signed_words.write_record(&mut signed_word_record, signed_word_values);
            assert_eq!(signed_word_record, signed_word_bytes);

            let floats = F32ArrayField::<3>::new(1, endian);
            let float_values = [
                f32::from_bits(0x8000_0000),
                f32::from_bits(0x7fc0_1234),
                f32::INFINITY,
            ];
            let mut float_bytes = [0x55; 14];
            floats.write(&mut float_bytes, float_values).unwrap();
            assert_eq!(
                floats.read(&float_bytes).unwrap().map(f32::to_bits),
                float_values.map(f32::to_bits)
            );
            let mut float_record = [0x55; 14];
            floats.write_record(&mut float_record, float_values);
            assert_eq!(float_record, float_bytes);
        }

        let bytes_field = BytesField::<4>::new(2);
        let mut bytes = [0x55; 8];
        bytes_field.write(&mut bytes, b"ABCD").unwrap();
        assert_eq!(bytes_field.read(&bytes).unwrap(), b"ABCD");
        assert_eq!(bytes_field.read_record(&bytes), b"ABCD");
        assert_eq!(&bytes[..2], &[0x55; 2]);
        assert_eq!(&bytes[6..], &[0x55; 2]);
        let mut record = [0x55; 8];
        bytes_field.write_record(&mut record, b"ABCD");
        assert_eq!(record, bytes);
    }

    #[test]
    fn new_fields_reject_short_and_overflowing_ranges_before_mutation() {
        for offset in [0, 1, usize::MAX] {
            let mut bytes = [];
            let original = bytes;
            assert!(U8Field::new(offset).write(&mut bytes, 0).is_err());
            assert_eq!(bytes, original);

            let mut bytes = [0x55; 7];
            let original = bytes;
            assert!(U64Field::new(offset, Endian::Little)
                .write(&mut bytes, 0)
                .is_err());
            assert_eq!(bytes, original);

            let mut bytes = [0x55; 7];
            let original = bytes;
            assert!(U16ArrayField::<4>::new(offset, Endian::Little)
                .write(&mut bytes, [0; 4])
                .is_err());
            assert_eq!(bytes, original);

            let mut bytes = [0x55; 7];
            let original = bytes;
            assert!(I16ArrayField::<4>::new(offset, Endian::Little)
                .write(&mut bytes, [0; 4])
                .is_err());
            assert_eq!(bytes, original);

            let mut bytes = [0x55; 11];
            let original = bytes;
            assert!(U32ArrayField::<3>::new(offset, Endian::Little)
                .write(&mut bytes, [0; 3])
                .is_err());
            assert_eq!(bytes, original);

            let mut bytes = [0x55; 11];
            let original = bytes;
            assert!(I32ArrayField::<3>::new(offset, Endian::Little)
                .write(&mut bytes, [0; 3])
                .is_err());
            assert_eq!(bytes, original);

            let mut bytes = [0x55; 3];
            let original = bytes;
            assert!(BytesField::<4>::new(offset)
                .write(&mut bytes, b"ABCD")
                .is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn new_record_field_definitions_reject_out_of_record_placement() {
        assert!(std::panic::catch_unwind(|| { U8Field::new(2).read_record(&[0; 2]) }).is_err());
        assert!(
            std::panic::catch_unwind(|| { I8Field::new(2).write_record(&mut [0; 2], 0) }).is_err()
        );
        assert!(std::panic::catch_unwind(|| {
            I16Field::new(1, Endian::Little).read_record(&[0; 2])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            I32Field::new(1, Endian::Little).read_record(&[0; 4])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            U64Field::new(1, Endian::Little).read_record(&[0; 8])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            F32Field::new(1, Endian::Little).read_record(&[0; 4])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| BytesField::<4>::new(1).read_record(&[0; 4])).is_err());
        assert!(std::panic::catch_unwind(|| {
            U16ArrayField::<2>::new(1, Endian::Little).write_record(&mut [0; 4], [0; 2])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            I16ArrayField::<2>::new(1, Endian::Little).read_record(&[0; 4])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            U32ArrayField::<2>::new(1, Endian::Little).read_record(&[0; 8])
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            I32ArrayField::<2>::new(1, Endian::Little).write_record(&mut [0; 8], [0; 2])
        })
        .is_err());
    }

    fn assert_u16_definition_panics<const WIDTH: usize>(offset: usize) {
        let panic = std::panic::catch_unwind(|| {
            U16Field::new(offset, Endian::Little).read_record(&[0; WIDTH])
        })
        .unwrap_err();
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("u16 field exceeds record"));
    }

    fn assert_u32_definition_panics<const WIDTH: usize>(offset: usize) {
        let panic = std::panic::catch_unwind(|| {
            U32Field::new(offset, Endian::Little).read_record(&[0; WIDTH])
        })
        .unwrap_err();
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("u32 field exceeds record"));

        let panic = std::panic::catch_unwind(|| {
            U32Field::new(offset, Endian::Little).write_record(&mut [0; WIDTH], 0)
        })
        .unwrap_err();
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("u32 field exceeds record"));
    }

    #[test]
    fn u16_record_definitions_reject_short_widths_outside_fields_and_overflow() {
        assert_u16_definition_panics::<0>(0);
        assert_u16_definition_panics::<1>(0);
        assert_u16_definition_panics::<2>(1);
        assert_u16_definition_panics::<2>(usize::MAX - 1);
        assert_u16_definition_panics::<2>(usize::MAX);
    }

    #[test]
    fn u32_record_definitions_reject_short_widths_outside_fields_and_overflow() {
        assert_u32_definition_panics::<0>(0);
        assert_u32_definition_panics::<1>(0);
        assert_u32_definition_panics::<2>(0);
        assert_u32_definition_panics::<3>(0);
        assert_u32_definition_panics::<4>(1);
        assert_u32_definition_panics::<4>(usize::MAX - 3);
        assert_u32_definition_panics::<4>(usize::MAX);
    }

    #[test]
    fn short_or_overflowing_fields_do_not_partially_write() {
        for offset in [0, 1, usize::MAX] {
            let scalar = U32Field::new(offset, Endian::Little);
            for len in 0..4 {
                let mut bytes = vec![0x55; len];
                assert!(scalar.read(&bytes).is_err());
                assert!(scalar.write(&mut bytes, 0).is_err());
                assert_eq!(bytes, vec![0x55; len]);
            }
            if offset == 0 {
                assert_eq!(scalar.read_record(&[0; 4]), 0);
            } else {
                assert!(std::panic::catch_unwind(|| scalar.read_record(&[0; 4])).is_err());
            }

            let xyz = F32ArrayField::<3>::new(offset, Endian::Little);
            for len in 0..12 {
                let mut bytes = vec![0x55; len];
                assert!(xyz.write(&mut bytes, [1.0; 3]).is_err());
                assert_eq!(bytes, vec![0x55; len]);
            }
            if offset == 0 {
                assert_eq!(xyz.read_record(&[0; 12]), [0.0; 3]);
            } else {
                assert!(std::panic::catch_unwind(|| xyz.read_record(&[0; 12])).is_err());
            }
        }
    }
}
