//! Fixed-position byte-string fields.
//!
//! These descriptors combine resident placement with raw byte-string framing.
//! They deliberately do not decode character sets, validate allowed characters,
//! or assign meaning to empty strings and padding bytes.

use formatkit_core::{
    bytes_at, bytes_at_mut, fixed_field, nul_terminated, write_nul_or_full, write_nul_padded,
    write_nul_terminated, Result,
};

/// A fixed-width byte-string field at a configured resident offset.
///
/// Methods name the framing contract explicitly. Required-NUL reads reject a
/// field without a terminator; NUL-or-full reads accept a complete field with
/// no terminator. Writers likewise distinguish preserved opaque tails, strict
/// NUL padding, and the full-width encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedByteStringField<const N: usize> {
    offset: usize,
}

impl<const N: usize> FixedByteStringField<N> {
    /// Configure the byte offset of the fixed-width field.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Read raw bytes before a required NUL from an arbitrary resident carrier.
    pub fn read_required_nul(self, bytes: &[u8]) -> Result<&[u8]> {
        let field = bytes_at(bytes, self.offset, N)?;
        nul_terminated(field, N)
    }

    /// Read raw bytes before the first NUL, or the complete field if none exists.
    pub fn read_nul_or_full(self, bytes: &[u8]) -> Result<&[u8]> {
        let field = bytes_at(bytes, self.offset, N)?;
        fixed_field(field, N)
    }

    /// Read a required-NUL value after the enclosing record has been bounded.
    ///
    /// Invalid static placement panics. Missing termination remains a checked
    /// input error.
    #[inline(always)]
    pub fn read_record_required_nul<const WIDTH: usize>(
        self,
        bytes: &[u8; WIDTH],
    ) -> Result<&[u8]> {
        nul_terminated(self.record_field(bytes), N)
    }

    /// Read a NUL-or-full value after the enclosing record has been bounded.
    ///
    /// Invalid static placement panics.
    #[must_use]
    #[inline(always)]
    pub fn read_record_nul_or_full<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> &[u8] {
        let field = self.record_field(bytes);
        let end = field.iter().position(|byte| *byte == 0).unwrap_or(N);
        &field[..end]
    }

    /// Write a required-NUL value while preserving bytes after its terminator.
    ///
    /// The complete field is bounded before validation or mutation.
    pub fn write_required_nul(self, bytes: &mut [u8], value: &[u8]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, N)?;
        write_nul_terminated(field, value)
    }

    /// Write a required-NUL value and zero-fill the rest of the field.
    ///
    /// The complete field is bounded before validation or mutation.
    pub fn write_required_nul_padded(self, bytes: &mut [u8], value: &[u8]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, N)?;
        write_nul_padded(field, value)
    }

    /// Write a zero-padded value that may occupy the field without a NUL.
    ///
    /// The complete field is bounded before validation or mutation.
    pub fn write_nul_or_full(self, bytes: &mut [u8], value: &[u8]) -> Result<()> {
        let field = bytes_at_mut(bytes, self.offset, N)?;
        write_nul_or_full(field, value)
    }

    /// Write a required-NUL value in a bounded record, preserving its tail.
    ///
    /// Invalid static placement panics. Invalid values return an error without
    /// changing the record.
    #[inline(always)]
    pub fn write_record_required_nul<const WIDTH: usize>(
        self,
        bytes: &mut [u8; WIDTH],
        value: &[u8],
    ) -> Result<()> {
        write_nul_terminated(self.record_field_mut(bytes), value)
    }

    /// Write a zero-padded required-NUL value in a bounded record.
    ///
    /// Invalid static placement panics. Invalid values return an error without
    /// changing the record.
    #[inline(always)]
    pub fn write_record_required_nul_padded<const WIDTH: usize>(
        self,
        bytes: &mut [u8; WIDTH],
        value: &[u8],
    ) -> Result<()> {
        write_nul_padded(self.record_field_mut(bytes), value)
    }

    /// Write a zero-padded NUL-or-full value in a bounded record.
    ///
    /// Invalid static placement panics. Invalid values return an error without
    /// changing the record.
    #[inline(always)]
    pub fn write_record_nul_or_full<const WIDTH: usize>(
        self,
        bytes: &mut [u8; WIDTH],
        value: &[u8],
    ) -> Result<()> {
        write_nul_or_full(self.record_field_mut(bytes), value)
    }

    #[inline(always)]
    fn record_field<const WIDTH: usize>(self, bytes: &[u8; WIDTH]) -> &[u8] {
        let end = self
            .offset
            .checked_add(N)
            .expect("byte-string field end overflow");
        assert!(end <= WIDTH, "byte-string field exceeds record");
        &bytes[self.offset..end]
    }

    #[inline(always)]
    fn record_field_mut<const WIDTH: usize>(self, bytes: &mut [u8; WIDTH]) -> &mut [u8] {
        let end = self
            .offset
            .checked_add(N)
            .expect("byte-string field end overflow");
        assert!(end <= WIDTH, "byte-string field exceeds record");
        &mut bytes[self.offset..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use formatkit_core::Error;

    #[test]
    fn read_modes_distinguish_required_nul_and_full_width() {
        let field = FixedByteStringField::<4>::new(1);
        let terminated = *b"Xab\0cY";
        assert_eq!(field.read_required_nul(&terminated).unwrap(), b"ab");
        assert_eq!(field.read_nul_or_full(&terminated).unwrap(), b"ab");
        assert_eq!(field.read_record_required_nul(&terminated).unwrap(), b"ab");
        assert_eq!(field.read_record_nul_or_full(&terminated), b"ab");

        let full = *b"XabcdY";
        assert!(field.read_required_nul(&full).is_err());
        assert!(field.read_record_required_nul(&full).is_err());
        assert_eq!(field.read_nul_or_full(&full).unwrap(), b"abcd");
        assert_eq!(field.read_record_nul_or_full(&full), b"abcd");
    }

    #[test]
    fn write_modes_have_record_parity_and_preserve_neighbors() {
        let field = FixedByteStringField::<5>::new(1);

        let mut retained = *b"Lold\0xR";
        field.write_required_nul(&mut retained, b"n").unwrap();
        assert_eq!(&retained, b"Ln\0d\0xR");
        let mut retained_record = *b"Lold\0xR";
        field
            .write_record_required_nul(&mut retained_record, b"n")
            .unwrap();
        assert_eq!(retained_record, retained);

        let mut padded = [0x55; 7];
        field.write_required_nul_padded(&mut padded, b"ab").unwrap();
        assert_eq!(&padded, b"Uab\0\0\0U");
        let mut padded_record = [0x55; 7];
        field
            .write_record_required_nul_padded(&mut padded_record, b"ab")
            .unwrap();
        assert_eq!(padded_record, padded);

        let mut full = [0x55; 7];
        field.write_nul_or_full(&mut full, b"abcde").unwrap();
        assert_eq!(&full, b"UabcdeU");
        let mut full_record = [0x55; 7];
        field
            .write_record_nul_or_full(&mut full_record, b"abcde")
            .unwrap();
        assert_eq!(full_record, full);
    }

    #[test]
    fn bounds_and_value_errors_do_not_mutate() {
        let field = FixedByteStringField::<4>::new(1);

        let mut short = [0x55; 4];
        assert!(matches!(
            field.write_required_nul(&mut short, b"a"),
            Err(Error::Truncated { offset: 1, .. })
        ));
        assert_eq!(short, [0x55; 4]);

        let mut invalid = [0x55; 6];
        assert!(field
            .write_required_nul_padded(&mut invalid, b"a\0b")
            .is_err());
        assert_eq!(invalid, [0x55; 6]);
        assert!(field.write_nul_or_full(&mut invalid, b"abcde").is_err());
        assert_eq!(invalid, [0x55; 6]);
    }

    #[test]
    fn invalid_record_placement_panics() {
        let field = FixedByteStringField::<4>::new(1);
        assert!(std::panic::catch_unwind(|| field.read_record_nul_or_full(&[0; 4])).is_err());
        assert!(std::panic::catch_unwind(|| {
            let mut record = [0; 4];
            let _ = field.write_record_nul_or_full(&mut record, b"a");
        })
        .is_err());
    }
}
