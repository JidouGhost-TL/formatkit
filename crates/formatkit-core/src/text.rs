//! Bounds-safe framing for common on-disc string fields.
//!
//! These helpers return raw bytes or byte lengths. Character-set interpretation remains with
//! the format that knows whether a field is ASCII, Shift-JIS, UTF-16, or opaque.

use crate::{Error, Result};

/// Find the byte length before the first NUL within `max_len` bytes.
///
/// This performs no allocation or decoding. `None` means the bounded input
/// contains no NUL; the caller owns the missing-terminator diagnostic. An early
/// NUL succeeds even if the input is shorter than `max_len`, so callers requiring
/// a complete fixed-width field must validate that field separately.
pub fn nul_terminated_len(bytes: &[u8], max_len: usize) -> Option<usize> {
    bytes.iter().take(max_len).position(|byte| *byte == 0)
}

/// Return bytes through the first NUL, bounded by `max_len` and the input slice.
pub fn nul_terminated(bytes: &[u8], max_len: usize) -> Result<&[u8]> {
    let bounded = bytes.get(..max_len).unwrap_or(bytes);
    let end = match nul_terminated_len(bytes, max_len) {
        Some(end) => end,
        None if bytes.len() < max_len => {
            return Err(Error::Truncated {
                offset: 0,
                needed: max_len,
                available: bytes.len(),
            });
        }
        None => {
            return Err(Error::Malformed(format!(
                "string has no NUL within {max_len} bytes"
            )))
        }
    };
    Ok(&bounded[..end])
}

/// Trim a fixed-width, NUL-padded field without reading beyond its declared width.
pub fn fixed_field(bytes: &[u8], width: usize) -> Result<&[u8]> {
    let field = bytes.get(..width).ok_or(Error::Truncated {
        offset: 0,
        needed: width,
        available: bytes.len(),
    })?;
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    Ok(&field[..end])
}

fn reject_embedded_nul(value: &[u8]) -> Result<()> {
    if let Some(index) = value.iter().position(|byte| *byte == 0) {
        return Err(Error::InvalidField {
            what: "byte string embedded NUL position",
            value: index as u64,
        });
    }
    Ok(())
}

fn require_capacity(field: &[u8], needed: usize) -> Result<()> {
    if needed > field.len() {
        return Err(Error::Truncated {
            offset: 0,
            needed,
            available: field.len(),
        });
    }
    Ok(())
}

/// Write raw bytes followed by a required NUL, preserving the rest of the field.
///
/// The value may be empty but may not contain an embedded NUL. All validation
/// completes before `field` is changed. Character encoding, the meaning of an
/// empty value, and whether the preserved suffix is semantically significant
/// remain the format owner's policy.
pub fn write_nul_terminated(field: &mut [u8], value: &[u8]) -> Result<()> {
    reject_embedded_nul(value)?;
    let needed = value.len().checked_add(1).ok_or(Error::InvalidField {
        what: "NUL-terminated byte string length",
        value: u64::MAX,
    })?;
    require_capacity(field, needed)?;

    field[..value.len()].copy_from_slice(value);
    field[value.len()] = 0;
    Ok(())
}

/// Write raw bytes followed by a required NUL and zero-fill the remaining field.
///
/// The value may be empty but may not contain an embedded NUL. All validation
/// completes before `field` is changed. Character encoding remains the format
/// owner's policy.
pub fn write_nul_padded(field: &mut [u8], value: &[u8]) -> Result<()> {
    reject_embedded_nul(value)?;
    let needed = value.len().checked_add(1).ok_or(Error::InvalidField {
        what: "NUL-padded byte string length",
        value: u64::MAX,
    })?;
    require_capacity(field, needed)?;

    field.fill(0);
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

/// Write a NUL-padded value that may occupy the complete field without a NUL.
///
/// Short values are followed by zero fill. A value exactly as wide as the
/// field is copied verbatim. Embedded NULs are rejected so reading with
/// [`fixed_field`] recovers the same logical value. All validation completes
/// before `field` is changed.
pub fn write_nul_or_full(field: &mut [u8], value: &[u8]) -> Result<()> {
    reject_embedded_nul(value)?;
    require_capacity(field, value.len())?;

    field.fill(0);
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

/// Decode a `u8` byte count followed by exactly that many raw string bytes.
pub fn u8_prefixed(bytes: &[u8]) -> Result<&[u8]> {
    let length = *bytes.first().ok_or(Error::Truncated {
        offset: 0,
        needed: 1,
        available: 0,
    })? as usize;
    bytes.get(1..1 + length).ok_or(Error::Truncated {
        offset: 1,
        needed: length,
        available: bytes.len().saturating_sub(1),
    })
}

/// Decode a little-endian `u16` byte count followed by that many raw bytes.
pub fn u16_le_prefixed(bytes: &[u8]) -> Result<&[u8]> {
    let prefix = bytes.get(..2).ok_or(Error::Truncated {
        offset: 0,
        needed: 2,
        available: bytes.len(),
    })?;
    let length = u16::from_le_bytes([prefix[0], prefix[1]]) as usize;
    bytes.get(2..2 + length).ok_or(Error::Truncated {
        offset: 2,
        needed: length,
        available: bytes.len().saturating_sub(2),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nul_string_respects_its_field_boundary() {
        assert_eq!(nul_terminated(b"name\0sibling", 8).unwrap(), b"name");
        assert!(nul_terminated(b"namesibling\0", 4).is_err());
        assert!(matches!(
            nul_terminated(b"abc", 8),
            Err(Error::Truncated {
                needed: 8,
                available: 3,
                ..
            })
        ));
    }

    #[test]
    fn fixed_and_prefixed_fields_are_bounded() {
        assert_eq!(fixed_field(b"abc\0junk", 4).unwrap(), b"abc");
        assert_eq!(u8_prefixed(b"\x03abcjunk").unwrap(), b"abc");
        assert_eq!(u16_le_prefixed(b"\x03\x00abcjunk").unwrap(), b"abc");
        assert!(u8_prefixed(b"\x05abc").is_err());
        assert!(u16_le_prefixed(b"\x05\x00abc").is_err());
    }

    #[test]
    fn terminated_writer_preserves_the_opaque_tail() {
        let mut field = *b"old\0STALE";
        write_nul_terminated(&mut field, b"n").unwrap();
        assert_eq!(&field, b"n\0d\0STALE");
        assert_eq!(nul_terminated(&field, field.len()).unwrap(), b"n");
    }

    #[test]
    fn padded_writers_distinguish_required_nul_from_full_width() {
        let mut required = [0x55; 4];
        write_nul_padded(&mut required, b"abc").unwrap();
        assert_eq!(&required, b"abc\0");
        assert!(write_nul_padded(&mut required, b"abcd").is_err());

        let mut optional = [0x55; 4];
        write_nul_or_full(&mut optional, b"abcd").unwrap();
        assert_eq!(&optional, b"abcd");
        assert_eq!(fixed_field(&optional, optional.len()).unwrap(), b"abcd");
        write_nul_or_full(&mut optional, b"a").unwrap();
        assert_eq!(&optional, b"a\0\0\0");
    }

    #[test]
    fn invalid_string_writes_are_transactional() {
        for write in [
            write_nul_terminated as fn(&mut [u8], &[u8]) -> Result<()>,
            write_nul_padded,
            write_nul_or_full,
        ] {
            let mut embedded = [0x55; 4];
            assert!(matches!(
                write(&mut embedded, b"a\0b"),
                Err(Error::InvalidField {
                    what: "byte string embedded NUL position",
                    value: 1
                })
            ));
            assert_eq!(embedded, [0x55; 4]);

            let mut short = [0x55; 2];
            assert!(write(&mut short, b"abc").is_err());
            assert_eq!(short, [0x55; 2]);
        }

        let mut empty = [];
        assert!(write_nul_terminated(&mut empty, b"").is_err());
        write_nul_or_full(&mut empty, b"").unwrap();
    }
}
