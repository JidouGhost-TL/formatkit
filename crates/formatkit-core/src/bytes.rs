//! Offset-addressed, bounds-checked reads over a byte slice.
//!
//! `Reader` is for sequential streams; these are for binary
//! formats that address fixed fields and offset tables by absolute position.
//! Both signal a short read the same way: `Error::Truncated`.

use crate::error::{Error, Result};

/// Byte order for formats whose fixed-offset fields can use either encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Round `value` up to a nonzero power-of-two `alignment` without overflow.
///
/// Returning `None` for an invalid alignment keeps format-specific callers in
/// control of their public error vocabulary.
pub fn checked_align_up(value: usize, alignment: usize) -> Option<usize> {
    if !alignment.is_power_of_two() {
        return None;
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
}

/// Round `value` up to a nonzero `multiple` without overflow.
///
/// Unlike [`checked_align_up`], the multiple need not be a power of two.
/// Returning `None` for zero or overflow leaves format owners in control of
/// their public diagnostics.
#[inline]
pub fn checked_align_up_multiple(value: usize, multiple: usize) -> Option<usize> {
    let remainder = value.checked_rem(multiple)?;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(multiple - remainder)
    }
}

/// Whether every boundary is ordered, within `[minimum, maximum]`, and aligned.
///
/// Equal adjacent boundaries are accepted. Returning a boolean leaves format
/// owners in control of their public diagnostics and section semantics. An
/// invalid (zero or non-power-of-two) alignment never matches; use `1` for
/// byte-granular boundaries.
pub fn monotone_bounded(
    boundaries: &[usize],
    minimum: usize,
    maximum: usize,
    alignment: usize,
) -> bool {
    alignment.is_power_of_two()
        && minimum <= maximum
        && boundaries
            .iter()
            .all(|&boundary| (minimum..=maximum).contains(&boundary) && boundary % alignment == 0)
        && boundaries.windows(2).all(|pair| pair[0] <= pair[1])
}

/// Whether `content_end` is followed by fewer than `maximum_tail` zero bytes.
///
/// This validates an allocation tail only. It does not assign meaning to the
/// content extent or require the complete carrier to have any alignment.
pub fn zero_tail_lt(bytes: &[u8], content_end: usize, maximum_tail: usize) -> bool {
    bytes
        .get(content_end..)
        .is_some_and(|tail| tail.len() < maximum_tail && tail.iter().all(|&byte| byte == 0))
}

/// Borrow `length` bytes at absolute `offset` without overflowing the range.
///
/// This is the common fixed-offset read contract used by format parsers. Both
/// an offset beyond the input and an overflowing `offset + length` are
/// reported as [`Error::Truncated`], with availability measured from `offset`.
#[inline]
pub fn bytes_at(b: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let available = b.len().saturating_sub(offset);
    let Some(end) = offset.checked_add(length) else {
        return Err(Error::Truncated {
            offset,
            needed: length,
            available,
        });
    };
    let Some(bytes) = b.get(offset..end) else {
        return Err(Error::Truncated {
            offset,
            needed: length,
            available,
        });
    };
    Ok(bytes)
}

/// Borrow an exact mutable byte range without overflowing or partially writing.
///
/// Uses the same offset and availability diagnostics as [`bytes_at`]. This
/// operation neither resizes the carrier nor assigns meaning to its bytes.
#[inline]
pub fn bytes_at_mut(b: &mut [u8], offset: usize, length: usize) -> Result<&mut [u8]> {
    let available = b.len().saturating_sub(offset);
    let Some(end) = offset.checked_add(length) else {
        return Err(Error::Truncated {
            offset,
            needed: length,
            available,
        });
    };
    let Some(bytes) = b.get_mut(offset..end) else {
        return Err(Error::Truncated {
            offset,
            needed: length,
            available,
        });
    };
    Ok(bytes)
}

/// Read an unsigned big-endian integer stored in exactly `BYTES` bytes.
///
/// Width is a static codec property and must be in `1..=8`. Carrier bounds use
/// the same structured truncation diagnostics as [`bytes_at`].
///
/// ```compile_fail
/// let _ = formatkit_core::uint_be_at::<0>(&[], 0);
/// ```
#[inline]
pub fn uint_be_at<const BYTES: usize>(b: &[u8], offset: usize) -> Result<u64> {
    const { assert!(BYTES >= 1 && BYTES <= 8) }
    Ok(bytes_at(b, offset, BYTES)?
        .iter()
        .fold(0u64, |value, &byte| (value << 8) | u64::from(byte)))
}

/// Write an unsigned big-endian integer into exactly `BYTES` existing bytes.
///
/// The value fit and destination bounds are both validated before any byte is
/// changed. Width is a static codec property and must be in `1..=8`.
///
/// ```compile_fail
/// let mut bytes = [0; 9];
/// formatkit_core::write_uint_be_at::<9>(&mut bytes, 0, 0)?;
/// # Ok::<(), formatkit_core::Error>(())
/// ```
#[inline]
pub fn write_uint_be_at<const BYTES: usize>(b: &mut [u8], offset: usize, value: u64) -> Result<()> {
    const { assert!(BYTES >= 1 && BYTES <= 8) }
    if BYTES < 8 && value >= (1u64 << (BYTES * 8)) {
        return Err(Error::InvalidField {
            what: "fixed-width big-endian integer",
            value,
        });
    }
    let target = bytes_at_mut(b, offset, BYTES)?;
    target.copy_from_slice(&value.to_be_bytes()[8 - BYTES..]);
    Ok(())
}

/// Read a `u8` at absolute offset `off`.
pub fn u8_at(b: &[u8], off: usize) -> Result<u8> {
    Ok(bytes_at(b, off, 1)?[0])
}

/// Read a little-endian `u16` at absolute offset `off`.
pub fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    let s = bytes_at(b, off, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

/// Read a `u16` in `endian` byte order at absolute offset `off`.
#[inline]
pub fn u16_at_endian(b: &[u8], off: usize, endian: Endian) -> Result<u16> {
    let s = bytes_at(b, off, 2)?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes([s[0], s[1]]),
        Endian::Big => u16::from_be_bytes([s[0], s[1]]),
    })
}

/// Read a little-endian `u32` at absolute offset `off`.
pub fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    let s = bytes_at(b, off, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a little-endian `i32` at absolute offset `off`.
#[inline]
pub fn i32_at(b: &[u8], off: usize) -> Result<i32> {
    Ok(u32_at(b, off)? as i32)
}

/// Read a `u32` in `endian` byte order at absolute offset `off`.
#[inline]
pub fn u32_at_endian(b: &[u8], off: usize, endian: Endian) -> Result<u32> {
    let s = bytes_at(b, off, 4)?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        Endian::Big => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
    })
}

/// Read a little-endian `u64` at absolute offset `off`.
#[inline]
pub fn u64_at(b: &[u8], off: usize) -> Result<u64> {
    u64_at_endian(b, off, Endian::Little)
}

/// Read a `u64` in `endian` byte order at absolute offset `off`.
#[inline]
pub fn u64_at_endian(b: &[u8], off: usize, endian: Endian) -> Result<u64> {
    let s = bytes_at(b, off, 8)?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        Endian::Big => u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
    })
}

/// Read an `i32` in `endian` byte order at absolute offset `off`.
pub fn i32_at_endian(b: &[u8], off: usize, endian: Endian) -> Result<i32> {
    Ok(u32_at_endian(b, off, endian)? as i32)
}

/// Read a little-endian `i16` at absolute offset `off`.
pub fn i16_at(b: &[u8], off: usize) -> Result<i16> {
    Ok(u16_at(b, off)? as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_multiple_alignment_is_checked() {
        assert_eq!(checked_align_up_multiple(0, 3), Some(0));
        assert_eq!(checked_align_up_multiple(6, 3), Some(6));
        assert_eq!(checked_align_up_multiple(7, 3), Some(9));
        assert_eq!(checked_align_up_multiple(7, 0), None);
        assert_eq!(checked_align_up_multiple(usize::MAX, 2), None);
        assert_eq!(checked_align_up_multiple(usize::MAX, 3), Some(usize::MAX));
    }

    #[test]
    fn u16_endian_reads_share_checked_range_semantics() {
        let bytes = [0x12, 0x34, 0x56];
        assert_eq!(u16_at_endian(&bytes, 0, Endian::Little).unwrap(), 0x3412);
        assert_eq!(u16_at_endian(&bytes, 0, Endian::Big).unwrap(), 0x1234);
        assert_eq!(
            u16_at_endian(&bytes, 2, Endian::Big).unwrap_err(),
            Error::Truncated {
                offset: 2,
                needed: 2,
                available: 1,
            }
        );
        assert_eq!(
            u16_at_endian(&bytes, usize::MAX, Endian::Little).unwrap_err(),
            Error::Truncated {
                offset: usize::MAX,
                needed: 2,
                available: 0,
            }
        );
    }

    #[test]
    fn mutable_ranges_match_reads_and_preserve_surroundings() {
        for offset in [0, 1, 4, 5, usize::MAX] {
            for length in [0, 1, 4, usize::MAX] {
                let mut bytes = [0x55; 4];
                let expected = bytes_at(&bytes, offset, length).map(|s| s.len());
                assert_eq!(
                    bytes_at_mut(&mut bytes, offset, length).map(|s| s.len()),
                    expected
                );
                assert_eq!(bytes, [0x55; 4]);
            }
        }
        let mut bytes = [0x55; 6];
        bytes_at_mut(&mut bytes, 2, 2)
            .unwrap()
            .copy_from_slice(&[1, 2]);
        assert_eq!(bytes, [0x55, 0x55, 1, 2, 0x55, 0x55]);
    }

    #[test]
    fn fixed_width_big_endian_codec_covers_every_width_and_offset() {
        for width in 1..=8 {
            let value = if width == 8 {
                0x0123_4567_89ab_cdef
            } else {
                (1u64 << (width * 8)) - 1
            };
            let mut bytes = [0xa5; 10];
            match width {
                1 => write_uint_be_at::<1>(&mut bytes, 1, value).unwrap(),
                2 => write_uint_be_at::<2>(&mut bytes, 1, value).unwrap(),
                3 => write_uint_be_at::<3>(&mut bytes, 1, value).unwrap(),
                4 => write_uint_be_at::<4>(&mut bytes, 1, value).unwrap(),
                5 => write_uint_be_at::<5>(&mut bytes, 1, value).unwrap(),
                6 => write_uint_be_at::<6>(&mut bytes, 1, value).unwrap(),
                7 => write_uint_be_at::<7>(&mut bytes, 1, value).unwrap(),
                8 => write_uint_be_at::<8>(&mut bytes, 1, value).unwrap(),
                _ => unreachable!(),
            }
            let decoded = match width {
                1 => uint_be_at::<1>(&bytes, 1).unwrap(),
                2 => uint_be_at::<2>(&bytes, 1).unwrap(),
                3 => uint_be_at::<3>(&bytes, 1).unwrap(),
                4 => uint_be_at::<4>(&bytes, 1).unwrap(),
                5 => uint_be_at::<5>(&bytes, 1).unwrap(),
                6 => uint_be_at::<6>(&bytes, 1).unwrap(),
                7 => uint_be_at::<7>(&bytes, 1).unwrap(),
                8 => uint_be_at::<8>(&bytes, 1).unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(decoded, value);
            assert_eq!(bytes[0], 0xa5);
            assert!(bytes[1 + width..].iter().all(|&byte| byte == 0xa5));
        }
    }

    #[test]
    fn fixed_width_big_endian_errors_do_not_mutate() {
        assert_eq!(
            uint_be_at::<3>(&[0; 2], 0),
            Err(Error::Truncated {
                offset: 0,
                needed: 3,
                available: 2,
            })
        );
        let mut bytes = [0xa5; 4];
        assert_eq!(
            write_uint_be_at::<3>(&mut bytes, 1, 0x1_000000),
            Err(Error::InvalidField {
                what: "fixed-width big-endian integer",
                value: 0x1_000000,
            })
        );
        assert_eq!(bytes, [0xa5; 4]);
        assert!(matches!(
            write_uint_be_at::<3>(&mut bytes, 2, 1),
            Err(Error::Truncated {
                offset: 2,
                needed: 3,
                available: 2,
            })
        ));
        assert_eq!(bytes, [0xa5; 4]);
    }

    #[test]
    fn reads_le_at_offset() {
        let b = [0xAAu8, 0x10, 0x00, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(u8_at(&b, 0).unwrap(), 0xAA);
        assert_eq!(u16_at(&b, 1).unwrap(), 0x0010);
        // bytes[5..9] = [0x78,0x56,0x34,0x12] -> LE 0x1234_5678
        assert_eq!(u32_at(&b, 5).unwrap(), 0x1234_5678);
        assert_eq!(i16_at(&b, 1).unwrap(), 0x0010i16);
        assert_eq!(u32_at_endian(&b, 5, Endian::Little).unwrap(), 0x1234_5678);
    }

    #[test]
    fn reads_both_endians_at_offset() {
        let b = [0xAA, 0x12, 0x34, 0x56, 0x78];
        assert_eq!(u32_at_endian(&b, 1, Endian::Big).unwrap(), 0x1234_5678);
        assert_eq!(u32_at_endian(&b, 1, Endian::Little).unwrap(), 0x7856_3412);
        assert_eq!(i32_at_endian(&[0xff; 4], 0, Endian::Big).unwrap(), -1);

        let b = [0xaa, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(
            u64_at_endian(&b, 1, Endian::Big).unwrap(),
            0x0123_4567_89ab_cdef
        );
        assert_eq!(u64_at(&b, 1).unwrap(), 0xefcd_ab89_6745_2301);
    }

    #[test]
    fn u64_fields_preserve_every_bit_class_and_surrounding_offsets() {
        for value in [
            0,
            1,
            1 << 63,
            u64::MAX,
            0x7ff0_0000_0000_0001,
            0x0123_4567_89ab_cdef,
        ] {
            let mut little = [0xa5; 10];
            little[1..9].copy_from_slice(&value.to_le_bytes());
            assert_eq!(u64_at(&little, 1).unwrap(), value);
            let mut big = [0x5a; 10];
            big[1..9].copy_from_slice(&value.to_be_bytes());
            assert_eq!(u64_at_endian(&big, 1, Endian::Big).unwrap(), value);
        }
    }

    #[test]
    fn short_read_is_truncated_with_offset_and_availability() {
        let b = [0x01u8, 0x02];
        assert_eq!(bytes_at(&b, 1, 1).unwrap(), &[0x02]);
        assert_eq!(bytes_at(&b, b.len(), 0).unwrap(), &[]);
        assert_eq!(
            u32_at(&b, 0),
            Err(Error::Truncated {
                offset: 0,
                needed: 4,
                available: 2
            })
        );
        // Offset past end reports zero available, not an underflow panic.
        assert_eq!(
            u16_at(&b, 5),
            Err(Error::Truncated {
                offset: 5,
                needed: 2,
                available: 0
            })
        );
        assert_eq!(
            bytes_at(&b, usize::MAX, 2),
            Err(Error::Truncated {
                offset: usize::MAX,
                needed: 2,
                available: 0
            })
        );
        assert!(matches!(
            u16_at(&b, usize::MAX),
            Err(Error::Truncated {
                offset: usize::MAX,
                needed: 2,
                available: 0
            })
        ));
        assert!(matches!(
            u32_at(&b, usize::MAX),
            Err(Error::Truncated {
                offset: usize::MAX,
                needed: 4,
                available: 0
            })
        ));
        assert!(matches!(
            u32_at_endian(&b, usize::MAX, Endian::Big),
            Err(Error::Truncated {
                offset: usize::MAX,
                needed: 4,
                available: 0
            })
        ));
        for offset in 0..=b.len() {
            assert_eq!(
                u64_at(&b, offset),
                Err(Error::Truncated {
                    offset,
                    needed: 8,
                    available: b.len().saturating_sub(offset),
                })
            );
        }
        assert_eq!(
            u64_at_endian(&b, usize::MAX, Endian::Big),
            Err(Error::Truncated {
                offset: usize::MAX,
                needed: 8,
                available: 0,
            })
        );
    }

    #[test]
    fn checked_alignment_rejects_invalid_and_overflowing_requests() {
        assert_eq!(checked_align_up(0x21, 0x20), Some(0x40));
        assert_eq!(checked_align_up(0x40, 0x20), Some(0x40));
        assert_eq!(checked_align_up(1, 0), None);
        assert_eq!(checked_align_up(1, 3), None);
        assert_eq!(checked_align_up(usize::MAX, 2), None);
    }

    #[test]
    fn monotone_bounds_keep_order_range_and_alignment_independent() {
        assert!(monotone_bounded(&[], 4, 8, 4));
        assert!(monotone_bounded(&[4, 4, 8], 4, 8, 4));
        assert!(!monotone_bounded(&[4, 3], 0, 8, 1));
        assert!(!monotone_bounded(&[0, 4], 1, 8, 1));
        assert!(!monotone_bounded(&[4, 12], 0, 8, 1));
        assert!(!monotone_bounded(&[4, 6], 0, 8, 4));
        assert!(!monotone_bounded(&[4], 0, 8, 0));
        assert!(!monotone_bounded(&[4], 0, 8, 3));
        assert!(!monotone_bounded(&[], 8, 4, 1));
    }

    #[test]
    fn zero_tail_is_bounded_exclusive_and_never_indexes_out_of_range() {
        let bytes = [1, 2, 0, 0, 0];
        assert!(zero_tail_lt(&bytes, 2, 4));
        assert!(zero_tail_lt(&bytes, bytes.len(), 1));
        assert!(!zero_tail_lt(&bytes, 1, 5));
        assert!(!zero_tail_lt(&bytes, 2, 3));
        assert!(!zero_tail_lt(&bytes, 2, 0));
        assert!(!zero_tail_lt(&bytes, bytes.len() + 1, 16));
        assert!(!zero_tail_lt(&bytes, usize::MAX, 16));
    }

    #[test]
    fn signed_le_at_offset() {
        let b = [0xFFu8, 0x00, 0x80];
        assert_eq!(i16_at(&b, 1).unwrap(), -32768i16);
    }

    #[test]
    fn signed_i32_le_preserves_bits_and_checked_range_errors() {
        for value in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut bytes = [0xa5; 6];
            bytes[1..5].copy_from_slice(&value.to_le_bytes());
            assert_eq!(i32_at(&bytes, 1).unwrap(), value);
        }
        for available in 0..4 {
            let bytes = vec![0; available];
            assert_eq!(
                i32_at(&bytes, 0),
                Err(Error::Truncated {
                    offset: 0,
                    needed: 4,
                    available,
                })
            );
        }
        assert_eq!(
            i32_at(&[0; 4], usize::MAX),
            Err(Error::Truncated {
                offset: usize::MAX,
                needed: 4,
                available: 0,
            })
        );
    }
}
