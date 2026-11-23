//! Binary-coded decimal (BCD) byte conversions.
//!
//! Each packed BCD byte stores two decimal digits (`0..=9`): the tens digit in
//! the high nibble (`byte >> 4`) and the ones digit in the low nibble
//! (`byte & 0x0f`).

/// Decode one packed two-digit BCD byte into its decimal value (`0..=99`).
///
/// Returns `None` if either nibble is `>= 10`.
#[inline]
pub const fn bcd_to_u8(byte: u8) -> Option<u8> {
    let hi = byte >> 4;
    let lo = byte & 0x0f;
    if hi >= 10 || lo >= 10 {
        None
    } else {
        Some(hi * 10 + lo)
    }
}

/// Encode a decimal value (`0..=99`) into one packed two-digit BCD byte.
///
/// Returns `None` if `value >= 100`.
#[inline]
pub const fn u8_to_bcd(value: u8) -> Option<u8> {
    if value >= 100 {
        None
    } else {
        Some(((value / 10) << 4) | (value % 10))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_to_u8_exhaustive() {
        let mut valid_count = 0usize;
        for byte in 0u8..=u8::MAX {
            let hi = byte >> 4;
            let lo = byte & 0x0f;
            if hi < 10 && lo < 10 {
                let expected = hi * 10 + lo;
                assert_eq!(bcd_to_u8(byte), Some(expected));
                assert_eq!(u8_to_bcd(expected), Some(byte));
                valid_count += 1;
            } else {
                assert_eq!(bcd_to_u8(byte), None);
            }
        }
        assert_eq!(valid_count, 100);
    }

    #[test]
    fn u8_to_bcd_exhaustive() {
        for value in 0u8..100 {
            let bcd = u8_to_bcd(value).expect("0..=99 must encode");
            assert_eq!(bcd_to_u8(bcd), Some(value));
            assert_eq!(bcd >> 4, value / 10);
            assert_eq!(bcd & 0x0f, value % 10);
        }
        for value in 100u8..=u8::MAX {
            assert_eq!(u8_to_bcd(value), None);
        }
    }

    #[test]
    fn const_evaluation_works() {
        const DECODED: Option<u8> = bcd_to_u8(0x95);
        const INVALID_DECODE: Option<u8> = bcd_to_u8(0x9a);
        const ENCODED: Option<u8> = u8_to_bcd(95);
        const INVALID_ENCODE: Option<u8> = u8_to_bcd(100);

        assert_eq!(DECODED, Some(95));
        assert_eq!(INVALID_DECODE, None);
        assert_eq!(ENCODED, Some(0x95));
        assert_eq!(INVALID_ENCODE, None);
    }
}
