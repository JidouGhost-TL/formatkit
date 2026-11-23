//! Pure-Rust Shift-JIS / CP932 (Windows-31J / WHATWG `shift_jis`) and
//! JIS X 0201 byte classification, validation, and UTF-8 conversion helpers.

use std::sync::OnceLock;

use super::shift_jis_table::{
    POINTER_HIGH, POINTER_HIGH_LEN, POINTER_HIGH_START, POINTER_LOW, POINTER_LOW_LEN,
    POINTER_NEC_IBM_START, POINTER_PUA_END, POINTER_PUA_START,
};
use crate::{Error, Result};

/// Classification of a single leading byte in Shift-JIS / CP932.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftJisByteClass {
    /// 7-bit ASCII byte (`0x00..=0x7F`).
    Ascii,
    /// Single-byte JIS X 0201 half-width katakana (`0xA1..=0xDF`).
    HalfwidthKatakana,
    /// First byte of a two-byte sequence (`0x81..=0x9F` or `0xE0..=0xFC`).
    Lead,
    /// Single-byte CP932 / WHATWG Shift_JIS extension (`0x80` -> `U+0080`).
    Cp932SingleByte,
    /// Unassigned single byte (`0xA0`, `0xFD..=0xFF`).
    Invalid,
}

/// Returns `true` if `byte` is a valid Shift-JIS / CP932 lead byte
/// (`0x81..=0x9F` or `0xE0..=0xFC`).
#[must_use]
pub const fn is_shift_jis_lead(byte: u8) -> bool {
    matches!(byte, 0x81..=0x9F | 0xE0..=0xFC)
}

/// Returns `true` if `byte` is a valid JIS X 0208 lead byte range
/// (`0x81..=0x9F` or `0xE0..=0xEF`).
#[must_use]
pub const fn is_jis0208_lead(byte: u8) -> bool {
    matches!(byte, 0x81..=0x9F | 0xE0..=0xEF)
}

/// Returns `true` if `byte` is a valid Shift-JIS / CP932 trail byte
/// (`0x40..=0x7E` or `0x80..=0xFC`).
#[must_use]
pub const fn is_shift_jis_trail(byte: u8) -> bool {
    matches!(byte, 0x40..=0x7E | 0x80..=0xFC)
}

/// Returns `true` if `byte` is a single-byte JIS X 0201 half-width katakana
/// (`0xA1..=0xDF`).
#[must_use]
pub const fn is_halfwidth_katakana(byte: u8) -> bool {
    matches!(byte, 0xA1..=0xDF)
}

/// Classify a byte as it appears at the start of a Shift-JIS / CP932 character.
#[must_use]
pub const fn classify_shift_jis_byte(byte: u8) -> ShiftJisByteClass {
    match byte {
        0x00..=0x7F => ShiftJisByteClass::Ascii,
        0x80 => ShiftJisByteClass::Cp932SingleByte,
        0x81..=0x9F | 0xE0..=0xFC => ShiftJisByteClass::Lead,
        0xA1..=0xDF => ShiftJisByteClass::HalfwidthKatakana,
        0xA0 | 0xFD..=0xFF => ShiftJisByteClass::Invalid,
    }
}

/// Expected byte length (`1` or `2`) for a Shift-JIS sequence starting with
/// `lead`, or `None` for invalid/unassigned lead bytes (`0x80`, `0xA0`,
/// `0xFD..=0xFF`).
#[must_use]
pub const fn shift_jis_sequence_len(lead: u8) -> Option<usize> {
    match lead {
        0x00..=0x7F | 0xA1..=0xDF => Some(1),
        0x81..=0x9F | 0xE0..=0xFC => Some(2),
        _ => None,
    }
}

/// Convert a two-byte Shift-JIS code (`lead`, `trail`) into 1-based JIS X 0208
/// `(ku, ten)` coordinates in `1..=94`, or `None` if outside the JIS X 0208
/// coordinate grid.
#[must_use]
pub const fn shift_jis_to_ku_ten(lead: u8, trail: u8) -> Option<(u8, u8)> {
    if !is_jis0208_lead(lead) || !is_shift_jis_trail(trail) {
        return None;
    }
    let (j1, j2) = if trail < 0x9F {
        let j1 = ((lead as u16) << 1) - if lead < 0xA0 { 0xE1 } else { 0x161 };
        let j2 = (trail as u16) - if trail > 0x7F { 0x20 } else { 0x1F };
        (j1, j2)
    } else {
        let j1 = ((lead as u16) << 1) - if lead < 0xA0 { 0xE0 } else { 0x160 };
        let j2 = (trail as u16) - 0x7E;
        (j1, j2)
    };
    if j1 < 0x21 || j1 > 0x7E || j2 < 0x21 || j2 > 0x7E {
        return None;
    }
    Some(((j1 - 0x20) as u8, (j2 - 0x20) as u8))
}

/// Convert 1-based JIS X 0208 `(ku, ten)` coordinates (`1..=94`) into a
/// two-byte Shift-JIS pair `[lead, trail]`.
#[must_use]
pub const fn ku_ten_to_shift_jis(ku: u8, ten: u8) -> Option<[u8; 2]> {
    if ku < 1 || ku > 94 || ten < 1 || ten > 94 {
        return None;
    }
    let lead = if ku <= 62 {
        ((ku - 1) >> 1) + 0x81
    } else {
        ((ku - 1) >> 1) + 0xC1
    };
    let trail = if ku & 1 == 1 {
        let raw = ten + 0x3F;
        if raw >= 0x7F {
            raw + 1
        } else {
            raw
        }
    } else {
        ten + 0x9E
    };
    Some([lead, trail])
}

#[inline]
const fn pair_to_pointer(lead: u8, trail: u8) -> Option<usize> {
    if !is_shift_jis_lead(lead) || !is_shift_jis_trail(trail) {
        return None;
    }
    let lead_offset = if lead < 0xA0 { 0x81 } else { 0xC1 };
    let trail_offset = if trail < 0x7F { 0x40 } else { 0x41 };
    Some(((lead - lead_offset) as usize) * 188 + ((trail - trail_offset) as usize))
}

#[inline]
const fn pointer_to_pair(pointer: usize) -> [u8; 2] {
    let lead = pointer / 188;
    let lead_offset = if lead < 0x1F { 0x81 } else { 0xC1 };
    let trail = pointer % 188;
    let trail_offset = if trail < 0x3F { 0x40 } else { 0x41 };
    [(lead + lead_offset) as u8, (trail + trail_offset) as u8]
}

/// Decode a single two-byte CP932 / WHATWG `shift_jis` pair without allocating.
///
/// Covers JIS X 0208, NEC specials (`0x87xx`), NEC-selected IBM extensions
/// (`0xEDxx..=0xEExx`), the PUA block (`0xF0xx..=0xF9xx` -> `U+E000..=U+E757`),
/// and IBM extensions (`0xFAxx..=0xFC4B`).
#[must_use]
pub fn decode_cp932_pair(lead: u8, trail: u8) -> Option<char> {
    let pointer = pair_to_pointer(lead, trail)?;
    let cp = if pointer < POINTER_LOW_LEN {
        u32::from(POINTER_LOW[pointer])
    } else if (POINTER_PUA_START..=POINTER_PUA_END).contains(&pointer) {
        0xE000 + (pointer - POINTER_PUA_START) as u32
    } else if pointer >= POINTER_HIGH_START && pointer - POINTER_HIGH_START < POINTER_HIGH_LEN {
        u32::from(POINTER_HIGH[pointer - POINTER_HIGH_START])
    } else {
        0
    };
    if cp == 0 {
        None
    } else {
        char::from_u32(cp)
    }
}

/// Decode a single two-byte strict JIS X 0208 Shift-JIS pair (excluding
/// Windows-31J NEC/IBM vendor extensions and applying the six standard JIS
/// Unicode code-point mappings).
#[must_use]
pub fn decode_jis0208_pair(lead: u8, trail: u8) -> Option<char> {
    if !matches!(lead, 0x81..=0x9F | 0xE0..=0xEA) || lead == 0x87 || !is_shift_jis_trail(trail) {
        return None;
    }
    let pointer = pair_to_pointer(lead, trail)?;
    // JIS X 0208 row 84 ends at 0xEAA4 (pointer 7906).
    if pointer > 7906 {
        return None;
    }
    let cp = u32::from(POINTER_LOW[pointer]);
    if cp == 0 {
        return None;
    }
    let overridden = match u16::from_be_bytes([lead, trail]) {
        0x8160 => '\u{301C}',
        0x8161 => '\u{2016}',
        0x817C => '\u{2212}',
        0x8191 => '\u{00A2}',
        0x8192 => '\u{00A3}',
        0x81CA => '\u{00AC}',
        _ => return char::from_u32(cp),
    };
    Some(overridden)
}

/// Check structural Shift-JIS byte framing without requiring every two-byte
/// cell to be assigned in a specific code-page table.
///
/// Accepts ASCII (`0x00..=0x7F`), half-width katakana (`0xA1..=0xDF`), and
/// paired lead (`0x81..=0x9F | 0xE0..=0xFC`) + trail (`0x40..=0x7E |
/// 0x80..=0xFC`) sequences.
#[must_use]
pub fn is_valid_shift_jis_syntax(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        match lead {
            0x00..=0x7F | 0xA1..=0xDF => index += 1,
            0x81..=0x9F | 0xE0..=0xFC => {
                let Some(&trail) = bytes.get(index + 1) else {
                    return false;
                };
                if !is_shift_jis_trail(trail) {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    true
}

/// Returns `true` if `bytes` is strictly valid CP932 / WHATWG `shift_jis`
/// without allocating.
#[must_use]
pub fn is_valid_cp932(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        match lead {
            0x00..=0x80 | 0xA1..=0xDF => index += 1,
            0x81..=0x9F | 0xE0..=0xFC => {
                let Some(&trail) = bytes.get(index + 1) else {
                    return false;
                };
                if decode_cp932_pair(lead, trail).is_none() {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    true
}

/// Returns `true` if `bytes` is strictly valid JIS X 0208 Shift-JIS (no
/// Windows-31J vendor extensions) without allocating.
#[must_use]
pub fn is_valid_shift_jis_jis0208(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        match lead {
            0x00..=0x7F | 0xA1..=0xDF => index += 1,
            0x81..=0x9F | 0xE0..=0xEA => {
                let Some(&trail) = bytes.get(index + 1) else {
                    return false;
                };
                if decode_jis0208_pair(lead, trail).is_none() {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    true
}

/// Returns `true` if every byte in `bytes` is a valid 8-bit JIS X 0201 byte
/// (`0x00..=0x7F` or `0xA1..=0xDF`).
#[must_use]
pub fn is_valid_jis_x_0201(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b <= 0x7F || is_halfwidth_katakana(b))
}

/// Strictly decode CP932 / WHATWG `shift_jis` bytes to UTF-8.
///
/// Rejects truncated lead bytes, unmapped two-byte pairs, and invalid single
/// bytes (`0xA0`, `0xFD..=0xFF`).
pub fn decode_cp932(bytes: &[u8]) -> Result<String> {
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        match lead {
            0x00..=0x80 => {
                out.push(char::from(lead));
                index += 1;
            }
            0xA1..=0xDF => {
                out.push(
                    char::from_u32(0xFF61 + u32::from(lead - 0xA1))
                        .expect("halfwidth katakana scalar"),
                );
                index += 1;
            }
            0x81..=0x9F | 0xE0..=0xFC => {
                let Some(&trail) = bytes.get(index + 1) else {
                    return Err(Error::Malformed(format!(
                        "truncated Shift-JIS lead byte {lead:#04x} at offset {index}"
                    )));
                };
                let Some(ch) = decode_cp932_pair(lead, trail) else {
                    return Err(Error::Malformed(format!(
                        "invalid CP932 byte pair {lead:#04x} {trail:#04x} at offset {index}"
                    )));
                };
                out.push(ch);
                index += 2;
            }
            _ => {
                return Err(Error::Malformed(format!(
                    "invalid CP932 byte {lead:#04x} at offset {index}"
                )));
            }
        }
    }
    Ok(out)
}

/// Lossily decode CP932 / WHATWG `shift_jis` bytes to UTF-8, replacing invalid
/// sequences with `U+FFFD`.
///
/// Follows WHATWG error-consumption rules: when a lead byte is followed by an
/// ASCII byte (`<= 0x7F`), `U+FFFD` is emitted for the lead byte and the ASCII
/// byte is reprocessed; otherwise the invalid pair is consumed together.
#[must_use]
pub fn decode_cp932_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        match lead {
            0x00..=0x80 => {
                out.push(char::from(lead));
                index += 1;
            }
            0xA1..=0xDF => {
                out.push(
                    char::from_u32(0xFF61 + u32::from(lead - 0xA1))
                        .expect("halfwidth katakana scalar"),
                );
                index += 1;
            }
            0x81..=0x9F | 0xE0..=0xFC => {
                if let Some(&trail) = bytes.get(index + 1) {
                    if let Some(ch) = decode_cp932_pair(lead, trail) {
                        out.push(ch);
                        index += 2;
                    } else {
                        out.push('\u{FFFD}');
                        // WHATWG Shift_JIS decoder: prepend ASCII trail byte back to stream.
                        if trail <= 0x7F {
                            index += 1;
                        } else {
                            index += 2;
                        }
                    }
                } else {
                    out.push('\u{FFFD}');
                    index += 1;
                }
            }
            _ => {
                out.push('\u{FFFD}');
                index += 1;
            }
        }
    }
    out
}

/// Strictly decode JIS X 0208 Shift-JIS bytes to UTF-8, excluding Windows-31J
/// vendor extensions (`0x80`, `0x87xx`, `0xEDxx..=0xFCxx`) and preserving the
/// six standard JIS Unicode mappings (`U+301C`, `U+2016`, `U+2212`, `U+00A2`,
/// `U+00A3`, `U+00AC`).
pub fn decode_shift_jis_jis0208(bytes: &[u8]) -> Result<String> {
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        match lead {
            0x00..=0x7F => {
                out.push(char::from(lead));
                index += 1;
            }
            0xA1..=0xDF => {
                out.push(
                    char::from_u32(0xFF61 + u32::from(lead - 0xA1))
                        .expect("halfwidth katakana scalar"),
                );
                index += 1;
            }
            0x81..=0x9F | 0xE0..=0xEA => {
                let Some(&trail) = bytes.get(index + 1) else {
                    return Err(Error::Malformed(format!(
                        "truncated JIS X 0208 Shift-JIS lead byte {lead:#04x} at offset {index}"
                    )));
                };
                let Some(ch) = decode_jis0208_pair(lead, trail) else {
                    return Err(Error::Malformed(format!(
                        "invalid JIS X 0208 Shift-JIS pair {lead:#04x} {trail:#04x} at offset {index}"
                    )));
                };
                out.push(ch);
                index += 2;
            }
            _ => {
                return Err(Error::Malformed(format!(
                    "invalid JIS X 0208 Shift-JIS byte {lead:#04x} at offset {index}"
                )));
            }
        }
    }
    Ok(out)
}

/// Lossily decode JIS X 0208 Shift-JIS bytes to UTF-8, replacing each invalid
/// byte with `U+FFFD` and retrying the following byte (matching strict
/// single-byte error recovery).
#[must_use]
pub fn decode_shift_jis_jis0208_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        if lead < 0x80 {
            out.push(char::from(lead));
            index += 1;
            continue;
        }
        if is_halfwidth_katakana(lead) {
            out.push(
                char::from_u32(0xFF61 + u32::from(lead - 0xA1)).expect("halfwidth katakana scalar"),
            );
            index += 1;
            continue;
        }
        if let Some(&trail) = bytes.get(index + 1) {
            if let Some(ch) = decode_jis0208_pair(lead, trail) {
                out.push(ch);
                index += 2;
                continue;
            }
        }
        out.push('\u{FFFD}');
        index += 1;
    }
    out
}

fn cp932_encode_table() -> &'static [(u16, u16)] {
    static REVERSE: OnceLock<Vec<(u16, u16)>> = OnceLock::new();
    REVERSE.get_or_init(|| {
        // Collect (unicode_cp, pointer) in ascending pointer order, skipping
        // WHATWG Shift_JIS excluded encoder range 8272..=8835 (0xED40..=0xEEFC).
        let mut pairs: Vec<(u16, usize)> = Vec::with_capacity(7400);
        for (pointer, &cp) in POINTER_LOW[..POINTER_NEC_IBM_START].iter().enumerate() {
            if cp != 0 {
                pairs.push((cp, pointer));
            }
        }
        for (offset, &cp) in POINTER_HIGH.iter().enumerate() {
            if cp != 0 {
                pairs.push((cp, POINTER_HIGH_START + offset));
            }
        }
        // Sort by (cp, pointer) so the lowest pointer wins for duplicate code points.
        pairs.sort_unstable();
        pairs.dedup_by_key(|entry| entry.0);
        pairs
            .into_iter()
            .map(|(cp, pointer)| {
                let [lead, trail] = pointer_to_pair(pointer);
                (cp, u16::from_be_bytes([lead, trail]))
            })
            .collect()
    })
}

/// Encode a single Unicode scalar value to CP932 / WHATWG `shift_jis`.
///
/// Returns `Some(([b0, b1], len))` where `len` is `1` or `2`, or `None` if the
/// character is not representable in WHATWG `shift_jis`.
#[must_use]
pub fn encode_cp932_char(ch: char) -> Option<([u8; 2], usize)> {
    let cp = ch as u32;
    if cp <= 0x80 {
        return Some(([cp as u8, 0], 1));
    }
    match cp {
        0x00A5 => return Some(([0x5C, 0], 1)),
        0x203E => return Some(([0x7E, 0], 1)),
        0xFF61..=0xFF9F => return Some(([0xA1 + (cp - 0xFF61) as u8, 0], 1)),
        _ => {}
    }
    // WHATWG Shift_JIS encoder maps U+2212 (MINUS SIGN) to U+FF0D (0x81 0x7C).
    let lookup = if cp == 0x2212 {
        0xFF0Du16
    } else {
        u16::try_from(cp).ok()?
    };
    let table = cp932_encode_table();
    let idx = table.binary_search_by_key(&lookup, |&(c, _)| c).ok()?;
    let bytes = table[idx].1.to_be_bytes();
    Some((bytes, 2))
}

/// Strictly encode UTF-8 text to CP932 / WHATWG `shift_jis`.
///
/// Rejects any character not representable in WHATWG `shift_jis`.
pub fn encode_cp932(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let Some((bytes, len)) = encode_cp932_char(ch) else {
            return Err(Error::Malformed(format!(
                "unencodable CP932 character U+{:04X}",
                ch as u32
            )));
        };
        out.extend_from_slice(&bytes[..len]);
    }
    Ok(out)
}

/// Strictly decode 8-bit JIS X 0201 bytes (Roman `0x5C` -> `'¥'`,
/// `0x7E` -> `'‾'`, ASCII `0x00..=0x7F`, and half-width katakana
/// `0xA1..=0xDF`).
pub fn decode_jis_x_0201(bytes: &[u8]) -> Result<String> {
    let mut out = String::with_capacity(bytes.len());
    for (index, &b) in bytes.iter().enumerate() {
        let ch = match b {
            0x5C => '¥',
            0x7E => '‾',
            0x00..=0x7F => char::from(b),
            0xA1..=0xDF => {
                char::from_u32(0xFF61 + u32::from(b - 0xA1)).expect("halfwidth katakana scalar")
            }
            _ => {
                return Err(Error::Malformed(format!(
                    "undefined JIS X 0201 byte {b:#04x} at offset {index}"
                )));
            }
        };
        out.push(ch);
    }
    Ok(out)
}

/// Strictly encode UTF-8 text to 8-bit JIS X 0201 bytes.
///
/// Maps `'¥'` -> `0x5C` and `'‾'` -> `0x7E`, rejects ASCII `'\\'` and `'~'`
/// (which are replaced by yen and overline in JIS X 0201 Roman), and maps
/// half-width katakana `U+FF61..=U+FF9F` -> `0xA1..=0xDF`.
pub fn encode_jis_x_0201(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let b = match ch {
            '¥' => 0x5C,
            '‾' => 0x7E,
            '\u{0000}'..='\u{007F}' if ch != '\\' && ch != '~' => ch as u8,
            '\u{FF61}'..='\u{FF9F}' => 0xA1 + (ch as u32 - 0xFF61) as u8,
            _ => {
                return Err(Error::Malformed(format!(
                    "unencodable JIS X 0201 character U+{:04X}",
                    ch as u32
                )));
            }
        };
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_classification_and_lengths() {
        assert_eq!(classify_shift_jis_byte(b'A'), ShiftJisByteClass::Ascii);
        assert_eq!(
            classify_shift_jis_byte(0x80),
            ShiftJisByteClass::Cp932SingleByte
        );
        assert_eq!(classify_shift_jis_byte(0x81), ShiftJisByteClass::Lead);
        assert_eq!(classify_shift_jis_byte(0x9F), ShiftJisByteClass::Lead);
        assert_eq!(classify_shift_jis_byte(0xE0), ShiftJisByteClass::Lead);
        assert_eq!(classify_shift_jis_byte(0xFC), ShiftJisByteClass::Lead);
        assert_eq!(
            classify_shift_jis_byte(0xA1),
            ShiftJisByteClass::HalfwidthKatakana
        );
        assert_eq!(
            classify_shift_jis_byte(0xDF),
            ShiftJisByteClass::HalfwidthKatakana
        );
        assert_eq!(classify_shift_jis_byte(0xA0), ShiftJisByteClass::Invalid);
        assert_eq!(classify_shift_jis_byte(0xFD), ShiftJisByteClass::Invalid);
        assert_eq!(classify_shift_jis_byte(0xFF), ShiftJisByteClass::Invalid);

        assert_eq!(shift_jis_sequence_len(b'Z'), Some(1));
        assert_eq!(shift_jis_sequence_len(0xB1), Some(1));
        assert_eq!(shift_jis_sequence_len(0x82), Some(2));
        assert_eq!(shift_jis_sequence_len(0x80), None);
        assert_eq!(shift_jis_sequence_len(0xA0), None);
        assert_eq!(shift_jis_sequence_len(0xFE), None);

        assert!(is_shift_jis_lead(0x81));
        assert!(is_shift_jis_lead(0xFC));
        assert!(!is_jis0208_lead(0xF0));
        assert!(is_jis0208_lead(0xEF));
        assert!(is_shift_jis_trail(0x40));
        assert!(!is_shift_jis_trail(0x7F));
        assert!(is_shift_jis_trail(0xFC));
        assert!(is_halfwidth_katakana(0xA1));
        assert!(is_halfwidth_katakana(0xDF));
    }

    #[test]
    fn ku_ten_round_trips_every_jis0208_cell() {
        for ku in 1..=94u8 {
            for ten in 1..=94u8 {
                let [lead, trail] = ku_ten_to_shift_jis(ku, ten).unwrap();
                assert_eq!(shift_jis_to_ku_ten(lead, trail), Some((ku, ten)));
            }
        }
        assert_eq!(shift_jis_to_ku_ten(0x81, 0x40), Some((1, 1)));
        assert_eq!(shift_jis_to_ku_ten(0x82, 0x4F), Some((3, 16))); // '０'
        assert_eq!(shift_jis_to_ku_ten(0x82, 0xA0), Some((4, 2))); // 'あ'
        assert_eq!(shift_jis_to_ku_ten(0x81, 0x7F), None);
        assert_eq!(ku_ten_to_shift_jis(0, 1), None);
        assert_eq!(ku_ten_to_shift_jis(95, 1), None);
    }

    #[test]
    fn cp932_round_trips_ascii_kana_kanji_and_extensions() {
        let sample = "Hello あいｶﾞ①髙黒¥‾−";
        let encoded = encode_cp932(sample).unwrap();
        assert!(is_valid_cp932(&encoded));
        let decoded = decode_cp932(&encoded).unwrap();
        // WHATWG Shift_JIS maps ¥ -> 0x5C ('\'), ‾ -> 0x7E ('~'), − -> 0x817C ('－').
        assert_eq!(decoded, "Hello あいｶﾞ①髙黒\\~－");

        // Standard hiragana + halfwidth katakana exact round-trip.
        let exact = [0x82, 0xA0, 0x82, 0xA2, 0xB6, 0xDE];
        assert_eq!(decode_cp932(&exact).unwrap(), "あいｶﾞ");
        assert_eq!(encode_cp932("あいｶﾞ").unwrap(), exact);

        // PUA decoding (0xF040 -> U+E000) and non-encodable PUA.
        assert_eq!(decode_cp932(&[0xF0, 0x40]).unwrap(), "\u{E000}");
        assert!(encode_cp932("\u{E000}").is_err());

        // 0x80 is valid in CP932 / WHATWG Shift_JIS.
        assert_eq!(decode_cp932(&[0x80]).unwrap(), "\u{0080}");
        assert_eq!(encode_cp932("\u{0080}").unwrap(), &[0x80]);

        // Unencodable emoji fails strictly.
        assert!(encode_cp932("😀").is_err());
    }

    #[test]
    fn cp932_rejects_malformed_and_lossy_recovers_ascii() {
        for bad in [
            &[0x81][..],
            &[0x81, 0x3F][..],
            &[0x81, 0x7F][..],
            &[0xA0][..],
            &[0xFD][..],
            &[0xFF][..],
        ] {
            assert!(!is_valid_cp932(bad));
            assert!(decode_cp932(bad).is_err());
        }

        // Lead byte followed by ASCII byte forming an invalid/unmapped pair -> U+FFFD + ASCII.
        assert_eq!(decode_cp932_lossy(&[0x81, b' ']), "\u{FFFD} ");
        assert_eq!(decode_cp932_lossy(&[0x85, b'A']), "\u{FFFD}A");
        // Lead byte followed by invalid non-ASCII trail -> single U+FFFD.
        assert_eq!(decode_cp932_lossy(&[0x81, 0xFF, b'B']), "\u{FFFD}B");
        // Truncated lead at end.
        assert_eq!(decode_cp932_lossy(&[b'X', 0x82]), "X\u{FFFD}");
    }

    #[test]
    fn jis0208_preserves_standard_mappings_and_rejects_vendor_extensions() {
        // Six standard JIS X 0208 mappings vs CP932.
        let six = [
            0x81, 0x60, 0x81, 0x61, 0x81, 0x7C, 0x81, 0x91, 0x81, 0x92, 0x81, 0xCA,
        ];
        assert_eq!(
            decode_shift_jis_jis0208(&six).unwrap(),
            "\u{301C}\u{2016}\u{2212}\u{00A2}\u{00A3}\u{00AC}"
        );
        assert_eq!(
            decode_cp932(&six).unwrap(),
            "\u{FF5E}\u{2225}\u{FF0D}\u{FFE0}\u{FFE1}\u{FFE2}"
        );

        // NEC special (0x8740 = ①) and 0x80 are valid CP932 but rejected by JIS X 0208.
        assert!(is_valid_cp932(&[0x87, 0x40]));
        assert!(!is_valid_shift_jis_jis0208(&[0x87, 0x40]));
        assert!(decode_shift_jis_jis0208(&[0x87, 0x40]).is_err());
        assert!(decode_shift_jis_jis0208(&[0x80]).is_err());
        assert_eq!(
            decode_shift_jis_jis0208_lossy(&[0x81, 0x60, 0x80, 0x87, 0x40]),
            "\u{301C}\u{FFFD}\u{FFFD}@"
        );
    }

    #[test]
    fn jis_x_0201_strict_round_trip() {
        assert!(is_valid_jis_x_0201(&[0x20, 0x5C, 0x7E, 0xA1, 0xDF]));
        assert!(!is_valid_jis_x_0201(&[0x80]));
        assert!(!is_valid_jis_x_0201(&[0xA0]));

        assert_eq!(decode_jis_x_0201(&[0x5C, 0x7E, 0xA1, 0xDF]).unwrap(), "¥‾｡ﾟ");
        assert_eq!(
            encode_jis_x_0201("¥‾｡ﾟ").unwrap(),
            vec![0x5C, 0x7E, 0xA1, 0xDF]
        );
        assert!(encode_jis_x_0201("\\").is_err());
        assert!(encode_jis_x_0201("~").is_err());
        assert!(encode_jis_x_0201("あ").is_err());
        assert!(decode_jis_x_0201(&[0x80]).is_err());
    }

    #[test]
    fn syntax_validation_handles_structural_framing() {
        assert!(is_valid_shift_jis_syntax(b"ABC\x82\xA0\xB1"));
        assert!(!is_valid_shift_jis_syntax(b"\x82"));
        assert!(!is_valid_shift_jis_syntax(b"\x82\x7F"));
        assert!(!is_valid_shift_jis_syntax(b"\x80"));
        assert!(!is_valid_shift_jis_syntax(b"\xA0"));
    }
}
