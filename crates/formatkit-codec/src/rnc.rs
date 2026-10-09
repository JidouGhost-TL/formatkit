//! Rob Northen Computing ProPack method-2 streams.
//!
//! Method 2 is the speed-oriented, MSB-first LZ variant. Control bits and raw
//! bytes share one source cursor: a control byte is consumed when the bit pool
//! empties, while literal and offset bytes are read directly from the same
//! cursor. The 18-byte envelope supplies exact packed and unpacked extents plus
//! CRC-16 checks for both sides, so malformed streams can be rejected without
//! accepting a magic-only guess.

use formatkit_core::MsbInterleavedBitReader;

const HEADER_LEN: usize = 18;
const IDENTIFY_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

/// Parsed fields from an `RNC\x02` data envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rnc2Header {
    pub unpacked_size: u32,
    pub packed_size: u32,
    pub unpacked_crc16: u16,
    pub packed_crc16: u16,
    pub leeway: u8,
    pub chunks: u8,
}

impl Rnc2Header {
    /// Parse a complete method-2 envelope, including its exact packed extent.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.get(..4)? != b"RNC\x02" {
            return None;
        }
        let header = Self {
            unpacked_size: u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?),
            packed_size: u32::from_be_bytes(bytes.get(8..12)?.try_into().ok()?),
            unpacked_crc16: u16::from_be_bytes(bytes.get(12..14)?.try_into().ok()?),
            packed_crc16: u16::from_be_bytes(bytes.get(14..16)?.try_into().ok()?),
            leeway: *bytes.get(16)?,
            chunks: *bytes.get(17)?,
        };
        let packed_size = usize::try_from(header.packed_size).ok()?;
        (bytes.len() == HEADER_LEN.checked_add(packed_size)?).then_some(header)
    }
}

/// The CRC-16/IBM checksum stored in both RNC envelope checksum fields.
pub fn rnc_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
    }
    crc
}

fn bits(input: &mut MsbInterleavedBitReader<'_>, count: u8) -> Option<usize> {
    let mut value = 0usize;
    for _ in 0..count {
        value = (value << 1) | usize::from(input.read_bit()?);
    }
    Some(value)
}

fn match_offset(input: &mut MsbInterleavedBitReader<'_>) -> Option<usize> {
    let mut high = 0usize;
    if input.read_bit()? {
        high = usize::from(input.read_bit()?);
        if input.read_bit()? {
            high = ((high << 1) | usize::from(input.read_bit()?)) | 4;
            if !input.read_bit()? {
                high = (high << 1) | usize::from(input.read_bit()?);
            }
        } else if high == 0 {
            high = usize::from(input.read_bit()?) + 2;
        }
    }
    ((high << 8) | usize::from(input.read_byte()?)).checked_add(1)
}

fn append_match(output: &mut Vec<u8>, distance: usize, count: usize, target: usize) -> Option<()> {
    if distance == 0 || distance > output.len() || count > target.checked_sub(output.len())? {
        return None;
    }
    for _ in 0..count {
        output.push(output[output.len() - distance]);
    }
    Some(())
}

/// Decode a complete RNC ProPack method-2 envelope.
///
/// Key-protected streams are rejected by this convenience entry point. Use
/// [`rnc2_decompress_with_key_and_limit`] when the title supplies a key.
pub fn rnc2_decompress(bytes: &[u8]) -> Option<Vec<u8>> {
    rnc2_decompress_with_key_and_limit(bytes, None, usize::MAX)
}

/// Decode a complete method-2 envelope while bounding its declared output.
pub fn rnc2_decompress_with_limit(bytes: &[u8], max_output_len: usize) -> Option<Vec<u8>> {
    rnc2_decompress_with_key_and_limit(bytes, None, max_output_len)
}

/// Decode a complete method-2 stream under an aggregate work budget.
///
/// This is a top-level charging entry point. Do not call it from a
/// [`formatkit_core::materialize_transformed_member`] codec closure: that executor
/// already owns the materialized-byte charge. Use the bounded compatibility
/// decoder inside such a closure instead.
pub fn rnc2_decompress_with_work_budget(
    bytes: &[u8],
    max_output_len: usize,
    budget: &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<Vec<u8>> {
    let header = Rnc2Header::parse(bytes)
        .ok_or_else(|| formatkit_core::Error::Malformed("invalid RNC method-2 envelope".into()))?;
    let declared = usize::try_from(header.unpacked_size).map_err(|_| {
        formatkit_core::Error::ResourceLimit {
            resource: "RNC decoded bytes",
            requested: u64::from(header.unpacked_size),
            limit: usize::MAX as u64,
        }
    })?;
    if declared > max_output_len {
        return Err(formatkit_core::Error::ResourceLimit {
            resource: "RNC decoded bytes",
            requested: declared as u64,
            limit: max_output_len as u64,
        });
    }
    budget.charge(
        formatkit_core::WorkResource::MaterializedBytes,
        declared as u64,
    )?;
    let decoded = rnc2_decompress_with_limit(bytes, declared)
        .ok_or_else(|| formatkit_core::Error::Malformed("invalid RNC method-2 stream".into()))?;
    if decoded.len() != declared {
        return Err(formatkit_core::Error::Malformed(format!(
            "RNC method-2 stream decoded to {} bytes, expected {declared}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Decode a complete method-2 envelope with an optional 16-bit literal XOR
/// key and an output bound.
pub fn rnc2_decompress_with_key_and_limit(
    bytes: &[u8],
    key: Option<u16>,
    max_output_len: usize,
) -> Option<Vec<u8>> {
    let header = Rnc2Header::parse(bytes)?;
    let target = usize::try_from(header.unpacked_size).ok()?;
    if target > max_output_len || header.chunks == 0 {
        return None;
    }
    let payload = bytes.get(HEADER_LEN..)?;
    if rnc_crc16(payload) != header.packed_crc16 {
        return None;
    }

    let mut input = MsbInterleavedBitReader::new(payload);
    let _locked = input.read_bit()?;
    let keyed = input.read_bit()?;
    let mut key: u16 = match (keyed, key) {
        (true, Some(key)) => key,
        (true, None) => return None,
        (false, _) => 0,
    };
    let mut output = Vec::with_capacity(target);
    let mut chunks = 0usize;

    while output.len() < target {
        loop {
            if !input.read_bit()? {
                let literal = input.read_byte()? ^ key.to_le_bytes()[0];
                if output.len() == target {
                    return None;
                }
                output.push(literal);
                key = key.rotate_right(1);
                continue;
            }

            if input.read_bit()? {
                let (count, distance) = if input.read_bit()? {
                    let count = if input.read_bit()? {
                        let encoded = usize::from(input.read_byte()?);
                        if encoded == 0 {
                            let _continuation = input.read_bit()?;
                            chunks += 1;
                            break;
                        }
                        encoded + 8
                    } else {
                        3
                    };
                    (count, match_offset(&mut input)?)
                } else {
                    (2, usize::from(input.read_byte()?) + 1)
                };
                append_match(&mut output, distance, count, target)?;
                continue;
            }

            let mut count = usize::from(input.read_bit()?) + 4;
            if input.read_bit()? {
                count = ((count - 1) << 1) | usize::from(input.read_bit()?);
            }
            if count == 9 {
                let raw_count = (bits(&mut input, 4)? << 2) + 12;
                if raw_count > target.checked_sub(output.len())? {
                    return None;
                }
                for _ in 0..raw_count {
                    output.push(input.read_byte()? ^ key.to_le_bytes()[0]);
                }
                key = key.rotate_right(1);
            } else {
                let distance = match_offset(&mut input)?;
                append_match(&mut output, distance, count, target)?;
            }
        }
    }

    if input.position() != payload.len()
        || chunks != usize::from(header.chunks)
        || rnc_crc16(&output) != header.unpacked_crc16
    {
        return None;
    }
    Some(output)
}

/// Strict structural recognition used by the format catalog.
pub fn rnc2_identifies(bytes: &[u8]) -> bool {
    rnc2_decompress_with_limit(bytes, IDENTIFY_OUTPUT_LIMIT).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_standard_check_vector() {
        assert_eq!(rnc_crc16(b"123456789"), 0xbb3d);
    }

    #[test]
    fn header_is_big_endian_and_requires_exact_extent() {
        let mut bytes =
            Vec::from(&b"RNC\x02\x00\x00\x00\x01\x00\x00\x00\x02\x12\x34\x56\x78\x09\x01"[..]);
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let header = Rnc2Header::parse(&bytes).unwrap();
        assert_eq!(header.unpacked_size, 1);
        assert_eq!(header.packed_size, 2);
        assert_eq!(header.unpacked_crc16, 0x1234);
        assert_eq!(header.packed_crc16, 0x5678);
        assert_eq!(header.leeway, 9);
        assert_eq!(header.chunks, 1);
        bytes.push(0);
        assert!(Rnc2Header::parse(&bytes).is_none());
    }

    #[test]
    fn rejects_magic_only_bad_crc_zero_chunks_and_output_over_limit() {
        let mut bytes =
            Vec::from(&b"RNC\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00"[..]);
        bytes.push(0);
        assert!(!rnc2_identifies(&bytes));
        assert!(rnc2_decompress_with_limit(&bytes, 0).is_none());
        bytes[17] = 1;
        assert!(rnc2_decompress(&bytes).is_none());
    }
}
