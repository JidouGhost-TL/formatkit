//! Beat Patching System (BPS) binary patch parser, applier, and encoder.
//!
//! Specification summary:
//! - Magic header: `BPS1` (`0x42, 0x50, 0x53, 0x31`)
//! - Source file size: variable-length integer (VLI)
//! - Target file size: variable-length integer (VLI)
//! - Metadata length: variable-length integer (VLI)
//! - Metadata payload: `[u8; metadata_len]`
//! - Action commands until `output_offset == target_size`:
//!   - Command header: `((length - 1) << 2) | action_type`
//!   - Action 0 (`SourceRead`): copy `length` bytes from source at `output_offset`
//!   - Action 1 (`TargetRead`): copy `length` literal bytes from the patch stream
//!   - Action 2 (`SourceCopy`): copy `length` bytes from source at relative signed offset
//!   - Action 3 (`TargetCopy`): copy `length` bytes from target at relative signed offset
//! - Trailer (final 12 bytes, little-endian):
//!   - Source CRC-32 (ISO-HDLC)
//!   - Target CRC-32 (ISO-HDLC)
//!   - Patch CRC-32 (ISO-HDLC of all preceding patch bytes)

use formatkit_core::{Crc32Params, Error, Reader, Result};

use crate::vli::{decode_vli, encode_vli};

/// Magic header bytes for the BPS1 format.
pub const BPS_MAGIC: &[u8; 4] = b"BPS1";

/// Default upper bound on target output size in bytes (64 MiB).
pub const DEFAULT_MAX_OUTPUT_SIZE: usize = 64 * 1024 * 1024;

const MIN_PATCH_LEN: usize = 19;
const TRAILER_LEN: usize = 12;

fn crc32(bytes: &[u8]) -> u32 {
    Crc32Params::ISO_HDLC.compute(bytes)
}

fn allocation_error() -> Error {
    Error::Malformed("BPS allocation could not be reserved".into())
}

fn decode_signed_delta(reader: &mut Reader<'_>) -> Result<i64> {
    let encoded = decode_vli(reader)?;
    let magnitude = encoded >> 1;
    let signed = i64::try_from(magnitude)
        .map_err(|_| Error::Malformed("BPS relative delta overflows i64".into()))?;
    if (encoded & 1) != 0 {
        signed
            .checked_neg()
            .ok_or_else(|| Error::Malformed("BPS negative relative delta overflow".into()))
    } else {
        Ok(signed)
    }
}

/// An individual action command in a BPS patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpsAction {
    /// Action 0: copy `length` bytes from the source buffer at the current output offset.
    SourceRead {
        /// Number of bytes to copy (must be `>= 1`).
        length: usize,
    },
    /// Action 1: write literal bytes from the patch stream.
    TargetRead {
        /// Literal bytes to append (must be non-empty).
        bytes: Vec<u8>,
    },
    /// Action 2: copy `length` bytes from source starting at `source_relative_offset + delta`.
    SourceCopy {
        /// Number of bytes to copy (must be `>= 1`).
        length: usize,
        /// Signed delta added to the running source cursor before copying.
        delta: i64,
    },
    /// Action 3: copy `length` bytes from already-written target starting at `target_relative_offset + delta`.
    TargetCopy {
        /// Number of bytes to copy (must be `>= 1`).
        length: usize,
        /// Signed delta added to the running target cursor before copying.
        delta: i64,
    },
}

/// Parsed Beat Patching System (BPS) patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpsPatch {
    /// Expected source byte length.
    pub source_size: usize,
    /// Expected target byte length.
    pub target_size: usize,
    /// Optional embedded metadata bytes.
    pub metadata: Vec<u8>,
    /// Expected CRC-32/ISO-HDLC of the source bytes.
    pub source_crc32: u32,
    /// Expected CRC-32/ISO-HDLC of the target bytes.
    pub target_crc32: u32,
    /// Expected CRC-32/ISO-HDLC of all patch bytes preceding this field.
    pub patch_crc32: u32,
    /// Decoded action sequence.
    pub actions: Vec<BpsAction>,
}

impl BpsPatch {
    /// Parse a BPS patch from raw bytes, verifying the patch integrity CRC-32.
    pub fn parse(patch_bytes: &[u8]) -> Result<Self> {
        if patch_bytes.len() < MIN_PATCH_LEN {
            return Err(Error::Truncated {
                offset: 0,
                needed: MIN_PATCH_LEN,
                available: patch_bytes.len(),
            });
        }

        if &patch_bytes[0..4] != BPS_MAGIC {
            return Err(Error::BadMagic {
                offset: 0,
                expected: u32::from_be_bytes(*BPS_MAGIC),
                found: u32::from_be_bytes([
                    patch_bytes[0],
                    patch_bytes[1],
                    patch_bytes[2],
                    patch_bytes[3],
                ]),
            });
        }

        let trailer_start = patch_bytes.len() - TRAILER_LEN;
        let expected_patch_crc32 = u32::from_le_bytes([
            patch_bytes[patch_bytes.len() - 4],
            patch_bytes[patch_bytes.len() - 3],
            patch_bytes[patch_bytes.len() - 2],
            patch_bytes[patch_bytes.len() - 1],
        ]);
        let computed_patch_crc32 = crc32(&patch_bytes[..patch_bytes.len() - 4]);
        if computed_patch_crc32 != expected_patch_crc32 {
            return Err(Error::Malformed(format!(
                "BPS patch CRC-32 mismatch: expected {expected_patch_crc32:#010x}, actual {computed_patch_crc32:#010x}"
            )));
        }

        let source_crc32 = u32::from_le_bytes([
            patch_bytes[trailer_start],
            patch_bytes[trailer_start + 1],
            patch_bytes[trailer_start + 2],
            patch_bytes[trailer_start + 3],
        ]);
        let target_crc32 = u32::from_le_bytes([
            patch_bytes[trailer_start + 4],
            patch_bytes[trailer_start + 5],
            patch_bytes[trailer_start + 6],
            patch_bytes[trailer_start + 7],
        ]);

        let mut reader = Reader::new(&patch_bytes[4..trailer_start]);
        let source_size = usize::try_from(decode_vli(&mut reader)?)
            .map_err(|_| Error::Malformed("BPS source size overflows usize".into()))?;
        let target_size = usize::try_from(decode_vli(&mut reader)?)
            .map_err(|_| Error::Malformed("BPS target size overflows usize".into()))?;
        let metadata_len = usize::try_from(decode_vli(&mut reader)?)
            .map_err(|_| Error::Malformed("BPS metadata length overflows usize".into()))?;

        let metadata = reader.bytes(metadata_len)?.to_vec();

        let mut actions = Vec::new();
        let mut output_offset: usize = 0;

        while output_offset < target_size {
            let data = decode_vli(&mut reader)?;
            let action = data & 3;
            let length_u64 = (data >> 2)
                .checked_add(1)
                .ok_or_else(|| Error::Malformed("BPS action length overflow".into()))?;
            let length = usize::try_from(length_u64)
                .map_err(|_| Error::Malformed("BPS action length overflows usize".into()))?;

            let next_output = output_offset
                .checked_add(length)
                .ok_or_else(|| Error::Malformed("BPS output offset overflow".into()))?;
            if next_output > target_size {
                return Err(Error::Malformed(format!(
                    "BPS action exceeds target size: {next_output} > {target_size}"
                )));
            }

            let decoded = match action {
                0 => BpsAction::SourceRead { length },
                1 => {
                    let bytes = reader.bytes(length)?.to_vec();
                    BpsAction::TargetRead { bytes }
                }
                2 => {
                    let delta = decode_signed_delta(&mut reader)?;
                    BpsAction::SourceCopy { length, delta }
                }
                3 => {
                    let delta = decode_signed_delta(&mut reader)?;
                    BpsAction::TargetCopy { length, delta }
                }
                _ => unreachable!(),
            };

            actions.try_reserve(1).map_err(|_| allocation_error())?;
            actions.push(decoded);
            output_offset = next_output;
        }

        if reader.remaining() != 0 {
            return Err(Error::Trailing(reader.remaining()));
        }

        Ok(Self {
            source_size,
            target_size,
            metadata,
            source_crc32,
            target_crc32,
            patch_crc32: expected_patch_crc32,
            actions,
        })
    }

    /// Apply this patch to `source` using [`DEFAULT_MAX_OUTPUT_SIZE`].
    pub fn apply(&self, source: &[u8]) -> Result<Vec<u8>> {
        self.apply_with_limit(source, DEFAULT_MAX_OUTPUT_SIZE)
    }

    /// Apply this patch to `source`, enforcing `max_output_size` before allocating
    /// and validating both source and target CRC-32 checksums.
    pub fn apply_with_limit(&self, source: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
        if self.target_size > max_output_size {
            return Err(Error::ResourceLimit {
                resource: "BPS output bytes",
                requested: self.target_size as u64,
                limit: max_output_size as u64,
            });
        }

        if source.len() != self.source_size {
            return Err(Error::Malformed(format!(
                "BPS source size mismatch: expected {}, actual {}",
                self.source_size,
                source.len()
            )));
        }

        let actual_source_crc = crc32(source);
        if actual_source_crc != self.source_crc32 {
            return Err(Error::Malformed(format!(
                "BPS source CRC-32 mismatch: expected {:#010x}, actual {actual_source_crc:#010x}",
                self.source_crc32
            )));
        }

        let mut target = Vec::new();
        target
            .try_reserve_exact(self.target_size)
            .map_err(|_| allocation_error())?;
        target.resize(self.target_size, 0);

        let mut output_offset: usize = 0;
        let mut source_relative_offset: i64 = 0;
        let mut target_relative_offset: i64 = 0;

        for action in &self.actions {
            match action {
                BpsAction::SourceRead { length } => {
                    let end = output_offset
                        .checked_add(*length)
                        .ok_or_else(|| Error::Malformed("BPS output offset overflow".into()))?;
                    if end > target.len() {
                        return Err(Error::Malformed(format!(
                            "BPS target size overflow: expected {}, produced {end}",
                            self.target_size
                        )));
                    }
                    if end > source.len() {
                        return Err(Error::Malformed(
                            "BPS SourceRead extends beyond source buffer".into(),
                        ));
                    }
                    target[output_offset..end].copy_from_slice(&source[output_offset..end]);
                    output_offset = end;
                }
                BpsAction::TargetRead { bytes } => {
                    let end = output_offset
                        .checked_add(bytes.len())
                        .ok_or_else(|| Error::Malformed("BPS output offset overflow".into()))?;
                    if end > target.len() {
                        return Err(Error::Malformed(format!(
                            "BPS target size overflow: expected {}, produced {end}",
                            self.target_size
                        )));
                    }
                    target[output_offset..end].copy_from_slice(bytes);
                    output_offset = end;
                }
                BpsAction::SourceCopy { length, delta } => {
                    source_relative_offset = source_relative_offset
                        .checked_add(*delta)
                        .ok_or_else(|| Error::Malformed("BPS source offset overflow".into()))?;

                    let s_start = usize::try_from(source_relative_offset).map_err(|_| {
                        Error::Malformed(format!(
                            "BPS source relative offset out of bounds: {source_relative_offset}"
                        ))
                    })?;
                    let s_end = s_start
                        .checked_add(*length)
                        .ok_or_else(|| Error::Malformed("BPS source copy overflow".into()))?;
                    if s_end > source.len() {
                        return Err(Error::Malformed(format!(
                            "BPS source copy out of bounds: {s_end} > {}",
                            source.len()
                        )));
                    }
                    let out_end = output_offset
                        .checked_add(*length)
                        .ok_or_else(|| Error::Malformed("BPS output offset overflow".into()))?;
                    if out_end > target.len() {
                        return Err(Error::Malformed(format!(
                            "BPS target size overflow: expected {}, produced {out_end}",
                            self.target_size
                        )));
                    }

                    target[output_offset..out_end].copy_from_slice(&source[s_start..s_end]);
                    output_offset = out_end;
                    source_relative_offset = i64::try_from(s_end)
                        .map_err(|_| Error::Malformed("BPS source cursor overflow".into()))?;
                }
                BpsAction::TargetCopy { length, delta } => {
                    target_relative_offset = target_relative_offset
                        .checked_add(*delta)
                        .ok_or_else(|| Error::Malformed("BPS target offset overflow".into()))?;

                    let mut t_pos = usize::try_from(target_relative_offset).map_err(|_| {
                        Error::Malformed(format!(
                            "BPS target relative offset out of bounds: {target_relative_offset}"
                        ))
                    })?;
                    if t_pos >= output_offset {
                        return Err(Error::Malformed(format!(
                            "BPS target copy references unwritten output: {t_pos} >= {output_offset}"
                        )));
                    }
                    let out_end = output_offset
                        .checked_add(*length)
                        .ok_or_else(|| Error::Malformed("BPS output offset overflow".into()))?;
                    if out_end > target.len() {
                        return Err(Error::Malformed(format!(
                            "BPS target size overflow: expected {}, produced {out_end}",
                            self.target_size
                        )));
                    }

                    // Byte-by-byte copy preserves overlapping self-copy (RLE) semantics.
                    for _ in 0..*length {
                        let byte = target[t_pos];
                        target[output_offset] = byte;
                        output_offset += 1;
                        t_pos += 1;
                    }
                    target_relative_offset = i64::try_from(t_pos)
                        .map_err(|_| Error::Malformed("BPS target cursor overflow".into()))?;
                }
            }
        }

        if output_offset != self.target_size {
            return Err(Error::Malformed(format!(
                "BPS output length mismatch: expected {}, produced {output_offset}",
                self.target_size
            )));
        }

        let actual_target_crc = crc32(&target);
        if actual_target_crc != self.target_crc32 {
            return Err(Error::Malformed(format!(
                "BPS target CRC-32 mismatch: expected {:#010x}, actual {actual_target_crc:#010x}",
                self.target_crc32
            )));
        }

        Ok(target)
    }

    /// Serialize this patch into raw BPS1 bytes with a freshly computed patch CRC-32.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(BPS_MAGIC);
        encode_vli(self.source_size as u64, &mut out);
        encode_vli(self.target_size as u64, &mut out);
        encode_vli(self.metadata.len() as u64, &mut out);
        out.extend_from_slice(&self.metadata);

        for action in &self.actions {
            match action {
                BpsAction::SourceRead { length } => {
                    let encoded_len = length.checked_sub(1).ok_or_else(|| {
                        Error::Malformed("BPS SourceRead length must be >= 1".into())
                    })?;
                    encode_vli((encoded_len as u64) << 2, &mut out);
                }
                BpsAction::TargetRead { bytes } => {
                    let encoded_len = bytes.len().checked_sub(1).ok_or_else(|| {
                        Error::Malformed("BPS TargetRead must be non-empty".into())
                    })?;
                    encode_vli(((encoded_len as u64) << 2) | 1, &mut out);
                    out.extend_from_slice(bytes);
                }
                BpsAction::SourceCopy { length, delta } => {
                    let encoded_len = length.checked_sub(1).ok_or_else(|| {
                        Error::Malformed("BPS SourceCopy length must be >= 1".into())
                    })?;
                    encode_vli(((encoded_len as u64) << 2) | 2, &mut out);
                    let mag = delta.unsigned_abs();
                    let offset_data = (mag << 1) | u64::from(*delta < 0);
                    encode_vli(offset_data, &mut out);
                }
                BpsAction::TargetCopy { length, delta } => {
                    let encoded_len = length.checked_sub(1).ok_or_else(|| {
                        Error::Malformed("BPS TargetCopy length must be >= 1".into())
                    })?;
                    encode_vli(((encoded_len as u64) << 2) | 3, &mut out);
                    let mag = delta.unsigned_abs();
                    let offset_data = (mag << 1) | u64::from(*delta < 0);
                    encode_vli(offset_data, &mut out);
                }
            }
        }

        out.extend_from_slice(&self.source_crc32.to_le_bytes());
        out.extend_from_slice(&self.target_crc32.to_le_bytes());
        let p_crc = crc32(&out);
        out.extend_from_slice(&p_crc.to_le_bytes());

        Ok(out)
    }

    /// Create a BPS1 patch encoding the binary difference between `source` and `target`.
    pub fn create(source: &[u8], target: &[u8], metadata: Option<&[u8]>) -> Vec<u8> {
        let mut actions = Vec::new();
        let mut output_offset: usize = 0;
        let mut cur_target_rel: i64 = 0;

        while output_offset < target.len() {
            if output_offset < source.len() && source[output_offset] == target[output_offset] {
                let mut match_len = 0;
                while output_offset + match_len < source.len()
                    && output_offset + match_len < target.len()
                    && source[output_offset + match_len] == target[output_offset + match_len]
                {
                    match_len += 1;
                }
                actions.push(BpsAction::SourceRead { length: match_len });
                output_offset += match_len;
                continue;
            }

            let mut rle_len = 1;
            let val = target[output_offset];
            while output_offset + rle_len < target.len() && target[output_offset + rle_len] == val {
                rle_len += 1;
            }

            if rle_len >= 4 {
                actions.push(BpsAction::TargetRead { bytes: vec![val] });
                output_offset += 1;

                let wanted_pos = (output_offset - 1) as i64;
                let delta = wanted_pos - cur_target_rel;
                let copy_len = rle_len - 1;
                actions.push(BpsAction::TargetCopy {
                    length: copy_len,
                    delta,
                });
                cur_target_rel = wanted_pos + copy_len as i64;
                output_offset += copy_len;
                continue;
            }

            let mut diff_len = 0;
            while output_offset + diff_len < target.len() {
                let curr = output_offset + diff_len;
                if curr < source.len() && source[curr] == target[curr] {
                    let mut lookahead = 0;
                    while curr + lookahead < source.len()
                        && curr + lookahead < target.len()
                        && source[curr + lookahead] == target[curr + lookahead]
                    {
                        lookahead += 1;
                    }
                    if lookahead >= 4 {
                        break;
                    }
                }
                diff_len += 1;
            }

            actions.push(BpsAction::TargetRead {
                bytes: target[output_offset..output_offset + diff_len].to_vec(),
            });
            output_offset += diff_len;
        }

        let patch = Self {
            source_size: source.len(),
            target_size: target.len(),
            metadata: metadata.unwrap_or(&[]).to_vec(),
            source_crc32: crc32(source),
            target_crc32: crc32(target),
            patch_crc32: 0,
            actions,
        };

        // All actions produced above have length >= 1.
        patch.serialize().expect("generated BPS actions are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_round_trip_identical() {
        let source = b"SyntheticSourceBytes123456789";
        let target = b"SyntheticSourceBytes123456789";

        let patch_bytes = BpsPatch::create(source, target, None);
        assert!(patch_bytes.starts_with(BPS_MAGIC));

        let patch = BpsPatch::parse(&patch_bytes).expect("parse identical");
        assert_eq!(patch.source_size, source.len());
        assert_eq!(patch.target_size, target.len());

        let applied = patch.apply(source).expect("apply identical");
        assert_eq!(applied, target);
    }

    #[test]
    fn bps_round_trip_rle_metadata_and_modifications() {
        let mut source = vec![0x33; 2048];
        source[0x50..0x60].copy_from_slice(b"ORIGINAL_HEADER_");

        let mut target = source.clone();
        target[0x50..0x60].copy_from_slice(b"MODIFIED_HEADER_");
        target[1000..1200].fill(0xaa);

        let patch_bytes = BpsPatch::create(&source, &target, Some(b"<meta>Synthetic</meta>"));
        let patch = BpsPatch::parse(&patch_bytes).expect("parse bps");
        assert_eq!(patch.metadata, b"<meta>Synthetic</meta>");

        let applied = patch.apply(&source).expect("apply bps");
        assert_eq!(applied, target);
    }

    #[test]
    fn bps_all_four_action_opcodes_and_negative_delta() {
        let source = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut target_expected = Vec::new();
        target_expected.extend_from_slice(b"ABC");
        target_expected.extend_from_slice(b"!!!");
        target_expected.extend_from_slice(b"XYZ");
        target_expected.extend_from_slice(b"!!!XYZ");
        target_expected.extend_from_slice(b"ABC");

        let actions = vec![
            BpsAction::SourceRead { length: 3 },
            BpsAction::TargetRead {
                bytes: b"!!!".to_vec(),
            },
            BpsAction::SourceCopy {
                length: 3,
                delta: 23,
            },
            BpsAction::TargetCopy {
                length: 6,
                delta: 3,
            },
            BpsAction::SourceCopy {
                length: 3,
                delta: -26,
            },
        ];

        let patch = BpsPatch {
            source_size: source.len(),
            target_size: target_expected.len(),
            metadata: Vec::new(),
            source_crc32: crc32(source),
            target_crc32: crc32(&target_expected),
            patch_crc32: 0,
            actions,
        };

        let patch_bytes = patch.serialize().expect("serialize");
        let parsed = BpsPatch::parse(&patch_bytes).expect("parse 4-action patch");
        assert_eq!(parsed.actions.len(), 5);

        let applied = parsed.apply(source).expect("apply 4-action patch");
        assert_eq!(applied, target_expected);
    }

    #[test]
    fn bps_crc_size_magic_and_limit_checks() {
        let source = b"AlphaImage";
        let target = b"OmegaImage";
        let mut patch_bytes = BpsPatch::create(source, target, None);

        // Truncated input
        assert!(matches!(
            BpsPatch::parse(&patch_bytes[..10]),
            Err(Error::Truncated { .. })
        ));

        // Bad magic
        let mut bad_magic = patch_bytes.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            BpsPatch::parse(&bad_magic),
            Err(Error::BadMagic { offset: 0, .. })
        ));

        // Corrupted patch CRC
        let last_idx = patch_bytes.len() - 1;
        patch_bytes[last_idx] ^= 0x55;
        assert!(matches!(
            BpsPatch::parse(&patch_bytes),
            Err(Error::Malformed(_))
        ));
        patch_bytes[last_idx] ^= 0x55;

        let patch = BpsPatch::parse(&patch_bytes).expect("valid patch");

        // Output limit exceeded
        assert!(matches!(
            patch.apply_with_limit(source, target.len() - 1),
            Err(Error::ResourceLimit {
                resource: "BPS output bytes",
                ..
            })
        ));

        // Wrong source CRC
        assert!(matches!(
            patch.apply(b"Beta_Image"),
            Err(Error::Malformed(_))
        ));

        // Wrong source size
        assert!(matches!(patch.apply(b"Alpha"), Err(Error::Malformed(_))));

        // Wrong target CRC
        let mut bad_target_crc = patch.clone();
        bad_target_crc.target_crc32 ^= 1;
        assert!(matches!(
            bad_target_crc.apply(source),
            Err(Error::Malformed(_))
        ));
    }
}
