//! Universal Patching System (UPS) binary patch parser, applier, and encoder.
//!
//! Specification summary:
//! - Magic header: `UPS1` (`0x55, 0x50, 0x53, 0x31`)
//! - Source file size: variable-length integer (VLI)
//! - Target file size: variable-length integer (VLI)
//! - Payload: XOR delta chunks `(offset_delta: VLI, xor_bytes: [u8], 0x00 terminator)`
//! - Trailer (final 12 bytes, little-endian):
//!   - Source CRC-32 (ISO-HDLC)
//!   - Target CRC-32 (ISO-HDLC)
//!   - Patch CRC-32 (ISO-HDLC of all preceding patch bytes)

use formatkit_core::{Crc32Params, Error, Reader, Result};

use crate::vli::{decode_vli, encode_vli};

/// Magic header bytes for the UPS1 format.
pub const UPS_MAGIC: &[u8; 4] = b"UPS1";

/// Default upper bound on target output size in bytes (64 MiB).
pub const DEFAULT_MAX_OUTPUT_SIZE: usize = 64 * 1024 * 1024;

const MIN_PATCH_LEN: usize = 18;
const TRAILER_LEN: usize = 12;

fn crc32(bytes: &[u8]) -> u32 {
    Crc32Params::ISO_HDLC.compute(bytes)
}

fn allocation_error() -> Error {
    Error::Malformed("UPS allocation could not be reserved".into())
}

/// An XOR delta chunk in a UPS patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsChunk {
    /// Number of unchanged bytes to skip since the previous chunk terminator.
    pub offset_delta: u64,
    /// Non-zero XOR difference bytes applied sequentially.
    pub xor_bytes: Vec<u8>,
}

/// Parsed Universal Patching System (UPS) patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsPatch {
    /// Expected source byte length.
    pub source_size: usize,
    /// Expected target byte length.
    pub target_size: usize,
    /// Expected CRC-32/ISO-HDLC of the source bytes.
    pub source_crc32: u32,
    /// Expected CRC-32/ISO-HDLC of the target bytes.
    pub target_crc32: u32,
    /// Expected CRC-32/ISO-HDLC of all patch bytes preceding this field.
    pub patch_crc32: u32,
    /// Decoded XOR delta chunks.
    pub chunks: Vec<UpsChunk>,
}

impl UpsPatch {
    /// Parse a UPS patch from raw bytes, verifying the patch integrity CRC-32.
    pub fn parse(patch_bytes: &[u8]) -> Result<Self> {
        if patch_bytes.len() < MIN_PATCH_LEN {
            return Err(Error::Truncated {
                offset: 0,
                needed: MIN_PATCH_LEN,
                available: patch_bytes.len(),
            });
        }

        if &patch_bytes[0..4] != UPS_MAGIC {
            return Err(Error::BadMagic {
                offset: 0,
                expected: u32::from_be_bytes(*UPS_MAGIC),
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
                "UPS patch CRC-32 mismatch: expected {expected_patch_crc32:#010x}, actual {computed_patch_crc32:#010x}"
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
            .map_err(|_| Error::Malformed("UPS source size overflows usize".into()))?;
        let target_size = usize::try_from(decode_vli(&mut reader)?)
            .map_err(|_| Error::Malformed("UPS target size overflows usize".into()))?;

        let mut chunks = Vec::new();
        while reader.remaining() > 0 {
            let offset_delta = decode_vli(&mut reader)?;
            let mut xor_bytes = Vec::new();
            let mut terminated = false;
            while reader.remaining() > 0 {
                let x = reader.u8()?;
                if x == 0 {
                    terminated = true;
                    break;
                }
                xor_bytes.try_reserve(1).map_err(|_| allocation_error())?;
                xor_bytes.push(x);
            }
            if !terminated {
                return Err(Error::Malformed(
                    "UPS chunk missing 0x00 terminator before trailer".into(),
                ));
            }
            chunks.try_reserve(1).map_err(|_| allocation_error())?;
            chunks.push(UpsChunk {
                offset_delta,
                xor_bytes,
            });
        }

        Ok(Self {
            source_size,
            target_size,
            source_crc32,
            target_crc32,
            patch_crc32: expected_patch_crc32,
            chunks,
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
                resource: "UPS output bytes",
                requested: self.target_size as u64,
                limit: max_output_size as u64,
            });
        }

        if source.len() != self.source_size {
            return Err(Error::Malformed(format!(
                "UPS source size mismatch: expected {}, actual {}",
                self.source_size,
                source.len()
            )));
        }

        let actual_source_crc = crc32(source);
        if actual_source_crc != self.source_crc32 {
            return Err(Error::Malformed(format!(
                "UPS source CRC-32 mismatch: expected {:#010x}, actual {actual_source_crc:#010x}",
                self.source_crc32
            )));
        }

        let mut target = Vec::new();
        target
            .try_reserve_exact(self.target_size)
            .map_err(|_| allocation_error())?;
        let copy_len = source.len().min(self.target_size);
        target.extend_from_slice(&source[..copy_len]);
        target.resize(self.target_size, 0);

        let mut relative: usize = 0;
        for chunk in &self.chunks {
            let delta = usize::try_from(chunk.offset_delta)
                .map_err(|_| Error::Malformed("UPS offset delta overflows usize".into()))?;
            relative = relative
                .checked_add(delta)
                .ok_or_else(|| Error::Malformed("UPS relative offset overflow".into()))?;

            for &x in &chunk.xor_bytes {
                if relative < target.len() {
                    target[relative] ^= x;
                }
                relative = relative
                    .checked_add(1)
                    .ok_or_else(|| Error::Malformed("UPS relative offset overflow".into()))?;
            }
            // The 0x00 terminator advances the cursor by one byte.
            relative = relative
                .checked_add(1)
                .ok_or_else(|| Error::Malformed("UPS relative offset overflow".into()))?;
        }

        let actual_target_crc = crc32(&target);
        if actual_target_crc != self.target_crc32 {
            return Err(Error::Malformed(format!(
                "UPS target CRC-32 mismatch: expected {:#010x}, actual {actual_target_crc:#010x}",
                self.target_crc32
            )));
        }

        Ok(target)
    }

    /// Create a UPS1 patch encoding the binary difference between `source` and `target`.
    pub fn create(source: &[u8], target: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(UPS_MAGIC);
        encode_vli(source.len() as u64, &mut out);
        encode_vli(target.len() as u64, &mut out);

        let max_len = source.len().max(target.len());
        let mut relative: usize = 0;

        while relative < max_len {
            let mut diff_pos = None;
            for i in relative..max_len {
                let s = source.get(i).copied().unwrap_or(0);
                let t = target.get(i).copied().unwrap_or(0);
                if (s ^ t) != 0 {
                    diff_pos = Some(i);
                    break;
                }
            }

            let Some(i) = diff_pos else {
                break;
            };

            let offset_delta = (i - relative) as u64;
            encode_vli(offset_delta, &mut out);
            relative = i;

            while relative < max_len {
                let s = source.get(relative).copied().unwrap_or(0);
                let t = target.get(relative).copied().unwrap_or(0);
                let xor_val = s ^ t;
                if xor_val == 0 {
                    break;
                }
                out.push(xor_val);
                relative += 1;
            }

            out.push(0x00);
            relative += 1;
        }

        let s_crc = crc32(source);
        let t_crc = crc32(target);
        out.extend_from_slice(&s_crc.to_le_bytes());
        out.extend_from_slice(&t_crc.to_le_bytes());

        let p_crc = crc32(&out);
        out.extend_from_slice(&p_crc.to_le_bytes());

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ups_round_trip_identical() {
        let source = b"SyntheticOriginalImageData012345";
        let target = b"SyntheticOriginalImageData012345";

        let patch_bytes = UpsPatch::create(source, target);
        assert!(patch_bytes.starts_with(UPS_MAGIC));

        let patch = UpsPatch::parse(&patch_bytes).expect("parse identical patch");
        assert_eq!(patch.source_size, source.len());
        assert_eq!(patch.target_size, target.len());
        assert!(patch.chunks.is_empty());

        let applied = patch.apply(source).expect("apply identical patch");
        assert_eq!(applied, target);
    }

    #[test]
    fn ups_round_trip_sparse_modifications() {
        let mut source = vec![0xea; 4096];
        source[0x100..0x104].copy_from_slice(b"TEST");
        source[0x200..0x204].copy_from_slice(b"INIT");

        let mut target = source.clone();
        target[0x100..0x104].copy_from_slice(b"EDIT");
        target[0x202] = 0xaa;
        target[0x300] = 0x55;

        let patch_bytes = UpsPatch::create(&source, &target);
        let patch = UpsPatch::parse(&patch_bytes).expect("parse patch");
        let applied = patch.apply(&source).expect("apply patch");
        assert_eq!(applied, target);
    }

    #[test]
    fn ups_expansion_and_shrinking() {
        let source = vec![0x11; 512];
        let mut target = vec![0x11; 1024];
        target[600..604].copy_from_slice(b"EXP!");

        let patch_bytes = UpsPatch::create(&source, &target);
        let patch = UpsPatch::parse(&patch_bytes).expect("parse expansion patch");
        assert_eq!(patch.source_size, 512);
        assert_eq!(patch.target_size, 1024);
        assert_eq!(patch.apply(&source).expect("apply expansion"), target);

        let shrink_bytes = UpsPatch::create(&target, &source);
        let shrink_patch = UpsPatch::parse(&shrink_bytes).expect("parse shrinking patch");
        assert_eq!(shrink_patch.source_size, 1024);
        assert_eq!(shrink_patch.target_size, 512);
        assert_eq!(
            shrink_patch.apply(&target).expect("apply shrinking"),
            source
        );
    }

    #[test]
    fn ups_crc_size_magic_malformed_and_limit_checks() {
        let source = b"OriginalImageBase";
        let target = b"ModifiedImageBase";
        let mut patch_bytes = UpsPatch::create(source, target);

        // Truncated input
        assert!(matches!(
            UpsPatch::parse(&patch_bytes[..10]),
            Err(Error::Truncated { .. })
        ));

        // Bad magic
        let mut bad_magic = patch_bytes.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            UpsPatch::parse(&bad_magic),
            Err(Error::BadMagic { offset: 0, .. })
        ));

        // Corrupted patch CRC
        let last_idx = patch_bytes.len() - 1;
        patch_bytes[last_idx] ^= 0xff;
        assert!(matches!(
            UpsPatch::parse(&patch_bytes),
            Err(Error::Malformed(_))
        ));
        patch_bytes[last_idx] ^= 0xff;

        let patch = UpsPatch::parse(&patch_bytes).expect("valid patch");

        // Output limit exceeded
        assert!(matches!(
            patch.apply_with_limit(source, target.len() - 1),
            Err(Error::ResourceLimit {
                resource: "UPS output bytes",
                ..
            })
        ));

        // Wrong source CRC
        assert!(matches!(
            patch.apply(b"OriginalImageDiff"),
            Err(Error::Malformed(_))
        ));

        // Wrong source size
        assert!(matches!(patch.apply(b"Short"), Err(Error::Malformed(_))));

        // Wrong target CRC
        let mut bad_target_crc = patch.clone();
        bad_target_crc.target_crc32 ^= 1;
        assert!(matches!(
            bad_target_crc.apply(source),
            Err(Error::Malformed(_))
        ));

        // Missing 0x00 chunk terminator before trailer
        let mut unterminated = Vec::new();
        unterminated.extend_from_slice(UPS_MAGIC);
        encode_vli(source.len() as u64, &mut unterminated);
        encode_vli(target.len() as u64, &mut unterminated);
        encode_vli(0, &mut unterminated); // delta = 0
        unterminated.push(0x01); // non-zero xor byte without 0x00 terminator
        unterminated.extend_from_slice(&crc32(source).to_le_bytes());
        unterminated.extend_from_slice(&crc32(target).to_le_bytes());
        let p_crc = crc32(&unterminated);
        unterminated.extend_from_slice(&p_crc.to_le_bytes());
        assert!(matches!(
            UpsPatch::parse(&unterminated),
            Err(Error::Malformed(_))
        ));
    }
}
