//! Bounded C-string slot patching over raw bytes.
//!
//! This module never parses a format: callers hand it file offsets,
//! capacities, and already-encoded source/target bytes (no trailing NUL).
//! Every patch is verified (hash gate, exact source match, NUL terminator,
//! capacity fit, no overlaps) and the output is diff-checked so undeclared
//! bytes are provably identical. Length is always preserved.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// One bounded overwrite: `target + NUL + zeros` fills `[offset,
/// offset+capacity)` after `source` is verified in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedCstrPatch<'a> {
    pub id: &'a str,
    pub offset: u32,
    pub capacity: u32,
    /// Already encoded bytes without the trailing NUL.
    pub source: &'a [u8],
    /// Already encoded bytes without the trailing NUL.
    pub target: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedCstrApplied {
    pub id: String,
    pub offset: u32,
    pub capacity: u32,
    pub source_bytes: usize,
    pub target_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedCstrReport {
    pub source_sha256: [u8; 32],
    pub output_sha256: [u8; 32],
    pub source_size: usize,
    pub output_size: usize,
    pub applied: Vec<BoundedCstrApplied>,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Fail the input-identity gate before any heavier check (coverage scan,
/// per-patch validation). Same error the apply gate reports, so callers
/// can fail fast without duplicating the message.
pub fn verify_input_sha256(bytes: &[u8], expected: &[u8; 32]) -> Result<()> {
    let actual = sha256(bytes);
    if actual != *expected {
        return Err(sha256_mismatch(expected, &actual));
    }
    Ok(())
}

fn sha256_mismatch(expected: &[u8; 32], actual: &[u8; 32]) -> Error {
    Error::Malformed(format!(
        "bounded C-string input SHA-256 mismatch: expected {}, found {}",
        hex(expected),
        hex(actual),
    ))
}

fn has_interior_nul(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Apply bounded C-string patches, returning the patched bytes and a report.
///
/// Rules: optional SHA-256 gate on the input; ids present and unique;
/// non-empty patch list; `capacity > 0` with the slot inside `bytes`;
/// half-open slots must not overlap; source and target (+NUL each) must
/// fit; the source must match exactly with a NUL terminator in place;
/// neither source nor target may contain an interior NUL and the source
/// must be non-empty; patches apply in offset order; afterwards every
/// changed byte must lie inside a declared slot.
pub fn apply_bounded_cstr_patches(
    bytes: &[u8],
    patches: &[BoundedCstrPatch<'_>],
    expected_sha256: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, BoundedCstrReport)> {
    if patches.is_empty() {
        return Err(Error::InvalidField {
            what: "bounded C-string patches",
            value: 0,
        });
    }
    let source_sha256 = sha256(bytes);
    if let Some(expected) = expected_sha256 {
        if source_sha256 != *expected {
            return Err(sha256_mismatch(expected, &source_sha256));
        }
    }
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for patch in patches {
        if patch.id.is_empty() {
            return Err(Error::InvalidField {
                what: "bounded C-string patch id",
                value: patch.offset as u64,
            });
        }
        if !seen_ids.insert(patch.id) {
            return Err(Error::InvalidField {
                what: "bounded C-string patch id",
                value: patch.offset as u64,
            });
        }
        if patch.source.is_empty() {
            return Err(Error::InvalidField {
                what: "bounded C-string patch source",
                value: patch.offset as u64,
            });
        }
        if has_interior_nul(patch.source) {
            return Err(Error::InvalidField {
                what: "bounded C-string patch source",
                value: patch.offset as u64,
            });
        }
        if has_interior_nul(patch.target) {
            return Err(Error::InvalidField {
                what: "bounded C-string patch target",
                value: patch.offset as u64,
            });
        }
        if patch.capacity == 0 {
            return Err(Error::InvalidField {
                what: "bounded C-string patch capacity",
                value: patch.offset as u64,
            });
        }
        let end = patch.offset as u64 + patch.capacity as u64;
        if end > bytes.len() as u64 {
            return Err(Error::Truncated {
                offset: patch.offset as usize,
                needed: patch.capacity as usize,
                available: bytes.len().saturating_sub(patch.offset as usize),
            });
        }
        if patch.source.len() + 1 > patch.capacity as usize {
            return Err(Error::Malformed(format!(
                "bounded C-string patch '{}' at {:#x} needs {} source bytes for capacity {}",
                patch.id,
                patch.offset,
                patch.source.len() + 1,
                patch.capacity,
            )));
        }
        if patch.target.len() + 1 > patch.capacity as usize {
            return Err(Error::Malformed(format!(
                "bounded C-string patch '{}' at {:#x} needs {} target bytes for capacity {}",
                patch.id,
                patch.offset,
                patch.target.len() + 1,
                patch.capacity,
            )));
        }
    }
    let mut ordered: Vec<&BoundedCstrPatch<'_>> = patches.iter().collect();
    ordered.sort_by_key(|patch| (patch.offset, patch.capacity));
    for pair in ordered.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        let first_end = first.offset as u64 + first.capacity as u64;
        if (second.offset as u64) < first_end {
            return Err(Error::Malformed(format!(
                "bounded C-string patches '{}' and '{}' overlap",
                first.id, second.id,
            )));
        }
    }
    let mut output = bytes.to_vec();
    let mut applied = Vec::with_capacity(patches.len());
    for patch in &ordered {
        let offset = patch.offset as usize;
        let slot = &bytes[offset..offset + patch.capacity as usize];
        if slot[..patch.source.len()] != *patch.source {
            return Err(Error::Malformed(format!(
                "bounded C-string patch '{}' at {:#x}: source bytes do not match",
                patch.id, patch.offset,
            )));
        }
        if slot[patch.source.len()] != 0 {
            return Err(Error::Malformed(format!(
                "bounded C-string patch '{}' at {:#x}: missing NUL terminator",
                patch.id, patch.offset,
            )));
        }
        let out_slot = &mut output[offset..offset + patch.capacity as usize];
        out_slot[..patch.target.len()].copy_from_slice(patch.target);
        out_slot[patch.target.len()] = 0;
        for byte in &mut out_slot[patch.target.len() + 1..] {
            *byte = 0;
        }
        applied.push(BoundedCstrApplied {
            id: patch.id.to_string(),
            offset: patch.offset,
            capacity: patch.capacity,
            source_bytes: patch.source.len(),
            target_bytes: patch.target.len(),
        });
    }
    debug_assert_eq!(output.len(), bytes.len());
    for (index, (before, after)) in bytes.iter().zip(output.iter()).enumerate() {
        if before == after {
            continue;
        }
        let inside = ordered.iter().any(|patch| {
            let start = patch.offset as usize;
            index >= start && index < start + patch.capacity as usize
        });
        if !inside {
            return Err(Error::Malformed(format!(
                "bounded C-string apply changed undeclared byte at {:#x}",
                index
            )));
        }
    }
    let output_sha256 = sha256(&output);
    let output_size = output.len();
    Ok((
        output,
        BoundedCstrReport {
            source_sha256,
            output_sha256,
            source_size: bytes.len(),
            output_size,
            applied,
        },
    ))
}

fn hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch<'a>(
        id: &'a str,
        offset: u32,
        capacity: u32,
        source: &'a [u8],
        target: &'a [u8],
    ) -> BoundedCstrPatch<'a> {
        BoundedCstrPatch {
            id,
            offset,
            capacity,
            source,
            target,
        }
    }

    #[test]
    fn applies_two_slots_with_zero_remainder() {
        let bytes = b"Hello\0\0\0Hello\0\0\0........";
        let patches = [
            patch("a", 0, 8, b"Hello", b"Hi"),
            patch("b", 8, 8, b"Hello", b"Yo"),
        ];
        let (output, report) = apply_bounded_cstr_patches(bytes, &patches, None).unwrap();
        assert_eq!(&output[..16], b"Hi\0\0\0\0\0\0Yo\0\0\0\0\0\0");
        assert_eq!(&output[16..], b"........");
        assert_eq!(output.len(), bytes.len());
        assert_eq!(report.source_size, bytes.len());
        assert_eq!(report.output_size, bytes.len());
        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.applied[0].id, "a");
        assert_ne!(report.source_sha256, report.output_sha256);
    }

    #[test]
    fn partial_coverage_is_allowed() {
        let bytes = b"Hello\0\0\0Hello\0\0\0";
        let patches = [patch("a", 0, 8, b"Hello", b"Hi")];
        let (output, _) = apply_bounded_cstr_patches(bytes, &patches, None).unwrap();
        assert_eq!(&output[..8], b"Hi\0\0\0\0\0\0");
        assert_eq!(&output[8..], b"Hello\0\0\0");
    }

    #[test]
    fn oversize_target_refuses_without_writing() {
        let bytes = b"Hi\0\0\0\0\0";
        let patches = [patch("a", 0, 4, b"Hi", b"Hello")];
        let before = bytes.to_vec();
        assert!(apply_bounded_cstr_patches(bytes, &patches, None).is_err());
        assert_eq!(bytes.to_vec(), before);
    }

    #[test]
    fn unsorted_input_applies_in_offset_order() {
        let bytes = b"Hello\0\0\0Hello\0\0\0";
        let patches = [
            patch("b", 8, 8, b"Hello", b"Yo"),
            patch("a", 0, 8, b"Hello", b"Hi"),
        ];
        let (output, report) = apply_bounded_cstr_patches(bytes, &patches, None).unwrap();
        assert_eq!(&output[..16], b"Hi\0\0\0\0\0\0Yo\0\0\0\0\0\0");
        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.applied[0].id, "a");
        assert_eq!(report.applied[1].id, "b");
    }

    #[test]
    fn exact_fit_at_capacity_boundary_is_accepted() {
        let bytes = b"AB\0\0\0\0\0\0";
        // target + NUL is exactly the capacity: accepted.
        let exact = [patch("a", 0, 4, b"AB", b"XYZ")];
        let (output, _) = apply_bounded_cstr_patches(bytes, &exact, None).unwrap();
        assert_eq!(&output[..4], b"XYZ\0");
        // One byte more is refused.
        let over = [patch("a", 0, 4, b"AB", b"WXYZ")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &over, None).unwrap_err(),
            Error::Malformed(_)
        ));
    }

    #[test]
    fn input_sha256_verifier_matches_apply_gate() {
        let bytes = b"Hi\0\0\0\0\0\0";
        let expected = sha256(bytes);
        assert!(verify_input_sha256(bytes, &expected).is_ok());
        let direct = verify_input_sha256(bytes, &[0u8; 32]).unwrap_err();
        let via_apply =
            apply_bounded_cstr_patches(bytes, &[patch("a", 0, 8, b"Hi", b"Yo")], Some(&[0u8; 32]))
                .unwrap_err();
        assert_eq!(direct.to_string(), via_apply.to_string());
    }

    #[test]
    fn sha_gate_mismatch_refuses() {
        let bytes = b"Hi\0\0\0\0\0\0";
        let patches = [patch("a", 0, 8, b"Hi", b"Yo")];
        assert!(apply_bounded_cstr_patches(bytes, &patches, Some(&[0u8; 32])).is_err());
        let expected = sha256(bytes);
        assert!(apply_bounded_cstr_patches(bytes, &patches, Some(&expected)).is_ok());
    }

    #[test]
    fn overlapping_slots_refuse() {
        let bytes = b"Hello\0\0\0Hello\0\0\0";
        let patches = [
            patch("a", 0, 8, b"Hello", b"Hi"),
            patch("b", 4, 8, b"o", b"X"),
        ];
        let error = apply_bounded_cstr_patches(bytes, &patches, None).unwrap_err();
        assert!(matches!(error, Error::Malformed(_)));
    }

    #[test]
    fn source_mismatch_and_missing_nul_refuse() {
        let bytes = b"Hello\0\0\0";
        let wrong = [patch("a", 0, 8, b"World", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &wrong, None).unwrap_err(),
            Error::Malformed(_)
        ));
        // Source matches but the terminator was overwritten.
        let mut no_nul = bytes.to_vec();
        no_nul[5] = b'!';
        let missing = [patch("a", 0, 8, b"Hello", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(&no_nul, &missing, None).unwrap_err(),
            Error::Malformed(_)
        ));
    }

    #[test]
    fn bad_ids_and_shapes_refuse() {
        let bytes = b"Hello\0\0\0";
        let none: &[BoundedCstrPatch<'_>] = &[];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, none, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let dup = [patch("a", 0, 4, b"H", b"X"), patch("a", 4, 4, b"l", b"Y")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &dup, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let empty_id = [patch("", 0, 8, b"Hello", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &empty_id, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let empty_source = [patch("a", 0, 8, b"", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &empty_source, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let nul_source = [patch("a", 0, 8, b"He\0lo", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &nul_source, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let nul_target = [patch("a", 0, 8, b"Hello", b"X\0Y")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &nul_target, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let zero_cap = [patch("a", 0, 0, b"Hello", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &zero_cap, None).unwrap_err(),
            Error::InvalidField { .. }
        ));
        let past_end = [patch("a", 6, 8, b"ab", b"X")];
        assert!(matches!(
            apply_bounded_cstr_patches(bytes, &past_end, None).unwrap_err(),
            Error::Truncated { .. }
        ));
    }
}
