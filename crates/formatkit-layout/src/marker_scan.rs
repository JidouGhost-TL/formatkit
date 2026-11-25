//! Declarative magic-marker delimited stream specification, checked parser, and symmetric writer.
//!
//! [`MarkerScanStreamSpec`] describes aligned streams where entries are delimited
//! by a fixed byte magic marker occurring at `start_offset + k * step_alignment + marker_offset_in_step`.

use formatkit_core::checked_align_up_multiple;

use crate::spec::{LayoutError, PackPolicy};
use crate::tables::OffsetSpan;

/// `const`-constructible declarative specification for an aligned magic-marker delimited stream.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     pack_marker_scan_stream, parse_marker_scan_stream, MarkerScanStreamSpec, PackPolicy,
/// };
///
/// const SPEC: MarkerScanStreamSpec = MarkerScanStreamSpec {
///     start_offset: 0,
///     step_alignment: 4,
///     marker: b"ITEM",
///     marker_offset_in_step: 0,
///     require_first_at_start: true,
///     min_entries: 1,
///     max_entries: 64,
/// };
///
/// let payloads: &[&[u8]] = &[b"ITEMabc", b"ITEM12345"];
/// let packed = pack_marker_scan_stream(&SPEC, &PackPolicy::TIGHT, &[], payloads).unwrap();
/// let spans = parse_marker_scan_stream(&packed, &SPEC).unwrap();
/// assert_eq!(spans.len(), 2);
/// assert_eq!(spans[0].offset, 0);
/// assert_eq!(spans[0].size, 8); // 7 bytes padded to step_alignment=4
/// assert_eq!(spans[1].offset, 8);
/// assert_eq!(spans[1].slice(&packed), Some(&b"ITEM12345"[..]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkerScanStreamSpec {
    /// Byte offset where scanning begins.
    pub start_offset: usize,
    /// Fixed byte stride between candidate marker positions (e.g. `4` or `2048`; must be `>= 1`).
    pub step_alignment: usize,
    /// Non-empty magic marker byte sequence identifying the start of an entry.
    pub marker: &'static [u8],
    /// Byte offset of `marker` within each aligned step.
    pub marker_offset_in_step: usize,
    /// When `true`, the first entry must match at `start_offset`.
    pub require_first_at_start: bool,
    /// Minimum number of matched entries required.
    pub min_entries: usize,
    /// Maximum number of matched entries permitted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_entries: usize,
}

impl MarkerScanStreamSpec {
    /// Construct a [`MarkerScanStreamSpec`] with sensible defaults
    /// (`marker_offset_in_step: 0`, `require_first_at_start: false`, `min_entries: 0`).
    #[must_use]
    pub const fn new(
        start_offset: usize,
        step_alignment: usize,
        marker: &'static [u8],
        max_entries: usize,
    ) -> Self {
        Self {
            start_offset,
            step_alignment,
            marker,
            marker_offset_in_step: 0,
            require_first_at_start: false,
            min_entries: 0,
            max_entries,
        }
    }

    /// Set [`MarkerScanStreamSpec::marker_offset_in_step`].
    #[must_use]
    pub const fn with_marker_offset_in_step(mut self, offset: usize) -> Self {
        self.marker_offset_in_step = offset;
        self
    }

    /// Set [`MarkerScanStreamSpec::require_first_at_start`].
    #[must_use]
    pub const fn with_require_first_at_start(mut self, require: bool) -> Self {
        self.require_first_at_start = require;
        self
    }

    /// Set [`MarkerScanStreamSpec::min_entries`].
    #[must_use]
    pub const fn with_min_entries(mut self, min_entries: usize) -> Self {
        self.min_entries = min_entries;
        self
    }
}

fn validate_marker_scan_spec(spec: &MarkerScanStreamSpec) -> Result<(), LayoutError> {
    if spec.step_alignment == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "step_alignment",
            reason: "must be nonzero",
        });
    }
    if spec.marker.is_empty() {
        return Err(LayoutError::InvalidSpec {
            field: "marker",
            reason: "must be non-empty",
        });
    }
    if spec
        .marker_offset_in_step
        .checked_add(spec.marker.len())
        .is_none()
    {
        return Err(LayoutError::InvalidSpec {
            field: "marker_offset_in_step",
            reason: "marker_offset_in_step + marker.len() overflows usize",
        });
    }
    if spec.min_entries > spec.max_entries {
        return Err(LayoutError::InvalidSpec {
            field: "min_entries",
            reason: "must not exceed max_entries",
        });
    }
    Ok(())
}

/// Scan `data` at aligned steps `start_offset + k * step_alignment`, finding every
/// `marker` match at `pos + marker_offset_in_step` and deriving contiguous spans
/// `[pos[i], pos[i + 1])` with the final span `[pos[last], data.len())`.
pub fn parse_marker_scan_stream(
    data: &[u8],
    spec: &MarkerScanStreamSpec,
) -> Result<Vec<OffsetSpan>, LayoutError> {
    validate_marker_scan_spec(spec)?;

    if spec.start_offset > data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.start_offset,
            needed: 0,
            available: 0,
        });
    }

    let mut positions: Vec<usize> = Vec::new();
    let mut pos = spec.start_offset;
    while pos < data.len() {
        if let Some(match_start) = pos.checked_add(spec.marker_offset_in_step) {
            if let Some(match_end) = match_start.checked_add(spec.marker.len()) {
                if match_end <= data.len() && &data[match_start..match_end] == spec.marker {
                    if positions.len() >= spec.max_entries {
                        return Err(LayoutError::MaxEntriesExceeded {
                            max: spec.max_entries,
                        });
                    }
                    positions.push(pos);
                }
            }
        }
        match pos.checked_add(spec.step_alignment) {
            Some(next) => pos = next,
            None => break,
        }
    }

    if spec.require_first_at_start && positions.first().copied() != Some(spec.start_offset) {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "missing required marker at start_offset",
        });
    }
    if positions.len() < spec.min_entries {
        return Err(LayoutError::InvalidInput {
            index: positions.len(),
            reason: "fewer marker matches than min_entries",
        });
    }

    let mut spans = Vec::new();
    spans
        .try_reserve_exact(positions.len())
        .map_err(|_| LayoutError::AllocationFailed {
            requested: positions.len(),
        })?;
    let data_len = data.len() as u64;
    for (index, &start) in positions.iter().enumerate() {
        let end = positions
            .get(index + 1)
            .map_or(data_len, |&next| next as u64);
        let offset = start as u64;
        spans.push(OffsetSpan {
            index,
            offset,
            size: end - offset,
        });
    }
    Ok(spans)
}

/// Serialize `payloads` into an aligned magic-marker delimited stream conforming to `spec` and `policy`.
///
/// Each payload is verified to contain `spec.marker` at `spec.marker_offset_in_step`,
/// and subsequent payloads are aligned to `spec.start_offset + k * spec.step_alignment`.
pub fn pack_marker_scan_stream(
    spec: &MarkerScanStreamSpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    payloads: &[&[u8]],
) -> Result<Vec<u8>, LayoutError> {
    validate_marker_scan_spec(spec)?;
    policy.validate()?;

    if payloads.len() > spec.max_entries {
        return Err(LayoutError::MaxEntriesExceeded {
            max: spec.max_entries,
        });
    }
    if payloads.len() < spec.min_entries {
        return Err(LayoutError::InvalidInput {
            index: payloads.len(),
            reason: "fewer payloads than min_entries",
        });
    }
    if spec.require_first_at_start && payloads.is_empty() {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "require_first_at_start requires at least one payload",
        });
    }
    if header_prefix.len() > spec.start_offset {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "header_prefix exceeds start_offset",
        });
    }

    let marker_end = spec.marker_offset_in_step + spec.marker.len();
    for (index, payload) in payloads.iter().enumerate() {
        if payload.len() < marker_end
            || &payload[spec.marker_offset_in_step..marker_end] != spec.marker
        {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "payload missing required marker at marker_offset_in_step",
            });
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(header_prefix);
    out.resize(spec.start_offset, policy.prefix_fill_byte);

    for (index, payload) in payloads.iter().enumerate() {
        out.extend_from_slice(payload);
        let needs_step_align = index + 1 < payloads.len() || policy.pad_final_entry;
        if needs_step_align && spec.step_alignment > 1 {
            let rel = out.len() - spec.start_offset;
            let aligned_rel = checked_align_up_multiple(rel, spec.step_alignment).ok_or(
                LayoutError::Overflow {
                    what: "marker_scan_alignment",
                },
            )?;
            let aligned =
                spec.start_offset
                    .checked_add(aligned_rel)
                    .ok_or(LayoutError::Overflow {
                        what: "marker_scan_alignment",
                    })?;
            out.resize(aligned, policy.pad_byte);
        }
    }

    if policy.pad_final_entry && policy.data_alignment > 1 {
        let aligned = checked_align_up_multiple(out.len(), policy.data_alignment).ok_or(
            LayoutError::Overflow {
                what: "data_alignment",
            },
        )?;
        out.resize(aligned, policy.pad_byte);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_scan_round_trips_aligned_and_offset_marker() {
        const SPEC: MarkerScanStreamSpec = MarkerScanStreamSpec::new(16, 2048, b"SIGN", 16)
            .with_marker_offset_in_step(4)
            .with_require_first_at_start(true)
            .with_min_entries(2);

        let p0 = b"\x01\x02\x03\x04SIGNpayload-zero";
        let p1 = b"\xAA\xBB\xCC\xDDSIGNpayload-one!!";
        let policy = PackPolicy {
            data_alignment: 1,
            pad_byte: 0x00,
            record_fill_byte: 0x00,
            pad_final_entry: false,
            prefix_fill_byte: 0xEE,
        };

        let packed = pack_marker_scan_stream(&SPEC, &policy, b"PREF", &[p0, p1]).unwrap();
        assert_eq!(&packed[0..4], b"PREF");
        assert_eq!(&packed[4..16], &[0xEE; 12]);

        let spans = parse_marker_scan_stream(&packed, &SPEC).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].index, 0);
        assert_eq!(spans[0].offset, 16);
        assert_eq!(spans[0].size, 2048);
        assert_eq!(&spans[0].slice(&packed).unwrap()[..p0.len()], p0);
        assert_eq!(spans[1].index, 1);
        assert_eq!(spans[1].offset, 16 + 2048);
        assert_eq!(spans[1].slice(&packed), Some(&p1[..]));
    }

    #[test]
    fn marker_scan_rejects_invalid_specs_missing_start_min_max_and_bad_payload() {
        let bad_step = MarkerScanStreamSpec::new(0, 0, b"M", 8);
        assert!(matches!(
            parse_marker_scan_stream(b"M", &bad_step),
            Err(LayoutError::InvalidSpec {
                field: "step_alignment",
                ..
            })
        ));

        let empty_marker = MarkerScanStreamSpec::new(0, 4, b"", 8);
        assert!(matches!(
            parse_marker_scan_stream(b"AAAA", &empty_marker),
            Err(LayoutError::InvalidSpec {
                field: "marker",
                ..
            })
        ));

        let bad_bounds = MarkerScanStreamSpec::new(0, 4, b"M", 1).with_min_entries(2);
        assert!(matches!(
            parse_marker_scan_stream(b"M", &bad_bounds),
            Err(LayoutError::InvalidSpec {
                field: "min_entries",
                ..
            })
        ));

        let req_start =
            MarkerScanStreamSpec::new(0, 4, b"MARK", 8).with_require_first_at_start(true);
        assert!(matches!(
            parse_marker_scan_stream(b"____MARK", &req_start),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));
        assert!(matches!(
            pack_marker_scan_stream(&req_start, &PackPolicy::TIGHT, &[], &[]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));
        assert!(matches!(
            pack_marker_scan_stream(&req_start, &PackPolicy::TIGHT, &[], &[b"NOPE"]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        let min2 = MarkerScanStreamSpec::new(0, 4, b"MARK", 8).with_min_entries(2);
        assert!(matches!(
            parse_marker_scan_stream(b"MARK1234", &min2),
            Err(LayoutError::InvalidInput { index: 1, .. })
        ));

        let max1 = MarkerScanStreamSpec::new(0, 4, b"MARK", 1);
        assert_eq!(
            parse_marker_scan_stream(b"MARKMARK", &max1),
            Err(LayoutError::MaxEntriesExceeded { max: 1 })
        );

        let truncated = MarkerScanStreamSpec::new(16, 4, b"MARK", 8);
        assert!(matches!(
            parse_marker_scan_stream(b"short", &truncated),
            Err(LayoutError::Truncated { offset: 16, .. })
        ));
    }
}
