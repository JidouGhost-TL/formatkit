//! Declarative magic-marker delimited stream specification, checked iterator/parser, and symmetric writer.
//!
//! [`MarkerScanStreamSpec`] describes aligned streams where entries are delimited
//! by a fixed byte magic marker occurring at `start_offset + k * step_alignment + marker_offset_in_step`,
//! with optional aligned [`MarkerScanStreamSpec::end_marker`] termination.

use formatkit_core::checked_align_up_multiple;

use crate::spec::{try_push, LayoutError, PackPolicy};
use crate::tables::OffsetSpan;

/// `const`-constructible declarative specification for an aligned magic-marker delimited stream.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     pack_marker_scan_stream, parse_marker_scan_stream, MarkerScanStreamSpec, PackPolicy,
/// };
///
/// const SPEC: MarkerScanStreamSpec = MarkerScanStreamSpec::new(0, 4, b"ITEM", 64)
///     .with_require_first_at_start(true)
///     .with_min_entries(1);
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
    /// Byte offset of `marker` (and `end_marker`) within each aligned step.
    pub marker_offset_in_step: usize,
    /// Optional non-empty terminator marker at `pos + marker_offset_in_step` that closes the
    /// final entry at `pos` and stops scanning cleanly.
    pub end_marker: Option<&'static [u8]>,
    /// When `true`, the first entry must match at `start_offset`.
    pub require_first_at_start: bool,
    /// Minimum number of matched entries required.
    pub min_entries: usize,
    /// Maximum number of matched entries permitted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_entries: usize,
}

impl MarkerScanStreamSpec {
    /// Construct a [`MarkerScanStreamSpec`] with sensible defaults
    /// (`marker_offset_in_step: 0`, `end_marker: None`, `require_first_at_start: false`,
    /// `min_entries: 0`).
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
            end_marker: None,
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

    /// Set [`MarkerScanStreamSpec::end_marker`].
    #[must_use]
    pub const fn with_end_marker(mut self, end_marker: &'static [u8]) -> Self {
        self.end_marker = Some(end_marker);
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
    if let Some(end_marker) = spec.end_marker {
        if end_marker.is_empty() {
            return Err(LayoutError::InvalidSpec {
                field: "end_marker",
                reason: "must be non-empty",
            });
        }
        if spec
            .marker_offset_in_step
            .checked_add(end_marker.len())
            .is_none()
        {
            return Err(LayoutError::InvalidSpec {
                field: "end_marker",
                reason: "marker_offset_in_step + end_marker.len() overflows usize",
            });
        }
        if end_marker == spec.marker {
            return Err(LayoutError::InvalidSpec {
                field: "end_marker",
                reason: "end_marker must differ from marker",
            });
        }
    }
    if spec.min_entries > spec.max_entries {
        return Err(LayoutError::InvalidSpec {
            field: "min_entries",
            reason: "must not exceed max_entries",
        });
    }
    Ok(())
}

#[inline]
fn matches_at(data: &[u8], pos: usize, offset_in_step: usize, needle: &[u8]) -> bool {
    let Some(start) = pos.checked_add(offset_in_step) else {
        return false;
    };
    let Some(end) = start.checked_add(needle.len()) else {
        return false;
    };
    end <= data.len() && &data[start..end] == needle
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanHit {
    Entry(usize),
    End(usize),
    Eof,
}

fn scan_next_hit(data: &[u8], spec: &MarkerScanStreamSpec, mut pos: usize) -> ScanHit {
    while pos < data.len() {
        if let Some(end_marker) = spec.end_marker {
            if matches_at(data, pos, spec.marker_offset_in_step, end_marker) {
                return ScanHit::End(pos);
            }
        }
        if matches_at(data, pos, spec.marker_offset_in_step, spec.marker) {
            return ScanHit::Entry(pos);
        }
        match pos.checked_add(spec.step_alignment) {
            Some(next) => pos = next,
            None => break,
        }
    }
    ScanHit::Eof
}

/// Zero-allocation checked iterator over spans in an aligned magic-marker delimited stream.
#[derive(Debug, Clone)]
pub struct MarkerScanIter<'a> {
    data: &'a [u8],
    spec: MarkerScanStreamSpec,
    current_start: Option<usize>,
    emitted: usize,
    finished: bool,
}

/// Create a zero-allocation checked iterator over aligned marker-delimited spans in `data`.
///
/// Validates `spec`, checks that `start_offset <= data.len()`, and verifies
/// [`MarkerScanStreamSpec::require_first_at_start`] upfront (returning
/// [`LayoutError::MissingMarker`] if the start marker is absent).
/// If fewer than [`MarkerScanStreamSpec::min_entries`] matches exist before stream end,
/// the iterator yields [`LayoutError::TooFewEntries`] on its final step.
pub fn iter_marker_scan_stream<'a>(
    data: &'a [u8],
    spec: &MarkerScanStreamSpec,
) -> Result<MarkerScanIter<'a>, LayoutError> {
    validate_marker_scan_spec(spec)?;

    if spec.start_offset > data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.start_offset,
            needed: 0,
            available: 0,
        });
    }

    let first_start = match scan_next_hit(data, spec, spec.start_offset) {
        ScanHit::Entry(pos) => Some(pos),
        ScanHit::End(_) | ScanHit::Eof => None,
    };

    if spec.require_first_at_start && first_start != Some(spec.start_offset) {
        return Err(LayoutError::MissingMarker {
            offset: spec.start_offset,
        });
    }

    Ok(MarkerScanIter {
        data,
        spec: *spec,
        current_start: first_start,
        emitted: 0,
        finished: false,
    })
}

impl Iterator for MarkerScanIter<'_> {
    type Item = Result<OffsetSpan, LayoutError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let Some(start) = self.current_start else {
            self.finished = true;
            if self.emitted < self.spec.min_entries {
                return Some(Err(LayoutError::TooFewEntries {
                    found: self.emitted,
                    min: self.spec.min_entries,
                }));
            }
            return None;
        };

        if self.emitted >= self.spec.max_entries {
            self.finished = true;
            return Some(Err(LayoutError::MaxEntriesExceeded {
                max: self.spec.max_entries,
            }));
        }

        let scan_from = start.checked_add(self.spec.step_alignment);
        let (end_offset, next_start) = match scan_from {
            Some(pos) => match scan_next_hit(self.data, &self.spec, pos) {
                ScanHit::Entry(next_pos) => (next_pos as u64, Some(next_pos)),
                ScanHit::End(end_pos) => (end_pos as u64, None),
                ScanHit::Eof => (self.data.len() as u64, None),
            },
            None => (self.data.len() as u64, None),
        };

        let index = self.emitted;
        self.emitted += 1;
        self.current_start = next_start;

        let offset = start as u64;
        Some(Ok(OffsetSpan {
            index,
            offset,
            size: end_offset - offset,
        }))
    }
}

/// Scan `data` in a single pass at aligned steps `start_offset + k * step_alignment`,
/// finding every `marker` match at `pos + marker_offset_in_step` and deriving contiguous spans
/// `[pos[i], pos[i + 1])` with the final span ending at [`MarkerScanStreamSpec::end_marker`]
/// (when present) or `data.len()`.
pub fn parse_marker_scan_stream(
    data: &[u8],
    spec: &MarkerScanStreamSpec,
) -> Result<Vec<OffsetSpan>, LayoutError> {
    let iter = iter_marker_scan_stream(data, spec)?;
    let mut spans = Vec::new();
    for item in iter {
        try_push(&mut spans, item?)?;
    }
    Ok(spans)
}

/// Serialize `payloads` into an aligned magic-marker delimited stream conforming to `spec` and `policy`.
///
/// Each payload is verified to contain `spec.marker` at `spec.marker_offset_in_step`
/// (and not `spec.end_marker`), and subsequent payloads (and any configured
/// [`MarkerScanStreamSpec::end_marker`]) are aligned to `spec.start_offset + k * spec.step_alignment`.
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
        if let Some(end_marker) = spec.end_marker {
            if matches_at(payload, 0, spec.marker_offset_in_step, end_marker) {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "payload collides with end_marker",
                });
            }
        }
    }

    let mut out = Vec::new();
    out.try_reserve(spec.start_offset)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: spec.start_offset,
        })?;
    out.extend_from_slice(header_prefix);
    out.resize(spec.start_offset, policy.prefix_fill_byte);

    for (index, payload) in payloads.iter().enumerate() {
        out.try_reserve(payload.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: out.len().saturating_add(payload.len()),
            })?;
        out.extend_from_slice(payload);
        let needs_step_align =
            index + 1 < payloads.len() || spec.end_marker.is_some() || policy.pad_final_entry;
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
            out.try_reserve(aligned.saturating_sub(out.len()))
                .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
            out.resize(aligned, policy.pad_byte);
        }
    }

    if let Some(end_marker) = spec.end_marker {
        let term_len = spec.marker_offset_in_step + end_marker.len();
        out.try_reserve(term_len)
            .map_err(|_| LayoutError::AllocationFailed {
                requested: out.len().saturating_add(term_len),
            })?;
        let new_len =
            out.len()
                .checked_add(spec.marker_offset_in_step)
                .ok_or(LayoutError::Overflow {
                    what: "marker_scan_end_marker",
                })?;
        out.resize(new_len, policy.record_fill_byte);
        out.extend_from_slice(end_marker);
        if policy.pad_final_entry && spec.step_alignment > 1 {
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
            out.try_reserve(aligned.saturating_sub(out.len()))
                .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
            out.resize(aligned, policy.pad_byte);
        }
    }

    if policy.pad_final_entry && policy.data_alignment > 1 {
        let aligned = checked_align_up_multiple(out.len(), policy.data_alignment).ok_or(
            LayoutError::Overflow {
                what: "data_alignment",
            },
        )?;
        out.try_reserve(aligned.saturating_sub(out.len()))
            .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
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
        let policy = PackPolicy::TIGHT.with_prefix_fill_byte(0xEE);

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
    fn marker_scan_end_marker_and_zero_alloc_iter() {
        const SPEC: MarkerScanStreamSpec = MarkerScanStreamSpec::new(4, 8, b"ITEM", 16)
            .with_end_marker(b"END!")
            .with_require_first_at_start(true)
            .with_min_entries(1);

        let payloads: &[&[u8]] = &[b"ITEMaa", b"ITEMbbbbbb"];
        let mut packed =
            pack_marker_scan_stream(&SPEC, &PackPolicy::TIGHT, b"HDR0", payloads).unwrap();
        // Append trailing junk after end_marker; parser must stop at end_marker
        packed.extend_from_slice(b"ITEMshould_not_be_scanned");

        let iter_spans: Vec<_> = iter_marker_scan_stream(&packed, &SPEC)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(iter_spans.len(), 2);
        assert_eq!(iter_spans[0].offset, 4);
        assert_eq!(iter_spans[0].size, 8);
        assert_eq!(iter_spans[1].offset, 12);
        assert_eq!(iter_spans[1].size, 16); // 10 bytes padded up to step_alignment=8
        assert_eq!(&iter_spans[1].slice(&packed).unwrap()[..10], b"ITEMbbbbbb");

        assert_eq!(
            parse_marker_scan_stream(&packed, &SPEC).unwrap(),
            iter_spans
        );
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

        let same_end = MarkerScanStreamSpec::new(0, 4, b"M", 8).with_end_marker(b"M");
        assert!(matches!(
            parse_marker_scan_stream(b"M", &same_end),
            Err(LayoutError::InvalidSpec {
                field: "end_marker",
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
        assert_eq!(
            parse_marker_scan_stream(b"____MARK", &req_start),
            Err(LayoutError::MissingMarker { offset: 0 })
        );
        assert!(matches!(
            pack_marker_scan_stream(&req_start, &PackPolicy::TIGHT, &[], &[]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));
        assert!(matches!(
            pack_marker_scan_stream(&req_start, &PackPolicy::TIGHT, &[], &[b"NOPE"]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        let min2 = MarkerScanStreamSpec::new(0, 4, b"MARK", 8).with_min_entries(2);
        assert_eq!(
            parse_marker_scan_stream(b"MARK1234", &min2),
            Err(LayoutError::TooFewEntries { found: 1, min: 2 })
        );

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
