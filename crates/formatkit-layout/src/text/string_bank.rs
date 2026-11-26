//! Declarative reader and symmetric packer for aligned or fixed-stride NUL-terminated string banks.
//!
//! [`AlignedStringBankSpec`] describes contiguous banks of NUL-terminated byte strings
//! laid out with either power-of-two/arbitrary record alignment (e.g. 1, 2, or 4 bytes)
//! or fixed-width slots, with configurable byte validation, termination rules, and exact
//! consumed-extent tracking.

use core::ops::Range;

use formatkit_core::checked_align_up_multiple;

use crate::spec::{try_push, LayoutError, PackPolicy};

/// Physical record layout of entries in an [`AlignedStringBankSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringBankLayout {
    /// Each NUL-terminated string is followed by alignment padding so the next entry
    /// starts at a multiple of `alignment` bytes relative to [`AlignedStringBankSpec::start_offset`]
    /// (must be `>= 1`; e.g. `1`, `2`, or `4`).
    Aligned {
        /// Byte alignment step between consecutive string entries (`>= 1`).
        alignment: usize,
    },
    /// Every entry occupies a fixed `stride`-byte slot (`>= 1`).
    FixedStride {
        /// Fixed byte stride of each string slot (`>= 1`).
        stride: usize,
    },
}

/// Byte-level character validation applied to each decoded or packed string entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StringBankEncoding {
    /// Accept any non-NUL byte sequence (`0x01..=0xFF`, default).
    #[default]
    RawBytes,
    /// Require every byte to be non-NUL ASCII (`0x01..=0x7F`).
    Ascii,
    /// Require every byte to be printable ASCII (`0x20..=0x7E`).
    PrintableAscii,
    /// Require every byte to be printable ASCII (`0x20..=0x7E`) or ASCII whitespace
    /// (`\t`, `\n`, `\r`).
    PrintableAsciiWithWhitespace,
}

impl StringBankEncoding {
    /// Return `true` if every byte in `bytes` satisfies this encoding rule.
    #[must_use]
    pub fn is_valid(self, bytes: &[u8]) -> bool {
        match self {
            Self::RawBytes => !bytes.contains(&0),
            Self::Ascii => bytes.iter().all(|&b| (0x01..=0x7F).contains(&b)),
            Self::PrintableAscii => bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)),
            Self::PrintableAsciiWithWhitespace => bytes
                .iter()
                .all(|&b| (0x20..=0x7E).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r')),
        }
    }
}

/// Rule determining where a string bank terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StringBankTermination {
    /// Read entries until the end of the input slice (default).
    #[default]
    Eof,
    /// Read an exact number of entries.
    Counted(usize),
    /// Stop cleanly upon encountering an empty entry (a leading NUL byte / double-NUL),
    /// consuming the empty terminator entry (and its alignment/slot).
    EmptyEntry,
    /// Stop cleanly upon encountering an entry that fails [`AlignedStringBankSpec::encoding`]
    /// validation or lacks a required NUL terminator, without consuming the invalid entry.
    StopOnInvalid,
}

/// `const`-constructible declarative specification for an aligned or fixed-stride
/// NUL-terminated string bank.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     pack_aligned_string_bank, parse_aligned_string_bank, AlignedStringBankSpec, PackPolicy,
///     StringBankEncoding, StringBankTermination,
/// };
///
/// const SPEC: AlignedStringBankSpec = AlignedStringBankSpec::aligned(0, 4, 32)
///     .with_encoding(StringBankEncoding::PrintableAscii)
///     .with_termination(StringBankTermination::EmptyEntry);
///
/// let entries: &[&[u8]] = &[b"MENU", b"PLAY", b"EXIT"];
/// let packed = pack_aligned_string_bank(&SPEC, &PackPolicy::TIGHT, &[], entries).unwrap();
/// let parsed = parse_aligned_string_bank(&packed, &SPEC).unwrap();
/// assert_eq!(parsed.entries.len(), 3);
/// assert_eq!(parsed.entries[0].as_str(), Some("MENU"));
/// assert_eq!(parsed.entries[1].as_str(), Some("PLAY"));
/// assert_eq!(parsed.entries[2].as_str(), Some("EXIT"));
/// assert_eq!(parsed.consumed_end, packed.len());
/// ```
#[doc(alias = "string bank")]
#[doc(alias = "string pool")]
#[doc(alias = "aligned strings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlignedStringBankSpec {
    /// Byte offset where the first string entry begins.
    pub start_offset: usize,
    /// Record layout (aligned variable-length or fixed-stride slots).
    pub layout: StringBankLayout,
    /// Byte validation applied to each entry (default [`StringBankEncoding::RawBytes`]).
    pub encoding: StringBankEncoding,
    /// Rule determining where the bank terminates (default [`StringBankTermination::Eof`]).
    pub termination: StringBankTermination,
    /// Maximum number of string entries accepted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_entries: usize,
    /// Optional maximum byte length of any single string excluding its NUL terminator
    /// (`0` means no per-entry byte cap beyond the carrier slice or fixed stride).
    pub max_entry_len: usize,
    /// Whether every entry must be NUL-terminated (default `true`).
    /// For [`StringBankLayout::FixedStride`], setting this to `false` permits full-stride
    /// entries with no NUL byte.
    pub require_nul: bool,
    /// Padding byte written after each entry's NUL terminator up to the next aligned
    /// boundary or end of fixed slot (default `0x00`).
    pub pad_byte: u8,
    /// Whether the final entry's aligned extent is included in `consumed_end` and packed output
    /// under [`StringBankLayout::Aligned`] (default `true`).
    pub align_final_entry: bool,
}

impl AlignedStringBankSpec {
    /// Construct an [`AlignedStringBankSpec`] with [`StringBankLayout::Aligned`] and sensible
    /// defaults (`encoding: RawBytes`, `termination: Eof`, `max_entry_len: 0`,
    /// `require_nul: true`, `pad_byte: 0x00`, `align_final_entry: true`).
    #[must_use]
    pub const fn aligned(start_offset: usize, alignment: usize, max_entries: usize) -> Self {
        Self {
            start_offset,
            layout: StringBankLayout::Aligned { alignment },
            encoding: StringBankEncoding::RawBytes,
            termination: StringBankTermination::Eof,
            max_entries,
            max_entry_len: 0,
            require_nul: true,
            pad_byte: 0,
            align_final_entry: true,
        }
    }

    /// Construct an [`AlignedStringBankSpec`] with [`StringBankLayout::FixedStride`] and sensible
    /// defaults (`encoding: RawBytes`, `termination: Eof`, `max_entry_len: 0`,
    /// `require_nul: true`, `pad_byte: 0x00`, `align_final_entry: true`).
    #[must_use]
    pub const fn fixed_stride(start_offset: usize, stride: usize, max_entries: usize) -> Self {
        Self {
            start_offset,
            layout: StringBankLayout::FixedStride { stride },
            encoding: StringBankEncoding::RawBytes,
            termination: StringBankTermination::Eof,
            max_entries,
            max_entry_len: 0,
            require_nul: true,
            pad_byte: 0,
            align_final_entry: true,
        }
    }

    /// Set [`AlignedStringBankSpec::encoding`].
    #[must_use]
    pub const fn with_encoding(mut self, encoding: StringBankEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Set [`AlignedStringBankSpec::termination`].
    #[must_use]
    pub const fn with_termination(mut self, termination: StringBankTermination) -> Self {
        self.termination = termination;
        self
    }

    /// Set [`AlignedStringBankSpec::max_entry_len`].
    #[must_use]
    pub const fn with_max_entry_len(mut self, max_entry_len: usize) -> Self {
        self.max_entry_len = max_entry_len;
        self
    }

    /// Set [`AlignedStringBankSpec::require_nul`].
    #[must_use]
    pub const fn with_require_nul(mut self, require_nul: bool) -> Self {
        self.require_nul = require_nul;
        self
    }

    /// Set [`AlignedStringBankSpec::pad_byte`].
    #[must_use]
    pub const fn with_pad_byte(mut self, pad_byte: u8) -> Self {
        self.pad_byte = pad_byte;
        self
    }

    /// Set [`AlignedStringBankSpec::align_final_entry`].
    #[must_use]
    pub const fn with_align_final_entry(mut self, align: bool) -> Self {
        self.align_final_entry = align;
        self
    }
}

/// One validated string entry decoded from an [`AlignedStringBankSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringBankEntry {
    /// Zero-based entry index in the string bank.
    pub index: usize,
    /// Byte offset where this entry starts within the input slice.
    pub offset: usize,
    /// Byte length of the string payload (excluding NUL and alignment padding).
    pub len: usize,
    /// Decoded raw string bytes (excluding NUL and alignment padding).
    pub bytes: Vec<u8>,
}

impl StringBankEntry {
    /// Return the checked half-open byte range of this entry's raw string bytes.
    #[must_use]
    pub const fn range(&self) -> Option<Range<usize>> {
        match self.offset.checked_add(self.len) {
            Some(end) => Some(self.offset..end),
            None => None,
        }
    }

    /// Borrow this entry's bytes as UTF-8, if valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.bytes).ok()
    }
}

/// Decoded string bank entries and exact consumed byte extent returned by
/// [`parse_aligned_string_bank`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringBankResult {
    /// Decoded string entries in order.
    pub entries: Vec<StringBankEntry>,
    /// Exclusive byte offset immediately after the last consumed entry (or terminator).
    pub consumed_end: usize,
}

fn validate_string_bank_spec(spec: &AlignedStringBankSpec) -> Result<(), LayoutError> {
    match spec.layout {
        StringBankLayout::Aligned { alignment } => {
            if alignment == 0 {
                return Err(LayoutError::InvalidSpec {
                    field: "alignment",
                    reason: "must be nonzero",
                });
            }
            if !spec.require_nul {
                return Err(LayoutError::InvalidSpec {
                    field: "require_nul",
                    reason: "Aligned layout requires NUL termination",
                });
            }
        }
        StringBankLayout::FixedStride { stride } => {
            if stride == 0 {
                return Err(LayoutError::InvalidSpec {
                    field: "stride",
                    reason: "must be nonzero",
                });
            }
        }
    }
    Ok(())
}

fn align_relative(pos: usize, start_offset: usize, alignment: usize) -> Result<usize, LayoutError> {
    if alignment <= 1 {
        return Ok(pos);
    }
    let rel = pos
        .checked_sub(start_offset)
        .ok_or(LayoutError::Overflow {
            what: "string_bank_alignment",
        })?;
    let aligned_rel =
        checked_align_up_multiple(rel, alignment).ok_or(LayoutError::Overflow {
            what: "string_bank_alignment",
        })?;
    start_offset
        .checked_add(aligned_rel)
        .ok_or(LayoutError::Overflow {
            what: "string_bank_alignment",
        })
}

/// Parse an aligned or fixed-stride NUL-terminated string bank according to `spec`.
pub fn parse_aligned_string_bank(
    data: &[u8],
    spec: &AlignedStringBankSpec,
) -> Result<StringBankResult, LayoutError> {
    validate_string_bank_spec(spec)?;
    if spec.start_offset > data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.start_offset,
            needed: 0,
            available: 0,
        });
    }

    let mut entries = Vec::new();
    let mut pos = spec.start_offset;

    let target_count = match spec.termination {
        StringBankTermination::Counted(n) => {
            if n > spec.max_entries {
                return Err(LayoutError::MaxEntriesExceeded {
                    max: spec.max_entries,
                });
            }
            Some(n)
        }
        StringBankTermination::Eof
        | StringBankTermination::EmptyEntry
        | StringBankTermination::StopOnInvalid => None,
    };

    loop {
        if let Some(target) = target_count {
            if entries.len() >= target {
                break;
            }
        }
        if pos >= data.len() {
            if let Some(target) = target_count {
                if entries.len() < target {
                    return Err(LayoutError::Truncated {
                        offset: pos,
                        needed: 1,
                        available: 0,
                    });
                }
            }
            break;
        }

        let index = entries.len();
        let (raw_slice, next_pos) = match spec.layout {
            StringBankLayout::Aligned { alignment } => {
                let tail = &data[pos..];
                let scan_limit = if spec.max_entry_len > 0 {
                    tail.len().min(spec.max_entry_len.saturating_add(1))
                } else {
                    tail.len()
                };
                let Some(nul_rel) = tail[..scan_limit].iter().position(|&b| b == 0) else {
                    if spec.termination == StringBankTermination::StopOnInvalid {
                        break;
                    }
                    return Err(LayoutError::InvalidName { index });
                };
                if spec.max_entry_len > 0 && nul_rel > spec.max_entry_len {
                    if spec.termination == StringBankTermination::StopOnInvalid {
                        break;
                    }
                    return Err(LayoutError::InvalidName { index });
                }
                let after_nul = pos.checked_add(nul_rel).and_then(|v| v.checked_add(1)).ok_or(
                    LayoutError::Overflow {
                        what: "string_bank_end",
                    },
                )?;
                let aligned_next = align_relative(after_nul, spec.start_offset, alignment)?;
                let next_pos = if aligned_next <= data.len() {
                    aligned_next
                } else if !spec.align_final_entry && after_nul == data.len() {
                    after_nul
                } else if spec.termination == StringBankTermination::StopOnInvalid {
                    break;
                } else {
                    return Err(LayoutError::Truncated {
                        offset: after_nul,
                        needed: aligned_next - after_nul,
                        available: data.len() - after_nul,
                    });
                };
                (&tail[..nul_rel], next_pos)
            }
            StringBankLayout::FixedStride { stride } => {
                let slot_end = pos.checked_add(stride).ok_or(LayoutError::Overflow {
                    what: "string_bank_slot_end",
                })?;
                if slot_end > data.len() {
                    if spec.termination == StringBankTermination::StopOnInvalid {
                        break;
                    }
                    return Err(LayoutError::Truncated {
                        offset: pos,
                        needed: stride,
                        available: data.len() - pos,
                    });
                }
                let slot = &data[pos..slot_end];
                let nul_rel = match slot.iter().position(|&b| b == 0) {
                    Some(p) => p,
                    None if !spec.require_nul => stride,
                    None => {
                        if spec.termination == StringBankTermination::StopOnInvalid {
                            break;
                        }
                        return Err(LayoutError::InvalidName { index });
                    }
                };
                if spec.max_entry_len > 0 && nul_rel > spec.max_entry_len {
                    if spec.termination == StringBankTermination::StopOnInvalid {
                        break;
                    }
                    return Err(LayoutError::InvalidName { index });
                }
                (&slot[..nul_rel], slot_end)
            }
        };

        if spec.termination == StringBankTermination::EmptyEntry && raw_slice.is_empty() {
            pos = next_pos;
            break;
        }

        if !spec.encoding.is_valid(raw_slice) {
            if spec.termination == StringBankTermination::StopOnInvalid {
                break;
            }
            return Err(LayoutError::InvalidName { index });
        }

        if entries.len() >= spec.max_entries {
            return Err(LayoutError::MaxEntriesExceeded {
                max: spec.max_entries,
            });
        }

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(raw_slice.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: raw_slice.len(),
            })?;
        owned.extend_from_slice(raw_slice);

        try_push(
            &mut entries,
            StringBankEntry {
                index,
                offset: pos,
                len: raw_slice.len(),
                bytes: owned,
            },
        )?;
        pos = next_pos;
    }

    Ok(StringBankResult {
        entries,
        consumed_end: pos,
    })
}

/// Serialize `entries` into an aligned or fixed-stride string bank conforming to `spec` and `policy`.
pub fn pack_aligned_string_bank(
    spec: &AlignedStringBankSpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    entries: &[&[u8]],
) -> Result<Vec<u8>, LayoutError> {
    validate_string_bank_spec(spec)?;
    policy.validate()?;

    if entries.len() > spec.max_entries {
        return Err(LayoutError::MaxEntriesExceeded {
            max: spec.max_entries,
        });
    }
    if let StringBankTermination::Counted(expected) = spec.termination {
        if entries.len() != expected {
            return Err(LayoutError::InvalidInput {
                index: entries.len(),
                reason: "entries length does not match StringBankTermination::Counted",
            });
        }
    }
    if header_prefix.len() > spec.start_offset {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "header_prefix exceeds start_offset",
        });
    }

    let mut out = Vec::new();
    out.try_reserve(spec.start_offset)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: spec.start_offset,
        })?;
    out.extend_from_slice(header_prefix);
    out.resize(spec.start_offset, policy.prefix_fill_byte);

    let has_empty_terminator = spec.termination == StringBankTermination::EmptyEntry;

    for (index, &entry) in entries.iter().enumerate() {
        if has_empty_terminator && entry.is_empty() {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "empty entry collides with StringBankTermination::EmptyEntry",
            });
        }
        if spec.max_entry_len > 0 && entry.len() > spec.max_entry_len {
            return Err(LayoutError::InvalidName { index });
        }
        if !spec.encoding.is_valid(entry) {
            return Err(LayoutError::InvalidName { index });
        }

        match spec.layout {
            StringBankLayout::Aligned { alignment } => {
                let with_nul = entry.len().checked_add(1).ok_or(LayoutError::Overflow {
                    what: "string_bank_entry",
                })?;
                out.try_reserve(with_nul)
                    .map_err(|_| LayoutError::AllocationFailed {
                        requested: out.len().saturating_add(with_nul),
                    })?;
                out.extend_from_slice(entry);
                out.push(0);

                let needs_align =
                    index + 1 < entries.len() || has_empty_terminator || spec.align_final_entry;
                if needs_align && alignment > 1 {
                    let aligned = align_relative(out.len(), spec.start_offset, alignment)?;
                    let pad = aligned.saturating_sub(out.len());
                    out.try_reserve(pad)
                        .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
                    out.resize(aligned, spec.pad_byte);
                }
            }
            StringBankLayout::FixedStride { stride } => {
                let max_bytes = if spec.require_nul {
                    stride.saturating_sub(1)
                } else {
                    stride
                };
                if entry.len() > max_bytes {
                    return Err(LayoutError::InvalidName { index });
                }
                out.try_reserve(stride)
                    .map_err(|_| LayoutError::AllocationFailed {
                        requested: out.len().saturating_add(stride),
                    })?;
                let slot_start = out.len();
                out.extend_from_slice(entry);
                if entry.len() < stride {
                    out.push(0);
                    let slot_end = slot_start.checked_add(stride).ok_or(LayoutError::Overflow {
                        what: "string_bank_slot_end",
                    })?;
                    out.resize(slot_end, spec.pad_byte);
                }
            }
        }
    }

    if has_empty_terminator {
        match spec.layout {
            StringBankLayout::Aligned { alignment } => {
                out.try_reserve(1)
                    .map_err(|_| LayoutError::AllocationFailed {
                        requested: out.len().saturating_add(1),
                    })?;
                out.push(0);
                if spec.align_final_entry && alignment > 1 {
                    let aligned = align_relative(out.len(), spec.start_offset, alignment)?;
                    let pad = aligned.saturating_sub(out.len());
                    out.try_reserve(pad)
                        .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
                    out.resize(aligned, spec.pad_byte);
                }
            }
            StringBankLayout::FixedStride { stride } => {
                let new_len = out.len().checked_add(stride).ok_or(LayoutError::Overflow {
                    what: "string_bank_terminator",
                })?;
                out.try_reserve(stride)
                    .map_err(|_| LayoutError::AllocationFailed { requested: new_len })?;
                out.push(0);
                out.resize(new_len, spec.pad_byte);
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_4byte_aligned_printable_ascii_with_empty_terminator() {
        const SPEC: AlignedStringBankSpec = AlignedStringBankSpec::aligned(4, 4, 16)
            .with_encoding(StringBankEncoding::PrintableAscii)
            .with_termination(StringBankTermination::EmptyEntry);

        let entries: &[&[u8]] = &[b"START", b"OPTIONS", b"QUIT"];
        let packed = pack_aligned_string_bank(&SPEC, &PackPolicy::TIGHT, b"STRB", entries).unwrap();
        // 4-byte prefix + "START\0\0\0" (8) + "OPTIONS\0" (8) + "QUIT\0\0\0\0" (8) + "\0\0\0\0" (4) = 32
        assert_eq!(packed.len(), 32);

        let mut with_tail = packed.clone();
        with_tail.extend_from_slice(b"OPAQUE_TAIL_BYTES");
        let parsed = parse_aligned_string_bank(&with_tail, &SPEC).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].as_str(), Some("START"));
        assert_eq!(parsed.entries[0].offset, 4);
        assert_eq!(parsed.entries[1].as_str(), Some("OPTIONS"));
        assert_eq!(parsed.entries[1].offset, 12);
        assert_eq!(parsed.entries[2].as_str(), Some("QUIT"));
        assert_eq!(parsed.entries[2].offset, 20);
        assert_eq!(parsed.consumed_end, 32);
        assert_eq!(&with_tail[parsed.consumed_end..], b"OPAQUE_TAIL_BYTES");
    }

    #[test]
    fn round_trips_1byte_and_2byte_aligned_banks() {
        const SPEC_1: AlignedStringBankSpec = AlignedStringBankSpec::aligned(0, 1, 8)
            .with_encoding(StringBankEncoding::Ascii)
            .with_termination(StringBankTermination::Eof);
        let packed1 = pack_aligned_string_bank(&SPEC_1, &PackPolicy::TIGHT, &[], &[b"a", b"bc"])
            .unwrap();
        assert_eq!(packed1, b"a\0bc\0");
        let parsed1 = parse_aligned_string_bank(&packed1, &SPEC_1).unwrap();
        assert_eq!(parsed1.entries.len(), 2);
        assert_eq!(parsed1.consumed_end, 5);

        const SPEC_2: AlignedStringBankSpec = AlignedStringBankSpec::aligned(0, 2, 8)
            .with_encoding(StringBankEncoding::PrintableAscii)
            .with_termination(StringBankTermination::Counted(2))
            .with_pad_byte(0xFF);
        let packed2 = pack_aligned_string_bank(&SPEC_2, &PackPolicy::TIGHT, &[], &[b"ab", b"c"])
            .unwrap();
        assert_eq!(packed2, b"ab\0\xFFc\0");
        let parsed2 = parse_aligned_string_bank(&packed2, &SPEC_2).unwrap();
        assert_eq!(parsed2.entries.len(), 2);
        assert_eq!(parsed2.entries[0].as_str(), Some("ab"));
        assert_eq!(parsed2.entries[1].as_str(), Some("c"));
        assert_eq!(parsed2.consumed_end, 6);
    }

    #[test]
    fn round_trips_fixed_stride_with_and_without_required_nul() {
        const SPEC_NUL: AlignedStringBankSpec = AlignedStringBankSpec::fixed_stride(0, 8, 8)
            .with_encoding(StringBankEncoding::PrintableAscii)
            .with_termination(StringBankTermination::Eof);
        let packed =
            pack_aligned_string_bank(&SPEC_NUL, &PackPolicy::TIGHT, &[], &[b"alpha", b"beta"])
                .unwrap();
        assert_eq!(packed.len(), 16);
        let parsed = parse_aligned_string_bank(&packed, &SPEC_NUL).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].as_str(), Some("alpha"));
        assert_eq!(parsed.entries[1].as_str(), Some("beta"));
        assert_eq!(parsed.consumed_end, 16);

        const SPEC_FULL: AlignedStringBankSpec = AlignedStringBankSpec::fixed_stride(0, 4, 8)
            .with_encoding(StringBankEncoding::PrintableAscii)
            .with_require_nul(false);
        let packed_full =
            pack_aligned_string_bank(&SPEC_FULL, &PackPolicy::TIGHT, &[], &[b"ABCD", b"XY"])
                .unwrap();
        assert_eq!(packed_full, b"ABCDXY\0\0");
        let parsed_full = parse_aligned_string_bank(&packed_full, &SPEC_FULL).unwrap();
        assert_eq!(parsed_full.entries[0].as_str(), Some("ABCD"));
        assert_eq!(parsed_full.entries[1].as_str(), Some("XY"));
        assert_eq!(parsed_full.consumed_end, 8);
    }

    #[test]
    fn stop_on_invalid_halts_cleanly_before_binary_tail() {
        const SPEC: AlignedStringBankSpec = AlignedStringBankSpec::aligned(0, 4, 16)
            .with_encoding(StringBankEncoding::PrintableAscii)
            .with_termination(StringBankTermination::StopOnInvalid);

        let mut data = Vec::new();
        data.extend_from_slice(b"ONE\0");
        data.extend_from_slice(b"TWO\0");
        data.extend_from_slice(&[0xFF, 0xFE, 0x01, 0x00, 0xAA, 0xBB]);

        let parsed = parse_aligned_string_bank(&data, &SPEC).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].as_str(), Some("ONE"));
        assert_eq!(parsed.entries[1].as_str(), Some("TWO"));
        assert_eq!(parsed.consumed_end, 8);
    }

    #[test]
    fn rejects_invalid_specs_malformed_inputs_and_limits() {
        let zero_align = AlignedStringBankSpec::aligned(0, 0, 8);
        assert!(matches!(
            parse_aligned_string_bank(b"a\0", &zero_align),
            Err(LayoutError::InvalidSpec {
                field: "alignment",
                ..
            })
        ));

        let zero_stride = AlignedStringBankSpec::fixed_stride(0, 0, 8);
        assert!(matches!(
            parse_aligned_string_bank(b"a\0", &zero_stride),
            Err(LayoutError::InvalidSpec {
                field: "stride",
                ..
            })
        ));

        let aligned_no_nul = AlignedStringBankSpec::aligned(0, 4, 8).with_require_nul(false);
        assert!(matches!(
            parse_aligned_string_bank(b"a\0\0\0", &aligned_no_nul),
            Err(LayoutError::InvalidSpec {
                field: "require_nul",
                ..
            })
        ));

        // Missing NUL terminator
        let spec = AlignedStringBankSpec::aligned(0, 1, 8);
        assert!(matches!(
            parse_aligned_string_bank(b"unterminated", &spec),
            Err(LayoutError::InvalidName { index: 0 })
        ));

        // Non-printable byte rejected under PrintableAscii
        let printable = AlignedStringBankSpec::aligned(0, 1, 8)
            .with_encoding(StringBankEncoding::PrintableAscii);
        assert!(matches!(
            parse_aligned_string_bank(b"bad\x01\0", &printable),
            Err(LayoutError::InvalidName { index: 0 })
        ));

        // Max entries exceeded
        let capped = AlignedStringBankSpec::aligned(0, 1, 1);
        assert!(matches!(
            parse_aligned_string_bank(b"a\0b\0", &capped),
            Err(LayoutError::MaxEntriesExceeded { max: 1 })
        ));

        // Empty entry rejected during pack when EmptyEntry termination is enabled
        let empty_term = AlignedStringBankSpec::aligned(0, 4, 8)
            .with_termination(StringBankTermination::EmptyEntry);
        assert!(matches!(
            pack_aligned_string_bank(&empty_term, &PackPolicy::TIGHT, &[], &[b""]),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        // Truncated aligned tail rejected
        let align4 = AlignedStringBankSpec::aligned(0, 4, 8);
        assert!(matches!(
            parse_aligned_string_bank(b"ab\0", &align4),
            Err(LayoutError::Truncated {
                offset: 3,
                needed: 1,
                available: 0,
            })
        ));
    }
}
