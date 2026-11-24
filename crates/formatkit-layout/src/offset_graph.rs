//! Exact reading and rewriting of offset-linked resident regions.
//!
//! Many binary formats are pointer graphs: a header holds offsets to arrays,
//! and those arrays hold offsets to further records. Records may share bytes,
//! and the bytes no record describes (alignment padding, unreferenced or
//! unknown records) must still be reproduced for an exact write.
//!
//! [`ClaimedReader`] reads typed fields at absolute offsets inside a region
//! and records every byte a read claimed. Because shared records can make a
//! small graph fan out into many reads, the reader charges each read against
//! a limit proportional to the region size. After parsing,
//! [`ClaimedReader::gaps`] returns the unclaimed runs as [`UnclaimedGap`]s.
//!
//! [`PlacementCanvas`] is the writing half: a fixed-length buffer on which
//! the owner places every structure back at its offset and then restores the
//! gaps. With [`OverlapPolicy::RejectConflicting`] two placements that write
//! different values to one byte are an error, which catches inconsistent
//! shared records before they become silent corruption.
//!
//! ```
//! use formatkit_layout::offset_graph::{ClaimedReader, OverlapPolicy, PlacementCanvas};
//!
//! // header: u32 offset of a u16 record; one padding byte; then the record.
//! let region = [5, 0, 0, 0, 0xAA, 0x34, 0x12];
//! let mut reader = ClaimedReader::new(&region);
//! let record_at = reader.u32_le("record offset", 0).unwrap() as usize;
//! let value = reader.u16_le("record value", record_at).unwrap();
//! assert_eq!(value, 0x1234);
//! let gaps = reader.gaps();
//! assert_eq!((gaps[0].offset, gaps[0].bytes.as_slice()), (4, &[0xAA][..]));
//!
//! let mut canvas = PlacementCanvas::new(region.len(), 0, OverlapPolicy::RejectConflicting);
//! canvas.put_u32_le("record offset", 0, record_at as u32).unwrap();
//! canvas.put_u16_le("record value", record_at, value).unwrap();
//! canvas.put_gaps(&gaps).unwrap();
//! assert_eq!(canvas.into_bytes(), region);
//! ```

use formatkit_core::{Endian, Error, ErrorContext, Result};

fn field_error(what: &'static str, at: usize, error: Error) -> Error {
    error.context(ErrorContext::Field {
        name: what,
        offset: at as u64,
    })
}

fn checked_range(what: &'static str, at: usize, len: usize, size: usize) -> Result<usize> {
    match at.checked_add(len) {
        Some(end) if end <= size => Ok(end),
        _ => Err(field_error(
            what,
            at,
            Error::Truncated {
                offset: at,
                needed: len,
                available: size.saturating_sub(at),
            },
        )),
    }
}

/// `base + offset`, checked, for following a stored relative offset.
pub fn checked_offset(what: &'static str, base: usize, offset: u64) -> Result<usize> {
    usize::try_from(offset)
        .ok()
        .and_then(|o| base.checked_add(o))
        .ok_or(Error::InvalidField {
            what,
            value: offset,
        })
}

/// `base + index * stride`, checked, for addressing an array element.
pub fn checked_element(
    what: &'static str,
    base: usize,
    index: usize,
    stride: usize,
) -> Result<usize> {
    index
        .checked_mul(stride)
        .and_then(|o| base.checked_add(o))
        .ok_or(Error::InvalidField {
            what,
            value: index as u64,
        })
}

/// A run of region bytes that no read claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclaimedGap {
    /// Offset from the start of the region.
    pub offset: usize,
    /// The bytes, verbatim.
    pub bytes: Vec<u8>,
}

impl UnclaimedGap {
    /// A gap of `byte` covering `from..to`, or `None` when `to <= from`; for
    /// writers that synthesize padding instead of replaying parsed gaps.
    #[must_use]
    pub fn fill(from: usize, to: usize, byte: u8) -> Option<Self> {
        (to > from).then(|| Self {
            offset: from,
            bytes: vec![byte; to - from],
        })
    }
}

/// Bounds-checked reader over a resident region that records claimed bytes.
#[doc(alias = "claimed bytes")]
#[doc(alias = "coverage reader")]
#[doc(alias = "pointer graph")]
#[derive(Debug, Clone)]
pub struct ClaimedReader<'a> {
    data: &'a [u8],
    claimed: Vec<u64>,
    reads_used: u64,
    read_limit: u64,
}

impl<'a> ClaimedReader<'a> {
    /// A reader with the default read limit of `16 * len + 65536` reads.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        let limit = (data.len() as u64)
            .saturating_mul(16)
            .saturating_add(1 << 16);
        Self::with_read_limit(data, limit)
    }

    /// A reader that rejects reads after `max_reads` of them.
    #[must_use]
    pub fn with_read_limit(data: &'a [u8], max_reads: u64) -> Self {
        Self {
            data,
            claimed: vec![0; data.len().div_ceil(64)],
            reads_used: 0,
            read_limit: max_reads,
        }
    }

    /// Region length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the region is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The whole region, without claiming anything.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Read and claim `len` bytes at `at`.
    ///
    /// Fails with [`Error::ResourceLimit`] once the read limit is spent and
    /// with [`Error::Truncated`] (inside an [`ErrorContext::Field`] naming
    /// `what`) when the range leaves the region; failed reads claim nothing.
    pub fn bytes(&mut self, what: &'static str, at: usize, len: usize) -> Result<&'a [u8]> {
        if self.reads_used >= self.read_limit {
            return Err(field_error(
                what,
                at,
                Error::ResourceLimit {
                    resource: "offset-graph field reads",
                    requested: self.reads_used.saturating_add(1),
                    limit: self.read_limit,
                },
            ));
        }
        self.reads_used += 1;
        let end = checked_range(what, at, len, self.data.len())?;
        for i in at..end {
            self.claimed[i / 64] |= 1u64 << (i % 64);
        }
        Ok(&self.data[at..end])
    }

    /// Read and claim a fixed-size array.
    pub fn array<const N: usize>(&mut self, what: &'static str, at: usize) -> Result<[u8; N]> {
        Ok(self.bytes(what, at, N)?.try_into().expect("length checked"))
    }

    /// Read and claim one byte.
    pub fn u8(&mut self, what: &'static str, at: usize) -> Result<u8> {
        Ok(self.array::<1>(what, at)?[0])
    }

    /// Read and claim a `u16` in `endian` order.
    pub fn u16(&mut self, what: &'static str, at: usize, endian: Endian) -> Result<u16> {
        let b = self.array::<2>(what, at)?;
        Ok(match endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    /// Read and claim a `u32` in `endian` order.
    pub fn u32(&mut self, what: &'static str, at: usize, endian: Endian) -> Result<u32> {
        let b = self.array::<4>(what, at)?;
        Ok(match endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    /// Read and claim a little-endian `u16`.
    pub fn u16_le(&mut self, what: &'static str, at: usize) -> Result<u16> {
        self.u16(what, at, Endian::Little)
    }

    /// Read and claim a little-endian `i16`.
    pub fn i16_le(&mut self, what: &'static str, at: usize) -> Result<i16> {
        Ok(self.u16_le(what, at)? as i16)
    }

    /// Read and claim a little-endian `u32`.
    pub fn u32_le(&mut self, what: &'static str, at: usize) -> Result<u32> {
        self.u32(what, at, Endian::Little)
    }

    /// Read and claim a little-endian `i32`.
    pub fn i32_le(&mut self, what: &'static str, at: usize) -> Result<i32> {
        Ok(self.u32_le(what, at)? as i32)
    }

    /// Claim `at..at + len` without reading it (for example a reserved field
    /// the owner reproduces itself). Counts as one read.
    pub fn claim(&mut self, what: &'static str, at: usize, len: usize) -> Result<()> {
        self.bytes(what, at, len).map(|_| ())
    }

    /// Whether byte `at` has been claimed (`false` outside the region).
    #[must_use]
    pub fn is_claimed(&self, at: usize) -> bool {
        at < self.data.len() && self.claimed[at / 64] & (1u64 << (at % 64)) != 0
    }

    /// Number of claimed bytes.
    #[must_use]
    pub fn claimed_len(&self) -> usize {
        self.claimed.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Unclaimed byte runs in ascending order.
    #[must_use]
    pub fn gaps(&self) -> Vec<UnclaimedGap> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.data.len() {
            if self.is_claimed(i) {
                i += 1;
                continue;
            }
            let start = i;
            while i < self.data.len() && !self.is_claimed(i) {
                i += 1;
            }
            out.push(UnclaimedGap {
                offset: start,
                bytes: self.data[start..i].to_vec(),
            });
        }
        out
    }
}

/// How a [`PlacementCanvas`] treats a write over bytes already placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// Later writes replace earlier ones.
    Overwrite,
    /// Writing the same value again is allowed (shared records); a different
    /// value is rejected with [`Error::Malformed`].
    RejectConflicting,
}

/// Fixed-length output buffer on which structures are placed at offsets.
#[doc(alias = "exact writer")]
#[doc(alias = "placement buffer")]
#[derive(Debug, Clone)]
pub struct PlacementCanvas {
    buf: Vec<u8>,
    written: Vec<u64>,
    policy: OverlapPolicy,
}

impl PlacementCanvas {
    /// A `len`-byte canvas initialized to `fill`.
    #[must_use]
    pub fn new(len: usize, fill: u8, policy: OverlapPolicy) -> Self {
        Self {
            buf: vec![fill; len],
            written: vec![0; len.div_ceil(64)],
            policy,
        }
    }

    /// Canvas length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when the canvas is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Place `bytes` at `at`. Fails without writing anything when the range
    /// leaves the canvas or, under [`OverlapPolicy::RejectConflicting`], when
    /// any byte was already placed with a different value.
    pub fn put(&mut self, what: &'static str, at: usize, bytes: &[u8]) -> Result<()> {
        let end = checked_range(what, at, bytes.len(), self.buf.len())?;
        if self.policy == OverlapPolicy::RejectConflicting {
            for (i, &b) in (at..end).zip(bytes) {
                if self.is_written(i) && self.buf[i] != b {
                    return Err(field_error(
                        what,
                        at,
                        Error::Malformed(format!(
                            "conflicting placement at {i:#x}: {:#04x} then {b:#04x}",
                            self.buf[i]
                        )),
                    ));
                }
            }
        }
        self.buf[at..end].copy_from_slice(bytes);
        for i in at..end {
            self.written[i / 64] |= 1u64 << (i % 64);
        }
        Ok(())
    }

    /// Place a `u16` in `endian` order.
    pub fn put_u16(
        &mut self,
        what: &'static str,
        at: usize,
        value: u16,
        endian: Endian,
    ) -> Result<()> {
        match endian {
            Endian::Little => self.put(what, at, &value.to_le_bytes()),
            Endian::Big => self.put(what, at, &value.to_be_bytes()),
        }
    }

    /// Place a `u32` in `endian` order.
    pub fn put_u32(
        &mut self,
        what: &'static str,
        at: usize,
        value: u32,
        endian: Endian,
    ) -> Result<()> {
        match endian {
            Endian::Little => self.put(what, at, &value.to_le_bytes()),
            Endian::Big => self.put(what, at, &value.to_be_bytes()),
        }
    }

    /// Place a little-endian `u16`.
    pub fn put_u16_le(&mut self, what: &'static str, at: usize, value: u16) -> Result<()> {
        self.put_u16(what, at, value, Endian::Little)
    }

    /// Place a little-endian `u32`.
    pub fn put_u32_le(&mut self, what: &'static str, at: usize, value: u32) -> Result<()> {
        self.put_u32(what, at, value, Endian::Little)
    }

    /// Restore previously collected gaps.
    pub fn put_gaps(&mut self, gaps: &[UnclaimedGap]) -> Result<()> {
        for gap in gaps {
            self.put("unclaimed gap", gap.offset, &gap.bytes)?;
        }
        Ok(())
    }

    /// Whether byte `at` has been placed (`false` outside the canvas).
    #[must_use]
    pub fn is_written(&self, at: usize) -> bool {
        at < self.buf.len() && self.written[at / 64] & (1u64 << (at % 64)) != 0
    }

    /// Byte runs never placed, as `(offset, len)` in ascending order; empty
    /// when every byte was written.
    #[must_use]
    pub fn unwritten_ranges(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.buf.len() {
            if self.is_written(i) {
                i += 1;
                continue;
            }
            let start = i;
            while i < self.buf.len() && !self.is_written(i) {
                i += 1;
            }
            out.push((start, i - start));
        }
        out
    }

    /// The placed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the canvas and return its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny synthetic graph: header {u16 count, u16 pad, u32 table offset},
    /// a table of `count` u32 record offsets, and u16 records that may be shared.
    fn graph() -> Vec<u8> {
        let mut b = vec![2, 0, 0xEE, 0xEE, 12, 0, 0, 0];
        b.extend_from_slice(&[0xCC; 4]); // unreferenced
        b.extend_from_slice(&20u32.to_le_bytes()); // table[0]
        b.extend_from_slice(&20u32.to_le_bytes()); // table[1] shares the record
        b.extend_from_slice(&0x0102u16.to_le_bytes());
        b.extend_from_slice(&[0x00, 0x00]); // alignment padding
        b
    }

    #[test]
    fn reads_claim_bytes_and_gaps_rebuild_exactly() {
        let src = graph();
        let mut r = ClaimedReader::new(&src);
        let count = r.u16_le("count", 0).unwrap() as usize;
        let table = r.u32_le("table offset", 4).unwrap() as usize;
        let mut records = Vec::new();
        for i in 0..count {
            let at = checked_element("table entry", table, i, 4).unwrap();
            let rec = r.u32_le("record offset", at).unwrap() as usize;
            records.push((rec, r.u16_le("record", rec).unwrap()));
        }
        assert_eq!(records, [(20, 0x0102), (20, 0x0102)]);
        assert_eq!(r.claimed_len(), 2 + 4 + 8 + 2);
        let gaps = r.gaps();
        assert_eq!(
            gaps,
            [
                UnclaimedGap {
                    offset: 2,
                    bytes: vec![0xEE, 0xEE]
                },
                UnclaimedGap {
                    offset: 8,
                    bytes: vec![0xCC; 4]
                },
                UnclaimedGap {
                    offset: 22,
                    bytes: vec![0, 0]
                },
            ]
        );

        let mut c = PlacementCanvas::new(src.len(), 0x55, OverlapPolicy::RejectConflicting);
        c.put_u16_le("count", 0, count as u16).unwrap();
        c.put_u32_le("table offset", 4, table as u32).unwrap();
        for (i, &(rec, value)) in records.iter().enumerate() {
            c.put_u32_le("record offset", table + i * 4, rec as u32)
                .unwrap();
            c.put_u16_le("record", rec, value).unwrap(); // shared: same value twice
        }
        assert_eq!(c.unwritten_ranges(), [(2, 2), (8, 4), (22, 2)]);
        c.put_gaps(&gaps).unwrap();
        assert!(c.unwritten_ranges().is_empty());
        assert_eq!(c.into_bytes(), src);
    }

    #[test]
    fn out_of_range_reads_and_writes_name_the_field() {
        let src = [1u8, 2, 3];
        let mut r = ClaimedReader::new(&src);
        let err = r.u32_le("table offset", 1).unwrap_err();
        assert_eq!(
            err.contexts().next(),
            Some(&ErrorContext::Field {
                name: "table offset",
                offset: 1
            })
        );
        assert!(matches!(
            err.leaf(),
            Error::Truncated {
                offset: 1,
                needed: 4,
                available: 2
            }
        ));
        assert_eq!(r.claimed_len(), 0);
        assert!(r.bytes("huge", usize::MAX, 2).is_err());
        assert!(r.bytes("past end", 4, 0).is_err());
        assert_eq!(r.bytes("empty at end", 3, 0).unwrap(), &[] as &[u8]);

        let mut c = PlacementCanvas::new(3, 0, OverlapPolicy::Overwrite);
        assert!(c.put("tail", 2, &[1, 2]).is_err());
        assert_eq!(c.as_bytes(), &[0, 0, 0]);
        assert!(checked_offset("offset", usize::MAX, 1).is_err());
        assert_eq!(checked_offset("offset", 4, 8).unwrap(), 12);
        assert!(checked_element("elem", 0, usize::MAX, 2).is_err());
    }

    #[test]
    fn read_limit_bounds_fan_out() {
        let src = [0u8; 4];
        let mut r = ClaimedReader::with_read_limit(&src, 2);
        r.u8("a", 0).unwrap();
        r.u8("b", 0).unwrap();
        assert!(matches!(
            r.u8("c", 0).unwrap_err().leaf(),
            Error::ResourceLimit {
                requested: 3,
                limit: 2,
                ..
            }
        ));
        assert_eq!(ClaimedReader::new(&src).read_limit, 4 * 16 + 65_536);
    }

    #[test]
    fn overlap_policies_and_endianness() {
        let mut strict = PlacementCanvas::new(4, 0, OverlapPolicy::RejectConflicting);
        strict.put_u16("word", 0, 0x1234, Endian::Big).unwrap();
        strict.put("same", 1, &[0x34]).unwrap();
        let err = strict.put("clash", 0, &[0x12, 0x99]).unwrap_err();
        assert!(matches!(err.leaf(), Error::Malformed(_)));
        assert_eq!(strict.as_bytes(), &[0x12, 0x34, 0, 0]);

        let mut loose = PlacementCanvas::new(4, 0, OverlapPolicy::Overwrite);
        loose.put_u32("dword", 0, 0x0102_0304, Endian::Big).unwrap();
        loose.put("over", 0, &[0xFF]).unwrap();
        assert_eq!(loose.into_bytes(), [0xFF, 2, 3, 4]);

        let src = [0x12, 0x34, 0x56, 0x78];
        let mut r = ClaimedReader::new(&src);
        assert_eq!(r.u32("be", 0, Endian::Big).unwrap(), 0x1234_5678);
        assert_eq!(r.i16_le("le", 2).unwrap(), 0x7856);
        assert_eq!(r.i32_le("le", 0).unwrap(), 0x7856_3412);
        assert!(r.gaps().is_empty());
        assert_eq!(UnclaimedGap::fill(3, 3, 0), None);
        assert_eq!(
            UnclaimedGap::fill(1, 3, 0xFF),
            Some(UnclaimedGap {
                offset: 1,
                bytes: vec![0xFF; 2]
            })
        );
    }
}
