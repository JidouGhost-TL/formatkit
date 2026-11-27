//! Externally counted commands with lazy interleaved LSB-first control bytes.
//!
//! A clear bit selects a literal. Set/clear selects a literal block of the
//! following byte plus eleven. Set/set selects a little-endian token with
//! distance minus one in its low twelve bits. A nonzero high nibble gives
//! length plus two; zero selects a following length byte plus eighteen.
//!
//! Counts are literal: zero means no commands. Header parsing, count wrapping,
//! output-size limits and carrier suffix policy remain with the caller.
//! Explicit history contains known bytes immediately preceding output; no
//! initialized ring or implicit fill is assumed. Copies can overlap output.
//! Scanning validates the same commands without allocating decoded output.
use crate::prelude::*;

use formatkit_core::{
    u8_at, Error, LsbInterleavedBitReader, Result, RetainedResidentPermit, WorkBudget,
    WorkResource as R,
};
fn invalid(what: &'static str) -> Error {
    Error::InvalidField { what, value: 0 }
}
fn tick(work: &mut WorkBudget) -> Result<()> {
    work.check_cancelled()?;
    work.spent(R::Nodes)
        .checked_add(1)
        .ok_or_else(|| invalid("counted LSB nodes overflow"))?;
    work.charge(R::Nodes, 1)
}
/// Exact stream extents and token statistics observed while scanning or decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// Source bytes consumed from the input slice.
    pub consumed: usize,
    /// Decoded bytes produced (or expected when scanning).
    pub produced: usize,
    /// Number of unread control bits left in the final control byte.
    pub unused_control_bits: u8,
    /// Raw value of the unread control bits in the final control byte.
    pub remaining_control: u8,
    /// Counts of each of the four command categories observed.
    pub token_kinds: [u32; 4],
}
/// Decoded counted-LSB output paired with its extent and retained memory permit.
pub struct Decoded {
    bytes: Vec<u8>,
    extent: Extent,
    resident: RetainedResidentPermit,
}
impl Decoded {
    /// Borrow the decoded output bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Return the stream extent and token statistics.
    pub fn extent(&self) -> Extent {
        self.extent
    }
    /// Return the allocated backing capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.bytes.capacity() as u64
    }
    /// Decompose into owned bytes, extent summary, and retained resident permit.
    pub fn into_parts(self) -> (Vec<u8>, Extent, RetainedResidentPermit) {
        (self.bytes, self.extent, self.resident)
    }
}
fn byte(reader: &mut LsbInterleavedBitReader<'_>) -> Result<u8> {
    reader
        .read_byte()
        .ok_or_else(|| invalid("counted LSB truncated operand"))
}
fn bit(reader: &mut LsbInterleavedBitReader<'_>, input: &[u8], last: &mut u8) -> Result<bool> {
    // Observe refill metadata; all bit consumption remains in the shared cursor.
    if reader.buffered_control_bits() == 0 {
        *last = u8_at(input, reader.position())?;
    }
    reader
        .read_bit()
        .ok_or_else(|| invalid("counted LSB truncated control"))
}
fn execute(
    input: &[u8],
    count: u32,
    history: &[u8],
    maximum: usize,
    mut output: Option<&mut Vec<u8>>,
    work: &mut WorkBudget,
) -> Result<Extent> {
    work.check_cancelled()?;
    let tokens = minimum_input(input, count)?;
    let history = &history[history.len().saturating_sub(4096)..];
    let mut reader = LsbInterleavedBitReader::new(input);
    let (mut produced, mut last, mut kinds) = (0usize, 0u8, [0u32; 4]);
    for _ in 0..tokens {
        tick(work)?;
        let (length, distance, literal, kind) = if !bit(&mut reader, input, &mut last)? {
            let value = byte(&mut reader)?;
            (1, 0, Some(value), 0)
        } else if !bit(&mut reader, input, &mut last)? {
            (usize::from(byte(&mut reader)?) + 11, 0, None, 1)
        } else {
            let lo = byte(&mut reader)?;
            let hi = byte(&mut reader)?;
            let distance = 1 + usize::from(lo) + (usize::from(hi & 15) << 8);
            let (n, kind) = if hi >> 4 == 0 {
                (usize::from(byte(&mut reader)?) + 18, 3)
            } else {
                (usize::from(hi >> 4) + 2, 2)
            };
            if distance.saturating_sub(produced) > history.len() {
                return Err(Error::UnsupportedDialect {
                    family: "counted LSB LZ",
                    dialect: "undefined pre-output history",
                });
            }
            (n, distance, None, kind)
        };
        let end = produced
            .checked_add(length)
            .ok_or_else(|| invalid("counted LSB output extent overflow"))?;
        if end > maximum {
            return Err(Error::ResourceLimit {
                resource: "counted LSB output bytes",
                requested: end as u64,
                limit: maximum as u64,
            });
        }
        let raw = if kind == 1 {
            Some(
                reader
                    .read_bytes(length)
                    .ok_or_else(|| invalid("counted LSB truncated literal block"))?,
            )
        } else {
            None
        };
        for i in 0..length {
            tick(work)?;
            if let Some(out) = output.as_deref_mut() {
                let value = if let Some(value) = literal {
                    value
                } else if let Some(raw) = raw {
                    raw[i]
                } else {
                    if distance > produced {
                        history[history.len() - (distance - produced)]
                    } else {
                        out[produced - distance]
                    }
                };
                out.push(value);
            }
            produced += 1;
        }
        kinds[kind] += 1;
    }
    work.check_cancelled()?;
    let left = reader.buffered_control_bits();
    Ok(Extent {
        consumed: reader.position(),
        produced,
        unused_control_bits: left,
        remaining_control: (u16::from(last) >> (8 - left)) as u8,
        token_kinds: kinds,
    })
}
fn minimum_input(input: &[u8], count: u32) -> Result<usize> {
    let tokens = usize::try_from(count).map_err(|_| invalid("counted LSB command count"))?;
    if tokens > input.len() {
        return Err(invalid("counted LSB minimum input extent"));
    }
    Ok(tokens)
}
/// Validate commands and report their exact extent without output allocation.
pub fn scan_with_work(
    input: &[u8],
    count: u32,
    history: &[u8],
    maximum: usize,
    work: &mut WorkBudget,
) -> Result<Extent> {
    execute(input, count, history, maximum, None, work)
}
fn reserve(n: usize, work: &mut WorkBudget) -> Result<(Vec<u8>, RetainedResidentPermit)> {
    work.check_cancelled()?;
    work.usage()
        .resident_bytes()
        .checked_add(n as u64)
        .ok_or_else(|| invalid("counted LSB resident overflow"))?;
    work.spent(R::MaterializedBytes)
        .checked_add(n as u64)
        .ok_or_else(|| invalid("counted LSB materialized overflow"))?;
    work.check(R::MaterializedBytes, n as u64)?;
    let mut permit = work.retain_resident(n as u64)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(n)
        .map_err(|_| Error::ResourceLimit {
            resource: "counted LSB allocation",
            requested: n as u64,
            limit: n as u64,
        })?;
    let actual = bytes.capacity() as u64;
    work.usage()
        .resident_bytes()
        .checked_add(actual - n as u64)
        .ok_or_else(|| invalid("counted LSB resident overflow"))?;
    work.spent(R::MaterializedBytes)
        .checked_add(actual)
        .ok_or_else(|| invalid("counted LSB materialized overflow"))?;
    permit.resize(work, actual)?;
    work.charge(R::MaterializedBytes, actual)?;
    Ok((bytes, permit))
}
/// Admit actual capacity once; the caller accounts source snapshots/emission.
pub fn decode_exact_with_work(
    input: &[u8],
    count: u32,
    history: &[u8],
    expected: usize,
    work: &mut WorkBudget,
) -> Result<Decoded> {
    work.check_cancelled()?;
    minimum_input(input, count)?;
    let (mut bytes, resident) = reserve(expected, work)?;
    let extent = execute(input, count, history, expected, Some(&mut bytes), work)?;
    if extent.produced != expected {
        return Err(invalid("counted LSB exact decoded size"));
    }
    Ok(Decoded {
        bytes,
        extent,
        resident,
    })
}
/// Two passes share the executor. Both scans spend Nodes, but scanning creates
/// no decoded bytes; only actual output capacity is materialized/admitted.
pub fn decode_with_work(
    input: &[u8],
    count: u32,
    history: &[u8],
    maximum: usize,
    work: &mut WorkBudget,
) -> Result<Decoded> {
    let extent = scan_with_work(input, count, history, maximum, work)?;
    let decoded = decode_exact_with_work(input, count, history, extent.produced, work)?;
    debug_assert_eq!(extent, decoded.extent());
    Ok(decoded)
}

#[cfg(test)]
#[path = "counted_lsb_tests.rs"]
mod tests;
