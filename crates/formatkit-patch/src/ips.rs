//! IPS grammar and explicit patch application policy, using Formatkit readers.

use crate::prelude::*;

use formatkit_core::{Error, ErrorContext, Reader, Result, Writer};

/// Largest encodable offset or EOF size.
pub const MAX_OFFSET: u32 = 0xff_ffff;
/// This offset is reserved by the EOF marker and cannot begin a record.
pub const EOF_OFFSET: u32 = 0x45_4f_46;
/// Maximum payload length of a single IPS record (`0xFFFF`).
pub const MAX_RECORD_SIZE: usize = 0xffff;
/// Default cap on the number of records accepted by [`Patch::parse`].
pub const DEFAULT_MAX_RECORDS: usize = 1_000_000;
/// Application resource policy, independent of any hardware image geometry.
pub const DEFAULT_MAX_OUTPUT_SIZE: usize = 64 * 1024 * 1024;

/// Payload carried by a single IPS patch record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData<'a> {
    /// Verbatim replacement bytes borrowed from the patch input.
    Literal(&'a [u8]),
    /// Run-length encoded fill of `len` copies of `value`.
    Rle {
        /// Number of repeated bytes (`1..=65535`).
        len: u16,
        /// Byte value written across the run.
        value: u8,
    },
}

impl RecordData<'_> {
    /// Number of bytes written by this record.
    pub fn len(&self) -> usize {
        match self {
            Self::Literal(bytes) => bytes.len(),
            Self::Rle { len, .. } => usize::from(*len),
        }
    }

    /// Return whether this record writes zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One IPS patch hunk targeting `offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    /// 24-bit destination offset in the target image.
    pub offset: u32,
    /// Bytes or run to write at `offset`.
    pub data: RecordData<'a>,
}

impl Record<'_> {
    fn end(&self) -> Result<usize> {
        if self.offset > MAX_OFFSET || self.offset == EOF_OFFSET {
            return Err(Error::InvalidField {
                what: "IPS record offset",
                value: self.offset.into(),
            });
        }
        if self.data.is_empty() || self.data.len() > MAX_RECORD_SIZE {
            return Err(Error::InvalidField {
                what: "IPS record length",
                value: self.data.len() as u64,
            });
        }
        (self.offset as usize)
            .checked_add(self.data.len())
            .ok_or_else(|| Error::Malformed("IPS record extent overflow".into()))
    }
}

/// Literal data borrows the patch input; RLE data stays compact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch<'a> {
    /// Ordered patch records as stored in the IPS stream.
    pub records: Vec<Record<'a>>,
    /// Exact final image size, applied after every record (zero-fill if larger).
    pub truncate_to: Option<u32>,
}

/// Policy for handling records whose byte ranges intersect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// Reject any patch containing overlapping record ranges.
    Reject,
    /// Apply records in file order; the last write wins.
    LastWriteWins,
}

/// Policy for handling records or EOF sizes that extend past the input length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowthPolicy {
    /// Reject patches that would grow the input image.
    Reject,
    /// Newly exposed image bytes, including gaps, are zero-filled.
    ZeroFill,
}

/// Explicit policy and size bounds for validating and applying an IPS [`Patch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOptions {
    /// How overlapping records are handled.
    pub overlaps: OverlapPolicy,
    /// How writes extending past the input length are handled.
    pub growth: GrowthPolicy,
    /// Bounds both the intermediate record extent and the final image size.
    pub max_output_size: usize,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            overlaps: OverlapPolicy::Reject,
            growth: GrowthPolicy::Reject,
            max_output_size: DEFAULT_MAX_OUTPUT_SIZE,
        }
    }
}

/// Summary produced by [`Patch::validate`] before applying a patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validation {
    /// Total number of records in the patch.
    pub record_count: usize,
    /// Number of records intersecting an earlier range in offset-sorted order.
    pub overlapping_records: usize,
    /// Original input image size in bytes.
    pub input_size: usize,
    /// Peak working buffer size needed during application.
    pub working_size: usize,
    /// Final output image size in bytes after optional EOF truncation.
    pub output_size: usize,
}

fn u24(reader: &mut Reader<'_>) -> Result<u32> {
    let bytes = reader.bytes(3)?;
    Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
}

fn write_u24(writer: &mut Writer, value: u32) {
    writer.bytes(&value.to_be_bytes()[1..]);
}

fn allocation_error() -> Error {
    Error::Malformed("IPS allocation could not be reserved".into())
}

impl<'a> Patch<'a> {
    /// Parse an IPS byte stream using [`DEFAULT_MAX_RECORDS`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::parse_with_record_limit(bytes, DEFAULT_MAX_RECORDS)
    }

    /// A caller-selected bound prevents record metadata from exhausting memory.
    pub fn parse_with_record_limit(bytes: &'a [u8], max_records: usize) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.bytes(5)? != b"PATCH" {
            return Err(Error::Malformed("IPS header is not PATCH".into()));
        }
        let mut records = Vec::new();
        loop {
            let offset = u24(&mut reader)?;
            if offset == EOF_OFFSET {
                let truncate_to = match reader.remaining() {
                    0 => None,
                    3 => Some(u24(&mut reader)?),
                    count => return Err(Error::Trailing(count)),
                };
                return Ok(Self {
                    records,
                    truncate_to,
                });
            }
            let index = records.len();
            if index >= max_records {
                return Err(Error::ResourceLimit {
                    resource: "IPS records",
                    requested: index as u64 + 1,
                    limit: max_records as u64,
                });
            }
            let mut read_record = || -> Result<Record<'a>> {
                let size = reader.u16_be()?;
                let data = if size == 0 {
                    let len = reader.u16_be()?;
                    let value = reader.u8()?;
                    RecordData::Rle { len, value }
                } else {
                    RecordData::Literal(reader.bytes(usize::from(size))?)
                };
                let record = Record { offset, data };
                record.end()?;
                Ok(record)
            };
            let record =
                read_record().map_err(|error| error.context(ErrorContext::Record { index }))?;
            records.try_reserve(1).map_err(|_| allocation_error())?;
            records.push(record);
        }
    }

    /// Validate this patch against `input_size` and `options` without modifying data.
    pub fn validate(&self, input_size: usize, options: ApplyOptions) -> Result<Validation> {
        if self.truncate_to.is_some_and(|size| size > MAX_OFFSET) {
            return Err(Error::InvalidField {
                what: "IPS EOF size",
                value: self.truncate_to.unwrap_or(0).into(),
            });
        }
        let mut working_size = input_size;
        for (index, record) in self.records.iter().enumerate() {
            let end = record
                .end()
                .map_err(|error| error.context(ErrorContext::Record { index }))?;
            working_size = working_size.max(end);
        }
        let output_size = self.truncate_to.map_or(working_size, |size| size as usize);
        working_size = working_size.max(output_size);
        if working_size > options.max_output_size {
            return Err(Error::ResourceLimit {
                resource: "IPS output bytes",
                requested: working_size as u64,
                limit: options.max_output_size as u64,
            });
        }
        if working_size > input_size && options.growth == GrowthPolicy::Reject {
            return Err(Error::Malformed(
                "IPS writes or EOF size grow the image; zero-fill growth was not authorized".into(),
            ));
        }
        // Check every supplied extent and policy before allocating metadata.
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(self.records.len())
            .map_err(|_| allocation_error())?;
        for record in &self.records {
            ranges.push((record.offset as usize, record.end()?));
        }
        ranges.sort_unstable();
        let mut prior_end = 0;
        let mut overlapping_records = 0;
        for (start, end) in ranges {
            if start < prior_end {
                overlapping_records += 1;
            }
            prior_end = prior_end.max(end);
        }
        if overlapping_records > 0 && options.overlaps == OverlapPolicy::Reject {
            return Err(Error::Malformed(format!(
                "IPS has {overlapping_records} overlapping record(s)"
            )));
        }
        Ok(Validation {
            record_count: self.records.len(),
            overlapping_records,
            input_size,
            working_size,
            output_size,
        })
    }

    /// Validate before allocating; the input image is never mutated.
    pub fn apply(&self, image: &[u8], options: ApplyOptions) -> Result<Vec<u8>> {
        let validation = self.validate(image.len(), options)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(validation.output_size)
            .map_err(|_| allocation_error())?;
        output.extend_from_slice(&image[..image.len().min(validation.output_size)]);
        output.resize(validation.output_size, 0);
        for record in &self.records {
            let start = record.offset as usize;
            // Writes outside the final truncation have no surviving effect.
            if start >= output.len() {
                continue;
            }
            let end = record.end()?.min(output.len());
            match record.data {
                RecordData::Literal(bytes) => {
                    output[start..end].copy_from_slice(&bytes[..end - start])
                }
                RecordData::Rle { value, .. } => output[start..end].fill(value),
            }
        }
        Ok(output)
    }

    /// Preserve record order, RLE representation and the optional EOF size.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_with_size_limit(DEFAULT_MAX_OUTPUT_SIZE)
    }

    /// Bound the entire serialized extent before using the Formatkit writer.
    pub fn encode_with_size_limit(&self, max_patch_size: usize) -> Result<Vec<u8>> {
        if self.truncate_to.is_some_and(|size| size > MAX_OFFSET) {
            return Err(Error::Malformed("IPS EOF size exceeds 24 bits".into()));
        }
        let mut size: usize = if self.truncate_to.is_some() { 11 } else { 8 };
        for record in &self.records {
            record.end()?;
            let record_size = match record.data {
                RecordData::Literal(bytes) => 5 + bytes.len(),
                RecordData::Rle { .. } => 8,
            };
            size = size
                .checked_add(record_size)
                .ok_or_else(|| Error::Malformed("IPS encoded extent overflow".into()))?;
        }
        if size > max_patch_size {
            return Err(Error::ResourceLimit {
                resource: "IPS encoded bytes",
                requested: size as u64,
                limit: max_patch_size as u64,
            });
        }
        let mut writer = Writer::new();
        writer.bytes(b"PATCH");
        for record in &self.records {
            write_u24(&mut writer, record.offset);
            match record.data {
                RecordData::Literal(bytes) => {
                    writer.u16_be(bytes.len() as u16);
                    writer.bytes(bytes);
                }
                RecordData::Rle { len, value } => {
                    writer.u16_be(0);
                    writer.u16_be(len);
                    writer.u8(value);
                }
            }
        }
        writer.bytes(b"EOF");
        if let Some(size) = self.truncate_to {
            write_u24(&mut writer, size);
        }
        Ok(writer.into_vec())
    }
}

/// Create a deterministic compact diff: unchanged spans are skipped, constant
/// spans use RLE when smaller, and records split at the 16-bit length limit.
/// This is a minimal changed-span diff, not a global compressed-size optimizer.
/// Targets can fill the 24-bit address space. Only shrinkage needs an EOF size.
pub fn create(image: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    if target.len() > MAX_OFFSET as usize + 1
        || (target.len() < image.len() && target.len() > MAX_OFFSET as usize)
    {
        return Err(Error::Unsupported(
            "IPS creation target exceeds 24-bit size".into(),
        ));
    }
    let mut records = Vec::new();
    let differs = |index: usize| image.get(index).is_none_or(|byte| target[index] != *byte);
    let mut index = 0;
    while index < target.len() {
        if !differs(index) {
            index += 1;
            continue;
        }
        let mut start = index;
        while index < target.len() && differs(index) {
            index += 1;
        }
        let span_end = index;
        // EOF cannot be a record offset. Include its preceding unchanged byte.
        if start == EOF_OFFSET as usize {
            start -= 1;
        }
        while start < span_end {
            let mut end = (start + MAX_RECORD_SIZE).min(span_end);
            // Avoid a reserved offset at the following split, without overlap.
            if end == EOF_OFFSET as usize && end < span_end {
                end -= 1;
            }
            let bytes = &target[start..end];
            let data = if bytes.len() > 3 && bytes.iter().all(|byte| *byte == bytes[0]) {
                RecordData::Rle {
                    len: bytes.len() as u16,
                    value: bytes[0],
                }
            } else {
                RecordData::Literal(bytes)
            };
            if records.len() >= DEFAULT_MAX_RECORDS {
                return Err(Error::ResourceLimit {
                    resource: "IPS diff records",
                    requested: records.len() as u64 + 1,
                    limit: DEFAULT_MAX_RECORDS as u64,
                });
            }
            records.try_reserve(1).map_err(|_| allocation_error())?;
            records.push(Record {
                offset: start as u32,
                data,
            });
            start = end;
        }
    }
    Patch {
        records,
        truncate_to: (target.len() < image.len()).then_some(target.len() as u32),
    }
    .encode()
}
