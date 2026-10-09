//! Bounded LZMA-alone decoding.
//!
//! A standard LZMA-alone stream begins with one properties byte, a little-endian
//! dictionary size, and a little-endian decoded size. Format owners can require
//! that a container record agrees with the stream's declared decoded size. The
//! decoder remains independently bounded for hostile inputs: the caller caps
//! output bytes, the dictionary allocation is capped, and the output writer
//! refuses the first write that would cross the limit.

use std::io::{self, Cursor, Write};

const HEADER_LEN: usize = 13;
const UNKNOWN_SIZE: u64 = u64::MAX;
const MIN_DICTIONARY_LIMIT: usize = 4096;

/// Return the decoded-size word from a structurally possible LZMA-alone
/// header. `u64::MAX` is the standard unknown-size/end-marker spelling.
pub fn lzma_alone_declared_size(bytes: &[u8]) -> Option<u64> {
    let properties = *bytes.first()?;
    if properties >= 9 * 5 * 5 || bytes.len() < HEADER_LEN {
        return None;
    }
    formatkit_core::u64_at(bytes, 5).ok()
}

/// Decode a complete LZMA-alone stream without permitting more than
/// `max_output_len` usable bytes or an unreasonably larger dictionary.
pub fn lzma_alone_decompress_with_limit(bytes: &[u8], max_output_len: usize) -> Option<Vec<u8>> {
    let declared = lzma_alone_declared_size(bytes)?;
    if declared != UNKNOWN_SIZE && declared > max_output_len as u64 {
        return None;
    }

    let reserve = if declared == UNKNOWN_SIZE {
        0
    } else {
        usize::try_from(declared).ok()?
    };
    let mut output = LimitedOutput::new(max_output_len, reserve)?;
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::ReadFromHeader,
        memlimit: Some(max_output_len.max(MIN_DICTIONARY_LIMIT)),
        allow_incomplete: false,
    };
    let mut input = Cursor::new(bytes);
    lzma_rs::lzma_decompress_with_options(&mut input, &mut output, &options).ok()?;
    let output = output.into_inner();
    if declared != UNKNOWN_SIZE && output.len() as u64 != declared {
        return None;
    }
    if input.position() != bytes.len() as u64 {
        // A known-size stream may carry an optional end marker after the last
        // output byte. Re-run it with the size word changed to "unknown" so
        // the decoder must consume that marker; this distinguishes the marker
        // from unrelated trailing bytes. Known-size streams with no marker
        // have already consumed the complete input above.
        if declared == UNKNOWN_SIZE {
            return None;
        }
        let mut end_marked = Vec::new();
        end_marked.try_reserve_exact(bytes.len()).ok()?;
        end_marked.extend_from_slice(bytes);
        end_marked[5..13].copy_from_slice(&UNKNOWN_SIZE.to_le_bytes());
        let mut probe_input = Cursor::new(end_marked.as_slice());
        let mut probe_output = LimitedOutput::new(max_output_len, output.len())?;
        lzma_rs::lzma_decompress_with_options(&mut probe_input, &mut probe_output, &options)
            .ok()?;
        if probe_input.position() != bytes.len() as u64 || probe_output.into_inner() != output {
            return None;
        }
    }
    Some(output)
}

struct LimitedOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl LimitedOutput {
    fn new(limit: usize, reserve: usize) -> Option<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(reserve).ok()?;
        Some(Self { bytes, limit })
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = self.bytes.len().checked_add(buffer.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "LZMA output size overflows")
        })?;
        if requested > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZMA output exceeds configured limit",
            ));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_UNKNOWN_SIZE: &[u8] = &[
        0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x34,
        0x19, 0x49, 0xee, 0x8e, 0x68, 0x21, 0xff, 0xff, 0xff, 0xb9, 0xe0, 0x00, 0x00,
    ];

    #[test]
    fn decodes_known_and_unknown_size_lzma_alone() {
        assert_eq!(
            lzma_alone_declared_size(HELLO_UNKNOWN_SIZE),
            Some(UNKNOWN_SIZE)
        );
        assert_eq!(
            lzma_alone_decompress_with_limit(HELLO_UNKNOWN_SIZE, 5).as_deref(),
            Some(&b"hello"[..])
        );

        let mut known = HELLO_UNKNOWN_SIZE.to_vec();
        known[5..13].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(lzma_alone_declared_size(&known), Some(5));
        assert_eq!(
            lzma_alone_decompress_with_limit(&known, 5).as_deref(),
            Some(&b"hello"[..])
        );
    }

    #[test]
    fn rejects_bad_headers_and_enforces_the_output_limit() {
        let mut invalid = HELLO_UNKNOWN_SIZE.to_vec();
        invalid[0] = 225;
        assert_eq!(lzma_alone_declared_size(&invalid), None);
        assert!(lzma_alone_decompress_with_limit(&invalid, 5).is_none());
        assert!(lzma_alone_decompress_with_limit(HELLO_UNKNOWN_SIZE, 4).is_none());

        let mut oversized = HELLO_UNKNOWN_SIZE.to_vec();
        oversized[5..13].copy_from_slice(&6u64.to_le_bytes());
        assert!(lzma_alone_decompress_with_limit(&oversized, 5).is_none());

        let mut trailing = HELLO_UNKNOWN_SIZE.to_vec();
        trailing.extend_from_slice(b"trailing");
        assert!(lzma_alone_decompress_with_limit(&trailing, 5).is_none());
    }
}
