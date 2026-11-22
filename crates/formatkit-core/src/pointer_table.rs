//! Platform-neutral scanner for contiguous aligned 32-bit address tables.

use crate::Endian;

/// A contiguous, 4-byte-aligned run of 32-bit pointers into a bounded address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerTable {
    /// Byte offset of the first entry in the scanned image.
    pub offset: usize,
    /// Raw 32-bit pointer entries in `[base_addr, base_addr + image.len())`.
    pub entries: Vec<u32>,
}

/// Scan `bytes` for maximal, non-overlapping 4-byte-aligned runs of at least
/// `min_entries` 32-bit pointers targeting `[base_addr, base_addr + bytes.len())`.
///
/// The caller supplies the platform bus `base_addr` (e.g. `0x0800_0000` for GBA ROMs)
/// and byte order. Returns an empty `Vec` if `min_entries == 0` or `bytes.len() < 4`.
pub fn scan_u32_pointer_tables(
    bytes: &[u8],
    base_addr: u32,
    endian: Endian,
    min_entries: usize,
) -> Vec<PointerTable> {
    if min_entries == 0 || bytes.len() < 4 {
        return Vec::new();
    }
    let end_addr = u64::from(base_addr) + bytes.len() as u64;
    let base_u64 = u64::from(base_addr);

    let mut tables = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_entries: Vec<u32> = Vec::new();

    for (word_idx, &chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let ptr = match endian {
            Endian::Little => u32::from_le_bytes(chunk),
            Endian::Big => u32::from_be_bytes(chunk),
        };
        let ptr_u64 = u64::from(ptr);
        if ptr_u64 >= base_u64 && ptr_u64 < end_addr {
            if run_start.is_none() {
                run_start = Some(word_idx * 4);
            }
            run_entries.push(ptr);
        } else if let Some(start) = run_start.take() {
            if run_entries.len() >= min_entries {
                tables.push(PointerTable {
                    offset: start,
                    entries: core::mem::take(&mut run_entries),
                });
            } else {
                run_entries.clear();
            }
        }
    }

    if let Some(start) = run_start {
        if run_entries.len() >= min_entries {
            tables.push(PointerTable {
                offset: start,
                entries: run_entries,
            });
        }
    }
    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_non_overlapping_runs_little_and_big_endian() {
        let mut img = vec![0u8; 64];
        let base = 0x0800_0000u32;
        for (i, ptr) in [base + 4, base + 16, base + 32].iter().enumerate() {
            img[8 + i * 4..12 + i * 4].copy_from_slice(&ptr.to_le_bytes());
        }
        let found = scan_u32_pointer_tables(&img, base, Endian::Little, 3);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, 8);
        assert_eq!(found[0].entries, vec![base + 4, base + 16, base + 32]);

        let mut be_img = vec![0u8; 32];
        for (i, ptr) in [base + 4, base + 8].iter().enumerate() {
            be_img[4 + i * 4..8 + i * 4].copy_from_slice(&ptr.to_be_bytes());
        }
        let be_found = scan_u32_pointer_tables(&be_img, base, Endian::Big, 2);
        assert_eq!(be_found.len(), 1);
        assert_eq!(be_found[0].offset, 4);
    }
}
