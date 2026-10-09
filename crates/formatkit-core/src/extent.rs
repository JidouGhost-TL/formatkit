//! Bounds-safe byte extents and declared-versus-containing size audits.

use crate::{Error, Result};

/// A half-open byte range `[offset, offset + length)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: usize,
    pub length: usize,
}

impl Extent {
    pub const fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    /// The exclusive end offset, or a malformed-input error on overflow.
    pub fn end(self) -> Result<usize> {
        self.offset
            .checked_add(self.length)
            .ok_or_else(|| Error::Malformed("extent end overflows usize".into()))
    }

    /// Resolve this extent inside `bytes` without allowing adjacent data to be read.
    pub fn slice(self, bytes: &[u8]) -> Result<&[u8]> {
        let end = self.end()?;
        bytes.get(self.offset..end).ok_or(Error::Truncated {
            offset: self.offset,
            needed: self.length,
            available: bytes.len().saturating_sub(self.offset),
        })
    }

    pub fn contains(self, other: Extent) -> bool {
        match (self.end(), other.end()) {
            (Ok(end), Ok(other_end)) => other.offset >= self.offset && other_end <= end,
            _ => false,
        }
    }
}

/// Relationship between an inner declared size and its trusted outer extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentStatus {
    Exact,
    TrailingData,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentAudit {
    pub declared: usize,
    pub available: usize,
    /// Bytes from the declared region that are actually present.
    pub declared_available: usize,
    pub trailing: usize,
    pub missing: usize,
    pub status: ExtentStatus,
}

/// Compare a structure's declared length with the bytes supplied by its container.
pub const fn audit_extent(declared: usize, available: usize) -> ExtentAudit {
    if declared == available {
        ExtentAudit {
            declared,
            available,
            declared_available: declared,
            trailing: 0,
            missing: 0,
            status: ExtentStatus::Exact,
        }
    } else if declared < available {
        ExtentAudit {
            declared,
            available,
            declared_available: declared,
            trailing: available - declared,
            missing: 0,
            status: ExtentStatus::TrailingData,
        }
    } else {
        ExtentAudit {
            declared,
            available,
            declared_available: available,
            trailing: 0,
            missing: declared - available,
            status: ExtentStatus::Truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_cannot_cross_the_containing_buffer() {
        let bytes = b"headerpixelsibling";
        assert_eq!(Extent::new(6, 5).slice(bytes).unwrap(), b"pixel");
        assert!(matches!(
            Extent::new(6, bytes.len()).slice(bytes),
            Err(Error::Truncated { offset: 6, .. })
        ));
    }

    #[test]
    fn containment_is_half_open_and_overflow_safe() {
        let outer = Extent::new(100, 20);
        assert!(outer.contains(Extent::new(100, 20)));
        assert!(outer.contains(Extent::new(120, 0)));
        assert!(!outer.contains(Extent::new(119, 2)));
        assert!(!outer.contains(Extent::new(usize::MAX, 2)));
    }

    #[test]
    fn audits_exact_trailing_and_truncated_extents() {
        assert_eq!(audit_extent(8, 8).status, ExtentStatus::Exact);
        assert_eq!(audit_extent(8, 12).trailing, 4);
        assert_eq!(audit_extent(12, 8).missing, 4);
        assert_eq!(audit_extent(12, 8).declared_available, 8);
    }
}
