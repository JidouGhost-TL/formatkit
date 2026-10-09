//! Byte-padded, MSB-first one-bit bitmap rows.

/// A validated view of tightly packed 1bpp rows.
#[derive(Debug, Clone, Copy)]
pub struct MsbFirst1bppRows<'a> {
    bytes: &'a [u8],
    width: usize,
    height: usize,
    stride: usize,
}

impl<'a> MsbFirst1bppRows<'a> {
    /// Build a view when `bytes` is exactly `ceil(width / 8) * height` bytes.
    pub fn new(bytes: &'a [u8], width: usize, height: usize) -> Option<Self> {
        let stride = width.checked_add(7)? / 8;
        // `slice::chunks_exact(0)` panics, so reject the otherwise ambiguous
        // zero-width shape at construction rather than leaving a latent trap.
        if stride == 0 {
            return None;
        }
        let expected = stride.checked_mul(height)?;
        (bytes.len() == expected).then_some(Self {
            bytes,
            width,
            height,
            stride,
        })
    }

    pub const fn width(self) -> usize {
        self.width
    }

    pub const fn height(self) -> usize {
        self.height
    }

    pub const fn stride(self) -> usize {
        self.stride
    }

    /// Iterate stored rows. Padding bits after `width` remain owner-opaque.
    pub fn rows(self) -> impl ExactSizeIterator<Item = &'a [u8]> {
        self.bytes.chunks_exact(self.stride)
    }

    /// Read one logical pixel. Out-of-range coordinates are unset.
    #[inline]
    pub fn is_set(self, x: usize, y: usize) -> bool {
        if x >= self.width || y >= self.height {
            return false;
        }
        self.bytes[y * self.stride + x / 8] & (0x80 >> (x % 8)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_shape_msb_order_and_padding_are_explicit() {
        let rows = MsbFirst1bppRows::new(&[0x81, 0x80, 0x40, 0x40], 9, 2).unwrap();
        assert_eq!((rows.width(), rows.height(), rows.stride()), (9, 2, 2));
        assert!(rows.is_set(0, 0));
        assert!(rows.is_set(7, 0));
        assert!(rows.is_set(8, 0));
        assert!(rows.is_set(1, 1));
        assert!(!rows.is_set(9, 0));
        assert_eq!(
            rows.rows().collect::<Vec<_>>(),
            [&[0x81, 0x80][..], &[0x40, 0x40][..]]
        );
        assert!(MsbFirst1bppRows::new(&[0; 3], 9, 2).is_none());
        assert!(MsbFirst1bppRows::new(&[], 0, 1).is_none());
        assert!(MsbFirst1bppRows::new(&[], usize::MAX, 1).is_none());
    }
}
