#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    /// Row-major RGBA8888, length == width * height * 4.
    pub rgba: Vec<u8>,
}

impl Image {
    /// Checked byte length of a tightly packed RGBA8888 image.
    pub fn rgba_len(width: u32, height: u32) -> crate::Result<usize> {
        (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(4))
            .ok_or(crate::Error::InvalidField {
                what: "image dimensions",
                value: ((width as u64) << 32) | height as u64,
            })
    }

    /// Preflight and reserve a tightly packed RGBA8888 output buffer.
    ///
    /// The buffer is returned empty with capacity for at least the requested
    /// RGBA byte length. Decoders retain responsibility for channel order and
    /// whether they append or zero-fill pixels. `resource` stays owner-selected
    /// so a shared allocation mechanism does not erase format-specific diagnostics.
    pub fn try_rgba_buffer(
        width: u32,
        height: u32,
        max_bytes: usize,
        resource: &'static str,
    ) -> crate::Result<Vec<u8>> {
        let requested = Self::rgba_len(width, height).map_err(|_| crate::Error::ResourceLimit {
            resource,
            requested: u64::MAX,
            limit: max_bytes as u64,
        })?;
        if requested > max_bytes {
            return Err(crate::Error::ResourceLimit {
                resource,
                requested: requested as u64,
                limit: max_bytes as u64,
            });
        }
        let mut rgba = Vec::new();
        rgba.try_reserve_exact(requested)
            .map_err(|_| crate::Error::ResourceLimit {
                resource,
                requested: requested as u64,
                limit: max_bytes as u64,
            })?;
        Ok(rgba)
    }

    /// Construct an image without revalidating a caller-established buffer
    /// invariant. Parsers should prefer [`Image::try_new`] when dimensions are
    /// derived from untrusted input.
    pub fn new(width: u32, height: u32, rgba: Vec<u8>) -> Self {
        Image {
            width,
            height,
            rgba,
        }
    }

    /// Construct an image after validating `width * height * 4` and the exact
    /// RGBA buffer length.
    pub fn try_new(width: u32, height: u32, rgba: Vec<u8>) -> crate::Result<Self> {
        let expected = Self::rgba_len(width, height)?;
        if rgba.len() != expected {
            return Err(crate::Error::InvalidField {
                what: "RGBA buffer length",
                value: rgba.len() as u64,
            });
        }
        Ok(Self {
            width,
            height,
            rgba,
        })
    }

    pub fn validate(&self) -> crate::Result<()> {
        let expected = Self::rgba_len(self.width, self.height)?;
        if self.rgba.len() != expected {
            return Err(crate::Error::InvalidField {
                what: "RGBA buffer length",
                value: self.rgba.len() as u64,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_holds_dims_and_pixels() {
        let img = Image::new(1, 1, vec![1, 2, 3, 4]);
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
        assert_eq!(img.rgba.len(), 4);
    }

    #[test]
    fn checked_constructor_rejects_wrong_buffer_length() {
        assert!(Image::try_new(2, 2, vec![0; 15]).is_err());
        assert!(Image::try_new(2, 2, vec![0; 16]).is_ok());
    }

    #[test]
    fn rgba_buffer_preflights_limit_and_reserves_without_initializing() {
        let rgba = Image::try_rgba_buffer(3, 2, 24, "test RGBA bytes").unwrap();
        assert!(rgba.is_empty());
        assert!(rgba.capacity() >= 24);
        assert!(matches!(
            Image::try_rgba_buffer(3, 2, 23, "test RGBA bytes"),
            Err(crate::Error::ResourceLimit {
                resource: "test RGBA bytes",
                requested: 24,
                limit: 23,
            })
        ));
    }
}
