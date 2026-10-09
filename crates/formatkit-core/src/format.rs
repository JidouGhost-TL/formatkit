use crate::error::Result;
use crate::writer::Writer;

/// A format with a **lossless byte round-trip**: `parse` reads it and
/// `to_bytes` (via `write`) reproduces it. Implement `Format` only when a type
/// offers that round-trip — reinsertion/rebuild-capable formats.
///
/// This is a *naming + round-trip convention*, not a generically-consumed
/// abstraction: nothing takes `T: Format` or `dyn Format`, so a read-only
/// extractor (which can decode but not faithfully re-emit) should expose an
/// inherent `parse(&[u8]) -> Result<Self>` and simply not implement `Format`.
/// Don't implement it with a stub `write` just to get the name.
pub trait Format: Sized {
    fn parse(bytes: &[u8]) -> Result<Self>;
    fn write(&self, out: &mut Writer) -> Result<()>;
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.write(&mut w)?;
        Ok(w.into_vec())
    }
}
