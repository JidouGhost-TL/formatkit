use crate::error::{Error, Result};

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated {
                offset: self.pos,
                needed: n,
                available: self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }
    /// Consume and return all remaining unread bytes.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16_le(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn i16_le(&mut self) -> Result<i16> {
        let b = self.bytes(2)?;
        Ok(i16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32_le(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u16_be(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32_be(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_advances() {
        let data = [0x10u8, 0x00, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        let mut r = Reader::new(&data);
        assert_eq!(r.u8().unwrap(), 0x10);
        assert_eq!(r.u8().unwrap(), 0x00);
        assert_eq!(r.u16_le().unwrap(), 0x1234);
        assert_eq!(r.u32_le().unwrap(), 0x1234_5678);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn short_read_is_truncated_error() {
        let data = [0x01u8, 0x02];
        let mut r = Reader::new(&data);
        assert_eq!(
            r.u32_le(),
            Err(Error::Truncated {
                offset: 0,
                needed: 4,
                available: 2
            })
        );
    }

    #[test]
    fn reads_big_endian() {
        let data = [0x12u8, 0x34, 0x56, 0x78];
        let mut r = Reader::new(&data);
        assert_eq!(r.u32_be().unwrap(), 0x1234_5678);

        let data16 = [0x12u8, 0x34];
        let mut r16 = Reader::new(&data16);
        assert_eq!(r16.u16_be().unwrap(), 0x1234);
    }

    #[test]
    fn short_be_read_is_truncated_error() {
        let data = [0x01u8, 0x02];
        let mut r = Reader::new(&data);
        assert_eq!(
            r.u32_be(),
            Err(Error::Truncated {
                offset: 0,
                needed: 4,
                available: 2
            })
        );
    }

    #[test]
    fn reads_signed_i16_le() {
        let data = [0x00u8, 0x80, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut r = Reader::new(&data);
        assert_eq!(r.i16_le().unwrap(), -32768i16);
        assert_eq!(r.i16_le().unwrap(), -1i16);
        assert_eq!(r.i16_le().unwrap(), 32767i16);
    }

    #[test]
    fn i16_le_short_read_is_truncated_error() {
        let data = [0x01u8];
        let mut r = Reader::new(&data);
        assert_eq!(
            r.i16_le(),
            Err(Error::Truncated {
                offset: 0,
                needed: 2,
                available: 1
            })
        );
    }
}
