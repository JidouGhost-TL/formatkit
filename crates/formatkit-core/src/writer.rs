#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i16_le(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u16_be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32_be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_little_endian() {
        let mut w = Writer::new();
        w.u8(0x10);
        w.u8(0x00);
        w.u16_le(0x1234);
        w.u32_le(0x1234_5678);
        assert_eq!(
            w.into_vec(),
            vec![0x10, 0x00, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn writes_big_endian() {
        let mut w = Writer::new();
        w.u32_be(0x1234_5678);
        w.u16_be(0x1234);
        let bytes = w.into_vec();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78, 0x12, 0x34]);
        // on-wire byte order is big-endian: first byte is the most significant
        assert_eq!(bytes[0], 0x12);
    }

    #[test]
    fn be_round_trips_through_reader() {
        use crate::reader::Reader;

        let mut w = Writer::new();
        w.u32_be(0x1234_5678);
        w.u16_be(0xABCD);
        let bytes = w.into_vec();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u32_be().unwrap(), 0x1234_5678);
        assert_eq!(r.u16_be().unwrap(), 0xABCD);
    }

    #[test]
    fn writes_signed_i16_le() {
        let mut w = Writer::new();
        w.i16_le(-1);
        w.i16_le(0);
        w.i16_le(32767);
        w.i16_le(-32768);
        assert_eq!(
            w.into_vec(),
            vec![0xFF, 0xFF, 0x00, 0x00, 0xFF, 0x7F, 0x00, 0x80]
        );
    }

    #[test]
    fn i16_le_round_trips_through_reader() {
        use crate::reader::Reader;

        let mut w = Writer::new();
        w.i16_le(-1);
        w.i16_le(0);
        w.i16_le(32767);
        w.i16_le(-32768);
        let bytes = w.into_vec();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.i16_le().unwrap(), -1i16);
        assert_eq!(r.i16_le().unwrap(), 0i16);
        assert_eq!(r.i16_le().unwrap(), 32767i16);
        assert_eq!(r.i16_le().unwrap(), -32768i16);
    }
}
