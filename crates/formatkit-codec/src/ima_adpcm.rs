//! IMA ADPCM 4-bit codes: state, reference tables, decode, nearest and exact encode.
//!
//! The arithmetic is the IMA ADPCM algorithm from the Interactive Multimedia
//! Association's *Recommended Practices for Enhancing Digital Audio
//! Compatibility in Multimedia Systems* (revision 3.00, 1992): 89 step sizes,
//! a step-index adjustment per code magnitude, a shift-and-add difference
//! (`step >> 3`, plus `step >> 2`, `step >> 1` and `step` for code bits 0, 1
//! and 2, negated by bit 3), the predictor clamped to the signed 16-bit range
//! and the step index clamped to `0..=88`.
//!
//! Containers differ only in framing, which stays with the caller:
//!
//! - [`ImaNibbleOrder`] picks which half of each byte holds the earlier code.
//! - [`ImaAdpcmHeader`] reads and writes the common 4-byte little-endian
//!   block header (`i16` predictor, `u8` step index, one reserved byte kept
//!   for exact writes); [`ImaHeaderSample`] says whether the header's
//!   predictor is also the block's first output sample.
//! - Streams without a header pass an explicit [`ImaAdpcmState`].
//!
//! [`encode_ima_adpcm_codes_exact`] re-encodes PCM that an IMA decoder
//! produced from the same initial state so that decoding reproduces it
//! exactly. Several codes can yield the same sample (for example `0` and `8`
//! when `step >> 3 == 0`), so the re-encoded *bytes* may differ from the
//! originals; callers needing byte-identical output keep the source bytes.
//!
//! ```
//! use formatkit_codec::ima_adpcm::{
//!     decode_ima_adpcm_block, encode_ima_adpcm_block, ImaAdpcmState, ImaHeaderSample,
//!     ImaNibbleOrder,
//! };
//!
//! // Low-nibble-first codes after a header whose predictor is state only.
//! let block = [0x00, 0x00, 0x00, 0x00, 0x77];
//! let pcm = decode_ima_adpcm_block(&block, 2, ImaNibbleOrder::LowFirst, ImaHeaderSample::StateOnly)
//!     .unwrap();
//! assert_eq!(pcm, [11, 41]);
//!
//! let again = encode_ima_adpcm_block(
//!     ImaAdpcmState::new(0, 0).unwrap(),
//!     &pcm,
//!     ImaNibbleOrder::LowFirst,
//!     0,
//! );
//! assert_eq!(again, block);
//! ```

use formatkit_core::{Error, Result};

/// IMA ADPCM step sizes, indexed by the step index `0..=88`.
pub const IMA_STEP_TABLE: [i16; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

/// IMA ADPCM step-index adjustment, indexed by the full 4-bit code.
pub const IMA_INDEX_TABLE: [i8; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// Largest valid step index.
pub const IMA_MAX_STEP_INDEX: u8 = 88;

/// Which half of each code byte holds the earlier of its two 4-bit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaNibbleOrder {
    /// Bits `0..=3` hold the earlier code, bits `4..=7` the later one.
    LowFirst,
    /// Bits `4..=7` hold the earlier code, bits `0..=3` the later one.
    HighFirst,
}

impl ImaNibbleOrder {
    fn code(self, codes: &[u8], i: usize) -> u8 {
        let byte = codes[i / 2];
        match (self, i % 2) {
            (Self::LowFirst, 0) | (Self::HighFirst, 1) => byte & 0x0f,
            _ => byte >> 4,
        }
    }

    fn put(self, codes: &mut [u8], i: usize, code: u8) {
        let shift = match (self, i % 2) {
            (Self::LowFirst, 0) | (Self::HighFirst, 1) => 0,
            _ => 4,
        };
        codes[i / 2] |= (code & 0x0f) << shift;
    }
}

/// Decoder/encoder state: the last reconstructed sample and the step index.
#[doc(alias = "adpcm predictor")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImaAdpcmState {
    /// Last reconstructed sample.
    pub predictor: i16,
    /// Index into [`IMA_STEP_TABLE`], `0..=88`.
    pub step_index: u8,
}

impl ImaAdpcmState {
    /// Construct a state, rejecting `step_index > 88`.
    pub fn new(predictor: i16, step_index: u8) -> Result<Self> {
        if step_index > IMA_MAX_STEP_INDEX {
            return Err(Error::InvalidField {
                what: "IMA ADPCM step index",
                value: u64::from(step_index),
            });
        }
        Ok(Self {
            predictor,
            step_index,
        })
    }

    /// Apply one 4-bit code (upper bits ignored) and return the new sample.
    ///
    /// A state built with an out-of-range public `step_index` is clamped to
    /// `88` before use.
    pub fn decode_code(&mut self, code: u8) -> i16 {
        let code = code & 0x0f;
        let step = i32::from(IMA_STEP_TABLE[usize::from(self.step_index.min(IMA_MAX_STEP_INDEX))]);
        let mut diff = step >> 3;
        if code & 1 != 0 {
            diff += step >> 2;
        }
        if code & 2 != 0 {
            diff += step >> 1;
        }
        if code & 4 != 0 {
            diff += step;
        }
        let p = i32::from(self.predictor);
        let p = if code & 8 != 0 { p - diff } else { p + diff };
        self.predictor = p.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        let index = i32::from(self.step_index.min(IMA_MAX_STEP_INDEX))
            + i32::from(IMA_INDEX_TABLE[usize::from(code)]);
        self.step_index = index.clamp(0, i32::from(IMA_MAX_STEP_INDEX)) as u8;
        self.predictor
    }
}

/// The common 4-byte little-endian block header: `i16` predictor, `u8` step
/// index, and one reserved byte (zero in conforming data, kept for exact writes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImaAdpcmHeader {
    /// Initial state.
    pub state: ImaAdpcmState,
    /// The fourth header byte.
    pub reserved: u8,
}

impl ImaAdpcmHeader {
    /// Encoded header length in bytes.
    pub const LEN: usize = 4;

    /// Parse the first four bytes of `bytes`, rejecting step indices above `88`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let Some(b) = bytes.first_chunk::<4>() else {
            return Err(Error::Truncated {
                offset: 0,
                needed: Self::LEN,
                available: bytes.len(),
            });
        };
        Ok(Self {
            state: ImaAdpcmState::new(i16::from_le_bytes([b[0], b[1]]), b[2])?,
            reserved: b[3],
        })
    }

    /// Serialize the header.
    pub fn to_bytes(&self) -> [u8; 4] {
        let p = self.state.predictor.to_le_bytes();
        [p[0], p[1], self.state.step_index, self.reserved]
    }
}

/// Whether a block header's predictor is also an output sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaHeaderSample {
    /// The predictor only seeds the decoder; output starts with the first code.
    StateOnly,
    /// The predictor is emitted as the first output sample, before the codes.
    FirstOutput,
}

/// Decode `count` samples from packed 4-bit `codes`, starting at `state`.
///
/// Returns the samples and the state after the last code. Rejects `codes`
/// shorter than `count.div_ceil(2)` bytes before allocating; surplus bytes
/// (and an unused final nibble) are ignored.
pub fn decode_ima_adpcm_codes(
    state: ImaAdpcmState,
    codes: &[u8],
    count: usize,
    order: ImaNibbleOrder,
) -> Result<(Vec<i16>, ImaAdpcmState)> {
    let needed = count.div_ceil(2);
    if needed > codes.len() {
        return Err(Error::Truncated {
            offset: 0,
            needed,
            available: codes.len(),
        });
    }
    let mut s = state;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(s.decode_code(order.code(codes, i)));
    }
    Ok((out, s))
}

/// Decode a block that begins with an [`ImaAdpcmHeader`].
///
/// `count` is the number of output samples. With
/// [`ImaHeaderSample::FirstOutput`] it includes the header sample, so
/// `count - 1` codes follow the header; with [`ImaHeaderSample::StateOnly`]
/// all `count` samples come from codes.
pub fn decode_ima_adpcm_block(
    block: &[u8],
    count: usize,
    order: ImaNibbleOrder,
    header_sample: ImaHeaderSample,
) -> Result<Vec<i16>> {
    let header = ImaAdpcmHeader::parse(block)?;
    let codes = &block[ImaAdpcmHeader::LEN..];
    let shift = |e: Error| match e {
        Error::Truncated {
            offset,
            needed,
            available,
        } => Error::Truncated {
            offset: offset + ImaAdpcmHeader::LEN,
            needed,
            available,
        },
        other => other,
    };
    match header_sample {
        ImaHeaderSample::StateOnly => decode_ima_adpcm_codes(header.state, codes, count, order)
            .map(|(pcm, _)| pcm)
            .map_err(shift),
        ImaHeaderSample::FirstOutput => {
            if count == 0 {
                return Ok(Vec::new());
            }
            let (rest, _) =
                decode_ima_adpcm_codes(header.state, codes, count - 1, order).map_err(shift)?;
            let mut out = Vec::with_capacity(count);
            out.push(header.state.predictor);
            out.extend_from_slice(&rest);
            Ok(out)
        }
    }
}

/// Encode samples to packed codes by choosing, per sample, the code whose
/// reconstruction is nearest (lowest code on ties). An odd final sample
/// leaves the other nibble zero. Returns the codes and the final state.
pub fn encode_ima_adpcm_codes_nearest(
    state: ImaAdpcmState,
    samples: &[i16],
    order: ImaNibbleOrder,
) -> (Vec<u8>, ImaAdpcmState) {
    let mut s = state;
    let mut out = vec![0u8; samples.len().div_ceil(2)];
    for (i, &target) in samples.iter().enumerate() {
        let mut best = (0u8, i32::MAX, s);
        for code in 0..16u8 {
            let mut trial = s;
            let err = (i32::from(trial.decode_code(code)) - i32::from(target)).abs();
            if err < best.1 {
                best = (code, err, trial);
                if err == 0 {
                    break;
                }
            }
        }
        order.put(&mut out, i, best.0);
        s = best.2;
    }
    (out, s)
}

/// Encode samples so that decoding from `state` reproduces them exactly, or
/// return `None` when no code sequence can.
///
/// The predictor after each code is fixed by its sample, so the step index
/// is the only free state. A forward pass records, per sample, the set of
/// step indices from which every sample so far is reproducible (16 bytes per
/// sample); a backward pass then picks one path, preferring the lowest step
/// index and the lowest code. The result is deterministic and linear in the
/// sample count.
pub fn encode_ima_adpcm_codes_exact(
    state: ImaAdpcmState,
    samples: &[i16],
    order: ImaNibbleOrder,
) -> Option<(Vec<u8>, ImaAdpcmState)> {
    let start_index = state.step_index.min(IMA_MAX_STEP_INDEX);
    // layers[i]: step indices reachable after i samples.
    let mut layers: Vec<u128> = Vec::with_capacity(samples.len() + 1);
    layers.push(1u128 << start_index);
    let mut predictor = state.predictor;
    for &target in samples {
        let prev = *layers.last()?;
        let mut next = 0u128;
        for from in set_bits(prev) {
            for code in 0..16u8 {
                let mut s = ImaAdpcmState {
                    predictor,
                    step_index: from,
                };
                if s.decode_code(code) == target {
                    next |= 1u128 << s.step_index;
                }
            }
        }
        if next == 0 {
            return None;
        }
        layers.push(next);
        predictor = target;
    }

    let end_index = set_bits(*layers.last()?).next()?;
    let end = ImaAdpcmState {
        predictor,
        step_index: end_index,
    };
    let mut out = vec![0u8; samples.len().div_ceil(2)];
    let mut want = end_index;
    for i in (0..samples.len()).rev() {
        let before = if i == 0 {
            state.predictor
        } else {
            samples[i - 1]
        };
        let (from, code) = set_bits(layers[i]).find_map(|from| {
            (0..16u8).find_map(|code| {
                let mut s = ImaAdpcmState {
                    predictor: before,
                    step_index: from,
                };
                (s.decode_code(code) == samples[i] && s.step_index == want).then_some((from, code))
            })
        })?;
        order.put(&mut out, i, code);
        want = from;
    }
    Some((out, end))
}

fn set_bits(mask: u128) -> impl Iterator<Item = u8> {
    (0..=IMA_MAX_STEP_INDEX).filter(move |&i| mask & (1u128 << i) != 0)
}

/// Encode samples to packed codes: exactly (see
/// [`encode_ima_adpcm_codes_exact`]) when the samples are reachable from
/// `state`, otherwise by nearest code (see [`encode_ima_adpcm_codes_nearest`]).
pub fn encode_ima_adpcm_codes(
    state: ImaAdpcmState,
    samples: &[i16],
    order: ImaNibbleOrder,
) -> (Vec<u8>, ImaAdpcmState) {
    encode_ima_adpcm_codes_exact(state, samples, order)
        .unwrap_or_else(|| encode_ima_adpcm_codes_nearest(state, samples, order))
}

/// Encode a block: an [`ImaAdpcmHeader`] for `state` (with `reserved` as its
/// fourth byte) followed by [`encode_ima_adpcm_codes`] of `samples`.
///
/// `samples` are the samples that come from codes. For a
/// [`ImaHeaderSample::FirstOutput`] block, pass the first PCM sample as
/// `state.predictor` and the remaining samples here.
pub fn encode_ima_adpcm_block(
    state: ImaAdpcmState,
    samples: &[i16],
    order: ImaNibbleOrder,
    reserved: u8,
) -> Vec<u8> {
    let state = ImaAdpcmState {
        predictor: state.predictor,
        step_index: state.step_index.min(IMA_MAX_STEP_INDEX),
    };
    let header = ImaAdpcmHeader { state, reserved };
    let (codes, _) = encode_ima_adpcm_codes(state, samples, order);
    let mut out = Vec::with_capacity(ImaAdpcmHeader::LEN + codes.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&codes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(predictor: i16, step_index: u8) -> ImaAdpcmState {
        ImaAdpcmState::new(predictor, step_index).unwrap()
    }

    #[test]
    fn reference_arithmetic_and_clamping() {
        let mut s = st(0, 0);
        // step 7, code 7: 0 + 1 + 3 + 7 = 11; index 0 + 8.
        assert_eq!(s.decode_code(7), 11);
        assert_eq!(s.step_index, 8);
        // step 16, code 8: -(16 >> 3) = -2; index 8 - 1.
        assert_eq!(s.decode_code(8), 9);
        assert_eq!(s.step_index, 7);

        let mut hi = st(32_000, 88);
        assert_eq!(hi.decode_code(7), i16::MAX);
        assert_eq!(hi.step_index, 88);
        let mut lo = st(-32_000, 88);
        assert_eq!(lo.decode_code(15), i16::MIN);
        let mut floor = st(0, 0);
        floor.decode_code(0);
        assert_eq!(floor.step_index, 0);
        assert!(ImaAdpcmState::new(0, 89).is_err());
    }

    #[test]
    fn header_round_trips_and_validates() {
        let h = ImaAdpcmHeader::parse(&[0x34, 0x12, 88, 0xAA]).unwrap();
        assert_eq!(h.state, st(0x1234, 88));
        assert_eq!(h.reserved, 0xAA);
        assert_eq!(h.to_bytes(), [0x34, 0x12, 88, 0xAA]);
        assert!(matches!(
            ImaAdpcmHeader::parse(&[0, 0, 89, 0]),
            Err(Error::InvalidField { value: 89, .. })
        ));
        assert!(matches!(
            ImaAdpcmHeader::parse(&[0, 0, 0]),
            Err(Error::Truncated {
                needed: 4,
                available: 3,
                ..
            })
        ));
    }

    #[test]
    fn nibble_orders_and_header_sample_policies() {
        // Codes 7 then 0 in one byte.
        let low = decode_ima_adpcm_codes(st(0, 0), &[0x07], 2, ImaNibbleOrder::LowFirst).unwrap();
        let high = decode_ima_adpcm_codes(st(0, 0), &[0x70], 2, ImaNibbleOrder::HighFirst).unwrap();
        assert_eq!(low, high);
        assert_eq!(low.0, [11, 13]);

        let block = [0x10, 0x00, 0, 0, 0x07];
        assert_eq!(
            decode_ima_adpcm_block(
                &block,
                2,
                ImaNibbleOrder::LowFirst,
                ImaHeaderSample::StateOnly
            )
            .unwrap(),
            [27, 29]
        );
        assert_eq!(
            decode_ima_adpcm_block(
                &block,
                3,
                ImaNibbleOrder::LowFirst,
                ImaHeaderSample::FirstOutput
            )
            .unwrap(),
            [16, 27, 29]
        );
        assert!(matches!(
            decode_ima_adpcm_block(
                &block,
                3,
                ImaNibbleOrder::LowFirst,
                ImaHeaderSample::StateOnly
            ),
            Err(Error::Truncated {
                offset: 4,
                needed: 2,
                available: 1
            })
        ));
    }

    #[test]
    fn exact_reencode_reproduces_decoded_pcm_in_both_orders() {
        let codes: Vec<u8> = (0..300u32).map(|i| (i * 37 + 11) as u8).collect();
        for order in [ImaNibbleOrder::LowFirst, ImaNibbleOrder::HighFirst] {
            for start in [st(-1234, 20), st(0, 0), st(30_000, 88)] {
                let (pcm, end) = decode_ima_adpcm_codes(start, &codes, 599, order).unwrap();
                let (again, end2) = encode_ima_adpcm_codes_exact(start, &pcm, order).unwrap();
                let (redecoded, end3) = decode_ima_adpcm_codes(start, &again, 599, order).unwrap();
                assert_eq!(redecoded, pcm);
                assert_eq!(end2, end3);
                assert_eq!(end2.predictor, end.predictor);
                assert_eq!(encode_ima_adpcm_codes(start, &pcm, order).0, again);
                // Unused final nibble stays zero.
                let last = *again.last().unwrap();
                match order {
                    ImaNibbleOrder::LowFirst => assert_eq!(last >> 4, 0),
                    ImaNibbleOrder::HighFirst => assert_eq!(last & 0x0f, 0),
                }
            }
        }
    }

    #[test]
    fn exact_returns_none_for_unreachable_and_nearest_tracks_a_sine() {
        // From step index 0 the first sample can move at most 11 away.
        assert!(
            encode_ima_adpcm_codes_exact(st(0, 0), &[1000], ImaNibbleOrder::LowFirst).is_none()
        );
        let pcm: Vec<i16> = (0..2000)
            .map(|i| ((i as f64 * 0.05).sin() * 12_000.0) as i16)
            .collect();
        let state = st(pcm[0], 0);
        let block = encode_ima_adpcm_block(state, &pcm[1..], ImaNibbleOrder::LowFirst, 0);
        assert_eq!(block.len(), 4 + (pcm.len() - 1).div_ceil(2));
        let decoded = decode_ima_adpcm_block(
            &block,
            pcm.len(),
            ImaNibbleOrder::LowFirst,
            ImaHeaderSample::FirstOutput,
        )
        .unwrap();
        let max_err = decoded
            .iter()
            .zip(&pcm)
            .skip(100)
            .map(|(a, b)| (i32::from(*a) - i32::from(*b)).abs())
            .max()
            .unwrap();
        assert!(max_err < 2000, "max error {max_err}");
        assert_eq!(decoded[0], pcm[0]);
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(
            decode_ima_adpcm_codes(st(5, 3), &[], 0, ImaNibbleOrder::LowFirst).unwrap(),
            (Vec::new(), st(5, 3))
        );
        assert_eq!(
            encode_ima_adpcm_codes_exact(st(5, 3), &[], ImaNibbleOrder::LowFirst),
            Some((Vec::new(), st(5, 3)))
        );
        assert_eq!(
            decode_ima_adpcm_block(
                &[0, 0, 0, 0],
                0,
                ImaNibbleOrder::LowFirst,
                ImaHeaderSample::FirstOutput
            )
            .unwrap(),
            Vec::<i16>::new()
        );
    }
}
