/// Interleaved, 16-bit signed PCM audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcm {
    sample_rate: u32,
    /// Number of interleaved channels. `1` is mono, `2` is stereo.
    channels: u16,
    samples: Vec<i16>,
}

impl Pcm {
    /// Construct mono PCM.
    pub fn new(sample_rate: u32, samples: Vec<i16>) -> Self {
        Pcm {
            sample_rate,
            channels: 1,
            samples,
        }
    }

    /// Construct interleaved PCM, validating its channel/frame shape.
    pub fn try_interleaved(
        sample_rate: u32,
        channels: u16,
        samples: Vec<i16>,
    ) -> crate::Result<Self> {
        if channels == 0 {
            return Err(crate::Error::InvalidField {
                what: "PCM channel count",
                value: 0,
            });
        }
        if !samples.len().is_multiple_of(channels as usize) {
            return Err(crate::Error::InvalidField {
                what: "PCM interleaved sample count",
                value: samples.len() as u64,
            });
        }
        Ok(Self {
            sample_rate,
            channels,
            samples,
        })
    }

    /// Samples per second for each channel.
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Number of interleaved channels.
    pub const fn channels(&self) -> u16 {
        self.channels
    }

    /// Interleaved signed 16-bit samples.
    pub fn samples(&self) -> &[i16] {
        &self.samples
    }

    /// Consume the PCM value and return its interleaved sample storage.
    pub fn into_samples(self) -> Vec<i16> {
        self.samples
    }

    /// Number of sample frames (one sample per channel per frame).
    pub fn frame_count(&self) -> usize {
        self.samples.len() / self.channels.max(1) as usize
    }

    /// Validate the channel count and interleaved sample shape.
    pub fn validate(&self) -> crate::Result<()> {
        if self.channels == 0 {
            return Err(crate::Error::InvalidField {
                what: "PCM channel count",
                value: 0,
            });
        }
        if !self.samples.len().is_multiple_of(self.channels as usize) {
            return Err(crate::Error::InvalidField {
                what: "PCM interleaved sample count",
                value: self.samples.len() as u64,
            });
        }
        Ok(())
    }

    /// Build the canonical 44-byte RIFF/WAVE header for signed 16-bit PCM.
    ///
    /// Validates the channel/sample shape and verifies that the payload size
    /// and derived RIFF fields fit within their 32-bit / 16-bit header fields.
    pub fn wav_header(&self) -> crate::Result<[u8; 44]> {
        const RIFF_OVERHEAD: u32 = 36;
        const MAX_DATA_BYTES: u64 = (u32::MAX - RIFF_OVERHEAD) as u64;

        self.validate()?;

        let block_align = self
            .channels
            .checked_mul(2)
            .ok_or(crate::Error::InvalidField {
                what: "WAV block align",
                value: u64::from(self.channels) * 2,
            })?;
        let byte_rate = self.sample_rate.checked_mul(u32::from(block_align)).ok_or(
            crate::Error::InvalidField {
                what: "WAV byte rate",
                value: u64::from(self.sample_rate) * u64::from(block_align),
            },
        )?;

        let sample_count = u64::try_from(self.samples.len())
            .map_err(|_| crate::Error::Malformed("WAV sample count exceeds u64".into()))?;
        let data_bytes = sample_count
            .checked_mul(2)
            .ok_or_else(|| crate::Error::Malformed("WAV data size overflow".into()))?;
        if data_bytes > MAX_DATA_BYTES {
            return Err(crate::Error::InvalidField {
                what: "WAV data size",
                value: data_bytes,
            });
        }

        let data_bytes_u32 = data_bytes as u32;
        let riff_chunk_size = RIFF_OVERHEAD + data_bytes_u32;

        let mut header = [0u8; 44];
        header[0..4].copy_from_slice(b"RIFF");
        header[4..8].copy_from_slice(&riff_chunk_size.to_le_bytes());
        header[8..12].copy_from_slice(b"WAVE");
        header[12..16].copy_from_slice(b"fmt ");
        header[16..20].copy_from_slice(&16u32.to_le_bytes());
        header[20..22].copy_from_slice(&1u16.to_le_bytes());
        header[22..24].copy_from_slice(&self.channels.to_le_bytes());
        header[24..28].copy_from_slice(&self.sample_rate.to_le_bytes());
        header[28..32].copy_from_slice(&byte_rate.to_le_bytes());
        header[32..34].copy_from_slice(&block_align.to_le_bytes());
        header[34..36].copy_from_slice(&16u16.to_le_bytes());
        header[36..40].copy_from_slice(b"data");
        header[40..44].copy_from_slice(&data_bytes_u32.to_le_bytes());
        Ok(header)
    }

    /// Serialize this PCM stream into a complete RIFF/WAVE byte buffer.
    pub fn to_wav_bytes(&self) -> crate::Result<Vec<u8>> {
        let header = self.wav_header()?;
        let data_bytes = self
            .samples
            .len()
            .checked_mul(2)
            .ok_or_else(|| crate::Error::Malformed("WAV data size overflow".into()))?;
        let total_bytes = header
            .len()
            .checked_add(data_bytes)
            .ok_or_else(|| crate::Error::Malformed("WAV output size overflow".into()))?;

        let mut out = Vec::with_capacity(total_bytes);
        out.extend_from_slice(&header);
        for &sample in &self.samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        Ok(out)
    }

    /// Write this PCM stream as a canonical RIFF/WAVE file to `out`.
    ///
    /// When `work` is provided, cooperative cancellation is checked before
    /// writing and between sample chunks, and written bytes are checked and
    /// charged against [`crate::WorkResource::OutputBytes`].
    pub fn write_wav(
        &self,
        out: &mut impl std::io::Write,
        mut work: Option<&mut crate::WorkBudget>,
    ) -> crate::Result<()> {
        let header = self.wav_header()?;
        let total_bytes = header.len() as u64 + (self.samples.len() as u64) * 2;

        if let Some(budget) = work.as_deref_mut() {
            budget.check_cancelled()?;
            budget.check(crate::WorkResource::OutputBytes, total_bytes)?;
        }

        out.write_all(&header)
            .map_err(|error| crate::Error::Malformed(format!("write WAV header: {error}")))?;
        if let Some(budget) = work.as_deref_mut() {
            budget.charge(crate::WorkResource::OutputBytes, header.len() as u64)?;
        }

        const CHUNK_SAMPLES: usize = 4096;
        let mut buf = [0u8; CHUNK_SAMPLES * 2];
        for chunk in self.samples.chunks(CHUNK_SAMPLES) {
            if let Some(budget) = work.as_deref_mut() {
                budget.check_cancelled()?;
            }
            let byte_len = chunk.len() * 2;
            for (dst, &sample) in buf[..byte_len].chunks_exact_mut(2).zip(chunk) {
                dst.copy_from_slice(&sample.to_le_bytes());
            }
            out.write_all(&buf[..byte_len])
                .map_err(|error| crate::Error::Malformed(format!("write WAV samples: {error}")))?;
            if let Some(budget) = work.as_deref_mut() {
                budget.charge(crate::WorkResource::OutputBytes, byte_len as u64)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, Error, WorkBudget, WorkLimits, WorkResource};

    #[test]
    fn new_holds_sample_rate_and_samples() {
        let pcm = Pcm::new(44_100, vec![1, -1, 2, -2]);
        assert_eq!(pcm.sample_rate(), 44_100);
        assert_eq!(pcm.channels(), 1);
        assert_eq!(pcm.samples(), [1, -1, 2, -2]);
    }

    #[test]
    fn interleaved_shape_is_validated() {
        let stereo = Pcm::try_interleaved(44_100, 2, vec![1, -1, 2, -2]).unwrap();
        assert_eq!(stereo.channels(), 2);
        assert_eq!(stereo.frame_count(), 2);
        assert!(Pcm::try_interleaved(44_100, 0, vec![]).is_err());
        assert!(Pcm::try_interleaved(44_100, 2, vec![1]).is_err());
        assert!(stereo.validate().is_ok());
    }

    #[test]
    fn wav_header_and_bytes_match_canonical_pcm16_layout() {
        let pcm = Pcm::try_interleaved(44_100, 2, vec![0x0102, -1, i16::MIN, i16::MAX]).unwrap();
        let header = pcm.wav_header().unwrap();
        assert_eq!(&header[0..4], b"RIFF");
        assert_eq!(u32::from_le_bytes(header[4..8].try_into().unwrap()), 36 + 8);
        assert_eq!(&header[8..12], b"WAVE");
        assert_eq!(&header[12..16], b"fmt ");
        assert_eq!(u32::from_le_bytes(header[16..20].try_into().unwrap()), 16);
        assert_eq!(u16::from_le_bytes(header[20..22].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(header[22..24].try_into().unwrap()), 2);
        assert_eq!(
            u32::from_le_bytes(header[24..28].try_into().unwrap()),
            44_100
        );
        assert_eq!(
            u32::from_le_bytes(header[28..32].try_into().unwrap()),
            44_100 * 4
        );
        assert_eq!(u16::from_le_bytes(header[32..34].try_into().unwrap()), 4);
        assert_eq!(u16::from_le_bytes(header[34..36].try_into().unwrap()), 16);
        assert_eq!(&header[36..40], b"data");
        assert_eq!(u32::from_le_bytes(header[40..44].try_into().unwrap()), 8);

        let bytes = pcm.to_wav_bytes().unwrap();
        assert_eq!(bytes.len(), 52);
        assert_eq!(&bytes[..44], &header);
        assert_eq!(
            &bytes[44..],
            &[0x02, 0x01, 0xFF, 0xFF, 0x00, 0x80, 0xFF, 0x7F]
        );
    }

    #[test]
    fn write_wav_matches_to_wav_bytes_and_honors_budget_and_cancellation() {
        let samples: Vec<i16> = (0..5000).map(|i| (i % 1000) as i16 - 500).collect();
        let pcm = Pcm::new(22_050, samples);
        let expected = pcm.to_wav_bytes().unwrap();

        let mut out = Vec::new();
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        pcm.write_wav(&mut out, Some(&mut budget)).unwrap();
        assert_eq!(out, expected);
        assert_eq!(
            budget.spent(WorkResource::OutputBytes),
            expected.len() as u64
        );

        // Output budget limit prevents writing anything.
        let mut limited_out = Vec::new();
        let mut tight = WorkBudget::new(
            WorkLimits::unlimited().with(WorkResource::OutputBytes, expected.len() as u64 - 1),
        );
        let err = pcm
            .write_wav(&mut limited_out, Some(&mut tight))
            .unwrap_err();
        assert!(matches!(err, Error::ResourceLimit { .. }));
        assert!(limited_out.is_empty());

        // Pre-cancelled token aborts before writing.
        let token = CancellationToken::new();
        token.cancel();
        let mut cancelled_out = Vec::new();
        let mut cancelled_budget =
            WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        let err = pcm
            .write_wav(&mut cancelled_out, Some(&mut cancelled_budget))
            .unwrap_err();
        assert_eq!(err, Error::Cancelled);
        assert!(cancelled_out.is_empty());
    }

    #[test]
    fn wav_header_rejects_overflowing_rate_or_channels() {
        let overflow_align = Pcm::try_interleaved(44_100, 40_000, vec![]).unwrap();
        assert!(matches!(
            overflow_align.wav_header(),
            Err(Error::InvalidField {
                what: "WAV block align",
                ..
            })
        ));

        let overflow_rate = Pcm::try_interleaved(u32::MAX, 2, vec![]).unwrap();
        assert!(matches!(
            overflow_rate.wav_header(),
            Err(Error::InvalidField {
                what: "WAV byte rate",
                ..
            })
        ));
    }
}
