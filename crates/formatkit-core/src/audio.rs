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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
