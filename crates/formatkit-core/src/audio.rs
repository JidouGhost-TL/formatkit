//! Shared PCM audio buffers, WAV header encoding and RIFF `smpl` loop chunks.
//!
//! The `smpl` (sampler) chunk layout follows the RIFF/WAVE sampler chunk
//! definition: a 36-byte header (manufacturer, product, sample period, MIDI
//! unity note and pitch fraction, SMPTE format and offset, loop count, sampler
//! data size) followed by 24-byte loop records (identifier, type, start, end,
//! fraction, play count), all little-endian `u32`.

/// Build the canonical 44-byte RIFF/WAVE header for linear PCM (8-bit unsigned
/// or 16-bit signed).
///
/// Validates that `sample_rate > 0`, `channels > 0`, `bits_per_sample` is `8`
/// or `16`, derived `block_align` and `byte_rate` do not overflow, `data_bytes`
/// is a whole number of sample frames (`data_bytes % block_align == 0`), and
/// `data_bytes <= u32::MAX as u64 - 36`.
pub fn wav_header_pcm(
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,
    data_bytes: u64,
) -> crate::Result<[u8; 44]> {
    const RIFF_OVERHEAD: u32 = 36;
    const MAX_DATA_BYTES: u64 = (u32::MAX - RIFF_OVERHEAD) as u64;

    if sample_rate == 0 {
        return Err(crate::Error::InvalidField {
            what: "WAV sample rate",
            value: 0,
        });
    }
    if channels == 0 {
        return Err(crate::Error::InvalidField {
            what: "WAV channel count",
            value: 0,
        });
    }
    if bits_per_sample != 8 && bits_per_sample != 16 {
        return Err(crate::Error::InvalidField {
            what: "WAV bits per sample",
            value: u64::from(bits_per_sample),
        });
    }

    let bytes_per_sample = bits_per_sample / 8;
    let block_align = channels
        .checked_mul(bytes_per_sample)
        .ok_or(crate::Error::InvalidField {
            what: "WAV block align",
            value: u64::from(channels) * u64::from(bytes_per_sample),
        })?;
    let byte_rate =
        sample_rate
            .checked_mul(u32::from(block_align))
            .ok_or(crate::Error::InvalidField {
                what: "WAV byte rate",
                value: u64::from(sample_rate) * u64::from(block_align),
            })?;
    if !data_bytes.is_multiple_of(u64::from(block_align)) || data_bytes > MAX_DATA_BYTES {
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
    header[22..24].copy_from_slice(&channels.to_le_bytes());
    header[24..28].copy_from_slice(&sample_rate.to_le_bytes());
    header[28..32].copy_from_slice(&byte_rate.to_le_bytes());
    header[32..34].copy_from_slice(&block_align.to_le_bytes());
    header[34..36].copy_from_slice(&bits_per_sample.to_le_bytes());
    header[36..40].copy_from_slice(b"data");
    header[40..44].copy_from_slice(&data_bytes_u32.to_le_bytes());
    Ok(header)
}

/// Playback direction of one [`WavLoop`] (`dwType` in a RIFF `smpl` loop record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WavLoopKind {
    /// Type `0`: play forward from start to end, then jump back to start.
    Forward,
    /// Type `1`: alternate forward and backward between start and end.
    Alternating,
    /// Type `2`: play backward.
    Backward,
}

impl WavLoopKind {
    /// The `dwType` value stored in the loop record.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Forward => 0,
            Self::Alternating => 1,
            Self::Backward => 2,
        }
    }

    /// Decode a `dwType` value; types above `2` are manufacturer-defined and
    /// return `None`.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Forward),
            1 => Some(Self::Alternating),
            2 => Some(Self::Backward),
            _ => None,
        }
    }
}

/// One sample loop for the RIFF/WAVE `smpl` (sampler) chunk.
///
/// Positions are sample-frame indices into the `data` chunk using a half-open
/// range: `start_frame` is the first looped frame and `end_frame` is one past
/// the last. The serialized `dwEnd` field holds the *inclusive* last frame,
/// `end_frame - 1`, as sampler software reads it.
#[doc(alias = "smpl")]
#[doc(alias = "loop point")]
#[doc(alias = "sustain loop")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavLoop {
    /// First looped sample frame (inclusive).
    pub start_frame: u32,
    /// One past the last looped sample frame (exclusive).
    pub end_frame: u32,
    /// Playback direction.
    pub kind: WavLoopKind,
    /// Number of repetitions; `0` loops indefinitely.
    pub play_count: u32,
}

impl WavLoop {
    /// An indefinitely repeating forward loop over `start_frame..end_frame`.
    #[must_use]
    pub const fn forward(start_frame: u32, end_frame: u32) -> Self {
        Self {
            start_frame,
            end_frame,
            kind: WavLoopKind::Forward,
            play_count: 0,
        }
    }
}

/// Fixed part of a `smpl` chunk payload before the loop records.
const SMPL_HEADER_LEN: usize = 36;
/// Size of one `smpl` loop record.
const SMPL_LOOP_LEN: usize = 24;
/// MIDI unity note written to `dwMIDIUnityNote` (middle C: play at the recorded pitch).
const SMPL_UNITY_NOTE: u32 = 60;

/// Serialize a complete RIFF `smpl` chunk (`"smpl"`, size, payload) with the
/// given loops.
///
/// Writes zero manufacturer/product/SMPTE fields, `dwSamplePeriod` =
/// `1_000_000_000 / sample_rate` nanoseconds, `dwMIDIUnityNote` = 60, no pitch
/// fraction and no sampler-specific data. Loop identifiers are their indices.
/// Each loop must satisfy `start_frame < end_frame`; the caller checks the
/// frames against its own `data` length (see [`wav_bytes_pcm_with_loops`]).
pub fn wav_smpl_chunk(sample_rate: u32, loops: &[WavLoop]) -> crate::Result<Vec<u8>> {
    if sample_rate == 0 {
        return Err(crate::Error::InvalidField {
            what: "WAV sample rate",
            value: 0,
        });
    }
    let count = u32::try_from(loops.len()).map_err(|_| crate::Error::InvalidField {
        what: "WAV smpl loop count",
        value: loops.len() as u64,
    })?;
    let payload_len = loops
        .len()
        .checked_mul(SMPL_LOOP_LEN)
        .and_then(|n| n.checked_add(SMPL_HEADER_LEN))
        .filter(|&n| n <= u32::MAX as usize)
        .ok_or(crate::Error::InvalidField {
            what: "WAV smpl loop count",
            value: loops.len() as u64,
        })?;
    let mut out = Vec::with_capacity(8 + payload_len);
    out.extend_from_slice(b"smpl");
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    let period_ns = 1_000_000_000 / sample_rate;
    for v in [0u32, 0, period_ns, SMPL_UNITY_NOTE, 0, 0, 0, count, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for (id, lp) in loops.iter().enumerate() {
        if lp.start_frame >= lp.end_frame {
            return Err(crate::Error::InvalidField {
                what: "WAV loop range",
                value: (u64::from(lp.start_frame) << 32) | u64::from(lp.end_frame),
            });
        }
        for v in [
            id as u32,
            lp.kind.to_raw(),
            lp.start_frame,
            lp.end_frame - 1,
            0,
            lp.play_count,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    Ok(out)
}

/// Parse the loop records of a `smpl` chunk *payload* (the bytes after the
/// chunk id and size), converting each inclusive `dwEnd` back to an exclusive
/// [`WavLoop::end_frame`].
///
/// Rejects payloads shorter than the 36-byte header or than the declared
/// `cSampleLoops` records, loops whose `dwEnd < dwStart` or `dwEnd ==
/// u32::MAX`, and manufacturer-defined loop types (`dwType > 2`). The trailing
/// `cbSamplerData` bytes are not interpreted.
pub fn parse_wav_smpl_loops(payload: &[u8]) -> crate::Result<Vec<WavLoop>> {
    let word = |at: usize| u32::from_le_bytes(payload[at..at + 4].try_into().unwrap());
    if payload.len() < SMPL_HEADER_LEN {
        return Err(crate::Error::Truncated {
            offset: 0,
            needed: SMPL_HEADER_LEN,
            available: payload.len(),
        });
    }
    let count = word(28) as usize;
    let needed = count
        .checked_mul(SMPL_LOOP_LEN)
        .and_then(|n| n.checked_add(SMPL_HEADER_LEN))
        .ok_or(crate::Error::InvalidField {
            what: "WAV smpl loop count",
            value: count as u64,
        })?;
    if payload.len() < needed {
        return Err(crate::Error::Truncated {
            offset: SMPL_HEADER_LEN,
            needed: needed - SMPL_HEADER_LEN,
            available: payload.len() - SMPL_HEADER_LEN,
        });
    }
    let mut loops = Vec::with_capacity(count);
    for i in 0..count {
        let at = SMPL_HEADER_LEN + i * SMPL_LOOP_LEN;
        let raw_kind = word(at + 4);
        let kind = WavLoopKind::from_raw(raw_kind).ok_or(crate::Error::InvalidField {
            what: "WAV loop type",
            value: u64::from(raw_kind),
        })?;
        let start = word(at + 8);
        let last = word(at + 12);
        if last < start || last == u32::MAX {
            return Err(crate::Error::InvalidField {
                what: "WAV loop range",
                value: (u64::from(start) << 32) | u64::from(last),
            });
        }
        loops.push(WavLoop {
            start_frame: start,
            end_frame: last + 1,
            kind,
            play_count: word(at + 20),
        });
    }
    Ok(loops)
}

/// Serialize a complete linear-PCM RIFF/WAVE file: the canonical 44-byte
/// header from [`wav_header_pcm`], the `data` payload (plus one RIFF pad byte
/// when its length is odd), and, when `loops` is non-empty, a trailing `smpl`
/// chunk from [`wav_smpl_chunk`].
///
/// `data` is already-encoded sample bytes (8-bit unsigned or 16-bit signed
/// little-endian). Every loop's `end_frame` must not exceed the frame count
/// `data.len() / block_align`. With no loops the output equals the header
/// followed by `data` (and the pad byte, if any).
///
/// ```
/// use formatkit_core::audio::{parse_wav_smpl_loops, wav_bytes_pcm_with_loops, WavLoop};
///
/// let data = [0u8, 0, 1, 0, 2, 0, 3, 0]; // four 16-bit mono frames
/// let wav = wav_bytes_pcm_with_loops(22_050, 1, 16, &data, &[WavLoop::forward(1, 4)]).unwrap();
/// assert_eq!(&wav[52..56], b"smpl");
/// let loops = parse_wav_smpl_loops(&wav[60..]).unwrap();
/// assert_eq!(loops, [WavLoop::forward(1, 4)]);
/// ```
pub fn wav_bytes_pcm_with_loops(
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,
    data: &[u8],
    loops: &[WavLoop],
) -> crate::Result<Vec<u8>> {
    let header = wav_header_pcm(sample_rate, channels, bits_per_sample, data.len() as u64)?;
    let block_align = usize::from(channels) * usize::from(bits_per_sample / 8);
    let frames = (data.len() / block_align) as u64;
    for lp in loops {
        if u64::from(lp.end_frame) > frames {
            return Err(crate::Error::InvalidField {
                what: "WAV loop end frame",
                value: u64::from(lp.end_frame),
            });
        }
    }
    let smpl = if loops.is_empty() {
        Vec::new()
    } else {
        wav_smpl_chunk(sample_rate, loops)?
    };
    let pad = data.len() & 1;
    let total = header.len() as u64 + data.len() as u64 + pad as u64 + smpl.len() as u64;
    if total - 8 > u64::from(u32::MAX) {
        return Err(crate::Error::InvalidField {
            what: "WAV RIFF size",
            value: total - 8,
        });
    }
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    if pad == 1 {
        out.push(0);
    }
    out.extend_from_slice(&smpl);
    out[4..8].copy_from_slice(&((total - 8) as u32).to_le_bytes());
    Ok(out)
}

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
        self.validate()?;

        let sample_count = u64::try_from(self.samples.len())
            .map_err(|_| crate::Error::Malformed("WAV sample count exceeds u64".into()))?;
        let data_bytes = sample_count
            .checked_mul(2)
            .ok_or_else(|| crate::Error::Malformed("WAV data size overflow".into()))?;

        wav_header_pcm(self.sample_rate(), self.channels(), 16, data_bytes)
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

    /// Serialize this PCM stream into a RIFF/WAVE byte buffer with a trailing
    /// `smpl` chunk holding one loop.
    ///
    /// Loop positions are sample frames (see [`WavLoop`]). The bytes before
    /// the `smpl` chunk equal [`Self::to_wav_bytes`] except for the RIFF size
    /// field. Use [`wav_bytes_pcm_with_loops`] for several loops or 8-bit data.
    pub fn to_wav_bytes_with_loop(&self, lp: WavLoop) -> crate::Result<Vec<u8>> {
        let header = self.wav_header()?;
        if u64::from(lp.end_frame) > self.frame_count() as u64 {
            return Err(crate::Error::InvalidField {
                what: "WAV loop end frame",
                value: u64::from(lp.end_frame),
            });
        }
        let smpl = wav_smpl_chunk(self.sample_rate, &[lp])?;
        let data_bytes = self
            .samples
            .len()
            .checked_mul(2)
            .ok_or_else(|| crate::Error::Malformed("WAV data size overflow".into()))?;
        let total = (header.len() as u64)
            .checked_add(data_bytes as u64)
            .and_then(|n| n.checked_add(smpl.len() as u64))
            .ok_or_else(|| crate::Error::Malformed("WAV output size overflow".into()))?;
        if total - 8 > u64::from(u32::MAX) {
            return Err(crate::Error::InvalidField {
                what: "WAV RIFF size",
                value: total - 8,
            });
        }
        let total_usize = usize::try_from(total)
            .map_err(|_| crate::Error::Malformed("WAV output size overflow".into()))?;
        let mut out = Vec::with_capacity(total_usize);
        out.extend_from_slice(&header);
        for &sample in &self.samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        out.extend_from_slice(&smpl);
        out[4..8].copy_from_slice(&((total - 8) as u32).to_le_bytes());
        Ok(out)
    }

    /// Parse a canonical 16-bit signed little-endian PCM RIFF/WAVE byte buffer.
    ///
    /// Walks RIFF chunks cleanly, skipping non-`fmt `/`data` chunks (and
    /// honoring odd-length chunk pad bytes), while validating `"RIFF"` /
    /// `"WAVE"` framing, PCM format (`1`), non-zero channels and sample rate,
    /// `bits_per_sample == 16`, `block_align == channels * 2`, and exact frame
    /// alignment of the `data` payload.
    pub fn from_wav_bytes(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() < 12 {
            return Err(crate::Error::Truncated {
                offset: 0,
                needed: 12,
                available: bytes.len(),
            });
        }
        if &bytes[0..4] != b"RIFF" {
            return Err(crate::Error::BadMagic {
                offset: 0,
                expected: u32::from_be_bytes(*b"RIFF"),
                found: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            });
        }
        let riff_size = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if riff_size < 4 {
            return Err(crate::Error::InvalidField {
                what: "WAV RIFF size",
                value: u64::from(riff_size),
            });
        }
        let riff_end =
            8usize
                .checked_add(riff_size as usize)
                .ok_or(crate::Error::InvalidField {
                    what: "WAV RIFF size",
                    value: u64::from(riff_size),
                })?;
        if riff_end > bytes.len() {
            return Err(crate::Error::Truncated {
                offset: 8,
                needed: riff_size as usize,
                available: bytes.len() - 8,
            });
        }
        if &bytes[8..12] != b"WAVE" {
            return Err(crate::Error::BadMagic {
                offset: 8,
                expected: u32::from_be_bytes(*b"WAVE"),
                found: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            });
        }

        let mut fmt: Option<(u16, u32, u16)> = None;
        let mut data: Option<&[u8]> = None;
        let mut pos = 12usize;

        while pos < riff_end {
            if riff_end - pos < 8 {
                return Err(crate::Error::Truncated {
                    offset: pos,
                    needed: 8,
                    available: riff_end - pos,
                });
            }
            let chunk_id = &bytes[pos..pos + 4];
            let chunk_len =
                u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let payload_start = pos + 8;
            let payload_end =
                payload_start
                    .checked_add(chunk_len)
                    .ok_or(crate::Error::InvalidField {
                        what: "WAV chunk length",
                        value: chunk_len as u64,
                    })?;
            if payload_end > riff_end {
                return Err(crate::Error::Truncated {
                    offset: payload_start,
                    needed: chunk_len,
                    available: riff_end - payload_start,
                });
            }
            let payload = &bytes[payload_start..payload_end];

            if chunk_id == b"fmt " {
                if payload.len() < 16 {
                    return Err(crate::Error::InvalidField {
                        what: "WAV fmt chunk length",
                        value: payload.len() as u64,
                    });
                }
                let audio_format = u16::from_le_bytes([payload[0], payload[1]]);
                if audio_format != 1 {
                    return Err(crate::Error::Unsupported(format!(
                        "WAV audio format {audio_format} (only PCM format 1 is supported)"
                    )));
                }
                let channels = u16::from_le_bytes([payload[2], payload[3]]);
                if channels == 0 {
                    return Err(crate::Error::InvalidField {
                        what: "WAV channel count",
                        value: 0,
                    });
                }
                let sample_rate =
                    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                if sample_rate == 0 {
                    return Err(crate::Error::InvalidField {
                        what: "WAV sample rate",
                        value: 0,
                    });
                }
                let block_align = u16::from_le_bytes([payload[12], payload[13]]);
                let bits_per_sample = u16::from_le_bytes([payload[14], payload[15]]);
                if bits_per_sample != 16 {
                    return Err(crate::Error::Unsupported(format!(
                        "WAV bits_per_sample {bits_per_sample} (only 16-bit PCM is supported)"
                    )));
                }
                let expected_block_align =
                    channels.checked_mul(2).ok_or(crate::Error::InvalidField {
                        what: "WAV block align",
                        value: u64::from(channels) * 2,
                    })?;
                if block_align != expected_block_align {
                    return Err(crate::Error::InvalidField {
                        what: "WAV block align",
                        value: u64::from(block_align),
                    });
                }
                fmt = Some((channels, sample_rate, block_align));
            } else if chunk_id == b"data" {
                data = Some(payload);
            }

            pos = if (chunk_len & 1) == 1 && payload_end < riff_end {
                payload_end + 1
            } else {
                payload_end
            };
        }

        let (channels, sample_rate, block_align) =
            fmt.ok_or_else(|| crate::Error::Malformed("WAV missing fmt chunk".into()))?;
        let data = data.ok_or_else(|| crate::Error::Malformed("WAV missing data chunk".into()))?;

        if !data.len().is_multiple_of(usize::from(block_align)) {
            return Err(crate::Error::InvalidField {
                what: "WAV data size",
                value: data.len() as u64,
            });
        }

        let mut samples = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks_exact(2) {
            samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Self::try_interleaved(sample_rate, channels, samples)
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

    #[test]
    fn from_wav_bytes_round_trips_and_skips_extra_chunks() {
        let original =
            Pcm::try_interleaved(48_000, 2, vec![-32768, -1, 0, 1, 12345, 32767]).unwrap();
        let canonical = original.to_wav_bytes().unwrap();
        assert_eq!(Pcm::from_wav_bytes(&canonical).unwrap(), original);

        // Insert an odd-length JUNK chunk before fmt and a trailing LIST chunk after data.
        let mut body = Vec::new();
        body.extend_from_slice(b"WAVE");
        body.extend_from_slice(b"JUNK");
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"abc");
        body.push(0); // odd-chunk pad
        body.extend_from_slice(&canonical[12..]);
        body.extend_from_slice(b"LIST");
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(b"INFO");

        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(b"RIFF");
        wrapped.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wrapped.extend_from_slice(&body);
        assert_eq!(Pcm::from_wav_bytes(&wrapped).unwrap(), original);
    }

    #[test]
    fn from_wav_bytes_rejects_malformed_or_unsupported_headers() {
        let valid = Pcm::new(44_100, vec![1, 2, 3, 4]).to_wav_bytes().unwrap();

        // Bad RIFF magic.
        let mut bad_riff = valid.clone();
        bad_riff[0] = b'X';
        assert!(matches!(
            Pcm::from_wav_bytes(&bad_riff),
            Err(Error::BadMagic { offset: 0, .. })
        ));

        // Bad WAVE magic.
        let mut bad_wave = valid.clone();
        bad_wave[8] = b'X';
        assert!(matches!(
            Pcm::from_wav_bytes(&bad_wave),
            Err(Error::BadMagic { offset: 8, .. })
        ));

        // Non-PCM audio format (3 = IEEE float).
        let mut float_fmt = valid.clone();
        float_fmt[20..22].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            Pcm::from_wav_bytes(&float_fmt),
            Err(Error::Unsupported(_))
        ));

        // Zero channels.
        let mut zero_ch = valid.clone();
        zero_ch[22..24].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            Pcm::from_wav_bytes(&zero_ch),
            Err(Error::InvalidField {
                what: "WAV channel count",
                ..
            })
        ));

        // Zero sample rate.
        let mut zero_rate = valid.clone();
        zero_rate[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Pcm::from_wav_bytes(&zero_rate),
            Err(Error::InvalidField {
                what: "WAV sample rate",
                ..
            })
        ));

        // Wrong bits_per_sample (8).
        let mut bps8 = valid.clone();
        bps8[34..36].copy_from_slice(&8u16.to_le_bytes());
        assert!(matches!(
            Pcm::from_wav_bytes(&bps8),
            Err(Error::Unsupported(_))
        ));

        // Wrong block_align (4 for mono 16-bit).
        let mut bad_align = valid.clone();
        bad_align[32..34].copy_from_slice(&4u16.to_le_bytes());
        assert!(matches!(
            Pcm::from_wav_bytes(&bad_align),
            Err(Error::InvalidField {
                what: "WAV block align",
                ..
            })
        ));

        // Truncated data chunk.
        assert!(matches!(
            Pcm::from_wav_bytes(&valid[..valid.len() - 1]),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn smpl_chunk_layout_matches_riff_sampler_record() {
        let pcm = Pcm::try_interleaved(32_000, 2, vec![1, -1, 2, -2, 3, -3, 4, -4]).unwrap();
        let plain = pcm.to_wav_bytes().unwrap();
        let wav = pcm.to_wav_bytes_with_loop(WavLoop::forward(1, 4)).unwrap();
        assert_eq!(wav.len(), plain.len() + 8 + 36 + 24);
        assert_eq!(&wav[8..44], &plain[8..44]);
        assert_eq!(&wav[44..plain.len()], &plain[44..]);
        assert_eq!(
            u32::from_le_bytes(wav[4..8].try_into().unwrap()) as usize,
            wav.len() - 8
        );
        let smpl = &wav[plain.len()..];
        assert_eq!(&smpl[0..4], b"smpl");
        assert_eq!(u32::from_le_bytes(smpl[4..8].try_into().unwrap()), 60);
        let w = |at: usize| u32::from_le_bytes(smpl[8 + at..12 + at].try_into().unwrap());
        assert_eq!(w(8), 1_000_000_000 / 32_000); // dwSamplePeriod
        assert_eq!(w(12), 60); // dwMIDIUnityNote
        assert_eq!(w(28), 1); // cSampleLoops
        assert_eq!(w(32), 0); // cbSamplerData
        assert_eq!(
            [w(36), w(40), w(44), w(48), w(52), w(56)],
            [0, 0, 1, 3, 0, 0]
        );
        assert_eq!(
            parse_wav_smpl_loops(&smpl[8..]).unwrap(),
            [WavLoop::forward(1, 4)]
        );
        // The PCM reader still accepts the file and ignores the extra chunk.
        assert_eq!(Pcm::from_wav_bytes(&wav).unwrap(), pcm);
    }

    #[test]
    fn eight_bit_odd_data_is_padded_before_smpl() {
        let loops = [
            WavLoop::forward(0, 3),
            WavLoop {
                start_frame: 1,
                end_frame: 2,
                kind: WavLoopKind::Alternating,
                play_count: 5,
            },
        ];
        let wav = wav_bytes_pcm_with_loops(8_000, 1, 8, &[0x80, 0x81, 0x82], &loops).unwrap();
        assert_eq!(u32::from_le_bytes(wav[40..44].try_into().unwrap()), 3);
        assert_eq!(wav[47], 0); // pad byte
        assert_eq!(&wav[48..52], b"smpl");
        assert_eq!(wav.len(), 48 + 8 + 36 + 48);
        assert_eq!(parse_wav_smpl_loops(&wav[56..]).unwrap(), loops);
        // No loops: header, data and pad only.
        let bare = wav_bytes_pcm_with_loops(8_000, 1, 8, &[0x80, 0x81, 0x82], &[]).unwrap();
        assert_eq!(bare.len(), 48);
        assert_eq!(u32::from_le_bytes(bare[4..8].try_into().unwrap()), 40);
    }

    #[test]
    fn loop_validation_rejects_bad_ranges_and_records() {
        let pcm = Pcm::new(44_100, vec![0; 4]);
        assert!(matches!(
            pcm.to_wav_bytes_with_loop(WavLoop::forward(2, 2)),
            Err(Error::InvalidField {
                what: "WAV loop range",
                ..
            })
        ));
        assert!(matches!(
            pcm.to_wav_bytes_with_loop(WavLoop::forward(0, 5)),
            Err(Error::InvalidField {
                what: "WAV loop end frame",
                value: 5
            })
        ));
        let chunk = wav_smpl_chunk(44_100, &[WavLoop::forward(0, 4)]).unwrap();
        let payload = &chunk[8..];
        assert!(matches!(
            parse_wav_smpl_loops(&payload[..payload.len() - 1]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            parse_wav_smpl_loops(&payload[..35]),
            Err(Error::Truncated { .. })
        ));
        let mut bad_type = payload.to_vec();
        bad_type[36 + 4] = 7;
        assert!(matches!(
            parse_wav_smpl_loops(&bad_type),
            Err(Error::InvalidField {
                what: "WAV loop type",
                value: 7
            })
        ));
        let mut reversed = payload.to_vec();
        reversed[36 + 8..36 + 12].copy_from_slice(&9u32.to_le_bytes());
        assert!(parse_wav_smpl_loops(&reversed).is_err());
        assert!(wav_smpl_chunk(0, &[]).is_err());
    }

    #[test]
    fn wav_header_pcm_supports_8bit_and_16bit_and_validates_fields() {
        // 8-bit mono PCM header.
        let hdr8 = wav_header_pcm(11_025, 1, 8, 100).unwrap();
        assert_eq!(&hdr8[0..4], b"RIFF");
        assert_eq!(u32::from_le_bytes(hdr8[4..8].try_into().unwrap()), 136);
        assert_eq!(&hdr8[8..12], b"WAVE");
        assert_eq!(u16::from_le_bytes(hdr8[20..22].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(hdr8[22..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(hdr8[24..28].try_into().unwrap()), 11_025);
        assert_eq!(u32::from_le_bytes(hdr8[28..32].try_into().unwrap()), 11_025);
        assert_eq!(u16::from_le_bytes(hdr8[32..34].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(hdr8[34..36].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(hdr8[40..44].try_into().unwrap()), 100);

        // 16-bit stereo matches Pcm::wav_header.
        let pcm = Pcm::try_interleaved(48_000, 2, vec![0; 6]).unwrap();
        assert_eq!(
            wav_header_pcm(48_000, 2, 16, 12).unwrap(),
            pcm.wav_header().unwrap()
        );

        // Validation errors.
        assert!(matches!(
            wav_header_pcm(0, 1, 16, 0),
            Err(Error::InvalidField {
                what: "WAV sample rate",
                value: 0
            })
        ));
        assert!(matches!(
            wav_header_pcm(44_100, 0, 16, 0),
            Err(Error::InvalidField {
                what: "WAV channel count",
                value: 0
            })
        ));
        assert!(matches!(
            wav_header_pcm(44_100, 1, 24, 0),
            Err(Error::InvalidField {
                what: "WAV bits per sample",
                value: 24
            })
        ));
        assert!(matches!(
            wav_header_pcm(44_100, 40_000, 16, 0),
            Err(Error::InvalidField {
                what: "WAV block align",
                ..
            })
        ));
        assert!(matches!(
            wav_header_pcm(u32::MAX, 2, 16, 0),
            Err(Error::InvalidField {
                what: "WAV byte rate",
                ..
            })
        ));
        // Unaligned data_bytes (not a multiple of block_align=4).
        assert!(matches!(
            wav_header_pcm(44_100, 2, 16, 6),
            Err(Error::InvalidField {
                what: "WAV data size",
                value: 6
            })
        ));
        // Data size exceeding RIFF u32 payload limit.
        let too_large = u64::from(u32::MAX) - 35;
        assert!(matches!(
            wav_header_pcm(44_100, 1, 8, too_large),
            Err(Error::InvalidField {
                what: "WAV data size",
                ..
            })
        ));
        // Exact maximum data size succeeds when aligned.
        let max_aligned = u64::from(u32::MAX - 36);
        assert!(wav_header_pcm(44_100, 1, 8, max_aligned).is_ok());
    }
}
