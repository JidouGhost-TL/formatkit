//! SoundFont 2.04 (`.sf2`) RIFF `sfbk` writer and structural validator.
//!
//! Writes and validates standard SoundFont 2.04 soundbanks (`RIFF`/`sfbk` with
//! `LIST INFO`, `LIST sdta`, and `LIST pdta` containing `phdr`, `pbag`, `pmod`,
//! `pgen`, `inst`, `ibag`, `imod`, `igen`, and `shdr` plus their required
//! terminal records and 46-sample zero padding after each sample).
//!
//! ```
//! use formatkit_codec::sf2::{
//!     validate_sf2, write_sf2, Sf2Font, Sf2Generator, Sf2Info, Sf2Instrument, Sf2Preset,
//!     Sf2Sample, Sf2SampleType, Sf2Zone,
//! };
//!
//! let font = Sf2Font {
//!     info: Sf2Info::new("Demo Bank"),
//!     samples: vec![Sf2Sample {
//!         name: "Sine".into(),
//!         pcm: vec![0, 1000, 0, -1000],
//!         sample_rate: 44_100,
//!         original_pitch: 60,
//!         pitch_correction: 0,
//!         loop_start: 0,
//!         loop_end: 4,
//!         sample_link: 0,
//!         sample_type: Sf2SampleType::Mono,
//!     }],
//!     instruments: vec![Sf2Instrument {
//!         name: "Lead".into(),
//!         zones: vec![Sf2Zone {
//!             generators: vec![Sf2Generator::sample_id(0)],
//!         }],
//!     }],
//!     presets: vec![Sf2Preset {
//!         name: "Lead".into(),
//!         preset: 0,
//!         bank: 0,
//!         zones: vec![Sf2Zone {
//!             generators: vec![Sf2Generator::instrument(0)],
//!         }],
//!     }],
//! };
//!
//! let bytes = write_sf2(&font).unwrap();
//! let summary = validate_sf2(&bytes).unwrap();
//! assert_eq!(summary.bank_name, "Demo Bank");
//! assert_eq!(summary.preset_count, 1);
//! assert_eq!(summary.instrument_count, 1);
//! assert_eq!(summary.sample_count, 1);
//! ```

use crate::prelude::*;

use formatkit_core::{Error, Result};

/// SoundFont 2.04 specification major version.
pub const SF2_VERSION_MAJOR: u16 = 2;
/// SoundFont 2.04 specification minor version.
pub const SF2_VERSION_MINOR: u16 = 4;

/// Size of one `phdr` (preset header) record in bytes.
pub const PHDR_RECORD_SIZE: usize = 38;
/// Size of one `pbag` (preset zone) record in bytes.
pub const PBAG_RECORD_SIZE: usize = 4;
/// Size of one `pmod` (preset modulator) record in bytes.
pub const PMOD_RECORD_SIZE: usize = 10;
/// Size of one `pgen` (preset generator) record in bytes.
pub const PGEN_RECORD_SIZE: usize = 4;
/// Size of one `inst` (instrument header) record in bytes.
pub const INST_RECORD_SIZE: usize = 22;
/// Size of one `ibag` (instrument zone) record in bytes.
pub const IBAG_RECORD_SIZE: usize = 4;
/// Size of one `imod` (instrument modulator) record in bytes.
pub const IMOD_RECORD_SIZE: usize = 10;
/// Size of one `igen` (instrument generator) record in bytes.
pub const IGEN_RECORD_SIZE: usize = 4;
/// Size of one `shdr` (sample header) record in bytes.
pub const SHDR_RECORD_SIZE: usize = 46;

/// Number of zero `i16` samples appended after each sample in `smpl`, per the
/// SoundFont 2 specification.
pub const SAMPLE_TERMINAL_PADDING: usize = 46;

/// Generator operator ID: stereo pan (`-500..=500`, 0.1% units).
pub const GEN_PAN: u16 = 17;
/// Generator operator ID: volume envelope attack time (timecents).
pub const GEN_ATTACK_VOL_ENV: u16 = 34;
/// Generator operator ID: volume envelope hold time (timecents).
pub const GEN_HOLD_VOL_ENV: u16 = 35;
/// Generator operator ID: volume envelope decay time (timecents).
pub const GEN_DECAY_VOL_ENV: u16 = 36;
/// Generator operator ID: volume envelope sustain level (centibels).
pub const GEN_SUSTAIN_VOL_ENV: u16 = 37;
/// Generator operator ID: volume envelope release time (timecents).
pub const GEN_RELEASE_VOL_ENV: u16 = 38;
/// Generator operator ID: instrument index (last generator of a preset zone).
pub const GEN_INSTRUMENT: u16 = 41;
/// Generator operator ID: MIDI key range `[lo, hi]`.
pub const GEN_KEY_RANGE: u16 = 43;
/// Generator operator ID: MIDI velocity range `[lo, hi]`.
pub const GEN_VEL_RANGE: u16 = 44;
/// Generator operator ID: initial attenuation (centibels).
pub const GEN_INITIAL_ATTENUATION: u16 = 48;
/// Generator operator ID: coarse pitch tuning (semitones).
pub const GEN_COARSE_TUNE: u16 = 51;
/// Generator operator ID: fine pitch tuning (cents).
pub const GEN_FINE_TUNE: u16 = 52;
/// Generator operator ID: sample index (last generator of an instrument zone).
pub const GEN_SAMPLE_ID: u16 = 53;
/// Generator operator ID: sample loop mode (`0` = no loop, `1` = continuous,
/// `3` = loop until release).
pub const GEN_SAMPLE_MODES: u16 = 54;
/// Generator operator ID: scale tuning (cents per key, default `100`).
pub const GEN_SCALE_TUNING: u16 = 56;
/// Generator operator ID: overriding root MIDI key (`0..=127`).
pub const GEN_OVERRIDING_ROOT_KEY: u16 = 58;

/// Sample linkage/type bitfield (`SFSampleLink`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sf2SampleType {
    /// Mono sample (`1`).
    Mono,
    /// Right channel of a stereo pair (`2`).
    Right,
    /// Left channel of a stereo pair (`4`).
    Left,
    /// Linked sample (`8`).
    Linked,
    /// ROM mono sample (`0x8001`).
    RomMono,
    /// ROM right sample (`0x8002`).
    RomRight,
    /// ROM left sample (`0x8004`).
    RomLeft,
    /// ROM linked sample (`0x8008`).
    RomLinked,
}

impl Sf2SampleType {
    /// Raw 16-bit `sfSampleType` value.
    #[must_use]
    pub const fn to_raw(self) -> u16 {
        match self {
            Self::Mono => 1,
            Self::Right => 2,
            Self::Left => 4,
            Self::Linked => 8,
            Self::RomMono => 0x8001,
            Self::RomRight => 0x8002,
            Self::RomLeft => 0x8004,
            Self::RomLinked => 0x8008,
        }
    }

    /// Decode a raw 16-bit `sfSampleType` value.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Mono),
            2 => Some(Self::Right),
            4 => Some(Self::Left),
            8 => Some(Self::Linked),
            0x8001 => Some(Self::RomMono),
            0x8002 => Some(Self::RomRight),
            0x8004 => Some(Self::RomLeft),
            0x8008 => Some(Self::RomLinked),
            _ => None,
        }
    }
}

/// Metadata written to the `LIST INFO` chunk of a SoundFont 2 bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sf2Info {
    /// Bank name (`INAM`, mandatory).
    pub bank_name: String,
    /// Target sound engine (`isng`, mandatory; defaults to `"EMU8000"`).
    pub sound_engine: String,
    /// Sound designer / engineer (`IENG`, optional).
    pub engineer: Option<String>,
    /// Authoring software (`ISFT`, optional).
    pub software: Option<String>,
    /// Target product (`IPRD`, optional).
    pub product: Option<String>,
    /// Copyright notice (`ICOP`, optional).
    pub copyright: Option<String>,
    /// Free-form comments (`ICMT`, optional).
    pub comments: Option<String>,
}

impl Sf2Info {
    /// Construct minimal valid `INFO` metadata with the given bank name and
    /// `"EMU8000"` as the target sound engine.
    #[must_use]
    pub fn new(bank_name: impl Into<String>) -> Self {
        Self {
            bank_name: bank_name.into(),
            sound_engine: "EMU8000".to_string(),
            engineer: None,
            software: None,
            product: None,
            copyright: None,
            comments: None,
        }
    }
}

impl Default for Sf2Info {
    fn default() -> Self {
        Self::new("Untitled")
    }
}

/// One 16-bit signed PCM sample in a SoundFont 2 bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sf2Sample {
    /// Sample name (truncated to 19 bytes + NUL in `shdr`).
    pub name: String,
    /// 16-bit signed PCM samples (46 trailing zero samples are added
    /// automatically by [`write_sf2`]).
    pub pcm: Vec<i16>,
    /// Sample rate in Hz (must be non-zero).
    pub sample_rate: u32,
    /// MIDI key number of the recorded pitch (`0..=127`, or `255` for unpitched).
    pub original_pitch: u8,
    /// Pitch correction in cents (`-128..=127`).
    pub pitch_correction: i8,
    /// Loop start offset in sample points relative to the start of `pcm`.
    pub loop_start: u32,
    /// Loop end offset in sample points relative to the start of `pcm`
    /// (must satisfy `loop_start <= loop_end <= pcm.len()`).
    pub loop_end: u32,
    /// Linked sample index (for stereo/linked samples; `0` for mono).
    pub sample_link: u16,
    /// Sample channel/linkage type.
    pub sample_type: Sf2SampleType,
}

/// One SoundFont 2 generator (`sfGenOper` + 2-byte `genAmountType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sf2Generator {
    /// Generator operator ID (see `GEN_*` constants).
    pub oper: u16,
    /// Raw 2-byte generator amount (`wAmount`, `shAmount`, or `[byLo, byHi]`).
    pub amount: [u8; 2],
}

impl Sf2Generator {
    /// Generator carrying an unsigned 16-bit integer amount.
    #[must_use]
    pub const fn from_u16(oper: u16, value: u16) -> Self {
        Self {
            oper,
            amount: value.to_le_bytes(),
        }
    }

    /// Generator carrying a signed 16-bit integer amount.
    #[must_use]
    pub const fn from_i16(oper: u16, value: i16) -> Self {
        Self {
            oper,
            amount: value.to_le_bytes(),
        }
    }

    /// Generator carrying a byte range `[lo, hi]`.
    #[must_use]
    pub const fn from_range(oper: u16, lo: u8, hi: u8) -> Self {
        Self {
            oper,
            amount: [lo, hi],
        }
    }

    /// MIDI key range generator (`GEN_KEY_RANGE`).
    #[must_use]
    pub const fn key_range(lo: u8, hi: u8) -> Self {
        Self::from_range(GEN_KEY_RANGE, lo, hi)
    }

    /// MIDI velocity range generator (`GEN_VEL_RANGE`).
    #[must_use]
    pub const fn vel_range(lo: u8, hi: u8) -> Self {
        Self::from_range(GEN_VEL_RANGE, lo, hi)
    }

    /// Preset-zone instrument reference (`GEN_INSTRUMENT`).
    #[must_use]
    pub const fn instrument(index: u16) -> Self {
        Self::from_u16(GEN_INSTRUMENT, index)
    }

    /// Instrument-zone sample reference (`GEN_SAMPLE_ID`).
    #[must_use]
    pub const fn sample_id(index: u16) -> Self {
        Self::from_u16(GEN_SAMPLE_ID, index)
    }

    /// Instrument-zone sample loop mode (`GEN_SAMPLE_MODES`).
    #[must_use]
    pub const fn sample_modes(mode: u16) -> Self {
        Self::from_u16(GEN_SAMPLE_MODES, mode)
    }

    /// Instrument-zone overriding root key (`GEN_OVERRIDING_ROOT_KEY`).
    #[must_use]
    pub const fn overriding_root_key(key: u8) -> Self {
        Self::from_u16(GEN_OVERRIDING_ROOT_KEY, key as u16)
    }
}

/// One zone (bag) in an instrument or preset, containing its generator list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sf2Zone {
    /// Generators applied in this zone.
    pub generators: Vec<Sf2Generator>,
}

/// One instrument (`inst` record + its `ibag` zones).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sf2Instrument {
    /// Instrument name (truncated to 19 bytes + NUL in `inst`).
    pub name: String,
    /// Zones belonging to this instrument.
    pub zones: Vec<Sf2Zone>,
}

/// One preset (`phdr` record + its `pbag` zones).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sf2Preset {
    /// Preset name (truncated to 19 bytes + NUL in `phdr`).
    pub name: String,
    /// MIDI program number (`0..=127`).
    pub preset: u16,
    /// MIDI bank number (`0..=128`).
    pub bank: u16,
    /// Zones belonging to this preset.
    pub zones: Vec<Sf2Zone>,
}

/// Complete SoundFont 2 bank description for serialization via [`write_sf2`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sf2Font {
    /// Bank metadata written into `LIST INFO`.
    pub info: Sf2Info,
    /// PCM samples written into `sdta`/`smpl` and `pdta`/`shdr`.
    pub samples: Vec<Sf2Sample>,
    /// Instruments written into `pdta`/`inst`, `ibag`, and `igen`.
    pub instruments: Vec<Sf2Instrument>,
    /// Presets written into `pdta`/`phdr`, `pbag`, and `pgen`.
    pub presets: Vec<Sf2Preset>,
}

/// Structural summary returned by [`validate_sf2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sf2Summary {
    /// `ifil` major version (always `2` for SoundFont 2).
    pub major_version: u16,
    /// `ifil` minor version (e.g. `1` or `4`).
    pub minor_version: u16,
    /// `isng` target sound engine string.
    pub sound_engine: String,
    /// `INAM` bank name string.
    pub bank_name: String,
    /// Number of samples (excluding the `EOS` terminal record).
    pub sample_count: usize,
    /// Byte length of the `smpl` subchunk.
    pub smpl_byte_len: usize,
    /// Number of presets (excluding the `EOP` terminal record).
    pub preset_count: usize,
    /// Number of instruments (excluding the `EOI` terminal record).
    pub instrument_count: usize,
    /// Number of preset zones (excluding the terminal `pbag` record).
    pub pbag_count: usize,
    /// Number of instrument zones (excluding the terminal `ibag` record).
    pub ibag_count: usize,
    /// Number of preset generators (excluding the terminal `pgen` record).
    pub pgen_count: usize,
    /// Number of instrument generators (excluding the terminal `igen` record).
    pub igen_count: usize,
}

fn encode_fixed_20(s: &str) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let bytes = s.as_bytes();
    let len = bytes.len().min(19);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

fn write_info_zstr(out: &mut Vec<u8>, fourcc: &[u8; 4], text: &str) -> Result<()> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    if !bytes.len().is_multiple_of(2) {
        bytes.push(0);
    }
    let len = u32::try_from(bytes.len()).map_err(|_| Error::InvalidField {
        what: "SF2 INFO string length",
        value: bytes.len() as u64,
    })?;
    out.extend_from_slice(fourcc);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&bytes);
    Ok(())
}

fn push_chunk(out: &mut Vec<u8>, fourcc: &[u8; 4], payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::InvalidField {
        what: "SF2 chunk length",
        value: payload.len() as u64,
    })?;
    out.extend_from_slice(fourcc);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    if !payload.len().is_multiple_of(2) {
        out.push(0);
    }
    Ok(())
}

fn push_list(out: &mut Vec<u8>, list_type: &[u8; 4], body: &[u8]) -> Result<()> {
    let total = body
        .len()
        .checked_add(4)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(Error::InvalidField {
            what: "SF2 LIST chunk length",
            value: body.len() as u64,
        })?;
    out.extend_from_slice(b"LIST");
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(list_type);
    out.extend_from_slice(body);
    if !body.len().is_multiple_of(2) {
        out.push(0);
    }
    Ok(())
}

fn checked_inc_u16(value: &mut u16, what: &'static str) -> Result<()> {
    *value = value.checked_add(1).ok_or(Error::InvalidField {
        what,
        value: u64::from(u16::MAX) + 1,
    })?;
    Ok(())
}

/// Serialize `font` into a SoundFont 2.04 RIFF `sfbk` byte buffer.
///
/// Presets are automatically sorted by `(bank, preset)` ascending as required
/// by the SoundFont 2 specification; duplicate `(bank, preset)` pairs are
/// rejected. Each sample is followed by [`SAMPLE_TERMINAL_PADDING`] zero `i16`
/// samples in `smpl`.
pub fn write_sf2(font: &Sf2Font) -> Result<Vec<u8>> {
    // 1. LIST INFO
    let mut info_body = Vec::new();
    info_body.extend_from_slice(b"ifil");
    info_body.extend_from_slice(&4u32.to_le_bytes());
    info_body.extend_from_slice(&SF2_VERSION_MAJOR.to_le_bytes());
    info_body.extend_from_slice(&SF2_VERSION_MINOR.to_le_bytes());
    write_info_zstr(&mut info_body, b"isng", &font.info.sound_engine)?;
    write_info_zstr(&mut info_body, b"INAM", &font.info.bank_name)?;
    if let Some(ref v) = font.info.engineer {
        write_info_zstr(&mut info_body, b"IENG", v)?;
    }
    if let Some(ref v) = font.info.software {
        write_info_zstr(&mut info_body, b"ISFT", v)?;
    }
    if let Some(ref v) = font.info.product {
        write_info_zstr(&mut info_body, b"IPRD", v)?;
    }
    if let Some(ref v) = font.info.copyright {
        write_info_zstr(&mut info_body, b"ICOP", v)?;
    }
    if let Some(ref v) = font.info.comments {
        write_info_zstr(&mut info_body, b"ICMT", v)?;
    }

    // 2. LIST sdta (smpl) + shdr records
    let mut smpl_bytes = Vec::new();
    let mut shdr_bytes = Vec::with_capacity((font.samples.len() + 1) * SHDR_RECORD_SIZE);
    let mut sample_cursor = 0usize;

    for sample in &font.samples {
        if sample.sample_rate == 0 {
            return Err(Error::InvalidField {
                what: "SF2 sample rate",
                value: 0,
            });
        }
        let sample_len = u32::try_from(sample.pcm.len()).map_err(|_| Error::InvalidField {
            what: "SF2 sample length",
            value: sample.pcm.len() as u64,
        })?;
        if sample.loop_start > sample.loop_end || sample.loop_end > sample_len {
            return Err(Error::InvalidField {
                what: "SF2 sample loop range",
                value: (u64::from(sample.loop_start) << 32) | u64::from(sample.loop_end),
            });
        }
        let dw_start = u32::try_from(sample_cursor).map_err(|_| Error::InvalidField {
            what: "SF2 sample start offset",
            value: sample_cursor as u64,
        })?;
        let dw_end = dw_start
            .checked_add(sample_len)
            .ok_or(Error::InvalidField {
                what: "SF2 sample end offset",
                value: u64::from(dw_start) + u64::from(sample_len),
            })?;
        let dw_startloop = dw_start + sample.loop_start;
        let dw_endloop = dw_start + sample.loop_end;

        for &s in &sample.pcm {
            smpl_bytes.extend_from_slice(&s.to_le_bytes());
        }
        smpl_bytes.resize(smpl_bytes.len() + SAMPLE_TERMINAL_PADDING * 2, 0);
        sample_cursor = sample_cursor
            .checked_add(sample.pcm.len())
            .and_then(|n| n.checked_add(SAMPLE_TERMINAL_PADDING))
            .ok_or(Error::InvalidField {
                what: "SF2 total sample count",
                value: u64::MAX,
            })?;

        shdr_bytes.extend_from_slice(&encode_fixed_20(&sample.name));
        shdr_bytes.extend_from_slice(&dw_start.to_le_bytes());
        shdr_bytes.extend_from_slice(&dw_end.to_le_bytes());
        shdr_bytes.extend_from_slice(&dw_startloop.to_le_bytes());
        shdr_bytes.extend_from_slice(&dw_endloop.to_le_bytes());
        shdr_bytes.extend_from_slice(&sample.sample_rate.to_le_bytes());
        shdr_bytes.push(sample.original_pitch);
        shdr_bytes.push(sample.pitch_correction as u8);
        shdr_bytes.extend_from_slice(&sample.sample_link.to_le_bytes());
        shdr_bytes.extend_from_slice(&sample.sample_type.to_raw().to_le_bytes());
    }
    // Terminal EOS record
    shdr_bytes.extend_from_slice(&encode_fixed_20("EOS"));
    shdr_bytes.extend_from_slice(&[0u8; SHDR_RECORD_SIZE - 20]);

    let mut sdta_body = Vec::new();
    push_chunk(&mut sdta_body, b"smpl", &smpl_bytes)?;

    // 3. LIST pdta
    let mut preset_order: Vec<usize> = (0..font.presets.len()).collect();
    preset_order.sort_by_key(|&i| (font.presets[i].bank, font.presets[i].preset));
    for pair in preset_order.windows(2) {
        let a = &font.presets[pair[0]];
        let b = &font.presets[pair[1]];
        if (a.bank, a.preset) == (b.bank, b.preset) {
            return Err(Error::InvalidField {
                what: "SF2 duplicate (bank, preset)",
                value: (u64::from(a.bank) << 16) | u64::from(a.preset),
            });
        }
    }

    let mut phdr_bytes = Vec::with_capacity((font.presets.len() + 1) * PHDR_RECORD_SIZE);
    let mut pbag_bytes = Vec::new();
    let mut pgen_bytes = Vec::new();
    let mut pbag_idx = 0u16;
    let mut pgen_idx = 0u16;

    for &pi in &preset_order {
        let preset = &font.presets[pi];
        phdr_bytes.extend_from_slice(&encode_fixed_20(&preset.name));
        phdr_bytes.extend_from_slice(&preset.preset.to_le_bytes());
        phdr_bytes.extend_from_slice(&preset.bank.to_le_bytes());
        phdr_bytes.extend_from_slice(&pbag_idx.to_le_bytes());
        phdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // dwLibrary
        phdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // dwGenre
        phdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // dwMorphology

        for zone in &preset.zones {
            pbag_bytes.extend_from_slice(&pgen_idx.to_le_bytes());
            pbag_bytes.extend_from_slice(&0u16.to_le_bytes()); // wModNdx
            checked_inc_u16(&mut pbag_idx, "SF2 pbag count")?;

            for gen in &zone.generators {
                if gen.oper == GEN_INSTRUMENT {
                    let inst_id = u16::from_le_bytes(gen.amount) as usize;
                    if inst_id >= font.instruments.len() {
                        return Err(Error::InvalidField {
                            what: "SF2 preset instrument index",
                            value: inst_id as u64,
                        });
                    }
                }
                pgen_bytes.extend_from_slice(&gen.oper.to_le_bytes());
                pgen_bytes.extend_from_slice(&gen.amount);
                checked_inc_u16(&mut pgen_idx, "SF2 pgen count")?;
            }
        }
    }
    // Terminal EOP, pbag, pmod, pgen
    phdr_bytes.extend_from_slice(&encode_fixed_20("EOP"));
    phdr_bytes.extend_from_slice(&0u16.to_le_bytes());
    phdr_bytes.extend_from_slice(&0u16.to_le_bytes());
    phdr_bytes.extend_from_slice(&pbag_idx.to_le_bytes());
    phdr_bytes.extend_from_slice(&[0u8; 12]);

    pbag_bytes.extend_from_slice(&pgen_idx.to_le_bytes());
    pbag_bytes.extend_from_slice(&0u16.to_le_bytes());
    let pmod_bytes = [0u8; PMOD_RECORD_SIZE];
    pgen_bytes.extend_from_slice(&[0u8; PGEN_RECORD_SIZE]);

    let mut inst_bytes = Vec::with_capacity((font.instruments.len() + 1) * INST_RECORD_SIZE);
    let mut ibag_bytes = Vec::new();
    let mut igen_bytes = Vec::new();
    let mut ibag_idx = 0u16;
    let mut igen_idx = 0u16;

    for inst in &font.instruments {
        inst_bytes.extend_from_slice(&encode_fixed_20(&inst.name));
        inst_bytes.extend_from_slice(&ibag_idx.to_le_bytes());

        for zone in &inst.zones {
            ibag_bytes.extend_from_slice(&igen_idx.to_le_bytes());
            ibag_bytes.extend_from_slice(&0u16.to_le_bytes()); // wInstModNdx
            checked_inc_u16(&mut ibag_idx, "SF2 ibag count")?;

            for gen in &zone.generators {
                if gen.oper == GEN_SAMPLE_ID {
                    let sample_id = u16::from_le_bytes(gen.amount) as usize;
                    if sample_id >= font.samples.len() {
                        return Err(Error::InvalidField {
                            what: "SF2 instrument sample index",
                            value: sample_id as u64,
                        });
                    }
                }
                igen_bytes.extend_from_slice(&gen.oper.to_le_bytes());
                igen_bytes.extend_from_slice(&gen.amount);
                checked_inc_u16(&mut igen_idx, "SF2 igen count")?;
            }
        }
    }
    // Terminal EOI, ibag, imod, igen
    inst_bytes.extend_from_slice(&encode_fixed_20("EOI"));
    inst_bytes.extend_from_slice(&ibag_idx.to_le_bytes());

    ibag_bytes.extend_from_slice(&igen_idx.to_le_bytes());
    ibag_bytes.extend_from_slice(&0u16.to_le_bytes());
    let imod_bytes = [0u8; IMOD_RECORD_SIZE];
    igen_bytes.extend_from_slice(&[0u8; IGEN_RECORD_SIZE]);

    let mut pdta_body = Vec::new();
    push_chunk(&mut pdta_body, b"phdr", &phdr_bytes)?;
    push_chunk(&mut pdta_body, b"pbag", &pbag_bytes)?;
    push_chunk(&mut pdta_body, b"pmod", &pmod_bytes)?;
    push_chunk(&mut pdta_body, b"pgen", &pgen_bytes)?;
    push_chunk(&mut pdta_body, b"inst", &inst_bytes)?;
    push_chunk(&mut pdta_body, b"ibag", &ibag_bytes)?;
    push_chunk(&mut pdta_body, b"imod", &imod_bytes)?;
    push_chunk(&mut pdta_body, b"igen", &igen_bytes)?;
    push_chunk(&mut pdta_body, b"shdr", &shdr_bytes)?;

    let mut riff_body = Vec::new();
    riff_body.extend_from_slice(b"sfbk");
    push_list(&mut riff_body, b"INFO", &info_body)?;
    push_list(&mut riff_body, b"sdta", &sdta_body)?;
    push_list(&mut riff_body, b"pdta", &pdta_body)?;

    let riff_size = u32::try_from(riff_body.len()).map_err(|_| Error::InvalidField {
        what: "SF2 RIFF size",
        value: riff_body.len() as u64,
    })?;
    let mut out = Vec::with_capacity(8 + riff_body.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&riff_size.to_le_bytes());
    out.extend_from_slice(&riff_body);
    Ok(out)
}

fn u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// Structurally validate a SoundFont 2 RIFF `sfbk` byte buffer and return its
/// [`Sf2Summary`].
///
/// Checks `RIFF`/`sfbk` framing, required `INFO`/`sdta`/`pdta` lists and
/// mandatory subchunks, SoundFont major version (`2`), exact record sizes and
/// terminal records (`EOP`, `EOI`, `EOS`), strictly ascending preset
/// `(bank, preset)` order, monotonic bag/generator/modulator indices, and
/// sample header offsets bounded by the `smpl` payload.
pub fn validate_sf2(bytes: &[u8]) -> Result<Sf2Summary> {
    if bytes.len() < 12 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 12,
            available: bytes.len(),
        });
    }
    if &bytes[0..4] != b"RIFF" {
        return Err(Error::BadMagic {
            offset: 0,
            expected: u32::from_be_bytes(*b"RIFF"),
            found: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        });
    }
    let riff_size = u32_le(bytes, 4) as usize;
    let expected_end = 8usize.checked_add(riff_size).ok_or(Error::InvalidField {
        what: "SF2 RIFF size",
        value: riff_size as u64,
    })?;
    if expected_end > bytes.len() {
        return Err(Error::Truncated {
            offset: 8,
            needed: riff_size,
            available: bytes.len() - 8,
        });
    }
    if expected_end < bytes.len() {
        return Err(Error::Trailing(bytes.len() - expected_end));
    }
    if &bytes[8..12] != b"sfbk" {
        return Err(Error::BadMagic {
            offset: 8,
            expected: u32::from_be_bytes(*b"sfbk"),
            found: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        });
    }

    let mut pos = 12usize;
    let mut saw_info = false;
    let mut saw_sdta = false;
    let mut saw_pdta = false;

    let mut version: Option<(u16, u16)> = None;
    let mut sound_engine: Option<String> = None;
    let mut bank_name: Option<String> = None;

    let mut smpl_byte_len: Option<usize> = None;
    let mut phdr: Option<&[u8]> = None;
    let mut pbag: Option<&[u8]> = None;
    let mut pmod: Option<&[u8]> = None;
    let mut pgen: Option<&[u8]> = None;
    let mut inst: Option<&[u8]> = None;
    let mut ibag: Option<&[u8]> = None;
    let mut imod: Option<&[u8]> = None;
    let mut igen: Option<&[u8]> = None;
    let mut shdr: Option<&[u8]> = None;

    while pos < bytes.len() {
        if bytes.len() - pos < 8 {
            return Err(Error::Truncated {
                offset: pos,
                needed: 8,
                available: bytes.len() - pos,
            });
        }
        let chunk_id = &bytes[pos..pos + 4];
        let chunk_len = u32_le(bytes, pos + 4) as usize;
        let payload_start = pos + 8;
        let payload_end = payload_start
            .checked_add(chunk_len)
            .ok_or(Error::InvalidField {
                what: "SF2 chunk length",
                value: chunk_len as u64,
            })?;
        if payload_end > bytes.len() {
            return Err(Error::Truncated {
                offset: payload_start,
                needed: chunk_len,
                available: bytes.len() - payload_start,
            });
        }

        if chunk_id == b"LIST" {
            if chunk_len < 4 {
                return Err(Error::Truncated {
                    offset: payload_start,
                    needed: 4,
                    available: chunk_len,
                });
            }
            let list_type = &bytes[payload_start..payload_start + 4];
            let mut sub_pos = payload_start + 4;
            match list_type {
                b"INFO" => {
                    saw_info = true;
                    while sub_pos < payload_end {
                        if payload_end - sub_pos < 8 {
                            return Err(Error::Truncated {
                                offset: sub_pos,
                                needed: 8,
                                available: payload_end - sub_pos,
                            });
                        }
                        let sub_id = &bytes[sub_pos..sub_pos + 4];
                        let sub_len = u32_le(bytes, sub_pos + 4) as usize;
                        let s_start = sub_pos + 8;
                        let s_end = s_start.checked_add(sub_len).ok_or(Error::InvalidField {
                            what: "SF2 INFO subchunk length",
                            value: sub_len as u64,
                        })?;
                        if s_end > payload_end {
                            return Err(Error::Truncated {
                                offset: s_start,
                                needed: sub_len,
                                available: payload_end - s_start,
                            });
                        }
                        let s_payload = &bytes[s_start..s_end];
                        match sub_id {
                            b"ifil" => {
                                if sub_len != 4 {
                                    return Err(Error::InvalidField {
                                        what: "SF2 ifil length",
                                        value: sub_len as u64,
                                    });
                                }
                                version = Some((u16_le(s_payload, 0), u16_le(s_payload, 2)));
                            }
                            b"isng" => {
                                sound_engine = Some(
                                    String::from_utf8_lossy(s_payload)
                                        .trim_end_matches('\0')
                                        .to_string(),
                                );
                            }
                            b"INAM" => {
                                bank_name = Some(
                                    String::from_utf8_lossy(s_payload)
                                        .trim_end_matches('\0')
                                        .to_string(),
                                );
                            }
                            _ => {}
                        }
                        sub_pos = if (sub_len & 1) == 1 && s_end < payload_end {
                            s_end + 1
                        } else {
                            s_end
                        };
                    }
                }
                b"sdta" => {
                    saw_sdta = true;
                    while sub_pos < payload_end {
                        if payload_end - sub_pos < 8 {
                            return Err(Error::Truncated {
                                offset: sub_pos,
                                needed: 8,
                                available: payload_end - sub_pos,
                            });
                        }
                        let sub_id = &bytes[sub_pos..sub_pos + 4];
                        let sub_len = u32_le(bytes, sub_pos + 4) as usize;
                        let s_start = sub_pos + 8;
                        let s_end = s_start.checked_add(sub_len).ok_or(Error::InvalidField {
                            what: "SF2 sdta subchunk length",
                            value: sub_len as u64,
                        })?;
                        if s_end > payload_end {
                            return Err(Error::Truncated {
                                offset: s_start,
                                needed: sub_len,
                                available: payload_end - s_start,
                            });
                        }
                        if sub_id == b"smpl" {
                            if !sub_len.is_multiple_of(2) {
                                return Err(Error::InvalidField {
                                    what: "SF2 smpl byte length",
                                    value: sub_len as u64,
                                });
                            }
                            smpl_byte_len = Some(sub_len);
                        }
                        sub_pos = if (sub_len & 1) == 1 && s_end < payload_end {
                            s_end + 1
                        } else {
                            s_end
                        };
                    }
                }
                b"pdta" => {
                    saw_pdta = true;
                    while sub_pos < payload_end {
                        if payload_end - sub_pos < 8 {
                            return Err(Error::Truncated {
                                offset: sub_pos,
                                needed: 8,
                                available: payload_end - sub_pos,
                            });
                        }
                        let sub_id = &bytes[sub_pos..sub_pos + 4];
                        let sub_len = u32_le(bytes, sub_pos + 4) as usize;
                        let s_start = sub_pos + 8;
                        let s_end = s_start.checked_add(sub_len).ok_or(Error::InvalidField {
                            what: "SF2 pdta subchunk length",
                            value: sub_len as u64,
                        })?;
                        if s_end > payload_end {
                            return Err(Error::Truncated {
                                offset: s_start,
                                needed: sub_len,
                                available: payload_end - s_start,
                            });
                        }
                        let s_payload = &bytes[s_start..s_end];
                        match sub_id {
                            b"phdr" => phdr = Some(s_payload),
                            b"pbag" => pbag = Some(s_payload),
                            b"pmod" => pmod = Some(s_payload),
                            b"pgen" => pgen = Some(s_payload),
                            b"inst" => inst = Some(s_payload),
                            b"ibag" => ibag = Some(s_payload),
                            b"imod" => imod = Some(s_payload),
                            b"igen" => igen = Some(s_payload),
                            b"shdr" => shdr = Some(s_payload),
                            _ => {}
                        }
                        sub_pos = if (sub_len & 1) == 1 && s_end < payload_end {
                            s_end + 1
                        } else {
                            s_end
                        };
                    }
                }
                _ => {}
            }
        }

        pos = if (chunk_len & 1) == 1 && payload_end < bytes.len() {
            payload_end + 1
        } else {
            payload_end
        };
    }

    if !saw_info {
        return Err(Error::Malformed("SF2 missing LIST INFO chunk".into()));
    }
    if !saw_sdta {
        return Err(Error::Malformed("SF2 missing LIST sdta chunk".into()));
    }
    if !saw_pdta {
        return Err(Error::Malformed("SF2 missing LIST pdta chunk".into()));
    }

    let (major_version, minor_version) =
        version.ok_or_else(|| Error::Malformed("SF2 missing ifil subchunk".into()))?;
    if major_version != SF2_VERSION_MAJOR {
        return Err(Error::InvalidField {
            what: "SF2 major version",
            value: u64::from(major_version),
        });
    }
    let sound_engine =
        sound_engine.ok_or_else(|| Error::Malformed("SF2 missing isng subchunk".into()))?;
    let bank_name =
        bank_name.ok_or_else(|| Error::Malformed("SF2 missing INAM subchunk".into()))?;
    let smpl_byte_len =
        smpl_byte_len.ok_or_else(|| Error::Malformed("SF2 missing smpl subchunk".into()))?;

    let phdr = phdr.ok_or_else(|| Error::Malformed("SF2 missing phdr subchunk".into()))?;
    let pbag = pbag.ok_or_else(|| Error::Malformed("SF2 missing pbag subchunk".into()))?;
    let pmod = pmod.ok_or_else(|| Error::Malformed("SF2 missing pmod subchunk".into()))?;
    let pgen = pgen.ok_or_else(|| Error::Malformed("SF2 missing pgen subchunk".into()))?;
    let inst = inst.ok_or_else(|| Error::Malformed("SF2 missing inst subchunk".into()))?;
    let ibag = ibag.ok_or_else(|| Error::Malformed("SF2 missing ibag subchunk".into()))?;
    let imod = imod.ok_or_else(|| Error::Malformed("SF2 missing imod subchunk".into()))?;
    let igen = igen.ok_or_else(|| Error::Malformed("SF2 missing igen subchunk".into()))?;
    let shdr = shdr.ok_or_else(|| Error::Malformed("SF2 missing shdr subchunk".into()))?;

    let phdr_total = check_records(phdr, PHDR_RECORD_SIZE, "SF2 phdr length")?;
    let pbag_total = check_records(pbag, PBAG_RECORD_SIZE, "SF2 pbag length")?;
    let pmod_total = check_records(pmod, PMOD_RECORD_SIZE, "SF2 pmod length")?;
    let pgen_total = check_records(pgen, PGEN_RECORD_SIZE, "SF2 pgen length")?;
    let inst_total = check_records(inst, INST_RECORD_SIZE, "SF2 inst length")?;
    let ibag_total = check_records(ibag, IBAG_RECORD_SIZE, "SF2 ibag length")?;
    let imod_total = check_records(imod, IMOD_RECORD_SIZE, "SF2 imod length")?;
    let igen_total = check_records(igen, IGEN_RECORD_SIZE, "SF2 igen length")?;
    let shdr_total = check_records(shdr, SHDR_RECORD_SIZE, "SF2 shdr length")?;

    // Check terminal records.
    let eop_off = (phdr_total - 1) * PHDR_RECORD_SIZE;
    if &phdr[eop_off..eop_off + 3] != b"EOP" {
        return Err(Error::Malformed(
            "SF2 phdr missing EOP terminal record".into(),
        ));
    }
    let eoi_off = (inst_total - 1) * INST_RECORD_SIZE;
    if &inst[eoi_off..eoi_off + 3] != b"EOI" {
        return Err(Error::Malformed(
            "SF2 inst missing EOI terminal record".into(),
        ));
    }
    let eos_off = (shdr_total - 1) * SHDR_RECORD_SIZE;
    if &shdr[eos_off..eos_off + 3] != b"EOS" {
        return Err(Error::Malformed(
            "SF2 shdr missing EOS terminal record".into(),
        ));
    }

    // Validate preset ordering and monotonic pbag indices.
    let mut prev_slot: Option<(u16, u16)> = None;
    let mut prev_pbag = 0u16;
    for i in 0..phdr_total {
        let rec = i * PHDR_RECORD_SIZE;
        let bag_idx = u16_le(phdr, rec + 24);
        if bag_idx < prev_pbag || usize::from(bag_idx) >= pbag_total {
            return Err(Error::InvalidField {
                what: "SF2 phdr bag index",
                value: u64::from(bag_idx),
            });
        }
        prev_pbag = bag_idx;
        if i + 1 < phdr_total {
            let preset = u16_le(phdr, rec + 20);
            let bank = u16_le(phdr, rec + 22);
            if let Some(prev) = prev_slot {
                if (bank, preset) <= prev {
                    return Err(Error::InvalidField {
                        what: "SF2 preset order",
                        value: (u64::from(bank) << 16) | u64::from(preset),
                    });
                }
            }
            prev_slot = Some((bank, preset));
        }
    }

    // Validate monotonic pbag -> pgen/pmod indices.
    validate_bags(pbag, pbag_total, pgen_total, pmod_total, "SF2 pbag index")?;

    // Validate monotonic inst -> ibag indices.
    let mut prev_ibag = 0u16;
    for i in 0..inst_total {
        let rec = i * INST_RECORD_SIZE;
        let bag_idx = u16_le(inst, rec + 20);
        if bag_idx < prev_ibag || usize::from(bag_idx) >= ibag_total {
            return Err(Error::InvalidField {
                what: "SF2 inst bag index",
                value: u64::from(bag_idx),
            });
        }
        prev_ibag = bag_idx;
    }

    // Validate monotonic ibag -> igen/imod indices.
    validate_bags(ibag, ibag_total, igen_total, imod_total, "SF2 ibag index")?;

    // Validate sample header offsets against smpl length.
    let total_points = (smpl_byte_len / 2) as u64;
    for i in 0..shdr_total - 1 {
        let rec = i * SHDR_RECORD_SIZE;
        let dw_start = u64::from(u32_le(shdr, rec + 20));
        let dw_end = u64::from(u32_le(shdr, rec + 24));
        let dw_startloop = u64::from(u32_le(shdr, rec + 28));
        let dw_endloop = u64::from(u32_le(shdr, rec + 32));
        if dw_start > dw_startloop
            || dw_startloop > dw_endloop
            || dw_endloop > dw_end
            || dw_end > total_points
        {
            return Err(Error::InvalidField {
                what: "SF2 sample bounds",
                value: dw_end,
            });
        }
    }

    Ok(Sf2Summary {
        major_version,
        minor_version,
        sound_engine,
        bank_name,
        sample_count: shdr_total - 1,
        smpl_byte_len,
        preset_count: phdr_total - 1,
        instrument_count: inst_total - 1,
        pbag_count: pbag_total - 1,
        ibag_count: ibag_total - 1,
        pgen_count: pgen_total - 1,
        igen_count: igen_total - 1,
    })
}

fn check_records(chunk: &[u8], record_size: usize, what: &'static str) -> Result<usize> {
    if chunk.is_empty() || !chunk.len().is_multiple_of(record_size) {
        return Err(Error::InvalidField {
            what,
            value: chunk.len() as u64,
        });
    }
    Ok(chunk.len() / record_size)
}

fn validate_bags(
    bag: &[u8],
    bag_total: usize,
    gen_total: usize,
    mod_total: usize,
    what: &'static str,
) -> Result<()> {
    let mut prev_gen = 0u16;
    let mut prev_mod = 0u16;
    for i in 0..bag_total {
        let rec = i * 4;
        let gen_idx = u16_le(bag, rec);
        let mod_idx = u16_le(bag, rec + 2);
        if gen_idx < prev_gen || usize::from(gen_idx) >= gen_total {
            return Err(Error::InvalidField {
                what,
                value: u64::from(gen_idx),
            });
        }
        if mod_idx < prev_mod || usize::from(mod_idx) >= mod_total {
            return Err(Error::InvalidField {
                what,
                value: u64::from(mod_idx),
            });
        }
        prev_gen = gen_idx;
        prev_mod = mod_idx;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_font() -> Sf2Font {
        Sf2Font {
            info: Sf2Info {
                bank_name: "Test Bank".into(),
                sound_engine: "EMU8000".into(),
                engineer: Some("FormatKit".into()),
                software: Some("formatkit-codec".into()),
                product: None,
                copyright: None,
                comments: None,
            },
            samples: vec![Sf2Sample {
                name: "Tone".into(),
                pcm: vec![0, 4096, 8192, 4096, 0, -4096, -8192, -4096],
                sample_rate: 44_100,
                original_pitch: 60,
                pitch_correction: 0,
                loop_start: 0,
                loop_end: 8,
                sample_link: 0,
                sample_type: Sf2SampleType::Mono,
            }],
            instruments: vec![Sf2Instrument {
                name: "ToneInst".into(),
                zones: vec![Sf2Zone {
                    generators: vec![
                        Sf2Generator::key_range(0, 127),
                        Sf2Generator::vel_range(0, 127),
                        Sf2Generator::sample_modes(1),
                        Sf2Generator::overriding_root_key(60),
                        Sf2Generator::sample_id(0),
                    ],
                }],
            }],
            presets: vec![Sf2Preset {
                name: "TonePreset".into(),
                preset: 0,
                bank: 0,
                zones: vec![Sf2Zone {
                    generators: vec![Sf2Generator::key_range(0, 127), Sf2Generator::instrument(0)],
                }],
            }],
        }
    }

    #[test]
    fn write_and_validate_minimal_soundfont() {
        let font = minimal_font();
        let bytes = write_sf2(&font).unwrap();
        assert_eq!(&bytes[0..4], b"RIFF");
        assert_eq!(&bytes[8..12], b"sfbk");

        let summary = validate_sf2(&bytes).unwrap();
        assert_eq!(summary.major_version, 2);
        assert_eq!(summary.minor_version, 4);
        assert_eq!(summary.sound_engine, "EMU8000");
        assert_eq!(summary.bank_name, "Test Bank");
        assert_eq!(summary.sample_count, 1);
        assert_eq!(summary.smpl_byte_len, (8 + SAMPLE_TERMINAL_PADDING) * 2);
        assert_eq!(summary.preset_count, 1);
        assert_eq!(summary.instrument_count, 1);
        assert_eq!(summary.pbag_count, 1);
        assert_eq!(summary.ibag_count, 1);
        assert_eq!(summary.pgen_count, 2);
        assert_eq!(summary.igen_count, 5);
    }

    #[test]
    fn writer_sorts_presets_and_rejects_duplicates_and_bad_refs() {
        let mut font = minimal_font();
        font.presets.push(Sf2Preset {
            name: "Earlier".into(),
            preset: 5,
            bank: 0,
            zones: vec![Sf2Zone {
                generators: vec![Sf2Generator::instrument(0)],
            }],
        });
        font.presets.swap(0, 1);
        let bytes = write_sf2(&font).unwrap();
        let summary = validate_sf2(&bytes).unwrap();
        assert_eq!(summary.preset_count, 2);

        // Duplicate (bank, preset) is rejected.
        let mut dup = minimal_font();
        dup.presets.push(dup.presets[0].clone());
        assert!(write_sf2(&dup).is_err());

        // Out-of-bounds instrument reference is rejected.
        let mut bad_inst = minimal_font();
        bad_inst.presets[0].zones[0].generators = vec![Sf2Generator::instrument(99)];
        assert!(write_sf2(&bad_inst).is_err());

        // Out-of-bounds sample reference is rejected.
        let mut bad_sample = minimal_font();
        bad_sample.instruments[0].zones[0].generators = vec![Sf2Generator::sample_id(99)];
        assert!(write_sf2(&bad_sample).is_err());

        // Invalid sample loop range is rejected.
        let mut bad_loop = minimal_font();
        bad_loop.samples[0].loop_start = 10;
        assert!(write_sf2(&bad_loop).is_err());
    }

    #[test]
    fn validate_rejects_truncated_and_corrupted_sfbk() {
        let valid = write_sf2(&minimal_font()).unwrap();

        // Too short
        assert!(matches!(
            validate_sf2(&valid[..8]),
            Err(Error::Truncated { .. })
        ));
        // Wrong RIFF magic
        let mut bad_riff = valid.clone();
        bad_riff[0..4].copy_from_slice(b"FORM");
        assert!(matches!(
            validate_sf2(&bad_riff),
            Err(Error::BadMagic { .. })
        ));

        // Wrong form type
        let mut bad_form = valid.clone();
        bad_form[8..12].copy_from_slice(b"WAVE");
        assert!(matches!(
            validate_sf2(&bad_form),
            Err(Error::BadMagic { .. })
        ));

        // Truncated payload
        assert!(matches!(
            validate_sf2(&valid[..valid.len() - 4]),
            Err(Error::Truncated { .. })
        ));

        // Trailing garbage past RIFF size
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(validate_sf2(&trailing), Err(Error::Trailing(4))));

        // Corrupted EOP terminal marker
        let eop_pos = valid
            .windows(3)
            .rposition(|w| w == b"EOP")
            .expect("EOP present");
        let mut bad_eop = valid.clone();
        bad_eop[eop_pos..eop_pos + 3].copy_from_slice(b"BAD");
        assert!(validate_sf2(&bad_eop).is_err());
    }
}
