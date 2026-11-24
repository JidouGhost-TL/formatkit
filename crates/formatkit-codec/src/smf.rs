//! Standard MIDI File (SMF) 1.0 writer: format 0/1, timed tracks, channel,
//! meta and system-exclusive events, and optional running status.
//!
//! Layout follows the MIDI Manufacturers Association *Standard MIDI Files 1.0*
//! specification: an `MThd` chunk (length 6, format, track count, division)
//! followed by one `MTrk` chunk per track whose events are each preceded by a
//! variable-length delta time. Meta events are `FF type length data`; system
//! exclusive events are `F0 length data`. With running status enabled the
//! status byte of a channel message is omitted when it repeats the previous
//! channel status; meta and system-exclusive events cancel running status,
//! as the specification requires.
//!
//! Tracks are built from *absolute* ticks. The writer orders each track's
//! events by `(tick, rank, insertion order)`, so a caller can make, for
//! example, note-offs sort before note-ons at the same tick by giving them a
//! lower rank, and appends the End of Track meta event at the last tick.
//! Event translation (what a source sequence means as MIDI) stays with the
//! caller.
//!
//! ```
//! use formatkit_codec::smf::{write_smf, SmfDivision, SmfEvent, SmfFormat, SmfTrack, SmfWriteOptions};
//!
//! let mut track = SmfTrack::new();
//! track.push(0, SmfEvent::track_name("lead"));
//! track.push(0, SmfEvent::Tempo { micros_per_quarter: 500_000 });
//! track.push(0, SmfEvent::NoteOn { channel: 0, key: 60, velocity: 100 });
//! track.push(48, SmfEvent::NoteOff { channel: 0, key: 60, velocity: 0 });
//! let bytes = write_smf(
//!     SmfFormat::SingleTrack,
//!     SmfDivision::TicksPerQuarter(48),
//!     &[track],
//!     &SmfWriteOptions::default(),
//! )
//! .unwrap();
//! assert_eq!(&bytes[..4], b"MThd");
//! assert_eq!(&bytes[14..18], b"MTrk");
//! ```

use formatkit_core::{Error, Result};

/// Largest value a variable-length quantity can carry (four 7-bit groups).
pub const SMF_MAX_VLQ: u32 = 0x0fff_ffff;

/// Append `value` as a variable-length quantity (7 bits per byte, most
/// significant group first, continuation bit `0x80` on all but the last).
///
/// Rejects values above [`SMF_MAX_VLQ`].
pub fn write_smf_vlq(out: &mut Vec<u8>, value: u32) -> Result<()> {
    if value > SMF_MAX_VLQ {
        return Err(Error::InvalidField {
            what: "SMF variable-length quantity",
            value: u64::from(value),
        });
    }
    let mut groups = [0u8; 4];
    let mut n = 0;
    let mut rest = value;
    loop {
        groups[n] = (rest & 0x7f) as u8;
        n += 1;
        rest >>= 7;
        if rest == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(groups[i] | if i > 0 { 0x80 } else { 0 });
    }
    Ok(())
}

/// Read a variable-length quantity from the start of `bytes`, returning the
/// value and the number of bytes consumed (`1..=4`).
pub fn read_smf_vlq(bytes: &[u8]) -> Result<(u32, usize)> {
    let mut value = 0u32;
    for (i, &b) in bytes.iter().enumerate().take(4) {
        value = (value << 7) | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    if bytes.len() >= 4 {
        Err(Error::Malformed(
            "SMF variable-length quantity exceeds four bytes".into(),
        ))
    } else {
        Err(Error::Truncated {
            offset: 0,
            needed: bytes.len() + 1,
            available: bytes.len(),
        })
    }
}

/// `MThd` format word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmfFormat {
    /// Format 0: exactly one track holding every channel.
    SingleTrack,
    /// Format 1: one or more simultaneous tracks (track 0 usually carries
    /// tempo and other conductor meta events).
    MultiTrack,
}

/// `MThd` division word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmfDivision {
    /// Metrical time: ticks per quarter note, `1..=0x7fff`.
    TicksPerQuarter(u16),
    /// SMPTE time: frames per second (24, 25, 29 for 30 drop-frame, or 30)
    /// and ticks per frame (non-zero).
    Smpte {
        /// Frames per second: `24`, `25`, `29` or `30`.
        frames_per_second: u8,
        /// Ticks (subframes) per frame.
        ticks_per_frame: u8,
    },
}

impl SmfDivision {
    fn to_word(self) -> Result<u16> {
        match self {
            Self::TicksPerQuarter(t) if (1..=0x7fff).contains(&t) => Ok(t),
            Self::TicksPerQuarter(t) => Err(Error::InvalidField {
                what: "SMF ticks per quarter note",
                value: u64::from(t),
            }),
            Self::Smpte {
                frames_per_second,
                ticks_per_frame,
            } => {
                if !matches!(frames_per_second, 24 | 25 | 29 | 30) {
                    return Err(Error::InvalidField {
                        what: "SMF SMPTE frames per second",
                        value: u64::from(frames_per_second),
                    });
                }
                if ticks_per_frame == 0 {
                    return Err(Error::InvalidField {
                        what: "SMF SMPTE ticks per frame",
                        value: 0,
                    });
                }
                let negative = (frames_per_second as i8).wrapping_neg() as u8;
                Ok(u16::from_be_bytes([negative, ticks_per_frame]))
            }
        }
    }
}

/// Text meta-event types `0x01..=0x07`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmfTextKind {
    /// `0x01` text event.
    Text,
    /// `0x02` copyright notice.
    Copyright,
    /// `0x03` sequence or track name.
    TrackName,
    /// `0x04` instrument name.
    InstrumentName,
    /// `0x05` lyric.
    Lyric,
    /// `0x06` marker.
    Marker,
    /// `0x07` cue point.
    CuePoint,
}

impl SmfTextKind {
    /// The meta-event type byte.
    pub const fn meta_type(self) -> u8 {
        match self {
            Self::Text => 0x01,
            Self::Copyright => 0x02,
            Self::TrackName => 0x03,
            Self::InstrumentName => 0x04,
            Self::Lyric => 0x05,
            Self::Marker => 0x06,
            Self::CuePoint => 0x07,
        }
    }
}

/// One MIDI file event. Channels are `0..=15`; data bytes are `0..=127`.
#[doc(alias = "midi event")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmfEvent {
    /// `8n key velocity`.
    NoteOff {
        /// Channel `0..=15`.
        channel: u8,
        /// Key number.
        key: u8,
        /// Release velocity.
        velocity: u8,
    },
    /// `9n key velocity` (velocity `0` is a note-off by convention).
    NoteOn {
        /// Channel `0..=15`.
        channel: u8,
        /// Key number.
        key: u8,
        /// Attack velocity.
        velocity: u8,
    },
    /// `An key pressure`.
    PolyPressure {
        /// Channel `0..=15`.
        channel: u8,
        /// Key number.
        key: u8,
        /// Pressure value.
        pressure: u8,
    },
    /// `Bn controller value`.
    ControlChange {
        /// Channel `0..=15`.
        channel: u8,
        /// Controller number.
        controller: u8,
        /// Controller value.
        value: u8,
    },
    /// `Cn program`.
    ProgramChange {
        /// Channel `0..=15`.
        channel: u8,
        /// Program number.
        program: u8,
    },
    /// `Dn pressure`.
    ChannelPressure {
        /// Channel `0..=15`.
        channel: u8,
        /// Pressure value.
        pressure: u8,
    },
    /// `En lsb msb`: 14-bit pitch bend, `8192` is centre.
    PitchBend {
        /// Channel `0..=15`.
        channel: u8,
        /// Bend value `0..=16383`.
        value: u16,
    },
    /// `FF 51 03 tttttt`: microseconds per quarter note (`1..=0xffffff`).
    Tempo {
        /// Microseconds per quarter note.
        micros_per_quarter: u32,
    },
    /// `FF 58 04 nn dd cc bb`.
    TimeSignature {
        /// Numerator.
        numerator: u8,
        /// Denominator as a power of two (`2` = quarter note).
        denominator_log2: u8,
        /// MIDI clocks per metronome click.
        clocks_per_click: u8,
        /// Notated 32nd notes per MIDI quarter note (usually `8`).
        thirty_seconds_per_quarter: u8,
    },
    /// `FF 59 02 sf mi`.
    KeySignature {
        /// Sharps (positive) or flats (negative), `-7..=7`.
        sharps_flats: i8,
        /// Minor key when true.
        minor: bool,
    },
    /// A text meta event (`FF 01..07 len text`).
    Text {
        /// Which text event.
        kind: SmfTextKind,
        /// Raw text bytes (the specification does not fix an encoding).
        text: Vec<u8>,
    },
    /// Any other meta event `FF kind len data`. End of Track (`0x2F`) is
    /// written by the writer and rejected here.
    Meta {
        /// Meta-event type `0x00..=0x7f`.
        kind: u8,
        /// Payload.
        data: Vec<u8>,
    },
    /// `F0 len data`: `data` is the bytes after `F0`, normally ending in `F7`.
    SysEx {
        /// Payload after the `F0` status byte.
        data: Vec<u8>,
    },
}

impl SmfEvent {
    /// A track-name text event.
    pub fn track_name(name: impl Into<Vec<u8>>) -> Self {
        Self::Text {
            kind: SmfTextKind::TrackName,
            text: name.into(),
        }
    }

    /// A marker text event.
    pub fn marker(text: impl Into<Vec<u8>>) -> Self {
        Self::Text {
            kind: SmfTextKind::Marker,
            text: text.into(),
        }
    }

    /// A tempo event for an integer `bpm` (`60_000_000 / bpm` microseconds
    /// per quarter note); `bpm` must be at least `4`.
    pub fn tempo_bpm(bpm: u32) -> Result<Self> {
        if bpm < 4 {
            return Err(Error::InvalidField {
                what: "SMF tempo BPM",
                value: u64::from(bpm),
            });
        }
        Ok(Self::Tempo {
            micros_per_quarter: 60_000_000 / bpm,
        })
    }

    /// Append the full event (status byte included) to `out`. Returns the
    /// status byte for channel messages and `None` for meta and SysEx events.
    fn encode(&self, out: &mut Vec<u8>) -> Result<Option<u8>> {
        fn ch(channel: u8) -> Result<u8> {
            if channel > 15 {
                return Err(Error::InvalidField {
                    what: "SMF channel",
                    value: u64::from(channel),
                });
            }
            Ok(channel)
        }
        fn d7(what: &'static str, v: u8) -> Result<u8> {
            if v > 0x7f {
                return Err(Error::InvalidField {
                    what,
                    value: u64::from(v),
                });
            }
            Ok(v)
        }
        fn meta(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<Option<u8>> {
            let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&[0xff, kind]);
            write_smf_vlq(out, len)?;
            out.extend_from_slice(data);
            Ok(None)
        }
        let (status, a, b) = match *self {
            Self::NoteOff {
                channel,
                key,
                velocity,
            } => (
                0x80 | ch(channel)?,
                d7("SMF key", key)?,
                Some(d7("SMF velocity", velocity)?),
            ),
            Self::NoteOn {
                channel,
                key,
                velocity,
            } => (
                0x90 | ch(channel)?,
                d7("SMF key", key)?,
                Some(d7("SMF velocity", velocity)?),
            ),
            Self::PolyPressure {
                channel,
                key,
                pressure,
            } => (
                0xa0 | ch(channel)?,
                d7("SMF key", key)?,
                Some(d7("SMF pressure", pressure)?),
            ),
            Self::ControlChange {
                channel,
                controller,
                value,
            } => (
                0xb0 | ch(channel)?,
                d7("SMF controller", controller)?,
                Some(d7("SMF controller value", value)?),
            ),
            Self::ProgramChange { channel, program } => {
                (0xc0 | ch(channel)?, d7("SMF program", program)?, None)
            }
            Self::ChannelPressure { channel, pressure } => {
                (0xd0 | ch(channel)?, d7("SMF pressure", pressure)?, None)
            }
            Self::PitchBend { channel, value } => {
                if value > 0x3fff {
                    return Err(Error::InvalidField {
                        what: "SMF pitch bend",
                        value: u64::from(value),
                    });
                }
                (
                    0xe0 | ch(channel)?,
                    (value & 0x7f) as u8,
                    Some((value >> 7) as u8),
                )
            }
            Self::Tempo { micros_per_quarter } => {
                if micros_per_quarter == 0 || micros_per_quarter > 0x00ff_ffff {
                    return Err(Error::InvalidField {
                        what: "SMF tempo",
                        value: u64::from(micros_per_quarter),
                    });
                }
                return meta(out, 0x51, &micros_per_quarter.to_be_bytes()[1..]);
            }
            Self::TimeSignature {
                numerator,
                denominator_log2,
                clocks_per_click,
                thirty_seconds_per_quarter,
            } => {
                return meta(
                    out,
                    0x58,
                    &[
                        numerator,
                        denominator_log2,
                        clocks_per_click,
                        thirty_seconds_per_quarter,
                    ],
                );
            }
            Self::KeySignature {
                sharps_flats,
                minor,
            } => {
                if !(-7..=7).contains(&sharps_flats) {
                    return Err(Error::InvalidField {
                        what: "SMF key signature",
                        value: u64::from(sharps_flats as u8),
                    });
                }
                return meta(out, 0x59, &[sharps_flats as u8, u8::from(minor)]);
            }
            Self::Text { kind, ref text } => return meta(out, kind.meta_type(), text),
            Self::Meta { kind, ref data } => {
                if kind > 0x7f || kind == 0x2f {
                    return Err(Error::InvalidField {
                        what: "SMF meta event type",
                        value: u64::from(kind),
                    });
                }
                return meta(out, kind, data);
            }
            Self::SysEx { ref data } => {
                out.push(0xf0);
                write_smf_vlq(out, u32::try_from(data.len()).unwrap_or(u32::MAX))?;
                out.extend_from_slice(data);
                return Ok(None);
            }
        };
        out.push(status);
        out.push(a);
        if let Some(b) = b {
            out.push(b);
        }
        Ok(Some(status))
    }
}

/// One event at an absolute tick with an ordering rank for equal ticks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmfTimedEvent {
    /// Absolute time in division ticks.
    pub tick: u64,
    /// Ordering among events at the same tick (lower first); insertion order
    /// breaks remaining ties.
    pub rank: u8,
    /// The event.
    pub event: SmfEvent,
}

/// One `MTrk` chunk's events, at absolute ticks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmfTrack {
    /// Events in insertion order; the writer sorts a copy of the order.
    pub events: Vec<SmfTimedEvent>,
}

impl SmfTrack {
    /// An empty track.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `event` at absolute `tick` with rank `0`.
    pub fn push(&mut self, tick: u64, event: SmfEvent) {
        self.push_ranked(tick, 0, event);
    }

    /// Append `event` at absolute `tick` with an explicit same-tick `rank`.
    pub fn push_ranked(&mut self, tick: u64, rank: u8, event: SmfEvent) {
        self.events.push(SmfTimedEvent { tick, rank, event });
    }

    /// Serialize this track as a complete `MTrk` chunk, ending with an End of
    /// Track meta event at the last event's tick.
    pub fn to_chunk(&self, options: &SmfWriteOptions) -> Result<Vec<u8>> {
        let mut order: Vec<usize> = (0..self.events.len()).collect();
        order.sort_by_key(|&i| (self.events[i].tick, self.events[i].rank));
        let mut body = Vec::new();
        let mut last_tick = 0u64;
        let mut running: Option<u8> = None;
        let mut scratch = Vec::new();
        for i in order {
            let ev = &self.events[i];
            let delta = ev.tick - last_tick;
            let delta = u32::try_from(delta)
                .ok()
                .filter(|&d| d <= SMF_MAX_VLQ)
                .ok_or(Error::InvalidField {
                    what: "SMF delta time",
                    value: delta,
                })?;
            write_smf_vlq(&mut body, delta)?;
            last_tick = ev.tick;
            scratch.clear();
            let status = ev.event.encode(&mut scratch)?;
            match status {
                Some(s) if options.running_status && running == Some(s) => {
                    body.extend_from_slice(&scratch[1..]);
                }
                _ => body.extend_from_slice(&scratch),
            }
            running = status;
        }
        body.extend_from_slice(&[0x00, 0xff, 0x2f, 0x00]);
        let len = u32::try_from(body.len()).map_err(|_| Error::ResourceLimit {
            resource: "SMF track bytes",
            requested: body.len() as u64,
            limit: u64::from(u32::MAX),
        })?;
        let mut out = Vec::with_capacity(8 + body.len());
        out.extend_from_slice(b"MTrk");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Writer settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmfWriteOptions {
    /// Omit repeated channel status bytes (running status). Off by default.
    pub running_status: bool,
}

/// Write a complete Standard MIDI File.
///
/// Rejects format 0 with other than one track, more than 65535 tracks, an
/// invalid division, out-of-range channels or data bytes, a delta time above
/// [`SMF_MAX_VLQ`], and an End of Track meta event supplied by the caller.
pub fn write_smf(
    format: SmfFormat,
    division: SmfDivision,
    tracks: &[SmfTrack],
    options: &SmfWriteOptions,
) -> Result<Vec<u8>> {
    let format_word = match format {
        SmfFormat::SingleTrack => {
            if tracks.len() != 1 {
                return Err(Error::InvalidField {
                    what: "SMF format 0 track count",
                    value: tracks.len() as u64,
                });
            }
            0u16
        }
        SmfFormat::MultiTrack => 1u16,
    };
    let count = u16::try_from(tracks.len()).map_err(|_| Error::InvalidField {
        what: "SMF track count",
        value: tracks.len() as u64,
    })?;
    let mut out = Vec::new();
    out.extend_from_slice(b"MThd");
    out.extend_from_slice(&6u32.to_be_bytes());
    out.extend_from_slice(&format_word.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&division.to_word()?.to_be_bytes());
    for track in tracks {
        out.extend_from_slice(&track.to_chunk(options)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vlq(v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        write_smf_vlq(&mut out, v).unwrap();
        out
    }

    #[test]
    fn vlq_matches_specification_examples() {
        for (value, bytes) in [
            (0x00, &[0x00][..]),
            (0x40, &[0x40]),
            (0x7f, &[0x7f]),
            (0x80, &[0x81, 0x00]),
            (0x2000, &[0xc0, 0x00]),
            (0x3fff, &[0xff, 0x7f]),
            (0x4000, &[0x81, 0x80, 0x00]),
            (0x10_0000, &[0xc0, 0x80, 0x00]),
            (0x1f_ffff, &[0xff, 0xff, 0x7f]),
            (0x20_0000, &[0x81, 0x80, 0x80, 0x00]),
            (0x0fff_ffff, &[0xff, 0xff, 0xff, 0x7f]),
        ] {
            assert_eq!(vlq(value), bytes, "{value:#x}");
            assert_eq!(read_smf_vlq(bytes).unwrap(), (value, bytes.len()));
        }
        assert!(write_smf_vlq(&mut Vec::new(), 0x1000_0000).is_err());
        assert!(matches!(
            read_smf_vlq(&[0x81]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            read_smf_vlq(&[0x81, 0x81, 0x81, 0x81, 0x00]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn format1_layout_with_meta_events_and_ordering() {
        let mut conductor = SmfTrack::new();
        conductor.push(0, SmfEvent::track_name("Conductor"));
        conductor.push(0, SmfEvent::tempo_bpm(120).unwrap());
        conductor.push(96, SmfEvent::marker("loop_start"));

        let mut lead = SmfTrack::new();
        lead.push_ranked(
            0,
            1,
            SmfEvent::NoteOn {
                channel: 2,
                key: 64,
                velocity: 90,
            },
        );
        lead.push_ranked(
            48,
            1,
            SmfEvent::NoteOn {
                channel: 2,
                key: 65,
                velocity: 90,
            },
        );
        // Pushed later, but rank 0 sorts the note-off first at tick 48.
        lead.push(
            48,
            SmfEvent::NoteOff {
                channel: 2,
                key: 64,
                velocity: 0,
            },
        );

        let smf = write_smf(
            SmfFormat::MultiTrack,
            SmfDivision::TicksPerQuarter(48),
            &[conductor, lead],
            &SmfWriteOptions::default(),
        )
        .unwrap();
        let mut expected = b"MThd\0\0\0\x06\0\x01\0\x02\0\x30".to_vec();
        let t0: &[u8] = &[
            0x00, 0xff, 0x03, 9, b'C', b'o', b'n', b'd', b'u', b'c', b't', b'o', b'r', //
            0x00, 0xff, 0x51, 0x03, 0x07, 0xa1, 0x20, //
            0x60, 0xff, 0x06, 10, b'l', b'o', b'o', b'p', b'_', b's', b't', b'a', b'r', b't', 0x00,
            0xff, 0x2f, 0x00,
        ];
        expected.extend_from_slice(b"MTrk");
        expected.extend_from_slice(&(t0.len() as u32).to_be_bytes());
        expected.extend_from_slice(t0);
        let t1: &[u8] = &[
            0x00, 0x92, 64, 90, //
            0x30, 0x82, 64, 0, //
            0x00, 0x92, 65, 90, //
            0x00, 0xff, 0x2f, 0x00,
        ];
        expected.extend_from_slice(b"MTrk");
        expected.extend_from_slice(&(t1.len() as u32).to_be_bytes());
        expected.extend_from_slice(t1);
        assert_eq!(smf, expected);
    }

    #[test]
    fn running_status_omits_repeats_and_meta_cancels_it() {
        let mut t = SmfTrack::new();
        t.push(
            0,
            SmfEvent::NoteOn {
                channel: 0,
                key: 60,
                velocity: 100,
            },
        );
        t.push(
            0,
            SmfEvent::NoteOn {
                channel: 0,
                key: 64,
                velocity: 100,
            },
        );
        t.push(0, SmfEvent::marker("x"));
        t.push(
            0,
            SmfEvent::NoteOn {
                channel: 0,
                key: 67,
                velocity: 100,
            },
        );
        t.push(
            0,
            SmfEvent::PitchBend {
                channel: 0,
                value: 0x2000,
            },
        );
        t.push(
            0,
            SmfEvent::PitchBend {
                channel: 0,
                value: 0x3fff,
            },
        );
        let on = SmfWriteOptions {
            running_status: true,
        };
        let chunk = t.to_chunk(&on).unwrap();
        assert_eq!(
            &chunk[8..],
            &[
                0x00, 0x90, 60, 100, //
                0x00, 64, 100, //
                0x00, 0xff, 0x06, 1, b'x', //
                0x00, 0x90, 67, 100, //
                0x00, 0xe0, 0x00, 0x40, //
                0x00, 0x7f, 0x7f, //
                0x00, 0xff, 0x2f, 0x00,
            ]
        );
        let off = t.to_chunk(&SmfWriteOptions::default()).unwrap();
        assert_eq!(off.len(), chunk.len() + 2);
    }

    #[test]
    fn format0_division_and_event_validation() {
        let mut t = SmfTrack::new();
        t.push(
            0,
            SmfEvent::ProgramChange {
                channel: 9,
                program: 5,
            },
        );
        let opts = SmfWriteOptions::default();
        let smf = write_smf(
            SmfFormat::SingleTrack,
            SmfDivision::Smpte {
                frames_per_second: 25,
                ticks_per_frame: 40,
            },
            std::slice::from_ref(&t),
            &opts,
        )
        .unwrap();
        assert_eq!(&smf[8..14], &[0, 0, 0, 1, 0xe7, 40]);
        assert_eq!(&smf[22..24], &[0x00, 0xc9]);

        let div = SmfDivision::TicksPerQuarter(96);
        assert!(write_smf(SmfFormat::SingleTrack, div, &[], &opts).is_err());
        assert!(write_smf(SmfFormat::SingleTrack, div, &[t.clone(), t.clone()], &opts).is_err());
        assert!(write_smf(
            SmfFormat::MultiTrack,
            SmfDivision::TicksPerQuarter(0x8000),
            &[],
            &opts
        )
        .is_err());
        assert!(write_smf(
            SmfFormat::MultiTrack,
            SmfDivision::Smpte {
                frames_per_second: 26,
                ticks_per_frame: 1
            },
            &[],
            &opts
        )
        .is_err());

        for bad in [
            SmfEvent::NoteOn {
                channel: 16,
                key: 0,
                velocity: 0,
            },
            SmfEvent::ControlChange {
                channel: 0,
                controller: 0x80,
                value: 0,
            },
            SmfEvent::PitchBend {
                channel: 0,
                value: 0x4000,
            },
            SmfEvent::Tempo {
                micros_per_quarter: 0x0100_0000,
            },
            SmfEvent::Meta {
                kind: 0x2f,
                data: vec![],
            },
            SmfEvent::KeySignature {
                sharps_flats: 8,
                minor: false,
            },
        ] {
            let mut t = SmfTrack::new();
            t.push(0, bad.clone());
            assert!(t.to_chunk(&opts).is_err(), "{bad:?}");
        }
        let mut far = SmfTrack::new();
        far.push(u64::from(SMF_MAX_VLQ) + 1, SmfEvent::marker("late"));
        assert!(matches!(
            far.to_chunk(&opts),
            Err(Error::InvalidField {
                what: "SMF delta time",
                ..
            })
        ));
        assert!(SmfEvent::tempo_bpm(3).is_err());
    }

    #[test]
    fn sysex_time_and_key_signature_encoding() {
        let mut t = SmfTrack::new();
        t.push(
            0,
            SmfEvent::TimeSignature {
                numerator: 6,
                denominator_log2: 3,
                clocks_per_click: 36,
                thirty_seconds_per_quarter: 8,
            },
        );
        t.push(
            0,
            SmfEvent::KeySignature {
                sharps_flats: -3,
                minor: true,
            },
        );
        t.push(
            0,
            SmfEvent::SysEx {
                data: vec![0x7e, 0x7f, 0x09, 0x01, 0xf7],
            },
        );
        let chunk = t.to_chunk(&SmfWriteOptions::default()).unwrap();
        assert_eq!(
            &chunk[8..],
            &[
                0x00, 0xff, 0x58, 4, 6, 3, 36, 8, //
                0x00, 0xff, 0x59, 2, 0xfd, 1, //
                0x00, 0xf0, 5, 0x7e, 0x7f, 0x09, 0x01, 0xf7, //
                0x00, 0xff, 0x2f, 0x00,
            ]
        );
    }
}
