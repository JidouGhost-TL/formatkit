//! Compressor oracle — the Phase 0 harness for bit-exact re-compression.
//!
//! Every independently decoded compressed member is a ground-truth
//! `(raw, stored)` pair: `raw` is the decompressed content, `stored` is the
//! exact bytes the game's original packer emitted. A candidate encoder is
//! correct for a codec iff `encode(raw) == stored` for **every** pair of that
//! codec. This module is the decoupling seam:
//!
//! - a **producer** (an application's archive layer) walks the
//!   corpus, and for each compressed member writes a content-addressed
//!   [`Pair`] file under `<root>/<codec>/`.
//! - a **consumer** (a `formatkit-codec` test) loads a codec's pairs and runs a
//!   candidate encoder through [`run`], which reports the **first divergent
//!   byte** of every mismatch — the exact parse decision to fix — plus a
//!   coverage [`Ledger`].
//!
//! The pair set is plain data on disk, so the consumer never depends on the
//! archive layer. When no corpus is configured the pair set is simply empty
//! and codec tests skip, matching the rest of the corpus-test policy.

use std::path::{Path, PathBuf};

use crate::helpers::hash_bytes;

/// The default pair-set root: `$FORMATKIT_CORPUS_DIR/_compress_pairs`, or `None`
/// when no corpus is configured.
pub fn pair_root() -> Option<PathBuf> {
    match formatkit_corpus::subdir("_compress_pairs") {
        Some(root) => Some(root),
        None => {
            // Honour the no-vacuous-pass switch here rather than only in `run_dir`:
            // a codec oracle that skips silently reports a green T1 assertion
            // having compared nothing.
            assert!(
                !crate::required_mode(),
                "FORMATKIT_CORPUS_REQUIRED=1 but no _compress_pairs under $FORMATKIT_CORPUS_DIR — \
                 codec oracles would pass vacuously"
            );
            None
        }
    }
}

const MAGIC: &[u8; 8] = b"SCEPAIR1";

/// One ground-truth compression sample: the decompressed input an encoder is
/// given, and the exact stored bytes it must reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    /// Codec label — the grouping key and subdirectory name (e.g. `flz`,
    /// `okumura-lzss`, `xap-lzss`).
    pub codec: String,
    /// Human-readable origin, carried only for divergence reports (e.g.
    /// `AFS:/dump/foo.afs#12 name=bar.bin`).
    pub provenance: String,
    /// Decompressed content — the encoder's input.
    pub raw: Vec<u8>,
    /// Exact on-disk compressed bytes — the encoder's expected output.
    pub stored: Vec<u8>,
}

impl Pair {
    /// Serialize to the self-describing `.pair` byte layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let codec = self.codec.as_bytes();
        let prov = self.provenance.as_bytes();
        let mut out = Vec::with_capacity(
            8 + 4 + 4 + 8 + 8 + codec.len() + prov.len() + self.raw.len() + self.stored.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(codec.len() as u32).to_le_bytes());
        out.extend_from_slice(&(prov.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.raw.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.stored.len() as u64).to_le_bytes());
        out.extend_from_slice(codec);
        out.extend_from_slice(prov);
        out.extend_from_slice(&self.raw);
        out.extend_from_slice(&self.stored);
        out
    }

    /// Parse the `.pair` byte layout. Returns `None` on any malformed input —
    /// a corrupt pair file is skipped, never a panic.
    pub fn from_bytes(bytes: &[u8]) -> Option<Pair> {
        let bytes = bytes.strip_prefix(MAGIC.as_slice())?;
        let (codec_len, bytes) = take_u32(bytes)?;
        let (prov_len, bytes) = take_u32(bytes)?;
        let (raw_len, bytes) = take_u64(bytes)?;
        let (stored_len, bytes) = take_u64(bytes)?;
        let codec = take(bytes, codec_len as usize)?;
        let bytes = &bytes[codec_len as usize..];
        let prov = take(bytes, prov_len as usize)?;
        let bytes = &bytes[prov_len as usize..];
        let raw = take(bytes, raw_len as usize)?;
        let bytes = &bytes[raw_len as usize..];
        let stored = take(bytes, stored_len as usize)?;
        Some(Pair {
            codec: String::from_utf8(codec.to_vec()).ok()?,
            provenance: String::from_utf8(prov.to_vec()).ok()?,
            raw: raw.to_vec(),
            stored: stored.to_vec(),
        })
    }

    /// The content-addressed filename for this pair: a stable digest of
    /// `codec`, `raw`, and `stored`. Identical pairs from different titles
    /// collapse; a raw that two packers compressed *differently* keeps both.
    pub fn file_name(&self) -> String {
        let mut keyed = Vec::new();
        keyed.extend_from_slice(self.codec.as_bytes());
        keyed.push(0);
        keyed.extend_from_slice(&self.raw);
        keyed.push(0);
        keyed.extend_from_slice(&self.stored);
        format!("{}.pair", &hash_bytes(&keyed)[..32])
    }

    /// Write this pair, content-addressed, under `root/<codec>/`. Returns the
    /// path written. Re-writing an identical pair is idempotent.
    pub fn write_to(&self, root: &Path) -> std::io::Result<PathBuf> {
        let dir = root.join(&self.codec);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(self.file_name());
        std::fs::write(&path, self.to_bytes())?;
        Ok(path)
    }
}

fn take(bytes: &[u8], n: usize) -> Option<&[u8]> {
    bytes.get(..n)
}
fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let b = bytes.get(..4)?;
    Some((u32::from_le_bytes(b.try_into().ok()?), &bytes[4..]))
}
fn take_u64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let b = bytes.get(..8)?;
    Some((u64::from_le_bytes(b.try_into().ok()?), &bytes[8..]))
}

/// Load every `.pair` for one codec from `root/<codec>/`. Missing directory or
/// unreadable/corrupt files yield an empty or short list — never an error, so a
/// codec with no corpus simply skips.
pub fn load_pairs(root: &Path, codec: &str) -> Vec<Pair> {
    let dir = root.join(codec);
    let mut pairs = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return pairs;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "pair").unwrap_or(false))
        .collect();
    paths.sort(); // deterministic order for reproducible ledgers
    for p in paths {
        if let Ok(bytes) = std::fs::read(&p) {
            if let Some(pair) = Pair::from_bytes(&bytes) {
                pairs.push(pair);
            }
        }
    }
    // A codec whose pair directory is present but empty (or unreadable) would
    // otherwise hand its oracle nothing to compare and still report success.
    assert!(
        !crate::required_mode() || !pairs.is_empty(),
        "FORMATKIT_CORPUS_REQUIRED=1 but codec {codec:?} loaded no pairs from {}",
        dir.display()
    );
    pairs
}

/// The result of checking one candidate encoding against its stored truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `encode(raw)` is byte-identical to `stored`.
    Exact,
    /// The encoder returned `None` (declined / not yet implemented).
    Refused,
    /// Same length, but bytes differ starting at `at`.
    Divergence {
        at: usize,
        got: u8,
        want: u8,
        /// A short window of `stored` around `at` for eyeballing the miss.
        want_window: Vec<u8>,
        got_window: Vec<u8>,
    },
    /// Lengths differ; `first_diff` is the first differing byte within the
    /// common prefix, if any (else the outputs match up to the shorter length).
    LengthMismatch {
        got: usize,
        want: usize,
        first_diff: Option<usize>,
    },
}

impl Outcome {
    pub fn is_exact(&self) -> bool {
        matches!(self, Outcome::Exact)
    }
}

const WINDOW: usize = 8;

/// Compare a produced encoding against the stored truth, reporting the first
/// divergence — the byte offset that identifies the wrong parse decision.
pub fn diff(got: &[u8], want: &[u8]) -> Outcome {
    let first_diff = got.iter().zip(want).position(|(a, b)| a != b);
    if got.len() != want.len() {
        return Outcome::LengthMismatch {
            got: got.len(),
            want: want.len(),
            first_diff,
        };
    }
    match first_diff {
        None => Outcome::Exact,
        Some(at) => {
            let lo = at.saturating_sub(WINDOW);
            let hi = (at + WINDOW).min(want.len());
            Outcome::Divergence {
                at,
                got: got[at],
                want: want[at],
                want_window: want[lo..hi].to_vec(),
                got_window: got[lo..hi.min(got.len())].to_vec(),
            }
        }
    }
}

/// Run `encode` against one pair.
pub fn check_pair(encode: &dyn Fn(&[u8]) -> Option<Vec<u8>>, pair: &Pair) -> Outcome {
    match encode(&pair.raw) {
        None => Outcome::Refused,
        Some(got) => diff(&got, &pair.stored),
    }
}

/// Coverage summary for one codec over its whole pair slice.
#[derive(Debug, Clone)]
pub struct Ledger {
    pub codec: String,
    pub total: usize,
    pub exact: usize,
    pub refused: usize,
    /// First-divergence offsets (mismatches only), for a histogram / to find
    /// the shallowest failure to attack first.
    pub first_divergences: Vec<usize>,
    /// Up to a few representative mismatch samples with provenance, for the
    /// human-readable report.
    pub samples: Vec<(String, Outcome)>,
}

impl Ledger {
    /// True once every pair encodes byte-exactly — the bar for `write:true`.
    pub fn is_bit_exact(&self) -> bool {
        self.total > 0 && self.exact == self.total
    }

    /// The shallowest first-divergence offset across all mismatches, i.e. the
    /// easiest miss to attack next. `None` when everything is exact.
    pub fn shallowest_divergence(&self) -> Option<usize> {
        self.first_divergences.iter().copied().min()
    }

    /// One-line-per-codec summary plus a few divergence samples.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(
            s,
            "codec {}: {}/{} bit-exact, {} refused, {} divergent",
            self.codec,
            self.exact,
            self.total,
            self.refused,
            self.total - self.exact - self.refused,
        );
        if let Some(shallow) = self.shallowest_divergence() {
            let _ = writeln!(s, "  shallowest divergence at byte {shallow}");
        }
        for (prov, outcome) in &self.samples {
            let _ = writeln!(s, "  {prov}: {outcome:?}");
        }
        s
    }
}

const MAX_SAMPLES: usize = 5;

/// Run a candidate encoder over every pair of one codec and tally the results.
pub fn run(codec: &str, pairs: &[Pair], encode: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> Ledger {
    let mut ledger = Ledger {
        codec: codec.to_string(),
        total: pairs.len(),
        exact: 0,
        refused: 0,
        first_divergences: Vec::new(),
        samples: Vec::new(),
    };
    for pair in pairs {
        let outcome = check_pair(encode, pair);
        match &outcome {
            Outcome::Exact => ledger.exact += 1,
            Outcome::Refused => ledger.refused += 1,
            Outcome::Divergence { at, .. } => ledger.first_divergences.push(*at),
            Outcome::LengthMismatch { first_diff, .. } => {
                if let Some(at) = first_diff {
                    ledger.first_divergences.push(*at);
                }
            }
        }
        if !outcome.is_exact() && ledger.samples.len() < MAX_SAMPLES {
            ledger.samples.push((pair.provenance.clone(), outcome));
        }
    }
    ledger
}

/// Convenience for a `formatkit-codec` test: load a codec's pairs from the
/// configured corpus and run `encode`. Returns `None` when no corpus is
/// configured (the test should then skip). An empty pair set still returns a
/// (zero-total) ledger so a missing codec directory is visible.
pub fn run_from_corpus(codec: &str, encode: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> Option<Ledger> {
    let root = pair_root()?;
    let pairs = load_pairs(&root, codec);
    Some(run(codec, &pairs, encode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(codec: &str, raw: &[u8], stored: &[u8]) -> Pair {
        Pair {
            codec: codec.into(),
            provenance: "test".into(),
            raw: raw.to_vec(),
            stored: stored.to_vec(),
        }
    }

    #[test]
    fn pair_round_trips_through_bytes() {
        let p = pair("flz", b"raw-content", b"\x01\x02stored");
        let back = Pair::from_bytes(&p.to_bytes()).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn malformed_pair_is_none_not_panic() {
        assert!(Pair::from_bytes(b"").is_none());
        assert!(Pair::from_bytes(b"SCEPAIR1").is_none());
        assert!(Pair::from_bytes(b"NOTMAGIC..........").is_none());
        // truncated body
        let mut good = pair("c", b"aaaa", b"bbbb").to_bytes();
        good.truncate(good.len() - 3);
        assert!(Pair::from_bytes(&good).is_none());
    }

    #[test]
    fn file_name_is_content_addressed() {
        let a = pair("flz", b"same", b"comp");
        let b = pair("flz", b"same", b"comp");
        let c = pair("flz", b"same", b"DIFFERENT");
        assert_eq!(a.file_name(), b.file_name());
        assert_ne!(a.file_name(), c.file_name());
    }

    #[test]
    fn exact_encoder_is_bit_exact() {
        // a "store" codec whose stored form equals raw
        let pairs = vec![pair("id", b"abc", b"abc"), pair("id", b"xyz", b"xyz")];
        let ledger = run("id", &pairs, &|raw| Some(raw.to_vec()));
        assert!(ledger.is_bit_exact());
        assert_eq!(ledger.exact, 2);
        assert_eq!(ledger.shallowest_divergence(), None);
    }

    #[test]
    fn divergence_reports_first_differing_byte() {
        // stored differs from raw at index 2
        let pairs = vec![pair("c", b"abcdef", b"abXdef")];
        let ledger = run("c", &pairs, &|raw| Some(raw.to_vec()));
        assert!(!ledger.is_bit_exact());
        assert_eq!(ledger.exact, 0);
        assert_eq!(ledger.shallowest_divergence(), Some(2));
        match &ledger.samples[0].1 {
            Outcome::Divergence { at, got, want, .. } => {
                assert_eq!((*at, *got, *want), (2, b'c', b'X'));
            }
            other => panic!("expected divergence, got {other:?}"),
        }
    }

    #[test]
    fn length_mismatch_is_flagged_with_common_prefix_diff() {
        let pairs = vec![pair("c", b"abc", b"abcd")];
        let ledger = run("c", &pairs, &|raw| Some(raw.to_vec()));
        assert_eq!(ledger.exact, 0);
        match &ledger.samples[0].1 {
            Outcome::LengthMismatch {
                got,
                want,
                first_diff,
            } => {
                assert_eq!((*got, *want, *first_diff), (3, 4, None));
            }
            other => panic!("expected length mismatch, got {other:?}"),
        }
    }

    #[test]
    fn refused_encoder_is_counted_separately() {
        let pairs = vec![pair("c", b"abc", b"abc")];
        let ledger = run("c", &pairs, &|_| None);
        assert_eq!((ledger.exact, ledger.refused), (0, 1));
        assert!(!ledger.is_bit_exact());
    }

    #[test]
    fn write_and_load_round_trip_on_disk() {
        let root = std::env::temp_dir().join(format!("formatkit-oracle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let p = pair("flz", b"hello-raw", b"\x00packed");
        let written = p.write_to(&root).unwrap();
        assert!(written.exists());
        // idempotent second write
        p.write_to(&root).unwrap();
        let loaded = load_pairs(&root, "flz");
        assert_eq!(loaded, vec![p]);
        assert!(load_pairs(&root, "missing").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
