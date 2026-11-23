//! Multi-byte custom character maps (`.tbl` tables) with longest-match byte
//! and UTF-8 tries.
//!
//! A [`Charmap`] maps arbitrary 1..=16 byte sequences to UTF-8 text or control
//! tokens, supporting:
//! - Standard `.tbl` definitions (`HEX=TEXT`, `/HEX=TEXT` terminators,
//!   `*HEX=TEXT` line breaks, `$HEX[,N]=TEXT` / `@HEX[,N]=TEXT` parameterized
//!   controls, and `#` / `;` / `//` comments).
//! - Programmatic construction with aliases, optional page/bank switching, and
//!   fixed-width control operands.
//! - Deterministic longest-match trie decoding (`bytes -> CharmapDecoded`) and
//!   encoding (`text -> Vec<u8>`) with explicit resource limits and lossless
//!   token round-tripping.

use std::collections::{BTreeMap, BTreeSet};

use formatkit_core::{Error, Result};

/// Explicit resource bounds for compiling, decoding, and encoding a [`Charmap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharmapLimits {
    /// Maximum number of glyph/string entries in a map.
    pub max_entries: usize,
    /// Maximum number of control-code rules in a map.
    pub max_controls: usize,
    /// Maximum input bytes accepted by parse/decode/encode operations.
    pub max_input_bytes: usize,
    /// Maximum output bytes produced by decode/encode operations.
    pub max_output_bytes: usize,
    /// Maximum number of tokens emitted in one decode/encode pass.
    pub max_tokens: usize,
    /// Maximum byte length of a single map key or control opcode.
    pub max_key_bytes: usize,
    /// Maximum UTF-8 byte length of a single entry or control display string.
    pub max_text_bytes: usize,
}

impl Default for CharmapLimits {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            max_controls: 1_024,
            max_input_bytes: 1_048_576,
            max_output_bytes: 4_194_304,
            max_tokens: 262_144,
            max_key_bytes: 16,
            max_text_bytes: 1_024,
        }
    }
}

/// One glyph or dictionary entry mapping a byte sequence to UTF-8 text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharmapEntry {
    /// Source bytes in file order (non-empty).
    pub bytes: Vec<u8>,
    /// Canonical decoded UTF-8 text (non-empty).
    pub text: String,
    /// Optional character page on which this entry is active (`None` = global).
    pub page: Option<u8>,
    /// Alternative UTF-8 spellings accepted when encoding.
    pub aliases: Vec<String>,
}

impl CharmapEntry {
    /// Create a global entry with no aliases.
    #[must_use]
    pub fn new(bytes: Vec<u8>, text: impl Into<String>) -> Self {
        Self {
            bytes,
            text: text.into(),
            page: None,
            aliases: Vec::new(),
        }
    }
}

/// One control-code rule matching a byte prefix with optional trailing operand
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharmapControl {
    /// Control opcode bytes in file order (non-empty).
    pub bytes: Vec<u8>,
    /// Display template rendered when decoding.
    ///
    /// When `arg_bytes > 0`, `{args}` is replaced with lowercase hexadecimal
    /// operand bytes (or appended as `:<hex>` if `{args}` is absent).
    pub text: String,
    /// Number of fixed operand bytes following the control opcode.
    pub arg_bytes: usize,
    /// Whether this control terminates a decoded string.
    pub ends: bool,
    /// Optional page number activated when this control is encountered.
    pub set_page: Option<u8>,
}

impl CharmapControl {
    /// Create a simple control code with no operand bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>, text: impl Into<String>) -> Self {
        Self {
            bytes,
            text: text.into(),
            arg_bytes: 0,
            ends: false,
            set_page: None,
        }
    }

    /// Create a terminating control code (`ends = true`).
    #[must_use]
    pub fn terminator(bytes: Vec<u8>, text: impl Into<String>) -> Self {
        Self {
            bytes,
            text: text.into(),
            arg_bytes: 0,
            ends: true,
            set_page: None,
        }
    }

    fn render(&self, args: &[u8]) -> String {
        if self.arg_bytes == 0 {
            return self.text.clone();
        }
        let hex = format_hex_bytes(args);
        if self.text.contains("{args}") {
            self.text.replace("{args}", &hex)
        } else if self.text.is_empty() {
            hex
        } else {
            format!("{}:{hex}", self.text)
        }
    }
}

/// One decoded token preserving exact source bytes and rendered text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharmapToken {
    /// Exact raw bytes consumed from input (opcode + operands for controls).
    pub bytes: Vec<u8>,
    /// Rendered UTF-8 text for this token.
    pub text: String,
    /// `true` if this token was matched by a [`CharmapControl`].
    pub is_control: bool,
}

/// Result of decoding a byte slice through a [`Charmap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharmapDecoded {
    /// Concatenated rendered UTF-8 text.
    pub text: String,
    /// Number of input bytes consumed (stops at the first terminating control).
    pub consumed: usize,
    /// `true` if decoding stopped at a control with `ends == true`.
    pub terminated: bool,
    /// Active page after the last decoded token.
    pub final_page: u8,
    /// Token stream preserving exact source bytes for lossless round-tripping.
    pub tokens: Vec<CharmapToken>,
}

#[derive(Debug, Clone, Default)]
struct ByteTrieNode {
    children: Vec<(u8, usize)>,
    entries: Vec<usize>,
    control: Option<usize>,
}

#[derive(Debug, Clone)]
struct ByteTrie {
    nodes: Vec<ByteTrieNode>,
}

impl ByteTrie {
    fn new() -> Self {
        Self {
            nodes: vec![ByteTrieNode::default()],
        }
    }

    fn insert_path(&mut self, key: &[u8]) -> usize {
        let mut node = 0;
        for &b in key {
            let next = match self.nodes[node]
                .children
                .binary_search_by_key(&b, |&(k, _)| k)
            {
                Ok(pos) => self.nodes[node].children[pos].1,
                Err(pos) => {
                    let id = self.nodes.len();
                    self.nodes.push(ByteTrieNode::default());
                    self.nodes[node].children.insert(pos, (b, id));
                    id
                }
            };
            node = next;
        }
        node
    }

    fn insert_entry(&mut self, key: &[u8], entry_index: usize) {
        let node = self.insert_path(key);
        self.nodes[node].entries.push(entry_index);
    }

    fn insert_control(&mut self, key: &[u8], control_index: usize) {
        let node = self.insert_path(key);
        self.nodes[node].control = Some(control_index);
    }

    fn longest_match(&self, bytes: &[u8], page: u8, entries: &[CharmapEntry]) -> Option<ByteMatch> {
        let mut node = 0;
        let mut best: Option<ByteMatch> = None;
        for (depth, &b) in bytes.iter().enumerate() {
            let Ok(pos) = self.nodes[node]
                .children
                .binary_search_by_key(&b, |&(k, _)| k)
            else {
                break;
            };
            node = self.nodes[node].children[pos].1;
            let n = &self.nodes[node];
            let len = depth + 1;
            if let Some(ctrl_idx) = n.control {
                best = Some(ByteMatch::Control {
                    index: ctrl_idx,
                    len,
                });
            } else if let Some(&entry_idx) = n
                .entries
                .iter()
                .find(|&&i| entries[i].page.is_none_or(|p| p == page))
            {
                best = Some(ByteMatch::Entry {
                    index: entry_idx,
                    len,
                });
            }
        }
        best
    }
}

#[derive(Debug, Clone, Copy)]
enum ByteMatch {
    Entry { index: usize, len: usize },
    Control { index: usize, len: usize },
}

#[derive(Debug, Clone, Default)]
struct TextTrieNode {
    children: Vec<(u8, usize)>,
    entry: Option<usize>,
    control: Option<usize>,
}

#[derive(Debug, Clone)]
struct TextTrie {
    nodes: Vec<TextTrieNode>,
}

impl TextTrie {
    fn new() -> Self {
        Self {
            nodes: vec![TextTrieNode::default()],
        }
    }

    fn insert_path(&mut self, key: &[u8]) -> usize {
        let mut node = 0;
        for &b in key {
            let next = match self.nodes[node]
                .children
                .binary_search_by_key(&b, |&(k, _)| k)
            {
                Ok(pos) => self.nodes[node].children[pos].1,
                Err(pos) => {
                    let id = self.nodes.len();
                    self.nodes.push(TextTrieNode::default());
                    self.nodes[node].children.insert(pos, (b, id));
                    id
                }
            };
            node = next;
        }
        node
    }

    fn insert_entry(&mut self, text: &str, entry_index: usize) {
        let node = self.insert_path(text.as_bytes());
        // Preserve definition order for ambiguous spellings.
        if self.nodes[node].entry.is_none() {
            self.nodes[node].entry = Some(entry_index);
        }
    }

    fn insert_control(&mut self, text: &str, control_index: usize) {
        let node = self.insert_path(text.as_bytes());
        if self.nodes[node].control.is_none() {
            self.nodes[node].control = Some(control_index);
        }
    }

    fn longest_match(&self, text: &str) -> Option<TextMatch> {
        let mut node = 0;
        let mut best: Option<TextMatch> = None;
        for (depth, &b) in text.as_bytes().iter().enumerate() {
            let Ok(pos) = self.nodes[node]
                .children
                .binary_search_by_key(&b, |&(k, _)| k)
            else {
                break;
            };
            node = self.nodes[node].children[pos].1;
            let n = &self.nodes[node];
            let len = depth + 1;
            if let Some(ctrl_idx) = n.control {
                best = Some(TextMatch::Control {
                    index: ctrl_idx,
                    len,
                });
            } else if let Some(entry_idx) = n.entry {
                best = Some(TextMatch::Entry {
                    index: entry_idx,
                    len,
                });
            }
        }
        best
    }
}

#[derive(Debug, Clone, Copy)]
enum TextMatch {
    Entry { index: usize, len: usize },
    Control { index: usize, len: usize },
}

#[derive(Debug, Clone)]
struct ParameterizedControl {
    index: usize,
    prefix: String,
    suffix: String,
}

/// Validated, compiled multi-byte character map backed by longest-match byte
/// and UTF-8 tries.
#[doc(alias = "tbl")]
#[derive(Debug, Clone)]
pub struct Charmap {
    initial_page: u8,
    entries: Vec<CharmapEntry>,
    controls: Vec<CharmapControl>,
    byte_trie: ByteTrie,
    text_trie: TextTrie,
    param_controls: Vec<ParameterizedControl>,
}

fn check_limit(resource: &'static str, requested: usize, limit: usize) -> Result<()> {
    if requested > limit {
        return Err(Error::ResourceLimit {
            resource,
            requested: requested as u64,
            limit: limit as u64,
        });
    }
    Ok(())
}

/// Parse an even-length hexadecimal string into 1..=16 raw bytes.
pub fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.is_empty() || hex.len() > 32 || !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return Err(Error::Malformed(format!(
            "charmap hex code must contain 1..=16 bytes: {hex:?}"
        )));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let hi = char::from(pair[0])
            .to_digit(16)
            .ok_or_else(|| Error::Malformed(format!("invalid hex digit in {hex:?}")))?;
        let lo = char::from(pair[1])
            .to_digit(16)
            .ok_or_else(|| Error::Malformed(format!("invalid hex digit in {hex:?}")))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Format raw bytes as lowercase hexadecimal.
#[must_use]
pub fn format_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0x0F) as usize]));
    }
    out
}

impl Charmap {
    /// Compile entries and controls with initial page `0` and default limits.
    pub fn new(entries: Vec<CharmapEntry>, controls: Vec<CharmapControl>) -> Result<Self> {
        Self::with_initial_page(0, entries, controls, CharmapLimits::default())
    }

    /// Compile entries and controls with an explicit initial page and resource
    /// limits.
    pub fn with_initial_page(
        initial_page: u8,
        entries: Vec<CharmapEntry>,
        controls: Vec<CharmapControl>,
        limits: CharmapLimits,
    ) -> Result<Self> {
        check_limit("charmap entries", entries.len(), limits.max_entries)?;
        check_limit("charmap controls", controls.len(), limits.max_controls)?;

        let mut seen_entry = BTreeSet::new();
        let mut code_pages = BTreeMap::<Vec<u8>, bool>::new();
        let mut seen_control = BTreeSet::new();
        let mut byte_trie = ByteTrie::new();
        let mut text_trie = TextTrie::new();
        let mut param_controls = Vec::new();

        for (index, entry) in entries.iter().enumerate() {
            if entry.bytes.is_empty() {
                return Err(Error::Malformed("charmap entry has empty byte key".into()));
            }
            check_limit("charmap key bytes", entry.bytes.len(), limits.max_key_bytes)?;
            if entry.text.is_empty() {
                return Err(Error::Malformed("charmap entry has empty text".into()));
            }
            check_limit(
                "charmap entry text bytes",
                entry.text.len(),
                limits.max_text_bytes,
            )?;
            if !seen_entry.insert((entry.page, entry.bytes.clone())) {
                return Err(Error::Malformed(format!(
                    "duplicate charmap entry for key {}",
                    format_hex_bytes(&entry.bytes)
                )));
            }
            if code_pages
                .get(&entry.bytes)
                .is_some_and(|global| *global || entry.page.is_none())
            {
                return Err(Error::Malformed(format!(
                    "global and page-specific charmap entries overlap for key {}",
                    format_hex_bytes(&entry.bytes)
                )));
            }
            code_pages.insert(entry.bytes.clone(), entry.page.is_none());

            byte_trie.insert_entry(&entry.bytes, index);
            text_trie.insert_entry(&entry.text, index);
            for alias in &entry.aliases {
                if alias.is_empty() {
                    return Err(Error::Malformed("charmap entry has empty alias".into()));
                }
                check_limit("charmap alias bytes", alias.len(), limits.max_text_bytes)?;
                text_trie.insert_entry(alias, index);
            }
        }

        for (index, ctrl) in controls.iter().enumerate() {
            if ctrl.bytes.is_empty() {
                return Err(Error::Malformed("charmap control has empty opcode".into()));
            }
            check_limit("charmap key bytes", ctrl.bytes.len(), limits.max_key_bytes)?;
            check_limit(
                "charmap control text bytes",
                ctrl.text.len(),
                limits.max_text_bytes,
            )?;
            check_limit("charmap control operand bytes", ctrl.arg_bytes, 256)?;
            if ctrl.text.matches("{args}").count() > 1 {
                return Err(Error::Malformed(
                    "charmap control template contains repeated {args} placeholder".into(),
                ));
            }
            if !seen_control.insert(ctrl.bytes.clone()) {
                return Err(Error::Malformed(format!(
                    "duplicate charmap control for opcode {}",
                    format_hex_bytes(&ctrl.bytes)
                )));
            }
            if code_pages.contains_key(&ctrl.bytes) {
                return Err(Error::Malformed(format!(
                    "charmap control overlaps entry key {}",
                    format_hex_bytes(&ctrl.bytes)
                )));
            }

            byte_trie.insert_control(&ctrl.bytes, index);
            if ctrl.arg_bytes == 0 {
                if !ctrl.text.is_empty() {
                    text_trie.insert_control(&ctrl.text, index);
                }
            } else {
                let (prefix, suffix) = if let Some((p, s)) = ctrl.text.split_once("{args}") {
                    (p.to_owned(), s.to_owned())
                } else if ctrl.text.is_empty() {
                    (String::new(), String::new())
                } else {
                    (format!("{}:", ctrl.text), String::new())
                };
                param_controls.push(ParameterizedControl {
                    index,
                    prefix,
                    suffix,
                });
            }
        }

        Ok(Self {
            initial_page,
            entries,
            controls,
            byte_trie,
            text_trie,
            param_controls,
        })
    }

    /// Parse a `.tbl` character-map definition using default limits.
    ///
    /// Supported line forms:
    /// - Blank lines and comments starting with `#`, `;`, or `//` are ignored.
    /// - `HEX=TEXT`: glyph or dictionary entry (`TEXT` is taken verbatim,
    ///   preserving spaces).
    /// - `/HEX=TEXT` or `/HEX`: terminating control code (`ends = true`).
    /// - `*HEX=TEXT` or `*HEX`: line-break control code (defaults to `"\n"`
    ///   when `TEXT` is omitted).
    /// - `$HEX[,N]=TEXT` or `@HEX[,N]=TEXT`: control code with `N` operand
    ///   bytes (defaults to `0`).
    pub fn from_tbl(source: &str) -> Result<Self> {
        Self::from_tbl_with_limits(source, CharmapLimits::default())
    }

    /// Parse a `.tbl` character-map definition with explicit resource limits.
    pub fn from_tbl_with_limits(source: &str, limits: CharmapLimits) -> Result<Self> {
        check_limit(
            "charmap .tbl input bytes",
            source.len(),
            limits.max_input_bytes,
        )?;
        let source = source.strip_prefix('\u{FEFF}').unwrap_or(source);
        let mut entries = Vec::new();
        let mut controls = Vec::new();

        for (line_no, raw_line) in source.lines().enumerate() {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
            {
                continue;
            }

            if let Some(rest) = line.strip_prefix('/') {
                let (hex, text) = match rest.split_once('=') {
                    Some((h, t)) => (h.trim(), t),
                    None => (rest.trim(), ""),
                };
                let bytes = parse_hex_bytes(hex).map_err(|_| {
                    Error::Malformed(format!("invalid terminator hex at line {}", line_no + 1))
                })?;
                controls.push(CharmapControl::terminator(bytes, text));
            } else if let Some(rest) = line.strip_prefix('*') {
                let (hex, text) = match rest.split_once('=') {
                    Some((h, t)) => (h.trim(), if t.is_empty() { "\n" } else { t }),
                    None => (rest.trim(), "\n"),
                };
                let bytes = parse_hex_bytes(hex).map_err(|_| {
                    Error::Malformed(format!(
                        "invalid newline control hex at line {}",
                        line_no + 1
                    ))
                })?;
                controls.push(CharmapControl::new(bytes, text));
            } else if let Some(rest) = line.strip_prefix('$').or_else(|| line.strip_prefix('@')) {
                let (lhs, text) = match rest.split_once('=') {
                    Some((h, t)) => (h.trim(), t),
                    None => (rest.trim(), ""),
                };
                let (hex, arg_bytes) = match lhs.split_once(',') {
                    Some((h, count)) => {
                        let n = count.trim().parse::<usize>().map_err(|_| {
                            Error::Malformed(format!(
                                "invalid control operand count at line {}",
                                line_no + 1
                            ))
                        })?;
                        (h.trim(), n)
                    }
                    None => (lhs, 0),
                };
                let bytes = parse_hex_bytes(hex).map_err(|_| {
                    Error::Malformed(format!("invalid control hex at line {}", line_no + 1))
                })?;
                controls.push(CharmapControl {
                    bytes,
                    text: text.to_owned(),
                    arg_bytes,
                    ends: false,
                    set_page: None,
                });
            } else if let Some((hex, text)) = line.split_once('=') {
                let bytes = parse_hex_bytes(hex.trim()).map_err(|_| {
                    Error::Malformed(format!("invalid entry hex at line {}", line_no + 1))
                })?;
                entries.push(CharmapEntry::new(bytes, text));
            } else {
                return Err(Error::Malformed(format!(
                    "expected HEX=TEXT at line {}",
                    line_no + 1
                )));
            }
        }

        Self::with_initial_page(0, entries, controls, limits)
    }

    /// Serialize global entries and controls to canonical `.tbl` text.
    #[must_use]
    pub fn to_tbl(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&format_hex_bytes(&entry.bytes).to_ascii_uppercase());
            out.push('=');
            out.push_str(&entry.text);
            out.push('\n');
        }
        for ctrl in &self.controls {
            let hex = format_hex_bytes(&ctrl.bytes).to_ascii_uppercase();
            if ctrl.ends && ctrl.arg_bytes == 0 {
                out.push('/');
                out.push_str(&hex);
                if !ctrl.text.is_empty() {
                    out.push('=');
                    out.push_str(&ctrl.text);
                }
            } else if !ctrl.ends && ctrl.arg_bytes == 0 && ctrl.text == "\n" {
                out.push('*');
                out.push_str(&hex);
            } else {
                out.push('$');
                out.push_str(&hex);
                if ctrl.arg_bytes > 0 {
                    out.push(',');
                    out.push_str(&ctrl.arg_bytes.to_string());
                }
                out.push('=');
                out.push_str(&ctrl.text);
            }
            out.push('\n');
        }
        out
    }

    /// Compiled glyph/string entries in definition order.
    #[must_use]
    pub fn entries(&self) -> &[CharmapEntry] {
        &self.entries
    }

    /// Compiled control rules in definition order.
    #[must_use]
    pub fn controls(&self) -> &[CharmapControl] {
        &self.controls
    }

    /// Initial active character page.
    #[must_use]
    pub const fn initial_page(&self) -> u8 {
        self.initial_page
    }

    /// Decode bytes using default limits.
    pub fn decode(&self, bytes: &[u8]) -> Result<CharmapDecoded> {
        self.decode_with_limits(bytes, CharmapLimits::default())
    }

    /// Decode bytes with explicit resource limits using longest-match trie
    /// lookup.
    pub fn decode_with_limits(
        &self,
        bytes: &[u8],
        limits: CharmapLimits,
    ) -> Result<CharmapDecoded> {
        check_limit(
            "charmap decode input bytes",
            bytes.len(),
            limits.max_input_bytes,
        )?;
        let mut pos = 0usize;
        let mut page = self.initial_page;
        let mut text = String::new();
        let mut tokens = Vec::new();
        let mut terminated = false;

        while pos < bytes.len() {
            check_limit(
                "charmap decode tokens",
                tokens.len().saturating_add(1),
                limits.max_tokens,
            )?;
            let matched = self
                .byte_trie
                .longest_match(&bytes[pos..], page, &self.entries)
                .ok_or_else(|| {
                    Error::Malformed(format!(
                        "unmapped charmap byte {:#04x} at offset {pos:#x}, page {page}",
                        bytes[pos]
                    ))
                })?;

            match matched {
                ByteMatch::Entry { index, len } => {
                    let entry = &self.entries[index];
                    check_limit(
                        "charmap decoded text bytes",
                        text.len().saturating_add(entry.text.len()),
                        limits.max_output_bytes,
                    )?;
                    text.push_str(&entry.text);
                    tokens.push(CharmapToken {
                        bytes: bytes[pos..pos + len].to_vec(),
                        text: entry.text.clone(),
                        is_control: false,
                    });
                    pos += len;
                }
                ByteMatch::Control { index, len } => {
                    let ctrl = &self.controls[index];
                    let total_len = len
                        .checked_add(ctrl.arg_bytes)
                        .ok_or_else(|| Error::Malformed("control length overflow".into()))?;
                    let end = pos
                        .checked_add(total_len)
                        .ok_or_else(|| Error::Malformed("control end offset overflow".into()))?;
                    if end > bytes.len() {
                        return Err(Error::Truncated {
                            offset: pos + len,
                            needed: ctrl.arg_bytes,
                            available: bytes.len().saturating_sub(pos + len),
                        });
                    }
                    let args = &bytes[pos + len..end];
                    let rendered = ctrl.render(args);
                    check_limit(
                        "charmap decoded text bytes",
                        text.len().saturating_add(rendered.len()),
                        limits.max_output_bytes,
                    )?;
                    text.push_str(&rendered);
                    tokens.push(CharmapToken {
                        bytes: bytes[pos..end].to_vec(),
                        text: rendered,
                        is_control: true,
                    });
                    pos = end;
                    if let Some(next_page) = ctrl.set_page {
                        page = next_page;
                    }
                    if ctrl.ends {
                        terminated = true;
                        break;
                    }
                }
            }
        }

        Ok(CharmapDecoded {
            text,
            consumed: pos,
            terminated,
            final_page: page,
            tokens,
        })
    }

    /// Encode UTF-8 text using default limits.
    pub fn encode(&self, text: &str) -> Result<Vec<u8>> {
        self.encode_with_limits(text, CharmapLimits::default())
    }

    /// Encode UTF-8 text with explicit resource limits using longest-match
    /// trie lookup.
    ///
    /// Automatically inserts silent page-switch controls when switching pages
    /// and appends a silent terminating control (`ends == true`, empty `text`,
    /// `arg_bytes == 0`) if the encoded stream is not already terminated.
    pub fn encode_with_limits(&self, text: &str, limits: CharmapLimits) -> Result<Vec<u8>> {
        check_limit(
            "charmap encode input bytes",
            text.len(),
            limits.max_input_bytes,
        )?;
        let mut out = Vec::new();
        let mut page = self.initial_page;
        let mut remaining = text;
        let mut token_count = 0usize;
        let mut terminated = false;

        while !remaining.is_empty() {
            token_count = token_count.saturating_add(1);
            check_limit("charmap encode tokens", token_count, limits.max_tokens)?;

            let mut best_len = 0usize;
            let mut best_bytes: Option<Vec<u8>> = None;
            let mut best_page: Option<u8> = None;
            let mut best_ends = false;

            if let Some(matched) = self.text_trie.longest_match(remaining) {
                match matched {
                    TextMatch::Entry { index, len } => {
                        let entry = &self.entries[index];
                        let mut chunk = Vec::new();
                        if let Some(target_page) = entry.page.filter(|&p| p != page) {
                            let switch = self
                                .controls
                                .iter()
                                .find(|c| {
                                    c.set_page == Some(target_page)
                                        && c.text.is_empty()
                                        && c.arg_bytes == 0
                                })
                                .ok_or_else(|| {
                                    Error::Malformed(format!(
                                        "charmap page {target_page} has no silent switch control"
                                    ))
                                })?;
                            chunk.extend_from_slice(&switch.bytes);
                        }
                        chunk.extend_from_slice(&entry.bytes);
                        best_len = len;
                        best_bytes = Some(chunk);
                        best_page = entry.page;
                    }
                    TextMatch::Control { index, len } => {
                        let ctrl = &self.controls[index];
                        best_len = len;
                        best_bytes = Some(ctrl.bytes.clone());
                        best_page = ctrl.set_page;
                        best_ends = ctrl.ends;
                    }
                }
            }

            for param in &self.param_controls {
                let ctrl = &self.controls[param.index];
                let Some(after_prefix) = remaining.strip_prefix(&param.prefix) else {
                    continue;
                };
                let hex_len = ctrl.arg_bytes * 2;
                let Some(hex_slice) = after_prefix.get(..hex_len) else {
                    continue;
                };
                let after_hex = &after_prefix[hex_len..];
                if !after_hex.starts_with(&param.suffix) {
                    continue;
                }
                let Ok(arg_bytes) = parse_hex_bytes(hex_slice) else {
                    continue;
                };
                let used = param.prefix.len() + hex_len + param.suffix.len();
                if used > best_len {
                    let mut chunk = Vec::with_capacity(ctrl.bytes.len() + arg_bytes.len());
                    chunk.extend_from_slice(&ctrl.bytes);
                    chunk.extend_from_slice(&arg_bytes);
                    best_len = used;
                    best_bytes = Some(chunk);
                    best_page = ctrl.set_page;
                    best_ends = ctrl.ends;
                }
            }

            let Some(chunk) = best_bytes else {
                let offset = text.len() - remaining.len();
                return Err(Error::Malformed(format!(
                    "unencodable charmap text at UTF-8 offset {offset}"
                )));
            };

            check_limit(
                "charmap encoded output bytes",
                out.len().saturating_add(chunk.len()),
                limits.max_output_bytes,
            )?;
            out.extend_from_slice(&chunk);
            if let Some(next_page) = best_page {
                page = next_page;
            }
            if best_ends {
                terminated = true;
            }
            remaining = &remaining[best_len..];
        }

        if !terminated {
            if let Some(end_ctrl) = self
                .controls
                .iter()
                .find(|c| c.ends && c.text.is_empty() && c.arg_bytes == 0)
            {
                check_limit(
                    "charmap encoded output bytes",
                    out.len().saturating_add(end_ctrl.bytes.len()),
                    limits.max_output_bytes,
                )?;
                out.extend_from_slice(&end_ctrl.bytes);
            }
        }

        Ok(out)
    }

    /// Re-assemble raw bytes from a token stream and validate that decoding
    /// reproduces the exact same token sequence without trailing bytes.
    pub fn encode_tokens(&self, tokens: &[CharmapToken], limits: CharmapLimits) -> Result<Vec<u8>> {
        check_limit("charmap encode tokens", tokens.len(), limits.max_tokens)?;
        let mut bytes = Vec::new();
        for token in tokens {
            check_limit(
                "charmap encoded output bytes",
                bytes.len().saturating_add(token.bytes.len()),
                limits.max_output_bytes,
            )?;
            bytes.extend_from_slice(&token.bytes);
        }
        let decoded = self.decode_with_limits(&bytes, limits)?;
        if decoded.consumed != bytes.len() || decoded.tokens != tokens {
            return Err(Error::Malformed(
                "token stream does not round-trip cleanly through charmap".into(),
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tbl_with_comments_multibyte_longest_match_and_controls() {
        let tbl = "\u{FEFF}\
# Comment line
; Semicolon comment
// Slash comment

00= 
01=A
02=B
0102=AB_WORD
8140=　
*FE
$F0,1=[COLOR:{args}]
/FF=[END]
";
        let map = Charmap::from_tbl(tbl).unwrap();
        let raw = [0x01, 0x02, 0x00, 0x01, 0xFE, 0xF0, 0x2A, 0xFF, 0x99];
        let decoded = map.decode(&raw).unwrap();
        assert_eq!(decoded.text, "AB_WORD A\n[COLOR:2a][END]");
        assert_eq!(decoded.consumed, 8);
        assert!(decoded.terminated);
        assert_eq!(decoded.tokens.len(), 6);
        assert!(decoded.tokens[3].is_control);
        assert!(decoded.tokens[4].is_control);
        assert!(decoded.tokens[5].is_control);

        // Round-trip encode -> decode.
        let encoded = map.encode(&decoded.text).unwrap();
        assert_eq!(encoded, &raw[..8]);
        assert_eq!(
            map.encode_tokens(&decoded.tokens, CharmapLimits::default())
                .unwrap(),
            &raw[..8]
        );

        // .tbl serialization round-trip.
        let serialized = map.to_tbl();
        let reparsed = Charmap::from_tbl(&serialized).unwrap();
        assert_eq!(reparsed.decode(&encoded).unwrap(), decoded);
    }

    #[test]
    fn silent_terminator_and_page_switching() {
        let entries = vec![
            CharmapEntry {
                bytes: vec![0x10],
                text: "a".into(),
                page: Some(0),
                aliases: vec!["alpha".into()],
            },
            CharmapEntry {
                bytes: vec![0x10],
                text: "b".into(),
                page: Some(1),
                aliases: vec![],
            },
        ];
        let controls = vec![
            CharmapControl {
                bytes: vec![0xF1],
                text: String::new(),
                arg_bytes: 0,
                ends: false,
                set_page: Some(1),
            },
            CharmapControl {
                bytes: vec![0xF0],
                text: String::new(),
                arg_bytes: 0,
                ends: false,
                set_page: Some(0),
            },
            CharmapControl::terminator(vec![0x00], ""),
        ];
        let map = Charmap::new(entries, controls).unwrap();

        let encoded = map.encode("alpha b".replace(' ', "").as_str()).unwrap();
        assert_eq!(encoded, vec![0x10, 0xF1, 0x10, 0x00]);

        let decoded = map.decode(&encoded).unwrap();
        assert_eq!(decoded.text, "ab");
        assert!(decoded.terminated);
        assert_eq!(decoded.final_page, 1);
        assert_eq!(decoded.consumed, 4);
    }

    #[test]
    fn longest_match_encoding_prefers_longer_spelling() {
        let map = Charmap::from_tbl("01=H\n02=He\n03=Hero\n").unwrap();
        assert_eq!(map.encode("HeroHeH").unwrap(), vec![0x03, 0x02, 0x01]);
    }

    #[test]
    fn rejects_invalid_tables_truncated_operands_and_limits() {
        assert!(Charmap::from_tbl("ZZ=bad").is_err());
        assert!(Charmap::from_tbl("01=").is_err());
        assert!(Charmap::from_tbl("01=A\n01=B\n").is_err());
        assert!(Charmap::from_tbl("01=A\n/01=[END]\n").is_err());
        assert!(Charmap::from_tbl("no_equals_sign").is_err());

        let map = Charmap::from_tbl("$F0,2=[WAIT:{args}]\n01=A\n").unwrap();
        assert!(matches!(
            map.decode(&[0xF0, 0x01]),
            Err(Error::Truncated {
                offset: 1,
                needed: 2,
                available: 1
            })
        ));
        assert!(map.decode(&[0x99]).is_err());
        assert!(map.encode("B").is_err());

        let tight = CharmapLimits {
            max_tokens: 1,
            ..CharmapLimits::default()
        };
        assert!(matches!(
            map.decode_with_limits(&[0x01, 0x01], tight),
            Err(Error::ResourceLimit { .. })
        ));
    }
}
