/// A typed format identifier shared by classifiers and dispatchers.
///
/// The classifier retains the public string tag on [`Id`] for serialization
/// compatibility, while dispatch code matches these constants instead of
/// repeating string literals. This makes a misspelled or renamed dispatch key
/// a compile-time-visible change at one shared API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FormatId(&'static str);

impl FormatId {
    pub const UNKNOWN: Self = Self("");

    /// Declare a decoder-owned static format identity.
    ///
    /// Construction is allocation-free and intentionally const. Catalog
    /// composition validates the lexical domain, so an owner crate can declare
    /// its identity without extending this crate's compatibility constant list.
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// Whether this is a composable format identity rather than [`Self::UNKNOWN`].
    ///
    /// Identities consist of lowercase ASCII alphanumeric components separated
    /// by `-` or `.`. Dots are retained for established names such as
    /// `image.raw` and `header.bin`; separators cannot lead, trail, or repeat.
    pub const fn is_valid(self) -> bool {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let mut index = 0;
        let mut previous_was_separator = true;
        while index < bytes.len() {
            let byte = bytes[index];
            let separator = byte == b'-' || byte == b'.';
            if separator {
                if previous_was_separator {
                    return false;
                }
            } else if !((byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9')) {
                return false;
            }
            previous_was_separator = separator;
            index += 1;
        }
        !previous_was_separator
    }

    pub const GZIP: Self = Self("gzip");
    pub const MIDI: Self = Self("midi");
    pub const PNG: Self = Self("png");
    pub const XML: Self = Self("xml");
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for FormatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The broad kind of a byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Category {
    /// A packed container with enumerable members.
    Archive,
    /// A compression codec (its output is usually itself an archive or asset).
    Compression,
    /// A still image / texture.
    Image,
    /// A video / FMV stream.
    Video,
    /// An audio stream or sound bank.
    Audio,
    /// A 3D model / geometry resource.
    Model,
    /// A glyph / font resource.
    Font,
    /// Human-readable text or markup.
    Text,
    /// An executable or code module.
    Executable,
    /// A disc image.
    Disc,
    /// A save / metadata blob.
    Save,
    /// Structured runtime data which is not itself a container or text asset.
    Data,
    /// Debug / symbol data.
    Debug,
    /// Nothing known matched (not proof the bytes are raw).
    Unknown,
}

impl Category {
    /// A short lowercase label (`"archive"`, `"image"`, …).
    pub fn label(self) -> &'static str {
        match self {
            Category::Archive => "archive",
            Category::Compression => "compression",
            Category::Image => "image",
            Category::Video => "video",
            Category::Audio => "audio",
            Category::Model => "model",
            Category::Font => "font",
            Category::Text => "text",
            Category::Executable => "executable",
            Category::Disc => "disc",
            Category::Save => "save",
            Category::Data => "data",
            Category::Debug => "debug",
            Category::Unknown => "unknown",
        }
    }
}

/// How the identification was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A leading (or fixed-offset) magic matched.
    Magic,
    /// A structural probe matched (no clean magic word).
    Structural,
}

/// The result of a composed catalog: category, a specific `format` tag, how it was found,
/// and which owner can decode it (`None` = recognized but no decoder yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Id {
    /// The broad category.
    pub category: Category,
    /// A specific format tag (`"synthetic-id-463fd14c2d8a"`, `"synthetic-id-ac5b24711344"`, `"bik"`); `""` when unknown.
    pub format: &'static str,
    /// Whether a magic or a structural probe matched.
    pub method: Method,
    /// An optional owner/decoder label; routing policy belongs to the product.
    pub opener: Option<&'static str>,
}

impl Id {
    pub const UNKNOWN: Id = Id {
        category: Category::Unknown,
        format: "",
        method: Method::Magic,
        opener: None,
    };

    /// Whether this is a packed archive (has members to enumerate).
    pub fn is_archive(&self) -> bool {
        self.category == Category::Archive
    }

    /// Whether an owner crate can decode it.
    pub fn has_decoder(&self) -> bool {
        self.opener.is_some()
    }

    /// The format tag as a typed dispatch key.
    pub fn format_id(&self) -> FormatId {
        // The legacy compatibility detector has a closed from_tag registry,
        // but a composed catalog may return an owner-declared static ID. Its
        // catalog has already checked the same lexical domain; do not panic
        // when such an owner identity reaches this public conversion.
        let id = FormatId::new(self.format);
        assert!(
            id == FormatId::UNKNOWN || id.is_valid(),
            "invalid format tag"
        );
        id
    }
}
