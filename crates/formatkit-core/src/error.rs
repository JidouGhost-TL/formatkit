use thiserror::Error;

/// One structured frame describing where a leaf parse/decode error occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorContext {
    /// A format decoder or encoder, such as `TIM`.
    Format(&'static str),
    /// A component within a format, such as a CLUT or packet table.
    Component(&'static str),
    /// An archive member, optionally including its stored name.
    ArchiveMember { index: usize, name: Option<String> },
    /// A zero-based record within a table or stream.
    Record { index: usize },
    /// A named field within the current format/component/record. `offset` uses
    /// that frame's current source or record coordinate space.
    Field { name: &'static str, offset: u64 },
    /// A source-relative byte range involved in the failed operation.
    SourceRange { offset: u64, length: u64 },
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(format) | Self::Component(format) => f.write_str(format),
            Self::ArchiveMember {
                index,
                name: Some(name),
            } => write!(f, "archive member {index} ({name})"),
            Self::ArchiveMember { index, name: None } => write!(f, "archive member {index}"),
            Self::Record { index } => write!(f, "record {index}"),
            Self::Field { name, offset } => write!(f, "{name} at {offset:#x}"),
            Self::SourceRange { offset, length } => {
                write!(f, "source range {offset:#x}+{length:#x}")
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// A typed leaf error with one additional location frame.
    #[error("{frame}: {source}")]
    Context {
        frame: ErrorContext,
        #[source]
        source: Box<Error>,
    },
    #[error("unexpected end of input: needed {needed} byte(s) at offset {offset}, {available} available")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    /// A `u64` range requested from a [`RangeSource`](crate::RangeSource) lies
    /// outside that source. Unlike [`Self::Truncated`], this retains the source
    /// coordinate width even on 32-bit hosts.
    #[error("source range {offset:#x}+{length:#x} lies outside source size {source_size:#x}")]
    SourceRangeOutside {
        offset: u64,
        length: u64,
        source_size: u64,
    },
    /// An external source no longer names the immutable snapshot opened by the
    /// caller.
    #[error("source identity changed: {identity}")]
    SourceIdentityChanged { identity: String },
    /// A cooperative cancellation token was observed at an explicit check.
    #[error("operation cancelled")]
    Cancelled,
    #[error("bad magic at offset {offset}: expected {expected:#x}, found {found:#x}")]
    BadMagic {
        offset: usize,
        expected: u32,
        found: u32,
    },
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The surrounding format family is valid, but this decoder deliberately
    /// implements a narrower dialect. This is distinct from malformed input.
    #[error("unsupported {family} dialect: {dialect}")]
    UnsupportedDialect {
        family: &'static str,
        dialect: &'static str,
    },
    #[error("invalid field {what}: {value}")]
    InvalidField { what: &'static str, value: u64 },
    #[error("resource limit exceeded for {resource}: requested {requested}, limit {limit}")]
    /// A valid-looking input requested more of a bounded resource than the
    /// caller's explicit policy permits.
    ResourceLimit {
        resource: &'static str,
        requested: u64,
        limit: u64,
    },
    #[error("{0} trailing byte(s) after structure")]
    Trailing(usize),
    #[error("{0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Attach one outer structured context frame while preserving the typed
    /// source error.
    pub fn context(self, frame: ErrorContext) -> Self {
        Self::Context {
            frame,
            source: Box::new(self),
        }
    }

    /// The original typed error below every context frame.
    pub fn leaf(&self) -> &Self {
        let mut error = self;
        while let Self::Context { source, .. } = error {
            error = source;
        }
        error
    }

    /// Structured frames from outermost to innermost.
    pub fn contexts(&self) -> impl Iterator<Item = &ErrorContext> {
        std::iter::successors(Some(self), |error| match error {
            Self::Context { source, .. } => Some(source.as_ref()),
            _ => None,
        })
        .filter_map(|error| match error {
            Self::Context { frame, .. } => Some(frame),
            _ => None,
        })
    }
}

/// Add structured context to a `formatkit-core` result without stringifying its
/// original error.
pub trait ResultExt<T> {
    fn with_context(self, frame: ErrorContext) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T> {
    fn with_context(self, frame: ErrorContext) -> Result<T> {
        self.map_err(|error| error.context(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_render() {
        let e = Error::Truncated {
            offset: 4,
            needed: 2,
            available: 1,
        };
        assert_eq!(
            e.to_string(),
            "unexpected end of input: needed 2 byte(s) at offset 4, 1 available"
        );
        let m = Error::BadMagic {
            offset: 0,
            expected: 0x10,
            found: 0x20,
        };
        assert_eq!(
            m.to_string(),
            "bad magic at offset 0: expected 0x10, found 0x20"
        );
        assert_eq!(Error::Cancelled.to_string(), "operation cancelled");
    }

    #[test]
    fn context_preserves_frames_and_typed_leaf() {
        let error = Error::Truncated {
            offset: 12,
            needed: 4,
            available: 1,
        }
        .context(ErrorContext::Component("CLUT"))
        .context(ErrorContext::Format("TIM"));

        assert_eq!(
            error.to_string(),
            "TIM: CLUT: unexpected end of input: needed 4 byte(s) at offset 12, 1 available"
        );
        assert_eq!(
            error.contexts().collect::<Vec<_>>(),
            vec![
                &ErrorContext::Format("TIM"),
                &ErrorContext::Component("CLUT")
            ]
        );
        assert!(matches!(error.leaf(), Error::Truncated { offset: 12, .. }));
    }

    #[test]
    fn structured_record_field_and_source_range_frames_render_in_order() {
        let error = Error::SourceRangeOutside {
            offset: 0x1_0000_0000,
            length: 0x20,
            source_size: 0x100,
        }
        .context(ErrorContext::SourceRange {
            offset: 0x1_0000_0000,
            length: 0x20,
        })
        .context(ErrorContext::Field {
            name: "payload",
            offset: 0x1_0000_0000,
        })
        .context(ErrorContext::Record { index: 7 });

        assert_eq!(
            error.to_string(),
            "record 7: payload at 0x100000000: source range 0x100000000+0x20: source range 0x100000000+0x20 lies outside source size 0x100"
        );
        assert!(matches!(
            error.leaf(),
            Error::SourceRangeOutside {
                offset: 0x1_0000_0000,
                length: 0x20,
                source_size: 0x100,
            }
        ));
    }
}
