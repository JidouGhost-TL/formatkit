//! Format-neutral services for existing mounted namespaces.
//!
//! Format owners supply namespaces and resolution; callers supply destinations,
//! policy, transfer buffers, and one shared work ledger.
#![forbid(unsafe_code)]

use std::io::Write;

use formatkit_core::{
    copy_source_range, IndexedNamespace, MemberLayout, MountedMember, SourceCopyError, SourceRange,
    WorkBudget,
};

mod walk;
pub use formatkit_core::MountedMembers;
pub use walk::{
    walk, Resolution, ResolutionVisitor, Resolver, WalkControl, WalkEvent, WalkOptions,
};

/// Exact selection never silently chooses between duplicate names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    #[error("member index {0} is outside the namespace")]
    IndexOutside(usize),
    #[error("member name was not found")]
    NameMissing,
    #[error("member name is ambiguous (indices {first} and {second})")]
    AmbiguousName { first: usize, second: usize },
}

/// Validate an index without constructing another member object model.
pub fn select_index(
    namespace: &dyn IndexedNamespace,
    index: usize,
) -> Result<usize, SelectionError> {
    if index < namespace.len() {
        Ok(index)
    } else {
        Err(SelectionError::IndexOutside(index))
    }
}

/// Select an exact UTF-8 display name, including the empty name. Raw names and
/// owner-specific normalization remain accessible through the namespace.
///
/// ```
/// use formatkit_archive::{select_name, SelectionError};
/// use formatkit_core::IndexedNamespace;
/// fn select(namespace: &dyn IndexedNamespace) -> Result<usize, SelectionError> {
///     select_name(namespace, "payload")
/// }
/// ```
pub fn select_name(namespace: &dyn IndexedNamespace, name: &str) -> Result<usize, SelectionError> {
    let mut matches = namespace
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(i, entry)| (entry.name.as_deref() == Some(name)).then_some(i));
    let first = matches.next().ok_or(SelectionError::NameMissing)?;
    match matches.next() {
        Some(second) => Err(SelectionError::AmbiguousName { first, second }),
        None => Ok(first),
    }
}

/// Explicit byte selection; semantic views never affect extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionMode {
    Stored,
    Content { max_output_len: u64 },
}

/// A completed transfer, preserving the owner's member layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionReceipt {
    pub bytes_written: u64,
    pub layout: MemberLayout,
    pub mode: ExtractionMode,
}

/// Stream a member to the caller's sink with exact partial-write accounting.
///
/// Uses the canonical source-copy implementation, including source revalidation,
/// cancellation and short-write handling. The caller's transfer buffer is not
/// allocated or retained here. This function does not flush or publish output.
pub fn extract(
    member: MountedMember<'_>,
    mode: ExtractionMode,
    output: &mut impl Write,
    buffer: &mut [u8],
    budget: &mut WorkBudget,
) -> Result<ExtractionReceipt, SourceCopyError> {
    if buffer.is_empty() {
        return Err(SourceCopyError::EmptyBuffer);
    }
    budget.check_cancelled()?;
    let layout = member.layout()?;
    let source = match mode {
        ExtractionMode::Stored => member.stored_source()?,
        ExtractionMode::Content { max_output_len } => {
            if let Some(size) = layout.content_size {
                if size > max_output_len {
                    return Err(formatkit_core::Error::ResourceLimit {
                        resource: "member content bytes",
                        requested: size,
                        limit: max_output_len,
                    }
                    .into());
                }
                budget.check(formatkit_core::WorkResource::OutputBytes, size)?;
            }
            let content = member.namespace().validated_content_source_with_work(
                member.index(),
                max_output_len,
                budget,
            )?;
            if content.source.size() > max_output_len {
                return Err(formatkit_core::Error::ResourceLimit {
                    resource: "member content bytes",
                    requested: content.source.size(),
                    limit: max_output_len,
                }
                .into());
            }
            content.source
        }
    };
    let bytes_written = copy_source_range(
        source.as_ref(),
        SourceRange::new(0, source.size()),
        output,
        buffer,
        budget,
        || false,
    )?;
    Ok(ExtractionReceipt {
        bytes_written,
        layout,
        mode,
    })
}
