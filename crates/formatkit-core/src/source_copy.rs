//! Bounded sequential transfer into an executor-owned writer.

use std::io::Write;

use crate::{Error, RangeSource, SourceRange, WorkBudget, WorkResource};

#[derive(Debug, thiserror::Error)]
pub enum SourceCopyError {
    #[error(transparent)]
    Source(#[from] Error),
    #[error("source copy requires a nonempty transfer buffer")]
    EmptyBuffer,
    #[error("source copy cancelled")]
    Cancelled,
    #[error("write copied source: {0}")]
    Write(#[source] std::io::Error),
}

fn check_cancelled(
    budget: &mut WorkBudget,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<(), SourceCopyError> {
    // Preserve the public callback's established call order and error variant.
    if cancelled() {
        return Err(SourceCopyError::Cancelled);
    }
    match budget.check_cancelled() {
        Ok(()) => Ok(()),
        Err(Error::Cancelled) => Err(SourceCopyError::Cancelled),
        Err(error) => Err(SourceCopyError::Source(error)),
    }
}

/// Copy a source range with bounded working memory and explicit cancellation.
///
/// Errors can leave a partial destination. The caller owns staging/publication.
/// Output bytes count successful writes; a chunk's full remaining output is
/// admitted before reading it. Source reads retain admitted charges on failure.
/// The source is revalidated before and after a successful copy. This method
/// checks the legacy callback before the budget's cooperative token at each
/// established interruption point; either reports [`SourceCopyError::Cancelled`].
/// Empty-buffer and invalid-range validation retain precedence over
/// cancellation. This method does not flush, sync, hash, or publish the
/// destination.
pub fn copy_source_range(
    source: &dyn RangeSource,
    range: SourceRange,
    output: &mut impl Write,
    buffer: &mut [u8],
    budget: &mut WorkBudget,
    mut cancelled: impl FnMut() -> bool,
) -> Result<u64, SourceCopyError> {
    if buffer.is_empty() {
        return Err(SourceCopyError::EmptyBuffer);
    }
    if range.end()? > source.size() {
        return Err(Error::Malformed("copy range exceeds source".into()).into());
    }
    check_cancelled(budget, &mut cancelled)?;
    // Reject a known oversized operation before source reads or destination writes.
    budget.check(WorkResource::OutputBytes, range.length)?;
    source.verify_unchanged()?;
    let mut copied = 0u64;
    while copied < range.length {
        check_cancelled(budget, &mut cancelled)?;
        let length = (range.length - copied).min(buffer.len() as u64) as usize;
        let bytes = &mut buffer[..length];
        source.read_exact_into(range.start + copied, bytes, budget)?;
        let mut remaining: &[u8] = bytes;
        while !remaining.is_empty() {
            check_cancelled(budget, &mut cancelled)?;
            match output.write(remaining) {
                Ok(0) => return Err(SourceCopyError::Write(std::io::ErrorKind::WriteZero.into())),
                Ok(written) if written <= remaining.len() => {
                    budget.charge(WorkResource::OutputBytes, written as u64)?;
                    copied += written as u64;
                    remaining = &remaining[written..];
                }
                Ok(_) => {
                    return Err(SourceCopyError::Write(std::io::Error::other(
                        "writer returned oversized count",
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(SourceCopyError::Write(error)),
            }
        }
    }
    check_cancelled(budget, &mut cancelled)?;
    source.verify_unchanged()?;
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, MemoryRangeSource, WorkLimits};

    struct FailsAfter {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for FailsAfter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() == self.limit {
                return Err(std::io::Error::other("injected"));
            }
            let n = bytes.len().min(2).min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_writes_count_only_completed_bytes_and_keep_read_work() {
        let source = MemoryRangeSource::new(b"abcdefgh".to_vec(), "test");
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let mut writer = FailsAfter {
            bytes: Vec::new(),
            limit: 5,
        };
        assert!(copy_source_range(
            &source,
            SourceRange::new(0, 8),
            &mut writer,
            &mut [0; 4],
            &mut budget,
            || false
        )
        .is_err());
        assert_eq!(writer.bytes, b"abcde");
        assert_eq!(budget.spent(WorkResource::OutputBytes), 5);
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 8);
    }

    #[test]
    fn limits_and_cancellation_prevent_unapproved_output() {
        let source = MemoryRangeSource::new(b"abcdefgh".to_vec(), "test");
        let mut budget =
            WorkBudget::new(WorkLimits::unlimited().with(WorkResource::OutputBytes, 7));
        let mut output = Vec::new();
        assert!(copy_source_range(
            &source,
            SourceRange::new(0, 8),
            &mut output,
            &mut [0; 3],
            &mut budget,
            || false
        )
        .is_err());
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 0);
        assert!(output.is_empty());
        assert!(matches!(
            copy_source_range(
                &source,
                SourceRange::new(0, 7),
                &mut output,
                &mut [0; 3],
                &mut budget,
                || true
            ),
            Err(SourceCopyError::Cancelled)
        ));
        copy_source_range(
            &source,
            SourceRange::new(1, 7),
            &mut output,
            &mut [0; 3],
            &mut budget,
            || false,
        )
        .unwrap();
        assert_eq!(output, b"bcdefgh");
    }

    #[test]
    fn work_token_uses_the_existing_copy_cancellation_error_and_stays_observable() {
        let source = MemoryRangeSource::new(b"abcdefgh".to_vec(), "test");
        let token = CancellationToken::new();
        token.cancel();
        let mut budget = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token.clone());
        let mut output = Vec::new();
        assert!(matches!(
            copy_source_range(
                &source,
                SourceRange::new(0, 8),
                &mut output,
                &mut [],
                &mut budget,
                || false,
            ),
            Err(SourceCopyError::EmptyBuffer)
        ));
        assert!(matches!(
            copy_source_range(
                &source,
                SourceRange::new(0, 9),
                &mut output,
                &mut [0; 4],
                &mut budget,
                || false,
            ),
            Err(SourceCopyError::Source(Error::Malformed(message)))
                if message == "copy range exceeds source"
        ));
        let mut callback_calls = 0;
        assert!(matches!(
            copy_source_range(
                &source,
                SourceRange::new(0, 8),
                &mut output,
                &mut [0; 4],
                &mut budget,
                || {
                    callback_calls += 1;
                    false
                },
            ),
            Err(SourceCopyError::Cancelled)
        ));
        assert_eq!(callback_calls, 1, "legacy callback keeps precedence");
        assert!(output.is_empty());
        assert_eq!(budget.spent(WorkResource::LogicalReadBytes), 0);
        assert!(budget.cancellation_requested());
        assert!(budget.cancellation_observed());
    }
}
