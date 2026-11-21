//! Bounded overlapping copies for codecs with explicit linear history.

/// Copy a bounded byte match from explicit history and overlapping output.
/// The caller chooses the count and owns stream framing and final-token policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchError {
    /// A nonzero distance did not resolve to retained history.
    Distance,
    /// The complete match would exceed the supplied output limit.
    OutputLimit,
}

impl core::fmt::Display for MatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Distance => write!(f, "sliding-window match distance out of range"),
            Self::OutputLimit => write!(f, "sliding-window match exceeds output limit"),
        }
    }
}

impl std::error::Error for MatchError {}

/// Append `count` bytes copied from `distance` bytes back in `history || out`,
/// supporting overlapping copies (such as `distance == 1` RLE-like runs) while
/// enforcing `out.len() + count <= limit`.
pub fn append_match(
    out: &mut Vec<u8>,
    history: &[u8],
    distance: usize,
    count: usize,
    limit: usize,
) -> Result<(), MatchError> {
    if out.len().checked_add(count).is_none_or(|end| end > limit) {
        return Err(MatchError::OutputLimit);
    }
    if distance == 0 || distance.saturating_sub(out.len()) > history.len() {
        return Err(MatchError::Distance);
    }
    for _ in 0..count {
        let byte = if let Some(index) = out.len().checked_sub(distance) {
            out[index]
        } else {
            history[history.len() - (distance - out.len())]
        };
        out.push(byte);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_and_explicit_history_transition() {
        let mut out = b"D".to_vec();
        append_match(&mut out, b"ABC", 3, 7, 8).unwrap();
        assert_eq!(out, b"DBCDBCDB");

        let mut out = b"z".to_vec();
        append_match(&mut out, b"", 1, 4, 5).unwrap();
        assert_eq!(out, b"zzzzz");
    }

    #[test]
    fn errors_leave_output_unchanged() {
        let mut out = b"x".to_vec();
        assert_eq!(
            append_match(&mut out, b"", 0, 1, 5),
            Err(MatchError::Distance)
        );
        assert_eq!(
            append_match(&mut out, b"a", 3, 1, 5),
            Err(MatchError::Distance)
        );
        assert_eq!(
            append_match(&mut out, b"", 1, 5, 5),
            Err(MatchError::OutputLimit)
        );
        assert_eq!(
            append_match(&mut out, b"", 1, usize::MAX, usize::MAX),
            Err(MatchError::OutputLimit)
        );
        assert_eq!(out, b"x");
    }
}
