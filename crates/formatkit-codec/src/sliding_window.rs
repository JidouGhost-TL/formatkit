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
    if count == 0 {
        return Ok(());
    }

    out.reserve(count);
    let mut remaining = count;

    if distance > out.len() {
        let deficit = distance - out.len();
        let from_hist = deficit.min(remaining);
        let hist_start = history.len() - deficit;
        out.extend_from_slice(&history[hist_start..hist_start + from_hist]);
        remaining -= from_hist;
        if remaining == 0 {
            return Ok(());
        }
    }

    if distance == 1 {
        let byte = out[out.len() - 1];
        out.resize(out.len() + remaining, byte);
    } else if distance >= remaining {
        let start = out.len() - distance;
        out.extend_from_within(start..start + remaining);
    } else {
        let start = out.len() - distance;
        let mut copied = distance;
        out.extend_from_within(start..start + distance);
        while copied < remaining {
            let chunk = copied.min(remaining - copied);
            out.extend_from_within(start..start + chunk);
            copied += chunk;
        }
    }
    Ok(())
}

/// Find the longest sliding-window match ending before `pos` for `data[pos..]`.
///
/// Scans distances from `min_dist` up to `max_dist.min(pos)` and returns
/// `Some((distance, length))` for the longest match with
/// `min_len <= length <= max_len` (breaking ties in favor of the nearest
/// distance). Supports self-overlapping (RLE-style) matches where
/// `match_pos + k >= pos`.
///
/// Returns `None` if `pos >= data.len()`, `min_dist == 0`,
/// `min_dist > max_dist`, `min_len == 0`, `min_len > max_len`, or no candidate
/// reaches `min_len`.
pub fn find_longest_match(
    data: &[u8],
    pos: usize,
    min_dist: usize,
    max_dist: usize,
    min_len: usize,
    max_len: usize,
) -> Option<(usize, usize)> {
    if pos >= data.len()
        || min_dist == 0
        || min_dist > max_dist
        || min_len == 0
        || min_len > max_len
    {
        return None;
    }
    let avail = data.len() - pos;
    let limit = max_len.min(avail);
    if limit < min_len {
        return None;
    }
    let upper_dist = max_dist.min(pos);
    if upper_dist < min_dist {
        return None;
    }

    let mut best_dist = 0usize;
    let mut best_len = 0usize;

    for dist in min_dist..=upper_dist {
        let start = pos - dist;
        let mut len = 0usize;
        while len < limit && data[start + len] == data[pos + len] {
            len += 1;
        }
        if len >= min_len && len > best_len {
            best_dist = dist;
            best_len = len;
            if best_len == limit {
                break;
            }
        }
    }

    if best_len >= min_len {
        Some((best_dist, best_len))
    } else {
        None
    }
}

const HASH_BITS: usize = 14;
const HASH_SIZE: usize = 1 << HASH_BITS;
const HASH_MASK: usize = HASH_SIZE - 1;
const HASH_NONE: u32 = u32::MAX;

#[inline]
fn hash3(b0: u8, b1: u8, b2: u8) -> usize {
    let v = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
    ((v.wrapping_mul(0x1E35_A7BD)) >> (32 - HASH_BITS)) as usize & HASH_MASK
}

/// Hash-chain sliding-window match finder for LZ77/LZSS encoders.
///
/// Indexes 3-byte sequences in a caller-supplied input slice using a fixed-size
/// hash table and circular `prev` chain, accelerating longest-match queries
/// while preserving exact nearest-distance tie-breaking semantics identical to
/// [`find_longest_match`].
#[derive(Debug, Clone)]
pub struct HashMatcher {
    head: Vec<u32>,
    prev: Vec<u32>,
    window_mask: usize,
    max_dist: usize,
    inserted_up_to: usize,
}

impl HashMatcher {
    /// Create a match finder supporting back-reference distances up to `max_dist`.
    #[must_use]
    pub fn new(max_dist: usize) -> Self {
        let window_size = max_dist.max(1).next_power_of_two();
        Self {
            head: vec![HASH_NONE; HASH_SIZE],
            prev: vec![HASH_NONE; window_size],
            window_mask: window_size - 1,
            max_dist,
            inserted_up_to: 0,
        }
    }

    /// Reset all hash chains so the matcher can be reused on a new input buffer.
    pub fn reset(&mut self) {
        self.head.fill(HASH_NONE);
        self.prev.fill(HASH_NONE);
        self.inserted_up_to = 0;
    }

    /// Index a single position `pos` into the 3-byte hash chain.
    #[inline]
    pub fn insert(&mut self, data: &[u8], pos: usize) {
        if pos + 3 <= data.len() && pos < HASH_NONE as usize {
            let h = hash3(data[pos], data[pos + 1], data[pos + 2]);
            let slot = pos & self.window_mask;
            self.prev[slot] = self.head[h];
            self.head[h] = pos as u32;
        }
    }

    /// Index all positions in `self.inserted_up_to..pos` so queries at `pos`
    /// see every preceding 3-byte sequence in the window.
    #[inline]
    pub fn advance_to(&mut self, data: &[u8], pos: usize) {
        let target = pos.min(data.len().saturating_sub(2));
        while self.inserted_up_to < target {
            let p = self.inserted_up_to;
            self.insert(data, p);
            self.inserted_up_to += 1;
        }
        if self.inserted_up_to < pos {
            self.inserted_up_to = pos;
        }
    }

    /// Find the longest match ending before `pos` for `data[pos..]`, returning
    /// `Some((distance, length))` with exact nearest-distance tie-breaking.
    ///
    /// Automatically advances the internal hash index up to `pos`. For
    /// `min_len < 3` or inputs exceeding `u32::MAX - 1` bytes, falls back to
    /// [`find_longest_match`].
    pub fn find_longest_match(
        &mut self,
        data: &[u8],
        pos: usize,
        min_dist: usize,
        min_len: usize,
        max_len: usize,
    ) -> Option<(usize, usize)> {
        if pos >= data.len()
            || min_dist == 0
            || min_dist > self.max_dist
            || min_len == 0
            || min_len > max_len
        {
            return None;
        }
        if min_len < 3 || data.len() >= HASH_NONE as usize {
            return find_longest_match(data, pos, min_dist, self.max_dist, min_len, max_len);
        }
        let avail = data.len() - pos;
        let limit = max_len.min(avail);
        if limit < min_len {
            return None;
        }
        let upper_dist = self.max_dist.min(pos);
        if upper_dist < min_dist {
            return None;
        }

        self.advance_to(data, pos);

        let min_cand = pos - upper_dist;
        let b0 = data[pos];
        let b1 = data[pos + 1];
        let b2 = data[pos + 2];
        let h = hash3(b0, b1, b2);

        let mut best_dist = 0usize;
        let mut best_len = 0usize;
        let mut cur = self.head[h];

        while cur != HASH_NONE {
            let cand = cur as usize;
            if cand < min_cand {
                break;
            }
            let dist = pos - cand;
            if dist >= min_dist
                && (best_len < min_len || data[cand + best_len] == data[pos + best_len])
                && data[cand] == b0
                && data[cand + 1] == b1
                && data[cand + 2] == b2
            {
                let mut len = 3usize;
                while len + 8 <= limit
                    && data[cand + len..cand + len + 8] == data[pos + len..pos + len + 8]
                {
                    len += 8;
                }
                while len < limit && data[cand + len] == data[pos + len] {
                    len += 1;
                }
                if len >= min_len && len > best_len {
                    best_dist = dist;
                    best_len = len;
                    if best_len == limit {
                        break;
                    }
                }
            }
            let next = self.prev[cand & self.window_mask];
            if next >= cur {
                break;
            }
            cur = next;
        }

        if best_len >= min_len {
            Some((best_dist, best_len))
        } else {
            None
        }
    }
}

/// Fixed-capacity circular history buffer for ring-buffer LZSS codecs.
///
/// The caller owns the initial fill byte, initial write cursor, and stream
/// framing. Copies wrap modulo `N` and write each copied byte back through the
/// write cursor, naturally supporting overlapping self-copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingBuffer<const N: usize> {
    buf: [u8; N],
    cursor: usize,
}

impl<const N: usize> RingBuffer<N> {
    /// Create a ring buffer prefilled with `fill` and positioned at `init_cursor % N`.
    ///
    /// Panics if `N == 0`.
    #[must_use]
    pub const fn new(fill: u8, init_cursor: usize) -> Self {
        assert!(N > 0, "ring buffer capacity must be nonzero");
        Self {
            buf: [fill; N],
            cursor: init_cursor % N,
        }
    }

    /// Write one byte at the current cursor and advance the cursor modulo `N`.
    #[inline]
    pub fn push(&mut self, byte: u8) {
        self.buf[self.cursor] = byte;
        self.cursor = (self.cursor + 1) % N;
    }

    /// Copy `len` bytes starting at `pos % N`, writing each byte both into this
    /// ring buffer (advancing the cursor) and into `out`, while enforcing
    /// `out.len() + len <= max_output`.
    ///
    /// If `out.len() + len > max_output`, returns `Err(MatchError::OutputLimit)`
    /// without mutating either `self` or `out`.
    pub fn copy_match(
        &mut self,
        pos: usize,
        len: usize,
        out: &mut Vec<u8>,
        max_output: usize,
    ) -> Result<(), MatchError> {
        if out
            .len()
            .checked_add(len)
            .is_none_or(|end| end > max_output)
        {
            return Err(MatchError::OutputLimit);
        }
        let mut read_pos = pos % N;
        for _ in 0..len {
            let byte = self.buf[read_pos];
            read_pos = (read_pos + 1) % N;
            self.push(byte);
            out.push(byte);
        }
        Ok(())
    }

    /// Return the current write cursor index (`0..N`).
    #[inline]
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Borrow the underlying fixed-size ring array.
    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        &self.buf
    }
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

    #[test]
    fn find_longest_match_handles_overlap_ties_and_bounds() {
        // Self-overlapping RLE-style match at distance 1.
        assert_eq!(
            find_longest_match(b"aaaaaaa", 1, 1, 16, 2, 10),
            Some((1, 6))
        );
        // Self-overlapping periodic pattern at distance 2.
        assert_eq!(
            find_longest_match(b"abababab", 2, 1, 16, 2, 10),
            Some((2, 6))
        );
        // Tie-breaking prefers nearest (smallest) distance.
        // At pos=8 ("abc"), matches exist at pos=4 (dist=4) and pos=0 (dist=8).
        assert_eq!(
            find_longest_match(b"abcXabcYabc", 8, 1, 16, 3, 10),
            Some((4, 3))
        );
        // Longer farther match beats shorter nearer match.
        assert_eq!(
            find_longest_match(b"abcdXabYabcd", 8, 1, 16, 2, 10),
            Some((8, 4))
        );
        // Respects max_len cap and min_dist floor.
        assert_eq!(find_longest_match(b"aaaaaaa", 1, 1, 16, 2, 4), Some((1, 4)));
        assert_eq!(
            find_longest_match(b"aaaaaaa", 2, 2, 16, 2, 10),
            Some((2, 5))
        );
        // Invalid or empty bounds return None.
        assert_eq!(find_longest_match(b"aaaa", 4, 1, 4, 1, 4), None);
        assert_eq!(find_longest_match(b"aaaa", 2, 0, 4, 1, 4), None);
        assert_eq!(find_longest_match(b"aaaa", 2, 5, 4, 1, 4), None);
        assert_eq!(find_longest_match(b"aaaa", 2, 1, 4, 0, 4), None);
        assert_eq!(find_longest_match(b"aaaa", 2, 1, 4, 5, 4), None);
        assert_eq!(find_longest_match(b"abcdef", 3, 1, 3, 2, 4), None);
    }

    #[test]
    fn ring_buffer_wrap_around_and_initial_fill() {
        let mut ring = RingBuffer::<8>::new(0x20, 6);
        assert_eq!(ring.cursor(), 6);
        assert_eq!(ring.as_slice(), &[0x20; 8]);

        let mut out = Vec::new();
        // Push 4 bytes across the wrap-around boundary (indices 6, 7, 0, 1).
        for &b in b"ABCD" {
            ring.push(b);
            out.push(b);
        }
        assert_eq!(ring.cursor(), 2);
        assert_eq!(ring.as_slice(), b"CD    AB");

        // Copy 6 bytes starting at index 4 ("  ABCD") reading initial fill and wrapping across end of ring.
        ring.copy_match(4, 6, &mut out, 16).unwrap();
        assert_eq!(out, b"ABCD  ABCD");
        assert_eq!(ring.cursor(), 0);
    }

    #[test]
    fn ring_buffer_overlapping_self_copy_and_output_limit() {
        let mut ring = RingBuffer::<16>::new(0x00, 0);
        let mut out = Vec::new();

        // Seed 2 bytes "XY" at positions 0 and 1 (cursor = 2).
        ring.push(b'X');
        ring.push(b'Y');
        out.extend_from_slice(b"XY");

        // Overlapping periodic self-copy from pos=0 for 6 bytes -> "XYXYXY".
        ring.copy_match(0, 6, &mut out, 8).unwrap();
        assert_eq!(out, b"XYXYXYXY");
        assert_eq!(ring.cursor(), 8);

        // Output limit exceeded leaves both ring and output unchanged.
        let snapshot_ring = ring.clone();
        let snapshot_out = out.clone();
        assert_eq!(
            ring.copy_match(0, 1, &mut out, 8),
            Err(MatchError::OutputLimit)
        );
        assert_eq!(
            ring.copy_match(0, usize::MAX, &mut out, usize::MAX),
            Err(MatchError::OutputLimit)
        );
        assert_eq!(ring, snapshot_ring);
        assert_eq!(out, snapshot_out);
    }

    #[test]
    #[should_panic(expected = "ring buffer capacity must be nonzero")]
    fn ring_buffer_zero_capacity_panics() {
        let _ = RingBuffer::<0>::new(0, 0);
    }

    #[test]
    fn hash_matcher_matches_brute_force_exactly() {
        let mut data = b"abcXabcYabcZ_PATTERN_1234_".repeat(8);
        data.extend(std::iter::repeat_n(0xAA, 40));
        data.extend_from_slice(b"abababababababab");
        let mut state = 0x1234_5678u32;
        for _ in 0..512 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push(((state >> 24) as u8) % 6);
        }

        for min_dist in [1, 2, 3, 16] {
            let mut matcher = HashMatcher::new(256);
            for pos in 0..data.len() {
                let expected = find_longest_match(&data, pos, min_dist, 256, 3, 18);
                let got = matcher.find_longest_match(&data, pos, min_dist, 3, 18);
                assert_eq!(got, expected, "mismatch at pos={pos}, min_dist={min_dist}");
            }
            matcher.reset();
            assert_eq!(
                matcher.find_longest_match(&data, 10, min_dist, 3, 18),
                find_longest_match(&data, 10, min_dist, 256, 3, 18)
            );
        }
    }

    #[test]
    fn append_match_fast_paths_match_byte_by_byte() {
        // Non-overlapping copy (distance >= count)
        let mut out = b"ABCDEFGH".to_vec();
        append_match(&mut out, b"", 6, 4, 16).unwrap();
        assert_eq!(out, b"ABCDEFGHCDEF");

        // Overlapping periodic copy (1 < distance < count)
        let mut out = b"XY".to_vec();
        append_match(&mut out, b"", 2, 7, 16).unwrap();
        assert_eq!(out, b"XYXYXYXYX");

        // Zero-length match is a no-op
        let mut out = b"A".to_vec();
        append_match(&mut out, b"", 1, 0, 1).unwrap();
        assert_eq!(out, b"A");
    }
}
