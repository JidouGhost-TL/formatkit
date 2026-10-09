//! Allocation-free, policy-neutral primitive-topology iterators.
//!
//! These preserve caller index values and emit degenerates. Restart markers,
//! filtering, stored-vs-derived authority, and output index widths remain with
//! each format owner.

/// Expand an alternating-winding triangle strip.
pub fn triangle_strip<I>(indices: I) -> impl Iterator<Item = [I::Item; 3]>
where
    I: IntoIterator,
    I::Item: Copy,
{
    let mut previous = [None, None];
    let mut odd = false;
    indices.into_iter().filter_map(move |next| {
        let triangle = match previous {
            [None, None] => {
                previous[0] = Some(next);
                return None;
            }
            [Some(_), None] => {
                previous[1] = Some(next);
                return None;
            }
            [Some(a), Some(b)] => {
                previous = [Some(b), Some(next)];
                if odd {
                    [b, a, next]
                } else {
                    [a, b, next]
                }
            }
            [None, Some(_)] => unreachable!("second strip index cannot precede the first"),
        };
        odd = !odd;
        Some(triangle)
    })
}

/// Expand a triangle fan whose first index is the hub.
pub fn triangle_fan<I>(indices: I) -> impl Iterator<Item = [I::Item; 3]>
where
    I: IntoIterator,
    I::Item: Copy,
{
    let mut first = None;
    let mut previous = None;
    indices.into_iter().filter_map(move |next| {
        let hub = match first {
            Some(first) => first,
            None => {
                first = Some(next);
                return None;
            }
        };
        let prior = match previous {
            Some(previous) => previous,
            None => {
                previous = Some(next);
                return None;
            }
        };
        previous = Some(next);
        Some([hub, prior, next])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_matches_the_closed_owner_loop_for_all_u8_lengths() {
        for len in 0..=u8::MAX {
            let expected = (2..usize::from(len))
                .map(|i| {
                    if i & 1 == 0 {
                        [(i - 2) as u8, (i - 1) as u8, i as u8]
                    } else {
                        [(i - 1) as u8, (i - 2) as u8, i as u8]
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(triangle_strip(0..len).collect::<Vec<_>>(), expected);
        }
    }

    #[test]
    fn fan_and_strip_keep_degenerates_and_sentinel_shaped_values() {
        assert_eq!(
            triangle_strip([0_u16, 1, 1, u16::MAX]).collect::<Vec<_>>(),
            [[0, 1, 1], [1, 1, u16::MAX]]
        );
        assert_eq!(
            triangle_fan([u16::MAX, 1, 1, 2]).collect::<Vec<_>>(),
            [[u16::MAX, 1, 1], [u16::MAX, 1, 2]]
        );
    }
}
