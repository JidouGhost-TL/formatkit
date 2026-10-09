use formatkit_core::{nul_terminated, nul_terminated_len, Error};

#[test]
fn bounded_required_nul_matches_independent_position_scanner() {
    // Include opaque/invalid-UTF-8 bytes: framing must not decode characters.
    const ALPHABET: [u8; 5] = [0, 1, b'A', 0x80, 0xff];
    for length in 0..=5u32 {
        for mut pattern in 0..5usize.pow(length) {
            let mut bytes = vec![0; length as usize];
            for byte in &mut bytes {
                *byte = ALPHABET[pattern % ALPHABET.len()];
                pattern /= ALPHABET.len();
            }
            for start in 0..=bytes.len() {
                let tail = &bytes[start..];
                for bound in 0..=tail.len() + 2 {
                    let expected = tail.iter().take(bound).position(|&byte| byte == 0);
                    assert_eq!(nul_terminated_len(tail, bound), expected);
                    let framed = nul_terminated(tail, bound);
                    assert_eq!(framed.as_ref().ok().map(|name| name.len()), expected);
                    match (framed, expected) {
                        (Ok(name), Some(end)) => {
                            assert_eq!(name, &tail[..end]);
                            assert_eq!(name.as_ptr(), tail.as_ptr());
                        }
                        (Err(error), None) if tail.len() < bound => {
                            assert_eq!(
                                error,
                                Error::Truncated {
                                    offset: 0,
                                    needed: bound,
                                    available: tail.len(),
                                }
                            );
                        }
                        (Err(error), None) => assert_eq!(
                            error,
                            Error::Malformed(format!("string has no NUL within {bound} bytes")),
                        ),
                        _ => unreachable!("result and scanner disagree"),
                    }
                }
            }
        }
    }
}

#[test]
fn complete_field_guards_remain_required_before_nul_framing() {
    assert_eq!(nul_terminated_len(b"", usize::MAX), None);
    assert_eq!(nul_terminated_len(b"x", usize::MAX), None);
    assert_eq!(nul_terminated_len(b"x\0", usize::MAX), Some(1));
    assert_eq!(nul_terminated(b"a\0", 8).unwrap(), b"a");
    assert!(b"a\0".get(..8).is_none());
    assert!(nul_terminated(b"name\0next", 4).is_err());
    assert_eq!(nul_terminated(b"name\0next", 5).unwrap(), b"name");
    assert_eq!(nul_terminated(b"\0opaque", 7).unwrap(), b"");
    assert!(nul_terminated(b"", 0).is_err());
}
