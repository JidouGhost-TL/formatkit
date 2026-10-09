//! Position-independent codecs for small scalar wire domains.

/// A strict integer-backed boolean whose only encodings are zero and one.
///
/// This type deliberately does not model formats where any nonzero value is
/// true, where the sense is inverted, or where the raw value must be retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroOne(bool);

impl ZeroOne {
    /// Construct the wire value from its decoded boolean.
    #[must_use]
    pub const fn new(value: bool) -> Self {
        Self(value)
    }

    /// Return the decoded boolean.
    #[must_use]
    pub const fn get(self) -> bool {
        self.0
    }
}

impl From<bool> for ZeroOne {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl From<ZeroOne> for bool {
    fn from(value: ZeroOne) -> Self {
        value.get()
    }
}

/// An integer outside the strict zero-or-one domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("integer is neither zero nor one")]
pub struct NotZeroOne;

macro_rules! zero_one_integer {
    ($($integer:ty),+ $(,)?) => {$(
        impl TryFrom<$integer> for ZeroOne {
            type Error = NotZeroOne;

            fn try_from(value: $integer) -> Result<Self, Self::Error> {
                match value {
                    0 => Ok(Self(false)),
                    1 => Ok(Self(true)),
                    _ => Err(NotZeroOne),
                }
            }
        }

        impl From<ZeroOne> for $integer {
            fn from(value: ZeroOne) -> Self {
                if value.0 { 1 } else { 0 }
            }
        }
    )+};
}

zero_one_integer!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_integer_uses_the_exact_zero_one_domain() {
        assert!(!ZeroOne::try_from(0u8).unwrap().get());
        assert!(ZeroOne::try_from(1u16).unwrap().get());
        assert_eq!(ZeroOne::try_from(2u32), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(u64::MAX), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(-1i8), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(2i16), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(-1i32), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(2i64), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(2usize), Err(NotZeroOne));
        assert_eq!(ZeroOne::try_from(-1isize), Err(NotZeroOne));

        let yes = ZeroOne::from(true);
        let no = ZeroOne::from(false);
        assert_eq!(u8::from(yes), 1);
        assert_eq!(u16::from(no), 0);
        assert_eq!(i32::from(yes), 1);
        assert!(bool::from(yes));
        assert!(!bool::from(no));
    }
}
