//! A `u64` counter shared across threads, also on targets without 64-bit atomics.
//!
//! Targets with native 64-bit atomics use `core::sync::atomic::AtomicU64`
//! directly. Other targets (for example ARMv7-M) get a small spin lock over
//! two 32-bit halves. It provides only the operations this crate uses, with the
//! same results; every operation is linearizable because each one holds the
//! lock for its whole read-modify-write. Like any spin lock it must not be
//! taken from an interrupt handler that preempted a holder on the same core;
//! work budgets are not shared with interrupt context.

#[cfg(target_has_atomic = "64")]
pub(crate) use core::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
pub(crate) use fallback::AtomicU64;

#[cfg(any(not(target_has_atomic = "64"), test))]
mod fallback {
    use core::fmt;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    #[derive(Default)]
    pub(crate) struct AtomicU64 {
        locked: AtomicBool,
        high: AtomicU32,
        low: AtomicU32,
    }

    impl fmt::Debug for AtomicU64 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.load(Ordering::Relaxed), f)
        }
    }

    impl AtomicU64 {
        #[allow(dead_code)]
        pub(crate) const fn new(value: u64) -> Self {
            Self {
                locked: AtomicBool::new(false),
                high: AtomicU32::new((value >> 32) as u32),
                low: AtomicU32::new(value as u32),
            }
        }

        /// Run `update` on the current value under the lock, storing the
        /// value it returns (if any), and return the previous value.
        fn locked<R>(&self, update: impl FnOnce(u64) -> (Option<u64>, R)) -> R {
            while self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let current = (u64::from(self.high.load(Ordering::Relaxed)) << 32)
                | u64::from(self.low.load(Ordering::Relaxed));
            let (next, result) = update(current);
            if let Some(next) = next {
                self.high.store((next >> 32) as u32, Ordering::Relaxed);
                self.low.store(next as u32, Ordering::Relaxed);
            }
            self.locked.store(false, Ordering::Release);
            result
        }

        pub(crate) fn load(&self, _order: Ordering) -> u64 {
            self.locked(|current| (None, current))
        }

        pub(crate) fn fetch_add(&self, value: u64, _order: Ordering) -> u64 {
            self.locked(|current| (Some(current.wrapping_add(value)), current))
        }

        pub(crate) fn fetch_sub(&self, value: u64, _order: Ordering) -> u64 {
            self.locked(|current| (Some(current.wrapping_sub(value)), current))
        }

        pub(crate) fn fetch_update(
            &self,
            _set_order: Ordering,
            _fetch_order: Ordering,
            mut update: impl FnMut(u64) -> Option<u64>,
        ) -> Result<u64, u64> {
            self.locked(|current| match update(current) {
                Some(next) => (Some(next), Ok(current)),
                None => (None, Err(current)),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fallback::AtomicU64;
    use core::sync::atomic::Ordering;

    #[test]
    fn fallback_matches_native_semantics_across_the_word_boundary() {
        let value = AtomicU64::new(u64::from(u32::MAX));
        assert_eq!(value.fetch_add(1, Ordering::AcqRel), u64::from(u32::MAX));
        assert_eq!(value.load(Ordering::Acquire), 1 << 32);
        assert_eq!(value.fetch_sub(2, Ordering::AcqRel), 1 << 32);
        assert_eq!(value.load(Ordering::Acquire), (1 << 32) - 2);
        assert_eq!(
            value.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |v| Some(
                v.saturating_sub(u64::MAX)
            )),
            Ok((1 << 32) - 2)
        );
        assert_eq!(value.load(Ordering::Acquire), 0);
        assert_eq!(
            value.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |_| None),
            Err(0)
        );
        assert_eq!(AtomicU64::default().load(Ordering::Relaxed), 0);
        assert_eq!(format!("{:?}", AtomicU64::new(7)), "7");
    }

    #[test]
    fn fallback_serializes_concurrent_updates() {
        let value = std::sync::Arc::new(AtomicU64::new(u64::from(u32::MAX) - 1000));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let value = value.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        value.fetch_add(1, Ordering::AcqRel);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(value.load(Ordering::Acquire), u64::from(u32::MAX) + 3000);
    }
}
