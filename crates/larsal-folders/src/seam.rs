//! Test seams: faults and crash points named by a test, compiled out of a product
//! build. With a plan set, the named point fails, and a crash also leaves everything
//! as it stands, the way a power cut would.

#[cfg(not(test))]
use crate::error::Error;

/// A product build has no points.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn hit(_point: &str) -> Result<(), Error> {
    Ok(())
}

/// A product build never leaves cleanup undone on purpose.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn crashed() -> bool {
    false
}

/// A product build never fails its random source on purpose.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn rng_fails() -> bool {
    false
}

#[cfg(test)]
pub(crate) use on::{
    at_every_point, clear, count_kdf, crash_at, crashed, fail_at, fail_rng, hit, kdf_calls,
    rng_fails,
};

#[cfg(test)]
mod on {
    use crate::error::Error;
    use std::cell::{Cell, RefCell};

    /// What a test runs at every named point.
    pub(crate) type Hook = Box<dyn FnMut(&str)>;

    thread_local! {
        static PLAN: RefCell<Option<(String, Error, bool)>> = const { RefCell::new(None) };
        static CRASHED: Cell<bool> = const { Cell::new(false) };
        static RNG_FAILS: Cell<bool> = const { Cell::new(false) };
        static KDF_CALLS: Cell<u32> = const { Cell::new(0) };
        pub(crate) static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(crate) fn fail_at(point: &str, error: Error) {
        PLAN.with(|p| *p.borrow_mut() = Some((point.to_owned(), error, false)));
    }

    pub(crate) fn crash_at(point: &str) {
        PLAN.with(|p| *p.borrow_mut() = Some((point.to_owned(), Error::Io, true)));
    }

    pub(crate) fn clear() {
        PLAN.with(|p| *p.borrow_mut() = None);
        CRASHED.with(|c| c.set(false));
        RNG_FAILS.with(|c| c.set(false));
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    /// Runs `hook` at every named point of this thread's operations, to change the
    /// world between two steps as another writer would.
    pub(crate) fn at_every_point(hook: impl FnMut(&str) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn fail_rng(fails: bool) {
        RNG_FAILS.with(|c| c.set(fails));
    }

    pub(crate) fn rng_fails() -> bool {
        RNG_FAILS.with(Cell::get)
    }

    pub(crate) fn count_kdf() {
        KDF_CALLS.with(|c| c.set(c.get().saturating_add(1)));
    }

    pub(crate) fn kdf_calls() -> u32 {
        KDF_CALLS.with(Cell::get)
    }

    pub(crate) fn crashed() -> bool {
        CRASHED.with(Cell::get)
    }

    pub(crate) fn hit(point: &str) -> Result<(), Error> {
        HOOK.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook(point);
            }
        });
        PLAN.with(|p| {
            let mut plan = p.borrow_mut();
            match plan.as_ref() {
                Some((at, error, crash)) if at == point => {
                    let (error, crash) = (*error, *crash);
                    *plan = None;
                    if crash {
                        CRASHED.with(|c| c.set(true));
                    }
                    Err(error)
                }
                _ => Ok(()),
            }
        })
    }
}
