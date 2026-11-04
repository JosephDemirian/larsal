//! Secret types: [`SecretBytes`] and [`SecretString`] (story E2-S1).
//!
//! Both guarantee:
//! - the heap buffer is overwritten with zeros when the value is dropped,
//!   through `zeroize` (writes the compiler may not remove), including spare
//!   capacity, before the memory goes back to the allocator;
//! - no `Clone` and no `Copy`, so the only copy is the one you hold;
//! - `Debug` prints `[hidden]`; there is no `Display`;
//! - `==` compares the contents in constant time with `subtle`. The length
//!   is not treated as secret: values of different lengths are unequal at once.
//!
//! Limits: copies made before a value moved in (an old buffer left behind
//! when a `Vec` or `String` grew, stack temporaries, values a caller copied
//! out of [`SecretBytes::expose`]) are not wiped by these types. Keeping
//! pages out of swap is `app-platform`'s job.
//!
//! `Clone` does not compile:
//! ```compile_fail
//! let a = app_crypto::secret::SecretBytes::new(vec![1, 2, 3]);
//! let b = a.clone();
//! ```
//! ```compile_fail
//! let a = app_crypto::secret::SecretString::new(String::from("demo"));
//! let b = a.clone();
//! ```
//! `Display` does not compile:
//! ```compile_fail
//! let a = app_crypto::secret::SecretBytes::new(vec![1, 2, 3]);
//! let b = format!("{a}");
//! ```
//! ```compile_fail
//! let a = app_crypto::secret::SecretString::new(String::from("demo"));
//! let b = format!("{a}");
//! ```
//! Control: the same lines without `clone` and `Display` compile, so the
//! examples above fail for the reason they name.
//! ```
//! let a = app_crypto::secret::SecretBytes::new(vec![1, 2, 3]);
//! let b = app_crypto::secret::SecretString::new(String::from("demo"));
//! assert_eq!(format!("{a:?} {b:?}"), "[hidden] [hidden]");
//! ```

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Compares two byte strings in constant time (Rust rule 6): the time does
/// not depend on where the first difference is. Different lengths are unequal
/// at once (lengths are public). For checks where neither side is a secret
/// type, such as the version 3 start bytes (FMT-05.10).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    fold_eq(a, b).into()
}

/// Every byte compare of this module (F-099): the differences OR-folded
/// into one byte, then one `subtle` compare of that byte with zero, as Go's
/// `subtle.ConstantTimeCompare` and BoringSSL's `CRYPTO_memcmp` do. `subtle`'s
/// own slice compare passes each byte through a volatile read, and on an
/// Apple M4 Pro a difference at byte 31 took about 0.2 ns longer than one at
/// byte 0 (E13-S2 RT-B2). Different lengths are unequal at once.
fn fold_eq(a: &[u8], b: &[u8]) -> subtle::Choice {
    if a.len() != b.len() {
        return subtle::Choice::from(0);
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff.ct_eq(&0)
}

/// Runs `f`, then overwrites the stack it used with zeros. Moves leave
/// copies of keys and plaintext in dead stack frames that `Drop` never sees
/// (Verify V-02, AT-C01). Best effort: it zeroes 32 KiB below the caller
/// (in 16-byte words, so it costs under 1 µs), not registers or other threads.
pub(crate) fn scrubbed<T>(f: impl FnOnce() -> T) -> T {
    scrubbed_words::<2048, T>(f)
}

/// Same, 256 KiB: for derive, whose Argon2 frames reach about 93 KiB in debug
/// builds. Runs once per unlock, so the cost does not matter.
pub(crate) fn scrubbed_deep<T>(f: impl FnOnce() -> T) -> T {
    scrubbed_words::<16384, T>(f)
}

fn scrubbed_words<const N: usize, T>(f: impl FnOnce() -> T) -> T {
    let out = call(f);
    scrub_stack::<N>();
    out
}

/// A frame of its own, so `f`'s temporaries are dead when the scrub runs.
#[inline(never)]
fn call<T>(f: impl FnOnce() -> T) -> T {
    f()
}

#[inline(never)]
fn scrub_stack<const N: usize>() {
    let mut buf = [0u128; N];
    buf.zeroize();
    core::hint::black_box(&mut buf);
}

/// Secret bytes: a key, a keystream buffer, a decrypted payload.
///
/// See the module docs for what it guarantees. The length is fixed for the
/// value's life, so the buffer never moves and leaves no unwiped copy.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Takes ownership of `bytes` without copying them. The whole buffer,
    /// spare capacity included, is wiped on drop.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Makes `len` zero bytes to fill in place through [`Self::expose_mut`],
    /// so a result never sits in an unwiped buffer first.
    ///
    /// # Panics
    ///
    /// Panics if `len` is above `isize::MAX`, and aborts if memory runs out.
    /// Callers bound `len` first (Rust rule 5, the `app-format` limits).
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self(vec![0; len])
    }

    /// Borrows the secret bytes. Do not copy them into a type that is not
    /// wiped on drop.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Borrows the secret bytes for writing in place. The length cannot change.
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// The number of bytes. The length is not secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

impl ConstantTimeEq for SecretBytes {
    /// Constant time in the contents; different lengths are unequal at once.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        #[cfg(test)]
        probe::count_ct_eq();
        fold_eq(&self.0, &other.0)
    }
}

impl PartialEq for SecretBytes {
    /// Same as [`ConstantTimeEq::ct_eq`].
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretBytes {}

/// A secret text: a master password, a protected field value.
///
/// See the module docs for what it guarantees. There is no way to change the
/// text in place, so the buffer never moves and leaves no unwiped copy.
pub struct SecretString(String);

impl SecretString {
    /// Takes ownership of `text` without copying it. The whole buffer, spare
    /// capacity included, is wiped on drop.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// Borrows the secret text. Do not copy it into a type that is not wiped
    /// on drop.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The length in bytes (UTF-8). The length is not secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // Moves the buffer out without copying it (String::new does not allocate).
        wipe(&mut core::mem::take(&mut self.0).into_bytes());
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

impl ConstantTimeEq for SecretString {
    /// Constant time in the contents; different lengths are unequal at once.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        #[cfg(test)]
        probe::count_ct_eq();
        fold_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl PartialEq for SecretString {
    /// Same as [`ConstantTimeEq::ct_eq`].
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretString {}

/// The one wipe path for both types. It first grows the length to the full
/// capacity (this never reallocates: the room is already there), so the
/// volatile wipe covers the whole allocation, spare capacity included.
fn wipe(buf: &mut Vec<u8>) {
    let cap = buf.capacity();
    buf.resize(cap, 0);
    buf.as_mut_slice().zeroize();
    #[cfg(test)]
    probe::record(buf);
}

/// Test-only hooks: what the wipe path saw just before the memory is freed,
/// and how many times `ct_eq` ran.
#[cfg(test)]
mod probe {
    use core::cell::Cell;

    /// Address, length and "all zero" of the last buffer wiped on this thread.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Seen {
        pub addr: usize,
        pub len: usize,
        pub all_zero: bool,
    }

    thread_local! {
        static LAST: Cell<Option<Seen>> = const { Cell::new(None) };
        static CT_EQ_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record(buf: &[u8]) {
        let seen = Seen {
            addr: buf.as_ptr().addr(),
            len: buf.len(),
            all_zero: buf.iter().all(|&b| b == 0),
        };
        LAST.with(|last| last.set(Some(seen)));
    }

    pub(super) fn take() -> Option<Seen> {
        LAST.with(Cell::take)
    }

    pub(super) fn count_ct_eq() {
        CT_EQ_CALLS.with(|n| n.set(n.get().wrapping_add(1)));
    }

    /// Calls to `ct_eq` on this thread since the last `take_ct_eq_calls`.
    pub(super) fn take_ct_eq_calls() -> usize {
        CT_EQ_CALLS.with(Cell::take)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proof of "memory is zeroed after drop", and its limits:
    // - It proves that dropping runs the wipe path, on the very allocation
    //   the secret lived in (same address), over its full capacity (spare
    //   capacity included, also bytes left there by truncate or pop), and
    //   that every byte is zero right before the memory goes back to the
    //   allocator.
    // - It cannot read memory after it is freed.
    // - The hook exists only in test builds. Release builds keep the wipe
    //   because zeroize uses volatile writes; the hook does not prove that.
    // - Copies made before the value moved in are out of scope (module docs).
    //
    // Proof of "equality is constant-time", and its limits:
    // - A counter proves `==` goes through `ct_eq`, which calls subtle's
    //   slice `ct_eq`. That subtle itself runs in constant time rests on code
    //   review and the timing check AT-B05.

    #[test]
    fn bytes_are_zero_when_dropped() {
        let secret = SecretBytes::new(vec![0xA5; 64]);
        let addr = secret.expose().as_ptr().addr();
        let _ = probe::take();
        drop(secret);
        let seen = probe::take().expect("drop must run the wipe path");
        assert_eq!(
            seen,
            probe::Seen {
                addr,
                len: 64,
                all_zero: true
            }
        );
    }

    #[test]
    fn bytes_left_in_spare_capacity_are_zero_when_dropped() {
        // Secret bytes past len, as left when padding is cut off a buffer.
        let mut v = vec![0xA5; 100];
        v.truncate(10);
        let cap = v.capacity();
        assert!(cap >= 100);
        let secret = SecretBytes::new(v);
        let addr = secret.expose().as_ptr().addr();
        let _ = probe::take();
        drop(secret);
        let seen = probe::take().expect("drop must run the wipe path");
        assert_eq!(
            seen,
            probe::Seen {
                addr,
                len: cap,
                all_zero: true
            }
        );
    }

    #[test]
    fn text_left_in_spare_capacity_is_zero_when_dropped() {
        // Text past len, as left by backspace edits (pop) in a password field.
        let mut text = String::from("demo master password");
        let cap = text.capacity();
        for _ in 0..8 {
            text.pop();
        }
        assert!(cap > text.len());
        let secret = SecretString::new(text);
        let addr = secret.expose().as_ptr().addr();
        let _ = probe::take();
        drop(secret);
        let seen = probe::take().expect("drop must run the wipe path");
        assert_eq!(
            seen,
            probe::Seen {
                addr,
                len: cap,
                all_zero: true
            }
        );
    }

    #[test]
    fn filled_in_place_bytes_are_zero_when_dropped() {
        let mut secret = SecretBytes::zeroed(32);
        secret.expose_mut().fill(0xFF);
        let addr = secret.expose().as_ptr().addr();
        let _ = probe::take();
        drop(secret);
        let seen = probe::take().expect("drop must run the wipe path");
        assert_eq!(
            seen,
            probe::Seen {
                addr,
                len: 32,
                all_zero: true
            }
        );
    }

    #[test]
    fn string_is_zero_when_dropped() {
        let secret = SecretString::new(String::from("demo master password"));
        let addr = secret.expose().as_ptr().addr();
        let len = secret.len();
        let _ = probe::take();
        drop(secret);
        let seen = probe::take().expect("drop must run the wipe path");
        assert_eq!(
            seen,
            probe::Seen {
                addr,
                len,
                all_zero: true
            }
        );
    }

    #[test]
    fn the_probe_sees_bytes_that_are_not_zero() {
        // Control: the probe can report a buffer that is not zero.
        probe::record(&[0, 1, 0]);
        assert!(!probe::take().expect("recorded").all_zero);
    }

    #[test]
    fn equality_goes_through_ct_eq() {
        let _ = probe::take_ct_eq_calls();
        assert_eq!(SecretBytes::new(vec![1, 2]), SecretBytes::new(vec![1, 2]));
        assert_eq!(probe::take_ct_eq_calls(), 1);
        assert_ne!(
            SecretString::new(String::from("demo")),
            SecretString::new(String::from("Demo"))
        );
        assert_eq!(probe::take_ct_eq_calls(), 1);
    }

    #[test]
    fn ct_eq_matches_equality() {
        let a = SecretBytes::new(vec![1, 2, 3]);
        let b = SecretBytes::new(vec![1, 2, 3]);
        let c = SecretBytes::new(vec![1, 2, 4]);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
        let s = SecretString::new(String::from("demo"));
        let t = SecretString::new(String::from("demo"));
        assert!(bool::from(s.ct_eq(&t)));
    }
}
