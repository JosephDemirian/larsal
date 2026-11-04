//! HMAC-SHA-256 and HMAC-SHA-1 with constant-time verify (story E2-S3), and
//! HMAC-SHA-512 for one-time codes (RFC 6238, story E4-S10).
//!
//! - HMAC is RFC 2104 / FIPS 198-1, from the `hmac` crate. Keys of any
//!   length work (FMT-05.6 and FMT-06.5 use 64-byte keys).
//! - The message is a list of parts MACed as if joined, so a caller never
//!   builds a joined copy (FMT-06.5: `LE64(i) || size || data`).
//! - A tag comes back as [`SecretBytes`]: a valid tag over chosen data is
//!   worth keeping out of logs.
//! - The verify functions compare in constant time (`subtle`) and return only
//!   `true` or `false`, never the tag they computed. A tag of the wrong length
//!   is `false`; the length is not treated as secret.
//! - HMAC state inside the crates is wiped on drop (their `zeroize` feature):
//!   the two hash cores the HMAC holds (the same types `hash` checks at
//!   compile time) and the tag output type, checked below.
//!
//! The `hmac` crate (0.13) leaves two copies on the stack: the key padded to
//! one block (for a key longer than a block, its hash) and the inner hash.
//! After every compute a fixed 32 KiB of stack below the call is zeroed (best
//! effort), which covers both (E2-S7 stack probe), so FMT-04.19 holds.

use crate::{
    Error,
    secret::{SecretBytes, scrubbed},
};
use hmac::{Hmac, KeyInit, Mac};

/// HMAC-SHA-256 of `parts` joined in order, keyed with `key`. Always 32 bytes.
///
/// # Errors
/// [`Error::KeyLength`] only if the HMAC crate refuses the key, which it
/// never does for HMAC (any length is valid); kept so nothing can panic.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes, Error> {
    compute::<Hmac<sha2::Sha256>>(key, parts)
}

/// HMAC-SHA-1 of `parts` joined in order, keyed with `key`. Always 20 bytes.
/// Use only where a format or device demands it.
///
/// # Errors
/// Same as [`hmac_sha256`].
pub fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes, Error> {
    compute::<Hmac<sha1::Sha1>>(key, parts)
}

/// HMAC-SHA-512 of `parts` joined in order, keyed with `key`. Always 64
/// bytes. One-time codes need it (RFC 6238, FEA-04.11).
///
/// # Errors
/// Same as [`hmac_sha256`].
pub fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes, Error> {
    compute::<Hmac<sha2::Sha512>>(key, parts)
}

/// True only if `tag` is the full 32-byte HMAC-SHA-256 of `parts` under `key`.
///
/// Guarantees: the comparison takes the same time wherever the first
/// difference is; the computed tag is wiped and never returned. A wrong
/// length, or a key the crate refuses, gives `false`.
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    verify::<Hmac<sha2::Sha256>>(key, parts, tag)
}

/// True only if `tag` is the full 20-byte HMAC-SHA-1 of `parts` under `key`.
/// Same guarantees as [`verify_hmac_sha256`].
#[must_use]
pub fn verify_hmac_sha1(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    verify::<Hmac<sha1::Sha1>>(key, parts, tag)
}

fn compute<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes, Error> {
    scrubbed(|| compute_inner::<M>(key, parts))
}

fn compute_inner<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes, Error> {
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| Error::KeyLength)?;
    for part in parts {
        mac.update(part);
    }
    // The crate's output type wipes itself on drop, right after this copy.
    Ok(SecretBytes::new(mac.finalize().as_bytes().to_vec()))
}

fn verify<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    compute::<M>(key, parts).is_ok_and(|want| tags_equal(want.expose(), tag))
}

/// The one tag compare, through `subtle`: the time does not depend on where
/// the first difference is. Different lengths are unequal at once (the
/// length is public).
fn tags_equal(want: &[u8], tag: &[u8]) -> bool {
    #[cfg(test)]
    probe::count_ct_eq();
    crate::secret::ct_eq(want, tag)
}

// Compile-time proof of "wiped on drop" for the tag output: turning off the
// digest crate's `zeroize` feature (which the sha1, sha2 and hmac features
// turn on) breaks the build here. The hash cores are checked in `hash`.
const _: () = {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<hmac::digest::CtOutput<Hmac<sha2::Sha256>>>();
    wiped_on_drop::<hmac::digest::CtOutput<Hmac<sha1::Sha1>>>();
    wiped_on_drop::<hmac::digest::CtOutput<Hmac<sha2::Sha512>>>();
};

/// Test-only hook: how many times the tag compare ran on this thread.
#[cfg(test)]
mod probe {
    use core::cell::Cell;

    thread_local! {
        static CT_EQ_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count_ct_eq() {
        CT_EQ_CALLS.with(|n| n.set(n.get().wrapping_add(1)));
    }

    /// Calls since the last `take_ct_eq_calls`.
    pub(super) fn take_ct_eq_calls() -> usize {
        CT_EQ_CALLS.with(Cell::take)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proof that verify compares through `subtle` (E2-S3 "verify is
    // constant-time", Rust rule 6): every verify runs the one constant-time
    // compare exactly once, for a right tag, a wrong tag of the right length
    // and a tag of the wrong length (subtle's slice compare returns false at
    // once on a length mismatch, by design: lengths are public). An ordinary
    // `==` in verify skips the counter and fails this test. Measuring the
    // time itself is AT-B05: the ignored test in tests/mac.rs.
    #[test]
    fn verify_runs_the_constant_time_compare_once() {
        let key = [0x0b; 64];
        let parts: &[&[u8]] = &[b"demo"];
        let good256 = hmac_sha256(&key, parts).unwrap().expose().to_vec();
        let good1 = hmac_sha1(&key, parts).unwrap().expose().to_vec();
        let flip = |t: &[u8]| {
            let mut t = t.to_vec();
            t[0] ^= 1;
            t
        };
        let _ = probe::take_ct_eq_calls();
        for (tag, want) in [
            (good256.clone(), true),
            (flip(&good256), false),
            (good256[..31].to_vec(), false),
        ] {
            assert_eq!(verify_hmac_sha256(&key, parts, &tag), want);
            assert_eq!(probe::take_ct_eq_calls(), 1);
        }
        for (tag, want) in [
            (good1.clone(), true),
            (flip(&good1), false),
            (good256.clone(), false),
        ] {
            assert_eq!(verify_hmac_sha1(&key, parts, &tag), want);
            assert_eq!(probe::take_ct_eq_calls(), 1);
        }
    }

    // The counter cannot see an ordinary `==` written inside `tags_equal`
    // itself; this scan of the code above the test hooks can.
    #[test]
    fn no_ordinary_equality_in_the_mac_code() {
        let code = include_str!("mac.rs")
            .split("#[cfg(test)]\nmod probe")
            .next()
            .unwrap();
        for line in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
            for op in ["==", "!=", ".eq(", ".ne("] {
                assert!(!line.contains(op), "mac.rs uses {op}: {line}");
            }
        }
    }
}
