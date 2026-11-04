//! The OS random source: fill, bytes, below without bias (story E2-S2).
//!
//! Every random value App makes comes from here (Rust rule 7, AT-B04), and
//! here it comes only from the operating system, through `getrandom`'s
//! `SysRng` (a `rand_core` generator). There is no seed, no state and no
//! fallback: if the OS source fails, the caller gets [`Error::RandomSource`]
//! and no value at all, never a weaker one.
//!
//! Every public function is a thin wrapper over a private one that takes the
//! source as a parameter. Product code always passes `SysRng`; only the unit
//! tests below pass anything else (a failing or scripted source).

use crate::{Error, secret::SecretBytes};
use getrandom::SysRng;
use rand_core::TryCryptoRng;

/// How many draws [`below`] makes before it gives up. One draw is rejected
/// with a chance under 1/2, so a working source passes all of these with a
/// chance under 2^-64; a source stuck on a rejected value fails closed.
const MAX_DRAWS: u32 = 64;

/// The two crates behind the OS source, with their pinned versions, for the
/// build information of `--debug-info` (APP-09.4). Named here because only
/// this file may name them (AT-B04).
pub const SOURCE_CRATES: [(&str, &str); 2] = [("getrandom", "0.4.3"), ("rand_core", "0.10.1")];

/// Fills `buf` with bytes from the OS random source.
///
/// Guarantees: on `Ok` every byte came from the OS source. On error the
/// contents of `buf` are unspecified and must not be used.
///
/// # Errors
/// [`Error::RandomSource`] if the OS source fails.
pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    fill_from(&mut SysRng, buf)
}

/// Returns `n` bytes from the OS random source, in a type that wipes them on
/// drop (keys, seeds, IVs, salts).
///
/// Guarantees: exactly `n` bytes, all from the OS source.
///
/// # Errors
/// [`Error::RandomSource`] if the OS source fails; the partial buffer is
/// wiped and dropped.
///
/// # Panics
///
/// Panics if `n` is above `isize::MAX`, and aborts if memory runs out (both
/// from [`SecretBytes::zeroed`]). Callers bound `n` first; the sizes in
/// CRY-03 are fixed constants.
pub fn bytes(n: usize) -> Result<SecretBytes, Error> {
    bytes_from(&mut SysRng, n)
}

/// Returns a whole number in `0..n`, every value equally likely.
///
/// Guarantees: no modulo bias. A raw 32-bit draw `x` is used only when
/// `x >= 2^32 mod n`; the values left are a whole number of runs of `n`, so
/// `x mod n` is exactly uniform. Other draws are thrown away and drawn again.
///
/// # Errors
/// [`Error::EmptyRange`] if `n` is 0. [`Error::RandomSource`] if the OS source
/// fails, or if it gives a rejected value too many times in a row.
pub fn below(n: u32) -> Result<u32, Error> {
    below_from(&mut SysRng, n)
}

/// Returns a new random 16-byte id: an RFC 9562 (formerly RFC 4122) version 4
/// UUID, as CRY-03.11 needs for groups, entries and custom icons.
///
/// Guarantees: the high nibble of byte 6 is `4` (version), the top two bits
/// of byte 8 are `10` (variant); the other 122 bits come from the OS source.
///
/// # Errors
/// [`Error::RandomSource`] if the OS source fails.
pub fn uuid_v4() -> Result<[u8; 16], Error> {
    uuid_v4_from(&mut SysRng)
}

fn fill_from<R: TryCryptoRng>(rng: &mut R, buf: &mut [u8]) -> Result<(), Error> {
    rng.try_fill_bytes(buf).map_err(|_| Error::RandomSource)
}

fn bytes_from<R: TryCryptoRng>(rng: &mut R, n: usize) -> Result<SecretBytes, Error> {
    let mut out = SecretBytes::zeroed(n);
    fill_from(rng, out.expose_mut())?;
    Ok(out)
}

fn below_from<R: TryCryptoRng>(rng: &mut R, n: u32) -> Result<u32, Error> {
    if n == 0 {
        return Err(Error::EmptyRange);
    }
    for _ in 0..MAX_DRAWS {
        let x = rng.try_next_u32().map_err(|_| Error::RandomSource)?;
        if let Some(v) = accept(x, n) {
            return Ok(v);
        }
    }
    Err(Error::RandomSource)
}

/// The rejection rule of [`below`]: `Some(x mod n)` when `x >= 2^32 mod n`,
/// `None` when `x` must be thrown away (or `n` is 0).
fn accept(x: u32, n: u32) -> Option<u32> {
    // 2^32 mod n == (2^32 - n) mod n, and 2^32 - n is n.wrapping_neg() for n > 0.
    let reject_below = n.wrapping_neg().checked_rem(n)?;
    if x < reject_below {
        None
    } else {
        x.checked_rem(n)
    }
}

fn uuid_v4_from<R: TryCryptoRng>(rng: &mut R) -> Result<[u8; 16], Error> {
    let mut id = [0u8; 16];
    fill_from(rng, &mut id)?;
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    Ok(id)
}

/// Bytes already drawn from the OS source, served once to a crate that asks
/// a generator for them and cannot take a failing one (hpke's sender setup,
/// CRY-04.12). Draw first with [`bytes`], so a failed draw fails before any
/// work; then hand this over.
///
/// Guarantees: it serves exactly its bytes, once, to one fill of exactly
/// their length. Any other request gets zeros and marks it misused, and the
/// caller must then throw the result away: [`Prepared::served_once`] says
/// whether the only request was the one expected. The bytes are wiped on drop.
pub(crate) struct Prepared {
    bytes: SecretBytes,
    served: bool,
    misused: bool,
}

impl Prepared {
    pub(crate) fn new(bytes: SecretBytes) -> Self {
        Self {
            bytes,
            served: false,
            misused: false,
        }
    }

    /// True when the bytes were served, in one fill of their length, and
    /// nothing else was asked for.
    pub(crate) fn served_once(&self) -> bool {
        self.served && !self.misused
    }
}

impl rand_core::TryRng for Prepared {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.misused = true;
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.misused = true;
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if self.served || dst.len() != self.bytes.len() {
            self.misused = true;
            dst.fill(0);
        } else {
            dst.copy_from_slice(self.bytes.expose());
            self.served = true;
        }
        Ok(())
    }
}

impl TryCryptoRng for Prepared {}

// Rule 4 is about input handling; this test code counts and computes bounds.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use rand_core::TryRng;

    /// A source that always fails, like an OS source that is down. It counts
    /// the calls, so a test can see that one failure ends the work at once.
    #[derive(Default)]
    struct Broken(usize);

    impl Broken {
        fn down<T>(&mut self) -> Result<T, std::io::Error> {
            self.0 += 1;
            Err(std::io::Error::other("demo: source down"))
        }
    }

    impl TryRng for Broken {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.down()
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.down()
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
            self.down()
        }
    }
    impl TryCryptoRng for Broken {}

    /// A source that replays fixed 32-bit values, then fails. It counts the
    /// draws, the failed one included.
    struct Script {
        values: Vec<u32>,
        draws: usize,
    }

    fn script(values: Vec<u32>) -> Script {
        Script { values, draws: 0 }
    }

    impl TryRng for Script {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.draws += 1;
            if self.values.is_empty() {
                return Err(std::io::Error::other("demo: script ended"));
            }
            Ok(self.values.remove(0))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(std::io::Error::other("demo: not scripted"))
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
            Err(std::io::Error::other("demo: not scripted"))
        }
    }
    impl TryCryptoRng for Script {}

    /// 2^32 mod n, computed the slow obvious way.
    fn rem(n: u32) -> u32 {
        u32::try_from((1u64 << 32) % u64::from(n)).unwrap()
    }

    #[test]
    fn a_failing_source_gives_an_error_never_a_value() {
        // Each function asks the source once, gets the error and stops: no
        // retry, no stand-in value. For n = 1, 2 and 256 every raw draw is
        // accepted, so a swallowed error (say a 0 put in its place) would come
        // back as Ok here; for 3 and 448 the draw count catches it.
        let mut buf = [0u8; 32];
        let mut src = Broken::default();
        assert_eq!(fill_from(&mut src, &mut buf), Err(Error::RandomSource));
        assert_eq!(src.0, 1);
        let mut src = Broken::default();
        assert_eq!(bytes_from(&mut src, 32).err(), Some(Error::RandomSource));
        assert_eq!(src.0, 1);
        let mut src = Broken::default();
        assert_eq!(uuid_v4_from(&mut src), Err(Error::RandomSource));
        assert_eq!(src.0, 1);
        for n in [1, 2, 3, 256, 448, u32::MAX] {
            let mut src = Broken::default();
            assert_eq!(below_from(&mut src, n), Err(Error::RandomSource), "n = {n}");
            assert_eq!(src.0, 1, "n = {n}");
        }
    }

    #[test]
    fn below_draws_again_after_a_rejected_value() {
        // 2^32 mod 3 = 1: only x = 0 is rejected.
        assert_eq!(rem(3), 1);
        let mut src = script(vec![0, 0, 5]);
        assert_eq!(below_from(&mut src, 3), Ok(2));
        assert_eq!(src.draws, 3);
        assert_eq!(below_from(&mut script(vec![1]), 3), Ok(1));
        assert_eq!(below_from(&mut script(vec![u32::MAX]), 3), Ok(0));
    }

    #[test]
    fn below_fails_closed_on_a_stuck_source() {
        // A source stuck on a rejected value: an error after exactly MAX_DRAWS
        // draws, not a hang (the script has more values left).
        let mut src = script(vec![0; 100]);
        assert_eq!(below_from(&mut src, 3), Err(Error::RandomSource));
        assert_eq!(src.draws, usize::try_from(MAX_DRAWS).unwrap());
        // A failure in the middle of the loop is passed on at once (second
        // draw), not skipped and hidden behind the MAX_DRAWS limit.
        let mut src = script(vec![0]);
        assert_eq!(below_from(&mut src, 3), Err(Error::RandomSource));
        assert_eq!(src.draws, 2);
    }

    #[test]
    fn below_zero_is_an_error_and_draws_nothing() {
        let mut src = Broken::default();
        assert_eq!(below_from(&mut src, 0), Err(Error::EmptyRange));
        assert_eq!(src.0, 0);
        assert_eq!(accept(7, 0), None);
    }

    #[test]
    fn accept_rejects_exactly_the_values_under_2_pow_32_mod_n() {
        // The accepted values [r, 2^32) must be a whole number of runs of n,
        // and r must be the cut point. Checked for many n, including the worst
        // case for rejection (2^31 + 1) and the sizes App uses (448, 7776).
        let mut ns: Vec<u32> = (1..=2000).collect();
        ns.extend([
            448,
            7776,
            (1 << 16) + 1,
            (1 << 31) - 1,
            1 << 31,
            (1 << 31) + 1,
            u32::MAX - 1,
            u32::MAX,
        ]);
        for n in ns {
            let r = rem(n);
            assert_eq!(((1u64 << 32) - u64::from(r)) % u64::from(n), 0, "n = {n}");
            if r > 0 {
                assert_eq!(accept(r - 1, n), None, "n = {n}");
                assert_eq!(accept(0, n), None, "n = {n}");
            }
            assert_eq!(accept(r, n), Some(r % n), "n = {n}");
            assert_eq!(accept(u32::MAX, n), Some(u32::MAX % n), "n = {n}");
        }
    }

    #[test]
    #[ignore = "slow: run with --release -- --ignored"]
    fn accept_is_uniform_over_every_32_bit_input() {
        // Exhaustive (CRY-03 T9 style): every possible raw draw, no real source.
        // Each result value comes from exactly the same number of inputs, and
        // exactly 2^32 mod n inputs are rejected.
        for n in [3u32, 448, 7776] {
            let mut counts = vec![0u64; usize::try_from(n).unwrap()];
            let mut rejected = 0u64;
            for x in 0..=u32::MAX {
                match accept(x, n) {
                    Some(v) => counts[usize::try_from(v).unwrap()] += 1,
                    None => rejected += 1,
                }
            }
            assert_eq!(rejected, u64::from(rem(n)), "n = {n}");
            let each = ((1u64 << 32) - rejected) / u64::from(n);
            assert!(counts.iter().all(|&c| c == each), "n = {n}");
        }
    }

    #[test]
    fn prepared_serves_its_bytes_once_and_nothing_else() {
        use rand_core::TryRng as _;
        let fresh = || Prepared::new(SecretBytes::new(vec![7; 32]));
        // One fill of exactly its length: served once.
        let mut p = fresh();
        assert!(!p.served_once());
        let mut buf = [0u8; 32];
        p.try_fill_bytes(&mut buf).unwrap();
        assert_eq!(buf, [7; 32]);
        assert!(p.served_once());
        // A second fill gets zeros and marks it misused.
        p.try_fill_bytes(&mut buf).unwrap();
        assert_eq!(buf, [0; 32]);
        assert!(!p.served_once());
        // A fill of another length, or a word: misused.
        for n in [31, 33] {
            let mut p = fresh();
            let mut buf = vec![1u8; n];
            p.try_fill_bytes(&mut buf).unwrap();
            assert!(buf.iter().all(|&b| b == 0));
            assert!(!p.served_once());
        }
        let mut p = fresh();
        p.try_fill_bytes(&mut buf).unwrap();
        assert_eq!(p.try_next_u32(), Ok(0));
        assert!(!p.served_once());
        let mut p = fresh();
        p.try_fill_bytes(&mut buf).unwrap();
        assert_eq!(p.try_next_u64(), Ok(0));
        assert!(!p.served_once());
    }

    #[test]
    fn uuid_bits_are_set_from_a_scripted_source() {
        // All-ones and all-zeros inputs show the masks force exactly the
        // version and variant bits and keep every other bit.
        struct Fill(u8);
        impl TryRng for Fill {
            type Error = std::io::Error;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(std::io::Error::other("demo: not used"))
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(std::io::Error::other("demo: not used"))
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                dst.fill(self.0);
                Ok(())
            }
        }
        impl TryCryptoRng for Fill {}

        let ones = uuid_v4_from(&mut Fill(0xFF)).unwrap();
        let zeros = uuid_v4_from(&mut Fill(0x00)).unwrap();
        let mut want_ones = [0xFF; 16];
        want_ones[6] = 0x4F;
        want_ones[8] = 0xBF;
        let mut want_zeros = [0x00; 16];
        want_zeros[6] = 0x40;
        want_zeros[8] = 0x80;
        assert_eq!(ones, want_ones);
        assert_eq!(zeros, want_zeros);
    }
}
