//! Story check 6: a work factor above FIL-03's limit is refused at once, before
//! any allocation for it. Only the public calls and the real key derivation; the
//! count of derivations itself is `fil03_t02_*` in the crate's unit tests.

use larsal_crypto::secret::SecretString;
mod common;

use common::open_all;
use larsal_files::{Error, Lock, Unlock, encrypt_stream};
use larsal_platform::macos::resident_bytes;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Far below what scrypt at the lowest refused cost would take: 2 GiB and seconds.
const TIME_BOUND: Duration = Duration::from_secs(1);
const MEMORY_BOUND: u64 = 64 << 20;

/// `work`'s time, and the most the process's resident size rose while it ran.
fn watched<T>(work: impl FnOnce() -> T) -> (T, Duration, u64) {
    static STOP: AtomicBool = AtomicBool::new(false);
    static PEAK: AtomicU64 = AtomicU64::new(0);
    STOP.store(false, Relaxed);
    let base = resident_bytes().unwrap();
    PEAK.store(base, Relaxed);
    let sampler = std::thread::spawn(|| {
        while !STOP.load(Relaxed) {
            PEAK.fetch_max(resident_bytes().unwrap(), Relaxed);
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let start = Instant::now();
    let result = work();
    let took = start.elapsed();
    STOP.store(true, Relaxed);
    sampler.join().unwrap();
    (result, took, PEAK.load(Relaxed).saturating_sub(base))
}

/// A stanza line with any cost, and the shape of a file around it. The file's keys
/// are never reached, so it needs no key derivation to make.
fn file_with_cost(cost: &str) -> Vec<u8> {
    let filler = "A".repeat(43);
    format!(
        "age-encryption.org/v1\n-> scrypt {} {cost}\n{filler}\n--- {filler}\n",
        "A".repeat(22),
    )
    .into_bytes()
}

#[test]
fn check6_a_cost_above_the_ceiling_is_refused_at_once_with_no_memory_for_it() {
    let phrase = SecretString::from("demo passphrase");
    let unlock = Unlock::Passphrase(&phrase);

    // First, with nothing of a key derivation in this process's memory yet.
    for cost in [
        "21",
        "22",
        "30",
        "63",
        "64",
        "255",
        "340282366920938463463374607431768211456",
    ] {
        let file = file_with_cost(cost);
        let (result, took, rise) = watched(|| open_all(&file, &unlock));
        assert_eq!(result.map(|_| ()), Err(Error::Decrypt), "cost {cost}");
        assert!(took < TIME_BOUND, "cost {cost} took {took:?}");
        assert!(rise < MEMORY_BOUND, "cost {cost} rose {rise} bytes");
    }

    // The control: a legal cost takes real memory, so the bound above measures
    // something. New files have cost 18, which is 256 MiB.
    let mut good = Vec::new();
    let (written, _, control_rise) = watched(|| {
        encrypt_stream(
            &mut &b"demo plaintext"[..],
            &mut good,
            &Lock::Passphrase(&phrase),
            &mut |_, _| true,
        )
    });
    written.unwrap();
    assert!(
        control_rise > MEMORY_BOUND,
        "the control rose only {control_rise} bytes"
    );
    let opened = open_all(&good, &unlock).unwrap();
    assert_eq!(opened.expose(), b"demo plaintext");
}
