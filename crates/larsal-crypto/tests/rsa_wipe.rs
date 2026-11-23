//! Rule 4 for New SSH Key's RSA keys (E24-S2, lead ruling (6) of round 2):
//! which copies of p, q, d, dp, dq and qinv the blocks hold when they are
//! handed back. Two probes, as in larsal-cli's memory hygiene test: one
//! outside the zeroing allocator the Mac app installs (LD-133, LD-193:
//! larsal-ffi `lib.rs`) shows what a value leaves in the blocks it frees
//! (its own wipe); one inside it shows what reaches the system (all wiped).
//! No freed memory is read.
//!
//! Markers: the low 8 bytes of each value, in the rsa crate's limb order
//! (little-endian) and in OpenSSH's mpint order (big-endian); qinv also in
//! the Montgomery form the rsa crate keeps it in; and 8 characters of the
//! key text `NewSshKey` keeps. A control marker no key holds reads zero.
//!
//! The key is made the way New SSH Key makes it (ssh-key's
//! `RsaKeypair::random`, larsal-crypto `ssh.rs` `make_key`) from a replayable
//! byte stream, so that the same key can be made again with a marker set:
//! the copies freed while a key is made are counted and printed, not
//! asserted (proposed-findings.md). Keys in Larsal come from the OS source.
//!
//! Two tests that share the probes run one at a time (`ONE`).

use larsal_crypto::ssh::{NewKeyKind, OpenSshKey, new_key};
use larsal_platform::memory::{Probe, Seen, Zeroing, set_needle};
use rsa::traits::PrivateKeyParts;
use sha2::{Digest, Sha256};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{LineEnding, PrivateKey};
use std::alloc::System;
use std::sync::Mutex;
use std::sync::atomic::Ordering::Relaxed;

static BEFORE: Seen = Seen::new();
static AFTER: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<Zeroing<Probe<System>>> = Probe(Zeroing(Probe(System, &AFTER)), &BEFORE);

static ONE: Mutex<()> = Mutex::new(());

const SEED: u64 = 0x0e24_5202;

/// A replayable byte stream: SHA-256 of a seed and a block counter. A test
/// tool only, so the same key can be made twice. sha2 on the stack, not
/// `larsal_crypto::hash`: a `Hasher` box carries stale stack bytes past its
/// SHA-256 state (the probe's own needle among them), which the probe would
/// count in every key's row (proposed-findings.md, Low).
struct Replay {
    block: u64,
    bytes: [u8; 32],
    used: usize,
}

impl Replay {
    fn new() -> Self {
        Self {
            block: 0,
            bytes: [0; 32],
            used: 32,
        }
    }
}

impl rand_core::TryRng for Replay {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dst {
            if self.used == 32 {
                let next = Sha256::new()
                    .chain_update(SEED.to_le_bytes())
                    .chain_update(self.block.to_le_bytes())
                    .finalize();
                self.bytes.copy_from_slice(&next);
                self.block += 1;
                self.used = 0;
            }
            *byte = self.bytes[self.used];
            self.used += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Replay {}

/// The replayable key, made as New SSH Key makes RSA 3072.
fn made() -> RsaKeypair {
    RsaKeypair::random(&mut Replay::new(), 3072).expect("an RSA 3072 key")
}

/// The rsa crate's own private key value of an OpenSSH private key text
/// (what a signer would build from it; New SSH Key builds none).
fn rsa_value(text: &[u8]) -> rsa::RsaPrivateKey {
    let key = PrivateKey::from_openssh(text).expect("the key text");
    let pair = key.key_data().rsa().expect("an RSA key");
    rsa::RsaPrivateKey::try_from(pair).expect("its rsa crate value")
}

/// The markers of the key in `text`, named.
fn markers(text: &[u8]) -> Vec<(String, [u8; 8])> {
    let key = rsa_value(text);
    let low = |b: &rsa::BoxedUint| b.as_limbs()[0].0.to_le_bytes();
    let qinv = key.qinv().expect("precomputed");
    let values = [
        ("p", low(&key.primes()[0])),
        ("q", low(&key.primes()[1])),
        ("d", low(key.d())),
        ("dp", low(key.dp().expect("precomputed"))),
        ("dq", low(key.dq().expect("precomputed"))),
        ("qinv", low(&qinv.retrieve())),
        ("qinv Montgomery", low(qinv.as_montgomery())),
    ];
    let mut all = Vec::new();
    for (name, le) in values {
        let mut be = le;
        be.reverse();
        all.push((format!("{name} LE"), le));
        all.push((format!("{name} BE"), be));
    }
    all
}

/// Blocks freed while `f` runs that held `marker`: outside the zeroing
/// allocator (the values' own wipe) and inside it (what the system gets).
fn freed_with(marker: [u8; 8], f: impl FnOnce()) -> (usize, usize) {
    set_needle(marker);
    BEFORE.reset();
    AFTER.reset();
    f();
    let seen = (
        BEFORE.with_needle.load(Relaxed),
        AFTER.with_needle.load(Relaxed),
    );
    set_needle([0; 8]);
    seen
}

fn key_text(pair: RsaKeypair) -> String {
    let key = PrivateKey::new(KeypairData::Rsa(pair), "demo").expect("a key");
    key.to_openssh(LineEnding::LF)
        .expect("its text")
        .to_string()
}

/// E24-S02, rule 4: Larsal's RSA key values (New SSH Key's `NewSshKey` and
/// the parsed `OpenSshKey` E9 and New SSH Key hold) leave no copy of p, q,
/// d, dp, dq or qinv in the blocks they free; nothing reaches the system.
/// The copies the rsa crate frees while a key is made, and when its own key
/// value drops, are counted and printed (proposed-findings.md: the High row,
/// proposed closed in round 3 by LD-133's zeroing allocator, which this
/// test's "nothing reaches the system" holds).
#[test]
fn e24_s02_rule4_larsal_rsa_key_values_drop_with_no_copy() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let text = key_text(made());
    let marks = markers(text.as_bytes());
    let mut rows = Vec::new();
    // A marker no key holds: what the count reads with nothing to find.
    let control = freed_with(*b"no-key:\xa5", || drop(made()));
    rows.push(format!("{:<18} made: {control:?}", "control"));
    for (name, marker) in &marks {
        let made_seen = freed_with(*marker, || drop(made()));
        let parsed = OpenSshKey::parse(text.as_bytes()).expect("Larsal reads it");
        let parsed_seen = freed_with(*marker, || drop(parsed));
        let crate_value = rsa_value(text.as_bytes());
        let crate_seen = freed_with(*marker, || drop(crate_value));
        rows.push(format!(
            "{name:<18} made: {made_seen:?}  OpenSshKey drop: {parsed_seen:?}  rsa crate value drop: {crate_seen:?}"
        ));
        assert_eq!(parsed_seen, (0, 0), "{name}: OpenSshKey left a copy");
        assert_eq!(
            (made_seen.1, crate_seen.1),
            (0, 0),
            "{name}: a copy reached the system"
        );
    }
    for i in 0..marks.len() {
        let key = new_key(NewKeyKind::Rsa3072, "demo").expect("a key");
        let (name, marker) = markers(key.private().expose()).swap_remove(i);
        let seen = freed_with(marker, || drop(key));
        rows.push(format!("{name:<18} NewSshKey drop: {seen:?}"));
        assert_eq!(seen, (0, 0), "{name}: NewSshKey left a copy");
    }
    // The key text NewSshKey keeps: 8 of its characters 100 before the end
    // line, inside the base64 of q.
    let key = new_key(NewKeyKind::Rsa3072, "demo").expect("a key");
    let text = key.private().expose();
    let end = text
        .windows(8)
        .position(|w| w == b"-----END")
        .expect("the end line");
    let marker: [u8; 8] = text[end - 100..end - 92].try_into().expect("8 bytes");
    let seen = freed_with(marker, || drop(key));
    rows.push(format!("{:<18} NewSshKey drop: {seen:?}", "key text"));
    assert_eq!(seen, (0, 0), "key text: NewSshKey left a copy");
    eprintln!(
        "blocks with the marker (outside, inside the zeroing allocator):\n{}",
        rows.join("\n")
    );
}

/// The rsa crate's own key value (rsa 0.10.0-rc.18): red while that version
/// is shipped; it frees p and q (its Montgomery parameters) and qinv without
/// wiping them. Larsal never keeps this value (New SSH Key builds none); the
/// zeroing allocator wipes those blocks before the system gets them (LD-133,
/// lead ruling (11) of round 3).
#[test]
#[ignore = "a control of E24-S2 (rule 4): rsa 0.10.0-rc.18 frees p, q and qinv unwiped, and LD-133's zeroing allocator wipes them (the High row proposed closed in round 3); run with --ignored"]
fn e24_s02_rule4_rsa_crate_key_value_drops_with_no_copy() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let text = key_text(made());
    let mut left = Vec::new();
    for (name, marker) in markers(text.as_bytes()) {
        let value = rsa_value(text.as_bytes());
        let (before, _) = freed_with(marker, || drop(value));
        if before > 0 {
            left.push(format!("{name}: {before}"));
        }
    }
    assert!(left.is_empty(), "blocks freed with a copy: {left:?}");
}
