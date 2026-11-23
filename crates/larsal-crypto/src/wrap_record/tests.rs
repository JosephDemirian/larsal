//! CRY-05 tests that E25-S3 owns for the wrap record: CRY-05.4's order and
//! sizes, T12 (downgrade) with CRY-04 T20, T13 (one byte), T08's halves at
//! step 3, both halves of the hybrid KEM (the story's first check), a
//! server that strips or swaps the post-quantum half (the second), T27 and
//! T29 on a record.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use crate::base64::{Form, encode};
use crate::pq::{ENC, MAX_INFO, MAX_PLAINTEXT, PUBLIC_KEY, SIGNATURE};
use crate::{hash, hpke};

const INFO: &[u8] = b"demo wrap info: vault 1, reader 2";
const KEY: &[u8; 32] = b"demo vault key, thirty-two bytes";

struct Keys {
    seed: SecretBytes,
    pk: Vec<u8>,
    sk: SecretBytes,
    ipk: Vec<u8>,
}

fn keys() -> Keys {
    let (seed, pk) = pq::xwing_keypair().unwrap();
    let (sk, ipk) = pq::identity_keypair().unwrap();
    Keys { seed, pk, sk, ipk }
}

/// The three test counters since the last read: signature checks reached
/// (step 3), Ed25519 checks run, ML-KEM decapsulations run (pq's T10 count).
fn counts() -> (usize, usize, usize) {
    (probe::take(), sign::probe::take(), pq::probe::take())
}

/// `record` changed by `change`, then signed again validly by its sender.
fn resigned(
    record: &WrapRecord,
    sk: &SecretBytes,
    change: impl FnOnce(&mut WrapRecord),
) -> WrapRecord {
    let mut r = record.clone();
    change(&mut r);
    let signed = signed_part(r.suite, &r.enc, &r.ct, &r.info, &r.signer).unwrap();
    r.signature = pq::composite_sign(sk, &signed).unwrap();
    r
}

#[test]
fn cry05_4_cry05_14_t25_round_trip_and_exact_sizes() {
    assert_eq!(SUITE, [25722, 1, 3]);
    let k = keys();
    assert_eq!(
        (k.seed.len(), k.pk.len(), k.sk.len(), k.ipk.len()),
        (32, 1216, 64, 1984)
    );
    for (info, plaintext) in [
        (INFO, &KEY[..]),
        (&[][..], &[][..]),
        (&[7; MAX_INFO][..], &[9; MAX_PLAINTEXT][..]),
    ] {
        let r = make(&k.pk, info, plaintext, [3; 16], &k.sk).unwrap();
        assert_eq!(r.suite, [25722, 1, 3]);
        assert_eq!(
            (r.enc.len(), r.ct.len(), r.info.len(), r.signature.len()),
            (1120, plaintext.len() + 16, info.len(), 3373)
        );
        assert_eq!(open(&r, &k.ipk, info, &k.seed).unwrap().expose(), plaintext);
    }
    assert_eq!(
        make(&k.pk, &[7; MAX_INFO + 1], KEY, [3; 16], &k.sk).err(),
        Some(Error::TooLarge)
    );
    assert_eq!(
        make(&k.pk, INFO, &[9; MAX_PLAINTEXT + 1], [3; 16], &k.sk).err(),
        Some(Error::TooLarge)
    );
}

/// CRY-04.6's field list, built by hand from CRY-04.2: the label, the suite
/// as three u16, enc, ct, info and the signer id, each after its length as a
/// u32 big endian; the record's signature is a composite signature over it.
#[test]
fn cry04_6_cry05_4_the_signature_covers_the_whole_field_list() {
    let k = keys();
    let r = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    let mut signed = Vec::new();
    for f in [
        &b"sync-wrap-v1"[..],
        &[0x64, 0x7a],
        &[0, 1],
        &[0, 3],
        &r.enc,
        &r.ct,
        INFO,
        &[3; 16],
    ] {
        signed.extend_from_slice(&(f.len() as u32).to_be_bytes());
        signed.extend_from_slice(f);
    }
    assert_eq!(pq::composite_verify(&k.ipk, &signed, &r.signature), Ok(()));
}

/// CRY-05.4 (CRY-04 T09's order on the hybrid record): each step refuses
/// before the next one runs.
#[test]
fn cry05_4_open_checks_run_in_order() {
    let k = keys();
    let record = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    counts();
    assert_eq!(open(&record, &k.ipk, INFO, &k.seed).unwrap().expose(), KEY);
    assert_eq!(counts(), (1, 1, 1));
    // Another suite: step 1, before any signature check.
    let mut other = record.clone();
    other.suite = [25722, 1, 2];
    assert_eq!(
        open(&other, &k.ipk, INFO, &k.seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (0, 0, 0));
    // Another expected info (valid for another vault): step 2.
    assert_eq!(
        open(
            &record,
            &k.ipk,
            b"demo wrap info: vault 2, reader 2",
            &k.seed
        )
        .err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (0, 0, 0));
    // Another pinned identity key: step 3, no decapsulation.
    let (_, stranger) = pq::identity_keypair().unwrap();
    assert_eq!(
        open(&record, &stranger, INFO, &k.seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (1, 1, 0));
    // One changed byte of ct: the signature fails first (step 3).
    let mut changed = record.clone();
    changed.ct[0] ^= 1;
    assert_eq!(
        open(&changed, &k.ipk, INFO, &k.seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (1, 1, 0));
    // The right signer, a wrap to another receiving key: step 4.
    let (other_seed, _) = pq::xwing_keypair().unwrap();
    assert_eq!(
        open(&record, &k.ipk, INFO, &other_seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (1, 1, 1));
}

/// CRY-05 T12 and CRY-04 T20 (CRY-05.4, CRY-05.7, CRY-04.15): the hybrid
/// record opens; the same key wrapped with CRY-04's classical suite and
/// validly Ed25519-signed by the Ed25519 half of the identity key the Mac
/// pinned is refused at step 1: no signature check and no decapsulation run.
#[test]
fn cry05_7_t12_cry04_t20_classical_record_refused_at_step_1() {
    let k = keys();
    let hybrid = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    counts();
    assert_eq!(open(&hybrid, &k.ipk, INFO, &k.seed).unwrap().expose(), KEY);
    assert_eq!(counts(), (1, 1, 1));

    // The classical record, built only here (CRY-04.5's suite is test-only).
    let (_, x25519_public) = hpke::x25519_keypair().unwrap();
    let (enc, ct) = hpke::seal(&x25519_public, INFO, KEY).unwrap();
    let ed_seed = SecretBytes::new(k.sk.expose()[32..].to_vec());
    let signed = signed_part(hpke::SUITE, &enc, &ct, INFO, &[3; 16]).unwrap();
    let classical = WrapRecord {
        suite: hpke::SUITE,
        enc: enc.to_vec(),
        ct,
        info: INFO.to_vec(),
        signer: [3; 16],
        signature: sign::ed25519_sign(&ed_seed, &signed).unwrap().to_vec(),
    };
    assert_eq!(hpke::SUITE, [32, 1, 2]);
    // Valid in CRY-04.6's sense, by a key the Mac trusts.
    assert_eq!(
        sign::ed25519_verify(&k.ipk[1952..], &signed, &classical.signature),
        Ok(())
    );
    counts();
    assert_eq!(
        open(&classical, &k.ipk, INFO, &k.seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (0, 0, 0), "a check ran on a classical record");
    // Every other suite id the same way, the hybrid record's own fields kept.
    for suite in [
        [32, 1, 3],
        [25722, 1, 2],
        [25722, 3, 3],
        [0x0041, 1, 3],
        [0, 0, 0],
    ] {
        let mut r = hybrid.clone();
        r.suite = suite;
        assert_eq!(
            open(&r, &k.ipk, INFO, &k.seed).err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(counts(), (0, 0, 0), "{suite:?}");
    }
    // The classical record relabelled with the hybrid suite: its Ed25519
    // signature is no composite signature (step 3), and nothing decapsulates.
    let mut relabelled = classical;
    relabelled.suite = SUITE;
    assert_eq!(
        open(&relabelled, &k.ipk, INFO, &k.seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (1, 0, 0));
}

/// The story's second check (CRY-05.7, downgrade): a server that strips or
/// swaps the post-quantum half of a record or of a receiving key is refused.
#[test]
fn cry05_7_a_server_that_strips_or_swaps_the_post_quantum_half_is_refused() {
    let k = keys();
    let record = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    let second = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    assert_ne!(record.enc, second.enc);
    let cases: [(&str, WrapRecord, (usize, usize, usize)); 5] = [
        (
            "enc cut to its X25519 part",
            {
                let mut r = record.clone();
                r.enc = r.enc[ENC - 32..].to_vec();
                r
            },
            (1, 1, 0),
        ),
        (
            "enc with another record's ML-KEM part",
            {
                let mut r = record.clone();
                r.enc[..ENC - 32].copy_from_slice(&second.enc[..ENC - 32]);
                r
            },
            (1, 1, 0),
        ),
        (
            "the signature cut to its Ed25519 half",
            {
                let mut r = record.clone();
                r.signature = r.signature[SIGNATURE - 64..].to_vec();
                r
            },
            (1, 0, 0),
        ),
        (
            "the signature with another key's ML-DSA half",
            {
                let (other, _) = pq::identity_keypair().unwrap();
                let theirs = resigned(&record, &other, |_| {});
                let mut r = record.clone();
                r.signature[..SIGNATURE - 64].copy_from_slice(&theirs.signature[..SIGNATURE - 64]);
                r
            },
            (1, 1, 0),
        ),
        (
            "the suite relabelled classical",
            {
                let mut r = record.clone();
                r.suite = [32, 1, 2];
                r
            },
            (0, 0, 0),
        ),
    ];
    counts();
    for (what, r, want) in cases {
        assert_eq!(
            open(&r, &k.ipk, INFO, &k.seed).err(),
            Some(Error::WrapInvalid),
            "{what}"
        );
        assert_eq!(counts(), want, "{what}");
    }
    // A receiving key stripped to its X25519 part: nothing is sealed to it.
    assert_eq!(
        make(&k.pk[PUBLIC_KEY - 32..], INFO, KEY, [3; 16], &k.sk).err(),
        Some(Error::KeyLength)
    );
    // A receiving key whose ML-KEM part a server swapped for its own: the
    // real recipient cannot open what was sealed to it (the binding check,
    // account::check_kem_binding, refuses such a key before any seal).
    let (_, servers) = pq::xwing_keypair().unwrap();
    let mut swapped = servers[..PUBLIC_KEY - 32].to_vec();
    swapped.extend_from_slice(&k.pk[PUBLIC_KEY - 32..]);
    let r = make(&swapped, INFO, KEY, [3; 16], &k.sk).unwrap();
    counts();
    assert_eq!(
        open(&r, &k.ipk, INFO, &k.seed).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(counts(), (1, 1, 1));
}

/// The story's first check (ruling (3), CRY-05.3): a wrap opens only with
/// both private keys. Breaking the classical half alone (the X25519 part of
/// the receiving key or of enc changed, the ML-KEM part right) or the
/// post-quantum half alone (the ML-KEM part changed, the X25519 part right)
/// ends in `WrapInvalid` with no plaintext, after the decapsulation ran.
/// Records with a changed enc are signed again by the sender, so step 3
/// passes and step 4 decides.
#[test]
fn cry05_3_t10_a_wrap_opens_only_with_both_halves() {
    let k = keys();
    let record = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    counts();
    assert_eq!(open(&record, &k.ipk, INFO, &k.seed).unwrap().expose(), KEY);
    assert_eq!(counts(), (1, 1, 1));
    let key_with = |i: usize| {
        let mut pk = k.pk.clone();
        pk[i] ^= 0x01;
        make(&pk, INFO, KEY, [3; 16], &k.sk).unwrap()
    };
    // ML-KEM coefficient 0 (FIPS 203 ByteEncode_12) moved by one, mod 3,329,
    // so the key still passes the modulus check.
    let coefficient_moved = {
        let mut pk = k.pk.clone();
        let c = (u16::from(pk[0]) | (u16::from(pk[1] & 0x0f) << 8)) + 1;
        let c = c % 3329;
        pk[0] = (c & 0xff) as u8;
        pk[1] = (pk[1] & 0xf0) | (c >> 8) as u8;
        make(&pk, INFO, KEY, [3; 16], &k.sk).unwrap()
    };
    let enc_with = |i: usize| resigned(&record, &k.sk, |r| r.enc[i] ^= 0x01);
    let cases = [
        // The classical half: the X25519 public key, its first and last byte.
        (
            "X25519 part of the receiving key",
            key_with(PUBLIC_KEY - 32),
        ),
        (
            "X25519 part of the receiving key, last byte",
            key_with(PUBLIC_KEY - 1),
        ),
        ("X25519 part of enc", enc_with(ENC - 32)),
        ("X25519 part of enc, last byte", enc_with(ENC - 1)),
        // The post-quantum half: a coefficient of the ML-KEM key, a byte of
        // its rho, and the ML-KEM ciphertext's first and last byte.
        ("ML-KEM part of the receiving key", coefficient_moved),
        ("ML-KEM part of the receiving key, rho", key_with(1170)),
        ("ML-KEM part of enc", enc_with(0)),
        ("ML-KEM part of enc, last byte", enc_with(ENC - 33)),
    ];
    for (what, r) in cases {
        counts();
        assert_eq!(
            open(&r, &k.ipk, INFO, &k.seed).err(),
            Some(Error::WrapInvalid),
            "{what}"
        );
        assert_eq!(counts(), (1, 1, 1), "{what}");
    }
}

/// CRY-05 T13 (CRY-05.4): one changed byte of enc, ct, info, the signer id
/// or either half of the signature, every byte in turn; then records whose
/// enc is 1,119, 1,121 or 32 bytes, signed again validly by the sender:
/// `WrapInvalid` each time, and no wrong length reaches the decapsulation.
#[test]
fn cry05_4_t13_one_changed_byte_of_a_record_fails() {
    let k = keys();
    let record = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    assert!(open(&record, &k.ipk, INFO, &k.seed).is_ok());
    let lens = [ENC, record.ct.len(), INFO.len(), 16, SIGNATURE];
    for (part, len) in lens.into_iter().enumerate() {
        for i in 0..len {
            let mut r = record.clone();
            match part {
                0 => r.enc[i] ^= 1,
                1 => r.ct[i] ^= 1,
                2 => r.info[i] ^= 1,
                3 => r.signer[i] ^= 1,
                _ => r.signature[i] ^= 1,
            }
            assert_eq!(
                open(&r, &k.ipk, INFO, &k.seed).err(),
                Some(Error::WrapInvalid),
                "part {part} byte {i}"
            );
        }
    }
    let short = resigned(&record, &k.sk, |r| {
        r.enc.pop();
    });
    let long = resigned(&record, &k.sk, |r| r.enc.push(0));
    let classical = resigned(&record, &k.sk, |r| r.enc = r.enc[ENC - 32..].to_vec());
    counts();
    for r in [&short, &long, &classical] {
        assert_eq!(
            open(r, &k.ipk, INFO, &k.seed).err(),
            Some(Error::WrapInvalid),
            "{}",
            r.enc.len()
        );
    }
    assert_eq!(
        counts(),
        (3, 3, 0),
        "a wrong enc length reached the decapsulation"
    );
}

/// CRY-05 T08 on a record (CRY-05.5, CRY-05.7): the signature's halves in
/// T08's forms, and an Ed25519-only signature by the identity key's Ed25519
/// half over the record's own field list, are refused at step 3; nothing
/// decapsulates.
#[test]
fn cry05_5_t08_signature_halves_refused_at_step_3() {
    let k = keys();
    let record = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    let (other, _) = pq::identity_keypair().unwrap();
    let theirs = resigned(&record, &other, |_| {});
    let elsewhere = make(&k.pk, b"demo wrap info: vault 3", KEY, [3; 16], &k.sk).unwrap();
    let ml = SIGNATURE - 64;
    // CRY-05.7: an Ed25519-only signature over the record's own field list,
    // made by the Ed25519 half of the pinned identity key; valid as Ed25519.
    let ed_seed = SecretBytes::new(k.sk.expose()[32..].to_vec());
    let signed = signed_part(
        record.suite,
        &record.enc,
        &record.ct,
        &record.info,
        &record.signer,
    )
    .unwrap();
    let ed_only = sign::ed25519_sign(&ed_seed, &signed).unwrap();
    assert_eq!(
        sign::ed25519_verify(&k.ipk[1952..], &signed, &ed_only),
        Ok(())
    );
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut r = record.clone();
        f(&mut r.signature);
        r
    };
    let cases = [
        ("Ed25519 half zeroed", with(&|s| s[ml..].fill(0))),
        ("ML-DSA half zeroed", with(&|s| s[..ml].fill(0))),
        (
            "ML-DSA half of another key's signature",
            with(&|s| s[..ml].copy_from_slice(&theirs.signature[..ml])),
        ),
        (
            "ML-DSA half of a signature over another record",
            with(&|s| s[..ml].copy_from_slice(&elsewhere.signature[..ml])),
        ),
        (
            "cut to 3,372 bytes",
            with(&|s| {
                s.pop();
            }),
        ),
        ("the Ed25519 half alone", with(&|s| *s = s[ml..].to_vec())),
        ("the ML-DSA half alone", with(&|s| s.truncate(ml))),
        (
            "an Ed25519-only signature over the record by the identity key's half",
            with(&|s| *s = ed_only.to_vec()),
        ),
    ];
    counts();
    for (what, r) in cases {
        assert_eq!(
            open(&r, &k.ipk, INFO, &k.seed).err(),
            Some(Error::WrapInvalid),
            "{what}"
        );
        let (step3, _, decapsulations) = counts();
        assert_eq!((step3, decapsulations), (1, 0), "{what}");
    }
}

/// CRY-05 T27 (CRY-05.17): an opened plaintext prints `[hidden]`; the record
/// holds nothing secret; this module and account.rs write no log line.
#[test]
fn cry05_17_t27_secrets_print_hidden_and_nothing_is_logged() {
    let k = keys();
    let r = make(&k.pk, INFO, KEY, [3; 16], &k.sk).unwrap();
    let opened = open(&r, &k.ipk, INFO, &k.seed).unwrap();
    assert_eq!(
        format!("{opened:?} {:?} {:?}", k.seed, k.sk),
        "[hidden] [hidden] [hidden]"
    );
    for (name, source) in [
        ("wrap_record.rs", include_str!("../wrap_record.rs")),
        ("account.rs", include_str!("../account.rs")),
    ] {
        for word in [
            "println!",
            "eprintln!",
            "print!",
            "dbg!",
            "log::",
            "tracing::",
        ] {
            assert!(!source.contains(word), "{name} holds {word}");
        }
    }
}

/// A value raw, in upper and lower hex, in padded and URL base64, and its
/// SHA-256 (E13-S8's forms).
fn forms(value: &[u8]) -> Vec<Vec<u8>> {
    let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        value.to_vec(),
        hex.to_uppercase().into_bytes(),
        hex.into_bytes(),
        encode(Form::Padded, value).into_bytes(),
        encode(Form::Url, value).into_bytes(),
        hash::sha256(&[value]).expose().to_vec(),
    ]
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// CRY-05 T29 on the bytes a server will store (CRY-05.19): neither a
/// record (each field, the signed field list, its `Debug` text) nor the keys
/// row of E17-S1 (the identity key, the receiving key, the binding), nor the
/// base64url of either, holds `S_acct`, the identity private key or either
/// half of it, the receiving seed, the blob's plaintext, the KEM shared
/// secret or the wrapped key, in any of E13-S8's forms.
#[test]
fn cry05_19_t29_no_secret_in_a_record_or_the_keys_row() {
    let account = crate::account::AccountKeys::new().unwrap();
    let id = [0x29; 16];
    let binding = account.kem_signature(&id).unwrap();
    let blob = account.blob_plaintext();
    let plaintext = crate::random::bytes(32).unwrap();
    let r = make(
        account.kem_public_key(),
        INFO,
        plaintext.expose(),
        id,
        account.identity_private_key(),
    )
    .unwrap();
    let shared = pq::kem_shared_secret(account.kem_seed(), &r.enc).unwrap();
    assert_eq!(shared.len(), 32);
    let identity = account.identity_private_key().expose();
    let mut needles = Vec::new();
    for secret in [
        account.account_secret().expose(),
        identity,
        &identity[..32],
        &identity[32..],
        account.kem_seed().expose(),
        blob.expose(),
        shared.expose(),
        plaintext.expose(),
    ] {
        needles.extend(forms(secret));
    }
    assert_eq!(needles.len(), 8 * 6);
    let signed = signed_part(r.suite, &r.enc, &r.ct, &r.info, &r.signer).unwrap();
    let public = [
        &r.enc[..],
        &r.ct,
        &r.signature,
        account.identity_public_key(),
        account.kem_public_key(),
        &binding,
    ];
    let mut hays: Vec<Vec<u8>> = public.iter().map(|p| p.to_vec()).collect();
    hays.extend(public.iter().map(|p| encode(Form::Url, p).into_bytes()));
    hays.extend([
        r.info.clone(),
        signed,
        format!("{r:?}").into_bytes(),
        format!("{account:?}").into_bytes(),
    ]);
    for hay in &hays {
        for n in &needles {
            assert!(!holds(hay, n), "a stored byte holds a secret");
        }
    }
    let opened = open(&r, account.identity_public_key(), INFO, account.kem_seed()).unwrap();
    assert_eq!(opened.expose(), plaintext.expose());
}

proptest::proptest! {
    /// Round trip (Rust rule 10): open(make(x)) == x for every info and
    /// plaintext within the limits and every signer id, and one flipped byte
    /// of ct gives `WrapInvalid`.
    #[test]
    fn cry05_4_wrap_round_trip(
        info in proptest::collection::vec(0u8..=255, 0..=MAX_INFO),
        plaintext in proptest::collection::vec(0u8..=255, 0..=MAX_PLAINTEXT),
        signer in proptest::array::uniform16(0u8..=255),
        flip in proptest::prelude::any::<proptest::sample::Index>(),
    ) {
        let k = keys();
        let mut r = make(&k.pk, &info, &plaintext, signer, &k.sk).unwrap();
        proptest::prop_assert_eq!(
            open(&r, &k.ipk, &info, &k.seed).unwrap().expose().to_vec(),
            plaintext
        );
        let i = flip.index(r.ct.len());
        r.ct[i] ^= 1;
        proptest::prop_assert_eq!(open(&r, &k.ipk, &info, &k.seed).err(), Some(Error::WrapInvalid));
    }
}
