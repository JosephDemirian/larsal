//! CRY-05.8 and SYN-06.14 tests that E25-S3 owns: T14's parts that need no
//! server (sizes, the binding, the blob's seeds), the refusals of CRY-05.7
//! and of CRY-05's edge case of a key that fails the modulus check, the pin
//! compare of CRY-04.11, fresh and failing draws, and T27.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use std::cell::RefCell;

const ID: [u8; 16] = [0x14; 16];

#[test]
fn syn06_14_cry05_8_t14_account_key_sizes_and_names() {
    let a = AccountKeys::new().unwrap();
    let binding = a.kem_signature(&ID).unwrap();
    let blob = a.blob_plaintext();
    assert_eq!(
        (
            a.account_secret().len(),
            a.identity_private_key().len(),
            a.identity_public_key().len(),
            a.kem_seed().len(),
            a.kem_public_key().len(),
            binding.len(),
            blob.len(),
        ),
        (32, 64, 1984, 32, 1216, 3373, 96)
    );
    assert_eq!(BLOB_PLAINTEXT, pq::IDENTITY_PRIVATE + pq::SEED);
    // Every sign-up draws anew.
    let b = AccountKeys::new().unwrap();
    assert_ne!(a.account_secret(), b.account_secret());
    assert_ne!(a.identity_public_key(), b.identity_public_key());
    assert_ne!(a.kem_public_key(), b.kem_public_key());
}

#[test]
fn cry05_8_t14_binding_verifies_and_fails_on_one_changed_byte_of_each_field() {
    let a = AccountKeys::new().unwrap();
    let (ipk, kpk) = (a.identity_public_key(), a.kem_public_key());
    let sig = a.kem_signature(&ID).unwrap();
    assert_eq!(check_kem_binding(ipk, &ID, kpk, &sig), Ok(()));
    // The field list built by hand from CRY-05.8 and CRY-04.2.
    let by_hand = sign::field_list(&[b"sync-kem-key-v1", &ID, kpk]).unwrap();
    let theirs = pq::composite_sign(a.identity_private_key(), &by_hand).unwrap();
    assert_eq!(check_kem_binding(ipk, &ID, kpk, &theirs), Ok(()));
    let flip = |v: &[u8], i: usize| {
        let mut v = v.to_vec();
        v[i] ^= 1;
        v
    };
    for i in [0, 15] {
        let id: [u8; 16] = flip(&ID, i).try_into().unwrap();
        assert_eq!(
            check_kem_binding(ipk, &id, kpk, &sig),
            Err(Error::SignatureInvalid),
            "id {i}"
        );
    }
    for i in [0, 600, 1183, 1184, 1215] {
        assert_eq!(
            check_kem_binding(ipk, &ID, &flip(kpk, i), &sig),
            Err(Error::SignatureInvalid),
            "receiving key {i}"
        );
    }
    for i in [0, 1951, 1952, 1983] {
        assert_eq!(
            check_kem_binding(&flip(ipk, i), &ID, kpk, &sig),
            Err(Error::SignatureInvalid),
            "identity key {i}"
        );
    }
    for i in [0, 3308, 3309, 3372] {
        assert_eq!(
            check_kem_binding(ipk, &ID, kpk, &flip(&sig, i)),
            Err(Error::SignatureInvalid),
            "signature {i}"
        );
    }
    // Another account's identity key does not take this binding.
    let b = AccountKeys::new().unwrap();
    assert_eq!(
        check_kem_binding(b.identity_public_key(), &ID, kpk, &sig),
        Err(Error::SignatureInvalid)
    );
}

#[test]
fn cry05_8_t14_the_blobs_seeds_give_the_public_keys() {
    let a = AccountKeys::new().unwrap();
    let blob = a.blob_plaintext();
    let (identity, seed) = blob.expose().split_at(64);
    assert_eq!(identity, a.identity_private_key().expose());
    assert_eq!(seed, a.kem_seed().expose());
    let identity = SecretBytes::new(identity.to_vec());
    let seed = SecretBytes::new(seed.to_vec());
    assert_eq!(
        pq::identity_public(&identity).unwrap(),
        a.identity_public_key()
    );
    assert_eq!(pq::xwing_public(&seed).unwrap(), a.kem_public_key());
    // A Mac that has S_acct and the blob's plaintext has the same keys.
    let copy = || SecretBytes::new(a.account_secret().expose().to_vec());
    let restored = AccountKeys::from_blob(copy(), &blob).unwrap();
    assert_eq!(restored.account_secret(), a.account_secret());
    assert_eq!(restored.identity_public_key(), a.identity_public_key());
    assert_eq!(restored.kem_public_key(), a.kem_public_key());
    let sig = restored.kem_signature(&ID).unwrap();
    assert_eq!(
        check_kem_binding(a.identity_public_key(), &ID, a.kem_public_key(), &sig),
        Ok(())
    );
    for len in [0, 64, 95, 97] {
        let bad = SecretBytes::new(vec![7; len]);
        assert_eq!(
            AccountKeys::from_blob(copy(), &bad).err(),
            Some(Error::KeyLength),
            "{len}"
        );
    }
    let short = SecretBytes::new(vec![7; 31]);
    assert_eq!(
        AccountKeys::from_blob(short, &blob).err(),
        Some(Error::KeyLength)
    );
}

/// CRY-05.7, CRY-05.8: an Ed25519-only binding, a binding over the old label
/// `sync-x25519-v1`, a classical binding of an X25519 key, and a receiving
/// key of 32 bytes (X25519 alone) even with a valid composite binding, are
/// each refused; the 32-byte key before any signature check.
#[test]
fn cry05_7_ed25519_only_binding_old_label_and_x25519_key_refused() {
    let a = AccountKeys::new().unwrap();
    let (ipk, kpk) = (a.identity_public_key(), a.kem_public_key());
    let ed_seed = SecretBytes::new(a.identity_private_key().expose()[32..].to_vec());
    let list = |label: &[u8], key: &[u8]| sign::field_list(&[label, &ID, key]).unwrap();
    let new_label = list(b"sync-kem-key-v1", kpk);
    let old_label = list(b"sync-x25519-v1", kpk);
    let ed_only = sign::ed25519_sign(&ed_seed, &new_label).unwrap();
    assert_eq!(
        sign::ed25519_verify(&ipk[1952..], &new_label, &ed_only),
        Ok(())
    );
    let composite_old = pq::composite_sign(a.identity_private_key(), &old_label).unwrap();
    let (_, x25519) = crate::hpke::x25519_keypair().unwrap();
    let classical = sign::ed25519_sign(&ed_seed, &list(b"sync-x25519-v1", &x25519)).unwrap();
    let composite_x25519 =
        pq::composite_sign(a.identity_private_key(), &list(b"sync-kem-key-v1", &x25519)).unwrap();
    let good = a.kem_signature(&ID).unwrap();
    // What, the identity key, the receiving key, the binding.
    type Case<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8]);
    let cases: [Case<'_>; 6] = [
        ("an Ed25519-only binding", ipk, kpk, &ed_only),
        (
            "an Ed25519-only binding and key",
            &ipk[1952..],
            kpk,
            &ed_only,
        ),
        (
            "a composite binding over sync-x25519-v1",
            ipk,
            kpk,
            &composite_old,
        ),
        (
            "a classical binding of an X25519 key",
            &ipk[1952..],
            &x25519,
            &classical,
        ),
        (
            "an X25519 key with a valid composite binding",
            ipk,
            &x25519,
            &composite_x25519,
        ),
        ("a receiving key one byte short", ipk, &kpk[..1215], &good),
    ];
    for (what, identity, key, sig) in cases {
        assert_eq!(
            check_kem_binding(identity, &ID, key, sig),
            Err(Error::SignatureInvalid),
            "{what}"
        );
    }
    // The X25519 key is refused before the composite check (no Ed25519 check).
    sign::probe::take();
    assert!(check_kem_binding(ipk, &ID, &x25519, &composite_x25519).is_err());
    assert_eq!(sign::probe::take(), 0);
    // Control: the same check runs and passes on the real key.
    assert_eq!(check_kem_binding(ipk, &ID, kpk, &good), Ok(()));
    assert_eq!(sign::probe::take(), 1);
}

/// CRY-05's edge case: "A receiving key of 1,216 bytes whose ML-KEM part has
/// a coefficient of 3,329 or more (fails the modulus check): refused before
/// any wrap; the entry or account keys holding it fail their check." (Checker
/// 1's attack c1_b2, round 1.) The account's own key with one coefficient set
/// to 3,329, bound by a valid composite signature: the binding check refuses
/// it before any signature check (no Ed25519 check runs), the pin never
/// matches it, and neither `wrap_record::make` nor `pq::seal` seals to it.
/// Cases: the first coefficient (0 of polynomial 0) and the last (255 of
/// polynomial 2). Control: 3,328, the largest the check takes, passes all.
#[test]
fn cry05_edge_case_bad_modulus_key_with_a_valid_binding_is_refused() {
    let a = AccountKeys::new().unwrap();
    let ipk = a.identity_public_key();
    // FIPS 203 ByteEncode12: coefficient i is bits 12i to 12i + 11 of the
    // key, least significant bit first.
    let with = |i: usize, value: u16| {
        let mut key = a.kem_public_key().to_vec();
        for b in 0..12 {
            let (byte, bit) = ((12 * i + b) / 8, (12 * i + b) % 8);
            key[byte] = (key[byte] & !(1 << bit)) | (u8::from(((value >> b) & 1) == 1) << bit);
        }
        key
    };
    let bound = |key: &[u8]| {
        pq::composite_sign(a.identity_private_key(), &binding(&ID, key).unwrap()).unwrap()
    };
    for (what, i) in [("coefficient 0", 0), ("coefficient 767 (the last)", 767)] {
        let bad = with(i, 3329);
        assert_ne!(bad, a.kem_public_key(), "{what}");
        let sig = bound(&bad);
        sign::probe::take();
        assert_eq!(
            check_kem_binding(ipk, &ID, &bad, &sig),
            Err(Error::SignatureInvalid),
            "{what}"
        );
        assert_eq!(sign::probe::take(), 0, "{what}: a signature check ran");
        assert!(!pins_match(ipk, &bad, ipk, &bad), "{what}");
        assert_eq!(
            pq::seal(&bad, b"i", b"k").err(),
            Some(Error::WrapInvalid),
            "{what}"
        );
        assert_eq!(
            crate::wrap_record::make(&bad, b"i", b"k", ID, a.identity_private_key()).err(),
            Some(Error::WrapInvalid),
            "{what}"
        );
        // Control: the same position at 3,328 passes the check and the
        // signature check runs.
        let max = with(i, 3328);
        let sig = bound(&max);
        sign::probe::take();
        assert_eq!(check_kem_binding(ipk, &ID, &max, &sig), Ok(()), "{what}");
        assert_eq!(sign::probe::take(), 1, "{what}");
        assert!(pins_match(ipk, &max, ipk, &max), "{what}");
        assert!(pq::seal(&max, b"i", b"k").is_ok(), "{what}");
    }
}

/// CRY-05.8, SYN-06.6, CRY-04.11: a pin is the whole 1,984-byte identity key
/// and the whole 1,216-byte receiving key, compared in constant time.
#[test]
fn cry05_8_cry04_11_pins_compare_whole_keys_in_constant_time() {
    let a = AccountKeys::new().unwrap();
    let (ipk, kpk) = (a.identity_public_key(), a.kem_public_key());
    assert!(pins_match(ipk, kpk, ipk, kpk));
    let flip = |v: &[u8], i: usize| {
        let mut v = v.to_vec();
        v[i] ^= 1;
        v
    };
    for i in [0, 1951, 1952, 1983] {
        assert!(!pins_match(ipk, kpk, &flip(ipk, i), kpk), "identity {i}");
        assert!(
            !pins_match(&flip(ipk, i), kpk, ipk, kpk),
            "pinned identity {i}"
        );
    }
    for i in [0, 1183, 1184, 1215] {
        assert!(
            !pins_match(ipk, kpk, ipk, &flip(kpk, i)),
            "receiving key {i}"
        );
    }
    // A shorter pin, a 32-byte (X25519 or Ed25519 alone) pin, never match.
    assert!(!pins_match(&ipk[1952..], kpk, &ipk[1952..], kpk));
    assert!(!pins_match(ipk, &kpk[1184..], ipk, &kpk[1184..]));
    assert!(!pins_match(ipk, kpk, &ipk[..1983], kpk));
    let b = AccountKeys::new().unwrap();
    assert!(!pins_match(
        ipk,
        kpk,
        b.identity_public_key(),
        b.kem_public_key()
    ));
    // Both keys go through secret::ct_eq, with no early exit between them.
    let source = include_str!("../account.rs");
    let body = &source[source.find("pub fn pins_match").unwrap()..];
    let body = &body[..body.find("\n}\n").unwrap()];
    assert!(
        body.contains("ct_eq(pinned_identity, identity_public_key)"),
        "{body}"
    );
    assert!(body.contains("ct_eq(pinned_kem, kem_public_key)"), "{body}");
    assert!(!body.contains("&&") && !body.contains("||"), "{body}");
}

/// CRY-05.8, CRY-04 T17's rule: the three draws are S_acct (32), the
/// identity key (64) and the receiving seed (32); a source that fails at any
/// of them, or gives a wrong length, fails closed and returns nothing.
#[test]
fn cry05_8_t17_a_failed_random_draw_makes_nothing() {
    let asked = RefCell::new(Vec::new());
    let keys = AccountKeys::new_with(|n| {
        asked.borrow_mut().push(n);
        crate::random::bytes(n)
    })
    .unwrap();
    assert_eq!(*asked.borrow(), [32, 64, 32]);
    assert_eq!(keys.kem_public_key().len(), 1216);
    for fail_at in 0..3 {
        let calls = RefCell::new(0);
        let result = AccountKeys::new_with(|n| {
            let i = calls.replace_with(|c| *c + 1);
            if i == fail_at {
                Err(Error::RandomSource)
            } else {
                crate::random::bytes(n)
            }
        });
        assert_eq!(result.err(), Some(Error::RandomSource), "draw {fail_at}");
        assert_eq!(*calls.borrow(), fail_at + 1, "no draw after the failure");
    }
    for short_at in 0..3 {
        let calls = RefCell::new(0);
        let result = AccountKeys::new_with(|n| {
            let i = calls.replace_with(|c| *c + 1);
            crate::random::bytes(if i == short_at { n - 1 } else { n })
        });
        assert_eq!(result.err(), Some(Error::RandomSource), "draw {short_at}");
    }
}

/// CRY-05 T27 (CRY-05.17): every secret of an account prints `[hidden]`.
#[test]
fn cry05_17_t27_account_keys_print_hidden() {
    let a = AccountKeys::new().unwrap();
    assert_eq!(format!("{a:?}"), "[hidden]");
    assert_eq!(
        format!(
            "{:?} {:?} {:?} {:?}",
            a.account_secret(),
            a.identity_private_key(),
            a.kem_seed(),
            a.blob_plaintext()
        ),
        "[hidden] [hidden] [hidden] [hidden]"
    );
}
