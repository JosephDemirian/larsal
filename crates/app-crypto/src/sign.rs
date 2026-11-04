//! Signatures for sync, accounts and sharing (story E16-S2, CRY-04): Ed25519
//! sign and verify (RFC 8032), ECDSA P-256 verify (FIPS 186-5, SEC1 v2), and
//! the field lists every signed or bound message is made of (CRY-04.2).
//!
//! An Ed25519 private key is its 32-byte seed in a [`SecretBytes`]; the
//! signing key made from it lives only inside one call, wiped on drop, with
//! 32 KiB of stack below the call zeroed after it.

use crate::Error;
use crate::secret::{SecretBytes, scrubbed};

/// Puts fields into bytes for signing and binding (CRY-04.2): for each field
/// in order, its length as a u32 big endian, then its bytes.
///
/// Guarantees: two different lists never give the same bytes, so a
/// signature or binding made for one use cannot be read as another.
///
/// # Errors
/// [`Error::TooLarge`] when a field is 4 GiB or longer.
pub fn field_list(fields: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| Error::TooLarge)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

fn seed_of(seed: &SecretBytes) -> Result<&[u8; 32], Error> {
    seed.expose().try_into().map_err(|_| Error::KeyLength)
}

/// The Ed25519 public key of a 32-byte seed (RFC 8032 section 5.1.5).
///
/// # Errors
/// [`Error::KeyLength`] when the seed is not 32 bytes.
pub fn ed25519_public(seed: &SecretBytes) -> Result<[u8; 32], Error> {
    let seed = seed_of(seed)?;
    Ok(scrubbed(|| {
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes()
    }))
}

/// Signs `message` with pure Ed25519 (RFC 8032 section 5.1.6: no prehash,
/// no context) and the key of a 32-byte seed.
///
/// Guarantees: the same seed and message always give the same 64 bytes.
///
/// # Errors
/// [`Error::KeyLength`] when the seed is not 32 bytes.
pub fn ed25519_sign(seed: &SecretBytes, message: &[u8]) -> Result<[u8; 64], Error> {
    use ed25519_dalek::Signer as _;
    let seed = seed_of(seed)?;
    Ok(scrubbed(|| {
        ed25519_dalek::SigningKey::from_bytes(seed)
            .sign(message)
            .to_bytes()
    }))
}

/// Checks a pure Ed25519 signature, strictly (CRY-04.3): it refuses an S
/// that is not below the group order, small-order public keys and R values,
/// and a public key that does not decode.
///
/// # Errors
/// [`Error::SignatureInvalid`] for every failure, and for a public key that
/// is not 32 bytes or a signature that is not 64.
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    #[cfg(test)]
    probe::count();
    let public: &[u8; 32] = public.try_into().map_err(|_| Error::SignatureInvalid)?;
    let signature: &[u8; 64] = signature.try_into().map_err(|_| Error::SignatureInvalid)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(public).map_err(|_| Error::SignatureInvalid)?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| Error::SignatureInvalid)
}

/// Checks an ECDSA P-256 signature over SHA-256 of `message` (CRY-04.4).
///
/// Guarantees: the public key is the 65-byte SEC1 uncompressed form
/// `04 ‖ X ‖ Y` of a point on the curve (compressed and hybrid forms are
/// refused); the signature is strict DER (so at most 72 bytes) with no
/// trailing bytes and r and s from 1 to n − 1. A high s is accepted
/// (the Secure Enclave does not normalize it).
///
/// # Errors
/// [`Error::SignatureInvalid`] for every failure.
pub fn p256_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    use p256::ecdsa::signature::Verifier as _;
    let key = p256_key(public).ok_or(Error::SignatureInvalid)?;
    let signature =
        p256::ecdsa::Signature::from_der(signature).map_err(|_| Error::SignatureInvalid)?;
    key.verify(message, &signature)
        .map_err(|_| Error::SignatureInvalid)
}

/// The P-256 public key of CRY-04.4: only the uncompressed form (tag 04;
/// its length the SEC1 reader checks) of a point on the curve.
fn p256_key(public: &[u8]) -> Option<p256::ecdsa::VerifyingKey> {
    if public.first() != Some(&0x04) {
        return None;
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(public).ok()
}

/// True when `public` is a P-256 public key [`p256_verify`] takes: the
/// 65-byte SEC1 uncompressed form `04 ‖ X ‖ Y` of a point on the curve
/// (SYN-04.2: a device key is checked when it is registered).
#[must_use]
pub fn p256_public_ok(public: &[u8]) -> bool {
    p256_key(public).is_some()
}

/// Tests only (SYN-04, E16-S5): a software P-256 key in memory, the stand-in
/// for a Mac's device key (SYN-04.1) in the server's tests. Built only with
/// the `test-p256-key` feature, which only test builds turn on: in sync,
/// app-crypto never signs with P-256 (CRY-04.4).
///
/// Guarantees: the private key comes from [`crate::random`], stays in
/// `p256`'s own type (wiped on drop) and is never returned; `Debug` prints
/// `[hidden]`.
#[cfg(feature = "test-p256-key")]
pub struct P256TestKey(p256::ecdsa::SigningKey);

#[cfg(feature = "test-p256-key")]
impl P256TestKey {
    /// A new key from 32 random bytes.
    ///
    /// # Errors
    /// [`Error::RandomSource`] when the random source fails, and
    /// [`Error::KeyLength`] for the one draw in about 2^128 that is not a
    /// valid scalar.
    pub fn new() -> Result<Self, Error> {
        let scalar = crate::random::bytes(32)?;
        p256::ecdsa::SigningKey::from_slice(scalar.expose())
            .map(Self)
            .map_err(|_| Error::KeyLength)
    }

    /// The public key as 65 SEC1 bytes, `04 ‖ X ‖ Y` (CRY-04.4).
    #[must_use]
    pub fn public(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// ECDSA P-256 over SHA-256 of `message`, as X9.62 DER: the form
    /// [`p256_verify`] checks.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = self.0.sign(message);
        signature.to_der().as_bytes().to_vec()
    }
}

#[cfg(feature = "test-p256-key")]
impl core::fmt::Debug for P256TestKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[hidden]")
    }
}

/// Test-only: how many times [`ed25519_verify`] ran on this thread, so a test
/// can see that a check ran or did not run (CRY-04 T09).
#[cfg(test)]
pub(crate) mod probe {
    use core::cell::Cell;

    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count() {
        CALLS.with(|n| n.set(n.get().wrapping_add(1)));
    }

    /// Calls on this thread since the last `take`.
    pub(crate) fn take() -> usize {
        CALLS.with(Cell::take)
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn seed(s: &str) -> SecretBytes {
        SecretBytes::new(hex(s))
    }

    /// RFC 8032 section 7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc)
    /// (seed, public key, message, signature), from
    /// <https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1>.
    const RFC8032: [[&str; 4]; 4] = [
        [
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ],
        [
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ],
        [
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ],
        [
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ],
    ];

    #[test]
    fn t01_ed25519_rfc8032_vectors_sign_and_verify() {
        for [s, public, message, signature] in RFC8032 {
            let s = seed(s);
            let (public, message, signature) = (hex(public), hex(message), hex(signature));
            assert_eq!(ed25519_public(&s).unwrap().to_vec(), public);
            let made = ed25519_sign(&s, &message).unwrap();
            assert_eq!(made.to_vec(), signature);
            assert_eq!(ed25519_verify(&public, &message, &made), Ok(()));
        }
    }

    /// The group order L (RFC 8032 section 5.1), little endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    fn add_le(a: &[u8], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        out
    }

    #[test]
    fn t03_ed25519_refuses_s_plus_l_and_small_order_keys() {
        let [_, public, _, signature] = RFC8032[0];
        let (public, signature) = (hex(public), hex(signature));
        // S + L: the same point equation holds, but S is not below L.
        let mut high = signature.clone();
        let s = add_le(&signature[32..], &L);
        high[32..].copy_from_slice(&s);
        assert_eq!(
            ed25519_verify(&public, b"", &high),
            Err(Error::SignatureInvalid)
        );
        // Small-order public keys: the identity (y = 1) and the point of
        // order 2 (y = -1), with any signature.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        for key in [identity, minus_one] {
            assert_eq!(
                ed25519_verify(&key, b"", &signature),
                Err(Error::SignatureInvalid)
            );
            // An all-identity signature (R = identity, S = 0) is refused too.
            let mut zero = [0u8; 64];
            zero[0] = 1;
            assert_eq!(
                ed25519_verify(&key, b"", &zero),
                Err(Error::SignatureInvalid)
            );
        }
        // A public key that does not decode (y >= p): SignatureInvalid.
        assert_eq!(
            ed25519_verify(&[0xff; 32], b"", &signature),
            Err(Error::SignatureInvalid)
        );
    }

    /// RFC 6979 appendix A.2.5, the P-256 key, from
    /// <https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5>.
    fn rfc6979_key() -> Vec<u8> {
        [
            vec![4],
            hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"),
            hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"),
        ]
        .concat()
    }

    /// A DER `ECDSA-Sig-Value` of r and s (big endian, no leading zeros).
    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let int = |v: &[u8]| {
            let v: Vec<u8> = if v[0] & 0x80 != 0 {
                [&[0][..], v].concat()
            } else {
                v.to_vec()
            };
            [vec![2, v.len() as u8], v].concat()
        };
        let body = [int(r), int(s)].concat();
        [vec![0x30, body.len() as u8], body].concat()
    }

    /// RFC 6979 A.2.5 with SHA-256: "sample" and "test" (r, s).
    fn rfc6979_signatures() -> [(&'static [u8], Vec<u8>, Vec<u8>); 2] {
        [
            (
                b"sample",
                hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
                hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
            ),
            (
                b"test",
                hex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"),
                hex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
            ),
        ]
    }

    #[test]
    fn t04_p256_rfc6979_sample_and_test_verify() {
        let key = rfc6979_key();
        for (message, r, s) in rfc6979_signatures() {
            assert_eq!(p256_verify(&key, message, &der(&r, &s)), Ok(()));
        }
    }

    /// The group order n of P-256 (SEC 2 section 2.4.2), big endian.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    fn sub_be(a: &[u8; 32], b: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut v = i16::from(a[i]) - i16::from(b[i]) - borrow;
            borrow = i16::from(v < 0);
            if v < 0 {
                v += 256;
            }
            out[i] = v as u8;
        }
        out.to_vec()
    }

    /// SYN-04.2, CRY-04.4: a registered device key is the uncompressed
    /// form of a point on the curve; the compressed and hybrid forms, a
    /// point off the curve, the point at infinity and other lengths are
    /// refused.
    #[test]
    fn syn04_2_p256_public_ok_takes_only_an_uncompressed_point() {
        let key = rfc6979_key();
        assert!(p256_public_ok(&key));
        let mut compressed = vec![if key[64] & 1 == 1 { 3 } else { 2 }];
        compressed.extend_from_slice(&key[1..33]);
        let mut hybrid = key.clone();
        hybrid[0] = if key[64] & 1 == 1 { 7 } else { 6 };
        let mut off = key.clone();
        off[64] ^= 1;
        for bad in [
            compressed,
            hybrid,
            off,
            vec![0],
            vec![4; 65],
            key[..64].to_vec(),
        ] {
            assert!(!p256_public_ok(&bad), "{bad:02x?}");
        }
    }

    #[test]
    fn t06_p256_encodings() {
        let key = rfc6979_key();
        let [(message, r, s), _] = rfc6979_signatures();
        let good = der(&r, &s);
        // The same key in compressed form (Y is odd: 0x03): refused.
        let mut compressed = vec![if key[64] & 1 == 1 { 3 } else { 2 }];
        compressed.extend_from_slice(&key[1..33]);
        assert_eq!(
            p256_verify(&compressed, message, &good),
            Err(Error::SignatureInvalid)
        );
        // The hybrid form (0x06 or 0x07 with both coordinates): refused.
        let mut hybrid = key.clone();
        hybrid[0] = if key[64] & 1 == 1 { 7 } else { 6 };
        assert_eq!(
            p256_verify(&hybrid, message, &good),
            Err(Error::SignatureInvalid)
        );
        // One trailing byte: refused.
        assert_eq!(
            p256_verify(&key, message, &[good.as_slice(), &[0]].concat()),
            Err(Error::SignatureInvalid)
        );
        // A leading zero byte too many in r (not minimal): refused.
        let mut long_r = vec![0x30, good[1] + 1, 2, good[3] + 1, 0];
        long_r.extend_from_slice(&good[4..]);
        assert_eq!(
            p256_verify(&key, message, &long_r),
            Err(Error::SignatureInvalid)
        );
        // RFC 6979's "sample" s is already high (above n / 2): it passes,
        // and so does its low form n - s.
        assert!(s[0] > 0x7f);
        assert_eq!(p256_verify(&key, message, &good), Ok(()));
        let low = sub_be(&N, &s);
        assert!(low[0] < 0x80);
        assert_eq!(p256_verify(&key, message, &der(&r, &low)), Ok(()));
        // A valid X with Y off the curve (Y + 1): refused.
        let mut off = key.clone();
        off[64] ^= 1;
        assert_eq!(
            p256_verify(&off, message, &good),
            Err(Error::SignatureInvalid)
        );
        // r = 0 and s = n: refused.
        assert_eq!(
            p256_verify(&key, message, &der(&[0], &s)),
            Err(Error::SignatureInvalid)
        );
        assert_eq!(
            p256_verify(&key, message, &der(&r, &N)),
            Err(Error::SignatureInvalid)
        );
        // Over 72 bytes: refused.
        assert_eq!(
            p256_verify(&key, message, &[0x30; 73]),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn cry04_14_one_changed_byte_of_message_key_or_signature_fails() {
        // CRY-04.14 for both signature kinds: every byte of the message,
        // the public key and the signature, one at a time.
        let [_, public, message, signature] = RFC8032[2];
        let (public, message, signature) = (hex(public), hex(message), hex(signature));
        let key = rfc6979_key();
        let [(m2, r, s2), _] = rfc6979_signatures();
        let der_sig = der(&r, &s2);
        for (verify, pk, msg, sig) in [
            (
                ed25519_verify as fn(&[u8], &[u8], &[u8]) -> Result<(), Error>,
                public,
                message,
                signature,
            ),
            (p256_verify, key, m2.to_vec(), der_sig),
        ] {
            assert_eq!(verify(&pk, &msg, &sig), Ok(()));
            for part in 0..3 {
                let len = [pk.len(), msg.len(), sig.len()][part];
                for i in 0..len {
                    let (mut p, mut m, mut g) = (pk.clone(), msg.clone(), sig.clone());
                    [&mut p, &mut m, &mut g][part][i] ^= 0x01;
                    assert_eq!(
                        verify(&p, &m, &g),
                        Err(Error::SignatureInvalid),
                        "part {part} byte {i}"
                    );
                }
            }
        }
    }

    /// Reads RustCrypto's blobby file: a VLQ count of blobs, a VLQ count of
    /// shared blobs and those blobs, then each blob as a VLQ (low bit set:
    /// an index into the shared blobs; clear: a length) and its bytes.
    pub(crate) fn blobby(d: &[u8]) -> Vec<&[u8]> {
        fn vlq(d: &[u8], i: &mut usize) -> usize {
            let mut b = d[*i];
            *i += 1;
            let mut v = usize::from(b & 0x7f);
            while b & 0x80 != 0 {
                b = d[*i];
                *i += 1;
                v = ((v + 1) << 7) + usize::from(b & 0x7f);
            }
            v
        }
        let mut i = 0;
        let total = vlq(d, &mut i);
        let shared: Vec<&[u8]> = (0..vlq(d, &mut i))
            .map(|_| {
                let n = vlq(d, &mut i);
                i += n;
                &d[i - n..i]
            })
            .collect();
        let mut out = Vec::new();
        while i < d.len() {
            let v = vlq(d, &mut i);
            if v & 1 == 1 {
                out.push(shared[v >> 1]);
            } else {
                i += v >> 1;
                out.push(&d[i - (v >> 1)..i]);
            }
        }
        assert_eq!(out.len(), total);
        out
    }

    /// A coordinate as 32 bytes: Wycheproof writes them as DER integers, so
    /// some have a leading zero byte or are shorter.
    fn coordinate(v: &[u8]) -> Vec<u8> {
        let v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
        [vec![0; 32 - v.len()], v].concat()
    }

    /// CRY-04.13, T05: Wycheproof `ecdsa_secp256r1_sha256_test.json` (DER
    /// signatures), as the p256 0.14.0 copy keeps it: its file
    /// `src/test_vectors/data/wycheproof.blb`, made from Wycheproof
    /// (<https://github.com/C2SP/wycheproof/tree/main/testvectors_v1>) by
    /// RustCrypto's `wycheproof2blb`, 5 blobs a case: x, y, message, DER
    /// signature, valid (1) or not (0). The file's bytes are pinned by the
    /// copy's checksum list (scripts/check-vendor.sh) and by its SHA-256 here.
    #[test]
    fn t05_p256_wycheproof_cases() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/crates-io/p256-0.14.0/src/test_vectors/data/wycheproof.blb"
        );
        let data = std::fs::read(path).unwrap();
        assert_eq!(
            crate::hash::sha256(&[&data]).expose(),
            hex("5c833d53c7ad3f77c470f72d2bca6b1845986f66ac18af85d3db3cf896b403b8")
        );
        let blobs = blobby(&data);
        let (mut valid, mut invalid) = (0, 0);
        for case in blobs.chunks(5) {
            let key = [vec![4], coordinate(case[0]), coordinate(case[1])].concat();
            let want = match case[4] {
                [1] => Ok(()),
                [0] => Err(Error::SignatureInvalid),
                other => panic!("flag {other:?}"),
            };
            assert_eq!(p256_verify(&key, case[2], case[3]), want, "{case:02x?}");
            if want.is_ok() {
                valid += 1
            } else {
                invalid += 1
            }
        }
        assert_eq!((valid, invalid), (147, 239));
    }

    #[test]
    fn t16_field_lists_never_collide() {
        assert_eq!(
            field_list(&[b"a", b"bc"]).unwrap(),
            hex("00000001 61 00000002 6263")
        );
        assert_eq!(
            field_list(&[b"ab", b"c"]).unwrap(),
            hex("00000002 6162 00000001 63")
        );
        assert_eq!(field_list(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(field_list(&[b""]).unwrap(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn a_seed_of_the_wrong_length_is_refused() {
        for n in [0, 31, 33, 64] {
            let s = SecretBytes::new(vec![7; n]);
            assert_eq!(ed25519_public(&s), Err(Error::KeyLength));
            assert_eq!(ed25519_sign(&s, b"m"), Err(Error::KeyLength));
        }
        let [_, public, _, signature] = RFC8032[0];
        let (public, signature) = (hex(public), hex(signature));
        assert_eq!(
            ed25519_verify(&public[..31], b"", &signature),
            Err(Error::SignatureInvalid)
        );
        assert_eq!(
            ed25519_verify(&public, b"", &signature[..63]),
            Err(Error::SignatureInvalid)
        );
    }

    proptest::proptest! {
        /// Hostile keys and signatures give an answer, never a panic.
        #[test]
        fn hostile_verify_never_panics(
            key in proptest::collection::vec(0u8..=255, 0..80),
            sig in proptest::collection::vec(0u8..=255, 0..80),
            msg in proptest::collection::vec(0u8..=255, 0..40),
        ) {
            let _ = ed25519_verify(&key, &msg, &sig);
            let _ = p256_verify(&key, &msg, &sig);
            let mut sec1 = vec![4];
            sec1.extend(key.iter().copied().cycle().take(64));
            let _ = p256_verify(&sec1, &msg, &sig);
        }

        /// Round trip (Rust rule 10): every seed's signature over every
        /// message verifies with that seed's public key.
        #[test]
        fn sign_then_verify_round_trip(
            seed in proptest::array::uniform32(0u8..=255),
            msg in proptest::collection::vec(0u8..=255, 0..300),
        ) {
            let seed = SecretBytes::new(seed.to_vec());
            let public = ed25519_public(&seed).unwrap();
            let signature = ed25519_sign(&seed, &msg).unwrap();
            proptest::prop_assert_eq!(ed25519_verify(&public, &msg, &signature), Ok(()));
        }
    }
}
