//! CRY-05 tests that E25-S2 owns: the known answers of CRY-05.16 (T02 to
//! T06), the composite rules (T07 to T09), the HPKE refusals (T10, T11),
//! fresh draws (CRY-05.3, CRY-05.5), the sizes of CRY-05.14 and the secrets
//! and worker threads of CRY-05.17 (T27). The test data and where each file
//! comes from: tests/data/pq/README.md.
#![allow(clippy::arithmetic_side_effects, deprecated)]

use super::*;
use ::hpke::kem::SharedSecret;
use ml_dsa::{ExpandedSigningKeyBytes, Keypair as _, SigningKey};
use ml_kem::{
    Decapsulate as _, DecapsulationKey768, EncapsulationKey768, ExpandedKeyEncoding as _,
    KeyExport as _, MlKem768,
};
use std::cell::Cell;
use std::rc::Rc;

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hexed(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Reads a file of the tree and checks its SHA-256 (the pins below and in
/// tests/data/pq/README.md).
fn pinned(rel: &str, sha256: &str) -> String {
    let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
    let file = std::fs::read(&path).unwrap();
    assert_eq!(
        hexed(crate::hash::sha256(&[&file]).expose()),
        sha256,
        "{rel} changed"
    );
    String::from_utf8(file).unwrap()
}

const PQ: &str = "tests/data/pq";
const MLKEM_ACVP: (&str, &str) = (
    "mlkem768-acvp.txt",
    "491953645a0d8be76ce5abe3b71606c8948b08e88d8b2131925b7a5a6bcd271f",
);
const MLKEM_WYCHEPROOF: (&str, &str) = (
    "mlkem768-wycheproof.txt",
    "d1da45e27e10ad0a5f51499b43a07b9ffb65a25f986af8a23211c7118eabdfa2",
);
const MLDSA_ACVP: (&str, &str) = (
    "mldsa65-acvp.txt",
    "c32e32783c82088bc1ba0ab4d6a375d6e309e92c6dfa4e55d8afa36f48369620",
);
const MLDSA_WYCHEPROOF: (&str, &str) = (
    "mldsa65-wycheproof.txt",
    "53cebf39c3d23a904c725633baca8e24dd029e01f355debe639ea5506f4b7f03",
);
const COMPOSITE: (&str, &str) = (
    "composite-mldsa65-ed25519.txt",
    "d4cadfadfe63f6fb8526633cf899164f5ae4bf031760573199bfee86304d8e2b",
);
const XWING_DRAFT11: (&str, &str) = (
    "xwing-draft11.txt",
    "18134890933e3f86ce21771d98813800a65b6328e6cbc0bc49099e9c1d7d19c6",
);

fn data((name, sha256): (&str, &str)) -> String {
    pinned(&format!("{PQ}/{name}"), sha256)
}

/// One line of a cut file: its kind and its fields, with the fields of the
/// `group` line above it first (a line's own field wins).
struct Rec<'a> {
    kind: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}

impl Rec<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }
    fn bytes(&self, key: &str) -> Vec<u8> {
        hex(self.get(key).unwrap_or_else(|| panic!("no {key}")))
    }
    fn opt(&self, key: &str) -> Option<Vec<u8>> {
        self.get(key).map(hex)
    }
    fn tc(&self) -> String {
        format!("{} tc {}", self.kind, self.get("tc").unwrap_or("-"))
    }
    /// Wycheproof: "valid" is true, "invalid" false (no case is "acceptable").
    fn valid(&self) -> bool {
        match self.get("result").unwrap() {
            "valid" => true,
            "invalid" => false,
            other => panic!("{}: result {other}", self.tc()),
        }
    }
    fn passed(&self) -> bool {
        self.get("passed").unwrap() == "true"
    }
}

fn records(text: &str) -> Vec<Rec<'_>> {
    let mut group: Vec<(&str, &str)> = Vec::new();
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let mut parts = line.split(' ');
        let kind = parts.next().unwrap();
        let fields: Vec<(&str, &str)> = parts.map(|p| p.split_once('=').unwrap()).collect();
        if kind == "group" {
            group = fields;
        } else {
            out.push(Rec {
                kind,
                fields: group.iter().copied().chain(fields).collect(),
            });
        }
    }
    out
}

fn count(recs: &[Rec<'_>], kind: &str) -> usize {
    recs.iter().filter(|r| r.kind == kind).count()
}

/// A draw that returns these bytes: the test seam for random bytes.
fn scripted(bytes: &[u8]) -> impl FnOnce(usize) -> Result<SecretBytes, Error> {
    let bytes = bytes.to_vec();
    move |n| {
        assert_eq!(n, bytes.len(), "draw of another length");
        Ok(SecretBytes::new(bytes))
    }
}

/// A draw that counts its calls and returns fresh random bytes.
fn counted(calls: &Rc<Cell<usize>>) -> impl FnOnce(usize) -> Result<SecretBytes, Error> {
    let calls = Rc::clone(calls);
    move |n| {
        calls.set(calls.get() + 1);
        random::bytes(n)
    }
}

fn down(_: usize) -> Result<SecretBytes, Error> {
    Err(Error::RandomSource)
}

// --- T02: the hybrid HPKE suite ---------------------------------------------

/// A hex string value `"name":"…"` of a JSON object with its white space
/// taken out (no value of these files holds a space).
fn field<'a>(object: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":\"");
    let start = object.find(&key).unwrap() + key.len();
    &object[start..start + object[start..].find('"').unwrap()]
}

/// The JSON object that starts at `start`, to its matching brace.
fn object_at(text: &str, start: usize) -> &str {
    let mut depth = 0usize;
    for (i, c) in text[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[start..start + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("no end");
}

fn squeezed(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// CRY-05.16: hpke 0.14.1's own `test-vectors/pq-6433c8f.json` (hpkewg/hpke-pq
/// at commit 6433c8f), pinned by the copy's checksum list and the SHA-256
/// here.
const HPKE_PQ: (&str, &str) = (
    "../../vendor/crates-io/hpke-0.14.1/test-vectors/pq-6433c8f.json",
    "35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c",
);
/// CRY-05.16: hpke 0.14.1's `test-vectors/hybrid-defafa2.json`
/// (cfrg/draft-irtf-cfrg-concrete-hybrid-kems at commit defafa2).
const HPKE_HYBRID: (&str, &str) = (
    "../../vendor/crates-io/hpke-0.14.1/test-vectors/hybrid-defafa2.json",
    "08b47d9fe5c827f7ceb20dd10a59bc853a949d6eaf0ad835405e86d833f92bad",
);

#[test]
fn t02_hybrid_suite_vectors_open_and_seal() {
    let text = squeezed(&pinned(HPKE_PQ.0, HPKE_PQ.1));
    let head = r#"{"mode":0,"kem_id":25722,"kdf_id":1,"aead_id":3,"#;
    assert_eq!(text.matches(head).count(), 1);
    let record = object_at(&text, text.find(head).unwrap());
    let info = hex(field(record, "info"));
    let ikm_e = hex(field(record, "ikmE"));
    let ikm_r = hex(field(record, "ikmR"));
    let sk_rm = hex(field(record, "skRm"));
    let pk_rm = hex(field(record, "pkRm"));
    let enc_v = hex(field(record, "enc"));
    assert_eq!(field(record, "suite_id"), "48504b45647a00010003");
    let list = &record[record.find(r#""encryptions":["#).unwrap()..];
    let list = &list[..list.find(']').unwrap()];
    let encryptions: Vec<[Vec<u8>; 3]> = list
        .split('{')
        .skip(1)
        .map(|e| {
            [
                hex(field(e, "aad")),
                hex(field(e, "ct")),
                hex(field(e, "pt")),
            ]
        })
        .collect();
    assert_eq!(encryptions.len(), 10);
    assert_eq!(
        (sk_rm.len(), pk_rm.len(), enc_v.len(), ikm_e.len()),
        (SEED, PUBLIC_KEY, ENC, ENCAP_RANDOMNESS)
    );

    // The record's keys: DeriveKeyPair(ikmR) gives skRm, and Larsal's
    // public key of that seed is pkRm.
    let (sk, pk) = XWing::derive_keypair(&ikm_r);
    assert_eq!(sk.to_bytes().to_vec(), sk_rm);
    assert_eq!(pk.to_bytes().to_vec(), pk_rm);
    let seed = SecretBytes::new(sk_rm.clone());
    assert_eq!(xwing_public(&seed).unwrap(), pk_rm);

    // Larsal's single shot: the first encryption opens, and with ikmE through
    // the seam seals to the record's enc and ct.
    let [aad, ct, pt] = &encryptions[0];
    assert_eq!(
        open_aad(&seed, &enc_v, &info, aad, ct).unwrap().expose(),
        pt
    );
    let (enc, sealed) = seal_with(scripted(&ikm_e), &pk_rm, &info, aad, pt).unwrap();
    assert_eq!((&enc, &sealed), (&enc_v, ct));

    // All ten, in order, through the copy's contexts (the same suite types).
    let mut receiver = ::hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &PrivateKey::from_bytes(&sk_rm).unwrap(),
        &EncappedKey::from_bytes(&enc_v).unwrap(),
        &info,
    )
    .unwrap();
    let mut rng = Prepared::new(SecretBytes::new(ikm_e));
    let (enc, mut sender) = ::hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &PublicKey::from_bytes(&pk_rm).unwrap(),
        &info,
        &mut rng,
    )
    .unwrap();
    assert!(rng.served_once());
    assert_eq!(enc.to_bytes().to_vec(), enc_v);
    for (i, [aad, ct, pt]) in encryptions.iter().enumerate() {
        assert_eq!(&receiver.open(ct, aad).unwrap(), pt, "open {i}");
        assert_eq!(&sender.seal(pt, aad).unwrap(), ct, "seal {i}");
    }
}

// --- T03: the hybrid KEM ----------------------------------------------------

/// Encapsulates to `pk` with these 64 bytes through the copy's KEM (the
/// randomness goes in as the one fill of a [`Prepared`]).
fn encap(pk: &[u8], randomness: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = Prepared::new(SecretBytes::new(randomness.to_vec()));
    let (ss, ct): (SharedSecret<XWing>, _) =
        XWing::encap_with_rng(&PublicKey::from_bytes(pk).unwrap(), None, &mut rng).unwrap();
    assert!(rng.served_once());
    (ct.to_bytes().to_vec(), ss.0.to_vec())
}

fn decap(seed: &[u8], ct: &[u8]) -> Vec<u8> {
    let sk = PrivateKey::from_bytes(seed).unwrap();
    let ss = XWing::decap(&sk, None, &EncappedKey::from_bytes(ct).unwrap()).unwrap();
    ss.0.to_vec()
}

#[test]
fn t03_hybrid_kem_vectors_concrete_hybrid_kems_binding() {
    let text = squeezed(&pinned(HPKE_HYBRID.0, HPKE_HYBRID.1));
    let start = text.find(r#""mlkem768_x25519":["#).unwrap();
    let list = &text[start..];
    let list = &list[..list.find(']').unwrap()];
    let mut n = 0;
    for v in list.split('{').skip(1) {
        let seed = hex(field(v, "seed"));
        let pk = hex(field(v, "encapsulation_key"));
        assert_eq!(hex(field(v, "decapsulation_key")), seed);
        assert_eq!(xwing_public(&SecretBytes::new(seed.clone())).unwrap(), pk);
        let (ct, ss) = encap(&pk, &hex(field(v, "randomness")));
        assert_eq!(ct, hex(field(v, "ciphertext")));
        assert_eq!(ss, hex(field(v, "shared_secret")));
        assert_eq!(decap(&seed, &ct), ss);
        n += 1;
    }
    assert_eq!(n, 10);
}

/// Provisional (CRY-05.16): X-Wing draft 11 Appendix C carries a note that
/// its vectors will be replaced; a later draft's vectors replace them only by
/// a card change.
#[test]
fn t03_hybrid_kem_vectors_xwing_draft11_provisional() {
    let text = data(XWING_DRAFT11);
    let recs = records(&text);
    assert_eq!(count(&recs, "xwing"), 3);
    for r in &recs {
        // Draft 11's GenerateKeyPair: the private key is the 32-byte seed.
        assert_eq!(r.bytes("sk"), r.bytes("seed"));
        let pk = xwing_public(&SecretBytes::new(r.bytes("sk"))).unwrap();
        assert_eq!(pk, r.bytes("pk"));
        let (ct, ss) = encap(&pk, &r.bytes("eseed"));
        assert_eq!((ct.clone(), ss.clone()), (r.bytes("ct"), r.bytes("ss")));
        assert_eq!(decap(&r.bytes("sk"), &ct), ss);
    }
}

// --- T04: ML-KEM-768 --------------------------------------------------------

fn ek768(bytes: &[u8]) -> Option<EncapsulationKey768> {
    EncapsulationKey768::new(bytes.try_into().ok()?).ok()
}

fn dk768_expanded(bytes: &[u8]) -> Option<DecapsulationKey768> {
    DecapsulationKey768::from_expanded_bytes(bytes.try_into().ok()?).ok()
}

fn dk768_seed(bytes: &[u8]) -> Option<DecapsulationKey768> {
    Some(DecapsulationKey768::from_seed(bytes.try_into().ok()?))
}

fn decapsulate(dk: &DecapsulationKey768, c: &[u8]) -> Option<Vec<u8>> {
    let c: &ml_kem::Ciphertext<MlKem768> = c.try_into().ok()?;
    Some(dk.decapsulate(c).to_vec())
}

fn encapsulate(ek: &EncapsulationKey768, m: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (c, k) = ek.encapsulate_deterministic(m.try_into().ok()?);
    Some((c.to_vec(), k.to_vec()))
}

#[test]
fn t04_mlkem768_acvp() {
    let text = data(MLKEM_ACVP);
    let recs = records(&text);
    for r in &recs {
        let tc = r.tc();
        match r.kind {
            "keygen" => {
                let dk = dk768_seed(&[r.bytes("d"), r.bytes("z")].concat()).unwrap();
                assert_eq!(
                    dk.encapsulation_key().to_bytes().to_vec(),
                    r.bytes("ek"),
                    "{tc}"
                );
                assert_eq!(dk.to_expanded_bytes().to_vec(), r.bytes("dk"), "{tc}");
            }
            "encap" => {
                let ek = ek768(&r.bytes("ek")).unwrap();
                let (c, k) = encapsulate(&ek, &r.bytes("m")).unwrap();
                assert_eq!((c, k), (r.bytes("c"), r.bytes("k")), "{tc}");
            }
            "decap" => {
                let dk = dk768_expanded(&r.bytes("dk")).unwrap();
                assert_eq!(
                    decapsulate(&dk, &r.bytes("c")).unwrap(),
                    r.bytes("k"),
                    "{tc}"
                );
            }
            "dkcheck" => {
                assert_eq!(dk768_expanded(&r.bytes("dk")).is_some(), r.passed(), "{tc}");
            }
            "ekcheck" => {
                assert_eq!(ek768(&r.bytes("ek")).is_some(), r.passed(), "{tc}");
            }
            other => panic!("kind {other}"),
        }
    }
    let kinds = ["keygen", "encap", "decap", "dkcheck", "ekcheck"].map(|k| count(&recs, k));
    assert_eq!(kinds, [25, 25, 10, 10, 10]);
}

#[test]
fn t04_mlkem768_wycheproof() {
    let text = data(MLKEM_WYCHEPROOF);
    let recs = records(&text);
    for r in &recs {
        let tc = r.tc();
        // Each case runs as far as it goes; a valid case must reach its
        // values, an invalid one must be refused somewhere on the way.
        let got: Option<()> = (|| {
            match r.kind {
                "test" => {
                    let dk = dk768_seed(&r.bytes("seed"))?;
                    if let Some(ek) = r.opt("ek") {
                        assert_eq!(dk.encapsulation_key().to_bytes().to_vec(), ek, "{tc}");
                    }
                    let k = decapsulate(&dk, &r.bytes("c"))?;
                    assert_eq!(k, r.bytes("k"), "{tc}");
                }
                "encaps" => {
                    let ek = ek768(&r.bytes("ek"))?;
                    let (c, k) = encapsulate(&ek, &r.bytes("m"))?;
                    assert_eq!((c, k), (r.bytes("c"), r.bytes("k")), "{tc}");
                }
                "keygen" => {
                    let dk = dk768_seed(&r.bytes("seed"))?;
                    assert_eq!(
                        dk.encapsulation_key().to_bytes().to_vec(),
                        r.bytes("ek"),
                        "{tc}"
                    );
                    assert_eq!(dk.to_expanded_bytes().to_vec(), r.bytes("dk"), "{tc}");
                }
                "decaps" => {
                    let dk = dk768_expanded(&r.bytes("dk"))?;
                    let k = decapsulate(&dk, &r.bytes("c"))?;
                    assert_eq!(k, r.bytes("k"), "{tc}");
                }
                other => panic!("kind {other}"),
            }
            Some(())
        })();
        assert_eq!(got.is_some(), r.valid(), "{tc}");
    }
    let kinds = ["test", "encaps", "keygen", "decaps"].map(|k| count(&recs, k));
    assert_eq!(kinds, [201, 265, 100, 9]);
}

// --- T05: ML-DSA-65 ---------------------------------------------------------

fn vk65(bytes: &[u8]) -> Option<VerifyingKey<MlDsa65>> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).ok()?;
    Some(VerifyingKey::decode(&enc))
}

fn sig65(bytes: &[u8]) -> Option<ml_dsa::Signature<MlDsa65>> {
    ml_dsa::Signature::try_from(bytes).ok()
}

fn rng32(rnd: &[u8]) -> Prepared {
    Prepared::new(SecretBytes::new(rnd.to_vec()))
}

#[test]
fn t05_mldsa65_acvp() {
    let text = data(MLDSA_ACVP);
    let recs = records(&text);
    for r in &recs {
        let tc = r.tc();
        let internal = r.get("iface") == Some("internal");
        let extmu = r.get("extmu") == Some("true");
        match r.kind {
            "keygen" => {
                let key = SigningKey::<MlDsa65>::from_seed(
                    r.bytes("seed").as_slice().try_into().unwrap(),
                );
                assert_eq!(key.verifying_key().encode().to_vec(), r.bytes("pk"), "{tc}");
                assert_eq!(
                    key.expanded_key().to_expanded().to_vec(),
                    r.bytes("sk"),
                    "{tc}"
                );
            }
            "siggen" => {
                let sk = r.bytes("sk");
                let sk = ExpandedSigningKey::<MlDsa65>::from_expanded(
                    &ExpandedSigningKeyBytes::<MlDsa65>::try_from(sk.as_slice()).unwrap(),
                );
                let det = r.get("det") == Some("true");
                let rnd = if det { vec![0; RND] } else { r.bytes("rnd") };
                let mut rng = rng32(&rnd);
                let sig = match (internal, extmu) {
                    (true, true) => {
                        let mu = r.bytes("mu");
                        sk.sign_mu_randomized(mu.as_slice().try_into().unwrap(), &mut rng)
                            .unwrap()
                    }
                    (true, false) => {
                        sk.sign_internal(&[&r.bytes("message")], rnd.as_slice().try_into().unwrap())
                    }
                    (false, false) => sk
                        .sign_randomized(&r.bytes("message"), &r.bytes("context"), &mut rng)
                        .unwrap(),
                    (false, true) => panic!("{tc}: no such group"),
                };
                assert_eq!(sig.encode().to_vec(), r.bytes("signature"), "{tc}");
            }
            "sigver" => {
                let vk = vk65(&r.bytes("pk")).unwrap();
                let ok = sig65(&r.bytes("signature")).is_some_and(|sig| match (internal, extmu) {
                    (true, true) => {
                        vk.verify_mu(r.bytes("mu").as_slice().try_into().unwrap(), &sig)
                    }
                    (true, false) => vk.verify_internal(&r.bytes("message"), &sig),
                    (false, false) => {
                        vk.verify_with_context(&r.bytes("message"), &r.bytes("context"), &sig)
                    }
                    (false, true) => panic!("{tc}: no such group"),
                });
                assert_eq!(ok, r.passed(), "{tc}");
            }
            other => panic!("kind {other}"),
        }
    }
    let kinds = ["keygen", "siggen", "sigver"].map(|k| count(&recs, k));
    assert_eq!(kinds, [25, 90, 45]);
}

#[test]
fn t05_mldsa65_wycheproof() {
    let text = data(MLDSA_WYCHEPROOF);
    let recs = records(&text);
    for r in &recs {
        let tc = r.tc();
        let ctx = r.opt("ctx").unwrap_or_default();
        let got: Option<()> = (|| {
            match r.kind {
                "verify" => {
                    let vk = vk65(&r.bytes("pk"))?;
                    let sig = sig65(&r.bytes("sig"))?;
                    vk.verify_with_context(&r.bytes("msg"), &ctx, &sig)
                        .then_some(())?;
                }
                "sign" => {
                    let seed = r.bytes("seed");
                    let key = SigningKey::<MlDsa65>::from_seed(seed.as_slice().try_into().ok()?);
                    if let Some(pk) = r.opt("pk") {
                        assert_eq!(key.verifying_key().encode().to_vec(), pk, "{tc}");
                    }
                    let key = key.expanded_key();
                    let rnd = r.opt("rnd").unwrap_or_else(|| vec![0; RND]);
                    let sig = match r.get("msg") {
                        Some(msg) => key
                            .sign_randomized(&hex(msg), &ctx, &mut rng32(&rnd))
                            .ok()?,
                        None => key
                            .sign_mu_randomized(
                                r.bytes("mu").as_slice().try_into().ok()?,
                                &mut rng32(&rnd),
                            )
                            .ok()?,
                    };
                    assert_eq!(sig.encode().to_vec(), r.bytes("sig"), "{tc}");
                }
                other => panic!("kind {other}"),
            }
            Some(())
        })();
        assert_eq!(got.is_some(), r.valid(), "{tc}");
    }
    let kinds = ["verify", "sign"].map(|k| count(&recs, k));
    assert_eq!(kinds, [210, 105]);
}

// --- T06: the composite vector ----------------------------------------------

#[test]
fn t06_composite_rfc10073_vector() {
    let text = data(COMPOSITE);
    let recs = records(&text);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    let m = r.bytes("m");
    assert_eq!(m, b"The quick brown fox jumps over the lazy dog.");
    let ctx = r.bytes("ctx");
    let pk = r.bytes("pk");
    let sk = SecretBytes::new(r.bytes("sk"));
    assert_eq!(identity_public(&sk).unwrap(), pk);
    let s = r.bytes("s");
    let swc = r.bytes("swithcontext");
    assert_eq!(composite_verify(&pk, &m, &s), Ok(()));
    assert_eq!(verify_ctx(&pk, &m, &ctx, &swc), Ok(()));
    // Each signature only with its own ctx.
    assert_eq!(
        composite_verify(&pk, &m, &swc),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(verify_ctx(&pk, &m, &ctx, &s), Err(Error::SignatureInvalid));
    // One changed byte in either half of either signature fails.
    for (sig, ctx) in [(&s, &[][..]), (&swc, &ctx[..])] {
        for i in [0, 1000, MLDSA_SIGNATURE - 1, MLDSA_SIGNATURE, SIGNATURE - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                verify_ctx(&pk, &m, ctx, &bad),
                Err(Error::SignatureInvalid),
                "byte {i}"
            );
        }
    }
    // And one changed byte in either half of the public key.
    for i in [0, MLDSA_PUBLIC - 1, MLDSA_PUBLIC, IDENTITY_PUBLIC - 1] {
        let mut bad = pk.clone();
        bad[i] ^= 0x01;
        assert_eq!(
            composite_verify(&bad, &m, &s),
            Err(Error::SignatureInvalid),
            "pk byte {i}"
        );
    }
}

/// Larsal's own composite signatures are hedged; with 32 zero bytes through
/// the seam they are FIPS 204's deterministic variant, which a plain
/// ML-DSA-65 signature over M' with context Label must equal.
#[test]
fn composite_halves_are_rfc10073_message_prime() {
    let sk = SecretBytes::new((0u8..64).collect());
    let message = b"demo message";
    let sig = sign_with(scripted(&[0; RND]), &sk, message, &[]).unwrap();
    let mut m_prime =
        b"CompositeAlgorithmSignatures2025COMPSIG-MLDSA65-Ed25519-SHA512\x00".to_vec();
    m_prime.extend_from_slice(crate::hash::sha512(&[message]).expose());
    assert_eq!(message_prime(message, &[]).unwrap(), m_prime);
    let ml = SigningKey::<MlDsa65>::from_seed(
        &(0u8..32).collect::<Vec<_>>().as_slice().try_into().unwrap(),
    );
    let want = ml
        .expanded_key()
        .sign_deterministic(&m_prime, LABEL)
        .unwrap();
    assert_eq!(&sig[..MLDSA_SIGNATURE], want.encode().as_slice());
    let ed = crate::sign::ed25519_sign(&SecretBytes::new((32u8..64).collect()), &m_prime).unwrap();
    assert_eq!(&sig[MLDSA_SIGNATURE..], ed.as_slice());
    assert_eq!(
        composite_verify(&identity_public(&sk).unwrap(), message, &sig),
        Ok(())
    );
}

// --- T07 to T09: the composite signature -----------------------------------

#[test]
fn t07_sign_twice_both_verify_and_differ() {
    let (sk, pk) = identity_keypair().unwrap();
    let m = sign::field_list(&[b"a", b"b"]).unwrap();
    let s1 = composite_sign(&sk, &m).unwrap();
    let s2 = composite_sign(&sk, &m).unwrap();
    assert_eq!(composite_verify(&pk, &m, &s1), Ok(()));
    assert_eq!(composite_verify(&pk, &m, &s2), Ok(()));
    assert_ne!(s1[..MLDSA_SIGNATURE], s2[..MLDSA_SIGNATURE], "hedged");
    // Ed25519 is deterministic: the second halves are equal.
    assert_eq!(s1[MLDSA_SIGNATURE..], s2[MLDSA_SIGNATURE..]);
    for i in [0, m.len() - 1] {
        let mut changed = m.clone();
        changed[i] ^= 0x01;
        assert_eq!(
            composite_verify(&pk, &changed, &s1),
            Err(Error::SignatureInvalid)
        );
    }
}

#[test]
fn t08_halves_alone_or_mixed_are_refused() {
    let (sk, pk) = identity_keypair().unwrap();
    let (other_sk, _) = identity_keypair().unwrap();
    let m = sign::field_list(&[b"a", b"b"]).unwrap();
    let s = composite_sign(&sk, &m).unwrap();
    let other = composite_sign(&other_sk, &m).unwrap();
    let mut ed_zeroed = s.clone();
    ed_zeroed[MLDSA_SIGNATURE..].fill(0);
    let mut ml_zeroed = s.clone();
    ml_zeroed[..MLDSA_SIGNATURE].fill(0);
    // The ML-DSA half of another key's valid signature over M.
    let mixed = [&other[..MLDSA_SIGNATURE], &s[MLDSA_SIGNATURE..]].concat();
    let cut = s[..SIGNATURE - 1].to_vec();
    let ed_alone = s[MLDSA_SIGNATURE..].to_vec();
    let ml_alone = s[..MLDSA_SIGNATURE].to_vec();
    for (what, sig) in [
        ("Ed25519 half zeroed", &ed_zeroed),
        ("ML-DSA half zeroed", &ml_zeroed),
        ("another key's ML-DSA half", &mixed),
        ("3,372 bytes", &cut),
        ("Ed25519 half alone", &ed_alone),
        ("ML-DSA half alone", &ml_alone),
    ] {
        assert_eq!(
            composite_verify(&pk, &m, sig),
            Err(Error::SignatureInvalid),
            "{what}"
        );
    }
    // Both halves run even when the ML-DSA half fails its check (the verify
    // count of the Ed25519 half), so a refusal says nothing of which half
    // failed. An ML-DSA half that does not even decode (all zeros: a bad
    // hint encoding) is refused before either check runs.
    sign::probe::take();
    assert!(composite_verify(&pk, &m, &mixed).is_err());
    assert_eq!(sign::probe::take(), 1);
    assert!(composite_verify(&pk, &m, &ml_zeroed).is_err());
    assert_eq!(sign::probe::take(), 0);
}

/// T08 (amended words): two signatures by one key over one M share their
/// Ed25519 half (Ed25519 is deterministic; only the ML-DSA half is hedged),
/// so swapping halves between them gives the other signature byte for
/// byte. That is no recombination, and it verifies; T08's refusal is for
/// halves of other keys or other messages (the next test).
#[test]
fn t08_same_key_same_message_swap_is_the_second_signature() {
    let (sk, pk) = identity_keypair().unwrap();
    let m = sign::field_list(&[b"a", b"b"]).unwrap();
    let s1 = composite_sign(&sk, &m).unwrap();
    let s2 = composite_sign(&sk, &m).unwrap();
    assert_ne!(s1, s2, "hedged");
    let swapped = [&s2[..MLDSA_SIGNATURE], &s1[MLDSA_SIGNATURE..]].concat();
    assert_eq!(swapped, s2);
    let swapped = [&s1[..MLDSA_SIGNATURE], &s2[MLDSA_SIGNATURE..]].concat();
    assert_eq!(swapped, s1);
    assert_eq!(composite_verify(&pk, &m, &s1), Ok(()));
    assert_eq!(composite_verify(&pk, &m, &s2), Ok(()));
}

/// T08: a half taken from a valid signature by another key over M, or by
/// the same key over another message, is refused, whichever half it is.
#[test]
fn t08_halves_of_other_keys_or_messages_are_refused() {
    let (sk, pk) = identity_keypair().unwrap();
    let (other_sk, other_pk) = identity_keypair().unwrap();
    let m = sign::field_list(&[b"a", b"b"]).unwrap();
    let m2 = sign::field_list(&[b"a", b"c"]).unwrap();
    let s = composite_sign(&sk, &m).unwrap();
    let other_key = composite_sign(&other_sk, &m).unwrap();
    let other_message = composite_sign(&sk, &m2).unwrap();
    // The donors are valid signatures.
    assert_eq!(composite_verify(&pk, &m, &s), Ok(()));
    assert_eq!(composite_verify(&other_pk, &m, &other_key), Ok(()));
    assert_eq!(composite_verify(&pk, &m2, &other_message), Ok(()));
    let (ml, ed) = s.split_at(MLDSA_SIGNATURE);
    for (by, donor) in [
        ("another key over M", &other_key),
        ("the same key over another message", &other_message),
    ] {
        let (donor_ml, donor_ed) = donor.split_at(MLDSA_SIGNATURE);
        for (half, sig) in [
            ("ML-DSA", [donor_ml, ed].concat()),
            ("Ed25519", [ml, donor_ed].concat()),
        ] {
            assert_eq!(
                composite_verify(&pk, &m, &sig),
                Err(Error::SignatureInvalid),
                "the {half} half of a signature by {by}"
            );
        }
    }
}

/// CRY-05.5: the Ed25519 half is checked strictly (CRY-04.3). A small-order
/// Ed25519 public key (the identity point) with R the identity and S zero
/// passes a non-strict check for every message; inside an otherwise valid
/// composite (a real ML-DSA-65 half over M') it is refused.
#[test]
fn t08_weak_ed25519_half_is_refused() {
    use ed25519_dalek::Verifier as _;
    let (sk, pk) = identity_keypair().unwrap();
    let m = b"m";
    let s = composite_sign(&sk, m).unwrap();
    assert_eq!(composite_verify(&pk, m, &s), Ok(()));
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak_pk = [&pk[..MLDSA_PUBLIC], &identity[..]].concat();
    let weak_sig = [&s[..MLDSA_SIGNATURE], &identity[..], &[0u8; 32][..]].concat();
    // The witness: a non-strict Ed25519 check takes it, the strict one not.
    let key = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
    let half = ed25519_dalek::Signature::from_slice(&weak_sig[MLDSA_SIGNATURE..]).unwrap();
    let m_prime = message_prime(m, &[]).unwrap();
    assert!(key.verify(&m_prime, &half).is_ok());
    assert!(key.verify_strict(&m_prime, &half).is_err());
    assert_eq!(
        composite_verify(&weak_pk, m, &weak_sig),
        Err(Error::SignatureInvalid)
    );
}

/// T09: the public functions of this module are exactly these, and no other
/// module of larsal-crypto names ml_dsa or a composite half. E25-S3 adds one
/// test-only function (CRY-05 T29's KEM shared secret, under its cfg line),
/// makes T10's decapsulation count crate-wide in test builds only, and shares
/// `seal`'s receiving key check crate-wide (the account keys' checks).
#[test]
fn t09_no_standalone_half_in_the_api() {
    let source = include_str!("../pq.rs");
    let public: Vec<&str> = source
        .lines()
        .filter_map(|l| l.strip_prefix("pub fn "))
        .map(|l| &l[..l.find('(').unwrap()])
        .collect();
    assert_eq!(
        public,
        [
            "xwing_keypair",
            "xwing_public",
            "seal",
            "open",
            "kem_shared_secret",
            "identity_keypair",
            "identity_public",
            "composite_sign",
            "composite_verify"
        ]
    );
    assert!(
        source.contains(
            "#[cfg(any(test, feature = \"test-kem-secret\"))]\npub fn kem_shared_secret("
        )
    );
    let crate_wide: Vec<&str> = source
        .lines()
        .filter(|l| l.contains("pub(crate)"))
        .map(str::trim)
        .collect();
    assert_eq!(
        crate_wide,
        [
            "pub(crate) fn receiving_key(recipient: &[u8]) -> Result<PublicKey, Error> {",
            "pub(crate) mod probe {",
            "pub(crate) fn take() -> usize {"
        ],
        "a crate-wide seam"
    );
    assert!(source.contains("#[cfg(test)]\npub(crate) mod probe {"));
    for line in source.lines().filter(|l| l.starts_with("pub ")) {
        assert!(
            line.starts_with("pub fn ") || line.starts_with("pub const "),
            "{line}"
        );
    }
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("pq.rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            for name in ["ml_dsa", "ml_kem", "x_wing", "XWing"] {
                assert!(!text.contains(name), "{} names {name}", path.display());
            }
        }
    }
}

// --- T10, T11: the HPKE suite -----------------------------------------------

#[test]
fn t10_round_trip_info_and_enc() {
    let (seed, pk) = xwing_keypair().unwrap();
    let info = b"demo info";
    let pt = [0x5a; 32];
    let (enc, ct) = seal(&pk, info, &pt).unwrap();
    assert_eq!((enc.len(), ct.len()), (ENC, 48));
    probe::take();
    assert_eq!(open(&seed, &enc, info, &ct).unwrap().expose(), pt);
    let longer = [&info[..], b"x"].concat();
    assert_eq!(
        open(&seed, &enc, &longer, &ct).err(),
        Some(Error::WrapInvalid)
    );
    let mut changed = enc.clone();
    changed[500] ^= 0x01;
    assert_eq!(
        open(&seed, &changed, info, &ct).err(),
        Some(Error::WrapInvalid)
    );
    let mut changed = enc.clone();
    changed[ENC - 1] ^= 0x01;
    assert_eq!(
        open(&seed, &changed, info, &ct).err(),
        Some(Error::WrapInvalid)
    );
    let mut changed = ct.clone();
    changed[3] ^= 0x01;
    assert_eq!(
        open(&seed, &enc, info, &changed).err(),
        Some(Error::WrapInvalid)
    );
    // Five opens reached the decapsulation.
    assert_eq!(probe::take(), 5);
    // Wrong lengths: refused before any decapsulation.
    let short = enc[..ENC - 1].to_vec();
    let long = [&enc[..], &[0]].concat();
    let classical = enc[..32].to_vec();
    for bad in [&short, &long, &classical] {
        assert_eq!(
            open(&seed, bad, info, &ct).err(),
            Some(Error::WrapInvalid),
            "{}",
            bad.len()
        );
    }
    assert_eq!(
        open(&seed, &enc, info, &ct[..15]).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(probe::take(), 0);
}

/// A copy of `pk` with ML-KEM coefficient 0 set to `value` (12-bit little
/// endian, FIPS 203 ByteEncode_12).
fn with_first_coefficient(pk: &[u8], value: u16) -> Vec<u8> {
    let mut pk = pk.to_vec();
    pk[0] = (value & 0xff) as u8;
    pk[1] = (pk[1] & 0xf0) | ((value >> 8) as u8 & 0x0f);
    pk
}

#[test]
fn t11_bad_keys_refused_before_any_draw() {
    let (_, pk) = xwing_keypair().unwrap();
    let draws = Rc::new(Cell::new(0));
    let modulus = with_first_coefficient(&pk, 3329);
    let max = with_first_coefficient(&pk, 3328);
    let cases: [(&str, &[u8], Error); 4] = [
        ("coefficient 3,329", &modulus, Error::WrapInvalid),
        (
            "coefficient 4,095",
            &with_first_coefficient(&pk, 4095),
            Error::WrapInvalid,
        ),
        ("1,215 bytes", &pk[..PUBLIC_KEY - 1], Error::KeyLength),
        ("an X25519 key", &pk[PUBLIC_KEY - 32..], Error::KeyLength),
    ];
    for (what, key, want) in cases {
        assert_eq!(
            seal_with(counted(&draws), key, b"i", &[], b"demo").err(),
            Some(want),
            "{what}"
        );
    }
    assert_eq!(draws.get(), 0, "a refused key reached the draw");
    // Control: 3,328 is the largest coefficient the check takes.
    assert!(seal_with(counted(&draws), &max, b"i", &[], b"demo").is_ok());
    assert_eq!(draws.get(), 1);
}

#[test]
fn a_changed_public_key_byte_never_opens_with_the_real_seed() {
    let (seed, pk) = xwing_keypair().unwrap();
    // A byte of the ML-KEM part (its low nibble pair stays under 3,329 when
    // only bit 0 of an even byte flips), the ML-KEM part's 32-byte rho, and
    // the X25519 part.
    for i in [2, 1170, PUBLIC_KEY - 1] {
        let mut changed = pk.clone();
        changed[i] ^= 0x01;
        match seal(&changed, b"i", b"demo") {
            Ok((enc, ct)) => {
                assert_eq!(
                    open(&seed, &enc, b"i", &ct).err(),
                    Some(Error::WrapInvalid),
                    "byte {i}"
                );
            }
            Err(e) => assert_eq!(e, Error::WrapInvalid, "byte {i}"),
        }
    }
}

#[test]
fn limits_and_lengths() {
    let (seed, pk) = xwing_keypair().unwrap();
    assert_eq!(
        seal(&pk, b"i", &[0; MAX_PLAINTEXT + 1]).err(),
        Some(Error::TooLarge)
    );
    assert_eq!(
        seal(&pk, &[0; MAX_INFO + 1], b"p").err(),
        Some(Error::TooLarge)
    );
    let (enc, ct) = seal(&pk, &[7; MAX_INFO], &[9; MAX_PLAINTEXT]).unwrap();
    assert_eq!(
        open(&seed, &enc, &[7; MAX_INFO], &ct).unwrap().len(),
        MAX_PLAINTEXT
    );
    probe::take();
    let big = vec![0; MAX_PLAINTEXT + TAG + 1];
    assert_eq!(
        open(&seed, &enc, b"i", &big).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(
        open(&seed, &enc, &[7; MAX_INFO + 1], &ct).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(probe::take(), 0);
    let short = SecretBytes::new(vec![1; SEED - 1]);
    assert_eq!(open(&short, &enc, b"i", &ct).err(), Some(Error::KeyLength));
    assert_eq!(xwing_public(&short).err(), Some(Error::KeyLength));
    let id = SecretBytes::new(vec![1; IDENTITY_PRIVATE + 1]);
    assert_eq!(identity_public(&id).err(), Some(Error::KeyLength));
    assert_eq!(composite_sign(&id, b"m").err(), Some(Error::KeyLength));
    let id = SecretBytes::new(vec![1; 32]);
    assert_eq!(composite_sign(&id, b"m").err(), Some(Error::KeyLength));
    let (sk, ipk) = identity_keypair().unwrap();
    let s = composite_sign(&sk, b"m").unwrap();
    // Wrong lengths are refused before either half is checked (the verify
    // count of the Ed25519 half stays 0).
    sign::probe::take();
    assert_eq!(
        composite_verify(&ipk[..IDENTITY_PUBLIC - 1], b"m", &s),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(
        composite_verify(&[&ipk[..], &[0]].concat(), b"m", &s),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(
        composite_verify(&ipk, b"m", &[&s[..], &[0]].concat()),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(
        composite_verify(&ipk, b"m", &s[..SIGNATURE - 1]),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(sign::probe::take(), 0, "a wrong length reached a check");
    assert_eq!(
        verify_ctx(&ipk, b"m", &[0; 256], &s),
        Err(Error::SignatureInvalid)
    );
}

#[test]
fn a_failing_random_source_returns_nothing() {
    let (_, pk) = xwing_keypair().unwrap();
    assert_eq!(
        seal_with(down, &pk, b"i", &[], b"p").err(),
        Some(Error::RandomSource)
    );
    assert_eq!(keypair_with(down).err(), Some(Error::RandomSource));
    assert_eq!(identity_keypair_with(down).err(), Some(Error::RandomSource));
    let (sk, _) = identity_keypair().unwrap();
    assert_eq!(
        sign_with(down, &sk, b"m", &[]).err(),
        Some(Error::RandomSource)
    );
    // A draw of the wrong length is not served, and nothing is returned.
    let short = |_: usize| Ok(SecretBytes::new(vec![1; 31]));
    assert_eq!(
        sign_with(short, &sk, b"m", &[]).err(),
        Some(Error::RandomSource)
    );
    let short = |_: usize| Ok(SecretBytes::new(vec![1; 63]));
    assert_eq!(
        seal_with(short, &pk, b"i", &[], b"p").err(),
        Some(Error::RandomSource)
    );
}

/// CRY-05.3, CRY-05.5 (as CRY-04.12): every seal draws a fresh
/// encapsulation and every key pair a fresh seed. No enc repeats in either
/// of its parts (the ML-KEM ciphertext, the X25519 share), no X-Wing seed
/// repeats, and neither half of an identity key repeats.
#[test]
fn cry05_3_every_seal_and_key_pair_is_fresh() {
    use std::collections::BTreeSet;
    let (_, pk) = xwing_keypair().unwrap();
    let encs: Vec<Vec<u8>> = (0..50)
        .map(|_| seal(&pk, b"i", b"demo").unwrap().0)
        .collect();
    let ml_kem: BTreeSet<&[u8]> = encs.iter().map(|e| &e[..ENC - 32]).collect();
    let x25519: BTreeSet<&[u8]> = encs.iter().map(|e| &e[ENC - 32..]).collect();
    assert_eq!((ml_kem.len(), x25519.len()), (50, 50));
    let seeds: Vec<SecretBytes> = (0..20).map(|_| xwing_keypair().unwrap().0).collect();
    let distinct: BTreeSet<&[u8]> = seeds.iter().map(SecretBytes::expose).collect();
    assert_eq!(distinct.len(), 20);
    let keys: Vec<SecretBytes> = (0..20).map(|_| identity_keypair().unwrap().0).collect();
    let ml: BTreeSet<&[u8]> = keys.iter().map(|k| &k.expose()[..32]).collect();
    let ed: BTreeSet<&[u8]> = keys.iter().map(|k| &k.expose()[32..]).collect();
    assert_eq!((ml.len(), ed.len()), (20, 20));
}

// --- CRY-05.14, CRY-05.17 ---------------------------------------------------

#[test]
fn cry05_14_sizes_match_e25_s1() {
    let (seed, pk) = xwing_keypair().unwrap();
    let (enc, ct) = seal(&pk, b"i", &[1; 100]).unwrap();
    let (sk, ipk) = identity_keypair().unwrap();
    let sig = composite_sign(&sk, b"m").unwrap();
    assert_eq!(
        [
            seed.len(),
            pk.len(),
            enc.len(),
            ct.len(),
            sk.len(),
            ipk.len(),
            sig.len()
        ],
        [32, 1216, 1120, 116, 64, 1984, 3373]
    );
    assert_eq!(
        [
            SEED,
            PUBLIC_KEY,
            ENC,
            IDENTITY_PRIVATE,
            IDENTITY_PUBLIC,
            SIGNATURE
        ],
        [32, 1216, 1120, 64, 1984, 3373]
    );
    assert_eq!(SUITE, [25722, 1, 3]);
    assert_eq!(
        (
            <XWing as ::hpke::Kem>::KEM_ID,
            <HkdfSha256 as ::hpke::kdf::Kdf>::KDF_ID,
            <ChaCha20Poly1305 as ::hpke::aead::Aead>::AEAD_ID
        ),
        (SUITE[0], SUITE[1], SUITE[2])
    );
}

fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

/// CRY-05.17: every vendored type that holds a key of this module is built
/// with its `zeroize` feature (a compile-time check: without it these types
/// do not implement `ZeroizeOnDrop`). X-Wing's own key wipes under the same
/// feature (hpke turns it on); tests/pq_wipe.rs checks the stack and heap.
#[test]
fn cry05_17_vendored_key_types_wipe_on_drop() {
    wipes_on_drop::<DecapsulationKey768>();
    wipes_on_drop::<SigningKey<MlDsa65>>();
    wipes_on_drop::<ExpandedSigningKey<MlDsa65>>();
    wipes_on_drop::<ed25519_dalek::SigningKey>();
    wipes_on_drop::<x25519_dalek::StaticSecret>();
}

/// Runs `f` below 128 KiB of frames of its own, as a caller that is already
/// some way down its stack (a Swift or UniFFI caller) would.
#[inline(never)]
fn below_caller_frames(f: impl FnOnce()) {
    let mut frames = [0x33u8; 128 << 10];
    std::hint::black_box(&mut frames);
    f();
    std::hint::black_box(&frames);
}

/// CRY-05.17: every call works from a thread with a 512 KiB stack (a macOS
/// secondary thread's size) whose caller already used 128 KiB of it, because
/// the deep vendored work runs on the call's own worker thread. With that
/// work on the caller's stack (round 1) this overflows: the ML-DSA-65 key
/// expansion alone writes 431 to 507 KiB.
#[test]
fn cry05_17_every_pq_call_runs_on_a_512_kib_thread() {
    std::thread::Builder::new()
        .stack_size(512 << 10)
        .spawn(|| {
            below_caller_frames(|| {
                let (seed, pk) = xwing_keypair().unwrap();
                assert_eq!(xwing_public(&seed).unwrap(), pk);
                let (enc, ct) = seal(&pk, b"i", &[7; MAX_PLAINTEXT]).unwrap();
                let opened = open(&seed, &enc, b"i", &ct).unwrap();
                assert_eq!(opened.expose(), [7; MAX_PLAINTEXT]);
                let (sk, ipk) = identity_keypair().unwrap();
                assert_eq!(identity_public(&sk).unwrap(), ipk);
                let sig = composite_sign(&sk, b"m").unwrap();
                assert_eq!(composite_verify(&ipk, b"m", &sig), Ok(()));
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

/// The bytes of stack below its caller that `op` writes, found by painting:
/// the deepest `k` 64-byte chunks of a 1 MiB area just below the caller get
/// a needle, `op` runs, and the needle's copies in all writable memory are
/// counted against the same steps without `op`. A binary search finds the
/// largest `k` that `op` leaves whole. Run alone: the count reads all of the
/// process's memory.
fn painted_depth(op: &dyn Fn()) -> usize {
    use larsal_platform::memory::copies_in_memory;
    const AREA: usize = 1 << 20;
    const CHUNK: usize = 64;
    const MASK: u8 = 0x5a;
    #[inline(never)]
    fn paint(masked: &[u8; CHUNK], deep_chunks: usize) {
        let mut area = [0x11u8; AREA];
        for chunk in area.as_chunks_mut::<CHUNK>().0.iter_mut().take(deep_chunks) {
            for (b, m) in chunk.iter_mut().zip(masked) {
                *b = m ^ MASK;
            }
        }
        std::hint::black_box(&mut area);
    }
    let masked: [u8; CHUNK] = core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0xb7);
    let left_whole = |k: usize| {
        paint(&masked, k);
        let without = copies_in_memory(&masked, MASK);
        paint(&masked, k);
        op();
        copies_in_memory(&masked, MASK) == without
    };
    let (mut whole, mut cut) = (0, AREA / CHUNK);
    assert!(!left_whole(cut), "op wrote nothing");
    while cut - whole > 1 {
        let mid = whole + (cut - whole) / 2;
        if left_whole(mid) {
            whole = mid;
        } else {
            cut = mid;
        }
    }
    AREA - whole * CHUNK
}

/// The worker's own wipe: work on a `scrubbed_thread` worker paints a
/// needle into every 64-byte chunk of 704 KiB of its stack; when the thread
/// ends (a thread-local's drop: after the wipe, before the stack is given
/// back), the needle's copies in all writable memory are counted.
fn worker_wipe_leaves() -> usize {
    use larsal_platform::memory::copies_in_memory;
    use std::cell::RefCell;
    use std::sync::mpsc::{Sender, channel};
    const DEEP: usize = 704 << 10;
    const MASK: u8 = 0x5a;
    struct AtExit([u8; 64], Sender<usize>);
    impl Drop for AtExit {
        fn drop(&mut self) {
            let _ = self.1.send(copies_in_memory(&self.0, MASK));
        }
    }
    thread_local! {
        static AT_EXIT: RefCell<Option<AtExit>> = const { RefCell::new(None) };
    }
    #[inline(never)]
    fn paint(masked: &[u8; 64]) {
        let mut area = [0u8; DEEP];
        for chunk in area.as_chunks_mut::<64>().0 {
            for (b, m) in chunk.iter_mut().zip(masked) {
                *b = m ^ MASK;
            }
        }
        std::hint::black_box(&mut area);
    }
    let masked: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x6c);
    let (tx, rx) = channel();
    crate::secret::scrubbed_thread(Error::RandomSource, || {
        AT_EXIT.with(|a| *a.borrow_mut() = Some(AtExit(masked, tx)));
        paint(&masked);
    })
    .unwrap();
    rx.recv().unwrap()
}

/// CRY-05.17: how deep each worker body writes (its secrets reach that
/// deep), and that the worker's wipe covers it. A measurement that reads all
/// memory, so it runs alone: `--ignored --exact
/// pq::tests::cry05_17_pq_stack_depth --test-threads 1 --nocapture`, in a
/// debug and a release build; the numbers are in secret.rs.
#[test]
#[ignore = "reads all memory: run alone, debug and release"]
fn cry05_17_pq_stack_depth() {
    std::thread::Builder::new()
        .stack_size(3 << 20)
        .spawn(measure_depths)
        .unwrap()
        .join()
        .unwrap();
}

fn measure_depths() {
    use crate::secret::{PQ_SCRUB_WORDS, PQ_STACK};
    use std::hint::black_box;
    let (seed, pk) = xwing_keypair().unwrap();
    let pt = [7u8; MAX_PLAINTEXT];
    let (enc, ct) = seal(&pk, b"i", &pt).unwrap();
    let (sk, ipk) = identity_keypair().unwrap();
    let sig = composite_sign(&sk, b"m").unwrap();
    let (ml_seed, ed_seed) = halves(&sk).unwrap();
    let recipient = PublicKey::from_bytes(&pk).unwrap();
    let encapped = EncappedKey::from_bytes(&enc).unwrap();
    let (body, tag) = ct.split_at(MAX_PLAINTEXT);
    let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(tag).unwrap();
    let m_prime = message_prime(b"m", &[]).unwrap();
    let bodies: [(&str, &dyn Fn()); 5] = [
        ("xwing_public", &|| {
            let mut out = vec![0u8; PUBLIC_KEY];
            xwing_public_in(seed.expose(), &mut out).unwrap();
            black_box(out);
        }),
        ("seal", &|| {
            let mut out = vec![0u8; MAX_PLAINTEXT];
            let mut rng = Prepared::new(random::bytes(ENCAP_RANDOMNESS).unwrap());
            black_box(seal_in(&recipient, b"i", &[], &pt, &mut out, &mut rng).unwrap());
        }),
        ("open", &|| {
            let mut out = SecretBytes::zeroed(MAX_PLAINTEXT);
            open_in(
                seed.expose(),
                &encapped,
                &tag,
                b"i",
                &[],
                body,
                out.expose_mut(),
            )
            .unwrap();
            black_box(out);
        }),
        ("identity_public", &|| {
            let mut out = vec![0u8; IDENTITY_PUBLIC];
            let (ml_out, ed_out) = out.split_at_mut(MLDSA_PUBLIC);
            identity_public_in(ml_seed, ed_seed, ml_out, ed_out);
            black_box(out);
        }),
        ("composite_sign", &|| {
            let mut out = vec![0u8; SIGNATURE];
            let (ml_out, ed_out) = out.split_at_mut(MLDSA_SIGNATURE);
            let mut rng = Prepared::new(random::bytes(RND).unwrap());
            sign_in(ml_seed, ed_seed, &m_prime, &mut rng, ml_out, ed_out).unwrap();
            black_box(out);
        }),
    ];
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut deepest = 0;
    for (what, op) in bodies {
        let depth = painted_depth(op);
        println!("STACK {build} {what}: {depth} bytes ({} KiB)", depth / 1024);
        deepest = deepest.max(depth);
    }
    let verify = painted_depth(&|| composite_verify(&ipk, b"m", &sig).unwrap());
    println!("STACK {build} composite_verify (caller's thread, no secret): {verify} bytes");
    let scrub = PQ_SCRUB_WORDS * 16;
    println!("STACK {build} deepest worker body {deepest} bytes; wipe {scrub}; stack {PQ_STACK}");
    assert!(
        deepest + deepest / 4 <= scrub,
        "the wipe is short of depth + 25%"
    );
    assert!(scrub + (256 << 10) <= PQ_STACK, "no room above the wipe");
    let left = worker_wipe_leaves();
    println!("STACK {build} worker wipe: {left} of 11,264 needle chunks painted 704 KiB deep left");
    assert_eq!(left, 0, "the worker's wipe does not reach 704 KiB");
}

#[test]
fn t27_secrets_have_no_debug_output() {
    let (seed, pk) = xwing_keypair().unwrap();
    let (enc, ct) = seal(&pk, b"i", b"demo").unwrap();
    let opened = open(&seed, &enc, b"i", &ct).unwrap();
    let (sk, _) = identity_keypair().unwrap();
    assert_eq!(
        format!("{seed:?} {opened:?} {sk:?}"),
        "[hidden] [hidden] [hidden]"
    );
    // Errors carry no bytes.
    let e = open(&seed, &enc, b"j", &ct).unwrap_err();
    assert_eq!(format!("{e:?}"), "WrapInvalid");
}

/// CRY-05.14 timings (E25-S2 build step 6): a release build on this Mac,
/// the median of 101 runs of each. Run with
/// `cargo test --release -p larsal-crypto --lib -- --ignored --nocapture cry05_14_times`.
#[test]
#[ignore = "timing run, release builds only"]
fn cry05_14_times_on_this_mac() {
    use std::time::Instant;
    fn median(mut f: impl FnMut()) -> f64 {
        let mut times: Vec<f64> = (0..101)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        times.sort_by(f64::total_cmp);
        times[50]
    }
    let (seed, pk) = xwing_keypair().unwrap();
    let sk = PrivateKey::from_bytes(seed.expose()).unwrap();
    let pk_k = PublicKey::from_bytes(&pk).unwrap();
    let (_, enc) = {
        let mut rng = Prepared::new(random::bytes(ENCAP_RANDOMNESS).unwrap());
        XWing::encap_with_rng(&pk_k, None, &mut rng).unwrap()
    };
    let encap_us = median(|| {
        let mut rng = Prepared::new(random::bytes(ENCAP_RANDOMNESS).unwrap());
        std::hint::black_box(XWing::encap_with_rng(&pk_k, None, &mut rng).unwrap());
    });
    let decap_us = median(|| {
        std::hint::black_box(XWing::decap(&sk, None, &enc).unwrap());
    });
    let ml = ExpandedSigningKey::<MlDsa65>::from_seed(&[7u8; 32].into());
    let vk = ml.verifying_key();
    let msg = [0x42u8; 200];
    let ml_sig = ml
        .sign_randomized(&msg, LABEL, &mut rng32(&[1; RND]))
        .unwrap();
    let sign_us = median(|| {
        let mut rng = Prepared::new(random::bytes(RND).unwrap());
        std::hint::black_box(ml.sign_randomized(&msg, LABEL, &mut rng).unwrap());
    });
    let verify_us = median(|| {
        assert!(std::hint::black_box(
            vk.verify_with_context(&msg, LABEL, &ml_sig)
        ));
    });
    let (isk, ipk) = identity_keypair().unwrap();
    let csig = composite_sign(&isk, &msg).unwrap();
    let csign_us = median(|| {
        std::hint::black_box(composite_sign(&isk, &msg).unwrap());
    });
    let cverify_us = median(|| {
        composite_verify(&ipk, &msg, &csig).unwrap();
    });
    let seal_us = median(|| {
        std::hint::black_box(seal(&pk, b"info", &[3; 1024]).unwrap());
    });
    let (e, c) = seal(&pk, b"info", &[3; 1024]).unwrap();
    let open_us = median(|| {
        std::hint::black_box(open(&seed, &e, b"info", &c).unwrap());
    });
    let ipub_us = median(|| {
        std::hint::black_box(identity_public(&isk).unwrap());
    });
    let xpub_us = median(|| {
        std::hint::black_box(xwing_public(&seed).unwrap());
    });
    let worker_us = median(|| {
        crate::secret::scrubbed_thread(Error::RandomSource, || std::hint::black_box(1)).unwrap();
    });
    for (what, us) in [
        ("X-Wing encapsulate", encap_us),
        ("X-Wing decapsulate", decap_us),
        ("ML-DSA-65 sign (hedged, 200-byte message)", sign_us),
        ("ML-DSA-65 verify", verify_us),
        ("composite sign (on its worker thread)", csign_us),
        ("composite verify (caller's thread)", cverify_us),
        ("pq::seal (1 KiB, on its worker thread)", seal_us),
        ("pq::open (1 KiB, on its worker thread)", open_us),
        ("identity_public (on its worker thread)", ipub_us),
        ("xwing_public (on its worker thread)", xpub_us),
        (
            "worker thread alone (start, 768 KiB wipe, end, join)",
            worker_us,
        ),
    ] {
        println!("TIMING {what}: median of 101 = {us:.1} us");
    }
}
