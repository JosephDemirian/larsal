//! FMT-04 (key flow), FMT-05 (header integrity) and FMT-06 (block stream)
//! vector rows, plus the FMT-01 Vector L4 keys. One test per card row.

mod format_common;

use format_common::*;
use larsal_crypto::kdf::{self, Argon2Type, KdfParams, Verdict};
use larsal_crypto::secret::SecretBytes;
use larsal_format::Error;
use larsal_format::integrity::{
    header_hash_ok, header_hmac, header_hmac_ok, read_blocks, write_blocks,
};
use larsal_format::keys::{
    SlotMode, SoftwareKey, composite_key, final_keys, hardware_part, padded_challenge,
    password_part,
};
use larsal_format::limits::Limits;

fn sb(h: &str) -> SecretBytes {
    SecretBytes::new(hex(h))
}

fn p(s: &[u8]) -> SecretBytes {
    // Passwords given as UTF-8 bytes in the cards.
    password_part(&pw(std::str::from_utf8(s).unwrap()))
}

fn derive(params: &KdfParams, composite: &SecretBytes) -> SecretBytes {
    let mut h = host();
    let Verdict::Run(c) = kdf::assess(params, &mut h, &Limits::DEFAULT.kdf, None).unwrap() else {
        panic!("ask")
    };
    kdf::derive(composite, &c).unwrap()
}

fn aes(rounds: u64, seed: &str) -> KdfParams {
    KdfParams::AesKdf {
        rounds,
        seed: hex(seed),
    }
}

const DEMO_PASS_C: &str = "dc00c46876f8ab6f1ea1f5fcd0a29e2a7a808bcd6e1d32076dbf779df06dcdb6";
const KS_V4: &str = "3481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e63";
const S_V4: &str = "0eeaa8a41e9d10b6901ec07f2de0698b3d2d996e86be1b2285b3c4e03fcae277";
const F_X: &str = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
const SECRET: &[u8] = b"Larsal demo HMAC key";

// ---------------------------------------------------------------------------
// FMT-04

#[test]
fn fmt_04_1_a() {
    assert_eq!(
        to_hex(p(b"demo-pass").expose()),
        "02ccf27105554b9a7fc512ba9f40b863ff974c35487512a7ea8b0e661f831b12"
    );
}

#[test]
fn fmt_04_1_b_no_normalization() {
    let nfc = p(&hex("50c3a4737377c3b67264"));
    let nfd = p(&hex("5061cc887373776fcc887264"));
    assert_eq!(
        to_hex(nfc.expose()),
        "b9fdf96f902f18de9c513b0b05383d0f47a06890832799cc0af2f583df530f61"
    );
    assert_eq!(
        to_hex(nfd.expose()),
        "7d73593078ce5f4906e8d2167b03b5883111eb854fe1146c4e3a3a4f88b6ce16"
    );
}

#[test]
fn fmt_04_1_c_no_trimming() {
    assert_eq!(
        to_hex(p(&hex("20737020616365 2009")).expose()),
        "5d6787e78636482da925e09ac4e3015ecd9f5fde66d4c448197b5076c010ac53"
    );
}

#[test]
fn fmt_04_1_d() {
    assert_eq!(
        to_hex(p(&hex("f09f9491")).expose()),
        "c5c75521402748f523eee2f15d74f10f38acbb134ebd026d5777958c3df862cb"
    );
}

#[test]
fn fmt_04_2_a_empty_password() {
    let e = p(b"");
    assert_eq!(
        to_hex(e.expose()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        to_hex(composite_key(Some(&e), None, None).expose()),
        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    );
}

#[test]
fn fmt_04_3_a_and_4_4_a() {
    let f = read_key_file_bytes(b"Larsal demo key file for the hashed kind.\n");
    assert_eq!(
        to_hex(f.key().expose()),
        "e31742b2095b0ee4303149e3cd1889cdb04ee0e01539f3a9798948f593974091"
    );
    assert_eq!(
        to_hex(composite_key(None, Some(f.key()), None).expose()),
        "c0da7d5312fc291e1d6d663d175c4c303966f0fc43e2f9269bed21734f35e744"
    );
    let pp = p(b"demo-pass");
    assert_eq!(
        to_hex(composite_key(Some(&pp), Some(f.key()), None).expose()),
        "c11e2f5765885c5646a4bb2f3404348e961b65a782697c008e6e2108274ed1a8"
    );
    let wrong = larsal_crypto::hash::sha256(&[f.key().expose(), pp.expose()]);
    assert_eq!(
        to_hex(wrong.expose()),
        "4db887e681ee24ec5b2454046ba817526c46159d50ac5edf901b5984decf7e41"
    );
}

fn read_key_file_bytes(b: &[u8]) -> larsal_format::keyfile::KeyFileKey {
    larsal_format::keyfile::read_key_file(std::io::Cursor::new(b.to_vec()), &Limits::DEFAULT)
        .unwrap()
}

#[test]
fn fmt_04_5_a_and_b() {
    let pp = p(b"demo-pass");
    assert_eq!(
        to_hex(composite_key(Some(&pp), None, None).expose()),
        DEMO_PASS_C
    );
    assert_eq!(
        to_hex(composite_key(Some(&pp), Some(&sb(F_X)), None).expose()),
        "2c6c7513daf938019ed5af937a20c41dab110d59228f7b7b355636143c44f4e1"
    );
}

fn soft(secret: &[u8], mode: SlotMode) -> SoftwareKey {
    SoftwareKey {
        secret: SecretBytes::new(secret.to_vec()),
        mode,
    }
}

#[test]
fn fmt_04_6_a_variable_mode() {
    let key = soft(SECRET, SlotMode::Variable);
    use larsal_format::keys::ChallengeResponse;
    let answer = key
        .challenge(&padded_challenge(&hex(KS_V4)).unwrap())
        .unwrap();
    assert_eq!(
        to_hex(answer.expose()),
        "05c98b753b0a4bda4c42e79228e79ddee3cdac14"
    );
    let r = hardware_part(&key, &hex(KS_V4)).unwrap();
    assert_eq!(
        to_hex(r.expose()),
        "0bb9f4e1ac2332efd4345b6776a36ae211a5000d108ecb6812f7caea44c1c59e"
    );
    let c = composite_key(Some(&p(b"demo-pass")), Some(&sb(F_X)), Some(&r));
    assert_eq!(
        to_hex(c.expose()),
        "5766f34ebf894d4f0339f5cb61f8eb3f596f0c490fd24dc6cca545d5ed3e4a16"
    );
}

#[test]
fn fmt_04_6_d_fixed_mode() {
    let key = soft(SECRET, SlotMode::Fixed);
    let r = hardware_part(&key, &hex(KS_V4)).unwrap();
    assert_eq!(
        to_hex(r.expose()),
        "f8e6a567fa41e4c19b82f376881e02c86c0b2662d49b9419139d0766a3ae04b6"
    );
    let c = composite_key(Some(&p(b"demo-pass")), Some(&sb(F_X)), Some(&r));
    assert_eq!(
        to_hex(c.expose()),
        "07dd73258c1a1065b121dd87c609b6d6c476ab1030a4a5b84128b84a93749f52"
    );
}

#[test]
fn fmt_04_6_e_vector_hk() {
    let ks = hex("828824cbe1a43319be44b303ddce4fcbf3daa0a02fe5d65fa73c5c903a8485d8");
    let secret = hex("1ce30fd78d20dcfa40b50c18779afb0f02288db7");
    let r = hardware_part(&soft(&secret, SlotMode::Variable), &ks).unwrap();
    assert_eq!(
        to_hex(r.expose()),
        "709b0674aa1124dab024c7d50e428badb26829ca8485e03844300daadff5bf6a"
    );
    let c = composite_key(Some(&p(b"a")), None, Some(&r));
    assert_eq!(
        to_hex(c.expose()),
        "df5d072b8c138f85dea5d2f04ceefcf3c001f3c83c25d9a2a5c0f548fbd8bfa1"
    );
    let r = hardware_part(&soft(&secret, SlotMode::Fixed), &ks).unwrap();
    let c = composite_key(Some(&p(b"a")), None, Some(&r));
    assert_eq!(
        to_hex(c.expose()),
        "2311208091a3912b3eac398e867873f08db702c7c9c8e9982d9ec16378f06d6e"
    );
}

#[test]
fn fmt_04_6_b_no_hardware_key_adds_nothing() {
    let pp = p(b"demo-pass");
    let without = composite_key(Some(&pp), Some(&sb(F_X)), None);
    assert_eq!(
        to_hex(without.expose()),
        "2c6c7513daf938019ed5af937a20c41dab110d59228f7b7b355636143c44f4e1"
    );
    let empty_r = larsal_crypto::hash::sha256(&[b""]);
    assert_ne!(
        without,
        composite_key(Some(&pp), Some(&sb(F_X)), Some(&empty_r))
    );
}

#[test]
fn fmt_04_6_c_hardware_key_through_the_kdf() {
    let r = hardware_part(&soft(SECRET, SlotMode::Variable), &hex(KS_V4)).unwrap();
    let c = composite_key(Some(&p(b"demo-pass")), Some(&sb(F_X)), Some(&r));
    let t = derive(&aes(1_000_000, KS_V4), &c);
    assert_eq!(
        to_hex(t.expose()),
        "8eef32387812d120632f8fbd2d69d04071a7e71f70f3cf6d327994f505fa60a5"
    );
    let k = final_keys(&hex(S_V4), &t);
    assert_eq!(
        to_hex(k.cipher_key.expose()),
        "98fd053d28a93c3b5c29289fdc0dc17ef5c9c7b618297d79d7b7fdcfe83f830e"
    );
    assert_eq!(
        to_hex(k.hmac_key.expose()),
        "698b35ce4a989cd80caa1444a94c90b455fcf01d28b4bb673d01d91a3cfc6e7777c0bdb6ed3819ca2ab300bf3b88f0859058d622a367a8f7bb6fbabd8a02cf63"
    );
}

#[test]
fn fmt_04_8_and_4_9_challenge_padding() {
    let c = padded_challenge(&hex(KS_V4)).unwrap();
    assert_eq!(c[..32], hex(KS_V4)[..]);
    assert_eq!(c[32..], [0x20; 32]);
    let s = hex("8ca3a3bbc9f2fb20c2ba098d9a1caf09ff8d05884cf9064f8ee674dab167c043");
    assert_eq!(padded_challenge(&s).unwrap()[32..], [0x20; 32]);
    let c8 = padded_challenge(&hex("a0a1a2a3a4a5a6a7")).unwrap();
    assert_eq!(
        (c8[..8].to_vec(), c8[8..].to_vec()),
        (hex("a0a1a2a3a4a5a6a7"), vec![0x38; 56])
    );
    let s16: Vec<u8> = (0xa0..=0xaf).collect();
    let c16 = padded_challenge(&s16).unwrap();
    assert_eq!(c16[16..], [0x30; 48]);
}

#[test]
fn fmt_04_10_b_answer_not_20_bytes() {
    struct Bad(usize);
    impl larsal_format::keys::ChallengeResponse for Bad {
        fn challenge(
            &self,
            _: &[u8; 64],
        ) -> Result<SecretBytes, larsal_format::error::HardwareKeyReason> {
            Ok(SecretBytes::new(vec![1; self.0]))
        }
    }
    for n in [19, 21] {
        assert_eq!(
            hardware_part(&Bad(n), &[0; 32]).unwrap_err(),
            Error::HardwareKey(larsal_format::error::HardwareKeyReason::BadAnswer)
        );
    }
}

#[test]
fn fmt_04_11_a_aes_kdf() {
    let c = sb(DEMO_PASS_C);
    let ks = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    for (rounds, want) in [
        (
            1,
            "ab1a9f624218636aac0df21a44480809c00d515186aafec4bb17748df8275099",
        ),
        (
            2,
            "bb44b70521f4a3490b25ac09bf16154278926b52addf70050bb462ed9c24f3ac",
        ),
        (
            1000,
            "2305dd9b08c603a1b3b2e3a71c98830a7d5e951732a92df7810af59576af7eed",
        ),
    ] {
        assert_eq!(
            to_hex(derive(&aes(rounds, ks), &c).expose()),
            want,
            "{rounds}"
        );
    }
}

#[test]
fn fmt_04_11_b_argon2() {
    let c = sb(DEMO_PASS_C);
    for (kind, want) in [
        (
            Argon2Type::D,
            "a5aba766c577d0aec14ae550dc428182d49fa7b933642f4b858d92935e7a0962",
        ),
        (
            Argon2Type::Id,
            "088bafc94c3fd1ad3e2035b7500d3cf640b2f6bb562166d20ba60ac170a262e3",
        ),
    ] {
        let params = KdfParams::Argon2 {
            kind,
            version: 0x13,
            iterations: 2,
            memory_kib: 64,
            lanes: 2,
            salt: (0u8..32).collect(),
        };
        assert_eq!(to_hex(derive(&params, &c).expose()), want);
    }
}

#[test]
fn fmt_04_11_c_both_aes_kdf_ids() {
    let r = hardware_part(&soft(SECRET, SlotMode::Variable), &hex(KS_V4)).unwrap();
    let old = aes_kdf_map(1_000, &hex(KS_V4));
    let mut new = old.clone();
    new[16..32].copy_from_slice(&kdf::AES_KDF_NEW_ID);
    let pp = p(b"demo-pass");
    let a = transformed_parts(&old, Some(&pp), None, Some(&r));
    let b = transformed_parts(&new, Some(&pp), None, Some(&r));
    assert_eq!(a, b);
    assert_ne!(
        a,
        transformed_parts(&old, Some(&pp), None, None),
        "R is inside C"
    );
}

#[test]
fn fmt_04_11_d_and_4_13_a() {
    let c = composite_key(Some(&p(b"demo-pass")), Some(&sb(F_X)), None);
    let t = derive(&aes(1_000_000, KS_V4), &c);
    assert_eq!(
        to_hex(t.expose()),
        "1513b1f95c2087fea5e1e396be862b7796464d4bf18449d7a3dca59e0c4f82c0"
    );
    let k = final_keys(&hex(S_V4), &t);
    assert_eq!(
        to_hex(k.cipher_key.expose()),
        "d386a895a6ea6f3e9b249157d83c497558b7ebb9b55fd89132add0617069809f"
    );
}

/// The V4 demo header of FMT-04.14-a (207 bytes).
fn v4_header() -> Vec<u8> {
    hex(
        "03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff03040000000100000004200000000eeaa8a41e9d10b6901ec07f2de0698b3d2d996e86be1b2285b3c4e03fcae27707100000008142ce41d6b614dee8a3c19f220f86640b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea0501000000520800000040420f0000000000420100000053200000003481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e630000040000000d0a0d0a",
    )
}

#[test]
fn fmt_04_14_a() {
    let h = v4_header();
    assert_eq!(h.len(), 207);
    let c = composite_key(Some(&p(b"demo-pass")), Some(&sb(F_X)), None);
    let t = derive(&aes(1_000_000, KS_V4), &c);
    let k = final_keys(&hex(S_V4), &t);
    assert_eq!(
        to_hex(k.hmac_key.expose()),
        "25580261b98d28d8443c5c6f98111ed6a21419ce3517a395f70bfb5d75eabb5e443aeda405facb650015a42f19ddf40e2dc763229ab7650d158842c7aac9fe97"
    );
    let key_hdr = larsal_crypto::hash::sha512(&[&[0xFF; 8], k.hmac_key.expose()]);
    assert_eq!(
        to_hex(key_hdr.expose()),
        "870b9e35ae27c6b5bcba99560ca214a087bf09e5779a0d41834779cec16ad80493d55a46d92570919a10935c3a50a1ceb5b6d2e48d8c30fc63cec5300956c04b"
    );
    assert_eq!(
        to_hex(header_hmac(&k.hmac_key, &h).expose()),
        "ab47e216d18d93e538ae83d10e8546f19c70038adbcf8e2291f4bdaf7c146a79"
    );
    assert!(header_hash_ok(
        &h,
        &hex("cd7ee6365f1016dcfaa5df2479258a08a9f88f8691ec9020be18b324a396c4d9")
    ));
}

#[test]
fn fmt_04_11_e_and_4_13_b_and_4_14_b_format400_keys() {
    // Values from the card only; the vault itself is in REF_TESTDATA.
    let c = composite_key(Some(&p(b"t")), None, None);
    assert_eq!(
        to_hex(c.expose()),
        "7415e100520c4fc2de9429958c0b64500a076b48ef2ad0648c7243c52046c671"
    );
    let params = KdfParams::Argon2 {
        kind: Argon2Type::D,
        version: 0x13,
        iterations: 2,
        memory_kib: 1024,
        lanes: 2,
        salt: hex("56ac066d2d862ab0c50c00f6143a349df441f2e6910b297da88f50c3c302d9a5"),
    };
    let t = derive(&params, &c);
    assert_eq!(
        to_hex(t.expose()),
        "5ef06327c2aa395e04aa9a94fb837b58030cf202eddc61f408046070c256a2e8"
    );
    let k = final_keys(
        &hex("3bfa79c0795325db317f99f475b559f195d73368da522c12a061a0c2b9efcb13"),
        &t,
    );
    assert_eq!(
        to_hex(k.cipher_key.expose()),
        "fe24792c0ffb62dbec19139addf06e6fb2ebb3924c1bbd23053caa453ab7d175"
    );
    assert_eq!(
        to_hex(k.hmac_key.expose()),
        "5f9f7be123af6d249558f4fa3b68d2d63405f8d72b90ae4ba670a2aa6fa1c235c12ea142ffbc3a6faa218bc2a5842cb7050407f95a4d0e6556ea1e5ad7b180f9"
    );
}

#[test]
fn fmt_04_12_a_and_4_15_a_version_3_key_math() {
    // The same AES-KDF and SHA-256(S || T) serve version 3 (E3-S8 reads the file).
    let t = derive(
        &aes(
            1_000_000,
            "e0d76aeae02eaa39ddc28327e61f1ce94f2dea34b82e8cffc424b4f984bb8e37",
        ),
        &sb(DEMO_PASS_C),
    );
    assert_eq!(
        to_hex(t.expose()),
        "816e7edddfe738c48b0d6fac9862eeb01295c8d3fc28bf56e381b066ad7d6199"
    );
    let s = hex("8ca3a3bbc9f2fb20c2ba098d9a1caf09ff8d05884cf9064f8ee674dab167c043");
    let k = final_keys(&s, &t).cipher_key;
    assert_eq!(
        to_hex(k.expose()),
        "67c681bc88295a0dd625a20d3cd40068b33bf2736104dddf979caca38878b96e"
    );
    // CBC: a dummy third block lets the decryptor hand back the first two.
    let mut ct = hex("9cf64ca3743991b6b667b5c0f98aa3cbd4fa6e2b70691db3f31ec226ccc3bec7");
    ct.extend([0; 16]);
    let mut d = larsal_crypto::cipher::Decryptor::new(
        larsal_crypto::cipher::Cipher::Aes256Cbc,
        &k,
        &hex("f15b240fd05118f3f35de05aecd72d25"),
    )
    .unwrap();
    assert_eq!(
        to_hex(d.update(&ct).unwrap().expose()),
        "8341f1326a7284ea021998e2455a97c1ba90da7cad9d9279cb323780f1c51dd1"
    );
}

#[test]
fn fmt_04_15_b_and_c_version_3_cipher_key_known_answers() {
    // K_enc = SHA256(S || R3 || T): the order is fixed (Checker R2-B3, Y05).
    let s = hex("8ca3a3bbc9f2fb20c2ba098d9a1caf09ff8d05884cf9064f8ee674dab167c043");
    let t = sb("816e7edddfe738c48b0d6fac9862eeb01295c8d3fc28bf56e381b066ad7d6199");
    for (r3, want) in [
        (
            "681c41243ccde847a3d56d4649b20a6628f2b30845ef86df0e0115f3bafc3882",
            "610661b8d519ef275c1ead499cba3cd2109ca9c76d7379dfc2b14439284fac5d",
        ),
        (
            "812b2c8b9202955875302570e81639ad962d7ae0361e448424bf80ae22b0afd2",
            "35975cb077886f5c86446b6bb7f9d249e5cfde1a0687d2d21effadb67b309723",
        ),
    ] {
        let k = larsal_format::keys::cipher_key_v3(&s, Some(&sb(r3)), &t);
        assert_eq!(to_hex(k.expose()), want);
    }
    let none = larsal_format::keys::cipher_key_v3(&s, None, &t);
    assert_eq!(
        to_hex(none.expose()),
        "67c681bc88295a0dd625a20d3cd40068b33bf2736104dddf979caca38878b96e"
    );
}

#[test]
fn fmt_04_15_b_and_c_version_3_challenge() {
    let s = hex("8ca3a3bbc9f2fb20c2ba098d9a1caf09ff8d05884cf9064f8ee674dab167c043");
    let r3 = hardware_part(&soft(SECRET, SlotMode::Variable), &s).unwrap();
    assert_eq!(
        to_hex(r3.expose()),
        "681c41243ccde847a3d56d4649b20a6628f2b30845ef86df0e0115f3bafc3882"
    );
    let r3 = hardware_part(&soft(SECRET, SlotMode::Fixed), &s).unwrap();
    assert_eq!(
        to_hex(r3.expose()),
        "812b2c8b9202955875302570e81639ad962d7ae0361e448424bf80ae22b0afd2"
    );
}

// ---------------------------------------------------------------------------
// FMT-01 Vector L4 keys

#[test]
fn fmt_01_12_vector_l4_keys() {
    let pp = p(b"demo-pass-1");
    assert_eq!(
        to_hex(pp.expose()),
        "89fe410c581e0e309e8852e267653da9151989600138c7901b635db0e4bd46c3"
    );
    let c = composite_key(Some(&pp), None, None);
    assert_eq!(
        to_hex(c.expose()),
        "ca6c3aa4439ae1debe011a795f6e0bd95ce30fdde4ca7fac92395588eeddf7a2"
    );
    let l4 = vector_l4()[..207].to_vec();
    assert_eq!(l4.len(), 207);
    let seed = &l4[0x2F..0x4F];
    let t = derive(&aes(1_000_000, &to_hex(&l4[0xA5..0xC5])), &c);
    assert_eq!(
        to_hex(t.expose()),
        "6466c670b915f3b5502ec910bc1895e9665a29c2a2ab731bf5f6cd127383eb2e"
    );
    let k = final_keys(seed, &t);
    assert_eq!(
        to_hex(k.cipher_key.expose()),
        "65061551da83d0bcc3c7a60c50da0a7f70dab8365a954187d9274fa6e43f037b"
    );
    assert_eq!(
        to_hex(k.hmac_key.expose()),
        "0775582a05c6d298c2fd959b5444244dd7c83407280f80103e9b5939cfc9a6f861c18326f41cdfe81f36737da0582ba87cdaa49b7d2ec83ef4b8a6878c34ac5a"
    );
    let stored = hex("D5F280EF3AC39CCE7A915EA7702B6EC7117C96EF1B600455B5E7DDED1F50225A");
    assert!(header_hmac_ok(&k.hmac_key, &l4, &stored));
    let wrong = final_keys(
        seed,
        &derive(
            &aes(1_000_000, &to_hex(&l4[0xA5..0xC5])),
            &composite_key(Some(&p(b"wrong")), None, None),
        ),
    );
    assert_eq!(
        to_hex(header_hmac(&wrong.hmac_key, &l4).expose()),
        "d616936860041257f7572438efad232ca07888382cceb6bceb225755615dc0af"
    );
}

// ---------------------------------------------------------------------------
// FMT-05

fn s_0_31() -> Vec<u8> {
    (0u8..32).collect()
}

fn t_32_63() -> SecretBytes {
    SecretBytes::new((32u8..64).collect())
}

const HDR: &str = "03d9a29a67fb4bb501000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0710000000404142434445464748494a4b4c4d4e4f00040000000d0a0d0a";

#[test]
fn fmt_05_4_base_key() {
    let k = final_keys(&s_0_31(), &t_32_63());
    assert_eq!(
        to_hex(k.hmac_key.expose()),
        "f09af394435628155b2d8ba7af6236610e63c26d6595f5bc508d3e1f2328dd7040c6ce1001efc85f9e7ef54e83df08e2c448fcc47dfd768d7f130de6666c37c3"
    );
}

#[test]
fn fmt_05_1_and_5_3_hash_over_raw_bytes() {
    assert_eq!(hex(HDR).len(), 109);
    assert!(header_hash_ok(
        &hex(HDR),
        &hex("34984c167a5ea4e3e7b565585d76a902207a5294c8d7c33041b6193ca17d51d3")
    ));
}

#[test]
fn fmt_05_5_and_5_6_header_hmac() {
    let k = final_keys(&s_0_31(), &t_32_63());
    let want = "3cb9a0fdb600461265b8e28ab9452479a12a313e34f4bae0b7b30184b6086989";
    assert_eq!(to_hex(header_hmac(&k.hmac_key, &hex(HDR)).expose()), want);
    assert!(header_hmac_ok(&k.hmac_key, &hex(HDR), &hex(want)));
}

#[test]
fn fmt_05_6_and_5_8_one_bit_key_change() {
    let mut t: Vec<u8> = (32u8..64).collect();
    t[0] = 0x21;
    let k = final_keys(&s_0_31(), &SecretBytes::new(t));
    assert_eq!(
        to_hex(header_hmac(&k.hmac_key, &hex(HDR)).expose()),
        "a6ad4d0a4ea8ed1dafaa57f55afe29c83576a8f2cdeabc98215dd5bf7614f081"
    );
    assert!(!header_hmac_ok(
        &k.hmac_key,
        &hex(HDR),
        &hex("3cb9a0fdb600461265b8e28ab9452479a12a313e34f4bae0b7b30184b6086989")
    ));
}

/// Demo header D4 of FMT-05 (207 bytes).
fn d4() -> Vec<u8> {
    let v = hex(concat!(
        "03 d9 a2 9a 67 fb 4b b5 00 00 04 00 02 10 00 00 00 31 c1 f2 e6 bf 71 43 50 be 58 05 21 6a fc 5a",
        "ff 03 04 00 00 00 01 00 00 00 04 20 00 00 00 df 71 ea 4f d2 e9 c9 4f 8e 17 9e 14 44 57 8e 1b 79",
        "2c 26 c1 6e 8f 27 af a9 7a b9 42 a9 1d 79 aa 07 10 00 00 00 9e cb 02 07 27 8f 2a c4 e7 a8 99 fc",
        "68 42 6e a9 0b 5d 00 00 00 00 01 42 05 00 00 00 24 55 55 49 44 10 00 00 00 c9 d9 f3 9a 62 8a 44",
        "60 bf 74 0d 08 c1 8a 4f ea 05 01 00 00 00 52 08 00 00 00 40 42 0f 00 00 00 00 00 42 01 00 00 00",
        "53 20 00 00 00 bc ea a2 9c 67 08 58 31 db 1d ad 53 b1 ab e4 6d 43 89 4c 16 40 ab 5a 05 78 d1 70",
        "24 2f 5a d6 c1 00 00 04 00 00 00 0d 0a 0d 0a"
    ));
    assert_eq!(v.len(), 207);
    v
}

#[test]
fn fmt_05_1_header_length() {
    let h = larsal_format::header::read_header(&[d4(), vec![0; 64]].concat(), &Limits::DEFAULT)
        .unwrap();
    assert_eq!(h.len, 207);
    assert_eq!(d4()[198..], hex("00 04 00 00 00 0d 0a 0d 0a")[..]);
}

#[test]
fn fmt_05_2_5_3_5_6_end_to_end_and_5_8_wrong_password() {
    let h = d4();
    let seed = &h[47..79];
    let ks = to_hex(&h[165..197]);
    let t = derive(
        &aes(1_000_000, &ks),
        &composite_key(Some(&p(b"demo-pass")), None, None),
    );
    assert_eq!(
        to_hex(t.expose()),
        "3922759997b81034d3c16c77e31649d01c75caba0809da42a782be60d668b33f"
    );
    assert!(header_hash_ok(
        &h,
        &hex("33a5cc7bbf83bfb2ae447739f18a4780cc0f1477e33b821cf71f6feeec6d61a8")
    ));
    let k = final_keys(seed, &t);
    assert_eq!(
        to_hex(k.hmac_key.expose()),
        "96aff2c2abaf7917fd4fa58651b2698def0f798c739233cd6671dc19950d70c23eab826cc2387fad37a3aaddc2916dc3eb483a486779a469b3ac72cc1814e8b7"
    );
    let stored = hex("d4c72728909426d045a25d0005e00dde9b3e94ce828e91fe58a2457f64c551db");
    assert!(header_hmac_ok(&k.hmac_key, &h, &stored));
    let tw = derive(
        &aes(1_000_000, &ks),
        &composite_key(Some(&p(b"wrong-pass")), None, None),
    );
    assert_eq!(
        to_hex(tw.expose()),
        "cb0bad4e7dfc64bfd769893b8499113fd76b531261f3b6c01ef1b19427066f00"
    );
    let kw = final_keys(seed, &tw);
    assert_eq!(
        to_hex(header_hmac(&kw.hmac_key, &h).expose()),
        "9b6cac5696b2cc1f55ab9bc4b319a182748e88ee572806b36c5c782197700f37"
    );
    assert!(!header_hmac_ok(&kw.hmac_key, &h, &stored));
}

// ---------------------------------------------------------------------------
// FMT-06

fn k() -> larsal_format::keys::LockedKey {
    final_keys(&s_0_31(), &t_32_63()).hmac_key
}

const P31: &[u8] = b"Larsal block stream test vec 01";
const THREE: &str = "49798586e44dc9158b065c2a9e1e63653bbcbb09242b8dbc2ed7a1339dcf0046100000004c617273616c20626c6f636b20737472b3439329945d3fab5e6b570726d093bfbb168be02509c431728dde6211f1995b0f00000065616d2074657374207665632030313b11fbddce34f0ecaf4597332bbab78bb992807d91bb509eaba01ea80822960b00000000";
const ONE: &str = "24af3c33b161aa8769533d0ad75636c26e8e1a3c1045606e3279419bb59723411f0000004c617273616c20626c6f636b2073747265616d207465737420766563203031aefcc91d8fb70ad4625a68e65c9844b8198b2c9631bcb0f43cbf8d2f36c2407d00000000";

fn read(stream: &[u8]) -> Result<Vec<u8>, Error> {
    read_blocks(stream, &k(), &Limits::DEFAULT).map(|b| b.concat())
}

#[test]
fn fmt_06_4_6_5_6_6_per_block_keys_and_hmacs() {
    // The three-block stream holds the block HMACs of K_0, K_1 and K_2.
    let three = hex(THREE);
    assert_eq!(three.len(), 139);
    assert_eq!(write_blocks(P31, &k(), 16).unwrap(), three);
}

#[test]
fn fmt_06_1_6_6_d4_final_block() {
    let kd4 = sb(
        "96aff2c2abaf7917fd4fa58651b2698def0f798c739233cd6671dc19950d70c23eab826cc2387fad37a3aaddc2916dc3eb483a486779a469b3ac72cc1814e8b7",
    );
    let s = write_blocks(&[0; 1584], &kd4, 1 << 20).unwrap();
    assert_eq!(s.len(), 36 + 1584 + 36);
    assert_eq!(
        to_hex(&s[s.len() - 36..s.len() - 4]),
        "601fb5c16408feed310b9f9488f70b7a2b84840aa7315f012d56aefe0fe12a4a"
    );
    assert_eq!(207 + 64 + s.len(), 1927);
}

#[test]
fn fmt_06_2_6_7_read_and_boundaries() {
    assert_eq!(read(&hex(THREE)).unwrap(), P31);
    assert_eq!(read(&hex(ONE)).unwrap(), P31);
}

#[test]
fn fmt_06_8_writer() {
    assert_eq!(write_blocks(P31, &k(), 1 << 20).unwrap(), hex(ONE));
    let mb = 1 << 20;
    let one = write_blocks(&vec![7; mb], &k(), mb).unwrap();
    assert_eq!(one.len(), 1_048_648);
    assert_eq!(read_blocks(&one, &k(), &Limits::DEFAULT).unwrap().len(), 1);
    let over = write_blocks(&vec![7; mb + 1], &k(), mb).unwrap();
    assert_eq!(
        read_blocks(&over, &k(), &Limits::DEFAULT)
            .unwrap()
            .iter()
            .map(|b| b.len())
            .collect::<Vec<_>>(),
        [mb, 1]
    );
    let two = write_blocks(&vec![7; 2 * mb], &k(), mb).unwrap();
    assert_eq!(
        read_blocks(&two, &k(), &Limits::DEFAULT)
            .unwrap()
            .iter()
            .map(|b| b.len())
            .collect::<Vec<_>>(),
        [mb, mb]
    );
}

fn flip(mut v: Vec<u8>, at: usize, x: u8) -> Vec<u8> {
    v[at] ^= x;
    v
}

#[test]
fn fmt_06_9_6_5_6_10_damage_and_sizes() {
    let three = hex(THREE);
    assert_eq!(read(&flip(three.clone(), 36, 1)), Err(Error::Corrupt));
    assert_eq!(read(&flip(three.clone(), 0, 1)), Err(Error::Corrupt));
    let mut s = three.clone();
    s[32] = 0x11;
    assert_eq!(read(&s), Err(Error::Corrupt));
    let mut s = three.clone();
    s[35] = 0x01;
    assert_eq!(read(&s), Err(Error::Corrupt));
    for size in ["ffffffff", "00000080", "ffffff7f"] {
        let mut s = three.clone();
        s[32..36].copy_from_slice(&hex(size));
        assert_eq!(read(&s), Err(Error::Corrupt), "{size}");
    }
}

/// A block stream whose HMACs use the given indexes (for "wrong index base").
fn stream_with_indexes(blocks: &[&[u8]], first: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for (n, data) in blocks.iter().chain([&&[][..]]).enumerate() {
        let i = first + n as u64;
        let key = larsal_crypto::hash::sha512(&[&i.to_le_bytes(), k().expose()]);
        let size = (data.len() as u32).to_le_bytes();
        let tag = larsal_crypto::mac::hmac_sha256(key.expose(), &[&i.to_le_bytes(), &size, data])
            .unwrap();
        out.extend_from_slice(tag.expose());
        out.extend_from_slice(&size);
        out.extend_from_slice(data);
    }
    out
}

#[test]
fn fmt_06_3_swap_drop_repeat_index_base() {
    let three = hex(THREE);
    let (b0, b1, fin) = (&three[..52], &three[52..103], &three[103..]);
    assert_eq!(stream_with_indexes(&[&P31[..16], &P31[16..]], 0), three);
    assert_eq!(read(&[b1, b0, fin].concat()), Err(Error::Corrupt));
    assert_eq!(read(&[b0, fin].concat()), Err(Error::Corrupt));
    assert_eq!(read(&[b0, b0, b1, fin].concat()), Err(Error::Corrupt));
    assert_eq!(
        read(&stream_with_indexes(&[&P31[..16], &P31[16..]], 1)),
        Err(Error::Corrupt)
    );
}

#[test]
fn fmt_06_6_6_11_final_block_and_cuts() {
    let three = hex(THREE);
    assert_eq!(read(&three[..103]), Err(Error::Corrupt));
    assert_eq!(read(&flip(three.clone(), 110, 1)), Err(Error::Corrupt));
    // A final block of size -1 whose HMAC is made over that size.
    let mut neg = three[..103].to_vec();
    let i = 2u64;
    let key = larsal_crypto::hash::sha512(&[&i.to_le_bytes(), k().expose()]);
    let tag =
        larsal_crypto::mac::hmac_sha256(key.expose(), &[&i.to_le_bytes(), &[0xFF; 4]]).unwrap();
    neg.extend_from_slice(tag.expose());
    neg.extend([0xFF; 4]);
    assert_eq!(read(&neg), Err(Error::Corrupt));
    for n in [40, 20, 34] {
        assert_eq!(read(&three[..n]), Err(Error::Corrupt), "{n}");
    }
}

#[test]
fn fmt_06_12_bytes_after_the_final_block() {
    let three = hex(THREE);
    assert_eq!(read(&[three.clone(), vec![0]].concat()).unwrap(), P31);
    assert_eq!(read(&[three.clone(), vec![0; 36]].concat()).unwrap(), P31);
    let extra = stream_with_indexes(&[&P31[..16], &P31[16..], b"EXTRA"], 0);
    let extra_block = &extra[103..103 + 41];
    assert_eq!(
        read(&[three.clone(), extra_block.to_vec()].concat()).unwrap(),
        P31
    );
    let second_final = &stream_with_indexes(&[&P31[..16], &P31[16..], b"EXTRA"], 0)[103 + 41..];
    assert_eq!(
        read(&[three.clone(), second_final.to_vec()].concat()).unwrap(),
        P31
    );
}

#[test]
fn fmt_06_14_empty_payload() {
    let fin = hex("a81cb0e4a59e138e1a5ee1755c778c30a45cb02d6c6382d78a627b7715eeefce00000000");
    assert_eq!(stream_with_indexes(&[], 0), fin);
    assert_eq!(read(&fin), Err(Error::Corrupt));
}

#[test]
fn fmt_06_10_lowered_block_limit() {
    let three = hex(THREE);
    let lim = |n: usize| Limits {
        block: n,
        ..Limits::DEFAULT
    };
    assert_eq!(
        read_blocks(&three, &k(), &lim(16)).map(|b| b.concat()),
        Ok(P31.to_vec())
    );
    assert_eq!(
        read_blocks(&three, &k(), &lim(15)).err(),
        Some(Error::Corrupt)
    );
}
