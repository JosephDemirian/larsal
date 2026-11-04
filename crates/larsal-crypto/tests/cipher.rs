//! Payload cipher tests (story E2-S4, spec CRY-01): known answers, the one
//! decrypt error (LD-04), length checks, streaming, round-trip properties.
//!
//! Vector sources are named next to each vector. Every AES-256-CBC and
//! ChaCha20 vector below was also reproduced on this Mac with
//! /usr/bin/openssl (LibreSSL 3.3.6) and /opt/homebrew/bin/openssl (4.0.3).
//! Twofish was cross-checked with libgcrypt and nettle on this Mac (Verify); its vectors are the Twofish authors' tables as
//! quoted in spec CRY-01 (T9, T9b, T10) and the twofish crate's own tests.

use larsal_crypto::Error;
use larsal_crypto::cipher::{self, BLOCK_LEN, Cipher, Decryptor, Encryptor, KEY_LEN};
use larsal_crypto::secret::SecretBytes;
use proptest::prelude::*;

const ALL: [Cipher; 3] = [Cipher::Aes256Cbc, Cipher::Twofish256Cbc, Cipher::ChaCha20];

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn key(s: &str) -> SecretBytes {
    SecretBytes::new(hex(s))
}

/// Cuts `data` into chunks with the given sizes, used in turn.
fn split<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    for &n in sizes.iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let (head, tail) = rest.split_at(n.min(rest.len()));
        out.push(head);
        rest = tail;
    }
    out
}

fn encrypt_chunked(c: Cipher, k: &SecretBytes, iv: &[u8], data: &[u8], sizes: &[usize]) -> Vec<u8> {
    let mut enc = Encryptor::new(c, k, iv).unwrap();
    let mut out = Vec::new();
    for chunk in split(data, sizes) {
        out.extend(enc.update(chunk).unwrap());
    }
    out.extend(enc.finish());
    out
}

fn decrypt_chunked(
    c: Cipher,
    k: &SecretBytes,
    iv: &[u8],
    data: &[u8],
    sizes: &[usize],
) -> Result<Vec<u8>, Error> {
    let mut dec = Decryptor::new(c, k, iv)?;
    let mut out = Vec::new();
    for chunk in split(data, sizes) {
        out.extend_from_slice(dec.update(chunk)?.expose());
    }
    out.extend_from_slice(dec.finish()?.expose());
    Ok(out)
}

// ---------------------------------------------------------------- AES-256-CBC

// NIST SP 800-38A appendix F.2.5 (CBC-AES256.Encrypt) and F.2.6 (Decrypt).
const NIST_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const NIST_IV: &str = "000102030405060708090a0b0c0d0e0f";
const NIST_PT: &str = "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
                       30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710";
const NIST_CT: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d
                       39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b";
// The PKCS#7 block that follows NIST_CT when the same plaintext is padded
// (16 bytes of 10). Computed with `openssl enc -aes-256-cbc` (both builds).
const NIST_PAD_BLOCK: &str = "3f461796d6b0d6b2e0c2a72b4d80e644";

#[test]
fn wrong_key_and_bad_padding_give_one_error_cry01_t38() {
    // CRY-01 T38 (LD-04): (a) T4 key with last byte f5; (b) right key,
    // ciphertext byte 15 changed from d6 to d7.
    let ct = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0");
    let iv = hex(NIST_IV);
    let mut wrong = hex(NIST_KEY);
    assert_eq!(wrong.pop(), Some(0xf4));
    wrong.push(0xf5);
    let a = cipher::decrypt(Cipher::Aes256Cbc, &SecretBytes::new(wrong), &iv, &ct);
    let mut bad = ct.clone();
    assert_eq!(bad[15], 0xd6);
    bad[15] = 0xd7;
    let b = cipher::decrypt(Cipher::Aes256Cbc, &key(NIST_KEY), &iv, &bad);
    assert_eq!(a.err(), Some(Error::Decrypt));
    assert_eq!(b.err(), Some(Error::Decrypt));
}

#[test]
fn aes256_cbc_nist_sp800_38a_f25_encrypt() {
    let ct = cipher::encrypt(
        Cipher::Aes256Cbc,
        &key(NIST_KEY),
        &hex(NIST_IV),
        &hex(NIST_PT),
    );
    let ct = ct.unwrap();
    assert_eq!(ct.len(), 80, "64 bytes plus one full padding block");
    assert_eq!(ct[..64], hex(NIST_CT)[..], "SP 800-38A F.2.5");
    assert_eq!(ct[64..], hex(NIST_PAD_BLOCK)[..], "openssl padding block");
}

#[test]
fn aes256_cbc_nist_sp800_38a_f26_decrypt() {
    let k = key(NIST_KEY);
    let iv = hex(NIST_IV);
    // Raw CBC decryption (F.2.6): the stream decryptor returns every block
    // but the held-back last one before any padding is looked at.
    let mut dec = Decryptor::new(Cipher::Aes256Cbc, &k, &iv).unwrap();
    let head = dec.update(&hex(NIST_CT)).unwrap();
    assert_eq!(
        head.expose(),
        &hex(NIST_PT)[..48],
        "SP 800-38A F.2.6 blocks 1-3"
    );
    // With the openssl padding block, all four blocks come back.
    let full = [hex(NIST_CT), hex(NIST_PAD_BLOCK)].concat();
    let pt = cipher::decrypt(Cipher::Aes256Cbc, &k, &iv, &full).unwrap();
    assert_eq!(pt.expose(), &hex(NIST_PT)[..], "SP 800-38A F.2.6");
}

// Spec CRY-01 T5, T6, T7 (padding cases with the NIST key and IV) and T8
// (round trip). Values match openssl.
#[test]
fn aes256_cbc_pkcs7_padding_cry01_t5_to_t8() {
    let k = key(NIST_KEY);
    let iv = hex(NIST_IV);
    for (pt, ct) in [
        ("6bc1bee22e409f96e93d", "565d88409a86d17478875abf0a26d532"),
        (
            "6bc1bee22e409f96e93d7e117393172a",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0",
        ),
        ("", "7e9248e5d829ca7593f0c549db2f5b8c"),
    ] {
        assert_eq!(
            cipher::encrypt(Cipher::Aes256Cbc, &k, &iv, &hex(pt)).unwrap(),
            hex(ct)
        );
        let back = cipher::decrypt(Cipher::Aes256Cbc, &k, &iv, &hex(ct)).unwrap();
        assert_eq!(back.expose(), &hex(pt)[..]);
    }
}

// Spec FMT-08 T08-01 (decrypt to gzip("hello"), last block ends in 07 x 7)
// and T08-03 (16-byte plaintext gets a full padding block). Match openssl.
#[test]
fn aes256_cbc_fmt08_t01_and_t03() {
    let k = key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let iv = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    let gzip_hello = hex("1f8b0800000000000013cb48cdc9c9070086a6103605000000");
    let ct = hex("b994ac0feca700c7cf211083f93a67f250ce691225e01004bc56f04fc46a1163");
    let pt = cipher::decrypt(Cipher::Aes256Cbc, &k, &iv, &ct).unwrap();
    assert_eq!(pt.expose(), &gzip_hello[..]);
    let ct = cipher::encrypt(Cipher::Aes256Cbc, &k, &iv, b"0123456789abcdef").unwrap();
    assert_eq!(
        ct,
        hex("ce1cf3a4e3b87b139ba3cff10ace35b606d96b2e184bf22b73d31ba4be14d8c9")
    );
}

// ------------------------------------------------------------ Twofish-256-CBC

/// One Twofish block through the public API: CBC with a zero IV makes the
/// first ciphertext block E(P xor 0) = E(P), the plain block function.
fn twofish_block(k: &[u8], pt: &[u8]) -> Vec<u8> {
    let ct = cipher::encrypt(
        Cipher::Twofish256Cbc,
        &SecretBytes::new(k.to_vec()),
        &[0; 16],
        pt,
    );
    ct.unwrap()[..16].to_vec()
}

// Spec CRY-01 T9 and T9b: the Twofish authors' 256-bit full-encryption table
// (49 steps; next key = this plaintext ++ first half of this key, next
// plaintext = this ciphertext). Steps 4, 5 and 48 are from the twofish
// crate's tests (the same published table).
#[test]
fn twofish256_authors_table_cry01_t9_t9b() {
    let mut k = [0u8; 32];
    let mut pt = [0u8; 16];
    for step in 1..=49 {
        let ct = twofish_block(&k, &pt);
        let want = match step {
            1 => Some("57ff739d4dc92c1bd7fc01700cc8216f"), // T9
            2 => Some("d43bb7556ea32e46f2a282b7d45b4e0d"),
            3 => Some("90afe91bb288544f2c32dc239b2635e6"),
            4 => Some("6cb4561c40bf0a9705931cb6d408e7fa"),
            5 => Some("3059d6d61753b958d92f4781c8640e58"),
            48 => Some("431058f4dbc7f734da4f02f04cc4f459"),
            49 => Some("37fe26ff1cf66175f5ddf4c33b97a205"),
            _ => None,
        };
        if step == 3 {
            let want_key = [hex("57ff739d4dc92c1bd7fc01700cc8216f"), vec![0; 16]].concat();
            assert_eq!(k.to_vec(), want_key, "T9b step 3 key");
        }
        if step == 49 {
            let want_key = "248a7f3528b168acfdd1386e3f51e30c2e2158bc3e5fc714c1eeeca0ea696d48";
            assert_eq!(k.to_vec(), hex(want_key), "T9b step 49 key");
            assert_eq!(
                pt.to_vec(),
                hex("431058f4dbc7f734da4f02f04cc4f459"),
                "T9b step 49 plaintext"
            );
        }
        if let Some(want) = want {
            assert_eq!(ct, hex(want), "step {step}");
        }
        let (left, right) = k.split_at_mut(16);
        right.copy_from_slice(left);
        left.copy_from_slice(&pt);
        pt.copy_from_slice(&ct);
    }
}

/// XORs the last two 16-byte outputs into a 32-byte Monte Carlo key.
fn mct_next_key(k: &mut [u8; 32], second_last: &[u8; 16], last: &[u8; 16]) {
    for (b, x) in k.iter_mut().zip(second_last.iter().chain(last)) {
        *b ^= x;
    }
}

// Spec CRY-01 T10, encrypt table: the Twofish authors' 256-bit CBC Monte
// Carlo test, 5 rows of 10,000 encryptions, run through the streaming
// Encryptor (one update per block, so its CBC chaining is what is tested).
#[test]
fn twofish256_cbc_monte_carlo_encrypt_cry01_t10() {
    let rows = [
        "ea7162e65490b03b1ae4871fb35ef23b",
        "549ff6c6274f034211c31fadf3f22571",
        "cf222616b0e4f8e48967d769456b916b",
        "957108025bfd57125b40057bc2de4fe2",
        "6f725c5950133f82ef021a94cadc8508",
    ];
    let (mut k, mut iv, mut pt) = ([0u8; 32], [0u8; 16], [0u8; 16]);
    for (row, want) in rows.iter().enumerate() {
        let mut enc =
            Encryptor::new(Cipher::Twofish256Cbc, &SecretBytes::new(k.to_vec()), &iv).unwrap();
        let (mut second_last, mut last, mut input) = ([0u8; 16], [0u8; 16], pt);
        for j in 0..10_000 {
            let ct: [u8; 16] = enc.update(&input).unwrap().try_into().unwrap();
            if row == 0 && j == 0 {
                assert_eq!(ct.to_vec(), hex("57ff739d4dc92c1bd7fc01700cc8216f"));
            }
            input = if j == 0 { iv } else { last };
            second_last = last;
            last = ct;
        }
        assert_eq!(last.to_vec(), hex(want), "encrypt row {row}");
        mct_next_key(&mut k, &second_last, &last);
        if row == 0 {
            let row1_key = "d0a260eb41755b19374babf259a79db3ea7162e65490b03b1ae4871fb35ef23b";
            assert_eq!(k.to_vec(), hex(row1_key));
        }
        iv = last;
        pt = second_last;
    }
}

// Spec CRY-01 T10, decrypt table. Each output is the next input, so the
// streaming Decryptor (which holds back the last block for its padding)
// cannot run it; this checks the approved twofish crate with cbc directly,
// as CRY-01 asks of the Builder's unit tests.
#[test]
fn twofish256_cbc_monte_carlo_decrypt_cry01_t10() {
    use cbc::cipher::array::Array;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
    let rows = [
        "2cba6271a1044f90c30ba8fe91e1c163",
        "05f05148ef495836ab0da226b2e9d0c2",
        "a792ac61e7110c434bc2bbcab6e53cae",
        "4c81f5bdc1081170ff96f50b1f76a566",
        "bd959f5b787037631a37051ea5f369f8",
    ];
    let (mut k, mut iv, mut ct) = ([0u8; 32], [0u8; 16], [0u8; 16]);
    for (row, want) in rows.iter().enumerate() {
        let mut dec = cbc::Decryptor::<twofish::Twofish>::new_from_slices(&k, &iv).unwrap();
        let (mut second_last, mut last, mut input) = ([0u8; 16], [0u8; 16], ct);
        let mut last_input = input;
        for _ in 0..10_000 {
            let mut block = Array::from(input);
            dec.decrypt_block(&mut block);
            last_input = input;
            second_last = last;
            last.copy_from_slice(&block);
            input = last;
        }
        assert_eq!(last.to_vec(), hex(want), "decrypt row {row}");
        mct_next_key(&mut k, &second_last, &last);
        if row == 0 {
            let row1_key = "1b1fe8f5a911cd4c0d800edce8ed0a942cba6271a1044f90c30ba8fe91e1c163";
            assert_eq!(k.to_vec(), hex(row1_key));
        }
        iv = last_input;
        ct = last;
    }
}

// Spec CRY-01 T34: the Twofish demo vault blocks the reference tool opened.
#[test]
fn twofish256_cbc_vault_blocks_cry01_t34() {
    let k = key("85f2c6883b3e4c61497c856a2b94d7d14713baf6434650fce461e05b34a06ad0");
    let iv = hex("606162636465666768696a6b6c6d6e6f");
    let p = hex(
        "01040000000300000002400000000001 02030405060708090a0b0c0d0e0f1011
                 12131415161718191a1b1c1d1e1f2021",
    );
    let c = hex(
        "8f07ff5cd93bfb2466569e7f4ebdc6f7 cf0e07298c7ffa271d2ba1652944a86b
                 486ee224e6c03bf979ee8af40b0b1ceb",
    );
    let ct = cipher::encrypt(Cipher::Twofish256Cbc, &k, &iv, &p).unwrap();
    assert_eq!(ct[..48], c[..], "C0 to C2");
    let mut dec = Decryptor::new(Cipher::Twofish256Cbc, &k, &iv).unwrap();
    assert_eq!(dec.update(&c).unwrap().expose(), &p[..32], "P0, P1 back");
    // The last block: 12 plaintext bytes and 4 bytes of 04 padding, chained
    // on the previous ciphertext block.
    let prev = hex("72b86e2d1fd3be9862d1e0da6ceae920");
    let tail = hex("65655061737346696c653e0a");
    let last = hex("516f3836d4cac99d6c9465a9ba4112c2");
    assert_eq!(
        cipher::encrypt(Cipher::Twofish256Cbc, &k, &prev, &tail).unwrap(),
        last
    );
    let back = cipher::decrypt(Cipher::Twofish256Cbc, &k, &prev, &last).unwrap();
    assert_eq!(back.expose(), &tail[..]);
}

// ------------------------------------------------------------------- ChaCha20

const KEY_00_1F: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// The payload keystream from block `counter` on: our counter starts at 0
/// (CRY-01.6), so the first `counter` blocks are encrypted and dropped.
fn chacha_from_block(k: &str, nonce: &str, counter: usize, data: &[u8]) -> Vec<u8> {
    let mut enc = Encryptor::new(Cipher::ChaCha20, &key(k), &hex(nonce)).unwrap();
    assert_eq!(
        enc.update(&vec![0; 64 * counter]).unwrap().len(),
        64 * counter
    );
    enc.update(data).unwrap()
}

// RFC 8439 appendix A.1 test vectors 1 to 5 and section 2.3.2.
#[test]
fn chacha20_rfc8439_a1_and_2_3_2_blocks() {
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    let one = "0000000000000000000000000000000000000000000000000000000000000001";
    let ff = "00ff000000000000000000000000000000000000000000000000000000000000";
    for (name, k, nonce, counter, want) in [
        (
            "A.1 #1",
            zero,
            "000000000000000000000000",
            0,
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ),
        (
            "A.1 #2",
            zero,
            "000000000000000000000000",
            1,
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
        ),
        (
            "A.1 #3",
            one,
            "000000000000000000000000",
            1,
            "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
        ),
        (
            "A.1 #4",
            ff,
            "000000000000000000000000",
            2,
            "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
        ),
        (
            "A.1 #5",
            zero,
            "000000000000000000000002",
            0,
            "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
        ),
        (
            "2.3.2",
            KEY_00_1F,
            "000000090000004a00000000",
            1,
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        ),
    ] {
        assert_eq!(
            chacha_from_block(k, nonce, counter, &[0; 64]),
            hex(want),
            "RFC 8439 {name}"
        );
    }
}

// RFC 8439 section 2.4.2 (counter 1) and appendix A.2 test vector 3 (counter 42).
#[test]
fn chacha20_rfc8439_2_4_2_and_a2_3_encryption() {
    let sunscreen = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let want = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
    assert_eq!(
        chacha_from_block(KEY_00_1F, "000000000000004a00000000", 1, sunscreen),
        hex(want)
    );
    let jabberwocky = b"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
    let k = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
    let want = "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1";
    assert_eq!(
        chacha_from_block(k, "000000000000000000000002", 42, jabberwocky),
        hex(want)
    );
}

// Spec CRY-01 T13 (counter starts at 0) and T14 (chunks of 1, 7, 63, 64, 65
// bytes give the same 130 bytes).
#[test]
fn chacha20_counter_from_zero_and_chunking_cry01_t13_t14() {
    let want = hex(
        "103af111c18b549d39248fb07d60c29a95d1db88d892f7b4af709a5fd47a9e4bd5ff9a658dd52c708bef1f0f622b3747040fa3551300b1f293150a88620d5fed89fb08002917a540b7833ff3981d0e63c970b2e75174adb9e6972fc575c0a63cec802cf3e61eb198373276d865948f237e84a974fd28b89b12b8d907904f9ed67978",
    );
    let k = key(KEY_00_1F);
    let nonce = hex("000102030405060708090a0b");
    assert_eq!(
        cipher::encrypt(Cipher::ChaCha20, &k, &nonce, &[0; 130]).unwrap(),
        want
    );
    for size in [1, 7, 63, 64, 65] {
        assert_eq!(
            encrypt_chunked(Cipher::ChaCha20, &k, &nonce, &[0; 130], &[size]),
            want
        );
        assert_eq!(
            decrypt_chunked(Cipher::ChaCha20, &k, &nonce, &want, &[size]).unwrap(),
            vec![0; 130]
        );
    }
}

// Spec FMT-08 T08-02: decrypting with counter 0 gives gzip("hello");
// counter 1 would give bytes starting 03 41 52 6c.
#[test]
fn chacha20_payload_counter_zero_fmt08_t02() {
    let k = key(KEY_00_1F);
    let nonce = hex("c0c1c2c3c4c5c6c7c8c9cacb");
    let ct = hex("1ab97de8d0612b20dfd50ffcbbdd0dac60a9c9c925198df6b0");
    let gzip_hello = hex("1f8b0800000000000013cb48cdc9c9070086a6103605000000");
    let pt = cipher::decrypt(Cipher::ChaCha20, &k, &nonce, &ct).unwrap();
    assert_eq!(pt.expose(), &gzip_hello[..]);
    let mut dec = Decryptor::new(Cipher::ChaCha20, &k, &nonce).unwrap();
    let _ = dec.update(&[0; 64]).unwrap();
    assert_eq!(dec.update(&ct).unwrap().expose()[..4], hex("0341526c")[..]);
}

// ------------------------------------------- errors (LD-04) and length checks

// spec/decisions.md LD-04, CRY-01.11, AT-B07: empty input, a length that is
// not whole blocks, bad padding and a wrong key all give one error value with
// one text.
#[test]
fn every_decrypt_failure_is_the_same_error_ld04() {
    for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc] {
        let k = SecretBytes::new(vec![0x11; KEY_LEN]);
        let wrong = SecretBytes::new(vec![0x22; KEY_LEN]);
        let iv = [0x33; BLOCK_LEN];
        // 32 aligned bytes: the last block is all padding (16 bytes of 10).
        let good = cipher::encrypt(c, &k, &iv, &[0x44; 32]).unwrap();
        let mut bad_pad = good.clone();
        bad_pad[good.len() - BLOCK_LEN - 1] ^= 0x01; // padding byte 10 becomes 11
        let failures = [
            cipher::decrypt(c, &k, &iv, &[]).err(),
            cipher::decrypt(c, &k, &iv, &good[..37]).err(),
            cipher::decrypt(c, &k, &iv, &good[..good.len() - 1]).err(),
            cipher::decrypt(c, &k, &iv, &bad_pad).err(),
            cipher::decrypt(c, &wrong, &iv, &good).err(),
        ];
        for f in failures {
            let e = f.expect("must fail");
            assert_eq!(e, Error::Decrypt, "{c:?}");
            assert_eq!(e.to_string(), "decryption failed");
            assert_eq!(format!("{e:?}"), "Decrypt");
        }
        // The same through the streaming API.
        let mut dec = Decryptor::new(c, &wrong, &iv).unwrap();
        let _ = dec.update(&good).unwrap();
        assert_eq!(dec.finish().err(), Some(Error::Decrypt));
    }
}

// E2-S4: key and IV length errors come before any work. Key is checked
// first; a wrong IV with a broken ciphertext still says IvLength, so no
// decryption ran.
#[test]
fn key_and_iv_lengths_are_checked_before_any_work() {
    for c in ALL {
        let good_key = SecretBytes::new(vec![1; KEY_LEN]);
        let good_iv = vec![2; c.iv_len()];
        for n in [0, 16, 31, 33, 64] {
            let k = SecretBytes::new(vec![1; n]);
            assert_eq!(
                Encryptor::new(c, &k, &good_iv).err(),
                Some(Error::KeyLength)
            );
            assert_eq!(
                Decryptor::new(c, &k, &good_iv).err(),
                Some(Error::KeyLength)
            );
            assert_eq!(
                cipher::encrypt(c, &k, &good_iv, b"x").err(),
                Some(Error::KeyLength)
            );
            assert_eq!(
                cipher::decrypt(c, &k, &good_iv, &[0; 37]).err(),
                Some(Error::KeyLength)
            );
            assert_eq!(
                cipher::decrypt(c, &k, &[0; 5], &[0; 37]).err(),
                Some(Error::KeyLength)
            );
        }
        for n in [0, 8, 11, 12, 13, 15, 16, 17, 24] {
            if n == c.iv_len() {
                continue;
            }
            let iv = vec![2; n];
            assert_eq!(
                Encryptor::new(c, &good_key, &iv).err(),
                Some(Error::IvLength)
            );
            assert_eq!(
                Decryptor::new(c, &good_key, &iv).err(),
                Some(Error::IvLength)
            );
            assert_eq!(
                cipher::encrypt(c, &good_key, &iv, b"x").err(),
                Some(Error::IvLength)
            );
            assert_eq!(
                cipher::decrypt(c, &good_key, &iv, &[0; 37]).err(),
                Some(Error::IvLength)
            );
        }
    }
    assert_eq!(
        [
            Cipher::Aes256Cbc.iv_len(),
            Cipher::Twofish256Cbc.iv_len(),
            Cipher::ChaCha20.iv_len()
        ],
        [16, 16, 12],
        "CRY-01.8"
    );
}

// CRY-01 "Inputs and outputs": CBC output is the length rounded up to the next
// block, plus a block when already aligned; ChaCha20 output has the same length.
#[test]
fn ciphertext_lengths() {
    let k = SecretBytes::new(vec![3; KEY_LEN]);
    for c in ALL {
        let iv = vec![4; c.iv_len()];
        for n in 0..=50 {
            let ct = cipher::encrypt(c, &k, &iv, &vec![5; n]).unwrap();
            let want = if c == Cipher::ChaCha20 {
                n
            } else {
                (n / 16 + 1) * 16
            };
            assert_eq!(ct.len(), want, "{c:?} {n}");
        }
    }
}

// CRY-01.12: a CBC encryptor holds back at most 15 bytes and a decryptor at
// most one block (16 bytes); empty updates change nothing.
#[test]
fn streaming_holds_back_at_most_one_block() {
    let k = SecretBytes::new(vec![6; KEY_LEN]);
    for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc] {
        let iv = [7; 16];
        let mut enc = Encryptor::new(c, &k, &iv).unwrap();
        assert_eq!(enc.update(&[]).unwrap().len(), 0);
        assert_eq!(enc.update(&[8; 15]).unwrap().len(), 0);
        assert_eq!(enc.update(&[8; 1]).unwrap().len(), 16);
        assert_eq!(enc.update(&[8; 40]).unwrap().len(), 32);
        assert_eq!(enc.finish().len(), 16);
        let mut dec = Decryptor::new(c, &k, &iv).unwrap();
        assert_eq!(dec.update(&[9; 16]).unwrap().len(), 0);
        assert_eq!(dec.update(&[]).unwrap().len(), 0);
        assert_eq!(dec.update(&[9; 16]).unwrap().len(), 16);
        assert_eq!(dec.update(&[9; 40]).unwrap().len(), 48);
    }
    let mut enc = Encryptor::new(Cipher::ChaCha20, &k, &[0; 12]).unwrap();
    assert_eq!(enc.update(&[1; 5]).unwrap().len(), 5);
    assert!(enc.finish().is_empty());
}

// ------------------------------------------------------------ property tests

fn any_cipher() -> impl Strategy<Value = Cipher> {
    prop::sample::select(ALL.to_vec())
}

proptest! {
    // Round trip: decrypt(encrypt(x)) == x for every cipher.
    #[test]
    fn round_trip(
        c in any_cipher(),
        k in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
        data in prop::collection::vec(any::<u8>(), 0..600),
    ) {
        let k = SecretBytes::new(k.to_vec());
        let iv = &iv[..c.iv_len()];
        let ct = cipher::encrypt(c, &k, iv, &data).unwrap();
        let pt = cipher::decrypt(c, &k, iv, &ct).unwrap();
        prop_assert_eq!(pt.expose(), &data[..]);
    }

    // Streaming in chunks of any sizes equals one call, both ways (CRY-01.7).
    #[test]
    fn streaming_equals_one_shot(
        c in any_cipher(),
        k in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
        data in prop::collection::vec(any::<u8>(), 0..600),
        enc_sizes in prop::collection::vec(1usize..80, 1..8),
        dec_sizes in prop::collection::vec(1usize..80, 1..8),
    ) {
        let k = SecretBytes::new(k.to_vec());
        let iv = &iv[..c.iv_len()];
        let one_shot = cipher::encrypt(c, &k, iv, &data).unwrap();
        prop_assert_eq!(&encrypt_chunked(c, &k, iv, &data, &enc_sizes), &one_shot);
        prop_assert_eq!(decrypt_chunked(c, &k, iv, &one_shot, &dec_sizes).unwrap(), data);
    }

    // Any input decrypts or fails with the one error; never a panic.
    #[test]
    fn garbage_gives_ok_or_the_one_error(
        c in any_cipher(),
        k in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
        data in prop::collection::vec(any::<u8>(), 0..100),
        sizes in prop::collection::vec(1usize..40, 1..4),
    ) {
        let k = SecretBytes::new(k.to_vec());
        let iv = &iv[..c.iv_len()];
        let one = cipher::decrypt(c, &k, iv, &data).map(|p| p.expose().to_vec());
        let streamed = decrypt_chunked(c, &k, iv, &data, &sizes);
        prop_assert!(matches!(one, Ok(_) | Err(Error::Decrypt)));
        prop_assert_eq!(one, streamed);
    }
}

/// LD-41: the version 3 end call returns whole blocks with no padding check.
#[test]
fn finish_unpadded_returns_whole_blocks_ld41() {
    let k = key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let iv = [0x40u8; 16];
    for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc] {
        // 32 plaintext bytes padded with 16 x 10: three cipher blocks.
        let pt: Vec<u8> = (0u8..32).collect();
        let ct = cipher::encrypt(c, &k, &iv, &pt).unwrap();
        for sizes in [vec![48], vec![1, 47], vec![16, 16, 16]] {
            let mut d = Decryptor::new(c, &k, &iv).unwrap();
            let mut out = Vec::new();
            for part in split(&ct, &sizes) {
                out.extend_from_slice(d.update(part).unwrap().expose());
            }
            out.extend_from_slice(d.finish_unpadded().unwrap().expose());
            assert_eq!(
                out,
                [pt.clone(), vec![0x10; 16]].concat(),
                "{c:?} {sizes:?}"
            );
        }
        // No padding check: a last block that is not padding comes back as it is.
        let mut d = Decryptor::new(c, &k, &iv).unwrap();
        let first = d.update(&ct[..32]).unwrap();
        let last = d.finish_unpadded().unwrap();
        assert_eq!([first.expose(), last.expose()].concat(), pt);
        // Nothing held: nothing returned. Not whole blocks: Decrypt.
        let d = Decryptor::new(c, &k, &iv).unwrap();
        assert!(d.finish_unpadded().unwrap().is_empty());
        let mut d = Decryptor::new(c, &k, &iv).unwrap();
        let _ = d.update(&ct[..20]).unwrap();
        assert_eq!(d.finish_unpadded().err(), Some(Error::Decrypt));
    }
    let mut d = Decryptor::new(Cipher::ChaCha20, &k, &[0; 12]).unwrap();
    assert_eq!(d.update(&[0; 5]).unwrap().len(), 5);
    assert!(d.finish_unpadded().unwrap().is_empty());
}
