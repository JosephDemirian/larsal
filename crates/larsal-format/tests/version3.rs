//! Version 3 rows (story E3-S8): FMT-17, FMT-07 (hashed blocks) and the
//! version 3 rows of FMT-05 (start bytes, header hash, open order). Test
//! vaults come from testdata/ (made by the reference CLI) and from the
//! test-only version 3 builder in format_common (LD-35).

mod format_common;

use format_common::*;
use larsal_crypto::cipher::{Cipher, Decryptor};
use larsal_crypto::kdf::KdfParams;
use larsal_crypto::secret::SecretBytes;
use larsal_format::Error;
use larsal_format::hashed_blocks::read_hashed_blocks;
use larsal_format::header::{Compression, read_header};
use larsal_format::inner::StreamAlgorithm;
use larsal_format::keys::{cipher_key_v3, composite_key, final_keys, password_part};
use larsal_format::limits::{Limit, Limits};
use larsal_format::payload::probe;
use std::sync::OnceLock;

const L: Limits = Limits::DEFAULT;

/// Vector L3 of FMT-17 (222 bytes).
fn l3() -> Vec<u8> {
    let v = hex(concat!(
        "03 D9 A2 9A 67 FB 4B B5 01 00 03 00 02 10 00 31",
        "C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF 03",
        "04 00 01 00 00 00 04 20 00 30 16 C0 D9 6D 00 70",
        "B5 AF 02 12 73 33 AF DE 72 39 81 A6 2F 5C 20 13",
        "A4 9E 54 FC C5 33 33 2C 26 05 20 00 58 21 C9 8B",
        "89 6E 99 07 5E 97 0E CE E5 7E 29 F5 D6 CC A2 F9",
        "25 7C 0C 76 0C 5C E7 8F A3 DB 25 1A 06 08 00 40",
        "42 0F 00 00 00 00 00 07 10 00 9B B8 89 95 35 B4",
        "6B E0 42 33 5A 17 C5 63 1B 32 08 20 00 B3 21 CD",
        "A3 B8 4D 81 6E F4 08 77 77 D9 49 73 77 E4 00 33",
        "AF FA B3 47 C6 AB 70 93 DD 1D 61 51 3E 09 20 00",
        "6C CB 4E 01 E7 25 E9 FE 0C 32 66 41 3B 49 5B B8",
        "69 CF FC 15 82 67 E3 55 60 39 DC 78 56 18 D2 30",
        "0A 04 00 02 00 00 00 00 04 00 0D 0A 0D 0A"
    ));
    assert_eq!(v.len(), 222);
    v
}

fn splice(mut v: Vec<u8>, at: usize, remove: usize, insert: &[u8]) -> Vec<u8> {
    v.splice(at..at + remove, insert.iter().copied());
    v
}

fn parse(v: &[u8]) -> Result<larsal_format::header::Header, Error> {
    read_header(v, &L)
}

fn xml(r: Result<larsal_format::payload::Open, Error>) -> Vec<u8> {
    opened(r).xml.bytes().to_vec()
}

/// password-only.larsalvault, its cipher key (AES-KDF ~13M rounds, once per
/// binary) and its XML.
struct PasswordOnly {
    file: Vec<u8>,
    key: SecretBytes,
    xml: Vec<u8>,
}

fn password_only() -> &'static PasswordOnly {
    static P: OnceLock<PasswordOnly> = OnceLock::new();
    P.get_or_init(|| {
        let file = testdata("password-only.larsalvault");
        let h = parse(&file).unwrap();
        let KdfParams::AesKdf { rounds, seed } = &h.kdf else {
            panic!()
        };
        let t = transformed(
            &aes_kdf_map(*rounds, seed),
            &password_part(&pw("demo-pass-1")),
        );
        let key = cipher_key_v3(&h.master_seed, None, &t);
        let xml = xml(open(&file, "demo-pass-1"));
        PasswordOnly { file, key, xml }
    })
}

/// Decrypts whole CBC blocks with no padding check (LD-41).
fn cbc_whole(key: &SecretBytes, iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut d = Decryptor::new(Cipher::Aes256Cbc, key, iv).unwrap();
    let mut out = d.update(ct).unwrap().expose().to_vec();
    out.extend_from_slice(d.finish_unpadded().unwrap().expose());
    out
}

// ---------------------------------------------------------------------------
// testdata/: every 3.1 vault opens down to its XML (the JSON comparison is
// tests/testdata.rs, every_vault_opens_and_matches_its_json).

#[test]
fn testdata_version_3_vaults_open() {
    for (name, password) in [
        ("password-only", "demo-pass-1"),
        ("default-time", "demo-pass-3"),
        ("rich-v3", "demo-pass-4"),
    ] {
        let p = opened(open(&testdata(&format!("{name}.larsalvault")), password));
        assert_eq!((p.header.major, p.header.minor), (3, 1), "{name}");
        assert_eq!(&p.xml.bytes()[..5], b"<?xml", "{name}");
        assert_eq!(
            (p.inner.stream, p.inner.pool.len()),
            (StreamAlgorithm::Salsa20, 0)
        );
        assert_eq!(
            p.inner.stream_key.expose(),
            p.header.v3.as_ref().unwrap().stream_key.as_slice()
        );
    }
}

#[test]
fn fmt_17_13_wrong_key() {
    let _ = probe::take();
    assert_eq!(kind(open(&password_only().file, "wrong")), Error::WrongKey);
    let file = testdata("password-and-keyfile.larsalvault");
    assert_eq!(
        kind(open(&file, "demo-pass-2")),
        Error::WrongKey,
        "key file part missing"
    );
    let c = probe::take();
    assert_eq!(c.inflate, 0);
}

// ---------------------------------------------------------------------------
// FMT-17

#[test]
fn fmt_17_2_and_17_3_vector_l3() {
    let h = parse(&[l3(), vec![0; 48]].concat()).unwrap();
    assert_eq!((h.major, h.minor, h.len), (3, 1, 222));
    assert_eq!(
        (h.cipher, h.compression),
        (Cipher::Aes256Cbc, Compression::Gzip)
    );
    assert_eq!(
        h.kdf,
        KdfParams::AesKdf {
            rounds: 1_000_000,
            seed: l3()[0x4C..0x6C].to_vec()
        }
    );
    let v3 = h.v3.unwrap();
    assert_eq!(
        (v3.stream_key.len(), v3.start_bytes.to_vec()),
        (32, l3()[0xB0..0xD0].to_vec())
    );
    assert_eq!(h.iv, l3()[0x7A..0x8A].to_vec());
}

#[test]
fn fmt_17_3_size_errors() {
    let short9 = splice(splice(l3(), 0xAE, 2, &[31, 0]), 0xB0, 1, &[]);
    assert_eq!(parse(&short9).unwrap_err(), Error::Corrupt);
    let short2 = splice(splice(l3(), 0x0D, 2, &[15, 0]), 0x1E, 1, &[]);
    assert_eq!(parse(&short2).unwrap_err(), Error::Corrupt);
}

#[test]
fn fmt_17_5_duplicate_field() {
    let v = splice(l3(), 0xD7, 0, &hex("0A 04 00 02 00 00 00"));
    assert_eq!(parse(&v).unwrap_err(), Error::Corrupt);
}

#[test]
fn fmt_17_6_and_17_7_missing_fields() {
    // Field spans in Vector L3: 2 at 0x0C (19), 3 at 0x1F (7), 9 at 0xAD (35).
    for (at, n) in [(0xAD, 35), (0x0C, 19), (0x1F, 7)] {
        assert_eq!(
            parse(&splice(l3(), at, n, &[])).unwrap_err(),
            Error::Corrupt,
            "{at:#x}"
        );
    }
    let file = testdata("password-only.larsalvault");
    let _ = probe::take();
    assert_eq!(
        kind(open(&splice(file, 12, 19, &[]), "demo-pass-1")),
        Error::Corrupt
    );
    let file = testdata("default-time.larsalvault");
    assert_eq!(
        kind(open(&splice(file, 0x6C, 11, &[]), "demo-pass-3")),
        Error::Corrupt
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_17_8_stream_id() {
    for v in ["01000000", "09000000", "03000000"] {
        assert_eq!(
            parse(&splice(l3(), 0xD3, 4, &hex(v))).unwrap_err(),
            Error::Unsupported,
            "{v}"
        );
    }
    let without = splice(l3(), 0xD0, 7, &[]);
    assert!(parse(&without).is_ok(), "field 10 absent means Salsa20");
}

#[test]
fn fmt_17_9_key_flow() {
    let l3 = l3();
    let c = composite_key(Some(&password_part(&pw("demo-pass-1"))), None, None);
    assert_eq!(
        to_hex(c.expose()),
        "ca6c3aa4439ae1debe011a795f6e0bd95ce30fdde4ca7fac92395588eeddf7a2"
    );
    let t = transformed(
        &aes_kdf_map(1_000_000, &l3[0x4C..0x6C]),
        &password_part(&pw("demo-pass-1")),
    );
    assert_eq!(
        to_hex(t.expose()),
        "acbfeeff70b21ef0b85e79d0442887c297e0db34a7a02eb25ecf9e5369736785"
    );
    let k = cipher_key_v3(&l3[0x29..0x49], None, &t);
    assert_eq!(
        to_hex(k.expose()),
        "a55252a59d717d59109e3f56c92e5ed526f4e60c6718a58aff379c45ba527771"
    );
    assert_eq!(
        k,
        *final_keys(&l3[0x29..0x49], &t).cipher_key,
        "without a hardware key: the version 4 formula"
    );
}

#[test]
fn fmt_17_10_hardware_key_step() {
    let d = DemoV3 {
        hardware: Some(b"Larsal demo HMAC key".to_vec()),
        ..DemoV3::new()
    };
    let file = d.build();
    let p = pw("demo-pass");
    let key = soft_key(b"Larsal demo HMAC key");
    let creds = larsal_format::keys::Credentials {
        password: Some(&p),
        key_file: None,
        hardware_key: Some(&key),
    };
    assert_eq!(xml(open_creds(&file, &creds)), DEMO_XML);
    // The response hashed into the composite key instead (version 4 way): WrongKey.
    let mut v4_way = d.clone();
    v4_way.hardware = None;
    let r = larsal_format::keys::hardware_part(&key, &d.seed).unwrap();
    let t = transformed_parts(
        &aes_kdf_map(d.rounds, &d.transform_seed),
        Some(&password_part(&p)),
        None,
        Some(&r),
    );
    let wrong_key = cipher_key_v3(&d.seed, None, &t);
    let c = larsal_crypto::cipher::encrypt(d.cipher, &wrong_key, &d.iv, &d.plaintext()).unwrap();
    assert_eq!(
        kind(open_creds(&d.build_with_ciphertext(&c), &creds)),
        Error::WrongKey
    );
}

#[test]
fn fmt_17_11_and_17_12_ciphertext_start_and_length() {
    for name in ["password-only", "default-time", "rich-v3"] {
        let file = testdata(&format!("{name}.larsalvault"));
        assert_eq!(parse(&file).unwrap().len, 222, "{name}");
        assert_eq!((file.len() - 222) % 16, 0, "{name}");
    }
}

#[test]
fn fmt_17_12_odd_length_after_the_end() {
    let p = password_only();
    assert_eq!(
        xml(open(&[p.file.clone(), vec![0]].concat(), "demo-pass-1")),
        p.xml
    );
}

#[test]
fn fmt_17_12_cut_ciphertext() {
    let p = password_only();
    for cut in [48, 47] {
        assert_eq!(
            kind(open(&p.file[..p.file.len() - cut], "demo-pass-1")),
            Error::Corrupt,
            "{cut}"
        );
    }
}

#[test]
fn fmt_17_13_start_bytes_vector() {
    let k = SecretBytes::new(hex(
        "A55252A59D717D59109E3F56C92E5ED526F4E60C6718A58AFF379C45BA527771",
    ));
    let ct = hex(
        "CA D3 FE 0F 32 C9 F0 15 99 97 B2 D8 44 AC FD C1 26 90 BC 24 26 C8 ED 29 C6 E5 D4 EA 04 E6 83 B4",
    );
    let pt = cbc_whole(
        &k,
        &hex("9B B8 89 95 35 B4 6B E0 42 33 5A 17 C5 63 1B 32"),
        &ct,
    );
    assert_eq!(pt, l3()[0xB0..0xD0].to_vec());
}

#[test]
fn fmt_17_14_and_17_15_hashed_blocks_of_password_only() {
    let p = password_only();
    let h = parse(&p.file).unwrap();
    let plain = cbc_whole(&p.key, &h.iv, &p.file[222..]);
    assert_eq!(plain[..32], h.v3.unwrap().start_bytes);
    let blocks = read_hashed_blocks(&plain[32..], &L).unwrap();
    assert_eq!(
        blocks.len(),
        1,
        "one data block: the reference writes 1 MiB blocks"
    );
    let end = 32 + 40 + blocks[0].len();
    assert_eq!(
        u32::from_le_bytes(plain[end..end + 4].try_into().unwrap()),
        1,
        "final block index 1"
    );
    let tail = &plain[end + 40..];
    let n = *tail.last().unwrap() as usize;
    assert!(
        (1..=16).contains(&n) && tail.len() == n && tail.iter().all(|&b| b as usize == n),
        "only PKCS#7 padding remains"
    );
}

#[test]
fn fmt_17_15_padding_never_checked() {
    // Plaintext before the padding a multiple of 16: the last cipher block is all padding.
    let mut d = DemoV3::new();
    d.gzip = false;
    let mut n = 0;
    while !d.plaintext().len().is_multiple_of(16) {
        n += 1;
        d.xml = [DEMO_XML.to_vec(), vec![b' '; n]].concat();
    }
    let file = d.build();
    let want = xml(open(&file, "demo-pass"));
    let cut = &file[..file.len() - 16];
    assert_eq!(xml(open(cut, "demo-pass")), want);
    let mut replaced = file.clone();
    let len = replaced.len();
    replaced[len - 16..].copy_from_slice(&[0xA7; 16]);
    let _ = probe::take();
    assert_eq!(xml(open(&replaced, "demo-pass")), want);
}

#[test]
fn fmt_17_15_appended_bytes_ignored() {
    let p = password_only();
    for n in [16usize, 4096] {
        let tail: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
        assert_eq!(
            xml(open(&[p.file.clone(), tail].concat(), "demo-pass-1")),
            p.xml
        );
    }
}

#[test]
fn fmt_17_19_header_hash_values() {
    assert_eq!(
        to_hex(larsal_crypto::hash::sha256(&[&l3()]).expose()),
        "2b985b7deb7f246f5d67329a7b0e0e9f65519b86dd055aaea0a9583136b4792c"
    );
    let p = password_only();
    let text = String::from_utf8(p.xml.clone()).unwrap();
    let b64 = text
        .split("<HeaderHash>")
        .nth(1)
        .unwrap()
        .split("</HeaderHash>")
        .next()
        .unwrap();
    let got = larsal_crypto::base64::decode(larsal_crypto::base64::Form::Padded, b64).unwrap();
    assert_eq!(got, larsal_crypto::hash::sha256(&[&p.file[..222]]).expose());
}

#[test]
fn fmt_17_19_mismatch_through_open() {
    // A changed header byte (the end-of-header data, not read as a value)
    // passes the payload layer, then fails the document's header hash.
    let p = password_only();
    let mut file = p.file.clone();
    file[219] ^= 0x01;
    assert!(
        open(&file, "demo-pass-1").is_ok(),
        "the payload layer has no header check in version 3"
    );
    let pass = pw("demo-pass-1");
    let creds = larsal_format::keys::Credentials {
        password: Some(&pass),
        ..Default::default()
    };
    let r = larsal_format::open(&file, &creds, &mut host(), &L, None);
    assert_eq!(r.err(), Some(Error::Corrupt));
}

#[test]
fn fmt_17_21_and_17_25_writer_facts() {
    let order = |v: &[u8]| -> Vec<(u8, u16)> {
        let mut pos = 12;
        let mut out = Vec::new();
        loop {
            let id = v[pos];
            let len = u16::from_le_bytes([v[pos + 1], v[pos + 2]]);
            out.push((id, len));
            pos += 3 + len as usize;
            if id == 0 {
                return out;
            }
        }
    };
    let want = vec![
        (2, 16),
        (3, 4),
        (4, 32),
        (5, 32),
        (6, 8),
        (7, 16),
        (8, 32),
        (9, 32),
        (10, 4),
        (0, 4),
    ];
    assert_eq!(order(&l3()), want);
    for name in [
        "password-only",
        "keyfile-binary32",
        "keyfile-hex64",
        "keyfile-hashed",
        "keyfile-xml-v1",
        "keyfile-xml-v2",
        "keyfile-cli-made",
        "password-and-keyfile",
        "default-time",
        "rich-v3",
        "big-10000",
    ] {
        let file = testdata(&format!("{name}.larsalvault"));
        assert_eq!(order(&file), want, "{name}");
        assert_eq!(parse(&file).unwrap().len, 222);
    }
}

#[test]
fn fmt_17_26_rounds_range() {
    for v in [
        "0000000000000000",
        "FFFFFF7F00000000",
        "0000008000000000",
        "0500000001000000",
    ] {
        assert_eq!(
            parse(&splice(l3(), 0x6F, 8, &hex(v))).unwrap_err(),
            Error::Unsupported,
            "{v}"
        );
    }
    assert!(parse(&splice(l3(), 0x6F, 8, &hex("FEFFFF7F00000000"))).is_ok());
}

#[test]
fn fmt_17_1_any_minor() {
    for (major, minor) in [(3u16, 0u16), (3, 2), (3, 65535), (2, 0), (2, 4)] {
        let d = DemoV3 {
            major,
            minor,
            ..DemoV3::new()
        };
        assert_eq!(
            xml(open(&d.build(), "demo-pass")),
            DEMO_XML,
            "{major}.{minor}"
        );
    }
}

#[test]
fn fmt_17_12_every_cipher_and_compression() {
    for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc, Cipher::ChaCha20] {
        for gzip in [true, false] {
            let d = DemoV3 {
                gzip,
                ..DemoV3::new().with_cipher(c)
            };
            assert_eq!(xml(open(&d.build(), "demo-pass")), DEMO_XML, "{c:?} {gzip}");
            assert_eq!(kind(open(&d.build(), "wrong-pass")), Error::WrongKey);
        }
    }
}

// ---------------------------------------------------------------------------
// FMT-07

const P31: &[u8] = b"Larsal block stream test vec 01";
const THREE: &str = "00000000e3c0a7a3375948832e2acea67686ca5628ff02f0a623208c5b962b76a13a09ab100000004c617273616c20626c6f636b207374720100000048e27c0212a775566758c465f0883d2c22414eb11e1bc6475d168ba3044bd7280f00000065616d20746573742076656320303102000000000000000000000000000000000000000000000000000000000000000000000000000000";
const ONE: &str = "00000000d226535d5e4992f915d2812e2e03bde16380c90dcd676f3401868e4db4406a991f0000004c617273616c20626c6f636b2073747265616d20746573742076656320303101000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn read(s: &[u8]) -> Result<Vec<u8>, Error> {
    read_hashed_blocks(s, &L).map(|b| b.concat())
}

#[test]
fn fmt_07_2_to_07_7_vectors() {
    assert_eq!(hex(THREE).len(), 151);
    assert_eq!(hashed_blocks(P31, 16), hex(THREE));
    assert_eq!(hashed_blocks(P31, 1 << 20), hex(ONE));
    assert_eq!(read(&hex(THREE)).unwrap(), P31);
    assert_eq!(read(&hex(ONE)).unwrap(), P31);
    assert_eq!(hashed_blocks(&vec![1; 1 << 20], 1 << 20).len(), 1_048_656);
}

#[test]
fn fmt_07_1_and_07_11_encrypted_form_and_fmt_05_10_05_11() {
    let ct = hex(
        "23db97b1fbe632c63b581e30a4df5f878944ccc91e52c4bcf08eddcb124d45cc1a7f15b7ee289331a8832a62f5d8cd424df7a6090126b10e0b213ebeadb9b92aa607c0332d468313b05785278ef8409330c6d6eb77b2bb77c97384e0ed1d4f3dcc127b6bbb69bfe4f0fb156265fcdf0b8fc7180f4fd3a097538f3df6b13001a3452c7153367661fff6de47a0670d0e8f5e2987e7685b127574aebf9760f8db76c74454a1dcb46627e9b70fbd038d46533135ec6b80334157f5e120481889a662",
    );
    let iv: Vec<u8> = (0x40..=0x4F).collect();
    let plain = cbc_whole(&SecretBytes::new((0x60..=0x7F).collect()), &iv, &ct);
    assert_eq!(plain[..32], (0x80..=0x9F).collect::<Vec<u8>>()[..]);
    assert_eq!(to_hex(&plain[176..]), "00000000000000090909090909090909");
    assert_eq!(
        read(&plain[32..]).unwrap(),
        P31,
        "the padding after the final block is not read"
    );
    let mut wrong: Vec<u8> = (0x60..=0x7F).collect();
    wrong[0] = 0x61;
    let bad = cbc_whole(&SecretBytes::new(wrong), &iv, &ct);
    assert_eq!(
        to_hex(&bad[..32]),
        "b7396b0c28c6b8c74534315822da9353818598d447e883b0edd8d2826b000272"
    );
}

#[test]
fn fmt_07_3_to_07_5_damage() {
    let three = hex(THREE);
    let flipped = |at: usize, v: u8| {
        let mut s = three.clone();
        s[at] = v;
        s
    };
    assert_eq!(read(&flipped(56, 0x02)), Err(Error::Corrupt), "wrong index");
    let (b0, b1, fin) = (&three[..56], &three[56..111], &three[111..]);
    assert_eq!(
        read(&[b1, b0, fin].concat()),
        Err(Error::Corrupt),
        "swapped"
    );
    assert_eq!(
        read(&[b0, b0, b1, fin].concat()),
        Err(Error::Corrupt),
        "repeated"
    );
    assert_eq!(
        read(&flipped(40, three[40] ^ 1)),
        Err(Error::Corrupt),
        "data"
    );
    assert_eq!(read(&flipped(4, three[4] ^ 1)), Err(Error::Corrupt), "hash");
    assert_eq!(
        read(&flipped(115, 0x01)),
        Err(Error::Corrupt),
        "final hash not zero"
    );
    assert_eq!(
        read(&flipped(111, 0x07)),
        Err(Error::Corrupt),
        "final index"
    );
    // Index base 1 with correct hashes.
    let mut base1 = three.clone();
    for (at, i) in [(0usize, 1u32), (56, 2), (111, 3)] {
        base1[at..at + 4].copy_from_slice(&i.to_le_bytes());
    }
    assert_eq!(read(&base1), Err(Error::Corrupt), "index base 1");
}

#[test]
fn fmt_07_9_and_07_10_sizes_and_cuts() {
    let three = hex(THREE);
    for at in [36, 147] {
        let mut s = three.clone();
        s[at..at + 4].copy_from_slice(&[0xFF; 4]);
        assert_eq!(read(&s), Err(Error::Corrupt), "negative size at {at}");
    }
    let mut s = three.clone();
    s[39] = 0x01;
    assert_eq!(read(&s), Err(Error::Corrupt), "size beyond input");
    assert_eq!(
        read(&three[..111]),
        Err(Error::Corrupt),
        "missing final block"
    );
    for n in [2, 20, 38, 0] {
        assert_eq!(read(&three[..n]), Err(Error::Corrupt), "{n}");
    }
}

#[test]
fn fmt_07_11_bytes_after_the_final_block() {
    let three = hex(THREE);
    for tail in [
        vec![],
        vec![9; 9],
        [vec![9; 8], vec![1]].concat(),
        b"TRAILING".to_vec(),
        b"TRAILING\x01".to_vec(),
    ] {
        assert_eq!(read(&[three.clone(), tail].concat()).unwrap(), P31);
    }
}

#[test]
fn fmt_07_13_no_data_blocks() {
    assert_eq!(
        read(&hex(&format!("00000000{}", "00".repeat(36)))),
        Err(Error::Corrupt)
    );
}

#[test]
fn fmt_07_9_block_sizes_in_vaults() {
    for block in [1, 64, 2 << 20] {
        let d = DemoV3 {
            block,
            ..DemoV3::new()
        };
        assert_eq!(xml(open(&d.build(), "demo-pass")), DEMO_XML, "{block}");
    }
}

#[test]
fn fmt_07_11_trailing_plaintext_and_bad_padding_in_vaults() {
    let d = DemoV3 {
        gzip: false,
        ..DemoV3::new()
    };
    // Trailing plaintext after the final block, then a valid padding.
    let trailing = [d.plaintext(), b"TRAILING-PLAINTEXT-DATA".to_vec()].concat();
    assert_eq!(
        xml(open(&d.build_with_plaintext(&trailing), "demo-pass")),
        DEMO_XML
    );
    // Every padding byte 00, in a last cipher block shared with the final block.
    let mut p = d.plaintext();
    assert_ne!(p.len() % 16, 0);
    let pad = 16 - p.len() % 16;
    p.extend(vec![0; pad]);
    let mut c = larsal_crypto::cipher::encrypt(d.cipher, &d.key(), &d.iv, &p).unwrap();
    c.truncate(p.len());
    assert_eq!(
        xml(open(&d.build_with_ciphertext(&c), "demo-pass")),
        DEMO_XML
    );
}

#[test]
fn fmt_07_11_trailing_ciphertext() {
    let file = DemoV3::new().build();
    for tail in [vec![0x5A], vec![0; 16]] {
        let f = [file.clone(), tail].concat();
        assert_eq!(xml(open(&f, "demo-pass")), DEMO_XML);
        assert_eq!(kind(open(&f, "wrong-pass")), Error::WrongKey);
    }
}

#[test]
fn fmt_07_8_nothing_reaches_the_parser_early() {
    let d = DemoV3::new();
    let mut p = d.plaintext();
    let n = p.len();
    p[n - 30] ^= 1; // inside the final block's zero hash
    let _ = probe::take();
    assert_eq!(
        kind(open(&d.build_with_plaintext(&p), "demo-pass")),
        Error::Corrupt
    );
    assert_eq!(probe::take().inflate, 0);
}

// ---------------------------------------------------------------------------
// FMT-05, version 3

/// Demo header D3 of FMT-05 (222 bytes).
fn d3() -> Vec<u8> {
    let v = hex(concat!(
        "03 d9 a2 9a 67 fb 4b b5 01 00 03 00 02 10 00 31 c1 f2 e6 bf 71 43 50 be 58 05 21 6a fc 5a ff 03",
        "04 00 01 00 00 00 04 20 00 a8 49 74 eb c6 da 1f 91 8a f2 19 bc f9 2b 5a 71 c0 0e 97 e0 ac 5d f5",
        "6f 17 59 fc 81 6e b9 ab 32 05 20 00 13 86 6c af 70 f8 bd 8e bd 73 ad dc 36 8a e4 e0 4b 9a 1d 4f",
        "4a c7 ce 64 25 b5 08 ca bd 77 0f d7 06 08 00 80 c3 c9 01 00 00 00 00 07 10 00 63 1c 92 83 ec 7f",
        "b8 68 ca d1 e0 83 68 17 96 6e 08 20 00 e2 03 3d 85 3d 21 a2 bc c9 58 05 40 6b e2 b9 c4 14 f9 8c",
        "40 ee c6 9e b1 a4 33 6a 41 7f 3e 7a 71 09 20 00 80 57 51 54 9e aa cd f9 15 e2 ab 56 82 45 cf 1e",
        "e5 96 16 7e 84 62 b8 60 d5 85 58 1c 1e a1 12 16 0a 04 00 02 00 00 00 00 04 00 0d 0a 0d 0a"
    ));
    assert_eq!(v.len(), 222);
    v
}

#[test]
fn fmt_05_10_and_05_11_demo_version_3() {
    // T is taken from the card (30,000,000 rounds are not re-run here; the
    // AES-KDF itself is proven by FMT-04.11-a and FMT-17.9).
    let h = parse(&d3()).unwrap();
    let start = h.v3.as_ref().unwrap().start_bytes;
    assert_eq!(
        h.kdf,
        KdfParams::AesKdf {
            rounds: 30_000_000,
            seed: d3()[76..108].to_vec()
        }
    );
    let ct = hex("5137fd2c7af22daa60a5fd74d00d7fde9271db1f9ca82a281a8fc9beb29d9389");
    let t = SecretBytes::new(hex(
        "b8caf4f22b5e734cb76e43d433562910520bf7d3201cbf8b95457b6f2d1fc115",
    ));
    let k = cipher_key_v3(&h.master_seed, None, &t);
    assert_eq!(
        to_hex(k.expose()),
        "6a33983cef363ade35dfcb80bf2a5119265359afd53a9bf399a21762a934297b"
    );
    assert_eq!(cbc_whole(&k, &h.iv, &ct), start.to_vec());
    let tw = SecretBytes::new(hex(
        "5d25042eeb6e5a25e00bc23a5c2033e91f7a9119783fad652c2b5becb7d65bb5",
    ));
    let kw = cipher_key_v3(&h.master_seed, None, &tw);
    assert_eq!(
        to_hex(kw.expose()),
        "3b54593af5284f098bd0c2624fed509c3a78c37e5c9f3b7d4238a4470b570497"
    );
    assert_eq!(
        to_hex(&cbc_whole(&kw, &h.iv, &ct)),
        "d2e013b8ae66d798904bc82dd9041cdfd3ba3454cadf3580f66ae09f43022e4d"
    );
}

#[test]
fn fmt_05_11_version_3_key_field_damage() {
    let p = password_only();
    for at in [50, 125, 222] {
        let mut f = p.file.clone();
        f[at] ^= 0x01;
        assert_eq!(kind(open(&f, "demo-pass-1")), Error::WrongKey, "{at}");
    }
}

#[test]
fn fmt_05_13_version_3_last_byte_flipped() {
    // Shared last block: the walk fails. All-padding last block: opens.
    let d = DemoV3 {
        gzip: false,
        ..DemoV3::new()
    };
    assert_ne!(d.plaintext().len() % 16, 0);
    let mut f = d.build();
    *f.last_mut().unwrap() ^= 1;
    assert_eq!(kind(open(&f, "demo-pass")), Error::Corrupt);
    let mut aligned = d.clone();
    let mut n = 0;
    while !aligned.plaintext().len().is_multiple_of(16) {
        n += 1;
        aligned.xml = [DEMO_XML.to_vec(), vec![b' '; n]].concat();
    }
    let mut f = aligned.build();
    let want = xml(open(&f, "demo-pass"));
    *f.last_mut().unwrap() ^= 1;
    assert_eq!(xml(open(&f, "demo-pass")), want);
}

#[test]
fn fmt_05_13_version_3_short_file() {
    let p = password_only();
    let _ = probe::take();
    for pass in ["demo-pass-1", "wrong-pass"] {
        assert_eq!(kind(open(&p.file[..222 + 20], pass)), Error::Corrupt);
    }
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_05_13_step_5_walk() {
    let d = DemoV3 {
        gzip: false,
        ..DemoV3::new()
    };
    let mut p = d.plaintext();
    p[32 + 40] ^= 1; // a data byte of hashed block 0, its stored hash kept
    assert_eq!(
        kind(open(&d.build_with_plaintext(&p), "demo-pass")),
        Error::Corrupt
    );
}

#[test]
fn fmt_05_13_version_3_stream_cipher() {
    let d = DemoV3::new().with_cipher(Cipher::ChaCha20);
    let file = d.build();
    assert_ne!((file.len() - 222) % 16, 0, "no padding");
    assert_eq!(xml(open(&file, "demo-pass")), DEMO_XML);
    assert_eq!(kind(open(&file, "wrong-pass")), Error::WrongKey);
    assert_eq!(xml(open(&[file, vec![7]].concat(), "demo-pass")), DEMO_XML);
}

#[test]
fn fmt_05_12_header_hash_rules_through_open() {
    // password-only's own document, re-encrypted by the test builder around
    // a changed HeaderHash (plan (e)); the document reader checks it.
    let p = password_only();
    let text = String::from_utf8(p.xml.clone()).unwrap();
    let real = text
        .split("<HeaderHash>")
        .nth(1)
        .unwrap()
        .split("</HeaderHash>")
        .next()
        .unwrap()
        .to_owned();
    let d = DemoV3 {
        xml: Vec::new(),
        ..DemoV3::new()
    };
    let hash = larsal_crypto::hash::sha256(&[&d.header()]);
    let b64 = |b: &[u8]| larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, b);
    let pass = pw("demo-pass");
    let creds = larsal_format::keys::Credentials {
        password: Some(&pass),
        ..Default::default()
    };
    let try_with = |value: &str| {
        let doc = text.replace(
            &format!("<HeaderHash>{real}</HeaderHash>"),
            &format!("<HeaderHash>{value}</HeaderHash>"),
        );
        let file = DemoV3 {
            xml: doc.into_bytes(),
            ..d.clone()
        }
        .build();
        larsal_format::open(&file, &creds, &mut host(), &L, None).err()
    };
    assert_eq!(
        try_with(&b64(hash.expose())),
        None,
        "the right hash of this header"
    );
    assert_eq!(
        try_with(&b64(&hash.expose()[..31])),
        Some(Error::Corrupt),
        "31 bytes"
    );
    assert_eq!(try_with(""), None, "empty: no check");
    assert_eq!(try_with("-_"), None, "decodes to zero bytes: no check");
    let spaced = format!(" {}\n!", b64(hash.expose()));
    assert_eq!(try_with(&spaced), None, "lenient decoding");
    assert_eq!(
        try_with(&real),
        Some(Error::Corrupt),
        "the hash of another header"
    );
}

// ---------------------------------------------------------------------------
// FMT-02 version 3 rows on H3demo (example A), and FMT-17.4

/// H3demo of FMT-02 (222 bytes).
fn h3demo() -> Vec<u8> {
    let v = hex(concat!(
        "03 D9 A2 9A 67 FB 4B B5 01 00 03 00 02 10 00 31",
        "C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF 03",
        "04 00 01 00 00 00 04 20 00 72 3D 68 5D 06 C1 13",
        "84 89 A4 FA 52 AD D4 13 F9 86 91 76 3F 2B F4 E8",
        "06 F7 C1 DE B1 A8 7B C3 D8 05 20 00 AB BE 5B 4D",
        "57 5C F2 93 DC EF 6B 27 9C E5 A7 61 9D 0C AA A4",
        "40 9E 07 59 92 A8 BF A2 4E CD 7B 81 06 08 00 16",
        "07 C7 00 00 00 00 00 07 10 00 A1 A7 A0 14 32 FC",
        "C2 76 C6 BE EA 20 72 29 7F 4E 08 20 00 78 14 2C",
        "81 CF 1E FD 4D 88 2C 82 CB 57 3B AF DD 0A 69 3B",
        "4F B6 5C 50 61 4D 9D EF 17 FF 2D AD D5 09 20 00",
        "6D 54 64 8E E5 9D 00 67 7B 84 93 1B E8 A2 EF 43",
        "00 48 E3 FA 5B B0 D8 7A 6A CA EE 40 DE A5 EE 46",
        "0A 04 00 02 00 00 00 00 04 00 0D 0A 0D 0A"
    ));
    assert_eq!(v.len(), 222);
    v
}

// Field spans in H3demo (and Vector L3): 2 at 0x0C (19), 3 at 0x1F (7),
// 4 at 0x26 (35), 5 at 0x49 (35), 6 at 0x6C (11), 7 at 0x77 (19),
// 8 at 0x8A (35), 9 at 0xAD (35), 10 at 0xD0 (7), end at 0xD7.
const SPANS3: [(usize, usize); 8] = [
    (0x0C, 19),
    (0x1F, 7),
    (0x26, 35),
    (0x49, 35),
    (0x6C, 11),
    (0x77, 19),
    (0x8A, 35),
    (0xAD, 35),
];

#[test]
fn c02_c03_d49_fmt_02_2() {
    for version in ["01000300", "00000200"] {
        let v = splice(h3demo(), 8, 4, &hex(version));
        let h = parse(&v).unwrap();
        assert_eq!(h.len, 222);
        assert_eq!(
            (h.cipher, h.compression),
            (Cipher::Aes256Cbc, Compression::Gzip)
        );
        assert_eq!(to_hex(&h.master_seed[..2]), "723d");
        assert_eq!(to_hex(&h.master_seed[30..]), "c3d8");
        let KdfParams::AesKdf { rounds, seed } = &h.kdf else {
            panic!()
        };
        assert_eq!(
            (*rounds, to_hex(&seed[..2]), to_hex(&seed[30..])),
            (13_043_478, "abbe".into(), "7b81".into())
        );
        assert_eq!(
            (to_hex(&h.iv[..2]), to_hex(&h.iv[14..])),
            ("a1a7".into(), "7f4e".into())
        );
        let v3 = h.v3.unwrap();
        assert_eq!(
            (to_hex(&v3.stream_key[..2]), to_hex(&v3.stream_key[30..])),
            ("7814".into(), "add5".into())
        );
        assert_eq!(
            (to_hex(&v3.start_bytes[..2]), to_hex(&v3.start_bytes[30..])),
            ("6d54".into(), "ee46".into())
        );
    }
}

#[test]
fn c27_c41b_fmt_02_15_fields_11_and_12_skipped() {
    let one = splice(h3demo(), 0xD7, 0, &hex("0B 03 00 00 01 00"));
    assert_eq!(parse(&one).unwrap().len, 228);
    assert_eq!(
        parse(&splice(h3demo(), 0xD7, 0, &hex("0C 03 00 FF FF FF")))
            .unwrap()
            .len,
        228
    );
    let two = splice(one, 0xD7, 0, &hex("0B 03 00 00 01 00"));
    assert_eq!(parse(&two).unwrap().len, 234);
}

#[test]
fn c28_c29_c33_fmt_02_16_to_02_19_sizes() {
    let short = |at: usize| splice(splice(h3demo(), at + 1, 2, &[31, 0]), at + 3, 1, &[]);
    assert_eq!(parse(&short(0x49)).unwrap_err(), Error::Corrupt, "field 5");
    assert_eq!(parse(&short(0xAD)).unwrap_err(), Error::Corrupt, "field 9");
    let f6 = splice(h3demo(), 0x6C, 11, &hex("06 04 00 16 07 C7 00"));
    assert_eq!(
        parse(&f6).unwrap_err(),
        Error::Corrupt,
        "field 6 of 4 bytes"
    );
}

#[test]
fn c30_fmt_02_17_rounds() {
    let r = |v: &str| parse(&splice(h3demo(), 0x6F, 8, &hex(v)));
    assert_eq!(r("0000000000000000").unwrap_err(), Error::Unsupported);
    assert_eq!(r("FFFFFF7F00000000").unwrap_err(), Error::Unsupported);
    assert!(matches!(
        r("FEFFFF7F00000000").unwrap().kdf,
        KdfParams::AesKdf {
            rounds: 2_147_483_646,
            ..
        }
    ));
    assert_eq!(r("1607C70001000000").unwrap_err(), Error::Unsupported);
}

#[test]
fn c31_c32_t09_45_fmt_02_18_stream_key() {
    let five = splice(splice(h3demo(), 0x8B, 2, &[5, 0]), 0x8D + 5, 27, &[]);
    assert_eq!(parse(&five).unwrap().v3.unwrap().stream_key.len(), 5);
    let empty = splice(h3demo(), 0x8A, 35, &hex("08 00 00"));
    assert_eq!(parse(&empty).unwrap_err(), Error::Corrupt);
    assert_eq!(
        parse(&splice(h3demo(), 0x8A, 35, &[])).unwrap_err(),
        Error::Corrupt
    );
}

#[test]
fn c34_c35_c36_fmt_02_20_stream_id() {
    assert!(parse(&h3demo()).is_ok());
    assert!(
        parse(&splice(h3demo(), 0xD0, 7, &[])).is_ok(),
        "absent: Salsa20"
    );
    for v in ["03000000", "01000000", "04000000"] {
        assert_eq!(
            parse(&splice(h3demo(), 0xD3, 4, &hex(v))).unwrap_err(),
            Error::Unsupported,
            "{v}"
        );
    }
    assert_eq!(
        parse(&splice(h3demo(), 0xD0, 7, &hex("0A 02 00 02 00"))).unwrap_err(),
        Error::Corrupt
    );
}

#[test]
fn c43_c45_fmt_02_23_required_and_truncation() {
    for (at, n) in SPANS3 {
        assert_eq!(
            parse(&splice(h3demo(), at, n, &[])).unwrap_err(),
            Error::Corrupt,
            "{at:#x}"
        );
    }
    assert_eq!(parse(&h3demo()[..14]).unwrap_err(), Error::Corrupt);
}

#[test]
fn c50_fmt_02_28_cipher_in_version_3() {
    let chacha = splice(h3demo(), 0x0F, 16, &hex("D6038A2B8B6F4CB5A524339A31DBB59A"));
    let iv12 = splice(
        chacha.clone(),
        0x77,
        19,
        &[hex("07 0C 00"), vec![0x22; 12]].concat(),
    );
    assert_eq!(parse(&iv12).unwrap().cipher, Cipher::ChaCha20);
    assert_eq!(
        parse(&chacha).unwrap_err(),
        Error::Unsupported,
        "16-byte nonce"
    );
}

#[test]
fn fmt_17_4_skipped_fields() {
    for f in [
        "01 05 00 61 62 63 64 65",
        "0B 03 00 01 02 03",
        "63 02 00 01 02",
    ] {
        assert!(parse(&splice(l3(), 0xD7, 0, &hex(f))).is_ok(), "{f}");
    }
}

#[test]
fn fmt_07_9_large_block_in_a_vault() {
    let big = [
        b"<?xml version=\"1.0\"?><D>".as_slice(),
        &vec![b'a'; 1_517_261 - 30],
        b"</D>",
    ]
    .concat();
    let d = DemoV3 {
        gzip: false,
        xml: big.clone(),
        block: 2 << 20,
        ..DemoV3::new()
    };
    assert_eq!(xml(open(&d.build(), "demo-pass")), big);
}

// ---------------------------------------------------------------------------
// E3 fix pass

#[test]
fn fmt_05_13_step_4_wrong_key_decrypts_only_the_first_blocks() {
    let d = DemoV3 {
        xml: vec![b'x'; 10_000],
        gzip: false,
        ..DemoV3::new()
    };
    let file = d.build();
    let _ = probe::take();
    assert_eq!(kind(open(&file, "wrong-pass")), Error::WrongKey);
    let c = probe::take();
    assert!(
        c.decrypted <= 48,
        "decrypted {} bytes before the start bytes check",
        c.decrypted
    );
    assert_eq!(xml(open(&file, "demo-pass")).len(), 10_000);
    for c in [Cipher::Twofish256Cbc, Cipher::ChaCha20] {
        let f = DemoV3 {
            gzip: false,
            ..d.clone().with_cipher(c)
        }
        .build();
        let _ = probe::take();
        assert_eq!(kind(open(&f, "wrong-pass")), Error::WrongKey);
        assert!(probe::take().decrypted <= 48);
    }
}

#[test]
fn fmt_08_12_version_3_document_and_total_limits() {
    let d = DemoV3 {
        xml: vec![b'd'; 1_000],
        ..DemoV3::new()
    };
    for gzip in [true, false] {
        let file = DemoV3 { gzip, ..d.clone() }.build();
        let doc = |n: usize| Limits { document: n, ..L };
        assert!(open_lim(&file, "demo-pass", &doc(1_000)).is_ok());
        assert_eq!(
            kind(open_lim(&file, "demo-pass", &doc(999))),
            Error::TooLarge(Limit::Document),
            "document, gzip {gzip}"
        );
        let total = |n: usize| Limits { total: n, ..L };
        assert!(open_lim(&file, "demo-pass", &total(1_000)).is_ok());
        assert_eq!(
            kind(open_lim(&file, "demo-pass", &total(999))),
            Error::TooLarge(Limit::Total),
            "total, gzip {gzip}"
        );
    }
}
