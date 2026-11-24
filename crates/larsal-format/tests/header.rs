//! FMT-01 (detection, frame), FMT-02 (outer header) and FMT-03 (KDF map)
//! test rows that need no key. One test per card row, named after it.

mod format_common;

use format_common::*;
use larsal_crypto::cipher::Cipher;
use larsal_crypto::kdf::{Argon2Type, KdfParams};
use larsal_format::Error;
use larsal_format::detect::{Detected, check, detect, read_vault};
use larsal_format::header::{Compression, Header, read_header};
use larsal_format::kdf_params::{parse_kdf, parse_map};
use larsal_format::limits::{Limit, Limits};
use larsal_format::payload::probe;

const L: Limits = Limits::DEFAULT;

/// H4min of FMT-02 (207 bytes).
fn h4min() -> Vec<u8> {
    let v = hex(concat!(
        "03 D9 A2 9A 67 FB 4B B5 01 00 04 00 02 10 00 00",
        "00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A",
        "FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 11",
        "11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11",
        "11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 07",
        "10 00 00 00 22 22 22 22 22 22 22 22 22 22 22 22",
        "22 22 22 22 0B 5D 00 00 00 00 01 42 05 00 00 00",
        "24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44",
        "60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08",
        "00 00 00 40 42 0F 00 00 00 00 00 42 01 00 00 00",
        "53 20 00 00 00 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B",
        "4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B",
        "4B 4B 4B 4B 4B 00 00 04 00 00 00 0D 0A 0D 0A"
    ));
    assert_eq!(v.len(), 207);
    v
}

/// H4demo of FMT-02 example B (207 bytes).
fn h4demo() -> Vec<u8> {
    let v = hex(concat!(
        "03 D9 A2 9A 67 FB 4B B5 00 00 04 00 02 10 00 00",
        "00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A",
        "FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 B8",
        "D0 5E 01 14 D0 B1 5D AD 0F B6 7D 24 0C C7 A5 2B",
        "57 97 F5 FF F6 A2 4D A4 33 5D E5 72 C5 7F 99 07",
        "10 00 00 00 60 6D 84 40 AA C3 95 17 B6 3E AB 8F",
        "D3 1E 76 E2 0B 5D 00 00 00 00 01 42 05 00 00 00",
        "24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44",
        "60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08",
        "00 00 00 C0 E1 E4 00 00 00 00 00 42 01 00 00 00",
        "53 20 00 00 00 B4 ED E5 64 F2 76 AF 60 7D 75 0C",
        "E8 84 D0 18 B9 0E 1C 4F 3C 9E 7C 9B A1 8B 30 C6",
        "AC 1D 93 17 41 00 00 04 00 00 00 0D 0A 0D 0A"
    ));
    assert_eq!(v.len(), 207);
    v
}

fn splice(mut v: Vec<u8>, at: usize, remove: usize, insert: &[u8]) -> Vec<u8> {
    v.splice(at..at + remove, insert.iter().copied());
    v
}

fn parse(v: &[u8]) -> Result<Header, Error> {
    read_header(v, &L)
}

fn err(v: &[u8]) -> Error {
    parse(v).unwrap_err()
}

// Field spans in H4min: 2 at 0x0C (21 bytes), 3 at 0x21 (9), 4 at 0x2A (37),
// 7 at 0x4F (21), 11 at 0x64 (98), end at 0xC6 (9).
const F2: (usize, usize) = (0x0C, 21);
const F3: (usize, usize) = (0x21, 9);
const F4: (usize, usize) = (0x2A, 37);
const F7: (usize, usize) = (0x4F, 21);
const F11: (usize, usize) = (0x64, 98);

fn without(v: Vec<u8>, f: (usize, usize)) -> Vec<u8> {
    splice(v, f.0, f.1, &[])
}

// ---------------------------------------------------------------------------
// FMT-01

#[test]
fn fmt_01_1_little_endian() {
    let mut v = h4min();
    v[8..12].copy_from_slice(&[0x01, 0x00, 0x04, 0x00]);
    assert_eq!(detect(&v), Detected::Vault { major: 4, minor: 1 });
}

#[test]
fn fmt_01_2_too_short() {
    for v in [&[][..], &hex("03D9A29A67FB4BB5"), &[0x03; 11]] {
        assert_eq!(detect(v), Detected::TooShort);
        assert_eq!(check(v), Err(Error::NotAVault));
    }
}

#[test]
fn fmt_01_3_vault() {
    assert_eq!(
        detect(&hex("03D9A29A67FB4BB500000400")),
        Detected::Vault { major: 4, minor: 0 }
    );
    assert_eq!(
        detect(&hex("03D9A29A67FB4BB501000300")),
        Detected::Vault { major: 3, minor: 1 }
    );
}

#[test]
fn fmt_01_4_old_format() {
    let v = hex("03D9A29A65FB4BB50300000002000300");
    assert_eq!(detect(&v), Detected::OldFormat);
    assert_eq!(check(&v), Err(Error::OldFormat));
}

#[test]
fn fmt_01_5_not_a_vault() {
    assert_eq!(
        detect(&hex("03D9A29A66FB4BB50000030000000000")),
        Detected::NotAVault
    );
    assert_eq!(detect(b"hello world, not a vault"), Detected::NotAVault);
    assert_eq!(check(b"hello world, not a vault"), Err(Error::NotAVault));
}

#[test]
fn fmt_01_6_minor_and_major() {
    for (b, major, minor) in [
        ("02000400", 4, 2),
        ("FFFF0300", 3, 65535),
        ("04000200", 2, 4),
    ] {
        let v = [hex("03D9A29A67FB4BB5"), hex(b)].concat();
        assert_eq!(detect(&v), Detected::Vault { major, minor });
    }
}

#[test]
fn fmt_01_7_accepted_and_rejected() {
    let sig = hex("03D9A29A67FB4BB5");
    for (major, minor) in [
        (2u16, 0u16),
        (2, 1),
        (3, 0),
        (3, 1),
        (3, 2),
        (3, 65535),
        (4, 0),
        (4, 1),
        (4, 2),
        (4, 65535),
    ] {
        let v = [
            sig.clone(),
            [minor.to_le_bytes(), u16::to_le_bytes(major)].concat(),
        ]
        .concat();
        assert_eq!(check(&v), Ok((major, minor)));
    }
    for b in ["00000000", "00000100", "FFFF0100", "00000500", "0000FFFF"] {
        assert_eq!(
            check(&[sig.clone(), hex(b)].concat()),
            Err(Error::Unsupported),
            "{b}"
        );
    }
}

#[test]
fn fmt_01_8_dispatch() {
    // Version 4 minors all go to the version 4 reader.
    for minor in [0u16, 1, 65535] {
        let mut v = h4min();
        v[8..10].copy_from_slice(&minor.to_le_bytes());
        let h = parse(&v).unwrap();
        assert_eq!((h.minor, h.v3.is_none()), (minor, true));
    }
    // Versions 2.x and 3.x go to the version 3 reader: H4min read with
    // 2-byte lengths misreads field 2 as an unknown cipher id. FMT-02.7 and
    // FMT-02.30 make that Unsupported; FMT-01's edge table says Corrupt
    // (reported to the lead).
    for (major, minor) in [(2u16, 0u16), (3, 0), (3, 1), (3, 65535)] {
        let mut v = h4min();
        v[8..10].copy_from_slice(&minor.to_le_bytes());
        v[10..12].copy_from_slice(&major.to_le_bytes());
        assert_eq!(err(&v), Error::Unsupported);
    }
}

#[test]
fn fmt_01_9_same_layout() {
    let l4 = parse(&vector_l4()).unwrap();
    let rich = parse(&testdata("rich-v4.larsalvault")).unwrap();
    assert_eq!((l4.len, rich.len), (207, 207));
    assert_eq!((l4.major, l4.minor, rich.major, rich.minor), (4, 0, 4, 1));
    // Same field ids, sizes and order: compare the frames byte for byte
    // outside the random values and the rounds.
    let (a, b) = (vector_l4(), testdata("rich-v4.larsalvault"));
    for (lo, hi) in [
        (0x0C, 0x2F),
        (0x4F, 0x54),
        (0x64, 0x93),
        (0x9B, 0xA5),
        (0xC5, 0xCF),
    ] {
        assert_eq!(a[lo..hi], b[lo..hi], "{lo:#x}..{hi:#x}");
    }
}

#[test]
fn fmt_01_12_version_4_frame() {
    let v = vector_l4();
    let h = parse(&v).unwrap();
    assert_eq!(h.len, 207);
    assert_eq!(h.cipher, Cipher::Aes256Cbc);
    assert_eq!(h.compression, Compression::Gzip);
    assert_eq!(h.iv.len(), 16);
    assert_eq!(
        h.kdf,
        KdfParams::AesKdf {
            rounds: 1_000_000,
            seed: v[0xA5..0xC5].to_vec()
        }
    );
    assert_eq!(
        to_hex(&v[207..239]),
        "16f1f6204baef1ac71143bf94f3c719ebec9b5ecfd524df084ec355a403b6e64"
    );
    assert_eq!(
        larsal_crypto::hash::sha256(&[&v[..207]]).expose(),
        &v[207..239]
    );
}

#[test]
fn fmt_01_14_end_field() {
    let v = splice(h4min(), 0xC6, 9, &hex("0000000000"));
    assert_eq!(parse(&v).unwrap().len, 203);
    let v = [h4min(), vec![0x05]].concat();
    assert_eq!(
        parse(&v).unwrap().len,
        207,
        "the 05 after the end field is not read"
    );
}

#[test]
fn fmt_01_15_required_in_app() {
    // Vector L4 with field 3 (9 bytes at 0x21), then field 11 (98 at 0x64), removed.
    assert_eq!(err(&splice(vector_l4(), 0x21, 9, &[])), Error::Corrupt);
    assert_eq!(err(&splice(vector_l4(), 0x64, 98, &[])), Error::Corrupt);
}

#[test]
fn fmt_01_22_bounded_length() {
    let v = splice(h4min(), 0x0D, 4, &[0xFF; 4]);
    assert_eq!(err(&v), Error::TooLarge(Limit::Header));
    assert_eq!(err(&vector_l4()[..25]), Error::Corrupt);
}

#[test]
fn fmt_01_31_detection_first() {
    let lim = Limits {
        total_file: 4096,
        ..L
    };
    let text = vec![b'a'; 4097];
    assert_eq!(read_vault(&text[..], &lim).map(|v| v.len()), Ok(4097));
    assert_eq!(open_lim(&text, "x", &lim).unwrap_err(), Error::NotAVault);
    let v5 = [hex("03D9A29A67FB4BB500000500"), vec![0; 4085]].concat();
    assert!(read_vault(&v5[..], &lim).is_ok());
    assert_eq!(open_lim(&v5, "x", &lim).unwrap_err(), Error::Unsupported);
}

/// A source of a valid 12-byte prefix then endless zeros, counting what it gave.
struct Endless {
    given: usize,
}

impl std::io::Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let head = hex("03D9A29A67FB4BB500000400");
        for b in buf.iter_mut() {
            *b = head.get(self.given).copied().unwrap_or(0);
            self.given += 1;
        }
        Ok(buf.len())
    }
}

#[test]
fn fmt_01_31_no_reservation() {
    let lim = Limits {
        total_file: 4096,
        ..L
    };
    let mut src = Endless { given: 0 };
    assert_eq!(
        read_vault(&mut src, &lim),
        Err(Error::TooLarge(Limit::TotalFile))
    );
    assert!(
        src.given <= 4097,
        "read stops right after the limit: {}",
        src.given
    );
    let file = testdata("rich-v4.larsalvault");
    assert_eq!(read_vault(&file[..], &L).unwrap(), file);
}

// ---------------------------------------------------------------------------
// FMT-02

#[test]
fn c01_fmt_02_1() {
    let h = parse(&h4min()).unwrap();
    assert_eq!((h.major, h.minor, h.len), (4, 1, 207));
    assert_eq!(h.cipher, Cipher::Aes256Cbc);
    assert_eq!(h.compression, Compression::Gzip);
    assert_eq!(h.master_seed, [0x11; 32]);
    assert_eq!(h.iv, vec![0x22; 16]);
    assert_eq!(
        h.kdf,
        KdfParams::AesKdf {
            rounds: 1_000_000,
            seed: vec![0x4B; 32]
        }
    );
    assert!(h.public_custom_data.is_empty());
}

#[test]
fn c04_c05_fmt_02_3() {
    assert_eq!(
        parse(&splice(h4min(), 0xC6, 9, &hex("0000000000")))
            .unwrap()
            .len,
        203
    );
    assert_eq!(
        parse(&splice(h4min(), 0xC6, 9, &hex("0003000000616263")))
            .unwrap()
            .len,
        206
    );
}

#[test]
fn c06_fmt_02_4() {
    let v = splice(h4min(), 0xC6, 0, &hex("0D0500000068656C6C6F"));
    assert_eq!(parse(&v).unwrap().len, 217);
}

#[test]
fn c07_fmt_02_5() {
    let h = h4min();
    let order = [F11, F7, F4, F3, F2];
    let mut v = h[..12].to_vec();
    for (at, n) in order {
        v.extend_from_slice(&h[at..at + n]);
    }
    v.extend_from_slice(&h[0xC6..]);
    let (a, b) = (parse(&v).unwrap(), parse(&h).unwrap());
    assert_eq!(
        (a.cipher, a.compression, a.master_seed, a.iv, a.kdf),
        (b.cipher, b.compression, b.master_seed, b.iv, b.kdf)
    );
}

#[test]
fn c10_fmt_02_7() {
    for (id, c) in [
        (AES256_ID_HEX, Cipher::Aes256Cbc),
        (TWOFISH_HEX, Cipher::Twofish256Cbc),
        (CHACHA_HEX, Cipher::ChaCha20),
    ] {
        let mut v = splice(h4min(), 0x11, 16, &hex(id));
        if c == Cipher::ChaCha20 {
            v = splice(v, F7.0, F7.1, &field(7, &[0x22; 12]));
        }
        assert_eq!(parse(&v).unwrap().cipher, c);
    }
}

const AES256_ID_HEX: &str = "31C1F2E6BF714350BE5805216AFC5AFF";
const TWOFISH_HEX: &str = "AD68F29F576F4BB9A36AD47AF965346C";
const CHACHA_HEX: &str = "D6038A2B8B6F4CB5A524339A31DBB59A";

#[test]
fn c11_c13_fmt_02_7_unknown_cipher() {
    for id in [
        "000102030405060708090A0B0C0D0E0F",
        "00000000000000000000000000000000",
        "61AB05A1946441C38D743A563DF8DD35",
    ] {
        assert_eq!(
            err(&splice(h4min(), 0x11, 16, &hex(id))),
            Error::Unsupported,
            "{id}"
        );
    }
}

#[test]
fn c12_fmt_02_7() {
    let v = splice(h4min(), F2.0, F2.1, &field(2, &hex(AES256_ID_HEX)[..15]));
    assert_eq!(err(&v), Error::Corrupt);
}

#[test]
fn c14_c15_fmt_02_9() {
    let set = |d: &str| splice(h4min(), F3.0, F3.1, &field(3, &hex(d)));
    assert_eq!(
        parse(&set("00000000")).unwrap().compression,
        Compression::None
    );
    assert_eq!(err(&set("02000000")), Error::Unsupported);
    assert_eq!(err(&set("FFFFFFFF")), Error::Unsupported);
    assert_eq!(err(&set("010000")), Error::Corrupt);
}

#[test]
fn c16_fmt_02_10() {
    for n in [31, 33] {
        assert_eq!(
            err(&splice(h4min(), F4.0, F4.1, &field(4, &vec![0x11; n]))),
            Error::Corrupt
        );
    }
}

#[test]
fn c17_c18_c19_fmt_02_11() {
    let iv = |v: Vec<u8>, n: usize| splice(v, F7.0, F7.1, &field(7, &vec![0x22; n]));
    assert_eq!(err(&iv(h4min(), 12)), Error::Unsupported);
    let chacha = splice(h4min(), 0x11, 16, &hex(CHACHA_HEX));
    for n in [8, 16, 24, 32] {
        assert_eq!(err(&iv(chacha.clone(), n)), Error::Unsupported, "{n}");
    }
    assert_eq!(parse(&iv(chacha, 12)).unwrap().iv.len(), 12);
    assert_eq!(err(&iv(h4min(), 0)), Error::Corrupt);
}

#[test]
fn c20_fmt_02_11() {
    let h = splice(h4min(), 0x11, 16, &hex(CHACHA_HEX));
    let mut v = h[..12].to_vec();
    v.extend(field(7, &[0x22; 12]));
    v.extend_from_slice(&h[F2.0..F7.0]);
    v.extend_from_slice(&h[F11.0..]);
    assert_eq!(parse(&v).unwrap().cipher, Cipher::ChaCha20);
}

#[test]
fn c21_fmt_02_12() {
    assert_eq!(
        err(&splice(h4min(), 0x69, 2, &[0x00, 0x02])),
        Error::Unsupported
    );
}

/// M3 of FMT-03 (70 bytes).
fn m3() -> Vec<u8> {
    let v = hex(concat!(
        "00 01",
        "0C 03 00 00 00 43 44 31 04 00 00 00 7B 00 00 00",
        "08 03 00 00 00 43 44 32 01 00 00 00 01",
        "18 03 00 00 00 43 44 33 09 00 00 00 61 62 63 C3 A4 C3 B6 C3 BC",
        "42 03 00 00 00 43 44 34 05 00 00 00 AB AB A1 23 FF",
        "00"
    ));
    assert_eq!(v.len(), 70);
    v
}

#[test]
fn c22_fmt_02_13() {
    let v = splice(h4min(), 0xC6, 0, &field(12, &m3()));
    let h = parse(&v).unwrap();
    assert_eq!(h.public_custom_data.len(), 4);
    assert_eq!(h.public_custom_data[2].value, hex("616263C3A4C3B6C3BC"));
}

#[test]
fn c23_c24_c25_fmt_02_13() {
    let ins = |d: &str| splice(h4min(), 0xC6, 0, &hex(d));
    assert_eq!(
        err(&ins("0C0F00000000010301000000580200000001 0000")),
        Error::Corrupt
    );
    assert_eq!(err(&ins("0C00000000")), Error::Corrupt);
    assert!(
        parse(&ins("0C03000000000100"))
            .unwrap()
            .public_custom_data
            .is_empty()
    );
}

#[test]
fn c26_fmt_02_14() {
    for f in [
        "0520000000".to_owned() + &"00".repeat(32),
        "060800000000000000000000 00".into(),
        "0820000000".to_owned() + &"00".repeat(32),
        "0920000000".to_owned() + &"00".repeat(32),
        "0A0400000002000000".into(),
    ] {
        assert_eq!(
            err(&splice(h4min(), 0xC6, 0, &hex(&f))),
            Error::Corrupt,
            "{f}"
        );
    }
}

#[test]
fn c37_c38_fmt_02_21() {
    assert!(
        parse(&splice(
            h4min(),
            0x0C,
            0,
            &hex("010C00000064656D6F20636F6D6D656E74")
        ))
        .is_ok()
    );
    assert!(parse(&splice(h4min(), 0x21, 0, &hex("FF03000000000000"))).is_ok());
}

#[test]
fn c39_c40_c41_fmt_02_22() {
    let v = splice(h4min(), 0x0C, 0, &hex(&format!("0210000000{TWOFISH_HEX}")));
    assert_eq!(err(&v), Error::Corrupt);
    let f11 = h4min()[F11.0..F11.0 + F11.1].to_vec();
    assert_eq!(err(&splice(h4min(), 0xC6, 0, &f11)), Error::Corrupt);
    let f12 = hex("0C03000000000100");
    assert_eq!(
        err(&splice(h4min(), 0xC6, 0, &[f12.clone(), f12].concat())),
        Error::Corrupt
    );
    assert!(parse(&splice(h4min(), 0xC6, 0, &hex("0D01000000410D0100000041"))).is_ok());
}

#[test]
fn c42_fmt_02_23() {
    for f in [F2, F3, F4, F7, F11] {
        assert_eq!(err(&without(h4min(), f)), Error::Corrupt, "{f:?}");
    }
}

#[test]
fn c44_fmt_02_24() {
    let h = h4min();
    for v in [&h[..12], &h[..14], &h[..20], &h[..198]] {
        assert_eq!(err(v), Error::Corrupt);
    }
}

#[test]
fn c46_fmt_02_25() {
    let v = [h4min()[..0xC6].to_vec(), hex("0DFFFFFFFF"), vec![0x78; 100]].concat();
    assert_eq!(err(&v), Error::TooLarge(Limit::Header));
}

#[test]
fn c47_fmt_02_25() {
    let at_limit = splice(h4min(), 0xC6, 0, &field(0x0D, &vec![0; 1_048_364]));
    assert_eq!(parse(&at_limit).unwrap().len, 1_048_576);
    let over = splice(h4min(), 0xC6, 0, &field(0x0D, &vec![0; 1_048_365]));
    assert_eq!(err(&over), Error::TooLarge(Limit::Header));
}

#[test]
fn c48_fmt_02_26() {
    let mut d = Demo::new();
    d.gzip = false;
    let file = splice(d.build(), F3.0 + 5, 4, &hex("02000000"));
    let _ = probe::take();
    assert_eq!(open(&file, "demo-pass").unwrap_err(), Error::Unsupported);
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn c49_fmt_02_27() {
    let h = parse(&h4demo()).unwrap();
    assert_eq!(
        (h.cipher, h.compression, h.len),
        (Cipher::Aes256Cbc, Compression::Gzip, 207)
    );
    let KdfParams::AesKdf { rounds, seed } = h.kdf else {
        panic!()
    };
    assert_eq!(rounds, 15_000_000);
    assert_eq!(
        to_hex(&seed),
        "b4ede564f276af607d750ce884d018b90e1c4f3c9e7c9ba18b30c6ac1d931741"
    );
}

#[test]
fn c52_fmt_02_30() {
    let bad_uuid = splice(h4min(), 0x79, 16, &hex("000102030405060708090A0B0C0D0E0F"));
    let short3 = hex("0303000000010000");
    // Field 11 comes before the broken field 3: Unsupported.
    let a = splice(splice(bad_uuid.clone(), 0xC6, 0, &short3), F3.0, F3.1, &[]);
    assert_eq!(a.len(), 206);
    assert_eq!(err(&a), Error::Unsupported);
    // The broken field 3 in its place comes first: Corrupt.
    let b = splice(bad_uuid, F3.0, F3.1, &short3);
    assert_eq!(b.len(), 206);
    assert_eq!(err(&b), Error::Corrupt);
}

#[test]
fn c53_fmt_02_30() {
    let v = splice(
        without(h4min(), F4),
        F7.0 - F4.1,
        F7.1,
        &field(7, &[0x22; 12]),
    );
    assert_eq!(v.len(), 166);
    assert_eq!(err(&v), Error::Corrupt);
}

#[test]
fn c54_fmt_02_30() {
    assert_eq!(
        err(&splice(h4min(), 0xC6, 0, &hex("030400000002000000"))),
        Error::Corrupt
    );
}

#[test]
fn c55_fmt_02_30() {
    let v2 = splice(h4min(), 0x26, 4, &hex("02000000"));
    assert_eq!(err(&v2[..48]), Error::Unsupported);
    assert_eq!(err(&h4min()[..48]), Error::Corrupt);
}

#[test]
fn c56_fmt_02_30() {
    let v = splice(h4min(), 0x26, 4, &hex("02000000"));
    let v = splice(v, 0x0C, 0, &[hex("0DFFFFFFFF"), vec![0x78; 100]].concat());
    assert_eq!(err(&v), Error::TooLarge(Limit::Header));
}

#[test]
fn c57_fmt_02_27() {
    assert_eq!(err(&without(h4min(), F7)), Error::Corrupt);
}

// ---------------------------------------------------------------------------
// FMT-03

fn m1() -> Vec<u8> {
    let salt: Vec<u8> = (0u8..32).collect();
    argon2_map(larsal_crypto::kdf::ARGON2ID_ID, 2, 64 << 20, 4, &salt, 0x13)
}

fn m2() -> Vec<u8> {
    aes_kdf_map(1_000_000, &[0x4B; 32])
}

fn kdf_err(m: &[u8]) -> Error {
    parse_kdf(m).unwrap_err()
}

#[test]
fn m1_m2_match_the_card_bytes() {
    assert_eq!(m1().len(), 139);
    assert_eq!(
        &m1()[..32],
        &hex("0001420500000024555549441000 00009E298B1956DB4773B23DFC3EC6F0A1E6")[..]
    );
    assert_eq!(m2(), h4min()[0x69..0xC6].to_vec());
}

#[test]
fn d01_fmt_03_1_fmt_03_12() {
    assert_eq!(
        parse_kdf(&m1()).unwrap(),
        KdfParams::Argon2 {
            kind: Argon2Type::Id,
            version: 0x13,
            iterations: 2,
            memory_kib: 65_536,
            lanes: 4,
            salt: (0u8..32).collect()
        }
    );
}

#[test]
fn d02_fmt_03_16() {
    assert_eq!(
        parse_kdf(&m2()).unwrap(),
        KdfParams::AesKdf {
            rounds: 1_000_000,
            seed: vec![0x4B; 32]
        }
    );
}

#[test]
fn d03_fmt_03_1() {
    let salt = hex("640168F0F1843BCF2F8E77DC73EFBB6C1E05ACAD54C9B9C347438BD5B0FCFB47");
    let m = argon2_map(larsal_crypto::kdf::ARGON2D_ID, 2, 1 << 20, 2, &salt, 0x13);
    assert_eq!(m.len(), 139);
    assert_eq!(
        parse_kdf(&m).unwrap(),
        KdfParams::Argon2 {
            kind: Argon2Type::D,
            version: 0x13,
            iterations: 2,
            memory_kib: 1024,
            lanes: 2,
            salt
        }
    );
}

#[test]
fn d04_fmt_03_11() {
    let KdfParams::AesKdf { rounds, .. } = parse_kdf(&h4demo()[0x69..0xC6]).unwrap() else {
        panic!()
    };
    assert_eq!(rounds, 15_000_000);
}

#[test]
fn d07_d08_d09_fmt_03_2() {
    for v in ["0000", "0100", "FF01"] {
        assert_eq!(
            parse_kdf(&splice(m2(), 0, 2, &hex(v))).unwrap(),
            parse_kdf(&m2()).unwrap(),
            "{v}"
        );
    }
    for v in ["0002", "FFFF"] {
        assert_eq!(kdf_err(&splice(m2(), 0, 2, &hex(v))), Error::Unsupported);
    }
    assert_eq!(kdf_err(&[0x00]), Error::Corrupt);
}

#[test]
fn d10_fmt_03_8_parse() {
    let e = parse_map(&m3()).unwrap();
    assert_eq!(e.len(), 4);
    assert_eq!(
        (e[0].kind, e[0].name.as_slice(), e[0].value.as_slice()),
        (0x0C, &b"CD1"[..], &123i32.to_le_bytes()[..])
    );
    assert_eq!((e[1].kind, e[1].value.as_slice()), (0x08, &[1][..]));
    assert_eq!(e[3].value, hex("ABABA123FF"));
}

#[test]
fn d11_d12_d12b_fmt_03_3() {
    assert_eq!(
        kdf_err(&splice(m2(), 33, 4, &hex("FFFF0000"))),
        Error::Corrupt
    );
    assert_eq!(
        kdf_err(&splice(m2(), 56, 4, &hex("22000000"))),
        Error::Corrupt
    );
    assert_eq!(
        kdf_err(&splice(m2(), 56, 4, &hex("21000000"))),
        Error::Corrupt
    );
}

#[test]
fn d13_d14_fmt_03_4() {
    for ins in [
        "08010000004202000000 0100",
        "0C0100000058080000000000000000000000",
        "040100000058030000 00000000",
        "05010000005804000000 00000000",
        "0D010000005809000000000000000000000000",
    ] {
        assert_eq!(
            kdf_err(&splice(m2(), 92, 0, &hex(ins))),
            Error::Corrupt,
            "{ins}"
        );
    }
}

#[test]
fn d15_fmt_03_8() {
    assert!(parse_kdf(&splice(m2(), 92, 0, &hex("0801000000420100000002"))).is_ok());
}

#[test]
fn d16_fmt_03_5() {
    assert_eq!(
        kdf_err(&splice(m2(), 92, 0, &hex("030100000058020000000100"))),
        Error::Corrupt
    );
    assert_eq!(
        kdf_err(&splice(m2(), 92, 0, &hex("FF010000005800000000"))),
        Error::Corrupt
    );
}

#[test]
fn d17_d18_fmt_03_6() {
    assert_eq!(kdf_err(&m2()[..92]), Error::Corrupt);
    assert_eq!(
        parse_kdf(&[m2(), b"GARBAGE".to_vec()].concat()).unwrap(),
        parse_kdf(&m2()).unwrap()
    );
}

#[test]
fn d19_d20_fmt_03_7() {
    assert!(parse_kdf(&splice(m2(), 92, 0, &hex("040000000004000000 01000000"))).is_ok());
    let e = parse_map(&hex("0001040000000004000000010000 0000")).unwrap();
    assert_eq!((e.len(), e[0].name.len()), (1, 0));
}

#[test]
fn d21_fmt_03_9() {
    let dup = hex("050100000049080000006300000000000000");
    assert_eq!(kdf_err(&splice(m1(), 2, 0, &dup)), Error::Corrupt);
    assert_eq!(kdf_err(&splice(m1(), 138, 0, &dup)), Error::Corrupt);
}

#[test]
fn d22_d23_fmt_03_10() {
    assert_eq!(kdf_err(&hex("000100")), Error::Unsupported);
    assert!(parse_map(&hex("000100")).unwrap().is_empty());
}

#[test]
fn d24_d25_d26_fmt_03_11() {
    assert_eq!(
        kdf_err(&splice(
            m1(),
            16,
            16,
            &hex("000102030405060708090A0B0C0D0E0F")
        )),
        Error::Unsupported
    );
    assert_eq!(
        kdf_err(&splice(splice(m1(), 12, 4, &hex("0F000000")), 16, 1, &[])),
        Error::Unsupported
    );
    let newer = splice(m2(), 16, 16, &hex("7C02BB8279A74AC0927D114A00648238"));
    assert_eq!(parse_kdf(&newer).unwrap(), parse_kdf(&m2()).unwrap());
}

#[test]
fn d27_fmt_03_12_missing_keys() {
    // Entry spans in M1: $UUID 2..32, I 32..50, M 50..68, P 68..82, S 82..124, V 124..138.
    for (at, n) in [(2, 30), (82, 42), (124, 14), (68, 14), (50, 18), (32, 18)] {
        assert_eq!(
            kdf_err(&splice(m1(), at, n, &[])),
            Error::Unsupported,
            "{at}"
        );
    }
}

#[test]
fn d28_fmt_03_12_lanes() {
    assert_eq!(
        kdf_err(&splice(m1(), 78, 4, &hex("00000000"))),
        Error::Unsupported
    );
    assert_eq!(
        kdf_err(&splice(m1(), 78, 4, &hex("00000001"))),
        Error::Unsupported
    );
    // 2^24 - 1 lanes pass this card only with enough memory for m >= 8 x p (CRY-02.10).
    let big = argon2_map(
        larsal_crypto::kdf::ARGON2ID_ID,
        2,
        (8 * 16_777_215) << 10,
        16_777_215,
        &[0; 32],
        0x13,
    );
    assert!(parse_kdf(&big).is_ok());
}

#[test]
fn d29_fmt_03_12_salt() {
    for n in [7, 33] {
        let m = argon2_map(
            larsal_crypto::kdf::ARGON2ID_ID,
            2,
            64 << 20,
            4,
            &vec![1; n],
            0x13,
        );
        assert_eq!(kdf_err(&m), Error::Unsupported);
    }
}

#[test]
fn d30_fmt_03_18_iterations() {
    let i = |v: &str| splice(m1(), 42, 8, &hex(v));
    assert_eq!(kdf_err(&i("0000000000000000")), Error::Unsupported);
    assert!(parse_kdf(&i("FEFFFF7F00000000")).is_ok());
    for v in ["FFFFFF7F00000000", "0200000001000000", "0000000000000080"] {
        assert_eq!(kdf_err(&i(v)), Error::Unsupported, "{v}");
    }
}

#[test]
fn d31_fmt_03_13() {
    let KdfParams::Argon2 { memory_kib, .. } =
        parse_kdf(&splice(m1(), 60, 8, &hex("0500100000000000"))).unwrap()
    else {
        panic!()
    };
    assert_eq!(memory_kib, 1024);
}

#[test]
fn d32_fmt_03_13() {
    let m = |v: &str| splice(m1(), 60, 8, &hex(v));
    assert_eq!(kdf_err(&m("FF1F000000000000")), Error::Unsupported);
    assert_eq!(
        kdf_err(&m("0020000000000000")),
        Error::Unsupported,
        "m = 8 < 8 x P = 32 (CRY-02.10)"
    );
    assert_eq!(kdf_err(&m("0000000000040000")), Error::Unsupported);
    assert!(parse_kdf(&splice(m("0020000000000000"), 78, 4, &hex("01000000"))).is_ok());
}

#[test]
fn d33_d34_fmt_03_14() {
    let KdfParams::Argon2 { version, .. } =
        parse_kdf(&splice(m1(), 134, 4, &hex("10000000"))).unwrap()
    else {
        panic!()
    };
    assert_eq!(version, 0x10);
    for v in ["11000000", "12000000", "0F000000", "14000000"] {
        assert_eq!(
            kdf_err(&splice(m1(), 134, 4, &hex(v))),
            Error::Unsupported,
            "{v}"
        );
    }
}

#[test]
fn d35_d36_fmt_03_15() {
    assert_eq!(
        kdf_err(&splice(
            m1(),
            138,
            0,
            &hex("42010000004B06000000736563726574")
        )),
        Error::Unsupported
    );
    assert!(parse_kdf(&splice(m1(), 138, 0, &hex("42010000004100000000"))).is_ok());
}

#[test]
fn d37_d38_d39_fmt_03_16() {
    let r = |v: &str| splice(m2(), 42, 8, &hex(v));
    for v in [
        "0000000000000000",
        "FFFFFF7F00000000",
        "0000008000000000",
        "40420F0001000000",
    ] {
        assert_eq!(kdf_err(&r(v)), Error::Unsupported, "{v}");
    }
    assert!(parse_kdf(&r("FEFFFF7F00000000")).is_ok());
    for n in [16, 7] {
        assert_eq!(
            kdf_err(&aes_kdf_map(1_000_000, &vec![0x4B; n])),
            Error::Unsupported
        );
    }
}

#[test]
fn d40_d41_d42_fmt_03_17() {
    let p64 = splice(m1(), 68, 14, &hex("050100000050080000000400000000000000"));
    assert!(matches!(
        parse_kdf(&p64).unwrap(),
        KdfParams::Argon2 { lanes: 4, .. }
    ));
    for e in [
        "04010000004904000000 02000000",
        "0D010000004908000000 0200000000000000",
    ] {
        assert!(
            matches!(
                parse_kdf(&splice(m1(), 32, 18, &hex(e))).unwrap(),
                KdfParams::Argon2 { iterations: 2, .. }
            ),
            "{e}"
        );
    }
    assert_eq!(
        kdf_err(&splice(
            m1(),
            32,
            18,
            &hex("0D010000004908000000FFFFFFFFFFFFFFFF")
        )),
        Error::Unsupported
    );
}

#[test]
fn d43_d44_d44b_fmt_03_17() {
    assert_eq!(
        kdf_err(&splice(m1(), 124, 14, &hex("18010000005602000000 3139"))),
        Error::Unsupported
    );
    let mut s_string = m1();
    s_string[82] = 0x18;
    assert_eq!(kdf_err(&s_string), Error::Unsupported);
    assert_eq!(
        kdf_err(&splice(m1(), 124, 14, &hex("42010000005602000000 3139"))),
        Error::Unsupported
    );
    assert_eq!(
        kdf_err(&splice(m1(), 32, 18, &hex("08010000004901000000 01"))),
        Error::Unsupported
    );
}

#[test]
fn d45_fmt_03_19_parse() {
    assert_eq!(
        parse_kdf(&splice(m1(), 138, 0, &hex("04010000005804000000 07000000"))).unwrap(),
        parse_kdf(&m1()).unwrap()
    );
}

#[test]
fn d47_d48_d50_d52_fmt_03_22_parse() {
    let d47 = parse_map(&hex("0001050400000 07A657461080000000500000000000000 04050000 00416C70686104000000 01000000 0D0400000062657461080000 00FEFFFFFFFFFFFFFF 1802000000 5F7800000000 00")).unwrap();
    assert_eq!(
        d47.iter().map(|e| e.kind).collect::<Vec<_>>(),
        [0x05, 0x04, 0x0D, 0x18]
    );
    let d52 = parse_map(&hex("0001080100000042010000000200")).unwrap();
    assert_eq!(d52[0].value, [0x02], "the raw Bool byte is kept");
}

#[test]
fn d53_fmt_03_18() {
    assert_eq!(
        kdf_err(&splice(
            m1(),
            68,
            14,
            &hex("050100000050080000000400000001000000")
        )),
        Error::Unsupported
    );
}

#[test]
fn d56_fmt_03_20() {
    let m = splice(
        splice(m1(), 16, 16, &hex("000102030405060708090A0B0C0D0E0F")),
        138,
        0,
        &hex("030100000058020000000100"),
    );
    assert_eq!(kdf_err(&m), Error::Corrupt);
}

#[test]
fn d57_fmt_03_20() {
    assert_eq!(
        kdf_err(&splice(m2(), 0, 2, &hex("0002"))[..92]),
        Error::Unsupported
    );
}

#[test]
fn d32b_fmt_03_12_memory_upper_boundary() {
    // M of 2^32 - 1 KiB (in bytes) is the largest accepted (FMT-03.12).
    let top = u64::from(u32::MAX) << 10;
    let m = argon2_map(larsal_crypto::kdf::ARGON2ID_ID, 2, top, 4, &[0; 32], 0x13);
    assert!(matches!(
        parse_kdf(&m).unwrap(),
        KdfParams::Argon2 {
            memory_kib: 4_294_967_295,
            ..
        }
    ));
    let over = argon2_map(
        larsal_crypto::kdf::ARGON2ID_ID,
        2,
        top + 1024,
        4,
        &[0; 32],
        0x13,
    );
    assert_eq!(kdf_err(&over), Error::Unsupported);
}

#[test]
fn d42b_fmt_03_17_negative_int32() {
    // M as Int32 -1: negative is Unsupported, never wrapped to 4 GiB.
    let m = splice(m1(), 50, 18, &hex("0C010000004D04000000FFFFFFFF"));
    assert_eq!(kdf_err(&m), Error::Unsupported);
    let p = splice(m1(), 68, 14, &hex("0C0100000050040000000400 0000"));
    assert!(parse_kdf(&p).is_ok(), "a positive Int32 is accepted");
}
