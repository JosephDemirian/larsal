//! Attacks AT-A01 to AT-A06 and AT-A12 (plan/attacks-and-checks.md) on the
//! payload layer, for version 4 and version 3 files.

mod format_common;

use app_crypto::kdf::{ARGON2D_ID, ARGON2ID_ID};
use app_crypto::secret::SecretBytes;
use app_format::Error;
use app_format::error::{HardwareKeyReason, KeyFileReason};
use app_format::header::read_header;
use app_format::keyfile::read_key_file;
use app_format::keys::{ChallengeResponse, Credentials};
use app_format::limits::{Limit, Limits};
use app_format::payload::{Open, open_payload, probe};
use format_common::*;
use std::io::Cursor;

const L: Limits = Limits::DEFAULT;
const HW: &[u8] = b"App demo HMAC secret";

fn xml(r: Result<Open, Error>) -> Vec<u8> {
    opened(r).xml.bytes().to_vec()
}

/// A header with a valid SHA-256 and a dummy rest: every check before the KDF.
fn header_only(d: &Demo) -> Vec<u8> {
    let mut f = d.header();
    f.extend_from_slice(app_crypto::hash::sha256(&[&f]).expose());
    f.extend([0; 104]);
    f
}

// ---------------------------------------------------------------------------
// AT-A01 Wrong credentials: every wrong case gives the same WrongKey, and
// nothing is decrypted.

#[test]
fn at_a01_wrong_credentials() {
    let f_good = [0x46u8; 32];
    let f_bad = [0x47u8; 32];
    let v4 = Demo {
        key_file: Some(f_good.to_vec()),
        hardware: Some(HW.to_vec()),
        ..Demo::new()
    }
    .build();
    let v3 = DemoV3 {
        key_file: Some(f_good.to_vec()),
        hardware: Some(HW.to_vec()),
        ..DemoV3::new()
    }
    .build();
    let (good_pw, bad_pw) = (pw("demo-pass"), pw("wrong-pass"));
    let (good_kf, bad_kf) = (raw_key_file(&f_good), raw_key_file(&f_bad));
    let (good_hw, bad_hw) = (soft_key(HW), soft_key(b"another demo secret!"));
    for file in [&v4, &v3] {
        let ok = Credentials {
            password: Some(&good_pw),
            key_file: Some(&good_kf),
            hardware_key: Some(&good_hw),
        };
        assert_eq!(xml(open_creds(file, &ok)), DEMO_XML);
        let pws = [Some(&good_pw), Some(&bad_pw), None];
        let kfs = [Some(&good_kf), Some(&bad_kf), None];
        let hws: [Option<&dyn ChallengeResponse>; 3] = [Some(&good_hw), Some(&bad_hw), None];
        for (i, p) in pws.iter().enumerate() {
            for (j, k) in kfs.iter().enumerate() {
                for (m, h) in hws.iter().enumerate() {
                    if (i, j, m) == (0, 0, 0) || (i, j, m) == (2, 2, 2) {
                        continue;
                    }
                    let c = Credentials {
                        password: *p,
                        key_file: *k,
                        hardware_key: *h,
                    };
                    let _ = probe::take();
                    assert_eq!(kind(open_creds(file, &c)), Error::WrongKey, "{i}{j}{m}");
                    let counts = probe::take();
                    assert_eq!(counts.inflate, 0, "nothing is decompressed");
                }
            }
        }
    }
    // A device that is not there is a hardware key problem, never WrongKey.
    struct Gone;
    impl ChallengeResponse for Gone {
        fn challenge(&self, _: &[u8; 64]) -> Result<SecretBytes, HardwareKeyReason> {
            Err(HardwareKeyReason::Missing)
        }
    }
    let c = Credentials {
        password: Some(&good_pw),
        key_file: Some(&good_kf),
        hardware_key: Some(&Gone),
    };
    assert_eq!(
        kind(open_creds(&v4, &c)),
        Error::HardwareKey(HardwareKeyReason::Missing)
    );
    assert_eq!(
        kind(open_creds(&v3, &c)),
        Error::HardwareKey(HardwareKeyReason::Missing)
    );
}

#[test]
fn at_a01_version_4_wrong_password_decrypts_nothing() {
    let _ = probe::take();
    assert_eq!(
        kind(open(&Demo::new().build(), "wrong-pass")),
        Error::WrongKey
    );
    assert_eq!(probe::take().decrypt, 0);
}

// ---------------------------------------------------------------------------
// AT-A02 Header tampering: flip each header byte; every file is rejected.

#[test]
fn at_a02_version_4_header_byte_sweep() {
    let file = Demo::rich_content().build();
    let h = read_header(&file, &L).unwrap().len;
    for at in 0..h + 64 {
        let mut f = file.clone();
        f[at] ^= 0x01;
        let got = open(&f, "demo-pass");
        let e = match got {
            Err(e) => e,
            Ok(o) => panic!("byte {at}: {o:?}"),
        };
        if (h + 32..h + 64).contains(&at) {
            assert_eq!(e, Error::WrongKey, "byte {at}");
        } else {
            assert_ne!(e, Error::WrongKey, "byte {at}");
        }
    }
}

#[test]
fn at_a02_rich_v4_header_byte_sweep() {
    // The real reference-made file: every flip before the stored HMAC is
    // rejected before any KDF work.
    let file = testdata("rich-v4.appvault");
    let h = read_header(&file, &L).unwrap().len;
    let _ = probe::take();
    for at in 0..h + 32 {
        let mut f = file.clone();
        f[at] ^= 0x01;
        let e = kind(open(&f, "demo-pass-5"));
        assert_ne!(e, Error::WrongKey, "byte {at}");
    }
    assert_eq!(probe::take().kdf, 0);
}

/// A version 3.1 vault whose document is password-only's, with a correct
/// HeaderHash for this test header, under a cheap KDF.
fn v3_with_header_hash() -> DemoV3 {
    let p = opened(open(&testdata("password-only.appvault"), "demo-pass-1"));
    let text = String::from_utf8(p.xml.bytes().to_vec()).unwrap();
    let real = text
        .split("<HeaderHash>")
        .nth(1)
        .unwrap()
        .split("</HeaderHash>")
        .next()
        .unwrap();
    let d = DemoV3::new();
    let hash = app_crypto::base64::encode(
        app_crypto::base64::Form::Padded,
        app_crypto::hash::sha256(&[&d.header()]).expose(),
    );
    DemoV3 {
        xml: text.replace(real, &hash).into_bytes(),
        ..d
    }
}

#[test]
fn at_a02_version_3_header_byte_sweep() {
    // Version 3 has no header check before the document; the HeaderHash
    // inside it finds the rest (FMT-17.19). Through app_format::open.
    let file = v3_with_header_hash().build();
    let pass = pw("demo-pass");
    let creds = Credentials {
        password: Some(&pass),
        ..Default::default()
    };
    assert!(
        app_format::open(&file, &creds, &mut host(), &L, None).is_ok(),
        "control"
    );
    for at in 0..222 {
        let mut f = file.clone();
        f[at] ^= 0x01;
        match app_format::open(&f, &creds, &mut host(), &L, None) {
            Ok(app_format::Opened::Ask(_)) | Err(_) => {}
            Ok(app_format::Opened::Vault(_)) => panic!("byte {at} was accepted"),
        }
    }
}

// ---------------------------------------------------------------------------
// AT-A03 Payload tampering: flip, cut, swap, repeat, append blocks.

#[test]
fn at_a03_version_4_payload() {
    let d = Demo {
        block: 512,
        ..Demo::rich_content()
    };
    let file = d.build();
    let want = xml(open(&file, "demo-pass"));
    let h = read_header(&file, &L).unwrap().len;
    let start = h + 64;
    for at in start..file.len() {
        let mut f = file.clone();
        f[at] ^= 0x01;
        assert_eq!(kind(open(&f, "demo-pass")), Error::Corrupt, "byte {at}");
    }
    // Block spans, walked from their size fields (36-byte head + data).
    let mut spans = Vec::new();
    let mut at = start;
    loop {
        let n = u32::from_le_bytes(file[at + 32..at + 36].try_into().unwrap()) as usize;
        spans.push(&file[at..at + 36 + n]);
        at += 36 + n;
        if n == 0 {
            break;
        }
    }
    let (data, fin) = spans.split_at(spans.len() - 1);
    let body = |order: &[usize]| {
        [
            file[..start].to_vec(),
            order.iter().flat_map(|&i| data[i].to_vec()).collect(),
            fin[0].to_vec(),
        ]
        .concat()
    };
    let n = data.len();
    assert!(n >= 3);
    let mut swapped: Vec<usize> = (0..n).collect();
    swapped.swap(0, 1);
    let repeated: Vec<usize> = [0].into_iter().chain(0..n).collect();
    let dropped: Vec<usize> = (1..n).collect();
    for order in [swapped, repeated, dropped] {
        assert_eq!(
            kind(open(&body(&order), "demo-pass")),
            Error::Corrupt,
            "{order:?}"
        );
    }
    assert_eq!(
        kind(open(&file[..file.len() - 36], "demo-pass")),
        Error::Corrupt,
        "cut final block"
    );
    // Appended after the final block: ignored (LD-01), content unchanged.
    let appended = [file.clone(), data[0].to_vec(), fin[0].to_vec()].concat();
    assert_eq!(xml(open(&appended, "demo-pass")), want);
}

#[test]
fn at_a03_version_3_payload() {
    let d = DemoV3 {
        block: 512,
        ..v3_with_header_hash()
    };
    let file = d.build();
    let want = xml(open(&file, "demo-pass"));
    let padding_only_last_block = d.plaintext().len().is_multiple_of(16);
    for at in 222..file.len() {
        let mut f = file.clone();
        f[at] ^= 0x01;
        let got = open(&f, "demo-pass");
        if at < 222 + 32 {
            assert_eq!(kind(got), Error::WrongKey, "byte {at}: start bytes");
        } else if padding_only_last_block && at >= file.len() - 16 {
            assert_eq!(xml(got), want, "byte {at}: padding only");
        } else {
            assert_eq!(kind(got), Error::Corrupt, "byte {at}");
        }
    }
    let appended = [file.clone(), vec![0x11; 4096]].concat();
    assert_eq!(xml(open(&appended, "demo-pass")), want);
}

// ---------------------------------------------------------------------------
// AT-A04 Truncation: cut at every 1 KB step and every byte of the last 100.

#[test]
fn at_a04_truncation() {
    for file in [
        Demo::rich_content().build(),
        DemoV3 {
            gzip: true,
            ..v3_with_header_hash()
        }
        .build(),
    ] {
        let len = file.len();
        let cuts: Vec<usize> = (0..len)
            .step_by(1024)
            .chain(len.saturating_sub(100)..len)
            .collect();
        for cut in cuts {
            let e = kind(open(&file[..cut], "demo-pass"));
            assert!(
                matches!(e, Error::Corrupt | Error::NotAVault),
                "cut {cut}: {e:?}"
            );
        }
    }
}

#[test]
fn at_a04_rich_v4_truncation() {
    let file = testdata("rich-v4.appvault");
    for cut in (0..file.len()).step_by(1024) {
        let e = kind(open(&file[..cut], "demo-pass-5"));
        assert!(
            matches!(e, Error::Corrupt | Error::NotAVault),
            "cut {cut}: {e:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// AT-A05 KDF cost bomb: refused before any work, or the user is asked.

#[test]
fn at_a05_kdf_cost_bomb() {
    let salt = [1u8; 32];
    let refused = [
        argon2_map(ARGON2ID_ID, 2, 1 << 42, 4, &salt, 0x13), // 4 TiB
        argon2_map(ARGON2ID_ID, 1 << 63, 64 << 20, 4, &salt, 0x13), // I = 2^63
        argon2_map(ARGON2ID_ID, 2, 1 << 40, 1 << 24, &salt, 0x13), // P = 2^24
    ];
    let _ = probe::take();
    for m in refused {
        let d = Demo {
            kdf_map: m,
            ..Demo::new()
        };
        assert_eq!(
            kind(open(&header_only(&d), "demo-pass")),
            Error::Unsupported
        );
    }
    // In range but above a refuse ceiling: TooLarge, never approvable.
    for m in [
        argon2_map(ARGON2ID_ID, 1, (u64::from(u32::MAX)) << 10, 4, &salt, 0x13), // above 16 GiB
        argon2_map(ARGON2ID_ID, 1_000_000_001, 8 << 10, 1, &salt, 0x13),
    ] {
        let d = Demo {
            kdf_map: m,
            ..Demo::new()
        };
        assert_eq!(
            kind(open(&header_only(&d), "demo-pass")),
            Error::TooLarge(Limit::KdfCost)
        );
    }
    // The ask band: the cost is shown first.
    for m in [
        argon2_map(ARGON2D_ID, 1, 2 << 30, 4, &salt, 0x13),
        argon2_map(ARGON2ID_ID, 1, 1032 << 10, 129, &salt, 0x13),
        aes_kdf_map(2_147_483_646, &salt),
    ] {
        let d = Demo {
            kdf_map: m,
            ..Demo::new()
        };
        let p = pw("demo-pass");
        let c = Credentials {
            password: Some(&p),
            ..Default::default()
        };
        let Ok(Open::Ask(report)) = open_payload(&header_only(&d), &c, &mut host(), &L, None)
        else {
            panic!("ask expected")
        };
        assert!(report.over_memory() || report.over_lanes() || report.over_time());
    }
    // Version 3: rounds out of range are refused at the header.
    let v3 = DemoV3 {
        rounds: 2_147_483_647,
        ..DemoV3::new()
    };
    assert_eq!(
        kind(open(&v3.build_with_ciphertext(&[0; 64]), "demo-pass")),
        Error::Unsupported
    );
    assert_eq!(probe::take().kdf, 0, "no KDF ran for any of them");
}

// ---------------------------------------------------------------------------
// AT-A06 Decompression bomb: stopped at the limit; no output buffer before
// the whole member is counted (memory stays flat).

/// A gzip member that inflates to `mib` MiB of zeros, built from repeated
/// deflate blocks (each byte-aligned by a sync flush). Its trailer is not
/// valid: a bomb is stopped before the trailer is read.
fn gzip_bomb(mib: usize) -> Vec<u8> {
    use flate2::{Compress, Compression, FlushCompress};
    let zeros = vec![0u8; 1 << 20];
    let mut c = Compress::new(Compression::default(), false);
    let chunk = |c: &mut Compress| {
        let mut out = Vec::with_capacity(4 << 10);
        let before = c.total_in();
        c.compress_vec(&zeros, &mut out, FlushCompress::Sync)
            .unwrap();
        assert_eq!(c.total_in() - before, 1 << 20, "the whole MiB went in");
        out
    };
    let first = chunk(&mut c);
    let next = chunk(&mut c);
    let mut g = vec![0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0x13];
    g.extend(first);
    for _ in 1..mib {
        g.extend_from_slice(&next);
    }
    g.extend([0x03, 0x00]); // the final empty block
    g.extend([0; 8]);
    g
}

#[test]
fn at_a06_decompression_bomb_lowered_limit() {
    // T08-21: 512 MiB inflated, limit 64 MiB.
    let bomb = gzip_bomb(513);
    assert!(
        bomb.len() < 600 << 10,
        "about half a megabyte: {}",
        bomb.len()
    );
    let lim = Limits {
        total: 64 << 20,
        ..L
    };
    let d = Demo::new();
    let inner_len = d.inner.len();
    assert!(inner_len < 1024);
    let file = d.build_with_plaintext(&bomb);
    assert_eq!(
        kind(open_lim(&file, "demo-pass", &lim)),
        Error::TooLarge(Limit::Total)
    );
    let v3 = DemoV3::new();
    let v3_file =
        v3.build_with_plaintext(&[v3.start_bytes.to_vec(), hashed_blocks(&bomb, 1 << 20)].concat());
    assert_eq!(
        kind(open_lim(&v3_file, "demo-pass", &lim)),
        Error::TooLarge(Limit::Total)
    );
}

#[test]
fn at_a06_decompression_bomb_default_limit() {
    // Past the 1 GiB default total limit.
    let file = Demo::new().build_with_plaintext(&gzip_bomb(1100));
    assert_eq!(
        kind(open(&file, "demo-pass")),
        Error::TooLarge(Limit::Total)
    );
}

// ---------------------------------------------------------------------------
// AT-A12 Key file attacks (with tests/keyfile.rs: fmt_18_5_b hashes a 1 GiB
// file with flat memory; the FMT-18.6 to FMT-18.17 rows cover malformed
// documents).

fn key(bytes: Vec<u8>) -> Result<app_format::keyfile::KeyFileKind, Error> {
    read_key_file(Cursor::new(bytes), &L).map(|k| k.kind())
}

#[test]
fn at_a12_key_file_attacks() {
    let data = "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F";
    let doc = |hash: &str, digits: &str| {
        format!("<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{hash}\">{digits}</Data></Key></KeyFile>").into_bytes()
    };
    assert_eq!(
        key(doc("4D8D274F", data)).unwrap(),
        app_format::keyfile::KeyFileKind::Xml2
    );
    // Wrong check value: a clear error, before any key work.
    assert_eq!(
        key(doc("00000000", data)),
        Err(Error::KeyFile(KeyFileReason::CheckValueMismatch))
    );
    // Malformed structure: falls back to the hashed kind, as the reference.
    let mut broken = doc("4D8D274F", data);
    broken.truncate(broken.len() - 4);
    assert_eq!(
        key(broken).unwrap(),
        app_format::keyfile::KeyFileKind::Hashed
    );
    // Oversized data text and deep nesting: KeyFile(TooLarge), never a fall-back.
    let huge = doc("4D8D274F", &"0".repeat((1 << 20) + 2));
    assert_eq!(
        key(huge),
        Err(Error::KeyFile(KeyFileReason::TooLarge(Limit::KeyFileText)))
    );
    let deep = format!(
        "<KeyFile><Meta><Version>2.0</Version></Meta><Key>{}<Data Hash=\"4D8D274F\">{data}</Data>{}</Key></KeyFile>",
        "<W>".repeat(300),
        "</W>".repeat(300)
    );
    assert_eq!(
        key(deep.into_bytes()),
        Err(Error::KeyFile(KeyFileReason::TooLarge(Limit::KeyFileDepth)))
    );
    // A DTD in a KeyFile document: refused (LD-30).
    let dtd = [b"<!DOCTYPE KeyFile>".to_vec(), doc("4D8D274F", data)].concat();
    assert_eq!(key(dtd), Err(Error::KeyFile(KeyFileReason::Dtd)));
    assert_eq!(key(Vec::new()), Err(Error::KeyFile(KeyFileReason::Empty)));
}
