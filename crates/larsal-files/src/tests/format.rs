//! FIL-01 rows at this layer.

use super::*;
use crate::armor::Source;
use crate::decrypt::kdf_probe;
use crate::encrypt::encrypt_file_with;
use crate::fsio::{OutputFolder, SourceFile};
use crate::header::{self, Stanza};
use crate::keys::generate_identity;
use crate::limits::{MAX_HEADER, WRITE_LOG_N};
use std::cell::Cell;

fn stanzas_of(data: &[u8]) -> Vec<Stanza> {
    let mut src = Source::detect(Cursor::new(data)).unwrap();
    header::read(&mut src).unwrap().stanzas
}

fn identity_a() -> Identities {
    ids(ID_A)
}

fn phrase_unlock(p: &SecretString) -> Unlock<'_> {
    Unlock::Passphrase(p)
}

#[test]
fn fil01_t02_bad_syntax_is_one_generic_failure_with_no_output() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    let good = craft(b"", PLAIN);
    assert_eq!(open(&good, &unlock).unwrap(), PLAIN);

    // A CRLF binary header.
    let crlf = String::from_utf8_lossy(&good[..header_end(&good)]).replace('\n', "\r\n");
    let mut with_crlf = crlf.into_bytes();
    with_crlf.extend_from_slice(&good[header_end(&good)..]);
    assert_eq!(refused(&with_crlf, &unlock), Failure::Header);

    // Oversized arguments: refused at the header's limit, whatever they say.
    let long_args = format!("demo {}", "a".repeat(MAX_HEADER));
    let oversized = craft(&raw_stanza(&long_args, b""), PLAIN);
    assert_eq!(refused(&oversized, &unlock), Failure::Header);

    // Noncanonical base64, in an ignored stanza and in a known one.
    let noncanonical = craft(b"-> demo\nQR\n", PLAIN);
    assert_eq!(refused(&noncanonical, &unlock), Failure::Header);
    let share = b64(&[7; 32]);
    let bad_share = format!("-> X25519 {}B\n{}\n", &share[..42], b64(&[7; 32]));
    let bad = sealed_header(&demo_file_key(), bad_share.as_bytes());
    assert_eq!(refused(&bad, &unlock), Failure::Header);

    // Bad padding in armor has its own test: fil03_t01_armor_padding_is_exactly_what_the_length_needs.
}

#[test]
fn fil01_t02_mac_runs_over_the_original_bytes() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    // An unusual, valid ignored stanza stays exactly as it came.
    let unusual = raw_stanza("demo !\"#$ ~", &[9; 49]);
    let file = craft(&unusual, PLAIN);
    assert_eq!(open(&file, &unlock).unwrap(), PLAIN);

    let mut src = Source::detect(Cursor::new(&file[..])).unwrap();
    let head = header::read(&mut src).unwrap();
    let end = file.windows(4).position(|w| w == b"--- ").unwrap() + 3;
    assert_eq!(
        head.covered(),
        &file[..end],
        "MAC input is the bytes as read"
    );
    assert_eq!(head.raw, &file[..header_end(&file)]);

    // A repair that keeps the grammar still breaks the MAC.
    let edited = craft(&raw_stanza("demo !\"#$ ~", &[9; 49]), PLAIN);
    let at = edited.windows(5).position(|w| w == b"-> de").unwrap() + 3;
    let mut one_arg_changed = edited;
    one_arg_changed[at] = b'D';
    assert_eq!(refused(&one_arg_changed, &unlock), Failure::Mac);
}

#[test]
fn fil01_t03_two_encryptions_share_no_salt_body_or_nonce() {
    let a = seal_pass(PLAIN, PASS);
    let b = seal_pass(PLAIN, PASS);
    let (
        Stanza::Scrypt {
            salt: s1, body: b1, ..
        },
        Stanza::Scrypt {
            salt: s2, body: b2, ..
        },
    ) = (&stanzas_of(&a)[0], &stanzas_of(&b)[0])
    else {
        panic!("one scrypt stanza each");
    };
    assert_ne!(s1, s2);
    assert_ne!(b1, b2);
    assert_ne!(
        a[header_end(&a)..][..16],
        b[header_end(&b)..][..16],
        "nonces"
    );
    assert_ne!(a[header_end(&a)..], b[header_end(&b)..]);

    let to = [rec(ID_A)];
    let (x, y) = (seal_to(PLAIN, &to), seal_to(PLAIN, &to));
    let (Stanza::X25519 { share: s1, .. }, Stanza::X25519 { share: s2, .. }) =
        (&stanzas_of(&x)[0], &stanzas_of(&y)[0])
    else {
        panic!("one X25519 stanza each");
    };
    assert_ne!(s1, s2);
    assert_ne!(x[header_end(&x)..], y[header_end(&y)..]);
}

#[test]
fn fil01_t03_rng_failure_leaves_no_completed_file() {
    let phrase = secret(PASS);
    let to = [rec(ID_A)];
    for lock in [Lock::Passphrase(&phrase), Lock::Recipients(&to)] {
        // File key, then salt or ephemeral key, then nonce: each can fail.
        for fail_at in 0..3 {
            let calls = Cell::new(0);
            let mut draw = |n: usize| {
                let at = calls.get();
                calls.set(at + 1);
                if at == fail_at {
                    Err(larsal_crypto::Error::RandomSource)
                } else {
                    random::bytes(n)
                }
            };
            let mut stream = Vec::new();
            let result =
                encrypt_stream_with(&mut draw, LOW, &mut &*PLAIN, &mut stream, &lock, &mut keep);
            assert_eq!(result, Err(Error::Io));
            assert!(stream.is_empty(), "no byte before every draw held");

            let t = Temp::new();
            let source = SourceFile::open(&t.file("demo.bin", PLAIN)).unwrap();
            let out = t.sub("out");
            let folder = OutputFolder::open(&out).unwrap();
            calls.set(0);
            let result = encrypt_file_with(
                &mut draw,
                LOW,
                source,
                &folder,
                "demo.age".as_ref(),
                &lock,
                &mut keep,
            );
            assert_eq!(result, Err(Error::Io));
            assert!(names_in(&out).is_empty(), "no owned partial stays");
        }
    }
}

#[test]
fn fil01_t04_bad_scrypt_shapes_fail_before_any_key_derivation() {
    let file_key = demo_file_key();
    let salt = [7u8; 16];
    let good = s_stanza(&file_key, PASS, LOW, &salt);
    let other_x = x_stanza(&file_key, &rec(ID_A), 7);
    let salt_text = b64(&salt);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("plus X25519", [good.clone(), other_x.clone()].concat()),
        ("after X25519", [other_x, good.clone()].concat()),
        ("twice", [good.clone(), good.clone()].concat()),
        ("plus ignored", [good, raw_stanza("demo", b"")].concat()),
        (
            "body 31",
            raw_stanza(&format!("scrypt {salt_text} 4"), &[7; 31]),
        ),
        (
            "body 33",
            raw_stanza(&format!("scrypt {salt_text} 4"), &[7; 33]),
        ),
        (
            "cost 21",
            raw_stanza(&format!("scrypt {salt_text} 21"), &[7; 32]),
        ),
        (
            "long decimal",
            raw_stanza(&format!("scrypt {salt_text} {}", "1".repeat(40)), &[7; 32]),
        ),
    ];
    let phrase = secret(PASS);
    for (name, stanzas) in cases {
        let mut file = sealed_header(&file_key, &stanzas);
        file.extend(payload_of(&payload_key(&file_key, &NONCE), &NONCE, PLAIN));
        kdf_probe::take();
        assert_eq!(
            refused(&file, &phrase_unlock(&phrase)),
            Failure::Header,
            "{name}"
        );
        assert_eq!(kdf_probe::take(), 0, "{name}: a key derivation ran");
    }
}

#[test]
fn fil01_t04_valid_single_stanza_derives_once() {
    let file = seal_pass(PLAIN, PASS);
    let phrase = secret(PASS);
    kdf_probe::take();
    assert_eq!(open(&file, &phrase_unlock(&phrase)).unwrap(), PLAIN);
    assert_eq!(kdf_probe::take(), 1);
}

#[test]
fn fil01_t05_only_the_identical_utf8_opens() {
    let forms = [
        "demo",
        " demo",
        "demo ",
        "caf\u{e9}",
        "cafe\u{301}",
        "de\0mo",
        "de\0",
    ];
    for written in forms {
        let file = seal_pass(PLAIN, written);
        for tried in forms {
            let phrase = secret(tried);
            let result = open(&file, &phrase_unlock(&phrase));
            if tried == written {
                assert_eq!(result.unwrap(), PLAIN, "{written:?}");
            } else {
                assert_eq!(result, Err(Failure::NoMatch), "{written:?} by {tried:?}");
            }
        }
    }
}

#[test]
fn fil01_t05_empty_passphrase_is_refused_with_no_key_derivation() {
    let empty = secret("");
    kdf_probe::take();
    let mut out = Vec::new();
    let result =
        crate::encrypt_stream(&mut &*PLAIN, &mut out, &Lock::Passphrase(&empty), &mut keep);
    assert_eq!(result, Err(Error::Passphrase));
    assert!(out.is_empty());
    let file = seal_pass(PLAIN, PASS);
    kdf_probe::take();
    assert_eq!(
        snapshot(&file)
            .unlock(&Unlock::Passphrase(&empty))
            .map(|_| ()),
        Err(Error::Passphrase)
    );
    assert_eq!(kdf_probe::take(), 0);
}

#[test]
fn fil01_t08_each_recipient_opens_alone_and_nothing_hidden_is_added() {
    let (a, b) = (rec(ID_A), rec(ID_B));
    let file = seal_to(PLAIN, &[a, b]);
    assert_eq!(stanzas_of(&file).len(), 2, "exactly the recipients named");
    for id in [ID_A, ID_B] {
        let keys = ids(id);
        assert_eq!(open(&file, &Unlock::Identities(&keys)).unwrap(), PLAIN);
    }
    let (third, _) = generate_identity().unwrap();
    let keys = Identities::single(&third).unwrap();
    assert_eq!(refused(&file, &Unlock::Identities(&keys)), Failure::NoMatch);
    assert_eq!(
        stanzas_of(&seal_to(PLAIN, &[a, a])).len(),
        1,
        "same key once"
    );
    let mut out = Vec::new();
    assert_eq!(
        crate::encrypt_stream(&mut &*PLAIN, &mut out, &Lock::Recipients(&[]), &mut keep),
        Err(Error::Recipient)
    );
}

#[test]
fn fil01_t09_only_a_conforming_native_key_is_accepted() {
    let lower = Recipient::parse(REC_A).unwrap();
    assert_eq!(lower, rec(ID_A));
    assert_eq!(lower.to_text().unwrap(), REC_A);
    let upper = "AGE1Q73HE0Q5YZFU3D64MSD3P6RVKSNRWJK3D2598MGTMLQT9WRDR37Q2VRN72";
    assert_eq!(Recipient::parse(upper).unwrap(), lower);
    for bad in [
        // Mixed case.
        "Age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72",
        // Bech32m: the same key with the other checksum.
        "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37qlsnlmg",
        // 31 and 33 bytes.
        "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdrsldtmhq",
        "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37qqpjk3x3",
        // Another prefix, and nonzero padding bits.
        "demo1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37qghklml",
        "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37ph6hxrc",
        "",
        "age1",
    ] {
        assert_eq!(Recipient::parse(bad), Err(Error::Recipient), "{bad}");
    }
    assert!(Identities::single(&secret(ID_A)).is_ok());
    for bad in [
        // Bech32m and 33 bytes.
        "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQAASGUM",
        "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQQL5Q4XU",
        REC_A,
    ] {
        assert_eq!(
            Identities::single(&secret(bad)).map(|_| ()),
            Err(Error::Decrypt)
        );
    }
}

#[test]
fn fil01_t11_low_order_share_and_one_bit_bad_mac_are_generic() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    for hex in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let share: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let stanza = raw_stanza(&format!("X25519 {}", b64(&share)), &[7; 32]);
        let file = sealed_header(&demo_file_key(), &stanza);
        assert_eq!(refused(&file, &unlock), Failure::Header, "{hex}");
    }

    let good = craft(b"", PLAIN);
    let mac_at = good.windows(4).position(|w| w == b"--- ").unwrap() + 4;
    let mut bad = good.clone();
    bad[mac_at] = if bad[mac_at] == b'A' { b'B' } else { b'A' };
    assert_eq!(refused(&bad, &unlock), Failure::Mac);

    // A low-order recipient: refused on encrypt, with nothing written.
    let mut out = Vec::new();
    assert_eq!(
        crate::encrypt_stream(
            &mut &*PLAIN,
            &mut out,
            &Lock::Recipients(&[Recipient([0; 32])]),
            &mut keep,
        ),
        Err(Error::Recipient)
    );
    assert!(out.is_empty());

    // Normal recipients: this file's own share in the derivation, so the same
    // file key under another share has another wrapped body.
    let (one, two) = (
        x_stanza(&demo_file_key(), &rec(ID_A), 7),
        x_stanza(&demo_file_key(), &rec(ID_A), 8),
    );
    assert_ne!(one, two);
    assert_eq!(open(&good, &unlock).unwrap(), PLAIN);
}

#[test]
fn fil01_t12_bad_prefixes_and_chunk_games_are_one_generic_error() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    let file_key = demo_file_key();
    let key = payload_key(&file_key, &NONCE);
    let other = payload_key(&SecretBytes::new(vec![0x11; 16]), &NONCE);
    let full = demo_bytes(crate::limits::CHUNK);
    let c = |n: u64, last: bool, plain: &[u8]| chunk(&key, n, last, plain);
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("missing final", vec![c(0, false, &full)]),
        (
            "bad final",
            vec![c(0, false, &full), {
                let mut d = c(1, true, PLAIN);
                d[0] ^= 1;
                d
            }],
        ),
        ("appended", vec![c(0, true, PLAIN), vec![0]]),
        ("appended after full", vec![c(0, true, &full), vec![0]]),
        (
            "swapped",
            vec![c(1, false, &full), c(0, false, &full), c(2, true, PLAIN)],
        ),
        (
            "repeated",
            vec![c(0, false, &full), c(0, false, &full), c(1, true, PLAIN)],
        ),
        ("skipped", vec![c(0, false, &full), c(2, true, PLAIN)]),
        (
            "cross file",
            vec![c(0, false, &full), chunk(&other, 1, true, PLAIN)],
        ),
    ];
    let head = sealed_header(&file_key, &x_stanza(&file_key, &rec(ID_A), 7));
    for (name, parts) in cases {
        let mut file = head.clone();
        file.extend_from_slice(&NONCE);
        file.extend(parts.concat());
        assert_eq!(refused(&file, &unlock), Failure::Payload, "{name}");
    }
}

#[test]
fn fil01_t13_armor_transport_variants_open_alike_and_bad_armor_does_not() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    let plain = demo_bytes(70_000);
    let binary = craft(b"", &plain);
    assert_eq!(open(&binary, &unlock).unwrap(), plain);
    for eol in ["\n", "\r\n"] {
        assert_eq!(
            open(&armor(&binary, eol), &unlock).unwrap(),
            plain,
            "{eol:?}"
        );
    }

    // Changed base64 bits: decoded bytes change, or the form breaks.
    let mut changed = armor(&binary, "\n");
    let line_start = changed.iter().position(|b| *b == b'\n').unwrap() + 1;
    changed[line_start + 400] = if changed[line_start + 400] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let failure = refused(&changed, &unlock);
    assert_ne!(failure, Failure::Armor, "still armor: the content fails");

    let mut junk = armor(&binary, "\n");
    junk.extend_from_slice(b"junk\n");
    assert_eq!(refused(&junk, &unlock), Failure::Armor);
    let mut extra = armor(&binary, "\n");
    extra.extend(armor(&binary, "\n"));
    assert_eq!(refused(&extra, &unlock), Failure::Armor);
    let blank =
        String::from_utf8(armor(&binary, "\n"))
            .unwrap()
            .replacen("-----\n", "-----\n\n", 1);
    assert_eq!(refused(blank.as_bytes(), &unlock), Failure::Armor);
    let mut spaced = b" \t\r\n".to_vec();
    spaced.extend(armor(&binary, "\n"));
    spaced.extend_from_slice(b"\n \t\r\n");
    assert_eq!(
        open(&spaced, &unlock).unwrap(),
        plain,
        "outer white space is legal"
    );
}

#[test]
fn fil01_t14_unknown_stanzas_are_ignored_and_never_run() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    let with_unknown = craft(&raw_stanza("demo-plugin arg", &[9; 20]), PLAIN);
    assert_eq!(open(&with_unknown, &unlock).unwrap(), PLAIN);
    // Its authentication still covers the ignored stanza.
    let mut changed = with_unknown;
    let at = changed.windows(9).position(|w| w == b"demo-plug").unwrap();
    changed[at] = b'D';
    assert_eq!(refused(&changed, &unlock), Failure::Mac);

    let file_key = demo_file_key();
    let mut unknown_only = sealed_header(&file_key, &raw_stanza("demo-plugin arg", &[9; 32]));
    unknown_only.extend(payload_of(&payload_key(&file_key, &NONCE), &NONCE, PLAIN));
    assert_eq!(refused(&unknown_only, &unlock), Failure::NoMatch);

    for (name, source) in production_sources() {
        for word in ["std::process", "Command::", "std::net", "dlopen"] {
            assert!(!source.contains(word), "{name} holds {word}");
        }
    }
}

#[test]
fn fil01_t15_hostile_identity_text_is_refused_and_a_list_is_bounded() {
    for hostile in [
        "$(touch /tmp/larsal-demo)",
        "`touch /tmp/larsal-demo`",
        "/usr/bin/demo-plugin --flag",
        "~/.ssh/id_demo",
        "AGE-PLUGIN-DEMO-1QQQQQQQ",
    ] {
        let list = format!("# demo\n{hostile}\n");
        assert_eq!(
            Identities::from_list(list.as_bytes()).map(|_| ()),
            Err(Error::Decrypt)
        );
        assert_eq!(
            Identities::single(&secret(hostile)).map(|_| ()),
            Err(Error::Decrypt)
        );
        // One bad line fails the whole list, even after a good one.
        let mixed = format!("{ID_A}\n{hostile}\n");
        assert_eq!(
            Identities::from_list(mixed.as_bytes()).map(|_| ()),
            Err(Error::Decrypt)
        );
    }
    let list = format!("# demo keys\n\n{ID_A}\n# the other\n{ID_B}\n");
    let keys = Identities::from_list(list.as_bytes()).unwrap();
    assert_eq!(keys.keys.len(), 2);
    let file = seal_to(PLAIN, &[rec(ID_B)]);
    assert_eq!(open(&file, &Unlock::Identities(&keys)).unwrap(), PLAIN);
    assert_eq!(
        Identities::from_list(b"# only a comment\n").map(|_| ()),
        Err(Error::Decrypt)
    );
    assert_eq!(
        Identities::from_list(b"\xff\n").map(|_| ()),
        Err(Error::Decrypt)
    );

    // Nothing ambient: no home folder, agent or key store is named.
    for (name, source) in production_sources() {
        let code = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for word in [
            "\".ssh",
            "HOME",
            "home_dir",
            "env::var",
            "Keychain",
            "SSH_AUTH_SOCK",
        ] {
            assert!(!code.contains(word), "{name} names {word}");
        }
    }
}

#[test]
fn fil01_t16_encrypted_key_file_and_its_limits() {
    let phrase = secret(PASS);
    let list = format!("# demo\n{ID_A}\n");
    let key_file = seal_pass(list.as_bytes(), PASS);
    let keys = Identities::read_key_file(&mut &key_file[..], Some(&phrase)).unwrap();
    assert!(keys.from_weak_file(), "a low work factor is reported");
    let data = seal_to(PLAIN, &[rec(ID_A)]);
    assert_eq!(open(&data, &Unlock::Identities(&keys)).unwrap(), PLAIN);

    // A plain list reads as one, and needs no passphrase.
    let plain_list = Identities::read_key_file(&mut list.as_bytes(), None).unwrap();
    assert!(!plain_list.from_weak_file());
    assert_eq!(plain_list.keys.len(), 1);

    // No passphrase, a wrong one, recursion, an oversized plaintext, a changed byte.
    assert_eq!(
        Identities::read_key_file(&mut &key_file[..], None).map(|_| ()),
        Err(Error::Decrypt)
    );
    assert_eq!(
        Identities::read_key_file(&mut &key_file[..], Some(&secret("other"))).map(|_| ()),
        Err(Error::Decrypt)
    );
    let nested = seal_pass(&key_file, PASS);
    assert_eq!(
        Identities::read_key_file(&mut &nested[..], Some(&phrase)).map(|_| ()),
        Err(Error::Decrypt),
        "the content of a key file is never decrypted again"
    );
    let padded = format!("{}{ID_A}\n", "#\n".repeat(32_769));
    let oversized = seal_pass(padded.as_bytes(), PASS);
    assert_eq!(
        Identities::read_key_file(&mut &oversized[..], Some(&phrase)).map(|_| ()),
        Err(Error::Decrypt)
    );
    let mut cut = key_file.clone();
    cut.truncate(key_file.len() - 1);
    assert_eq!(
        Identities::read_key_file(&mut &cut[..], Some(&phrase)).map(|_| ()),
        Err(Error::Decrypt)
    );
    // The bound of an in-memory open, at and one below the plaintext's length.
    assert_eq!(
        crate::decrypt::open_bounded(&key_file, &Unlock::Passphrase(&phrase), list.len())
            .unwrap()
            .0
            .expose(),
        list.as_bytes()
    );
    assert_eq!(
        crate::decrypt::open_bounded(&key_file, &Unlock::Passphrase(&phrase), list.len() - 1)
            .map(|_| ()),
        Err(Error::Decrypt)
    );
    // An encrypted key file over the read bound is not even buffered whole.
    let huge = vec![b'#'; crate::limits::MAX_IDENTITY_FILE + 1];
    assert_eq!(
        Identities::read_key_file(&mut &huge[..], Some(&phrase)).map(|_| ()),
        Err(Error::Decrypt)
    );
    // Armored files are found by their form, too.
    let armored = armor(&key_file, "\n");
    assert!(Identities::read_key_file(&mut &armored[..], Some(&phrase)).is_ok());
    let mut spaced = b" \t\r\n".to_vec();
    spaced.extend_from_slice(&armored);
    assert!(Identities::read_key_file(&mut &spaced[..], Some(&phrase)).is_ok());
    // A dash or white space first says nothing: those stay a list, and fail as one.
    for first in ["-", " ", "-----BEGIN"] {
        let not_armor = format!("{first}\n{list}");
        assert_eq!(
            Identities::read_key_file(&mut not_armor.as_bytes(), Some(&phrase)).map(|_| ()),
            Err(Error::Decrypt),
            "{first}"
        );
    }
}

#[test]
fn fil01_t19_import_boundary_and_no_secret_in_debug() {
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps = manifest.split("[dev-dependencies]").next().unwrap();
    let names: Vec<&str> = deps
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && l.contains('='))
        .map(|l| l.split('=').next().unwrap().trim())
        .collect();
    assert_eq!(names, ["larsal-crypto", "larsal-platform"]);

    let banned = [
        "chacha20",
        "poly1305",
        "scrypt::",
        "x25519_dalek",
        "hkdf::",
        "hmac::",
        "sha2::",
        "getrandom",
        "rand::",
        "zeroize",
        "unsafe ",
    ];
    for (name, source) in production_sources() {
        let code = source
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                !l.starts_with("//") && !l.starts_with('#')
            })
            .collect::<Vec<_>>()
            .join("\n");
        for word in banned {
            assert!(!code.contains(word), "{name} names {word}");
        }
    }
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));

    // Every public state and error prints no content.
    let keys = ids(ID_A);
    let shown = format!("{keys:?}");
    assert_eq!(shown, "Identities(1)");
    let file = seal_to(PLAIN, &[rec(ID_A)]);
    let unwrapped = snapshot(&file).unlock(&Unlock::Identities(&keys)).unwrap();
    assert_eq!(format!("{unwrapped:?}"), "Unwrapped");
    let validated = checked(&file, &Unlock::Identities(&keys)).unwrap();
    assert_eq!(format!("{validated:?}"), "Validated");
    assert_eq!(format!("{:?}", snapshot(&file)), "Snapshot");
}

#[test]
fn fil01_t20_native_pq_is_refused_with_no_fallback() {
    // Public and private text of the native hybrid form: never accepted, and
    // nothing is tried in its place.
    assert_eq!(
        Recipient::parse("age1pq1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72"),
        Err(Error::Recipient)
    );
    assert_eq!(
        Identities::single(&secret("AGE-SECRET-KEY-PQ-1QQQQQQQQQQ")).map(|_| ()),
        Err(Error::Decrypt)
    );
    let file_key = demo_file_key();
    let stanza = raw_stanza("mlkem768x25519 demo", &[9; 1000]);
    let mut file = sealed_header(&file_key, &stanza);
    file.extend(payload_of(&payload_key(&file_key, &NONCE), &NONCE, PLAIN));
    let keys = identity_a();
    assert_eq!(refused(&file, &Unlock::Identities(&keys)), Failure::NoMatch);
}

#[test]
fn fil01_t21_a_replacement_opens_and_says_nothing_of_a_sender() {
    let keys = identity_a();
    let unlock = Unlock::Identities(&keys);
    let first = seal_to(b"first demo", &[rec(ID_A)]);
    let second = seal_to(b"second demo", &[rec(ID_A)]);
    // Either is valid: the format does not know which one a sender meant.
    assert_eq!(open(&first, &unlock).unwrap(), b"first demo");
    assert_eq!(open(&second, &unlock).unwrap(), b"second demo");
    // What a checked file says about itself is its length, nothing of who or when.
    assert_eq!(checked(&second, &unlock).unwrap().plain_len(), 11);
}

#[test]
fn fil01_t22_a_weak_file_can_be_guessed_offline_and_no_service_is_asked() {
    let file = seal_pass(PLAIN, "demo");
    let hits: Vec<&str> = ["one", "two", "demo", "three"]
        .into_iter()
        .filter(|guess| {
            let phrase = secret(guess);
            open(&file, &phrase_unlock(&phrase)).is_ok()
        })
        .collect();
    assert_eq!(hits, ["demo"], "guesses need nothing but the file");
    for (name, source) in production_sources() {
        for word in ["std::net", "TcpStream", "http"] {
            assert!(!source.contains(word), "{name} names {word}");
        }
    }
    assert_eq!(WRITE_LOG_N, 18, "the cost a new file gets is only a delay");
}

/// A file key read by hand, as the format says: these tests look at the key
/// itself, so it must not come through the code they check.
fn open_key(wrap_key: &SecretBytes, body: &[u8; 32]) -> Vec<u8> {
    let (sealed, tag) = body.split_at(16);
    let mut key = sealed.to_vec();
    aead::open_in_place(wrap_key, &[0; 12], b"", &mut key, tag.try_into().unwrap()).unwrap();
    key
}

fn file_key_of_stanza(stanza: &Stanza, id: &str) -> Vec<u8> {
    let keys = ids(id);
    let Stanza::X25519 { share, body } = stanza else {
        panic!("an X25519 stanza");
    };
    let shared = keys.keys[0].secret.agree(share).unwrap();
    let mut salt = share.to_vec();
    salt.extend_from_slice(&keys.keys[0].public);
    open_key(
        &wrap::hkdf_sha256(&salt, &shared, X25519_LABEL).unwrap(),
        body,
    )
}

fn file_key_to_id_a(file: &[u8]) -> Vec<u8> {
    file_key_of_stanza(&stanzas_of(file)[0], ID_A)
}

fn file_key_by_phrase(file: &[u8], pass: &str) -> Vec<u8> {
    let stanzas = stanzas_of(file);
    let [Stanza::Scrypt { salt, log_n, body }] = &stanzas[..] else {
        panic!("one scrypt stanza");
    };
    open_key(&derive_wrap_key(&secret(pass), salt, *log_n).unwrap(), body)
}

#[test]
fn fil01_t03_every_encryption_has_its_own_file_key() {
    let to = [rec(ID_A)];
    let by_key = Lock::Recipients(&to);
    let public_seal = || {
        let mut out = Vec::new();
        crate::encrypt_stream(&mut &*PLAIN, &mut out, &by_key, &mut keep).unwrap();
        out
    };

    // The right key is what this reads: it opens the file's own MAC.
    let file = seal_to(PLAIN, &to);
    let key = file_key_to_id_a(&file);
    assert_eq!(key.len(), 16);
    let footer = file.windows(4).position(|w| w == b"--- ").unwrap();
    assert_eq!(
        sealed_header(&SecretBytes::new(key), &file[22..footer]),
        file[..header_end(&file)],
        "the key read by hand gives this file's MAC"
    );

    let mut keys = std::collections::BTreeSet::new();
    for _ in 0..8 {
        keys.insert(file_key_to_id_a(&public_seal()));
        keys.insert(file_key_by_phrase(&seal_pass(PLAIN, PASS), PASS));
    }
    assert_eq!(keys.len(), 16, "no file key came twice");

    // A retry after a cancel gets a new one, and so does the file route.
    let mut cancelled = Vec::new();
    let stopped = crate::encrypt_stream(&mut &*PLAIN, &mut cancelled, &by_key, &mut |_, _| false);
    assert_eq!(stopped, Err(Error::Cancelled));
    assert!(keys.insert(file_key_to_id_a(&cancelled)));
    assert!(keys.insert(file_key_to_id_a(&public_seal())));

    let t = Temp::new();
    let input = t.file("demo.bin", PLAIN);
    let out = t.sub("out");
    let folder = OutputFolder::open(&out).unwrap();
    for name in ["one.age", "two.age"] {
        crate::encrypt_file(
            SourceFile::open(&input).unwrap(),
            &folder,
            name.as_ref(),
            &by_key,
            &mut keep,
        )
        .unwrap();
        let written = fs::read(out.join(name)).unwrap();
        assert!(keys.insert(file_key_to_id_a(&written)), "{name}");
    }

    // Every other public road: the passphrase at the real cost, and two recipients,
    // each on a stream and on a file. This proves that no key repeats on any road.
    // It does not prove that the keys are random: nothing a test reads can. That
    // rests on the one generator of larsal-crypto, the next test's rule.
    let phrase = secret(PASS);
    let by_phrase = Lock::Passphrase(&phrase);
    let two = [rec(ID_A), rec(ID_B)];
    let by_two = Lock::Recipients(&two);
    let mut sorted = two;
    sorted.sort();
    let id_a_at = sorted.iter().position(|r| *r == two[0]).unwrap();
    let of_two = |file: &[u8]| file_key_of_stanza(&stanzas_of(file)[id_a_at], ID_A);
    let by_stream = |lock: &Lock<'_>| {
        let mut out = Vec::new();
        crate::encrypt_stream(&mut &*PLAIN, &mut out, lock, &mut keep).unwrap();
        out
    };
    let by_file = |lock: &Lock<'_>, name: &str| {
        let source = SourceFile::open(&input).unwrap();
        crate::encrypt_file(source, &folder, name.as_ref(), lock, &mut keep).unwrap();
        fs::read(out.join(name)).unwrap()
    };
    assert!(keys.insert(file_key_by_phrase(&by_stream(&by_phrase), PASS)));
    assert!(keys.insert(file_key_by_phrase(&by_stream(&by_phrase), PASS)));
    assert!(keys.insert(file_key_by_phrase(&by_file(&by_phrase, "p1"), PASS)));
    assert!(keys.insert(file_key_by_phrase(&by_file(&by_phrase, "p2"), PASS)));
    for round in 0..4 {
        assert!(keys.insert(of_two(&by_stream(&by_two))));
        let name = format!("r{round}");
        assert!(keys.insert(of_two(&by_file(&by_two, &name))));
    }

    // Every byte of the key varies, over all the roads: not a few random bits and
    // the rest fixed.
    for at in 0..16 {
        let values: std::collections::BTreeSet<u8> = keys.iter().map(|k| k[at]).collect();
        assert!(values.len() > 1, "byte {at} of the file key never changes");
    }
}

#[test]
fn fil01_t03_both_public_roads_draw_from_the_one_generator() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/encrypt.rs")).unwrap();
    assert_eq!(source.matches("&mut random::bytes").count(), 2);
    assert_eq!(source.matches("random::").count(), 2);
}

#[test]
fn fil01_t03_every_stanza_has_its_own_ephemeral_key_over_the_one_file_key() {
    let (a, b) = (rec(ID_A), rec(ID_B));
    let (third, _) = generate_identity().unwrap();
    let third = Identities::single(&third).unwrap();
    let c = Recipient(third.keys[0].public);
    let file = seal_to(PLAIN, &[a, b, c]);
    let stanzas = stanzas_of(&file);
    let shares: std::collections::BTreeSet<[u8; 32]> = stanzas
        .iter()
        .map(|s| match s {
            Stanza::X25519 { share, .. } => *share,
            _ => panic!("X25519 stanzas only"),
        })
        .collect();
    assert_eq!(shares.len(), 3, "one ephemeral share per stanza");

    // And none of them is the fixed one of another file.
    let again = seal_to(PLAIN, &[a, b, c]);
    for stanza in stanzas_of(&again) {
        let Stanza::X25519 { share, .. } = stanza else {
            panic!("X25519 stanzas only");
        };
        assert!(!shares.contains(&share));
    }

    // Each person's stanza holds the same file key.
    let opened: std::collections::BTreeSet<Vec<u8>> = [(a, ID_A), (b, ID_B)]
        .iter()
        .map(|(recipient, id)| {
            let at = {
                let mut sorted = [a, b, c];
                sorted.sort();
                sorted.iter().position(|r| r == recipient).unwrap()
            };
            file_key_of_stanza(&stanzas[at], id)
        })
        .collect();
    assert_eq!(opened.len(), 1);
}

#[test]
fn fil01_t04_every_public_encrypt_writes_the_cards_cost_of_18() {
    let phrase = secret(PASS);
    let mut by_stream = Vec::new();
    crate::encrypt_stream(
        &mut &*PLAIN,
        &mut by_stream,
        &Lock::Passphrase(&phrase),
        &mut keep,
    )
    .unwrap();

    let t = Temp::new();
    let input = t.file("demo.bin", PLAIN);
    let out = t.sub("out");
    let folder = OutputFolder::open(&out).unwrap();
    crate::encrypt_file(
        SourceFile::open(&input).unwrap(),
        &folder,
        "demo.age".as_ref(),
        &Lock::Passphrase(&phrase),
        &mut keep,
    )
    .unwrap();
    let by_file = fs::read(out.join("demo.age")).unwrap();

    for file in [by_stream, by_file] {
        let stanzas = stanzas_of(&file);
        let [Stanza::Scrypt { log_n, .. }] = &stanzas[..] else {
            panic!("exactly one scrypt stanza");
        };
        assert_eq!(*log_n, 18);
        assert!(matches!(
            snapshot(&file)
                .unlock(&phrase_unlock(&phrase))
                .unwrap()
                .validate(&mut keep),
            Ok(Validation::Ready(_))
        ));
    }
}

#[test]
fn fil01_t14_a_known_type_in_another_case_is_an_unknown_stanza() {
    let phrase = secret(PASS);
    let mut file = seal_pass(PLAIN, PASS);
    let at = file.windows(6).position(|w| w == b"scrypt").unwrap();
    file[at..at + 6].copy_from_slice(b"SCRYPT");
    assert_eq!(
        refused(&file, &phrase_unlock(&phrase)),
        Failure::NoMatch,
        "it matches no credential"
    );
    let keys = identity_a();
    let mut file = seal_to(PLAIN, &[rec(ID_A)]);
    let at = file.windows(6).position(|w| w == b"X25519").unwrap();
    file[at..at + 6].copy_from_slice(b"x25519");
    assert_eq!(refused(&file, &Unlock::Identities(&keys)), Failure::NoMatch);
}

#[test]
fn fil01_t15_list_lines_are_read_as_they_are() {
    let list = |text: String| Identities::from_list(text.as_bytes()).map(|l| l.keys.len());
    assert_eq!(list(format!("{ID_A}\n")), Ok(1));
    assert_eq!(list(ID_A.to_string()), Ok(1), "no final line end");
    assert_eq!(list(format!("{ID_A}\r\n")), Ok(1), "a CRLF line end");
    assert_eq!(list(format!("# a\n\n{ID_A}\n\n# b\n")), Ok(1));
    assert_eq!(list(ID_A.to_lowercase()), Ok(1), "lower case");
    assert_eq!(
        list(format!(" {ID_A}\n")),
        Err(Error::Decrypt),
        "a space first"
    );
    assert_eq!(
        list(format!("{ID_A} \n")),
        Err(Error::Decrypt),
        "a space after"
    );
    assert_eq!(
        list(format!("{ID_A} # c\n")),
        Err(Error::Decrypt),
        "a comment after"
    );
    assert_eq!(
        list(format!("{ID_A}\n   \n")),
        Err(Error::Decrypt),
        "a line of spaces"
    );
    assert_eq!(
        list(format!("{ID_A}\n  # c\n")),
        Err(Error::Decrypt),
        "a comment after spaces"
    );
}
