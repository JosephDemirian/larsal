//! Story E4-S10, card FEA-04: one-time passwords. One test per rule
//! (`fea04_NN_…`), the card's test cases 04-01 to 04-50 inside them.
//!
//! Vector sources: RFC 6238 appendix B (SHA-1, SHA-256, SHA-512) and
//! RFC 4226 appendix D (HOTP counters 0 to 9), as the card lists them;
//! values the card does not list were computed with `python3 -I` (hmac,
//! hashlib, base64) from the same RFCs.
//!
//! The screens (E5-S4, E5-S5) own the parts that are only screen behaviour:
//! the QR picture and its 44-second close (04-44), the code window, and
//! what the copy actions put on the clipboard (04-45 beyond the code).

mod common;

use app_core::edit::{change_entry, edit_entry};
use app_core::refs::{self, Context};
use app_core::totp::{
    self, Algorithm, BadSecret, Choice, Encoder, Form, Problem, Settings, setup_secret,
};
use app_crypto::secret::SecretString;
use app_model::{Entry, Time};
use common::{Berlin, NOW, entry, field, find, id, sample};

const R: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const R32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
const J: &str = "JBSWY3DPEHPK3PXP";
const TIMES: [i64; 6] = [
    59,
    1_111_111_109,
    1_111_111_111,
    1_234_567_890,
    2_000_000_000,
    20_000_000_000,
];

fn r64() -> String {
    format!("{}GEZDGNA=", "GEZDGNBVGY3TQOJQ".repeat(6))
}

fn at(unix: i64) -> Time {
    Time::from_unix(unix).unwrap()
}

fn with(fields: &[(&str, &str)]) -> Entry {
    let mut e = entry(0x40, "Demo");
    for (n, v) in fields {
        e.set_field((*n).to_owned(), field(v));
    }
    e
}

fn otp(text: &str) -> Entry {
    with(&[("otp", text)])
}

fn get(e: &Entry) -> Settings {
    totp::settings(e).expect("settings")
}

fn code(e: &Entry, unix: i64) -> String {
    totp::code_for(e, at(unix)).map_or(String::new(), |c| c.expose().to_owned())
}

fn key_len(e: &Entry) -> usize {
    get(e).key().map_or(0, |k| k.len())
}

fn key_of(e: &Entry) -> Vec<u8> {
    get(e).key().unwrap().expose().to_vec()
}

/// (digits, period, algorithm, encoder, form)
fn shape(s: &Settings) -> (u32, u32, Algorithm, Encoder, Form) {
    (s.digits, s.period, s.algorithm, s.encoder, s.form)
}

#[test]
fn fea04_01_which_form_wins() {
    // 04-22 A: an empty `TOTP Settings` hides a valid `otp`.
    let a = with(&[
        ("TOTP Settings", ""),
        ("otp", &format!("otpauth://totp/a:b?secret={R}")),
    ]);
    assert!(totp::settings(&a).is_none());
    // B: `TOTP Seed` alone gives none.
    assert!(totp::settings(&with(&[("TOTP Seed", R)])).is_none());
    // C: `otp` beats form T.
    let c = with(&[
        ("otp", &format!("otpauth://totp/a:b?secret={R}&digits=8")),
        ("TimeOtp-Secret-Base32", "AAAAAAAA"),
    ]);
    assert_eq!(
        shape(&get(&c)),
        (8, 30, Algorithm::Sha1, Encoder::Decimal, Form::U)
    );
    assert_eq!(code(&c, 59), "94287082");
    // D: `TOTP Settings` holding a link is read as the link; the seed is
    // ignored.
    let d = with(&[
        ("TOTP Seed", "AAAAAAAA"),
        (
            "TOTP Settings",
            &format!("otpauth://totp/Demo:alice?secret={R}&digits=8"),
        ),
    ]);
    assert_eq!(get(&d).digits, 8);
    assert_eq!(code(&d, 59), "94287082");
    // A present field counts whatever its value: an empty `otp` is none and
    // form T is not tried.
    let e = with(&[("otp", ""), ("TimeOtp-Secret-Base32", R)]);
    assert!(totp::settings(&e).is_none());
    // Form T alone, and no fields at all.
    assert_eq!(get(&with(&[("TimeOtp-Secret-Base32", R)])).form, Form::T);
    assert!(totp::settings(&entry(0x41, "plain")).is_none());
}

#[test]
fn fea04_02_settings_are_derived_on_every_change() {
    // 04-48: edit the field without the setup screen; nothing else stored.
    let mut v = sample();
    let link = format!("otpauth://totp/a:b?secret={R}");
    change_entry(&mut v, id(0x10), NOW, |e| {
        e.set_field("otp".into(), field(&link));
    })
    .unwrap();
    assert_eq!(get(find(&v, id(0x10))).digits, 6);
    change_entry(&mut v, id(0x10), NOW, |e| {
        e.set_field("otp".into(), field(&format!("{link}&digits=8")));
    })
    .unwrap();
    assert_eq!(get(find(&v, id(0x10))).digits, 8);
    let names: Vec<&str> = find(&v, id(0x10)).fields().map(|(n, _)| n).collect();
    assert!(names.iter().all(|n| !n.starts_with("TOTP")), "{names:?}");
}

#[test]
fn fea04_03_settings_text_forms_and_clamps() {
    // (a) Form U: scheme without case, nothing trimmed (04-15).
    let up = otp(&format!("OTPAUTH://totp/Demo:alice?secret={R}"));
    assert_eq!(
        shape(&get(&up)),
        (6, 30, Algorithm::Sha1, Encoder::Decimal, Form::U)
    );
    assert_eq!(code(&up, 59), "287082");
    assert!(totp::settings(&otp(&format!(" otpauth://totp/Demo:alice?secret={R}"))).is_none());
    // Names are case-sensitive (04-16): an empty secret, invalid key.
    let upper = get(&otp(&format!("otpauth://totp/Demo:alice?SECRET={R}")));
    assert_eq!(upper.problem(), Some(Problem::InvalidKey));
    // The first item wins; the part after `#` is not query.
    let two = otp(&format!(
        "otpauth://totp/a:b?secret={R}&secret=ABCDEFGH&digits=8#&digits=7"
    ));
    assert_eq!(code(&two, 59), "94287082");
    // Unknown items, issuer, label and counter are ignored.
    let extra = otp(&format!(
        "otpauth://totp/x:y?issuer=z&foo=bar&secret={R}&counter=5"
    ));
    assert_eq!(code(&extra, 59), "287082");
    // No `?`: an empty query, so an empty secret (edge case table).
    let bare = get(&otp("otpauth:secret=GEZDGNBV"));
    assert_eq!(bare.problem(), Some(Problem::InvalidKey));
    // D-04-3: a type other than `totp` or empty is an error state (04-47).
    let hotp = get(&otp(&format!(
        "otpauth://hotp/Demo:alice?secret={R}&counter=5"
    )));
    assert_eq!(hotp.problem(), Some(Problem::UnsupportedType));
    assert!(hotp.code(at(59)).is_none());
    assert_eq!(
        get(&otp(&format!("otpauth://TOTP/a?secret={R}"))).problem(),
        None
    );

    // (b) Form K (04-17), its value decoding (04-18).
    let k = otp(&format!("key={R}&size=8&step=60&otpHashMode=Sha256"));
    assert_eq!(
        shape(&get(&k)),
        (8, 60, Algorithm::Sha256, Encoder::Decimal, Form::K)
    );
    assert_eq!(code(&k, 59), "74875740");
    assert_eq!(code(&k, 1_111_111_109), "69648066");
    let k2 = otp("key=GEZDGNBVGY3TQOJQ%3d&size=6");
    assert_eq!(key_len(&k2), 10);
    assert_eq!(code(&k2, 59), "263420");
    // A bare secret is not form U, has no `key` and no fallback: none.
    assert!(totp::settings(&otp(J)).is_none());

    // (c) Form L (04-19, 04-21, 04-10 and the edge case table).
    let seed = |s: &str| with(&[("TOTP Seed", R), ("TOTP Settings", s)]);
    assert_eq!(code(&seed("30;8"), 59), "94287082");
    for s in ["30", ""] {
        assert_eq!(
            shape(&get(&seed(s))),
            (6, 30, Algorithm::Sha1, Encoder::Decimal, Form::L)
        );
    }
    let steam = get(&seed("60;S"));
    assert_eq!(
        (steam.digits, steam.period, steam.encoder),
        (5, 30, Encoder::Steam)
    );
    assert_eq!(code(&seed("60;S"), 59), "PV9M4");
    assert_eq!(get(&seed("30;S;9")).encoder, Encoder::Steam);
    assert_eq!(
        (get(&seed("abc;def")).period, get(&seed("abc;def")).digits),
        (1, 1)
    );
    assert_eq!(
        (get(&seed("60;s")).period, get(&seed("60;s")).digits),
        (60, 1)
    );
    assert_eq!(get(&seed("30;8;junk")).digits, 8);
    // `TOTP Settings` text that is neither form, with an empty seed: none.
    assert!(totp::settings(&with(&[("TOTP Seed", ""), ("TOTP Settings", "30;6")])).is_none());

    // Clamps (04-13).
    let u = |q: &str| otp(&format!("otpauth://totp/a:b?secret={R}&{q}"));
    assert_eq!(code(&u("digits=0"), 59), "2");
    assert_eq!(code(&u("digits=12"), 59), "1094287082");
    assert_eq!(code(&u("digits=10"), 59), "1094287082");
    assert_eq!(code(&u("period=0"), 59), "083773");
    assert_eq!(code(&u("period=90000"), 59), "755224");
    assert_eq!(get(&u("period=90000")).period, 86_400);
    assert_eq!(get(&otp("key=GEZDGNBV&size=99&step=0")).digits, 10);
    assert_eq!(get(&otp("key=GEZDGNBV&size=99&step=0")).period, 1);
}

#[test]
fn fea04_04_numbers() {
    // 04-14.
    let d = |v: &str| get(&otp(&format!("otpauth://totp/a:b?secret={R}&digits={v}"))).digits;
    assert_eq!(d("8abc"), 1);
    assert_eq!(d("-3"), 1);
    assert_eq!(d("+8"), 8);
    assert_eq!(d("%208"), 8);
    assert_eq!(d("%208%20"), 8);
    assert_eq!(d("++8"), 1);
    assert_eq!(d("0x8"), 1);
    assert_eq!(d("4294967295"), 10);
    assert_eq!(d("4294967296"), 1, "overflow is 0, then clamped");
    assert_eq!(d(""), 1);
    let p = |v: &str| get(&otp(&format!("otpauth://totp/a:b?secret={R}&period={v}"))).period;
    assert_eq!(p("abc"), 1);
    assert_eq!(p("0045"), 45);
}

#[test]
fn fea04_05_percent_decoding() {
    // 04-30: `%3D` and `%26` decode (then cleaning drops them); `%2B` and
    // `%25` stay as three characters, so their digits change the key.
    let s = |v: &str| otp(&format!("otpauth://totp/a:b?secret={v}"));
    let plain = key_of(&s("GEZDGNBVGY3TQOJQ"));
    assert_eq!(key_of(&s("GEZDGNBV%3DGY3TQOJQ")), plain);
    assert_eq!(key_of(&s("GEZDGNBV%26GY3TQOJQ")), plain);
    assert_eq!(
        key_of(&s("GEZDGNBV%2BGY3TQOJQ")),
        key_of(&s("GEZDGNBV2BGY3TQOJQ"))
    );
    assert_eq!(
        key_of(&s("GEZDGNBV%25GY3TQOJQ")),
        key_of(&s("GEZDGNBV25GY3TQOJQ"))
    );
    assert_ne!(key_of(&s("GEZDGNBV%2BGY3TQOJQ")), plain);
    // `+` stays `+` (then dropped by cleaning); `%C3%A9` is one character,
    // dropped too; a broken escape stays literal.
    assert_eq!(key_of(&s("GEZDGNBV+GY3TQOJQ")), plain);
    assert_eq!(key_of(&s("GEZDGNBV%C3%A9GY3TQOJQ")), plain);
    assert_eq!(key_of(&s("GEZDGNBV%GY3TQOJQ")), plain);
    assert_eq!(
        key_of(&s("GEZDGNBV%4GY3TQOJ")),
        key_of(&s("GEZDGNBV4GY3TQOJ"))
    );
    // Escapes of letters decode (`%38` is `8`, cleaned to `B`).
    assert_eq!(
        key_of(&s("GEZDGNBVGY3TQOJ%38")),
        key_of(&s("GEZDGNBVGY3TQOJB"))
    );
    // Form K decodes too (04-18), and an escaped `&` does not split items.
    assert_eq!(get(&otp("key=GEZDGNBV&size=%38")).digits, 8);
    assert_eq!(
        key_of(&otp("key=GEZDGNBV%26size=8&size=7")),
        key_of(&otp("key=GEZDGNBVSIZEB"))
    );
    // A bad UTF-8 escape is U+FFFD, dropped by cleaning.
    assert_eq!(key_of(&s("GEZDGNBV%FFGY3TQOJQ")), plain);
}

#[test]
fn fea04_05_control_escapes_make_the_secret_invalid() {
    // LD-128: an escape of a control character (%00 to %1F, %7F, any hex
    // case) in a decoded secret: invalid key, no code, the setup banner.
    for esc in [
        "%00", "%01", "%09", "%0A", "%0d", "%1F", "%1f", "%7F", "%7f",
    ] {
        for text in [
            format!("otpauth://totp/a:b?secret=GEZDGNBV{esc}GY3TQOJQ"),
            format!("key=GEZDGNBV{esc}GY3TQOJQ&size=6"),
        ] {
            let e = otp(&text);
            let s = get(&e);
            assert_eq!(s.problem(), Some(Problem::InvalidKey), "{text}");
            assert!(
                s.key().is_none() && totp::code_for(&e, at(59)).is_none(),
                "{text}"
            );
            assert!(totp::prefill(&e).invalid, "{text}");
        }
    }
    // Other escapes stay valid, and so do control escapes outside the
    // secret or in a form that is not decoded.
    for text in [
        "otpauth://totp/a:b?secret=GEZDGNBV%20GY3TQOJQ",
        "otpauth://totp/a:b?secret=GEZDGNBV%7EGY3TQOJQ",
        "otpauth://totp/a:b?secret=GEZDGNBV%80GY3TQOJQ",
        "otpauth://totp/a%00:b?secret=GEZDGNBVGY3TQOJQ&issuer=%0A",
    ] {
        assert_eq!(get(&otp(text)).problem(), None, "{text}");
    }
    let legacy = with(&[
        ("TOTP Seed", "GEZDGNBV%00GY3TQOJQ"),
        ("TOTP Settings", "30;6"),
    ]);
    assert_eq!(
        get(&legacy).problem(),
        None,
        "form L is not percent-decoded"
    );
}

#[test]
fn fea04_06_algorithm_and_encoder_names() {
    // 04-12.
    let a = |n: &str| {
        otp(&format!(
            "otpauth://totp/a:b?secret={R}&digits=8&algorithm={n}"
        ))
    };
    assert_eq!(code(&a("sha256"), 59), "32247374");
    assert_eq!(code(&a("SHA-256"), 59), "94287082");
    assert_eq!(code(&a("HmAc-ShA-512"), 59), "69342147");
    assert_eq!(code(&a("SHA1"), 59), "94287082");
    assert_eq!(get(&a("HMAC-SHA-256")).algorithm, Algorithm::Sha256);
    assert_eq!(get(&a("sha512")).algorithm, Algorithm::Sha512);
    assert_eq!(get(&a("")).algorithm, Algorithm::Sha1);
    // 04-11: only exactly `steam` is Steam.
    let e = |n: &str, d: &str| otp(&format!("otpauth://totp/a:b?secret={R}&encoder={n}{d}"));
    assert_eq!(code(&e("STEAM", "&digits=5"), 59), "87082");
    assert_eq!(code(&e("S", ""), 59), "287082");
    // 04-09: the encoder does not change the digits.
    assert_eq!(code(&e("steam", ""), 59), "PV9M4J");
}

#[test]
fn fea04_07_form_t() {
    // 04-23.
    let t = |more: &[(&str, &str)]| {
        let mut f = vec![("TimeOtp-Secret-Base32", R)];
        f.extend_from_slice(more);
        with(&f)
    };
    let e = t(&[
        ("TimeOtp-Length", "8"),
        ("TimeOtp-Algorithm", "HMAC-SHA-512"),
    ]);
    assert_eq!(code(&e, 59), "69342147");
    assert_eq!(get(&e).form, Form::T);
    // 04-24.
    assert_eq!(
        get(&t(&[("TimeOtp-Length", "0")])).problem(),
        Some(Problem::InvalidDigits)
    );
    assert_eq!(
        get(&t(&[("TimeOtp-Period", "0")])).problem(),
        Some(Problem::InvalidStep)
    );
    assert_eq!(
        get(&t(&[("TimeOtp-Period", "abc")])).problem(),
        Some(Problem::InvalidStep)
    );
    assert!(totp::settings(&with(&[("TimeOtp-Secret-Base32", "")])).is_none());
    // Empty values keep the defaults.
    let empty = t(&[
        ("TimeOtp-Length", ""),
        ("TimeOtp-Period", ""),
        ("TimeOtp-Algorithm", ""),
    ]);
    assert_eq!(
        shape(&get(&empty)),
        (6, 30, Algorithm::Sha1, Encoder::Decimal, Form::T)
    );
    // One hyphen is not a known name.
    assert_eq!(
        get(&t(&[("TimeOtp-Algorithm", "SHA-256")])).algorithm,
        Algorithm::Sha1
    );
    // 04-25 with D-04-8: large values are clamped, no huge allocation.
    assert_eq!(code(&t(&[("TimeOtp-Length", "12")]), 59), "1094287082");
    assert_eq!(
        code(&t(&[("TimeOtp-Length", "4294967295")]), 59),
        "1094287082"
    );
    let long = t(&[("TimeOtp-Period", "4000000000"), ("TimeOtp-Length", "10")]);
    assert_eq!(get(&long).period, 86_400);
    assert_eq!(code(&long, 59), "1284755224");
}

#[test]
fn fea04_08_defaults() {
    // 04-49.
    let e = otp(&format!("otpauth://totp/a:b?secret={R}"));
    assert_eq!(
        shape(&get(&e)),
        (6, 30, Algorithm::Sha1, Encoder::Decimal, Form::U)
    );
    assert_eq!(code(&e, 59), "287082");
    assert!(!get(&e).is_custom());
}

#[test]
fn fea04_09_base32_secret() {
    let s = |v: &str| otp(&format!("otpauth://totp/a:b?secret={v}"));
    // 04-26: 0 is O, 1 is L, 8 is B.
    assert_eq!(
        key_of(&s("GEZDGNBVGY3TQ0J8")),
        key_of(&s("GEZDGNBVGY3TQOJB"))
    );
    assert_eq!(key_of(&s("MZXW1")), key_of(&s("MZXWL")));
    // 04-27: trailing bits ignored.
    assert_eq!(key_of(&s("GEZDGNBVGY3TQOJ")), key_of(&s("GEZDGNBVGY3TQOK")));
    assert_eq!(key_len(&s("GEZDGNBVGY3TQOJ")), 9);
    assert_eq!(code(&s("GEZDGNBVGY3TQOK"), 59), "053248");
    // 04-28: `9` dropped.
    assert_eq!(key_len(&s("GEZDGNBVGY3TQOJ9")), 9);
    assert_eq!(code(&s("GEZDGNBVGY3TQOJ9"), 59), "053248");
    // 04-29: lengths 1, 3 and 6 modulo 8.
    for bad in ["ABC", "GEZDGNBVG", "GEZDGN", "A"] {
        assert_eq!(get(&s(bad)).problem(), Some(Problem::InvalidKey), "{bad}");
    }
    // Lengths 2, 4, 5, 7 pad and decode to 1, 2, 3, 4 bytes; letters in
    // any case.
    for (text, n) in [("GE", 1), ("GEZD", 2), ("GEZDG", 3), ("GEZDGNB", 4)] {
        assert_eq!(key_len(&s(text)), n, "{text}");
    }
    assert_eq!(
        key_of(&s("gezdgnbvgy3tqojq")),
        key_of(&s("GEZDGNBVGY3TQOJQ"))
    );
    // Edge case table: `=`, `+` and `é` inside are dropped.
    let plain = key_of(&s("GEZDGNBVGY3TQOJQ"));
    for odd in [
        "GEZDGNBV=GY3TQOJQ",
        "GEZDGNBV+GY3TQOJQ",
        "GEZDGNBV\u{e9}GY3TQOJQ",
    ] {
        assert_eq!(key_of(&s(odd)), plain, "{odd}");
    }
    // 04-20: spaces in a form L seed.
    let l = with(&[
        ("TOTP Seed", "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"),
        ("TOTP Settings", "30;6"),
    ]);
    assert_eq!(code(&l, 59), "287082");
    // The RFC seeds decode to the RFC keys.
    assert_eq!(key_of(&s(R)), b"12345678901234567890");
    assert_eq!(key_of(&s(R32)), b"12345678901234567890123456789012");
}

#[test]
fn fea04_10_validity_and_its_order() {
    // 04-31 with D-04-1: an empty secret is invalid key, no code.
    for text in ["otpauth://totp/x?issuer=y", "key="] {
        let s = get(&otp(text));
        assert_eq!(s.problem(), Some(Problem::InvalidKey), "{text}");
        assert!(s.code(at(59)).is_none());
        assert!(totp::code_for(&otp(text), at(59)).is_none());
    }
    // A secret of only dropped characters: empty key bytes, invalid key.
    assert_eq!(
        get(&otp("otpauth://totp/x?secret=9999")).problem(),
        Some(Problem::InvalidKey)
    );
    // Order: type, key, step, digits.
    let both = with(&[
        ("TimeOtp-Secret-Base32", "ABC"),
        ("TimeOtp-Period", "0"),
        ("TimeOtp-Length", "0"),
    ]);
    assert_eq!(get(&both).problem(), Some(Problem::InvalidKey));
    let step_digits = with(&[
        ("TimeOtp-Secret-Base32", R),
        ("TimeOtp-Period", "0"),
        ("TimeOtp-Length", "0"),
    ]);
    assert_eq!(get(&step_digits).problem(), Some(Problem::InvalidStep));
    assert!(get(&step_digits).seconds_left(at(59)).is_none());
    let hotp_bad = get(&otp("otpauth://hotp/x?secret=ABC"));
    assert_eq!(hotp_bad.problem(), Some(Problem::UnsupportedType));
}

#[test]
fn fea04_11_rfc_6238_and_rfc_4226_vectors() {
    // 04-01 SHA-1.
    let sha1 = otp(&format!("otpauth://totp/a:b?secret={R}&digits=8"));
    let want1 = [
        "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
    ];
    // 04-02 SHA-256.
    let sha256 = otp(&format!(
        "otpauth://totp/a:b?secret={R32}&digits=8&algorithm=SHA256"
    ));
    let want256 = [
        "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
    ];
    // 04-03 SHA-512.
    let sha512 = otp(&format!(
        "otpauth://totp/a:b?secret={}&digits=8&algorithm=SHA512",
        r64()
    ));
    let want512 = [
        "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
    ];
    for (i, t) in TIMES.iter().enumerate() {
        assert_eq!(code(&sha1, *t), want1[i], "SHA-1 at {t}");
        assert_eq!(code(&sha256, *t), want256[i], "SHA-256 at {t}");
        assert_eq!(code(&sha512, *t), want512[i], "SHA-512 at {t}");
    }
    assert_eq!(key_len(&sha512), 64);
    // 04-04 RFC 4226 through the counter: time 0 is counter 0, not "now".
    let hotp = otp(&format!("otpauth://totp/a:b?secret={R}"));
    let want = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (n, w) in want.iter().enumerate() {
        assert_eq!(code(&hotp, 30 * n as i64), *w, "counter {n}");
    }
    // 04-05.
    let demo = otp(&format!(
        "otpauth://totp/Demo:alice?secret={R}&period=30&digits=6&issuer=Demo"
    ));
    assert_eq!(code(&demo, 59), "287082");
    assert_eq!(code(&demo, 1_234_567_890), "005924");
    // 04-06 the demo entry.
    let full = otp(&format!("otpauth://totp/Demo:demo-user?secret={J}"));
    for (t, w) in [
        (59, "996554"),
        (1_700_000_000, "324550"),
        (1_700_000_009, "324550"),
        (1_700_000_010, "367665"),
    ] {
        assert_eq!(code(&full, t), w, "at {t}");
    }
    // Before 1970 there is no code.
    assert!(get(&full).code(at(-1)).is_none());
}

#[test]
fn fea04_12_decimal_code() {
    // 10 digits is V itself, padded; fewer digits keep leading zeros.
    let u = |d: u32| otp(&format!("otpauth://totp/a:b?secret={R}&digits={d}"));
    assert_eq!(code(&u(10), 59), "1094287082");
    assert_eq!(code(&u(7), 59), "4287082");
    assert_eq!(code(&u(6), 1_234_567_890), "005924");
    assert_eq!(code(&u(8), 1_111_111_109), "07081804");
}

#[test]
fn fea04_13_steam_code() {
    // 04-08.
    let e = otp(&format!(
        "otpauth://totp/a:b?secret={R}&encoder=steam&digits=5"
    ));
    for (t, w) in [
        (59, "PV9M4"),
        (1_111_111_109, "PY4YB"),
        (1_234_567_890, "VHHQY"),
        (2_000_000_000, "9N776"),
    ] {
        assert_eq!(code(&e, t), w, "at {t}");
    }
    // Other lengths use that count, least significant symbol first.
    let ten = otp(&format!(
        "otpauth://totp/a:b?secret={R}&encoder=steam&digits=10"
    ));
    assert_eq!(code(&ten, 59), "PV9M4J5222");
}

#[test]
fn fea04_14_seconds_left() {
    // 04-07.
    let s = get(&otp(&format!("otpauth://totp/a:b?secret={R}")));
    for (t, r) in [
        (1_700_000_000, 10),
        (1_700_000_009, 1),
        (1_700_000_010, 30),
        (1_700_000_039, 1),
    ] {
        assert_eq!(s.seconds_left(at(t)), Some(r), "at {t}");
    }
    let p1 = get(&otp(&format!("otpauth://totp/a:b?secret={R}&period=1")));
    assert_eq!(p1.seconds_left(at(59)), Some(1));
    assert!(s.seconds_left(at(-5)).is_none());
}

#[test]
fn fea04_15_display_space() {
    // 04-42.
    for (c, shown) in [
        ("287082", "287 082"),
        ("94287082", "9428 7082"),
        ("PV9M4", "PV 9M4"),
        ("1094287082", "10942 87082"),
        ("1234567", "123 4567"),
        ("2", "2"),
        ("", ""),
    ] {
        assert_eq!(totp::display(c).expose(), shown);
    }
    // Copy, type and placeholders use the code without the space.
    let e = otp(&format!("otpauth://totp/a:b?secret={R}"));
    assert!(!code(&e, 59).contains(' '));
}

/// The setup screen's controls for `choice` with `secret` typed.
fn setup(e: &Entry, secret: &str, choice: Choice) -> totp::Setup {
    let mut s = totp::prefill(e);
    s.secret = SecretString::new(secret.to_owned());
    s.choice = choice;
    s
}

fn save(e: &mut Entry, s: &totp::Setup, title: &str, user: &str) {
    let secret = setup_secret(s.secret.expose()).unwrap().unwrap();
    totp::write(e, &secret, s, title, user);
}

fn custom(e: &Entry, secret: &str, algorithm: Algorithm, period: u32, digits: u32) -> totp::Setup {
    let mut s = setup(e, secret, Choice::Custom);
    (s.algorithm, s.period, s.digits) = (algorithm, period, digits);
    s
}

fn value<'a>(e: &'a Entry, name: &str) -> Option<(&'a str, bool)> {
    e.field(name).map(|f| (f.value.expose(), f.protected))
}

#[test]
fn fea04_16_which_form_save_writes() {
    // None: form U (04-32).
    let mut e = entry(0x42, "Demo Site");
    let st = setup(&e, "jbsw y3dp ehpk 3px", Choice::Standard);
    save(&mut e, &st, "Demo Site", "alice@example.com");
    assert_eq!(get(&e).form, Form::U);
    assert!(value(&e, "TOTP Seed").is_none() && value(&e, "TOTP Settings").is_none());
    // Form L stays L for Standard and Steam (04-35), becomes U for Custom
    // (04-36).
    let legacy = || with(&[("TOTP Seed", J), ("TOTP Settings", "30;6")]);
    let mut l = legacy();
    let st = setup(&l, J, Choice::Steam);
    save(&mut l, &st, "t", "u");
    assert_eq!(get(&l).form, Form::L);
    let mut l = legacy();
    let st = custom(&l, J, Algorithm::Sha1, 30, 7);
    save(&mut l, &st, "t", "u");
    assert_eq!(get(&l).form, Form::U);
    assert!(value(&l, "TOTP Seed").is_none() && value(&l, "TOTP Settings").is_none());
    // Form K stays K for Standard and Custom (04-37); Steam writes U
    // (D-04-6).
    let mut k = otp(&format!("key={J}&size=6&step=30"));
    let st = setup(&k, J, Choice::Standard);
    save(&mut k, &st, "t", "u");
    assert_eq!(get(&k).form, Form::K);
    let mut k = otp(&format!("key={J}&size=6&step=30"));
    let st = setup(&k, J, Choice::Steam);
    save(&mut k, &st, "t", "u");
    assert_eq!(get(&k).form, Form::U);
    assert_eq!(get(&k).encoder, Encoder::Steam);
    // Form T: U, and the four form T fields are removed (D-04-7).
    let mut t = with(&[
        ("TimeOtp-Secret-Base32", R),
        ("TimeOtp-Algorithm", "SHA512"),
        ("TimeOtp-Length", "8"),
        ("TimeOtp-Period", "30"),
    ]);
    let st = setup(&t, J, Choice::Standard);
    save(&mut t, &st, "t", "u");
    assert_eq!(get(&t).form, Form::U);
    assert!(t.fields().all(|(n, _)| !n.starts_with("TimeOtp-")));
    // Form U stays U.
    let mut u = otp(&format!("otpauth://totp/a:b?secret={R}"));
    let st = setup(&u, J, Choice::Custom);
    save(&mut u, &st, "t", "u");
    assert_eq!(get(&u).form, Form::U);
}

#[test]
fn fea04_17_form_u_text() {
    // Custom values out of range are written clamped (FEA-04.3 bounds).
    for (digits, period, want) in [
        (0, 0, "&period=1&digits=1&"),
        (99, 100_000, "&period=86400&digits=10&"),
    ] {
        let mut c = entry(0x49, "C");
        let st = custom(&c, J, Algorithm::Sha1, period, digits);
        save(&mut c, &st, "C", "u");
        assert!(value(&c, "otp").unwrap().0.contains(want), "{want}");
    }
    // 04-32: percent-encoded title and user, padded secret, protected.
    let mut e = entry(0x42, "Demo Site");
    let st = setup(&e, "jbsw y3dp ehpk 3px", Choice::Standard);
    save(&mut e, &st, "Demo Site", "alice@example.com");
    assert_eq!(
        value(&e, "otp"),
        Some((
            "otpauth://totp/Demo%20Site:alice%40example.com?secret=JBSWY3DPEHPK3PX%3D&period=30&digits=6&issuer=Demo%20Site",
            true
        ))
    );
    // 04-33: empty user is `none`; the hash item.
    let mut b = entry(0x43, "Bank");
    let st = custom(&b, J, Algorithm::Sha256, 60, 8);
    save(&mut b, &st, "Bank", "");
    assert_eq!(
        value(&b, "otp").unwrap().0,
        "otpauth://totp/Bank:none?secret=JBSWY3DPEHPK3PXP&period=60&digits=8&issuer=Bank&algorithm=SHA256"
    );
    assert_eq!(code(&b, 59), "96023015");
    // 04-34 with D-04-2: empty title is `App`; Steam.
    let mut s = entry(0x44, "");
    let st = setup(&s, J, Choice::Steam);
    save(&mut s, &st, "", "bob");
    assert_eq!(
        value(&s, "otp").unwrap().0,
        "otpauth://totp/App:bob?secret=JBSWY3DPEHPK3PXP&period=30&digits=5&issuer=App&encoder=steam"
    );
    assert_eq!(code(&s, 59), "2YXGV");
    // Every byte but the unreserved ones is escaped, in uppercase hex.
    let mut odd = entry(0x45, "x");
    let st = custom(&odd, J, Algorithm::Sha512, 30, 6);
    save(&mut odd, &st, "a:b/é~_.-", "u v");
    assert_eq!(
        value(&odd, "otp").unwrap().0,
        "otpauth://totp/a%3Ab%2F%C3%A9~_.-:u%20v?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=a%3Ab%2F%C3%A9~_.-&algorithm=SHA512"
    );
}

#[test]
fn fea04_18_form_k_text() {
    // 04-37.
    let mut k = otp(&format!("key={J}&size=6&step=30"));
    let st = custom(&k, J, Algorithm::Sha512, 30, 6);
    save(&mut k, &st, "t", "u");
    assert_eq!(
        value(&k, "otp"),
        Some((
            "key=JBSWY3DPEHPK3PXP&size=6&step=30&otpHashMode=SHA512",
            true
        ))
    );
    // Padded, not percent-encoded.
    let mut p = otp("key=GEZDGNBV&size=6&step=30");
    let st = custom(&p, "JBSWY3DPEHPK3PX", Algorithm::Sha256, 45, 7);
    save(&mut p, &st, "t", "u");
    assert_eq!(
        value(&p, "otp").unwrap().0,
        "key=JBSWY3DPEHPK3PX=&size=7&step=45&otpHashMode=SHA256"
    );
    // FEA-04.9 padding of every decodable length: 2, 4, 5 and 7 symbols
    // (modulo 8) get 6, 4, 3 and 1 `=`.
    for (secret, padded) in [
        ("GE", "GE======"),
        ("GEZD", "GEZD===="),
        ("GEZDG", "GEZDG==="),
        ("GEZDGNB", "GEZDGNB="),
        ("GEZDGNBV", "GEZDGNBV"),
    ] {
        let mut e = otp("key=GEZDGNBV&size=6&step=30");
        let st = custom(&e, secret, Algorithm::Sha1, 30, 6);
        save(&mut e, &st, "t", "u");
        assert_eq!(
            value(&e, "otp").unwrap().0,
            format!("key={padded}&size=6&step=30")
        );
        let u = get(&otp(&format!("otpauth://totp/a?secret={secret}"))).uri("t", "u");
        assert!(
            u.expose()
                .contains(&format!("secret={}&", padded.replace('=', "%3D"))),
            "{secret}"
        );
    }
}

#[test]
fn fea04_19_form_l_text() {
    // 04-35.
    let mut l = with(&[("TOTP Seed", J), ("TOTP Settings", "30;6")]);
    let st = setup(&l, J, Choice::Steam);
    save(&mut l, &st, "t", "u");
    assert_eq!(value(&l, "TOTP Seed"), Some((J, true)));
    assert_eq!(value(&l, "TOTP Settings"), Some(("30;S", false)));
    assert!(value(&l, "otp").is_none());
    assert_eq!(code(&l, 59), "2YXGV");
    let mut s = with(&[("TOTP Seed", J), ("TOTP Settings", "30;S")]);
    let st = setup(&s, "jbsw y3dp ehpk 3pxp", Choice::Standard);
    save(&mut s, &st, "t", "u");
    assert_eq!(value(&s, "TOTP Settings"), Some(("30;6", false)));
    assert_eq!(
        value(&s, "TOTP Seed"),
        Some((J, true)),
        "stored cleaned, uppercase"
    );
    // The seed is stored without the padding (FEA-04.22).
    let mut p = with(&[("TOTP Seed", J), ("TOTP Settings", "30;6")]);
    let st = setup(&p, "jbsw y3dp ehpk 3px", Choice::Standard);
    save(&mut p, &st, "t", "u");
    assert_eq!(value(&p, "TOTP Seed"), Some(("JBSWY3DPEHPK3PX", true)));
}

#[test]
fn fea04_20_remove_is_one_change() {
    // 04-40, with D-04-7: form T goes too; one history item.
    let mut v = sample();
    change_entry(&mut v, id(0x10), NOW, |e| {
        e.set_field(
            "otp".into(),
            field(&format!("otpauth://totp/a:b?secret={R}")),
        );
        e.set_field("TOTP Seed".into(), field(R));
        e.set_field("TimeOtp-Secret-Base32".into(), field(R));
        e.set_field("TimeOtp-Length".into(), field("8"));
    })
    .unwrap();
    let before = find(&v, id(0x10)).history.len();
    assert!(edit_entry(&mut v, id(0x10), NOW, totp::remove).unwrap());
    let e = find(&v, id(0x10));
    assert!(totp::settings(e).is_none());
    assert!(
        e.fields()
            .all(|(n, _)| n != "otp" && !n.starts_with("TOTP") && !n.starts_with("TimeOtp-"))
    );
    assert_eq!(e.history.len(), before + 1);
    // Removing from an entry without one changes nothing.
    assert!(!edit_entry(&mut v, id(0x10), NOW, totp::remove).unwrap());
    // LD-125: every `TimeOtp-` field goes, on Remove and on Save, also
    // ones App never reads; other fields stay.
    let others = [
        ("TimeOtp-Secret", "plain secret"),
        ("TimeOtp-Secret-Hex", "3132"),
        ("TimeOtp-Secret-Base64", "MTI="),
        ("TimeOtp-Whatever", "x"),
        ("TimeOtpNoDash", "kept"),
        ("Plain", "kept"),
    ];
    let mut r = with(&others);
    r.set_field("otp".into(), field(&format!("otpauth://totp/a?secret={R}")));
    totp::remove(&mut r);
    let left: Vec<&str> = r
        .fields()
        .map(|(n, _)| n)
        .filter(|n| !STANDARD.contains(n))
        .collect();
    assert_eq!(left, ["Plain", "TimeOtpNoDash"]);
    let mut w = with(&others);
    let st = setup(&w, J, Choice::Standard);
    save(&mut w, &st, "t", "u");
    let left: Vec<&str> = w
        .fields()
        .map(|(n, _)| n)
        .filter(|n| !STANDARD.contains(n))
        .collect();
    assert_eq!(left, ["Plain", "TimeOtpNoDash", "otp"]);
}

const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

#[test]
fn fea04_21_custom_settings() {
    let s = |q: &str| get(&otp(&format!("otpauth://totp/a:b?secret={R}{q}")));
    assert!(!s("").is_custom());
    assert!(!s("&digits=6&period=30&algorithm=SHA1").is_custom());
    assert!(s("&digits=8").is_custom());
    assert!(s("&period=60").is_custom());
    assert!(s("&algorithm=SHA256").is_custom());
    assert!(s("&encoder=steam&digits=5").is_custom());
    assert!(s("&encoder=steam&digits=6").is_custom(), "Steam is custom");
}

#[test]
fn fea04_22_setup_screen() {
    // 04-39 with D-04-5.
    for bad in [
        "JBSWY3DP-EHPK3PXP",
        "JBSWY3DPEHPK3PX1",
        "ABC",
        "A",
        "GEZDGN",
        "GEZDGNBVG",
        "JBSWY3DP\tEHPK3PXP",
        "JBSWYé",
    ] {
        assert_eq!(setup_secret(bad).err(), Some(BadSecret), "{bad}");
    }
    // Uppercased, spaces and `=` removed, ends trimmed.
    for good in [
        "jbsw y3dp ehpk 3pxp",
        " JBSWY3DPEHPK3PXP\n",
        "JBSWY3DPEHPK3PXP==",
        "jbswy3dpehpk3px",
    ] {
        assert!(setup_secret(good).unwrap().is_some(), "{good}");
    }
    // Empty: no secret; the caller confirms and removes (04-40).
    assert!(setup_secret("  = ").unwrap().is_none());
    assert!(setup_secret("").unwrap().is_none());
    // 04-41 pre-fill.
    let e = otp("otpauth://totp/a:b?secret=JBSWY3DPEHPK3PXP%3D%3D&period=45&digits=8");
    let p = totp::prefill(&e);
    assert_eq!(p.secret.expose(), J);
    assert_eq!(
        (p.choice, p.period, p.digits, p.algorithm, p.invalid),
        (Choice::Custom, 45, 8, Algorithm::Sha1, false)
    );
    // Steam pre-fills Steam; default settings Standard; none: empty.
    let steam = totp::prefill(&otp(&format!(
        "otpauth://totp/a:b?secret={J}&encoder=steam&digits=5"
    )));
    assert_eq!(steam.choice, Choice::Steam);
    let std = totp::prefill(&otp(&format!("otpauth://totp/a:b?secret={J}")));
    assert_eq!(
        (std.choice, std.period, std.digits),
        (Choice::Standard, 30, 6)
    );
    let none = totp::prefill(&entry(0x46, "x"));
    assert_eq!(
        (none.secret.expose(), none.choice, none.invalid),
        ("", Choice::Standard, false)
    );
    // The banner shows for settings in an error state.
    assert!(totp::prefill(&otp("otpauth://totp/a:b?secret=ABC")).invalid);
    // D-04-12: digits outside 6..10 stay unless the user changes them.
    let mut five = otp(&format!("key={J}&size=5&step=30"));
    let kept = totp::prefill(&five);
    assert_eq!((kept.choice, kept.digits), (Choice::Custom, 5));
    save(&mut five, &kept, "t", "u");
    assert_eq!(get(&five).digits, 5);
    // Values used: Standard 6/30/SHA-1 whatever the Custom controls hold.
    let mut s = otp(&format!(
        "otpauth://totp/a:b?secret={J}&digits=8&period=60&algorithm=SHA512"
    ));
    let mut st = totp::prefill(&s);
    st.choice = Choice::Standard;
    save(&mut s, &st, "t", "u");
    assert_eq!(
        shape(&get(&s)),
        (6, 30, Algorithm::Sha1, Encoder::Decimal, Form::U)
    );
}

#[test]
fn fea04_38_written_text_reads_back_the_same_settings() {
    // 04-38: every form Save writes gives back the saved settings.
    let cases: Vec<(Entry, totp::Setup)> = {
        let fresh = entry(0x47, "T");
        let legacy = with(&[("TOTP Seed", J), ("TOTP Settings", "30;6")]);
        let k = otp(&format!("key={J}&size=6&step=30"));
        vec![
            (fresh.duplicate(false), setup(&fresh, J, Choice::Standard)),
            (fresh.duplicate(false), setup(&fresh, J, Choice::Steam)),
            (
                fresh.duplicate(false),
                custom(&fresh, J, Algorithm::Sha256, 60, 8),
            ),
            (legacy.duplicate(false), setup(&legacy, J, Choice::Steam)),
            (legacy.duplicate(false), setup(&legacy, J, Choice::Standard)),
            (
                legacy.duplicate(false),
                custom(&legacy, J, Algorithm::Sha1, 30, 7),
            ),
            (k.duplicate(false), custom(&k, J, Algorithm::Sha512, 30, 6)),
            (
                k.duplicate(false),
                custom(&k, "JBSWY3DPEHPK3PX", Algorithm::Sha256, 86_400, 10),
            ),
        ]
    };
    for (i, (mut e, s)) in cases.into_iter().enumerate() {
        save(&mut e, &s, "Title", "user");
        let back = get(&e);
        let want = match s.choice {
            Choice::Standard => (6, 30, Algorithm::Sha1, Encoder::Decimal),
            Choice::Steam => (5, 30, Algorithm::Sha1, Encoder::Steam),
            Choice::Custom => (s.digits, s.period, s.algorithm, Encoder::Decimal),
        };
        assert_eq!(
            (back.digits, back.period, back.algorithm, back.encoder),
            want,
            "case {i}"
        );
        let typed = setup_secret(s.secret.expose()).unwrap().unwrap();
        let mut probe = entry(0x48, "p");
        totp::write(&mut probe, &typed, &s, "", "");
        assert_eq!(
            back.key().unwrap().expose(),
            get(&probe).key().unwrap().expose(),
            "case {i}"
        );
        assert_eq!(back.problem(), None, "case {i}");
    }
}

#[test]
fn fea04_23_qr_content_and_note() {
    // 04-43: always form U from the current settings, title unresolved.
    let e = {
        let mut e = with(&[
            ("TOTP Seed", J),
            ("TOTP Settings", "30;6"),
            ("UserName", "alice"),
        ]);
        e.set_field("Title".into(), field("{USERNAME} site"));
        e
    };
    let s = get(&e);
    assert_eq!(
        s.uri(e.value("Title"), e.value("UserName")).expose(),
        "otpauth://totp/%7BUSERNAME%7D%20site:alice?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=%7BUSERNAME%7D%20site"
    );
    assert!(!s.is_custom(), "no custom note");
    // 04-44: Steam settings show the note.
    assert!(
        get(&otp(&format!(
            "otpauth://totp/a:b?secret={J}&encoder=steam&digits=5"
        )))
        .is_custom()
    );
    // The content reads back as the same settings.
    let k = get(&otp(&format!("key={R}&size=8&step=60&otpHashMode=Sha256")));
    let back = otp(k.uri("a", "b").expose());
    assert_eq!(code(&back, 59), "74875740");
    assert_eq!(get(&back).form, Form::U);
}

#[test]
fn fea04_24_actions_get_codes_only_from_valid_settings() {
    // 04-45, the part the core owns: A gives its code; B (invalid) and C
    // (none) give nothing, so copy does nothing or opens setup (E5-S4).
    let a = with(&[
        ("otp", &format!("otpauth://totp/a:b?secret={R}")),
        ("Password", "pw"),
    ]);
    assert_eq!(code(&a, 59), "287082");
    let b = otp("otpauth://totp/x?secret=ABC");
    assert!(
        totp::settings(&b).is_some(),
        "B has settings: copy opens setup"
    );
    assert!(totp::code_for(&b, at(59)).is_none());
    let c = entry(0x49, "C");
    assert!(totp::settings(&c).is_none() && totp::code_for(&c, at(59)).is_none());
    // Copy password and code: the password resolved, then the code.
    let ctx = Context {
        otp: totp::code_for,
        ..Context::new(None, at(59))
    };
    assert_eq!(
        refs::resolve("{PASSWORD}{TOTP}", &a, &ctx).text.expose(),
        "pw287082"
    );
}

#[test]
fn fea04_25_placeholder() {
    // 04-46 with D-04-4 and D-04-11.
    let ctx = Context {
        otp: totp::code_for,
        ..Context::new(None, at(59))
    };
    let res = |e: &Entry, t: &str| refs::resolve(t, e, &ctx).text.expose().to_owned();
    let a = otp(&format!("otpauth://totp/a:b?secret={R}"));
    assert_eq!(
        res(&a, "a{TOTP}b|{totp}|{TIMEOTP}"),
        "a287082b|287082|287082"
    );
    assert_eq!(res(&otp("otpauth://totp/x?secret=ABC"), "x{TOTP}y"), "xy");
    assert_eq!(res(&entry(0x4a, "C"), "x{TOTP}y"), "xy");
}

#[test]
fn fea04_26_clock_is_utc_seconds() {
    // 04-50: the code takes UTC seconds; a local zone never enters.
    let e = otp(&format!("otpauth://totp/a:b?secret={R}"));
    assert_eq!(code(&e, 1_234_567_890), "005924");
    let ctx = Context {
        otp: totp::code_for,
        zone: &Berlin,
        ..Context::new(None, at(1_234_567_890))
    };
    assert_eq!(refs::resolve("{TOTP}", &e, &ctx).text.expose(), "005924");
}

#[test]
fn fea04_security_secret_never_in_debug_text() {
    let s = get(&otp(&format!("otpauth://totp/a:b?secret={J}")));
    let text = format!("{s:?}");
    assert!(!text.contains(J) && !text.contains("JBSW"), "{text}");
    assert!(text.contains("digits: 6"));
}

#[test]
fn fea04_security_hostile_text_is_bounded() {
    // A long link with many items parses quickly and gives clamped values.
    let mut long = String::from("otpauth://totp/a?");
    for _ in 0..20_000 {
        long.push_str("x=%41%42&");
    }
    long.push_str("secret=GEZDGNBV&digits=99999999999999999999");
    let started = std::time::Instant::now();
    let s = get(&otp(&long));
    assert_eq!(s.digits, 1);
    assert!(s.code(at(59)).is_some());
    assert!(started.elapsed().as_secs() < 2);
    // Fields of a form T with huge numbers never allocate a long code.
    let t = with(&[
        ("TimeOtp-Secret-Base32", R),
        ("TimeOtp-Length", "999999999"),
    ]);
    assert_eq!(code(&t, 59).len(), 10);
}
