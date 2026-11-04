//! Story E4-S8, card FEA-01: the search language. One test per rule
//! (`fea01_NN_…`) with the card's cases T01 to T79 on demo vaults S1 and
//! S2, built here with demo data.
//!
//! Screen-only rules belong to E5-S4 and are tested there: when a search
//! runs (FEA-01.25, T06 and T50 beyond `is_blank`), live results
//! (FEA-01.26, T47 beyond re-running), ending a search and the idle timer
//! (FEA-01.27, T43, T48, T49), the result header (FEA-01.30, T76). The
//! `is:weak` estimate is FEA-05's (E4-S11); here a demo table stands in
//! for it with the card's scores.

mod common;

use common::{Berlin, at};
use larsal_core::health::Ratings;
use larsal_core::search::{self, Found, Options, QueryError, parse, search, search_tags};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::json::{self, Value};
use larsal_model::{Attachment, Entry, Field, Group, Switch, Time, Uuid, Vault};
use std::sync::Arc;

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn set(e: &mut Entry, name: &str, value: &str, protected: bool) {
    e.set_field(
        name.to_owned(),
        Field {
            value: SecretString::new(value.to_owned()),
            protected,
        },
    );
}

fn ent(b: u8, title: &str, user: &str, pw: &str, url: &str, notes: &str, tags: &[&str]) -> Entry {
    let mut e = Entry::new(uid(b), at(2026, 1, 1, 0, 0, 0));
    set(&mut e, "Title", title, false);
    set(&mut e, "UserName", user, false);
    set(&mut e, "Password", pw, true);
    set(&mut e, "URL", url, false);
    set(&mut e, "Notes", notes, false);
    e.set_tags(tags.iter().map(|t| (*t).to_owned()).collect());
    e
}

fn group(b: u8, name: &str, searching: Switch) -> Group {
    let mut g = Group::new(uid(b), name.into(), at(2026, 1, 1, 0, 0, 0));
    g.searching = searching;
    g
}

/// Demo vault S1 of the card.
fn s1() -> Vault {
    let mut root = group(0x01, "Vault", Switch::Inherit);
    root.entries.push(ent(
        0x11,
        "GitHub",
        "alex@example.com",
        "Tr0ub4dor&3",
        "https://github.com/login",
        "Work account\nrecovery codes in safe",
        &["work", "dev"],
    ));
    root.entries.push(ent(
        0x12,
        "Gmail",
        "alex.personal",
        "hunter2",
        "https://mail.google.com",
        "",
        &["personal"],
    ));
    let mut banking = group(0x02, "Banking", Switch::Inherit);
    let mut e3 = ent(
        0x13,
        "Big Bank",
        "alex99",
        "hunter2",
        "https://bigbank.example",
        "PIN is not here",
        &[],
    );
    set(&mut e3, "Account No", "12345678", false);
    set(&mut e3, "Security answer", "blue whale", true);
    e3.attachments.push(Attachment {
        name: "statement.pdf".into(),
        data: Arc::new(SecretBytes::new(b"demo".to_vec())),
    });
    banking.entries.push(e3);
    let mut cards = group(0x03, "Cards", Switch::Inherit);
    let mut e4 = ent(
        0x14,
        "Visa Card",
        "",
        "4111-1111",
        "",
        "expires soon",
        &["finance"],
    );
    e4.times.expires = true;
    e4.times.expiry = at(2026, 1, 1, 0, 0, 0);
    cards.entries.push(e4);
    banking.groups.push(cards);
    let mut archive = group(0x04, "Archive", Switch::Off);
    archive.entries.push(ent(
        0x15,
        "Old GitHub",
        "alex",
        "oldpass",
        "https://github.com",
        "",
        &["work"],
    ));
    let mut bin = group(0x05, "Recycle Bin", Switch::Off);
    bin.entries.push(ent(
        0x16,
        "Deleted GitHub",
        "alex",
        "",
        "https://github.com/old",
        "",
        &[],
    ));
    let mut dev = group(0x06, "Dev & Ops", Switch::Inherit);
    let mut e7 = ent(
        0x17,
        "Build server",
        "{REF:U@I:11111111111111111111111111111111}",
        "s3rver!",
        "ssh://build.example:22",
        "Uses key",
        &["dev", "ops"],
    );
    set(
        &mut e7,
        "otp",
        "otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP",
        true,
    );
    dev.entries.push(e7);
    root.groups.extend([banking, archive, bin, dev]);
    let mut v = Vault::new(root, at(2026, 1, 1, 0, 0, 0));
    v.meta.recycle_bin = Some(uid(0x05));
    v
}

/// Demo vault S2 of the card.
fn s2() -> Vault {
    let mut root = group(0x01, "Root", Switch::Inherit);
    let mut add = |b: u8, title: &str| {
        let e = ent(b, title, "", "", "", "", &[]);
        root.entries.push(e);
    };
    add(0x21, "Éclair Café");
    add(0x22, "trail\n");
    add(0x23, "Ref test");
    add(0x24, "Straße");
    add(0x25, "Soon");
    add(0x26, "Later");
    add(0x27, "Notes ref");
    add(0xab, "Hexy");
    add(0x29, "Emoji 🔑 key");
    add(0x2a, "c++ notes");
    for entry in &mut root.entries {
        match entry.uuid.0[0] {
            0x21 => set(entry, "UserName", "chef", false),
            0x22 => set(entry, "Notes", "hello\n", false),
            0x23 => {
                set(entry, "UserName", "{PASSWORD}", false);
                set(entry, "Password", "zebra42", true);
            }
            0x25 => {
                entry.times.expires = true;
                entry.times.expiry = at(2026, 10, 30, 12, 0, 0);
            }
            0x26 => {
                entry.times.expires = true;
                entry.times.expiry = at(2026, 11, 30, 12, 0, 0);
            }
            0x27 => set(entry, "Notes", "{TITLE}", false),
            0x2a => set(entry, "Notes", "-5 degrees", false),
            _ => {}
        }
    }
    Vault::new(root, at(2026, 1, 1, 0, 0, 0))
}

fn now() -> Time {
    at(2026, 10, 25, 12, 0, 0)
}

/// FEA-05 password-only scores of the card (Tr0ub4dor&3 46, s3rver! 15,
/// hunter2 and oldpass low); demo stand-in for E4-S11's estimate.
fn demo_strength(pw: &str, _: &[&str]) -> f64 {
    match pw {
        "Tr0ub4dor&3" => 46.0,
        "s3rver!" => 15.0,
        "hunter2" | "oldpass" | "4111-1111" => 8.0,
        "exactly75" => 75.0,
        "" => 0.0,
        _ => 120.0,
    }
}

fn opts() -> Options<'static> {
    // A fresh rating cache per call (FEA-05's shared cache, LD-137).
    let ratings: &'static Ratings<'static> = Box::leak(Box::new(Ratings::new(&demo_strength)));
    Options {
        ratings: Some(ratings),
        ..Options::new(now())
    }
}

fn found(v: &Vault, q: &str, o: &Options<'_>) -> Found {
    search(v, q, o).unwrap()
}

/// The ids as the card's entry bytes.
fn ids(v: &Vault, q: &str) -> Vec<u8> {
    ids_with(v, q, &opts())
}

fn ids_with(v: &Vault, q: &str, o: &Options<'_>) -> Vec<u8> {
    found(v, q, o).ids.iter().map(|u| u.0[0]).collect()
}

const SCOPE: [u8; 5] = [0x11, 0x12, 0x13, 0x14, 0x17];

#[test]
fn fea01_01_terms_split_on_space_only() {
    let v = s1();
    assert_eq!(ids(&v, "git hub"), [0x11]); // T03
    assert_eq!(ids(&v, "   git    hub   "), [0x11]);
    assert_eq!(ids(&v, "t:GitHub\tGmail"), Vec::<u8>::new()); // T75
    let terms = parse::parse("a\u{a0}b\nc d").unwrap();
    assert_eq!(terms.len(), 2);
    assert_eq!(terms[0].value, "a\u{a0}b\nc");
}

#[test]
fn fea01_02_term_shape() {
    let v = s1();
    // T32.
    assert_eq!(ids(&v, "*hub"), [0x11]);
    assert_eq!(ids(&v, "t:*hub"), [0x11]);
    assert_eq!(ids(&v, "t:-git"), Vec::<u8>::new());
    assert_eq!(ids(&v, "url:build.example:22"), [0x17]);
    let t = &parse::parse("+-*!t:a:b").unwrap()[0];
    assert!(t.exclude && t.regex && t.exact);
    assert!(t.field == parse::Field::Title && t.value == "a:b");
    // T74 on S2.
    let w = s2();
    assert_eq!(ids(&w, "c++"), [0x2a]);
    let all_but: Vec<u8> = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0xab, 0x29].to_vec();
    assert_eq!(ids(&w, "-5"), all_but);
    assert_eq!(ids(&w, "\"-5\""), [0x2a]);
    // A field run not followed by `:` is no field.
    let t = &parse::parse("foo.bar:x").unwrap()[0];
    assert!(t.field == parse::Field::Default && t.value == "foo.bar:x");
}

#[test]
fn fea01_03_quoted_values() {
    let v = s1();
    // T33.
    assert_eq!(ids(&v, "\"PIN is\""), [0x13]);
    assert_eq!(ids(&v, "\"PIN"), Vec::<u8>::new());
    assert_eq!(ids(&v, "\"git\" \"hub\""), [0x11]);
    // T34.
    assert_eq!(ids(&v, "g:Dev & Ops"), Vec::<u8>::new());
    assert_eq!(ids(&v, "g:\"Dev & Ops\""), [0x17]);
    let p = |q: &str| -> Vec<String> {
        parse::parse(q)
            .unwrap()
            .into_iter()
            .map(|t| t.value)
            .collect()
    };
    assert_eq!(p("\"abc\"def ghi"), ["\"abc\"def", "ghi"]);
    assert_eq!(p(r#""a\"b c""#), [r#"a"b c"#]);
    assert_eq!(p(r#""a\b""#), [r"a\b"]);
    assert_eq!(p(r#""a\\" b"#), [r"a\\", "b"]);
    assert_eq!(p("\"PIN"), ["\"PIN"]);
    assert_eq!(p("t:\"x y\" z"), ["x y", "z"]);
}

#[test]
fn fea01_04_empty_values_are_dropped() {
    let v = s1();
    for q in ["*", "-", "title:", "x:", "\"\"", "+", "**", ""] {
        assert_eq!(ids(&v, q), SCOPE, "{q:?}"); // T04, T05
    }
    assert!(parse::parse("title: x: \"\" - * + **").unwrap().is_empty());
}

#[test]
fn fea01_05_field_names() {
    let v = s1();
    for q in [
        "pw:hunter2",
        "p:hunter",
        "pass:hunter",
        "password:hunter",
        "PW:hunter",
        "PassWord:hunter",
    ] {
        assert_eq!(ids(&v, q), [0x12, 0x13], "{q}"); // T08, case ignored
    }
    // The field part is letters, digits and `_` only: `user-x:alex` has no
    // field, so its whole text is the value.
    assert_eq!(ids(&v, "user-x:alex"), Vec::<u8>::new());
    for q in ["foo:github", "e:github", ":github", "https://github.com"] {
        assert_eq!(ids(&v, q), [0x11], "{q}"); // T26
    }
    assert_eq!(ids(&v, "tags:safe"), [0x11]); // T27
    assert_eq!(ids(&v, "tag:safe"), Vec::<u8>::new());
    assert_eq!(ids(&v, "TITLE:git"), [0x11]); // T28
    assert_eq!(ids(&v, "Url:bigbank"), [0x13]);
    assert_eq!(ids(&v, "user:alex.p"), [0x12]);
    assert_eq!(ids(&v, "us:alex.p"), [0x12]);
    for q in ["attach:statement", "a:pdf", "at:pdf", "att:pdf"] {
        assert_eq!(ids(&v, q), [0x13], "{q}"); // T19
    }
    use parse::Field as F;
    let f = |q: &str| parse::parse(q).unwrap().remove(0).field;
    for (q, want) in [
        ("attr:x", F::Attribute),
        ("n:x", F::Notes),
        ("ta:x", F::Tag),
        ("u:x", F::UserName),
        ("ur:x", F::Url),
        ("uu:x", F::Uuid),
        ("g:x", F::Group),
        ("i:x", F::Is),
        ("h:x", F::Has),
        ("user1:x", F::Default),
        ("12:x", F::Default),
        ("_otp:x", F::Named("otp".into())),
    ] {
        assert!(f(q) == want, "{q}");
    }
}

#[test]
fn fea01_06_field_by_name() {
    let v = s1();
    assert_eq!(ids(&v, "_UserName:alex"), [0x11, 0x12, 0x13]); // T10
    for q in ["_username:alex", "_Security:blue", "_:x"] {
        assert_eq!(ids(&v, q), Vec::<u8>::new(), "{q}"); // T11
    }
    assert_eq!(ids(&v, "_otp:JBSWY"), [0x17]); // T12
    assert_eq!(ids(&v, "_Password:hunter"), [0x12, 0x13]);
}

#[test]
fn fea01_07_wildcards() {
    let v = s1();
    assert_eq!(ids(&v, "t:G?tHub"), [0x11]); // T29
    assert_eq!(ids(&v, "t:Git*b"), [0x11]);
    assert_eq!(ids(&v, "t:G?Hub"), Vec::<u8>::new());
    assert_eq!(ids(&v, "url:github.com"), [0x11]); // T30
    assert_eq!(ids(&v, "url:github?com"), [0x11]);
    assert_eq!(ids(&v, "t:gmail|bank"), [0x12, 0x13]);
    // `?` does not cross a line feed either.
    assert_eq!(ids(&v, "n:account?recovery"), Vec::<u8>::new());
    assert_eq!(ids(&v, "n:accoun?"), [0x11]);
    assert_eq!(ids(&v, "|"), SCOPE); // T31
    assert_eq!(ids(&v, "?"), SCOPE);
    assert_eq!(ids(&v, "n:account*recovery"), Vec::<u8>::new()); // T35
    assert_eq!(ids(&v, "n:\"codes in\""), [0x11]);
    // `.`, `(`, `[`, `\` and `$` are plain.
    assert_eq!(ids(&v, "url:bigbank.example"), [0x13]);
    assert_eq!(ids(&v, "url:big.ank"), Vec::<u8>::new());
    for q in ["(", "[", "\\", "$", "t:.*"] {
        assert_eq!(ids(&v, q), Vec::<u8>::new(), "{q}");
    }
    // `?` alone needs a character that is not a line feed.
    let w = s2();
    assert_eq!(ids(&w, "n:?"), [0x22, 0x27, 0x2a]);
    // T73: `?` is one code point.
    assert_eq!(ids(&w, "t:Emoji???key"), [0x29]);
    assert_eq!(ids(&w, "t:Emoji??key"), Vec::<u8>::new());
    assert_eq!(ids(&w, "🔑"), [0x29]);
}

#[test]
fn fea01_08_regular_expressions() {
    let v = s1();
    // T24.
    let f = found(&v, "*t:^Git", &opts());
    assert_eq!((f.ids.len(), f.invalid), (1, false));
    let bad = found(&v, "*t:[", &opts());
    assert!(bad.ids.is_empty() && bad.invalid);
    let ex = found(&v, "-*t:[", &opts());
    assert_eq!(ex.ids.iter().map(|u| u.0[0]).collect::<Vec<_>>(), SCOPE);
    assert!(ex.invalid);
    // T25 with LD-110's ASCII `\w`.
    assert_eq!(ids(&v, r"*u:^\w+$"), [0x13]);
    // T62: look-ahead is invalid; so are back-references and `\p{L}`.
    for q in [r"*t:(?=Git)G", r"*t:(G)\1", r"*t:\p{L}", r"*t:\p{Greek}"] {
        let f = found(&v, q, &opts());
        assert!(f.ids.is_empty() && f.invalid, "{q}");
    }
    // A pattern that is unbalanced alone stays invalid inside Larsal's
    // anchor group.
    let f = found(&v, "+*t:G)(?:x", &opts());
    assert!(f.ids.is_empty() && f.invalid);
    // Unanchored by default; `+*` anchors.
    assert_eq!(ids(&v, "*t:it"), [0x11]);
    assert_eq!(ids(&v, "+*t:G.*"), [0x11, 0x12]);
    assert_eq!(ids(&v, "+*t:it"), Vec::<u8>::new());
}

#[test]
fn fea01_09_exact_match() {
    let v = s1();
    assert_eq!(ids(&v, "+u:alex99"), [0x13]); // T13
    assert_eq!(ids(&v, "+u:alex"), Vec::<u8>::new());
    assert_eq!(ids(&v, "+t:github"), Vec::<u8>::new()); // T14
    assert_eq!(ids(&v, "+t:GitHub"), [0x11]);
    assert_eq!(ids(&v, "+t:Gmail|Big"), [0x12]); // T15
    assert_eq!(ids(&v, "+t:\"Big Bank|Gmail\""), [0x12, 0x13]);
    assert_eq!(ids(&v, "+-t:Gmail"), [0x11, 0x13, 0x14, 0x17]); // T38
    // T67: one final line feed also matches.
    let w = s2();
    for q in ["+t:trail", "+n:hello", "+n:\"hello\""] {
        assert_eq!(ids(&w, q), [0x22], "{q}");
    }
    // T72.
    assert_eq!(ids(&w, "uuid:abab"), [0xab]);
    assert_eq!(ids(&w, "uuid:ABAB"), [0xab]);
    assert_eq!(
        ids(&w, &format!("+uuid:{}", "AB".repeat(16))),
        Vec::<u8>::new()
    );
    assert_eq!(ids(&w, &format!("+uuid:{}", "ab".repeat(16))), [0xab]);
}

#[test]
fn fea01_10_case() {
    let v = s1();
    assert_eq!(ids(&v, "GITHUB"), [0x11]); // T02
    let w = s2();
    for q in ["éclair", "ÉCLAIR", "CAFÉ"] {
        assert_eq!(ids(&w, q), [0x21], "{q}"); // T65
    }
    assert_eq!(ids(&w, "straße"), [0x24]); // T66
    assert_eq!(ids(&w, "STRAßE"), [0x24]);
    assert_eq!(ids(&w, "STRASSE"), Vec::<u8>::new());
    // No normalization: `e` plus a combining accent is not `é`.
    assert_eq!(ids(&w, "e\u{301}clair"), Vec::<u8>::new());
    // A pattern may switch case itself.
    assert_eq!(ids(&v, "*t:(?-i)GITHUB"), Vec::<u8>::new());
}

#[test]
fn fea01_11_exclusion() {
    let v = s1();
    for q in ["-github", "!github", "--github", "-!github"] {
        assert_eq!(ids(&v, q), [0x12, 0x13, 0x14, 0x17], "{q}"); // T23
    }
}

#[test]
fn fea01_12_all_terms_must_hold() {
    let v = s1();
    assert_eq!(ids(&v, "alex bank"), [0x13]);
    assert_eq!(ids(&v, "bank alex"), [0x13]);
    assert_eq!(ids(&v, "u:\"alex.personal|alex99\""), [0x12, 0x13]);
}

#[test]
fn fea01_13_field_sources() {
    let v = s1();
    assert_eq!(ids(&v, "github"), [0x11]); // T01
    assert_eq!(ids(&v, "hunter2"), Vec::<u8>::new()); // T07
    // T18.
    assert_eq!(ids(&v, "attr:blue"), [0x13]);
    assert_eq!(ids(&v, "attr:Account"), [0x13]);
    assert_eq!(ids(&v, "attr:pdf"), Vec::<u8>::new());
    assert_eq!(ids(&v, "attr:otpauth"), [0x17]);
    // Nor the foreign passkey user name field (INT-04; its name as bytes).
    let mut pk = s1();
    let foreign: String = [
        0x4Bu8, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x41, 0x53, 0x53, 0x4B, 0x45, 0x59, 0x5F, 0x55, 0x53,
        0x45, 0x52, 0x4E, 0x41, 0x4D, 0x45,
    ]
    .iter()
    .map(|b| char::from(*b))
    .collect();
    set(&mut pk.root.entries[1], &foreign, "foreign-user", false);
    assert_eq!(ids(&pk, "attr:foreign-user"), Vec::<u8>::new());
    // Not the standard fields.
    assert_eq!(ids(&v, "attr:GitHub"), Vec::<u8>::new());
    // T22.
    assert_eq!(ids(&v, "uuid:1414"), [0x14]);
    assert_eq!(ids(&v, "uuid:"), SCOPE);
    // Notes are a default field; passwords and custom fields are not.
    assert_eq!(ids(&v, "safe"), [0x11]);
    assert_eq!(ids(&v, "whale"), Vec::<u8>::new());
    // Passkey fields are left out of `attribute` (INT-04).
    let mut w = s1();
    let e2 = &mut w.root.entries[1];
    set(e2, "KPEX_PASSKEY_RELYING_PARTY", "passkey.example", false);
    set(e2, "Plain", "other.example", false);
    assert_eq!(ids(&w, "attr:passkey.example"), Vec::<u8>::new());
    assert_eq!(ids(&w, "attr:other.example"), [0x12]);
    assert_eq!(ids(&w, "_KPEX_PASSKEY_RELYING_PARTY:passkey"), [0x12]);
}

#[test]
fn fea01_14_tags_match_whole() {
    let v = s1();
    // T16.
    assert_eq!(ids(&v, "tag:work"), [0x11]);
    assert_eq!(ids(&v, "tag:wor"), Vec::<u8>::new());
    assert_eq!(ids(&v, "tag:wor*"), [0x11]);
    assert_eq!(ids(&v, "tag:WORK"), [0x11]);
    // T17.
    assert_eq!(ids(&v, "dev"), [0x11, 0x17]);
    assert_eq!(ids(&v, "de"), [0x11]);
    // A regex too must cover the whole tag.
    assert_eq!(ids(&v, "*tag:wor"), Vec::<u8>::new());
    assert_eq!(ids(&v, "*tag:w.rk"), [0x11]);
    assert_eq!(ids(&v, "*tag:op"), Vec::<u8>::new());
}

#[test]
fn fea01_15_group() {
    let v = s1();
    // T20.
    assert_eq!(ids(&v, "g:Cards"), [0x14]);
    assert_eq!(ids(&v, "g:Bank"), [0x13]);
    assert_eq!(ids(&v, "g:/Banking"), [0x13, 0x14]);
    assert_eq!(ids(&v, "g:/Vault/Banking/Cards"), [0x14]);
    assert_eq!(ids(&v, "g:Vault"), [0x11, 0x12]);
    assert_eq!(ids(&v, "g:Banking/Cards"), [0x14]);
    assert_eq!(ids(&v, "+g:/Vault/Banking"), [0x13]);
}

#[test]
fn fea01_16_is_expired() {
    let v = s1();
    assert_eq!(ids(&v, "is:expired"), [0x14]); // T21
    assert_eq!(ids(&v, "i:EXPIRED"), [0x14]);
    // `*` and `+` have no effect on `is` terms.
    assert_eq!(ids(&v, "+*is:expired"), [0x14]);
    let w = s2();
    // T70.
    assert_eq!(ids(&w, "is:expired"), Vec::<u8>::new());
    assert_eq!(ids(&w, "is:expired-5"), Vec::<u8>::new());
    assert_eq!(ids(&w, "is:expired-6"), [0x25]);
    // T71.
    assert_eq!(ids(&w, "is:expired-36"), [0x25]);
    assert_eq!(ids(&w, "is:expired-37"), [0x25, 0x26]);
    assert_eq!(ids(&w, "is:EXPIRED-6"), [0x25]);
    assert_eq!(ids(&w, "is:expiredxyz"), Vec::<u8>::new());
    assert_eq!(ids(&w, "is:expired-abc"), Vec::<u8>::new());
    assert_eq!(ids(&w, "is:expired-99999999999"), Vec::<u8>::new());
    assert_eq!(ids(&w, "is:expire"), Vec::<u8>::new());
    // Calendar days in the local zone: across the end of summer time in
    // Berlin (25 October) six local days are 145 hours.
    let berlin = Options {
        zone: &Berlin,
        now: at(2026, 10, 24, 12, 0, 0).into(),
        ..opts()
    };
    let mut x = s2();
    x.root.entries[4].times.expiry = at(2026, 10, 30, 12, 30, 0);
    assert_eq!(ids_with(&x, "is:expired-6", &berlin), [0x25]);
    let utc = Options {
        now: at(2026, 10, 24, 12, 0, 0).into(),
        ..opts()
    };
    assert_eq!(ids_with(&x, "is:expired-6", &utc), Vec::<u8>::new());
}

#[test]
fn fea01_17_is_weak() {
    let v = s1();
    assert_eq!(ids(&v, "is:weak"), [0x11, 0x12, 0x13, 0x17]); // T37
    assert_eq!(ids(&v, "is:WEAK"), [0x11, 0x12, 0x13, 0x17]);
    assert_eq!(ids(&v, "is:foo"), Vec::<u8>::new());
    assert_eq!(ids(&v, "is:weakish"), Vec::<u8>::new());
    // Excluded from reports, an empty password and no estimate: never.
    let mut w = s1();
    w.root.entries[0].exclude_from_reports = true;
    set(&mut w.root.entries[1], "Password", "", true);
    assert_eq!(ids(&w, "is:weak"), [0x13, 0x17]);
    let none = Options::new(now());
    assert_eq!(ids_with(&v, "is:weak", &none), Vec::<u8>::new());
    // The password is resolved before it is rated.
    let mut r = s1();
    set(&mut r.root.entries[0], "Password", "{S:Strong}", true);
    set(&mut r.root.entries[0], "Strong", "correct horse", true);
    assert_eq!(ids(&r, "is:weak"), [0x12, 0x13, 0x17]);
    set(&mut r.root.entries[0], "Password", "{S:Weak}", true);
    set(&mut r.root.entries[0], "Weak", "hunter2", true);
    assert_eq!(ids(&r, "is:weak"), [0x11, 0x12, 0x13, 0x17]);
    // A score of exactly 75 is not weak; an expired entry never is (E4's
    // password rates weak, but it expired).
    set(&mut r.root.entries[1], "Password", "exactly75", true);
    assert_eq!(ids(&r, "is:weak"), [0x11, 0x13, 0x17]);
    assert_eq!(demo_strength("4111-1111", &[]), 8.0);
}

#[test]
fn fea01_18_has_totp() {
    let v = s1();
    // T36.
    assert_eq!(ids(&v, "has:totp"), [0x17]);
    assert_eq!(ids(&v, "h:TOTP"), [0x17]);
    assert_eq!(ids(&v, "!has:totp"), [0x11, 0x12, 0x13, 0x14]);
    assert_eq!(ids(&v, "has:foo"), Vec::<u8>::new());
    // Settings in an error state count too.
    let mut w = s1();
    set(
        &mut w.root.entries[0],
        "otp",
        "otpauth://totp/x?secret=ABC",
        true,
    );
    assert_eq!(ids(&w, "has:totp"), [0x11, 0x17]);
}

#[test]
fn fea01_19_placeholders() {
    let v = s1();
    assert_eq!(ids(&v, "u:alex"), [0x11, 0x12, 0x13, 0x17]); // T09
    let w = s2();
    assert_eq!(ids(&w, "zebra42"), [0x23]); // T68
    assert_eq!(ids(&w, "u:zebra"), [0x23]);
    assert_eq!(ids(&w, "n:TITLE"), [0x27]); // T69
    assert_eq!(ids(&w, "n:Notes"), Vec::<u8>::new());
    // The one-time code resolves when the search runs.
    let mut x = s1();
    set(&mut x.root.entries[1], "Title", "code {TOTP}", false);
    set(
        &mut x.root.entries[1],
        "otp",
        "otpauth://totp/a?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        true,
    );
    let at59 = Options {
        now: Time::from_unix(59).unwrap().into(),
        ..opts()
    };
    assert_eq!(ids_with(&x, "+t:\"code 287082\"", &at59), [0x12]);
    // References by field value and by any value go through the run's
    // index the same way (LD-126 (3)); the first live entry in tree order
    // wins.
    let mut f = s1();
    set(
        &mut f.root.entries[1],
        "UserName",
        "{REF:U@T:Big Bank}",
        false,
    );
    set(
        &mut f.root.groups[3].entries[0],
        "UserName",
        "{REF:U@O:blue whale}",
        false,
    );
    assert_eq!(ids(&f, "+u:alex99"), [0x12, 0x13, 0x17]);
    // Password and URL resolve too (title and user name above).
    let mut r = s1();
    set(&mut r.root.entries[1], "Password", "{S:Pw}", true);
    set(&mut r.root.entries[1], "Pw", "correct horse", true);
    set(&mut r.root.entries[1], "URL", "https://{S:Host}/", false);
    set(&mut r.root.entries[1], "Host", "resolved.example", false);
    assert_eq!(ids(&r, "pw:horse"), [0x12]);
    assert_eq!(ids(&r, "url:resolved.example"), [0x12]);
    // Date placeholders resolve in the run's local zone.
    let mut d = s1();
    set(&mut d.root.entries[1], "Title", "Year {DT_YEAR}", false);
    let late = Options {
        now: at(2026, 12, 31, 23, 30, 0).into(),
        zone: &common::Fixed(3_600),
        ..opts()
    };
    assert_eq!(ids_with(&d, "t:\"Year 2027\"", &late), [0x12]);
    assert_eq!(ids_with(&d, "t:\"Year 2026\"", &late), Vec::<u8>::new());
}

#[test]
fn fea01_20_scope_and_search_flags() {
    // T39: a group set to on below one set to off is searched.
    let mut v = s1();
    let mut keep = group(0x07, "Keep", Switch::On);
    keep.entries.push(ent(0x18, "Keep me", "", "", "", "", &[]));
    v.root.groups[1].groups.push(keep);
    assert_eq!(ids(&v, "keep"), [0x18]);
    assert_eq!(ids(&v, "github"), [0x11]);
    // Inherit at the root means on; history items are never results.
    let mut h = s1();
    let item = h.root.entries[1].duplicate(false);
    let mut old = item;
    set(&mut old, "Title", "Ancient", false);
    h.root.entries[1].history.push(old);
    assert_eq!(ids(&h, "ancient"), Vec::<u8>::new());
    // The root set to off hides its own entries only.
    let mut r = s1();
    r.root.searching = Switch::Off;
    assert_eq!(ids(&r, "*"), Vec::<u8>::new());
    r.root.groups[0].searching = Switch::On;
    assert_eq!(ids(&r, "*"), [0x13, 0x14]);
}

#[test]
fn fea01_21_recycle_bin_never_searched() {
    // T40 and T79 (LD-57).
    let mut v = s1();
    v.root.groups[2].searching = Switch::Inherit;
    let mut b2 = group(0x08, "B2", Switch::On);
    b2.entries
        .push(ent(0x1c, "github bin", "", "", "", "", &[]));
    v.root.groups[2].groups.push(b2);
    assert_eq!(ids(&v, "github"), [0x11]);
    assert_eq!(ids(&v, "-is:expired"), [0x11, 0x12, 0x13, 0x17]);
    // A base inside the bin finds nothing.
    let inside = Options {
        base: Some(uid(0x08)),
        ..opts()
    };
    assert_eq!(ids_with(&v, "*", &inside), Vec::<u8>::new());
}

#[test]
fn fea01_22_tree_order() {
    let v = s1();
    assert_eq!(ids(&v, "alex"), [0x11, 0x12, 0x13, 0x17]); // T45
}

#[test]
fn fea01_23_limit_to_group() {
    let v = s1();
    let banking = Options {
        base: Some(uid(0x02)),
        ..opts()
    };
    assert_eq!(ids_with(&v, "*", &banking), [0x13, 0x14]); // T41
    let archive = Options {
        base: Some(uid(0x04)),
        ..opts()
    };
    assert_eq!(ids_with(&v, "github", &archive), Vec::<u8>::new()); // T42
    let cards = Options {
        base: Some(uid(0x03)),
        ..opts()
    };
    assert_eq!(ids_with(&v, "*", &cards), [0x14]); // T44
    // A flag above the base still applies.
    let mut off = s1();
    off.root.groups[0].searching = Switch::Off;
    assert_eq!(ids_with(&off, "*", &cards), Vec::<u8>::new());
    // Tag terms follow the base too.
    assert_eq!(search_tags(&v, &["finance"], &banking).ids, [uid(0x14)]);
}

#[test]
fn fea01_24_case_sensitive_option() {
    let v = s1();
    let cs = Options {
        case_sensitive: true,
        ..opts()
    };
    assert_eq!(ids_with(&v, "gmail", &cs), Vec::<u8>::new()); // T46
    assert_eq!(ids_with(&v, "Gmail", &cs), [0x12]);
    assert_eq!(ids(&v, "gmail"), [0x12], "off again by default");
    // `*` terms follow it unless they carry their own flag.
    assert_eq!(ids_with(&v, "*t:^git", &cs), Vec::<u8>::new());
    assert_eq!(ids_with(&v, "*t:(?i)^git", &cs), [0x11]);
}

#[test]
fn fea01_25_blank_text_ends_the_search() {
    // T06: the core says blank; the screen ends the search (E5-S4).
    for t in ["", "   ", "\t "] {
        assert!(search::is_blank(t), "{t:?}");
    }
    assert!(!search::is_blank(" x "));
}

#[test]
fn fea01_26_a_changed_vault_runs_the_same_query_again() {
    // T47, the core part: the same query after the change.
    let mut v = s1();
    assert_eq!(ids(&v, "pw:hunter"), [0x12, 0x13]);
    set(&mut v.root.entries[1], "Password", "x", true);
    assert_eq!(ids(&v, "pw:hunter"), [0x13]);
}

#[test]
fn fea01_28_builtin_queries() {
    let v = s1();
    assert_eq!(ids(&v, search::ALL), SCOPE);
    assert_eq!(ids(&v, search::EXPIRED), [0x14]);
    assert_eq!(ids(&v, search::WEAK), [0x11, 0x12, 0x13, 0x17]);
    assert_eq!(ids(&v, search::TOTP), [0x17]);
    // T54: after unlock, from the root whatever group was selected.
    assert_eq!(search::unlock_expired(0), "is:expired-0");
    assert_eq!(ids(&v, &search::unlock_expired(0)), [0x14]);
    // T55.
    let mut none = s1();
    none.root.groups[0].groups[0].entries[0].times.expires = false;
    assert!(ids(&none, &search::unlock_expired(0)).is_empty());
}

#[test]
fn fea01_29_saved_searches() {
    let mut v = s1();
    let t = now();
    // T56.
    assert!(search::save(&mut v, "Work stuff", "tag:work", t));
    assert_eq!(
        search::saved(&v),
        [("Work stuff".to_owned(), "tag:work".to_owned())]
    );
    let key: String = [
        0x4Bu8, 0x50, 0x58, 0x43, 0x5F, 0x53, 0x61, 0x76, 0x65, 0x64, 0x53, 0x65, 0x61, 0x72, 0x63,
        0x68,
    ]
    .iter()
    .map(|b| char::from(*b))
    .collect();
    let raw = v.meta.custom_data.get(&key).unwrap();
    let json: Value = json::from_str(raw).unwrap();
    assert_eq!(json, larsal_model::json!({"Work stuff": "tag:work"}));
    let item = v
        .meta
        .custom_data
        .items
        .iter()
        .find(|i| i.key == key)
        .unwrap();
    assert_eq!(item.last_modified, Some(t));
    // A later save or remove moves the item's time.
    let later = Time(t.0 + 60);
    search::save(&mut v, "Other", "x", later);
    let item = v
        .meta
        .custom_data
        .items
        .iter()
        .find(|i| i.key == key)
        .unwrap();
    assert_eq!(item.last_modified, Some(later));
    search::remove(&mut v, "Other", Time(t.0 + 120));
    let item = v
        .meta
        .custom_data
        .items
        .iter()
        .find(|i| i.key == key)
        .unwrap();
    assert_eq!(item.last_modified, Some(Time(t.0 + 120)));
    // UTF-16 code unit order, not code point or UTF-8 byte order: U+1F600
    // is D83D DE00 in UTF-16, so it sorts before U+FF5E.
    let mut u = s1();
    search::save(&mut u, "\u{ff5e}", "a", t);
    search::save(&mut u, "\u{1f600}", "b", t);
    let names: Vec<String> = search::saved(&u).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["\u{1f600}", "\u{ff5e}"]);
    // T58.
    assert!(search::save(&mut v, "Work stuff", "tag:dev", t));
    assert_eq!(search::saved(&v)[0].1, "tag:dev");
    assert!(!search::save(&mut v, "", "x", t));
    assert!(search::remove(&mut v, "Work stuff", t));
    assert!(!search::remove(&mut v, "Work stuff", t));
    let raw = v.meta.custom_data.get(&key).unwrap();
    assert_eq!(json::from_str(raw).unwrap(), larsal_model::json!({}));
    // T57: code unit order, with case.
    search::save(&mut v, "alpha", "a", t);
    search::save(&mut v, "Zeta", "z", t);
    let names: Vec<String> = search::saved(&v).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["Zeta", "alpha"]);
    // T59: not an object reads as none; a save replaces it.
    let mut w = s1();
    w.meta.custom_data.items.push(larsal_model::CustomDataItem {
        key: key.clone(),
        value: "[1,2]".into(),
        last_modified: None,
        unknown: Vec::new(),
    });
    assert!(search::saved(&w).is_empty());
    search::save(&mut w, "A", "x", t);
    let raw = w.meta.custom_data.get(&key).unwrap();
    assert_eq!(
        json::from_str(raw).unwrap(),
        larsal_model::json!({"A": "x"})
    );
    // Members that are not text are left out; broken JSON is none.
    let mut m = s1();
    m.meta.custom_data.items.push(larsal_model::CustomDataItem {
        key: key.clone(),
        value: r#"{"n": 5, "q": "tag:dev", "o": {}}"#.into(),
        last_modified: None,
        unknown: Vec::new(),
    });
    assert_eq!(search::saved(&m), [("q".to_owned(), "tag:dev".to_owned())]);
    m.meta.custom_data.items[0].value = "{not json".into();
    assert!(search::saved(&m).is_empty());
}

#[test]
fn fea01_31_invalid_notice() {
    let v = s1();
    assert!(!found(&v, "github *t:^G", &opts()).invalid);
    assert!(found(&v, "github *t:(", &opts()).invalid);
    // A wildcard past a bound fails the same way.
    let many = format!("t:{}", "?".repeat(900));
    assert!(found(&v, &many, &opts()).invalid);
}

#[test]
fn fea01_32_limits() {
    let v = s1();
    // T60: over 1,024 characters is refused.
    let long = "a".repeat(2_000);
    assert_eq!(search(&v, &long, &opts()).err(), Some(QueryError::TooLong));
    assert_eq!(
        search(&v, &"a".repeat(1_025), &opts()).err(),
        Some(QueryError::TooLong)
    );
    assert!(search(&v, &"a".repeat(1_024), &opts()).is_ok());
    // LD-124: at most 16 terms that become patterns; `is:` and `has:` do
    // not count; empty values are no terms.
    let terms = |n: usize, kind: &str| (0..n).map(|i| format!("{kind}{i} ")).collect::<String>();
    assert!(search(&v, &terms(16, "x"), &opts()).is_ok());
    for kind in ["x", "*x", "t:x?", "-x"] {
        assert_eq!(
            search(&v, &terms(17, kind), &opts()).err(),
            Some(QueryError::TooManyTerms),
            "{kind}"
        );
    }
    let mixed = format!(
        "{} is:weak has:totp is:expired-{} title: -",
        terms(16, "x"),
        3
    );
    assert!(search(&v, &mixed, &opts()).is_ok());
    assert!(search(&v, &"é".repeat(1_024), &opts()).is_ok());
    // T61: no blow-up.
    let mut w = s1();
    set(
        &mut w.root.entries[0],
        "Title",
        &format!("{}!", "a".repeat(40)),
        false,
    );
    let started = std::time::Instant::now();
    assert!(ids(&w, "*t:(a+)+$").is_empty());
    assert!(started.elapsed() < bound(50));
    // Nesting over 100 levels is invalid.
    let deep = format!("*t:{}a{}", "(".repeat(101), ")".repeat(101));
    assert!(found(&v, &deep, &opts()).invalid);
    let ok = format!("*t:{}G{}", "(".repeat(100), ")".repeat(100));
    assert!(!found(&v, &ok, &opts()).invalid);
    // One case-folding budget per query: many wide ranges together fail.
    // (identical terms compile once, so these differ).
    let wide: String = (0..8)
        .map(|i| format!("*t:[\\x{{0}}-\\x{{{:X}}}]x ", 0x9C30 + i))
        .collect();
    assert!(found(&v, &wide, &opts()).invalid);
    let few: String = (0..4)
        .map(|i| format!("*t:[\\x{{0}}-\\x{{{:X}}}]x ", 0x9C30 + i))
        .collect();
    assert!(!found(&v, &few, &opts()).invalid);
    // A compiled size too large for a long text counts as invalid there.
    let mut n = s1();
    set(
        &mut n.root.entries[0],
        "Notes",
        &"b".repeat(1_000_000),
        false,
    );
    let big = found(&n, "*n:(?:[a-z]{1,30}){1,30}[0-9]", &opts());
    assert!(big.invalid && big.ids.is_empty());
    // The cap alone decides here: the lazy DFA finds `z{40}` at once, but
    // its compiled size is over 1.6 × 10^9 / 1,000,040 bytes.
    let mut z = s1();
    set(
        &mut z.root.entries[0],
        "Notes",
        &format!("{}{}", "b".repeat(1_000_000), "z".repeat(40)),
        false,
    );
    let capped = found(&z, "*n:z{40}", &opts());
    assert!(capped.invalid && capped.ids.is_empty());
    assert_eq!(
        ids(&z, "*n:z{4}"),
        [0x11],
        "a small pattern is under the cap"
    );
}

#[test]
fn fea01_33_only_ids_leave() {
    // T63: the result type holds ids and a flag, nothing else.
    let v = s1();
    let f = found(&v, "pw:hunter2", &opts());
    assert_eq!(
        (f.ids.as_slice(), f.invalid),
        ([uid(0x12), uid(0x13)].as_slice(), false)
    );
    assert!(f.spent > 0 && f.spent < search::RUN_BUDGET);
    let debug = format!("{f:?}");
    assert!(!debug.contains("hunter2"));
}

fn bound(release_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(if cfg!(debug_assertions) {
        release_ms * 20
    } else {
        release_ms
    })
}

/// A generated demo vault: 10,000 entries in 10 groups under the root.
fn big_vault() -> Vault {
    let mut root = group(0x01, "Vault", Switch::Inherit);
    for g in 0..10u16 {
        let mut grp = Group::new(
            Uuid([0x70, g as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            format!("Group {g}"),
            at(2026, 1, 1, 0, 0, 0),
        );
        for i in 0..1_000u16 {
            let n = g * 1_000 + i;
            let mut b = [0u8; 16];
            b[0] = 0x80;
            b[1..3].copy_from_slice(&n.to_be_bytes());
            let mut e = Entry::new(Uuid(b), at(2026, 1, 1, 0, 0, 0));
            set(&mut e, "Title", &format!("Demo site {n}"), false);
            let user = if n % 3 == 0 {
                format!("alex{n}@example.com")
            } else {
                format!("user{n}")
            };
            set(&mut e, "UserName", &user, false);
            set(
                &mut e,
                "Password",
                if n % 4 == 1 {
                    "hunter2"
                } else {
                    "Correct-Horse-Battery-9"
                },
                true,
            );
            set(
                &mut e,
                "URL",
                &format!("https://site{n}.example/login"),
                false,
            );
            set(
                &mut e,
                "Notes",
                &format!("Demo notes for entry {n}\nPIN {:04}", n % 10_000),
                false,
            );
            set(&mut e, "Custom", &format!("value {n}"), true);
            e.set_tags(if n % 2 == 0 {
                vec!["work".into()]
            } else {
                vec!["home".into(), "demo".into()]
            });
            grp.entries.push(e);
        }
        root.groups.push(grp);
    }
    Vault::new(root, at(2026, 1, 1, 0, 0, 0))
}

#[test]
fn fea01_34_speed_10000_entries() {
    // T64: under 50 ms in release (the best of 3 runs, so a busy Mac's
    // scheduler does not decide); the debug build gets 20 times that.
    let v = big_vault();
    let q = r"user:alex -tag:work *n:\d{4} is:weak g:/Vault";
    // LD-137: the session fills the rating cache off the screen thread;
    // `is:weak` then reads ratings, it does not estimate.
    let ratings = Ratings::new(&demo_strength);
    ratings.fill(&v);
    let warm = Options {
        ratings: Some(&ratings),
        ..Options::new(now())
    };
    let mut best = std::time::Duration::MAX;
    let mut count = 0;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let f = found(&v, q, &warm);
        best = best.min(started.elapsed());
        count = f.ids.len();
        assert!(!f.invalid);
    }
    // alex: n % 3 == 0; not work: n odd; weak: n % 4 == 1.
    assert_eq!(
        count,
        (0..10_000).filter(|n| n % 3 == 0 && n % 4 == 1).count()
    );
    let f = found(&v, r"user:alex -tag:work *n:\d{4} g:/Vault", &opts());
    assert_eq!(
        f.ids.len(),
        (0..10_000).filter(|n| n % 3 == 0 && n % 2 == 1).count()
    );
    println!("T64 best of 3: {best:?}");
    assert!(best < bound(50), "T64 took {best:?}");
    // Five default-field terms over every entry.
    let started = std::time::Instant::now();
    let f = found(&v, "demo site example notes entry", &opts());
    let five = started.elapsed();
    println!("five default terms: {five:?}");
    assert_eq!(f.ids.len(), 10_000);
    assert!(five < bound(50), "five terms took {five:?}");
}

#[test]
fn fea01_35_exact_tag_terms() {
    let v = s1();
    assert_eq!(search_tags(&v, &["work"], &opts()).ids, [uid(0x11)]); // T51
    assert_eq!(search_tags(&v, &["work", "dev"], &opts()).ids, [uid(0x11)]); // T53
    assert_eq!(search_tags(&v, &["WORK"], &opts()).ids, Vec::<Uuid>::new());
    assert_eq!(search::tag_display(&["work"]), "tag:\"work\"");
    // T52.
    let mut q = s1();
    q.root.entries[1].set_tags(vec!["say \"hi\"".into()]);
    assert_eq!(search_tags(&q, &["say \"hi\""], &opts()).ids, [uid(0x12)]);
    assert_eq!(search::tag_display(&["say \"hi\""]), r#"tag:"say \"hi\"""#);
    // T77, T78.
    let mut t = s1();
    t.root.entries[0].set_tags(vec!["a\\".into()]);
    t.root.entries[1].set_tags(vec!["a".into()]);
    t.root.groups[0].entries[0].set_tags(vec!["a\\\"b".into()]);
    assert_eq!(search_tags(&t, &["a\\"], &opts()).ids, [uid(0x11)]);
    assert_eq!(search_tags(&t, &["a\\\"b"], &opts()).ids, [uid(0x13)]);
    let mut g = s1();
    g.root.entries[0].set_tags(vec!["Work".into()]);
    g.root.entries[1].set_tags(vec!["work".into()]);
    g.root.groups[0].entries[0].set_tags(vec!["x*".into()]);
    g.root.groups[3].entries[0].set_tags(vec!["xyz".into()]);
    assert_eq!(search_tags(&g, &["work"], &opts()).ids, [uid(0x12)]);
    assert_eq!(search_tags(&g, &["x*"], &opts()).ids, [uid(0x13)]);
    // The bin stays out.
    let mut b = s1();
    b.root.groups[2].entries[0].set_tags(vec!["work".into()]);
    b.root.groups[2].searching = Switch::On;
    assert_eq!(search_tags(&b, &["work"], &opts()).ids, [uid(0x11)]);
}

/// A demo id: a tag byte, then `n`.
fn uidn(tag: u8, n: u32) -> Uuid {
    let mut b = [0u8; 16];
    b[0] = tag;
    b[1..5].copy_from_slice(&n.to_be_bytes());
    b[15] = 1;
    Uuid(b)
}

fn hex_upper(u: Uuid) -> String {
    u.0.iter().map(|b| format!("{b:02X}")).collect()
}

fn flat_vault(entries: Vec<Entry>) -> Vault {
    let mut root = group(0x01, "Vault", Switch::Inherit);
    root.entries = entries;
    Vault::new(root, at(2026, 1, 1, 0, 0, 0))
}

/// One release run: under 250 ms; a run that spent its meter shows the
/// notice; the meter never goes past [`search::RUN_BUDGET`].
fn bounded_run(label: &str, v: &Vault, q: &str) -> Found {
    let started = std::time::Instant::now();
    let f = found(v, q, &opts());
    let took = started.elapsed();
    println!(
        "{label}: {took:?}, spent {} of {}, notice {}",
        f.spent,
        search::RUN_BUDGET,
        f.invalid
    );
    assert!(
        took < std::time::Duration::from_millis(250),
        "{label}: {took:?}"
    );
    assert!(f.spent <= search::RUN_BUDGET);
    if f.spent == search::RUN_BUDGET {
        assert!(f.invalid, "{label}: an empty meter shows the notice");
    }
    f
}

/// FEA-01.32 and LD-126, release timing: hostile vaults stay under 250 ms
/// a run. a/b notes whose patterns make the lazy DFA give up; references
/// to 1,000,000 characters of notes in every title, user name and URL
/// (the Checker's S8-B1 vault: 1.3 / 12.7 / 136 s before); regex replaces
/// in every resolved field (10.4 s before); a cheap placeholder in every
/// user name over 40,000 entries (808 ms before the index); 16 terms that
/// all hold over 10,000 entries.
#[test]
#[cfg_attr(debug_assertions, ignore = "release timing test: cargo test --release")]
fn fea01_32_hostile_runs_stay_bounded() {
    let mut x: u32 = 99;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let ab: Vec<Entry> = (0..781u32)
        .map(|i| {
            let notes: String = (0..8_192)
                .map(|_| if rnd() % 2 == 0 { 'a' } else { 'b' })
                .collect();
            let mut e = ent(0x30, &format!("n{i}"), "", "", "", &notes, &[]);
            e.uuid = uidn(0x30, i);
            e
        })
        .collect();
    let v = flat_vault(ab);
    let many: String = (0..16)
        .map(|i| format!("-*n:(?-i)(?:[ab]{{1,15}}){{1,{}}}[0-9] ", 10 + i))
        .collect();
    for q in [
        "-*n:(?-i)(?:[ab]{1,15}){1,15}[0-9]",
        "-*n:(?-i)(?:[ab]{1,20}){1,20}[0-9]",
        "-*n:(?-i)(?:[ab]{1,25}){1,25}[0-9]",
        "-*n:(?-i)[ab]*a[ab]{20}c",
        "-n:*a?????????????????????????c",
        "-*(:?[a-z]{1,30}){1,30}`0-9]",
        &many,
    ] {
        bounded_run(&format!("a/b notes {q:.40}"), &v, q);
    }
    // Normal patterns on the same notes stay within the meter.
    let f = found(&v, "-*n:(?-i)(?:[ab]{1,6}){1,6}[0-9]", &opts());
    assert!(!f.invalid && f.ids.len() == 781);

    // References to 1,000,000 characters of notes.
    for n in [100u32, 1_000, 10_000] {
        let target = uidn(0x50, 0);
        let mut big = Entry::new(target, at(2026, 1, 1, 0, 0, 0));
        set(&mut big, "Notes", &"b".repeat(1_000_000), false);
        let r = format!("{{REF:N@I:{}}}", hex_upper(target));
        let mut es = vec![big];
        for i in 1..=n {
            let mut e = Entry::new(uidn(0x50, i), at(2026, 1, 1, 0, 0, 0));
            for f in ["Title", "UserName", "URL"] {
                set(&mut e, f, &r, false);
            }
            es.push(e);
        }
        let v = flat_vault(es);
        let f = bounded_run(&format!("refs to 1M notes, n={n}, zzz"), &v, "zzz");
        assert!(f.invalid && f.ids.is_empty());
        bounded_run(&format!("refs to 1M notes, n={n}, t:zzz"), &v, "t:zzz");
        bounded_run(&format!("refs to 1M notes, n={n}, -zzz"), &v, "-zzz");
    }

    // Regex replaces in every resolved field (LD-113's largest patterns).
    for len in [65_536usize, 16_384, 1_000] {
        let largest = (1..=120usize)
            .rev()
            .find(|n| {
                larsal_core::pattern::compile_for(&format!("(?:[a-z]{{1,{n}}}){{1,{n}}}x"), len)
                    .is_some()
            })
            .unwrap();
        let source = uidn(0x60, 0);
        let mut big = Entry::new(source, at(2026, 1, 1, 0, 0, 0));
        set(&mut big, "Notes", &"a".repeat(len), false);
        let mut title = String::new();
        for k in 0..8 {
            let n = largest - k;
            title.push_str(&format!(
                "{{T-REPLACE-RX:/{{REF:N@I:{}}}/(?:[a-z]{{1,{n}}}){{1,{n}}}x/X/}}",
                hex_upper(source)
            ));
        }
        let mut es = vec![big];
        for i in 1..=30u32 {
            let mut e = Entry::new(uidn(0x60, i), at(2026, 1, 1, 0, 0, 0));
            for f in ["Title", "UserName", "URL", "Password"] {
                set(&mut e, f, &title, false);
            }
            es.push(e);
        }
        let v = flat_vault(es);
        bounded_run(
            &format!("8 regex replaces over {len}, 30 entries, zzz"),
            &v,
            "zzz",
        );
        bounded_run(
            &format!("8 regex replaces over {len}, 30 entries, pw:zzz"),
            &v,
            "pw:zzz is:weak",
        );
    }

    // A cheap placeholder in every user name: one index per run.
    for n in [10_000u32, 40_000] {
        let es = (0..n)
            .map(|i| {
                let mut e = Entry::new(uidn(0x40, i), at(2026, 1, 1, 0, 0, 0));
                set(&mut e, "Title", &format!("t{i}"), false);
                set(&mut e, "UserName", "{TITLE}", false);
                e
            })
            .collect();
        let v = flat_vault(es);
        if n == 10_000 {
            let f = bounded_run("{TITLE} user names, n=10000, u:t9999", &v, "u:t9999");
            assert_eq!(f.ids, [uidn(0x40, 9_999)]);
            assert!(!f.invalid, "10,000 cheap resolutions fit the meter");
        } else {
            bounded_run("{TITLE} user names, n=40000, zzz", &v, "zzz");
        }
    }

    // 16 terms (the LD-124 cap) that all hold, over 10,000 entries.
    let big = big_vault();
    for q in [
        (0..16).map(|i| format!("-*a{i} ")).collect::<String>(),
        (0..16).map(|i| format!("-q{i} ")).collect::<String>(),
    ] {
        let f = bounded_run(&format!("16 terms over 10,000 {q:.12}"), &big, &q);
        assert!(
            !f.invalid && f.ids.len() == 10_000,
            "normal terms fit the meter"
        );
    }
}

/// The `search_query` fuzz target's vault (fuzz/fuzz_targets/search_query.rs;
/// change both together).
fn fuzz_vault() -> Vault {
    let e = |b: u8, fields: &[(&str, &str)], tags: &[&str]| {
        let mut e = Entry::new(Uuid([b; 16]), Time(0));
        for (n, v) in fields {
            set(&mut e, n, v, *n == "Password");
        }
        e.set_tags(tags.iter().map(|t| (*t).to_owned()).collect());
        e
    };
    let mut root = Group::new(Uuid([1; 16]), "Vault".into(), Time(0));
    root.entries.push(e(
        0x11,
        &[
            ("Title", "GitHub"),
            ("UserName", "alex@example.com"),
            ("Password", "Tr0ub4dor&3"),
            ("URL", "https://github.com/login"),
            ("Notes", "Work account\nrecovery codes"),
        ],
        &["work", "dev"],
    ));
    root.entries.push(e(
        0x12,
        &[
            ("Title", "Ref {USERNAME}"),
            ("UserName", "{REF:U@I:11111111111111111111111111111111}"),
            ("Password", "{S:Secret}"),
            ("Secret", "blue whale"),
            ("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
        ],
        &["say \"hi\"", "a\\"],
    ));
    let mut sub = Group::new(Uuid([2; 16]), "Sub".into(), Time(0));
    let mut x = e(
        0x13,
        &[("Title", "Éclair 🔑"), ("Notes", &"ab".repeat(2_000))],
        &["x*"],
    );
    x.times.expires = true;
    sub.entries.push(x);
    let mut off = Group::new(Uuid([3; 16]), "Off".into(), Time(0));
    off.searching = Switch::Off;
    off.entries.push(e(0x14, &[("Title", "hidden")], &[]));
    let mut bin = Group::new(Uuid([4; 16]), "Bin".into(), Time(0));
    bin.searching = Switch::On;
    bin.entries
        .push(e(0x15, &[("Title", "deleted GitHub")], &["work"]));
    root.groups.extend([sub, off, bin]);
    let mut v = Vault::new(root, Time(0));
    v.meta.recycle_bin = Some(Uuid([4; 16]));
    v
}

/// Inputs the `search_query` fuzz target once failed on, as it reads them
/// (a flag byte, then the query). Also written to its seed corpus by
/// `fuzz_seeds.rs`.
pub const FUZZ_REGRESSIONS: &[&[u8]] = &[
    // S8-B2: the lazy DFA filled its cache on the 4,000-character note
    // before it gave up (3 s in the sanitizer build).
    b"-*(:?[a-z]{1,30}){1,30}`0-9]",
];

#[test]
fn fea01_32_fuzz_regressions() {
    let v = fuzz_vault();
    for input in FUZZ_REGRESSIONS {
        let (&flags, rest) = input.split_first().unwrap();
        let query = String::from_utf8_lossy(rest);
        let o = Options {
            case_sensitive: flags & 1 != 0,
            base: (flags & 2 != 0).then_some(Uuid([2; 16])),
            ..Options::new(Time(63_928_466_236))
        };
        let started = std::time::Instant::now();
        let f = search(&v, &query, &o).unwrap();
        assert!(started.elapsed() < bound(250), "{query}");
        assert!(f.spent <= search::RUN_BUDGET);
        if f.spent == search::RUN_BUDGET {
            assert!(f.invalid);
        }
        // The DFA's give-up and the slow engine are paid: this one input
        // costs over half the run's meter.
        assert!(
            f.spent > search::RUN_BUDGET / 2,
            "{query}: spent {}",
            f.spent
        );
        assert!(f.ids.iter().all(|id| [0x11, 0x12, 0x13].contains(&id.0[0])));
        if flags & 4 != 0 {
            let tags: Vec<&str> = query.split(',').take(16).collect();
            assert!(search_tags(&v, &tags, &o).ids.is_empty());
        }
    }
}

/// F-046 and LD-127, release timing: Verify's field-heavy vaults. Every
/// field visit is paid, and an empty meter ends the walk, so an
/// `attribute:` run stays under 250 ms (251 to 408 ms before). Each case is
/// the best of 3 runs, so a busy Mac's scheduler does not decide; a
/// `title:` run on the same vault is unchanged.
#[test]
#[cfg_attr(debug_assertions, ignore = "release timing test: cargo test --release")]
fn fea01_32_field_heavy_vaults_stay_bounded() {
    let sixteen: String = (0..16).map(|i| format!("attribute:zz?{i} ")).collect();
    for (entries, fields) in [(10_000u32, 1_500usize), (10_000, 2_000), (100_000, 200)] {
        let names: Vec<String> = (0..fields).map(|i| format!("f{i:04}")).collect();
        let es: Vec<Entry> = (0..entries)
            .map(|i| {
                let mut e = Entry::new(uidn(0x70, i), at(2026, 1, 1, 0, 0, 0));
                let mut all: Vec<(String, Field)> =
                    names.iter().map(|n| (n.clone(), field("v"))).collect();
                all.push(("Title".into(), field(&format!("t{i}"))));
                e.replace_fields(all);
                e
            })
            .collect();
        let v = flat_vault(es);
        for q in ["attribute:zzz", sixteen.as_str(), "title:zzz"] {
            let mut best = std::time::Duration::MAX;
            let mut last = None;
            for _ in 0..3 {
                let started = std::time::Instant::now();
                let f = found(&v, q, &opts());
                best = best.min(started.elapsed());
                last = Some(f);
            }
            let f = last.unwrap();
            println!(
                "{entries} entries x {fields} fields, {q:.20}: {best:?}, spent {} of {}, notice {}",
                f.spent,
                search::RUN_BUDGET,
                f.invalid
            );
            assert!(best < std::time::Duration::from_millis(250), "{best:?}");
            assert!(f.ids.is_empty() && f.spent <= search::RUN_BUDGET);
            if q.starts_with("attribute") {
                assert!(f.invalid, "the meter runs out, the notice shows");
            } else {
                assert!(!f.invalid, "title: never walks the fields");
            }
        }
    }
}

fn field(v: &str) -> Field {
    Field {
        value: SecretString::new(v.to_owned()),
        protected: false,
    }
}

/// LD-185: which queries need the ratings filled first.
#[test]
fn ld185_rates_names_is_weak_queries() {
    use larsal_core::search::rates;
    for q in [
        "is:weak",
        "IS:Weak",
        "title:x is:weak",
        "-is:weak",
        "is:\"weak\"",
    ] {
        assert!(rates(q), "{q}");
    }
    for q in ["weak", "is:expired", "*is:weak", "title:is:weak", ""] {
        assert!(!rates(q), "{q}");
    }
}
