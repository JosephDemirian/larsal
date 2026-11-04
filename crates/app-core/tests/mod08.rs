//! E4-S6: the rules of MOD-08 (references and placeholders), on the card's
//! vault R8. Each test names its rule.

mod common;

use app_core::edit::holds_reference;
use app_core::recycle::{References, delete_entries};
use app_core::refs::{Context, MASK, browser_refuses, holds_any_reference, reference, resolve};
use app_core::url::{Open, command_words, open_kind, question_text, remember_key, vault_link_path};
use app_crypto::secret::SecretString;
use app_model::{Entry, Field, Group, Vault};
use common::*;

fn set(e: &mut Entry, name: &str, value: &str) {
    let protected = e.field(name).is_some_and(|f| f.protected);
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected,
        },
    );
}

fn mk(n: u8, title: &str, fields: &[(&str, &str)]) -> Entry {
    let mut e = entry(n, title);
    for (k, v) in fields {
        set(&mut e, k, v);
    }
    e
}

fn hx(n: u8) -> String {
    format!("{n:02x}").repeat(16)
}

/// Vault R8 (MOD-08 test cases): entries 1 to 9 in search order.
fn r8() -> Vault {
    let probe = mk(
        0x0f,
        "Probe",
        &[
            ("UserName", "probe-user"),
            ("Password", "{PASSWORD}"),
            ("URL", "https://u:pw@example.com:8443/p/a.php?q=1&r=2#frag"),
            ("Custom1", "cval"),
        ],
    );
    let alpha = mk(
        0x0a,
        "Alpha",
        &[
            ("UserName", "alice"),
            ("Password", "pw-A"),
            ("URL", "https://alpha.example"),
            ("Notes", "note-A"),
            ("Custom1", "cval"),
            ("Mixed", "x{TITLE}y{USERNAME}z"),
        ],
    );
    let b = mk(
        0x0b,
        &format!("{{REF:T@I:{}}}", hx(0x0c)),
        &[("UserName", "bob")],
    );
    let c = mk(
        0x0c,
        &format!("{{REF:T@I:{}}}", hx(0x0b)),
        &[("UserName", "carol")],
    );
    let no_port = mk(
        0x77,
        "NoPort",
        &[
            ("UserName", "{URL:PORT}|{URL:HOST}|{URL:SCM}"),
            ("URL", "example.org/x"),
        ],
    );
    let nested = mk(
        0x88,
        "Nested",
        &[
            ("UserName", &format!("{{REF:U@I:{}}}-{{S:Extra}}", hx(0x0a))),
            ("Extra", "{TITLE}"),
        ],
    );
    let dup = mk(0x11, "Dup", &[("UserName", "root")]);
    let mut sub = Group::new(id(0x31), "Sub".into(), T0);
    sub.entries.push(mk(0x22, "Dup", &[("UserName", "sub")]));
    let mut bin = Group::new(id(0x32), "Recycle Bin".into(), T0);
    bin.entries
        .push(mk(0x44, "Binned", &[("UserName", "binned-user")]));
    let mut root = Group::new(id(1), "Root".into(), T0);
    root.entries = vec![probe, alpha, b, c, no_port, nested, dup];
    root.groups = vec![sub, bin];
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin = Some(id(0x32));
    v
}

/// Resolves `text` in live entry `n` of `v`.
fn res(v: &Vault, n: u8, text: &str) -> String {
    res_ctx(v, n, text, &Context::new(Some(v), T0))
}

fn res_ctx(v: &Vault, n: u8, text: &str, ctx: &Context<'_>) -> String {
    let e = find(v, id(n));
    resolve(text, e, ctx).text.expose().to_owned()
}

/// Resolves live entry `n`'s field `name`.
fn field_of(v: &Vault, n: u8, name: &str) -> String {
    let e = find(v, id(n));
    res(v, n, e.value(name))
}

#[test]
fn mod_08_1_spans() {
    let v = r8();
    for t in ["{TITLE", "TITLE}", "{}", "{{FOO}}", "}{", "{{}}"] {
        assert_eq!(res(&v, 0x0f, t), t, "{t}");
    }
    assert_eq!(
        res(&v, 0x0f, "{a{TITLE}"),
        "{aProbe",
        "in {{a{{b}} the span is {{b}}"
    );
    assert_eq!(res(&v, 0x0f, "x{TITLE}y{URL:SCM}"), "xProbeyhttps");
}

#[test]
fn mod_08_2_escape() {
    let v = r8();
    assert_eq!(res(&v, 0x0f, "\\{TITLE\\}"), "{TITLE}");
    assert_eq!(res(&v, 0x0f, "a\\{TITLE\\}b"), "a\\{TITLE\\}b");
    // Also for a value reached through another placeholder.
    let mut w = r8();
    w.root.entries[0].set_field("Esc".into(), field("\\{USERNAME\\}"));
    assert_eq!(res(&w, 0x0f, "{S:Esc}"), "{USERNAME}");
}

#[test]
fn mod_08_3_classification() {
    let v = r8();
    for t in ["{TITLE}", "{title}", "{Title}"] {
        assert_eq!(res(&v, 0x0f, t), "Probe");
    }
    assert_eq!(res(&v, 0x0f, "{s:Custom1}"), "{s:Custom1}");
    let lower = format!("{{ref:u@i:{}}}", hx(0x0a));
    assert_eq!(res(&v, 0x0f, &lower), lower);
    assert_eq!(res(&v, 0x0f, &format!("{{REF:u@i:{}}}", hx(0x0a))), "alice");
    assert_eq!(res(&v, 0x0f, "{t-conv:/AbC/l/}"), "abc", "T-CONV any case");
}

#[test]
fn mod_08_4_fixed_placeholders() {
    let v = r8();
    let cases = [
        ("{url:host}", "example.com"),
        ("{URL:SCHEME}", "https"),
        (
            "{url:withoutscheme}",
            "//u:pw@example.com:8443/p/a.php?q=1&r=2#frag",
        ),
        ("{USERNAME}", "probe-user"),
        ("{NOTES}", ""),
        (
            "{URL}",
            "https://u:pw@example.com:8443/p/a.php?q=1&r=2#frag",
        ),
        ("{UUID}", &hx(0x0f)),
        ("{DB_DIR}", ""),
    ];
    for (t, want) in cases {
        assert_eq!(res(&v, 0x0f, t), want, "{t}");
    }
}

#[test]
fn mod_08_5_unknown_spans() {
    let v = r8();
    let cases = [
        ("{FOO}", "{FOO}".to_owned()),
        ("{ {TITLE} }", "{ Probe }".to_owned()),
        ("{{TITLE}}", "{Probe}".to_owned()),
        ("{{S:Custom1}}", "{cval}".to_owned()),
        (
            &format!("{{{{REF:U@I:{}}}}}", hx(0x0a)),
            "{alice}".to_owned(),
        ),
    ];
    for (t, want) in cases {
        assert_eq!(res(&v, 0x0f, t), want, "{t}");
    }
}

#[test]
fn mod_08_6_standard_fields_chain() {
    let mut v = r8();
    set(&mut v.root.entries[1], "Title", "{USERNAME}");
    set(&mut v.root.entries[1], "UserName", "{S:Login}");
    set(&mut v.root.entries[1], "Login", "demo-login");
    assert_eq!(field_of(&v, 0x0a, "Title"), "demo-login");
}

#[test]
fn mod_08_7_custom_fields() {
    let mut v = r8();
    set(&mut v.root.entries[0], "P01", "{TITLE}");
    let cases = [
        ("{S:Custom1}", "cval"),
        ("{S:custom1}", ""),
        ("{S:Missing}", ""),
        ("{S:UserName}", "probe-user"),
        ("{S:P01}", "Probe"),
        ("{S:}", ""),
        ("{S:{TITLE}}", ""),
    ];
    for (t, want) in cases {
        assert_eq!(res(&v, 0x0f, t), want, "{t}");
    }
}

#[test]
fn mod_08_8_uuid() {
    let v = r8();
    assert_eq!(res(&v, 0x0f, "{UUID}"), "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
}

/// One entry per URL row of MOD-08.9; UserName = the ten placeholders.
#[test]
fn mod_08_9_url_parts() {
    let rows: [(&str, [&str; 10]); 14] = [
        (
            "https://u:pw@example.com:8443/p/a.php?q=1&r=2#frag",
            [
                "https",
                "example.com",
                "8443",
                "/p/a.php",
                "q=1&r=2",
                "frag",
                "u:pw",
                "u",
                "pw",
                "//u:pw@example.com:8443/p/a.php?q=1&r=2#frag",
            ],
        ),
        (
            "https://Example.COM/A%20B/c?x=%41&y=1#F%20g",
            [
                "https",
                "example.com",
                "-1",
                "/A B/c",
                "x=A&y=1",
                "F g",
                "",
                "",
                "",
                "//example.com/A B/c?x=A&y=1#F g",
            ],
        ),
        (
            "https://example.com",
            [
                "https",
                "example.com",
                "-1",
                "",
                "",
                "",
                "",
                "",
                "",
                "//example.com",
            ],
        ),
        (
            "http://example.com:80/",
            [
                "http",
                "example.com",
                "80",
                "/",
                "",
                "",
                "",
                "",
                "",
                "//example.com:80/",
            ],
        ),
        (
            "example.com",
            [
                "",
                "",
                "-1",
                "example.com",
                "",
                "",
                "",
                "",
                "",
                "example.com",
            ],
        ),
        (
            "https://[::1]:8080/x",
            [
                "https",
                "::1",
                "8080",
                "/x",
                "",
                "",
                "",
                "",
                "",
                "//[::1]:8080/x",
            ],
        ),
        (
            "https://bücher.example/",
            [
                "https",
                "xn--bcher-kva.example",
                "-1",
                "/",
                "",
                "",
                "",
                "",
                "",
                "//xn--bcher-kva.example/",
            ],
        ),
        (
            "ftp://user@host.example:21/file.txt",
            [
                "ftp",
                "host.example",
                "21",
                "/file.txt",
                "",
                "",
                "user",
                "user",
                "",
                "//user@host.example:21/file.txt",
            ],
        ),
        (
            "https://user%40mail:p%3Ass@host.example/",
            [
                "https",
                "host.example",
                "-1",
                "/",
                "",
                "",
                "user@mail:p%3Ass",
                "user@mail",
                "p:ss",
                "//user%40mail:p%3Ass@host.example/",
            ],
        ),
        (
            "https://example.com:/x",
            [
                "https",
                "example.com",
                "-1",
                "/x",
                "",
                "",
                "",
                "",
                "",
                "//example.com/x",
            ],
        ),
        (
            "mailto:a@b.example",
            [
                "mailto",
                "",
                "-1",
                "a@b.example",
                "",
                "",
                "",
                "",
                "",
                "a@b.example",
            ],
        ),
        (
            "HTTPS://EXAMPLE.COM/Path",
            [
                "https",
                "example.com",
                "-1",
                "/Path",
                "",
                "",
                "",
                "",
                "",
                "//example.com/Path",
            ],
        ),
        (
            "https://exa mple.com/a b",
            ["https", "", "-1", "/a b", "", "", "", "", "", ""],
        ),
        (
            "cmd://open -a Safari https://x.example",
            ["cmd", "", "-1", "//x.example", "", "", "", "", "", ""],
        ),
    ];
    let user = "{URL:SCM}|{URL:HOST}|{URL:PORT}|{URL:PATH}|{URL:QUERY}|{URL:FRAGMENT}|{URL:USERINFO}|{URL:USERNAME}|{URL:PASSWORD}|{URL:RMVSCM}";
    let mut v = r8();
    for (i, (url, _)) in rows.iter().enumerate() {
        v.root
            .entries
            .push(mk(0xa0 + i as u8, "U", &[("URL", url), ("UserName", user)]));
    }
    for (i, (url, want)) in rows.iter().enumerate() {
        assert_eq!(
            field_of(&v, 0xa0 + i as u8, "UserName"),
            want.join("|"),
            "{url}"
        );
    }
    // LD-58: hosts always in ASCII.
    for (url, host) in [
        ("https://bücher.com/", "xn--bcher-kva.com"),
        ("https://bücher.de/", "xn--bcher-kva.de"),
        ("https://xn--bcher-kva.de/", "xn--bcher-kva.de"),
        ("https://bücher.fr/", "xn--bcher-kva.fr"),
    ] {
        let mut w = r8();
        set(&mut w.root.entries[1], "URL", url);
        assert_eq!(res(&w, 0x0a, "{URL:HOST}"), host);
        assert_eq!(res(&w, 0x0a, "{URL:RMVSCM}"), format!("//{host}/"));
    }
    // No port, and an empty URL.
    assert_eq!(field_of(&v, 0x77, "UserName"), "-1||");
    let mut w = r8();
    set(&mut w.root.entries[1], "URL", "");
    assert_eq!(res(&w, 0x0a, "{URL:PORT}"), "");
}

#[test]
fn mod_08_10_date_and_time() {
    let v = r8();
    let now = at(2026, 10, 24, 22, 46, 28);
    let zone = Fixed(7200);
    let mut ctx = Context::new(Some(&v), now);
    ctx.zone = &zone;
    let r = |t: &str| res_ctx(&v, 0x0f, t, &ctx);
    assert_eq!(r("{DT_SIMPLE}"), "20261025004628");
    assert_eq!(r("{DT_UTC_SIMPLE}"), "20261024224628");
    assert_eq!(
        r("{DT_YEAR}-{DT_MONTH}-{DT_DAY} {DT_HOUR}:{DT_MINUTE}:{DT_SECOND}"),
        "2026-10-25 00:46:28"
    );
    assert_eq!(r("{DT_UTC_HOUR}{dt_utc_minute}"), "2246");
}

#[test]
fn mod_08_11_db_dir() {
    let v = r8();
    let mut ctx = Context::new(Some(&v), T0);
    ctx.vault_dir = "/private/tmp/spec-mod08-10";
    assert_eq!(
        res_ctx(&v, 0x0f, "{DB_DIR}", &ctx),
        "/private/tmp/spec-mod08-10"
    );
    assert_eq!(res(&v, 0x0f, "{DB_DIR}"), "", "never saved (D-08-8)");
}

#[test]
fn mod_08_12_one_time_codes() {
    let v = r8();
    assert_eq!(res(&v, 0x0f, "{TOTP}{TIMEOTP}"), "", "none: empty (D-08-7)");
    let mut ctx = Context::new(Some(&v), T0);
    ctx.otp = |e, _| (e.value("Title") == "Probe").then(|| SecretString::new("123456".into()));
    assert_eq!(res_ctx(&v, 0x0f, "{TOTP}|{totp}", &ctx), "123456|123456");
    assert_eq!(res_ctx(&v, 0x0a, "{TOTP}", &ctx), "");
}

#[test]
fn mod_08_13_reference_syntax() {
    let v = r8();
    let a = hx(0x0a);
    let cases = [
        (format!("{{REF:U@I:{}}}", a.to_uppercase()), "alice"),
        (format!("{{REF:U@I:{a}}}"), "alice"),
        ("{REF:T@U:alice}".into(), "Alpha"),
        ("{REF:I@T:Alpha}".into(), "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
        ("{REF:N@T:Alpha}".into(), "note-A"),
        ("{REF:A@T:Alpha}".into(), "https://alpha.example"),
        ("{REF:T@A:https://alpha.example}".into(), "Alpha"),
        ("{REF:T@N:note-A}".into(), "Alpha"),
        ("{REF:T@P:pw-A}".into(), "Alpha"),
    ];
    for (t, want) in &cases {
        assert_eq!(res(&v, 0x0f, t), *want, "{t}");
    }
    for bad in [
        "{REF:X@T:Alpha}",
        "{REF:O@T:Alpha}",
        "{REF:T@T:}",
        "{REF:T#T:Alpha}",
    ] {
        assert_eq!(res(&v, 0x0f, bad), bad, "stays as written");
    }
}

#[test]
fn mod_08_14_search_text_resolved_first() {
    let mut v = r8();
    set(&mut v.root.entries[0], "Target", &hx(0x0a));
    assert_eq!(res(&v, 0x0f, "{REF:T@I:{UUID}}"), "Probe");
    assert_eq!(res(&v, 0x0f, "{REF:T@I:{S:Target}}"), "Alpha");
}

#[test]
fn mod_08_15_which_entry_is_found() {
    let v = r8();
    assert_eq!(res(&v, 0x0f, "{REF:U@T:Dup}"), "root", "root entries first");
    assert_eq!(
        res(&v, 0x0f, "{REF:U@T:Binned}"),
        "binned-user",
        "the bin counts"
    );
    assert_eq!(
        res(&v, 0x0f, "{REF:T@O:cval}"),
        "Probe",
        "the referring entry counts"
    );
    assert_eq!(res(&v, 0x0f, "{REF:T@O:alice}"), "Alpha");
    for t in [
        "{REF:T@T:alpha}",
        "{REF:T@U:ALICE}",
        "{REF:T@T:Alpha }",
        "{REF:P@T:Nonexistent}",
    ] {
        assert_eq!(res(&v, 0x0f, t), "", "{t}");
    }
    let a = hx(0x0a);
    let cases = [
        (
            "{REF:T@I:0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a}".to_owned(),
            "Alpha",
        ),
        (format!("{{REF:T@I: {a} }}"), "Alpha"),
        ("{REF:U@I:0A0A}".to_owned(), ""),
        (format!("{{REF:T@I:{}}}", "0a".repeat(15)), ""),
        (format!("{{REF:T@I:a{}}}", "0a".repeat(15)), "Alpha"),
        (format!("{{REF:T@I:{}0}}", "0a".repeat(16)), ""),
    ];
    for (t, want) in &cases {
        assert_eq!(res(&v, 0x0f, t), *want, "{t}");
    }
    // 30 digits are 15 bytes: no match, even for an id whose first byte is 0.
    let mut z = r8();
    let mut lead = [0x0a; 16];
    lead[0] = 0;
    let mut e = mk(0x01, "Lead", &[]);
    e.uuid = app_model::Uuid(lead);
    z.root.entries.push(e);
    assert_eq!(
        res(&z, 0x0f, &format!("{{REF:T@I:{}}}", "0a".repeat(15))),
        ""
    );
    assert_eq!(
        res(&z, 0x0f, &format!("{{REF:T@I:00{}}}", "0a".repeat(15))),
        "Lead"
    );
    // History items are never searched.
    let mut w = r8();
    let mut old = w.root.entries[1].duplicate(false);
    set(&mut old, "Title", "OldTitle");
    w.root.entries[1].history.push(old);
    assert_eq!(res(&w, 0x0f, "{REF:U@T:OldTitle}"), "");
}

#[test]
fn mod_08_16_result_in_the_found_entry() {
    let v = r8();
    assert_eq!(field_of(&v, 0x88, "UserName"), "alice-Nested");
    assert_eq!(
        res(
            &v,
            0x0f,
            &format!("{{REF:U@I:{0}}} and {{REF:P@I:{0}}}", hx(0x0a))
        ),
        "alice and pw-A"
    );
    // The found value resolves in the found entry: Alpha's Mixed field.
    let mut w = r8();
    set(&mut w.root.entries[1], "Notes", "{S:Mixed}");
    assert_eq!(res(&w, 0x0f, "{REF:N@T:Alpha}"), "xAlphayalicez");
}

#[test]
fn mod_08_17_standard_fields_only() {
    let mut v = r8();
    v.root
        .entries
        .push(mk(0x55, "T2", &[("Notes", "{S:Pin}"), ("Pin", "1234")]));
    assert_eq!(res(&v, 0x0f, "{REF:N@T:T2}"), "1234");
}

#[test]
fn mod_08_18_depth_budget() {
    let mut v = r8();
    assert_eq!(res(&v, 0x0f, "{PASSWORD}"), "{PASSWORD}");
    set(&mut v.root.entries[1], "Title", "{TITLE}");
    assert_eq!(field_of(&v, 0x0a, "Title"), "{TITLE}");
    set(&mut v.root.entries[1], "Title", "{USERNAME}!");
    set(&mut v.root.entries[1], "UserName", "{TITLE}?");
    assert_eq!(field_of(&v, 0x0a, "Title"), "{TITLE}?!?!?!");
    assert_eq!(
        field_of(&v, 0x0b, "Title"),
        format!("{{REF:T@I:{}}}", hx(0x0b))
    );
    set(&mut v.root.entries[0], "Loop1", "{S:Loop2}");
    set(&mut v.root.entries[0], "Loop2", "{S:Loop1}");
    assert_eq!(res(&v, 0x0f, "{S:Loop1}"), "{S:Loop2}");
    assert_eq!(res(&v, 0x0f, "{{{{{TITLE}}}}}"), "{{{{Probe}}}}");
    assert_eq!(res(&v, 0x0f, "{{{{{{TITLE}}}}}}"), "{{{{{{TITLE}}}}}}");
    let e = find(&v, id(0x0f));
    assert!(resolve("{PASSWORD}", e, &Context::new(Some(&v), T0)).depth_hit);
    // The search text as one span (08-46), on a fresh R8.
    let mut v = r8();
    set(&mut v.root.entries[0], "SA", "Al");
    set(&mut v.root.entries[0], "SB", "pha");
    set(&mut v.root.entries[0], "SC", "Alpha");
    for (t, want) in [
        ("{REF:U@T:{S:SA}{S:SB}}", ""),
        ("{REF:U@T:Al{S:SB}}", "alice"),
        ("{REF:U@T:{S:SC}}", "alice"),
        ("{REF:U@I:{UUID}x{TITLE}}", ""),
    ] {
        assert_eq!(res(&v, 0x0f, t), want, "{t}");
    }
}

#[test]
fn mod_08_19_no_fresh_budgets() {
    let mut v = r8();
    v.root.entries.push(mk(
        0x61,
        "C1",
        &[("UserName", "{T-CONV:/{USERNAME}/upper/}")],
    ));
    v.root.entries.push(mk(
        0x62,
        "C2",
        &[("UserName", "{T-REPLACE-RX:/{USERNAME}/a/b/}")],
    ));
    v.root.entries.push(mk(0x63, "{REF:T@T:{TITLE}}", &[]));
    let started = std::time::Instant::now();
    assert_eq!(field_of(&v, 0x61, "UserName"), "{USERNAME}");
    assert_eq!(field_of(&v, 0x62, "UserName"), "{USERNAME}");
    assert_eq!(field_of(&v, 0x63, "Title"), "");
    assert!(started.elapsed().as_millis() < 50 * 3);
}

#[test]
fn mod_08_20_work_bound() {
    let mut v = r8();
    v.root
        .entries
        .push(mk(0x64, "W4", &[("UserName", &"{USERNAME}".repeat(4))]));
    v.root
        .entries
        .push(mk(0x65, "W8", &[("UserName", &"{USERNAME}".repeat(8))]));
    let four = field_of(&v, 0x64, "UserName");
    assert_eq!(four.len(), 40_960, "as the reference");
    assert_eq!(four, "{USERNAME}".repeat(4096));
    let e = find(&v, id(0x65));
    let r = resolve(e.value("UserName"), e, &Context::new(Some(&v), T0));
    assert!(r.bounded);
    assert_eq!(
        r.text.expose(),
        "{USERNAME}".repeat(8),
        "the raw 80 characters"
    );
    // A huge value is returned raw even without a placeholder.
    let huge = "x".repeat(1_048_577);
    let p = find(&v, id(0x0f));
    assert_eq!(
        resolve(&huge, p, &Context::new(Some(&v), T0)).text.expose(),
        huge
    );
    // A conversion that drops a large text many times stops on total work.
    let mut w = r8();
    let big = "a".repeat(900_000);
    w.root.entries.push(mk(
        0x66,
        "Heavy",
        &[
            ("B", &big),
            ("X", "{T-CONV:/{S:B}/junk/}"),
            ("UserName", &"{S:X}".repeat(3000)),
        ],
    ));
    let started = std::time::Instant::now();
    let e = find(&w, id(0x66));
    let r = resolve(e.value("UserName"), e, &Context::new(Some(&w), T0));
    assert!(r.bounded);
    assert!(started.elapsed().as_secs() < 2);
}

#[test]
fn mod_08_21_conversions() {
    let v = r8();
    let cases = [
        ("{T-CONV:/{USERNAME}/upper/}", "PROBE-USER"),
        ("{t-conv:/AbC/l/}", "abc"),
        ("{T-CONV:/abc/base64/}", "YWJj"),
        ("{T-CONV:/ä/base64/}", "w6Q="),
        ("{T-CONV:/abc/hex/}", "616263"),
        ("{T-CONV:/a b&c/uri/}", "a%20b%26c"),
        ("{T-CONV:/äö €/uri/}", "%C3%A4%C3%B6%20%E2%82%AC"),
        ("{T-CONV:/a%20b/uri-dec/}", "a b"),
        ("{T-CONV:|a/b|upper|}", "A/B"),
        ("{T-CONV:/abc/uri-x/}", "ABC"),
        ("{T-CONV:/straße/upper/}", "STRASSE"),
        ("{T-CONV:/İ/lower/}", "i\u{307}"),
        ("x{T-CONV:/abc/junk/}y", "xy"),
        ("{T-CONV:/abc/upper}", ""),
        ("{T-CONV:/a/b/upper/}", ""),
        ("{T-CONV:/a\nb/upper/}", ""),
        ("{T-CONV:/abc/upper/extra/}", "ABC"),
        ("{T-CONV:/%41%2/uri-dec/}", "A%2"),
        ("{T-CONV:/a+b/uri-dec/}", "a+b"),
        ("{T-CONV:/%zz%C3%28/uri-dec/}", "%zz\u{FFFD}("),
        ("{T-CONV:/ä/hex/}", "c3a4"),
    ];
    for (t, want) in cases {
        assert_eq!(res(&v, 0x0f, t), want, "{t:?}");
    }
}

/// The card's 08-32 to 08-34 rows with App's engine, `regex` (LD-110).
#[test]
fn mod_08_22_regex_replace() {
    let v = r8();
    let r = |t: &str| res(&v, 0x0f, t);
    let cases = [
        ("{T-REPLACE-RX:/abc123/\\d+/X/}", "abcX"),
        (
            "{T-REPLACE-RX:/2024-10-25/(\\d+)-(\\d+)-(\\d+)/$3.$2.$1/}",
            "25.10.2024",
        ),
        ("{T-REPLACE-RX:/aaa/a/b/}", "bbb"),
        ("{T-REPLACE-RX:/abc/(?i)B/x/}", "axc"),
        ("{T-REPLACE-RX:/abc//x/}", "xaxbxcx"),
        ("{T-REPLACE-RX:/abc/a+?/X/}", "Xbc"),
        ("{T-REPLACE-RX:/abc/(b)/[$1$1]/}", "a[bb]c"),
        ("{T-REPLACE-RX:/abc/(b)/[$0]/}", "a[\\0]c"),
        ("{T-REPLACE-RX:/abc/(b)/[$2]/}", "a[\\2]c"),
        ("{T-REPLACE-RX:/abc/b/[\\1]/}", "a[\\1]c"),
        ("{T-REPLACE-RX:/abc/(b)/$10/}", "ab0c"),
        ("x{T-REPLACE-RX:/abc/(/X/}y", "xy"),
        ("{T-REPLACE-RX:/abc/b/x}", ""),
        ("{T-REPLACE-RX:/{TITLE}/o/0/}", "Pr0be"),
    ];
    for (t, want) in cases {
        assert_eq!(r(t), want, "{t}");
    }
    // LD-110: look-around and backreferences are refused like an invalid
    // pattern (the reference gives `aXc` for the look-behind).
    assert_eq!(r("x{T-REPLACE-RX:/abc/(?<=a)b/X/}y"), "xy");
    assert_eq!(r("x{T-REPLACE-RX:/abc/b(?=c)/X/}y"), "xy");
    assert_eq!(r("x{T-REPLACE-RX:/abab/(ab)\\1/X/}y"), "xy");
    // `\d` and `\w` match ASCII only, outside and inside classes.
    assert_eq!(r("{T-REPLACE-RX:/a٣b7/\\d/X/}"), "a٣bX");
    assert_eq!(r("{T-REPLACE-RX:/é_z/\\w/X/}"), "éXX");
    assert_eq!(r("{T-REPLACE-RX:/a٣b7/[\\d]/X/}"), "a٣bX");
    assert_eq!(r("{T-REPLACE-RX:/a7/\\D/X/}"), "X7");
    assert_eq!(
        r("{T-REPLACE-RX:/a\\\\d/\\\\d/X/}"),
        "a\\X",
        "an escaped backslash matches a backslash, then d"
    );
}

/// A pattern that blows up a backtracking engine finishes fast (LD-110).
#[test]
fn mod_08_22_no_catastrophic_backtracking() {
    let mut v = r8();
    let text = format!("{}!", "a".repeat(4000));
    set(&mut v.root.entries[0], "Long", &text);
    let started = std::time::Instant::now();
    assert_eq!(res(&v, 0x0f, "{T-REPLACE-RX:/{S:Long}/(a+)+$/X/}"), text);
    assert_eq!(res(&v, 0x0f, "{T-REPLACE-RX:/{S:Long}/(a|aa)*b/X/}"), text);
    assert!(
        started.elapsed().as_millis() < 500,
        "{:?}",
        started.elapsed()
    );
    assert!(app_core::pattern::compile("(a+)+$").is_some());
}

#[test]
fn mod_08_23_display_mask() {
    let mut v = r8();
    v.root.entries.push(mk(
        0x67,
        "M1",
        &[
            ("UserName", "al"),
            ("Password", "pw1"),
            ("URL", "https://h.example/?u={USERNAME}&p={PASSWORD}"),
        ],
    ));
    let mut m2 = mk(0x68, "M2", &[("URL", "https://h.example/?p={S:Pin}")]);
    m2.set_field(
        "Pin".into(),
        Field {
            value: SecretString::new("9876".into()),
            protected: true,
        },
    );
    v.root.entries.push(m2);
    let mut show = Context::new(Some(&v), T0);
    show.display = true;
    let url = |n: u8| find(&v, id(n)).value("URL").to_owned();
    assert_eq!(
        res_ctx(&v, 0x67, &url(0x67), &show),
        format!("https://h.example/?u=al&p={MASK}")
    );
    assert_eq!(
        res(&v, 0x67, &url(0x67)),
        "https://h.example/?u=al&p=pw1",
        "the link is unmasked"
    );
    assert_eq!(
        res_ctx(&v, 0x68, &url(0x68), &show),
        "https://h.example/?p=******"
    );
    assert_eq!(
        res_ctx(&v, 0x0f, "{REF:P@T:M1}|{T-CONV:/{PASSWORD}/upper/}", &show),
        "******|******"
    );
    // 08-48: copy and search use the unmasked form.
    assert_eq!(res(&v, 0x67, "{URL}"), "https://h.example/?u=al&p=pw1");
}

#[test]
fn mod_08_24_reference_marker() {
    let mut v = r8();
    v.root.entries.push(mk(
        0x69,
        "R",
        &[("UserName", &format!("{{REF:U@I:{}}}", hx(0x0a)))],
    ));
    assert!(!holds_any_reference(find(&v, id(0x0a))));
    assert!(!holds_any_reference(find(&v, id(0x0f))));
    assert!(holds_any_reference(find(&v, id(0x69))));
    assert!(holds_reference("{ref:u@i:x}"), "any case of ref: counts");
}

#[test]
fn mod_08_25_places() {
    let mut v = r8();
    set(&mut v.root.entries[0], "UserName", "{S:Custom1}");
    // Copy, preview and `show` resolve; `clip`, exports and merge use the
    // raw value.
    assert_eq!(field_of(&v, 0x0f, "UserName"), "cval");
    assert_eq!(find(&v, id(0x0f)).value("UserName"), "{S:Custom1}");
}

#[test]
fn mod_08_26_one_resolution_form() {
    let mut v = r8();
    v.root.entries.push(mk(
        0x6a,
        "{USERNAME} and {NOTES}",
        &[("UserName", "zed"), ("Notes", "qq")],
    ));
    assert_eq!(field_of(&v, 0x6a, "Title"), "zed and qq");
}

#[test]
fn mod_08_27_delete_for_good_with_references() {
    let x = |v: &mut Vault| {
        v.meta.recycle_bin_enabled = false;
        v.root.entries.push(mk(
            0x70,
            "Y",
            &[
                ("UserName", &format!("{{REF:U@I:{}}}", hx(0x0a))),
                ("Notes", &format!("{{REF:P@I:{}}}", hx(0x0a))),
            ],
        ));
    };
    // 08-39 Overwrite: same field name, not the wanted field.
    let mut v = r8();
    x(&mut v);
    delete_entries(&mut v, &[id(0x0a)], NOW, |_, n| {
        assert_eq!(n, 2, "Y and R8's Nested");
        References::Overwrite
    })
    .unwrap();
    let y = find(&v, id(0x70));
    assert_eq!(
        (y.value("UserName"), y.value("Notes"), y.history.len()),
        ("alice", "note-A", 0)
    );
    // 08-40 Skip, then Delete.
    let mut v = r8();
    x(&mut v);
    delete_entries(&mut v, &[id(0x0a)], NOW, |_, _| References::Skip).unwrap();
    find(&v, id(0x0a));
    delete_entries(&mut v, &[id(0x0a)], NOW, |_, _| References::Delete).unwrap();
    assert_eq!(field_of(&v, 0x70, "UserName"), "");
    // 08-41 not by title; 08-58 same delete asks nothing.
    let mut v = r8();
    v.meta.recycle_bin_enabled = false;
    v.root
        .entries
        .push(mk(0x71, "Z", &[("Password", "{REF:P@T:Alpha}")]));
    // R8's Nested refers to Alpha by id: it goes in the same selection.
    delete_entries(&mut v, &[id(0x0a), id(0x88)], NOW, |_, _| {
        panic!("no prompt")
    })
    .unwrap();
    let mut v = r8();
    x(&mut v);
    delete_entries(&mut v, &[id(0x0a), id(0x70), id(0x88)], NOW, |_, _| {
        panic!("no prompt")
    })
    .unwrap();
    // 08-42 to the bin: no prompt, the reference keeps working.
    let mut v = r8();
    x(&mut v);
    v.meta.recycle_bin_enabled = true;
    delete_entries(&mut v, &[id(0x0a)], NOW, |_, _| panic!("no prompt")).unwrap();
    assert_eq!(field_of(&v, 0x70, "UserName"), "alice");
    ok(&v);
}

#[test]
fn mod_08_28_browser_save_guard() {
    let v = r8();
    assert!(browser_refuses(&v, "{REF:P@T:Bank}", T0));
    assert!(!browser_refuses(&v, "{abc}", T0));
    assert!(browser_refuses(&v, "\\{TITLE\\}", T0));
    assert!(browser_refuses(&v, "user{DT_YEAR}", T0));
    assert!(!browser_refuses(&v, "plain-user", T0));
}

#[test]
fn mod_08_29_context() {
    let v = r8();
    let r = format!("{{REF:U@I:{}}}", hx(0x0a));
    let loose = mk(0x72, "Loose", &[]);
    let ctx = Context::new(Some(&v), T0);
    let at = |e: &Entry, t: &str| resolve(t, e, &ctx).text.expose().to_owned();
    assert_eq!(at(&loose, &r), r, "not in a vault");
    assert_eq!(at(&loose, "{TITLE}"), "Loose");
    assert_eq!(at(&loose, "{DB_DIR}"), "");
    let mut w = r8();
    let item = w.root.entries[0].duplicate(false);
    w.root.entries[0].history.push(item);
    let hist = &find(&w, id(0x0f)).history[0];
    let ctx = Context::new(Some(&w), T0);
    assert_eq!(
        resolve(&r, hist, &ctx).text.expose(),
        r,
        "a history item is not in a vault"
    );
}

#[test]
fn mod_08_30_reference_format() {
    assert_eq!(
        reference('U', id(0x0a)),
        "{REF:U@I:0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A}"
    );
    assert_eq!(
        reference('P', id(0x5a)),
        format!("{{REF:P@I:{}}}", "5A".repeat(16))
    );
}

#[test]
fn mod_08_31_opening_urls() {
    let secret = |o: Open| match o {
        Open::Command(s) | Open::VaultLink(s) | Open::Url(s) => s.expose().to_owned(),
        other => panic!("{other:?}"),
    };
    assert_eq!(open_kind("cmd://"), Open::Nothing);
    assert_eq!(
        secret(open_kind("cmd:///usr/bin/touch /tmp/m08-run")),
        "/usr/bin/touch /tmp/m08-run"
    );
    let link = format!(
        "{}b.appvault",
        String::from_utf8(app_core::url::VAULT_LINK.to_vec()).unwrap()
    );
    assert!(matches!(open_kind(&link), Open::VaultLink(_)));
    assert_eq!(secret(open_kind(&link)), "b.appvault");
    assert_eq!(secret(open_kind("example.com")), "http://example.com");
    assert_eq!(
        secret(open_kind("https://example.com")),
        "https://example.com"
    );
    assert_eq!(
        secret(open_kind("mailto:a@b.example")),
        "mailto:a@b.example"
    );
    for bad in [
        "javascript:alert(1)",
        "file:///etc/hosts",
        "data:text/html,x",
        "ssh://host.example",
    ] {
        assert_eq!(open_kind(bad), Open::Refused, "{bad}");
    }
    assert_eq!(open_kind(""), Open::Nothing);
    // The scheme is checked on the resolved text.
    let mut v = r8();
    set(&mut v.root.entries[0], "a", "javascript");
    assert_eq!(open_kind(&res(&v, 0x0f, "{S:a}:alert(1)")), Open::Refused);
    // Command words: quotes group, three quotes are one quote, no shell.
    let words: Vec<String> =
        command_words("/usr/bin/touch \"/tmp/m08 a\" /tmp/m08-$HOME;x say\"\"\"hi\"\"\"")
            .into_iter()
            .map(|w| w.expose().to_owned())
            .collect();
    assert_eq!(
        words,
        [
            "/usr/bin/touch",
            "/tmp/m08 a",
            "/tmp/m08-$HOME;x",
            "say\"hi\""
        ]
    );
    assert!(command_words("").is_empty());
    // The question: masked text without cmd://, cut after 400 characters.
    let long = format!("cmd://echo {MASK} {MASK} {}", "x".repeat(500));
    let q = question_text(&long);
    assert!(q.starts_with("echo ****** ****** xxx") && q.ends_with(" […]"));
    assert_eq!(q.chars().count(), 400 + 4);
    // A remembered Yes is keyed by the exact command.
    assert_ne!(remember_key("v", id(1), "a"), remember_key("v", id(1), "b"));
    assert_eq!(remember_key("v", id(1), "a"), remember_key("v", id(1), "a"));
    // Vault link paths.
    assert_eq!(
        vault_link_path("b.appvault", "/tmp/m08v"),
        "/tmp/m08v/b.appvault"
    );
    assert_eq!(
        vault_link_path("file:///tmp/a%20b.appvault", "/x"),
        "/tmp/a b.appvault"
    );
    assert_eq!(vault_link_path("/abs.appvault", "/x"), "/abs.appvault");
}

/// Time bound for one resolution in the timed tests: LD-113's 250 ms in
/// release, the goal, checked on a busy Mac (LD-123). Debug builds the
/// resolver unoptimized and runs these tests in parallel with the rest;
/// measured up to about 520 ms there, so 2 s.
fn time_bound() -> std::time::Duration {
    std::time::Duration::from_millis(if cfg!(debug_assertions) { 2_000 } else { 250 })
}

/// LD-113: pattern and text bounds; LD-114: the pattern is never resolved.
#[test]
fn mod_08_22_bounds_and_unresolved_pattern() {
    let mut v = r8();
    let a = |n: usize| "a".repeat(n);
    let pat = |n: usize| format!("(?:{})", "x".repeat(n - 4));
    assert_eq!(pat(1_024).chars().count(), 1_024);
    set(&mut v.root.entries[0], "T", "abc");
    assert_eq!(
        res(
            &v,
            0x0f,
            &format!("{{T-REPLACE-RX:/{{S:T}}/{}/X/}}", pat(1_024))
        ),
        "abc"
    );
    assert_eq!(
        res(
            &v,
            0x0f,
            &format!("x{{T-REPLACE-RX:/{{S:T}}/{}/X/}}y", pat(1_025))
        ),
        "xy",
        "over 1,024: invalid"
    );
    // The text: 65,536 characters are replaced, one more comes back raw.
    set(&mut v.root.entries[0], "T", &a(65_536));
    assert_eq!(
        res(&v, 0x0f, "{T-REPLACE-RX:/{S:T}/a/b/}"),
        "b".repeat(65_536)
    );
    set(&mut v.root.entries[0], "T", &a(65_537));
    assert_eq!(
        res(&v, 0x0f, "{T-REPLACE-RX:/{S:T}/a/b/}"),
        a(65_537),
        "unreplaced"
    );
    // The pattern is used as written: a placeholder there is just braces.
    set(&mut v.root.entries[0], "T", "Probe");
    set(&mut v.root.entries[0], "P", "o");
    assert_eq!(
        res(&v, 0x0f, "x{T-REPLACE-RX:/{S:T}/{S:P}/0/}y"),
        "xy",
        "`{{S:P}}` is an invalid pattern"
    );
    assert_eq!(
        res(&v, 0x0f, "{T-REPLACE-RX:/{TITLE}/o{1}/0/}"),
        "Pr0be",
        "braces are a quantifier"
    );
}

/// LD-113: the Checker's patterns, and the largest allowed patterns of
/// their shape, each finish one resolution at the largest allowed text
/// within the bound.
#[test]
fn mod_08_22_timed_patterns() {
    let mut v = r8();
    let cases = [
        ("(?:[a-z]{1,40}){1,40}x", "a".repeat(65_536)),
        ("(?:[a-z]{1,120}){1,120}x", "a".repeat(65_536)),
        ("(a+)+$", format!("{}!", "a".repeat(65_535))),
    ];
    for (p, text) in &cases {
        set(&mut v.root.entries[0], "T", text);
        let started = std::time::Instant::now();
        let out = res(&v, 0x0f, &format!("{{T-REPLACE-RX:/{{S:T}}/{p}/X/}}"));
        assert!(
            started.elapsed() < time_bound(),
            "{p}: {:?}",
            started.elapsed()
        );
        assert!(out.is_empty() || out == *text, "{p}");
    }
    for len in [65_536usize, 16_384, 6_100, 1_000] {
        let largest = (1..=120)
            .rev()
            .map(|n| format!("(?:[a-z]{{1,{n}}}){{1,{n}}}x"))
            .find(|p| app_core::pattern::compile_for(p, len).is_some())
            .unwrap();
        set(&mut v.root.entries[0], "T", &"a".repeat(len));
        let started = std::time::Instant::now();
        let out = res(&v, 0x0f, &format!("{{T-REPLACE-RX:/{{S:T}}/{largest}/X/}}"));
        assert!(
            started.elapsed() < time_bound(),
            "{len} {largest}: {:?}",
            started.elapsed()
        );
        assert_eq!(out.len(), len);
    }
}

/// LD-112: DNS limits come before encoding; a huge label is invalid at
/// once.
#[test]
fn mod_08_9_hosts_within_dns_limits() {
    let mut v = r8();
    let host = |h: &str| {
        let mut w = r8();
        set(&mut w.root.entries[1], "URL", &format!("https://{h}/x"));
        (res(&w, 0x0a, "{URL:HOST}"), res(&w, 0x0a, "{URL:RMVSCM}"))
    };
    let l63 = "a".repeat(63);
    assert_eq!(host(&l63).0, l63);
    assert_eq!(
        host(&"a".repeat(64)),
        (String::new(), String::new()),
        "label over 63"
    );
    let h253 = format!("{0}.{0}.{0}.{1}", "b".repeat(63), "c".repeat(61));
    assert_eq!(h253.len(), 253);
    assert_eq!(host(&h253).0, h253);
    assert_eq!(host(&format!("{h253}d")).0, "", "host over 253");
    // Encoding counts: 60 non-ASCII characters encode past 63 octets.
    assert_eq!(host(&"ü".repeat(60)).0, "");
    // Under 253 characters, but past 253 once encoded.
    let one = format!("{}ü", "a".repeat(54));
    let grows = format!("{0}.{0}.{0}.{0}.{1}", one, "b".repeat(10));
    assert_eq!(grows.chars().count(), 234);
    assert_eq!(host(&grows).0, "", "the encoded host passes 253");
    let same = format!("{0}.{0}.{0}.{0}.{1}", "a".repeat(55), "b".repeat(10));
    assert_eq!(host(&same).0, same, "the same lengths in ASCII fit");
    // A huge label, ASCII or not, is invalid at once (Punycode never sees
    // it).
    for label in ["a".repeat(1_000_000), "ü".repeat(1_000_000)] {
        set(
            &mut v.root.entries[1],
            "URL",
            &format!("https://{label}.example/"),
        );
        let started = std::time::Instant::now();
        assert_eq!(res(&v, 0x0a, "{URL:HOST}"), "");
        let ms = started.elapsed().as_millis();
        // The release bound is the proof (check.sh runs this file in
        // release too); a debug build under load only must not hang.
        assert!(
            ms < if cfg!(debug_assertions) { 2_000 } else { 30 },
            "{ms} ms"
        );
    }
}

/// The budget is exactly 10: an escape reached at the sixth string step
/// stays raw (with 11 it would be unescaped).
#[test]
fn mod_08_18_budget_is_ten() {
    let mut v = r8();
    let p = &mut v.root.entries[0];
    for (k, val) in [
        ("Title", "{USERNAME}"),
        ("UserName", "{NOTES}"),
        ("Notes", "{S:x}"),
        ("x", "{S:y}"),
        ("y", "\\{Y\\}"),
    ] {
        set(p, k, val);
    }
    assert_eq!(res(&v, 0x0f, "{TITLE}"), "\\{Y\\}");
    assert_eq!(
        res(&v, 0x0f, "{NOTES}"),
        "{Y}",
        "two levels less: unescaped"
    );
}

/// A reference costs no budget of its own (MOD-08.18: the span step hands
/// its budget plus 1): a chain of four references resolves fully.
#[test]
fn mod_08_18_reference_chain() {
    let mut v = r8();
    for (n, next) in [(0x81u8, 0x82u8), (0x82, 0x83), (0x83, 0x84), (0x84, 0x85)] {
        v.root
            .entries
            .push(mk(n, &format!("{{REF:T@I:{}}}", hx(next)), &[]));
    }
    v.root.entries.push(mk(0x85, "end", &[]));
    assert_eq!(field_of(&v, 0x81, "Title"), "end");
}

/// Each bound alone (MOD-08.20): span steps and output characters.
#[test]
fn mod_08_20_each_bound_alone() {
    let v = r8();
    let p = find(&v, id(0x0f));
    let ctx = Context::new(Some(&v), T0);
    let at_bound = "{S:x}".repeat(10_000);
    let r = resolve(&at_bound, p, &ctx);
    assert!(
        !r.bounded && r.text.expose().is_empty(),
        "10,000 span steps resolve"
    );
    let over = "{S:x}".repeat(10_001);
    let r = resolve(&over, p, &ctx);
    assert!(r.bounded && r.text.expose() == over, "10,001 come back raw");
    let mut w = r8();
    set(&mut w.root.entries[0], "Half", &"a".repeat(524_288));
    let p = find(&w, id(0x0f));
    let ctx = Context::new(Some(&w), T0);
    let r = resolve("{S:Half}{S:Half}", p, &ctx);
    assert!(
        !r.bounded && r.text.expose().len() == 1_048_576,
        "exactly 1,048,576"
    );
    let r = resolve("{S:Half}{S:Half}x", p, &ctx);
    assert!(
        r.bounded && r.text.expose() == "{S:Half}{S:Half}x",
        "one more: raw"
    );
}

#[test]
fn mod_08_mutant_probes() {
    let mut v = r8();
    // F08: `{ref:` is unknown, so its inside resolves.
    assert_eq!(res(&v, 0x0f, "{ref:x{TITLE}}"), "{ref:xProbe}");
    // F17: `~` is unreserved in `uri`.
    assert_eq!(res(&v, 0x0f, "{T-CONV:/a~b/uri/}"), "a~b");
    // F20: a regex replace result is resolved again.
    assert_eq!(res(&v, 0x0f, "{T-REPLACE-RX:/{TITLE/$/}/}"), "Probe");
    // F31: {DB_DIR} needs the entry in the vault.
    let mut ctx = Context::new(Some(&v), T0);
    ctx.vault_dir = "/tmp/demo";
    let loose = mk(0x72, "Loose", &[]);
    assert_eq!(resolve("{DB_DIR}", &loose, &ctx).text.expose(), "");
    // m3: a protected one-time password shows masked for display.
    v.root.entries[0].set_field(
        "otp".into(),
        Field {
            value: SecretString::new("otpauth://demo".into()),
            protected: true,
        },
    );
    let mut show = Context::new(Some(&v), T0);
    show.display = true;
    show.otp = |_, _| Some(SecretString::new("123456".into()));
    assert_eq!(res_ctx(&v, 0x0f, "{TOTP}", &show), MASK);
    show.display = false;
    assert_eq!(res_ctx(&v, 0x0f, "{TOTP}", &show), "123456");
}

#[test]
fn mod_08_9_url_mutant_probes() {
    let host = |h: &str| {
        let mut w = r8();
        set(&mut w.root.entries[1], "URL", &format!("https://{h}/"));
        res(&w, 0x0a, "{URL:HOST}")
    };
    // U06: RFC 3492 section 7.1 samples (lower case labels).
    for (label, code) in [
        ("ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"),
        ("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"),
        ("他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb"),
        ("pročprostěnemluvíčesky", "proprostnemluvesky-uyb24dma41a"),
        ("3年b組金八先生", "3b-ww4c5e180e575a65lsy2b"),
        (
            "安室奈美恵-with-super-monkeys",
            "-with-super-monkeys-pc58ag80a8qai00g7n9n",
        ),
        (
            "hello-another-way-それぞれの場所",
            "hello-another-way--fc4qua05auwb3674vfr0b",
        ),
        ("majiでkoiする5秒前", "majikoi5-783gue6qz075azm5e"),
        ("そのスピードで", "d9juau41awczczp"),
    ] {
        assert_eq!(host(label), format!("xn--{code}"), "{label}");
    }
    // U04: a port with a sign is invalid.
    let mut w = r8();
    set(&mut w.root.entries[1], "URL", "https://example.com:+80/");
    assert_eq!(res(&w, 0x0a, "{URL:PORT}|{URL:RMVSCM}"), "-1|");
    // U09: only `cmd://` in exact case is a command.
    assert_eq!(open_kind("CMD://x"), Open::Refused);
    // U19: the URL is trimmed before reading it.
    match open_kind("  https://example.com  ") {
        Open::Url(u) => assert_eq!(u.expose(), "https://example.com"),
        other => panic!("{other:?}"),
    }
}

/// LD-119: strict hosts, as the reference: an invalid bracketed host or an
/// empty label gives an empty host.
#[test]
fn mod_08_9_strict_hosts() {
    let parts = |url: &str| {
        let mut w = r8();
        set(&mut w.root.entries[1], "URL", url);
        res(&w, 0x0a, "{URL:HOST}|{URL:RMVSCM}")
    };
    for bad in [
        "https://[:::::]/x",
        "https://[1::2::3]/",
        "https://[12345::]/",
        "https://[::g]/",
        "https://[]/",
    ] {
        assert_eq!(parts(bad), "|", "{bad}");
    }
    assert_eq!(parts("https://[::1]:8080/x"), "::1|//[::1]:8080/x");
    assert_eq!(
        parts("https://[2001:DB8::1]/"),
        "2001:db8::1|//[2001:db8::1]/"
    );
    assert_eq!(
        parts("https://[::ffff:192.0.2.1]/"),
        "::ffff:192.0.2.1|//[::ffff:192.0.2.1]/"
    );
    assert_eq!(
        parts("https://[::1]x/"),
        "|",
        "LD-121: an invalid URL, no host"
    );
    for bad in [
        "https://a..b/",
        "https://.a/",
        "https://a.b../",
        "https://./",
    ] {
        assert_eq!(parts(bad), "|", "{bad}");
    }
    assert_eq!(
        parts("https://example.com./p"),
        "example.com.|//example.com./p",
        "one final dot"
    );
}

/// LD-118: one regex budget per resolution. Verify's many-copies cases
/// (the heaviest pattern allowed for the text, many times in one field)
/// each finish within the bound.
#[test]
fn mod_08_22_one_budget_per_resolution() {
    for (len, copies) in [(16_384usize, 64usize), (4_096, 256), (1_000, 1_024)] {
        let n = (1..=200)
            .rev()
            .find(|&n| {
                app_core::pattern::compile_for(&format!("(?:[a-z]{{1,{n}}}){{1,{n}}}x"), len)
                    .is_some()
            })
            .unwrap();
        let one = format!("{{T-REPLACE-RX:/{{S:T}}/(?:[a-z]{{1,{n}}}){{1,{n}}}x/X/}}");
        let mut v = r8();
        set(&mut v.root.entries[0], "T", &"a".repeat(len));
        let started = std::time::Instant::now();
        let out = res(&v, 0x0f, &one.repeat(copies));
        assert!(
            started.elapsed() < time_bound(),
            "{copies} × n={n} on {len}: {:?}",
            started.elapsed()
        );
        assert_eq!(out.len(), copies * len);
    }
    // Once the budget is spent, later replaces leave their text unchanged:
    // each costs its compiled size × 1,000, so only some of 8 fit.
    let mut v = r8();
    set(&mut v.root.entries[0], "T", &"a".repeat(1_000));
    let pattern = "(?:[a-z]{1,48}){1,48}a";
    let one = format!("{{T-REPLACE-RX:/{{S:T}}/{pattern}/X/}}");
    let fit = budget_fit(pattern, 1_000);
    assert!(fit < 8, "{fit}");
    let out = res(&v, 0x0f, &one.repeat(8));
    assert_eq!(
        out,
        format!("{}{}", "X".repeat(fit), "a".repeat(1_000 * (8 - fit)))
    );
    // A fresh resolution has a fresh budget.
    assert_eq!(res(&v, 0x0f, &one), "X");
}

/// How many replaces with `pattern` on a text of `len` bytes fit one
/// resolution's budget (LD-118, LD-123): each costs its compiled size × the
/// length (at least 512).
fn budget_fit(pattern: &str, len: usize) -> usize {
    let app_core::pattern::Compiled::Ok(_, size) = app_core::pattern::compile_sized(pattern) else {
        panic!("compiles")
    };
    app_core::pattern::RESOLUTION_BUDGET / (size * len.max(app_core::pattern::MIN_CHARGED))
}

/// LD-118, LD-123: a very short text still costs at least 512 per byte of
/// the compiled pattern, so many heavy replaces on it stop too.
#[test]
fn mod_08_22_budget_floor_for_short_texts() {
    let mut v = r8();
    set(&mut v.root.entries[0], "T", "aa");
    let pattern = "(?:[a-z]{1,48}){1,48}a";
    let fit = budget_fit(pattern, 2);
    assert!(fit < 500, "{fit}");
    let one = format!("{{T-REPLACE-RX:/{{S:T}}/{pattern}/X/}}");
    let started = std::time::Instant::now();
    let out = res(&v, 0x0f, &one.repeat(500));
    assert!(started.elapsed() < time_bound(), "{:?}", started.elapsed());
    assert_eq!(
        out,
        format!("{}{}", "X".repeat(fit), "aa".repeat(500 - fit))
    );
}

/// LD-120: at most 8 distinct patterns are compiled per resolution; the
/// same text is compiled once; past the cap the text stays unchanged.
#[test]
fn mod_08_22_compile_cap() {
    let mut v = r8();
    set(&mut v.root.entries[0], "T", "x");
    let patterns = [
        "x", "(?:x)", "x{1}", "[x]", "x+", "x?x?", "(x)", "x|y", "x{1,1}",
    ];
    let field: String = patterns
        .iter()
        .chain(["x"].iter())
        .map(|p| format!("{{T-REPLACE-RX:/{{S:T}}/{p}/Y/}}"))
        .collect();
    assert_eq!(
        res(&v, 0x0f, &field),
        "YYYYYYYYxY",
        "the 9th is unchanged; the 1st again is reused"
    );
    // Invalid patterns count too.
    let field: String = (0..8)
        .map(|i| format!("{{T-REPLACE-RX:/{{S:T}}/{}/Y/}}", "(".repeat(i + 1)))
        .chain(["{T-REPLACE-RX:/{S:T}/x/Y/}".to_owned()])
        .collect();
    assert_eq!(
        res(&v, 0x0f, &field),
        "x",
        "8 invalid (empty), then the cap: unchanged"
    );
}

/// LD-120: Verify's cases (the text is one letter) and the slowest
/// compile found, 8 distinct times in one field: each resolution within
/// the bound, compiles included.
#[test]
fn mod_08_22_timed_compiles() {
    let mut v = r8();
    set(&mut v.root.entries[0], "t", "a");
    let one = |p: &str| format!("{{T-REPLACE-RX:/{{S:t}}/{p}/X/}}");
    let cases = [
        (format!("(?i){}\\p{{Nope}}", "\\W".repeat(330)), 10_000usize),
        (format!("(?i){}\\p{{Nope}}", "[^\\W]".repeat(200)), 10_000),
        (format!("(?i){}", "[^\\W]".repeat(200)), 1_000),
    ];
    for (p, copies) in &cases {
        let started = std::time::Instant::now();
        let _ = res(&v, 0x0f, &one(p).repeat(*copies));
        assert!(
            started.elapsed() < time_bound(),
            "{copies} × {}: {:?}",
            &p[..20],
            started.elapsed()
        );
    }
    // The slowest compile found at 1,024 characters, 8 distinct ones, each
    // used many times.
    let field: String = (0..8)
        .map(|i| one(&format!("(?i){}{}", "\\W".repeat(500), "a".repeat(i + 1))).repeat(100))
        .collect();
    let started = std::time::Instant::now();
    let _ = res(&v, 0x0f, &field);
    assert!(started.elapsed() < time_bound(), "{:?}", started.elapsed());
    // Wide case-folded ranges are refused before any folding (LD-120).
    assert!(app_core::pattern::compile("(?i)[\\x{80}-\\x{10FFFF}]").is_none());
    assert!(
        app_core::pattern::compile("(?i)[\\x{0}-\\x{FFFF}][\\x{0}-\\x{FFFF}][\\x{0}-\\x{FFFF}]")
            .is_some()
    );
    assert!(
        app_core::pattern::compile("[\\x{80}-\\x{10FFFF}]").is_some(),
        "no folding without (?i)"
    );
}

/// The largest pattern of the Checker's shape allowed on a text of `len`.
fn largest(len: usize) -> usize {
    (1..=200)
        .rev()
        .find(|&n| {
            app_core::pattern::compile_for(&format!("(?:[a-z]{{1,{n}}}){{1,{n}}}x"), len).is_some()
        })
        .unwrap()
}

/// LD-123: Verify's many-copies cases, each resolution within the bound
/// on a busy Mac: 64 copies of the largest allowed pattern on 200, 500,
/// 1,000 and 16,384 letters, and 8 distinct largest patterns × 128.
#[test]
fn mod_08_22_many_copies_under_load() {
    let rx = |n: usize| format!("{{T-REPLACE-RX:/{{S:T}}/(?:[a-z]{{1,{n}}}){{1,{n}}}x/X/}}");
    let mut cases: Vec<(usize, String)> = [200usize, 500, 1_000, 16_384]
        .iter()
        .map(|&len| (len, rx(largest(len)).repeat(64)))
        .collect();
    let n = largest(1_000);
    cases.push((1_000, (0..8).map(|i| rx(n - i).repeat(128)).collect()));
    for (len, field) in &cases {
        let mut v = r8();
        set(&mut v.root.entries[0], "T", &"a".repeat(*len));
        let started = std::time::Instant::now();
        let out = res(&v, 0x0f, field);
        assert!(
            started.elapsed() < time_bound(),
            "{len}: {:?}",
            started.elapsed()
        );
        assert!(!out.is_empty());
    }
}

/// LD-123: Unicode category and script classes are invalid (the engine is
/// built without those tables): a replace with one gives the empty result.
#[test]
fn mod_08_22_unicode_classes_invalid() {
    let mut v = r8();
    set(&mut v.root.entries[0], "T", "abc αβγ");
    for p in ["\\p{L}", "\\p{Greek}", "\\pL", "[\\p{Lu}a]", "\\P{N}"] {
        assert_eq!(
            res(&v, 0x0f, &format!("x{{T-REPLACE-RX:/{{S:T}}/{p}/X/}}y")),
            "xy",
            "{p}"
        );
        assert!(
            app_core::pattern::compile(&p.replace("\\\\", "\\")).is_none(),
            "{p}"
        );
    }
}

/// F-129 (LD-238 (2)): `masked` says the display resolution put in the mask,
/// through `{S:…}`, a standard field, a reference and the one-time code,
/// also when a transform turns the mask and the value into the same text
/// (the regex probe of security/findings.md); never without display or for
/// plain fields.
#[test]
fn f_129_masked_marks_every_mask() {
    let mut v = r8();
    let mut p = mk(0x69, "P", &[("UserName", "plain")]);
    for (name, value) in [
        ("Password", "demo-s"),
        ("Pin", "9876"),
        ("otp", "otpauth://demo"),
    ] {
        p.set_field(
            name.into(),
            Field {
                value: SecretString::new(value.into()),
                protected: true,
            },
        );
    }
    v.root.entries.push(p);
    let e = find(&v, id(0x69));
    let mut show = Context::new(Some(&v), T0);
    show.display = true;
    show.otp = |_, _| Some(SecretString::new("123456".into()));
    let probe = "https://example.com/?p={T-REPLACE-RX:/{PASSWORD}/^.{6}$/six/}";
    let by_ref = format!("{{REF:P@I:{}}}", hx(0x69));
    let texts = [probe, "{S:Pin}", "{PASSWORD}", by_ref.as_str(), "{TOTP}"];
    let shown = resolve(probe, e, &show);
    assert_eq!(shown.text.expose(), "https://example.com/?p=six");
    for text in texts {
        assert!(resolve(text, e, &show).masked, "{text}");
    }
    assert!(!resolve("{USERNAME} {TITLE} {S:Nope}", e, &show).masked);
    show.display = false;
    assert_eq!(resolve(probe, e, &show).text.expose(), shown.text.expose());
    for text in texts {
        assert!(!resolve(text, e, &show).masked, "{text}");
    }
}
