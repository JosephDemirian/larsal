//! INT-05 test cases on the reader and planner level (E8-S1): T01 to T39,
//! T41, the planner half of T98, T99 and T108, and the R05 findings of
//! LD-177. T40 is the fuzz target `autotype_sequence`. Demo data only.

use app_autotype::{Action, Error, Layout, Mods, Options, Picked, Plan, Shortcut, check, plan};
use app_core::edit::entry_sequence;
use app_core::refs::Context;
use app_core::totp;
use app_crypto::secret::SecretString;
use app_model::times::Civil;
use app_model::{Entry, Field, Group, Switch, Time, Uuid, Vault};
use std::time::Duration;

/// This thread's CPU time (F-092): the bounds below measure work, so a busy
/// Mac that leaves the test waiting for a core does not fail them.
fn cpu() -> Duration {
    app_platform::macos::thread_cpu_time()
}

const P: Uuid = Uuid([0x50; 16]);
const E1: Uuid = Uuid([0x01; 16]);
const E3: Uuid = Uuid([0x03; 16]);
const E4: Uuid = Uuid([0x04; 16]);
const E5: Uuid = Uuid([0x05; 16]);
const E6: Uuid = Uuid([0x06; 16]);
const E1_OTP: &str = "otpauth://totp/GitHub:alex-dev?secret=JBSWY3DPEHPK3PXP&period=30&digits=6";

fn at(hour: u32, minute: u32, second: u32) -> Time {
    Time::from_civil(Civil {
        year: 2026,
        month: 10,
        day: 28,
        hour,
        minute,
        second,
    })
    .unwrap()
}

fn set(e: &mut Entry, name: &str, value: &str, protected: bool) {
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected,
        },
    );
}

fn entry(id: Uuid, fields: &[(&str, &str)]) -> Entry {
    let mut e = Entry::new(id, Time(0));
    for (n, v) in fields {
        set(&mut e, n, v, false);
    }
    e
}

/// The card's demo vault V, the parts these cases use: root R holds the
/// parser entry P; group Web holds E1, E3, E4; group Bank (sequence
/// `{USERNAME}{ENTER}{DELAY 200}{PASSWORD}{ENTER}`) holds E5 and E6.
/// `edit` changes P first.
fn demo(edit: impl FnOnce(&mut Entry)) -> Vault {
    let mut p = entry(
        P,
        &[
            ("Title", "Parser"),
            ("UserName", "Username"),
            ("Password", "Password@1"),
            ("URL", "https://example.com"),
            ("attr1", "value1"),
        ],
    );
    edit(&mut p);
    let mut e1 = entry(
        E1,
        &[
            ("Title", "GitHub"),
            ("UserName", "alex-dev"),
            ("Password", "demo-gh-pass-1"),
            ("URL", "https://github.com/login"),
            ("otp", E1_OTP),
        ],
    );
    e1.auto_type.default_sequence = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}".into();
    let e3 = entry(
        E3,
        &[
            ("Title", "Demo Mail"),
            ("UserName", "demo@mail.example"),
            ("Password", "demo-pass-1"),
        ],
    );
    let e4 = entry(E4, &[("Title", "Pin only"), ("Password", "4321")]);
    let e5 = entry(
        E5,
        &[
            ("Title", "Bank login"),
            ("UserName", "demo-bank"),
            ("Password", "demo-bank-pass"),
        ],
    );
    let mut e6 = entry(
        E6,
        &[("Title", "Fields"), ("Site", "Portal"), ("Field 2", "two")],
    );
    set(&mut e6, "Pin", "1234", true);
    let mut web = Group::new(Uuid([0x0A; 16]), "Web".into(), Time(0));
    web.entries = vec![e1, e3, e4];
    let mut bank = Group::new(Uuid([0x0B; 16]), "Bank".into(), Time(0));
    bank.default_sequence = "{USERNAME}{ENTER}{DELAY 200}{PASSWORD}{ENTER}".into();
    bank.auto_type = Switch::Inherit;
    bank.entries = vec![e5, e6];
    let mut root = Group::new(Uuid([0x0F; 16]), "R".into(), Time(0));
    root.entries.push(p);
    root.groups = vec![web, bank];
    Vault::new(root, Time(0))
}

fn find(v: &Vault, id: Uuid) -> &Entry {
    v.root
        .subtree()
        .into_iter()
        .flat_map(|g| g.entries.iter())
        .find(|e| e.uuid == id)
        .unwrap()
}

/// The US layout's keys with no modifier (Carbon `kVK_ANSI_*`).
fn us() -> Layout {
    Layout::new([
        ('a', 0x00),
        ('s', 0x01),
        ('d', 0x02),
        ('f', 0x03),
        ('h', 0x04),
        ('g', 0x05),
        ('z', 0x06),
        ('x', 0x07),
        ('c', 0x08),
        ('v', 0x09),
        ('b', 0x0B),
        ('q', 0x0C),
        ('w', 0x0D),
        ('e', 0x0E),
        ('r', 0x0F),
        ('y', 0x10),
        ('t', 0x11),
        ('1', 0x12),
        ('o', 0x1F),
        ('u', 0x20),
        ('i', 0x22),
        ('p', 0x23),
        ('l', 0x25),
        ('j', 0x26),
        ('k', 0x28),
        ('n', 0x2D),
        ('m', 0x2E),
    ])
}

fn opts(layout: &Layout) -> Options<'_> {
    Options {
        layout,
        shortcut: None,
        start_delay_ms: 500,
        key_pause_ms: 25,
    }
}

fn plan_in(v: &Vault, id: Uuid, seq: &str, o: &Options<'_>) -> Result<Plan, Error> {
    plan(seq, find(v, id), &Context::new(Some(v), at(10, 0, 29)), o)
}

/// The plan as readable lines; adjacent text of one mode is joined.
fn render(p: &Plan) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut last_text: Option<bool> = None;
    for a in p.actions() {
        match a {
            Action::Text { text, by_key } => {
                if last_text == Some(*by_key) {
                    out.last_mut().unwrap().push_str(text.expose());
                } else {
                    let tag = if *by_key { "keys " } else { "text " };
                    out.push(format!("{tag}{}", text.expose()));
                }
                last_text = Some(*by_key);
                continue;
            }
            Action::Key { code, mods } => out.push(format!("key {code:#04x}{mods}")),
            Action::Wait(ms) => out.push(format!("wait {ms}")),
            Action::Pause(ms) => out.push(format!("pause {ms}")),
            Action::Otp { .. } => out.push("otp".into()),
            Action::Pick { value, .. } => {
                out.push(format!("pick {}", value.expose().chars().count()))
            }
        }
        last_text = None;
    }
    out
}

fn run_in(v: &Vault, id: Uuid, seq: &str) -> Result<Vec<String>, Error> {
    plan_in(v, id, seq, &opts(&us())).map(|p| render(&p))
}

fn run(seq: &str) -> Result<Vec<String>, Error> {
    run_in(&demo(|_| {}), P, seq)
}

fn fails(seq: &str) -> (&'static str, String) {
    let e = run(seq).unwrap_err();
    (e.id(), e.to_string())
}

#[test]
fn t01_default_sequence() {
    let v = demo(|_| {});
    let p = plan_in(&v, P, "{USERNAME}{TAB}{PASSWORD}{ENTER}", &opts(&us())).unwrap();
    assert_eq!(
        render(&p),
        ["text Username", "key 0x30", "text Password@1", "key 0x24"]
    );
    assert_eq!((p.start_delay_ms, p.key_pause_ms), (500, 25));
    assert_eq!(p.keys(), 20);
}

#[test]
fn t02_brace_escapes() {
    assert_eq!(run("{{}x{}}").unwrap(), ["text {x}"]);
}

#[test]
fn t03_unpaired_brace() {
    assert_eq!(run("{TAB}}").unwrap_err(), Error::Unpaired);
    assert_eq!(Error::Unpaired.to_string(), "A { or } has no partner.");
}

#[test]
fn t04_lone_braces_are_characters() {
    assert_eq!(run("}{").unwrap(), ["text }{"]);
    assert_eq!(run("{}").unwrap(), ["text {}"]);
}

#[test]
fn t05_modifiers() {
    assert_eq!(
        run("+{TAB}^a#v%{F4}").unwrap(),
        ["key 0x30⇧", "key 0x00⌃", "key 0x09⌘", "key 0x76⌥"]
    );
    // A modifier repeated in one run counts once.
    assert_eq!(run("++^+a").unwrap(), ["key 0x00⌃⇧"]);
}

#[test]
fn t06_dangling_modifiers() {
    assert_eq!(run("abc+").unwrap_err(), Error::DanglingMods("+".into()));
    assert_eq!(
        fails("a^%"),
        (
            "MI05-24",
            "^% at the end of the sequence have no key to go with.".into()
        )
    );
}

#[test]
fn t07_repeat_counts() {
    let mut want = vec!["key 0x30".to_string(); 3];
    want.extend(vec!["key 0x7b".to_string(); 100]);
    assert_eq!(run("{TAB 3}{SPACE 0}{LEFT 100}").unwrap(), want);
}

#[test]
fn t08_repeat_over_100() {
    assert_eq!(
        fails("{LEFT 101}"),
        ("MI05-12", "{LEFT 101} repeats more than 100 times.".into())
    );
}

#[test]
fn t09_overflowing_counts_fail() {
    assert_eq!(fails("{TAB 99999999999}").0, "MI05-12");
    assert_eq!(fails("{DELAY 5000000000}").0, "MI05-13");
    assert_eq!(fails("{TAB 99999999999999999999999999}").0, "MI05-12");
    assert_eq!(fails("{DELAY=99999999999999999999999}").0, "MI05-14");
}

#[test]
fn t10_names_ignore_case() {
    assert_eq!(
        run("{tab}{Enter}{PGDN}{pgdown}{Bksp}").unwrap(),
        ["key 0x30", "key 0x24", "key 0x79", "key 0x79", "key 0x33"]
    );
}

#[test]
fn t11_keypad_and_right_command() {
    assert_eq!(
        run("{NUMPAD5}{ADD}{SUBTRACT}{MULTIPLY}{DIVIDE}{RWIN}").unwrap(),
        [
            "key 0x57", "key 0x45", "key 0x4e", "key 0x43", "key 0x4b", "key 0x36"
        ]
    );
    assert_eq!(
        run("{NUMPAD0}{NUMPAD8}{NUMPAD9}{F1}{F16}{DELETE}").unwrap(),
        [
            "key 0x52", "key 0x5b", "key 0x5c", "key 0x7a", "key 0x6a", "key 0x75"
        ]
    );
}

#[test]
fn t11_leading_zeros_are_not_keys() {
    // LD-184 (2): they read as placeholders, which MOD-08 does not know.
    for n in 1..=9 {
        assert_eq!(fails(&format!("{{F0{n}}}")).0, "MI05-19", "F0{n}");
    }
    for n in 0..=9 {
        assert_eq!(fails(&format!("{{NUMPAD0{n}}}")).0, "MI05-19", "NUMPAD0{n}");
    }
    assert_eq!(fails("{F0}").0, "MI05-19");
    assert_eq!(run("{NUMPAD0}{F10}").unwrap(), ["key 0x52", "key 0x6d"]);
}

#[test]
fn t12_keys_a_mac_lacks() {
    let p = plan_in(
        &demo(|_| {}),
        P,
        "{INSERT}{INS}{BREAK}{NUMLOCK}{PTRSC}{SCROLLLOCK}{APPS}",
        &opts(&us()),
    )
    .unwrap();
    assert!(p.actions().is_empty());
    assert_eq!(p.keys(), 0);
}

#[test]
fn t13_brace_and_paren_names() {
    assert_eq!(
        run("{LEFTBRACE}{RIGHTBRACE}{LEFTPAREN}{RIGHTPAREN}{(}{)}{[}{]}{+}{%}{^}{~}{#}").unwrap(),
        ["text {}()()[]+%^~#"]
    );
}

#[test]
fn t14_count_on_text_key_and_tilde() {
    assert_eq!(run("{+ 3}~@").unwrap(), ["text +++~@"]);
}

#[test]
fn t15_delay() {
    assert_eq!(run("{DELAY 500}").unwrap(), ["wait 500"]);
    assert_eq!(run("{DELAY 10000}").unwrap(), ["wait 10000"]);
    assert_eq!(
        fails("{DELAY 10001}"),
        (
            "MI05-13",
            "{DELAY 10001} waits longer than 10 seconds.".into()
        )
    );
}

#[test]
fn t16_key_pause() {
    assert_eq!(
        run("{DELAY=50}a{DELAY= 0 }b").unwrap(),
        ["pause 50", "text a", "pause 0", "text b"]
    );
    assert_eq!(run("{DELAY= 40}c").unwrap(), ["pause 40", "text c"]);
    assert_eq!(
        fails("{DELAY=501}"),
        (
            "MI05-14",
            "{DELAY=501} pauses more than 500 ms between keys.".into()
        )
    );
    assert_eq!(fails("{DELAY = 5}").0, "MI05-19");
}

#[test]
fn t17_delay_needs_a_number() {
    assert_eq!(
        fails("{DELAY}"),
        ("MI05-15", "{DELAY} needs a number.".into())
    );
    assert_eq!(fails("{DELAY=abc}").0, "MI05-15");
}

#[test]
fn t18_start_delay_and_pause_clamped() {
    let layout = us();
    let o = Options {
        start_delay_ms: 50,
        key_pause_ms: 900,
        ..opts(&layout)
    };
    let p = plan_in(&demo(|_| {}), P, "ab", &o).unwrap();
    assert_eq!((p.start_delay_ms, p.key_pause_ms), (100, 500));
    let o = Options {
        start_delay_ms: 20_000,
        ..opts(&layout)
    };
    assert_eq!(
        plan_in(&demo(|_| {}), P, "ab", &o).unwrap().start_delay_ms,
        10_000
    );
}

#[test]
fn t19_clearfield() {
    assert_eq!(run("{CLEARFIELD 3}").unwrap(), ["key 0x00⌘", "key 0x33"]);
}

#[test]
fn t20_totp_computed_when_typing_reaches_it() {
    let v = demo(|_| {});
    // The plan is made at 10:00:29; with the 500 ms start delay typing
    // reaches the token in the 30-second step that starts at 10:00:30.
    let p = plan_in(&v, E1, "{TOTP}", &opts(&us())).unwrap();
    assert_eq!(render(&p), ["otp"]);
    assert_eq!(p.keys(), 6);
    let e1 = find(&v, E1);
    let typed = p.otp_code(at(10, 0, 30)).unwrap();
    assert_eq!(typed, totp::code_for(e1, at(10, 0, 30)).unwrap());
    assert_ne!(typed, totp::code_for(e1, at(10, 0, 29)).unwrap());
}

#[test]
fn t21_totp_none_or_invalid() {
    assert_eq!(run("x{TOTP}").unwrap(), ["text x"]);
    let v = demo(|p| set(p, "otp", "otpauth://totp/x?secret=!!", false));
    assert_eq!(run_in(&v, P, "x{TOTP}").unwrap_err(), Error::Otp);
    assert_eq!(
        Error::Otp.to_string(),
        "The one-time code settings of this entry are not valid."
    );
}

#[test]
fn ld184_3_totp_through_a_field() {
    // Computed when the plan is made, as MOD-08 resolves the field.
    let v = demo(|p| {
        set(p, "otp", E1_OTP, false);
        set(p, "Code", "{TOTP}", false);
    });
    let code = totp::code_for(find(&v, P), at(10, 0, 29)).unwrap();
    assert_eq!(
        run_in(&v, P, "{S:Code}").unwrap(),
        [format!("text {}", code.expose())]
    );
    // Invalid settings fail the run instead of typing nothing.
    let v = demo(|p| {
        set(p, "otp", "otpauth://totp/x?secret=!!", false);
        set(p, "Code", "{TOTP}", false);
    });
    assert_eq!(run_in(&v, P, "x{S:Code}").unwrap_err(), Error::Otp);
    assert_eq!(
        run_in(&v, P, "{T-CONV:/{TOTP}/upper/}").unwrap_err(),
        Error::Otp
    );
    let ctx = Context::new(Some(&v), at(10, 0, 29));
    let layout = us();
    assert_eq!(
        check("{S:Code}", find(&v, P), &ctx, &opts(&layout)),
        Err(Error::Otp)
    );
    // No one-time password: nothing, no error.
    let v = demo(|p| set(p, "Code", "{TOTP}", false));
    assert_eq!(run_in(&v, P, "x{S:Code}").unwrap(), ["text x"]);
}

#[test]
fn t22_pickchars() {
    let v = demo(|_| {});
    let mut p = plan_in(&v, E1, "{PICKCHARS}", &opts(&us())).unwrap();
    assert_eq!(p.picks(), [14]);
    assert_eq!(p.keys(), 0);
    p.fill_picks(&[Picked {
        positions: vec![0, 2],
        tab_after: true,
    }])
    .unwrap();
    assert_eq!(render(&p), ["text d", "key 0x30", "text m"]);
    assert_eq!(p.keys(), 3);
    assert!(p.picks().is_empty());
}

#[test]
fn t23_pickchars_field_names() {
    let v = demo(|_| {});
    assert_eq!(
        run_in(&v, E6, "{PICKCHARS:Nope}").unwrap_err(),
        Error::NoField("{PICKCHARS:Nope}".into())
    );
    let p = plan_in(&v, E6, "{PICKCHARS:Pin}", &opts(&us())).unwrap();
    assert_eq!(p.picks(), [4]);
    assert_eq!(
        run_in(&v, E6, "{PICKCHARS:Pin:C=2}").unwrap_err().id(),
        "MI05-17"
    );
}

#[test]
fn t24_pick_cancel_types_nothing() {
    // Cancel drops the plan (D-INT05-9): until the picks are filled the
    // plan holds the pick, so nothing after it can be typed without it.
    let v = demo(|_| {});
    let p = plan_in(&v, E1, "{USERNAME}{TAB}{PICKCHARS}{ENTER}", &opts(&us())).unwrap();
    assert_eq!(p.picks(), [14]);
    assert_eq!(
        render(&p),
        ["text alex-dev", "key 0x30", "pick 14", "key 0x24"]
    );
}

#[test]
fn t25_pick_over_256_characters() {
    let long = "x".repeat(257);
    let v = demo(|p| set(p, "Password", &long, true));
    assert_eq!(
        run_in(&v, P, "{PICKCHARS}").unwrap_err(),
        Error::PickTooLong("{PICKCHARS}".into())
    );
    let v = demo(|p| set(p, "Password", &long[..256], true));
    assert_eq!(
        plan_in(&v, P, "{PICKCHARS}", &opts(&us())).unwrap().picks(),
        [256]
    );
}

#[test]
fn t26_mode_virtual() {
    // Key-code lookups happen while typing (E8-S3); the plan marks the text.
    assert_eq!(
        run("{MODE=VIRTUAL}aB{MODE=NORMAL}c").unwrap(),
        ["keys aB", "text c"]
    );
    assert_eq!(
        run("{mode=xvirtual}a{MODE=other}b").unwrap(),
        ["keys a", "text b"]
    );
}

#[test]
fn t27_ignored_commands() {
    assert_eq!(
        run("{BEEP 3 3}{VKEY 0x01}{VKEY-EX 0x01}{APPACTIVATE Notes}{C:note}x").unwrap(),
        ["text x"]
    );
}

#[test]
fn t28_custom_fields() {
    assert_eq!(run("{S:attr1}").unwrap(), ["text value1"]);
    assert!(run("{S:ATTR1}").unwrap().is_empty());
    assert_eq!(
        fails("{s:attr1}"),
        (
            "MI05-19",
            "{s:attr1} is not a placeholder App knows.".into()
        )
    );
}

#[test]
fn t29_unknown_placeholders() {
    assert_eq!(fails("{FOO}").0, "MI05-19");
    assert_eq!(fails("{USERNAME 2}").0, "MI05-19");
}

#[test]
fn t30_field_name_with_digits() {
    assert_eq!(
        run_in(&demo(|_| {}), E6, "{S:Field 2}").unwrap(),
        ["text two"]
    );
}

#[test]
fn t31_references() {
    let id: String = E3.0.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        run(&format!("{{REF:U@I:{id}}}")).unwrap(),
        ["text demo@mail.example"]
    );
    assert_eq!(fails(&format!("{{ref:U@I:{id}}}")).0, "MI05-19");
}

#[test]
fn t32_conversions() {
    assert_eq!(
        run("{T-CONV:;{USERNAME};hex;}").unwrap(),
        ["text 557365726e616d65"]
    );
    assert_eq!(
        fails("{T-CONV:/{USERNAME}/nope/}"),
        (
            "MI05-20",
            "{T-CONV:/{USERNAME}/nope/} is not a conversion App can use.".into()
        )
    );
    assert_eq!(fails("{T-CONV:}").0, "MI05-20");
    assert_eq!(
        run("{T-REPLACE-RX:/{USERNAME}/name/NAME/}").unwrap(),
        ["text UserNAME"]
    );
    assert_eq!(fails("{T-REPLACE-RX:/{USERNAME}/a/}").0, "MI05-20");
    assert_eq!(fails("{T-REPLACE-RX:/x/(?<=a)b/c/}").0, "MI05-20");
}

#[test]
fn t33_control_characters_in_values() {
    let v = demo(|p| set(p, "Notes", "l1\r\nl2\nl3\rx\ty\u{7}z", false));
    assert_eq!(
        run_in(&v, P, "{NOTES}").unwrap(),
        [
            "text l1", "key 0x24", "text l2", "key 0x24", "text l3", "key 0x24", "text x",
            "key 0x30", "text yz"
        ]
    );
}

#[test]
fn t34_modifiers_on_a_placeholder_are_ignored() {
    assert_eq!(run("+{USERNAME}").unwrap(), ["text Username"]);
}

#[test]
fn t35_unicode() {
    let v = demo(|p| set(p, "UserName", "é😀", false));
    let p = plan_in(&v, P, "{USERNAME}", &opts(&us())).unwrap();
    assert_eq!(render(&p), ["text é😀"]);
    assert_eq!(p.keys(), 2, "one key per Unicode scalar value");
}

#[test]
fn t36_run_bounds() {
    assert_eq!(run(&"{TAB 100}".repeat(100)).unwrap().len(), 10_000);
    assert_eq!(
        fails(&"{TAB 100}".repeat(101)),
        (
            "MI05-21",
            "The sequence has more than 10,000 keys, waits and pauses.".into()
        )
    );
    assert_eq!(run(&"{DELAY 10000}".repeat(6)).unwrap().len(), 6);
    assert_eq!(
        fails(&"{DELAY 10000}".repeat(7)),
        (
            "MI05-22",
            "The waits in the sequence add up to more than 60 seconds.".into()
        )
    );
    // Resolved characters count: a 10,001-character username.
    let v = demo(|p| set(p, "UserName", &"u".repeat(10_001), false));
    assert_eq!(run_in(&v, P, "{USERNAME}").unwrap_err(), Error::TooManyKeys);
    // Picked characters count too; a failed fill leaves the plan as it was.
    let v = demo(|_| {});
    let mut p = plan_in(
        &v,
        E1,
        &format!("{}{{PICKCHARS}}", "{TAB 100}".repeat(99)),
        &opts(&us()),
    )
    .unwrap();
    let many = Picked {
        positions: vec![0; 101],
        tab_after: false,
    };
    assert_eq!(p.fill_picks(&[many]), Err(Error::TooManyKeys));
    assert_eq!(p.picks(), [14]);
    p.fill_picks(&[Picked {
        positions: vec![0; 100],
        tab_after: false,
    }])
    .unwrap();
    assert_eq!(p.keys(), 10_000);
}

#[test]
fn t37_growth_bound() {
    // R05-7: MOD-08.20's work bound shows as MI05-27, not MI05-19.
    let v = demo(|p| {
        set(p, "Grow", &"{USERNAME}".repeat(16), false);
        set(p, "UserName", "{S:Grow}", false);
    });
    let start = cpu();
    let e = run_in(&v, P, "{S:Grow}").unwrap_err();
    assert!(cpu() - start < Duration::from_secs(1));
    assert_eq!(e, Error::Grows("{S:Grow}".into()));
    assert_eq!(
        e.to_string(),
        "{S:Grow} refers to itself or grows too large."
    );
}

#[test]
fn t38_messages_hold_no_values() {
    let v = demo(|p| set(p, "otp", "otpauth://totp/x?secret=!!", false));
    let messages = [
        run_in(&v, E6, "{PICKCHARS:Nope}").unwrap_err().to_string(),
        run_in(&v, P, "{TOTP}").unwrap_err().to_string(),
    ];
    assert!(messages[0].contains("{PICKCHARS:Nope}"));
    assert_eq!(messages[1], Error::Otp.to_string());
    for m in messages {
        for secret in ["1234", "Password@1", "Username", "!!"] {
            assert!(!m.contains(secret), "{m}");
        }
    }
    // A token is cut to its first 40 characters (INT-05.18).
    let long = format!("{{FOO{}}}", "x".repeat(60));
    let e = run(&long).unwrap_err();
    assert_eq!(e, Error::Unknown(long.chars().take(40).collect()));
}

#[test]
fn t39_editor_check() {
    let long = "x".repeat(300);
    let v = demo(|p| set(p, "Password", &long, true));
    let ctx = Context::new(Some(&v), at(10, 0, 29));
    let layout = us();
    assert_eq!(
        check("{USERNAME}{PICKCHARS}", find(&v, P), &ctx, &opts(&layout)),
        Ok(())
    );
    assert_eq!(
        check("{PICKCHARS:Nope}", find(&v, P), &ctx, &opts(&layout))
            .unwrap_err()
            .id(),
        "MI05-17"
    );
    assert_eq!(
        check("{TAB 101}", find(&v, P), &ctx, &opts(&layout))
            .unwrap_err()
            .id(),
        "MI05-12"
    );
}

#[test]
fn t41_command_names_ignore_case() {
    let v = demo(|p| set(p, "Password", "", true));
    let p = plan_in(
        &v,
        P,
        "{Delay 5}{clearfield}{totp}{PickChars}",
        &opts(&us()),
    )
    .unwrap();
    assert_eq!(render(&p), ["wait 5", "key 0x00⌘", "key 0x33"]);
    assert!(p.picks().is_empty());
}

#[test]
fn t98_combination_follows_the_layout() {
    // INT-05.42 on a French AZERTY table: `a` is the key at 0x0C.
    let azerty = Layout::new([('a', 0x0C), ('q', 0x00), ('v', 0x09)]);
    let p = plan_in(&demo(|_| {}), P, "#a", &opts(&azerty)).unwrap();
    assert_eq!(render(&p), ["key 0x0c⌘"]);
}

#[test]
fn t99_no_key_for_the_character() {
    let e = run("^ü").unwrap_err();
    assert_eq!(
        e,
        Error::NoKey {
            ch: 'ü',
            mods: Mods::CONTROL
        }
    );
    assert_eq!(
        e.to_string(),
        "ü can't be typed with ⌃ on this keyboard layout."
    );
    // A layout with no `a` key cannot clear a field.
    let none = Layout::default();
    assert_eq!(
        plan_in(&demo(|_| {}), P, "{CLEARFIELD}", &opts(&none))
            .unwrap_err()
            .id(),
        "MI05-23"
    );
}

#[test]
fn t108_effective_sequences_through_the_planner() {
    // INT-05.1, MOD-02.15, MOD-02.16: the sequence comes from app-core.
    let v = demo(|_| {});
    let seq = entry_sequence(&v, E4);
    assert_eq!(seq, "{PASSWORD}{ENTER}");
    assert_eq!(run_in(&v, E4, &seq).unwrap(), ["text 4321", "key 0x24"]);
    let seq = entry_sequence(&v, E5);
    assert_eq!(
        run_in(&v, E5, &seq).unwrap(),
        [
            "text demo-bank",
            "key 0x24",
            "wait 200",
            "text demo-bank-pass",
            "key 0x24"
        ]
    );
    let seq = entry_sequence(&v, E1);
    assert_eq!(
        run_in(&v, E1, &seq).unwrap(),
        [
            "text alex-dev",
            "key 0x30",
            "text demo-gh-pass-1",
            "key 0x30",
            "otp",
            "key 0x24"
        ]
    );
}

#[test]
fn r05_2_deep_nesting_fails_fast() {
    let deep = format!("{}{}", "{a".repeat(50_000), "}".repeat(50_000));
    let start = cpu();
    let e = run(&deep).unwrap_err();
    let took = cpu() - start;
    assert_eq!(e.id(), "MI05-25");
    assert_eq!(
        e.to_string(),
        format!("{} has braces nested more than 32 deep.", "{a".repeat(20))
    );
    assert!(took < Duration::from_millis(100), "{took:?}");
}

#[test]
fn r05_2_thirty_two_levels_read() {
    // An ignored comment, so MOD-08's own depth budget does not apply.
    let nested = |levels: usize| {
        format!(
            "{{C:{}x{}}}",
            "{a".repeat(levels - 1),
            "}".repeat(levels - 1)
        )
    };
    assert_eq!(run(&format!("{}y", nested(32))).unwrap(), ["text y"]);
    assert_eq!(run(&nested(33)).unwrap_err().id(), "MI05-25");
}

#[test]
fn r05_3_control_characters_in_the_sequence() {
    assert_eq!(
        run("a\nb\tc\r\u{0}d").unwrap(),
        ["text ab", "key 0x30", "text cd"]
    );
}

#[test]
fn r05_4_own_shortcut_fails_before_typing() {
    let layout = us();
    let o = Options {
        shortcut: Some(Shortcut {
            code: 0x09,
            mods: Mods::CONTROL | Mods::OPTION,
        }),
        ..opts(&layout)
    };
    let v = demo(|_| {});
    let e = plan_in(&v, P, "x^%v", &o).unwrap_err();
    assert_eq!(e, Error::Shortcut("^%v".into()));
    assert_eq!(e.id(), "MI05-26");
    // Exact modifiers only, and named keys too.
    assert!(plan_in(&v, P, "^v%v^%+v", &o).is_ok());
    let o = Options {
        shortcut: Some(Shortcut {
            code: 0x60,
            mods: Mods::CONTROL | Mods::OPTION,
        }),
        ..opts(&layout)
    };
    assert_eq!(
        plan_in(&v, P, "^%{F5}", &o).unwrap_err(),
        Error::Shortcut("^%{F5}".into())
    );
}

#[test]
fn r05_7_self_reference() {
    let v = demo(|p| set(p, "UserName", "{USERNAME}", false));
    assert_eq!(run_in(&v, P, "{USERNAME}").unwrap_err().id(), "MI05-27");
}

#[test]
fn t40_slowest_fuzz_inputs_stay_fast() {
    // The two slowest inputs of the first fuzz run (tests/data): a
    // username that refers to itself through conversions and references.
    // MOD-08's bounds and the plan's meter end them with MI05-27.
    for data in [
        &include_bytes!("data/slow-1")[..],
        &include_bytes!("data/slow-2")[..],
    ] {
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let parts: Vec<&[u8]> = data.split(|&b| b == 0x1E).collect();
        let v = demo(|p| {
            set(p, "UserName", &text(parts[1]), false);
            set(p, "Password", &text(parts[2]), false);
            set(p, "Notes", &text(parts[3]), false);
        });
        let start = cpu();
        let r = run_in(&v, P, &text(parts[0]));
        let took = cpu() - start;
        assert_eq!(r.unwrap_err().id(), "MI05-27");
        assert!(took < Duration::from_millis(100), "{took:?}");
    }
}
