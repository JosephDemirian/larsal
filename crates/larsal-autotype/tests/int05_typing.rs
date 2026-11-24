//! INT-05 typing cases on the recording backend (E8-S3): T01, T15, T16,
//! T18 to T20, T26, T33, T35, T90 to T93, T97 and T98 at the fake-layout
//! level, T102, T103, T110, LD-186 (2) and (3). The recorder posts nothing
//! and its clock is fake (AGENTS.md rule 10). Demo data only.

use larsal_autotype::{
    Error, Layout, Mods, Options, Picked, Plan, Recorder, Stop, Typed, plan, type_plan,
};
use larsal_core::refs::Context;
use larsal_core::totp;
use larsal_crypto::secret::SecretString;
use larsal_model::times::Civil;
use larsal_model::{Entry, Field, Group, Time, Uuid, Vault};

const P: Uuid = Uuid([0x50; 16]);
const OTP: &str = "otpauth://totp/GitHub:alex-dev?secret=JBSWY3DPEHPK3PXP&period=30&digits=6";

fn at(hour: u32, minute: u32, second: u32) -> Time {
    let civil = Civil {
        year: 2026,
        month: 10,
        day: 28,
        hour,
        minute,
        second,
    };
    Time::from_civil(civil).unwrap()
}

/// The vault with the parser entry P (INT-05 test cases) and `extra` fields.
fn vault(extra: &[(&str, &str)]) -> Vault {
    let mut p = Entry::new(P, Time(0));
    let fields = [
        ("Title", "Parser"),
        ("UserName", "Username"),
        ("Password", "Password@1"),
        ("URL", "https://example.com"),
    ];
    for (n, v) in fields.iter().chain(extra) {
        let value = SecretString::new((*v).into());
        p.set_field(
            (*n).into(),
            Field {
                value,
                protected: false,
            },
        );
    }
    let mut root = Group::new(Uuid([0x0F; 16]), "R".into(), Time(0));
    root.entries.push(p);
    Vault::new(root, Time(0))
}

/// A US table with modifier forms (Carbon `kVK_ANSI_*`; ⌥ and ⌥⇧ forms as
/// the US layout types them); `é` and `ü` are dead keys there, so absent.
fn us() -> Layout {
    let mut keys = vec![];
    for (c, code) in [
        ('a', 0x00),
        ('s', 0x01),
        ('z', 0x06),
        ('v', 0x09),
        ('b', 0x0B),
    ] {
        keys.push((c, code, Mods::NONE));
        keys.push((c.to_ascii_uppercase(), code, Mods::SHIFT));
    }
    keys.extend([
        ('1', 0x12, Mods::NONE),
        ('!', 0x12, Mods::SHIFT),
        ('c', 0x08, Mods::NONE),
        ('©', 0x05, Mods::OPTION),
        ('±', 0x18, Mods::OPTION | Mods::SHIFT),
    ]);
    Layout::with_mods(keys)
}

fn plan_with(v: &Vault, seq: &str, layout: &Layout, start: u32, pause: u32) -> Result<Plan, Error> {
    let entry = &v.root.entries[0];
    let opts = Options {
        layout,
        shortcut: None,
        start_delay_ms: start,
        key_pause_ms: pause,
    };
    plan(seq, entry, &Context::new(Some(v), at(10, 0, 29)), &opts)
}

/// Types `seq` for P with S-AT-09 500 and S-AT-10 25; the recorder after.
fn typed(seq: &str) -> (Typed, Recorder) {
    let p = plan_with(&vault(&[]), seq, &us(), 500, 25).unwrap();
    run(&p, Recorder::default(), u32::MAX)
}

/// Runs `p`; `go_on` says yes `yes` times (the first is INT-05.38 step 1).
fn run(p: &Plan, mut rec: Recorder, yes: u32) -> (Typed, Recorder) {
    let mut left = yes;
    let end = type_plan(p, &mut rec, &mut || {
        let ok = left > 0;
        left = left.saturating_sub(1);
        ok
    });
    (end, rec)
}

/// Each press as `at code mods text`; every key-down must come with its
/// key-up right after it, same code, flags and text (INT-05.39, INT-05.43).
fn presses(rec: &Recorder) -> Vec<String> {
    assert_eq!(rec.events.len() % 2, 0, "every key-down has its key-up");
    rec.events
        .chunks(2)
        .map(|pair| {
            let (d, u) = (&pair[0], &pair[1]);
            assert!(d.down && !u.down, "key-down before key-up");
            assert_eq!((d.code, d.mods, d.at_ms), (u.code, u.mods, u.at_ms));
            assert_eq!(d.text, u.text);
            format!("{} {:#04x}{} {}", d.at_ms, d.code, d.mods, d.text.expose())
                .trim_end()
                .to_owned()
        })
        .collect()
}

#[test]
fn t01_int_05_40_ascii_text_and_named_keys_with_the_start_delay_and_pause() {
    let (end, rec) = typed("{USERNAME}{TAB}{PASSWORD}{ENTER}");
    assert_eq!(end, Typed::Finished(8 + 1 + 10 + 1));
    let got = presses(&rec);
    // 500 ms before the first event, then 25 ms after each press.
    let want: Vec<String> = "Username"
        .chars()
        .map(|c| format!("0x00 {c}"))
        .chain(["0x30".to_owned()])
        .chain("Password@1".chars().map(|c| format!("0x00 {c}")))
        .chain(["0x24".to_owned()])
        .enumerate()
        .map(|(i, p)| format!("{} {p}", 500 + 25 * i))
        .collect();
    assert_eq!(got, want);
    assert_eq!(rec.clock_ms, 500 + 25 * 20);
}

#[test]
fn t35_int_05_40_accented_and_emoji_one_event_each_key_code_0_no_flags() {
    let v = vault(&[("Notes", "é😀ü")]);
    let p = plan_with(&v, "{NOTES}", &us(), 500, 25).unwrap();
    let (end, rec) = run(&p, Recorder::default(), u32::MAX);
    assert_eq!(end, Typed::Finished(3));
    assert_eq!(presses(&rec), ["500 0x00 é", "525 0x00 😀", "550 0x00 ü"]);
    // U+1F600 goes as one event holding both of its UTF-16 units.
    let emoji: Vec<u16> = rec.events[2].text.expose().encode_utf16().collect();
    assert_eq!(emoji, [0xD83D, 0xDE00]);
    assert!(
        rec.events
            .iter()
            .all(|e| e.code == 0 && e.mods == Mods::NONE)
    );
}

#[test]
fn t26_t97_int_05_41_key_code_mode_with_modifier_forms_and_dead_keys_as_text() {
    let (_, rec) = typed("{MODE=VIRTUAL}aB{MODE=NORMAL}c");
    assert_eq!(presses(&rec), ["500 0x00", "525 0x0b⇧", "550 0x00 c"]);
    // LD-186 (3): ⇧, ⌥ and ⌥⇧ forms; `é` is a dead key on US, so it goes
    // as its Unicode string (T97 on the fake US table).
    let (_, rec) = typed("{MODE=VIRTUAL}aZ1é©±!");
    assert_eq!(
        presses(&rec),
        [
            "500 0x00",
            "525 0x06⇧",
            "550 0x12",
            "575 0x00 é",
            "600 0x05⌥",
            "625 0x18⌥⇧",
            "650 0x12⇧"
        ]
    );
    // ⌘5 (`{MODE=VIRTUAL}` plus the row's sequence) types resolved values
    // and `{TOTP}` by key too.
    let (_, rec) = typed("{MODE=VIRTUAL}{USERNAME}");
    assert_eq!(presses(&rec)[0], "500 0x00 U", "U is not on the fake table");
    assert_eq!(presses(&rec)[1], "525 0x01", "s by its key");
}

#[test]
fn ld_186_3_the_layout_keeps_one_press_with_the_fewest_modifiers() {
    let l = Layout::with_mods([
        ('+', 0x18, Mods::SHIFT),
        ('+', 0x45, Mods::NONE),
        ('x', 0x07, Mods::COMMAND),
        ('y', 0x10, Mods::OPTION | Mods::SHIFT),
        ('y', 0x11, Mods::OPTION),
        ('z', 0x06, Mods::NONE),
        ('z', 0x2C, Mods::NONE),
    ]);
    assert_eq!(l.key('+'), Some((0x45, Mods::NONE)));
    assert_eq!(l.key('x'), None, "only ⇧ and ⌥ forms count");
    assert_eq!(l.key('y'), Some((0x11, Mods::OPTION)));
    assert_eq!(
        l.key('z'),
        Some((0x06, Mods::NONE)),
        "the first among equals"
    );
    // A combination needs the plain form (INT-05.42): `^!` has none on US.
    let v = vault(&[]);
    assert!(matches!(
        plan_with(&v, "^!", &us(), 500, 25),
        Err(Error::NoKey { ch: '!', .. })
    ));
}

#[test]
fn t98_t102_int_05_42_int_05_43_combinations_by_the_layout_with_explicit_flags() {
    let (_, rec) = typed("a#v^a{CLEARFIELD}");
    assert_eq!(
        presses(&rec),
        [
            "500 0x00 a",
            "525 0x09⌘",
            "550 0x00⌃",
            "575 0x00⌘",
            "600 0x33"
        ]
    );
    // T98: the AZERTY `a` key is 0x0C, so `#a` is ⌘ on 0x0C, not ⌘Q's 0x00.
    let azerty = Layout::with_mods([('a', 0x0C, Mods::NONE), ('q', 0x00, Mods::NONE)]);
    let p = plan_with(&vault(&[]), "#a", &azerty, 500, 25).unwrap();
    let (_, rec) = run(&p, Recorder::default(), u32::MAX);
    assert_eq!(presses(&rec), ["500 0x0c⌘"]);
}

#[test]
fn t15_t16_t18_int_05_7_waits_pauses_and_the_clamped_settings() {
    // T18: S-AT-09 50 is used as 100, S-AT-10 900 as 500.
    let p = plan_with(&vault(&[]), "ab", &us(), 50, 900).unwrap();
    let (_, rec) = run(&p, Recorder::default(), u32::MAX);
    assert_eq!(presses(&rec), ["100 0x00 a", "600 0x00 b"]);
    assert_eq!(rec.clock_ms, 1_100, "500 ms after each key");
    // T16: `{DELAY=50}` after `a`, `{DELAY= 0 }` after `b`; T15: a wait.
    let (_, rec) = typed("{DELAY=50}a{DELAY= 0 }b{DELAY 500}c");
    assert_eq!(presses(&rec), ["500 0x00 a", "550 0x00 b", "1050 0x00 c"]);
    assert_eq!(rec.clock_ms, 1_050);
}

#[test]
fn t33_int_05_14_control_characters_of_a_value() {
    let v = vault(&[("Notes", "l1\r\nl2\nx\ty\u{7}z")]);
    let p = plan_with(&v, "{NOTES}", &us(), 500, 0).unwrap();
    let (_, rec) = run(&p, Recorder::default(), u32::MAX);
    let got: Vec<String> = presses(&rec).iter().map(|l| l[4..].to_owned()).collect();
    assert_eq!(
        got,
        [
            "0x00 l", "0x00 1", "0x24", "0x00 l", "0x00 2", "0x24", "0x00 x", "0x30", "0x00 y",
            "0x00 z"
        ]
    );
}

#[test]
fn t20_int_05_9_the_code_is_computed_when_typing_reaches_it() {
    let v = vault(&[("otp", OTP)]);
    let p = plan_with(&v, "{TOTP}", &us(), 500, 25).unwrap();
    // The fake clock at 10:00:29.800; after the 500 ms start delay typing
    // reaches the token in the step that starts at 10:00:30.
    let mut rec = Recorder::new(at(10, 0, 29));
    rec.clock_ms = 800;
    let (end, rec) = run(&p, rec, u32::MAX);
    assert_eq!(end, Typed::Finished(6));
    let code: String = rec
        .events
        .iter()
        .step_by(2)
        .map(|e| e.text.expose().to_owned())
        .collect();
    let entry = &v.root.entries[0];
    assert_eq!(code, totp::code_for(entry, at(10, 0, 30)).unwrap().expose());
    assert_ne!(code, totp::code_for(entry, at(10, 0, 29)).unwrap().expose());
}

#[test]
fn t90_t91_t103_at_g02_int_05_39_a_focus_change_stops_typing_with_every_key_released() {
    // Step 1 and three keys pass, then another app or window is in front
    // (or the target quit): `a`, `b`, `c` only.
    let p = plan_with(&vault(&[]), "abcdef", &us(), 500, 25).unwrap();
    let (end, rec) = run(&p, Recorder::default(), 1 + 3);
    assert_eq!(end, Typed::Stopped(3, Stop::Changed));
    assert_eq!(presses(&rec), ["500 0x00 a", "525 0x00 b", "550 0x00 c"]);
    // Changed before the first key: nothing goes out.
    let (end, rec) = run(&p, Recorder::default(), 1);
    assert_eq!(
        (end, rec.events.len()),
        (Typed::Stopped(0, Stop::Changed), 0)
    );
}

#[test]
fn t92_int_05_39_a_lock_or_the_shortcut_again_stops_after_the_second_key() {
    // The bridge's `go_on` reads the run's stop flag, which a lock or the
    // shortcut sets (larsal-ffi); here the flag goes up after the second key.
    let p = plan_with(&vault(&[]), "abcdef", &us(), 500, 25).unwrap();
    let mut rec = Recorder::default();
    let stop = core::cell::Cell::new(false);
    let mut checks = 0;
    let end = type_plan(&p, &mut rec, &mut || {
        checks += 1;
        if checks == 1 + 3 {
            stop.set(true);
        }
        !stop.get()
    });
    assert_eq!(end, Typed::Stopped(2, Stop::Changed));
    assert_eq!(presses(&rec).len(), 2);
}

#[test]
fn t93_int_05_38_step_3_waits_for_the_modifier_keys_at_most_2_s() {
    let p = plan_with(&vault(&[]), "a", &us(), 500, 25).unwrap();
    // ⌃ let go 1 s after the start: typing starts then.
    let rec = Recorder {
        held_until_ms: 1_000,
        ..Recorder::default()
    };
    let (end, rec) = run(&p, rec, u32::MAX);
    assert_eq!(end, Typed::Finished(1));
    assert_eq!(presses(&rec), ["1000 0x00 a"]);
    // Held 3 s: the run stops with the alert sound; no event.
    let rec = Recorder {
        held_until_ms: 3_000,
        ..Recorder::default()
    };
    let (end, rec) = run(&p, rec, u32::MAX);
    assert_eq!((end, rec.events.len()), (Typed::Stopped(0, Stop::Held), 0));
    assert_eq!(rec.clock_ms, 500 + 2_000);
}

#[test]
fn t110_int_05_38_step_1_the_target_never_comes_back() {
    let p = plan_with(&vault(&[]), "a", &us(), 500, 25).unwrap();
    let (end, rec) = run(&p, Recorder::default(), 0);
    assert_eq!(end, Typed::Stopped(0, Stop::NotInFront));
    assert_eq!((rec.events.len(), rec.clock_ms), (0, 2_000));
    // Back in front after 300 ms: the start delay counts from then.
    let mut asked = 0;
    let mut rec = Recorder::default();
    let end = type_plan(&p, &mut rec, &mut || {
        asked += 1;
        asked > 6
    });
    assert_eq!(end, Typed::Finished(1));
    assert_eq!(presses(&rec), ["800 0x00 a"]);
}

#[test]
fn int_05_10_d_int05_9_a_plan_with_picks_left_types_nothing() {
    let mut p = plan_with(&vault(&[]), "x{PICKCHARS}", &us(), 500, 25).unwrap();
    let (end, rec) = run(&p, Recorder::default(), u32::MAX);
    assert_eq!((end, rec.events.len()), (Typed::Stopped(0, Stop::Picks), 0));
    let pick = Picked {
        positions: vec![0, 2],
        tab_after: true,
    };
    p.fill_picks(&[pick]).unwrap();
    let (end, rec) = run(&p, Recorder::default(), u32::MAX);
    assert_eq!(end, Typed::Finished(4));
    assert_eq!(
        presses(&rec),
        ["500 0x00 x", "525 0x00 P", "550 0x30", "575 0x00 s"]
    );
}

#[test]
fn int_05_16_ld_186_2_the_action_limit_counts_zero_waits() {
    // 10,000 presses type; one more action, even a zero wait, is MI05-21.
    let full = "{TAB 100}".repeat(100);
    let p = plan_with(&vault(&[]), &full, &us(), 500, 0).unwrap();
    let (end, rec) = run(&p, Recorder::default(), u32::MAX);
    assert_eq!((end, rec.events.len()), (Typed::Finished(10_000), 20_000));
    for extra in ["{DELAY 0}", "{DELAY=0}", "a"] {
        let seq = format!("{full}{extra}");
        let e = plan_with(&vault(&[]), &seq, &us(), 500, 0).unwrap_err();
        assert_eq!(e, Error::TooManyKeys, "{extra}");
    }
}

/// MOD-08 rows 08-63 and 08-68 (MOD-08.32, INT-08 T68, F-158): Auto-Type of
/// `{USERNAME}{TAB}{PASSWORD}` on Team wiki, whose password is the planted
/// `{REF:P@U:ann@example.com}`, types no `gmail-secret-demo`: Team carries
/// a share item (one that cannot be read, which also counts), so the
/// reference searches Team only. The same entry in Home, outside every
/// share group, types Gmail's password.
#[test]
fn mod08_63_auto_type_of_a_planted_reference_types_nothing_outside_the_share() {
    let entry = |n: u8, title: &str, user: &str, password: &str| {
        let mut e = Entry::new(Uuid([n; 16]), Time(0));
        for (name, value) in [("Title", title), ("UserName", user), ("Password", password)] {
            let field = Field {
                value: SecretString::new(value.into()),
                protected: name == "Password",
            };
            e.set_field(name.into(), field);
        }
        e
    };
    let planted = "{REF:P@U:ann@example.com}";
    let mut team = Group::new(Uuid([0x20; 16]), "Team".into(), Time(0));
    team.entries.push(entry(0x44, "Team wiki", "", planted));
    team.custom_data.items.push(larsal_model::CustomDataItem {
        key: String::from_utf8(larsal_core::edit::SHARED_KEY.to_vec()).unwrap(),
        value: larsal_crypto::secret::SecretString::new("not base64 !!".into()),
        last_modified: None,
        unknown: Vec::new(),
    });
    let mut home = Group::new(Uuid([0x30; 16]), "Home".into(), Time(0));
    home.entries
        .push(entry(0x0F, "Gmail", "ann@example.com", "gmail-secret-demo"));
    home.entries.push(entry(0x31, "Outside", "", planted));
    let mut root = Group::new(Uuid([0x0F; 16]), "R".into(), Time(0));
    root.groups.push(team);
    root.groups.push(home);
    let v = Vault::new(root, Time(0));
    let layout = us();
    let opts = Options {
        layout: &layout,
        shortcut: None,
        start_delay_ms: 100,
        key_pause_ms: 0,
    };
    let typed = |g: usize| {
        let e = v.root.groups[g].entries.last().unwrap();
        let ctx = Context::new(Some(&v), at(10, 0, 29));
        let p = plan("{USERNAME}{TAB}{PASSWORD}", e, &ctx, &opts).unwrap();
        let (end, rec) = run(&p, Recorder::default(), u32::MAX);
        assert!(matches!(end, Typed::Finished(_)), "{end:?}");
        let text: String = rec
            .events
            .iter()
            .filter(|r| r.down)
            .map(|r| r.text.expose().to_owned())
            .collect();
        (text, rec.events.len())
    };
    let (wiki, events) = typed(0);
    assert_eq!(wiki, "");
    assert_eq!(events, 2, "only the Tab key");
    assert_eq!(typed(1).0, "gmail-secret-demo");
}
