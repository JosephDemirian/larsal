//! E8-S2: global Auto-Type over the session (INT-05.25 to INT-05.31,
//! AT-G01, AT-G02) on copies of the Option A demo vaults (passwords in
//! testdata/README.md). Each test names its card rule. Nothing is typed:
//! a run only counts the key events it would post (E8-S3 posts them).

use larsal_ffi::autotype::{
    AutoTypeAction, AutoTypeChosen, AutoTypeEnd, AutoTypeFocus, AutoTypeList, AutoTypeStart,
};
use larsal_ffi::edit::EditText;
use larsal_ffi::larsal_settings::{LarsalSetting, LarsalSettingValue};
use larsal_ffi::session::{Session, UnlockResult};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The frame's window (menubar-auto-type-picker, T63).
const SAFARI: &str = "Sign in to GitHub · GitHub — Safari";
/// GitHub's password in the Personal demo vault (20 characters).
const GITHUB_PASSWORD: &str = "x9!Lq#4vT@m2Zr8&Wk5p";
const UTC: i32 = 0;

/// Personal and Work opened in a test session (private pasteboard, memory
/// settings), the ones in `unlock` unlocked, Personal shown.
fn open(name: &str, unlock: &[usize]) -> (Arc<Session>, [u64; 2]) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autotype-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let session = Session::new();
    let mut ids = [0; 2];
    for (i, (file, password)) in [("personal", "demo-pass-7"), ("work", "demo-pass-8")]
        .iter()
        .enumerate()
    {
        let path = dir.join(format!("{name}-{file}.larsalvault"));
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../testdata/option-a-{file}.larsalvault"));
        std::fs::copy(source, &path).unwrap();
        ids[i] = session.open(path.to_string_lossy().into_owned()).unwrap();
        if unlock.contains(&i) {
            let unlocked = session
                .unlock(ids[i], Some((*password).into()), None)
                .unwrap();
            assert_eq!(unlocked, UnlockResult::Unlocked);
        }
    }
    session.switch_to(ids[0]).unwrap();
    (session, ids)
}

fn set(s: &Session, key: &str, value: LarsalSettingValue) {
    s.save_settings(vec![LarsalSetting {
        key: key.into(),
        value,
    }])
    .unwrap();
}

/// The frame's second row: "GitHub (work bot)" with a `*GitHub*` window.
fn add_bot(s: &Session, v: u64) {
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::Title, "GitHub (work bot)".into())
        .unwrap();
    s.set_text(v, EditText::UserName, "morgan-labs-ci".into())
        .unwrap();
    s.set_text(v, EditText::Url, "https://github.com".into())
        .unwrap();
    s.add_window(v, "*GitHub*".into(), String::new()).unwrap();
    s.commit_edit(v).unwrap();
}

fn picker(start: AutoTypeStart) -> AutoTypeList {
    match start {
        AutoTypeStart::Picker { list } => list,
        other => panic!("no picker: {other:?}"),
    }
}

fn lines(list: &AutoTypeList) -> Vec<(String, String)> {
    list.rows
        .iter()
        .map(|r| (r.title.clone(), r.username.clone()))
        .collect()
}

fn plan(chosen: AutoTypeChosen) -> u64 {
    match chosen {
        AutoTypeChosen::Type { plan } => plan,
        other => panic!("no plan: {other:?}"),
    }
}

/// The fake front window: the captured one for `left` checks, then another.
struct Focus(Mutex<u32>);

impl AutoTypeFocus for Focus {
    fn same_window(&self) -> bool {
        let mut left = self.0.lock().unwrap();
        let same = *left > 0;
        *left = left.saturating_sub(1);
        same
    }
}

fn focus(left: u32) -> Arc<Focus> {
    Arc::new(Focus(Mutex::new(left)))
}

#[test]
fn int_05_25_step_5_no_vault_then_a_locked_shown_vault() {
    assert_eq!(
        Session::new().autotype_start(SAFARI.into(), UTC),
        AutoTypeStart::NoVault
    );
    // T62: the shown vault is locked, even with another one unlocked.
    let (s, [personal, _]) = open("locked", &[1]);
    assert_eq!(
        s.autotype_start(SAFARI.into(), UTC),
        AutoTypeStart::Locked { vault: personal }
    );
}

#[test]
fn int_05_26_t63_rows_of_the_frame_window_hold_no_secret() {
    let (s, [personal, _]) = open("t63", &[0]);
    add_bot(&s, personal);
    let list = picker(s.autotype_start(SAFARI.into(), UTC));
    let alex = ("GitHub".to_owned(), "alex-dev".to_owned());
    let bot = ("GitHub (work bot)".to_owned(), "morgan-labs-ci".to_owned());
    // GitHub twice (its two matching window rules), sorted before the bot.
    assert_eq!(lines(&list), [alex.clone(), alex, bot]);
    assert_eq!(list.highlight, 0);
    assert!(
        list.rows
            .iter()
            .all(|r| r.host == "github.com" && r.vault == personal && !r.expired)
    );
    // LD-191 R02-2, INT-05.45: no sequence and no value crosses.
    let shown = format!("{list:?}");
    for secret in [
        "{USERNAME}",
        "{PASSWORD}",
        "{TOTP}",
        GITHUB_PASSWORD,
        "DEMOGITHUB",
    ] {
        assert!(!shown.contains(secret), "{secret}");
    }
}

#[test]
fn at_g01_a_lookalike_window_gets_the_picker_not_typing() {
    let (s, _) = open("at-g01", &[0]);
    // Another program names its window like a mail sign-in page: with
    // "Always ask" on (the default) the single match waits in the picker
    // for the user's Return.
    let lookalike = "Inbox – Proton Mail";
    let list = picker(s.autotype_start(lookalike.into(), UTC));
    assert_eq!(
        lines(&list),
        [("Proton Mail".to_owned(), "alex.morgan@proton.me".to_owned())]
    );
    // INT-05.25 step 7 with "Always ask" off: the picker still shows for
    // several rows, an empty title and a title nothing matches.
    set(
        &s,
        "autotype.always_ask",
        LarsalSettingValue::Flag { on: false },
    );
    assert_eq!(picker(s.autotype_start(SAFARI.into(), UTC)).rows.len(), 2);
    let every = picker(s.autotype_start(String::new(), UTC)).rows.len();
    assert!(every > 10, "INT-05.24: every candidate, {every}");
    assert_eq!(
        picker(s.autotype_start("Quiet".into(), UTC)).rows.len(),
        every
    );
    // A title over 64 KiB counts as empty (INT-05.22a).
    let huge = "Proton Mail ".repeat(6_000);
    assert_eq!(picker(s.autotype_start(huge, UTC)).rows.len(), every);
    // Only with it off and one match does Larsal type without asking (the
    // weakening APP-01 lists); nothing is remembered then (INT-05.31).
    let AutoTypeStart::Type { plan } = s.autotype_start(lookalike.into(), UTC) else {
        panic!("one match, always ask off")
    };
    let typed = s.autotype_type(plan, focus(u32::MAX));
    // {USERNAME}{TAB}{PASSWORD}{ENTER}: 21 + 1 + 48 + 1.
    assert_eq!(typed, AutoTypeEnd::Finished { keys: 71 });
}

#[test]
fn int_05_27_search_finds_candidates_in_every_vault() {
    let (s, [_, work]) = open("t64", &[0, 1]);
    picker(s.autotype_start(SAFARI.into(), UTC));
    let found = s.autotype_rows("wiki".into(), UTC);
    assert_eq!(
        lines(&found),
        [("Team wiki".to_owned(), "alex@morgan-labs.dev".to_owned())]
    );
    assert_eq!(found.rows[0].vault, work);
    // Back to the matches with an empty field.
    assert_eq!(s.autotype_rows(String::new(), UTC).rows.len(), 2);
    // FEA-01: the user's search text never makes the picker type.
    assert!(s.autotype_rows("x".repeat(70_000), UTC).rows.is_empty());
}

#[test]
fn int_05_29_actions_make_the_plan_in_rust_and_hand_back_a_handle() {
    let (s, _) = open("t65", &[0]);
    // T65: Return types the first row: GitHub's Safari rule,
    // {USERNAME}{TAB}{PASSWORD}{ENTER} = 8 + 1 + 20 + 1 keys.
    picker(s.autotype_start(SAFARI.into(), UTC));
    let login = plan(s.autotype_choose(0, AutoTypeAction::Login, UTC));
    assert_eq!(
        s.autotype_type(login, focus(u32::MAX)),
        AutoTypeEnd::Finished { keys: 30 }
    );
    // The picker closed and the plan is used once.
    assert_eq!(
        s.autotype_choose(0, AutoTypeAction::Login, UTC),
        AutoTypeChosen::Gone
    );
    assert_eq!(s.autotype_type(login, focus(u32::MAX)), AutoTypeEnd::Gone);
    // ⇧Return and ⌘2 type the password, ⌘1 the user name, ⌘3 the code,
    // ⌘4 the URL, ⌘5 the sequence with key codes.
    for (action, keys) in [
        (AutoTypeAction::Password, 20),
        (AutoTypeAction::Username, 8),
        (AutoTypeAction::Code, 6),
        (AutoTypeAction::Url, 24),
        (AutoTypeAction::KeyCodes, 30),
    ] {
        picker(s.autotype_start(SAFARI.into(), UTC));
        let p = plan(s.autotype_choose(0, action, UTC));
        assert_eq!(
            s.autotype_type(p, focus(u32::MAX)),
            AutoTypeEnd::Finished { keys },
            "{action:?}"
        );
    }
    // A row of an entry deleted while the picker was open types nothing.
    picker(s.autotype_start(SAFARI.into(), UTC));
    let github = s.autotype_rows(String::new(), UTC).rows[0].entry.clone();
    let personal = s.autotype_rows(String::new(), UTC).rows[0].vault;
    s.delete_entry(personal, github).unwrap();
    assert_eq!(
        s.autotype_choose(0, AutoTypeAction::Login, UTC),
        AutoTypeChosen::Gone
    );
}

#[test]
fn int_05_15_a_bad_sequence_fails_with_its_reason() {
    let (s, [personal, _]) = open("int05-15", &[0]);
    s.begin_new(personal, None).unwrap();
    s.set_text(personal, EditText::Title, "Bank login".into())
        .unwrap();
    s.add_window(personal, "*Bank*".into(), "{TAB 101}".into())
        .unwrap();
    s.commit_edit(personal).unwrap();
    picker(s.autotype_start("My Bank".into(), UTC));
    assert_eq!(
        s.autotype_choose(0, AutoTypeAction::Login, UTC),
        AutoTypeChosen::Failed {
            reason: "{TAB 101} repeats more than 100 times.".into(),
            code: "MI05-12".into()
        }
    );
}

#[test]
fn int_05_28_int_05_31_the_previous_choice_is_highlighted() {
    let (s, [personal, _]) = open("t70", &[0]);
    add_bot(&s, personal);
    // T70: the bot chosen; the next picker highlights it.
    picker(s.autotype_start(SAFARI.into(), UTC));
    plan(s.autotype_choose(2, AutoTypeAction::Login, UTC));
    assert_eq!(picker(s.autotype_start(SAFARI.into(), UTC)).highlight, 2);
    // A search keeps it highlighted where it is in the new list.
    assert_eq!(s.autotype_rows("bot".into(), UTC).highlight, 0);
    assert_eq!(s.autotype_rows(String::new(), UTC).highlight, 2);
    // ⌘1 on the bot remembers `{USERNAME}`: its entry's first row.
    plan(s.autotype_choose(2, AutoTypeAction::Username, UTC));
    assert_eq!(picker(s.autotype_start(SAFARI.into(), UTC)).highlight, 2);
    // T73: a lock drops it. GitHub's second row is saved in the file, so it
    // is back after the unlock and only the forgotten choice leaves it dark.
    plan(s.autotype_choose(1, AutoTypeAction::Login, UTC));
    assert_eq!(picker(s.autotype_start(SAFARI.into(), UTC)).highlight, 1);
    s.autotype_close();
    s.lock(personal).unwrap();
    s.unlock(personal, Some("demo-pass-7".into()), None)
        .unwrap();
    assert_eq!(picker(s.autotype_start(SAFARI.into(), UTC)).highlight, 0);
    // T71: S-AT-08 = 0 remembers nothing.
    set(
        &s,
        "autotype.retype_seconds",
        LarsalSettingValue::Number { value: 0 },
    );
    picker(s.autotype_start(SAFARI.into(), UTC));
    let n = s.autotype_rows(String::new(), UTC).rows.len();
    plan(s.autotype_choose(u32::try_from(n - 1).unwrap(), AutoTypeAction::Login, UTC));
    assert_eq!(picker(s.autotype_start(SAFARI.into(), UTC)).highlight, 0);
}

#[test]
fn at_g02_a_focus_change_stops_typing() {
    let (s, _) = open("at-g02", &[0]);
    // T90 and T91 at the model level: the fake front window changes after
    // the third key (one check first that it is in front, INT-05.38 step
    // 1); the run stops there.
    picker(s.autotype_start(SAFARI.into(), UTC));
    let p = plan(s.autotype_choose(0, AutoTypeAction::Login, UTC));
    assert_eq!(
        s.autotype_type(p, focus(1 + 3)),
        AutoTypeEnd::Stopped {
            keys: 3,
            reason: "window-changed".into()
        }
    );
    // Not in front at INT-05.38 step 1: nothing goes out.
    picker(s.autotype_start(SAFARI.into(), UTC));
    let p = plan(s.autotype_choose(0, AutoTypeAction::Login, UTC));
    assert_eq!(
        s.autotype_type(p, focus(0)),
        AutoTypeEnd::Stopped {
            keys: 0,
            reason: "not-in-front".into()
        }
    );
}

#[test]
fn int_05_30_the_global_shortcut_from_s_at_07() {
    let s = Session::new();
    // D-INT05-10: ⌃⌥V by default; V is kVK_ANSI_V (0x09).
    let key = s.autotype_hot_key().unwrap();
    assert_eq!(
        (key.code, key.control, key.option, key.shift, key.command),
        (0x09, true, true, false, false)
    );
    let text = |t: &str| LarsalSettingValue::Text { text: t.into() };
    set(&s, "autotype.global_shortcut", text("⌘⇧K"));
    let key = s.autotype_hot_key().unwrap();
    assert_eq!(
        (key.code, key.command, key.shift, key.control),
        (0x28, true, true, false)
    );
    // MI05-34's rule: ⌘ or ⌃ is needed; cleared or unknown is none.
    for refused in ["⌥V", "⇧⌥V", "", "⌃⌥", "⌃⌥VV", "⌃⌥F5", "⌃⌥é"] {
        set(&s, "autotype.global_shortcut", text(refused));
        assert_eq!(s.autotype_hot_key(), None, "{refused}");
    }
}

#[test]
fn sr_16_a_lock_closes_the_picker_and_drops_the_plan() {
    let (s, [personal, _]) = open("sr16", &[0]);
    picker(s.autotype_start(SAFARI.into(), UTC));
    let p = plan(s.autotype_choose(0, AutoTypeAction::Login, UTC));
    picker(s.autotype_start(SAFARI.into(), UTC));
    s.lock(personal).unwrap();
    assert!(s.autotype_rows(String::new(), UTC).rows.is_empty());
    assert_eq!(
        s.autotype_choose(0, AutoTypeAction::Login, UTC),
        AutoTypeChosen::Gone
    );
    assert_eq!(s.autotype_type(p, focus(u32::MAX)), AutoTypeEnd::Gone);
}

#[test]
fn ld_207_a_title_or_user_name_from_a_protected_field_shows_the_mask() {
    let (s, [personal, _]) = open("ld207", &[0]);
    s.begin_new(personal, None).unwrap();
    let name = s.add_field(personal).unwrap();
    s.rename_field(personal, name, "PIN".into()).unwrap();
    s.set_field(personal, "PIN".into(), "4711".into()).unwrap();
    s.protect_field(personal, "PIN".into(), true).unwrap();
    s.set_text(personal, EditText::Title, "{S:PIN} bank".into())
        .unwrap();
    s.set_text(personal, EditText::UserName, "{S:PIN}".into())
        .unwrap();
    s.add_window(personal, "*Bank*".into(), String::new())
        .unwrap();
    s.commit_edit(personal).unwrap();
    let list = picker(s.autotype_start("My Bank".into(), UTC));
    assert_eq!(list.rows.len(), 1);
    assert_eq!(list.rows[0].title, larsal_core::health::MASKED_TITLE);
    assert_eq!(list.rows[0].username, larsal_core::health::MASKED_TITLE);
    assert!(!format!("{list:?}").contains("4711"));
}

#[test]
fn int_05_31_t72_a_single_match_typed_directly_is_not_remembered() {
    let (s, _) = open("t72", &[0]);
    let lookalike = "Inbox – Proton Mail";
    let every = picker(s.autotype_start(String::new(), UTC));
    let proton = every
        .rows
        .iter()
        .position(|r| r.title == "Proton Mail")
        .unwrap();
    assert!(proton > 0, "Proton Mail is not the first row");
    // S-AT-03 off: the one match types without the picker.
    set(
        &s,
        "autotype.always_ask",
        LarsalSettingValue::Flag { on: false },
    );
    let AutoTypeStart::Type { plan: direct } = s.autotype_start(lookalike.into(), UTC) else {
        panic!("one match, always ask off")
    };
    assert!(matches!(
        s.autotype_type(direct, focus(u32::MAX)),
        AutoTypeEnd::Finished { .. }
    ));
    // The next picker of every candidate highlights the first row.
    assert_eq!(picker(s.autotype_start(String::new(), UTC)).highlight, 0);
    // The same entry chosen in the picker is remembered there.
    set(
        &s,
        "autotype.always_ask",
        LarsalSettingValue::Flag { on: true },
    );
    picker(s.autotype_start(lookalike.into(), UTC));
    plan(s.autotype_choose(0, AutoTypeAction::Login, UTC));
    let again = picker(s.autotype_start(String::new(), UTC));
    assert_eq!(usize::try_from(again.highlight).unwrap(), proton);
}

#[test]
fn s_at_05_hide_expired_entries_from_the_settings_store() {
    let (s, [personal, _]) = open("s-at-05", &[0]);
    let lookalike = "Inbox – Proton Mail";
    let proton = picker(s.autotype_start(lookalike.into(), UTC)).rows[0]
        .entry
        .clone();
    s.autotype_close();
    s.begin_edit(personal, proton).unwrap();
    s.set_expiry(personal, true, Some(1)).unwrap();
    s.commit_edit(personal).unwrap();
    // T56: an expired entry is listed, marked expired (struck through).
    let list = picker(s.autotype_start(lookalike.into(), UTC));
    assert_eq!(lines(&list)[0].0, "Proton Mail");
    assert!(list.rows.len() == 1 && list.rows[0].expired);
    // S-AT-05 on: it is no candidate, so nothing matches and no row of it
    // is among every candidate.
    set(
        &s,
        "autotype.hide_expired",
        LarsalSettingValue::Flag { on: true },
    );
    let list = picker(s.autotype_start(lookalike.into(), UTC));
    assert!(list.rows.len() > 1);
    assert!(list.rows.iter().all(|r| r.title != "Proton Mail"));
}

#[test]
fn s_at_01_title_matching_from_the_settings_store() {
    let (s, _) = open("s-at-01", &[0]);
    let lookalike = "Inbox – Proton Mail";
    let every = picker(s.autotype_start(String::new(), UTC)).rows.len();
    assert_eq!(
        picker(s.autotype_start(lookalike.into(), UTC)).rows.len(),
        1
    );
    // S-AT-01 off: the entry's title no longer matches the window, so the
    // picker lists every candidate (INT-05.27).
    set(
        &s,
        "autotype.match_title",
        LarsalSettingValue::Flag { on: false },
    );
    assert_eq!(
        picker(s.autotype_start(lookalike.into(), UTC)).rows.len(),
        every
    );
}

#[test]
fn s_at_02_url_matching_from_the_settings_store() {
    let (s, [personal, _]) = open("s-at-02", &[0]);
    s.begin_new(personal, None).unwrap();
    s.set_text(personal, EditText::Title, "Intranet".into())
        .unwrap();
    s.set_text(
        personal,
        EditText::Url,
        "https://zeta-portal.example/login".into(),
    )
    .unwrap();
    s.commit_edit(personal).unwrap();
    let every = picker(s.autotype_start(String::new(), UTC)).rows.len();
    let title = "Login at zeta-portal.example — Safari";
    // T52: the URL's host in the window title lists that entry alone.
    assert_eq!(
        lines(&picker(s.autotype_start(title.into(), UTC))),
        [("Intranet".to_owned(), String::new())]
    );
    // S-AT-02 off: no URL match, so the picker lists every candidate
    // (INT-05.27).
    set(
        &s,
        "autotype.match_url",
        LarsalSettingValue::Flag { on: false },
    );
    assert_eq!(
        picker(s.autotype_start(title.into(), UTC)).rows.len(),
        every
    );
}
