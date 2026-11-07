//! E21-S2 (FEA-10): Show as QR Code over the Rust session, on a copy of the
//! Option A Personal demo vault (password in testdata/README.md). Each test
//! name carries its case of the card. The text never leaves Rust, so these
//! tests compare matrices: two equal matrices hold the same bytes, and
//! `macos/LarsalTests` reads the drawn code back with Core Image.

use larsal_ffi::edit::{EditText, Qr};
use larsal_ffi::qr::{QrExport, QrShown};
use larsal_ffi::saving::{DiskChoice, DiskEvent};
use larsal_ffi::session::{LarsalError, Session, UnlockResult};
use larsal_ffi::views::ListView;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

const TOO_LARGE: &str =
    "This value is too large for one QR code. Nothing was shown, saved or shared.";
const EMPTY: &str = "This field is empty.";
const INVALID: &str = "This Wi-Fi entry is incomplete or has invalid settings.";
const UNSUPPORTED: &str = "This network type cannot be shared as a Wi-Fi join code. Show an individual field as text instead.";
const SAVE_FAILED: &str = "The QR image could not be saved.";
const SHARE_FAILED: &str = "The QR image could not be shared.";

/// This run's own folder; each test names its own files in it, so tests side by side,
/// in one run or two, never share a vault file.
fn folder() -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("qr-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn personal(name: &str) -> (Arc<Session>, u64) {
    let path = folder().join(format!("{name}.larsalvault"));
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/option-a-personal.larsalvault"),
        &path,
    )
    .unwrap();
    let session = Session::new();
    let id = session.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        session
            .unlock(id, Some("demo-pass-7".into()), None)
            .unwrap(),
        UnlockResult::Unlocked
    );
    (session, id)
}

fn entry_id(session: &Session, vault: u64, title: &str) -> String {
    session
        .list(vault, ListView::All)
        .unwrap()
        .rows
        .into_iter()
        .find(|r| r.title == title)
        .unwrap_or_else(|| panic!("{title}"))
        .id
}

/// An entry saved with these fields; `Password` by its own call.
fn saved(s: &Session, v: u64, fields: &[(&str, &str)]) -> String {
    s.begin_new(v, None).unwrap();
    for (name, value) in fields {
        match *name {
            "Password" => {
                s.set_password(v, (*value).to_owned()).unwrap();
            }
            "Title" => s.set_text(v, EditText::Title, (*value).to_owned()).unwrap(),
            "UserName" => s
                .set_text(v, EditText::UserName, (*value).to_owned())
                .unwrap(),
            _ => {
                let made = s.add_field(v).unwrap();
                s.rename_field(v, made, (*name).to_owned()).unwrap();
                s.set_field(v, (*name).to_owned(), (*value).to_owned())
                    .unwrap();
            }
        }
    }
    s.commit_edit(v).unwrap()
}

/// The matrix of literal bytes, through a throwaway draft.
fn literal(s: &Session, v: u64, text: &str) -> Qr {
    s.begin_new(v, None).unwrap();
    s.set_password(v, text.to_owned()).unwrap();
    let shown = s.qr_show_draft(v, "Password".into()).unwrap();
    s.qr_release(v, shown.ticket);
    s.cancel_edit(v).unwrap();
    shown.symbol
}

fn refusal<T>(r: Result<T, LarsalError>) -> String {
    match r {
        Ok(_) => "no refusal".to_owned(),
        Err(LarsalError::Refused(why)) => why,
        Err(other) => format!("{other:?}"),
    }
}

fn demo(name: &str) -> (Arc<Session>, u64, String) {
    let (s, v) = personal(name);
    let id = saved(&s, v, &[("Title", "QR demo"), ("Password", "demo-pass")]);
    (s, v, id)
}

fn field(s: &Session, v: u64, id: &str, name: &str) -> Result<QrShown, LarsalError> {
    s.qr_show_field(v, id.to_owned(), name.to_owned())
}

#[test]
fn qr_t01_each_field_is_exactly_the_selected_one_and_nothing_changes() {
    let (s, v) = personal("t01");
    let id = saved(
        &s,
        v,
        &[
            ("Title", "Demo login"),
            ("UserName", "demo-user"),
            ("Password", "demo-pass-1"),
            ("PIN", "4321"),
            ("Private key note", "demo private note"),
        ],
    );
    s.protect_field(v, "x".into(), true).unwrap_err();
    let before = s.save_status(v).unwrap().changes;
    for (name, text) in [
        ("Password", "demo-pass-1"),
        ("UserName", "demo-user"),
        ("PIN", "4321"),
        ("Private key note", "demo private note"),
    ] {
        let shown = field(&s, v, &id, name).unwrap();
        assert_eq!(s.show_field(v, id.clone(), name.into()).unwrap(), text);
        assert_eq!(shown.symbol, literal(&s, v, text), "{name}");
    }
    assert_eq!(s.save_status(v).unwrap().changes, before, "no vault change");
    // The editor's draft, unsaved, wins for the draft door.
    s.begin_edit(v, id).unwrap();
    s.set_password(v, "unsaved-demo".into()).unwrap();
    s.set_field(v, "PIN".into(), "9999".into()).unwrap();
    let draft = s.qr_show_draft(v, "Password".into()).unwrap().symbol;
    let pin = s.qr_show_draft(v, "PIN".into()).unwrap().symbol;
    s.cancel_edit(v).unwrap();
    assert_eq!(draft, literal(&s, v, "unsaved-demo"));
    assert_eq!(pin, literal(&s, v, "9999"));
}

#[test]
fn qr_t02_refusals_leave_no_old_matrix_and_no_unrelated_value() {
    let (s, v) = personal("t02");
    let id = saved(&s, v, &[("Title", "Demo"), ("Password", "demo-pass")]);
    let live = field(&s, v, &id, "Password").unwrap();
    assert!(s.qr_is_current(v, live.ticket));
    // Missing and empty fields, and a hostile direct call.
    assert!(matches!(
        field(&s, v, &id, "No such field"),
        Err(LarsalError::UnknownField)
    ));
    assert!(!s.qr_is_current(v, live.ticket), "the failure destroys it");
    assert_eq!(refusal(field(&s, v, &id, "Notes")), EMPTY);
    assert!(matches!(
        field(&s, v, "not-an-id", "Password"),
        Err(LarsalError::UnknownEntry)
    ));
    assert!(matches!(
        s.qr_show_field(v + 1000, id.clone(), "Password".into()),
        Err(LarsalError::UnknownVault)
    ));
    assert!(matches!(
        s.qr_show_field(v, id.clone(), "x".repeat(70_000)),
        Err(LarsalError::TooLong)
    ));
    // No editor open.
    assert!(matches!(
        s.qr_show_draft(v, "Password".into()),
        Err(LarsalError::Refused(_))
    ));
    // Locked.
    s.lock(v).unwrap();
    assert!(matches!(
        field(&s, v, &id, "Password"),
        Err(LarsalError::Locked)
    ));
}

#[test]
fn qr_t02_non_exportable_controls_stay_out() {
    let (s, v) = personal("t02b");
    let github = entry_id(&s, v, "GitHub");
    for name in [
        "TimeOtp-Secret-Base32",
        "otp",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
    ] {
        assert!(
            matches!(field(&s, v, &github, name), Err(LarsalError::UnknownField)),
            "{name}"
        );
    }
    s.begin_edit(v, github).unwrap();
    for name in [
        "TimeOtp-Secret-Base32",
        "otp",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
    ] {
        assert!(matches!(
            s.qr_show_draft(v, name.into()),
            Err(LarsalError::UnknownField)
        ));
    }
    s.cancel_edit(v).unwrap();
}

#[test]
fn qr_t03_saved_resolves_draft_stays_literal_and_bytes_are_untouched() {
    let (s, v) = personal("t03");
    let id = saved(
        &s,
        v,
        &[
            ("Title", "T03"),
            ("UserName", "demo-user"),
            ("Password", "{USERNAME}"),
        ],
    );
    assert_eq!(
        field(&s, v, &id, "Password").unwrap().symbol,
        literal(&s, v, "demo-user")
    );
    s.begin_edit(v, id).unwrap();
    let draft = s.qr_show_draft(v, "Password".into()).unwrap().symbol;
    s.cancel_edit(v).unwrap();
    assert_eq!(draft, literal(&s, v, "{USERNAME}"));
    assert_ne!(draft, literal(&s, v, "demo-user"));
    // Whitespace is a value, not an empty field, and no byte is normalized.
    for text in [
        " ",
        "\t",
        "\r\n",
        "\n",
        "\0",
        "a\0b",
        "https://demo.example/<b>",
    ] {
        let shown = literal(&s, v, text);
        assert!(shown.size >= 29, "{text:?}");
    }
    assert_ne!(literal(&s, v, "a\n"), literal(&s, v, "a"));
    assert_ne!(literal(&s, v, "a\r\n"), literal(&s, v, "a\n"));
    assert_ne!(literal(&s, v, "caf\u{e9}"), literal(&s, v, "cafe\u{301}"));
    // A saved value is its Show result, byte for byte, in a custom field and
    // in the password: nothing trimmed, and the end of a value is data.
    for text in [
        " ",
        "\t",
        "\r\n",
        "\n",
        "\0",
        "a\0b",
        "a\n",
        "a ",
        " a",
        "a\r\n",
        "https://demo.example/<b>",
    ] {
        let id = saved(
            &s,
            v,
            &[("Title", "T03"), ("Password", text), ("Demo note", text)],
        );
        for name in ["Password", "Demo note"] {
            assert_eq!(s.show_field(v, id.clone(), name.into()).unwrap(), text);
            assert_eq!(
                field(&s, v, &id, name).unwrap().symbol,
                literal(&s, v, text),
                "{name} {text:?}"
            );
        }
    }
}

#[test]
fn qr_t05_exact_capacity_after_resolution_literal_and_wifi() {
    let (s, v) = personal("t05");
    // Literal draft bytes.
    assert_eq!(literal(&s, v, &"a".repeat(1_272)).size, 185);
    s.begin_new(v, None).unwrap();
    s.set_password(v, "a".repeat(1_273)).unwrap();
    assert_eq!(refusal(s.qr_show_draft(v, "Password".into())), TOO_LARGE);
    s.cancel_edit(v).unwrap();
    // A saved placeholder whose resolution reaches the sizes: the raw field
    // is 10 bytes either way.
    for (size, fits) in [(1_272, true), (1_273, false)] {
        let name = "u".repeat(size);
        let id = saved(
            &s,
            v,
            &[
                ("Title", "T05"),
                ("UserName", &name),
                ("Password", "{USERNAME}"),
            ],
        );
        let got = field(&s, v, &id, "Password");
        if fits {
            assert_eq!(got.unwrap().symbol, literal(&s, v, &name));
        } else {
            assert_eq!(refusal(got), TOO_LARGE);
        }
    }
    // Wi-Fi on the final wire: 32 bytes around a five-escape password.
    let wifi = |password: String, ssid: &str| {
        saved(
            &s,
            v,
            &[
                ("Title", "T05 Wi-Fi"),
                ("UserName", ssid),
                ("Password", &password),
                ("Security", "WPA"),
            ],
        )
    };
    let fits = format!(r#"\;,":é{}"#, "a".repeat(1_228));
    let shown = s
        .qr_show_wifi(v, wifi(fits.clone(), "ABCD"))
        .unwrap()
        .symbol;
    let wire = format!(
        r#"WIFI:T:WPA;S:"ABCD";P:\\\;\,\"\:é{};H:false;;"#,
        "a".repeat(1_228)
    );
    assert_eq!(wire.len(), 1_272);
    assert_eq!(shown, literal(&s, v, &wire));
    let over = format!("{fits}a");
    assert_eq!(refusal(s.qr_show_wifi(v, wifi(over, "ABCD"))), TOO_LARGE);
    // A wrapper is counted: even hex takes two more bytes, odd hex none.
    let hex = |n: usize| "a1".repeat(n / 2) + if n % 2 == 1 { "a" } else { "" };
    assert_eq!(
        s.qr_show_wifi(v, wifi(hex(1_238), "ABCD"))
            .unwrap()
            .symbol
            .size,
        185
    );
    assert_eq!(
        refusal(s.qr_show_wifi(v, wifi(hex(1_240), "ABCD"))),
        TOO_LARGE
    );
    assert_eq!(
        s.qr_show_wifi(v, wifi(hex(1_239), "ABCD"))
            .unwrap()
            .symbol
            .size,
        185
    );
    assert_eq!(
        refusal(s.qr_show_wifi(v, wifi(hex(1_241), "ABCD"))),
        TOO_LARGE
    );
}

#[test]
fn qr_t05_smallest_version_by_capacity_at_level_h() {
    let (s, v) = personal("t05b");
    // Version 1 at level H holds 9 codewords: ECI 1, mode and count 1.5, so
    // 6 bytes fit and the terminator is cut short.
    assert_eq!(literal(&s, v, "abcdef").size, 21 + 8);
    assert_eq!(literal(&s, v, "abcdefg").size, 25 + 8);
    assert_eq!(literal(&s, v, &"a".repeat(1_272)).size, 177 + 8);
}

#[test]
fn qr_t06_resolution_cases_and_real_errors() {
    let (s, v) = personal("t06");
    let make = |text: &str| saved(&s, v, &[("Title", "T06"), ("Password", text)]);
    // Unknown stays literal; a bounded fallback is the Show result.
    for text in ["{FOO}", "{PASSWORD}", "{REF:P@T:Nonexistent}x"] {
        let id = make(text);
        let show = s.show_field(v, id.clone(), "Password".into()).unwrap();
        assert_eq!(
            field(&s, v, &id, "Password").unwrap().symbol,
            literal(&s, v, &show),
            "{text}"
        );
    }
    assert_eq!(literal(&s, v, "{FOO}"), {
        let id = make("{FOO}");
        field(&s, v, &id, "Password").unwrap().symbol
    });
    // A reference to a missing entry or an excluded field resolves empty.
    for text in ["{REF:P@T:Nonexistent}", "{S:TimeOtp-Secret-Base32}"] {
        let id = make(text);
        assert_eq!(s.show_field(v, id.clone(), "Password".into()).unwrap(), "");
        assert_eq!(refusal(field(&s, v, &id, "Password")), EMPTY, "{text}");
    }
}

/// MOD-08.20: a user name holding itself 16 times passes the work bound, so
/// Show gives the raw text: encoded exactly when it fits, refused when not.
#[test]
fn qr_t06_the_work_bound_fallback_is_encoded_exactly_and_oversize_refuses() {
    let (s, v) = personal("t06-bound");
    let make = |raw: &str| {
        saved(
            &s,
            v,
            &[("Title", "T06"), ("UserName", raw), ("Password", raw)],
        )
    };
    let raw = "{USERNAME}".repeat(16);
    let id = make(&raw);
    assert_eq!(
        s.show_field(v, id.clone(), "Password".into()).unwrap(),
        raw,
        "the bound was reached"
    );
    assert_eq!(
        field(&s, v, &id, "Password").unwrap().symbol,
        literal(&s, v, &raw)
    );
    let raw = "{USERNAME}".repeat(128);
    let id = make(&raw);
    assert_eq!(
        s.show_field(v, id.clone(), "Password".into()).unwrap(),
        raw,
        "the bound was reached"
    );
    assert_eq!(refusal(field(&s, v, &id, "Password")), TOO_LARGE);
}

#[test]
fn qr_t07_join_is_read_from_the_entry_and_password_show_stays_apart() {
    let (s, v) = personal("t07");
    let id = saved(
        &s,
        v,
        &[
            ("Title", "Demo Wi-Fi"),
            ("UserName", "Demo Net"),
            ("Password", "demo-pass"),
            ("Security", "WPA2 Personal"),
        ],
    );
    assert_eq!(
        s.qr_show_wifi(v, id.clone()).unwrap().symbol,
        literal(&s, v, "WIFI:T:WPA;S:Demo Net;P:demo-pass;H:false;;")
    );
    assert_eq!(
        field(&s, v, &id, "Password").unwrap().symbol,
        literal(&s, v, "demo-pass")
    );
    s.begin_edit(v, id.clone()).unwrap();
    s.add_field(v).unwrap();
    s.rename_field(v, "New field".into(), "Hidden".into())
        .unwrap();
    s.set_field(v, "Hidden".into(), "true".into()).unwrap();
    s.commit_edit(v).unwrap();
    assert_eq!(
        s.qr_show_wifi(v, id).unwrap().symbol,
        literal(&s, v, "WIFI:T:WPA;S:Demo Net;P:demo-pass;H:true;;")
    );
}

#[test]
fn qr_t12_demo_wpa3_is_unsupported_and_its_fields_stay_offered() {
    let (s, v) = personal("t12");
    let home = entry_id(&s, v, "Home Wi-Fi");
    assert_eq!(refusal(s.qr_show_wifi(v, home.clone())), UNSUPPORTED);
    assert!(field(&s, v, &home, "Password").is_ok());
    let none = saved(
        &s,
        v,
        &[
            ("Title", "No security"),
            ("UserName", "n"),
            ("Password", "p"),
        ],
    );
    assert_eq!(refusal(s.qr_show_wifi(v, none)), INVALID);
}

#[test]
fn qr_t18_every_source_change_and_lock_makes_the_ticket_stale() {
    let (s, v, id) = demo("t18-stale");
    let live = field(&s, v, &id, "Password").unwrap();
    assert!(s.qr_is_current(v, live.ticket));
    // Same-entry edit, even of another field.
    s.begin_edit(v, id.clone()).unwrap();
    assert!(
        s.qr_is_current(v, live.ticket),
        "opening an editor changes nothing"
    );
    s.set_text(v, EditText::UserName, "x".into()).unwrap();
    assert!(
        s.qr_is_current(v, live.ticket),
        "a draft is not the saved source"
    );
    s.commit_edit(v).unwrap();
    assert!(!s.qr_is_current(v, live.ticket));
    // A draft ticket follows the draft.
    s.begin_edit(v, id.clone()).unwrap();
    let draft = s.qr_show_draft(v, "Password".into()).unwrap();
    s.set_text(v, EditText::Title, "Other".into()).unwrap();
    assert!(!s.qr_is_current(v, draft.ticket));
    let draft = s.qr_show_draft(v, "Password".into()).unwrap();
    s.cancel_edit(v).unwrap();
    assert!(!s.qr_is_current(v, draft.ticket), "the draft is gone");
    // A new request ends the old one: one per vault.
    let one = field(&s, v, &id, "Password").unwrap();
    let two = field(&s, v, &id, "Password").unwrap();
    assert!(!s.qr_is_current(v, one.ticket));
    assert!(s.qr_is_current(v, two.ticket));
    assert_ne!(one.ticket, two.ticket);
    // Lock.
    let consent = s.qr_consent(v, two.ticket, QrExport::Share).unwrap();
    s.lock(v).unwrap();
    assert!(!s.qr_is_current(v, two.ticket));
    assert_eq!(
        refusal(s.qr_share_png(v, two.ticket, consent)),
        SHARE_FAILED
    );
}

/// R2C2-3, FEA-10.14: a move is a source change, the Recycle Bin too, though no
/// value changes; a restore brings nothing back. A draft is its own source.
#[test]
fn qr_t18_a_move_to_the_bin_ends_the_ticket_and_a_restore_brings_nothing_back() {
    let (s, v, id) = demo("t18-bin");
    for join in [false, true] {
        let wifi = saved(
            &s,
            v,
            &[
                ("Title", "Bin demo"),
                ("UserName", "demo-net"),
                ("Password", "demo-pass-b"),
                ("Security", "WPA"),
            ],
        );
        let live = if join {
            s.qr_show_wifi(v, wifi.clone()).unwrap()
        } else {
            field(&s, v, &wifi, "Password").unwrap()
        };
        let consent = s.qr_consent(v, live.ticket, QrExport::Share).unwrap();
        assert_eq!(s.delete_entry(v, wifi.clone()).unwrap().to_bin, 1);
        assert!(!s.qr_is_current(v, live.ticket), "the move ends it");
        assert_eq!(
            refusal(s.qr_share_png(v, live.ticket, consent)),
            SHARE_FAILED
        );
        s.restore_entry(v, wifi).unwrap();
        assert!(
            !s.qr_is_current(v, live.ticket),
            "not back with the restore"
        );
    }
    // Another entry's move leaves it.
    let live = field(&s, v, &id, "Password").unwrap();
    let other = saved(&s, v, &[("Title", "Other"), ("Password", "x")]);
    assert!(
        s.qr_is_current(v, live.ticket),
        "a new entry is not this one"
    );
    s.delete_entry(v, other).unwrap();
    assert!(s.qr_is_current(v, live.ticket), "another entry's move");
    // A draft's ticket stays when its saved entry moves to the bin.
    s.begin_edit(v, id.clone()).unwrap();
    let draft = s.qr_show_draft(v, "Password".into()).unwrap();
    assert_eq!(s.delete_entry(v, id).unwrap().to_bin, 1);
    assert!(
        s.qr_is_current(v, draft.ticket),
        "a draft is its own source"
    );
}

/// C2-1: an undone edit brings back neither the ticket nor its consent, with
/// or without a check between, on the draft and on the saved entry.
#[test]
fn qr_t18_an_undone_edit_brings_back_no_ticket_and_no_consent() {
    let (s, v) = personal("t18-undo");
    let id = saved(&s, v, &[("Title", "Undo"), ("Password", "demo-one")]);
    let is_gone = |ticket: u64, consent: u64| {
        assert!(!s.qr_is_current(v, ticket));
        assert_eq!(refusal(s.qr_share_png(v, ticket, consent)), SHARE_FAILED);
        assert!(s.qr_consent(v, ticket, QrExport::Share).is_err());
    };
    // A draft edit undone, no check between.
    s.begin_edit(v, id.clone()).unwrap();
    let shown = s.qr_show_draft(v, "Password".into()).unwrap();
    let consent = s.qr_consent(v, shown.ticket, QrExport::Share).unwrap();
    s.set_password(v, "demo-two".into()).unwrap();
    s.set_password(v, "demo-one".into()).unwrap();
    is_gone(shown.ticket, consent);
    // A check between.
    let shown = s.qr_show_draft(v, "Password".into()).unwrap();
    let consent = s.qr_consent(v, shown.ticket, QrExport::Share).unwrap();
    s.set_password(v, "demo-two".into()).unwrap();
    assert!(!s.qr_is_current(v, shown.ticket));
    s.set_password(v, "demo-one".into()).unwrap();
    is_gone(shown.ticket, consent);
    // The editor closed and opened again on the same entry, no check between.
    let shown = s.qr_show_draft(v, "Password".into()).unwrap();
    let consent = s.qr_consent(v, shown.ticket, QrExport::Share).unwrap();
    s.cancel_edit(v).unwrap();
    s.begin_edit(v, id.clone()).unwrap();
    is_gone(shown.ticket, consent);
    s.cancel_edit(v).unwrap();
    // A saved edit undone, no check between.
    let shown = field(&s, v, &id, "Password").unwrap();
    let consent = s.qr_consent(v, shown.ticket, QrExport::Share).unwrap();
    for value in ["demo-two", "demo-one"] {
        s.begin_edit(v, id.clone()).unwrap();
        s.set_password(v, value.into()).unwrap();
        s.commit_edit(v).unwrap();
    }
    is_gone(shown.ticket, consent);
}

/// FEA-10.14: a look through the change doors moves no source, so it ends no
/// ticket; a value not in use by the ticket may change around it.
#[test]
fn qr_t18_looks_and_other_entries_leave_the_ticket() {
    let (s, v, id) = demo("t18-looks");
    let other = saved(&s, v, &[("Title", "Other"), ("Password", "other-demo")]);
    let live = field(&s, v, &id, "Password").unwrap();
    s.save_status(v).unwrap();
    s.save(v).unwrap();
    s.begin_edit(v, other).unwrap();
    s.set_password(v, "other-two".into()).unwrap();
    s.commit_edit(v).unwrap();
    assert!(s.qr_is_current(v, live.ticket));
}

#[test]
fn qr_t18_a_reference_targets_edit_ends_it_and_an_old_release_leaves_the_newer() {
    let (s, v) = personal("t18-ref");
    let target = saved(&s, v, &[("Title", "Target"), ("Password", "target-demo")]);
    let id = saved(
        &s,
        v,
        &[("Title", "User"), ("Password", "{REF:P@T:Target}")],
    );
    let expected = literal(&s, v, "target-demo");
    let old = field(&s, v, &id, "Password").unwrap();
    let new = field(&s, v, &id, "Password").unwrap();
    assert_eq!(new.symbol, expected);
    s.qr_release(v, old.ticket);
    assert!(s.qr_is_current(v, new.ticket), "the old one's release");
    s.begin_edit(v, target).unwrap();
    s.set_password(v, "target-two".into()).unwrap();
    s.commit_edit(v).unwrap();
    assert!(!s.qr_is_current(v, new.ticket));
}

/// C1-11, FEA-10.14: a clock is no source change. The code stays for its 44
/// seconds, and an export is the code on screen, not a new reading of the clock.
#[test]
fn qr_t18_a_clock_placeholder_keeps_its_code_and_the_export_is_that_code() {
    let (s, v) = personal("t18-clock");
    let target = saved(&s, v, &[("Title", "Clock target"), ("Password", "demo")]);
    let id = saved(
        &s,
        v,
        &[
            ("Title", "Clock"),
            ("Password", "{DT_SIMPLE}{REF:P@T:Clock target}"),
        ],
    );
    let shown = field(&s, v, &id, "Password").unwrap();
    let share = s.qr_consent(v, shown.ticket, QrExport::Share).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert!(s.qr_is_current(v, shown.ticket), "its clock moved on");
    assert_eq!(
        s.qr_share_png(v, shown.ticket, share).unwrap(),
        picture(&shown.symbol)
    );
    // A new request reads the clock anew.
    let fresh = field(&s, v, &id, "Password").unwrap();
    assert_ne!(fresh.symbol, shown.symbol);
    // What it refers to is still its source.
    s.begin_edit(v, target).unwrap();
    s.set_password(v, "demo-two".into()).unwrap();
    s.commit_edit(v).unwrap();
    assert!(!s.qr_is_current(v, fresh.ticket));
}

/// QR-T18's reload and merge: another session changes the entry on disk.
#[test]
fn qr_t18_a_reload_and_a_merge_of_the_same_entry_end_the_ticket() {
    let (s, v) = personal("t18-disk");
    let path = folder().join("t18-disk.larsalvault");
    let id = saved(&s, v, &[("Title", "Disk"), ("Password", "demo-one")]);
    let other = saved(&s, v, &[("Title", "Kept"), ("Password", "kept-demo")]);
    s.save(v).unwrap();
    let second = Session::new();
    let w = second.open(path.to_string_lossy().into_owned()).unwrap();
    second.unlock(w, Some("demo-pass-7".into()), None).unwrap();
    let on_disk = |value: &str, id: &str| {
        second.begin_edit(w, id.to_owned()).unwrap();
        second.set_password(w, value.to_owned()).unwrap();
        second.commit_edit(w).unwrap();
        second.save(w).unwrap();
    };
    // Reload: the same entry ends it; another entry does not.
    let same = field(&s, v, &id, "Password").unwrap();
    on_disk("disk-two", &id);
    assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Reloaded);
    assert!(!s.qr_is_current(v, same.ticket), "reload, same entry");
    let kept = field(&s, v, &other, "Password").unwrap();
    on_disk("disk-three", &id);
    assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Reloaded);
    assert!(s.qr_is_current(v, kept.ticket), "reload, another entry");
    // Merge: unsaved work here makes it ask.
    s.begin_edit(v, other.clone()).unwrap();
    s.set_password(v, "kept-two".into()).unwrap();
    s.commit_edit(v).unwrap();
    let same = field(&s, v, &id, "Password").unwrap();
    on_disk("disk-four", &id);
    assert!(matches!(
        s.check_disk(v).unwrap(),
        DiskEvent::Ask { .. } | DiskEvent::AskOlder { .. }
    ));
    assert!(
        s.qr_is_current(v, same.ticket),
        "the question moves nothing"
    );
    s.resolve_disk(v, DiskChoice::Merge).unwrap();
    assert!(!s.qr_is_current(v, same.ticket), "merge, same entry");
}

#[test]
fn qr_t19_consent_is_per_attempt_action_and_ticket() {
    let (s, v, id) = demo("t19");
    let live = field(&s, v, &id, "Password").unwrap();
    let path = folder().join("t19.png");
    let target = path.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&path);
    let save = |consent: u64| s.qr_save_png(v, live.ticket, consent, target.clone());
    // No consent, a made-up one, the other action's.
    assert_eq!(refusal(save(0)), SAVE_FAILED);
    assert_eq!(refusal(save(u64::MAX)), SAVE_FAILED);
    let share = s.qr_consent(v, live.ticket, QrExport::Share).unwrap();
    assert_eq!(refusal(save(share)), SAVE_FAILED);
    let saving = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    assert_eq!(
        refusal(s.qr_share_png(v, live.ticket, saving)),
        SHARE_FAILED
    );
    assert!(!path.exists());
    // Only the last confirmation holds: the earlier one is gone.
    let again = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    assert_ne!(saving, again);
    assert_eq!(refusal(save(saving)), SAVE_FAILED);
    let again = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    save(again).unwrap();
    assert!(path.exists());
    // Single use: the double click does nothing.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(refusal(save(again)), SAVE_FAILED);
    assert!(!path.exists());
    // A consent on a dead ticket is refused, and is no consent for a new one.
    s.qr_release(v, live.ticket);
    assert!(s.qr_consent(v, live.ticket, QrExport::Save).is_err());
    let other = field(&s, v, &id, "Password").unwrap();
    assert_eq!(
        refusal(s.qr_save_png(v, other.ticket, again, target.clone())),
        SAVE_FAILED
    );
}

/// FEA-10.17's file for `symbol`, drawn here on its own: every module 8 by 8,
/// pure black or pure white, quiet zone included, through the one PNG encoder.
fn picture(symbol: &Qr) -> Vec<u8> {
    let side = symbol.size as usize;
    let edge = side * 8;
    let mut rgba = Vec::with_capacity(edge * edge * 4);
    for y in 0..edge {
        for x in 0..edge {
            let dark = symbol.modules[(y / 8) * side + x / 8] == 1;
            rgba.extend_from_slice(if dark {
                &[0, 0, 0, 0xFF]
            } else {
                &[0xFF, 0xFF, 0xFF, 0xFF]
            });
        }
    }
    larsal_core::icons::encode_png(edge as u32, edge as u32, &rgba).unwrap()
}

/// Chunk names and the header of a PNG.
fn chunks(bytes: &[u8]) -> (Vec<String>, u32, u32) {
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    let mut names = Vec::new();
    let (mut at, mut size) = (8, (0, 0));
    while at + 8 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let name = String::from_utf8_lossy(&bytes[at + 4..at + 8]).into_owned();
        if name == "IHDR" {
            size = (
                u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
                u32::from_be_bytes(bytes[at + 12..at + 16].try_into().unwrap()),
            );
        }
        names.push(name);
        at += 12 + len;
    }
    (names, size.0, size.1)
}

#[test]
fn qr_t20_save_is_full_private_plain_and_refuses_links() {
    let (s, v, id) = demo("t20");
    let dir = folder().join("t20");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Larsal QR.png");
    let target = path.to_string_lossy().into_owned();
    let live = field(&s, v, &id, "Password").unwrap();
    let side = live.symbol.size * 8;
    let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    s.qr_save_png(v, live.ticket, consent, target.clone())
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes, picture(&live.symbol), "every pixel");
    assert_eq!(
        chunks(&bytes),
        (
            vec!["IHDR".into(), "IDAT".into(), "IEND".into()],
            side,
            side
        )
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no leftover");
    // Overwrite works; a link is refused, and neither end changes.
    std::fs::write(&path, b"old").unwrap();
    let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    s.qr_save_png(v, live.ticket, consent, target.clone())
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::write(&path, b"old").unwrap();
    let link = dir.join("link.png");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    assert_eq!(
        refusal(s.qr_save_png(v, live.ticket, consent, link.to_string_lossy().into_owned())),
        SAVE_FAILED
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // A partial write: no such folder. Nothing new appears.
    let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    let missing = dir.join("nowhere").join("x.png");
    assert_eq!(
        refusal(s.qr_save_png(
            v,
            live.ticket,
            consent,
            missing.to_string_lossy().into_owned()
        )),
        SAVE_FAILED
    );
    // A race: the source changes between consent and commit.
    let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    s.begin_edit(v, id).unwrap();
    s.set_password(v, "changed-demo".into()).unwrap();
    s.commit_edit(v).unwrap();
    assert_eq!(
        refusal(s.qr_save_png(v, live.ticket, consent, target.clone())),
        SAVE_FAILED
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "file and link");
    // Lock wins over a confirmed consent.
    let id = saved(&s, v, &[("Title", "Lock"), ("Password", "demo")]);
    let live = field(&s, v, &id, "Password").unwrap();
    let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
    s.lock(v).unwrap();
    assert!(s.qr_save_png(v, live.ticket, consent, target).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
}

#[test]
fn qr_t21_share_bytes_are_in_memory_and_fail_closed_after_revocation() {
    let (s, v, id) = demo("t21");
    let dir = folder().join("t21");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let live = field(&s, v, &id, "Password").unwrap();
    assert_eq!(refusal(s.qr_share_png(v, live.ticket, 0)), SHARE_FAILED);
    let consent = s.qr_consent(v, live.ticket, QrExport::Share).unwrap();
    let bytes = s.qr_share_png(v, live.ticket, consent).unwrap();
    assert_eq!(chunks(&bytes).0, ["IHDR", "IDAT", "IEND"]);
    // A provider may ask twice while live; never after.
    assert_eq!(s.qr_share_png(v, live.ticket, consent).unwrap(), bytes);
    s.qr_release(v, live.ticket);
    assert_eq!(
        refusal(s.qr_share_png(v, live.ticket, consent)),
        SHARE_FAILED
    );
}

#[test]
fn qr_t29_tickets_do_not_cross_vaults_and_debug_hides_the_matrix() {
    let (s, v, id) = demo("t29");
    let path = folder().join("t29-other.larsalvault");
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/option-a-personal.larsalvault"),
        &path,
    )
    .unwrap();
    let other = s.open(path.to_string_lossy().into_owned()).unwrap();
    s.unlock(other, Some("demo-pass-7".into()), None).unwrap();
    let live = field(&s, v, &id, "Password").unwrap();
    assert!(!s.qr_is_current(other, live.ticket));
    assert!(s.qr_consent(other, live.ticket, QrExport::Save).is_err());
    assert!(
        s.qr_is_current(v, live.ticket),
        "that vault's request stays"
    );
    s.qr_release(other, live.ticket);
    assert!(
        s.qr_is_current(v, live.ticket),
        "release in another vault is nothing"
    );
    // A ticket number from before a lock means nothing after the unlock.
    s.lock(v).unwrap();
    s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
    assert!(!s.qr_is_current(v, live.ticket));
    let text = format!("{live:?}");
    assert!(
        text.contains("<hidden>") && !text.contains("modules: ["),
        "{text}"
    );
}
