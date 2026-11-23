//! E5-S5: the editor and the window's vault changes over the Rust session,
//! on a copy of the Option A Personal demo vault (password in
//! testdata/README.md). Each test names its card rule.

use larsal_ffi::edit::EditText;
use larsal_ffi::session::{LarsalError, Session, UnlockResult};
use larsal_ffi::views::ListView;
use std::path::PathBuf;
use std::sync::Arc;

/// A fresh copy of the Personal vault, opened and unlocked in a test
/// session (private pasteboard).
fn personal(name: &str) -> (Arc<Session>, u64, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.larsalvault"));
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
    (session, id, path)
}

fn entry_id(session: &Session, vault: u64, title: &str) -> String {
    session
        .list(vault, ListView::All)
        .unwrap()
        .rows
        .into_iter()
        .chain(session.list(vault, ListView::Bin).unwrap().rows)
        .find(|r| r.title == title)
        .unwrap_or_else(|| panic!("{title}"))
        .id
}

#[test]
fn mod_01_edit_commit_save_and_reopen() {
    let (s, v, path) = personal("commit");
    let github = entry_id(&s, v, "GitHub");
    let view = s.begin_edit(v, github.clone()).unwrap();
    assert_eq!(view.identifier, "3f2a9c1e-77b4-4c0d-9a51-6e0b2d8c4f17");
    assert_eq!((view.usage, view.history_items), (214, 3));
    assert_eq!(view.tags, ["2fa", "dev"]);
    assert!(view.favorite && view.passkey.is_some() && view.totp.is_some());
    let rows: Vec<&str> = view.history.iter().map(|r| r.change.as_str()).collect();
    assert_eq!(
        rows,
        [
            "Passkey added",
            "Password changed",
            "Notes changed",
            "Entry created"
        ]
    );
    // MOD-01.3 fields, MOD-01.5 line breaks, the password from Swift.
    s.set_text(v, EditText::Title, "Git\r\nHub".into()).unwrap();
    assert_eq!(s.set_password(v, "demo-new-pass-1".into()).unwrap(), 15);
    assert_eq!(s.add_field(v).unwrap(), "New field");
    assert_eq!(s.add_field(v).unwrap(), "New field 1");
    assert!(matches!(
        s.rename_field(v, "New field".into(), "Password".into()),
        Err(LarsalError::Refused(_))
    ));
    s.rename_field(v, "New field".into(), "  PIN  ".into())
        .unwrap();
    s.set_field(v, "PIN".into(), "4711".into()).unwrap();
    s.protect_field(v, "PIN".into(), true).unwrap();
    s.remove_field(v, "New field 1".into()).unwrap();
    s.set_tags(v, vec!["dev".into(), "work".into()]).unwrap();
    let draft = s.editor(v).unwrap();
    assert!(
        draft
            .custom
            .iter()
            .any(|f| f.name == "PIN" && f.protected && f.value.is_empty())
    );
    assert!(draft.changed.contains(&"Password".to_owned()));
    assert_eq!(s.draft_password(v).unwrap(), "demo-new-pass-1");
    assert!(s.rate_draft(v).unwrap().is_some_and(|r| r.chars == 15));
    // Nothing changed before the commit.
    assert_eq!(s.save_status(v).unwrap().changes, 0);
    assert_eq!(s.commit_edit(v).unwrap(), github);
    assert_eq!(s.save_status(v).unwrap().changes, 1);
    let detail = s.entry(v, github.clone()).unwrap();
    assert_eq!(detail.title, "Git Hub");
    assert_eq!(detail.history, 4, "one history item (MOD-01.32)");
    assert!(detail.favorite, "the favorite mark stays");
    assert_eq!(detail.tags, ["dev", "work"]);
    // APP-05: saved, then the file opens with the new values.
    let status = s.save(v).unwrap();
    assert_eq!((status.changes, status.failure), (0, None));
    let again = Session::new();
    let id = again.open(path.to_string_lossy().into_owned()).unwrap();
    again.unlock(id, Some("demo-pass-7".into()), None).unwrap();
    assert_eq!(
        again
            .show_field(id, github.clone(), "Password".into())
            .unwrap(),
        "demo-new-pass-1"
    );
    assert_eq!(again.show_field(id, github, "PIN".into()).unwrap(), "4711");
    // A second save works too (the transformed key moves on, CRY-03.16).
    s.begin_edit(v, entry_id(&s, v, "Wise")).unwrap();
    s.set_text(v, EditText::Notes, "demo note".into()).unwrap();
    s.commit_edit(v).unwrap();
    assert_eq!(s.save(v).unwrap().failure, None);
}

#[test]
fn mod_01_25_cancel_and_new_entry() {
    let (s, v, _) = personal("new");
    let all = s.sidebar(v).unwrap().all;
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::Title, "Demo".into()).unwrap();
    s.cancel_edit(v).unwrap();
    assert_eq!(s.sidebar(v).unwrap().all, all, "cancel leaves no trace");
    assert!(s.editor(v).is_err());
    let work = s
        .sidebar(v)
        .unwrap()
        .groups
        .into_iter()
        .find(|g| g.name == "Work")
        .unwrap()
        .id;
    let view = s.begin_new(v, Some(work.clone())).unwrap();
    assert!(view.new && view.history.is_empty() && view.group_name == "Work");
    s.set_text(v, EditText::Title, "Demo".into()).unwrap();
    let id = s.commit_edit(v).unwrap();
    assert_eq!(s.sidebar(v).unwrap().all, all + 1);
    assert_eq!(s.entry(v, id).unwrap().group, "Work");
}

#[test]
fn mod_03_restore_and_delete_versions() {
    let (s, v, _) = personal("history");
    let github = entry_id(&s, v, "GitHub");
    s.begin_edit(v, github.clone()).unwrap();
    let old = s.show_version(v, 0).unwrap();
    assert_eq!(
        (old.password.as_str(), old.user.as_str()),
        ("m8@Ty3!Kq6#Pv1$Zr4&", "alex-dev")
    );
    assert_eq!(
        s.show_version(v, 2).unwrap().before,
        "the passkey was added"
    );
    s.restore_version(v, 0).unwrap();
    assert_eq!(s.draft_password(v).unwrap(), "m8@Ty3!Kq6#Pv1$Zr4&");
    s.delete_version(v, Some(1)).unwrap();
    assert_eq!(
        s.editor(v).unwrap().history.len(),
        3,
        "the marked item is hidden"
    );
    s.commit_edit(v).unwrap();
    // One item removed, one added for the edit session (MOD-03.13).
    assert_eq!(s.entry(v, github).unwrap().history, 3);
}

#[test]
fn mod_04_bin_and_mod_10_clone() {
    let (s, v, _) = personal("bin");
    let amazon = entry_id(&s, v, "Amazon");
    let bin_before = s.sidebar(v).unwrap().bin.unwrap();
    assert_eq!(s.delete_entry(v, amazon.clone()).unwrap().to_bin, 1);
    assert_eq!(s.sidebar(v).unwrap().bin, Some(bin_before + 1));
    assert!(!s.restore_entry(v, amazon.clone()).unwrap());
    assert_eq!(s.sidebar(v).unwrap().bin, Some(bin_before));
    let clone = s
        .clone_entry(v, amazon.clone(), true, false, false)
        .unwrap();
    let detail = s.entry(v, clone.clone()).unwrap();
    assert_eq!(
        (detail.title.as_str(), detail.history),
        ("Amazon - Clone", 0)
    );
    // In the bin, a delete is for good (MOD-04.4).
    let myspace = entry_id(&s, v, "MySpace");
    assert_eq!(s.delete_entry(v, myspace).unwrap().for_good, 1);
    assert_eq!(s.empty_bin(v).unwrap(), 1);
    assert_eq!(s.sidebar(v).unwrap().bin, Some(0));
    assert_eq!(s.save_status(v).unwrap().changes, 5);
    let group = s.add_group(v, None, "Travel".into(), 48, None).unwrap();
    assert!(
        s.sidebar(v)
            .unwrap()
            .groups
            .iter()
            .any(|g| g.id == group && g.name == "Travel")
    );
}

#[test]
fn fea_04_setup_qr_and_passkey() {
    let (s, v, _) = personal("totp");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let qr = s.totp_qr(v).unwrap();
    assert_eq!(qr.modules.len(), (qr.size * qr.size) as usize);
    assert!(qr.size >= 29 && qr.modules.contains(&1));
    assert!(matches!(
        s.set_totp(v, "not base32 1".into(), 6, 30, "SHA-1".into()),
        Err(LarsalError::Refused(_))
    ));
    s.set_totp(v, "jbsw y3dp ehpk 3pxp".into(), 8, 30, "SHA-1".into())
        .unwrap();
    let info = s.editor(v).unwrap().totp.unwrap();
    assert_eq!((info.digits, info.custom), (8, true));
    assert_eq!(s.totp_setup(v).unwrap().secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(
        s.draft_code(v)
            .unwrap()
            .unwrap()
            .code
            .replace(' ', "")
            .len(),
        8
    );
    s.set_totp(
        v,
        "otpauth://totp/Demo:alice?secret=JBSWY3DPEHPK3PXP&digits=7".into(),
        6,
        30,
        "SHA-1".into(),
    )
    .unwrap();
    assert_eq!(s.editor(v).unwrap().totp.unwrap().digits, 7);
    assert!(
        s.set_totp(v, "otpauth://hotp/x?secret=1".into(), 6, 30, "SHA-1".into())
            .is_err()
    );
    s.remove_passkey(v).unwrap();
    assert!(s.editor(v).unwrap().passkey.is_none());
}

#[test]
fn ld_170_show_and_copy_resolve_hidden_fields_to_nothing() {
    let (s, v, _) = personal("ld170");
    let github = entry_id(&s, v, "GitHub");
    s.begin_edit(v, github.clone()).unwrap();
    s.set_text(
        v,
        EditText::Notes,
        "a{S:otp}b{S:KPEX_PASSKEY_PRIVATE_KEY_PEM}c{S:Missing}".into(),
    )
    .unwrap();
    s.commit_edit(v).unwrap();
    assert_eq!(s.show_field(v, github, "Notes".into()).unwrap(), "abc");
}

#[test]
fn ld_139_an_edit_drops_the_ratings() {
    let (s, v, _) = personal("ratings");
    while !s.rate(v, 100, 3600).unwrap() {}
    assert!(s.sidebar(v).unwrap().attention.is_some());
    s.begin_edit(v, entry_id(&s, v, "Amazon")).unwrap();
    s.set_password(v, "a-much-longer-demo-pass-2026!".into())
        .unwrap();
    s.commit_edit(v).unwrap();
    assert!(
        s.sidebar(v).unwrap().attention.is_none(),
        "the Health Check runs again"
    );
    while !s.rate(v, 100, 3600).unwrap() {}
    let amazon = s.entry(v, entry_id(&s, v, "Amazon")).unwrap();
    assert!(!amazon.rating.unwrap().attention, "no longer reused");
}

#[test]
fn at_e03_editor_refuses_hostile_arguments() {
    let (s, v, _) = personal("hostile");
    assert!(s.editor(v).is_err(), "no draft");
    assert_eq!(
        s.begin_edit(v, "+".repeat(32)).unwrap_err(),
        LarsalError::UnknownEntry
    );
    assert_eq!(
        s.begin_new(v, Some("zz".into())).unwrap_err(),
        LarsalError::UnknownGroup
    );
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    assert_eq!(
        s.set_password(v, "x".repeat(70_000)).unwrap_err(),
        LarsalError::TooLong
    );
    // The editor's custom field calls never reach the hidden fields.
    for name in [
        "otp",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "Password",
        "KP2A_URL",
    ] {
        assert_eq!(
            s.show_draft_field(v, name.into()).unwrap_err(),
            LarsalError::UnknownField,
            "{name}"
        );
        assert_eq!(
            s.remove_field(v, name.into()).unwrap_err(),
            LarsalError::UnknownField,
            "{name}"
        );
    }
    assert!(s.show_version(v, 99).is_err());
    assert!(s.set_icon(v, 69).is_err());
    assert!(s.has_draft(v));
    s.lock(v).unwrap();
    assert_eq!(s.editor(v).unwrap_err(), LarsalError::Locked);
    // Read while locked: the lock itself dropped the draft and the kept
    // key parts (fails if Slot::lock stops resetting the edit state).
    assert!(!s.has_draft(v), "a lock drops the draft");
    assert_eq!(
        s.password_pages_locked(v),
        None,
        "a lock drops the kept password"
    );
    s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
    assert!(s.editor(v).is_err());
}

/// A 1 × 1 PNG, as the screen renders a symbol tile (base64).
fn tiny_png() -> Vec<u8> {
    larsal_format::document::encode::base64_decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
    )
}

#[test]
fn ld_192_custom_icon_for_entry_and_group() {
    let (s, v, _) = personal("icons");
    let github = entry_id(&s, v, "GitHub");
    s.begin_edit(v, github.clone()).unwrap();
    assert!(
        s.add_custom_icon(v, b"not a png".to_vec(), "x y".into())
            .is_err()
    );
    let icon = s
        .add_custom_icon(v, tiny_png(), "airplane cyan".into())
        .unwrap();
    assert_eq!(
        s.add_custom_icon(v, tiny_png(), "again".into()).unwrap(),
        icon,
        "MOD-06.9"
    );
    s.set_custom_icon(v, icon.clone()).unwrap();
    assert_eq!(
        s.editor(v).unwrap().custom_icon.as_deref(),
        Some("airplane cyan")
    );
    s.commit_edit(v).unwrap();
    let detail = s.entry(v, github).unwrap();
    assert_eq!(
        (detail.icon, detail.custom_icon.as_deref()),
        (-1, Some("airplane cyan"))
    );
    let travel = s
        .add_group(v, None, "Travel".into(), 48, Some(icon))
        .unwrap();
    let row = s
        .sidebar(v)
        .unwrap()
        .groups
        .into_iter()
        .find(|g| g.id == travel)
        .unwrap();
    assert_eq!(row.custom_icon.as_deref(), Some("airplane cyan"));
}

#[test]
fn int_02_29_browser_page_stores_its_options() {
    let (s, v, _) = personal("browser");
    let github = entry_id(&s, v, "GitHub");
    let view = s.begin_edit(v, github.clone()).unwrap();
    assert_eq!(view.allow, ["gist.github.com", "github.com"]);
    assert_eq!(
        view.browsers
            .iter()
            .map(|b| b.name.as_str())
            .collect::<Vec<_>>(),
        ["Firefox on MacBook", "Safari"]
    );
    assert!(view.browser_options[1].on && view.browser_options[1].group.is_none());
    assert!(matches!(
        s.add_site(v, "not a host!".into(), false),
        Err(LarsalError::Refused(_))
    ));
    s.add_site(v, "https://Bücher.example/login".into(), true)
        .unwrap();
    s.add_site(v, "github.com".into(), true).unwrap();
    let view = s.editor(v).unwrap();
    assert_eq!(
        view.allow,
        ["gist.github.com"],
        "adding to Deny removes it from Allow"
    );
    assert_eq!(view.deny, ["github.com", "xn--bcher-kva.example"]);
    s.remove_site(v, "github.com".into(), true).unwrap();
    s.set_browser_option(v, "BrowserHideEntry".into(), true)
        .unwrap();
    s.set_browser_option(v, "BrowserSkipAutoSubmit".into(), false)
        .unwrap();
    s.set_browser_option(v, "BrowserOnlyHttpAuth".into(), false)
        .unwrap();
    assert!(s.set_browser_option(v, "Other".into(), true).is_err());
    s.commit_edit(v).unwrap();
    let view = s.begin_edit(v, github).unwrap();
    let on: Vec<bool> = view.browser_options.iter().map(|o| o.on).collect();
    assert_eq!(on, [true, false, false]);
    assert_eq!(view.deny, ["xn--bcher-kva.example"]);
    let keys: Vec<&str> = view.custom_data.iter().map(|c| c.key.as_str()).collect();
    assert!(
        keys.contains(&"BrowserSkipAutoSubmit"),
        "off with a key: written false"
    );
    assert!(
        !keys.contains(&"BrowserOnlyHttpAuth"),
        "off without a key: nothing written"
    );
    assert!(keys.contains(&"Browser site access"));
}

/// F-281, INT-02.16: the editor writes the site access item as the bridge
/// does: a full list drops its oldest hosts in list order, so a host just
/// added stays even when it sorts last.
#[test]
fn f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list() {
    let (s, v, _) = personal("full-allow");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    for n in 0..1000 {
        s.add_site(v, format!("h{n:04}.example"), false).unwrap();
    }
    s.add_site(v, "zz.example".into(), false).unwrap();
    let allow = s.editor(v).unwrap().allow;
    assert_eq!(allow.len(), 1000);
    assert!(
        allow.contains(&"zz.example".to_owned()),
        "the host just added"
    );
    assert!(!allow.contains(&"h0000.example".to_owned()), "the oldest");
}

#[test]
fn mod_05_open_save_and_wipe() {
    use std::os::unix::fs::PermissionsExt;
    let (s, v, _) = personal("attach");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let name = "github-recovery-codes.txt".to_owned();
    let larsal_ffi::edit::OpenAttachment::Opened { path } =
        s.open_attachment(v, name.clone(), false).unwrap()
    else {
        panic!("opened")
    };
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 1229);
    assert!(path.ends_with(".txt") && path.contains("/Larsal/open-attachments/"));
    s.cancel_edit(v).unwrap();
    assert!(
        !std::path::Path::new(&path).exists(),
        "wiped when the editor closes"
    );
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    s.attach_file(v, testdata_file("key-hex64.larsalkey"))
        .unwrap();
    let larsal_ffi::edit::OpenAttachment::Opened { path } = s
        .open_attachment(v, "key-hex64.larsalkey".into(), false)
        .unwrap()
    else {
        panic!("plain types open at once")
    };
    s.lock(v).unwrap();
    assert!(!std::path::Path::new(&path).exists(), "wiped on lock");
    s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    // MOD-05.14: into a folder, 0600, asking before an overwrite.
    let folder = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/saved");
    let _ = std::fs::remove_dir_all(&folder);
    let dir = folder.to_string_lossy().into_owned();
    assert!(
        s.save_attachment(v, name.clone(), dir.clone(), false)
            .unwrap()
    );
    assert!(
        !s.save_attachment(v, name.clone(), dir.clone(), false)
            .unwrap(),
        "exists: ask first"
    );
    assert!(s.save_attachment(v, name.clone(), dir, true).unwrap());
    let saved = std::fs::metadata(folder.join(&name)).unwrap();
    assert_eq!(saved.permissions().mode() & 0o777, 0o600);
}

#[test]
fn mod_05_12_risky_types_ask_first() {
    let (s, v, _) = personal("risky");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/risky");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("demo.command");
    std::fs::write(&file, "echo demo").unwrap();
    s.attach_file(v, file.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(
        s.open_attachment(v, "demo.command".into(), false).unwrap(),
        larsal_ffi::edit::OpenAttachment::AskFirst
    );
    assert!(matches!(
        s.open_attachment(v, "demo.command".into(), true).unwrap(),
        larsal_ffi::edit::OpenAttachment::Opened { .. }
    ));
}

/// F-103: the types whose default app runs code or acts (LaunchServices on
/// macOS 26) and the system's quarantine list ask first too, in any case
/// (Unicode's, as LaunchServices reads it) and as the copy's extension
/// reads; a plain type opens.
#[test]
fn f_103_every_type_that_runs_or_acts_asks_first() {
    let (s, v, _) = personal("f103");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/f103");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let added = [
        "term",
        "xhtml",
        "xht",
        "shtml",
        "webarchive",
        "url",
        "xsl",
        "jnlp",
        "class",
        "afploc",
        "ftploc",
        "atloc",
        "vncloc",
        "mailloc",
        "action",
        "wflow",
        "shortcut",
        "scptd",
        "osax",
        "svgz",
        "iso",
        "img",
        "cdr",
        "sparseimage",
        "toast",
        "cin",
        "gcx",
        "help",
        "ibplugin",
        "icp",
        "inputplugin",
        "menu",
        "nib",
        "service",
        "x11app",
        "ipg",
        "qtz",
        "ipa",
        "dylib",
        "war",
        "shtm",
        "xhtm",
        "jhtml",
        "xslt",
        "xbl",
        "xml",
        "asif",
        "udif",
        "dvdr",
        "dmgpart",
        "nslloc",
        "webbookmark",
        "networkconnect",
        "internetconnect",
        "prefpane",
        "sysprefex",
        "saver",
        "safariextz",
        "caction",
        "definition",
        "download",
        "webhistory",
        "sparsebundle",
        "backupbundle",
        "bash",
        "zsh",
        "csh",
        "ksh",
        "tcsh",
        // Verify round 2 (LD-246).
        "dist",
        "distz",
        "placeholder",
        "remoteplaceholder",
        "py",
        "pl",
        "pm",
        "rb",
        "rbw",
        "php",
        "ph3",
        "ph4",
        "php3",
        "php4",
        "phtml",
    ];
    let names = added.iter().map(|x| format!("demo.{x}")).chain([
        "DEMO.TERM".into(),
        "demo.Xhtml".into(),
        // KELVIN SIGN: LaunchServices lowercases it to k and opens Installer.
        "demo.p\u{212A}g".into(),
        "demo.mp\u{212A}g".into(),
        "notes.txt".into(),
    ]);
    for name in names {
        let file = dir.join(&name);
        std::fs::write(&file, "demo").unwrap();
        s.attach_file(v, file.to_string_lossy().into_owned())
            .unwrap();
        let open = s.open_attachment(v, name.clone(), false).unwrap();
        if name == "notes.txt" {
            assert!(
                matches!(open, larsal_ffi::edit::OpenAttachment::Opened { .. }),
                "{name}"
            );
        } else {
            assert_eq!(open, larsal_ffi::edit::OpenAttachment::AskFirst, "{name}");
        }
    }
}

/// F-104: Open checks the vault, the editor and the attachment before the
/// type, so the screen never asks about one that cannot be opened.
#[test]
fn f_104_open_attachment_checks_the_vault_and_the_name_before_it_asks() {
    let none = Session::new();
    for v in [0, 999_999, u64::MAX] {
        assert_eq!(
            none.open_attachment(v, "x.command".into(), false),
            Err(LarsalError::UnknownVault),
            "{v}"
        );
    }
    let (s, v, _) = personal("f104");
    assert!(
        s.open_attachment(v, "x.command".into(), false).is_err(),
        "no editor"
    );
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    assert_eq!(
        s.open_attachment(v, "missing.command".into(), false),
        Err(LarsalError::UnknownField)
    );
    s.lock(v).unwrap();
    assert_eq!(
        s.open_attachment(v, "x.command".into(), false),
        Err(LarsalError::Locked)
    );
}

/// MOD-09.10. F-439: "now" is read inside the call, so it lies between two
/// reads of the same clock, one before the call and one after, however long
/// a busy Mac makes the call; no margin of seconds.
#[test]
fn mod_09_10_ticking_expires_sets_now() {
    let (s, v, _) = personal("expiry");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };
    let before = secs();
    s.set_expiry(v, true, None).unwrap();
    let after = secs();
    let view = s.editor(v).unwrap();
    assert!(view.expires);
    assert!(
        (before..=after).contains(&view.expiry),
        "{} not in {before}..={after}",
        view.expiry
    );
    s.set_expiry(v, true, Some(1_800_000_000)).unwrap();
    s.set_expiry(v, false, None).unwrap();
    let view = s.editor(v).unwrap();
    assert_eq!(
        (view.expires, view.expiry),
        (false, 1_800_000_000),
        "unticking keeps the value"
    );
}

fn testdata_file(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn ld_199_3_kept_password_is_page_locked() {
    let (s, v, _) = personal("pages");
    assert_eq!(s.password_pages_locked(v), Some(true), "SR-07, APP-11.9");
    s.close(v).unwrap();
    assert_eq!(s.password_pages_locked(v), None);
}

#[test]
fn ld_199_6_7_copies_go_on_remove_and_on_a_new_edit() {
    let (s, v, _) = personal("copies");
    let github = entry_id(&s, v, "GitHub");
    let name = "github-recovery-codes.txt".to_owned();
    let open = |s: &Session| match s.open_attachment(v, name.clone(), false).unwrap() {
        larsal_ffi::edit::OpenAttachment::Opened { path } => std::path::PathBuf::from(path),
        other => panic!("{other:?}"),
    };
    s.begin_edit(v, github.clone()).unwrap();
    let copy = open(&s);
    s.remove_attachment(v, name.clone()).unwrap();
    assert!(
        !copy.exists(),
        "MOD-05.11: removing the attachment wipes its copy"
    );
    s.begin_edit(v, github.clone()).unwrap();
    let copy = open(&s);
    s.begin_edit(v, github.clone()).unwrap();
    assert!(!copy.exists(), "a new edit wipes the last edit's copies");
    let copy = open(&s);
    s.begin_new(v, None).unwrap();
    assert!(!copy.exists(), "a new entry's edit too");
}

#[test]
fn notes_attach_takes_regular_files_only() {
    let (s, v, _) = personal("fifo");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests");
    let fifo = dir.join("demo.fifo");
    let _ = std::fs::remove_file(&fifo);
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // Returns at once (a read would block for ever).
    assert!(matches!(
        s.attach_file(v, fifo.to_string_lossy().into_owned()),
        Err(LarsalError::CannotOpen(_))
    ));
    assert!(matches!(
        s.attach_file(v, dir.to_string_lossy().into_owned()),
        Err(LarsalError::CannotOpen(_))
    ));
    let _ = std::fs::remove_file(&fifo);
}

#[test]
fn notes_strength_rates_the_resolved_password() {
    let (s, v, _) = personal("resolved");
    let amazon = entry_id(&s, v, "Amazon");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    // A reference to Amazon's weak password rates as that password.
    s.set_password(v, format!("{{REF:P@I:{}}}", amazon.to_uppercase()))
        .unwrap();
    let weak = s.rate_draft(v).unwrap().unwrap();
    assert_eq!(weak.chars, 11, "Summer2024! resolved");
}

#[test]
fn mod_09_10_a_new_entry_keeps_the_expiry_set_in_the_editor() {
    let (s, v, path) = personal("new-expiry");
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::Title, "Expiring demo".into())
        .unwrap();
    s.set_expiry(v, true, Some(1_900_000_000)).unwrap();
    let id = s.commit_edit(v).unwrap();
    assert_eq!(s.save(v).unwrap().changes, 0);
    // Read back in a fresh session.
    let again = Session::new();
    let w = again.open(path.to_string_lossy().into_owned()).unwrap();
    again.unlock(w, Some("demo-pass-7".into()), None).unwrap();
    let view = again.begin_edit(w, id).unwrap();
    assert_eq!((view.expires, view.expiry), (true, 1_900_000_000));
}

/// E5-S5 Verify R1: a new entry saved with Expires off keeps its expiry time
/// at its creation time (MOD-01.25, MOD-09.1), not the draft's zero time.
#[test]
fn mod_09_1_a_new_entry_without_expiry_keeps_the_creation_time() {
    let (s, v, path) = personal("new-no-expiry");
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::Title, "Never expires".into())
        .unwrap();
    let id = s.commit_edit(v).unwrap();
    assert_eq!(s.save(v).unwrap().changes, 0);
    let again = Session::new();
    let w = again.open(path.to_string_lossy().into_owned()).unwrap();
    again.unlock(w, Some("demo-pass-7".into()), None).unwrap();
    let view = again.begin_edit(w, id).unwrap();
    assert!(!view.expires);
    assert_eq!(
        view.expiry, view.created,
        "expiry time is the creation time"
    );
}

// ------------------------------------------------- New SSH Key (E24-S2)

use larsal_ffi::edit::{NewSshKeyView, SshKeyKind};
use std::os::unix::fs::PermissionsExt;

const KINDS: [(SshKeyKind, &str, &str, &str); 6] = [
    (SshKeyKind::Ed25519, "ED25519", "ssh-ed25519", "id_ed25519"),
    (
        SshKeyKind::EcdsaP256,
        "ECDSA P-256",
        "ecdsa-sha2-nistp256",
        "id_ecdsa",
    ),
    (
        SshKeyKind::EcdsaP384,
        "ECDSA P-384",
        "ecdsa-sha2-nistp384",
        "id_ecdsa",
    ),
    (
        SshKeyKind::EcdsaP521,
        "ECDSA P-521",
        "ecdsa-sha2-nistp521",
        "id_ecdsa",
    ),
    (SshKeyKind::Rsa3072, "RSA 3072", "ssh-rsa", "id_rsa"),
    (SshKeyKind::Rsa4096, "RSA 4096", "ssh-rsa", "id_rsa"),
];

/// The vault at `path` as the file holds it, read in memory only.
fn on_disk(path: &std::path::Path) -> larsal_model::Vault {
    let p = larsal_crypto::secret::SecretString::new("demo-pass-7".into());
    let c = larsal_format::keys::Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let mut host = larsal_crypto::kdf::Host {
        physical_memory: 8 << 30,
        logical_processors: 4,
        argon2_record: None,
        aes_record: None,
    };
    let bytes = std::fs::read(path).unwrap();
    let limits = larsal_format::limits::Limits::DEFAULT;
    match larsal_format::open(&bytes, &c, &mut host, &limits, None).unwrap() {
        larsal_format::Opened::Vault(o) => o.vault,
        larsal_format::Opened::Ask(_) => panic!("no ask"),
    }
}

fn stored_entry(v: &larsal_model::Vault, id: &str) -> larsal_model::Entry {
    let hex = |u: &larsal_model::Uuid| u.0.iter().map(|b| format!("{b:02x}")).collect::<String>();
    v.root
        .all_entries()
        .find(|e| hex(&e.uuid) == id)
        .unwrap_or_else(|| panic!("{id}"))
        .duplicate(false)
}

/// No file in `dir` holds a private key in the clear (INT-06.E24.04).
fn no_private_file(dir: &std::path::Path) {
    for f in std::fs::read_dir(dir).unwrap() {
        let p = f.unwrap().path();
        if p.is_file() {
            let bytes = std::fs::read(&p).unwrap();
            assert!(
                !bytes.windows(11).any(|w| w == b"PRIVATE KEY"),
                "{} holds a private key",
                p.display()
            );
        }
    }
}

/// E24-S01, E24-S04, E24-S05: every kind New SSH Key offers, on a blank
/// editor: committed with the entry, saved in the vault as one-key
/// openssh-key-v1 inside the encryption, its public parts in the answer, the
/// detail and the `.pub` attachment; no private key file anywhere.
#[test]
fn e24_s01_s04_each_kind_on_a_blank_editor_is_committed_and_saved_in_the_vault() {
    let (s, v, path) = personal("e24-kinds");
    let mut made: Vec<(NewSshKeyView, &str, &str)> = Vec::new();
    for (kind, label, algorithm, file) in KINDS {
        s.begin_new(v, None).unwrap();
        s.set_text(v, EditText::Title, format!("Key {label}"))
            .unwrap();
        let before = s.save_status(v).unwrap().changes;
        let view = s.new_ssh_key(v, kind, "demo@larsal".into()).unwrap();
        assert!(!s.has_draft(v), "committed: the editor closed");
        assert_eq!(s.save_status(v).unwrap().changes, before + 1);
        assert_eq!(view.kind, label);
        assert_eq!(view.attachment, file);
        assert!(view.fingerprint.starts_with("SHA256:"));
        assert_eq!(view.fingerprint.len(), 7 + 43);
        let parts: Vec<&str> = view.public_key.split(' ').collect();
        assert_eq!((parts[0], parts.len()), (algorithm, 3));
        assert_eq!(parts[2], "demo@larsal");
        assert!(!format!("{view:?}").contains("PRIVATE"));
        let detail = s.entry(v, view.entry.clone()).unwrap();
        assert_eq!(detail.title, format!("Key {label}"));
        assert_eq!(detail.ssh.unwrap().fingerprint, view.fingerprint);
        made.push((view, algorithm, file));
    }
    let status = s.save(v).unwrap();
    assert_eq!((status.changes, status.failure), (0, None));
    let disk = on_disk(&path);
    for (view, algorithm, file) in &made {
        let e = stored_entry(&disk, &view.entry);
        let names: Vec<&str> = e.attachments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        let public_name = format!("{file}.pub");
        assert!(names.contains(file) && names.contains(&public_name.as_str()));
        let private = e.attachments.iter().find(|a| a.name == *file).unwrap();
        let key = larsal_crypto::ssh::OpenSshKey::parse(private.data.expose()).unwrap();
        assert_eq!(key.algorithm(), *algorithm);
        assert!(!key.is_encrypted(), "inside the vault's encryption only");
        assert_eq!(key.fingerprint(), view.fingerprint);
        assert_eq!(key.public_line(), view.public_key);
        let public = e
            .attachments
            .iter()
            .find(|a| a.name == public_name)
            .unwrap();
        assert_eq!(
            public.data.expose(),
            format!("{}\n", view.public_key).as_bytes()
        );
        let settings = larsal_sshagent::Settings::of(&e).unwrap().unwrap();
        assert_eq!(settings.attachment_name, *file);
        assert!(
            larsal_sshagent::has_ssh_key(&disk, &e).is_some(),
            "E9 finds it"
        );
    }
    no_private_file(path.parent().unwrap());
}

/// E24-S03: the comment is kept exactly or refused with its labelled error
/// before any key is made; a blank comment is blank, never the protected
/// user name or anything else of the entry.
#[test]
fn e24_s03_the_comment_is_exact_or_refused_never_the_user_name() {
    let (s, v, path) = personal("e24-comment");
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::UserName, "demo-user".into())
        .unwrap();
    s.set_text(v, EditText::Title, "Blank comment".into())
        .unwrap();
    let long = "a".repeat(257);
    for bad in ["two\nlines", "tab\t", "rlo\u{202E}x", long.as_str()] {
        assert_eq!(
            s.new_ssh_key(v, SshKeyKind::Ed25519, bad.into()),
            Err(LarsalError::Refused(
                larsal_ffi::edit::MSG_SSH_COMMENT.into()
            )),
            "{bad:?}"
        );
        assert!(s.has_draft(v) && s.editor(v).unwrap().attachments.is_empty());
    }
    let blank = s
        .new_ssh_key(v, SshKeyKind::Ed25519, String::new())
        .unwrap();
    assert_eq!(
        blank.public_key.split(' ').count(),
        2,
        "{}",
        blank.public_key
    );
    assert!(!blank.public_key.contains("demo-user"));
    s.begin_new(v, None).unwrap();
    let label = "Développement · 鍵 🔑";
    let kept = s
        .new_ssh_key(v, SshKeyKind::EcdsaP256, label.into())
        .unwrap();
    assert!(kept.public_key.ends_with(&format!(" {label}")));
    assert_eq!(s.save(v).unwrap().failure, None);
    let disk = on_disk(&path);
    for (view, comment) in [(&blank, ""), (&kept, label)] {
        let e = stored_entry(&disk, &view.entry);
        let a = e
            .attachments
            .iter()
            .find(|a| a.name == view.attachment)
            .unwrap();
        let key = larsal_crypto::ssh::OpenSshKey::parse(a.data.expose()).unwrap();
        assert_eq!(key.comment(), Some(comment));
    }
}

/// E24-S04: a key never replaces an attachment or SSH settings by name; the
/// refusal comes before any key is made and leaves the draft as it was.
#[test]
fn e24_s04_a_name_in_the_way_or_a_key_already_there_is_refused() {
    let (s, v, _) = personal("e24-collide");
    let github = entry_id(&s, v, "GitHub");
    s.begin_edit(v, github.clone()).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/e24-collide-src");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("id_ed25519"), b"demo text, not a key\n").unwrap();
    s.attach_file(v, dir.join("id_ed25519").to_string_lossy().into_owned())
        .unwrap();
    let before = s.editor(v).unwrap().attachments;
    let refused = s.new_ssh_key(v, SshKeyKind::Ed25519, String::new());
    assert!(
        matches!(&refused, Err(LarsalError::Refused(t)) if t.contains("“id_ed25519”")),
        "{refused:?}"
    );
    assert_eq!(s.editor(v).unwrap().attachments, before, "nothing replaced");
    // Another type's names are free: the key joins, the demo file stays.
    let ecdsa = s
        .new_ssh_key(v, SshKeyKind::EcdsaP256, String::new())
        .unwrap();
    s.begin_edit(v, github.clone()).unwrap();
    let names: Vec<String> = s
        .editor(v)
        .unwrap()
        .attachments
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert!(names.contains(&"id_ed25519".to_owned()) && names.contains(&"id_ecdsa".to_owned()));
    // The entry now has SSH settings: no second key, of any type.
    for kind in [SshKeyKind::Rsa3072, SshKeyKind::EcdsaP256] {
        assert_eq!(
            s.new_ssh_key(v, kind, String::new()),
            Err(LarsalError::Refused(
                larsal_ffi::edit::MSG_SSH_HAS_KEY.into()
            ))
        );
    }
    let shown = s.entry(v, github).unwrap().ssh.unwrap();
    assert_eq!(shown.fingerprint, ecdsa.fingerprint);
}

/// E24-S04 (lead ruling (5), APP-05): a save that fails leaves the vault file
/// as it was, byte for byte, keeps the key in the open vault as an unsaved
/// change and reports it; the next save writes it.
#[test]
fn e24_s04_a_failed_save_leaves_the_file_unchanged_and_reports_unsaved() {
    let (_, _, path) = personal("e24-disk");
    let lockdir = path.parent().unwrap().join("e24-disk-ro");
    let _ = std::fs::set_permissions(&lockdir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&lockdir);
    std::fs::create_dir_all(&lockdir).unwrap();
    let moved = lockdir.join("Personal.larsalvault");
    std::fs::rename(&path, &moved).unwrap();
    let s = Session::new();
    let w = s.open(moved.to_string_lossy().into_owned()).unwrap();
    s.unlock(w, Some("demo-pass-7".into()), None).unwrap();
    let wise = entry_id(&s, w, "Wise");
    s.begin_edit(w, wise.clone()).unwrap();
    let view = s
        .new_ssh_key(w, SshKeyKind::Ed25519, String::new())
        .unwrap();
    let file = std::fs::read(&moved).unwrap();
    // A folder the save cannot write into (the file is replaced in one step).
    std::fs::set_permissions(&lockdir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let status = s.save(w).unwrap();
    std::fs::set_permissions(&lockdir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(status.failure.is_some(), "{status:?}");
    assert_eq!(status.changes, 1, "reported unsaved");
    assert_eq!(
        std::fs::read(&moved).unwrap(),
        file,
        "the vault file, byte for byte"
    );
    let open = s.entry(w, wise.clone()).unwrap();
    assert_eq!(
        open.ssh.map(|k| k.fingerprint),
        Some(view.fingerprint.clone()),
        "the key stays in the open vault"
    );
    assert!(open.attachments.iter().any(|a| a.name == "id_ed25519"));
    let saved = stored_entry(&on_disk(&moved), &wise);
    assert!(
        !saved.attachments.iter().any(|a| a.name.starts_with("id_")),
        "the file is unchanged"
    );
    assert_eq!(s.save(w).unwrap().failure, None);
    let saved = stored_entry(&on_disk(&moved), &wise);
    assert!(saved.attachments.iter().any(|a| a.name == "id_ed25519"));
    no_private_file(&lockdir);
}

/// E24-S05: Save Public Key writes the public line only, 0600, asks before
/// replacing a file, and the file stays after the vault locks.
#[test]
fn e24_s05_save_public_key_writes_the_public_line_and_asks_before_replacing() {
    let (s, v, path) = personal("e24-pub");
    s.begin_new(v, None).unwrap();
    let view = s
        .new_ssh_key(v, SshKeyKind::Rsa3072, "demo@larsal".into())
        .unwrap();
    let folder = path.parent().unwrap().join("e24-pub-out");
    let _ = std::fs::remove_dir_all(&folder);
    let f = folder.to_string_lossy().into_owned();
    let save = |overwrite| s.save_ssh_public_key(v, view.entry.clone(), f.clone(), overwrite);
    assert_eq!(save(false), Ok(true));
    let file = folder.join("id_rsa.pub");
    let line = format!("{}\n", view.public_key);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), line);
    let mode = std::fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::read_dir(&folder).unwrap().count(),
        1,
        "the public file only"
    );
    assert_eq!(save(false), Ok(false), "asks first");
    std::fs::write(&file, b"other\n").unwrap();
    assert_eq!(save(true), Ok(true));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), line);
    let other = entry_id(&s, v, "Wise");
    assert_eq!(
        s.save_ssh_public_key(v, other, f.clone(), false),
        Err(LarsalError::UnknownField)
    );
    s.lock(v).unwrap();
    assert!(file.exists(), "a saved public file stays after the lock");
    no_private_file(&folder);
}

/// E24-S05, Checker 1 (C1-F1), lead ruling (1): an attachment that starts
/// like a public line but holds no key blob. The editor shows New SSH Key on
/// that entry; after the key is made, the detail, the editor public line and
/// Save Public Key (Copy reads the same line) all show the new key.
#[test]
fn e24_s05_c1_public_line_after_new_key_on_an_entry_with_a_broken_public_line() {
    let (s, v, path) = personal("c1-e24-broken-line");
    let wise = entry_id(&s, v, "Wise");
    s.begin_edit(v, wise.clone()).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/c1-e24-broken-src");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("notes.txt"),
        "ssh-ed25519 is the key type the demo server wants\n",
    )
    .unwrap();
    s.attach_file(v, dir.join("notes.txt").to_string_lossy().into_owned())
        .unwrap();
    let before = s.editor(v).unwrap();
    assert!(
        before.ssh.is_none(),
        "the editor shows New SSH Key on this entry (EditorMorePages.swift:167)"
    );
    let view = s
        .new_ssh_key(v, SshKeyKind::Ed25519, "c1@new".into())
        .unwrap();
    let detail = s.entry(v, wise.clone()).unwrap();
    let folder = path.parent().unwrap().join("c1-e24-broken-pub-out");
    let _ = std::fs::remove_dir_all(&folder);
    let saved = s.save_ssh_public_key(
        v,
        view.entry.clone(),
        folder.to_string_lossy().into_owned(),
        false,
    );
    let names: Vec<String> = std::fs::read_dir(&folder)
        .map(|d| {
            d.map(|f| f.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let reopened = s.begin_edit(v, wise.clone()).unwrap();
    s.cancel_edit(v).unwrap();
    assert_eq!(
        detail.ssh.map(|k| k.fingerprint),
        Some(view.fingerprint.clone()),
        "the detail shows the new key"
    );
    assert_eq!(
        reopened.ssh_public_key,
        Some(view.public_key.clone()),
        "the editor shows the new key"
    );
    assert!(
        names.contains(&"id_ed25519.pub".to_owned()),
        "Save Public Key writes the new key file: {names:?}"
    );
    assert_eq!((saved, names.len()), (Ok(true), 1), "{names:?}");
    assert_eq!(
        std::fs::read_to_string(folder.join("id_ed25519.pub")).unwrap(),
        format!("{}\n", view.public_key)
    );
}

/// E24-S04, E24-S05, Checker 1 (C1-F1), lead ruling (1): an entry whose
/// draft holds another public line under another name shows that key, so
/// the editor hides New SSH Key; the Rust call refuses as well, with nothing
/// changed, and the public line is that key with its own comment.
#[test]
fn e24_s04_s05_c1_new_key_on_an_entry_with_another_public_line_is_refused() {
    let (s, v, path) = personal("c1-e24-other-line");
    let wise = entry_id(&s, v, "Wise");
    s.begin_edit(v, wise.clone()).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/c1-e24-src");
    std::fs::create_dir_all(&dir).unwrap();
    let other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcFDq2T71wERCeKk/6BZCGHILdNQmAt+6GVCObXA9mG other@host\n";
    std::fs::write(dir.join("authorized_keys"), other).unwrap();
    s.attach_file(
        v,
        dir.join("authorized_keys").to_string_lossy().into_owned(),
    )
    .unwrap();
    let before = s.editor(v).unwrap();
    assert!(before.ssh.is_some(), "the editor hides New SSH Key");
    assert_eq!(
        before.ssh_public_key.as_deref(),
        Some(other.trim_end()),
        "the line of the key shown, with its own comment"
    );
    for kind in [SshKeyKind::EcdsaP256, SshKeyKind::Ed25519] {
        assert_eq!(
            s.new_ssh_key(v, kind, "c1@new".into()),
            Err(LarsalError::Refused(
                larsal_ffi::edit::MSG_SSH_HAS_KEY.into()
            ))
        );
    }
    let after = s.editor(v).unwrap();
    assert_eq!(after.attachments, before.attachments, "nothing changed");
    assert_eq!(after.ssh_public_key, before.ssh_public_key);
    assert!(s.has_draft(v), "the editor stays open");
    assert_eq!(s.save_status(v).unwrap().changes, 0);
    s.commit_edit(v).unwrap();
    let folder = path.parent().unwrap().join("c1-e24-other-pub-out");
    let _ = std::fs::remove_dir_all(&folder);
    let f = folder.to_string_lossy().into_owned();
    assert_eq!(s.save_ssh_public_key(v, wise, f, false), Ok(true));
    assert_eq!(
        std::fs::read_to_string(folder.join("authorized_keys.pub")).unwrap(),
        other,
        "Save Public Key writes that line under that key name with .pub"
    );
}

/// E24-S05 (lead ruling (1), INT-06.E24.05): the public line, Copy Public
/// Key and Save Public Key give the key the editor shows, in OpenSSH form
/// with its own comment, never the attachment's text: its extra spaces, its
/// carriage return and its second line stay out.
#[test]
fn e24_s05_the_public_line_is_the_shown_key_never_the_attachment_text() {
    let (s, v, path) = personal("e24-shown-line");
    let wise = entry_id(&s, v, "Wise");
    s.begin_edit(v, wise.clone()).unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests/e24-shown-line-src");
    std::fs::create_dir_all(&dir).unwrap();
    let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBcFDq2T71wERCeKk/6BZCGHILdNQmAt+6GVCObXA9mG";
    let text =
        format!("ssh-ed25519  {blob}   other@host  \r\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5 second\n");
    std::fs::write(dir.join("authorized_keys"), &text).unwrap();
    s.attach_file(
        v,
        dir.join("authorized_keys").to_string_lossy().into_owned(),
    )
    .unwrap();
    let line = format!("ssh-ed25519 {blob} other@host");
    assert_eq!(s.editor(v).unwrap().ssh_public_key, Some(line.clone()));
    s.commit_edit(v).unwrap();
    let folder = path.parent().unwrap().join("e24-shown-line-out");
    let _ = std::fs::remove_dir_all(&folder);
    let f = folder.to_string_lossy().into_owned();
    assert_eq!(s.save_ssh_public_key(v, wise, f, false), Ok(true));
    assert_eq!(
        std::fs::read_to_string(folder.join("authorized_keys.pub")).unwrap(),
        format!("{line}\n"),
        "the shown key's line, not the attachment's text"
    );
}
