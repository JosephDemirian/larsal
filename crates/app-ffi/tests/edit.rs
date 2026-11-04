//! E5-S5: the editor and the window's vault changes over the Rust session,
//! on a copy of the Option A Personal demo vault (password in
//! testdata/README.md). Each test names its card rule.

use app_ffi::edit::EditText;
use app_ffi::session::{AppError, Session, UnlockResult};
use app_ffi::views::ListView;
use std::path::PathBuf;
use std::sync::Arc;

/// A fresh copy of the Personal vault, opened and unlocked in a test
/// session (private pasteboard).
fn personal(name: &str) -> (Arc<Session>, u64, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("edit-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.appvault"));
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/option-a-personal.appvault"),
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
        Err(AppError::Refused(_))
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
        Err(AppError::Refused(_))
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
    let wifi = entry_id(&s, v, "Home Wi-Fi");
    assert!(s.wifi_qr(v, wifi).unwrap().size >= 21);
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
        AppError::UnknownEntry
    );
    assert_eq!(
        s.begin_new(v, Some("zz".into())).unwrap_err(),
        AppError::UnknownGroup
    );
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    assert_eq!(
        s.set_password(v, "x".repeat(70_000)).unwrap_err(),
        AppError::TooLong
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
            AppError::UnknownField,
            "{name}"
        );
        assert_eq!(
            s.remove_field(v, name.into()).unwrap_err(),
            AppError::UnknownField,
            "{name}"
        );
    }
    assert!(s.show_version(v, 99).is_err());
    assert!(s.set_icon(v, 69).is_err());
    assert!(s.has_draft(v));
    s.lock(v).unwrap();
    assert_eq!(s.editor(v).unwrap_err(), AppError::Locked);
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
    app_format::document::encode::base64_decode(
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
        Err(AppError::Refused(_))
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

#[test]
fn mod_05_open_save_and_wipe() {
    use std::os::unix::fs::PermissionsExt;
    let (s, v, _) = personal("attach");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let name = "github-recovery-codes.txt".to_owned();
    let app_ffi::edit::OpenAttachment::Opened { path } =
        s.open_attachment(v, name.clone(), false).unwrap()
    else {
        panic!("opened")
    };
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 1229);
    assert!(path.ends_with(".txt") && path.contains("/App/open-attachments/"));
    s.cancel_edit(v).unwrap();
    assert!(
        !std::path::Path::new(&path).exists(),
        "wiped when the editor closes"
    );
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    s.attach_file(v, testdata_file("key-hex64.appkey")).unwrap();
    let app_ffi::edit::OpenAttachment::Opened { path } = s
        .open_attachment(v, "key-hex64.appkey".into(), false)
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
        app_ffi::edit::OpenAttachment::AskFirst
    );
    assert!(matches!(
        s.open_attachment(v, "demo.command".into(), true).unwrap(),
        app_ffi::edit::OpenAttachment::Opened { .. }
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
                matches!(open, app_ffi::edit::OpenAttachment::Opened { .. }),
                "{name}"
            );
        } else {
            assert_eq!(open, app_ffi::edit::OpenAttachment::AskFirst, "{name}");
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
            Err(AppError::UnknownVault),
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
        Err(AppError::UnknownField)
    );
    s.lock(v).unwrap();
    assert_eq!(
        s.open_attachment(v, "x.command".into(), false),
        Err(AppError::Locked)
    );
}

#[test]
fn mod_09_10_ticking_expires_sets_now() {
    let (s, v, _) = personal("expiry");
    s.begin_edit(v, entry_id(&s, v, "GitHub")).unwrap();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    s.set_expiry(v, true, None).unwrap();
    let view = s.editor(v).unwrap();
    assert!(view.expires && (view.expiry - before).abs() <= 2);
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
        app_ffi::edit::OpenAttachment::Opened { path } => std::path::PathBuf::from(path),
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
        Err(AppError::CannotOpen(_))
    ));
    assert!(matches!(
        s.attach_file(v, dir.to_string_lossy().into_owned()),
        Err(AppError::CannotOpen(_))
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
