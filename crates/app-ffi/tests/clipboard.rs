//! E6-S1: Copy through the session (APP-03, SC-01 to SC-03), on a demo
//! vault made here (card APP-03's test vault A). Every session of these
//! tests copies to its own private pasteboard, never the user's clipboard.

use app_core::refs::reference;
use app_crypto::kdf::Host;
use app_crypto::secret::{SecretBytes, SecretString};
use app_ffi::session::{AppError, Session, UnlockResult};
use app_ffi::views::Copied;
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Saved, save};
use app_model::entry::Field;
use app_model::{Argon2Kind, Attachment, Encryption, Entry, Group, Kdf, Time, Uuid, Vault};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

const MAIL: Uuid = Uuid([0x11; 16]);
const EMPTY: Uuid = Uuid([0x22; 16]);
const REF: Uuid = Uuid([0x33; 16]);
const CODE: Uuid = Uuid([0x55; 16]);
const BAD_CODE: Uuid = Uuid([0x66; 16]);
const SSH: Uuid = Uuid([0x77; 16]);
/// A demo OpenSSH public key made for these tests (`ssh-keygen -t ed25519`;
/// the private half was deleted) and the fingerprint `ssh-keygen -lf` prints.
const DEMO_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINK5iEzW23QMLuDKjxJ9fy8IKwFJZn28vGLGSfevrhLu demo@example.com\n";
const DEMO_FINGERPRINT: &str = "SHA256:pUh1sFqh6s6r+cdihtf8oMgAat4yHnr6XaCk58aahb8";
const TEXT: &str = "public.utf8-plain-text";
const CONCEALED: &str = "org.nspasteboard.ConcealedType";
const TRANSIENT: &str = "org.nspasteboard.TransientType";

fn hex(id: Uuid) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn entry(id: Uuid, fields: &[(&str, &str, bool)]) -> Entry {
    let mut e = Entry::new(id, Time::from_unix(1_700_000_000).unwrap());
    for (name, value, protected) in fields {
        let field = Field {
            value: SecretString::new((*value).to_owned()),
            protected: *protected,
        };
        e.set_field((*name).to_owned(), field);
    }
    e
}

/// Demo vault A of card APP-03 (password `demo-master-A`), written once per
/// run with a fast KDF.
fn vault_a() -> &'static str {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| {
        let now = Time::from_unix(1_700_000_000).unwrap();
        let mut root = Group::new(Uuid([0x01; 16]), "Demo".to_owned(), now);
        root.entries.push(entry(
            MAIL,
            &[
                ("Title", "Demo Mail", false),
                ("UserName", "demo@example.com", false),
                ("Password", "demo-pass-1", true),
                ("URL", "https://mail.example.com", false),
                ("Notes", "demo note", false),
                ("PIN", "4321", true),
            ],
        ));
        root.entries.push(entry(
            EMPTY,
            &[("Title", "Empty Demo", false), ("Password", "", true)],
        ));
        root.entries.push(entry(
            REF,
            &[
                ("Title", "Ref Demo", false),
                ("UserName", &reference('U', MAIL), false),
            ],
        ));
        // The RFC 6238 demo secret "12345678901234567890" (FEA-04).
        root.entries.push(entry(
            CODE,
            &[
                ("Title", "Code Demo", false),
                (
                    "otp",
                    "otpauth://totp/Demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    true,
                ),
            ],
        ));
        root.entries.push(entry(
            BAD_CODE,
            &[
                ("Title", "Bad Code Demo", false),
                ("otp", "otpauth://totp/Demo?secret=not-base32!", true),
            ],
        ));
        let mut ssh = entry(SSH, &[("Title", "Server Demo", false)]);
        ssh.attachments.push(Attachment {
            name: "id_ed25519.pub".to_owned(),
            data: Arc::new(SecretBytes::new(DEMO_KEY.as_bytes().to_vec())),
        });
        root.entries.push(ssh);
        let mut vault = Vault::new(root, now);
        vault.encryption = Encryption {
            kdf: Kdf::Argon2 {
                kind: Argon2Kind::Id,
                iterations: 2,
                memory_kib: 1024,
                lanes: 1,
            },
            ..Encryption::default()
        };
        let password = SecretString::new("demo-master-A".to_owned());
        let credentials = Credentials {
            password: Some(&password),
            key_file: None,
            hardware_key: None,
        };
        let mut host = Host {
            physical_memory: 8 << 30,
            logical_processors: 4,
            argon2_record: None,
            aes_record: None,
        };
        let Ok(Saved::File(saved)) = save(
            &vault,
            &credentials,
            None,
            &mut host,
            &Limits::DEFAULT,
            None,
        ) else {
            panic!("save demo vault A");
        };
        // Cargo's temp folder for tests; written under a per-run name and
        // moved into place, so a parallel run never reads half a file.
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("clipboard-vault-a.appvault");
        let part = path.with_extension(std::process::id().to_string());
        std::fs::write(&part, &saved.bytes).unwrap();
        std::fs::rename(&part, &path).unwrap();
        path.to_string_lossy().into_owned()
    })
}

/// A test session (private pasteboard) with vault A open and unlocked.
fn unlocked() -> (Arc<Session>, u64) {
    let session = Session::new();
    let id = session.open(vault_a().to_owned()).unwrap();
    assert_eq!(
        session.unlock(id, Some("demo-master-A".into()), None),
        Ok(UnlockResult::Unlocked)
    );
    (session, id)
}

/// The pasteboard's text when it holds exactly one item with both markers;
/// `None` when it is empty.
fn pasted(session: &Session) -> Option<String> {
    let items = session.clipboard().peek();
    let [item] = items.as_slice() else {
        assert!(items.is_empty(), "one item or none");
        return None;
    };
    let mut types: Vec<&str> = item.iter().map(|(k, _)| k.as_str()).collect();
    types.sort_unstable();
    if types == [TEXT] {
        // Written by "another app" in these tests: no markers.
        return Some(String::from_utf8(item[0].1.clone()).unwrap());
    }
    assert_eq!(types, [CONCEALED, TRANSIENT, TEXT], "markers (SC-02)");
    let (_, text) = item.iter().find(|(k, _)| k == TEXT).unwrap();
    Some(String::from_utf8(text.clone()).unwrap())
}

fn copied(label: &str) -> Copied {
    Copied {
        label: label.to_owned(),
        seconds: 10,
        empty: false,
    }
}

/// APP-03.1 T01, APP-03.21 T41, APP-03.2 T04: each field lands on the
/// pasteboard with both markers; Swift gets only the label and seconds.
#[test]
fn app_03_copy_fields() {
    let (session, id) = unlocked();
    for (field, label, value) in [
        ("UserName", "Username", "demo@example.com"),
        ("Password", "Password", "demo-pass-1"),
        ("URL", "URL", "https://mail.example.com"),
        ("Notes", "Notes", "demo note"),
        ("PIN", "PIN", "4321"),
        ("Title", "Title", "Demo Mail"),
    ] {
        let answer = session.copy_field(id, hex(MAIL), field.into()).unwrap();
        assert_eq!(answer, copied(label));
        assert!(
            !format!("{answer:?}").contains(value),
            "no value in the answer"
        );
        assert_eq!(pasted(&session).as_deref(), Some(value), "{field}");
    }
}

/// APP-03.3 T06: a field reference is copied resolved in full (MOD-08.26).
#[test]
fn app_03_3_copy_resolves_references() {
    let (session, id) = unlocked();
    session.copy_field(id, hex(REF), "UserName".into()).unwrap();
    assert_eq!(pasted(&session).as_deref(), Some("demo@example.com"));
}

/// APP-03.5 T09: an empty value copies nothing and leaves the user's text.
#[test]
fn app_03_5_empty_value_copies_nothing() {
    let (session, id) = unlocked();
    session.clipboard().write_as_other_app("user text");
    let answer = session
        .copy_field(id, hex(EMPTY), "Password".into())
        .unwrap();
    assert_eq!(
        answer,
        Copied {
            label: "Password".into(),
            seconds: 0,
            empty: true
        }
    );
    assert_eq!(pasted(&session).as_deref(), Some("user text"));
}

/// APP-03.15 T27, T29, T30, SC-03, AT-D03: lock, lock-all, close and the
/// quit call clear App's copy, and only App's copy.
#[test]
fn app_03_15_lock_close_and_quit_clear() {
    let (session, id) = unlocked();
    let copy = || {
        session
            .copy_field(id, hex(MAIL), "Password".into())
            .unwrap();
        assert_eq!(pasted(&session).as_deref(), Some("demo-pass-1"));
    };
    copy();
    session.clear_clipboard();
    assert_eq!(pasted(&session), None, "quit");
    copy();
    session.lock_all();
    assert_eq!(pasted(&session), None, "lock all");
    session
        .unlock(id, Some("demo-master-A".into()), None)
        .unwrap();
    copy();
    session.lock(id).unwrap();
    assert_eq!(pasted(&session), None, "lock");
    // T30: content another app wrote after the copy stays.
    session
        .unlock(id, Some("demo-master-A".into()), None)
        .unwrap();
    copy();
    session.clipboard().write_as_other_app("other");
    session.lock(id).unwrap();
    assert_eq!(pasted(&session).as_deref(), Some("other"));
    session
        .unlock(id, Some("demo-master-A".into()), None)
        .unwrap();
    copy();
    session.close(id).unwrap();
    assert_eq!(pasted(&session), None, "close");
}

/// APP-03.15 T27: a lock of another vault clears the copy of this one.
#[test]
fn app_03_15_lock_of_another_vault_clears() {
    let (session, a) = unlocked();
    let b = session
        .open(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/password-only.appvault")
                .to_string_lossy()
                .into_owned(),
        )
        .unwrap();
    session.copy_field(a, hex(MAIL), "Password".into()).unwrap();
    session.lock(b).unwrap();
    assert_eq!(pasted(&session), None);
    assert!(session.entry(a, hex(MAIL)).is_ok(), "A stays unlocked");
}

/// AT-E03: hostile arguments give typed errors and copy nothing.
#[test]
fn at_e03_copy_refuses_hostile_arguments() {
    let (session, id) = unlocked();
    session.clipboard().write_as_other_app("user text");
    for (entry, field, want) in [
        (hex(MAIL), "otp".to_owned(), AppError::UnknownField),
        (
            hex(MAIL),
            "No such field".to_owned(),
            AppError::UnknownField,
        ),
        (hex(MAIL), "a".repeat(1 << 20), AppError::TooLong),
        (
            "+".repeat(32),
            "Password".to_owned(),
            AppError::UnknownEntry,
        ),
        (
            hex(Uuid([0x44; 16])),
            "Password".to_owned(),
            AppError::UnknownEntry,
        ),
    ] {
        assert_eq!(session.copy_field(id, entry, field), Err(want));
    }
    assert_eq!(
        session.copy_field(999, hex(MAIL), "Password".into()),
        Err(AppError::UnknownVault)
    );
    session.lock(id).unwrap();
    assert_eq!(
        session.copy_field(id, hex(MAIL), "Password".into()),
        Err(AppError::Locked)
    );
    assert_eq!(pasted(&session).as_deref(), Some("user text"));
}

/// APP-03.1 `copy.totp`, FEA-04: the code of this moment, computed in Rust,
/// without the display space, lands on the pasteboard with both markers;
/// Swift gets only the label. A lock clears it like any copy.
#[test]
fn app_03_copy_code() {
    let (session, id) = unlocked();
    let shown = || {
        let view = session.totp(id, hex(CODE)).unwrap().unwrap();
        view.code
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<String>()
    };
    let before = shown();
    let answer = session.copy_code(id, hex(CODE)).unwrap();
    let after = shown();
    assert_eq!(answer, copied("One-time password"));
    let text = pasted(&session).unwrap();
    assert!(text == before || text == after, "the current code");
    assert_eq!(text.len(), 6, "no display space");
    assert!(
        !format!("{answer:?}").contains(&text),
        "no code in the answer"
    );
    session.lock(id).unwrap();
    assert_eq!(pasted(&session), None, "lock clears it (APP-03.15)");
}

/// The SSH key's fingerprint, as the detail shows it and as `ssh-keygen -lf`
/// prints it, lands on the pasteboard with both markers.
#[test]
fn app_03_copy_fingerprint() {
    let (session, id) = unlocked();
    let answer = session.copy_fingerprint(id, hex(SSH)).unwrap();
    assert_eq!(answer, copied("Fingerprint"));
    assert_eq!(pasted(&session).as_deref(), Some(DEMO_FINGERPRINT));
    let shown = session.entry(id, hex(SSH)).unwrap().ssh.unwrap();
    assert_eq!(shown.fingerprint, DEMO_FINGERPRINT);
}

/// AT-E03, APP-03.4: hostile or wrong arguments give typed errors and copy
/// nothing; an entry without a valid one-time password or SSH key has
/// nothing to copy.
#[test]
fn at_e03_copy_code_and_fingerprint_refuse_hostile_arguments() {
    type Call = fn(&Session, u64, String) -> Result<Copied, AppError>;
    let (session, id) = unlocked();
    session.clipboard().write_as_other_app("user text");
    let calls: [(Call, Uuid); 2] = [(Session::copy_code, CODE), (Session::copy_fingerprint, SSH)];
    for (call, good) in calls {
        for (entry, want) in [
            (hex(MAIL), AppError::UnknownField),
            (String::new(), AppError::UnknownEntry),
            ("+".repeat(32), AppError::UnknownEntry),
            ("a".repeat(1 << 20), AppError::UnknownEntry),
            (hex(Uuid([0x44; 16])), AppError::UnknownEntry),
        ] {
            assert_eq!(call(&session, id, entry), Err(want));
        }
        assert_eq!(call(&session, 999, hex(good)), Err(AppError::UnknownVault));
    }
    assert_eq!(
        session.copy_code(id, hex(BAD_CODE)),
        Err(AppError::UnknownField)
    );
    assert_eq!(session.copy_code(id, hex(SSH)), Err(AppError::UnknownField));
    assert_eq!(
        session.copy_fingerprint(id, hex(CODE)),
        Err(AppError::UnknownField)
    );
    session.lock(id).unwrap();
    for (call, good) in calls {
        assert_eq!(call(&session, id, hex(good)), Err(AppError::Locked));
    }
    assert_eq!(pasted(&session).as_deref(), Some("user text"));
}
