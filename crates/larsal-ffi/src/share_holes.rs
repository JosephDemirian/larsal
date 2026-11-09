//! E11-S6: the shared-group holes the Red team found on e5c8c23, as real
//! tests through the session's own passes (RT-1, RT-2, RT-3, RT-5 to RT-8,
//! E11S6-V-01, F-278). Demo vaults and demo passwords only.

use crate::bridge_vaults::bridge_door;
use crate::larsal_settings::{LarsalSetting, LarsalSettingValue};
use crate::saving::{DiskChoice, DiskEvent};
use crate::session::{LarsalError, Session, UnlockResult};
use crate::share::tests::*;
use crate::share::{ShareLevel, guarded, share_path_shown};
use crate::share_edit::{ShareChange, ShareMode, ShareState, ShareWarning};
use crate::test_dir::TempDir;
use larsal_browser::Changed;
use larsal_core::storage::{self, DEFAULT_BACKUP_PATTERN};
use larsal_crypto::kdf::Host;
use larsal_format::Saved;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::share_item;
use larsal_model::{DeletedObject, Group, Time, Vault};
use larsal_share::{container, run};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const T2: Time = Time(63_907_920_000);
const KEY_BYTES: &[u8] = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const EXPORT: (bool, bool) = (false, true);
const SYNC: (bool, bool) = (true, true);

/// MI08-26.
fn left_alone(path: &str) -> String {
    format!(
        "{path}: export failed. Another file is already there, and Larsal did not write it for this share, so it was left alone. Choose another file or move that one."
    )
}

/// MI08-27.
fn key_refused(path: &str) -> String {
    format!("{path}: export failed. It is a vault's key file, so it was left alone.")
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: None,
    }
}

fn opens(p: &Path, password: &str) -> bool {
    read(p, password).is_ok()
}

/// Two changes and two saves with the share running: each save of the vault
/// itself succeeds, whatever the share does.
fn two_saves(s: &Session, v: u64) {
    for n in ["V2", "V3"] {
        change(s, v, |m| m.meta.name = n.into());
        let st = s.save(v).unwrap();
        assert_eq!(st.failure, None, "the vault's own save");
        s.share_wait(v);
    }
}

/// V under the main password and `key` at `file`.
fn write_with_key(file: &Path, vault: &Vault, key: &[u8]) {
    let k =
        larsal_format::keyfile::read_key_file(std::io::Cursor::new(key.to_vec()), &Limits::DEFAULT)
            .unwrap();
    let pw = secret(MAIN);
    let c = Credentials {
        password: Some(&pw),
        key_file: Some(&k),
        ..Credentials::default()
    };
    let Saved::File(f) =
        larsal_format::save(vault, &c, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("a cheap KDF")
    };
    std::fs::write(file, &f.bytes).unwrap();
}

/// Opens V at `file` with its key file in a session where its shares are
/// approved, as the Approve door does.
fn unlock_with_key(s: &Session, file: &Path, key: &Path, vault: &Vault) -> u64 {
    for share in run::shares(vault, Some(file)) {
        s.settings.approve_share(share.approval(vault));
    }
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    let key = key.to_string_lossy().into_owned();
    assert_eq!(
        s.unlock(v, Some(MAIN.into()), Some(key)).unwrap(),
        UnlockResult::Unlocked
    );
    s.share_wait(v);
    v
}

/// The next unlock with the main password and the key file works.
fn key_still_works(file: &Path, key: &Path) {
    let again = session(false);
    let w = again.open(file.to_string_lossy().into_owned()).unwrap();
    let key = key.to_string_lossy().into_owned();
    assert_eq!(
        again.unlock(w, Some(MAIN.into()), Some(key)).unwrap(),
        UnlockResult::Unlocked,
        "the vault no longer opens"
    );
}

/// RT-1, High: an approved Export or Synchronize share on the vault's own key
/// file. The file stays, the share says why, the vault saves and opens again.
#[test]
fn e11s6_rt1_export_and_synchronize_never_replace_the_vaults_key_file() {
    for (tag, mode) in [("export", EXPORT), ("sync", SYNC)] {
        let dir = TempDir::new(&format!("e11s6-key-{tag}"));
        let (file, key) = (dir.join("v.larsalvault"), dir.join("v.larsalkey"));
        std::fs::write(&key, KEY_BYTES).unwrap();
        let mut vault = base();
        set_share(team(&mut vault), settings(mode.0, mode.1, "v.larsalkey"));
        write_with_key(&file, &vault, KEY_BYTES);
        let s = session(false);
        let v = unlock_with_key(&s, &file, &key, &vault);
        assert!(s.share_paths(v).unwrap().is_empty(), "{tag}: watched");
        assert_eq!(
            s.share_edit(v, hex(id(0x20))).unwrap().warning,
            Some(ShareWarning::KeyFile)
        );
        s.share_edit_cancel(v).unwrap();
        two_saves(&s, v);
        assert_eq!(std::fs::read(&key).unwrap(), KEY_BYTES, "{tag}: replaced");
        assert_eq!(
            banner(&s, v),
            Some((ShareLevel::Error, vec![key_refused("v.larsalkey")])),
            "{tag}"
        );
        drop(s);
        key_still_works(&file, &key);
    }
}

/// RT-1: an Import share on the key file never writes, and is not read either.
#[test]
fn e11s6_rt1_an_import_share_on_the_key_file_does_not_run() {
    let dir = TempDir::new("e11s6-key-import");
    let (file, key) = (dir.join("x.larsalvault"), dir.join("x.larsalkey"));
    std::fs::write(&key, KEY_BYTES).unwrap();
    let mut vault = base();
    set_share(team(&mut vault), settings(true, false, "x.larsalkey"));
    write_with_key(&file, &vault, KEY_BYTES);
    let s = session(false);
    let v = unlock_with_key(&s, &file, &key, &vault);
    assert!(s.share_paths(v).unwrap().is_empty());
    two_saves(&s, v);
    assert_eq!(std::fs::read(&key).unwrap(), KEY_BYTES);
    assert_eq!(news(&s, v), None, "not read, so no line");
}

/// RT-1: the planted route: the share arrives by a change on disk and takes one
/// Approve. The file stays.
#[test]
fn e11s6_rt1_a_planted_key_file_share_and_one_approve_change_nothing() {
    let dir = TempDir::new("e11s6-key-plant");
    let (file, key) = (dir.join("v.larsalvault"), dir.join("v.larsalkey"));
    std::fs::write(&key, KEY_BYTES).unwrap();
    write_with_key(&file, &base(), KEY_BYTES);
    let s = session(false);
    let v = unlock_with_key(&s, &file, &key, &base());
    s.add_group(v, None, "Local".into(), 48, None).unwrap();
    let mut other = base();
    set_share(team(&mut other), settings(false, true, "v.larsalkey"));
    team(&mut other).times.last_modification = T2;
    write_with_key(&file, &other, KEY_BYTES);
    s.check_disk(v).unwrap();
    assert_eq!(
        s.resolve_disk(v, DiskChoice::Merge).unwrap(),
        DiskEvent::Reloaded
    );
    s.share_wait(v);
    let label = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
    assert_eq!(label.state, ShareState::Waiting);
    // The sheet says so before the click.
    let block = s.share_block(v, hex(id(0x20))).unwrap().unwrap();
    assert!(block.contains("key file"), "{block}");
    s.approve_share_shown(v, label.group, label.mode, label.full_path)
        .unwrap();
    s.share_wait(v);
    two_saves(&s, v);
    assert_eq!(std::fs::read(&key).unwrap(), KEY_BYTES);
    assert_eq!(
        banner(&s, v),
        Some((ShareLevel::Error, vec![key_refused("v.larsalkey")]))
    );
    drop(s);
    key_still_works(&file, &key);
}

/// RT-1: typed or chosen in the group editor: the editor warns, Save approves
/// what the user typed, and the export is refused all the same.
#[test]
fn e11s6_rt1_the_key_file_typed_in_the_group_editor_is_refused() {
    let dir = TempDir::new("e11s6-key-editor");
    let (file, key) = (dir.join("v.larsalvault"), dir.join("v.larsalkey"));
    std::fs::write(&key, KEY_BYTES).unwrap();
    write_with_key(&file, &base(), KEY_BYTES);
    let s = session(false);
    let v = unlock_with_key(&s, &file, &key, &base());
    s.share_edit(v, hex(id(0x20))).unwrap();
    s.share_edit_change(
        v,
        ShareChange::Mode {
            mode: ShareMode::Export,
        },
    )
    .unwrap();
    s.share_edit_change(
        v,
        ShareChange::Path {
            path: "v.larsalkey".into(),
        },
    )
    .unwrap();
    let view = s.share_edit_password(v, SHARE.into()).unwrap();
    assert_eq!(view.warning, Some(ShareWarning::KeyFile));
    s.share_edit_save(v).unwrap();
    two_saves(&s, v);
    assert_eq!(std::fs::read(&key).unwrap(), KEY_BYTES);
    assert_eq!(
        banner(&s, v),
        Some((ShareLevel::Error, vec![key_refused("v.larsalkey")]))
    );
    drop(s);
    key_still_works(&file, &key);
}

/// RT-1 with item 2: every spelling and every link of the key file is the key
/// file, while the file is there and after it went.
#[test]
fn e11s6_rt1_every_spelling_of_the_key_file_is_the_key_file() {
    for (n, (name, text)) in [
        ("v.larsalkey", "V.LARSALKEY"),
        ("v.larsalkey", "v.lar\u{17f}alkey"),
        ("v.larsalkey", "./v.larsalkey"),
        ("v.larsalkey", "link.larsalkey"),
        ("v.larsalkey", "hard.larsalkey"),
        ("k\u{e9}y.larsalkey", "ke\u{301}y.larsalkey"),
        ("\u{212a}.larsalkey", "k.larsalkey"),
        ("gross.larsalkey", "gro\u{df}.larsalkey"),
    ]
    .into_iter()
    .enumerate()
    {
        for key_there in [true, false] {
            let dir = TempDir::new(&format!("e11s6-key-spell-{n}-{key_there}"));
            let (file, key) = (dir.join("v.larsalvault"), dir.join(name));
            std::fs::write(&key, KEY_BYTES).unwrap();
            if text == "link.larsalkey" {
                symlink(&key, dir.join(text)).unwrap();
            } else if text == "hard.larsalkey" {
                std::fs::hard_link(&key, dir.join(text)).unwrap();
            }
            let mut vault = base();
            set_share(team(&mut vault), settings(false, true, text));
            write_with_key(&file, &vault, KEY_BYTES);
            let s = session(false);
            let v = unlock_with_key(&s, &file, &key, &vault);
            if !key_there {
                if text == "link.larsalkey" || text == "hard.larsalkey" {
                    continue;
                }
                std::fs::remove_file(&key).unwrap();
            }
            two_saves(&s, v);
            let msg = (key_there, name, text);
            assert_eq!(
                banner(&s, v),
                Some((ShareLevel::Error, vec![key_refused(text)])),
                "{msg:?}"
            );
            if key_there {
                assert_eq!(std::fs::read(&key).unwrap(), KEY_BYTES, "{msg:?}");
            } else {
                assert!(!dir.join(text).exists(), "{msg:?}: a file was made");
            }
        }
    }
}

/// RT-1: a key file can be any file, so one that opens as this share's
/// container is refused by what it is, not by what it holds; also the
/// remembered key file of a vault not open in Larsal.
#[test]
fn e11s6_rt1_a_key_file_that_is_a_container_is_still_the_key_file() {
    let dir = TempDir::new("e11s6-key-container");
    let (file, key) = (dir.join("v.larsalvault"), dir.join("v.larsalkey"));
    publish(&key, &member());
    let bytes = std::fs::read(&key).unwrap();
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "v.larsalkey"));
    write_with_key(&file, &vault, &bytes);
    let s = session(false);
    let v = unlock_with_key(&s, &file, &key, &vault);
    two_saves(&s, v);
    assert_eq!(std::fs::read(&key).unwrap(), bytes);
    assert_eq!(
        banner(&s, v),
        Some((ShareLevel::Error, vec![key_refused("v.larsalkey")]))
    );

    // Remembered for a vault not open here (APP-01.16): relative to that vault.
    let dir = TempDir::new("e11s6-key-remembered");
    let (file, key) = (dir.join("v.larsalvault"), dir.join("closed.larsalkey"));
    publish(&key, &member());
    let bytes = std::fs::read(&key).unwrap();
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "closed.larsalkey"));
    let s = session(false);
    s.save_settings(vec![LarsalSetting {
        key: "recent.remember_keys".into(),
        value: LarsalSettingValue::Flag { on: true },
    }])
    .unwrap();
    s.settings.note_keys(
        &dir.join("closed.larsalvault"),
        Some("closed.larsalkey".into()),
        None,
    );
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    two_saves(&s, v);
    assert_eq!(std::fs::read(&key).unwrap(), bytes);
    assert_eq!(
        banner(&s, v),
        Some((ShareLevel::Error, vec![key_refused("closed.larsalkey")]))
    );
}

/// The same cause as RT-1: a vault file that is not open in Larsal, and a hard
/// link to a locked vault that is. Neither gets the container.
#[test]
fn e11s6_rt1_a_vault_not_open_in_larsal_is_left_alone() {
    let dir = TempDir::new("e11s6-closed");
    let (file, w, closed) = (
        dir.join("v.larsalvault"),
        dir.join("w.larsalvault"),
        dir.join("closed.larsalvault"),
    );
    write(&w, &base(), MAIN);
    write(&closed, &base(), "demo-closed");
    let hard = dir.join("wh.larsalvault");
    std::fs::hard_link(&w, &hard).unwrap();
    for text in ["wh.larsalvault", "closed.larsalvault"] {
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, text));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        s.open(w.to_string_lossy().into_owned()).unwrap();
        unlock(&s, v);
        two_saves(&s, v);
        assert!(opens(&w, MAIN), "{text}: W");
        assert!(opens(&closed, "demo-closed"), "{text}: the closed vault");
        assert!(!opens(&closed, SHARE), "{text}: the closed vault");
        assert!(opens(&file, MAIN), "{text}: V");
        let want = (text == "closed.larsalvault")
            .then(|| (ShareLevel::Error, vec![left_alone("closed.larsalvault")]));
        assert_eq!(banner(&s, v), want, "{text}");
        s.lock_all();
    }
}

/// INT-08.34: anything at the path that is not this share's: a plain file, a
/// link (its target stays too), a folder, a FIFO. The vault still saves, and
/// the share tells why every time.
#[test]
fn e11s6_rt1_odd_things_at_the_path_are_left_alone() {
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
    type Plant = fn(&Path);
    let plants: [(&str, Plant); 4] = [
        ("plain", |p| {
            std::fs::write(p, "the user's own text").unwrap()
        }),
        ("link", |p| {
            let victim = p.with_file_name("victim.txt");
            std::fs::write(&victim, "victim").unwrap();
            symlink(&victim, p).unwrap();
        }),
        ("folder", |p| {
            std::fs::create_dir(p).unwrap();
            std::fs::write(p.join("inside.txt"), "inside").unwrap();
        }),
        ("fifo", |p| {
            let made = std::process::Command::new("/usr/bin/mkfifo")
                .arg(p)
                .status()
                .unwrap();
            assert!(made.success());
        }),
    ];
    for (what, plant) in plants {
        let dir = TempDir::new(&format!("e11s6-odd-{what}"));
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        plant(&path);
        let before = std::fs::symlink_metadata(&path).unwrap().ino_and_len();
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        two_saves(&s, v);
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().ino_and_len(),
            before,
            "{what}"
        );
        assert_eq!(
            banner(&s, v),
            Some((ShareLevel::Error, vec![left_alone("team.larsalvault")])),
            "{what}"
        );
        assert!(opens(&file, MAIN), "{what}: V");
        match what {
            "plain" => assert_eq!(std::fs::read(&path).unwrap(), b"the user's own text"),
            "link" => assert_eq!(
                std::fs::read(path.with_file_name("victim.txt")).unwrap(),
                b"victim"
            ),
            "folder" => assert!(path.join("inside.txt").exists()),
            _ => {}
        }
    }
}

/// What the file is, as a look can compare it.
trait Identity {
    fn ino_and_len(&self) -> (u64, u64);
}

impl Identity for std::fs::Metadata {
    fn ino_and_len(&self) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        (self.ino(), self.len())
    }
}

/// INT-08.17 stays: repeat exports replace the share's own file, a container
/// the other side rewrote is kept in the loop, and the record of the last
/// write covers a change of the share password, which the file itself cannot.
#[test]
fn e11s6_rt1_repeat_exports_and_the_other_sides_rewrite_still_work() {
    let dir = TempDir::new("e11s6-repeat");
    let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
    let s = session(false);
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    let exported = || {
        Some((
            ShareLevel::Success,
            vec!["team.larsalvault: exported.".to_owned()],
        ))
    };
    two_saves(&s, v);
    assert_eq!(banner(&s, v), exported());
    let first = std::fs::read(&path).unwrap();
    assert!(opens(&path, SHARE));
    two_saves(&s, v);
    assert_ne!(std::fs::read(&path).unwrap(), first, "not written again");
    assert_eq!(banner(&s, v), exported());
    // The other side rewrites it under the share key.
    publish(&path, &member());
    two_saves(&s, v);
    assert_eq!(banner(&s, v), exported());
    assert_eq!(
        read(&path, SHARE).unwrap().root.entries.len(),
        2,
        "this vault's Team"
    );
    // A new share password: the file there still opens only with the old one.
    s.share_edit(v, hex(id(0x20))).unwrap();
    s.share_edit_password(v, "demo-share-2".into()).unwrap();
    s.share_edit_save(v).unwrap();
    two_saves(&s, v);
    assert_eq!(banner(&s, v), exported());
    assert!(opens(&path, "demo-share-2") && !opens(&path, SHARE));
    // The record stays across a lock.
    s.lock(v).unwrap();
    unlock(&s, v);
    two_saves(&s, v);
    assert_eq!(banner(&s, v), exported());
    // A file that is not the record and does not open: left alone.
    let other = dir.join("other.larsalvault");
    publish(&other, &member());
    std::fs::rename(&other, &path).unwrap();
    two_saves(&s, v);
    assert_eq!(
        banner(&s, v),
        Some((ShareLevel::Error, vec![left_alone("team.larsalvault")]))
    );
    assert!(opens(&path, SHARE), "the other side's file stays");
}

/// INT-08.34: what the look saw must still be there at the rename. A file put
/// at the path after the look, or a container changed after it, stays.
#[test]
fn e11s6_rt1_a_file_changed_after_the_look_is_left_alone() {
    for container_first in [false, true] {
        let dir = TempDir::new(&format!("e11s6-race-{container_first}"));
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        if container_first {
            publish(&path, &member());
        }
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let target = path.clone();
        s.with_share(v, |slot| {
            slot.share.before_write = Some(Box::new(move |_: &Session| {
                std::fs::write(&target, "written after the look").unwrap();
            }));
        })
        .unwrap();
        change(&s, v, |m| m.meta.name = "V2".into());
        assert_eq!(s.save(v).unwrap().failure, None);
        s.share_wait(v);
        assert_eq!(std::fs::read(&path).unwrap(), b"written after the look");
        let line = banner(&s, v).unwrap().1.remove(0);
        assert!(line.contains("did not write it"), "{line}");
    }
}

/// The Approve sheet's notice (INT-08.31, INT-08.34): nothing for an empty path
/// or this share's own file, else the reason, before the click.
#[test]
fn e11s6_rt1_the_approve_sheet_says_what_will_be_refused() {
    let dir = TempDir::new("e11s6-block");
    let (file, path, other) = (
        dir.join("v.larsalvault"),
        dir.join("team.larsalvault"),
        dir.join("other.larsalvault"),
    );
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
    let s = session(false);
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    let block = |s: &Session| s.share_block(v, hex(id(0x20))).unwrap();
    assert_eq!(block(&s), None, "nothing there");
    two_saves(&s, v);
    assert_eq!(block(&s), None, "this share's own file");
    std::fs::write(&path, "text").unwrap();
    assert!(
        block(&s)
            .unwrap()
            .starts_with("A file is already at this path.")
    );
    // An import never replaces anything.
    change(&s, v, |m| {
        set_share(team(m), settings(true, false, "team.larsalvault"));
    });
    assert_eq!(block(&s), None, "import");
    change(&s, v, |m| {
        set_share(team(m), settings(false, true, "v.larsalvault"));
    });
    assert!(
        block(&s)
            .unwrap()
            .contains("the file of a vault open in Larsal")
    );
    change(&s, v, |m| {
        set_share(team(m), settings(false, true, &other.to_string_lossy()));
    });
    assert_eq!(block(&s), None, "nothing there");
    assert_eq!(
        s.share_block(v, hex(id(0x7F))),
        Err(LarsalError::UnknownGroup)
    );
}

/// The spellings of item 2: the vault's stem, a spelling of its backup's name,
/// and whether this Mac's file system takes them for one file.
const SPELLINGS: &[(&str, &str, bool)] = &[
    ("v", "v.old.lar\u{17f}alvault", true),
    ("v", "V.OLD.LARSALVAULT", true),
    ("v\u{e9}", "ve\u{301}.old.larsalvault", true),
    ("ve\u{301}", "v\u{e9}.old.larsalvault", true),
    ("\u{212a}ey", "key.old.larsalvault", true),
    ("key", "\u{212a}EY.old.larsalvault", true),
    ("i", "\u{131}.old.larsalvault", false),
    ("i", "\u{130}.old.larsalvault", false),
    ("i\u{307}", "\u{130}.old.larsalvault", true),
    ("\u{131}", "I.old.larsalvault", false),
    ("gross", "gro\u{df}.old.larsalvault", true),
    ("gro\u{df}", "GRO\u{1e9e}.old.larsalvault", true),
    ("v\u{e9}\u{df}", "VE\u{301}SS.OLD.LAR\u{17f}ALVAULT", true),
    ("v", "v.old.larsalvault\u{200d}", false),
    ("v", "v\u{202e}.old.larsalvault", false),
];

/// E11S6-V-01 and RT-3, on a real APFS folder: for every spelling, with the
/// target absent and with it there, the guards answer what the file system
/// does. The table's own truth is taken from the folder, so it cannot drift.
/// `old_copies` feeds a delete: it lists a real second spelling, never a name
/// the file system keeps apart.
#[test]
fn e11s6_item2_every_spelling_compares_as_the_file_system_does() {
    let dir = TempDir::new("e11s6-spell");
    let home = dir.join("home");
    for (n, (stem, spelled, one)) in SPELLINGS.iter().enumerate() {
        let sub = dir.join(format!("{n}"));
        std::fs::create_dir_all(&sub).unwrap();
        let (file, backup, alias) = (
            sub.join(format!("{stem}.larsalvault")),
            sub.join(format!("{stem}.old.larsalvault")),
            sub.join(spelled),
        );
        std::fs::write(&file, b"demo").unwrap();
        let open = std::slice::from_ref(&file);
        // Absent: only the compare of names can tell.
        assert_eq!(guarded(&alias, open, ""), *one, "absent {spelled:?}");
        assert_eq!(storage::same_entry(&alias, &backup), *one, "{spelled:?}");
        // There: this folder says what is true.
        std::fs::write(&backup, b"backup").unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&alias).is_ok(),
            *one,
            "the table is wrong for {spelled:?}"
        );
        assert_eq!(guarded(&alias, open, ""), *one, "there {spelled:?}");
        assert_eq!(storage::same_entry(&alias, &backup), *one, "{spelled:?}");
        // The file on disk under the second spelling.
        std::fs::remove_file(&backup).unwrap();
        std::fs::write(&alias, b"backup").unwrap();
        assert_eq!(guarded(&alias, open, ""), *one, "on disk {spelled:?}");
        let real = storage::real_path(&file);
        let copies = storage::old_copies(DEFAULT_BACKUP_PATTERN, &real, &home, None);
        assert_eq!(copies.len(), usize::from(*one), "{spelled:?}: {copies:?}");
    }
    // Vaults too: the open vault's own name, its file gone.
    let gone = dir.join("v\u{e9}.larsalvault");
    assert!(guarded(
        &dir.join("VE\u{301}.lar\u{17f}alvault"),
        std::slice::from_ref(&gone),
        ""
    ));
}

/// F-269's residual through the real passes (RT-3): the default backup's name in
/// a second spelling, backups off and on, a file there first or not. The backup
/// stays the vault's; no share ever writes there.
#[test]
fn e11s6_rt3_a_second_spelling_of_the_backup_never_gets_the_container() {
    let long_s = "v.old.lar\u{17f}alvault";
    let decomposed = "ve\u{301}.old.larsalvault";
    for (n, (name, spelled, backup, first_off, plant)) in [
        ("v.larsalvault", long_s, "v.old.larsalvault", true, false),
        ("v.larsalvault", long_s, "v.old.larsalvault", false, false),
        ("v.larsalvault", long_s, "v.old.larsalvault", false, true),
        (
            "v\u{e9}.larsalvault",
            decomposed,
            "v\u{e9}.old.larsalvault",
            true,
            false,
        ),
        (
            "v\u{e9}.larsalvault",
            decomposed,
            "v\u{e9}.old.larsalvault",
            false,
            true,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = TempDir::new(&format!("e11s6-alias-{n}"));
        let file = dir.join(name);
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, spelled));
        let s = session(false);
        backup_settings(&s, !first_off, "");
        if plant {
            std::fs::write(dir.join(spelled), b"a file a folder sync left").unwrap();
        }
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(
            s.share_edit(v, hex(id(0x20))).unwrap().warning,
            Some(ShareWarning::OpenVault),
            "{n}"
        );
        s.share_edit_cancel(v).unwrap();
        two_saves(&s, v);
        if first_off {
            assert!(!dir.join(backup).exists(), "{n}: the container went there");
        }
        backup_settings(&s, true, "");
        two_saves(&s, v);
        let at = dir.join(backup);
        assert!(opens(&at, MAIN), "{n}: the backup no longer is V");
        assert!(!opens(&at, SHARE), "{n}: the container is at the backup");
        assert_eq!(news(&s, v), None, "{n}: a guarded share never runs");
        assert_eq!(names(&dir).len(), 2, "{n}: {:?}", names(&dir));
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

fn backup_settings(s: &Session, enabled: bool, pattern: &str) {
    s.save_settings(vec![
        LarsalSetting {
            key: "backup.enabled".into(),
            value: LarsalSettingValue::Flag { on: enabled },
        },
        LarsalSetting {
            key: "backup.pattern".into(),
            value: LarsalSettingValue::Text {
                text: pattern.into(),
            },
        },
    ])
    .unwrap();
}

mod r6_files;

/// RT-2, Medium: the deleted item through the real flows. Mac A imports the
/// hostile container and saves; Mac B merges that file as a conflict copy and
/// as a change on disk. What B holds outside the share stays.
#[test]
fn e11s6_rt2_a_containers_item_never_reaches_outside_the_share() {
    let dir = TempDir::new("e11s6-poison");
    let (a_file, path, b_file, copy) = (
        dir.join("a/v.larsalvault"),
        dir.join("a/team.larsalvault"),
        dir.join("b/v.larsalvault"),
        dir.join("b/v (conflicted copy).larsalvault"),
    );
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let mut common = base();
    set_share(team(&mut common), settings(true, false, "team.larsalvault"));
    let mut mac_b = common.duplicate();
    let mut private = Group::new(id(0x30), "Private".into(), T2);
    private
        .entries
        .push(entry(0x50, "Outside the share", "demo-b", "mac-b-demo"));
    mac_b.root.groups.push(private);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    for n in [0x50, 0x30] {
        c.deleted_objects.push(DeletedObject {
            uuid: id(n),
            deleted_at: Time(T2.0 + 3_000_000_000_000),
            unknown: Vec::new(),
        });
    }
    write(&path, &c, SHARE);
    let a = session(false);
    let va = approved(&a, &a_file, &common);
    unlock(&a, va);
    assert_eq!(mail(&a, va), "pw-2", "the container was imported");
    change(&a, va, |m| m.meta.name = "V saved on Mac A".into());
    assert_eq!(a.save(va).unwrap().failure, None);
    a.share_wait(va);
    let kept = read(&a_file, MAIN).unwrap();
    // The share's items are rows of this share, off the vault's list (FMT-15.11).
    let rows = larsal_core::origin::read_rows(&kept.meta.custom_data);
    for n in [0x50, 0x30] {
        assert!(!kept.deleted_objects.iter().any(|x| x.uuid == id(n)));
        assert!(rows.contains_key(&(id(n), id(0x20))));
    }
    // Conflict copy.
    std::fs::copy(&a_file, &copy).unwrap();
    write(&b_file, &mac_b, MAIN);
    let b = session(false);
    flags(&b, false, false, false);
    let vb = b.open(b_file.to_string_lossy().into_owned()).unwrap();
    unlock(&b, vb);
    b.merge_copy(vb, copy.to_string_lossy().into_owned(), None, None, false)
        .unwrap();
    let outside = |s: &Session, v: u64| {
        model(s, v, |m| {
            find(m, 0x50).is_some() && m.root.find_group(id(0x30)).is_some()
        })
    };
    assert!(outside(&b, vb), "conflict copy");
    assert_eq!(b.save(vb).unwrap().failure, None);
    assert!(read(&b_file, MAIN).is_ok_and(|m| find(&m, 0x50).is_some()));
    // Change on disk, with an unsaved change on Mac B.
    b.add_group(vb, None, "Local".into(), 48, None).unwrap();
    write(&b_file, &kept, MAIN);
    b.check_disk(vb).unwrap();
    assert_eq!(
        b.resolve_disk(vb, DiskChoice::Merge).unwrap(),
        DiskEvent::Reloaded
    );
    assert!(outside(&b, vb), "change on disk");
    // The row stays a row, so it never reaches E on a later round; and it saves.
    assert_eq!(b.save(vb).unwrap().failure, None);
    let saved = read(&b_file, MAIN).unwrap();
    assert!(find(&saved, 0x50).is_some());
    assert!(!saved.deleted_objects.iter().any(|x| x.uuid == id(0x50)));
    assert!(
        larsal_core::origin::read_rows(&saved.meta.custom_data).contains_key(&(id(0x50), id(0x20)))
    );
}

/// `find` with the password, for what a Mac holds.
fn password_of(s: &Session, v: u64, n: u8) -> Option<String> {
    model(s, v, |m| find(m, n).map(|e| e.value("Password").to_owned()))
}

fn held_in_container(path: &Path, password: &str, secret_text: &str) -> bool {
    read(path, password).is_ok_and(|c| {
        c.root.all_entries().any(|e| {
            e.value("Password") == secret_text
                || e.history.iter().any(|h| h.value("Password") == secret_text)
        })
    })
}

/// One Mac of a member's vault on a real file.
fn mac(name: &str, dir: &Path, vault: &Vault) -> (Arc<Session>, u64, PathBuf) {
    std::fs::create_dir_all(dir.join(name)).unwrap();
    let file = dir.join(name).join("v.larsalvault");
    let s = session(false);
    let v = approved(&s, &file, vault);
    unlock(&s, v);
    (s, v, file)
}

fn merge_file(s: &Session, v: u64, from: &Path, dir: &Path, tag: &str) {
    let copy = dir.join(format!("{tag}.larsalvault"));
    std::fs::copy(from, &copy).unwrap();
    s.merge_copy(v, copy.to_string_lossy().into_owned(), None, None, false)
        .unwrap();
}

fn saved_as(s: &Session, v: u64, name: &str) {
    change(s, v, |m| m.meta.name = name.into());
    assert_eq!(s.save(v).unwrap().failure, None);
    s.share_wait(v);
}

/// The attacks of C1-01, C1-02 and C2-2 on real files. Mac B holds E outside
/// the share with its password, and the share is Synchronize on both Macs, so
/// B's next export would give away whatever the share holds. `older` dates the
/// planted copy before B's.
fn planted_scene(older: bool, tag: &str) {
    let dir = TempDir::new(&format!("e11s6-planted-{tag}"));
    let path = dir.join("team.larsalvault");
    let at = |n: i64| Time(T2.0 + n);
    let path_text = path.to_string_lossy().into_owned();
    let mut common = base();
    set_share(team(&mut common), settings(true, true, &path_text));
    let mut mac_b_vault = common.duplicate();
    let mut own = entry(0x50, "Outside the share", "demo-b", "mac-b-demo");
    own.times.last_modification = at(1000);
    own.times.location_changed = at(1000);
    let mut private = Group::new(id(0x30), "Private".into(), at(1000));
    private.entries.push(own);
    mac_b_vault.root.groups.push(private);
    // Round one: the container brings an entry with E's id.
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let when = at(if older { 500 } else { 2000 });
    let mut planted = entry(0x50, "Planted", "demo-a", "planted-demo");
    planted.times.last_modification = when;
    planted.times.location_changed = when;
    c.root.entries.push(planted);
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    assert_eq!(password_of(&a, va, 0x50).as_deref(), Some("planted-demo"));
    saved_as(&a, va, "A1");
    // The next look brings nothing more: only what Mac A's file holds travels.
    std::fs::remove_file(&path).ok();
    let (b, vb, b_file) = mac("b", &dir, &mac_b_vault);
    merge_file(&b, vb, &a_file, &dir, "from-a-1");
    assert_eq!(
        password_of(&b, vb, 0x50).as_deref(),
        Some("mac-b-demo"),
        "{tag}"
    );
    // Changed by R6 E5 (limit 10): the losing copy's value stays as one history item
    // here; round 2 dropped it. It holds nothing of Mac B's, and it is not exported.
    assert!(
        model(&b, vb, |m| {
            let e = find(m, 0x50).unwrap();
            e.history.len() <= 1
                && e.history
                    .iter()
                    .all(|h| h.value("Password") == "planted-demo")
        }),
        "{tag}: history"
    );
    assert!(model(&b, vb, |m| m
        .root
        .find_group(id(0x30))
        .is_some_and(|p| p.entries.iter().any(|e| e.uuid == id(0x50)))));
    // Mac B's next export holds no outside value.
    saved_as(&b, vb, "B1");
    assert!(path.exists(), "{tag}: B exported");
    assert!(
        !held_in_container(&path, SHARE, "mac-b-demo"),
        "{tag}: leaked"
    );
    assert!(read(&path, SHARE).is_ok_and(|c| c.root.all_entries().all(|e| e.uuid != id(0x50))));
    // From the other side: A takes B's copy whole, so it leaves the share.
    merge_file(&a, va, &b_file, &dir, "from-b-1");
    assert_eq!(
        password_of(&a, va, 0x50).as_deref(),
        Some("mac-b-demo"),
        "{tag}"
    );
    assert!(model(&a, va, |m| m
        .root
        .find_group(id(0x20))
        .is_some_and(|g| g.entries.iter().all(|e| e.uuid != id(0x50)))));
    // Round two: the container lists E. On a repeat round E stays.
    saved_as(&a, va, "A2");
    let mut c2 = container::build(id(0x20), true, &member(), T2).unwrap();
    c2.deleted_objects.push(DeletedObject {
        uuid: id(0x50),
        deleted_at: at(9000),
        unknown: Vec::new(),
    });
    write(&path, &c2, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A3");
    merge_file(&b, vb, &a_file, &dir, "from-a-2");
    assert_eq!(
        password_of(&b, vb, 0x50).as_deref(),
        Some("mac-b-demo"),
        "{tag}: round 2"
    );
    saved_as(&b, vb, "B2");
    assert!(
        !held_in_container(&path, SHARE, "mac-b-demo"),
        "{tag}: round 2"
    );
    merge_file(&a, va, &b_file, &dir, "from-b-2");
    assert_eq!(
        password_of(&a, va, 0x50).as_deref(),
        Some("mac-b-demo"),
        "{tag}: A"
    );
}

#[test]
fn int08_32_real_files_a_planted_copy_never_changes_mac_bs_entry() {
    planted_scene(false, "newer");
}

#[test]
fn int08_32_real_files_an_older_planted_copy_never_changes_mac_bs_entry() {
    planted_scene(true, "older");
}

/// C1-01, C2-2 on real files: the first container brings E and a group that
/// holds F; the second lists them. Mac A saves; Mac B merges that file: B's own
/// E, F and group stay, on repeat rounds too.
#[test]
fn int08_32_real_files_two_rounds_never_reach_outside() {
    let dir = TempDir::new("e11s6-two-rounds");
    let path = dir.join("team.larsalvault");
    let path_text = path.to_string_lossy().into_owned();
    let mut common = base();
    set_share(team(&mut common), settings(true, false, &path_text));
    let mut mac_b_vault = common.duplicate();
    let mut private = Group::new(id(0x30), "Private".into(), T2);
    private
        .entries
        .push(entry(0x50, "E", "demo-b", "mac-b-demo"));
    let mut g = Group::new(id(0x31), "G".into(), T2);
    g.entries.push(entry(0x51, "F", "demo-b", "mac-b-demo"));
    mac_b_vault.root.groups.push(private);
    mac_b_vault.root.groups.push(g);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root
        .entries
        .push(entry(0x50, "E", "demo-a", "planted-demo"));
    let mut planted = Group::new(id(0x31), "G".into(), T2);
    planted
        .entries
        .push(entry(0x51, "F", "demo-a", "planted-demo"));
    c.root.groups.push(planted);
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    assert_eq!(password_of(&a, va, 0x50).as_deref(), Some("planted-demo"));
    let far = Time(T2.0 + 3_000_000_000_000);
    let mut second = container::build(id(0x20), true, &member(), T2).unwrap();
    for n in [0x50, 0x51, 0x31] {
        second.deleted_objects.push(DeletedObject {
            uuid: id(n),
            deleted_at: far,
            unknown: Vec::new(),
        });
    }
    write(&path, &second, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    assert_eq!(password_of(&a, va, 0x50), None, "erased in the share on A");
    saved_as(&a, va, "A1");
    let (b, vb, b_file) = mac("b", &dir, &mac_b_vault);
    for round in 0..2 {
        merge_file(&b, vb, &a_file, &dir, &format!("from-a-{round}"));
        for n in [0x50, 0x51] {
            assert_eq!(
                password_of(&b, vb, n).as_deref(),
                Some("mac-b-demo"),
                "round {round}"
            );
        }
        assert!(
            model(&b, vb, |m| m.root.find_group(id(0x31)).is_some()),
            "round {round}"
        );
        saved_as(&b, vb, &format!("B{round}"));
        merge_file(&a, va, &b_file, &dir, &format!("from-b-{round}"));
        assert_eq!(
            password_of(&a, va, 0x50).as_deref(),
            Some("mac-b-demo"),
            "A round {round}"
        );
        saved_as(&a, va, &format!("A{round}2"));
    }
}

/// Honest deletion on real files: X deletes; Y imports (a holder, and a
/// newcomer that never held E); Y's other Mac holds E and merges Y's file: E is
/// gone. The saved list survives a reopen, and a repeat round changes nothing.
#[test]
fn int08_32_real_files_an_honest_deletion_reaches_the_other_mac() {
    for newcomer in [false, true] {
        let dir = TempDir::new(&format!("e11s6-honest-{newcomer}"));
        let path = dir.join("team.larsalvault");
        let path_text = path.to_string_lossy().into_owned();
        let mut common = base();
        set_share(team(&mut common), settings(true, true, &path_text));
        let mut holder = common.duplicate();
        team(&mut holder)
            .entries
            .push(entry(0x50, "E", "demo", "demo-e"));
        let (x, vx, _) = mac("x", &dir, &holder);
        saved_as(&x, vx, "X1");
        assert!(read(&path, SHARE).is_ok_and(|c| c.root.all_entries().any(|e| e.uuid == id(0x50))));
        let early = (!newcomer).then(|| mac("y", &dir, &holder));
        change(&x, vx, |m| {
            team(m).entries.retain(|e| e.uuid != id(0x50));
            m.deleted_objects.push(DeletedObject {
                uuid: id(0x50),
                deleted_at: Time(T2.0 + 1000),
                unknown: Vec::new(),
            });
        });
        saved_as(&x, vx, "X2");
        // A newcomer opens the vault only now: it never held E.
        let (y, vy, y_file) = early.unwrap_or_else(|| mac("y", &dir, &common));
        y.share_look(vy, path_text.clone()).unwrap();
        y.share_wait(vy);
        assert_eq!(password_of(&y, vy, 0x50), None, "newcomer {newcomer}");
        saved_as(&y, vy, "Y1");
        // A new read: what travels in the file is the row, off the vault's list.
        let on_file = read(&y_file, MAIN).unwrap();
        assert!(!on_file.deleted_objects.iter().any(|d| d.uuid == id(0x50)));
        assert!(
            larsal_core::origin::read_rows(&on_file.meta.custom_data)
                .contains_key(&(id(0x50), id(0x20)))
        );
        // Y's other Mac holds E; it does not run the share (off this Mac).
        std::fs::rename(&path, dir.join("away.larsalvault")).unwrap();
        let (w, vw, w_file) = mac("w", &dir, &holder);
        merge_file(&w, vw, &y_file, &dir, "from-y");
        assert_eq!(password_of(&w, vw, 0x50), None, "newcomer {newcomer}: W");
        saved_as(&w, vw, "W1");
        merge_file(&y, vy, &w_file, &dir, "from-w");
        assert_eq!(password_of(&y, vy, 0x50), None, "repeat round");
        merge_file(&w, vw, &y_file, &dir, "from-y-2");
        assert_eq!(password_of(&w, vw, 0x50), None, "repeat round");
    }
}

/// Honest flow on real files: a member moves E out of the share on one Mac while
/// the other imported it. From either side, on repeat rounds, E stays out with
/// the moved Mac's value; the share's next export does not hold it.
#[test]
fn int08_32_real_files_a_members_move_out_wins_on_both_macs() {
    let dir = TempDir::new("e11s6-move-out");
    let path = dir.join("team.larsalvault");
    let path_text = path.to_string_lossy().into_owned();
    let mut common = base();
    set_share(team(&mut common), settings(true, true, &path_text));
    common
        .root
        .groups
        .push(Group::new(id(0x30), "Private".into(), T2));
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root
        .entries
        .push(entry(0x50, "E", "demo", "brought-demo"));
    write(&path, &c, SHARE);
    let (one, v1, f1) = mac("one", &dir, &common);
    let (two, v2, f2) = mac("two", &dir, &common);
    for (s, v) in [(&one, v1), (&two, v2)] {
        assert_eq!(password_of(s, v, 0x50).as_deref(), Some("brought-demo"));
    }
    // The move on Mac one, through the screen layer's route.
    let at = Time(T2.0 + 500);
    change(&one, v1, |m| {
        larsal_core::edit::move_entries(m, &[id(0x50)], id(0x30), at).unwrap();
    });
    saved_as(&one, v1, "one");
    saved_as(&two, v2, "two");
    for round in 0..2 {
        merge_file(&two, v2, &f1, &dir, &format!("to-two-{round}"));
        assert!(
            model(&two, v2, |m| {
                m.root
                    .find_group(id(0x30))
                    .is_some_and(|g| g.entries.iter().any(|e| e.uuid == id(0x50)))
            }),
            "round {round}: Mac two"
        );
        saved_as(&two, v2, &format!("two-{round}"));
        merge_file(&one, v1, &f2, &dir, &format!("to-one-{round}"));
        assert!(model(&one, v1, |m| {
            m.root
                .find_group(id(0x30))
                .is_some_and(|g| g.entries.iter().any(|e| e.uuid == id(0x50)))
        }));
        saved_as(&one, v1, &format!("one-{round}"));
        assert!(
            read(&path, SHARE).is_ok_and(|c| c.root.all_entries().all(|e| e.uuid != id(0x50))),
            "round {round}: the export holds E"
        );
    }
}

/// INT-08.32 D on real files: a container cannot plant a stamp, a marker, rows
/// or a known list, an export holds none, and a save keeps them.
#[test]
fn int08_32_real_files_markers_are_stripped_at_import_and_export_and_kept_by_save() {
    use larsal_core::origin;
    let dir = TempDir::new("e11s6-strip");
    let path = dir.join("team.larsalvault");
    let path_text = path.to_string_lossy().into_owned();
    let mut common = base();
    set_share(team(&mut common), settings(true, true, &path_text));
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let mut e = entry(0x50, "E", "demo", "brought-demo");
    origin::set_mark(&mut e.custom_data, id(0x30));
    origin::set_stamp(
        &mut e.custom_data,
        Some(origin::Stamp {
            group: id(0x20),
            at: Time(T2.0 + 1),
        }),
    );
    c.root.entries.push(e);
    let mut planted = larsal_model::custom_data::CustomData::default();
    origin::write_rows(
        &mut planted,
        &origin::Rows::from([((id(0x60), id(0x30)), T2)]),
    );
    origin::write_known(&mut planted, &origin::Set::from([id(0x30)]));
    c.meta.custom_data.items.extend(planted.items);
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    let mark = |m: &Vault| find(m, 0x50).and_then(|e| origin::mark_of(&e.custom_data));
    assert_eq!(
        model(&a, va, mark),
        Some(id(0x20)),
        "this group, not the file's"
    );
    assert_eq!(
        model(&a, va, |m| find(m, 0x50)
            .and_then(|e| origin::stamp_of(&e.custom_data))),
        None,
        "no stamp from a file"
    );
    assert!(model(&a, va, |m| origin::read_rows(&m.meta.custom_data)
        .is_empty()));
    assert_eq!(
        model(&a, va, origin::known),
        origin::Set::from([id(0x20)]),
        "this share only"
    );
    saved_as(&a, va, "A1");
    let on_file = read(&a_file, MAIN).unwrap();
    assert_eq!(mark(&on_file), Some(id(0x20)), "a save keeps the marker");
    assert!(on_file.meta.custom_data.get(origin::SCOPES).is_none());
    let export = read(&path, SHARE).unwrap();
    assert!(!origin::held(&export), "an export holds none of the four");
    assert!(find(&export, 0x50).is_some());
    // The editor does not show the marker.
    let shown = a.begin_edit(va, hex(id(0x50))).unwrap();
    assert!(!shown.custom_data.iter().any(|c| origin::ours(&c.key)));
}

/// C2-1: a FIFO as the path's folder. `share_block`, the sheet's call, and the
/// export both answer at once and the FIFO stays.
#[test]
fn e11s6_a_fifo_in_the_path_never_makes_a_call_wait() {
    use std::os::unix::fs::FileTypeExt as _;
    use std::sync::mpsc;
    use std::time::Duration;
    let dir = TempDir::new("e11s6-fifo-folder");
    let (file, pipe) = (dir.join("v.larsalvault"), dir.join("pipe"));
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&pipe)
        .status()
        .unwrap();
    assert!(made.success());
    let target = pipe.join("team.larsalvault");
    let mut vault = base();
    set_share(
        team(&mut vault),
        settings(false, true, &target.to_string_lossy()),
    );
    let s = session(false);
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    let answered = |what: &str, f: Box<dyn FnOnce() + Send>| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("{what} waits on the FIFO"));
    };
    let s2 = s.clone();
    answered(
        "share_block",
        Box::new(move || {
            let _ = s2.share_block(v, hex(id(0x20)));
        }),
    );
    let s2 = s.clone();
    answered(
        "a save and its export",
        Box::new(move || {
            change(&s2, v, |m| m.meta.name = "V2".into());
            assert_eq!(s2.save(v).unwrap().failure, None);
            s2.share_wait(v);
        }),
    );
    assert!(
        std::fs::symlink_metadata(&pipe)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert!(opens(&file, MAIN));
    assert_eq!(banner(&s, v).map(|b| b.0), Some(ShareLevel::Error));
}

/// C1-03, C2-3: a failed attempt changes nothing the slot holds. T72's file, a
/// key file that opens as this share's container, with the vault that uses it
/// locked and one failed attempt without the key file.
#[test]
fn e11s6_a_failed_attempt_keeps_the_key_file() {
    let dir = TempDir::new("e11s6-attempt");
    let (key, one) = (dir.join("k.larsalkey"), dir.join("one.larsalvault"));
    publish(&key, &member());
    let bytes = std::fs::read(&key).unwrap();
    write_with_key(&one, &base(), &bytes);
    let typed = key.to_string_lossy().into_owned();
    let s = session(false);
    let v1 = s.open(one.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        s.unlock(v1, Some(MAIN.into()), Some(typed.clone()))
            .unwrap(),
        UnlockResult::Unlocked
    );
    s.lock(v1).unwrap();
    let failed = s.unlock(v1, Some(MAIN.into()), None).unwrap();
    assert!(matches!(failed, UnlockResult::Failed { .. }), "{failed:?}");
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, &typed));
    let v2 = approved(&s, &dir.join("two.larsalvault"), &vault);
    unlock(&s, v2);
    two_saves(&s, v2);
    assert_eq!(
        std::fs::read(&key).unwrap(),
        bytes,
        "the key file was replaced"
    );
    drop(s);
    key_still_works(&one, &key);
}

/// C1-07: the slot holds the file the typed path names, not the text. A relative
/// path is beside the vault, not in the process's folder.
#[test]
fn e11s6_the_slot_holds_the_key_file_a_relative_path_names() {
    let dir = TempDir::new("e11s6-relative-key");
    let (key, one) = (dir.join("rel.larsalkey"), dir.join("one.larsalvault"));
    publish(&key, &member());
    let bytes = std::fs::read(&key).unwrap();
    write_with_key(&one, &base(), &bytes);
    let s = session(false);
    let v1 = s.open(one.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        s.unlock(v1, Some(MAIN.into()), Some("rel.larsalkey".into()))
            .unwrap(),
        UnlockResult::Unlocked
    );
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "rel.larsalkey"));
    let v2 = approved(&s, &dir.join("two.larsalvault"), &vault);
    unlock(&s, v2);
    two_saves(&s, v2);
    assert_eq!(
        std::fs::read(&key).unwrap(),
        bytes,
        "the key file was replaced"
    );
}

/// C1-07: `~/` in a typed key file path is the home folder. Text only: no file
/// is made in the home folder.
#[test]
fn e11s6_a_typed_tilde_path_is_in_the_home_folder() {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap();
    let got = crate::session::key_path(Path::new("/any/v.larsalvault"), "~/k.larsalkey");
    assert_eq!(got, home.join("k.larsalkey"));
}

/// C1-04: Clear and then a new path on one page forgets the old approval, so
/// the old mode and path cannot be planted back without the sheet.
#[test]
fn e11s6_clear_then_a_new_path_forgets_the_old_approval() {
    let dir = TempDir::new("e11s6-clear-new");
    let file = dir.join("v.larsalvault");
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "old.larsalvault"));
    let s = session(false);
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    two_saves(&s, v);
    let old = s.settings.share_approvals();
    assert_eq!(old.len(), 1);
    s.share_edit(v, hex(id(0x20))).unwrap();
    s.share_edit_change(v, ShareChange::Clear).unwrap();
    s.share_edit_change(
        v,
        ShareChange::Mode {
            mode: ShareMode::Export,
        },
    )
    .unwrap();
    s.share_edit_change(
        v,
        ShareChange::Path {
            path: "new.larsalvault".into(),
        },
    )
    .unwrap();
    s.share_edit_password(v, "demo-new-password".into())
        .unwrap();
    s.share_edit_save(v).unwrap();
    let now = s.settings.share_approvals();
    assert!(!now.contains(&old[0]), "the old approval stayed");
    assert_eq!(now.len(), 1, "the new share is approved: {now:?}");
}

/// RT-5: Approve is tied to what the sheet showed: a change on disk that moves
/// the path, or the mode, under the sheet is refused; nothing is approved.
#[test]
fn e11s6_rt5_approve_approves_only_what_the_sheet_showed() {
    let dir = TempDir::new("e11s6-toctou");
    let (file, victim) = (dir.join("v.larsalvault"), dir.join("victim.txt"));
    std::fs::write(&victim, "victim").unwrap();
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "shown.larsalvault"));
    write(&file, &vault, MAIN);
    let s = session(false);
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    unlock(&s, v);
    let shown = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
    s.add_group(v, None, "Local".into(), 48, None).unwrap();
    let mut other = read(&file, MAIN).unwrap();
    set_share(
        team(&mut other),
        settings(false, true, &victim.to_string_lossy()),
    );
    team(&mut other).times.last_modification = T2;
    write(&file, &other, MAIN);
    s.check_disk(v).unwrap();
    assert_eq!(
        s.resolve_disk(v, DiskChoice::Merge).unwrap(),
        DiskEvent::Reloaded
    );
    s.share_wait(v);
    let refused = LarsalError::Refused(
        "This share changed while the sheet was open. Look at it again.".to_owned(),
    );
    assert_eq!(
        s.approve_share_shown(v, shown.group.clone(), shown.mode, shown.full_path.clone()),
        Err(refused.clone())
    );
    assert!(s.settings.share_approvals().is_empty(), "approved anyway");
    let now = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
    assert_eq!(now.state, ShareState::Waiting);
    // The mode alone, under the sheet.
    assert_eq!(
        s.approve_share_shown(
            v,
            now.group.clone(),
            ShareMode::Synchronize,
            now.full_path.clone()
        ),
        Err(refused)
    );
    // What the sheet shows now is approved; item 1 still holds at the write.
    s.approve_share_shown(v, now.group, now.mode, now.full_path)
        .unwrap();
    s.share_wait(v);
    assert_eq!(
        s.share_label(v, hex(id(0x20))).unwrap().unwrap().state,
        ShareState::Running
    );
    two_saves(&s, v);
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert_eq!(
        s.approve_share_shown(
            v,
            hex(id(0x7F)),
            ShareMode::Export,
            victim.to_string_lossy().into_owned()
        ),
        Err(LarsalError::UnknownGroup)
    );
}

/// RT-6: Clear forgets the approval. The same mode and path planted later, with
/// another password, wait for the sheet, and no container goes out under it.
#[test]
fn e11s6_rt6_clear_forgets_the_approval() {
    let dir = TempDir::new("e11s6-clear");
    let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
    let s = session(false);
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    two_saves(&s, v);
    let exported = std::fs::read(&path).unwrap();
    assert_eq!(s.settings.share_approvals().len(), 1);
    let written = model(&s, v, |m| {
        run::shares(m, Some(&file)).first().unwrap().written(m)
    });
    assert!(s.settings.share_written(&written).is_some());
    s.share_edit(v, hex(id(0x20))).unwrap();
    s.share_edit_change(v, ShareChange::Clear).unwrap();
    s.share_edit_save(v).unwrap();
    assert!(s.settings.share_approvals().is_empty(), "Clear kept it");
    assert_eq!(s.settings.share_written(&written), None, "Clear kept it");
    assert_eq!(s.save(v).unwrap().failure, None);
    s.share_wait(v);
    s.add_group(v, None, "Local".into(), 48, None).unwrap();
    let mut other = read(&file, MAIN).unwrap();
    let mut planted = settings(false, true, "team.larsalvault");
    planted.password = secret("demo-planted-password");
    set_share(team(&mut other), planted);
    team(&mut other).times.last_modification = T2;
    write(&file, &other, MAIN);
    s.check_disk(v).unwrap();
    assert_eq!(
        s.resolve_disk(v, DiskChoice::Merge).unwrap(),
        DiskEvent::Reloaded
    );
    s.share_wait(v);
    assert_eq!(
        s.share_label(v, hex(id(0x20))).unwrap().unwrap().state,
        ShareState::Waiting
    );
    assert_eq!(s.save(v).unwrap().failure, None);
    s.share_wait(v);
    assert_eq!(std::fs::read(&path).unwrap(), exported, "exported anyway");
    assert!(!opens(&path, "demo-planted-password"));
}

/// RT-7: a change of one other box does not approve a planted path; the sheet
/// does, or typing the path. A change on a share already approved stays so.
#[test]
fn e11s6_rt7_one_changed_box_does_not_approve_a_planted_path() {
    let dir = TempDir::new("e11s6-box");
    let (file, victim) = (dir.join("v.larsalvault"), dir.join("victim.txt"));
    std::fs::write(&victim, "victim").unwrap();
    let text = victim.to_string_lossy().into_owned();
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, &text));
    write(&file, &vault, MAIN);
    let s = session(false);
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    unlock(&s, v);
    let state = |s: &Session| s.share_label(v, hex(id(0x20))).unwrap().unwrap().state;
    let boxes: [&dyn Fn(&Session); 4] = [
        // Saved with no change at all.
        &|_| {},
        &|s| {
            s.share_edit_change(v, ShareChange::Keep { on: false })
                .unwrap();
        },
        &|s| {
            s.share_edit_password(v, "demo-new".into()).unwrap();
        },
        &|s| {
            s.share_edit_change(
                v,
                ShareChange::Mode {
                    mode: ShareMode::Synchronize,
                },
            )
            .unwrap();
        },
    ];
    for (n, change_box) in boxes.iter().enumerate() {
        s.share_edit(v, hex(id(0x20))).unwrap();
        change_box(&s);
        s.share_edit_save(v).unwrap();
        assert_eq!(state(&s), ShareState::Waiting, "box {n}");
        assert_eq!(s.save(v).unwrap().failure, None);
        s.share_wait(v);
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim", "box {n}");
    }
    // Typing the path is the user's own choice.
    let mine = dir.join("mine.larsalvault");
    s.share_edit(v, hex(id(0x20))).unwrap();
    s.share_edit_change(
        v,
        ShareChange::Path {
            path: mine.to_string_lossy().into_owned(),
        },
    )
    .unwrap();
    s.share_edit_save(v).unwrap();
    assert_eq!(state(&s), ShareState::Running, "typed");
    // Then its Type, on the share this Mac approved.
    s.share_edit(v, hex(id(0x20))).unwrap();
    s.share_edit_change(
        v,
        ShareChange::Mode {
            mode: ShareMode::Export,
        },
    )
    .unwrap();
    s.share_edit_save(v).unwrap();
    assert_eq!(state(&s), ShareState::Running, "approved share, new Type");
}

/// RT-8: what the Approve sheet shows of a path built to read as another.
#[test]
fn e11s6_rt8_the_sheet_shows_control_and_bidi_characters_escaped() {
    for (path, shown) in [
        (
            "/tmp/x\n\n/Users/demo/team",
            "/tmp/x\\u{a}\\u{a}/Users/demo/team",
        ),
        ("team\u{202e}tluav\u{202c}", "team\\u{202e}tluav\\u{202c}"),
        ("te\u{7}am\u{1b}[2J", "te\\u{7}am\\u{1b}[2J"),
        ("a\u{ad}b\u{200b}c\u{feff}", "a\\u{ad}b\\u{200b}c\\u{feff}"),
        (
            "a\u{61c}b\u{180e}c\u{2066}d\u{fff9}",
            "a\\u{61c}b\\u{180e}c\\u{2066}d\\u{fff9}",
        ),
        ("a\u{2028}b\u{2029}c\u{85}", "a\\u{2028}b\\u{2029}c\\u{85}"),
        // The backslash, so a typed form cannot read as a written-out one.
        ("a\\u{202e}b", "a\\u{5c}u{202e}b"),
        // Ordinary text and every other language stay as they are: combining
        // marks, joined scripts, a plain space, a picture.
        (
            "/Users/demo/Tea\u{1e9e} m\u{e9}/\u{5d0}e\u{301}\u{4e2d}\u{1f512}.larsalvault",
            "/Users/demo/Tea\u{1e9e} m\u{e9}/\u{5d0}e\u{301}\u{4e2d}\u{1f512}.larsalvault",
        ),
    ] {
        assert_eq!(share_path_shown(path.to_owned()), shown);
    }
    // C1-06, C2-5: every format character (Cf) of Unicode 16, and the other
    // invisible scalars: none reaches the sheet as it is.
    let cf: [(u32, u32); 19] = [
        (0xAD, 0xAD),
        (0x600, 0x605),
        (0x61C, 0x61C),
        (0x6DD, 0x6DD),
        (0x70F, 0x70F),
        (0x890, 0x891),
        (0x8E2, 0x8E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
    ];
    let others = [
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
        (0x34F, 0x34F),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFF8),
        (0xE0100, 0xE01EF),
        (0xA0, 0xA0),
        (0x2000, 0x200A),
        (0x202F, 0x202F),
        (0x205F, 0x205F),
        (0x3000, 0x3000),
        (0x2800, 0x2800),
        (0xE000, 0xE000),
        (0xFFFE, 0xFFFE),
        (0x1FFFF, 0x1FFFF),
    ];
    for (from, to) in cf.into_iter().chain(others) {
        for c in (from..=to).filter_map(char::from_u32) {
            let shown = share_path_shown(format!("a{c}b"));
            assert_eq!(
                shown,
                format!("a\\u{{{:x}}}b", c as u32),
                "U+{:04X}",
                c as u32
            );
        }
    }
    // The stored path does not change: Approve still gets it as it is.
    let dir = TempDir::new("e11s6-spoof");
    let file = dir.join("v.larsalvault");
    let text = "te\u{7}am.larsalvault";
    let mut vault = base();
    set_share(team(&mut vault), settings(false, true, text));
    write(&file, &vault, MAIN);
    let s = session(false);
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    unlock(&s, v);
    let l = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
    assert!(l.full_path.ends_with(text));
    s.approve_share_shown(v, l.group, l.mode, l.full_path)
        .unwrap();
}

/// A share item that came by a merge into a group the user never shared, and a
/// group new with it: they wait for the sheet, and the editor opened and saved
/// with no change approves nothing (T52's merge route).
#[test]
fn e11s6_a_share_planted_by_a_merge_waits() {
    let dir = TempDir::new("e11s6-plant");
    let (file, victim) = (dir.join("v.larsalvault"), dir.join("victim.txt"));
    std::fs::write(&victim, "victim").unwrap();
    let mut mine = base();
    mine.root
        .groups
        .push(Group::new(id(0x31), "Never shared".into(), T2));
    write(&file, &mine, MAIN);
    let s = session(false);
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    unlock(&s, v);
    s.add_group(v, None, "Local".into(), 48, None).unwrap();
    let mut other = mine.duplicate();
    let mut planted = Group::new(id(0x33), "Planted export".into(), T2);
    set_share(
        &mut planted,
        settings(false, true, &victim.to_string_lossy()),
    );
    other.root.groups.push(planted);
    let never = other
        .root
        .groups
        .iter_mut()
        .find(|g| g.uuid == id(0x31))
        .unwrap();
    set_share(never, settings(false, true, &victim.to_string_lossy()));
    never.times.last_modification = Time(T2.0 + 10);
    write(&file, &other, MAIN);
    s.check_disk(v).unwrap();
    assert_eq!(
        s.resolve_disk(v, DiskChoice::Merge).unwrap(),
        DiskEvent::Reloaded
    );
    s.share_wait(v);
    let has = |n: u8| {
        model(&s, v, |m| {
            m.root
                .find_group(id(n))
                .is_some_and(|g| share_item::of(g).is_some())
        })
    };
    assert!(has(0x31) && has(0x33));
    assert!(s.share_paths(v).unwrap().is_empty());
    for n in [0x31, 0x33] {
        s.share_edit(v, hex(id(n))).unwrap();
        s.share_edit_save(v).unwrap();
        assert_eq!(
            s.share_label(v, hex(id(n))).unwrap().unwrap().state,
            ShareState::Waiting
        );
    }
    assert_eq!(s.save(v).unwrap().failure, None);
    s.share_wait(v);
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert!(s.settings.share_approvals().is_empty());
}

/// The trial hook that looks at the vault with `look` each time the trial runs,
/// and arms itself again, at most five runs.
fn arm(s: &Session, v: u64, runs: &Arc<AtomicUsize>, look: &Arc<dyn Fn(&Session) + Send + Sync>) {
    let (runs, look) = (Arc::clone(runs), Arc::clone(look));
    s.with_share(v, |slot| {
        slot.share.trial = Some(Box::new(move |s: &Session| {
            let done = runs.fetch_add(1, Ordering::SeqCst);
            look(s);
            if done < 4 {
                arm(s, v, &runs, &look);
            }
        }));
    })
    .unwrap();
}

/// F-278: a look during an import's trial does not re-queue the import, through
/// the live doors: the change-on-disk check and the browser bridge. A real
/// change there still wins, and the import runs again on it.
#[test]
fn f278_a_look_during_a_trial_does_not_queue_the_import_again() {
    let dir = TempDir::new("f278");
    for (n, want) in [(0, 1), (1, 1), (2, 5), (3, 5)] {
        let sub = dir.join(format!("{n}"));
        std::fs::create_dir_all(&sub).unwrap();
        let (file, path) = (sub.join("v.larsalvault"), sub.join("team.larsalvault"));
        publish(&path, &member());
        let mut vault = base();
        set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        let door = Arc::clone(&s);
        let look: Arc<dyn Fn(&Session) + Send + Sync> = match n {
            0 => Arc::new(move |s: &Session| {
                s.check_disk(v).unwrap();
            }),
            1 => Arc::new(move |_: &Session| {
                assert!(bridge_door(&door, v, &mut |_, _| Changed::Nothing));
            }),
            2 => Arc::new(move |_: &Session| {
                assert!(bridge_door(&door, v, &mut |_, _| Changed::View));
            }),
            _ => Arc::new(move |_: &Session| {
                assert!(bridge_door(&door, v, &mut |_, _| Changed::Data));
            }),
        };
        let runs = Arc::new(AtomicUsize::new(0));
        arm(&s, v, &runs, &look);
        unlock(&s, v);
        assert_eq!(runs.load(Ordering::SeqCst), want, "door {n}");
        assert_eq!(mail(&s, v), "pw-2", "door {n}: the import landed");
        s.with_share(v, |slot| slot.share.trial = None).unwrap();
        s.lock_all();
    }
}

/// RT-1: the Red team's saved key file demo, from copies of its files, through
/// the Approve door. Needs `LARSAL_E11S6_DEMO`, a folder holding copies of the
/// demo's `v.larsalvault` and `v.larsalkey`.
#[test]
#[ignore = "needs LARSAL_E11S6_DEMO, a folder with copies of the saved demo files"]
fn e11s6_rt1_replay_of_the_saved_key_file_demo() {
    let dir = PathBuf::from(std::env::var_os("LARSAL_E11S6_DEMO").unwrap());
    let (file, key) = (dir.join("v.larsalvault"), dir.join("v.larsalkey"));
    let before = std::fs::read(&key).unwrap();
    let s = session(false);
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    let key_text = key.to_string_lossy().into_owned();
    assert_eq!(
        s.unlock(v, Some(MAIN.into()), Some(key_text)).unwrap(),
        UnlockResult::Unlocked
    );
    s.share_wait(v);
    let label = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
    assert_eq!(label.state, ShareState::Waiting);
    s.approve_share_shown(v, label.group, label.mode, label.full_path)
        .unwrap();
    s.share_wait(v);
    two_saves(&s, v);
    assert_eq!(
        std::fs::read(&key).unwrap(),
        before,
        "the key file was replaced"
    );
    assert_eq!(banner(&s, v).map(|b| b.0), Some(ShareLevel::Error));
    drop(s);
    key_still_works(&file, &key);
}

/// The Red team's saved closed-vault demo, the same way: the vault's Team
/// aims at a vault file not open in Larsal. Needs `LARSAL_E11S6_DEMO`, as above,
/// holding copies of `v-aimed-at-closed.larsalvault` and `closed.larsalvault`.
#[test]
#[ignore = "needs LARSAL_E11S6_DEMO, a folder with copies of the saved demo files"]
fn e11s6_rt1_replay_of_the_saved_closed_vault_demo() {
    let dir = PathBuf::from(std::env::var_os("LARSAL_E11S6_DEMO").unwrap());
    let (file, closed) = (
        dir.join("v-aimed-at-closed.larsalvault"),
        dir.join("closed.larsalvault"),
    );
    let before = std::fs::read(&closed).unwrap();
    let s = session(false);
    let v = s.open(file.to_string_lossy().into_owned()).unwrap();
    unlock(&s, v);
    s.share_wait(v);
    let label = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
    assert_eq!(label.state, ShareState::Waiting);
    s.approve_share_shown(v, label.group, label.mode, label.full_path)
        .unwrap();
    s.share_wait(v);
    two_saves(&s, v);
    assert_eq!(
        std::fs::read(&closed).unwrap(),
        before,
        "the closed vault was replaced"
    );
    assert_eq!(
        banner(&s, v),
        Some((ShareLevel::Error, vec![left_alone("closed.larsalvault")]))
    );
}
