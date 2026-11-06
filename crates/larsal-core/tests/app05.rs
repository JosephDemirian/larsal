//! Story E4-S15, card APP-05: storage. One test per core rule
//! (`app05_NN_…`) and the attacks AT-I01 to AT-I06 (`at_i0N_…`), each in a
//! scratch folder under the system temp folder; no real vault is touched.
//!
//! Screen and session rules are E5-S10's: what triggers a save and its
//! timers (APP-05.1 to APP-05.8), the questions and the reload flow
//! (APP-05.25 to APP-05.31), the version 3 notice (APP-05.32). Their core
//! parts are here: the pre-save check, the failure count, the merge after a
//! change on disk (AT-I05), the copies listed after a key change.

mod common;

use common::at;
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::storage::{
    self, Backup, Checksum, Failures, Fault, FaultPoint, Method, SaveError, SaveReport,
    SaveRequest, backup_path, changed_on_disk, checksum, read_checksum,
};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::times::Civil;
use larsal_model::{Entry, Field, Group, Kdf, Uuid, Vault};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A scratch folder, removed (permissions restored first) when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("app05-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fn open_up(p: &Path) {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
            if let Ok(list) = fs::read_dir(p) {
                for e in list.flatten() {
                    let path = e.path();
                    if path.is_dir() && !path.is_symlink() {
                        open_up(&path);
                    } else if !path.is_symlink() {
                        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                    }
                }
            }
        }
        open_up(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn req<'a>(
    path: &'a Path,
    bytes: &'a [u8],
    last: Option<Checksum>,
    private: &'a Path,
) -> SaveRequest<'a> {
    SaveRequest {
        path,
        bytes,
        last_known: last,
        ignore_disk_changes: false,
        method: Method::Safe,
        backup: None,
        private_temp: private,
        fault: None,
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn local() -> Civil {
    Civil {
        year: 2026,
        month: 10,
        day: 25,
        hour: 14,
        minute: 3,
        second: 9,
    }
}

fn backup<'a>(pattern: &'a str, home: &'a Path) -> Backup<'a> {
    Backup {
        pattern,
        local: local(),
        millis: 7,
        home,
    }
}

fn fault(at: FaultPoint, kind: ErrorKind) -> Option<Fault> {
    Some(Fault {
        at,
        kind,
        temp_name: None,
    })
}

#[test]
fn app05_09_real_path_and_links() {
    // T16: a symbolic link stays a link; its target gets a new file.
    let s = Scratch::new("links");
    let p = s.path("Personal.larsalvault");
    fs::write(&p, b"old").unwrap();
    let inode = fs::metadata(&p).unwrap().ino();
    let l = s.path("L.larsalvault");
    std::os::unix::fs::symlink(&p, &l).unwrap();
    storage::save(&req(&l, b"new", None, &s.0)).unwrap();
    assert!(fs::symlink_metadata(&l).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&p).unwrap(), b"new");
    assert_ne!(fs::metadata(&p).unwrap().ino(), inode);
    assert_eq!(
        s.names(),
        ["L.larsalvault", "Personal.larsalvault"],
        "no temp file left"
    );
    // A link whose target is gone: written as a new file at the path.
    let gone = s.path("Gone.larsalvault");
    std::os::unix::fs::symlink(s.path("missing.larsalvault"), &gone).unwrap();
    assert_eq!(storage::real_path(&gone), gone);
}

#[test]
fn app05_10_pre_save_check() {
    let s = Scratch::new("presave");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"version 1").unwrap();
    let known = checksum(b"version 1");
    // Equal: the save goes on.
    let r = storage::save(&req(&p, b"version 2", Some(known), &s.0)).unwrap();
    assert!(!r.recreated);
    let known = r.checksum;
    // T17: another writer changed the file: nothing written, no backup.
    fs::write(&p, b"rewritten by another app").unwrap();
    let mut q = req(&p, b"version 3", Some(known), &s.0);
    q.backup = Some(backup("", &s.0));
    match storage::save(&q) {
        Err(SaveError::ChangedOnDisk(now)) => {
            assert_eq!(now, checksum(b"rewritten by another app"))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fs::read(&p).unwrap(), b"rewritten by another app");
    assert_eq!(s.names(), ["P.larsalvault"], "no backup made");
    // Ignore or Overwrite: no check.
    q.ignore_disk_changes = true;
    q.backup = None;
    storage::save(&q).unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"version 3");
    // T18: the file vanished: written anew, 0600, reported.
    fs::remove_file(&p).unwrap();
    let r = storage::save(&req(&p, b"version 4", Some(checksum(b"version 3")), &s.0)).unwrap();
    assert!(r.recreated);
    assert_eq!(mode(&p), 0o600);
    // T19: the file cannot be read: nothing written.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        storage::save(&req(&p, b"version 5", Some(checksum(b"version 4")), &s.0)),
        Err(SaveError::CannotRead(ErrorKind::PermissionDenied))
    );
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"version 4");
    // No last-known checksum (never read here): no check.
    fs::write(&p, b"other").unwrap();
    storage::save(&req(&p, b"mine", None, &s.0)).unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"mine");
}

#[test]
fn app05_11_safe_save() {
    // T20 (the parts std can do): mode kept, new inode, no temp left.
    let s = Scratch::new("safe");
    let p = s.path("Personal.larsalvault");
    fs::write(&p, b"old bytes").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    let inode = fs::metadata(&p).unwrap().ino();
    let r: SaveReport = storage::save(&req(&p, b"new bytes", None, &s.0)).unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"new bytes");
    assert_eq!(mode(&p), 0o644);
    assert_ne!(fs::metadata(&p).unwrap().ino(), inode);
    assert_eq!(r.checksum, read_checksum(&p).unwrap().unwrap());
    assert_eq!(s.names(), ["Personal.larsalvault"]);
}

#[test]
fn f_089_safe_save_keeps_creation_date_tags_and_acl() {
    // F-089 (APP-05.11 step 5, LD-129): the creation date, the Finder tags
    // attribute and the access control list survive the rename. The test
    // sets them with the system's own tools.
    let s = Scratch::new("keep");
    let p = s.path("Personal.larsalvault");
    fs::write(&p, b"old bytes").unwrap();
    // A modification time before the creation date moves the creation
    // date back with it (APFS).
    let born = SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800); // 2020-01-01
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(born)
        .unwrap();
    assert_eq!(fs::metadata(&p).unwrap().created().unwrap(), born);
    let tool = |cmd: &str, args: &[&str]| {
        let out = std::process::Command::new(cmd)
            .args(args)
            .arg(&p)
            .output()
            .unwrap();
        assert!(out.status.success(), "{cmd} {args:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let tags = "com.apple.metadata:_kMDItemUserTags";
    tool("/usr/bin/xattr", &["-wx", tags, "0102030405"]);
    tool("/bin/chmod", &["+a", "everyone allow read"]);
    let acl = |p: &Path| {
        let out = std::process::Command::new("/bin/ls")
            .arg("-le")
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).contains("everyone allow read")
    };
    assert!(acl(&p));
    storage::save(&req(&p, b"new bytes", None, &s.0)).unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"new bytes");
    assert_eq!(fs::metadata(&p).unwrap().created().unwrap(), born);
    assert!(tool("/usr/bin/xattr", &["-px", tags]).contains("01 02 03 04 05"));
    assert!(acl(&p));
    tool("/bin/chmod", &["-N"]);
}

#[test]
fn at_i06_owner_only_permissions() {
    // T22: a new vault, its backups and temp files are 0600.
    let s = Scratch::new("perm");
    let n = s.path("N.larsalvault");
    storage::save(&req(&n, b"first", None, &s.0)).unwrap();
    assert_eq!(mode(&n), 0o600);
    fs::set_permissions(&n, fs::Permissions::from_mode(0o644)).unwrap();
    let mut q = req(&n, b"second", None, &s.0);
    q.backup = Some(backup("", &s.0));
    let r = storage::save(&q).unwrap();
    let b = r.backup.unwrap().unwrap();
    assert_eq!(
        (mode(&b), mode(&n)),
        (0o600, 0o644),
        "backup 0600, vault keeps 0644"
    );
    // A kept temp file (temp_move without backup, failed move) is 0600.
    let private = s.path("private");
    let mut q = req(&n, b"third", None, &private);
    q.method = Method::TempMove;
    q.fault = fault(FaultPoint::Rename, ErrorKind::ResourceBusy);
    match storage::save(&q) {
        Err(SaveError::Write {
            kept_temp: Some(t), ..
        }) => assert_eq!(mode(&t), 0o600),
        other => panic!("{other:?}"),
    }
}

#[test]
fn at_i04_link_tricks() {
    let s = Scratch::new("hard");
    // T23: hard links split; the other link is never written.
    let h1 = s.path("H1.larsalvault");
    let h2 = s.path("H2.larsalvault");
    fs::write(&h1, b"shared old").unwrap();
    fs::hard_link(&h1, &h2).unwrap();
    storage::save(&req(&h1, b"through H1", None, &s.0)).unwrap();
    assert_eq!(fs::read(&h1).unwrap(), b"through H1");
    assert_eq!(fs::read(&h2).unwrap(), b"shared old");
    // A link planted at the temp file's name is never followed: exclusive
    // create refuses it and the victim stays as it was.
    let victim = s.path("victim.txt");
    fs::write(&victim, b"do not touch").unwrap();
    std::os::unix::fs::symlink(&victim, s.path(".H1.larsalvault.planted.tmp")).unwrap();
    let mut q = req(&h1, b"attempt", None, &s.0);
    q.fault = Some(Fault {
        at: FaultPoint::Write,
        kind: ErrorKind::Other,
        temp_name: Some(".H1.larsalvault.planted.tmp".into()),
    });
    assert!(matches!(
        storage::save(&q),
        Err(SaveError::Write {
            kind: ErrorKind::AlreadyExists,
            ..
        })
    ));
    assert_eq!(fs::read(&victim).unwrap(), b"do not touch");
    assert_eq!(fs::read(&h1).unwrap(), b"through H1");
}

#[test]
fn app05_13_failed_write_leaves_the_old_file() {
    let s = Scratch::new("fail");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"old intact").unwrap();
    // AT-I02 (by a hook; `at_i02_real_disk_full` uses a full disk image):
    // no space half way through: temp removed, old file intact.
    for at in [FaultPoint::Write, FaultPoint::Sync, FaultPoint::Rename] {
        let mut q = req(&p, b"new bytes that do not fit", None, &s.0);
        q.fault = fault(at, ErrorKind::StorageFull);
        assert_eq!(
            storage::save(&q),
            Err(SaveError::Write {
                kind: ErrorKind::StorageFull,
                kept_temp: None
            }),
            "{at:?}"
        );
        assert_eq!(fs::read(&p).unwrap(), b"old intact");
        assert_eq!(s.names(), ["P.larsalvault"], "{at:?}: temp removed");
    }
}

#[test]
fn at_i03_no_permission() {
    // T26: a read-only folder: a clear error, nothing lost.
    let s = Scratch::new("ro");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"old").unwrap();
    fs::set_permissions(&s.0, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(!storage::is_writable(&p));
    let r = storage::save(&req(&p, b"new", None, &s.0));
    fs::set_permissions(&s.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        r,
        Err(SaveError::Write {
            kind: ErrorKind::PermissionDenied,
            kept_temp: None
        })
    );
    assert_eq!(fs::read(&p).unwrap(), b"old");
    // A file without write bits is not replaced either.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(!storage::is_writable(&p));
    assert!(matches!(
        storage::save(&req(&p, b"new", None, &s.0)),
        Err(SaveError::Write {
            kind: ErrorKind::PermissionDenied,
            ..
        })
    ));
    assert_eq!(fs::read(&p).unwrap(), b"old");
}

#[test]
fn app05_14_repeated_failures() {
    // T25: the question after the third failed safe save, not before (the
    // folder is gone, a reason the other methods can help with).
    let busy = SaveError::Write {
        kind: ErrorKind::NotFound,
        kept_temp: None,
    };
    let mut f = Failures::default();
    assert!(!f.failed(&busy, Method::Safe));
    assert!(!f.failed(&busy, Method::Safe));
    assert!(f.failed(&busy, Method::Safe));
    f.reset();
    assert_eq!(f.count(), 0);
    // T26 and D-A05-2: permission, read-only and no-space failures never
    // count; a changed-on-disk refusal is not a failure.
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::ReadOnlyFilesystem,
        ErrorKind::StorageFull,
    ] {
        let e = SaveError::Write {
            kind,
            kept_temp: None,
        };
        for _ in 0..3 {
            assert!(!f.failed(&e, Method::Safe));
        }
    }
    assert!(!f.failed(&SaveError::ChangedOnDisk(checksum(b"x")), Method::Safe));
    assert_eq!(f.count(), 0);
    // Not asked again for a vault already switched to an unsafe method.
    for _ in 0..5 {
        assert!(!f.failed(&busy, Method::TempMove));
    }
}

/// F-124 (APP-05.14, F-110): another program holding the vault file's lock
/// past the wait never counts, so it never offers `MSG-SAVE-UNSAFE-ASK`:
/// the unsafe methods take the same lock.
#[test]
fn f_124_a_busy_vault_file_does_not_count() {
    let busy = SaveError::Write {
        kind: ErrorKind::ResourceBusy,
        kept_temp: None,
    };
    let mut f = Failures::default();
    for _ in 0..5 {
        assert!(!f.failed(&busy, Method::Safe));
    }
    assert_eq!(f.count(), 0);
}

#[test]
fn app05_15_temp_move() {
    let s = Scratch::new("tempmove");
    let private = s.path("private");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"old").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
    let mut q = req(&p, b"moved in", None, &private);
    q.method = Method::TempMove;
    storage::save(&q).unwrap();
    assert_eq!(
        (fs::read(&p).unwrap(), mode(&p)),
        (b"moved in".to_vec(), 0o640)
    );
    // T27: the move fails with a backup: restored from it.
    let mut q = req(&p, b"lost?", None, &private);
    q.method = Method::TempMove;
    q.backup = Some(backup("", &s.0));
    q.fault = fault(FaultPoint::Rename, ErrorKind::ResourceBusy);
    assert!(matches!(
        storage::save(&q),
        Err(SaveError::Write {
            kept_temp: None,
            ..
        })
    ));
    assert_eq!(fs::read(&p).unwrap(), b"moved in");
    // T28: without a backup the temp file with the new bytes is kept.
    let mut q = req(&p, b"keep me", None, &private);
    q.method = Method::TempMove;
    q.fault = fault(FaultPoint::Rename, ErrorKind::ResourceBusy);
    match storage::save(&q) {
        Err(SaveError::Write {
            kept_temp: Some(t), ..
        }) => {
            assert_eq!(fs::read(&t).unwrap(), b"keep me");
            let name = t.file_name().unwrap().to_string_lossy().into_owned();
            let middle = name
                .strip_prefix(".P.larsalvault.")
                .and_then(|n| n.strip_suffix(".tmp"))
                .unwrap();
            assert_eq!(middle.len(), 8);
            assert!(
                middle
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn app05_16_direct() {
    let s = Scratch::new("direct");
    let p = s.path("P.larsalvault");
    let h = s.path("H.larsalvault");
    fs::write(&p, b"old bytes").unwrap();
    fs::hard_link(&p, &h).unwrap();
    let inode = fs::metadata(&p).unwrap().ino();
    let mut q = req(&p, b"in place", None, &s.0);
    q.method = Method::Direct;
    storage::save(&q).unwrap();
    assert_eq!(fs::metadata(&p).unwrap().ino(), inode, "same inode");
    assert_eq!(fs::read(&h).unwrap(), b"in place", "hard links stay");
    // T29: a write failure after the truncation puts the old bytes back.
    let mut q = req(&p, b"cut off", None, &s.0);
    q.method = Method::Direct;
    q.fault = fault(FaultPoint::Write, ErrorKind::StorageFull);
    assert!(storage::save(&q).is_err());
    assert_eq!(fs::read(&p).unwrap(), b"in place");
}

#[test]
fn app05_17_no_lock_files_or_cleanup() {
    // T30: only the vault and its backup in the folder.
    let s = Scratch::new("tidy");
    let p = s.path("Personal.larsalvault");
    fs::write(&p, b"v1").unwrap();
    let mut q = req(&p, b"v2", None, &s.0);
    q.backup = Some(backup("", &s.0));
    storage::save(&q).unwrap();
    assert_eq!(
        s.names(),
        ["Personal.larsalvault", "Personal.old.larsalvault"]
    );
    // Leftovers of an interrupted save are not deleted (APP-05.17).
    fs::write(s.path(".Personal.larsalvault.abcdefgh.tmp"), b"leftover").unwrap();
    storage::save(&req(&p, b"v3", None, &s.0)).unwrap();
    assert!(
        s.names()
            .contains(&".Personal.larsalvault.abcdefgh.tmp".to_owned())
    );
}

#[test]
fn app05_18_writable_check() {
    let s = Scratch::new("writable");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"x").unwrap();
    assert!(storage::is_writable(&p));
    assert!(storage::is_writable(&s.path("new.larsalvault")));
    assert_eq!(s.names(), ["P.larsalvault"], "the check leaves nothing");
}

#[test]
fn app05_19_backup_before_save() {
    // T32: the backup equals the file after the previous save.
    let s = Scratch::new("backup");
    let p = s.path("Personal.larsalvault");
    let mut q = req(&p, b"save 1", None, &s.0);
    q.backup = Some(backup("", &s.0));
    // T33: a new vault's first save makes no backup.
    assert_eq!(storage::save(&q).unwrap().backup, None);
    let mut q = req(&p, b"save 2", None, &s.0);
    q.backup = Some(backup("", &s.0));
    let r = storage::save(&q).unwrap();
    let b = r.backup.unwrap().unwrap();
    assert_eq!(b, storage::real_path(&s.path("Personal.old.larsalvault")));
    assert_eq!(fs::read(&b).unwrap(), b"save 1");
    // T39: a backup that cannot be made: the save goes on, reported.
    let locked = s.path("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    let pattern = format!("{}/{{FILE_NAME}}.bak", locked.display());
    let mut q = req(&p, b"save 3", None, &s.0);
    q.backup = Some(backup(&pattern, &s.0));
    let r = storage::save(&q).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(r.backup, Some(Err(ErrorKind::PermissionDenied)));
    assert_eq!(fs::read(&p).unwrap(), b"save 3");
}

#[test]
fn app05_20_backup_path_pattern() {
    // T34, T35, T36.
    let vault = Path::new("/Users/demo/Vaults/Personal.larsalvault");
    let home = Path::new("/Users/demo");
    let path = |pattern: &str| backup_path(pattern, vault, local(), 7, home);
    for (pattern, want) in [
        (
            "{FILE_NAME}.old.larsalvault",
            "/Users/demo/Vaults/Personal.old.larsalvault",
        ),
        ("{TIME}", "/Users/demo/Vaults/25_10_2026_14-03-09"),
        (
            "{TIME:yyyyMMdd_HHmmss}",
            "/Users/demo/Vaults/20261025_140309",
        ),
        (
            "backups/{FILE_NAME}_{TIME:yyyy-MM-dd}.larsalvault",
            "/Users/demo/Vaults/backups/Personal_2026-10-25.larsalvault",
        ),
        (
            "{FILE_NAME} {TIME:yy} {FILE_NAME}",
            "/Users/demo/Vaults/Personal 26 Personal",
        ),
        ("\\{FILE_NAME\\}", "/Users/demo/Vaults/{FILE_NAME}"),
        ("{NO_MATCH}", "/Users/demo/Vaults/{NO_MATCH}"),
        ("{FILE_NAME", "/Users/demo/Vaults/{FILE_NAME"),
        ("{TIME:}", "/Users/demo/Vaults/25_10_2026_14-03-09"),
        ("{TIME:'at' HH'h'}", "/Users/demo/Vaults/at 14h"),
        (
            "{TIME:d-M-H-m-s-zzz}",
            "/Users/demo/Vaults/25-10-14-3-9-007",
        ),
        ("", "/Users/demo/Vaults/Personal.old.larsalvault"),
    ] {
        assert_eq!(path(pattern), PathBuf::from(want), "{pattern}");
    }
    let odd = Path::new("/v/{TIME}.larsalvault");
    assert_eq!(
        backup_path("{FILE_NAME}.bak", odd, local(), 0, home),
        PathBuf::from("/v/{TIME}.bak")
    );
    for (name, want) in [
        ("a.b.larsalvault", "/v/a.b.x"),
        ("noext", "/v/noext.x"),
        (".larsalvault", "/v/.x"),
    ] {
        assert_eq!(
            backup_path(
                "{FILE_NAME}.x",
                &Path::new("/v").join(name),
                local(),
                0,
                home
            ),
            PathBuf::from(want)
        );
    }
}

#[test]
fn app05_21_backup_path_resolution() {
    // T37: `~/` from home, the folder made, mode 0600.
    let s = Scratch::new("home");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"v1").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    let mut q = req(&p, b"v2", None, &s.0);
    q.backup = Some(backup("~/Backups/{FILE_NAME}.old.larsalvault", &s.0));
    let b = storage::save(&q).unwrap().backup.unwrap().unwrap();
    assert_eq!(b, s.path("Backups/P.old.larsalvault"));
    assert_eq!(mode(&b), 0o600);
}

#[test]
fn app05_22_time_slots() {
    // T38: a pattern with the time makes a file per slot, none deleted.
    let s = Scratch::new("slots");
    let p = s.path("P.larsalvault");
    fs::write(&p, b"v1").unwrap();
    for (i, second) in [9u32, 10].into_iter().enumerate() {
        let mut t = local();
        t.second = second;
        let mut q = req(&p, if i == 0 { b"v2" } else { b"v3" }, None, &s.0);
        q.backup = Some(Backup {
            pattern: "{FILE_NAME}_{TIME:HHmmss}.larsalvault",
            local: t,
            millis: 0,
            home: &s.0,
        });
        storage::save(&q).unwrap();
    }
    assert_eq!(
        s.names(),
        [
            "P.larsalvault",
            "P_140309.larsalvault",
            "P_140310.larsalvault"
        ]
    );
}

#[test]
fn app05_24_change_detection() {
    // T40 to T42: a rewrite is noticed; Larsal's own save is not; a missing
    // file raises nothing.
    let s = Scratch::new("watch");
    let p = s.path("P.larsalvault");
    let r = storage::save(&req(&p, b"by Larsal", None, &s.0)).unwrap();
    assert_eq!(changed_on_disk(&p, &r.checksum), None);
    fs::write(&p, b"by another tool").unwrap();
    assert_eq!(
        changed_on_disk(&p, &r.checksum),
        Some(checksum(b"by another tool"))
    );
    fs::remove_file(&p).unwrap();
    assert_eq!(changed_on_disk(&p, &r.checksum), None);
    // The checksum covers the first 1,024 bytes and the length.
    let a = vec![1u8; 2_000];
    let mut b = a.clone();
    b[1_500] = 2;
    assert_eq!(checksum(&a), checksum(&b));
    b.push(0);
    assert_ne!(checksum(&a), checksum(&b));
    let mut c = a.clone();
    c[10] = 9;
    assert_ne!(checksum(&a), checksum(&c));
}

#[test]
fn app05_33_old_copies_after_a_key_change() {
    // T57: the vault's own backups and its recovery copy, not others.
    let s = Scratch::new("copies");
    let p = s.path("Personal.larsalvault");
    for name in [
        "Personal.larsalvault",
        "Personal_140309.larsalvault",
        "Personal_140310.larsalvault",
        "Other_140311.larsalvault",
    ] {
        fs::write(s.path(name), b"x").unwrap();
    }
    let recovery = s.path("recovery.larsalvault");
    fs::write(&recovery, b"r").unwrap();
    let list = storage::old_copies(
        "{FILE_NAME}_{TIME:HHmmss}.larsalvault",
        &p,
        &s.0,
        Some(&recovery),
    );
    assert_eq!(
        list,
        [
            s.path("Personal_140309.larsalvault"),
            s.path("Personal_140310.larsalvault"),
            recovery
        ]
    );
    // T56: the default pattern.
    fs::write(s.path("Personal.old.larsalvault"), b"b").unwrap();
    assert_eq!(
        storage::old_copies("", &p, &s.0, None),
        [s.path("Personal.old.larsalvault")]
    );
    // T59: nothing made, nothing listed.
    assert!(storage::old_copies("{FILE_NAME}.none", &p, &s.0, None).is_empty());
}

// ---------------------------------------------------------------------------
// AT-I05: two writers, merged without lost entries.

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

fn file_of(v: &Vault) -> Vec<u8> {
    let pw = SecretString::new("demo-pass-1".into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let Saved::File(f) =
        larsal_format::save(v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    f.bytes
}

fn open(bytes: &[u8]) -> Vault {
    let pw = SecretString::new("demo-pass-1".into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let Opened::Vault(o) =
        larsal_format::open(bytes, &creds, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    o.vault
}

fn entry(b: u8, title: &str, t: larsal_model::Time) -> Entry {
    let mut e = Entry::new(Uuid([b; 16]), t);
    e.set_field(
        "Title".into(),
        Field {
            value: SecretString::new(title.into()),
            protected: false,
        },
    );
    e
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v
        .root
        .all_entries()
        .map(|e| e.value("Title").to_owned())
        .collect();
    t.sort();
    t
}

#[test]
fn at_i05_two_writers() {
    // T46: P has an unsaved change; the disk copy gained an entry from the
    // other writer. The save refuses, the merge keeps both, the next save
    // writes both.
    let s = Scratch::new("writers");
    let p = s.path("Personal.larsalvault");
    let t0 = at(2026, 1, 1, 0, 0, 0);
    let mut base = Vault::new(Group::new(Uuid([1; 16]), "Root".into(), t0), t0);
    base.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    base.root.entries.push(entry(0x0a, "Demo Mail", t0));
    let first = storage::save(&req(&p, &file_of(&base), None, &s.0)).unwrap();
    // The other writer: opens, adds "Demo Shop", saves.
    let mut other = open(&fs::read(&p).unwrap());
    other
        .root
        .entries
        .push(entry(0x0b, "Demo Shop", at(2026, 2, 1, 0, 0, 0)));
    let theirs = storage::save(&req(&p, &file_of(&other), Some(first.checksum), &s.0)).unwrap();
    // Larsal, still holding the first version, renames "Demo Mail".
    let mut mine = open(&file_of(&base));
    let mail = mine
        .root
        .entries
        .iter_mut()
        .find(|e| e.uuid == Uuid([0x0a; 16]))
        .unwrap();
    *mail = entry(0x0a, "Demo Mail 2", at(2026, 3, 1, 0, 0, 0));
    let my_bytes = file_of(&mine);
    let refused = storage::save(&req(&p, &my_bytes, Some(first.checksum), &s.0));
    assert_eq!(refused, Err(SaveError::ChangedOnDisk(theirs.checksum)));
    // Merge then save (APP-05.28, MOD-11.29: the disk version is the target).
    let disk_bytes = fs::read(&p).unwrap();
    let mut disk = open(&disk_bytes);
    merge(
        &mut disk,
        &mine,
        &Options::new(Kind::ChangeOnDisk),
        at(2026, 4, 1, 0, 0, 0),
    )
    .unwrap();
    storage::save(&req(&p, &file_of(&disk), Some(checksum(&disk_bytes)), &s.0)).unwrap();
    assert_eq!(
        titles(&open(&fs::read(&p).unwrap())),
        ["Demo Mail 2", "Demo Shop"]
    );
    // A sync service's conflict copy merges in the same way (MOD-11.1).
    let copy = s.path("Personal (conflict).larsalvault");
    let mut conflicted = open(&disk_bytes);
    conflicted
        .root
        .entries
        .push(entry(0x0c, "Demo Bank", at(2026, 5, 1, 0, 0, 0)));
    fs::write(&copy, file_of(&conflicted)).unwrap();
    let mut current = open(&fs::read(&p).unwrap());
    merge(
        &mut current,
        &open(&fs::read(&copy).unwrap()),
        &Options::new(Kind::Window),
        at(2026, 6, 1, 0, 0, 0),
    )
    .unwrap();
    assert_eq!(titles(&current), ["Demo Bank", "Demo Mail 2", "Demo Shop"]);
}

// ---------------------------------------------------------------------------
// AT-I01: killed at random points during 1,000 saves.

const CRASH_ENV: &str = "LARSAL_TEST_CRASH_DIR";
const VERSION_BYTES: usize = 256 * 1024;

/// Version `n`: a header with `n`, filler made from `n`, a SHA-256 trailer
/// over the rest, so a cut or mixed file never passes `version_of`.
fn version(n: u64) -> Vec<u8> {
    let mut out = format!("APP05 TEST VERSION {n:020}\n").into_bytes();
    let mut x = n.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while out.len() < VERSION_BYTES - 32 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push(x as u8);
    }
    let digest = larsal_crypto::hash::sha256(&[&out]);
    out.extend_from_slice(digest.expose());
    out
}

fn version_of(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != VERSION_BYTES {
        return None;
    }
    let (body, trailer) = bytes.split_at(VERSION_BYTES - 32);
    if larsal_crypto::hash::sha256(&[body]).expose() != trailer {
        return None;
    }
    let head = std::str::from_utf8(body.get(19..39)?).ok()?;
    head.parse().ok()
}

/// The child: saves versions 1, 2, … until it is killed, logging each
/// finished save as one 8-byte record. Does nothing outside that test.
#[test]
#[ignore = "the AT-I01 child process; started by at_i01_killed_mid_save"]
fn app05_crash_child() {
    let Some(dir) = std::env::var_os(CRASH_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let vault = dir.join("V.larsalvault");
    let log = dir.join("done.log");
    let mut known = read_checksum(&vault).unwrap();
    let mut n = 0u64;
    loop {
        n += 1;
        let bytes = version(n);
        let r = storage::save(&req(&vault, &bytes, known, &dir)).unwrap();
        known = Some(r.checksum);
        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log)
            .unwrap();
        std::io::Write::write_all(&mut f, &n.to_le_bytes()).unwrap();
    }
}

#[test]
fn at_i01_killed_mid_save() {
    let s = Scratch::new("crash");
    let exe = std::env::current_exe().unwrap();
    let mut seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    let mut random = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    const RUNS: usize = 1_000;
    const PARALLEL: usize = 8;
    let (mut mid, mut done, mut writing) = (0usize, 0usize, 0usize);
    for batch in 0..RUNS / PARALLEL {
        let mut children = Vec::new();
        for k in 0..PARALLEL {
            let dir = s.path(&format!("run{}", batch * PARALLEL + k));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("V.larsalvault"), version(0)).unwrap();
            let child = std::process::Command::new(&exe)
                .args([
                    "app05_crash_child",
                    "--exact",
                    "--ignored",
                    "--test-threads=1",
                    "--quiet",
                ])
                .env(CRASH_ENV, &dir)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            children.push((dir, child, Duration::from_millis(random(80))));
        }
        let started = std::time::Instant::now();
        let mut order: Vec<usize> = (0..children.len()).collect();
        order.sort_by_key(|&i| children[i].2);
        for i in order {
            let (_, child, delay) = &mut children[i];
            if let Some(wait) = delay.checked_sub(started.elapsed()) {
                std::thread::sleep(wait);
            }
            let _ = child.kill();
        }
        for (dir, mut child, _) in children {
            child.wait().unwrap();
            let logged = fs::read(dir.join("done.log")).map_or(0, |b| b.len() / 8) as u64;
            let bytes =
                fs::read(dir.join("V.larsalvault")).expect("the vault file is always there");
            let v =
                version_of(&bytes).expect("the vault file is a whole version, never a broken one");
            assert!(
                v == logged || v == logged + 1,
                "old or new: file {v}, last finished {logged}"
            );
            if v == logged + 1 {
                mid += 1;
            }
            if logged > 0 {
                done += 1;
            }
            // A temp file left over: killed while writing the next version.
            if fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            {
                writing += 1;
            }
            fs::remove_dir_all(&dir).unwrap();
        }
    }
    println!(
        "AT-I01: {RUNS} runs; {done} killed after at least one save; {writing} killed while writing a temp file; {mid} with the newest save not yet logged"
    );
    assert!(
        done > RUNS / 4,
        "most runs were killed while saving ({done})"
    );
}

/// AT-I02 with a real full disk: a 1 MiB disk image (macOS `hdiutil`).
/// Run on purpose: `cargo test -p larsal-core --test app05 -- --ignored at_i02`.
#[test]
#[ignore = "mounts a small disk image; run on purpose"]
fn at_i02_real_disk_full() {
    let s = Scratch::new("diskfull");
    let img = s.path("small.dmg");
    let mnt = s.path("mnt");
    fs::create_dir(&mnt).unwrap();
    let ok = |args: &[&str]| {
        std::process::Command::new("hdiutil")
            .args(args)
            .status()
            .is_ok_and(|x| x.success())
    };
    assert!(ok(&[
        "create",
        "-size",
        "1m",
        "-fs",
        "HFS+",
        "-volname",
        "larsaltest",
        "-layout",
        "NONE",
        img.to_str().unwrap()
    ]));
    assert!(ok(&[
        "attach",
        "-nobrowse",
        "-noautoopen",
        "-mountpoint",
        mnt.to_str().unwrap(),
        img.to_str().unwrap()
    ]));
    let p = mnt.join("P.larsalvault");
    let old = vec![7u8; 300 * 1024];
    let first = storage::save(&req(&p, &old, None, &s.0));
    let full = storage::save(&req(&p, &vec![9u8; 700 * 1024], None, &s.0));
    let leftovers: Vec<String> = fs::read_dir(&mnt)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    let intact = fs::read(&p).map(|b| b == old);
    let _ = ok(&["detach", mnt.to_str().unwrap()]);
    first.unwrap();
    assert!(
        matches!(
            full,
            Err(SaveError::Write {
                kind: ErrorKind::StorageFull,
                ..
            })
        ),
        "{full:?}"
    );
    assert!(intact.unwrap(), "the old file is intact");
    assert!(leftovers.is_empty(), "the temp file was removed");
}

// ---------------------------------------------------------------------------
// Checker fix pass: LD-131 and the surviving mutants.

fn is_link(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

#[test]
fn ld131_backup_never_written_through_a_planted_link() {
    // S15-B1: a symlink and a hard link planted at the backup name.
    for hard in [false, true] {
        let s = Scratch::new("backup-link");
        let v = s.path("V.larsalvault");
        fs::write(&v, b"OLD").unwrap();
        let victim = s.path("victim.txt");
        fs::write(&victim, b"do not touch").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        let planted = s.path("V.old.larsalvault");
        if hard {
            fs::hard_link(&victim, &planted).unwrap();
        } else {
            std::os::unix::fs::symlink(&victim, &planted).unwrap();
        }
        let mut q = req(&v, b"NEW", None, &s.0);
        q.backup = Some(backup("", &s.0));
        let r = storage::save(&q).unwrap();
        assert_eq!(r.backup, Some(Ok(storage::real_path(&planted))));
        assert_eq!(
            (fs::read(&victim).unwrap(), mode(&victim)),
            (b"do not touch".to_vec(), 0o644),
            "hard link: {hard}"
        );
        assert!(!is_link(&planted));
        assert_eq!(
            (fs::read(&planted).unwrap(), mode(&planted)),
            (b"OLD".to_vec(), 0o600)
        );
        assert_eq!(fs::read(&v).unwrap(), b"NEW");
    }
}

/// The first `.V.larsalvault.*.tmp` name in `dir` that is a plain file.
fn temp_in(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            let n = p.file_name().unwrap().to_string_lossy().into_owned();
            n.starts_with(".V.larsalvault.") && n.ends_with(".tmp") && !is_link(p)
        })
}

#[test]
fn ld131_temp_swapped_for_a_link_is_caught() {
    // S15-B2: another writer in the folder swaps the temp file for a symlink
    // to a private file while Larsal writes and syncs 256 MiB.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let s = Scratch::new("temp-race");
    let v = s.path("V.larsalvault");
    fs::write(&v, b"OLD").unwrap();
    fs::set_permissions(&v, fs::Permissions::from_mode(0o644)).unwrap();
    let victim = s.path("id_demo_key");
    fs::write(&victim, b"PRIVATE KEY DEMO").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = vec![7u8; 256 << 20];
    let stop = Arc::new(AtomicBool::new(false));
    let (dir, target, halt) = (s.0.clone(), victim.clone(), stop.clone());
    let attacker = std::thread::spawn(move || {
        while !halt.load(Ordering::Relaxed) {
            if let Some(p) = temp_in(&dir) {
                fs::remove_file(&p).unwrap();
                std::os::unix::fs::symlink(&target, &p).unwrap();
                return Some(p);
            }
        }
        None
    });
    let result = storage::save(&req(&v, &bytes, None, &s.0));
    stop.store(true, Ordering::Relaxed);
    let swapped = attacker
        .join()
        .unwrap()
        .expect("the swap happened during the save");
    assert_eq!(
        result,
        Err(SaveError::Write {
            kind: ErrorKind::Other,
            kept_temp: None
        })
    );
    assert_eq!(
        (fs::read(&victim).unwrap(), mode(&victim)),
        (b"PRIVATE KEY DEMO".to_vec(), 0o600)
    );
    assert!(!is_link(&v));
    assert_eq!((fs::read(&v).unwrap(), mode(&v)), (b"OLD".to_vec(), 0o644));
    assert!(is_link(&swapped), "the other writer's link is left alone");
    println!("RACE swap at {} caught: {result:?}", swapped.display());
}

#[test]
fn ld131_change_on_disk_found_again_before_the_rename() {
    let s = Scratch::new("recheck");
    let v = s.path("V.larsalvault");
    fs::write(&v, b"VERSION A").unwrap();
    let last = read_checksum(&v).unwrap();
    let bytes = vec![9u8; 256 << 20];
    let (dir, vault) = (s.0.clone(), v.clone());
    let other = std::thread::spawn(move || {
        while temp_in(&dir).is_none() {}
        fs::write(&vault, b"VERSION B FROM ANOTHER MAC").unwrap();
    });
    let result = storage::save(&req(&v, &bytes, last, &s.0));
    other.join().unwrap();
    assert!(
        matches!(result, Err(SaveError::ChangedOnDisk(_))),
        "{result:?}"
    );
    assert_eq!(fs::read(&v).unwrap(), b"VERSION B FROM ANOTHER MAC");
    assert_eq!(s.names(), ["V.larsalvault"], "temp removed");
}

#[test]
fn ld131_direct_refuses_a_dangling_link() {
    let s = Scratch::new("dangling");
    let v = s.path("V.larsalvault");
    let elsewhere = s.path("sub").join("created.txt");
    fs::create_dir_all(s.path("sub")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &v).unwrap();
    let mut q = req(&v, b"NEW", None, &s.0);
    q.method = Method::Direct;
    assert_eq!(
        storage::save(&q),
        Err(SaveError::Write {
            kind: ErrorKind::NotFound,
            kept_temp: None
        })
    );
    assert!(!elsewhere.exists() && is_link(&v));
}

#[test]
fn ld131_long_vault_names_save() {
    let s = Scratch::new("long");
    let private = s.path("private");
    for total in [242, 250, 255] {
        let name = format!("{}.larsalvault", "n".repeat(total - ".larsalvault".len()));
        assert_eq!(name.len(), total);
        let v = s.path(&name);
        fs::write(&v, b"OLD").unwrap();
        storage::save(&req(&v, b"NEW", None, &s.0)).unwrap();
        let mut q = req(&v, b"MOVED", None, &private);
        q.method = Method::TempMove;
        storage::save(&q).unwrap();
        assert_eq!(fs::read(&v).unwrap(), b"MOVED", "{total}");
    }
    // Multi-byte names are cut on a character boundary.
    let v = s.path(&format!("{}.larsalvault", "é".repeat(120)));
    fs::write(&v, b"OLD").unwrap();
    storage::save(&req(&v, b"NEW", None, &s.0)).unwrap();
    assert_eq!(fs::read(&v).unwrap(), b"NEW");
}

#[test]
fn app05_16_reads_bounded_by_the_file_limit() {
    // A sparse file one byte over the total file limit (no disk used).
    let s = Scratch::new("bounded");
    let v = s.path("V.larsalvault");
    fs::File::create(&v)
        .unwrap()
        .set_len(storage::MAX_FILE + 1)
        .unwrap();
    let mut q = req(&v, b"NEW", None, &s.0);
    q.method = Method::Direct;
    assert_eq!(
        storage::save(&q),
        Err(SaveError::Write {
            kind: ErrorKind::FileTooLarge,
            kept_temp: None
        })
    );
    assert_eq!(fs::metadata(&v).unwrap().len(), storage::MAX_FILE + 1);
    let mut q = req(&v, b"NEW", None, &s.0);
    q.backup = Some(backup("", &s.0));
    let r = storage::save(&q).unwrap();
    assert_eq!(r.backup, Some(Err(ErrorKind::FileTooLarge)));
    assert_eq!(fs::read(&v).unwrap(), b"NEW");
}

#[test]
fn app05_storage_survivors() {
    // SG09: byte 1,023 is inside the checksum; byte 1,024 is not.
    let a = vec![0u8; 2_000];
    let mut b = a.clone();
    b[1_023] = 1;
    assert_ne!(checksum(&a), checksum(&b));
    let mut c = a.clone();
    c[1_024] = 1;
    assert_eq!(checksum(&a), checksum(&c));
    let s = Scratch::new("survivors");
    let private = s.path("private");
    // SG21: the old vault cannot be removed (its folder is read-only): that
    // error. (A folder at the vault path is refused before any write, F-101.)
    let ro = s.path("ro");
    fs::create_dir(&ro).unwrap();
    let held = ro.join("D.larsalvault");
    fs::write(&held, b"OLD").unwrap();
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
    let mut q = req(&held, b"NEW", None, &private);
    q.method = Method::TempMove;
    match storage::save(&q) {
        Err(SaveError::Write {
            kind,
            kept_temp: Some(t),
        }) => {
            assert_eq!(kind, ErrorKind::PermissionDenied);
            assert_eq!((fs::read(&t).unwrap(), mode(&t)), (b"NEW".to_vec(), 0o600));
            fs::remove_file(t).unwrap();
        }
        other => panic!("{other:?}"),
    }
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
    // SG23: a failed move with a backup removes the temp file.
    let v = s.path("V.larsalvault");
    fs::write(&v, b"OLD").unwrap();
    let mut q = req(&v, b"NEW", None, &private);
    q.method = Method::TempMove;
    q.backup = Some(backup("", &s.0));
    q.fault = fault(FaultPoint::Rename, ErrorKind::ResourceBusy);
    assert!(storage::save(&q).is_err());
    assert_eq!(fs::read(&v).unwrap(), b"OLD");
    assert_eq!(fs::read_dir(&private).unwrap().count(), 0, "temp removed");
    // SG29: a backup over an older 0644 backup is 0600.
    fs::set_permissions(&v, fs::Permissions::from_mode(0o644)).unwrap();
    let old = s.path("V.old.larsalvault");
    fs::set_permissions(&old, fs::Permissions::from_mode(0o644)).unwrap();
    let mut q = req(&v, b"NEW", None, &s.0);
    q.backup = Some(backup("", &s.0));
    storage::save(&q).unwrap();
    assert_eq!((mode(&old), mode(&v)), (0o600, 0o644));
}

#[test]
fn app05_20_pattern_survivors() {
    let vault = Path::new("/Users/demo/Vaults/Personal.larsalvault");
    let home = Path::new("/Users/demo");
    let path = |pattern: &str| backup_path(pattern, vault, local(), 7, home);
    // SG37: a format with a backslash is kept as text.
    assert_eq!(
        path("{TIME:a\\b}.bak"),
        Path::new("/Users/demo/Vaults/{TIME:a\\b}.bak")
    );
    // SG40: hh is the 24-hour hour; SG42: '' is one quote.
    assert_eq!(path("{TIME:hh''mm}"), Path::new("/Users/demo/Vaults/14'03"));
}

#[test]
fn app05_33_old_copies_survivors() {
    let s = Scratch::new("globs");
    let v = s.path("abba.larsalvault");
    for name in [
        "abba.larsalvault",
        "abba-1.larsalvault",
        "abba-x.larsalvault",
    ] {
        fs::write(s.path(name), b"x").unwrap();
    }
    // SG43: the vault itself matches the glob but is never listed.
    assert_eq!(
        storage::old_copies("{FILE_NAME}{TIME}.larsalvault", &v, &s.0, None),
        [s.path("abba-1.larsalvault"), s.path("abba-x.larsalvault")]
    );
    // SG45: a middle part must be there.
    assert_eq!(
        storage::old_copies("{FILE_NAME}{TIME}1{TIME}.larsalvault", &v, &s.0, None),
        [s.path("abba-1.larsalvault")]
    );
    // SG45: middle parts in order, each after the one before.
    let s2 = Scratch::new("globs-order");
    let w = s2.path("abba.larsalvault");
    for name in [
        "abba-1-2.larsalvault",
        "abba-2-1.larsalvault",
        "abba-1.larsalvault",
    ] {
        fs::write(s2.path(name), b"x").unwrap();
    }
    assert_eq!(
        storage::old_copies(
            "{FILE_NAME}{TIME}1{TIME}2{TIME}.larsalvault",
            &w,
            &s2.0,
            None
        ),
        [s2.path("abba-1-2.larsalvault")]
    );
    assert!(
        storage::old_copies(
            "{FILE_NAME}{TIME}1{TIME}1{TIME}.larsalvault",
            &w,
            &s2.0,
            None
        )
        .is_empty()
    );
    // SG46: the first and last parts may not overlap ("ab*ba" is not "aba").
    fs::write(s.path("aba"), b"x").unwrap();
    assert!(storage::old_copies("ab{TIME}ba", &v, &s.0, None).is_empty());
}

/// INT-10.20: `SaveRequest::plain` saves the safe way and keeps the
/// pre-save check.
#[test]
fn int10_20_plain_request() {
    let dir = std::env::temp_dir().join(format!("app05-plain-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.larsalvault");
    fs::write(&path, b"old bytes").unwrap();
    let last = read_checksum(&path).unwrap();
    let r = SaveRequest::plain(&path, b"new bytes", last, &dir);
    assert_eq!(
        (r.method, r.ignore_disk_changes, r.backup.is_none()),
        (Method::Safe, false, true)
    );
    storage::save(&r).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new bytes");
    let stale = SaveRequest::plain(&path, b"third", last, &dir);
    assert!(matches!(
        storage::save(&stale),
        Err(SaveError::ChangedOnDisk(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"new bytes");
    fs::remove_dir_all(&dir).unwrap();
}

/// F-047 hook: another writer moves the vault's folder away right before
/// the rename and puts a new folder at its path, with its own file at the
/// temp name and at the vault name.
fn swap_folder(temp: &Path) {
    let dir = temp.parent().unwrap();
    fs::rename(dir, dir.with_extension("moved")).unwrap();
    fs::create_dir(dir).unwrap();
    fs::write(temp, b"PLANTED").unwrap();
    fs::write(dir.join("V.larsalvault"), b"OTHER").unwrap();
}

/// F-047: the rename stays in the folder Larsal opened and checked; nothing
/// in the folder now at that path is moved.
#[test]
fn f_047_rename_stays_in_the_folder_it_checked() {
    let s = Scratch::new("f047-folder");
    let dir = s.path("box");
    fs::create_dir(&dir).unwrap();
    let v = dir.join("V.larsalvault");
    fs::write(&v, b"OLD").unwrap();
    let mut q = req(&v, b"NEW", None, &s.0);
    q.fault = Some(Fault {
        at: FaultPoint::Swap(swap_folder),
        kind: ErrorKind::Other,
        temp_name: None,
    });
    storage::save(&q).unwrap();
    assert_eq!(fs::read(s.path("box.moved/V.larsalvault")).unwrap(), b"NEW");
    assert_eq!(fs::read(&v).unwrap(), b"OTHER");
    let mut left: Vec<Vec<u8>> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| fs::read(e.unwrap().path()).unwrap())
        .collect();
    left.sort();
    assert_eq!(left, [b"OTHER".to_vec(), b"PLANTED".to_vec()]);
}

/// F-047 hook: another writer in the folder swaps the temp file for its
/// own right before the rename.
fn swap_temp(temp: &Path) {
    fs::rename(temp, temp.with_extension("kept")).unwrap();
    fs::write(temp, b"PLANTED").unwrap();
}

/// F-047: a temp file swapped after the identity check is caught at the
/// vault name: the save is not reported as done, and not as a failed write
/// that left the old file, because the vault path now holds the other
/// file: the file changed on disk, with that file's checksum.
#[test]
fn f_047_temp_swapped_after_the_check_fails_the_save() {
    let s = Scratch::new("f047-temp");
    let v = s.path("V.larsalvault");
    fs::write(&v, b"OLD").unwrap();
    let mut q = req(&v, b"NEW", None, &s.0);
    q.fault = Some(Fault {
        at: FaultPoint::Swap(swap_temp),
        kind: ErrorKind::Other,
        temp_name: None,
    });
    assert_eq!(
        storage::save(&q),
        Err(SaveError::ChangedOnDisk(checksum(b"PLANTED")))
    );
    assert_eq!(fs::read(&v).unwrap(), b"PLANTED");
}

/// Runs `job` on its own thread and gives its result, failing the test
/// when it takes a second or more; the waiting open of `fifo` is then
/// freed, as the attack's watchdog did (F-101).
fn within_a_second<T: Send + 'static>(fifo: &Path, job: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(job()));
    rx.recv_timeout(Duration::from_secs(1)).unwrap_or_else(|_| {
        let f = fifo.to_path_buf();
        std::thread::spawn(move || fs::OpenOptions::new().write(true).open(f));
        panic!("waited a second or more on the FIFO");
    })
}

fn mkfifo(p: &Path) {
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(p)
        .status()
        .unwrap();
    assert!(made.success());
}

/// F-101 (LD-225 (1)): a FIFO at the vault path, behind a link, or as the
/// Save As target is refused at once with `InvalidInput` before any open;
/// the checksum read and the change check never wait for a writer, and the
/// FIFO stays as it was.
#[test]
fn f_101_a_fifo_vault_path_or_save_as_target_is_refused_at_once() {
    use std::os::unix::fs::FileTypeExt;
    let s = Scratch::new("f101");
    let fifo = s.path("V.larsalvault");
    mkfifo(&fifo);
    let link = s.path("L.larsalvault");
    std::os::unix::fs::symlink(&fifo, &link).unwrap();
    let refused = Err(SaveError::Write {
        kind: ErrorKind::InvalidInput,
        kept_temp: None,
    });
    for (path, last) in [
        (fifo.clone(), None),
        (fifo.clone(), Some(checksum(b"OLD"))),
        (link.clone(), Some(checksum(b"OLD"))),
    ] {
        let dir = s.0.clone();
        let got = within_a_second(&fifo, move || {
            storage::save(&req(&path, b"NEW", last, &dir))
        });
        assert_eq!(got, refused);
    }
    let p = fifo.clone();
    let read = within_a_second(&fifo, move || read_checksum(&p).map_err(|e| e.kind()));
    assert_eq!(read, Err(ErrorKind::InvalidInput));
    let p = fifo.clone();
    assert_eq!(
        within_a_second(&fifo, move || changed_on_disk(&p, &checksum(b"OLD"))),
        None
    );
    assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
    assert_eq!(
        s.names(),
        ["L.larsalvault", "V.larsalvault"],
        "no temp file left"
    );
    // A folder at the path is no vault file either.
    let folder = s.path("D.larsalvault");
    fs::create_dir(&folder).unwrap();
    assert_eq!(storage::save(&req(&folder, b"NEW", None, &s.0)), refused);
}

/// F-110 hook: a second writer, which read the vault as the first one did,
/// saves while the first one is between its last check and its rename.
static SECOND: std::sync::Mutex<Option<std::thread::JoinHandle<Result<SaveReport, SaveError>>>> =
    std::sync::Mutex::new(None);

fn second_writer(temp: &Path) {
    let dir = temp.parent().unwrap().to_path_buf();
    let job = std::thread::spawn(move || {
        let vault = dir.join("V.larsalvault");
        storage::save(&req(&vault, b"SECOND", Some(checksum(b"OLD")), &dir))
    });
    // Time for the second writer to save, had nothing stopped it.
    std::thread::sleep(Duration::from_millis(500));
    *SECOND.lock().unwrap() = Some(job);
}

/// F-110 (APP-05.10, SD-03): two writers of one vault take turns from the
/// last check to the rename; the second one's check sees the first save
/// and asks (ChangedOnDisk), so neither save is lost while reported done.
#[test]
fn f_110_two_writers_take_turns_and_no_save_is_lost() {
    let s = Scratch::new("f110");
    let v = s.path("V.larsalvault");
    fs::write(&v, b"OLD").unwrap();
    let mut first = req(&v, b"FIRST", Some(checksum(b"OLD")), &s.0);
    first.fault = Some(Fault {
        at: FaultPoint::Swap(second_writer),
        kind: ErrorKind::Other,
        temp_name: None,
    });
    storage::save(&first).unwrap();
    let second = SECOND.lock().unwrap().take().unwrap().join().unwrap();
    assert_eq!(
        second,
        Err(SaveError::ChangedOnDisk(checksum(b"FIRST"))),
        "the second writer's check sees the first save"
    );
    assert_eq!(fs::read(&v).unwrap(), b"FIRST");
    assert_eq!(s.names(), ["V.larsalvault"], "no temp file left");
}

/// F-269: enumeration and the absent-target guard use the same name matching.
#[test]
fn f269_old_copies_use_the_case_insensitive_backup_matcher() {
    let s = Scratch::new("backup-case");
    let vault = s.path("v.larsalvault");
    fs::write(&vault, b"demo vault").unwrap();
    fs::create_dir(s.path("v-backup-directory.larsalvault")).unwrap();
    for (pattern, name) in [
        ("", "V.OLD.LARSALVAULT"),
        (
            "{FILE_NAME}-backup-{TIME:HHmmss}.larsalvault",
            "V-BACKUP-any-text.LARSALVAULT",
        ),
    ] {
        let path = s.path(name);
        fs::write(&path, b"demo backup").unwrap();
        fs::write(s.path("other.old.larsalvault"), b"other").unwrap();
        assert!(storage::is_backup(pattern, &vault, &s.0, &path));
        assert_eq!(storage::old_copies(pattern, &vault, &s.0, None), [path]);
    }
    let alias = s.path("alias");
    std::os::unix::fs::symlink(&s.0, &alias).unwrap();
    assert_eq!(
        storage::old_copies("alias/{FILE_NAME}.old.larsalvault", &vault, &s.0, None),
        [alias.join("V.OLD.LARSALVAULT")]
    );
    // A broad pattern still excludes the vault and its hard-link alias.
    let link = s.path("V-copy.larsalvault");
    fs::hard_link(&vault, &link).unwrap();
    assert!(
        !storage::old_copies("{FILE_NAME}{TIME}.larsalvault", &vault, &s.0, None).contains(&link)
    );
    assert_eq!(fs::read(&vault).unwrap(), b"demo vault");
}

#[test]
fn f269_directory_patterns_list_every_date_and_keep_recovery_last() {
    let s = Scratch::new("backup-dates");
    let vault = s.path("V.larsalvault");
    fs::write(&vault, b"demo vault").unwrap();
    let recovery = s.path("recovery.larsalvault");
    fs::write(&recovery, b"demo recovery").unwrap();
    for pattern in [
        "backups/{TIME}/{FILE_NAME}.old.larsalvault",
        "backups/{TIME:}/{FILE_NAME}.old.larsalvault",
        "backups/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
        "backups/{TIME:yyyy/MM}/{FILE_NAME}-{TIME:dd}.old.larsalvault",
        "backups/pre{TIME:yyyy/MM}post/fixed/{FILE_NAME}-{TIME}.old.larsalvault",
        "backups/{TIME:'archive/'yyyy/'copies'/MM}/{FILE_NAME}.old.larsalvault",
        "{FILE_NAME}/{TIME:yyyy/MM/dd}/{FILE_NAME}.old.larsalvault",
        "~/home-backups/{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault",
        "{TIME:'~/'yyyy/MM}/{FILE_NAME}.old.larsalvault",
        "backups/{TIME:'./'}{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault",
        "backups/{TIME:'.'}{TIME:'.'}/{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault",
        "backups/{TIME:'/'yyyy/MM}/{FILE_NAME}.old.larsalvault",
        "backups/fixed/{TIME:'}/{FILE_NAME}.old.larsalvault",
    ] {
        let mut expected = Vec::new();
        for year in [1999, 2026] {
            let time = Civil { year, ..local() };
            let bytes = fs::read(&vault).unwrap();
            let mut q = req(&vault, &bytes, None, &s.0);
            q.backup = Some(Backup {
                pattern,
                local: time,
                millis: 7,
                home: &s.0,
            });
            let backup = backup_path(pattern, &vault, time, 7, &s.0);
            assert_eq!(storage::save(&q).unwrap().backup, Some(Ok(backup.clone())));
            assert_eq!(fs::read(&backup).unwrap(), bytes);
            assert!(storage::is_backup(pattern, &vault, &s.0, &backup));
            expected.push(backup);
        }
        expected.sort();
        let list = storage::old_copies(pattern, &vault, &s.0, Some(&recovery));
        assert!(
            expected.iter().all(|p| list.contains(p)),
            "{pattern}: {list:?}"
        );
        assert_eq!(list.last(), Some(&recovery));
        assert!(!list.contains(&vault));
    }
}

#[test]
fn f269_directory_patterns_preserve_identity_and_bound_symlink_cycles() {
    use std::os::unix::fs::symlink;
    let s = Scratch::new("backup-directory-identity");
    let vault = s.path("V.larsalvault");
    fs::write(&vault, b"demo vault").unwrap();
    let root = s.path("backups");
    fs::create_dir_all(root.join("1999/10/fixed")).unwrap();
    let backup = root.join("1999/10/fixed/V.OLD.LARSALVAULT");
    fs::write(&backup, b"demo backup").unwrap();
    symlink(&root, s.path("alias")).unwrap();
    symlink(root.join("1999/10/fixed"), s.path("date-alias")).unwrap();
    symlink(root.join("missing"), root.join("dangling")).unwrap();
    let pattern = "alias/{TIME:yyyy/MM}/fixed/{FILE_NAME}.old.larsalvault";
    assert!(storage::is_backup(
        pattern,
        &vault,
        &s.0,
        &s.path("date-alias/V.old.larsalvault")
    ));
    assert!(storage::is_backup(
        pattern,
        &vault,
        &s.0,
        &root.join("1980/01/fixed/V.old.larsalvault")
    ));
    assert!(storage::is_backup(
        pattern,
        &vault,
        &s.0,
        &s.path("alias/1980/01/fixed/V.old.larsalvault")
    ));
    let hardlink = root.join("1999/10/fixed/V-linked.old.larsalvault");
    fs::hard_link(&vault, &hardlink).unwrap();
    fs::create_dir(root.join("1999/10/fixed/V-folder.old.larsalvault")).unwrap();
    let list = storage::old_copies(
        "alias/{TIME:yyyy/MM}/fixed/{FILE_NAME}{TIME}.larsalvault",
        &vault,
        &s.0,
        None,
    );
    assert_eq!(list, [s.path("alias/1999/10/fixed/V.OLD.LARSALVAULT")]);
    for path in [
        "unrelated/1999/10/fixed/V.old.larsalvault",
        "backups/1999/10/other/V.old.larsalvault",
        "backups/1999/10/fixed/team.larsalvault",
        "backups/1999/10/extra/fixed/V.old.larsalvault",
        "backups/1999/fixed/V.old.larsalvault",
    ] {
        let path = s.path(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"unrelated demo").unwrap();
        assert!(
            !storage::is_backup(pattern, &vault, &s.0, &path),
            "{path:?}"
        );
        assert!(!storage::old_copies(pattern, &vault, &s.0, None).contains(&path));
    }
    symlink(&root, root.join("cycle")).unwrap();
    // This folder now also has a matching spelling through cycle/1999/fixed.
    assert!(storage::is_backup(
        pattern,
        &vault,
        &s.0,
        &root.join("1999/fixed/V.old.larsalvault")
    ));
    assert!(!storage::old_copies(pattern, &vault, &s.0, None).is_empty());
}

#[test]
fn f269_literal_directory_stars_keep_folder_identity() {
    let s = Scratch::new("literal-backup-stars");
    let literal = s.path("literal*");
    let unrelated = s.path("literal-other");
    for dir in [&literal, &unrelated] {
        fs::create_dir_all(dir.join("backups/1999")).unwrap();
        fs::write(dir.join("V.old.larsalvault"), b"demo").unwrap();
        fs::write(dir.join("backups/1999/V.old.larsalvault"), b"demo").unwrap();
    }
    let vault = literal.join("V.larsalvault");
    fs::write(&vault, b"demo vault").unwrap();
    for (pattern, suffix) in [
        ("", "V.old.larsalvault"),
        (
            "backups/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
            "backups/1999/V.old.larsalvault",
        ),
    ] {
        assert!(storage::is_backup(
            pattern,
            &vault,
            &s.0,
            &literal.join(suffix)
        ));
        assert!(!storage::is_backup(
            pattern,
            &vault,
            &s.0,
            &unrelated.join(suffix)
        ));
        assert_eq!(
            storage::old_copies(pattern, &vault, &s.0, None),
            [literal.join(suffix)]
        );
    }
}

#[test]
fn f269_partial_time_components_still_match_arbitrary_text() {
    let s = Scratch::new("partial-time-components");
    let vault = s.path("V.larsalvault");
    fs::write(&vault, b"demo vault").unwrap();
    for pattern in ["pre{TIME:'..'}.old", "pre{TIME:'.'}.old", "pre{TIME:'}.old"] {
        let path = s.path("pre-any-text.old");
        assert!(
            storage::is_backup(pattern, &vault, &s.0, &path),
            "{pattern}"
        );
    }
}

#[test]
fn f269_missing_literal_prefix_through_alias() {
    use std::os::unix::fs::symlink;
    let s = Scratch::new("backup-missing-prefix");
    let vault = s.path("V.larsalvault");
    fs::write(&vault, b"demo vault").unwrap();
    symlink(&s.0, s.path("alias")).unwrap();
    let pattern = "alias/new/{TIME:yyyy}/{FILE_NAME}.old.larsalvault";
    let t = Civil {
        year: 1999,
        ..local()
    };
    let backup = backup_path(pattern, &vault, t, 7, &s.0);
    let canonical_candidate = s.path("new/1999/V.old.larsalvault");
    let before_alias = storage::is_backup(pattern, &vault, &s.0, &backup);
    let before_canonical = storage::is_backup(pattern, &vault, &s.0, &canonical_candidate);
    let mut q = req(&vault, b"demo next vault", None, &s.0);
    q.backup = Some(Backup {
        pattern,
        local: t,
        millis: 7,
        home: &s.0,
    });
    assert_eq!(storage::save(&q).unwrap().backup, Some(Ok(backup.clone())));
    assert_eq!(fs::read(&backup).unwrap(), b"demo vault");
    assert_eq!(
        storage::file_id(&backup),
        storage::file_id(&canonical_candidate)
    );
    let after = storage::is_backup(pattern, &vault, &s.0, &canonical_candidate);
    println!(
        "missing literal prefix: alias={before_alias}, canonical={before_canonical}, after actual save={after}, bytes preserved=true"
    );
    assert!(after);
    assert!(
        before_alias && before_canonical,
        "permitted missing backup folders must match through aliases before creation"
    );
}

#[test]
fn f269_canonical_missing_alias_component_contract() {
    use std::os::unix::fs::symlink;
    let mut missed = Vec::new();
    for (n, (pattern, suffix)) in [
        (
            "alias/new/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
            "new/1999/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:yyyy/MM/dd}/fixed/{FILE_NAME}.old.larsalvault",
            "new/1999/10/25/fixed/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:'archive/'yyyy/'copies'/MM}/{FILE_NAME}.old.larsalvault",
            "new/archive/1999/copies/10/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:'./'}{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault",
            "new/1999/10/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:'/'yyyy/MM}/{FILE_NAME}.old.larsalvault",
            "new/1999/10/V.old.larsalvault",
        ),
        (
            "~/alias/new/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
            "new/1999/V.old.larsalvault",
        ),
        (
            "alias/new/pre{TIME:yyyy/MM}post/fixed/{FILE_NAME}.old.larsalvault",
            "new/pre1999/10post/fixed/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:yyyy}/../fixed/{FILE_NAME}.old.larsalvault",
            "new/fixed/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:yyyy/../MM}/{FILE_NAME}.old.larsalvault",
            "new/10/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:'..'}/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
            "1999/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:'.'}{TIME:'.'}/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
            "1999/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:yyyy/MM}/../fixed/{FILE_NAME}.old.larsalvault",
            "new/1999/fixed/V.old.larsalvault",
        ),
        (
            "alias/new/{TIME:yyyy}/fixed/{TIME:MM}/../../last/{FILE_NAME}.old.larsalvault",
            "new/1999/last/V.old.larsalvault",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let s = Scratch::new(&format!("f269-fix5-missing-component-{n}"));
        let vault = s.path("V.larsalvault");
        fs::write(&vault, b"demo original").unwrap();
        symlink(&s.0, s.path("alias")).unwrap();
        let t = Civil {
            year: 1999,
            ..local()
        };
        let generated = backup_path(pattern, &vault, t, 7, &s.0);
        let canonical = s.path(suffix);
        let before_generated = storage::is_backup(pattern, &vault, &s.0, &generated);
        let before_canonical = storage::is_backup(pattern, &vault, &s.0, &canonical);
        for unrelated in [
            s.path(&format!("other/{suffix}")),
            s.path(&format!("other-new/{suffix}")),
            canonical.with_file_name("team.larsalvault"),
        ] {
            assert!(
                !storage::is_backup(pattern, &vault, &s.0, &unrelated),
                "unrelated missing parent/name: {pattern} {unrelated:?}"
            );
            assert!(!unrelated.exists());
        }
        let mut q = req(&vault, b"demo next", None, &s.0);
        q.backup = Some(Backup {
            pattern,
            local: t,
            millis: 7,
            home: &s.0,
        });
        assert_eq!(
            storage::save(&q).unwrap().backup,
            Some(Ok(generated.clone()))
        );
        assert_eq!(fs::read(&generated).unwrap(), b"demo original");
        assert_eq!(fs::canonicalize(&generated).unwrap(), canonical);
        assert_eq!(storage::file_id(&generated), storage::file_id(&canonical));
        assert!(storage::is_backup(pattern, &vault, &s.0, &canonical));
        assert!(
            storage::old_copies(pattern, &vault, &s.0, None)
                .iter()
                .any(|p| storage::file_id(p) == storage::file_id(&canonical))
        );
        println!(
            "component case {n}: pattern={pattern}, before literal={before_generated}, canonical={before_canonical}, actual save=true, bytes=true, after=true"
        );
        if !(before_generated && before_canonical) {
            missed.push(n);
        }
    }
    assert!(
        missed.is_empty(),
        "permitted actual-save canonical candidates missed before creation: {missed:?}"
    );
}

#[test]
fn f269_canonical_identity_cycle_and_breadth() {
    use std::os::unix::fs::symlink;
    let s = Scratch::new("f269-fix5-cycle-breadth");
    let vault = s.path("V.larsalvault");
    fs::write(&vault, b"demo original").unwrap();
    let root = s.path("backups");
    fs::create_dir_all(root.join("1999/fixed")).unwrap();
    let candidate = root.join("1999/fixed/V.old.larsalvault");
    fs::write(&candidate, b"demo backup").unwrap();
    let pattern = "backups/{TIME:yyyy/MM}/fixed/{FILE_NAME}.old.larsalvault";
    assert!(!storage::is_backup(pattern, &vault, &s.0, &candidate));
    symlink(&root, root.join("cycle")).unwrap();
    let alternate = root.join("cycle/1999/fixed/V.old.larsalvault");
    assert_eq!(storage::file_id(&alternate), storage::file_id(&candidate));
    assert_eq!(
        storage::file_id(alternate.parent().unwrap()),
        storage::file_id(candidate.parent().unwrap())
    );
    assert!(storage::is_backup(pattern, &vault, &s.0, &candidate));
    let list = storage::old_copies(pattern, &vault, &s.0, None);
    assert_eq!(
        list.iter()
            .filter(|p| storage::file_id(p) == storage::file_id(&candidate))
            .count(),
        1
    );
    assert!(!storage::is_backup(
        pattern,
        &vault,
        &s.0,
        &s.path("unrelated/1999/fixed/V.old.larsalvault")
    ));
    for n in 0..270 {
        let dir = s.path(&format!("wide/{n:03}/fixed"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("V.old.larsalvault"), b"demo backup").unwrap();
    }
    let wide = storage::old_copies(
        "wide/{TIME:yyyy}/fixed/{FILE_NAME}.old.larsalvault",
        &vault,
        &s.0,
        None,
    );
    assert_eq!(wide.len(), 270);
    assert!(wide.windows(2).all(|w| w[0] < w[1]));
}
