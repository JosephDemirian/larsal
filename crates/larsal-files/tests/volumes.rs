//! FIL-03.8, FIL-03.9 on real volumes (C1-R2-02, C2R2-08). `LARSAL_TEST_VOLUMES` names
//! a folder with four private disk images mounted in it. `fat32`, `exfat` and
//! `noowners` cannot keep a file private; `owners` can and is the control. Attach
//! them with `hdiutil attach -nobrowse -noverify -noautoopen -mountpoint`, and with
//! `-owners on` for the control. A default run shows the check as ignored, with its
//! reason. A set path always runs, so a wrong one fails. Demo data only.

mod common;

use common::open_all;
use larsal_crypto::secret::SecretString;
use larsal_files::{
    Error, Identities, Lock, OutputFolder, Phase, Recipient, ScratchRoot, SourceFile, Unlock,
    Validated, Validation, encrypt_file, encrypt_stream,
};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const ID: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const RECIPIENT: &str = "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72";

fn keep(_: Phase, _: u64) -> bool {
    true
}

fn name(text: &str) -> &OsStr {
    text.as_ref()
}

fn chmod_acl(entry: &str, path: &Path) {
    let done = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .status()
        .unwrap();
    assert!(done.success(), "chmod +a {entry}");
}

fn chmod_no_acl(path: &Path) {
    let done = Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .status()
        .unwrap();
    assert!(done.success(), "chmod -N");
}

fn names_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with("._"))
        .collect();
    names.sort();
    names
}

/// What the volume tests share: a local private scratch folder and demo files.
struct Local {
    scratch: PathBuf,
    plain: PathBuf,
    sealed: Vec<u8>,
    bytes: Vec<u8>,
    keys: Identities,
    to: [Recipient; 1],
}

impl Local {
    fn new() -> Self {
        let scratch = std::env::temp_dir().join(format!("larsal-volumes-{}", std::process::id()));
        fs::create_dir(&scratch).unwrap();
        fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
        let plain = scratch.with_extension("plain");
        fs::write(&plain, &bytes).unwrap();
        let to = [Recipient::parse(RECIPIENT).unwrap()];
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut &bytes[..],
            &mut sealed,
            &Lock::Recipients(&to),
            &mut keep,
        )
        .unwrap();
        Self {
            scratch,
            plain,
            sealed,
            bytes,
            keys: Identities::single(&SecretString::from(ID)).unwrap(),
            to,
        }
    }

    fn validated(&self) -> Validated {
        let snapshot = ScratchRoot::open(&self.scratch)
            .unwrap()
            .capture_stream(&mut &self.sealed[..], &mut keep)
            .unwrap();
        let unwrapped = snapshot.unlock(&Unlock::Identities(&self.keys)).unwrap();
        match unwrapped.validate(&mut keep).unwrap() {
            Validation::Ready(v) => v,
            Validation::Weak(_) => panic!("X25519 files have no work factor"),
        }
    }

    fn encrypt_to(&self, dir: &Path, file: &str) -> Result<u64, Error> {
        encrypt_file(
            SourceFile::open(&self.plain).unwrap(),
            &OutputFolder::open(dir).unwrap(),
            name(file),
            &Lock::Recipients(&self.to),
            &mut keep,
        )
    }

    fn save_to(&self, dir: &Path, file: &str) -> Result<u64, Error> {
        self.validated()
            .save_new(&OutputFolder::open(dir).unwrap(), name(file), &mut keep)
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.scratch);
        let _ = fs::remove_file(&self.plain);
    }
}

/// A new folder on the volume, for this run.
fn work_folder(base: &Path, volume: &str) -> PathBuf {
    let mount = base.join(volume);
    assert!(mount.is_dir(), "no volume at {}", mount.display());
    let dir = mount.join(format!("run-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    dir
}

/// FAT32, exFAT, a mount with no owners.
fn cannot_keep_a_file_private(local: &Local, base: &Path, volume: &str) {
    let dir = work_folder(base, volume);

    // Plaintext: refused, with its own reason, and nothing stays.
    assert_eq!(
        local.save_to(&dir, "demo.out"),
        Err(Error::Unprotected),
        "{volume}"
    );
    assert!(names_in(&dir).is_empty(), "{volume}");

    // Ciphertext: goes there and opens, and a taken name is still taken.
    assert_eq!(local.encrypt_to(&dir, "demo.age"), Ok(200_000), "{volume}");
    let written = fs::read(dir.join("demo.age")).unwrap();
    let opened = open_all(&written, &Unlock::Identities(&local.keys)).unwrap();
    assert_eq!(opened.expose(), &local.bytes[..], "{volume}");
    assert_eq!(
        local.encrypt_to(&dir, "demo.age"),
        Err(Error::Exists),
        "{volume}"
    );

    // A cancel is a cancel: the name gone and nothing left is not a cleanup failure,
    // though the volume may go on showing one link.
    let result = encrypt_file(
        SourceFile::open(&local.plain).unwrap(),
        &OutputFolder::open(&dir).unwrap(),
        name("stopped.age"),
        &Lock::Recipients(&local.to),
        &mut |_, _| false,
    );
    assert_eq!(result, Err(Error::Cancelled), "{volume}");
    assert_eq!(names_in(&dir), ["demo.age"], "{volume}");

    // A file there can be a source: it is captured to local scratch.
    let snapshot = ScratchRoot::open(&local.scratch)
        .unwrap()
        .capture_file(SourceFile::open(&dir.join("demo.age")).unwrap(), &mut keep)
        .unwrap();
    assert!(
        snapshot.unlock(&Unlock::Identities(&local.keys)).is_ok(),
        "{volume}"
    );

    // Scratch never goes there.
    let scratch = dir.join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        ScratchRoot::open(&scratch).map(|_| ()),
        Err(Error::Destination),
        "{volume}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// A mount with no owners still holds access lists: one on a new file is refused on
/// any volume, and a folder that blocks deletion gets the empty file named.
fn lists_still_count(local: &Local, base: &Path, volume: &str) {
    let dir = work_folder(base, volume);
    chmod_acl("everyone allow read,file_inherit", &dir);
    assert_eq!(local.encrypt_to(&dir, "demo.age"), Err(Error::Destination));
    assert_eq!(local.save_to(&dir, "demo.out"), Err(Error::Destination));
    assert!(names_in(&dir).is_empty());
    chmod_no_acl(&dir);

    chmod_acl("everyone deny delete,file_inherit", &dir);
    let encrypted = local.encrypt_to(&dir, "demo.age");
    let decrypted = local.save_to(&dir, "demo.out");
    for left in names_in(&dir) {
        chmod_no_acl(&dir.join(left));
    }
    chmod_no_acl(&dir);
    assert_eq!(encrypted, Err(Error::CleanupEmpty));
    assert_eq!(decrypted, Err(Error::CleanupEmpty));
    for left in ["demo.age", "demo.out"] {
        assert_eq!(fs::read(dir.join(left)).unwrap().len(), 0, "{left}");
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// The control: a mounted image that keeps ownership takes both, at 0600.
fn keeps_a_file_private(local: &Local, base: &Path, volume: &str) {
    let dir = work_folder(base, volume);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(local.save_to(&dir, "demo.out"), Ok(200_000));
    assert_eq!(fs::read(dir.join("demo.out")).unwrap(), local.bytes);
    assert_eq!(local.encrypt_to(&dir, "demo.age"), Ok(200_000));
    for file in ["demo.out", "demo.age"] {
        let mode = fs::metadata(dir.join(file)).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o600, "{file}");
    }
    fs::remove_dir_all(&dir).unwrap();
}

fn all_volumes(base: &Path) {
    let local = Local::new();
    for volume in ["fat32", "exfat", "noowners"] {
        cannot_keep_a_file_private(&local, base, volume);
    }
    lists_still_count(&local, base, "noowners");
    keeps_a_file_private(&local, base, "owners");
}

#[test]
#[ignore = "needs LARSAL_TEST_VOLUMES, a folder holding mounted private disk images fat32, exfat, noowners and owners; the default run proves these rules through fault hooks, flow.rs says which"]
fn fil03_t08_t09_real_volumes() {
    let base = std::env::var_os("LARSAL_TEST_VOLUMES").expect("LARSAL_TEST_VOLUMES is not set");
    all_volumes(Path::new(&base));
}

#[test]
fn fil03_t08_a_set_volume_folder_runs_or_fails_loudly() {
    if let Some(base) = std::env::var_os("LARSAL_TEST_VOLUMES") {
        all_volumes(Path::new(&base));
    }
}
