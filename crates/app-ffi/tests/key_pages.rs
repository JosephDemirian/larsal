//! E6-S6, APP-11.9-b and AT-C05: while a vault is unlocked in a session, the
//! pages of the key material it holds (`T`, `F` with a key file, and the
//! password kept for saving, E5-S5, LD-199 (3)) are wired; lock and close
//! unwire them. When the kernel refuses every lock
//! (RLIMIT_MEMLOCK 0), unlock still works and M11-01 is written once.
//! A binary of its own: the wired count is per process.

use app_ffi::session::{Session, UnlockResult};
use app_platform::memory::{page_size, wired_bytes};
use std::path::PathBuf;
use std::process::Command;

const ROLE: &str = "APP_TEST_KEY_PAGES_ROLE";

fn testdata(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn app11_9_b_key_pages_are_wired_while_the_vault_is_unlocked() {
    let page = page_size() as u64;
    let session = Session::new();
    let id = session.open(testdata("password-only.appvault")).unwrap();
    let before = wired_bytes();
    let result = session.unlock(id, Some("demo-pass-1".into()), None);
    assert_eq!(result.unwrap(), UnlockResult::Unlocked);
    // T (32 bytes) and the kept password: one page each, or two when one
    // straddles a page boundary; they may share one.
    let held = wired_bytes() - before;
    println!("unlocked, password only: {held} bytes wired (page {page})");
    assert!(
        held.is_multiple_of(page) && (page..=4 * page).contains(&held),
        "{held}"
    );
    assert_eq!(
        session.password_pages_locked(id),
        Some(true),
        "the kept password"
    );
    session.lock(id).unwrap();
    assert_eq!(session.password_pages_locked(id), None);
    assert_eq!(wired_bytes(), before, "lock unwires");

    // T and F (32 bytes each): one to four pages.
    let id = session
        .open(testdata("password-and-keyfile.appvault"))
        .unwrap();
    let key = Some(testdata("key-hex64.appkey"));
    let result = session.unlock(id, Some("demo-pass-2".into()), key);
    assert_eq!(result.unwrap(), UnlockResult::Unlocked);
    let held = wired_bytes() - before;
    println!("unlocked, password and key file: {held} bytes wired");
    assert!(
        held.is_multiple_of(page) && (page..=6 * page).contains(&held),
        "{held}"
    );
    assert_eq!(session.password_pages_locked(id), Some(true));
    session.close(id).unwrap();
    assert_eq!(wired_bytes(), before, "close unwires");
}

/// A child, started under `ulimit -l 0`: unlocks and prints
/// `child <unlocked> <bytes wired by the unlock>`.
#[test]
#[ignore = "a child of app11_9_refused_locks_still_unlock_with_one_warning"]
fn refused_lock_child() {
    if std::env::var(ROLE).as_deref() != Ok("limit-0") {
        return;
    }
    let session = Session::new();
    let id = session.open(testdata("password-only.appvault")).unwrap();
    let before = wired_bytes();
    let result = session.unlock(id, Some("demo-pass-1".into()), None);
    let unlocked = result.unwrap() == UnlockResult::Unlocked;
    // Refused: the password is kept unlocked, saving still works.
    assert_eq!(session.password_pages_locked(id), Some(false));
    println!("child {unlocked} {}", wired_bytes().saturating_sub(before));
}

#[test]
fn app11_9_refused_locks_still_unlock_with_one_warning() {
    let out = Command::new("/bin/sh")
        .args(["-c", r#"ulimit -l 0 && exec "$0" "$@""#])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "refused_lock_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, "limit-0")
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("child true 0"), "{stdout}");
    let warnings = stderr.matches(app_platform::hardening::M11_01).count();
    assert_eq!(warnings, 1, "{stderr}");
}
