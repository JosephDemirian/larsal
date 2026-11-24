//! Test folders that clean up after themselves (LD-230 (5), LD-240 (5)).

use std::path::{Path, PathBuf};

/// A fresh `$TMPDIR/larsal-ffi-<tag>-<pid>` folder (canonical, as the session
/// keeps paths, APP-09.15), removed with everything in it when dropped, also
/// when the test panics. It derefs to the folder, or to one file in it after
/// [`TempDir::file`]; keep it bound for the whole test.
pub struct TempDir {
    dir: PathBuf,
    path: PathBuf,
}

impl TempDir {
    /// Makes the folder, empty.
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("larsal-ffi-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .unwrap();
        }
        let dir = std::fs::canonicalize(&dir).unwrap();
        Self {
            path: dir.clone(),
            dir,
        }
    }

    /// The same folder, now standing for the file `name` in it.
    pub fn file(mut self, name: &str) -> Self {
        self.path = self.dir.join(name);
        self
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        // A test that made the folder read-only and then failed.
        let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// F-133: held for the whole test by every test in this binary that runs
/// the start-up clean or keeps a file in the opened-attachment folder, so
/// the clean never wipes another test's copy. Other test binaries run
/// after this one, one at a time.
pub fn open_folder_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// F-133's proof: with the lock held, `test` is still waiting after one
/// second (it takes under half a second alone), then passes once the lock
/// goes. A test that skips the lock has ended by then.
pub fn waits_for_open_folder_lock(test: fn()) {
    let held = open_folder_lock();
    let run = std::thread::spawn(test);
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!run.is_finished(), "the test ran without the lock");
    drop(held);
    if let Err(e) = run.join() {
        std::panic::resume_unwind(e);
    }
}

#[cfg(test)]
mod tests {
    use super::TempDir;

    /// LD-240 (5): the folder goes when the value drops, also on a panic.
    #[test]
    fn ld_240_5_temp_dir_removes_itself_on_drop_and_on_panic() {
        let t = TempDir::new("temp-dir-drop").file("v.larsalvault");
        std::fs::write(&t, b"demo").unwrap();
        let dir = t.parent().unwrap().to_path_buf();
        drop(t);
        assert!(!dir.exists(), "{}", dir.display());
        let mut kept = None;
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let t = TempDir::new("temp-dir-panic");
            kept = Some(t.to_path_buf());
            panic!("a failing test");
        }));
        assert!(panicked.is_err());
        let kept = kept.unwrap();
        assert!(!kept.exists(), "{}", kept.display());
    }
}
