//! The data folder (SYN-02.1): one folder given at start. This module makes
//! it and its `tls/` folder and checks it; the store, `blobs/` and `tmp/`
//! are made by [`crate::blobs`].
//!
//! Guarantees: folders the server makes have mode 0700 and files 0600. The
//! server refuses to start, before it writes anything, when the folder or
//! anything in it can be written by the group or others, belongs to another
//! user, or is a symbolic link, and when `tls/key.der` can be read by the
//! group or others (as SSH servers refuse a private host key that others
//! can read; LD-309). The key is the file the server opens as
//! `tls/key.der`, under any spelling of its name (LD-311).
//!
//! One server per folder (SYN-02.8, F-223): [`open`] takes the folder's
//! exclusive lock before it reads the tree, so a second server always gets
//! the lock error, never a tree error made by the running server's own
//! files (LD-321 (5)). The lock lives as long as the [`DataFolder`] or a
//! handle cloned from it; the system drops it when the process ends.

use crate::Error;
use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// An open data folder whose modes and owner were checked, locked for this
/// server.
#[derive(Debug)]
pub struct DataFolder {
    root: PathBuf,
    lock: File,
}

impl DataFolder {
    /// The open folder that holds the lock.
    pub(crate) fn lock(&self) -> &File {
        &self.lock
    }

    /// The folder itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `tls/` folder (SYN-02.1): `cert.der` and `key.der`.
    #[must_use]
    pub fn tls(&self) -> PathBuf {
        self.root.join("tls")
    }
}

/// Opens the data folder at `root`, making it (and `tls/`) with mode 0700
/// when it does not exist; its parent must exist. Takes the folder's lock,
/// then checks the tree. Async because it asks the tokio runtime for this
/// process's user id.
///
/// # Errors
/// Another server uses the folder, the folder or anything in it is not
/// safe (module guarantees), or it cannot be read or made.
pub async fn open(root: &Path) -> Result<DataFolder, Error> {
    let uid = own_uid()?;
    if fs::symlink_metadata(root).is_err() {
        make(root)?;
    }
    let lock =
        File::open(root).map_err(|e| Error::new(format!("cannot open {}: {e}", root.display())))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Err(Error::new(format!(
                "another server uses {}; this one does not start",
                root.display()
            )));
        }
        Err(fs::TryLockError::Error(e)) => {
            return Err(Error::new(format!("cannot lock {}: {e}", root.display())));
        }
    }
    check_tree(root, uid)?;
    let folder = DataFolder {
        root: root.to_path_buf(),
        lock,
    };
    if fs::symlink_metadata(folder.tls()).is_err() {
        make(&folder.tls())?;
    }
    Ok(folder)
}

/// Makes the folder `path` with mode 0700; its parent must exist.
pub(crate) fn make(path: &Path) -> Result<(), Error> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| Error::new(format!("cannot make the folder {}: {e}", path.display())))
}

/// This process's effective user id: the peer of one end of a socket pair
/// is this process (getpeereid through tokio, so no unsafe code here).
fn own_uid() -> Result<u32, Error> {
    let (one, _other) = tokio::net::UnixStream::pair()
        .map_err(|e| Error::new(format!("cannot read this process's user: {e}")))?;
    let cred = one
        .peer_cred()
        .map_err(|e| Error::new(format!("cannot read this process's user: {e}")))?;
    Ok(cred.uid())
}

/// Why an entry is not safe, if it is not (SYN-02.1).
fn problem(owner: u32, mode: u32, link: bool, uid: u32) -> Option<&'static str> {
    if link {
        Some("is a symbolic link")
    } else if owner != uid {
        Some("belongs to another user")
    } else if mode & 0o022 != 0 {
        Some("can be written by the group or others")
    } else {
        None
    }
}

fn check_tree(root: &Path, uid: u32) -> Result<(), Error> {
    let key = root.join("tls").join("key.der");
    // The key by the file it is, not by the spelling of its name: a
    // case-insensitive volume opens tls/KEY.DER as tls/key.der (LD-311).
    let key_id = fs::symlink_metadata(&key).ok().map(|m| (m.dev(), m.ino()));
    let mut todo = vec![root.to_path_buf()];
    while let Some(path) = todo.pop() {
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| Error::new(format!("cannot read {}: {e}", path.display())))?;
        let link = meta.file_type().is_symlink();
        let why = problem(meta.uid(), meta.mode(), link, uid).or_else(|| {
            (Some((meta.dev(), meta.ino())) == key_id && meta.mode() & 0o044 != 0)
                .then_some("can be read by the group or others")
        });
        if let Some(why) = why {
            return Err(Error::new(format!(
                "the data folder is not safe: {} {why}; the server makes its folders 0700 \
                 and its files 0600 for the user who runs it",
                path.display()
            )));
        }
        if meta.is_dir() {
            let entries = fs::read_dir(&path)
                .map_err(|e| Error::new(format!("cannot read {}: {e}", path.display())))?;
            for entry in entries {
                let entry = entry
                    .map_err(|e| Error::new(format!("cannot read {}: {e}", path.display())))?;
                todo.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh folder under the system's temp folder, deleted on drop.
    pub(crate) struct Scratch(pub PathBuf);

    impl Scratch {
        pub(crate) fn new() -> Self {
            let mut name = [0u8; 8];
            larsal_crypto::random::fill(&mut name).unwrap();
            let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("larsal-server-test-{hex}"));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn syn02_1_new_folder_is_0700_with_tls() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let folder = block_on(open(&root)).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&folder.tls()), 0o700);
        // A second start opens the same folder once the first is gone.
        drop(folder);
        block_on(open(&root)).unwrap();
    }

    #[test]
    fn syn02_1_folder_writable_by_group_refused_and_untouched() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        let err = block_on(open(&root)).unwrap_err().to_string();
        assert!(
            err.contains("can be written by the group or others"),
            "{err}"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0, "nothing written");
    }

    #[test]
    fn syn02_1_file_writable_by_others_refused() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let file = block_on(open(&root)).unwrap().tls().join("cert.der");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o602)).unwrap();
        let err = block_on(open(&root)).unwrap_err().to_string();
        assert!(err.contains("cert.der can be written"), "{err}");
    }

    /// Every path under `root` with its mode and, for a file, its bytes.
    fn tree(root: &Path) -> Vec<(PathBuf, u32, Vec<u8>)> {
        let mut all = Vec::new();
        let mut todo = vec![root.to_path_buf()];
        while let Some(path) = todo.pop() {
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                todo.extend(fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
                all.push((path, meta.mode(), Vec::new()));
            } else {
                let bytes = fs::read(&path).unwrap();
                all.push((path, meta.mode(), bytes));
            }
        }
        all.sort();
        all
    }

    /// T16: a key the group or others can read is refused at start, with
    /// the file named, and nothing is written.
    #[test]
    fn syn02_1_t16_key_others_can_read_refused_at_start() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let folder = block_on(open(&root)).unwrap();
        crate::tls::Certificate::load_or_make(&folder).unwrap();
        let (key, cert) = (folder.tls().join("key.der"), folder.tls().join("cert.der"));
        drop(folder);
        for bad in [0o644, 0o640, 0o604] {
            fs::set_permissions(&key, fs::Permissions::from_mode(bad)).unwrap();
            let before = tree(&root);
            let start = crate::Server::start(&root, 0, crate::http::Config::default());
            let err = block_on(start).err().unwrap().to_string();
            assert_eq!(
                err,
                format!(
                    "the data folder is not safe: {} can be read by the group or others; the \
                     server makes its folders 0700 and its files 0600 for the user who runs it",
                    key.display()
                ),
                "{bad:o}"
            );
            assert_eq!(tree(&root), before, "nothing written ({bad:o})");
        }
        // The certificate may be read by others; only the key is private.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&cert, fs::Permissions::from_mode(0o644)).unwrap();
        block_on(open(&root)).unwrap();
    }

    /// T16 under another spelling: a case-insensitive volume opens
    /// tls/KEY.DER as tls/key.der, so that file is the key too.
    #[test]
    fn syn02_1_t16_key_under_another_case_refused() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let folder = block_on(open(&root)).unwrap();
        crate::tls::Certificate::load_or_make(&folder).unwrap();
        let tls = folder.tls();
        drop(folder);
        let upper = tls.join("KEY.DER");
        fs::rename(tls.join("key.der"), &upper).unwrap();
        fs::set_permissions(&upper, fs::Permissions::from_mode(0o644)).unwrap();
        if fs::metadata(tls.join("key.der")).is_err() {
            return; // A case-sensitive volume: no other spelling to test.
        }
        let start = crate::Server::start(&root, 0, crate::http::Config::default());
        let err = block_on(start).err().unwrap().to_string();
        assert!(
            err.contains("KEY.DER can be read by the group or others"),
            "{err}"
        );
    }

    #[test]
    fn syn02_1_link_in_folder_refused() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let tls = block_on(open(&root)).unwrap().tls();
        std::os::unix::fs::symlink("/etc/hosts", tls.join("cert.der")).unwrap();
        let err = block_on(open(&root)).unwrap_err().to_string();
        assert!(err.contains("is a symbolic link"), "{err}");
    }

    #[test]
    fn syn02_1_owner_and_mode_rules() {
        assert_eq!(problem(501, 0o40700, false, 501), None);
        assert_eq!(problem(501, 0o40750, false, 501), None);
        assert_eq!(
            problem(0, 0o40700, false, 501),
            Some("belongs to another user")
        );
        for bad in [0o40720, 0o40702, 0o100620, 0o100606] {
            assert_eq!(
                problem(501, bad, false, 501),
                Some("can be written by the group or others")
            );
        }
        assert_eq!(
            problem(501, 0o120700, true, 501),
            Some("is a symbolic link")
        );
    }

    #[test]
    fn syn02_1_own_uid_is_the_owner_of_a_new_file() {
        let scratch = Scratch::new();
        let uid = block_on(async { own_uid() }).unwrap();
        assert_eq!(fs::metadata(&scratch.0).unwrap().uid(), uid);
    }

    /// LD-321 (5), F-223: the lock comes before the tree check, so while a
    /// server holds the folder a second one gets the lock error, even when
    /// the tree check would fail too; nothing is written. Once the first is
    /// gone, the tree check runs again.
    #[test]
    fn syn02_8_second_open_gets_the_lock_error_before_the_tree_check() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let first = block_on(open(&root)).unwrap();
        let file = first.tls().join("cert.der");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        let before = tree(&root);
        let err = block_on(open(&root)).unwrap_err().to_string();
        assert_eq!(
            err,
            format!(
                "another server uses {}; this one does not start",
                root.display()
            )
        );
        assert_eq!(tree(&root), before, "nothing written");
        drop(first);
        let err = block_on(open(&root)).unwrap_err().to_string();
        assert!(err.contains("cert.der can be written"), "{err}");
    }
}
