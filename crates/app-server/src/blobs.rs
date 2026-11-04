//! Content-addressed vault files and the compare-and-swap commit (SYN-02.1,
//! SYN-02.4 to SYN-02.8; P15).
//!
//! A new version streams into `tmp/` and is flushed to the device; then,
//! under the one writer lock, it is renamed to `blobs/<h[0..2]>/<h>` (h the
//! SHA-256 of its bytes), one transaction moves the vault row, and the files
//! no row names any more are deleted. Every read of a row and the open of
//! its file run under the same lock, so no commit deletes a file between
//! the two; the open handle then keeps it readable to the end (SYN-02.7).
//!
//! Guarantees: a crash at any point leaves the old version or the new one
//! served, never a mix, and the sweep at the next start deletes what it
//! left (SYN-02.6). Files are named only by hashes the server computed: no
//! name from a client reaches the file system. The bytes are never parsed
//! (P16).

use crate::data::{self, DataFolder};
use crate::store::{self, Cas, Row};
use crate::{Error, log};
use app_proto::messages::{AccountId, VaultId, VaultVersion};
use app_proto::routes::Precondition;
use rusqlite::Connection;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// The vault files and the store's one connection (SYN-02.8: one writer).
pub(crate) struct Blobs {
    /// The data folder's lock, held while the server runs: one server per
    /// folder, so no other start sweeps this one's files (SYN-02.6,
    /// SYN-02.8). The system drops it when the process ends.
    _lock: File,
    db: Mutex<Connection>,
    blobs: PathBuf,
    tmp: PathBuf,
    /// Test seam: where a commit stops as if the server had crashed.
    #[cfg(test)]
    pub(crate) crash: Mutex<Option<Crash>>,
}

/// Where a test makes a commit stop, as a crash would (SYN-02 T07, T08).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Crash {
    /// After step 3: the new file is in `blobs/`, the row has not moved.
    BeforeCommit,
    /// After step 4: the row has moved, no file was deleted.
    AfterCommit,
    /// Step 4 fails after the rename, as a store error would: the server
    /// goes on, deletes the new file and serves the old version (LD-321
    /// (5)).
    CommitFails,
}

/// A file being written in `tmp/`, deleted when dropped unless it was moved
/// into `blobs/`: an upload over the limit, timed out or cut off stores
/// nothing (SYN-02.4 step 1).
pub(crate) struct Temp {
    path: PathBuf,
    kept: bool,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.kept {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash a file in `blobs/<folder>/` is named by: 64 lowercase hex
/// digits whose first two are the folder's name; else `None`.
fn hash_name(folder: &str, name: &str) -> Option<[u8; 32]> {
    let lower = |c: u8| matches!(c, b'0'..=b'9' | b'a'..=b'f');
    if name.len() != 64 || !name.bytes().all(lower) || name.get(..2) != Some(folder) {
        return None;
    }
    let mut hash = [0u8; 32];
    for (byte, pair) in hash.iter_mut().zip(name.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(hash)
}

fn io_failed(what: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::new(format!("cannot write {}: {e}", what.display()))
}

impl Blobs {
    /// Keeps the data folder's lock (taken by [`data::open`]), opens the
    /// store (SYN-02.2), makes `blobs/` and `tmp/` with mode 0700 when they
    /// are missing, and sweeps what a crash left (SYN-02.6), all before the
    /// server listens.
    ///
    /// # Errors
    /// The store is refused or fails, or a folder cannot be made or read.
    pub(crate) fn open(folder: &DataFolder) -> Result<Self, Error> {
        let root = folder.root();
        // The same open file, so the lock stays while either handle lives.
        let lock = folder.lock().try_clone().map_err(io_failed(root))?;
        let db = store::open(&root.join("store.sqlite"))?;
        let (blobs, tmp) = (folder.root().join("blobs"), folder.root().join("tmp"));
        for dir in [&blobs, &tmp] {
            if fs::symlink_metadata(dir).is_err() {
                data::make(dir)?;
            }
        }
        let opened = Self {
            _lock: lock,
            db: Mutex::new(db),
            blobs,
            tmp,
            #[cfg(test)]
            crash: Mutex::new(None),
        };
        let others = opened.sweep()?;
        if others > 0 {
            log(format_args!(
                "{others} files in blobs/ are not named by a hash; left alone"
            ));
        }
        Ok(opened)
    }

    fn writer(&self) -> Result<MutexGuard<'_, Connection>, Error> {
        self.db
            .lock()
            .map_err(|_| Error::new("the store's lock was poisoned"))
    }

    /// Runs `f` on the store's one connection, under the writer lock
    /// (SYN-02.8): the account, sign-in and session rows of SYN-04.
    pub(crate) fn store<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut db = self.writer()?;
        f(&mut db)
    }

    fn path(&self, hash: &[u8; 32]) -> PathBuf {
        let name = hex(hash);
        self.blobs
            .join(name.get(..2).unwrap_or_default())
            .join(name)
    }

    /// SYN-02.6: deletes every file in `tmp/`, and every file in `blobs/`
    /// named by a well-formed hash that no row names. Returns the count of
    /// the other entries in `blobs/`, which are left alone.
    pub(crate) fn sweep(&self) -> Result<usize, Error> {
        let db = self.writer()?;
        let read = |dir: &Path| {
            fs::read_dir(dir).map_err(|e| Error::new(format!("cannot read {}: {e}", dir.display())))
        };
        for entry in read(&self.tmp)?.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_file()) {
                fs::remove_file(entry.path()).map_err(io_failed(&entry.path()))?;
            }
        }
        let mut others = 0usize;
        for folder in read(&self.blobs)?.flatten() {
            let name = folder.file_name();
            let (Some(name), true) = (name.to_str(), folder.file_type().is_ok_and(|t| t.is_dir()))
            else {
                others = others.saturating_add(1);
                continue;
            };
            for file in read(&folder.path())?.flatten() {
                let hash = file.file_name().to_str().and_then(|f| hash_name(name, f));
                let is_file = file.file_type().is_ok_and(|t| t.is_file());
                match hash {
                    Some(hash) if is_file => {
                        if !store::named(&db, &hash)? {
                            fs::remove_file(file.path()).map_err(io_failed(&file.path()))?;
                        }
                    }
                    _ => others = others.saturating_add(1),
                }
            }
        }
        Ok(others)
    }

    /// Every vault of `account`, sorted by id.
    pub(crate) fn list(&self, account: &AccountId) -> Result<Vec<VaultVersion>, Error> {
        store::list(&*self.writer()?, account)
    }

    /// The vault's current row, if it exists in any account.
    pub(crate) fn current(&self, id: &VaultId) -> Result<Option<Row>, Error> {
        store::current(&*self.writer()?, id)
    }

    /// SYN-02.7: the current row and its file, opened before the lock is let
    /// go. A missing file, or one whose length is not the row's, is outside
    /// damage: an error, and the row is not changed.
    pub(crate) fn read(&self, id: &VaultId) -> Result<Option<(Row, File)>, Error> {
        let db = self.writer()?;
        let Some(row) = store::current(&db, id)? else {
            return Ok(None);
        };
        let damaged = || Error::new(format!("the file of vault {id} is missing or damaged"));
        let file = File::open(self.path(&row.hash)).map_err(|_| damaged())?;
        let len = file.metadata().map_err(|_| damaged())?.len();
        if len != row.size {
            return Err(damaged());
        }
        Ok(Some((row, file)))
    }

    /// A new file in `tmp/` (mode 0600), named by 16 random bytes in hex.
    pub(crate) fn temp(&self) -> Result<(Temp, File), Error> {
        let mut name = [0u8; 16];
        app_crypto::random::fill(&mut name)
            .map_err(|e| Error::new(format!("cannot draw a file name: {e}")))?;
        let path = self.tmp.join(hex(&name));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(io_failed(&path))?;
        Ok((Temp { path, kept: false }, file))
    }

    /// Steps 3 to 5 of SYN-02.4 for a temp file already flushed to the
    /// device (step 2): rename it to its hash's name, or drop it when that
    /// file exists (the same bytes), and sync the folder; move the row with
    /// [`store::cas`]; then delete each file no row names any more (the
    /// pruned versions', and this upload's when it lost).
    ///
    /// # Errors
    /// A file or the store fails; the old version stays served.
    pub(crate) fn commit(
        &self,
        id: &VaultId,
        account: &AccountId,
        want: Precondition,
        mut temp: Temp,
        hash: [u8; 32],
        size: u64,
    ) -> Result<Cas, Error> {
        let mut db = self.writer()?;
        let path = self.path(&hash);
        let folder = path.parent().unwrap_or(&self.blobs);
        // A folder's new entry is durable only once the folder is synced.
        let sync = |dir: &Path| {
            File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(io_failed(dir))
        };
        if fs::symlink_metadata(folder).is_err() {
            data::make(folder)?;
            sync(&self.blobs)?;
        }
        match fs::symlink_metadata(&path) {
            Ok(_) => drop(temp),
            Err(_) => {
                fs::rename(&temp.path, &path).map_err(io_failed(&path))?;
                temp.kept = true;
            }
        }
        sync(folder)?;
        #[cfg(test)]
        if self.crashes(Crash::BeforeCommit) {
            return Err(Error::new("crash before the commit (test)"));
        }
        #[cfg(test)]
        let fails = self.crashes(Crash::CommitFails);
        #[cfg(not(test))]
        let fails = false;
        let result = if fails {
            Err(Error::new("the commit failed (test)"))
        } else {
            store::cas(&mut db, id, account, want, size, &hash)
        };
        #[cfg(test)]
        if self.crashes(Crash::AfterCommit) {
            return Err(Error::new("crash after the commit (test)"));
        }
        let mut unnamed = match &result {
            Ok((_, pruned)) => pruned.clone(),
            Err(_) => Vec::new(),
        };
        if !matches!(result, Ok((Cas::Done(_), _))) {
            unnamed.push(hash);
        }
        // Step 5. A failure here leaves only a file no row names, which the
        // next start sweeps: it is logged and never changes the reply.
        for gone in unnamed {
            let path = self.path(&gone);
            let cleared = store::named(&db, &gone).and_then(|named| {
                if named {
                    return Ok(());
                }
                match fs::remove_file(&path) {
                    Err(e) if e.kind() != ErrorKind::NotFound => Err(io_failed(&path)(e)),
                    _ => Ok(()),
                }
            });
            if let Err(e) = cleared {
                log(format_args!(
                    "an unused vault file stays until the next start: {e}"
                ));
            }
        }
        result.map(|(cas, _)| cas)
    }

    #[cfg(test)]
    fn crashes(&self, at: Crash) -> bool {
        *self.crash.lock().unwrap() == Some(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::tests::{Scratch, block_on};
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt;

    fn sha(bytes: &[u8]) -> [u8; 32] {
        let digest = app_crypto::hash::sha256(&[bytes]);
        <[u8; 32]>::try_from(digest.expose()).unwrap()
    }

    /// The account every upload here belongs to.
    const ME: AccountId = AccountId::from_bytes([1; 16]);

    /// One upload of [`ME`]'s, as the PUT route makes it: temp file, sync,
    /// commit. Makes [`ME`]'s row at the first upload.
    fn upload(b: &Blobs, id: &VaultId, want: Precondition, bytes: &[u8]) -> Result<Cas, Error> {
        b.store(|db| {
            db.execute(
                "INSERT OR IGNORE INTO accounts (id, created) VALUES (?1, 0)",
                [ME.as_bytes()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        let (temp, mut file) = b.temp().unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        b.commit(
            id,
            &ME,
            want,
            temp,
            sha(bytes),
            u64::try_from(bytes.len()).unwrap(),
        )
    }

    fn served(b: &Blobs, id: &VaultId) -> (u64, Vec<u8>) {
        let (row, file) = b.read(id).unwrap().unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut bytes).unwrap();
        (row.version, bytes)
    }

    /// Every file under `dir`, as paths below it.
    fn files(dir: &Path) -> Vec<String> {
        let mut all = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(p) = todo.pop() {
            for e in fs::read_dir(&p).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    todo.push(e.path());
                } else {
                    let rel = e.path().strip_prefix(dir).unwrap().display().to_string();
                    all.push(rel);
                }
            }
        }
        all.sort();
        all
    }

    fn blob_name(bytes: &[u8]) -> String {
        let h = hex(&sha(bytes));
        format!("{}/{h}", &h[..2])
    }

    const X: VaultId = VaultId::from_bytes([7; 16]);

    /// T07 and T08: a crash between the blob write and the commit leaves
    /// the old version served and the orphan swept at the next start; a
    /// crash after the commit leaves the new version served, the old kept.
    #[test]
    fn syn02_4_t07_t08_crash_before_commit_old_served_orphan_swept() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let open = || {
            let folder = block_on(data::open(&root)).unwrap();
            Blobs::open(&folder).unwrap()
        };
        let b = open();
        assert_eq!(
            upload(&b, &X, Precondition::Create, b"version 1"),
            Ok(Cas::Done(1))
        );
        *b.crash.lock().unwrap() = Some(Crash::BeforeCommit);
        let crashed = upload(&b, &X, Precondition::Update(Some(1)), b"version 2");
        assert!(crashed.is_err());
        let blobs = root.join("blobs");
        assert_eq!(
            files(&blobs),
            {
                let mut want = vec![blob_name(b"version 1"), blob_name(b"version 2")];
                want.sort();
                want
            },
            "the orphan is on disk after the crash"
        );
        drop(b);
        // The next start, through the server's own start path.
        let server = block_on(crate::Server::start(
            &root,
            0,
            crate::http::Config::default(),
        ))
        .unwrap();
        assert_eq!(served(&server.blobs, &X), (1, b"version 1".to_vec()));
        assert_eq!(files(&blobs), [blob_name(b"version 1")], "orphan swept");
        assert!(files(&root.join("tmp")).is_empty());
        drop(server);

        let b = open();
        *b.crash.lock().unwrap() = Some(Crash::AfterCommit);
        assert!(upload(&b, &X, Precondition::Update(Some(1)), b"version 2").is_err());
        drop(b);
        let b = open();
        assert_eq!(served(&b, &X), (2, b"version 2".to_vec()));
        let db = b.writer().unwrap();
        let kept: Vec<u8> = db
            .query_row(
                "SELECT hash FROM vault_versions WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, sha(b"version 1"), "version 1 kept for restore");
    }

    /// LD-321 (5), SYN-02.4 (Checker 2's mutant MC-U): a commit that fails
    /// after the rename, with the server still running, deletes the new
    /// file at once and leaves the old version served; no restart needed.
    #[test]
    fn syn02_4_failed_commit_after_rename_deletes_new_file_old_served() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let b = Blobs::open(&block_on(data::open(&root)).unwrap()).unwrap();
        assert_eq!(
            upload(&b, &X, Precondition::Create, b"version 1"),
            Ok(Cas::Done(1))
        );
        *b.crash.lock().unwrap() = Some(Crash::CommitFails);
        let failed = upload(&b, &X, Precondition::Update(Some(1)), b"version 2");
        assert_eq!(failed, Err(Error::new("the commit failed (test)")));
        assert_eq!(
            files(&root.join("blobs")),
            [blob_name(b"version 1")],
            "the new file is deleted"
        );
        assert!(files(&root.join("tmp")).is_empty());
        assert_eq!(served(&b, &X), (1, b"version 1".to_vec()));
        // A failed first upload stores nothing at all.
        let y = VaultId::from_bytes([8; 16]);
        assert!(upload(&b, &y, Precondition::Create, b"other").is_err());
        assert_eq!(files(&root.join("blobs")), [blob_name(b"version 1")]);
        assert!(b.read(&y).unwrap().is_none());
        // The next commit goes through again.
        *b.crash.lock().unwrap() = None;
        assert_eq!(
            upload(&b, &X, Precondition::Update(Some(1)), b"version 2"),
            Ok(Cas::Done(2))
        );
        assert_eq!(served(&b, &X), (2, b"version 2".to_vec()));
    }

    /// T11: the sweep deletes a temp file and an unnamed blob, and leaves a
    /// file of any other name, counted.
    #[test]
    fn syn02_6_t11_sweep_at_start() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let b = Blobs::open(&block_on(data::open(&root)).unwrap()).unwrap();
        assert_eq!(
            upload(&b, &X, Precondition::Create, b"kept"),
            Ok(Cas::Done(1))
        );
        drop(b);
        let write = |rel: &str| {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&p)
                .unwrap();
            f.write_all(b"x").unwrap();
        };
        let unnamed = format!("blobs/{}", blob_name(b"nobody names me"));
        let misplaced = format!("blobs/00/{}", hex(&sha(b"kept")));
        write("tmp/0123456789abcdef0123456789abcdef");
        write(&unnamed);
        write("blobs/zz/notahash");
        write(&misplaced);
        for dir in ["blobs/zz", "blobs/00"] {
            fs::set_permissions(
                root.join(dir),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
        }
        let b = Blobs::open(&block_on(data::open(&root)).unwrap()).unwrap();
        assert!(files(&root.join("tmp")).is_empty());
        assert!(!root.join(&unnamed).exists());
        assert!(root.join("blobs/zz/notahash").exists());
        assert!(
            root.join(&misplaced).exists(),
            "not where its hash puts it: left alone"
        );
        assert_eq!(b.sweep().unwrap(), 2, "two files with other names, counted");
        assert_eq!(served(&b, &X), (1, b"kept".to_vec()));
    }

    /// T01: the folders are 0700 and the files 0600, the store's `-wal`
    /// and `-shm` included.
    #[test]
    fn syn02_1_t01_modes_after_a_start_and_an_upload() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let server = block_on(crate::Server::start(
            &root,
            0,
            crate::http::Config::default(),
        ))
        .unwrap();
        assert_eq!(
            upload(&server.blobs, &X, Precondition::Create, b"v"),
            Ok(Cas::Done(1))
        );
        let mut todo = vec![root.clone()];
        let mut seen = Vec::new();
        while let Some(p) = todo.pop() {
            let meta = fs::symlink_metadata(&p).unwrap();
            let name = p.strip_prefix(&root).unwrap().display().to_string();
            if meta.is_dir() {
                assert_eq!(meta.mode() & 0o7777, 0o700, "{name}");
                todo.extend(fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
            } else {
                assert_eq!(meta.mode() & 0o7777, 0o600, "{name}");
            }
            seen.push(name);
        }
        let blob = format!("blobs/{}", blob_name(b"v"));
        for want in [
            "store.sqlite",
            "store.sqlite-wal",
            "store.sqlite-shm",
            "tls/cert.der",
            "tls/key.der",
            "tmp",
            &blob,
        ] {
            assert!(seen.iter().any(|s| s == want), "{want} in {seen:?}");
        }
    }

    /// Two vaults with the same bytes share one file: the second upload
    /// drops its temp file, and pruning one vault's row keeps the file
    /// while the other's row names it (SYN-02 edge cases).
    #[test]
    fn syn02_4_shared_file_kept_while_a_row_names_it() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let b = Blobs::open(&block_on(data::open(&root)).unwrap()).unwrap();
        let y = VaultId::from_bytes([8; 16]);
        assert_eq!(
            upload(&b, &X, Precondition::Create, b"same"),
            Ok(Cas::Done(1))
        );
        assert_eq!(
            upload(&b, &y, Precondition::Create, b"same"),
            Ok(Cas::Done(1))
        );
        assert!(
            files(&root.join("tmp")).is_empty(),
            "the second temp file is gone"
        );
        for n in 1..=6u8 {
            let bytes = [b'x', n];
            assert_eq!(
                upload(&b, &X, Precondition::Update(Some(u64::from(n))), &bytes),
                Ok(Cas::Done(u64::from(n) + 1))
            );
        }
        // X's version 1 row is pruned; Y's row still names the file.
        assert!(root.join("blobs").join(blob_name(b"same")).exists());
        assert_eq!(served(&b, &y), (1, b"same".to_vec()));
        // A losing upload with the bytes of a kept version keeps that file.
        assert_eq!(
            upload(&b, &y, Precondition::Update(Some(9)), b"same"),
            Ok(Cas::Conflict)
        );
        assert!(root.join("blobs").join(blob_name(b"same")).exists());
    }

    #[test]
    fn syn02_1_hash_names() {
        let h = sha(b"a");
        let name = hex(&h);
        assert_eq!(hash_name(&name[..2], &name), Some(h));
        assert_eq!(hash_name("zz", &name), None);
        assert_eq!(hash_name(&name[..2], &name.to_uppercase()), None);
        assert_eq!(hash_name(&name[..2], &name[..63]), None);
        assert_eq!(hash_name("no", "notahash"), None);
    }
}
