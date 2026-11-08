//! The local stores, never in the synced folder (FIL-06.13): scratch for sealed
//! ciphertext, recovery copies and the budget ledger. Larsal-owned 0700 folders, each
//! proven private when opened; only names this crate made are ever looked at in them.

use crate::error::{Error, io};
use larsal_platform::macos::{effective_uid, has_acl, ignores_ownership, make_dir_in, open_dir_in};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MODE_BITS: u32 = 0o7777;
const PRIVATE: u32 = 0o700;

/// One private local folder for the stores of every encrypted folder. The caller
/// chooses it, and it must not be synced: the Mac app's settings folder (E23-S4).
#[derive(Debug)]
pub struct Stores {
    path: PathBuf,
    root: File,
}

/// A folder this user alone may enter, as far as this volume can say.
pub(crate) fn check_private(dir: &File) -> Result<(), Error> {
    let meta = dir.metadata().map_err(|e| io(&e))?;
    let owned = meta.uid() == effective_uid();
    let mode = meta.permissions().mode() & MODE_BITS;
    if !owned
        || mode != PRIVATE
        || has_acl(dir).map_err(|e| io(&e))?
        || ignores_ownership(dir).map_err(|e| io(&e))?
    {
        return Err(Error::Input);
    }
    Ok(())
}

/// `name` in `parent`: made if missing, opened with no link followed, proven private.
pub(crate) fn private_child(parent: &File, name: &str) -> Result<File, Error> {
    let os = OsStr::new(name);
    match make_dir_in(parent, os, 0o700) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(&e)),
    }
    let dir = open_dir_in(parent, os).map_err(|_| Error::Input)?;
    check_private(&dir)?;
    Ok(dir)
}

impl Stores {
    /// Opens the stores at `path`, making the last step if it is missing.
    ///
    /// # Errors
    /// [`Error::Input`] for a link, anything but a folder, another owner, another mode,
    /// an access list or a volume that ignores ownership.
    pub fn open(path: &Path) -> Result<Self, Error> {
        match std::fs::create_dir(path) {
            Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE))
                .map_err(|e| io(&e))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(&e)),
        }
        let root = larsal_platform::macos::open_dir(path).map_err(|_| Error::Input)?;
        check_private(&root)?;
        Ok(Self {
            path: path.to_path_buf(),
            root,
        })
    }

    pub(crate) fn root(&self) -> &File {
        &self.root
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
