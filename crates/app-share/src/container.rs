//! Containers (INT-08.6, INT-08.8, INT-08.9, INT-08.12 to INT-08.14,
//! INT-08.33, INT-08.35, INT-08.36): the vault file a share reads and
//! writes, or a zip archive around it.

use crate::{Error, NotShare};
use app_core::edit::SHARED_KEY;
use app_core::import::{self, ImportError, zip};
use app_core::{recycle, storage};
use app_crypto::kdf::{CostReport, Host};
use app_crypto::secret::{SecretBytes, SecretString};
use app_format::detect::SIGNATURE_1;
use app_format::keys::Credentials;
use app_format::limits::{Limit, Limits};
use app_format::{Opened, OpenedVault, Saved};
use app_model::settings::Compression;
use app_model::{Group, Icon, Time, Uuid, Vault};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The name of the zip entry that holds the vault (INT-08.9 entry 2),
/// stored encoded (AGENTS rule 1).
pub const VAULT_ENTRY: &[u8] = &[
    0x63, 0x6F, 0x6E, 0x74, 0x61, 0x69, 0x6E, 0x65, 0x72, 0x2E, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2E,
    0x6B, 0x64, 0x62, 0x78,
];

/// The first bytes of a zip archive (a local header).
pub const ZIP_START: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// The share key (INT-08.6): exactly one part, the share password; an
/// empty password is the empty password part, never "no password"
/// (FMT-04.2). No key file, no hardware key.
#[must_use]
pub fn credentials(password: &SecretString) -> Credentials<'_> {
    Credentials {
        password: Some(password),
        ..Credentials::default()
    }
}

/// Opens a container's bytes with the share key (INT-08.8, INT-08.9,
/// INT-08.36). By its first bytes: `03 D9 A2 9A` is an unsigned
/// container; `50 4B 03 04` a zip archive, whose one entry named
/// [`VAULT_ENTRY`] (exact bytes) is the vault and every other entry, the
/// signature included, is ignored; anything else is not a share file.
///
/// Guarantees: the archive is read by app-core's ZIP reader inside
/// `limits.total_file`, and its vault entry never inflates past it
/// (AT-A06); the vault is read under `limits` (FMT-08.12, AT-A08); a KDF
/// cost in the ask band is refused like one above a ceiling, without a
/// question and before any key work (AT-A05). Every share item below the
/// container's root is dropped (INT-08.33).
///
/// # Errors
/// [`Error::NotShare`] (MI08-04) or [`Error::Vault`] (MI08-02).
pub fn open(
    file: &[u8],
    password: &SecretString,
    host: &mut Host,
    limits: &Limits,
) -> Result<OpenedVault, Error> {
    let zipped;
    let vault_file = match file.first_chunk::<4>() {
        Some(&SIGNATURE_1) => file,
        Some(&ZIP_START) => {
            zipped = vault_entry(file, limits)?;
            zipped.expose()
        }
        _ => return Err(Error::NotShare(NotShare::UnknownKind)),
    };
    let mut opened = match app_format::open(vault_file, &credentials(password), host, limits, None)
    {
        Ok(Opened::Vault(v)) => *v,
        Ok(Opened::Ask(_)) => {
            return Err(Error::Vault(app_format::Error::TooLarge(Limit::KdfCost)));
        }
        Err(e) => return Err(Error::Vault(e)),
    };
    for g in &mut opened.vault.root.groups {
        strip(g, None);
    }
    Ok(opened)
}

/// [`open`] on the file at `path` (INT-08.16 step 1). A file that is not
/// regular is refused without waiting on it; one over the vault file limit
/// before it is read.
///
/// # Errors
/// [`Error::Io`] with the system's reason, or those of [`open`].
pub fn open_file(
    path: &Path,
    password: &SecretString,
    host: &mut Host,
    limits: &Limits,
) -> Result<OpenedVault, Error> {
    open(&read_file(path)?, password, host, limits)
}

/// The bytes of the file at `path` for [`open`]: a file that is not
/// regular is refused without waiting on it; one over the vault file limit
/// before it is read.
///
/// # Errors
/// [`Error::Io`] with the system's reason; `TooLarge(TotalFile)`.
pub fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    storage::read_bounded(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::FileTooLarge => {
            Error::Vault(app_format::Error::TooLarge(Limit::TotalFile))
        }
        kind => Error::Io(kind),
    })
}

/// The vault entry of a zip container.
fn vault_entry(file: &[u8], limits: &Limits) -> Result<SecretBytes, Error> {
    if file.len() > limits.total_file {
        return Err(Error::Vault(app_format::Error::TooLarge(Limit::TotalFile)));
    }
    let archive = zip::open(file).map_err(zip_error)?;
    let mut named = archive
        .members()
        .iter()
        .filter(|m| m.name.as_bytes() == VAULT_ENTRY);
    let member = match (named.next(), named.next()) {
        (None, _) => return Err(Error::NotShare(NotShare::NoVault)),
        (Some(_), Some(_)) => return Err(Error::NotShare(NotShare::TwoVaults)),
        (Some(m), None) => m,
    };
    archive
        .read(member, limits.total_file, import::Limit::File)
        .map_err(zip_error)
}

fn zip_error(e: ImportError) -> Error {
    Error::Vault(match e {
        ImportError::TooLarge(_) => app_format::Error::TooLarge(Limit::TotalFile),
        ImportError::ZipUnsupported => app_format::Error::Unsupported,
        _ => app_format::Error::Corrupt,
    })
}

/// Removes every share item of `g` and the groups below it, and the
/// subtree of the recycle bin `bin` wherever it sits.
fn strip(g: &mut Group, bin: Option<Uuid>) {
    let mut stack = vec![g];
    while let Some(g) = stack.pop() {
        g.custom_data
            .items
            .retain(|i| i.key.as_bytes() != SHARED_KEY);
        g.groups.retain(|c| Some(c.uuid) != bin);
        stack.extend(g.groups.iter_mut());
    }
}

/// The container of share group `share` of `vault` (INT-08.12): a new
/// vault named after the group, recycle bin off, other metadata at
/// new-vault defaults at `now`; its root a copy of the group with its id,
/// fields, times and entries with full history; with `keep_groups` every
/// group below it too, else none; the custom icons the copies use; the whole
/// deleted-objects list of the source (FMT-15.12). Encryption: the source
/// vault's cipher and KDF, gzip (D-INT08-6); the writer draws a fresh seed
/// and salt and writes version 4.
///
/// App's rules: no group of the container carries a share item
/// (INT-08.33, D-INT08-5); the recycle bin and everything in it stay out
/// (INT-08.35, D-INT08-8); a share group inside the bin is inactive.
/// Every field keeps its text as written: no reference or placeholder is
/// resolved, so no value from outside the share enters the container
/// (INT-08.13, F-140: MOD-08's "references can exfiltrate").
///
/// # Errors
/// [`Error::NoGroup`] when `vault` has no group `share`;
/// [`Error::Recycled`] when the group is in the recycle bin.
pub fn build(share: Uuid, keep_groups: bool, vault: &Vault, now: Time) -> Result<Vault, Error> {
    let group = vault.root.find_group(share).ok_or(Error::NoGroup)?;
    if recycle::group_in_bin(vault, share) {
        return Err(Error::Recycled);
    }
    let mut root = group.duplicate();
    if !keep_groups {
        root.groups.clear();
    }
    strip(&mut root, recycle::bin_id(vault));
    let mut c = Vault::new(root, now);
    c.meta.name.clone_from(&group.name);
    c.meta.recycle_bin_enabled = false;
    c.encryption = app_model::settings::Encryption {
        compression: Compression::Gzip,
        ..vault.encryption
    };
    c.deleted_objects.clone_from(&vault.deleted_objects);
    let used = used_icons(&c.root);
    c.meta.custom_icons = vault
        .meta
        .custom_icons
        .iter()
        .filter(|i| used.contains(&i.uuid))
        .cloned()
        .collect();
    Ok(c)
}

/// The custom icon ids that groups, entries and history items below `root`
/// use.
fn used_icons(root: &Group) -> HashSet<Uuid> {
    let custom = |i: Icon| match i {
        Icon::Custom(id) => Some(id),
        Icon::Standard(_) => None,
    };
    let mut out = HashSet::new();
    for g in root.subtree() {
        out.extend(custom(g.icon));
        for e in &g.entries {
            out.extend(custom(e.icon));
            out.extend(e.history.iter().filter_map(|h| custom(h.icon)));
        }
    }
    out
}

/// Writes `container` to `path` as an unsigned container (INT-08.8,
/// INT-08.14): app-format builds it under the share key with fresh random
/// values, version 4; app-core's storage writes it atomically with mode
/// 0600, a link at `path` replaced, never followed (APP-05, SD-09, AT-I06).
/// No backup. A KDF cost in the ask band runs: the settings are the source
/// vault's, approved when it was opened (CRY-02.14: a save never asks).
/// Returns [`crate::run::head`] of the bytes written, so the writer's own
/// export is never imported back (INT-08.17). The file of a path in `keep`
/// (the open vaults' files and their backups) is never replaced: checked
/// after the KDF, in the folder the write uses (INT-08.34, F-162).
///
/// # Errors
/// [`Error::Vault`] from the writer; [`Error::Io`] with the system's
/// reason (MI08-07), `PermissionDenied` for a file in `keep`. On any error
/// the file at `path` is unchanged.
pub fn write_file(
    path: &Path,
    container: &Vault,
    password: &SecretString,
    host: &mut Host,
    limits: &Limits,
    keep: &[PathBuf],
) -> Result<[u8; 32], Error> {
    let key = credentials(password);
    let mut save = |approval: Option<&CostReport>| {
        app_format::save(container, &key, None, host, limits, approval).map_err(Error::Vault)
    };
    let saved = match save(None)? {
        Saved::Ask(report) => save(Some(&report))?,
        done @ Saved::File(_) => done,
    };
    let Saved::File(file) = saved else {
        return Err(Error::Vault(app_format::Error::TooLarge(Limit::KdfCost)));
    };
    storage::write_export_except(path, &file.bytes, keep).map_err(|e| Error::Io(e.kind()))?;
    Ok(crate::run::head(&file.bytes))
}
