//! Saving (E5-S10, APP-05): the save of an open vault with the backup and
//! method of the settings, Save As, the one-time format notice, and the
//! changed-on-disk flow over larsal-core's storage and merge.
//!
//! Guarantees:
//! - a save goes through larsal-core's `storage::save` only: the pre-save
//!   check (APP-05.10), the backup before the write (APP-05.19 to
//!   APP-05.22), the safe or chosen method (APP-05.11, APP-05.15,
//!   APP-05.16), 0600 for new files and the mode kept on a re-save
//!   (AT-I06);
//! - a file changed on disk is never overwritten without the user's choice
//!   (SD-03, AT-I05): the save answers `on_disk` and writes nothing; only
//!   Keep mine (Ignore, Overwrite) skips the check, for one save;
//! - Swift watches the folder and the file (DiskWatch.swift) and asks
//!   [`Session::check_disk`]; Rust decides by the checksum of APP-05 (the
//!   first 1,024 bytes and the length), so Larsal's own saves never raise the
//!   event: the save lock is held while a save runs, and the watched
//!   checksum moves with the bytes Larsal wrote before it is released;
//! - a reload or merge opens the disk version with the key parts kept from
//!   the unlock, off the session lock, and replaces the open vault under
//!   the lock; a merge takes the live vault as its source then, so a change
//!   made meanwhile is kept (MOD-11.29: the disk version is the target), and
//!   a reload merges too when a change was committed meanwhile (AT-I05);
//! - a save the lock overtook (F-101: an automatic lock waits at most a
//!   second for it, Saving.swift) and that then did not write keeps the
//!   change in the recovery copy (APP-02.16);
//! - one lock order: this vault's save lock before the session lock
//!   (LD-199 (4)); nothing locks the save lock inside `with_edit`;
//! - every text here names files, counts and the system's reason only,
//!   never vault content or key material.

use crate::edit::{EditState, SaveStatus, Saver};
use crate::session::{LarsalError, Session};
use crate::views::{Rated, now, unix};
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::storage::{self, Backup, Method, SaveError, SaveReport, SaveRequest};
use larsal_crypto::secret::SecretString;
use larsal_format::keyfile::KeyFileKey;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::Vault;
use larsal_model::times::{Civil, Time};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};

/// The per-vault flags of APP-05, kept in the edit state: dropped on lock.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Disk {
    /// "Ignore disk changes until saved" (APP-05.27 Ignore, APP-05.28
    /// Overwrite): the watch pauses and the next save skips APP-05.10.
    ignore: bool,
    /// The disk version could not be read (APP-05.30): a refused save
    /// offers Overwrite only.
    unreadable: bool,
    /// `MSG-SAVE-V4-NOTICE` was confirmed in this session (APP-05.32).
    notice_confirmed: bool,
    /// `MSG-SAVE-BACKUP-FAILED` was shown in this session (APP-05.22).
    backup_noted: bool,
    /// Consecutive failed saves (APP-05.14, F-087).
    failures: storage::Failures,
    /// Turn off of `MSG-SAVE-UNSAFE-ASK`: this vault saves with
    /// `save.unsafe_method` while it stays open (APP-05.14, LD-52).
    unsafe_method: bool,
    /// New key parts wait for the save that writes them: that save lists
    /// the old copies (APP-05.33, F-088).
    pub(crate) new_key: bool,
    /// The changed-on-disk question of this round (APP-05.27, APP-05.28),
    /// and whether its "went back in time" line was shown after the
    /// credentials opened the disk version (APP-05.29): a Discard is asked
    /// once more, never twice.
    asked: Option<DiskAsk>,
    older_asked: bool,
}

/// Which changed-on-disk question shows (frame `dialogs-changed-on-disk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum DiskAsk {
    /// APP-05.26 with `save.reload_on_change` off: Load or Keep.
    Reload,
    /// APP-05.27: the vault has unsaved changes: Merge, Discard, Ignore,
    /// Cancel.
    Unsaved,
    /// APP-05.28, found by a save: Merge then save, Discard, Overwrite,
    /// Cancel.
    OnSave,
    /// APP-05.30 then APP-05.28: nothing to merge; Overwrite or Cancel.
    OverwriteOnly,
}

/// What a disk check or an answer did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DiskEvent {
    /// Nothing changed, the file cannot be opened (no event, APP-05.24),
    /// the watch is paused, or the answer needed no more.
    None,
    /// A save runs or the editor is open: check again when it ends
    /// (APP-05.25).
    Busy,
    /// The open vault now holds the disk version (or the merge of both):
    /// `MSG-DISK-RELOADED` (APP-05.31).
    Reloaded,
    /// Ask (APP-05.26, APP-05.27).
    Ask {
        /// Which question.
        ask: DiskAsk,
        /// The unsaved changes, for "Your 2 changes are lost."
        changes: u32,
    },
    /// As `Ask`, and the rollback guard found the disk version older
    /// (APP-05.26): the question adds the "went back in time" line of
    /// `MSG-DISK-ROLLBACK`, and Merge stays the default.
    AskOlder {
        /// Which question.
        ask: DiskAsk,
        /// The unsaved changes.
        changes: u32,
    },
    /// The disk version does not open with the current key:
    /// `MSG-DISK-NEW-KEY` (APP-05.29). The open vault is unchanged.
    NewKey,
    /// The disk version cannot be read: `MSG-DISK-UNREADABLE` (APP-05.30).
    /// The open vault is unchanged and not marked changed.
    Unreadable,
    /// APP-05.29, MOD-11.31: the credentials given open the disk version,
    /// and they match a key this Mac retired. Nothing was merged: show
    /// `MSG-DISK-OLD-KEY` (Skip the default), then `resolve_old_key`.
    OldKey,
    /// The rollback guard (APP-05.26, LD-267 (3)): the disk version is
    /// older than one Larsal has seen, so it was merged into the open vault,
    /// never loaded. Save at once, whatever `save.after_every_change`
    /// says, then show `MSG-DISK-ROLLBACK`.
    Rollback,
    /// As `Reloaded`, and the disk version has a lower file version or
    /// weaker KDF settings than Larsal has seen: `MSG-DISK-WEAKER` (APP-05.26).
    Weaker {
        /// The settings' names, never a value.
        settings: String,
    },
}

/// The answer to a changed-on-disk question (APP-05.26 to APP-05.28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum DiskChoice {
    /// Merge the open vault into the disk version (MOD-11.29); a save
    /// follows (the caller starts it).
    Merge,
    /// Discard, Load: the disk version replaces the open vault.
    Reload,
    /// Ignore, Overwrite (the frame's "Keep mine"): the next save skips the
    /// pre-save check and replaces the disk version.
    KeepMine,
    /// Cancel, Keep (the frame's "Decide Later"): nothing is written; the
    /// vault is marked changed, so the next save asks again.
    Later,
}

/// The footer's state of vault `v` (APP-05.7, APP-05.3).
pub(crate) fn status(v: &Vault, s: &EditState) -> SaveStatus {
    SaveStatus {
        changes: s.changes,
        saved_at: s.saved_at,
        failure: s.failure.clone(),
        on_disk: None,
        format_notice: false,
        notice: None,
        autosave_minutes: larsal_core::settings::autosave_minutes(v),
        ask_unsafe: false,
        old_copies: None,
        older: false,
    }
}

/// What one write did, before it is recorded.
enum Wrote {
    /// With the file version and the bytes it wrote (the sync upload's,
    /// SYN-03.5 step 3).
    Saved(
        SaveReport,
        larsal_model::FileVersion,
        #[cfg_attr(not(feature = "sync"), allow(dead_code))] Vec<u8>,
    ),
    ChangedOnDisk,
    /// The reason in plain words, and the storage error when the write
    /// itself failed (APP-05.14 counts those).
    Failed(String, Option<SaveError>),
}

/// The key parts of the unlock sheet of APP-05.29: the password and the
/// key file with its name.
type NewKey = (Option<SecretString>, Option<(KeyFileKey, String)>);

fn locked(m: &Mutex<Saver>) -> MutexGuard<'_, Saver> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The same unlock: a lock (and unlock) meanwhile gave the vault other key
/// parts, and a result of the old ones stays here.
pub(crate) fn same(s: &EditState, saver: &Arc<Mutex<Saver>>) -> Result<(), LarsalError> {
    if s.saver.as_ref().is_some_and(|k| Arc::ptr_eq(k, saver)) {
        Ok(())
    } else {
        Err(LarsalError::Locked)
    }
}

/// SYN-03.4: the vault is busy for sync: unsaved changes, an open entry
/// or group editor (as F-261 asks of the disk check), a changed-on-disk
/// question or a held copy, or disk changes ignored until the next save.
#[cfg(feature = "sync")]
pub(crate) fn sync_busy(s: &EditState, share: &crate::share::State) -> bool {
    s.changes > 0
        || s.editing()
        || share.draft.is_some()
        || s.disk.asked.is_some()
        || s.disk.ignore
        || s.held.is_some()
}

/// `MSG-SAVE-FAILED`'s reason in plain words, from the system's error kind
/// (APP-05.13). No path, no content.
fn reason(kind: ErrorKind) -> String {
    match kind {
        ErrorKind::StorageFull => "There is no space left on the disk.".to_owned(),
        ErrorKind::PermissionDenied => {
            "This vault's file or its folder cannot be written.".to_owned()
        }
        ErrorKind::ReadOnlyFilesystem => "The disk is read-only.".to_owned(),
        ErrorKind::NotFound => {
            "The vault's folder is not there. Its disk may not be connected.".to_owned()
        }
        // F-101: a FIFO, a device or a folder at the vault's path.
        ErrorKind::InvalidInput => "This vault's path is not a file Larsal can write.".to_owned(),
        // F-110: another program holds the vault's file past the wait.
        ErrorKind::ResourceBusy => {
            "Another program is writing this vault's file. Try again.".to_owned()
        }
        other => {
            let text = other.to_string();
            let mut chars = text.chars();
            chars.next().map_or_else(String::new, |first| {
                format!("{}{}.", first.to_uppercase(), chars.as_str())
            })
        }
    }
}

/// The local time of a save for the backup name (APP-05.20).
fn local_now() -> (Civil, u32) {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = i64::try_from(since.as_secs()).unwrap_or(0);
    #[cfg(target_os = "macos")]
    let offset = larsal_platform::macos::utc_offset(secs).unwrap_or(0);
    #[cfg(not(target_os = "macos"))]
    let offset = 0;
    let civil = Time::from_unix(secs.saturating_add(offset))
        .and_then(Time::to_civil)
        .unwrap_or(Civil {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        });
    (civil, since.subsec_millis())
}

impl Session {
    /// Saves vault `vault` to its own path, or to `to` for Save As
    /// (APP-05.6: no pre-save check, the safe method, no notice; the vault
    /// then lives at `to`). Called by `save` and `save_as`.
    pub(crate) fn save_to(
        &self,
        vault: u64,
        to: Option<PathBuf>,
    ) -> Result<SaveStatus, LarsalError> {
        let saver = self.with_edit(vault, |_, _, _, s| {
            s.saver
                .clone()
                .ok_or_else(|| LarsalError::Refused("This vault cannot be saved.".to_owned()))
        })?;
        let mut sv = locked(&saver);
        let (copy, own, changes, disk) = self.with_edit(vault, |v, path, _, s| {
            same(s, &saver)?;
            Ok((v.duplicate(), path.to_path_buf(), s.changes, s.disk))
        })?;
        let save_as = to.is_some();
        // APP-05.32 (LD-07): before the first save of a version 3 file to
        // its own path, the notice; nothing is written until it is
        // confirmed.
        if !save_as && !disk.notice_confirmed && copy.read_version.is_some_and(|v| v.major < 4) {
            return self.with_edit(vault, |v, _, _, s| {
                Ok(SaveStatus {
                    format_notice: true,
                    ..status(v, s)
                })
            });
        }
        let target = to.clone().unwrap_or_else(|| own.clone());
        let method = self.method(save_as, disk);
        let wrote = self.write(&mut sv, &copy, &target, disk, (save_as, method));
        // Recorded while the save lock is held, so a disk check never sees
        // Larsal's own new bytes against the old checksum (APP-05.24).
        let saved = matches!(wrote, Wrote::Saved(..));
        let out = self.with_edit(vault, |v, _, _, s| {
            same(s, &saver)?;
            let mut out = status(v, s);
            match wrote {
                Wrote::Saved(report, version, _) => {
                    // F-226 (LD-319 (4)): the open vault is now the file
                    // just written, so it carries that version: a version 3
                    // file saved as 4 has stored its settings time.
                    v.read_version = Some(version);
                    s.changes = s.changes.saturating_sub(changes);
                    s.saved_at = Some(unix(now()));
                    s.failure = None;
                    if report.recreated {
                        out.notice = Some(format!(
                            "The vault file was missing. Larsal saved it again at {}.",
                            target.display()
                        ));
                    }
                    if let Some(Err(kind)) = report.backup
                        && !s.disk.backup_noted
                    {
                        s.disk.backup_noted = true;
                        out.notice = Some(format!(
                            "The backup copy could not be written: {} The vault was still saved.",
                            reason(kind)
                        ));
                    }
                    if disk.ignore && !save_as {
                        out.notice = Some("The file on disk was replaced.".to_owned());
                    }
                    s.disk.ignore = false;
                    s.disk.unreadable = false;
                    // SYN-03.4, SYN-03 T39: this save ended the disk question,
                    // so sync runs again.
                    (s.disk.asked, s.disk.older_asked) = (None, false);
                    s.disk.failures.reset();
                    // APP-05.33: the save that wrote new key parts lists
                    // the old copies (filled in below, off the lock).
                    if std::mem::take(&mut s.disk.new_key) {
                        out.old_copies = Some(Vec::new());
                    }
                }
                Wrote::ChangedOnDisk => {
                    out.on_disk = Some(if s.disk.unreadable {
                        DiskAsk::OverwriteOnly
                    } else {
                        DiskAsk::OnSave
                    });
                    (s.disk.asked, s.disk.older_asked) = (out.on_disk, false);
                }
                Wrote::Failed(why, error) => {
                    // APP-05.14 (F-087): the third failed safe save in a
                    // row asks to turn safe saving off for this vault.
                    out.ask_unsafe = error.is_some_and(|e| s.disk.failures.failed(&e, method));
                    s.failure = Some(why);
                }
            }
            Ok(SaveStatus {
                changes: s.changes,
                saved_at: s.saved_at,
                failure: s.failure.clone(),
                ..out
            })
        });
        // F-101: a lock that stopped waiting for this save (Saving.swift's
        // one-second deadline) came first; a save that then did not write
        // keeps the change in the recovery copy, as that lock would have
        // (APP-02.16).
        if !saved && matches!(out, Err(LarsalError::Locked)) {
            self.keep_copy(&sv, &copy, &own);
        }
        // SYN-03 T50: the path moves under the save lock, with the hash `write`
        // recorded, so `sync_read` never meets the new hash with the old path.
        let moved = to.filter(|_| saved).map(|to| storage::real_path(&to));
        if let Some(real) = &moved {
            self.set_path(vault, real);
        }
        drop(copy);
        drop(sv);
        #[cfg(all(test, feature = "sync"))]
        crate::sync::tests::save_lock_free();
        // APP-05.28 (LD-267 (3)): the rollback guard's compare before the
        // question.
        let out = match out {
            Ok(mut o) if o.on_disk == Some(DiskAsk::OnSave) => {
                o.older = self.disk_older(vault)?;
                Ok(o)
            }
            other => other,
        };
        if let Some(real) = moved {
            self.settings.note_opened(&real);
            crate::session::changed();
        }
        // INT-08.17: after every good save, the exporting shares write.
        if saved && out.is_ok() {
            self.share_saved(vault);
            // SYN-03.4: a run 2 s after the last save.
            #[cfg(feature = "sync")]
            self.sync_saved(vault);
        }
        out.map(|mut out| {
            if out.old_copies.is_some() {
                let copies = self.old_copies(&target);
                let backups = self.settings.flag("backup.enabled".into());
                out.old_copies = (backups || !copies.is_empty()).then(|| {
                    copies
                        .iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect()
                });
            }
            out
        })
    }

    /// APP-05.33: the copies Larsal made of the vault at `path` that still
    /// exist: the backups its pattern names and its recovery copy.
    fn old_copies(&self, path: &Path) -> Vec<PathBuf> {
        let pattern = self.settings.text("backup.pattern".into());
        let home = std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from);
        let real = storage::real_path(path);
        let recovery = self.recovery_path(&real);
        storage::old_copies(&pattern, &real, &home, recovery.as_deref())
    }

    /// APP-02.16: the recovery copy's path for the vault at `real`, in the
    /// `recovery` folder of Larsal's settings folder; `None` for a
    /// memory-only settings store.
    fn recovery_path(&self, real: &Path) -> Option<PathBuf> {
        let dir = self.settings.folder()?.join("recovery");
        Some(dir.join(format!("{}.larsalvault", copy_name(real))))
    }

    /// APP-02.16's memory note (LD-224 (4)): the change of the vault at
    /// `path` was kept in no copy.
    fn note_lost(&self, path: &Path) {
        let name = copy_name(&storage::real_path(path));
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name);
    }

    /// [`Session::write_recovery_copy`]'s write: `copy` of the vault at
    /// `path` under the key parts of `sv`, or the `.lost` marker and the
    /// memory note. True when the copy was written.
    fn keep_copy(&self, sv: &Saver, copy: &Vault, path: &Path) -> bool {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let Some(target) = self.recovery_path(&storage::real_path(path)) else {
            self.note_lost(path);
            return false;
        };
        let dir = target.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        // The mode is set when the folder is made; an existing folder keeps
        // its own (APP-02 T55: a read-only one makes the copy fail).
        let wrote = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .is_ok()
            && self.build(sv, copy).is_some_and(|file| {
                let temp = std::env::temp_dir();
                storage::save(&SaveRequest::plain(&target, &file.bytes, None, &temp)).is_ok()
            });
        if !wrote {
            let mut lost = target.into_os_string();
            lost.push(".lost");
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(lost);
            self.note_lost(path);
        }
        wrote
    }

    /// S-FILE-07, S-FILE-08 (APP-05.11, .15, .16): the method of this save;
    /// Save As is always safe; a vault switched by APP-05.14 uses the
    /// unsafe method.
    fn method(&self, save_as: bool, disk: Disk) -> Method {
        let settings = &self.settings;
        let alternative = settings.flag("save.alternative".into()) || disk.unsafe_method;
        match (save_as, alternative) {
            (false, true) if settings.number("save.alternative.mode".into()) == 1 => Method::Direct,
            (false, true) => Method::TempMove,
            _ => Method::Safe,
        }
    }

    /// The file of `copy` under the vault's current key, with the save lock
    /// `sv` held; `None` when it cannot be built.
    fn build(&self, sv: &Saver, copy: &Vault) -> Option<Box<larsal_format::SavedFile>> {
        // F-107: the kept key is asked again with the new seed (FMT-04.10).
        let part = sv.hardware.map(crate::hwkey::Choice::part);
        let credentials = Credentials {
            password: sv.password.as_ref(),
            key_file: sv.key_file.as_ref(),
            hardware_key: part.as_deref(),
        };
        let mut host = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        let mut run = |approval: Option<&larsal_crypto::kdf::CostReport>| {
            larsal_format::save(
                copy,
                &credentials,
                Some(&sv.key),
                &mut host,
                &Limits::DEFAULT,
                approval,
            )
        };
        // CRY-02.14: a save never asks. The user approved these settings at
        // open or chose them (M07-34); the refuse ceilings still hold.
        match run(None) {
            Ok(Saved::Ask(report)) => run(Some(&report)),
            other => other,
        }
        .ok()
        .and_then(|saved| match saved {
            Saved::File(file) => Some(file),
            Saved::Ask(_) => None,
        })
    }

    /// Builds the file from `copy` and writes it to `target` (APP-05.10 to
    /// APP-05.22), with the save lock `sv` held.
    fn write(
        &self,
        sv: &mut Saver,
        copy: &Vault,
        target: &Path,
        disk: Disk,
        (save_as, method): (bool, Method),
    ) -> Wrote {
        let Some(file) = self.build(sv, copy) else {
            return Wrote::Failed("The vault file could not be built.".to_owned(), None);
        };
        let settings = &self.settings;
        let temp = std::env::temp_dir();
        let pattern = settings.text("backup.pattern".into());
        let home = std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from);
        let (local, millis) = local_now();
        let mut request = SaveRequest::plain(
            target,
            &file.bytes,
            (!save_as).then_some(sv.checksum),
            &temp,
        );
        request.ignore_disk_changes = disk.ignore && !save_as;
        request.method = method;
        request.backup = settings.flag("backup.enabled".into()).then_some(Backup {
            pattern: &pattern,
            local,
            millis,
            home: &home,
        });
        match storage::save(&request) {
            Ok(report) => {
                sv.checksum = report.checksum;
                sv.watched = report.checksum;
                #[cfg(feature = "sync")]
                {
                    sv.proven = larsal_sync::sync::hash(&file.bytes);
                }
                // APP-05.26: the guard's values move up with each save.
                self.seen(copy, &file.bytes, Some(file.version));
                let larsal_format::SavedFile {
                    bytes,
                    key,
                    version,
                } = *file;
                sv.key = key;
                Wrote::Saved(report, version, bytes)
            }
            Err(SaveError::ChangedOnDisk(_)) => Wrote::ChangedOnDisk,
            Err(e @ SaveError::CannotRead(_)) => {
                Wrote::Failed("The vault file cannot be read.".to_owned(), Some(e))
            }
            Err(SaveError::Write { kind, kept_temp }) => {
                let why = match &kept_temp {
                    Some(kept) => {
                        format!("{} Your changes are in {}.", reason(kind), kept.display())
                    }
                    None => reason(kind),
                };
                Wrote::Failed(why, Some(SaveError::Write { kind, kept_temp }))
            }
        }
    }

    /// Editor exclusion and applying a disk result share the same state lock.
    fn with_closed_editors<R>(
        &self,
        vault: u64,
        f: impl FnOnce(&mut Vault, &mut Rated, &mut EditState) -> Result<R, LarsalError>,
    ) -> Result<Option<R>, LarsalError> {
        self.with_share(vault, |slot| {
            let v = slot.vault.ok_or(LarsalError::Locked)?;
            if slot.edit.editing() || slot.share.draft.is_some() {
                return Ok(None);
            }
            *slot.version = slot.version.wrapping_add(1);
            f(v, slot.rated, slot.edit).map(Some)
        })?
    }

    /// Opens the disk version with the kept key parts (APP-05.26 to
    /// APP-05.29) and puts it in place of the open vault, merged with it
    /// for Merge (`before` is `None`). A reload (`Some` of the change count
    /// the decision saw) merges too when a change was committed while the
    /// disk version opened, so that change is never lost (AT-I05), and,
    /// with `guard` (the silent reload, APP-05.26) or no unsaved change
    /// (LD-271 (6)), when the rollback guard finds the disk version older.
    /// Holds the save lock, so no save runs
    /// meanwhile. With `new_key` (APP-05.29, F-085) the disk version opens
    /// with those key parts: credentials that match a key this Mac retired
    /// merge nothing (`OldKey`, MOD-11.31); else the vault keeps the key the
    /// merge picks (LD-264, LD-283 (3)): this Mac's when the merge took it,
    /// else the disk copy's, and this Mac's key is then retired.
    fn take_disk_version(
        &self,
        vault: u64,
        before: Option<u32>,
        new_key: Option<NewKey>,
        guard: bool,
        watch_before: Option<storage::Checksum>,
    ) -> Result<DiskEvent, LarsalError> {
        let (saver, path, root) = self.with_edit(vault, |v, path, _, s| {
            Ok((s.saver.clone(), path.to_path_buf(), v.root.uuid))
        })?;
        let Some(saver) = saver else {
            return Ok(DiskEvent::None);
        };
        let mut sv = locked(&saver);
        let retry = watch_before.unwrap_or(sv.checksum);
        let busy = |sv: &mut Saver| {
            sv.watched = retry;
            Ok(DiskEvent::Busy)
        };
        let unreadable = |me: &Self, sv: &mut Saver| {
            let event = me.with_closed_editors(vault, |_, _, s| {
                same(s, &saver)?;
                if watch_before.is_some() {
                    (s.disk.asked, s.disk.older_asked) = (Some(DiskAsk::Unsaved), false);
                }
                s.disk.unreadable = true;
                Ok(DiskEvent::Unreadable)
            })?;
            match event {
                Some(event) => Ok(event),
                None => busy(sv),
            }
        };
        let real = storage::real_path(&path);
        // F-101: never waits on a pipe planted at the vault's path.
        let Ok(bytes) = larsal_platform::macos::open_regular(&real)
            .map_err(|e| larsal_format::Error::Io(e.kind()))
            .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT))
        else {
            return unreadable(self, &mut sv);
        };
        // F-107: the kept hardware key stays a part of either key (the
        // APP-05.29 sheet asks for the password and key file only).
        let part = sv.hardware.map(crate::hwkey::Choice::part);
        let credentials = match &new_key {
            Some((password, key_file)) => Credentials {
                password: password.as_ref(),
                key_file: key_file.as_ref().map(|k| &k.0),
                hardware_key: part.as_deref(),
            },
            None => Credentials {
                password: sv.password.as_ref(),
                key_file: sv.key_file.as_ref(),
                hardware_key: part.as_deref(),
            },
        };
        let Some(opened) = self.open_bytes(&bytes, &credentials, true) else {
            return unreadable(self, &mut sv);
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(()) => {
                let event = self.with_closed_editors(vault, |_, _, s| {
                    same(s, &saver)?;
                    if watch_before.is_some() {
                        (s.disk.asked, s.disk.older_asked) = (Some(DiskAsk::Unsaved), false);
                    }
                    Ok(DiskEvent::NewKey)
                })?;
                return match event {
                    Some(event) => Ok(event),
                    None => busy(&mut sv),
                };
            }
        };
        let sum = storage::checksum(&bytes);
        let larsal_format::OpenedVault {
            vault: mut disk_vault,
            key,
            ..
        } = *opened;
        let mut retiring = None;
        if new_key.is_some() {
            // MOD-11.31 (LD-269 (3)): a copy under a key this Mac retired is
            // never merged on its own; it waits for Skip or Merge anyway.
            match self.is_retired_copy(disk_vault.root.uuid, &credentials) {
                Some(false) => {}
                Some(true) => {
                    let event = self.with_closed_editors(vault, |_, _, s| {
                        same(s, &saver)?;
                        s.held = Some(Box::new(disk_vault));
                        Ok(DiskEvent::OldKey)
                    })?;
                    return match event {
                        Some(event) => Ok(event),
                        None => busy(&mut sv),
                    };
                }
                None => return unreadable(self, &mut sv),
            }
            // The record of this Mac's key, made now, off the session lock:
            // kept if the merge gives the vault the disk copy's key.
            retiring = Some(self.record_of(&sv)?);
        }
        let same_root = disk_vault.root.uuid == root;
        let verdict = if same_root {
            self.guard(&disk_vault, &bytes)
        } else {
            crate::local_state::Verdict::default()
        };
        // LD-271 (6): with no unsaved changes APP-05.26 governs: merge,
        // then save at once.
        let guard = guard || before == Some(0);
        // APP-05.29: a Discard chosen before the compare is asked once
        // more (the first question's kind), with Merge the default; the
        // second Discard loads it.
        if new_key.is_some() && !guard && before.is_some() && verdict.older {
            let Some(again) = self.with_closed_editors(vault, |_, _, s| {
                let ask = match s.disk.asked {
                    Some(DiskAsk::OnSave) => DiskAsk::OnSave,
                    _ => DiskAsk::Unsaved,
                };
                Ok(
                    (!std::mem::replace(&mut s.disk.older_asked, true)).then_some(
                        DiskEvent::AskOlder {
                            ask,
                            changes: s.changes,
                        },
                    ),
                )
            })?
            else {
                return busy(&mut sv);
            };
            if let Some(again) = again {
                return Ok(again);
            }
        }
        // The disk version as read, for the guard's stored values; an older
        // one is never taken as seen.
        let read = (!verdict.older).then(|| disk_vault.duplicate());
        let merging = before.is_none() || (guard && verdict.older);
        let Some(taken) = self.with_closed_editors(vault, |v, rated, s| {
            same(s, &saver)?;
            let mut replaced = None;
            if merging || before.is_some_and(|b| s.changes > b) {
                // MOD-11.29: the open vault is the source, the disk version
                // the target; the live vault, so nothing made meanwhile is
                // lost.
                // F-226 (LD-319 (4)): an older version 3 file stores no
                // settings time; its reader's filled-in open time is not a
                // change, so it never wins the settings of MOD-11.19
                // (LD-185) over this Mac's stored one.
                if verdict.older && disk_vault.read_version.is_some_and(|r| r.major < 4) {
                    disk_vault.meta.settings_changed = Time(i64::MIN);
                }
                let o = Options::new(Kind::ChangeOnDisk);
                let merged =
                    merge(&mut disk_vault, v, &o, now()).map_err(|e| crate::edit::refused(&e))?;
                // APP-05.26 (F-218): an older version never lowers the KDF;
                // a version 3 target's filled-in settings time can win the
                // merge's MOD-11.19 compare.
                if verdict.older
                    && crate::local_state::kdf_lower(&v.encryption.kdf, &disk_vault.encryption.kdf)
                {
                    disk_vault.encryption.kdf = v.encryption.kdf;
                }
                replaced = Some(larsal_core::retired::replaced_by_merge(
                    &o,
                    &merged,
                    new_key.is_some(),
                ));
                s.changes = s.changes.max(1);
            } else {
                s.changes = 0;
            }
            // LD-269 (4) (F-220): MOD-11.19 limit 1 guards the target, here
            // the disk version, so a merge can take its weaker settings too:
            // the weaker list is the merged vault's.
            let weaker = if replaced.is_some() {
                self.guard(&disk_vault, &[]).weaker
            } else {
                verdict.weaker.clone()
            };
            *v = disk_vault;
            *rated = Rated::default();
            s.failure = None;
            s.disk.ignore = false;
            s.disk.unreadable = false;
            (s.disk.asked, s.disk.older_asked) = (None, false);
            s.disk.failures.reset();
            // LD-283 (3), LD-264: after a merge the vault keeps the key the
            // merge picked: this Mac's when it took it (T51 (b)); after a
            // reload, or a merge that kept the disk copy's key, the disk
            // copy's (APP-05.29).
            let keeps_mine = replaced == Some(false) && new_key.is_some();
            if let Some((password, key_file)) = new_key.filter(|_| !keeps_mine) {
                // APP-05.29: the open vault uses the new key from now on;
                // not a key change of Larsal's (APP-05.33 stays as it was).
                let pending = s.disk.new_key;
                s.set_key(&mut sv, Some(password), Some(key_file));
                s.disk.new_key = pending;
            }
            Ok((keeps_mine, replaced == Some(true), weaker))
        })?
        else {
            return busy(&mut sv);
        };
        let (keeps_mine, retire, weaker) = taken;
        let other_key = retiring.is_some();
        sv.checksum = sum;
        sv.watched = sum;
        // Opened with the key parts just above. A merge that keeps this Mac's
        // key has unsaved changes, so its next upload is its own save's.
        #[cfg(feature = "sync")]
        {
            sv.proven = larsal_sync::sync::hash(&bytes);
        }
        if !keeps_mine {
            sv.key = key;
        }
        drop(sv);
        if retire && let Some(record) = retiring {
            self.retire(root, record);
        }
        if let Some(read) = read {
            self.seen(&read, &bytes, None);
        }
        // APP-06.25 (F-079): auto-open after each reload or merge (APP-05.31).
        self.auto_open(vault);
        Ok(if verdict.older && (guard || (merging && other_key)) {
            DiskEvent::Rollback
        } else if !weaker.is_empty() {
            DiskEvent::Weaker {
                settings: weaker.join(", "),
            }
        } else {
            DiskEvent::Reloaded
        })
    }

    /// `bytes` opened with `credentials` (CRY-02.14 still applies: a reload
    /// never asks, the refuse ceilings hold): `Some(Err)` for `WrongKey`,
    /// `None` when it cannot be read.
    ///
    /// `approve` runs an ask-band cost with no question: only for the
    /// vault's own file, never for a conflict copy nobody chose (F-219).
    #[allow(clippy::option_option)]
    pub(crate) fn open_bytes(
        &self,
        bytes: &[u8],
        credentials: &Credentials<'_>,
        approve: bool,
    ) -> Option<Result<Box<larsal_format::OpenedVault>, ()>> {
        let mut host = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        let mut run = |approval: Option<&larsal_crypto::kdf::CostReport>| {
            larsal_format::open(bytes, credentials, &mut host, &Limits::DEFAULT, approval)
        };
        match match run(None) {
            Ok(Opened::Ask(report)) if approve => run(Some(&report)),
            other => other,
        } {
            Ok(Opened::Vault(opened)) => Some(Ok(opened)),
            Err(larsal_format::Error::WrongKey) => Some(Err(())),
            _ => None,
        }
    }

    /// MOD-11.31: whether `credentials`, given for a copy of the vault
    /// `root`, match a key this Mac retired; `None` when the key work
    /// failed (the caller merges nothing). Runs the KDF once per record.
    pub(crate) fn is_retired_copy(
        &self,
        root: larsal_model::Uuid,
        credentials: &Credentials<'_>,
    ) -> Option<bool> {
        let records = self.retired_records(root);
        if records.is_empty() {
            return Some(false);
        }
        let mut host = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        larsal_core::retired::is_retired(&records, credentials, &mut host, &Limits::DEFAULT).ok()
    }

    /// MOD-11.31, LD-288 (2): the record of the key `sv` holds, with the
    /// password-alone digest when it has a password plus another part (one
    /// more KDF run).
    ///
    /// # Errors
    /// `Refused` when the key work or the random source fails.
    pub(crate) fn record_of(
        &self,
        sv: &Saver,
    ) -> Result<larsal_core::retired::Record, LarsalError> {
        let failed =
            || LarsalError::Refused("The old key could not be recorded. Try again.".to_owned());
        let part = sv.hardware.map(crate::hwkey::Choice::part);
        let credentials = Credentials {
            password: sv.password.as_ref(),
            key_file: sv.key_file.as_ref(),
            hardware_key: part.as_deref(),
        };
        let alone = {
            let mut host = self.host.lock().unwrap_or_else(PoisonError::into_inner);
            larsal_core::retired::password_alone(&sv.key, &credentials, &mut host, &Limits::DEFAULT)
                .map_err(|_| failed())?
        };
        larsal_core::retired::Record::with(&sv.key, alone.as_ref()).map_err(|_| failed())
    }

    /// SYN-03.4 for sync: the local file and the open vault's measures,
    /// with the save lock held for the read, so no save runs meanwhile;
    /// `None` while locked, saving, with unsaved changes, an open editor or
    /// a disk event pending.
    ///
    /// SYN-03.5 step 2, SYN-03.14: every upload of the file crosses this
    /// read. `Some(Err)` with `MSG-SYNC-LOCAL-FILE` when the file is not the
    /// one this unlock last opened or wrote (another SHA-256: plain text,
    /// another vault's file, a corrupt or missing copy), or the open vault
    /// lost the root group id it unlocked with (the disk check loaded another
    /// vault under the same key). `Some(Err)` with `MSG-SYNC-SAVE-FIRST` when
    /// the file opened but its frame has room the reader skips: bytes past the
    /// final block or fields a save drops (`exact_frame`). A tick runs no KDF.
    /// A refusal changes nothing the disk check reads, so its event still
    /// comes. `None` too for a run that began on a file the vault has left
    /// with Save As, or before an unlock (SYN-03 T51, T61).
    #[cfg(feature = "sync")]
    pub(crate) fn sync_read(
        &self,
        vault: u64,
    ) -> Option<Result<(Vec<u8>, larsal_sync::state::Measures), larsal_sync::sync::Unproven>> {
        let unlocked = self.sync.root(vault);
        let saver = self.with_edit_view(vault, |_, s| s.saver.clone()).ok()??;
        let sv = saver.try_lock().ok()?;
        if self.sync.left(vault) {
            return None;
        }
        let (path, measures, root) = self
            .with_share(vault, |slot| {
                let v = slot.vault?;
                (!sync_busy(slot.edit, slot.share)
                    && !v.read_version.is_some_and(|version| version.major < 4))
                .then(|| {
                    (
                        slot.path.to_path_buf(),
                        crate::sync::measures(v),
                        v.root.uuid,
                    )
                })
            })
            .ok()??;
        let bytes = larsal_platform::macos::open_regular(&storage::real_path(&path))
            .map_err(|e| larsal_format::Error::Io(e.kind()))
            .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT));
        let proven = bytes.ok().filter(|bytes| {
            let hash = larsal_sync::sync::hash(bytes);
            larsal_crypto::secret::ct_eq(&hash, &sv.proven) && unlocked == Some(root)
        });
        drop(sv);
        use larsal_sync::sync::{Message, Unproven};
        Some(match proven {
            None => Err(Unproven(Message::LocalFile)),
            Some(bytes) if !larsal_format::integrity::exact_frame(&bytes, &Limits::DEFAULT) => {
                Err(Unproven(Message::SaveFirst))
            }
            Some(bytes) => Ok((bytes, measures)),
        })
    }

    /// SYN-03.5 step 3: opens the server copy `server` with the kept key
    /// parts (off the save lock, as F-227), merges the open vault (the
    /// source) into it (the target) with a same-vault merge
    /// (`Kind::ServerSync`), puts the result in place of the open vault and
    /// saves it, as one step under the save lock. The vault is never left
    /// half merged: a result whose save failed stays open as an unsaved
    /// change. The copy's key is never taken here: a copy under other
    /// credentials is `WrongKey` (SYN-03.8, E16-S7b).
    #[cfg(feature = "sync")]
    pub(crate) fn merge_server(&self, vault: u64, server: &[u8]) -> larsal_sync::sync::Merge {
        use larsal_sync::sync::Merge;
        let Ok((Some(saver), root)) =
            self.with_edit_view(vault, |v, s| (s.saver.clone(), v.root.uuid))
        else {
            return Merge::Busy;
        };
        let kept = {
            let sv = locked(&saver);
            (
                sv.password
                    .as_ref()
                    .map(|p| SecretString::new(p.expose().to_owned())),
                sv.key_file.as_ref().map(KeyFileKey::duplicate),
                sv.hardware,
            )
        };
        let part = kept.2.map(crate::hwkey::Choice::part);
        let credentials = Credentials {
            password: kept.0.as_ref(),
            key_file: kept.1.as_ref(),
            hardware_key: part.as_deref(),
        };
        // F-219: a copy nobody chose never runs an ask-band cost unasked.
        let mut copy = match self.open_bytes(server, &credentials, false) {
            None => return Merge::Failed,
            Some(Err(())) => return Merge::WrongKey,
            Some(Ok(opened)) => opened.vault,
        };
        if copy.root.uuid != root {
            return Merge::OtherVault;
        }
        #[cfg(test)]
        crate::sync::tests::server_opened();
        let measured = crate::sync::measures(&copy);
        let mut sv = locked(&saver);
        // A copy opened with credentials retired meanwhile needs a fresh run.
        let same_key = sv.password == kept.0
            && sv.hardware == kept.2
            && match (&sv.key_file, &kept.1) {
                (Some(a), Some(b)) => a.key() == b.key(),
                (a, b) => a.is_none() && b.is_none(),
            };
        if !same_key || self.sync.left(vault) {
            return Merge::Busy;
        }
        let staged = self.with_share(vault, |slot| -> Result<_, LarsalError> {
            let (Some(v), s) = (slot.vault, &mut *slot.edit) else {
                return Ok(None);
            };
            same(s, &saver)?;
            if sync_busy(s, slot.share)
                || (!s.disk.notice_confirmed
                    && v.read_version.is_some_and(|version| version.major < 4))
            {
                return Ok(None);
            }
            // A change of the vault, as `with_edit` counts one (F-165).
            *slot.version = slot.version.wrapping_add(1);
            let (path, rated) = (slot.path, slot.rated);
            let o = Options::new(Kind::ServerSync);
            let m = merge(&mut copy, v, &o, now()).map_err(|e| crate::edit::refused(&e))?;
            *v = copy;
            *rated = Rated::default();
            // Unsaved until the save below writes it.
            s.changes = 1;
            s.failure = None;
            Ok(Some((
                v.duplicate(),
                path.to_path_buf(),
                s.disk,
                !m.changes.is_empty(),
            )))
        });
        let (result, path, disk, changed) = match staged {
            Ok(Ok(Some(staged))) => staged,
            // The merge refused the copy (a limit), or the vault left.
            Ok(Err(_)) => return Merge::Failed,
            Ok(Ok(None)) | Err(_) => return Merge::Busy,
        };
        let method = self.method(false, disk);
        let wrote = self.write(&mut sv, &result, &path, disk, (false, method));
        let Wrote::Saved(_, version, saved) = wrote else {
            return Merge::Failed;
        };
        let done = self.with_edit(vault, |v, _, _, s| {
            same(s, &saver)?;
            v.read_version = Some(version);
            s.changes = s.changes.saturating_sub(1);
            s.saved_at = Some(unix(now()));
            Ok(crate::sync::measures(v))
        });
        drop(sv);
        let Ok(result) = done else {
            return Merge::Failed;
        };
        // INT-08.17: after every good save, the exporting shares write.
        self.share_saved(vault);
        Merge::Done {
            copy: measured,
            result,
            changed,
            saved,
        }
    }

    /// APP-05.26, APP-05.27: whether the rollback guard finds the disk
    /// version older; it opens with the kept key parts (the KDF). False when
    /// it does not open with them or cannot be read (its compare waits for
    /// the credentials, APP-05.29).
    fn disk_older(&self, vault: u64) -> Result<bool, LarsalError> {
        let (saver, path) = self.with_edit(vault, |_, path, _, s| {
            Ok((s.saver.clone(), path.to_path_buf()))
        })?;
        let Some(saver) = saver else {
            return Ok(false);
        };
        let sv = locked(&saver);
        let Ok(bytes) = larsal_platform::macos::open_regular(&storage::real_path(&path))
            .map_err(|e| larsal_format::Error::Io(e.kind()))
            .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT))
        else {
            return Ok(false);
        };
        let part = sv.hardware.map(crate::hwkey::Choice::part);
        let credentials = Credentials {
            password: sv.password.as_ref(),
            key_file: sv.key_file.as_ref(),
            hardware_key: part.as_deref(),
        };
        let Some(Ok(opened)) = self.open_bytes(&bytes, &credentials, true) else {
            return Ok(false);
        };
        drop(sv);
        let root = self.with_edit_view(vault, |v, _| v.root.uuid)?;
        Ok(opened.vault.root.uuid == root && self.guard(&opened.vault, &bytes).older)
    }
}

#[uniffi::export]
impl Session {
    /// APP-05.24, APP-05.25: the disk watch (Swift) saw something in the
    /// vault's folder, or its 30-second timer ticked. Compares the file's
    /// checksum with the one the watch last saw: same, unreadable or
    /// paused gives `None`; while a save runs or the editor is open,
    /// `Busy` (check again when it ends). A change is noted once: with
    /// unsaved changes it asks (APP-05.27); without, it reloads at once when
    /// `save.reload_on_change` is on (APP-05.26; runs the KDF, call it off
    /// the main thread), else asks. Never writes.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked` (the event is dropped, APP-05.25).
    pub fn check_disk(&self, vault: u64) -> Result<DiskEvent, LarsalError> {
        // F-278: these are looks; they must not re-queue a share import.
        let path = self.with_open(vault, |_, path, _| Ok(path.to_path_buf()))?;
        let (saver, editing, ignore) =
            self.with_edit_view(vault, |_, s| (s.saver.clone(), s.editing(), s.disk.ignore))?;
        let Some(saver) = saver else {
            return Ok(DiskEvent::None);
        };
        if ignore {
            return Ok(DiskEvent::None);
        }
        // LD-310 (7): defer the disk event while the group editor has a draft.
        let group_editor = self.with_share(vault, |slot| slot.share.draft.is_some())?;
        if editing || group_editor {
            return Ok(DiskEvent::Busy);
        }
        let mut sv = match saver.try_lock() {
            Ok(sv) => sv,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return Ok(DiskEvent::Busy),
        };
        let Some(seen) = storage::changed_on_disk(&storage::real_path(&path), &sv.watched) else {
            return Ok(DiskEvent::None);
        };
        let previous = sv.watched;
        sv.watched = seen;
        drop(sv);
        let result = (|| {
            let changes = self.with_edit_view(vault, |_, s| s.changes)?;
            // The KDF runs off the state lock; editor exclusion is checked
            // again under that lock when the result is applied or published.
            let event = if changes > 0 {
                let ask = DiskAsk::Unsaved;
                if self.disk_older(vault)? {
                    DiskEvent::AskOlder { ask, changes }
                } else {
                    DiskEvent::Ask { ask, changes }
                }
            } else if !self.settings.flag("save.reload_on_change".into())
                && !self.disk_older(vault)?
            {
                DiskEvent::Ask {
                    ask: DiskAsk::Reload,
                    changes,
                }
            } else {
                return self.take_disk_version(vault, Some(changes), None, true, Some(previous));
            };
            Ok(self
                .with_closed_editors(vault, |_, _, s| {
                    same(s, &saver)?;
                    (s.disk.asked, s.disk.older_asked) = (Some(DiskAsk::Unsaved), false);
                    Ok(event)
                })?
                .unwrap_or(DiskEvent::Busy))
        })();
        if matches!(result, Ok(DiskEvent::Busy)) {
            let mut sv = locked(&saver);
            if sv.watched == seen {
                sv.watched = previous;
            }
        }
        result
    }

    /// The answer to a changed-on-disk question (APP-05.26 to APP-05.29).
    /// Merge and Reload open the disk version (the KDF: call it off the
    /// main thread) and give `Reloaded`, `NewKey` or `Unreadable`; after a
    /// Merge the caller saves. Keep mine and Later give `None`; after Keep
    /// mine the caller saves, which replaces the disk version.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`; `Refused` when the merge fails.
    pub fn resolve_disk(&self, vault: u64, choice: DiskChoice) -> Result<DiskEvent, LarsalError> {
        match choice {
            DiskChoice::Merge => self.take_disk_version(vault, None, None, false, None),
            DiskChoice::Reload => {
                let changes = self.with_edit(vault, |_, _, _, s| Ok(s.changes))?;
                self.take_disk_version(vault, Some(changes), None, false, None)
            }
            DiskChoice::KeepMine | DiskChoice::Later => self.with_edit(vault, |_, _, _, s| {
                s.disk.ignore |= choice == DiskChoice::KeepMine;
                s.changes = s.changes.max(1);
                Ok(DiskEvent::None)
            }),
        }
    }

    /// APP-05.29 (F-085): the unlock sheet's answer after `NewKey`. Opens
    /// the disk version with `password` and `key_file` (as `unlock` takes
    /// them; the password goes into a secret type at once) and goes on with
    /// `choice`: Merge, or Reload for Discard and the silent reload. On
    /// success the open vault keeps these key parts, so later saves write
    /// the new key. `NewKey` again when they do not open the file. Keep
    /// mine and Later act as in `resolve_disk`. Runs the KDF: call it off
    /// the main thread.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`; `Refused` with the key file's
    /// message, or when the merge fails.
    pub fn resolve_disk_with_key(
        &self,
        vault: u64,
        choice: DiskChoice,
        password: Option<String>,
        key_file: Option<String>,
    ) -> Result<DiskEvent, LarsalError> {
        let password = password.map(SecretString::new);
        if password
            .as_ref()
            .is_some_and(|p| p.len() > crate::session::MAX_TEXT)
            || key_file.as_ref().is_some_and(|k| k.len() > 4096)
        {
            return Err(LarsalError::TooLong);
        }
        let before = match choice {
            DiskChoice::Merge => None,
            DiskChoice::Reload => Some(self.with_edit(vault, |_, _, _, s| Ok(s.changes))?),
            DiskChoice::KeepMine | DiskChoice::Later => return self.resolve_disk(vault, choice),
        };
        let key_file = match key_file.filter(|k| !k.is_empty()) {
            Some(typed) => {
                let path = self.with_edit(vault, |_, path, _, _| Ok(path.to_path_buf()))?;
                Some(
                    crate::session::read_key(&storage::real_path(&path), &typed)
                        .map_err(|m| LarsalError::Refused(m.text))?,
                )
            }
            None => None,
        };
        if password.is_none() && key_file.is_none() {
            return Ok(DiskEvent::NewKey);
        }
        self.take_disk_version(vault, before, Some((password, key_file)), false, None)
    }

    /// The answer to `MSG-DISK-OLD-KEY` for the vault's own file (APP-05.29,
    /// MOD-11.31, LD-269 (3)). Skip (`merge_anyway` false) takes nothing of
    /// the copy; Merge anyway runs the content merge with the open vault as
    /// the target: its entries and changes, never its key, its deletions or
    /// its metadata. Either way the vault keeps this Mac's key and the
    /// caller saves at once over the copy, as Overwrite (APP-05.28): with
    /// backups on the copy is kept as the backup first. `Reloaded` after
    /// Merge anyway, else `None`.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`; `Refused` when the merge fails.
    pub fn resolve_old_key(
        &self,
        vault: u64,
        merge_anyway: bool,
    ) -> Result<DiskEvent, LarsalError> {
        self.with_edit(vault, |v, _, rated, s| {
            let held = s.held.take();
            let mut event = DiskEvent::None;
            if merge_anyway && let Some(copy) = held {
                let o = Options {
                    retired: true,
                    ..Options::new(Kind::ChangeOnDisk)
                };
                merge(v, &copy, &o, now()).map_err(|e| crate::edit::refused(&e))?;
                *rated = Rated::default();
                event = DiskEvent::Reloaded;
            }
            s.disk.ignore = true;
            s.changes = s.changes.max(1);
            Ok(event)
        })
    }

    /// APP-05.14 Turn off (F-087): this vault saves with `save.unsafe_method`
    /// for as long as it stays open; the app setting and every other vault
    /// are unchanged. The caller saves again at once.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn turn_off_safe_save(&self, vault: u64) -> Result<(), LarsalError> {
        self.with_edit(vault, |_, _, _, s| {
            s.disk.unsafe_method = true;
            s.disk.failures.reset();
            Ok(())
        })
    }

    /// APP-05.33 Delete checked (F-088): removes those of `paths` that are
    /// still old copies of this vault (`SaveStatus.old_copies` listed
    /// them); any other path is left alone. Returns the paths that could
    /// not be removed, for the report.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn delete_old_copies(
        &self,
        vault: u64,
        paths: Vec<String>,
    ) -> Result<Vec<String>, LarsalError> {
        let path = self.with_edit(vault, |_, path, _, _| Ok(path.to_path_buf()))?;
        let listed = self.old_copies(&path);
        Ok(paths
            .into_iter()
            .filter(|p| {
                let p = Path::new(p);
                !listed.iter().any(|l| l == p) || std::fs::remove_file(p).is_err()
            })
            .collect())
    }

    /// APP-05.32: the user saw `MSG-SAVE-V4-NOTICE` (OK); the next save
    /// writes version 4. Never asked again for this vault in this session.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn confirm_format_notice(&self, vault: u64) -> Result<(), LarsalError> {
        self.with_edit(vault, |_, _, _, s| {
            s.disk.notice_confirmed = true;
            Ok(())
        })
    }

    /// APP-05.6 Save As: writes the vault to `path` (the save panel asked
    /// before replacing a file) with the safe method and a backup of the
    /// file it replaces; no pre-save check, no notice. After a good write
    /// the vault's file is `path`, the recent list starts with it, and the
    /// old file stays as it was. Runs the KDF: call it off the main thread.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong` for a path over 4,096 bytes.
    pub fn save_as(&self, vault: u64, path: String) -> Result<SaveStatus, LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        self.save_to(vault, Some(PathBuf::from(path)))
    }

    /// APP-02.16 (LD-50): an automatic lock or quit signal whose save did
    /// not run, failed or met a file changed on disk keeps the vault as it
    /// is in memory in a recovery copy: a normal vault file under the
    /// current key, written with the safe method at 0600 into `recovery`
    /// (0700) of Larsal's settings folder, named by the SHA-256 of the vault's
    /// real path plus `.larsalvault`; a newer copy replaces the older one.
    /// When that fails too it leaves an empty `.lost` marker there. True
    /// when the copy was written; false, and nothing written, for a
    /// memory-only settings store. Whenever it is false the session keeps
    /// the memory note ([`Session::lost_changes`], LD-224 (4)). The caller
    /// locks after. Runs the KDF.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn write_recovery_copy(&self, vault: u64) -> Result<bool, LarsalError> {
        let (saver, path) = self.with_edit(vault, |_, path, _, s| {
            Ok((s.saver.clone(), path.to_path_buf()))
        })?;
        let Some(saver) = saver else {
            self.note_lost(&path);
            return Ok(false);
        };
        let sv = locked(&saver);
        let (copy, path) = self.with_edit(vault, |v, path, _, s| {
            same(s, &saver)?;
            Ok((v.duplicate(), path.to_path_buf()))
        })?;
        Ok(self.keep_copy(&sv, &copy, &path))
    }

    /// APP-02.16's memory note (LD-224 (4)), for the next unlock (W-16) and
    /// tests: the recovery copy names (lowercase SHA-256 hex of a vault's
    /// real path, no vault content) whose change an automatic lock or quit
    /// signal kept in no copy during this run.
    #[must_use]
    pub fn lost_changes(&self) -> Vec<String> {
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

/// APP-02.16: a recovery copy's name for the vault at `real`: the SHA-256 of
/// the real path in lowercase hex.
fn copy_name(real: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let digest = larsal_crypto::hash::sha256(&[real.as_os_str().as_bytes()]);
    digest.expose().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit::EditText;
    use crate::test_dir::TempDir;
    use crate::views::ListView;
    use std::os::unix::fs::PermissionsExt;

    const DEMO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/");

    /// A private folder with a copy of `file`, removed when the folder
    /// drops (LD-240 (5)).
    fn folder(tag: &str, file: &str, name: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new(&format!("saving-{tag}"));
        let path = dir.join(name);
        std::fs::copy(format!("{DEMO}{file}"), &path).unwrap();
        (dir, path)
    }

    /// A session (one window) with `path` unlocked.
    fn window(path: &Path, password: &str) -> (Arc<Session>, u64) {
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some(password.into()), None).unwrap();
        (s, v)
    }

    fn personal(tag: &str) -> (TempDir, PathBuf, Arc<Session>, u64) {
        let (dir, path) = folder(tag, "option-a-personal.larsalvault", "Personal.larsalvault");
        let (s, v) = window(&path, "demo-pass-7");
        (dir, path, s, v)
    }

    fn titles(s: &Session, v: u64) -> Vec<String> {
        let mut t: Vec<String> = s
            .list(v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.title)
            .collect();
        t.sort();
        t
    }

    fn id_of(s: &Session, v: u64, title: &str) -> String {
        s.list(v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == title)
            .unwrap()
            .id
    }

    /// One committed change: a new entry named `title`.
    fn add(s: &Session, v: u64, title: &str) {
        s.begin_new(v, None).unwrap();
        s.set_text(v, EditText::Title, title.into()).unwrap();
        s.commit_edit(v).unwrap();
    }

    /// One committed change: entry `title`'s notes.
    fn note(s: &Session, v: u64, title: &str, notes: &str) {
        s.begin_edit(v, id_of(s, v, title)).unwrap();
        s.set_text(v, EditText::Notes, notes.into()).unwrap();
        s.commit_edit(v).unwrap();
    }

    fn saved(st: &SaveStatus) {
        assert_eq!(
            (st.changes, &st.failure, st.on_disk),
            (0, &None, None),
            "{st:?}"
        );
    }

    /// What a later reader of the file sees.
    fn on_file(path: &Path) -> Vec<String> {
        let (s, v) = window(path, "demo-pass-7");
        titles(&s, v)
    }

    /// APP-05.19, APP-05.21 (T32, AT-I06): with backups on (Larsal's default)
    /// each save first copies the file on disk, byte for byte, to
    /// `Personal.old.larsalvault`, mode 0600 even when the vault is 0644; the
    /// vault keeps its 0644.
    #[test]
    fn app_05_19_the_backup_holds_the_file_before_each_save() {
        let (dir, path, s, v) = personal("backup");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        add(&s, v, "Demo Shop");
        saved(&s.save(v).unwrap());
        let first = std::fs::read(&path).unwrap();
        add(&s, v, "Demo Shop 2");
        saved(&s.save(v).unwrap());
        let backup = dir.join("Personal.old.larsalvault");
        assert_eq!(std::fs::read(&backup).unwrap(), first);
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.10 step 3, APP-05.28 (T17): another writer replaced the file;
    /// the save writes nothing, makes no backup, is not a failure, and asks.
    #[test]
    fn app_05_10_a_file_changed_on_disk_is_not_overwritten_and_asks() {
        let (dir, path, s, v) = personal("refuse");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        let theirs = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(dir.join("Personal.old.larsalvault"));
        add(&s, v, "Demo Mail 2");
        let st = s.save(v).unwrap();
        assert_eq!(
            (st.on_disk, st.failure, st.changes),
            (Some(DiskAsk::OnSave), None, 1)
        );
        assert_eq!(std::fs::read(&path).unwrap(), theirs, "nothing written");
        assert!(!dir.join("Personal.old.larsalvault").exists(), "no backup");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.24 (T40, T41): Larsal's own save raises no event; a change by
    /// another writer is seen once; a missing file raises none (T42).
    #[test]
    fn app_05_24_own_saves_raise_no_event_and_another_writer_does_once() {
        let (dir, path, s, v) = personal("watch");
        add(&s, v, "Demo Shop");
        saved(&s.save(v).unwrap());
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::None, "own save");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Bank 2");
        saved(&other.save(ov).unwrap());
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Reloaded,
            "APP-05.26 silent reload"
        );
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::None, "seen once");
        std::fs::rename(&path, dir.join("moved.larsalvault")).unwrap();
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::None,
            "a missing file raises no event"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.25 (T43): while the editor is open the event waits; when it
    /// closes the check runs the flow.
    #[test]
    fn app_05_25_the_editor_keeps_the_event_pending() {
        let (dir, path, s, v) = personal("pending");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        s.begin_edit(v, id_of(&s, v, "Wise")).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Busy);
        s.cancel_edit(v).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Reloaded);
        assert!(titles(&s, v).contains(&"Demo Shop".to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// LD-310 (7), APP-05.25: while the group editor is open the event
    /// waits, as it does for the entry editor; when it closes the check
    /// runs the flow.
    #[test]
    fn ld_310_7_the_group_editor_keeps_the_event_pending() {
        let (dir, path, s, v) = personal("pending-group");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        let root = s.sidebar(v).unwrap().root;
        s.share_edit(v, root).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Busy);
        s.share_edit_cancel(v).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Reloaded);
        assert!(titles(&s, v).contains(&"Demo Shop".to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// F-261, LD-310 (7): the early guard on its own. With the group editor
    /// open the check answers `Busy` before it looks at the file, also when
    /// the file did not change; only that guard can answer so, because every
    /// later check needs a change on disk.
    #[test]
    fn f261_the_group_editor_answers_busy_before_the_file_is_looked_at() {
        let (_dir, _path, s, v) = personal("early-group");
        let root = s.sidebar(v).unwrap().root;
        s.share_edit(v, root).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Busy);
        s.share_edit_cancel(v).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::None);
    }

    /// APP-05.26 (T44, T45): unchanged and auto reload on: the disk version
    /// shows at once, nothing changed; auto reload off: it asks, and Keep
    /// marks the vault changed so the next save asks.
    #[test]
    fn app_05_26_an_unchanged_vault_reloads_or_asks_by_the_setting() {
        let (dir, path, s, v) = personal("reload");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Reloaded);
        assert!(titles(&s, v).contains(&"Demo Shop".to_owned()));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        s.save_settings(vec![crate::larsal_settings::LarsalSetting {
            key: "save.reload_on_change".into(),
            value: crate::larsal_settings::LarsalSettingValue::Flag { on: false },
        }])
        .unwrap();
        add(&other, ov, "Demo Shop 2");
        saved(&other.save(ov).unwrap());
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Reload,
                changes: 0
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Later).unwrap(),
            DiskEvent::None
        );
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::None,
            "asked once: the 30 s tick does not ask again"
        );
        assert_eq!(s.save(v).unwrap().on_disk, Some(DiskAsk::OnSave));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.27 Merge (T46): the open vault's unsaved change and the disk
    /// version's new entry are both kept, in the vault and in the file.
    #[test]
    fn app_05_27_merge_keeps_both_sides_and_saves() {
        let (dir, path, s, v) = personal("merge");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        note(&s, v, "Wise", "mine");
        let ask = s.check_disk(v).unwrap();
        assert_eq!(
            ask,
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                changes: 1
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        saved(&s.save(v).unwrap());
        assert!(on_file(&path).contains(&"Demo Shop".to_owned()));
        let (again, av) = window(&path, "demo-pass-7");
        assert_eq!(
            again
                .show_field(av, id_of(&again, av, "Wise"), "Notes".into())
                .unwrap(),
            "mine"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// E15-S2 (LD-265, MOD-11.29, SD-03): a change-on-disk merge keeps a
    /// deletion made on the other copy. The other window deletes Google for
    /// good and empties the bin; this window, with an unsaved note, picks
    /// Merge: nothing deleted comes back from memory, and the note stays.
    #[test]
    fn ld_265_a_change_on_disk_merge_keeps_a_deletion_made_on_the_other_copy() {
        let (dir, path, s, v) = personal("deleted");
        let (other, ov) = window(&path, "demo-pass-7");
        other.delete_entry(ov, id_of(&other, ov, "Google")).unwrap();
        assert!(other.empty_bin(ov).unwrap() >= 1);
        saved(&other.save(ov).unwrap());
        note(&s, v, "Wise", "mine");
        assert!(matches!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                ..
            }
        ));
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        saved(&s.save(v).unwrap());
        let (again, av) = window(&path, "demo-pass-7");
        assert!(!titles(&again, av).contains(&"Google".to_owned()));
        assert!(again.list(av, ListView::Bin).unwrap().rows.is_empty());
        assert_eq!(
            again
                .show_field(av, id_of(&again, av, "Wise"), "Notes".into())
                .unwrap(),
            "mine"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.27 Ignore (the frame's Keep mine, T47) and APP-05.28
    /// Overwrite (T49): the next save replaces the disk version without
    /// asking and says so once.
    #[test]
    fn app_05_28_keep_mine_saves_over_the_disk_version() {
        let (dir, path, s, v) = personal("overwrite");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        add(&s, v, "Demo Mail 2");
        assert_eq!(s.save(v).unwrap().on_disk, Some(DiskAsk::OnSave));
        assert_eq!(
            s.resolve_disk(v, DiskChoice::KeepMine).unwrap(),
            DiskEvent::None
        );
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::None,
            "the watch pauses"
        );
        let st = s.save(v).unwrap();
        saved(&st);
        assert_eq!(st.notice.as_deref(), Some("The file on disk was replaced."));
        let file = on_file(&path);
        assert!(
            file.contains(&"Demo Mail 2".to_owned()) && !file.contains(&"Demo Shop".to_owned())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.27 Discard (the frame's Reload, T48): the disk version
    /// replaces the open vault; nothing is unsaved.
    #[test]
    fn app_05_27_discard_takes_the_disk_version() {
        let (dir, path, s, v) = personal("discard");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        add(&s, v, "Demo Mail 2");
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Reload).unwrap(),
            DiskEvent::Reloaded
        );
        let now = titles(&s, v);
        assert!(now.contains(&"Demo Shop".to_owned()) && !now.contains(&"Demo Mail 2".to_owned()));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.29 (T51) and APP-05.30 (T52): a disk version that needs other
    /// credentials, or is not a vault, leaves the open vault unchanged; after
    /// an unreadable one a refused save offers Overwrite only.
    #[test]
    fn app_05_30_an_unreadable_disk_version_keeps_the_open_copy() {
        let (dir, path, s, v) = personal("unreadable");
        let before = titles(&s, v);
        std::fs::copy(format!("{DEMO}password-only.larsalvault"), &path).unwrap();
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::NewKey
        );
        std::fs::write(&path, [7u8; 100]).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Unreadable);
        assert_eq!(titles(&s, v), before);
        assert_eq!(s.save_status(v).unwrap().changes, 0, "not marked changed");
        add(&s, v, "Demo Shop");
        assert_eq!(s.save(v).unwrap().on_disk, Some(DiskAsk::OverwriteOnly));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.13 (T26 without the question): a write that fails names the
    /// reason, keeps the changes counted and leaves the old file intact.
    #[test]
    fn app_05_13_a_failed_write_names_the_reason_and_keeps_the_file() {
        let (dir, path, s, v) = personal("failed");
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        add(&s, v, "Demo Shop");
        let st = s.save(v).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(st.changes, 1);
        assert_eq!(
            st.failure.as_deref(),
            Some("This vault's file or its folder cannot be written.")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        saved(&s.save(v).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.32 (T54): a version 3.1 vault shows the notice before its
    /// first save and writes nothing; after OK it saves version 4.0, and
    /// later saves never ask again.
    #[test]
    fn app_05_32_a_version_3_vault_shows_the_notice_once_then_saves_version_4() {
        let (dir, path) = folder("v4", "password-only.larsalvault", "Old.larsalvault");
        let (s, v) = window(&path, "demo-pass-1");
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            before.get(10..12),
            Some(&[3u8, 0][..]),
            "the demo file is version 3"
        );
        add(&s, v, "Demo Shop");
        let st = s.save(v).unwrap();
        assert!(st.format_notice && st.changes == 1);
        assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
        s.confirm_format_notice(v).unwrap();
        saved(&s.save(v).unwrap());
        assert_eq!(
            std::fs::read(&path).unwrap().get(10..12),
            Some(&[4u8, 0][..])
        );
        add(&s, v, "Demo Shop 2");
        let st = s.save(v).unwrap();
        assert!(!st.format_notice);
        saved(&st);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.6 Save As (T11): a new 0600 file; the vault lives there now;
    /// the old file is unchanged; the recent list starts with it.
    #[test]
    fn app_05_6_save_as_moves_the_vault_to_the_new_file() {
        let (dir, path, s, v) = personal("save-as");
        let before = std::fs::read(&path).unwrap();
        add(&s, v, "Demo Shop");
        let copy = dir.join("Copy.larsalvault");
        let signals = crate::session::CHANGED.get();
        saved(&s.save_as(v, copy.to_string_lossy().into_owned()).unwrap());
        assert_eq!(crate::session::CHANGED.get(), signals + 1);
        assert_eq!(
            s.settings().recent_vaults().first(),
            Some(&copy.to_string_lossy().into_owned())
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(s.vaults()[0].path.ends_with("Copy.larsalvault"));
        assert!(on_file(&copy).contains(&"Demo Shop".to_owned()));
        add(&s, v, "Demo Shop 2");
        saved(&s.save(v).unwrap());
        assert!(on_file(&copy).contains(&"Demo Shop 2".to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-05.6: a Save As that fails moves nothing: the vault's path, the recent
    /// list and the change signal stay as they were.
    #[test]
    fn app_05_6_a_failed_save_as_moves_nothing() {
        let (dir, path, s, v) = personal("save-as-failed");
        let recent = s.settings().recent_vaults();
        let signals = crate::session::CHANGED.get();
        let to = dir.join("no-folder").join("Copy.larsalvault");
        let st = s.save_as(v, to.to_string_lossy().into_owned()).unwrap();
        assert!(st.failure.is_some());
        assert_eq!(s.vaults()[0].path, path.to_string_lossy());
        assert_eq!(s.settings().recent_vaults(), recent);
        assert_eq!(crate::session::CHANGED.get(), signals);
    }

    /// AT-I05: two windows edit one vault and save in turn. The second
    /// save finds the first one's file, merges, and saves; the first
    /// window then reloads. Nothing is lost on either side.
    #[test]
    fn at_i05_two_windows_save_in_turn_and_keep_every_change() {
        let (dir, path, a, av) = personal("two-windows");
        let (b, bv) = window(&path, "demo-pass-7");
        add(&a, av, "Demo Shop");
        saved(&a.save(av).unwrap());
        note(&b, bv, "Wise", "from window B");
        assert_eq!(b.save(bv).unwrap().on_disk, Some(DiskAsk::OnSave));
        assert_eq!(
            b.resolve_disk(bv, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        saved(&b.save(bv).unwrap());
        assert_eq!(a.check_disk(av).unwrap(), DiskEvent::Reloaded);
        add(&a, av, "Demo Bank 2");
        saved(&a.save(av).unwrap());
        assert_eq!(b.check_disk(bv).unwrap(), DiskEvent::Reloaded);
        let all = on_file(&path);
        for t in ["Demo Shop", "Demo Bank 2", "Wise"] {
            assert!(all.contains(&t.to_owned()), "{t}");
        }
        assert_eq!(titles(&a, av), titles(&b, bv));
        assert_eq!(
            a.show_field(av, id_of(&a, av, "Wise"), "Notes".into())
                .unwrap(),
            "from window B"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// AT-I05: a sync service swaps a new version in with an atomic rename
    /// while this window has unsaved edits; a conflict copy appears next to
    /// the vault. The copy alone raises no event; the swap asks, and Merge
    /// keeps every entry and change of both sides.
    #[test]
    fn at_i05_a_sync_swap_with_unsaved_edits_merges_without_loss() {
        let (dir, path, s, v) = personal("sync");
        // The other Mac's version, written elsewhere.
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let remote = elsewhere.join("Personal.larsalvault");
        std::fs::copy(&path, &remote).unwrap();
        let (other, ov) = window(&remote, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        note(&other, ov, "Google", "theirs");
        saved(&other.save(ov).unwrap());
        // This window's unsaved edits.
        add(&s, v, "Demo Mail 2");
        note(&s, v, "Wise", "mine");
        let before = titles(&s, v);
        // A conflict copy appears next to the vault: not the vault.
        std::fs::copy(&remote, dir.join("Personal (conflicted copy).larsalvault")).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::None);
        // The sync service's atomic replace: a temp file renamed over it.
        let temp = dir.join(".Personal.larsalvault.sync");
        std::fs::copy(&remote, &temp).unwrap();
        std::fs::rename(&temp, &path).unwrap();
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                changes: 2
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        saved(&s.save(v).unwrap());
        let (again, gv) = window(&path, "demo-pass-7");
        let all = titles(&again, gv);
        for t in before.iter().chain(["Demo Shop".to_owned()].iter()) {
            assert!(all.contains(t), "{t} kept");
        }
        assert_eq!(
            again
                .show_field(gv, id_of(&again, gv, "Wise"), "Notes".into())
                .unwrap(),
            "mine"
        );
        assert_eq!(
            again
                .show_field(gv, id_of(&again, gv, "Google"), "Notes".into())
                .unwrap(),
            "theirs"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// AT-I05: the conflict copy a sync service left is merged into the
    /// vault (MOD-11): every entry and change of both sides is kept.
    #[test]
    fn at_i05_a_conflict_copy_merges_without_lost_entries() {
        let (dir, path, s, v) = personal("conflict");
        let conflict = dir.join("Personal (conflicted copy).larsalvault");
        std::fs::copy(&path, &conflict).unwrap();
        let (other, ov) = window(&conflict, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        note(&other, ov, "Google", "theirs");
        saved(&other.save(ov).unwrap());
        add(&s, v, "Demo Mail 2");
        note(&s, v, "Wise", "mine");
        saved(&s.save(v).unwrap());
        // The conflict copy goes in place of the vault, as a sync service
        // that keeps the other side's version does.
        std::fs::rename(&conflict, dir.join("swap")).unwrap();
        let mine = std::fs::read(&path).unwrap();
        std::fs::rename(dir.join("swap"), &path).unwrap();
        std::fs::write(&conflict, mine).unwrap();
        // Unchanged here: reloaded; when the two saves fell in different
        // seconds the copy is older, so the rollback guard merges it
        // (APP-05.26). Either way both sides' entries stay.
        let first = s.check_disk(v).unwrap();
        assert!(
            matches!(first, DiskEvent::Reloaded | DiskEvent::Rollback),
            "{first:?}"
        );
        // Our saved version now sits in the conflict copy; merge it back
        // through the same flow: it lands on disk, the open vault is
        // unchanged, and Merge keeps both.
        add(&s, v, "Demo Bank 2");
        let temp = dir.join(".swap");
        std::fs::copy(&conflict, &temp).unwrap();
        std::fs::rename(&temp, &path).unwrap();
        assert!(matches!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                ..
            } | DiskEvent::AskOlder {
                ask: DiskAsk::Unsaved,
                ..
            }
        ));
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        saved(&s.save(v).unwrap());
        let (again, gv) = window(&path, "demo-pass-7");
        let all = titles(&again, gv);
        for t in ["Demo Shop", "Demo Mail 2", "Demo Bank 2"] {
            assert!(all.contains(&t.to_owned()), "{t} kept");
        }
        assert_eq!(
            again
                .show_field(gv, id_of(&again, gv, "Wise"), "Notes".into())
                .unwrap(),
            "mine"
        );
        assert_eq!(
            again
                .show_field(gv, id_of(&again, gv, "Google"), "Notes".into())
                .unwrap(),
            "theirs"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The save lock of vault `v`, as the tests hold or watch it.
    fn save_lock(s: &Session, v: u64) -> Arc<Mutex<Saver>> {
        s.with_edit(v, |_, _, _, st| Ok(st.saver.clone().unwrap()))
            .unwrap()
    }

    /// Waits until `job` holds the save lock: `refs` references to it
    /// exist (the job cloned it), then a try fails. `job` only ever takes it
    /// blocking from there, so the tries never turn it away.
    fn wait_held<T>(saver: &Arc<Mutex<Saver>>, refs: usize, job: &std::thread::JoinHandle<T>) {
        while Arc::strong_count(saver) < refs || saver.try_lock().is_ok() {
            assert!(!job.is_finished(), "the job waits for the KDF");
            std::thread::yield_now();
        }
    }

    /// AT-I05, APP-05.26: a change committed while a silent reload opens
    /// the disk version (its KDF) is merged in and stays counted; it is
    /// never dropped by the reload.
    #[test]
    fn at_i05_a_change_made_during_a_silent_reload_is_kept() {
        let (dir, path, s, v) = personal("during-reload");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        let saver = save_lock(&s, v);
        let host = s.host.lock().unwrap();
        let reload = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.check_disk(v))
        };
        // check_disk and the reload hold their references: the change
        // count is read; the KDF waits for `host`.
        wait_held(&saver, 4, &reload);
        add(&s, v, "Typed meanwhile");
        drop(host);
        assert_eq!(reload.join().unwrap().unwrap(), DiskEvent::Reloaded);
        let now = titles(&s, v);
        for t in ["Typed meanwhile", "Demo Shop"] {
            assert!(now.contains(&t.to_owned()), "{t} in {now:?}");
        }
        assert!(s.save_status(v).unwrap().changes > 0, "still to be saved");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// AT-I05, APP-05.27 Discard (and Load): a change committed while the
    /// disk version opens (its KDF) is merged in and stays counted, so such
    /// a Discard turns into a merge and discards nothing.
    #[test]
    fn at_i05_a_change_made_during_a_discard_is_kept() {
        let (dir, path, s, v) = personal("during-discard");
        add(&s, v, "Local");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        let saver = save_lock(&s, v);
        let host = s.host.lock().unwrap();
        let discard = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.resolve_disk(v, DiskChoice::Reload))
        };
        // The reload holds its reference and the save lock; the KDF waits.
        wait_held(&saver, 3, &discard);
        add(&s, v, "Typed meanwhile");
        drop(host);
        assert_eq!(discard.join().unwrap().unwrap(), DiskEvent::Reloaded);
        let now = titles(&s, v);
        for t in ["Typed meanwhile", "Demo Shop"] {
            assert!(now.contains(&t.to_owned()), "{t} in {now:?}");
        }
        assert!(s.save_status(v).unwrap().changes > 0, "still to be saved");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// LD-199 (4), one lock order (the save lock before the session lock):
    /// Vault Settings opens while a reload or a save holds the save lock
    /// and waits for its KDF, and a key change during a save waits for it,
    /// then goes on. Time-boxed: the old order hung here.
    #[test]
    fn ld_199_4_vault_settings_during_a_reload_or_a_save_never_hangs() {
        use crate::vault_settings::VaultSettings;
        use std::sync::mpsc;
        use std::time::Duration;
        let (dir, path, s, v) = personal("settings-lock-order");
        let saver = save_lock(&s, v);
        let view = |s: &Arc<Session>| {
            let (tx, rx) = mpsc::channel();
            let s = Arc::clone(s);
            std::thread::spawn(move || tx.send(VaultSettings::new(s, v).view().is_ok()));
            rx
        };
        // A silent reload (check_disk clones the lock, then the reload).
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        let host = s.host.lock().unwrap();
        let reload = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.check_disk(v))
        };
        wait_held(&saver, 4, &reload);
        assert_eq!(
            view(&s).recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "Vault Settings opens during a reload"
        );
        drop(host);
        assert_eq!(reload.join().unwrap().unwrap(), DiskEvent::Reloaded);
        // A save.
        add(&s, v, "Demo Mail 2");
        let host = s.host.lock().unwrap();
        let save = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.save(v))
        };
        wait_held(&saver, 3, &save);
        assert_eq!(
            view(&s).recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "Vault Settings opens during a save"
        );
        drop(host);
        assert_eq!(save.join().unwrap().unwrap().failure, None);
        // A key change while a save holds the save lock (held here) waits
        // for it before it takes the session lock, so the save can still
        // record its result (the session answers meanwhile).
        let held = saver.lock().unwrap();
        let (tx, key) = mpsc::channel();
        {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let settings = VaultSettings::new(s, v);
                settings
                    .set_password("4v8Nq2LmZ7rT1xKc9WbP".into())
                    .unwrap();
                settings.set_repeat("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
                tx.send(settings.change_password(Vec::new()).ok())
            });
        }
        std::thread::sleep(Duration::from_millis(200));
        let (tx, status) = mpsc::channel();
        {
            let s = Arc::clone(&s);
            std::thread::spawn(move || tx.send(s.save_status(v).is_ok()));
        }
        assert_eq!(
            status.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the session answers while a key change waits for a save"
        );
        drop(held);
        assert_eq!(
            key.recv_timeout(Duration::from_secs(20)),
            Ok(Some(crate::wizard::Outcome::Done)),
            "then the key change goes on"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-02.16 T47, T55, T56, APP-05.28 T60 (LD-50): an automatic lock's
    /// save meets a file another writer changed; the unsaved change goes to
    /// the recovery copy (0600 in `recovery`, 0700, named by the SHA-256 of
    /// the real path), which opens with the vault's key; when the copy
    /// cannot be written, the `.lost` marker is left instead.
    #[test]
    fn app_02_16_an_unattended_lock_keeps_the_change_in_a_recovery_copy() {
        use std::os::unix::ffi::OsStrExt;
        let (dir, path, s, v) = personal("recovery");
        add(&s, v, "Typed before the lock");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Demo Shop");
        saved(&other.save(ov).unwrap());
        assert_eq!(s.save(v).unwrap().on_disk, Some(DiskAsk::OnSave));
        assert!(!s.write_recovery_copy(v).unwrap(), "memory-only settings");
        let settings = dir.join("settings");
        s.settings.use_folder(settings.display().to_string());
        let digest =
            larsal_crypto::hash::sha256(&[storage::real_path(&path).as_os_str().as_bytes()]);
        let name: String = digest.expose().iter().map(|b| format!("{b:02x}")).collect();
        let copy = settings
            .join("recovery")
            .join(format!("{name}.larsalvault"));
        let lost = settings
            .join("recovery")
            .join(format!("{name}.larsalvault.lost"));
        assert!(s.write_recovery_copy(v).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&copy), mode(copy.parent().unwrap())), (0o600, 0o700));
        assert!(on_file(&copy).contains(&"Typed before the lock".to_owned()));
        std::fs::remove_file(&copy).unwrap();
        std::fs::create_dir(&copy).unwrap();
        assert!(!s.write_recovery_copy(v).unwrap(), "a folder in the way");
        assert_eq!(std::fs::metadata(&lost).unwrap().len(), 0, "the marker");
        s.lock_all();
        assert!(!on_file(&path).contains(&"Typed before the lock".to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// APP-02 T55 (LD-224 (4)): a read-only `recovery` folder stops the
    /// copy and the marker; the vault still locks with no question, the
    /// folder stays empty, and the session keeps the memory note for the
    /// copy's name. A memory-only settings store keeps the note too.
    /// (MSG-LOCK-LOST at the next unlock waits for W-16.)
    #[test]
    fn app_02_t55_a_read_only_recovery_folder_leaves_the_memory_note() {
        let (dir, path, s, v) = personal("t55");
        add(&s, v, "Typed before the lock");
        let name = copy_name(&storage::real_path(&path));
        let settings = dir.join("settings");
        let recovery = settings.join("recovery");
        std::fs::create_dir_all(&recovery).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o500)).unwrap();
        s.settings.use_folder(settings.display().to_string());
        assert!(s.lost_changes().is_empty());
        let wrote = s.write_recovery_copy(v).unwrap();
        s.lock_all();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!wrote, "no copy in a read-only folder");
        assert!(s.vaults().iter().all(|i| i.locked));
        assert_eq!(
            std::fs::read_dir(&recovery).unwrap().count(),
            0,
            "no copy, no marker"
        );
        assert_eq!(s.lost_changes(), std::slice::from_ref(&name));
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Typed in a memory-only session");
        assert!(!other.write_recovery_copy(ov).unwrap());
        assert_eq!(other.lost_changes(), [name]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// LD-241 (2), APP-02.16: a vault with no key parts to save with (no
    /// saver) writes no recovery copy and keeps the memory note.
    #[test]
    fn ld_241_a_vault_with_no_saver_leaves_the_memory_note() {
        let (dir, path, s, v) = personal("no-saver");
        add(&s, v, "Typed before the lock");
        let settings = dir.join("settings");
        s.settings.use_folder(settings.display().to_string());
        s.with_edit(v, |_, _, _, st| {
            st.saver = None;
            Ok(())
        })
        .unwrap();
        assert!(s.lost_changes().is_empty());
        assert!(
            !s.write_recovery_copy(v).unwrap(),
            "no copy without a saver"
        );
        assert!(!settings.join("recovery").exists(), "no copy, no marker");
        assert_eq!(s.lost_changes(), [copy_name(&storage::real_path(&path))]);
    }

    /// APP-02 T62, the lock half (LD-224 (4)): a folder where the copy would
    /// go stops the copy; the empty `.lost` marker (0600) is left beside it
    /// and the session keeps the memory note. (MSG-LOCK-LOST from the
    /// marker after a restart waits for W-16.)
    #[test]
    fn app_02_t62_a_taken_copy_name_leaves_the_marker_and_the_note() {
        let (dir, path, s, v) = personal("t62");
        add(&s, v, "Typed before the lock");
        let name = copy_name(&storage::real_path(&path));
        let settings = dir.join("settings");
        let recovery = settings.join("recovery");
        let taken = recovery.join(format!("{name}.larsalvault"));
        std::fs::create_dir_all(&taken).unwrap();
        s.settings.use_folder(settings.display().to_string());
        assert!(
            !s.write_recovery_copy(v).unwrap(),
            "the copy's name is taken"
        );
        s.lock_all();
        assert!(s.vaults().iter().all(|i| i.locked));
        let meta = std::fs::metadata(recovery.join(format!("{name}.larsalvault.lost"))).unwrap();
        assert_eq!((meta.len(), meta.permissions().mode() & 0o777), (0, 0o600));
        assert!(taken.is_dir(), "the folder in the way is left");
        assert_eq!(s.lost_changes(), [name]);
        let _ = std::fs::remove_dir_all(dir);
    }
    /// The strong demo password the key changes below set.
    const NEW_PASSWORD: &str = "4v8Nq2LmZ7rT1xKc9WbP";

    /// MOD-12.10 through the vault settings: the password of vault `v`
    /// becomes `NEW_PASSWORD` for the next save.
    fn change_password(s: &Arc<Session>, v: u64) {
        let vs = crate::vault_settings::VaultSettings::new(Arc::clone(s), v);
        vs.set_password(NEW_PASSWORD.into()).unwrap();
        vs.set_repeat(NEW_PASSWORD.into()).unwrap();
        assert_eq!(
            vs.change_password(vec![]).unwrap(),
            crate::wizard::Outcome::Done
        );
    }

    /// F-085 (APP-05.29, T51): another session added 'Theirs' and changed
    /// the password. Merge gives `NewKey`; the unlock sheet's wrong
    /// password gives it again; the new one merges both sides, and the
    /// saved file holds both and opens with the new password only.
    #[test]
    fn f_085_a_rekeyed_disk_version_merges_with_the_new_password() {
        let (dir, path, s, v) = personal("rekey");
        add(&s, v, "Mine unsaved");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Theirs");
        change_password(&other, ov);
        saved(&other.save(ov).unwrap());
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                changes: 1
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::NewKey
        );
        assert_eq!(
            s.resolve_disk_with_key(v, DiskChoice::Merge, Some("wrong".into()), None)
                .unwrap(),
            DiskEvent::NewKey
        );
        assert_eq!(
            s.resolve_disk_with_key(v, DiskChoice::Merge, Some(NEW_PASSWORD.into()), None)
                .unwrap(),
            DiskEvent::Reloaded
        );
        saved(&s.save(v).unwrap());
        let (again, av) = window(&path, NEW_PASSWORD);
        let t = titles(&again, av);
        assert!(
            t.contains(&"Theirs".to_owned()) && t.contains(&"Mine unsaved".to_owned()),
            "{t:?}"
        );
        let (old, ol) = window(&path, "demo-pass-7");
        assert!(
            old.list(ol, ListView::All).is_err(),
            "the old password no longer opens it"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// F-087 (APP-05.14, LD-52): three failed safe saves in a row (the
    /// folder is gone, a reason the other methods can help with) ask to
    /// turn safe saving off; Turn off saves this vault with the unsafe
    /// method (direct here: the file keeps its inode), the setting stays.
    #[test]
    fn f_087_the_third_failed_safe_save_asks_to_turn_it_off() {
        use std::os::unix::fs::MetadataExt;
        let (dir, path, s, v) = personal("unsafe");
        s.save_settings(vec![crate::larsal_settings::LarsalSetting {
            key: "save.alternative.mode".into(),
            value: crate::larsal_settings::LarsalSettingValue::Number { value: 1 },
        }])
        .unwrap();
        add(&s, v, "Demo Shop");
        let away = dir.with_extension("away");
        let _ = std::fs::remove_dir_all(&away);
        std::fs::rename(&dir, &away).unwrap();
        let asks: Vec<bool> = (0..3).map(|_| s.save(v).unwrap().ask_unsafe).collect();
        assert_eq!(asks, [false, false, true]);
        std::fs::rename(&away, &dir).unwrap();
        s.turn_off_safe_save(v).unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let st = s.save(v).unwrap();
        saved(&st);
        assert!(!st.ask_unsafe);
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            inode,
            "direct write"
        );
        assert!(!s.settings.flag("save.alternative".into()));
        assert!(on_file(&path).contains(&"Demo Shop".to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// F-088 (APP-05.33, T56): the save that writes the new key lists the
    /// backup that still opens with the old password (the key-change save's
    /// own backup); later saves list nothing. Delete checked removes only
    /// listed copies.
    #[test]
    fn f_088_the_key_change_save_lists_the_old_copies() {
        let (dir, _path, s, v) = personal("old-copies");
        add(&s, v, "Demo Shop");
        assert_eq!(s.save(v).unwrap().old_copies, None);
        change_password(&s, v);
        let st = s.save(v).unwrap();
        saved(&st);
        let backup = storage::real_path(&dir).join("Personal.old.larsalvault");
        assert_eq!(
            st.old_copies,
            Some(vec![backup.to_string_lossy().into_owned()])
        );
        let (old, ol) = window(&backup, "demo-pass-7");
        assert!(
            old.list(ol, ListView::All).is_ok(),
            "the backup opens with the old password"
        );
        add(&s, v, "Demo Shop 2");
        assert_eq!(
            s.save(v).unwrap().old_copies,
            None,
            "only the key-change save"
        );
        let other = dir.join("other.txt");
        std::fs::write(&other, b"x").unwrap();
        let left = s
            .delete_old_copies(
                v,
                vec![
                    backup.to_string_lossy().into_owned(),
                    other.to_string_lossy().into_owned(),
                ],
            )
            .unwrap();
        assert_eq!(left, [other.to_string_lossy().into_owned()]);
        assert!(!backup.exists() && other.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// F-086 (MOD-05.13): another app saves an edit into the open copy; it
    /// is found, Save puts it into the draft, Discard keeps the draft, and
    /// each change asks once.
    #[test]
    fn f_086_an_outside_edit_of_an_open_copy_is_asked_and_saved() {
        // F-133: the copy lives in the folder the start-up clean wipes.
        let _folder = crate::test_dir::open_folder_lock();
        let (dir, _path, s, v) = personal("open-copy");
        let source = dir.join("codes.txt");
        std::fs::write(&source, b"first").unwrap();
        s.begin_edit(v, id_of(&s, v, "Wise")).unwrap();
        s.attach_file(v, source.to_string_lossy().into_owned())
            .unwrap();
        let crate::edit::OpenAttachment::Opened { path: copy } =
            s.open_attachment(v, "codes.txt".into(), false).unwrap()
        else {
            panic!("opened")
        };
        assert!(s.changed_attachments(v).unwrap().is_empty());
        let content = |s: &Session| {
            let out = dir.join("out");
            s.save_attachment(
                v,
                "codes.txt".into(),
                out.to_string_lossy().into_owned(),
                true,
            )
            .unwrap();
            std::fs::read(out.join("codes.txt")).unwrap()
        };
        std::fs::write(&copy, b"second edit").unwrap();
        assert_eq!(s.changed_attachments(v).unwrap(), ["codes.txt"]);
        s.take_changed_attachment(v, "codes.txt".into(), true)
            .unwrap();
        assert!(s.changed_attachments(v).unwrap().is_empty(), "asked once");
        assert_eq!(content(&s), b"second edit");
        std::fs::write(&copy, b"third").unwrap();
        assert_eq!(s.changed_attachments(v).unwrap(), ["codes.txt"]);
        s.take_changed_attachment(v, "codes.txt".into(), false)
            .unwrap();
        assert!(s.changed_attachments(v).unwrap().is_empty());
        assert_eq!(content(&s), b"second edit", "Discard keeps the draft");
        s.commit_edit(v).unwrap();
        assert!(!Path::new(&copy).exists(), "the copy goes with the editor");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// F-133: the open-copy test waits for the opened-attachment folder's
    /// lock, so the start-up clean test never wipes its copy mid-test.
    #[test]
    fn f_133_the_open_copy_test_waits_for_the_folder_lock() {
        crate::test_dir::waits_for_open_folder_lock(
            f_086_an_outside_edit_of_an_open_copy_is_asked_and_saved,
        );
    }

    fn mkfifo(p: &Path) {
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(p)
            .status()
            .unwrap();
        assert!(made.success());
    }

    /// Runs `job` on its own thread and gives its result, failing the test
    /// when it takes a second or more; the waiting open of `fifo` is then
    /// freed, as the attack's watchdog did (F-101).
    fn within_a_second<T: Send + 'static>(
        fifo: &Path,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(job()));
        rx.recv_timeout(std::time::Duration::from_secs(1))
            .unwrap_or_else(|_| {
                let f = fifo.to_path_buf();
                std::thread::spawn(move || std::fs::OpenOptions::new().write(true).open(f));
                panic!("waited a second or more on the FIFO");
            })
    }

    /// F-101 (LD-225 (1), E13-S2 AT-E03): with a FIFO swapped in at the
    /// vault's path, the save, the disk check and the reload each answer at
    /// once, and so does a Save As onto a FIFO: the saves fail with their
    /// reason, the check sees nothing, the reload finds the file
    /// unreadable; nothing waits for a writer. Once locked, the unlock and
    /// its header check answer at once too.
    #[test]
    fn f_101_save_check_reload_and_save_as_refuse_a_fifo_at_once() {
        let (dir, path, s, v) = personal("f101");
        add(&s, v, "Demo Shop");
        std::fs::remove_file(&path).unwrap();
        mkfifo(&path);
        let not_a_file = Some("This vault's path is not a file Larsal can write.".to_owned());
        let job = Arc::clone(&s);
        let st = within_a_second(&path, move || job.save(v)).unwrap();
        assert_eq!((st.failure, st.changes), (not_a_file.clone(), 1));
        let job = Arc::clone(&s);
        let seen = within_a_second(&path, move || job.check_disk(v)).unwrap();
        assert_eq!(seen, DiskEvent::None);
        let job = Arc::clone(&s);
        let reload = within_a_second(&path, move || job.resolve_disk(v, DiskChoice::Reload));
        assert_eq!(reload.unwrap(), DiskEvent::Unreadable);
        let other = dir.join("Other.larsalvault");
        mkfifo(&other);
        let (job, to) = (Arc::clone(&s), other.to_string_lossy().into_owned());
        let st = within_a_second(&other, move || job.save_as(v, to)).unwrap();
        assert_eq!(st.failure, not_a_file);
        assert_eq!(
            titles(&s, v).iter().filter(|t| *t == "Demo Shop").count(),
            1
        );
        s.lock(v).unwrap();
        let job = Arc::clone(&s);
        let header = within_a_second(&path, move || job.check_header(v));
        assert!(
            header.unwrap().is_some(),
            "the header check names the failure"
        );
        let job = Arc::clone(&s);
        let attempt = within_a_second(&path, move || {
            job.unlock(v, Some("demo-pass-7".into()), None)
        });
        assert!(
            matches!(attempt, Ok(crate::session::UnlockResult::Failed { .. })),
            "{attempt:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// F-101: a save an automatic lock overtook (Saving.swift stops waiting
    /// for it after a second) and that then does not write keeps the change
    /// in the recovery copy, as that lock would have (APP-02.16).
    #[test]
    fn f_101_a_save_the_lock_overtook_keeps_the_change_in_a_recovery_copy() {
        let (dir, path, s, v) = personal("f101-overtaken");
        let settings = dir.join("settings");
        s.settings.use_folder(settings.display().to_string());
        add(&s, v, "Typed before the lock");
        let copy = settings.join("recovery").join(format!(
            "{}.larsalvault",
            copy_name(&storage::real_path(&path))
        ));
        std::fs::remove_file(&path).unwrap();
        mkfifo(&path);
        let saver = save_lock(&s, v);
        let host = s.host.lock().unwrap();
        let save = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.save(v))
        };
        wait_held(&saver, 3, &save);
        // It takes its copy of the vault, then waits for `host` (the KDF).
        std::thread::sleep(std::time::Duration::from_millis(200));
        s.lock_all();
        drop(host);
        assert!(matches!(save.join().unwrap(), Err(LarsalError::Locked)));
        assert!(on_file(&copy).contains(&"Typed before the lock".to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    // A disk reload held at its KDF: existing save-lock reference and host-lock seam.
    fn late_group_editor(deleted: bool, ask: Option<DiskAsk>) {
        use crate::share_edit::ShareChange;
        use std::time::{Duration, Instant};
        let tag = match (deleted, ask) {
            (true, _) => "late-deleted",
            (false, Some(DiskAsk::Unsaved)) => "late-unsaved-question",
            (false, Some(DiskAsk::Reload)) => "late-reload-question",
            _ => "late-root",
        };
        let (_dir, path, s, v) = personal(tag);
        let group = if deleted {
            let id = s
                .add_group(v, None, "Demo target".into(), 48, None)
                .unwrap();
            saved(&s.save(v).unwrap());
            id
        } else {
            s.sidebar(v).unwrap().root
        };
        let (other, ov) = window(&path, "demo-pass-7");
        if deleted {
            let id = crate::views::parse_id(&group, LarsalError::UnknownGroup).unwrap();
            other
                .with_edit(ov, |vault, _, _, state| {
                    larsal_core::recycle::delete_group(vault, id, now()).unwrap();
                    larsal_core::recycle::empty_bin(vault, now()).unwrap();
                    state.count_change();
                    Ok(())
                })
                .unwrap();
        } else {
            add(&other, ov, "Demo disk entry");
        }
        saved(&other.save(ov).unwrap());
        match ask {
            Some(DiskAsk::Unsaved) => add(&s, v, "Local before disk check"),
            Some(DiskAsk::Reload) => s
                .save_settings(vec![crate::larsal_settings::LarsalSetting {
                    key: "save.reload_on_change".into(),
                    value: crate::larsal_settings::LarsalSettingValue::Flag { on: false },
                }])
                .unwrap(),
            None => {}
            _ => unreachable!(),
        }
        let changes_before = s.save_status(v).unwrap().changes;
        let saver = save_lock(&s, v);
        let watched_before = locked(&saver).watched;
        let host = s.host.lock().unwrap();
        let reload = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.check_disk(v))
        };
        // Check and reader each hold a saver reference while the KDF waits on host.
        let end = Instant::now() + Duration::from_secs(10);
        while Arc::strong_count(&saver) < 4 || saver.try_lock().is_ok() {
            assert!(
                !reload.is_finished() && Instant::now() < end,
                "reload did not reach KDF seam"
            );
            std::thread::yield_now();
        }
        let version_before = s.with_share(v, |slot| *slot.version).unwrap();
        let page = s.share_edit(v, group.clone()).unwrap();
        assert_eq!(page.group, group);
        s.share_edit_change(
            v,
            ShareChange::Path {
                path: "pending.larsalvault".into(),
            },
        )
        .unwrap();
        let version_after = s.with_share(v, |slot| *slot.version).unwrap();
        assert_eq!(
            version_before, version_after,
            "draft did not count as a committed change"
        );
        assert_eq!(s.save_status(v).unwrap().changes, changes_before);
        drop(host);
        let event = reload.join().unwrap().unwrap();
        let draft_retained = s.with_share(v, |slot| slot.share.draft.is_some()).unwrap();
        let target_present = s
            .with_vault(v, |vault| {
                let id = crate::views::parse_id(&group, LarsalError::UnknownGroup)?;
                Ok(vault.root.find_group(id).is_some())
            })
            .unwrap();
        assert_eq!(
            event,
            DiskEvent::Busy,
            "the disk event waits for the open editor"
        );
        assert!(
            draft_retained && target_present,
            "the editor keeps its target"
        );
        assert_eq!(
            locked(&saver).watched,
            watched_before,
            "the event remains pending"
        );
        let watched_changed = locked(&saver).watched != watched_before;
        println!(
            "Late editor: deleted={deleted}, event={event:?}, draft_retained={draft_retained}, target_present={target_present}, watched_changed={watched_changed}, version_unchanged_on_draft={}",
            version_before == version_after
        );
        if deleted {
            let applied = s.share_edit_save(v);
            let draft_after_save = s.with_share(v, |slot| slot.share.draft.is_some()).unwrap();
            println!("Save: result={applied:?}, draft_after_save={draft_after_save}");
            assert!(
                applied.is_ok(),
                "late reload removed the edited group; Save consumes the draft before UnknownGroup"
            );
        } else {
            s.share_edit_cancel(v).unwrap();
            let retry = s.check_disk(v).unwrap();
            println!("After Cancel: next_check={retry:?}");
            match (ask, retry) {
                (
                    Some(expected),
                    DiskEvent::Ask { ask, changes } | DiskEvent::AskOlder { ask, changes },
                ) => {
                    assert_eq!((ask, changes), (expected, changes_before));
                }
                (None, DiskEvent::Reloaded) => {}
                (_, event) => panic!("the deferred disk event after Cancel: {event:?}"),
            }
            assert_eq!(
                s.check_disk(v).unwrap(),
                DiskEvent::None,
                "handled only once"
            );
        }
    }

    #[test]
    fn ld_310_7_a_group_opened_during_the_disk_kdf_defers_reload() {
        late_group_editor(false, None);
    }

    #[test]
    fn ld_310_7_a_deleted_disk_group_keeps_its_open_editor() {
        late_group_editor(true, None);
    }

    #[test]
    fn ld_310_7_a_late_group_editor_defers_the_unsaved_question() {
        late_group_editor(false, Some(DiskAsk::Unsaved));
    }

    #[test]
    fn ld_310_7_a_late_group_editor_defers_the_reload_question() {
        late_group_editor(false, Some(DiskAsk::Reload));
    }

    #[test]
    fn ld_310_7_a_late_group_editor_defers_a_merge_answer() {
        let (_dir, path, s, v) = personal("late-merge-answer");
        add(&s, v, "Local before answer");
        let (other, ov) = window(&path, "demo-pass-7");
        add(&other, ov, "Other before answer");
        saved(&other.save(ov).unwrap());
        assert!(matches!(s.check_disk(v).unwrap(), DiskEvent::Ask { .. }));
        let saver = save_lock(&s, v);
        let host = s.host.lock().unwrap();
        let merge = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.resolve_disk(v, DiskChoice::Merge))
        };
        wait_held(&saver, 3, &merge);
        let root = s.sidebar(v).unwrap().root;
        s.share_edit(v, root).unwrap();
        drop(host);
        assert_eq!(merge.join().unwrap().unwrap(), DiskEvent::Busy);
        s.share_edit_cancel(v).unwrap();
        assert!(
            matches!(s.check_disk(v).unwrap(), DiskEvent::Ask { .. }),
            "the deferred answer keeps its disk event"
        );
        assert!(titles(&s, v).contains(&"Local before answer".to_owned()));
    }
    #[test]
    fn f261_group_save_and_reload_keep_the_changed_draft() {
        use crate::share_edit::ShareChange;
        use std::sync::mpsc;
        use std::time::Duration;
        let (_dir, path, s, v) = personal("f261-save-commit-race");
        let group = s
            .add_group(v, None, "Demo target".into(), 48, None)
            .unwrap();
        saved(&s.save(v).unwrap());
        let (other, ov) = window(&path, "demo-pass-7");
        let gid = crate::views::parse_id(&group, LarsalError::UnknownGroup).unwrap();
        other
            .with_edit(ov, |vault, _, _, state| {
                larsal_core::recycle::delete_group(vault, gid, now()).unwrap();
                larsal_core::recycle::empty_bin(vault, now()).unwrap();
                state.count_change();
                Ok(())
            })
            .unwrap();
        saved(&other.save(ov).unwrap());
        s.share_edit(v, group).unwrap();
        s.share_edit_change(
            v,
            ShareChange::Path {
                path: "pending.larsalvault".into(),
            },
        )
        .unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let save = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                crate::share_edit::SAVE_PREPARED.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        ready_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }));
                });
                s.share_edit_save(v)
            })
        };
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let commit_locked = s.state_busy_for_test();
        let reload = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.check_disk(v))
        };
        let event = if commit_locked {
            release_tx.send(()).unwrap();
            reload.join().unwrap().unwrap()
        } else {
            let event = reload.join().unwrap().unwrap();
            release_tx.send(()).unwrap();
            event
        };
        let result = save.join().unwrap();
        println!("commit_locked={commit_locked}, save={result:?}, disk={event:?}");
        assert!(
            result.is_ok(),
            "Save must keep the changed group while the disk update waits"
        );
        assert!(matches!(
            event,
            DiskEvent::Ask { .. } | DiskEvent::AskOlder { .. }
        ));
        let stored = s
            .with_vault(v, |vault| {
                Ok(vault
                    .root
                    .find_group(gid)
                    .and_then(larsal_format::share_item::of))
            })
            .unwrap();
        assert!(
            matches!(
                stored,
                Some(larsal_format::share_item::Item::Settings(settings))
                    if settings.path == "pending.larsalvault"
            ),
            "the committed setting is the user's draft value"
        );
    }
}
