//! The conflict-copy finder's Rust side (E15-S4, APP-05.17; design:
//! spec/research/sync-server.md P18 (3)). Swift finds the iCloud conflict
//! versions (NSFileVersion) and runs each read in a coordinated read; this
//! lists the sibling candidates in the vault's folder and merges each copy
//! with MOD-11 (kind "Cloud conflict copy": the copy is the source, the
//! open vault the target).
//!
//! Guarantees:
//! - a name only makes a file a candidate; a copy merges only when it opens
//!   with the current key, or with credentials the user gave for it, and has
//!   the vault's root group id (MOD-11's Notation);
//! - Larsal's own files are never listed or opened: every file that matches
//!   this vault's backup pattern (the current one and the default, also
//!   while backups are off) and Larsal's temp files (APP-05.11 step 3, kept
//!   out by their `.tmp` extension);
//! - credentials that match a key this Mac retired merge nothing on their
//!   own (MOD-11.31): the copy waits for Merge anyway, the content merge
//!   only;
//! - after a merge the vault keeps the key LD-264 picks; when that is the
//!   copy's, this Mac's key is retired;
//! - nothing here deletes or moves a file: Swift moves a copy to the Trash
//!   only after the user's OK;
//! - a copy merged, kept, or skipped for another root group id is not
//!   merged, opened or listed again in this session until its checksum
//!   changes; the checksum is the one its coordinated read gave, and no
//!   read here outside `merge_copy` fetches a dataless copy (APP-05.24).

use crate::saving::same;
use crate::session::{LarsalError, MAX_TEXT, Session};
use crate::views::{Rated, now};
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::storage::{self, DEFAULT_BACKUP_PATTERN};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

/// What happened to one copy (`MSG-DISK-COPIES`, APP-05.17 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CopyState {
    /// Merged into the open vault: listed as Merged, checked for the Trash.
    Merged,
    /// It does not open with the current key (or with the credentials
    /// given): listed as Needs its password, with Unlock….
    NeedsPassword,
    /// The credentials given match a key this Mac retired: listed as Uses
    /// a replaced password, with Merge anyway (`MSG-DISK-OLD-KEY`).
    OldKey,
    /// Another root group id, unreadable, or seen already with this
    /// checksum: not merged and not listed.
    Skipped,
}

/// `{FILE_NAME}` of APP-05.20: the file name without its last extension.
fn stem(name: &str) -> &str {
    name.rfind('.')
        .map_or(name, |dot| name.get(..dot).unwrap_or(""))
}

impl Session {
    /// APP-05.17 step 4: this vault's backups by the current pattern and
    /// by the default one.
    fn backups(&self, real: &Path) -> Vec<PathBuf> {
        let home = std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from);
        let pattern = self.settings.text("backup.pattern".into());
        let mut out = storage::old_copies(&pattern, real, &home, None);
        out.extend(storage::old_copies(
            DEFAULT_BACKUP_PATTERN,
            real,
            &home,
            None,
        ));
        out
    }
}

#[uniffi::export]
impl Session {
    /// APP-05.17 steps 3 and 4: the files in the vault's folder with its
    /// extension whose names start with its `{FILE_NAME}`, the vault itself,
    /// its backups (current and default pattern) and Larsal's temp files left
    /// out, and every copy merged or kept in this session whose checksum is
    /// unchanged. Full paths, sorted. Reads the folder: call it off the
    /// main thread.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn conflict_copies(&self, vault: u64) -> Result<Vec<String>, LarsalError> {
        let seen = self.with_edit_view(vault, |_, s| s.copies_seen.clone())?;
        let path = self.with_open(vault, |_, path, _| Ok(path.to_path_buf()))?;
        let real = storage::real_path(&path);
        let (Some(dir), Some(name)) = (
            real.parent(),
            real.file_name().map(|n| n.to_string_lossy().into_owned()),
        ) else {
            return Ok(Vec::new());
        };
        let ext = real.extension().map(|e| e.to_string_lossy().to_lowercase());
        let base = stem(&name);
        let backups: Vec<_> = self
            .backups(&real)
            .iter()
            .map(|b| storage::file_id(b))
            .collect();
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let file = e.file_name().to_string_lossy().into_owned();
                let p = e.path();
                // Larsal's temp files (APP-05.11 step 3) end in `.tmp`: the
                // extension keeps them out.
                let candidate = file != name
                    && file.starts_with(base)
                    && p.extension().map(|x| x.to_string_lossy().to_lowercase()) == ext
                    && e.file_type().is_ok_and(|t| t.is_file())
                    // By what file it is, not by path text (F-224).
                    && !backups.contains(&storage::file_id(&p))
                    // APP-05.24: a seen copy that is dataless is unchanged;
                    // its read would fetch it outside the coordinated read.
                    && seen.get(&p).is_none_or(|sum| {
                        !larsal_platform::macos::dataless(&p)
                            && storage::changed_on_disk(&p, sum).is_some()
                    });
                candidate.then(|| p.to_string_lossy().into_owned())
            })
            .collect();
        out.sort();
        Ok(out)
    }

    /// APP-05.17 step 5 for one copy at `path` (a sibling from
    /// `conflict_copies` or an iCloud conflict version's file): opens it
    /// with the current key parts, or with `password` and `key_file` (as
    /// `unlock` takes them) when the user gave them (Unlock…), and merges it
    /// into the open vault when it has the vault's root group id. With
    /// `anyway` (Merge anyway), the copy held under a key this Mac retired
    /// gets the content merge only. A merge marks the vault changed; the
    /// caller saves. Runs the KDF: call it off the main thread, inside a
    /// coordinated read of `path`.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`; `Refused` with the key file's
    /// message, or when the merge fails.
    pub fn merge_copy(
        &self,
        vault: u64,
        path: String,
        password: Option<String>,
        key_file: Option<String>,
        anyway: bool,
    ) -> Result<CopyState, LarsalError> {
        let password = password.map(SecretString::new);
        if password.as_ref().is_some_and(|p| p.len() > MAX_TEXT)
            || key_file.as_ref().is_some_and(|k| k.len() > 4096)
            || path.len() > 4096
        {
            return Err(LarsalError::TooLong);
        }
        let copy = PathBuf::from(&path);
        if anyway {
            return self.with_edit(vault, |v, _, rated, s| {
                let Some((sum, Some(held))) = s.held_copies.remove(&copy) else {
                    return Ok(CopyState::Skipped);
                };
                s.copies_seen.insert(copy.clone(), sum);
                // MOD-11.31: the content merge only, the open vault the
                // target; never the copy's key, deletions or metadata.
                let o = Options {
                    retired: true,
                    ..Options::new(Kind::ConflictCopy)
                };
                let m = merge(v, &held, &o, now()).map_err(|e| crate::edit::refused(&e))?;
                if !m.changes.is_empty() {
                    *rated = Rated::default();
                    s.changes = s.changes.max(1);
                }
                Ok(CopyState::Merged)
            });
        }
        let (saver, root, seen) = self.with_edit_view(vault, |v, s| {
            (
                s.saver.clone(),
                v.root.uuid,
                s.copies_seen.get(&copy).copied(),
            )
        })?;
        let vault_path = self.with_open(vault, |_, p, _| Ok(p.to_path_buf()))?;
        let Some(saver) = saver else {
            return Ok(CopyState::Skipped);
        };
        let key_file = match key_file.filter(|k| !k.is_empty()) {
            Some(typed) => Some(
                crate::session::read_key(&storage::real_path(&vault_path), &typed)
                    .map_err(|m| LarsalError::Refused(m.text))?,
            ),
            None => None,
        };
        let given = password.is_some() || key_file.is_some();
        // F-227 (LD-319 (4)): the copy is read and opened (the KDF) outside
        // the save lock, with a copy of the kept key parts, so a save never
        // waits for it; the lock is taken only for the merge.
        let kept = {
            let sv = saver.lock().unwrap_or_else(PoisonError::into_inner);
            (
                sv.password
                    .as_ref()
                    .map(|p| SecretString::new(p.expose().to_owned())),
                sv.key_file
                    .as_ref()
                    .map(larsal_format::keyfile::KeyFileKey::duplicate),
                sv.hardware,
            )
        };
        #[cfg(test)]
        {
            let held = saver.try_lock().is_err();
            tests::opened_with_save_lock(held);
        }
        let Ok(bytes) = larsal_platform::macos::open_regular(&copy)
            .map_err(|e| larsal_format::Error::Io(e.kind()))
            .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT))
        else {
            return Ok(CopyState::Skipped);
        };
        let sum = storage::checksum(&bytes);
        // Step 6: merged or kept this session, and unchanged since.
        if seen.is_some_and(|seen| storage::changed_on_disk(&copy, &seen).is_none()) {
            return Ok(CopyState::Skipped);
        }
        let part = kept.2.map(crate::hwkey::Choice::part);
        let credentials = if given {
            Credentials {
                password: password.as_ref(),
                key_file: key_file.as_ref().map(|k| &k.0),
                hardware_key: part.as_deref(),
            }
        } else {
            Credentials {
                password: kept.0.as_ref(),
                key_file: kept.1.as_ref(),
                hardware_key: part.as_deref(),
            }
        };
        let opened = match self.open_bytes(&bytes, &credentials, false) {
            None => return Ok(CopyState::Skipped),
            Some(Err(())) => {
                return self.with_draft_state(vault, |_, s| {
                    s.held_copies.insert(copy.clone(), (sum, None));
                    Ok(CopyState::NeedsPassword)
                });
            }
            Some(Ok(opened)) => opened,
        };
        let larsal_format::OpenedVault {
            vault: copy_vault,
            key,
            ..
        } = *opened;
        if copy_vault.root.uuid != root {
            // Step 6 (F-180): not opened again until it changes.
            return self.with_draft_state(vault, |_, s| {
                s.held_copies.remove(&copy);
                s.copies_seen.insert(copy.clone(), sum);
                Ok(CopyState::Skipped)
            });
        }
        let mut retiring = None;
        if given {
            match self.is_retired_copy(root, &credentials) {
                Some(false) => {}
                Some(true) => {
                    return self.with_draft_state(vault, |_, s| {
                        same(s, &saver)?;
                        s.held_copies
                            .insert(copy.clone(), (sum, Some(Box::new(copy_vault))));
                        Ok(CopyState::OldKey)
                    });
                }
                None => return Ok(CopyState::Skipped),
            }
        }
        let mut sv = saver.lock().unwrap_or_else(PoisonError::into_inner);
        // The vault's key changed while the copy opened (a credential
        // change, or a merge that took another key): the copy opened with
        // the old one, so nothing is merged now; the next look tries again.
        let same_key = sv.password == kept.0
            && sv.hardware == kept.2
            && match (&sv.key_file, &kept.1) {
                (Some(a), Some(b)) => a.key() == b.key(),
                (a, b) => a.is_none() && b.is_none(),
            };
        if !given && !same_key {
            return Ok(CopyState::Skipped);
        }
        if given {
            retiring = Some(self.record_of(&sv)?);
        }
        let takes_key = self.with_edit(vault, |v, _, rated, s| {
            same(s, &saver)?;
            let o = Options::new(Kind::ConflictCopy);
            let m = merge(v, &copy_vault, &o, now()).map_err(|e| crate::edit::refused(&e))?;
            if !m.changes.is_empty() {
                *rated = Rated::default();
                s.changes = s.changes.max(1);
            }
            s.held_copies.remove(&copy);
            s.copies_seen.insert(copy.clone(), sum);
            // LD-264: the copy's newer key replaces this Mac's; the vault
            // saves with the credentials the user gave for it from now on.
            let takes = larsal_core::retired::replaced_by_merge(&o, &m, given);
            if takes {
                let pending = s.disk.new_key;
                s.set_key(&mut sv, Some(password), Some(key_file));
                s.disk.new_key = pending;
            }
            Ok(takes)
        })?;
        if takes_key {
            sv.key = key;
            drop(sv);
            if let Some(record) = retiring {
                self.retire(root, record);
            }
        }
        Ok(CopyState::Merged)
    }

    /// APP-05.17 step 6: the user closed `MSG-DISK-COPIES` (Keep or Move to
    /// Trash): the listed copies at `paths` are not merged or listed again
    /// in this session until their checksum changes; any held under a
    /// retired key are dropped. Reads no file (APP-05.24): each checksum is
    /// the one `merge_copy` took inside its coordinated read.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn copies_done(&self, vault: u64, paths: Vec<String>) -> Result<(), LarsalError> {
        self.with_draft_state(vault, |_, s| {
            for p in paths.into_iter().map(PathBuf::from) {
                if let Some((sum, _)) = s.held_copies.remove(&p) {
                    s.copies_seen.insert(p, sum);
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit::EditText;
    use crate::edit::SaveStatus;
    use crate::larsal_settings::{LarsalSetting, LarsalSettingValue};
    use crate::saving::{DiskAsk, DiskChoice, DiskEvent};
    use crate::test_dir::TempDir;
    use crate::views::ListView;
    use std::sync::Arc;

    const DEMO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/");

    thread_local! {
        /// F-227: whether this thread's last `merge_copy` held the save
        /// lock when it started to read and open the copy.
        static OPENED_LOCKED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
        /// What happens on this thread while the copy opens, the save lock
        /// free (the F-227 key-change test).
        static MEANWHILE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn opened_with_save_lock(held: bool) {
        OPENED_LOCKED.with(|c| c.set(Some(held)));
        if let Some(f) = MEANWHILE.with(|m| m.borrow_mut().take()) {
            f();
        }
    }
    /// A strong demo password (the key change checks its quality).
    const NEW: &str = "4v8Nq2LmZ7rT1xKc9WbP";

    fn folder(tag: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new(&format!("copies-{tag}"));
        let path = dir.join("Personal.larsalvault");
        std::fs::copy(format!("{DEMO}option-a-personal.larsalvault"), &path).unwrap();
        (dir, path)
    }

    /// A session (one Mac, with its own local state) with `path` unlocked.
    fn window(path: &Path, password: &str) -> (Arc<Session>, u64) {
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some(password.into()), None).unwrap();
        (s, v)
    }

    fn opens(path: &Path, password: &str) -> bool {
        let (s, v) = window(path, password);
        s.list(v, ListView::All).is_ok()
    }

    fn titles(s: &Session, v: u64) -> Vec<String> {
        s.list(v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.title)
            .collect()
    }

    fn has(s: &Session, v: u64, title: &str) -> bool {
        titles(s, v).iter().any(|t| t == title)
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

    fn add(s: &Session, v: u64, title: &str) {
        s.begin_new(v, None).unwrap();
        s.set_text(v, EditText::Title, title.into()).unwrap();
        s.commit_edit(v).unwrap();
    }

    fn note(s: &Session, v: u64, title: &str, notes: &str) {
        s.begin_edit(v, id_of(s, v, title)).unwrap();
        s.set_text(v, EditText::Notes, notes.into()).unwrap();
        s.commit_edit(v).unwrap();
    }

    fn notes(s: &Session, v: u64, title: &str) -> String {
        s.show_field(v, id_of(s, v, title), "Notes".into()).unwrap()
    }

    /// Deletes `title` for good (the bin emptied).
    fn delete(s: &Session, v: u64, title: &str) {
        s.delete_entry(v, id_of(s, v, title)).unwrap();
        assert!(s.empty_bin(v).unwrap() >= 1);
    }

    fn saved(st: &SaveStatus) {
        assert_eq!(
            (st.changes, &st.failure, st.on_disk),
            (0, &None, None),
            "{st:?}"
        );
    }

    fn change_password(s: &Arc<Session>, v: u64) {
        let vs = crate::vault_settings::VaultSettings::new(Arc::clone(s), v);
        vs.set_password(NEW.into()).unwrap();
        vs.set_repeat(NEW.into()).unwrap();
        assert_eq!(
            vs.change_password(vec![]).unwrap(),
            crate::wizard::Outcome::Done
        );
    }

    fn setting(s: &Session, key: &str, value: LarsalSettingValue) {
        s.save_settings(vec![LarsalSetting {
            key: key.into(),
            value,
        }])
        .unwrap();
    }

    /// Another tool: the file at `from` opened with `password` (and the
    /// key file `key`), changed by `edit`, saved under `to_password` alone
    /// with a fresh seed, written to `to`.
    fn rewrite(
        from: &Path,
        (password, key): (&str, Option<&Path>),
        to: &Path,
        to_password: &str,
        edit: impl FnOnce(&mut larsal_model::Vault),
    ) {
        let s = Session::new();
        let mut host = s.host.lock().unwrap();
        let key = key.map(|k| {
            larsal_format::keyfile::read_key_file(std::fs::File::open(k).unwrap(), &Limits::DEFAULT)
                .unwrap()
        });
        let (old, new) = (
            SecretString::new(password.to_owned()),
            SecretString::new(to_password.to_owned()),
        );
        let given = Credentials {
            password: Some(&old),
            key_file: key.as_ref(),
            hardware_key: None,
        };
        let bytes = std::fs::read(from).unwrap();
        let Ok(larsal_format::Opened::Vault(opened)) =
            larsal_format::open(&bytes, &given, &mut host, &Limits::DEFAULT, None)
        else {
            panic!("opens")
        };
        let mut vault = opened.vault;
        edit(&mut vault);
        let to_key = Credentials {
            password: Some(&new),
            key_file: None,
            hardware_key: None,
        };
        // The other tool approves its own ask-band cost.
        let mut save = |approval: Option<&larsal_crypto::kdf::CostReport>| {
            larsal_format::save(&vault, &to_key, None, &mut host, &Limits::DEFAULT, approval)
        };
        let Ok(larsal_format::Saved::File(file)) = (match save(None) {
            Ok(larsal_format::Saved::Ask(report)) => save(Some(&report)),
            other => other,
        }) else {
            panic!("saves")
        };
        std::fs::write(to, &file.bytes).unwrap();
    }

    fn at(secs: i64) -> larsal_model::Time {
        larsal_model::Time::from_unix(secs).unwrap()
    }

    fn names(paths: &[String]) -> Vec<String> {
        paths
            .iter()
            .map(|p| crate::session::file_name(Path::new(p)))
            .collect()
    }

    /// A copy of P at `name` in P's folder, with `title` added, under P's
    /// password.
    fn copy_with(path: &Path, name: &str, title: &str) -> PathBuf {
        let copy = path.with_file_name(name);
        std::fs::copy(path, &copy).unwrap();
        let (c, cv) = window(&copy, "demo-pass-7");
        // That Mac's own backup of the copy would be a candidate too.
        setting(&c, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&c, cv, title);
        saved(&c.save(cv).unwrap());
        copy
    }

    /// APP-05.17 T65: two sibling copies with Dropbox's and OneDrive's
    /// names merge, and the merged vault saves with both entries; a file of
    /// another name stem is never opened or listed; once closed with Keep,
    /// the copies are not listed again until one changes.
    #[test]
    fn app05_17_t65_sibling_copies_merge_and_another_stem_is_left_alone() {
        let (_dir, path) = folder("t65");
        let dropbox = copy_with(
            &path,
            "Personal (Demo User's conflicted copy 2026-10-31).larsalvault",
            "Demo Dropbox",
        );
        let onedrive = copy_with(&path, "Personal-DemoMac.larsalvault", "Demo OneDrive");
        let other = path.with_file_name("Other.larsalvault");
        std::fs::copy(&path, &other).unwrap();
        let (s, v) = window(&path, "demo-pass-7");
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(
            names(&found),
            [
                "Personal (Demo User's conflicted copy 2026-10-31).larsalvault",
                "Personal-DemoMac.larsalvault"
            ]
        );
        for copy in &found {
            assert_eq!(
                s.merge_copy(v, copy.clone(), None, None, false).unwrap(),
                CopyState::Merged
            );
        }
        saved(&s.save(v).unwrap());
        let (again, av) = window(&path, "demo-pass-7");
        assert!(has(&again, av, "Demo Dropbox") && has(&again, av, "Demo OneDrive"));
        // Keep: both files stay; the next tick lists neither.
        s.copies_done(v, found.clone()).unwrap();
        assert!(dropbox.exists() && onedrive.exists() && other.exists());
        assert!(s.conflict_copies(v).unwrap().is_empty());
        // Step 6 also for a path never listed (an iCloud version's file).
        assert_eq!(
            s.merge_copy(v, found[0].clone(), None, None, false)
                .unwrap(),
            CopyState::Skipped
        );
        // A copy that changes is listed again.
        let (c, cv) = window(&onedrive, "demo-pass-7");
        setting(&c, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&c, cv, "Demo OneDrive 2");
        saved(&c.save(cv).unwrap());
        assert_eq!(
            names(&s.conflict_copies(v).unwrap()),
            ["Personal-DemoMac.larsalvault"]
        );
    }

    /// APP-05.17 T66: the backup (a same-vault copy under the current key)
    /// and a leftover temp file are never listed; with a time pattern, its
    /// backup and the default one are not either, also with backups off.
    #[test]
    fn app05_17_t66_app_backups_and_temp_files_are_never_listed() {
        let (_dir, path) = folder("t66");
        let (s, v) = window(&path, "demo-pass-7");
        add(&s, v, "Demo Shop");
        saved(&s.save(v).unwrap());
        assert!(path.with_file_name("Personal.old.larsalvault").is_file());
        std::fs::copy(
            &path,
            path.with_file_name(".Personal.larsalvault.k3x9a2b7.tmp"),
        )
        .unwrap();
        assert!(s.conflict_copies(v).unwrap().is_empty(), "first run");
        setting(
            &s,
            "backup.pattern",
            LarsalSettingValue::Text {
                text: "{FILE_NAME}_{TIME:HHmmss}.larsalvault".into(),
            },
        );
        std::fs::copy(&path, path.with_file_name("Personal_140309.larsalvault")).unwrap();
        assert!(s.conflict_copies(v).unwrap().is_empty(), "time pattern");
        setting(&s, "backup.enabled", LarsalSettingValue::Flag { on: false });
        assert!(s.conflict_copies(v).unwrap().is_empty(), "backups off");
    }

    /// APP-05.17 T67: a candidate with another root group id is not merged
    /// (and not listed); a copy under another password waits as Needs its
    /// password, P and the file unchanged, until the password is given;
    /// then it merges, and the vault keeps the key LD-264 picks (the copy's
    /// newer one): this Mac's key is retired.
    #[test]
    fn app05_17_t67_another_root_id_is_skipped_and_another_password_waits() {
        let (_dir, path) = folder("t67");
        let stranger = path.with_file_name("Personal 2.larsalvault");
        rewrite(
            Path::new(&format!("{DEMO}option-a-work.larsalvault")),
            ("demo-pass-8", None),
            &stranger,
            "demo-pass-7",
            |_| {},
        );
        let copy = path.with_file_name("Personal (copy).larsalvault");
        std::fs::copy(&path, &copy).unwrap();
        let (c, cv) = window(&copy, "demo-pass-7");
        setting(&c, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&c, cv, "Demo Copy");
        change_password(&c, cv);
        saved(&c.save(cv).unwrap());
        let (s, v) = window(&path, "demo-pass-7");
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(
            names(&found),
            ["Personal (copy).larsalvault", "Personal 2.larsalvault"]
        );
        let (copy_path, stranger_path) = (found[0].clone(), found[1].clone());
        assert_eq!(
            s.merge_copy(v, stranger_path, None, None, false).unwrap(),
            CopyState::Skipped
        );
        let before = std::fs::read(&copy).unwrap();
        assert_eq!(
            s.merge_copy(v, copy_path.clone(), None, None, false)
                .unwrap(),
            CopyState::NeedsPassword
        );
        assert!(!has(&s, v, "Demo Copy"));
        assert_eq!(s.save_status(v).unwrap().changes, 0, "P unchanged");
        assert_eq!(std::fs::read(&copy).unwrap(), before, "the file unchanged");
        assert_eq!(
            s.merge_copy(v, copy_path, Some(NEW.into()), None, false)
                .unwrap(),
            CopyState::Merged
        );
        assert!(has(&s, v, "Demo Copy"));
        saved(&s.save(v).unwrap());
        assert!(opens(&path, NEW) && !opens(&path, "demo-pass-7"));
        let root = s.with_vault(v, |v| Ok(v.root.uuid)).unwrap();
        assert_eq!(s.retired_records(root).len(), 1, "this Mac's key retired");
    }

    /// APP-05.17 with FMT-15 (a same-vault merge runs the deletion pass): a
    /// copy made before an entry was deleted for good does not bring it
    /// back.
    #[test]
    fn app05_17_a_merged_copy_brings_back_no_deleted_entry() {
        let (_dir, path) = folder("deleted");
        let copy = copy_with(&path, "Personal-DemoMac.larsalvault", "Demo Copy");
        let (s, v) = window(&path, "demo-pass-7");
        delete(&s, v, "Google");
        saved(&s.save(v).unwrap());
        assert_eq!(
            s.merge_copy(v, copy.to_string_lossy().into_owned(), None, None, false)
                .unwrap(),
            CopyState::Merged
        );
        assert!(has(&s, v, "Demo Copy") && !has(&s, v, "Google"));
    }

    /// APP-05.29 T64 (LD-267 (2), LD-269 (3)): this Mac changed P's password;
    /// P's file is replaced by a copy under the old password, saved again,
    /// with "Demo Old" added, "Wise" changed, "Google" deleted for good and
    /// a key-change time of 2099. The old password gives `OldKey` before
    /// any merge. Skip takes nothing and the save puts P over the copy
    /// under the new password; Merge anyway adds and changes, never
    /// deletes, and keeps this Mac's key and key-change time.
    #[test]
    fn app05_29_t64_a_copy_under_a_replaced_password_waits_for_skip_or_merge_anyway() {
        for anyway in [false, true] {
            let (dir, path) = folder(if anyway { "t64-anyway" } else { "t64-skip" });
            let (s, v) = window(&path, "demo-pass-7");
            let old = dir.join("old.larsalvault");
            std::fs::copy(&path, &old).unwrap();
            change_password(&s, v);
            saved(&s.save(v).unwrap());
            let changed = s.with_vault(v, |v| Ok(v.meta.master_key_changed)).unwrap();
            let (o, ov) = window(&old, "demo-pass-7");
            add(&o, ov, "Demo Old");
            note(&o, ov, "Wise", "theirs");
            delete(&o, ov, "Google");
            saved(&o.save(ov).unwrap());
            rewrite(&old, ("demo-pass-7", None), &path, "demo-pass-7", |v| {
                v.meta.master_key_changed = at(4_070_908_800);
            });
            assert_eq!(s.check_disk(v).unwrap(), DiskEvent::NewKey);
            assert_eq!(
                s.resolve_disk_with_key(v, DiskChoice::Merge, Some("demo-pass-7".into()), None)
                    .unwrap(),
                DiskEvent::OldKey
            );
            assert!(!has(&s, v, "Demo Old"), "nothing merged before the answer");
            let event = s.resolve_old_key(v, anyway).unwrap();
            saved(&s.save(v).unwrap());
            assert!(opens(&path, NEW) && !opens(&path, "demo-pass-7"));
            let (f, fv) = window(&path, NEW);
            assert!(has(&f, fv, "Google"), "never its deletions");
            assert_eq!(
                f.with_vault(fv, |v| Ok(v.meta.master_key_changed)).unwrap(),
                changed,
                "this Mac's key-change time"
            );
            if anyway {
                assert_eq!(event, DiskEvent::Reloaded);
                assert!(has(&f, fv, "Demo Old"));
                assert_eq!(notes(&f, fv, "Wise"), "theirs");
            } else {
                assert_eq!(event, DiskEvent::None);
                assert!(!has(&f, fv, "Demo Old"));
                assert_ne!(notes(&f, fv, "Wise"), "theirs");
            }
        }
    }

    /// APP-05.29 T64 for a conflict copy (APP-05.17 step 5): a sibling copy
    /// under the password this Mac replaced waits as Needs its password;
    /// that old password gives `OldKey` before any merge; Merge anyway
    /// takes its entries only, and the vault keeps this Mac's key.
    #[test]
    fn app05_29_t64_c_a_conflict_copy_under_a_replaced_password_gives_old_key() {
        let (_dir, path) = folder("t64-copy");
        let (s, v) = window(&path, "demo-pass-7");
        let old = path.with_file_name("Personal (old).larsalvault");
        std::fs::copy(&path, &old).unwrap();
        change_password(&s, v);
        saved(&s.save(v).unwrap());
        let (o, ov) = window(&old, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&o, ov, "Demo Old");
        saved(&o.save(ov).unwrap());
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(names(&found), ["Personal (old).larsalvault"]);
        let copy = found[0].clone();
        assert_eq!(
            s.merge_copy(v, copy.clone(), None, None, false).unwrap(),
            CopyState::NeedsPassword
        );
        assert_eq!(
            s.merge_copy(v, copy.clone(), Some("demo-pass-7".into()), None, false)
                .unwrap(),
            CopyState::OldKey
        );
        assert!(!has(&s, v, "Demo Old"), "nothing merged before the answer");
        assert_eq!(
            s.merge_copy(v, copy, None, None, true).unwrap(),
            CopyState::Merged
        );
        assert!(has(&s, v, "Demo Old"));
        saved(&s.save(v).unwrap());
        assert!(opens(&path, NEW) && !opens(&path, "demo-pass-7"));
    }

    /// APP-05.29 T51 (b) (LD-267 (1)): P is under the new password, with a
    /// key-change time of 2026-10-20 and no record of the old one; its file
    /// is replaced by a copy under the old password (2026-10-01) that adds
    /// "Demo Shop". The old password merges it; the next save keeps this
    /// Mac's newer key, so the file no longer opens with the old one.
    #[test]
    fn app05_29_t51_b_an_older_key_on_disk_keeps_this_macs_key() {
        let (dir, path) = folder("t51b");
        let original = dir.join("original.larsalvault");
        std::fs::copy(&path, &original).unwrap();
        rewrite(&original, ("demo-pass-7", None), &path, NEW, |v| {
            v.meta.master_key_changed = at(1_792_454_400);
        });
        let (s, v) = window(&path, NEW);
        let (o, ov) = window(&original, "demo-pass-7");
        add(&o, ov, "Demo Shop");
        saved(&o.save(ov).unwrap());
        rewrite(
            &original,
            ("demo-pass-7", None),
            &path,
            "demo-pass-7",
            |v| {
                v.meta.master_key_changed = at(1_790_812_800);
            },
        );
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::NewKey);
        assert_eq!(
            s.resolve_disk_with_key(v, DiskChoice::Merge, Some("demo-pass-7".into()), None)
                .unwrap(),
            DiskEvent::Reloaded
        );
        assert!(has(&s, v, "Demo Shop"));
        saved(&s.save(v).unwrap());
        assert!(opens(&path, NEW) && !opens(&path, "demo-pass-7"));
        let root = s.with_vault(v, |v| Ok(v.root.uuid)).unwrap();
        assert!(s.retired_records(root).is_empty(), "nothing retired");
    }

    /// APP-05.17, APP-05.29 T69 (LD-267 (2), LD-269 (3)): Macs A and B,
    /// each with its own local state, share P. A changes the password and
    /// adds "Demo A"; B, under the old password, adds "Demo B" and deletes
    /// "Wise" for good; B's save is the one at P's path. A gets `OldKey`
    /// and, after Skip, saves its vault under the new password. B asks for
    /// the password this copy opens with, merges and saves: the file holds
    /// both entries and no "Wise", and opens only with the new password.
    /// A then reloads it with no question.
    #[test]
    fn app05_17_t69_two_macs_converge_under_the_new_password() {
        let (dir, path) = folder("t69");
        let (a, av) = window(&path, "demo-pass-7");
        let (b, bv) = window(&path, "demo-pass-7");
        let original = std::fs::read(&path).unwrap();
        add(&b, bv, "Demo B");
        delete(&b, bv, "Wise");
        change_password(&a, av);
        add(&a, av, "Demo A");
        saved(&a.save(av).unwrap());
        std::fs::write(&path, &original).unwrap();
        saved(&b.save(bv).unwrap());
        let _ = std::fs::remove_file(dir.join("Personal.old.larsalvault"));
        assert_eq!(a.check_disk(av).unwrap(), DiskEvent::NewKey);
        assert_eq!(
            a.resolve_disk_with_key(av, DiskChoice::Merge, Some("demo-pass-7".into()), None)
                .unwrap(),
            DiskEvent::OldKey
        );
        assert_eq!(a.resolve_old_key(av, false).unwrap(), DiskEvent::None);
        saved(&a.save(av).unwrap());
        assert!(opens(&path, NEW) && !opens(&path, "demo-pass-7"));
        assert_eq!(b.check_disk(bv).unwrap(), DiskEvent::NewKey);
        assert_eq!(
            b.resolve_disk_with_key(bv, DiskChoice::Merge, Some(NEW.into()), None)
                .unwrap(),
            DiskEvent::Reloaded
        );
        saved(&b.save(bv).unwrap());
        assert!(opens(&path, NEW) && !opens(&path, "demo-pass-7"));
        let (f, fv) = window(&path, NEW);
        assert!(has(&f, fv, "Demo A") && has(&f, fv, "Demo B") && !has(&f, fv, "Wise"));
        assert_eq!(a.check_disk(av).unwrap(), DiskEvent::Reloaded);
        assert!(has(&a, av, "Demo B"));
    }

    /// MOD-11.31 T75 through Larsal (LD-288 (2)): the record of a password plus
    /// key file vault's key, made at the credential change, also matches
    /// the old password alone: a copy planted under it gives `OldKey`.
    #[test]
    fn mod11_31_t75_a_copy_under_the_old_password_alone_gives_old_key() {
        let dir = TempDir::new("copies-t75");
        let path = dir.join("Basic.larsalvault");
        let key = dir.join("key-hex64.larsalkey");
        std::fs::copy(format!("{DEMO}password-and-keyfile.larsalvault"), &path).unwrap();
        std::fs::copy(format!("{DEMO}key-hex64.larsalkey"), &key).unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(
            v,
            Some("demo-pass-2".into()),
            Some(key.to_string_lossy().into_owned()),
        )
        .unwrap();
        let original = dir.join("original.larsalvault");
        std::fs::copy(&path, &original).unwrap();
        change_password(&s, v);
        s.confirm_format_notice(v).unwrap();
        saved(&s.save(v).unwrap());
        rewrite(
            &original,
            ("demo-pass-2", Some(&key)),
            &path,
            "demo-pass-2",
            |v| {
                v.meta.master_key_changed = at(4_070_908_800);
            },
        );
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::NewKey);
        assert_eq!(
            s.resolve_disk_with_key(v, DiskChoice::Merge, Some("demo-pass-2".into()), None)
                .unwrap(),
            DiskEvent::OldKey
        );
    }

    /// The T70 setting: P with F1 on disk (the original bytes), then on
    /// this Mac the KDF raised to 2 MiB, "Demo Shop" added and "Google"
    /// deleted for good, saved as F2. Returns F1's bytes.
    fn f2(tag: &str) -> (TempDir, PathBuf, Arc<Session>, u64, Vec<u8>) {
        let (dir, path) = folder(tag);
        let first = std::fs::read(&path).unwrap();
        let (s, v) = window(&path, "demo-pass-7");
        setting(
            &s,
            "save.after_every_change",
            LarsalSettingValue::Flag { on: false },
        );
        set_memory(&s, v, 2);
        add(&s, v, "Demo Shop");
        delete(&s, v, "Google");
        saved(&s.save(v).unwrap());
        (dir, path, s, v, first)
    }

    /// The KDF set to Argon2id with `memory_mib` in Vault Settings.
    fn set_memory(s: &Arc<Session>, v: u64, memory_mib: u64) {
        let vs = crate::vault_settings::VaultSettings::new(Arc::clone(s), v);
        let choice = crate::wizard::EncryptionChoice {
            cipher: crate::wizard::CipherChoice::Aes256,
            kdf: crate::wizard::KdfChoice::Argon2id,
            memory_mib,
            lanes: 1,
            unlock_ms: 100,
        };
        assert!(vs.measure(choice).unwrap());
        assert_eq!(
            vs.set_kdf(choice, vec![crate::wizard::Answer::SafeMinimum])
                .unwrap(),
            crate::wizard::Outcome::Done
        );
    }

    /// APP-05.26 (MOD-12.12): the user's own lower KDF in Vault Settings
    /// sets the stored settings, so a later version from another Mac with
    /// those settings is not weaker.
    #[test]
    fn app05_26_the_users_own_kdf_change_is_not_weaker() {
        let (_dir, path, s, v, _) = f2("own-kdf");
        set_memory(&s, v, 1);
        saved(&s.save(v).unwrap());
        let (o, ov) = window(&path, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&o, ov, "Demo New");
        saved(&o.save(ov).unwrap());
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Reloaded);
    }

    fn memory_kib(s: &Session, v: u64) -> u64 {
        s.with_vault(v, |v| {
            Ok(match v.encryption.kdf {
                larsal_model::Kdf::Argon2 { memory_kib, .. } => memory_kib,
                larsal_model::Kdf::AesKdf { .. } => 0,
            })
        })
        .unwrap()
    }

    /// APP-05.26 T70 (LD-267 (3)): F1's bytes put back with no unsaved
    /// changes and auto reload on: no silent reload; `Rollback`, and the
    /// merged vault keeps "Demo Shop", the deletion and the 2 MiB KDF. The
    /// window saves it at once; the file then opens to the same content.
    #[test]
    fn app05_26_t70_an_older_file_is_merged_never_reloaded() {
        let (_dir, path, s, v, first) = f2("t70");
        std::fs::write(&path, &first).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Rollback);
        assert!(has(&s, v, "Demo Shop") && !has(&s, v, "Google"));
        assert_eq!(memory_kib(&s, v), 2048);
        saved(&s.save(v).unwrap());
        let (f, fv) = window(&path, "demo-pass-7");
        assert!(has(&f, fv, "Demo Shop") && !has(&f, fv, "Google"));
        assert_eq!(memory_kib(&f, fv), 2048);
    }

    /// APP-05.26 T71 (LD-269 (4)): at unlock the guard only warns. F1 put
    /// back opens as it is with `MSG-DISK-ROLLBACK-UNLOCK`; a newer copy
    /// whose KDF another Mac lowered opens with `MSG-DISK-WEAKER` naming
    /// the setting, never a value.
    #[test]
    fn app05_26_t71_the_unlock_only_warns() {
        let (_dir, path, s, v, first) = f2("t71");
        let f2_bytes = std::fs::read(&path).unwrap();
        s.lock(v).unwrap();
        std::fs::write(&path, &first).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert!(has(&s, v, "Google") && !has(&s, v, "Demo Shop"), "as it is");
        assert_eq!(
            s.after_unlock(v, 0).unwrap().disk_notice.as_deref(),
            Some(
                "\"Personal.larsalvault\" is older than a version Larsal has seen on this Mac, so newer changes may be missing. If you have a newer copy, open that one. \"Personal.larsalvault\" is saved with weaker settings than Larsal has seen for this vault: key derivation. Check them in Vault Settings."
            ),
            "F1 is older, and its KDF is the 1 MiB one"
        );
        s.lock(v).unwrap();
        std::fs::write(&path, &f2_bytes).unwrap();
        let (o, ov) = window(&path, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&o, ov, "Demo New");
        saved(&o.save(ov).unwrap());
        rewrite(
            &path.clone(),
            ("demo-pass-7", None),
            &path,
            "demo-pass-7",
            |v| {
                v.encryption.kdf = larsal_model::Kdf::Argon2 {
                    kind: larsal_model::Argon2Kind::Id,
                    iterations: 2,
                    memory_kib: 1024,
                    lanes: 1,
                };
            },
        );
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert!(has(&s, v, "Demo New"));
        assert_eq!(
            s.after_unlock(v, 0).unwrap().disk_notice.as_deref(),
            Some(
                "\"Personal.larsalvault\" is saved with weaker settings than Larsal has seen for this vault: key derivation. Check them in Vault Settings."
            )
        );
    }

    /// APP-05.27, APP-05.28 T76 (LD-267 (3)): as T70 with an unsaved "Demo
    /// Note": the question shows the "went back in time" line. Discard
    /// loads F1; Merge keeps both sides and the 2 MiB KDF and stays
    /// changed (no save); a save asks with the same line, and Merge then
    /// save writes the merge.
    #[test]
    fn app05_27_t76_an_older_version_with_unsaved_changes_asks_with_the_line() {
        for run in 0..3 {
            let (_dir, path, s, v, first) = f2(&format!("t76-{run}"));
            add(&s, v, "Demo Note");
            std::fs::write(&path, &first).unwrap();
            if run == 2 {
                let st = s.save(v).unwrap();
                assert_eq!((st.on_disk, st.older), (Some(DiskAsk::OnSave), true));
                assert_eq!(
                    s.resolve_disk(v, DiskChoice::Merge).unwrap(),
                    DiskEvent::Reloaded
                );
                saved(&s.save(v).unwrap());
                let (f, fv) = window(&path, "demo-pass-7");
                assert!(has(&f, fv, "Demo Shop") && has(&f, fv, "Demo Note"));
                assert!(!has(&f, fv, "Google"));
                continue;
            }
            assert_eq!(
                s.check_disk(v).unwrap(),
                DiskEvent::AskOlder {
                    ask: DiskAsk::Unsaved,
                    changes: 1
                }
            );
            if run == 0 {
                s.resolve_disk(v, DiskChoice::Reload).unwrap();
                assert!(has(&s, v, "Google") && !has(&s, v, "Demo Shop"), "F1");
            } else {
                assert_eq!(
                    s.resolve_disk(v, DiskChoice::Merge).unwrap(),
                    DiskEvent::Reloaded
                );
                assert!(has(&s, v, "Demo Shop") && has(&s, v, "Demo Note"));
                assert!(!has(&s, v, "Google"));
                assert_eq!(memory_kib(&s, v), 2048);
                assert!(s.save_status(v).unwrap().changes > 0, "not saved");
            }
        }
    }

    /// APP-05.29 (F-179): F1 put back under another password, with an
    /// unsaved change. A Discard chosen before the compare is asked once
    /// more, with the first question's kind (the unsaved question, or the
    /// save's); the second Discard loads F1.
    #[test]
    fn app05_29_c1_p1_a_discard_is_asked_once_more_never_twice() {
        for on_save in [false, true] {
            let (dir, path, s, v, first) = f2(&format!("c1-p1-{on_save}"));
            add(&s, v, "Demo Note");
            let f1 = dir.join("f1.larsalvault");
            std::fs::write(&f1, &first).unwrap();
            rewrite(&f1, ("demo-pass-7", None), &path, NEW, |_| {});
            let ask = if on_save {
                let st = s.save(v).unwrap();
                assert_eq!((st.on_disk, st.older), (Some(DiskAsk::OnSave), false));
                DiskAsk::OnSave
            } else {
                assert_eq!(
                    s.check_disk(v).unwrap(),
                    DiskEvent::Ask {
                        ask: DiskAsk::Unsaved,
                        changes: 1
                    }
                );
                DiskAsk::Unsaved
            };
            let discard = || {
                assert_eq!(
                    s.resolve_disk(v, DiskChoice::Reload).unwrap(),
                    DiskEvent::NewKey
                );
                s.resolve_disk_with_key(v, DiskChoice::Reload, Some(NEW.into()), None)
                    .unwrap()
            };
            assert_eq!(discard(), DiskEvent::AskOlder { ask, changes: 1 });
            assert!(has(&s, v, "Demo Note"), "nothing loaded yet");
            let second = discard();
            assert!(!matches!(second, DiskEvent::AskOlder { .. }), "{second:?}");
            assert!(has(&s, v, "Google") && !has(&s, v, "Demo Shop"), "F1");
            assert!(!has(&s, v, "Demo Note"));
        }
    }

    /// APP-05.17 step 6 (F-180): a copy with another root group id that
    /// opens with the current key is skipped, then not listed or opened
    /// again until it changes.
    #[test]
    fn app05_17_c1_p2_another_root_id_is_not_opened_again_until_it_changes() {
        let (_dir, path) = folder("c1-p2");
        let work = Path::new(&format!("{DEMO}option-a-work.larsalvault")).to_path_buf();
        let stranger = path.with_file_name("Personal 2.larsalvault");
        rewrite(
            &work,
            ("demo-pass-8", None),
            &stranger,
            "demo-pass-7",
            |_| {},
        );
        let (s, v) = window(&path, "demo-pass-7");
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(names(&found), ["Personal 2.larsalvault"]);
        assert_eq!(
            s.merge_copy(v, found[0].clone(), None, None, false)
                .unwrap(),
            CopyState::Skipped
        );
        assert!(s.conflict_copies(v).unwrap().is_empty(), "unchanged");
        rewrite(
            &work,
            ("demo-pass-8", None),
            &stranger,
            "demo-pass-7",
            |_| {},
        );
        assert_eq!(
            names(&s.conflict_copies(v).unwrap()),
            ["Personal 2.larsalvault"]
        );
    }

    /// APP-05.24 coordinated access (F-181): `copies_done` reads no file;
    /// a kept copy takes the checksum its coordinated read gave, so a copy
    /// that changed after that read is listed again, and one that did not
    /// is not.
    #[test]
    fn app05_24_f181_copies_done_keeps_the_checksum_of_the_coordinated_read() {
        let (dir, path) = folder("f181");
        let original = dir.join("original.larsalvault");
        std::fs::copy(&path, &original).unwrap();
        let copy = path.with_file_name("Personal (copy).larsalvault");
        rewrite(&original, ("demo-pass-7", None), &copy, NEW, |_| {});
        let (s, v) = window(&path, "demo-pass-7");
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(names(&found), ["Personal (copy).larsalvault"]);
        assert_eq!(
            s.merge_copy(v, found[0].clone(), None, None, false)
                .unwrap(),
            CopyState::NeedsPassword
        );
        rewrite(&original, ("demo-pass-7", None), &copy, NEW, |_| {});
        s.copies_done(v, found.clone()).unwrap();
        assert_eq!(
            found,
            s.conflict_copies(v).unwrap(),
            "changed after its read"
        );
        assert_eq!(
            s.merge_copy(v, found[0].clone(), None, None, false)
                .unwrap(),
            CopyState::NeedsPassword
        );
        s.copies_done(v, found).unwrap();
        assert!(s.conflict_copies(v).unwrap().is_empty(), "kept, unchanged");
    }

    /// APP-05.26 T70 with `save.reload_on_change` off (F-184): an older
    /// file is still merged, never asked about as a plain reload.
    #[test]
    fn app05_26_c1_t70_with_auto_reload_off_an_older_file_is_still_merged() {
        let (_dir, path, s, v, first) = f2("c1-t70");
        setting(
            &s,
            "save.reload_on_change",
            LarsalSettingValue::Flag { on: false },
        );
        std::fs::write(&path, &first).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Rollback);
        assert!(has(&s, v, "Demo Shop") && !has(&s, v, "Google"));
    }

    /// LD-271 (6), APP-05.26 (F-200): auto reload off, no unsaved change,
    /// F1 put back under another password. Load asks for it; with it the
    /// older version is merged, never loaded (`Rollback`; the window saves
    /// at once), never asked about as unsaved changes.
    #[test]
    fn ld271_6_reload_off_an_older_copy_under_another_password_is_merged() {
        let (dir, path, s, v, first) = f2("c1r2-p1");
        setting(
            &s,
            "save.reload_on_change",
            LarsalSettingValue::Flag { on: false },
        );
        let f1 = dir.join("f1.larsalvault");
        std::fs::write(&f1, &first).unwrap();
        rewrite(&f1, ("demo-pass-7", None), &path, NEW, |_| {});
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Reload,
                changes: 0
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Reload).unwrap(),
            DiskEvent::NewKey
        );
        assert_eq!(
            s.resolve_disk_with_key(v, DiskChoice::Reload, Some(NEW.into()), None)
                .unwrap(),
            DiskEvent::Rollback
        );
        assert!(has(&s, v, "Demo Shop") && !has(&s, v, "Google"));
        assert_eq!(memory_kib(&s, v), 2048);
    }

    /// APP-05.26 T70 under another password (F-200): auto reload on, the
    /// silent reload asks for it and goes on as Merge (APP-05.29): the
    /// older version is merged, never loaded (`Rollback`).
    #[test]
    fn app05_26_reload_on_an_older_copy_under_another_password_gives_rollback() {
        let (dir, path, s, v, first) = f2("c1r2-p2");
        let f1 = dir.join("f1.larsalvault");
        std::fs::write(&f1, &first).unwrap();
        rewrite(&f1, ("demo-pass-7", None), &path, NEW, |_| {});
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::NewKey);
        assert_eq!(
            s.resolve_disk_with_key(v, DiskChoice::Merge, Some(NEW.into()), None)
                .unwrap(),
            DiskEvent::Rollback
        );
        assert!(has(&s, v, "Demo Shop") && !has(&s, v, "Google"));
        assert_eq!(memory_kib(&s, v), 2048);
    }

    /// APP-05.17 step 5, MOD-11.31 T75 (F-202): Merge anyway on a sibling
    /// copy under the replaced password takes its entries only: never its
    /// deletions, its metadata (name, key-change time) or its key.
    #[test]
    fn mod11_31_merge_anyway_of_a_copy_takes_no_deletion_metadata_or_key() {
        let (_dir, path) = folder("c1r2-p3");
        let (s, v) = window(&path, "demo-pass-7");
        let old = path.with_file_name("Personal (old).larsalvault");
        std::fs::copy(&path, &old).unwrap();
        change_password(&s, v);
        saved(&s.save(v).unwrap());
        let meta = |s: &Session| {
            s.with_vault(v, |v| Ok((v.meta.master_key_changed, v.meta.name.clone())))
                .unwrap()
        };
        let mine = meta(&s);
        let (o, ov) = window(&old, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&o, ov, "Demo Old");
        delete(&o, ov, "Google");
        saved(&o.save(ov).unwrap());
        rewrite(
            &old.clone(),
            ("demo-pass-7", None),
            &old,
            "demo-pass-7",
            |v| {
                v.meta.master_key_changed = at(4_070_908_800);
                v.meta.name = "Planted".into();
                v.meta.name_changed = at(4_070_908_800);
            },
        );
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(names(&found), ["Personal (old).larsalvault"]);
        let copy = found[0].clone();
        assert_eq!(
            s.merge_copy(v, copy.clone(), Some("demo-pass-7".into()), None, false)
                .unwrap(),
            CopyState::OldKey
        );
        assert_eq!(
            s.merge_copy(v, copy, None, None, true).unwrap(),
            CopyState::Merged
        );
        assert!(has(&s, v, "Demo Old"), "its entries");
        assert!(has(&s, v, "Google"), "never its deletions");
        assert_eq!(meta(&s), mine, "never its metadata");
        saved(&s.save(v).unwrap());
        assert!(
            opens(&path, NEW) && !opens(&path, "demo-pass-7"),
            "never its key"
        );
    }

    /// APP-05.26 (F-212): auto reload off, the question shows for a newer
    /// version; F1's bytes are put back before Load. The older file is
    /// merged and saved at once, never loaded as it is.
    #[test]
    fn c1r3_p1_load_after_the_file_went_older_merges() {
        let (_dir, path, s, v, first) = f2("c1r3-p1");
        setting(
            &s,
            "save.reload_on_change",
            LarsalSettingValue::Flag { on: false },
        );
        let (o, ov) = window(&path, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&o, ov, "Demo New");
        saved(&o.save(ov).unwrap());
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Reload,
                changes: 0
            }
        );
        std::fs::write(&path, &first).unwrap();
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Reload).unwrap(),
            DiskEvent::Rollback
        );
        assert!(has(&s, v, "Demo Shop") && !has(&s, v, "Google"));
        assert_eq!(memory_kib(&s, v), 2048);
    }

    /// APP-05.17 step 6 (F-212): a copy taken by Merge anyway and closed
    /// with Keep is not listed again in this session until it changes.
    #[test]
    fn c1r3_p2_a_copy_merged_anyway_is_not_listed_again() {
        let (_dir, path) = folder("c1r3-p2");
        let (s, v) = window(&path, "demo-pass-7");
        let old = path.with_file_name("Personal (old).larsalvault");
        std::fs::copy(&path, &old).unwrap();
        change_password(&s, v);
        saved(&s.save(v).unwrap());
        let (o, ov) = window(&old, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        add(&o, ov, "Demo Old");
        saved(&o.save(ov).unwrap());
        let copy = s.conflict_copies(v).unwrap()[0].clone();
        assert_eq!(
            s.merge_copy(v, copy.clone(), Some("demo-pass-7".into()), None, false)
                .unwrap(),
            CopyState::OldKey
        );
        assert_eq!(
            s.merge_copy(v, copy.clone(), None, None, true).unwrap(),
            CopyState::Merged
        );
        saved(&s.save(v).unwrap());
        s.copies_done(v, vec![copy]).unwrap();
        assert!(s.conflict_copies(v).unwrap().is_empty());
    }
    /// APP-05.26, LD-267 (3) (F-218): a version 3 file stores no
    /// SettingsChanged, so the reader's filled-in open time never makes it
    /// newer. The original version 3 bytes put back after a version 4 save
    /// with "Demo Shop" and a 2 MiB KDF are older: merged, never loaded,
    /// and the merge keeps "Demo Shop" and the 2 MiB KDF; the saved file
    /// opens to the same.
    #[test]
    fn c2_p1_a_version_3_file_put_back_is_older() {
        let dir = TempDir::new("copies-c2-p1");
        let path = dir.join("Rich.larsalvault");
        std::fs::copy(format!("{DEMO}rich-v3.larsalvault"), &path).unwrap();
        let first = std::fs::read(&path).unwrap();
        let (s, v) = window(&path, "demo-pass-4");
        setting(
            &s,
            "save.after_every_change",
            LarsalSettingValue::Flag { on: false },
        );
        s.confirm_format_notice(v).unwrap();
        set_memory(&s, v, 2);
        add(&s, v, "Demo Shop");
        saved(&s.save(v).unwrap());
        std::fs::write(&path, &first).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Rollback);
        assert!(has(&s, v, "Demo Shop"));
        assert_eq!(memory_kib(&s, v), 2048);
        saved(&s.save(v).unwrap());
        let (f, fv) = window(&path, "demo-pass-4");
        assert!(has(&f, fv, "Demo Shop"));
        assert_eq!(memory_kib(&f, fv), 2048);
    }

    /// APP-05.17, LD-319 (4) (F-227): a copy is read and opened (its KDF)
    /// with the save lock free, so a save never waits for it; the merge
    /// still lands, under the lock.
    #[test]
    fn f227_a_copy_opens_outside_the_save_lock() {
        let (_dir, path) = folder("f227");
        let copy = copy_with(
            &path,
            "Personal (Demo's conflicted copy).larsalvault",
            "Demo Copy",
        );
        let (s, v) = window(&path, "demo-pass-7");
        OPENED_LOCKED.with(|c| c.set(None));
        let state = s.merge_copy(v, copy.to_string_lossy().into_owned(), None, None, false);
        assert_eq!(state.unwrap(), CopyState::Merged);
        assert_eq!(OPENED_LOCKED.with(std::cell::Cell::get), Some(false));
        assert!(has(&s, v, "Demo Copy"));
    }

    /// LD-319 (4) (F-227): the vault's key changes while the copy opens
    /// with the old one, the save lock free: nothing is merged.
    #[test]
    fn f227_a_key_change_while_the_copy_opens_merges_nothing() {
        let (_dir, path) = folder("f227k");
        let copy = copy_with(
            &path,
            "Personal (Demo's conflicted copy).larsalvault",
            "Demo Copy",
        );
        let (s, v) = window(&path, "demo-pass-7");
        let saver = s.with_edit_state(v, |e| e.saver.clone()).unwrap();
        MEANWHILE.with(|m| {
            *m.borrow_mut() = Some(Box::new(move || {
                saver.lock().unwrap().password = Some(SecretString::new("another".to_owned()));
            }));
        });
        let state = s.merge_copy(v, copy.to_string_lossy().into_owned(), None, None, false);
        assert_eq!(state.unwrap(), CopyState::Skipped);
        assert!(!has(&s, v, "Demo Copy"));
    }

    /// APP-05.26, LD-319 (4) (F-226, Checker 2's probe): after a version 3
    /// file is saved as version 4 with its history set to 3 items and
    /// "Demo Shop" added, the open vault carries the written version, and
    /// the original version 3 bytes put back are merged (`Rollback`) with
    /// this Mac's settings kept: the history stays at 3, not the old 10.
    #[test]
    fn f226_a_version_3_file_put_back_keeps_this_macs_settings() {
        let dir = TempDir::new("copies-f226");
        let path = dir.join("Rich.larsalvault");
        std::fs::copy(format!("{DEMO}rich-v3.larsalvault"), &path).unwrap();
        let first = std::fs::read(&path).unwrap();
        let (s, v) = window(&path, "demo-pass-4");
        setting(
            &s,
            "save.after_every_change",
            LarsalSettingValue::Flag { on: false },
        );
        let history = |s: &Session| s.with_vault(v, |v| Ok(v.meta.history_max_items)).unwrap();
        assert_eq!(history(&s), 10);
        s.confirm_format_notice(v).unwrap();
        let vs = crate::vault_settings::VaultSettings::new(Arc::clone(&s), v);
        let change = crate::vault_settings::SettingsChange {
            history_items: Some(3),
            ..Default::default()
        };
        assert_eq!(vs.apply(change).unwrap(), crate::wizard::Outcome::Done);
        add(&s, v, "Demo Shop");
        saved(&s.save(v).unwrap());
        let version = s.with_vault(v, |v| Ok(v.read_version)).unwrap();
        assert!(version.is_some_and(|r| r.major >= 4), "{version:?}");
        std::fs::write(&path, &first).unwrap();
        assert_eq!(s.check_disk(v).unwrap(), DiskEvent::Rollback);
        assert!(has(&s, v, "Demo Shop"));
        assert_eq!(history(&s), 3);
        saved(&s.save(v).unwrap());
        let (f, fv) = window(&path, "demo-pass-4");
        let reopened = f.with_vault(fv, |x| Ok(x.meta.history_max_items));
        assert_eq!(reopened.unwrap(), 3);
    }

    /// CRY-02.14, AT-A05, APP-05.17 step 1 (F-219): a planted sibling
    /// whose KDF cost is in the ask band (129 lanes) is never opened with
    /// no question: the finder skips it.
    #[test]
    fn c2_p2_a_planted_copy_in_the_ask_band_is_not_opened() {
        let (_dir, path) = folder("c2-p2");
        let (s, v) = window(&path, "demo-pass-7");
        let planted = path.with_file_name("Personal (planted).larsalvault");
        rewrite(&path, ("demo-pass-7", None), &planted, "demo-pass-7", |v| {
            v.encryption.kdf = larsal_model::Kdf::Argon2 {
                kind: larsal_model::Argon2Kind::Id,
                iterations: 2,
                memory_kib: 2048,
                lanes: 129,
            };
        });
        let mut host = s.host.lock().unwrap();
        let password = SecretString::new("demo-pass-7".to_owned());
        let credentials = Credentials {
            password: Some(&password),
            key_file: None,
            hardware_key: None,
        };
        assert!(matches!(
            larsal_format::open(
                &std::fs::read(&planted).unwrap(),
                &credentials,
                &mut host,
                &Limits::DEFAULT,
                None
            ),
            Ok(larsal_format::Opened::Ask(_))
        ));
        drop(host);
        let found = s.conflict_copies(v).unwrap();
        assert_eq!(names(&found), ["Personal (planted).larsalvault"]);
        assert_eq!(
            s.merge_copy(v, found[0].clone(), None, None, false)
                .unwrap(),
            CopyState::Skipped
        );
    }

    /// LD-269 (4), APP-05.26 `MSG-DISK-WEAKER` (F-220): MOD-11.19 limit 1
    /// guards the target, here the disk version, so a merge can take its
    /// weaker settings: another Mac lowers the KDF to 1 MiB, this Mac has
    /// an unsaved entry and answers Merge: the warning names the setting.
    #[test]
    fn c2_p4_a_merge_that_takes_weaker_settings_warns() {
        let (_dir, path, s, v, _) = f2("c2-p4");
        let (o, ov) = window(&path, "demo-pass-7");
        setting(&o, "backup.enabled", LarsalSettingValue::Flag { on: false });
        set_memory(&o, ov, 1);
        saved(&o.save(ov).unwrap());
        add(&s, v, "Demo Note");
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                changes: 1
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Weaker {
                settings: "key derivation".to_owned()
            }
        );
        assert_eq!(memory_kib(&s, v), 1024);
        assert!(has(&s, v, "Demo Note") && has(&s, v, "Demo Shop"));
    }
    /// LD-269 (4) (F-220): the weaker list after a merge is the merged
    /// vault's: a newer version with a weaker KDF but an older settings
    /// time merges to this Mac's 2 MiB, with no warning.
    #[test]
    fn c2_p4_a_merge_that_keeps_the_stronger_settings_does_not_warn() {
        let (_dir, path, s, v, _) = f2("c2-p4b");
        rewrite(
            &path.clone(),
            ("demo-pass-7", None),
            &path,
            "demo-pass-7",
            |v| {
                v.encryption.kdf = larsal_model::Kdf::Argon2 {
                    kind: larsal_model::Argon2Kind::Id,
                    iterations: 2,
                    memory_kib: 1024,
                    lanes: 1,
                };
                v.meta.settings_changed = at(1_700_000_000);
            },
        );
        add(&s, v, "Demo Note");
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                changes: 1
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        assert_eq!(memory_kib(&s, v), 2048);
    }

    /// F-224: the folder of `path` spelled another way: through a link in
    /// it that points at it (as `~/Dropbox` can), or in capitals (this
    /// Mac's disk ignores case).
    fn other_spelling(path: &Path, through_link: bool) -> PathBuf {
        let dir = path.parent().unwrap();
        if through_link {
            let link = dir.join("link");
            std::os::unix::fs::symlink(dir, &link).unwrap();
            link
        } else {
            dir.with_file_name(dir.file_name().unwrap().to_string_lossy().to_uppercase())
        }
    }

    /// APP-05.17 step 4 (LD-319 (1)): Larsal's backup is never listed,
    /// however the backup pattern spells the vault's folder.
    fn a_backup_spelled_another_way_is_not_listed(tag: &str, through_link: bool) {
        let (_dir, path) = folder(tag);
        let (s, v) = window(&path, "demo-pass-7");
        let other = other_spelling(&path, through_link);
        setting(
            &s,
            "backup.pattern",
            LarsalSettingValue::Text {
                text: format!("{}/{{FILE_NAME}} backup.larsalvault", other.display()),
            },
        );
        add(&s, v, "Demo Shop");
        saved(&s.save(v).unwrap());
        assert!(path.with_file_name("Personal backup.larsalvault").is_file());
        assert!(s.conflict_copies(v).unwrap().is_empty());
    }

    #[test]
    fn c2r2_p1_a_backup_named_through_a_link_to_the_folder_is_not_listed() {
        a_backup_spelled_another_way_is_not_listed("c2r2-p1", true);
    }

    #[test]
    fn c2r2_p1c_a_backup_named_in_another_case_is_not_listed() {
        a_backup_spelled_another_way_is_not_listed("c2r2-p1c", false);
    }

    /// APP-05.33 SG43 (LD-319 (1)): the key-change save never lists the
    /// vault file as an old copy, however the backup pattern spells its
    /// folder, so Delete checked never removes it.
    fn the_vault_is_never_an_old_copy(tag: &str, through_link: bool) {
        let (_dir, path) = folder(tag);
        let (s, v) = window(&path, "demo-pass-7");
        let other = other_spelling(&path, through_link);
        setting(
            &s,
            "backup.pattern",
            LarsalSettingValue::Text {
                text: format!(
                    "{}/{{FILE_NAME}}{{TIME:HHmmss}}.larsalvault",
                    other.display()
                ),
            },
        );
        change_password(&s, v);
        let st = s.save(v).unwrap();
        saved(&st);
        let listed = st.old_copies.unwrap();
        assert_eq!(listed.len(), 1, "the backup alone: {listed:?}");
        assert_ne!(
            storage::file_id(Path::new(&listed[0])),
            storage::file_id(&path)
        );
        assert!(s.delete_old_copies(v, listed.clone()).unwrap().is_empty());
        assert!(!Path::new(&listed[0]).exists());
        assert!(path.is_file() && opens(&path, NEW));
    }

    #[test]
    fn c2r2_p1b_the_vault_itself_is_never_an_old_copy() {
        the_vault_is_never_an_old_copy("c2r2-p1b", true);
    }

    #[test]
    fn c2r2_p1d_the_vault_itself_is_never_an_old_copy_in_another_case() {
        the_vault_is_never_an_old_copy("c2r2-p1d", false);
    }

    /// MOD-11.31, LD-319 (2) (F-225): a state file that exists but cannot
    /// be read is never written over: that run keeps its state in memory
    /// only, and the next start still finds the retired-key record.
    #[test]
    fn c2r2_p2_an_unreadable_state_file_keeps_its_records() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = folder("c2r2-p2");
        let settings = dir.join("settings");
        let start = || {
            let s = Session::new();
            s.settings.use_folder(settings.display().to_string());
            s
        };
        let unlock = |s: &Session, password: &str| {
            let v = s.open(path.to_string_lossy().into_owned()).unwrap();
            s.unlock(v, Some(password.into()), None).unwrap();
            v
        };
        let s = start();
        let v = unlock(&s, "demo-pass-7");
        let root = s.with_open(v, |vault, _, _| Ok(vault.root.uuid)).unwrap();
        change_password(&s, v);
        saved(&s.save(v).unwrap());
        assert_eq!(start().retired_records(root).len(), 1);
        let suffix = if cfg!(debug_assertions) { "_debug" } else { "" };
        let state = settings.join(format!("vault-state{suffix}.json"));
        let bytes = std::fs::read(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o000)).unwrap();
        let again = start();
        unlock(&again, NEW);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&state).unwrap(), bytes, "never written over");
        assert_eq!(start().retired_records(root).len(), 1);
    }

    /// MOD-11.31, LD-320 (1) (F-236): a state file that is a JSON object
    /// but holds one retired-key record that does not read is never written
    /// over, so the record is not lost when one byte goes bad.
    #[test]
    fn c2r3_p1_a_state_file_with_one_bad_record_keeps_it() {
        use larsal_model::json::{self, Value};
        let (dir, path) = folder("c2r3-p1");
        let settings = dir.join("settings");
        let start = || {
            let s = Session::new();
            s.settings.use_folder(settings.display().to_string());
            s
        };
        let s = start();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let root = s.with_open(v, |vault, _, _| Ok(vault.root.uuid)).unwrap();
        change_password(&s, v);
        saved(&s.save(v).unwrap());
        assert_eq!(start().retired_records(root).len(), 1);
        let suffix = if cfg!(debug_assertions) { "_debug" } else { "" };
        let state = settings.join(format!("vault-state{suffix}.json"));
        let mut file = json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        let Value::Object(vaults) = &mut file else {
            panic!("the state file is an object");
        };
        let retired = vaults.values_mut().next().unwrap().get_mut("retired");
        let records = retired.and_then(Value::as_array_mut).unwrap();
        let Some(Value::Object(kdf)) = records[0].get_mut("kdf") else {
            panic!("the record names its KDF");
        };
        let key = if kdf.contains_key("salt") {
            "salt"
        } else {
            "seed"
        };
        let broken = format!("z{}", &kdf[key].as_str().unwrap()[1..]);
        kdf.insert(key.into(), broken.into());
        let bad = json::to_string(&file);
        std::fs::write(&state, &bad).unwrap();
        let again = start();
        let v = again.open(path.to_string_lossy().into_owned()).unwrap();
        again.unlock(v, Some(NEW.into()), None).unwrap();
        let after = std::fs::read_to_string(&state).unwrap();
        assert_eq!(after, bad, "never written over");
    }

    /// MOD-11.31, LD-324 (3) (F-241, Checker 2's probe c2r4_p1): one bad
    /// byte in a key name, `"retired":` made `"retirfd":`, makes the state
    /// file bad: the next start keeps it in memory only, its unlock never
    /// writes it over, and with the byte put back the record is there.
    #[test]
    fn c2r4_p1_a_bad_key_name_in_the_state_file_keeps_its_records() {
        let (dir, path) = folder("c2r4-p1");
        let settings = dir.join("settings");
        let start = || {
            let s = Session::new();
            s.settings.use_folder(settings.display().to_string());
            s
        };
        let s = start();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let root = s.with_open(v, |vault, _, _| Ok(vault.root.uuid)).unwrap();
        change_password(&s, v);
        saved(&s.save(v).unwrap());
        assert_eq!(start().retired_records(root).len(), 1);
        let suffix = if cfg!(debug_assertions) { "_debug" } else { "" };
        let state = settings.join(format!("vault-state{suffix}.json"));
        let good = std::fs::read_to_string(&state).unwrap();
        let bad = good.replacen("\"retired\":", "\"retirfd\":", 1);
        assert_ne!(bad, good);
        std::fs::write(&state, &bad).unwrap();
        let again = start();
        assert!(again.retired_records(root).is_empty());
        let v = again.open(path.to_string_lossy().into_owned()).unwrap();
        again.unlock(v, Some(NEW.into()), None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&state).unwrap(),
            bad,
            "never written over"
        );
        std::fs::write(&state, &good).unwrap();
        assert_eq!(start().retired_records(root).len(), 1);
    }
}
