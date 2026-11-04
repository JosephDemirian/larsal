//! The vault settings window (E5-S8, MOD-12): General, Security, Recycle
//! Bin, History and Browser Keys of one unlocked vault.
//!
//! Guarantees:
//! - every change goes through app-core's `settings::apply` with all its
//!   checks and confirmations first, so a refusal changes nothing (D-12-1);
//!   a control left untouched keeps its stored value (D-12-2);
//! - a change counts one unsaved change; the next save writes it. A new
//!   cipher, KDF or key is used by that save, which derives the key again
//!   with a fresh salt (MOD-12.14, CRY-03); a key change replaces the key
//!   parts the save uses (MOD-12.10 step 8);
//! - the passwords typed on the Security page stay in Rust as the wizard's
//!   do (wizard.rs); no view holds a secret (AGENTS.md rule 4);
//! - the browser and history actions act at once and need the screen's
//!   confirmation first (MOD-12.18, MOD-03).

use crate::hwkey::{Choice, KeyPick};
use crate::session::{AppError, MAX_TEXT, Session, file_name, home_short};
use crate::views::{now, unix};
use crate::wizard::{
    self, Answer, CipherChoice, EncryptionChoice, KdfChoice, KeyFileOutcome, Outcome, Pair, Tuning,
    choice_of, cipher_of, confirms, outcome_of, refused,
};
use app_core::history::{self, Delete};
use app_core::recycle;
use app_core::settings::{self, Changes, EncryptionEdit, KeyChange, PasswordPart};
use app_crypto::kdf::CostReport;
use app_crypto::secret::SecretString;
use app_format::keyfile::KeyFileKey;
use app_format::limits::Limits;
use app_model::{Argon2Kind, Kdf, Uuid, Vault};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// One connected browser (MOD-12.18, INT-02): the association's name and
/// when it was made. The public key is not shown.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserKey {
    /// The name the user gave it.
    pub name: String,
    /// The `_CREATED_` time in unix seconds; `None` when missing or
    /// unreadable.
    pub created: Option<i64>,
}

/// What the five pages show. No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultSettingsView {
    /// `vault.name`.
    pub name: String,
    /// `vault.description`.
    pub description: String,
    /// `vault.default_username`.
    pub default_user_name: String,
    /// The public colour as `0xRRGGBB` (MOD-12.4); `None` when unset.
    pub colour: Option<u32>,
    /// The file path with the home folder as `~`.
    pub path: String,
    /// The full file path, for Show in Finder.
    pub full_path: String,
    /// The file version as read, for example `4.1`.
    pub version: String,
    /// The file's size in bytes.
    pub size: u64,
    /// The key has a password.
    pub has_password: bool,
    /// `MasterKeyChanged`, unix seconds.
    pub password_changed: i64,
    /// The key file's name; `None` without one.
    pub key_file: Option<String>,
    /// The hardware key's key and slot (F-126); `None` without one.
    pub security_key: Option<KeyPick>,
    /// The encryption page: cipher, KDF, memory, lanes and the unlock time
    /// (the unlock time item, else the estimate once measured, else 1,000).
    pub encryption: EncryptionChoice,
    /// Iterations (Argon2) or rounds (AES-KDF) stored now.
    pub iterations: u64,
    /// `vault.recycle_bin`.
    pub recycle_bin: bool,
    /// Entries and groups in the bin.
    pub bin_items: u32,
    /// `HistoryMaxItems`: −1 is no limit.
    pub history_items: i32,
    /// `HistoryMaxSize` in MiB rounded; −1 is no limit.
    pub history_mib: i32,
    /// Bytes held by every live entry's history items (MOD-03.7).
    pub history_bytes: u64,
    /// How many history items there are.
    pub history_versions: u32,
    /// The connected browsers, in stored order.
    pub browsers: Vec<BrowserKey>,
    /// Live entries holding stored site permissions.
    pub site_access: u32,
}

/// One change of the General, Recycle Bin or History page; `None` is a
/// control the user did not touch (D-12-2).
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct SettingsChange {
    /// `vault.name`.
    pub name: Option<String>,
    /// `vault.description`.
    pub description: Option<String>,
    /// `vault.default_username`.
    pub default_user_name: Option<String>,
    /// The public colour `#rrggbb`; an empty text clears it.
    pub colour: Option<String>,
    /// `vault.recycle_bin`.
    pub recycle_bin: Option<bool>,
    /// MOD-04.12's answer when a non-empty bin goes off: delete it.
    pub delete_old_bin: bool,
    /// `vault.history_items`: −1 no limit, else 0 to 100,000.
    pub history_items: Option<i32>,
    /// `vault.history_size` in MiB: −1 no limit, else 1 to 2,047.
    pub history_mib: Option<i32>,
}

/// The vault settings of one unlocked vault (MOD-12). Swift holds one while
/// the window shows; dropping it wipes the typed passwords.
#[derive(uniffi::Object)]
pub struct VaultSettings {
    session: Arc<Session>,
    vault: u64,
    tuning: Mutex<Tuning>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    pair: Pair,
    cost: Option<CostReport>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn kdf_choice(k: &Kdf) -> (KdfChoice, u64, u64, u64) {
    match *k {
        Kdf::AesKdf { rounds } => (KdfChoice::AesKdf, 64, 1, rounds),
        Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
        } => (
            if kind == Argon2Kind::D {
                KdfChoice::Argon2d
            } else {
                KdfChoice::Argon2id
            },
            memory_kib / 1024,
            lanes,
            iterations,
        ),
    }
}

/// History items and their bytes over every live entry (MOD-03.7).
fn history_use(v: &Vault) -> (u64, u32) {
    let (mut bytes, mut n) = (0u64, 0u32);
    for e in v.root.all_entries() {
        for h in &e.history {
            bytes = bytes.saturating_add(history::size(h));
            n = n.saturating_add(1);
        }
    }
    (bytes, n)
}

impl VaultSettings {
    /// Runs `changes` through app-core and counts the change.
    fn run(&self, changes: &Changes, edit: Option<&EncryptionEdit>) -> Result<Outcome, AppError> {
        let mut st = lock(&self.state);
        let outcome = self.session.with_edit(self.vault, |v, _, _, es| {
            let result = {
                let mut host = lock(&self.session.host);
                settings::apply(v, changes, &mut host, &Limits::DEFAULT.kdf, now())
            };
            match result {
                Ok(applied) => {
                    if applied.changed {
                        es.count_change();
                    }
                    Ok((
                        Outcome::Done,
                        changes
                            .encryption
                            .as_ref()
                            .map(|_| (v.root.uuid, v.encryption.kdf)),
                    ))
                }
                Err(r) => Ok((outcome_of(r, edit, &self.session, &mut st.cost), None)),
            }
        })?;
        let (outcome, encryption) = outcome;
        // APP-05.26 (MOD-12.12): the user's own encryption change sets the
        // rollback guard's stored KDF settings and file version.
        if let Some((root, kdf)) = encryption {
            self.session.settings_set(root, kdf);
        }
        if changes.public_color.is_some() {
            self.session.refresh_look(self.vault);
        }
        Ok(outcome)
    }

    /// MOD-12.10: a key change through app-core's checks, then the new key
    /// parts for the next save (step 8). `password`, `key_file` and
    /// `hardware`: `None` keeps the part, `Some(None)` removes it.
    fn change_key(
        &self,
        password: Option<PasswordPart>,
        key_file: Option<Option<(KeyFileKey, String)>>,
        hardware: Option<Option<Choice>>,
        answers: &[Answer],
    ) -> Result<Outcome, AppError> {
        let (saver, (had_password, had_key_file), pending, root) =
            self.session.with_edit(self.vault, |v, _, _, es| {
                Ok((
                    es.saver.clone(),
                    es.key_parts(),
                    es.disk.new_key,
                    v.root.uuid,
                ))
            })?;
        // One lock order (LD-199 (4)): the save lock before the session
        // lock, held from the key change to the new key parts, so no save
        // writes the one without the other.
        let saver = saver.ok_or(AppError::Locked)?;
        let mut sv = lock(&saver);
        // MOD-11.31: the record of the key this change retires, made now,
        // while the user waits (the KDF); none while an earlier change is
        // unsaved, whose key never reached the file.
        let retiring = if pending {
            None
        } else {
            Some(self.session.record_of(&sv)?)
        };
        let new_password = match &password {
            Some(PasswordPart::New { typed, .. }) => {
                Some(Some(SecretString::new(typed.expose().to_owned())))
            }
            Some(PasswordPart::Removed) => Some(None),
            _ => None,
        };
        let changes = Changes {
            key: Some(KeyChange {
                password: password.unwrap_or(PasswordPart::Untouched),
                had_password,
                key_file: key_file
                    .as_ref()
                    .map_or(had_key_file.is_some(), Option::is_some),
                // F-107: the kept hardware key stays a part of the new key.
                hardware: hardware.map_or(sv.hardware.is_some(), |h| h.is_some()),
                min_quality: wizard::min_quality(&self.session),
            }),
            confirmed: confirms(answers),
            ..Changes::default()
        };
        let outcome = self.run(&changes, None)?;
        drop(changes);
        if outcome == Outcome::Done {
            self.session.with_edit(self.vault, |_, _, _, es| {
                crate::saving::same(es, &saver)?;
                es.set_key(&mut sv, new_password, key_file);
                if let Some(hardware) = hardware {
                    es.set_hardware(&mut sv, hardware);
                }
                Ok(())
            })?;
            lock(&self.state).pair = Pair::default();
            drop(sv);
            if let Some(record) = retiring {
                self.session.retire(root, record);
            }
        }
        Ok(outcome)
    }

    fn vault_path(&self) -> Result<PathBuf, AppError> {
        self.session
            .with_open(self.vault, |_, path, _| Ok(path.to_path_buf()))
    }
}

#[uniffi::export]
impl VaultSettings {
    /// The settings of unlocked vault `vault` (MOD-12.21).
    #[uniffi::constructor]
    #[must_use]
    pub fn new(session: Arc<Session>, vault: u64) -> Arc<Self> {
        Arc::new(Self {
            session,
            vault,
            tuning: Mutex::default(),
            state: Mutex::default(),
        })
    }

    /// What the pages show.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn view(&self) -> Result<VaultSettingsView, AppError> {
        let tuning = &self.tuning;
        self.session.with_edit(self.vault, |v, path, _, es| {
            let (has_password, key_file) = es.key_parts();
            let m = &v.meta;
            let (kdf, memory_mib, lanes, iterations) = kdf_choice(&v.encryption.kdf);
            let mut encryption = EncryptionChoice {
                cipher: choice_of(v.encryption.cipher),
                kdf,
                memory_mib,
                lanes,
                unlock_ms: 1_000,
            };
            encryption.unlock_ms = settings::unlock_time_ms(v)
                .or_else(|| wizard::estimate_ms(tuning, &encryption, iterations))
                .unwrap_or(1_000)
                .clamp(100, 5_000);
            let bin_items = recycle::bin_id(v)
                .and_then(|id| v.root.find_group(id))
                .map_or(0, |g| g.entries.len().saturating_add(g.groups.len()));
            let (history_bytes, history_versions) = history_use(v);
            let history_mib = if m.history_max_size < 0 {
                -1
            } else {
                m.history_max_size.saturating_add(1 << 19) >> 20
            };
            let version = v
                .read_version
                .map_or_else(|| "4.0".to_owned(), |f| format!("{}.{}", f.major, f.minor));
            Ok(VaultSettingsView {
                name: m.name.clone(),
                description: m.description.clone(),
                default_user_name: m.default_user_name.clone(),
                colour: crate::session::public_look(
                    v.public_custom_data
                        .iter()
                        .map(|p| (p.kind, p.name.as_slice(), p.value.as_slice())),
                )
                .0,
                path: home_short(path),
                full_path: path.to_string_lossy().into_owned(),
                version,
                size: std::fs::metadata(path).map_or(0, |f| f.len()),
                has_password,
                password_changed: unix(m.master_key_changed),
                key_file,
                security_key: es.hardware().map(Choice::pick),
                encryption,
                iterations,
                recycle_bin: m.recycle_bin_enabled,
                bin_items: u32::try_from(bin_items).unwrap_or(u32::MAX),
                history_items: m.history_max_items,
                history_mib,
                history_bytes,
                history_versions,
                browsers: settings::associations(v)
                    .into_iter()
                    .map(|a| BrowserKey {
                        created: a.created.as_deref().and_then(crate::edit::iso_utc),
                        name: a.name,
                    })
                    .collect(),
                site_access: u32::try_from(settings::site_access_count(v)).unwrap_or(u32::MAX),
            })
        })
    }

    /// The General, Recycle Bin or History page changed (MOD-12.3 to
    /// MOD-12.6): applied at once when every check passes.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`.
    pub fn apply(&self, change: SettingsChange) -> Result<Outcome, AppError> {
        let long = |s: &Option<String>| s.as_ref().is_some_and(|t| t.len() > MAX_TEXT);
        if long(&change.name) || long(&change.description) || long(&change.default_user_name) {
            return Err(AppError::TooLong);
        }
        let changes = Changes {
            name: change.name,
            description: change.description,
            default_user_name: change.default_user_name,
            public_color: change.colour.map(|c| (!c.is_empty()).then_some(c)),
            recycle_bin: change.recycle_bin,
            delete_old_bin: change.delete_old_bin,
            history_items: change.history_items,
            history_mib: change.history_mib,
            ..Changes::default()
        };
        self.run(&changes, None)
    }

    /// APP-07.8 for the Security page: measures `choice`'s family, memory
    /// and lanes (call it off the screen thread).
    ///
    /// # Errors
    /// `Refused` with M07-35 or the KDF's refusal.
    pub fn measure(&self, choice: EncryptionChoice) -> Result<bool, AppError> {
        wizard::measure(&self.session, &self.tuning, &choice)
    }

    /// Drops the result of a running measurement.
    pub fn cancel_measure(&self) {
        wizard::cancel(&self.tuning);
    }

    /// M07-35 under the Memory row; `None` when it fits.
    #[must_use]
    pub fn memory_note(&self, memory_mib: u64) -> Option<String> {
        wizard::memory_note(&self.session, memory_mib)
    }

    /// `vault.cipher` (MOD-12.12): the KDF stays as stored. A vault whose
    /// stored KDF is below App's safe minimum or slow asks as the KDF
    /// change does (the time in the question is the page's).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn set_cipher(
        &self,
        cipher: CipherChoice,
        answers: Vec<Answer>,
    ) -> Result<Outcome, AppError> {
        let (kdf, item) = self.session.with_vault(self.vault, |v| {
            Ok((v.encryption.kdf, settings::unlock_time_ms(v)))
        })?;
        let edit = EncryptionEdit {
            cipher: cipher_of(cipher),
            kdf,
            unlock_time_ms: item,
        };
        let shown = EncryptionEdit {
            unlock_time_ms: Some(self.view()?.encryption.unlock_ms),
            ..edit
        };
        let approval = answers
            .contains(&Answer::Cost)
            .then(|| lock(&self.state).cost.clone())
            .flatten();
        self.run(
            &Changes {
                encryption: Some(edit),
                confirmed: confirms(&answers),
                cost_approval: approval,
                ..Changes::default()
            },
            Some(&shown),
        )
    }

    /// The key derivation, memory, lanes or unlock time changed
    /// (MOD-12.11, MOD-12.12): the iterations for the unlock time from the
    /// measurement, the time kept in the unlock time item; the warnings of
    /// APP-07.9 first. Measure first.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn set_kdf(
        &self,
        choice: EncryptionChoice,
        answers: Vec<Answer>,
    ) -> Result<Outcome, AppError> {
        if choice.kdf != KdfChoice::AesKdf
            && let Some(note) = self.memory_note(choice.memory_mib)
        {
            return Ok(refused("M07-35", &note));
        }
        let edit = match wizard::edit_for(&self.tuning, &choice) {
            Ok(edit) => edit,
            Err(outcome) => return Ok(outcome),
        };
        let approval = answers
            .contains(&Answer::Cost)
            .then(|| lock(&self.state).cost.clone())
            .flatten();
        self.run(
            &Changes {
                encryption: Some(edit),
                confirmed: confirms(&answers),
                cost_approval: approval,
                ..Changes::default()
            },
            Some(&edit),
        )
    }

    /// The Change… password sheet's Password field (APP-07.20): the meter.
    ///
    /// # Errors
    /// `TooLong`.
    pub fn set_password(&self, text: String) -> Result<Option<crate::views::Rating>, AppError> {
        lock(&self.state).pair.set_password(text)
    }

    /// Its Verify password field: the check mark or M07-20.
    ///
    /// # Errors
    /// `TooLong`.
    pub fn set_repeat(&self, text: String) -> Result<Option<bool>, AppError> {
        lock(&self.state).pair.set_repeat(text)
    }

    /// The repeat field's state after the Password field changed.
    #[must_use]
    pub fn repeat_matches(&self) -> Option<bool> {
        lock(&self.state).pair.match_state()
    }

    /// Show: the Password field's text (a crossing of LD-220 while the
    /// Change… sheet is open).
    #[must_use]
    pub fn password(&self) -> String {
        lock(&self.state).pair.shown(false)
    }

    /// Show: the Verify password field's text (LD-220, as `password`).
    #[must_use]
    pub fn repeat(&self) -> String {
        lock(&self.state).pair.shown(true)
    }

    /// The sheet closed without a change: the typed passwords are wiped.
    pub fn clear_password(&self) {
        lock(&self.state).pair = Pair::default();
    }

    /// The sheet's Change Password (MOD-12.10): the match first, then the
    /// no-password and weak warnings and "no part"; the new password is the
    /// key part the next save uses. An empty password removes the password
    /// part (M07-21).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn change_password(&self, answers: Vec<Answer>) -> Result<Outcome, AppError> {
        let part = {
            let st = lock(&self.state);
            if !st.pair.matches() {
                return Ok(refused("M07-20", "The two passwords are different."));
            }
            st.pair.part()
        };
        self.change_key(Some(part), None, None, &answers)
    }

    /// The Key file row's Change… with a new key file at `path`
    /// (APP-07.13): written, read back, and the vault's key file part.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`.
    pub fn new_key_file(
        &self,
        path: String,
        answers: Vec<Answer>,
    ) -> Result<KeyFileOutcome, AppError> {
        if path.len() > 4096 {
            return Err(AppError::TooLong);
        }
        match wizard::make_key_file(Path::new(&path)) {
            Ok(key) => Ok(KeyFileOutcome::Then {
                outcome: self.change_key(None, Some(Some(key)), None, &answers)?,
            }),
            Err(outcome) => Ok(KeyFileOutcome::Then { outcome }),
        }
    }

    /// The Key file row's Change… with an existing file (APP-07.14,
    /// APP-07.20): the vault's own file refused (M06-30), a vault-like name
    /// asked (M06-31), then the vault's key file part.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`.
    pub fn choose_key_file(
        &self,
        path: String,
        answers: Vec<Answer>,
    ) -> Result<KeyFileOutcome, AppError> {
        if path.len() > 4096 {
            return Err(AppError::TooLong);
        }
        let vault = self.vault_path()?;
        match wizard::choose_key_file(Path::new(&path), Some(&vault), &answers) {
            Ok((key, file)) => {
                let outcome =
                    self.change_key(None, Some(Some((key, file.name.clone()))), None, &answers)?;
                Ok(if outcome == Outcome::Done {
                    KeyFileOutcome::Chosen { file }
                } else {
                    KeyFileOutcome::Then { outcome }
                })
            }
            Err(outcome) => Ok(KeyFileOutcome::Then { outcome }),
        }
    }

    /// The Key file row's Remove (MOD-12.10): "no part" refused.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn remove_key_file(&self, answers: Vec<Answer>) -> Result<Outcome, AppError> {
        self.change_key(None, Some(None), None, &answers)
    }

    /// The Security key row (F-126; MOD-12.10, INT-07.25): `pick` adds or
    /// changes the key and slot, `None` removes the part; the next save
    /// asks the new key, or none. A chosen key must be plugged in now
    /// (step 6: M06-17, MI07-01); no challenge runs before that save. Call
    /// it off the main thread when `pick` is set: it looks for keys.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn set_security_key(
        &self,
        pick: Option<KeyPick>,
        answers: Vec<Answer>,
    ) -> Result<Outcome, AppError> {
        let choice = match pick.map(crate::hwkey::plugged) {
            None => None,
            Some(Ok(choice)) => Some(choice),
            Some(Err(m)) => return Ok(refused(m.id, &m.text)),
        };
        self.change_key(None, None, Some(choice), &answers)
    }

    /// Delete all history… (MOD-03.13 for every live entry), after the
    /// screen's confirmation. How many entries lost their history.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn delete_all_history(&self) -> Result<u32, AppError> {
        self.session.with_edit(self.vault, |v, _, rated, es| {
            let ids: Vec<Uuid> = v
                .root
                .all_entries()
                .filter(|e| !e.history.is_empty())
                .map(|e| e.uuid)
                .collect();
            let at = now();
            let mut n = 0u32;
            for id in ids {
                if history::delete_items(v, id, &Delete::All, at).unwrap_or(false) {
                    rated.forget(id);
                    n = n.saturating_add(1);
                }
            }
            if n > 0 {
                es.count_change();
            }
            Ok(n)
        })
    }

    /// Disconnect (INT-02.8, `vault.act.remove_association`) of the
    /// browser named `name`, after the screen's confirmation: its key item
    /// and its `_CREATED_` item go.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`.
    pub fn disconnect(&self, name: String) -> Result<bool, AppError> {
        if name.len() > MAX_TEXT {
            return Err(AppError::TooLong);
        }
        self.session.with_edit(self.vault, |v, _, _, es| {
            let gone = settings::remove_associations(v, &[name.as_str()], now()) > 0;
            if gone {
                es.count_change();
            }
            Ok(gone)
        })
    }

    /// Remove all… (`vault.act.forget_site_access`), after the screen's
    /// confirmation: how many entries changed.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn forget_site_access(&self) -> Result<u32, AppError> {
        self.session.with_edit(self.vault, |v, _, _, es| {
            let n = settings::forget_site_access(v, now());
            if n > 0 {
                es.count_change();
            }
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
    }

    /// The file name as the window title shows it (no vault content).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn file_name(&self) -> Result<String, AppError> {
        Ok(file_name(&self.vault_path()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UnlockResult;
    use app_crypto::kdf::{KdfParams, SpeedRecord};
    use app_format::header::read_header;

    /// CRY-02.14: a save never asks. A key derivation the user approved
    /// with M07-34 is written by the next save, which re-encrypts with it.
    /// A slow speed record puts every estimate far above 10 s (the ask band)
    /// while the real runs stay small.
    #[test]
    fn cry02_14_an_approved_costly_kdf_saves_without_asking() {
        let dir = std::env::temp_dir().join(format!("app-e5s8-cost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Vault.appvault");
        let demo =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/option-a-family.appvault");
        std::fs::copy(demo, &path).unwrap();
        let s = Session::new();
        let id = s.open(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(
            s.unlock(id, Some("demo-pass-9".into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        let vs = VaultSettings::new(Arc::clone(&s), id);
        let choice = EncryptionChoice {
            cipher: CipherChoice::Aes256,
            kdf: KdfChoice::Argon2id,
            memory_mib: 2,
            lanes: 1,
            unlock_ms: 100,
        };
        assert!(vs.measure(choice).unwrap());
        lock(&s.host).argon2_record = Some(SpeedRecord {
            count: 1,
            memory_kib: 1024,
            lanes: 1,
            ms: 60_000,
        });
        let asked = |answers: Vec<Answer>| match vs.set_kdf(choice, answers).unwrap() {
            Outcome::Ask { question } => question.id,
            other => panic!("{other:?}"),
        };
        assert_eq!(asked(vec![]), "M07-33");
        assert_eq!(asked(vec![Answer::SafeMinimum]), "M07-34");
        assert_eq!(
            vs.set_kdf(choice, vec![Answer::SafeMinimum, Answer::Cost])
                .unwrap(),
            Outcome::Done
        );
        let status = s.save(id).unwrap();
        assert_eq!((status.changes, status.failure), (0, None));
        let h = read_header(&std::fs::read(&path).unwrap(), &Limits::DEFAULT).unwrap();
        assert!(matches!(
            h.kdf,
            KdfParams::Argon2 {
                memory_kib: 2048,
                lanes: 1,
                ..
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
