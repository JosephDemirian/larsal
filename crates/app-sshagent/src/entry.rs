//! An entry's SSH key: where it lives, reading it, unlocking it, and the
//! plan for a vault that unlocks (INT-06.4, INT-06.5, INT-06.8, INT-06.9,
//! INT-06.22, R06-5).

use crate::keyring::Place;
use crate::settings::{SETTINGS_NAME, Settings, Source};
use crate::{Error, Limits, MAX_KEY_SIZE, MAX_LIFETIME, SshKey};
use app_core::health::MASKED_TITLE;
use app_core::refs;
use app_crypto::secret::{SecretBytes, SecretString};
use app_crypto::ssh::AgentKey;
use app_model::{Entry, Time, Uuid, Vault};
use core::cell::Cell;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};

/// INT-06.4 without the feature switch (the caller checks S-SSH-01): the
/// entry is not in the recycle bin, its settings attachment exists and can
/// be read, `AllowUseOfSshKey` is true and the selected source is set.
/// Then its settings; else `None`. The key itself is not read.
#[must_use]
pub fn has_ssh_key(vault: &Vault, entry: &Entry) -> Option<Settings> {
    let settings = Settings::of(entry).ok()??;
    // The bin check walks the tree, so it runs only for entries with settings.
    (settings.allow && settings.source_set() && !app_core::recycle::entry_in_bin(vault, entry.uuid))
        .then_some(settings)
}

/// `entry`'s Title as App's texts may name it (LD-207, rule 4, LD-105):
/// the mask the screen draws for hidden values when the Title is protected
/// by its own flag or by the vault's (MOD-01.7, as app-core's `refs`
/// masks). Records, MI06-18, MI06-19 and every message take this; the entry
/// stays reachable through its id.
fn shown_title<'e>(vault: &Vault, entry: &'e Entry) -> &'e str {
    match entry.field("Title") {
        Some(f) if f.protected || vault.meta.memory_protection.for_field("Title") => MASKED_TITLE,
        _ => entry.value("Title"),
    }
}

/// The key file path of INT-06.5, expanded once: a leading `~/` becomes
/// `home`; then, left to right in one pass over the rest, each `$NAME` (an
/// ASCII letter, then letters, digits or `_`) becomes `env(NAME)`, or
/// nothing when unset. Text an expansion produced is not expanded again;
/// `${NAME}` and `%NAME%` stay as written. A relative result is taken from
/// `vault_dir`.
#[must_use]
pub fn key_path(
    stored: &str,
    home: &Path,
    vault_dir: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> PathBuf {
    let mut out = OsString::new();
    let mut rest = stored;
    if let Some(after) = stored.strip_prefix("~/") {
        out.push(home.join(""));
        rest = after;
    }
    while let Some(i) = rest.find('$') {
        let (before, from) = rest.split_at(i);
        out.push(before);
        let name_len = from
            .char_indices()
            .skip(1)
            .take_while(|(n, c)| {
                c.is_ascii_alphabetic() || (*n > 1 && (c.is_ascii_digit() || *c == '_'))
            })
            .count();
        let (name, after) = from.split_at(name_len.saturating_add(1));
        if name_len == 0 {
            out.push("$");
        } else if let Some(value) = name.get(1..).and_then(env) {
            out.push(value);
        }
        rest = after;
    }
    out.push(rest);
    let path = PathBuf::from(out);
    if path.is_relative() {
        vault_dir.join(path)
    } else {
        path
    }
}

/// One entry's SSH key, read but not decrypted (INT-06.5 to INT-06.8).
///
/// Guarantees: holds no passphrase; a protected key's private part stays
/// encrypted until [`EntryKey::unlock`]; an unprotected one sits in
/// self-wiping types. No `Clone`.
#[derive(Debug)]
pub struct EntryKey {
    entry: Uuid,
    title: String,
    /// The UserName for INT-06.8's fallback; `None` when it is protected.
    user: Option<String>,
    name: String,
    settings: Settings,
    key: SshKey,
}

impl EntryKey {
    /// Reads the key `settings` select for `entry` (INT-06.5): the entry's
    /// attachment with exactly that name ([`Error::NoAttachment`]; the
    /// settings attachment is never a key), or the file at [`key_path`]
    /// with this process's `HOME` and environment ([`Error::CannotOpen`]
    /// for a missing file, a folder or anything not a regular file). Over
    /// 1 MiB is [`Error::TooLarge`] before anything is parsed, zero bytes
    /// [`Error::Empty`], then [`SshKey::read`]'s errors. The file is read
    /// now, never cached, never written. `vault` holds `entry`: its Title
    /// flag decides the title App's texts use (LD-207).
    pub fn read(
        vault: &Vault,
        entry: &Entry,
        settings: Settings,
        vault_dir: &Path,
    ) -> Result<Self, Error> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        Self::read_with(vault, entry, settings, &home, vault_dir, &|n| {
            std::env::var_os(n)
        })
    }

    /// [`EntryKey::read`] with the home folder and environment given.
    pub fn read_with(
        vault: &Vault,
        entry: &Entry,
        settings: Settings,
        home: &Path,
        vault_dir: &Path,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Self, Error> {
        let (bytes, name) = match settings.source {
            Source::Attachment => {
                let wanted = settings.attachment_name.as_str();
                let found = entry
                    .attachments
                    .iter()
                    .find(|a| a.name == wanted && a.name.as_bytes() != SETTINGS_NAME)
                    .ok_or(Error::NoAttachment)?;
                let data = found.data.expose();
                if data.len() > MAX_KEY_SIZE {
                    return Err(Error::TooLarge);
                }
                (SshKey::read(data)?, wanted.to_owned())
            }
            Source::File => {
                let path = key_path(&settings.file_name, home, vault_dir, env);
                let name = path
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                (SshKey::read(read_file(&path)?.expose())?, name)
            }
        };
        Ok(Self {
            entry: entry.uuid,
            title: shown_title(vault, entry).to_owned(),
            user: match entry.field("UserName") {
                Some(f) if f.protected || vault.meta.memory_protection.for_field("UserName") => {
                    None
                }
                _ => Some(entry.value("UserName").to_owned()),
            },
            name,
            settings,
            key: bytes,
        })
    }

    /// The key's public parts (type, fingerprint, public line, blob).
    #[must_use]
    pub fn key(&self) -> &SshKey {
        &self.key
    }

    /// The entry this key belongs to.
    #[must_use]
    pub fn entry(&self) -> Uuid {
        self.entry
    }

    /// The entry's title for records and messages; the mask when it is
    /// protected (LD-207).
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// What the question calls the key (INT-06.34, LD-207): the entry
    /// title, or for a protected one the key's own comment, else its
    /// fingerprint (never [`EntryKey::comment`]'s `<user name>@…`, whose
    /// user name may be protected too).
    #[must_use]
    pub fn question_name(&self, unlocked: &AgentKey) -> String {
        if self.title != MASKED_TITLE {
            self.title.clone()
        } else if unlocked.comment().is_empty() {
            self.key.fingerprint().to_owned()
        } else {
            unlocked.comment().to_owned()
        }
    }

    /// The settings the key was read with.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Which agent the key goes to: App's own when it asks before each use
    /// (INT-06.31), else the system agent.
    #[must_use]
    pub fn place(&self) -> Place {
        if self.settings.confirm {
            Place::Own
        } else {
            Place::System
        }
    }

    /// The record's remove-on-lock flag: always on for a key that asks
    /// (INT-06.31, R06-1), else `RemoveAtDatabaseClose`.
    #[must_use]
    pub fn remove_on_lock(&self) -> bool {
        self.settings.confirm || self.settings.remove_at_close
    }

    /// The limits for an add (INT-06.15, INT-06.20): the lifetime when its
    /// switch is on, 1 to 999,999,999 seconds, else [`Error::Lifetime`]
    /// (MI06-17). The confirm limit is never sent: such keys go to App's
    /// own agent (D-INT06-1 (b)).
    pub fn limits(&self, sk_provider: Option<&str>) -> Result<Limits, Error> {
        let lifetime = if self.settings.use_lifetime {
            let s = u32::try_from(self.settings.lifetime).map_err(|_| Error::Lifetime)?;
            if !(1..=MAX_LIFETIME).contains(&s) {
                return Err(Error::Lifetime);
            }
            Some(s)
        } else {
            None
        };
        Ok(Limits {
            lifetime,
            confirm: false,
            sk_provider: sk_provider.map(str::to_owned),
        })
    }

    /// Decrypts the key in memory (INT-06.9) with `entry`'s Password field
    /// resolved as Copy Password resolves it (D-INT06-5, MOD-08): in
    /// app-core's shared Copy context ([`refs::copy_context`]: references in
    /// `vault`, `{DB_DIR}` from `vault_dir`, one-time password and passkey
    /// fields hidden, LD-170 (4); its own work meter, LD-126). `entry` is the
    /// entry this key was read from. The resolved passphrase lives only in a
    /// wiping type. Errors as [`SshKey::unlock`].
    pub fn unlock(
        &self,
        vault: &Vault,
        entry: &Entry,
        vault_dir: &Path,
    ) -> Result<AgentKey, Error> {
        self.key.unlock(&Self::passphrase(vault, entry, vault_dir))
    }

    /// `entry`'s Password field resolved as [`EntryKey::unlock`] resolves
    /// it, without decrypting anything: for a caller that holds the vault
    /// only briefly ([`crate::Keyring::add_planned`]). A wiping type.
    #[must_use]
    pub fn passphrase(vault: &Vault, entry: &Entry, vault_dir: &Path) -> SecretString {
        let dir = vault_dir.to_string_lossy();
        let meter = Cell::new(refs::COPY_BUDGET);
        let ctx = refs::copy_context(vault, &dir, now(), &meter);
        refs::resolve(entry.value("Password"), entry, &ctx).text
    }

    /// The comment sent with the key (INT-06.8): the key's own comment, or
    /// `<user name>@<attachment name or file name>` when it is empty. A
    /// protected UserName (its own flag or the vault's, LD-207) is left out
    /// with its `@`, and an empty result is "App key" (LD-213 (2)): every
    /// program that lists an agent sees the comment.
    #[must_use]
    pub fn comment(&self, unlocked: &AgentKey) -> String {
        match (unlocked.comment(), &self.user) {
            ("", Some(user)) => format!("{user}@{}", self.name),
            ("", None) if self.name.is_empty() => "App key".to_owned(),
            ("", None) => self.name.clone(),
            (own, _) => own.to_owned(),
        }
    }
}

/// Reads a key file of at most [`MAX_KEY_SIZE`] bytes into a wiping buffer
/// of the file's full size, reserved before the read (Rust rule 3); only a
/// regular file (checked first, so a FIFO never blocks the open). A file
/// that changes size while it is read cannot be opened.
fn read_file(path: &Path) -> Result<SecretBytes, Error> {
    let cannot = || Error::CannotOpen {
        path: path.to_path_buf(),
    };
    if !std::fs::metadata(path).map_err(|_| cannot())?.is_file() {
        return Err(cannot());
    }
    let mut file = std::fs::File::open(path).map_err(|_| cannot())?;
    let meta = file.metadata().map_err(|_| cannot())?;
    if !meta.is_file() {
        return Err(cannot());
    }
    let len = usize::try_from(meta.len()).map_err(|_| Error::TooLarge)?;
    if len > MAX_KEY_SIZE {
        return Err(Error::TooLarge);
    }
    let mut bytes = SecretBytes::zeroed(len);
    file.read_exact(bytes.expose_mut()).map_err(|_| cannot())?;
    let mut more = [0u8; 1];
    if file.read(&mut more).map_err(|_| cannot())? != 0 {
        return Err(cannot());
    }
    Ok(bytes)
}

/// The clock for `{DT_…}` placeholders, as the Copy of the window app reads it.
fn now() -> Time {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Time::from_unix(secs).unwrap_or_default()
}

/// One entry App adds when the vault unlocks (INT-06.22).
#[derive(Debug)]
pub struct Step {
    /// The entry.
    pub entry: Uuid,
    /// Its title for MI06-18; the mask when protected (LD-207).
    pub title: String,
    /// Its key, or why it cannot be read.
    pub key: Result<EntryKey, Error>,
}

/// The entries whose keys App adds when `vault` unlocks (INT-06.22), in
/// tree order (a group's own entries, then its subgroups, depth first),
/// outside the recycle bin, with an SSH key (INT-06.4) and "Add the key when
/// the vault unlocks" on. Each step's [`EntryKey::place`] says the agent.
/// R06-5 (LD-175): a key lives in one agent only and an asking entry wins,
/// so a step that does not ask is left out when another step with the same
/// public key asks. Keys are read here (public parts only, no passphrase).
#[must_use]
pub fn unlock_plan(vault: &Vault, vault_dir: &Path) -> Vec<Step> {
    let mut steps: Vec<Step> = vault
        .root
        .all_entries()
        .filter_map(|e| {
            let settings = has_ssh_key(vault, e)?;
            settings.add_at_open.then(|| Step {
                entry: e.uuid,
                title: shown_title(vault, e).to_owned(),
                key: EntryKey::read(vault, e, settings, vault_dir),
            })
        })
        .collect();
    let asking: Vec<Vec<u8>> = steps
        .iter()
        .filter_map(|s| s.key.as_ref().ok())
        .filter(|k| k.place() == Place::Own)
        .map(|k| k.key().public_blob().to_vec())
        .collect();
    steps.retain(|s| match &s.key {
        Ok(k) => k.place() == Place::Own || !asking.iter().any(|b| b == k.key().public_blob()),
        Err(_) => true,
    });
    steps
}
