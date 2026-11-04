//! Unlocking and saving (INT-10.11 to INT-10.15, INT-10.20), key files
//! (FMT-18), the unlock error texts (APP-06 M06-01 to M06-30) and the entry
//! and group paths (INT-10.17 to INT-10.19).

use crate::args::Parsed;
use crate::term::{self, Res, fail};
use app_core::storage::{self, Checksum, SaveError, SaveRequest};
use app_crypto::kdf::{CostReport, Host};
use app_crypto::secret::SecretString;
use app_format::error::{HardwareKeyReason, KeyFileReason};
use app_format::keyfile::{KeyFileKey, read_key_file};
use app_format::keys::{ChallengeResponse, Credentials, TransformedKey};
use app_format::limits::{Limit, Limits};
use app_format::{Error, Opened, Saved};
use app_model::{Entry, Group, Time, Uuid, Vault};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The current time in whole seconds.
pub fn now() -> Time {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Time::from_unix(secs).unwrap_or_default()
}

/// This Mac for the KDF cost check (CRY-02.14). No speed record is read
/// from App's settings yet (APP-01 settings come with E5-S9), so the check
/// measures one in memory and the tool stores nothing (INT-10.9).
pub fn host() -> Host {
    let processors = std::thread::available_parallelism().map_or(1, |n| n.get());
    Host {
        physical_memory: app_platform::macos::physical_memory(),
        logical_processors: u64::try_from(processors).unwrap_or(1),
        argon2_record: None,
        aes_record: None,
    }
}

/// The key parts of one vault.
#[derive(Default)]
pub struct Creds {
    pub password: Option<SecretString>,
    pub key_file: Option<KeyFileKey>,
    /// F-107: the `--hw-key` slot, asked at each open and save (FMT-04.10).
    pub hardware: Option<Box<dyn ChallengeResponse>>,
}

impl Creds {
    pub fn new(password: Option<SecretString>, key_file: Option<KeyFileKey>) -> Self {
        Self {
            password,
            key_file,
            hardware: None,
        }
    }

    pub fn get(&self) -> Credentials<'_> {
        Credentials {
            password: self.password.as_ref(),
            key_file: self.key_file.as_ref(),
            hardware_key: self.hardware.as_deref(),
        }
    }
}

/// An unlocked vault and what its saves need.
pub struct Session {
    /// VAULT as typed.
    pub path: String,
    pub vault: Vault,
    pub creds: Creds,
    key: TransformedKey,
    checksum: Checksum,
    host: Host,
    approval: Option<CostReport>,
    /// The pages under `creds.password`, locked while the session keeps it
    /// for saving (APP-11.9, F-058). The last field, so the password is wiped
    /// before its pages are unlocked.
    password_pages: Option<app_platform::memory::Locked>,
}

impl Session {
    /// Locks the pages under the kept password; call it after the password
    /// is set or changed (F-058).
    pub fn keep_password(&mut self) {
        self.password_pages = self
            .creds
            .password
            .as_ref()
            .and_then(|p| app_platform::memory::lock(p.expose().as_bytes()));
    }
}

/// The unlock options of a command (U01 to U05).
pub struct Unlock<'a> {
    pub key_file: Option<&'a str>,
    pub no_password: bool,
    pub hw_key: Option<&'a str>,
    pub quiet: bool,
    pub slow: bool,
}

impl<'a> Unlock<'a> {
    pub fn of(p: &'a Parsed) -> Self {
        Self {
            key_file: p.value("key-file"),
            no_password: p.flag("no-password"),
            hw_key: p.value("hw-key"),
            quiet: p.quiet(),
            slow: p.flag("allow-slow-unlock"),
        }
    }
}

/// INT-10.11: VAULT exists, is a regular file after links, can be read.
pub fn check_vault(path: &str) -> Res {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => fail(format!("{path} cannot be read: permission denied.")),
        _ => fail(format!("{path} does not exist.")),
    })?;
    if !meta.is_file() {
        return Err(fail(format!(
            "{path} is not a vault file but a folder or special file."
        )));
    }
    File::open(path).map_err(|_| fail(format!("{path} cannot be read: permission denied.")))?;
    Ok(())
}

/// The checks before any prompt: the vault (INT-10.11), the key file equal
/// to the vault (FMT-18.24), `--no-password` alone (M10-14).
pub fn check_unlock(path: &str, u: &Unlock<'_>) -> Res {
    check_vault(path)?;
    if let Some(k) = u.key_file
        && same_file(k, path)
    {
        return Err(fail(vault_as_key_file()));
    }
    if u.no_password && u.key_file.is_none() && u.hw_key.is_none() {
        return Err(fail(format!(
            "nothing to unlock {path} with. --no-password needs --key-file or --hw-key."
        )));
    }
    Ok(())
}

/// FMT-18.24 for a vault that may not exist yet: the same file, or the
/// same absolute path.
pub fn same_target(a: &str, b: &str) -> bool {
    let abs = |p: &str| std::path::absolute(p).ok();
    same_file(a, b) || (abs(a).is_some() && abs(a) == abs(b))
}

fn same_file(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// INT-10.12 to INT-10.14: the password line, then the key file, then the
/// security key slot (F-107), asked when the vault opens.
pub fn read_creds(path: &str, u: &Unlock<'_>) -> Res<Creds> {
    let password = (!u.no_password)
        .then(|| term::read_secret(&format!("Vault password for {path}: "), u.quiet));
    let key_file = match u.key_file {
        Some(k) => Some(read_key(k, u.quiet)?),
        None => None,
    };
    Ok(Creds {
        hardware: u.hw_key.map(crate::hwkey::part),
        ..Creds::new(password, key_file)
    })
}

/// FMT-18 through the APP-06 texts; M10-16 for an early kind.
pub fn read_key(path: &str, quiet: bool) -> Res<KeyFileKey> {
    let key = load_key(path).map_err(fail)?;
    if key.kind().old_format() && !quiet {
        term::err(&format!(
            "Note: {path} is an early kind of key file. It works, but a later App may stop reading it. db-edit --set-key-file moves the vault to a new key file."
        ));
    }
    Ok(key)
}

/// A key file read, or the APP-06 text of why not. A folder or special
/// file is refused before it is opened, so a FIFO never blocks the read.
pub fn load_key(path: &str) -> Result<KeyFileKey, String> {
    let name = file_name(path);
    let fail = |r: KeyFileReason| open_error(&Error::KeyFile(r), "", &name);
    let meta = std::fs::metadata(path).map_err(|e| fail(KeyFileReason::Io(e.kind())))?;
    if !meta.is_file() {
        return Err(fail(KeyFileReason::NotRegularFile));
    }
    let file = File::open(path).map_err(|e| fail(KeyFileReason::Io(e.kind())))?;
    read_key_file(file, &Limits::DEFAULT).map_err(|e| open_error(&e, "", &name))
}

/// Opens VAULT with the credentials (INT-10.15). `who` names the vault in
/// M10-15.
pub fn open(path: &str, creds: Creds, u: &Unlock<'_>) -> Result<Session, (Creds, String)> {
    let file = file_name(path);
    let key_name = u.key_file.map(file_name).unwrap_or_default();
    let text = |e: &Error| open_error(e, &file, &key_name);
    let bytes = match File::open(path)
        .map_err(|e| Error::Io(e.kind()))
        .and_then(|f| app_format::detect::read_vault(f, &Limits::DEFAULT))
    {
        Ok(b) => b,
        Err(e) => return Err((creds, text(&e))),
    };
    let mut host = host();
    let mut approval = None;
    let opened = loop {
        match app_format::open(
            &bytes,
            &creds.get(),
            &mut host,
            &Limits::DEFAULT,
            approval.as_ref(),
        ) {
            Ok(Opened::Vault(o)) => break o,
            Ok(Opened::Ask(report)) if u.slow && approval.is_none() => approval = Some(report),
            Ok(Opened::Ask(report)) => return Err((creds, slow_text(path, &report))),
            Err(e) => return Err((creds, text(&e))),
        }
    };
    let opened = *opened;
    let mut session = Session {
        path: path.to_owned(),
        vault: opened.vault,
        creds,
        key: opened.key,
        checksum: storage::checksum(&bytes),
        host,
        approval,
        password_pages: None,
    };
    session.keep_password();
    Ok(session)
}

/// The whole unlock of a command: checks, lines, open, notes.
pub fn unlock(path: &str, u: &Unlock<'_>) -> Res<Session> {
    check_unlock(path, u)?;
    let creds = read_creds(path, u)?;
    let s = open(path, creds, u).map_err(|(_, text)| fail(text))?;
    s.notes(u.quiet);
    Ok(s)
}

/// M10-15.
fn slow_text(path: &str, r: &CostReport) -> String {
    let mut s = format!("unlocking {path} needs about ");
    if r.memory_bytes() > 0 {
        s.push_str(&format!(
            "{} of memory and about ",
            memory(r.memory_bytes())
        ));
    }
    s.push_str(&format!("{} on this Mac", duration(r.estimated_ms())));
    if r.over_lanes() {
        s.push_str(&format!(" and {} parallel lanes", r.lanes()));
    }
    s.push_str(". Nothing was done. Run the command again with --allow-slow-unlock to go ahead.");
    s
}

/// MiB below 1 GiB, else GiB with one decimal (APP-06.14).
fn memory(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes < GIB {
        format!("{} MiB", bytes / MIB)
    } else {
        let tenths = bytes.saturating_mul(10).saturating_add(GIB / 2) / GIB;
        format!("{}.{} GiB", tenths / 10, tenths % 10)
    }
}

/// One decimal under 10 seconds, whole seconds to 120, then minutes.
fn duration(ms: u64) -> String {
    let tenths = ms.saturating_add(50) / 100;
    if tenths < 100 {
        format!("{}.{} seconds", tenths / 10, tenths % 10)
    } else if ms <= 120_000 {
        format!("{} seconds", ms.saturating_add(500) / 1000)
    } else {
        format!("{} minutes", ms.saturating_add(30_000) / 60_000)
    }
}

impl Session {
    /// M10-17 and the MOD-13.16 notice, after a successful open.
    pub fn notes(&self, quiet: bool) {
        if quiet {
            return;
        }
        if let Some(v) = self.vault.read_version
            && (v.major, v.minor) > (4, 1)
        {
            term::err(&format!(
                "Note: {} uses a newer vault format than App knows. Saving may lose settings that only the newer format holds.",
                self.path
            ));
        }
        let r = app_core::settings::reminder(&self.vault.meta, now());
        if let Some(line) = app_core::settings::cli_notice(&r) {
            term::err(&line);
        }
    }

    /// The name of the shell prompt: the vault name, or the file name.
    pub fn name(&self) -> String {
        if self.vault.meta.name.is_empty() {
            file_name(&self.path)
        } else {
            self.vault.meta.name.clone()
        }
    }

    /// Saves the vault the safe way (INT-10.20, APP-05.9 to APP-05.12):
    /// links resolved, the pre-save check, mode kept, no backup.
    pub fn save(&mut self) -> Res {
        let path = self.path.clone();
        let failed = |reason: String| {
            fail(format!(
                "could not save {path}: {reason}. The file on disk is unchanged."
            ))
        };
        let file = match app_format::save(
            &self.vault,
            &self.creds.get(),
            Some(&self.key),
            &mut self.host,
            &Limits::DEFAULT,
            self.approval.as_ref(),
        ) {
            Ok(Saved::File(f)) => f,
            Ok(Saved::Ask(r)) => return Err(fail(slow_text(&path, &r))),
            Err(e) => return Err(failed(format_reason(&e))),
        };
        let temp = std::env::temp_dir();
        let request = SaveRequest::plain(
            Path::new(&self.path),
            &file.bytes,
            Some(self.checksum),
            &temp,
        );
        match storage::save(&request) {
            Ok(report) => {
                self.checksum = report.checksum;
                self.key = file.key;
                Ok(())
            }
            Err(SaveError::ChangedOnDisk(_)) => Err(fail(format!(
                "{path} changed on disk while this command ran. Nothing was saved; run the command again."
            ))),
            Err(SaveError::CannotRead(kind) | SaveError::Write { kind, .. }) => {
                Err(failed(kind.to_string()))
            }
        }
    }
}

/// A short reason for a vault that cannot be built (M10-90).
fn format_reason(e: &Error) -> String {
    match e {
        Error::TooLarge(l) => format!("it is over the limit {}", l.name()),
        Error::Io(kind) => kind.to_string(),
        Error::HardwareKey(r) => hardware_key_text(*r),
        _ => "the vault could not be written".to_owned(),
    }
}

/// Writes a new file that must not exist yet, with `mode` (APP-05.12,
/// FMT-18.22); never replaces anything.
pub fn write_new(path: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    let done = f.write_all(bytes).and_then(|()| f.sync_all());
    if done.is_err() {
        let _ = std::fs::remove_file(path);
    }
    done
}

/// The file name of a path, for messages.
pub fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// APP-06: one text per open error. The same words as the window app's
// messages (app-ffi messages.rs), which the tool does not link.

const MAX_NAME: usize = 64;
const KEEP: usize = 30;

/// APP-06.18: a file name with controls, direction marks and zero-width
/// characters removed; over 64 characters it keeps 30 at each end.
fn clean_name(name: &str) -> String {
    let kept: Vec<char> = name
        .chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{061C}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                )
        })
        .collect();
    if kept.len() <= MAX_NAME {
        return kept.into_iter().collect();
    }
    let head = kept.iter().take(KEEP);
    let tail = kept.iter().skip(kept.len() - KEEP);
    head.chain(std::iter::once(&'…')).chain(tail).collect()
}

/// M06-30 (FMT-18.24).
pub fn vault_as_key_file() -> String {
    "This is the vault file itself, so it cannot also be its key file. Leave the key file empty if the vault has none.".to_owned()
}

/// M06-01 to M06-26 for `error`, naming the vault file `file` and the key
/// file `key` (file names, cleaned here).
pub fn open_error(error: &Error, file: &str, key: &str) -> String {
    let file = clean_name(file);
    let key = clean_name(key);
    match error {
        Error::NotAVault => format!("\"{file}\" is not a vault file. Open the file that holds your vault."),
        Error::OldFormat => format!("\"{file}\" is in the first vault format. App can only import it: Import… makes a new vault from its contents."),
        Error::Unsupported => "This vault uses a file version or setting that App does not support yet. An App update may open it.".into(),
        Error::Corrupt => format!("\"{file}\" is damaged and cannot be unlocked. If you have a backup copy, open that instead."),
        Error::NoCredentials => "Enter the password for this vault.".into(),
        Error::WrongKey => "Wrong password, key file or security key. Check them and try again.".into(),
        Error::KeyFile(reason) => key_file_text(reason, &key),
        Error::HardwareKey(reason) => hardware_key_text(*reason),
        Error::TooLarge(Limit::KdfCost) => "This vault's unlock settings ask for more than this Mac can do. Lower them in the app that made the vault, then try again.".into(),
        Error::TooLarge(Limit::TotalFile) => format!("\"{file}\" is larger than App can open (about 1 GiB). Make it smaller in the app that made it, for example by removing large attachments."),
        Error::TooLarge(_) => format!("\"{file}\" holds more than App can open safely. Make it smaller in the app that made it."),
        Error::Io(ErrorKind::NotFound) => format!("\"{file}\" cannot be found. It may have been moved, renamed or deleted. Open it from its new place."),
        Error::Io(ErrorKind::PermissionDenied) => format!("App is not allowed to read \"{file}\". Check its permissions in Finder, then try again."),
        Error::Io(_) => format!("App could not read \"{file}\". Check that its disk is connected, then try again."),
    }
}

/// M06-07 to M06-16.
pub fn key_file_text(reason: &KeyFileReason, key: &str) -> String {
    match reason {
        KeyFileReason::Empty => {
            format!("The key file \"{key}\" is empty. Choose the right key file.")
        }
        KeyFileReason::UnsupportedVersion(v) => {
            let plain = !v.is_empty()
                && v.chars().count() <= 16
                && v.chars().all(|c| c.is_ascii_digit() || c == '.');
            if plain {
                format!(
                    "The key file \"{key}\" has version {v}, which App cannot read. Choose another key file."
                )
            } else {
                format!(
                    "The key file \"{key}\" has a version App cannot read. Choose another key file."
                )
            }
        }
        KeyFileReason::CheckValueMismatch => format!(
            "The key file \"{key}\" is damaged: its built-in check failed. Use a backup copy of the key file."
        ),
        KeyFileReason::DataUnreadable => format!(
            "The key file \"{key}\" is damaged: App cannot read the key in it. Use a backup copy of the key file."
        ),
        KeyFileReason::Io(ErrorKind::NotFound) => {
            format!("The key file \"{key}\" cannot be found. Choose it again.")
        }
        KeyFileReason::Io(ErrorKind::PermissionDenied) => format!(
            "App is not allowed to read the key file \"{key}\". Check its permissions in Finder, then try again."
        ),
        KeyFileReason::Io(_) => format!(
            "App could not read the key file \"{key}\". Check that its disk is connected, then try again."
        ),
        KeyFileReason::NotRegularFile => format!(
            "\"{key}\" is a folder or a special file. Choose a normal file as the key file."
        ),
        KeyFileReason::Dtd => format!(
            "App does not accept the key file \"{key}\" because it declares a document type. Choose another key file."
        ),
        KeyFileReason::TooLarge(_) => format!(
            "The key file \"{key}\" is too complex for App to read safely. Choose another key file."
        ),
    }
}

/// M06-17 to M06-20, and MI07-01 (INT-07.20).
pub fn hardware_key_text(reason: HardwareKeyReason) -> String {
    match reason {
        HardwareKeyReason::Missing => "Your security key is not connected. Plug it in, then try again.",
        HardwareKeyReason::TimedOut => "The security key was not touched in time. Try again, and touch the key when it flashes.",
        HardwareKeyReason::SlotNotConfigured => "The chosen slot of your security key is not set up for challenge-response. Choose another slot.",
        HardwareKeyReason::BadAnswer | HardwareKeyReason::Failed => "App could not use your security key. Unplug it, plug it in again, then try again.",
        HardwareKeyReason::NotPermitted => "macOS did not let App reach your security key. Allow App under System Settings › Privacy & Security › Input Monitoring, then try again.",
    }
    .to_owned()
}

// ---------------------------------------------------------------------------
// Paths (INT-10.17 to INT-10.19).

/// Calls `f` for every group in tree order (a group before its child
/// groups, children in stored order) with its path: `""` for the root,
/// `/A/B` below it. Stops when `f` returns true.
fn walk<'v>(g: &'v Group, path: &str, f: &mut impl FnMut(&str, &'v Group) -> bool) -> bool {
    if f(path, g) {
        return true;
    }
    g.groups
        .iter()
        .any(|c| walk(c, &format!("{path}/{}", c.name), f))
}

/// INT-10.17: the first entry, in tree order, that `path` names: by title
/// alone when it holds no `/`, else by `/` + group names + `/` + title
/// compared as one string (a leading `/` optional). An empty path names none.
pub fn find_entry<'v>(v: &'v Vault, path: &str) -> Option<(&'v Entry, &'v Group)> {
    if path.is_empty() {
        return None;
    }
    let full = path
        .contains('/')
        .then(|| format!("/{}", path.strip_prefix('/').unwrap_or(path)));
    let mut found = None;
    walk(&v.root, "", &mut |gpath, g| {
        found = g
            .entries
            .iter()
            .find(|e| match &full {
                Some(want) => {
                    let title = e.value("Title");
                    want.len() == gpath.len() + 1 + title.len()
                        && want.starts_with(gpath)
                        && want[gpath.len()..].starts_with('/')
                        && want.ends_with(title)
                }
                None => e.value("Title") == path,
            })
            .map(|e| (e, g));
        found.is_some()
    });
    found
}

/// INT-10.18: empty or `/` is the root; else group names joined by `/`, a
/// leading and a trailing `/` optional; the first match in tree order.
pub fn find_group<'v>(v: &'v Vault, path: &str) -> Option<&'v Group> {
    let p = path.strip_prefix('/').unwrap_or(path);
    let p = p.strip_suffix('/').unwrap_or(p);
    if p.is_empty() {
        return Some(&v.root);
    }
    let want = format!("/{p}");
    let mut found = None;
    walk(&v.root, "", &mut |gpath, g| {
        if gpath == want {
            found = Some(g);
        }
        found.is_some()
    });
    found
}

/// An entry's Title as the tool's messages, lists and paths name it: the
/// mask when the Title is protected (LD-207, F-066); `show -s` prints it.
pub fn title<'e>(v: &Vault, e: &'e Entry) -> &'e str {
    app_core::health::shown_title(e, v.meta.memory_protection.for_field("Title"))
}

/// INT-10.19: `/` + group names below the root + `/` + title (masked when
/// protected, F-066).
pub fn entry_path(v: &Vault, id: Uuid) -> Option<String> {
    let mut found = None;
    walk(&v.root, "", &mut |gpath, g| {
        found = g
            .entries
            .iter()
            .find(|e| e.uuid == id)
            .map(|e| format!("{gpath}/{}", title(v, e)));
        found.is_some()
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use app_crypto::secret::SecretString;
    use app_model::Field;

    fn entry(n: u8, title: &str) -> Entry {
        let mut e = Entry::new(Uuid([n; 16]), Time(0));
        e.set_field(
            "Title".into(),
            Field {
                value: SecretString::new(title.into()),
                protected: false,
            },
        );
        e
    }

    #[test]
    fn int10_17_paths() {
        let mut servers = Group::new(Uuid([3; 16]), "Servers".into(), Time(0));
        servers.entries.push(entry(10, "Server login"));
        let mut work = Group::new(Uuid([2; 16]), "Work".into(), Time(0));
        work.groups.push(servers);
        let mut root = Group::new(Uuid([1; 16]), "Root".into(), Time(0));
        root.entries.push(entry(11, "Work/Servers/Server login"));
        root.entries.push(entry(12, ""));
        root.groups.push(work);
        let v = Vault::new(root, Time(0));
        let id = |p: &str| find_entry(&v, p).map(|(e, _)| e.uuid.0[0]);
        assert_eq!(id("Server login"), Some(10));
        assert_eq!(id("Work/Servers/Server login"), Some(11));
        assert_eq!(id("/"), Some(12));
        assert_eq!(id(""), None);
        assert_eq!(id("Servers/Server login"), None);
        assert_eq!(find_group(&v, "/Work/Servers/").unwrap().name, "Servers");
        assert_eq!(find_group(&v, "").unwrap().name, "Root");
        assert!(find_group(&v, "Servers").is_none());
        assert_eq!(
            entry_path(&v, Uuid([10; 16])).as_deref(),
            Some("/Work/Servers/Server login")
        );
    }
}

#[cfg(test)]
mod kept_password_tests {
    use super::{Creds, Unlock, open};
    use app_crypto::secret::SecretString;

    #[test]
    fn f_058_kept_password_pages_are_locked() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/password-only.appvault"
        );
        let unlock = Unlock {
            key_file: None,
            no_password: false,
            hw_key: None,
            quiet: true,
            slow: true,
        };
        let creds = Creds::new(Some(SecretString::new("demo-pass-1".into())), None);
        let Ok(mut session) = open(path, creds, &unlock) else {
            panic!("the demo vault opens");
        };
        assert!(
            session.password_pages.is_some(),
            "the kept password's pages are locked"
        );
        session.creds.password = None;
        session.keep_password();
        assert!(session.password_pages.is_none());
    }
}
