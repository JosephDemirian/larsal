//! Auto-open (F-079; APP-06.25, APP-06.26, M06-39, SR-10, LD-97) and
//! opening an entry's URL (F-080; MOD-08.31, LD-59, LD-70, LD-71). Both
//! open other vaults with the credentials an entry gives, as passed-in
//! credentials (APP-06.24): the resolved password stays in a
//! `SecretString` and never reaches Swift.

use crate::session::{AppError, Session, changed};
use crate::views::{entry_of, is_protected, now, resolved};
use app_core::auto_open::{Target, resolve_field, targets};
use app_core::url::{self, Open};
use app_crypto::secret::SecretString;
use app_model::{Entry, Time, Vault};
use std::path::{Path, PathBuf};

/// The folder of the vault file `path`, as `{DB_DIR}` and relative paths
/// use it.
fn folder(path: &Path) -> String {
    path.parent().unwrap_or(path).to_string_lossy().into_owned()
}

/// M06-39 for `n` missing vaults.
pub(crate) fn m06_39(n: usize) -> String {
    match n {
        1 => "1 vault listed in the AutoOpen group is missing. Check the paths in that group's entries.".to_owned(),
        n => format!("{n} vaults listed in the AutoOpen group are missing. Check the paths in that group's entries."),
    }
}

/// What the open-URL action did (MOD-08.31). Holds no resolved value
/// except `Open`'s, which is a URL without any protected value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum UrlAction {
    /// Nothing to do: an empty URL, or `cmd://` with nothing after it.
    Nothing,
    /// Hand `url` to the system opener (`http`, `https`, `mailto`; text
    /// without a scheme got `http://`).
    Open {
        /// The URL to open.
        url: String,
    },
    /// MSG-08-2: ask Yes or No (default No), with "Remember my choice"
    /// when `remember`, then call `run_url_command` with `command`.
    Ask {
        /// The question.
        message: String,
        /// The command resolved for display (protected values masked),
        /// without `cmd://`, cut after 400 characters.
        command: String,
        /// Offer "Remember my choice": only when the URL is not protected
        /// and resolving changes nothing (F-071, LD-70).
        remember: bool,
        /// The question's clock (seconds since year 1), passed back to
        /// `run_url_command`, so dates and codes in the command resolve as
        /// shown (F-128).
        at: i64,
    },
    /// The command ran (a remembered Yes), or the vault link's vault opened
    /// in front and its unlock started; read the session again.
    Done,
    /// MSG-08-3 or MSG-08-4: show `message`; nothing opened.
    Refused {
        /// The message.
        message: String,
    },
}

/// MSG-08-4 (LD-59).
const MSG_08_4: &str = "App does not open this kind of link.";

/// The URL field resolved in full and for display, and whether a protected
/// value is inside ([`resolve_field`]); a protected URL field shows masked
/// as a whole, so a command question never shows it. At time `at`.
fn url_of(v: &Vault, path: &Path, e: &Entry, at: Time) -> (SecretString, String, bool) {
    let (full, shown, secret) = resolve_field(v, &folder(path), e, "URL", at);
    (full, shown.expose().to_owned(), secret)
}

/// MOD-08.31: the program and arguments of `cmd`, started directly and
/// detached, never through a shell. A program that does not start is
/// silent, as before the question (MOD-08.31 names no message for it).
fn run_command(cmd: &str) {
    let words = url::command_words(cmd);
    let Some((program, args)) = words.split_first() else {
        return;
    };
    let _ = std::process::Command::new(program.expose())
        .args(args.iter().map(SecretString::expose))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

impl Session {
    /// APP-06.25 for the unlocked vault `id`: on a worker thread, each
    /// target whose file exists opens beside the shown vault and unlocks
    /// with its entry's credentials (APP-06.24); M06-39 once when any is
    /// missing. Loops end because an open vault is never opened twice.
    pub(crate) fn auto_open(&self, id: u64) {
        let found = self.with_open(id, |v, path, _| {
            Ok(targets(
                v,
                &folder(path),
                &app_platform::macos::host_name(),
                now(),
            ))
        });
        let (Ok(targets), Some(me)) = (found, self.me.upgrade()) else {
            return;
        };
        if targets.is_empty() {
            return;
        }
        let worker = std::thread::Builder::new()
            .name("auto-open".into())
            .spawn(move || me.open_targets(targets));
        // No thread: nothing opens; the user opens the vaults by hand.
        drop(worker);
    }

    /// APP-06.25 step 6 on this thread; the count of missing vaults.
    pub(crate) fn open_targets(&self, targets: Vec<Target>) -> usize {
        let mut missing = 0;
        for target in targets {
            let path = PathBuf::from(&target.path);
            let opened = std::fs::metadata(&path)
                .is_ok_and(|m| m.is_file())
                .then(|| self.open_beside(&path, false).ok())
                .flatten();
            match opened {
                Some(id) => {
                    self.unlock_passed(id, target.password, target.key_file, target.key_secret)
                }
                None => missing += 1,
            }
            changed();
        }
        if missing > 0 {
            self.set_banner(m06_39(missing));
            changed();
        }
        missing
    }
}

#[uniffi::export]
impl Session {
    /// MOD-08.31 (F-080): the open-URL action for entry `entry`: the URL is
    /// resolved in full and its kind chosen. `http`, `https` and `mailto`
    /// (text without a scheme gets `http://`) come back to open, unless a
    /// protected value is inside (then MSG-08-4, rule 4); a command asks
    /// MSG-08-2 unless a remembered Yes matches (then it runs); a vault
    /// link opens that vault in front and starts its unlock with the
    /// entry's user name as key file and password (call it off the main
    /// thread); a missing vault is MSG-08-3; any other scheme MSG-08-4.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn open_url(&self, vault: u64, entry: String) -> Result<UrlAction, AppError> {
        enum Next {
            Done(UrlAction),
            Link(PathBuf, Option<SecretString>, Option<String>, bool, bool),
        }
        let next = self.with_open(vault, |v, path, _| {
            let e = entry_of(v, &entry)?;
            let at = now();
            let (full, shown, secret) = url_of(v, path, e, at);
            Ok(match url::open_kind(full.expose()) {
                Open::Nothing => Next::Done(UrlAction::Nothing),
                Open::Refused => Next::Done(UrlAction::Refused {
                    message: MSG_08_4.to_owned(),
                }),
                Open::Url(_) if secret => Next::Done(UrlAction::Refused {
                    message: MSG_08_4.to_owned(),
                }),
                Open::Url(u) => Next::Done(UrlAction::Open {
                    url: u.expose().to_owned(),
                }),
                Open::Command(cmd) => {
                    let key = remember_key(v, path, e, &full);
                    if key
                        .as_ref()
                        .is_some_and(|k| self.settings.command_remembered(k))
                    {
                        run_command(cmd.expose());
                        Next::Done(UrlAction::Done)
                    } else {
                        Next::Done(UrlAction::Ask {
                            message: "Run this command?".to_owned(),
                            command: url::question_text(&shown),
                            remember: key.is_some(),
                            at: at.0,
                        })
                    }
                }
                Open::VaultLink(link) => {
                    let dir = folder(path);
                    let target = PathBuf::from(url::vault_link_path(link.expose(), &dir));
                    let raw = e.field("Password").map_or("", |f| f.value.expose());
                    let password = Some(resolved(v, path, e, raw)).filter(|p| !p.is_empty());
                    let (key, _, key_secret) = resolve_field(v, &dir, e, "UserName", now());
                    let key = (!key.is_empty()).then(|| url::vault_link_path(key.expose(), &dir));
                    Next::Link(target, password, key, key_secret, secret)
                }
            })
        })?;
        match next {
            Next::Done(action) => Ok(action),
            Next::Link(target, password, key, key_secret, secret) => {
                let opened = std::fs::metadata(&target)
                    .is_ok_and(|m| m.is_file())
                    .then(|| self.open_beside(&target, true).ok())
                    .flatten();
                let Some(id) = opened else {
                    // MSG-08-3 names the path only when no protected value
                    // is in it (rule 4).
                    let message = if secret {
                        "App cannot find that vault.".to_owned()
                    } else {
                        format!("App cannot find the vault {}.", target.display())
                    };
                    return Ok(UrlAction::Refused { message });
                };
                self.unlock_passed(id, password, key, key_secret);
                changed();
                Ok(UrlAction::Done)
            }
        }
    }

    /// MOD-08.31 after MSG-08-2's Yes: runs entry `entry`'s command, and
    /// with `remember` keeps the Yes on this Mac for this vault, entry and
    /// exact command text (LD-70; never for a protected URL, F-071).
    /// `command` and `at` are the question's ([`UrlAction::Ask`]): the
    /// entry resolves on the question's clock, so dates run as shown.
    /// F-128: when the entry's command no longer reads as `command` (a sync
    /// changed it while the question was open), nothing runs or is kept and
    /// the answer is false: ask again. Otherwise true, also when the program
    /// did not start (no new question for that).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn run_url_command(
        &self,
        vault: u64,
        entry: String,
        command: String,
        at: i64,
        remember: bool,
    ) -> Result<bool, AppError> {
        self.with_open(vault, |v, path, _| {
            let e = entry_of(v, &entry)?;
            let (full, shown, _) = url_of(v, path, e, Time(at));
            let Open::Command(cmd) = url::open_kind(full.expose()) else {
                return Ok(false);
            };
            if url::question_text(&shown) != command {
                return Ok(false);
            }
            if remember && let Some(key) = remember_key(v, path, e, &full) {
                self.settings.remember_command(key);
            }
            run_command(cmd.expose());
            Ok(true)
        })
    }
}

/// LD-70, F-071: the remembered Yes's key of entry `e`, whose URL resolves
/// in full to `full`. `None`, so no "Remember my choice", for a protected
/// URL or one that resolving changes: the key then hashes the exact command,
/// and a sync that changes a field the command uses asks again.
fn remember_key(v: &Vault, path: &Path, e: &Entry, full: &SecretString) -> Option<String> {
    let f = e.field("URL")?;
    (!is_protected(v, "URL", f) && f.value.expose() == full.expose())
        .then(|| url::remember_key(&path.to_string_lossy(), e.uuid, f.value.expose()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UnlockResult;
    use crate::test_dir::TempDir;
    use app_crypto::kdf::Host;
    use app_format::keys::Credentials;
    use app_format::limits::Limits;
    use app_model::{Field, Group, Uuid};
    use std::time::{Duration, Instant};

    fn field(v: &str) -> Field {
        Field {
            value: SecretString::new(v.to_owned()),
            protected: false,
        }
    }

    fn entry(n: u8, fields: &[(&str, &str)]) -> Entry {
        let mut e = Entry::new(Uuid([n; 16]), now());
        for (k, v) in fields {
            e.set_field((*k).to_owned(), field(v));
        }
        e
    }

    /// A small vault (1 AES-KDF round) at `path` with `password`, its root
    /// holding `entries` and, when given, an `AutoOpen` group of `auto`.
    fn write(path: &Path, password: &str, entries: Vec<Entry>, auto: Option<Vec<Entry>>) {
        write_with(path, password, entries, auto, |_| {});
    }

    /// [`write`] with `edit` run on the vault before the save; a KDF cost
    /// in the ask band is approved.
    fn write_with(
        path: &Path,
        password: &str,
        entries: Vec<Entry>,
        auto: Option<Vec<Entry>>,
        edit: impl FnOnce(&mut Vault),
    ) {
        let mut root = Group::new(Uuid([1; 16]), "Root".to_owned(), now());
        root.entries = entries;
        if let Some(auto) = auto {
            let mut g = Group::new(Uuid([2; 16]), "AutoOpen".to_owned(), now());
            g.entries = auto;
            root.groups.push(g);
        }
        let mut vault = Vault::new(root, now());
        vault.encryption.kdf = app_model::Kdf::AesKdf { rounds: 1 };
        edit(&mut vault);
        let p = SecretString::new(password.to_owned());
        let credentials = Credentials {
            password: Some(&p),
            ..Credentials::default()
        };
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: None,
        };
        let mut save = |approval: Option<&app_crypto::kdf::CostReport>| {
            app_format::save(
                &vault,
                &credentials,
                None,
                &mut host,
                &Limits::DEFAULT,
                approval,
            )
        };
        let saved = match save(None) {
            Ok(app_format::Saved::Ask(report)) => save(Some(&report)),
            other => other,
        };
        let Ok(app_format::Saved::File(file)) = saved else {
            panic!("the demo vault saves");
        };
        std::fs::write(path, &file.bytes).unwrap();
    }

    /// The test's own folder, canonical as the session keeps paths
    /// (APP-09.15), removed when it drops (LD-240 (5)).
    fn dir(tag: &str) -> TempDir {
        TempDir::new(&format!("auto-{tag}"))
    }

    fn unlocked(s: &Session, path: &Path) -> bool {
        s.vaults()
            .iter()
            .any(|v| v.path == path.to_string_lossy() && !v.locked)
    }

    fn wait(what: impl Fn() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if what() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// F-079 (SR-10, APP-06.25): unlocking a vault whose AutoOpen group
    /// points at a second vault opens and unlocks that one in the
    /// background (the shown vault stays); a missing one gives M06-39.
    #[test]
    fn f_079_auto_open_after_unlock() {
        let d = dir("open");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        write(
            &a,
            "demo-a",
            Vec::new(),
            Some(vec![
                entry(10, &[("URL", "b.appvault"), ("Password", "demo-b")]),
                entry(11, &[("URL", "missing.appvault"), ("Password", "x")]),
                // Step 1: no user name and no password, skipped.
                entry(12, &[("URL", "b.appvault")]),
            ]),
        );
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        let got = s.unlock(va, Some("demo-a".into()), None).unwrap();
        assert_eq!(got, UnlockResult::Unlocked);
        assert!(wait(|| unlocked(&s, &b)), "{:?}", s.vaults());
        assert!(wait(|| s.take_banner().is_some_and(|t| t == m06_39(1))));
        // The shown vault did not change.
        assert!(
            s.vaults()
                .iter()
                .any(|v| v.path == a.to_string_lossy() && v.shown)
        );
    }

    /// The AutoOpen group of the tests below: `b.appvault` with `demo-b`.
    fn to_b() -> Option<Vec<Entry>> {
        Some(vec![entry(
            10,
            &[("URL", "b.appvault"), ("Password", "demo-b")],
        )])
    }

    /// F-079 (APP-06.25, APP-05.31): a reload or merge from disk runs
    /// auto-open with the disk version's AutoOpen group.
    #[test]
    fn f_079_auto_open_after_reload() {
        let d = dir("reload");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        write(&a, "demo-a", Vec::new(), None);
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        // Another copy of App saved A with an AutoOpen group.
        write(&a, "demo-a", Vec::new(), to_b());
        assert_eq!(
            s.resolve_disk(va, crate::saving::DiskChoice::Reload)
                .unwrap(),
            crate::saving::DiskEvent::Reloaded
        );
        assert!(wait(|| unlocked(&s, &b)), "{:?}", s.vaults());
    }

    /// F-079 (APP-06.22 step 8, MOD-13.8): while the forced key change
    /// waits nothing opens; once the key changed, auto-open runs.
    #[test]
    fn f_079_auto_open_after_the_forced_key_change() {
        use crate::vault_settings::VaultSettings;
        use crate::wizard::Outcome;
        let d = dir("forced");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        write_with(&a, "demo-a", Vec::new(), to_b(), |v| {
            v.meta.master_key_change_force_once = true;
        });
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!s.vaults().iter().any(|v| v.path == b.to_string_lossy()));
        let settings = VaultSettings::new(std::sync::Arc::clone(&s), va);
        let new = "orchid-meteor-pine-quartz-41".to_owned();
        settings.set_password(new.clone()).unwrap();
        settings.set_repeat(new).unwrap();
        assert_eq!(settings.change_password(vec![]).unwrap(), Outcome::Done);
        assert!(s.end_key_change(va).unwrap());
        assert!(wait(|| unlocked(&s, &b)), "{:?}", s.vaults());
    }

    /// F-079 (APP-06.14, APP-06.22 step 8): a vault in the KDF ask band
    /// (129 lanes, CRY-02.14) auto-opens after the user's "Unlock".
    #[test]
    fn f_079_auto_open_after_the_unlock_answer() {
        let d = dir("ask");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        write_with(&a, "demo-a", Vec::new(), to_b(), |v| {
            v.encryption.kdf = app_model::Kdf::Argon2 {
                kind: app_model::Argon2Kind::Id,
                iterations: 1,
                memory_kib: 8 * 129,
                lanes: 129,
            };
        });
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        let got = s.unlock(va, Some("demo-a".into()), None).unwrap();
        assert!(matches!(got, UnlockResult::Ask { .. }), "{got:?}");
        assert_eq!(s.approve_unlock(va).unwrap(), UnlockResult::Unlocked);
        assert!(wait(|| unlocked(&s, &b)), "{:?}", s.vaults());
    }

    /// Rule 4, SR-12: a key file path that a placeholder fills with a
    /// protected value (auto-open, a vault link) is used, but never kept in
    /// the state file and never named in the message; a plain one is kept.
    #[test]
    fn f_080_a_key_file_path_holding_a_secret_is_not_kept() {
        use crate::app_settings::{AppSetting, AppSettingValue};
        let d = dir("keyfile");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        let link = String::from_utf8(url::VAULT_LINK.to_vec()).unwrap();
        let to_b = format!("{link}b.appvault");
        let with_key = |n: u8, url: &str, user: &str| {
            let mut e = entry(n, &[("URL", url), ("UserName", user)]);
            let secret = SecretString::new("demo-kf-secret".into());
            e.set_field(
                "Password".into(),
                Field {
                    value: secret,
                    protected: true,
                },
            );
            e
        };
        let hidden = "{PASSWORD}.appkey";
        let entries = vec![
            with_key(40, &to_b, hidden),
            with_key(41, &to_b, "plain.appkey"),
        ];
        write(
            &a,
            "demo-a",
            entries,
            Some(vec![with_key(10, "b.appvault", hidden)]),
        );
        let s = Session::new();
        s.save_settings(vec![AppSetting {
            key: "recent.remember_keys".to_owned(),
            value: AppSettingValue::Flag { on: true },
        }])
        .unwrap();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        let vb = || {
            s.vaults()
                .into_iter()
                .find(|v| v.path == b.to_string_lossy())
                .map(|v| v.id)
        };
        let got = std::cell::RefCell::new(None);
        let message = || {
            got.replace(None);
            assert!(wait(|| {
                let m = vb().and_then(|id| s.take_message(id).unwrap());
                m.map(|m| got.replace(Some(m.text))).is_some()
            }));
            got.take().unwrap()
        };
        let kept = || s.remembered_keys(vb().unwrap()).unwrap().key_file;
        // Auto-open: B's unlock fails on the missing key file.
        let text = message();
        assert!(!text.contains("demo-kf-secret"), "{text}");
        assert!(text.contains(app_core::refs::MASK), "{text}");
        assert_eq!(kept(), None);
        // A vault link: the same.
        let act = |n: u8| s.open_url(va, crate::views::hex(Uuid([n; 16]))).unwrap();
        assert_eq!(act(40), UrlAction::Done);
        let text = message();
        assert!(!text.contains("demo-kf-secret"), "{text}");
        assert_eq!(kept(), None);
        // A plain key file path is named and kept.
        assert_eq!(act(41), UrlAction::Done);
        assert!(message().contains("plain.appkey"));
        assert_eq!(
            kept(),
            Some(d.join("plain.appkey").to_string_lossy().into())
        );
    }

    /// F-080 (MOD-08.31): the kinds of the open-URL action.
    #[test]
    fn f_080_open_url_follows_mod_08_31() {
        let d = dir("url");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        let link = String::from_utf8(url::VAULT_LINK.to_vec()).unwrap();
        let rows: Vec<(u8, String)> = vec![
            (20, "example.com".into()),
            (21, "https://example.com/a".into()),
            (22, "mailto:a@b.example".into()),
            (23, "javascript:alert(1)".into()),
            (24, "file:///etc/hosts".into()),
            (25, "{S:a}:alert(1)".into()),
            (26, "cmd:///usr/bin/true".into()),
            (27, "cmd://".into()),
            (28, "https://example.com/?p={PASSWORD}".into()),
            (29, format!("{link}missing.appvault")),
            (30, format!("{link}b.appvault")),
            (31, String::new()),
            (32, "https://example.com/demo-secret-path".into()),
            (33, "cmd:///usr/bin/true demo-secret".into()),
            (34, format!("{link}demo-secret-dir/missing.appvault")),
            (35, format!("{link}{{PASSWORD}}.appvault")),
            (36, app_core::refs::MASK.into()),
            (37, "https://example.com/?p={PASSWORD}".into()),
            (
                38,
                "https://example.com/?p={T-CONV:/{PASSWORD}/base64/}".into(),
            ),
            (
                39,
                format!("cmd:///usr/bin/touch {}/{{USERNAME}}", d.display()),
            ),
        ];
        // The vault with `user` as row 39's user name (a sync changes it).
        let entries = |user: &str| -> Vec<Entry> {
            rows.iter()
                .map(|(n, u)| {
                    let mut e = entry(*n, &[("URL", u), ("a", "javascript")]);
                    if *n == 30 {
                        e.set_field("Password".into(), field("demo-b"));
                    }
                    if *n == 39 {
                        e.set_field("UserName".into(), field(user));
                    }
                    if [32, 33, 34, 36].contains(n) {
                        e.set_field(
                            "URL".into(),
                            Field {
                                value: SecretString::new(u.clone()),
                                protected: true,
                            },
                        );
                    }
                    let secret = match n {
                        28 | 38 => Some("demo-secret"),
                        35 => Some("demo-secret-pw"),
                        // A protected password that is the mask itself.
                        37 => Some(app_core::refs::MASK),
                        _ => None,
                    };
                    if let Some(p) = secret {
                        e.set_field(
                            "Password".into(),
                            Field {
                                value: SecretString::new(p.into()),
                                protected: true,
                            },
                        );
                    }
                    e
                })
                .collect()
        };
        write(&a, "demo-a", entries("first"), None);
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        let act = |n: u8| untimed(s.open_url(va, crate::views::hex(Uuid([n; 16]))).unwrap());
        let open = |u: &str| UrlAction::Open { url: u.to_owned() };
        let refused = UrlAction::Refused {
            message: MSG_08_4.to_owned(),
        };
        assert_eq!(act(20), open("http://example.com"));
        assert_eq!(act(21), open("https://example.com/a"));
        assert_eq!(act(22), open("mailto:a@b.example"));
        for n in [23, 24, 25] {
            assert_eq!(act(n), refused, "{n}");
        }
        let ask = |command: &str, remember| UrlAction::Ask {
            message: "Run this command?".into(),
            command: command.into(),
            remember,
            at: 0,
        };
        assert_eq!(act(26), ask("/usr/bin/true", true));
        assert_eq!(act(27), UrlAction::Nothing);
        // A protected value never crosses to Swift (rule 4): not in a
        // placeholder, not as the URL field itself, not in the question.
        assert_eq!(act(28), refused);
        assert_eq!(act(32), refused);
        assert_eq!(act(33), ask(app_core::refs::MASK, false));
        assert_eq!(act(36), refused);
        assert_eq!(act(37), refused);
        // A transform hides the mask; the display still differs.
        assert_eq!(act(38), refused);
        assert!(
            matches!(act(29), UrlAction::Refused { message } if message.contains("missing.appvault"))
        );
        // MSG-08-3 names no path holding a protected value (F-080, rule 4).
        for n in [34, 35] {
            assert_eq!(
                act(n),
                UrlAction::Refused {
                    message: "App cannot find that vault.".into()
                },
                "{n}"
            );
        }
        assert_eq!(act(31), UrlAction::Nothing);
        // The vault link opens B in front and unlocks it with the entry's password.
        assert_eq!(act(30), UrlAction::Done);
        assert!(unlocked(&s, &b));
        assert!(
            s.vaults()
                .iter()
                .any(|v| v.path == b.to_string_lossy() && v.shown)
        );
        // A remembered Yes runs without the question (LD-70).
        assert!(
            s.run_url_command(
                va,
                crate::views::hex(Uuid([26; 16])),
                "/usr/bin/true".into(),
                now().0,
                true
            )
            .unwrap()
        );
        assert_eq!(act(26), UrlAction::Done);
        // F-071: a protected URL is never remembered, even when asked.
        let id = |n: u8| crate::views::hex(Uuid([n; 16]));
        let masked = app_core::refs::MASK.to_owned();
        assert!(
            s.run_url_command(va, id(33), masked, now().0, true)
                .unwrap()
        );
        assert_eq!(act(33), ask(app_core::refs::MASK, false));
        // F-071, LD-70: a command a placeholder changes is never remembered,
        // so a sync that changes the field asks again and runs nothing.
        let touched = |name: &str| d.join(name);
        let first = format!("/usr/bin/touch {}", touched("first").display());
        assert_eq!(act(39), ask(&first, false));
        let yes = s.run_url_command(va, id(39), first.clone(), now().0, true);
        assert!(yes.unwrap());
        assert!(wait(|| touched("first").exists()));
        assert_eq!(act(39), ask(&first, false));
        write(&a, "demo-a", entries("second"), None);
        assert_eq!(
            s.resolve_disk(va, crate::saving::DiskChoice::Reload)
                .unwrap(),
            crate::saving::DiskEvent::Reloaded
        );
        let second = format!("/usr/bin/touch {}", touched("second").display());
        assert_eq!(act(39), ask(&second, false));
        std::thread::sleep(Duration::from_millis(200));
        assert!(!touched("second").exists());
    }

    /// F-128 (MOD-08.31, LD-238 (1)): a sync changes the command while
    /// MSG-08-2 is open. Yes then runs and keeps nothing and answers false,
    /// so the question comes again with the new command; Yes to that runs
    /// it.
    #[test]
    fn f_128_a_command_changed_after_the_question_does_not_run() {
        let d = dir("f128");
        let a = d.join("a.appvault");
        let cmd = |name: &str| format!("cmd:///usr/bin/touch {}", d.join(name).display());
        let entries = |name: &str| vec![entry(50, &[("URL", cmd(name).as_str())])];
        write(&a, "demo-a", entries("shown"), None);
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        let id = crate::views::hex(Uuid([50; 16]));
        let shown = |name: &str| url::question_text(&cmd(name));
        let ask = |name: &str| UrlAction::Ask {
            message: "Run this command?".into(),
            command: shown(name),
            remember: true,
            at: 0,
        };
        let open = || untimed(s.open_url(va, id.clone()).unwrap());
        assert_eq!(open(), ask("shown"));
        // The sync while the question is open.
        write(&a, "demo-a", entries("swapped"), None);
        assert_eq!(
            s.resolve_disk(va, crate::saving::DiskChoice::Reload)
                .unwrap(),
            crate::saving::DiskEvent::Reloaded
        );
        let ran = s.run_url_command(va, id.clone(), shown("shown"), now().0, true);
        assert!(!ran.unwrap());
        std::thread::sleep(Duration::from_millis(200));
        assert!(!d.join("shown").exists() && !d.join("swapped").exists());
        assert_eq!(open(), ask("swapped"));
        let ran = s.run_url_command(va, id.clone(), shown("swapped"), now().0, true);
        assert!(ran.unwrap());
        assert!(wait(|| d.join("swapped").exists()));
        assert_eq!(open(), UrlAction::Done);
    }

    /// `action` with an `Ask`'s clock set to 0, to compare.
    fn untimed(action: UrlAction) -> UrlAction {
        match action {
            UrlAction::Ask {
                at: _,
                message,
                command,
                remember,
            } => UrlAction::Ask {
                message,
                command,
                remember,
                at: 0,
            },
            other => other,
        }
    }

    /// F-128 (MOD-08.10, MOD-08.31): false means only "changed, ask again".
    /// Yes a second after the question runs a dated command as shown (it
    /// resolves on the question's clock), and a program that does not start
    /// answers true, so the question does not come back without end.
    #[test]
    fn f_128_yes_asks_again_only_for_a_changed_command() {
        let d = dir("f128-again");
        let a = d.join("a.appvault");
        let dated = format!("cmd:///usr/bin/touch {}/ran-{{DT_SIMPLE}}", d.display());
        let entries = vec![
            entry(51, &[("URL", dated.as_str())]),
            entry(52, &[("URL", "cmd:///nonexistent/demo-program")]),
        ];
        write(&a, "demo-a", entries, None);
        let s = Session::new();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        let yes = |n: u8, later: bool| {
            let id = crate::views::hex(Uuid([n; 16]));
            let UrlAction::Ask { command, at, .. } = s.open_url(va, id.clone()).unwrap() else {
                panic!("a command asks");
            };
            assert!(!later || wait(|| now().0 > at));
            (
                s.run_url_command(va, id, command.clone(), at, false)
                    .unwrap(),
                command,
            )
        };
        let (ran, shown) = yes(51, true);
        assert!(ran, "{shown}");
        let made = shown.strip_prefix("/usr/bin/touch ").unwrap();
        assert!(wait(|| Path::new(made).exists()), "{shown}");
        assert!(yes(52, false).0);
    }

    /// F-129 (LD-238 (2)): the regex probe of security/findings.md, a
    /// transform that gives the same text for the protected password and
    /// for the mask. The URL is refused (MSG-08-4), and a key file path
    /// built so is neither named nor kept, as any holding a protected value.
    #[test]
    fn f_129_a_transform_cannot_pass_a_protected_value_as_plain() {
        use crate::app_settings::{AppSetting, AppSettingValue};
        let d = dir("f129");
        let (a, b) = (d.join("a.appvault"), d.join("b.appvault"));
        write(&b, "demo-b", Vec::new(), None);
        let link = String::from_utf8(url::VAULT_LINK.to_vec()).unwrap();
        let probe = "{T-REPLACE-RX:/{PASSWORD}/^.{6}$/six/}";
        let with_pw = |n: u8, url: &str, user: &str| {
            let mut e = entry(n, &[("URL", url), ("UserName", user)]);
            let secret = SecretString::new("demo-s".into());
            e.set_field(
                "Password".into(),
                Field {
                    value: secret,
                    protected: true,
                },
            );
            e
        };
        let entries = vec![
            with_pw(60, &format!("https://example.com/?p={probe}"), ""),
            with_pw(61, &format!("{link}b.appvault"), &format!("{probe}.appkey")),
        ];
        write(&a, "demo-a", entries, None);
        let s = Session::new();
        s.save_settings(vec![AppSetting {
            key: "recent.remember_keys".to_owned(),
            value: AppSettingValue::Flag { on: true },
        }])
        .unwrap();
        let va = s.open(a.to_string_lossy().into_owned()).unwrap();
        s.unlock(va, Some("demo-a".into()), None).unwrap();
        let act = |n: u8| s.open_url(va, crate::views::hex(Uuid([n; 16]))).unwrap();
        let refused = UrlAction::Refused {
            message: MSG_08_4.to_owned(),
        };
        assert_eq!(act(60), refused);
        assert_eq!(act(61), UrlAction::Done);
        let vb = s
            .vaults()
            .into_iter()
            .find(|v| v.path == b.to_string_lossy())
            .unwrap()
            .id;
        let got = std::cell::RefCell::new(None);
        assert!(wait(|| {
            let m = s.take_message(vb).unwrap();
            m.map(|m| got.replace(Some(m.text))).is_some()
        }));
        let text = got.take().unwrap();
        assert!(!text.contains("six.appkey"), "{text}");
        assert_eq!(s.remembered_keys(vb).unwrap().key_file, None);
    }
}
