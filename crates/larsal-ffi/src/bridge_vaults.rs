//! E7-S2: the browser bridge's vault side over Larsal's session (INT-02), and
//! its dialogs for the window: the Connect dialog (INT-02.4) and the site
//! access prompt (INT-02.18). One line of dialogs for the whole app
//! (INT-02.15); the window reads [`Session::browser_question`] when the
//! session changes and answers with [`Session::answer_browser_connect`] or
//! [`Session::answer_browser_access`], as for SSH key use (INT-06.34).
//! The words come from Rust; titles and user names are plain text
//! (AT-E01), never a password.

use crate::session::{self, Session};
use larsal_browser::{
    Answer, Changed, OpenVault, Options, Prompts, Question, SharedHandler, VaultSide, Vaults,
};
use larsal_model::{Time, Vault};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

/// MI02-02.
const NAME_TAKEN: &str = "A browser with this name is already connected. Choose another name.";

/// The app's one line of bridge dialogs (INT-02.15). A change of the
/// dialog on screen tells the window; a new one brings Larsal to the front.
pub(crate) fn line() -> &'static Arc<Prompts> {
    static LINE: OnceLock<Arc<Prompts>> = OnceLock::new();
    LINE.get_or_init(|| {
        Arc::new(Prompts::new(
            Arc::new(Instant::now),
            Box::new(|| {
                session::changed();
                if line().current().is_some() {
                    session::front();
                }
            }),
        ))
    })
}

/// The vault side for the bridge over `session` (the handler the browser
/// integration's `Bridge::shared` takes).
#[must_use]
pub fn handler(session: Weak<Session>) -> Arc<dyn SharedHandler> {
    Arc::new(VaultSide::new(
        Arc::new(SessionVaults(session)),
        Arc::clone(line()),
    ))
}

/// Larsal's open vaults as the bridge reaches them.
struct SessionVaults(Weak<Session>);

impl Vaults for SessionVaults {
    fn list(&self) -> Vec<OpenVault> {
        let Some(s) = self.0.upgrade() else {
            return Vec::new();
        };
        s.with_slots(|slots, shown| {
            slots
                .iter()
                .map(|(id, vault, path)| OpenVault {
                    id: *id,
                    name: path
                        .file_stem()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    shown: shown == Some(*id),
                    // MOD-13.8: `with_slots` gives `None` behind the forced
                    // prompt too.
                    unlocked: vault.is_some(),
                })
                .collect()
        })
    }

    fn with(&self, id: u64, f: &mut dyn FnMut(&mut Vault, &str) -> Changed) -> bool {
        let Some(s) = self.0.upgrade() else {
            return false;
        };
        if !self.list().iter().any(|v| v.id == id && v.unlocked) {
            return false;
        }
        let mut data = false;
        let done = s
            .with_share(id, |slot| {
                let Some(vault) = slot.vault else {
                    return false;
                };
                let dir = slot
                    .path
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // INT-02.9: a view-state change is kept for the next save
                // and marks nothing; a data change marks the vault changed.
                // F-278: a look changes nothing, so a share import tried
                // meanwhile still lands.
                let what = f(vault, &dir);
                if what != Changed::Nothing {
                    *slot.version = slot.version.wrapping_add(1);
                }
                if what == Changed::Data {
                    slot.edit.count_change();
                    data = true;
                }
                true
            })
            .unwrap_or(false);
        if data {
            session::changed();
        }
        done
    }

    fn options(&self) -> Options {
        let Some(s) = self.0.upgrade() else {
            return Options::default();
        };
        let flag = |key: &str| s.settings.flag(key.to_owned());
        Options {
            notify: flag("browser.notify"),
            match_scheme: flag("browser.match_scheme"),
            best_only: flag("browser.best_match_only"),
            allow_expired: flag("browser.allow_expired"),
            search_all: flag("browser.search_all_vaults"),
            never_ask: flag("browser.never_ask_access"),
            skip_http_ask: flag("browser.skip_http_auth_ask"),
            extra_fields: flag("browser.extra_fields"),
        }
    }

    fn now(&self) -> Time {
        crate::views::now()
    }

    fn computer(&self) -> String {
        let name = larsal_platform::macos::host_name();
        name.strip_suffix(".local").unwrap_or(&name).to_owned()
    }

    fn notify(&self, _text: &str) {
        // ponytail: MI02-13 is made and rate-limited in larsal-browser; posting
        // it needs macOS's notification permission prompt, a visible step
        // (W-08). Post it here once that step is approved.
    }
}

/// One row of the site access prompt (INT-02.18). Never a protected value:
/// a hidden title or user name comes empty with its mark.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserQuestionRow {
    /// The title, resolved for display, plain text; empty when hidden.
    pub title: String,
    /// The user name, resolved for display, plain text; empty when hidden.
    pub username: String,
    /// The title is protected or reads a protected value: the row shows the
    /// mask of hidden values (LD-207).
    pub title_hidden: bool,
    /// The same for the user name.
    pub username_hidden: bool,
    /// The host of the entry's URL for its logo; empty when none or hidden.
    pub host: String,
    /// The standard icon number; -1 for a custom icon.
    pub icon: i32,
    /// The custom icon's name, if any.
    pub custom_icon: Option<String>,
}

/// The bridge dialog on screen: the Connect dialog (`connect`, frame
/// `dialogs-connect-a-browser`) or the site access prompt (`access`,
/// frame `dialogs-browser-asks-for-an-entry`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserQuestion {
    /// For the answer.
    pub id: u64,
    /// The vault it shows over.
    pub vault: u64,
    /// `connect` or `access`.
    pub kind: String,
    /// "Connect a new browser?" or "‹browser› asks for a sign-in on ‹P›".
    pub title: String,
    /// The text under the title.
    pub text: String,
    /// Connect: the Name field's first value; empty for `access`.
    pub name: String,
    /// Connect: MI02-01 with the four pairing words; empty for `access`.
    pub words: String,
    /// Access: one row per entry, each starting checked.
    pub rows: Vec<BrowserQuestionRow>,
    /// Access: "Remember for ‹P›", or `None` when the box is hidden.
    pub remember: Option<String>,
    /// Access: MI02-05 or MI02-06 above the rows (INT-02.19).
    pub line: Option<String>,
}

fn question(id: u64, q: Question) -> BrowserQuestion {
    match q {
        Question::Connect(c) => BrowserQuestion {
            id,
            vault: c.vault,
            kind: "connect".into(),
            title: "Connect a new browser?".into(),
            text: c.text,
            name: c.name,
            words: c.words,
            rows: Vec::new(),
            remember: None,
            line: None,
        },
        Question::Access(a) => BrowserQuestion {
            id,
            vault: a.vault,
            kind: "access".into(),
            title: a.title,
            text: a.text,
            name: String::new(),
            words: String::new(),
            rows: a
                .rows
                .into_iter()
                .map(|r| BrowserQuestionRow {
                    title: r.title,
                    username: r.username,
                    title_hidden: r.title_hidden,
                    username_hidden: r.username_hidden,
                    host: r.host,
                    icon: r.icon,
                    custom_icon: r.custom_icon,
                })
                .collect(),
            remember: a.remember,
            line: a.line,
        },
    }
}

#[uniffi::export]
impl Session {
    /// The bridge dialog to show now, if any (INT-02.15).
    #[must_use]
    pub fn browser_question(&self) -> Option<BrowserQuestion> {
        line().current().map(|(id, q)| question(id, q))
    }

    /// The Connect dialog's answer: `Some(name)` is Connect, `None` Deny or
    /// Escape. A dialog that ended meanwhile ignores it.
    pub fn answer_browser_connect(&self, id: u64, name: Option<String>) {
        let answer = name.map_or(Answer::Deny { remember: false }, Answer::Connect);
        line().answer(id, answer);
    }

    /// The site access prompt's answer: Allow Selected (`allow`) with each
    /// row checked or not, or Deny; and the Remember box (INT-02.18).
    pub fn answer_browser_access(&self, id: u64, allow: bool, checked: Vec<bool>, remember: bool) {
        let answer = if allow {
            Answer::Allow { checked, remember }
        } else {
            Answer::Deny { remember }
        };
        line().answer(id, answer);
    }

    /// INT-02.2 for the Connect dialog's Name field in vault `vault`:
    /// `None` when Connect may be pressed; `Some("")` while the name is not
    /// valid (Connect disabled); `Some(MI02-02)` when the name is taken.
    #[must_use]
    pub fn browser_name_problem(&self, vault: u64, name: String) -> Option<String> {
        let Some(name) = larsal_browser::valid_name(&name) else {
            return Some(String::new());
        };
        let taken = self
            .with_vault(vault, |v| {
                Ok(larsal_core::settings::associations(v)
                    .iter()
                    .any(|a| a.name == name))
            })
            .unwrap_or(false);
        taken.then(|| NAME_TAKEN.to_owned())
    }
}

/// Tests (F-278): the bridge's door to a vault, as the bridge uses it.
#[cfg(test)]
pub(crate) fn bridge_door(
    s: &Arc<Session>,
    id: u64,
    f: &mut dyn FnMut(&mut Vault, &str) -> Changed,
) -> bool {
    SessionVaults(Arc::downgrade(s)).with(id, f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UnlockResult;
    use crate::test_dir::TempDir;
    use larsal_browser::{Live, Request};
    use larsal_model::json::{self, Map, Value};
    use std::path::Path;

    const K: [u8; 32] = [0x5A; 32];

    /// The dialog line is the process's one: tests that show a dialog take
    /// turns, so one test's screen never answers another's dialog.
    static LINE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn turn() -> std::sync::MutexGuard<'static, ()> {
        LINE.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn demo(name: &str) -> (Arc<Session>, u64, TempDir) {
        let folder = TempDir::new(&format!("bridge-{name}"));
        let path = folder.join(format!("{name}.larsalvault"));
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/option-a-personal.larsalvault"),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(
            s.unlock(v, Some("demo-pass-7".into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        (s, v, folder)
    }

    fn send(h: &dyn SharedHandler, live: &Live, kind: &str, fields: &str) -> Result<Map, u8> {
        let text = format!(r#"{{"type":"{kind}","req":1{fields}}}"#);
        let Ok(Value::Object(content)) = json::from_str(&text) else {
            panic!("{text}")
        };
        h.handle(&Request {
            kind,
            content: &content,
            browser: "Firefox",
            identity: Some(&K),
            session: live,
            keys: (&[1; 32], &[2; 32]),
        })
    }

    /// F-279 (1): a fresh settings store gives the card's defaults, and each
    /// S-BRW key the vault side reads reaches its option (a misspelled key
    /// would read as off).
    #[test]
    fn f279_1_every_s_brw_setting_reaches_the_vault_side() {
        let s = Session::new();
        let side = SessionVaults(Arc::downgrade(&s));
        assert_eq!(side.options(), Options::default());
        let folder = TempDir::new("bridge-options");
        std::fs::write(
            folder.join("settings.json"),
            r#"{"browser.notify":false,"browser.match_scheme":false,"browser.best_match_only":true,"browser.allow_expired":true,"browser.search_all_vaults":true,"browser.never_ask_access":true,"browser.skip_http_auth_ask":true,"browser.extra_fields":false}"#,
        )
        .unwrap();
        s.settings.use_folder(folder.to_string_lossy().into_owned());
        assert_eq!(
            side.options(),
            Options {
                notify: false,
                match_scheme: false,
                best_only: true,
                allow_expired: true,
                search_all: true,
                never_ask: true,
                skip_http_ask: true,
                extra_fields: false,
            }
        );
    }

    fn unsaved(s: &Session, v: u64) -> bool {
        s.with_edit(v, |_, _, _, es| Ok(es.unsaved())).unwrap()
    }

    #[test]
    fn t01_int02_6_connect_through_the_window_stores_the_association_as_a_data_change() {
        let _turn = turn();
        let (s, v, _folder) = demo("connect");
        let h = handler(Arc::downgrade(&s));
        let status = send(&*h, &Live::default(), "status", "").unwrap();
        let first = status["vaults"].as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(first["name"].as_str(), Some("connect"));
        assert_eq!(first["state"].as_str(), Some("unlocked"));
        let screen = {
            let s = s.clone();
            std::thread::spawn(move || {
                loop {
                    if let Some(q) = s.browser_question() {
                        assert_eq!(q.kind, "connect");
                        assert_eq!(
                            s.browser_name_problem(q.vault, "  ".into()),
                            Some(String::new())
                        );
                        assert_eq!(s.browser_name_problem(q.vault, q.name.clone()), None);
                        s.answer_browser_connect(q.id, Some("Firefox on Test".into()));
                        return q;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        let reply = send(&*h, &Live::default(), "connect", "").unwrap();
        let q = screen.join().unwrap();
        assert!(q.words.starts_with("Check that the extension shows: "));
        assert_eq!(reply["name"].as_str(), Some("Firefox on Test"));
        assert!(unsaved(&s, v), "a data change (APP-05)");
        assert_eq!(
            s.browser_name_problem(v, "Firefox on Test".into())
                .as_deref(),
            Some(NAME_TAKEN)
        );
        assert!(s.browser_question().is_none());
    }

    #[test]
    fn int02_9_10_find_and_get_use_the_session_and_last_use_marks_nothing() {
        let (s, v, _folder) = demo("find");
        let h = handler(Arc::downgrade(&s));
        assert_eq!(
            send(
                &*h,
                &Live::default(),
                "logins.find",
                r#","url":"https://github.com/""#
            ),
            Err(8)
        );
        s.with_edit(v, |vault, _, _, _| {
            let key = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, &K);
            assert!(larsal_core::settings::add_association(
                vault,
                "demo",
                &key,
                "2026-11-01T00:00:00Z",
                crate::views::now()
            ));
            Ok(())
        })
        .unwrap();
        let found = send(
            &*h,
            &Live::default(),
            "logins.find",
            r#","url":"https://github.com/","top_url":"https://github.com/""#,
        )
        .unwrap();
        let entries = found["entries"].as_array().unwrap();
        let github = entries
            .iter()
            .map(|e| e.as_object().unwrap())
            .find(|e| e["access"].as_str() == Some("allowed"))
            .expect("the demo GitHub entry allows github.com");
        let id = github["id"].as_str().unwrap().to_owned();
        let vid = github["vault"].as_str().unwrap().to_owned();
        let before = unsaved(&s, v);
        let got = send(
            &*h,
            &Live::default(),
            "logins.get",
            &format!(r#","ids":[{{"vault":"{vid}","id":"{id}"}}],"url":"https://github.com/","top_url":"https://github.com/""#),
        )
        .unwrap();
        assert!(
            !got["entries"].as_array().unwrap()[0].as_object().unwrap()["password"]
                .as_str()
                .unwrap()
                .is_empty()
        );
        assert_eq!(unsaved(&s, v), before, "last use is a view-state change");
        assert!(
            s.with_vault(v, |vault| Ok(vault
                .meta
                .custom_data
                .get("_LAST_USED_demo")
                .is_some()))
                .unwrap()
        );
        s.lock(v).unwrap();
        assert_eq!(
            send(
                &*h,
                &Live::default(),
                "logins.find",
                r#","url":"https://github.com/""#
            ),
            Err(1)
        );
    }

    /// V-1: what Swift reads of a prompt row never holds a protected value.
    /// With the vault protecting user names, the demo GitHub entry asked
    /// for on another site (an outside fill, INT-02.22) shows its title and
    /// logo host, and its user name empty with its mark.
    #[test]
    fn v1_int02_18_the_prompt_row_swift_reads_hides_a_protected_user_name() {
        let _turn = turn();
        let (s, v, _folder) = demo("rows");
        let h = handler(Arc::downgrade(&s));
        let (vid, id, user) = s
            .with_edit(v, |vault, _, _, _| {
                let key = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, &K);
                let now = crate::views::now();
                assert!(larsal_core::settings::add_association(
                    vault,
                    "demo",
                    &key,
                    "2026-11-01T00:00:00Z",
                    now
                ));
                vault.meta.memory_protection.user_name = true;
                let e = vault
                    .root
                    .all_entries()
                    .find(|e| e.value("Title") == "GitHub")
                    .expect("the demo GitHub entry");
                Ok((
                    larsal_browser::vault_id(vault),
                    larsal_browser::entry_id(e.uuid),
                    e.value("UserName").to_owned(),
                ))
            })
            .unwrap();
        assert!(!user.is_empty());
        let screen = {
            let s = s.clone();
            std::thread::spawn(move || {
                loop {
                    if let Some(q) = s.browser_question() {
                        s.answer_browser_access(q.id, false, Vec::new(), false);
                        return q;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        let got = send(
            &*h,
            &Live::default(),
            "logins.get",
            &format!(
                r#","ids":[{{"vault":"{vid}","id":"{id}"}}],"url":"https://example.org/","top_url":"https://example.org/""#
            ),
        );
        assert_eq!(got, Err(6));
        let q = screen.join().unwrap();
        assert_eq!(q.kind, "access");
        let row = &q.rows[0];
        assert_eq!((row.title.as_str(), row.title_hidden), ("GitHub", false));
        assert_eq!((row.username.as_str(), row.username_hidden), ("", true));
        assert_eq!(row.host, "github.com");
        assert!(!format!("{q:?}").contains(&user), "{q:?}");
    }

    /// Verify E7-S2 second pass (C2R3-01, F-635): the bridge passes a hidden
    /// title's mark on to Swift. Verify's probe, now a project test.
    #[test]
    fn verify_c2r3_01_the_prompt_row_swift_reads_hides_a_protected_title() {
        let _turn = turn();
        let (s, v, _folder) = demo("rows-title");
        let h = handler(Arc::downgrade(&s));
        let (vid, id, title) = s
            .with_edit(v, |vault, _, _, _| {
                let key = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, &K);
                let now = crate::views::now();
                assert!(larsal_core::settings::add_association(
                    vault,
                    "demo",
                    &key,
                    "2026-11-01T00:00:00Z",
                    now
                ));
                vault.meta.memory_protection.title = true;
                let e = vault
                    .root
                    .all_entries()
                    .find(|e| e.value("Title") == "GitHub")
                    .expect("the demo GitHub entry");
                Ok((
                    larsal_browser::vault_id(vault),
                    larsal_browser::entry_id(e.uuid),
                    e.value("Title").to_owned(),
                ))
            })
            .unwrap();
        assert_eq!(title, "GitHub");
        let screen = {
            let s = s.clone();
            std::thread::spawn(move || {
                loop {
                    if let Some(q) = s.browser_question() {
                        s.answer_browser_access(q.id, false, Vec::new(), false);
                        return q;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        let got = send(
            &*h,
            &Live::default(),
            "logins.get",
            &format!(
                r#","ids":[{{"vault":"{vid}","id":"{id}"}}],"url":"https://example.org/","top_url":"https://example.org/""#
            ),
        );
        assert_eq!(got, Err(6));
        let q = screen.join().unwrap();
        assert_eq!(q.kind, "access");
        let row = &q.rows[0];
        assert_eq!((row.title.as_str(), row.title_hidden), ("", true));
        assert!(!row.username_hidden);
        assert_eq!(row.host, "github.com");
        assert!(!format!("{q:?}").contains(&title), "{q:?}");
    }

    fn icons(g: &mut larsal_model::Group, n: i32) {
        for e in &mut g.entries {
            e.icon = larsal_model::Icon::Standard(n);
        }
        for c in &mut g.groups {
            icons(c, n);
        }
    }

    /// F-635 (C2R3-01): the prompt row Swift reads carries the entry's
    /// standard icon number (INT-02.18), not a default one.
    #[test]
    fn f635_int02_18_the_prompt_row_swift_reads_carries_the_icon_number() {
        let _turn = turn();
        let (s, v, _folder) = demo("rows-icon");
        let h = handler(Arc::downgrade(&s));
        let (vid, id) = s
            .with_edit(v, |vault, _, _, _| {
                let key = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, &K);
                let now = crate::views::now();
                assert!(larsal_core::settings::add_association(
                    vault,
                    "demo",
                    &key,
                    "2026-11-01T00:00:00Z",
                    now
                ));
                icons(&mut vault.root, 42);
                let e = vault
                    .root
                    .all_entries()
                    .find(|e| e.value("Title") == "GitHub")
                    .expect("the demo GitHub entry");
                Ok((
                    larsal_browser::vault_id(vault),
                    larsal_browser::entry_id(e.uuid),
                ))
            })
            .unwrap();
        let screen = {
            let s = s.clone();
            std::thread::spawn(move || {
                loop {
                    if let Some(q) = s.browser_question() {
                        s.answer_browser_access(q.id, false, Vec::new(), false);
                        return q;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        let got = send(
            &*h,
            &Live::default(),
            "logins.get",
            &format!(
                r#","ids":[{{"vault":"{vid}","id":"{id}"}}],"url":"https://example.org/","top_url":"https://example.org/""#
            ),
        );
        assert_eq!(got, Err(6));
        let q = screen.join().unwrap();
        assert_eq!(
            (q.rows[0].icon, q.rows[0].custom_icon.as_deref()),
            (42, None)
        );
    }
}
