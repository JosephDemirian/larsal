//! Browser integration in the Mac app (E7-S6; INT-01.6 to INT-01.15,
//! APP-01.30): Larsal's two sockets follow S-BRW-01 and the Safari switch,
//! and the settings page's browser switches write and remove each
//! browser's setup file.
//!
//! Guarantees: no socket listens while S-BRW-01 is off, and the rewrite at
//! start runs only while it is on; the browser switches write and remove
//! setup files on the page's OK (APP-01.30). The Safari socket listens only
//! in a build signed with a team id (Swift reads it from Larsal's own
//! signature); a launch started by a test keeps its sockets and setup files
//! in the test's instance folder (`<folder>/home` stands for the home
//! folder, `<folder>/group` for the app-group container), never the user's
//! (INT-01.10). Only the page's words and switch states cross to Swift.
//! The bridge answers over the app's session with the vault side of
//! E7-S2 (bridge_vaults.rs, LD-556), and tells the bridge-socket sessions
//! when a vault they may use locks or unlocks (INT-01.46, [`Notice`]).

use crate::instance;
use crate::larsal_settings::LarsalSettingsStore;
use crate::session::Session;
use larsal_browser::{
    ADDON_ID, Bridge, Browser, Clock, Listeners, MI01_04, Manifests, STORE_IDS, SharedHandler,
    Signed, Trouble,
};
use larsal_crypto::base64::{self, Form};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Instant;

/// The app's browser integrations, for the notices (INT-01.46).
static LIVE: Mutex<Vec<Weak<Browsers>>> = Mutex::new(Vec::new());

/// `browsers`, now also told the notices.
fn live(browsers: Arc<Browsers>) -> Arc<Browsers> {
    let mut all = LIVE.lock().unwrap_or_else(PoisonError::into_inner);
    all.retain(|b| b.strong_count() > 0);
    all.push(Arc::downgrade(&browsers));
    browsers
}

/// INT-01.46: a `locked` or `unlocked` notice of one vault, made while the
/// vault is open: the browser keys it stores (public keys) and whether it
/// is the shown vault.
pub(crate) struct Notice {
    keys: Vec<String>,
    shown: bool,
}

impl Notice {
    /// `None` when `vault` stores no browser key: no session may use it.
    pub(crate) fn of(vault: &larsal_model::Vault, shown: bool) -> Option<Self> {
        let keys: Vec<String> = larsal_core::settings::associations(vault)
            .into_iter()
            .map(|a| a.value)
            .collect();
        (!keys.is_empty()).then_some(Self { keys, shown })
    }

    /// Tells `event` to each bridge-socket session of the app's browser
    /// integrations that may use the vault (INT-01.29: the vault stores
    /// the session's proven key, and it is the shown vault or S-BRW-14 is
    /// on). Off the caller's thread: a write may wait for a slow reader.
    pub(crate) fn tell(self, event: &'static str) {
        let all: Vec<Arc<Browsers>> = LIVE
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        if all.is_empty() {
            return;
        }
        // ponytail: a thread per notice, so two can arrive out of order; the
        // extension reads the state again on each (INT-11), so the last read
        // is right. A queue if a notice ever carries more.
        let _ = std::thread::Builder::new()
            .name("larsal-bridge-notice".into())
            .spawn(move || {
                let stored = |key: Option<&[u8; 32]>| {
                    key.is_some_and(|k| self.keys.contains(&base64::encode(Form::Padded, k)))
                };
                for b in all {
                    if self.shown || b.flag("browser.search_all_vaults") {
                        b.state().listeners.notify(event, stored);
                    }
                }
            });
    }
}

/// A message for the browser page (INT-01's MI01 table).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserNote {
    /// `MI01-01` and so on.
    pub id: String,
    /// Larsal's words.
    pub text: String,
}

impl From<Trouble> for BrowserNote {
    fn from(t: Trouble) -> Self {
        Self {
            id: t.id.to_owned(),
            text: t.text,
        }
    }
}

/// One browser's switch (INT-01.8): on exactly when Larsal's setup file is in
/// its folder.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserSwitch {
    /// `Chrome`, `Firefox`, `Edge`, `Brave` or `Vivaldi`.
    pub browser: String,
    /// The switch.
    pub on: bool,
}

/// What the browser page shows (frame `settings-settings-browser-integration`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserPage {
    /// The browsers' switches, Safari aside.
    pub switches: Vec<BrowserSwitch>,
    /// INT-01.15: false in a build without a team id; the Safari switch
    /// then shows disabled with `safari_note`.
    pub safari_allowed: bool,
    /// MI01-04 when the Safari switch is disabled.
    pub safari_note: Option<String>,
    /// MI01-01 (the rewrite at start failed), MI01-02, MI01-05 and MI01-06
    /// while S-BRW-01 is on.
    pub notes: Vec<BrowserNote>,
}

/// The vault side over the app's one session (INT-02, E7-S2).
fn app_vaults() -> Arc<dyn SharedHandler> {
    crate::bridge_vaults::handler(Arc::downgrade(&Session::shared()))
}

struct State {
    listeners: Listeners,
    /// MI01-06 from the last apply.
    sockets: Vec<BrowserNote>,
    /// MI01-01 for each setup file the rewrite at start could not write
    /// (INT-01.10, INT-01.11), until that browser is set again.
    rewrite: Vec<BrowserNote>,
}

/// Larsal's browser integration: one per app, made by Swift at the end of the
/// launch.
#[derive(uniffi::Object)]
pub struct Browsers {
    settings: Arc<LarsalSettingsStore>,
    home: PathBuf,
    state: Mutex<State>,
}

impl std::fmt::Debug for Browsers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Browsers").finish_non_exhaustive()
    }
}

#[uniffi::export]
impl Browsers {
    /// Takes the app's settings, the team id Larsal is signed with and its
    /// app-group container `‹team id›.app.larsal.browser` (both `None` in a
    /// build without a team id, INT-01.15). The bridge socket goes in the
    /// user temp folder from the OS (INT-01.6), the setup files under the
    /// home folder; a launch started by a test uses its instance folder for
    /// both. Nothing listens until [`Browsers::start`].
    #[uniffi::constructor]
    #[must_use]
    pub fn new(
        settings: Arc<LarsalSettingsStore>,
        team_id: Option<String>,
        group_folder: Option<String>,
    ) -> Arc<Self> {
        let temp = instance::dir().unwrap_or_default();
        let home = if instance::started_by_test() {
            temp.join("home")
        } else {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
        };
        let signed = team_id.zip(group_folder).map(|(team, group)| Signed {
            team,
            // A test launch keeps the Safari socket in its own folder too,
            // never the real app-group container (INT-01.10).
            group: if instance::started_by_test() {
                temp.join("group")
            } else {
                group.into()
            },
        });
        live(Arc::new(Self::with(
            settings,
            &home,
            &temp,
            signed,
            app_vaults(),
        )))
    }

    /// Tests and Mac QA: a throwaway `folder`; the sockets go in it, the
    /// setup files under `folder/home`; unsigned.
    #[uniffi::constructor]
    #[must_use]
    pub fn in_folder(settings: Arc<LarsalSettingsStore>, folder: String) -> Arc<Self> {
        let folder = PathBuf::from(folder);
        live(Arc::new(Self::with(
            settings,
            &folder.join("home"),
            &folder,
            None,
            app_vaults(),
        )))
    }

    /// The launch's end (INT-01.11): with S-BRW-01 on, every setup file of
    /// Larsal's is written again with the current program (S-BRW-21 on);
    /// a file it cannot write shows MI01-01 (INT-01.10); then the sockets
    /// follow the settings. Returns the page's notes.
    pub fn start(&self) -> Vec<BrowserNote> {
        let rewrite = if self.flag("browser.enabled") && self.flag("browser.rewrite_manifests") {
            self.manifests()
                .rewrite()
                .into_iter()
                .map(BrowserNote::from)
                .collect()
        } else {
            Vec::new()
        };
        self.state().rewrite = rewrite;
        let notes = self.apply();
        #[cfg(debug_assertions)]
        if crate::browser_seam::on() {
            crate::browser_seam::ready();
        }
        notes
    }

    /// After the settings page's OK, Reset or Import (APP-01.3): the
    /// sockets follow S-BRW-01 and the Safari switch. Returns the notes.
    pub fn apply(&self) -> Vec<BrowserNote> {
        let (enabled, safari) = (self.flag("browser.enabled"), self.flag("browser.safari"));
        let mut state = self.state();
        state.sockets = state
            .listeners
            .apply(enabled, safari)
            .into_iter()
            .map(BrowserNote::from)
            .collect();
        drop(state);
        self.page().notes
    }

    /// The browser page's switches and messages.
    pub fn page(&self) -> BrowserPage {
        let manifests = self.manifests();
        let switches = Browser::ALL
            .into_iter()
            .map(|b| BrowserSwitch {
                browser: b.name().to_owned(),
                on: manifests.is_on(b),
            })
            .collect();
        let state = self.state();
        let safari_allowed = state.listeners.safari_allowed();
        let mut notes = Vec::new();
        if self.flag("browser.enabled") {
            notes.extend(state.sockets.iter().cloned());
            notes.extend(state.rewrite.iter().cloned());
            notes.extend(manifests.program_missing().map(BrowserNote::from));
            if !self.flag("browser.rewrite_manifests") {
                notes.extend(manifests.stale().into_iter().map(BrowserNote::from));
            }
        }
        BrowserPage {
            switches,
            safari_allowed,
            safari_note: (!safari_allowed).then(|| MI01_04.to_owned()),
            notes,
        }
    }

    /// APP-01.30 on OK: a checked browser's setup file is written, an
    /// unchecked one's removed. Returns MI01-01 or MI01-07 when that
    /// failed (the switch then shows its old state), or for an unknown
    /// browser name. Once set, the browser's MI01-01 from the rewrite at
    /// start goes.
    pub fn set(&self, browser: String, on: bool) -> Option<BrowserNote> {
        let Some(b) = Browser::ALL.into_iter().find(|b| b.name() == browser) else {
            return Some(BrowserNote {
                id: "MI01-01".into(),
                text: format!("Larsal can't set up {browser}."),
            });
        };
        let m = self.manifests();
        let done = if on { m.turn_on(b) } else { m.turn_off(b) };
        if done.is_ok() {
            // MI01-01's words name the browser: "Larsal couldn't set up Chrome."
            let name = format!("set up {}.", b.name());
            self.state().rewrite.retain(|n| !n.text.contains(&name));
        }
        done.err().map(BrowserNote::from)
    }

    /// Quit: both sockets close (INT-01.14: Safari sessions end too).
    pub fn stop(&self) {
        let _ = self.state().listeners.apply(false, false);
    }
}

impl Browsers {
    fn with(
        settings: Arc<LarsalSettingsStore>,
        home: &Path,
        temp: &Path,
        signed: Option<Signed>,
        vaults: Arc<dyn SharedHandler>,
    ) -> Self {
        // LD-556: a test launch that asks for it tells and answers the
        // dialogs on its standard input and output (debug builds only).
        #[cfg(debug_assertions)]
        let seam = crate::browser_seam::on();
        #[cfg(debug_assertions)]
        let vaults = if seam {
            crate::browser_seam::logged(vaults)
        } else {
            vaults
        };
        let bridge = Arc::new(Mutex::new(Bridge::shared(
            env!("CARGO_PKG_VERSION"),
            vaults,
        )));
        #[cfg(debug_assertions)]
        if seam {
            crate::browser_seam::start(
                Arc::clone(crate::bridge_vaults::line()),
                Arc::clone(&bridge),
            );
        }
        let clock: Clock = Arc::new(Instant::now);
        Self {
            settings,
            home: home.to_owned(),
            state: Mutex::new(State {
                listeners: Listeners::new(bridge, clock, temp, signed),
                sockets: Vec::new(),
                rewrite: Vec::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn flag(&self, key: &str) -> bool {
        self.settings.flag(key.to_owned())
    }

    /// The setup files (INT-01.9): `path` names S-BRW-24 when S-BRW-23 is
    /// on, else the `larsal-bridge` next to Larsal's own program, links resolved.
    /// A debug build adds the developer id of S-DEBUG-01 to the Chromium-family
    /// files (LD-556); a release build has no such setting, so its text is
    /// empty there and no file lists it.
    fn manifests(&self) -> Manifests {
        let program = if self.flag("browser.custom_proxy") {
            PathBuf::from(self.settings.text("browser.custom_proxy.path".into()))
        } else {
            std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map(|exe| exe.with_file_name("larsal-bridge"))
                .unwrap_or_default()
        };
        let debug = self.settings.text("browser.debug_extension_id".into());
        let ids: Vec<&str> = STORE_IDS.into_iter().chain([debug.as_str()]).collect();
        Manifests::new(&self.home, &program, &ids, ADDON_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UnlockResult;
    use crate::test_dir::TempDir;
    use larsal_crypto::bridge::{self, Secret};
    use larsal_crypto::secret::SecretBytes;
    use larsal_model::json::{self, Value};
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn store(dir: &Path) -> Arc<LarsalSettingsStore> {
        let s = Arc::new(LarsalSettingsStore::default());
        s.use_folder(dir.join("settings").display().to_string());
        s
    }

    /// Stores these settings as the settings file and reads it again.
    fn stored(dir: &Path, s: &LarsalSettingsStore, json: &str) {
        let folder = dir.join("settings");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("settings.json"), json).unwrap();
        s.use_folder(folder.display().to_string());
    }

    /// A folder removed when dropped.
    struct Short(PathBuf);

    impl Drop for Short {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// INT-01.6, APP-01.3: the bridge socket listens only while S-BRW-01 is
    /// on and goes at stop; an unsigned build shows the Safari switch
    /// disabled with MI01-04 (INT-01.15) and never listens on it.
    #[test]
    fn e7s6_sockets_follow_the_settings_and_safari_waits_for_signing() {
        let dir = socket_folder("o");
        let dir = &dir.0;
        let settings = store(dir);
        let b = Browsers::in_folder(settings.clone(), dir.display().to_string());
        let socket = dir.join(larsal_browser::BRIDGE_SOCKET);
        b.start();
        assert!(!socket.exists(), "listening with S-BRW-01 off");
        stored(
            dir,
            &settings,
            r#"{"browser.enabled":true,"browser.safari":true}"#,
        );
        b.apply();
        assert!(UnixStream::connect(&socket).is_ok());
        let page = b.page();
        assert!(!page.safari_allowed);
        assert_eq!(page.safari_note.as_deref(), Some(MI01_04));
        b.stop();
        assert!(!socket.exists());
    }

    /// INT-01.13 in a signed build (a test team id and a test group
    /// folder): the Safari socket listens only while S-BRW-01 and the Safari
    /// switch (S-BRW-02) are both on, and goes at stop.
    #[test]
    fn e7s6_the_safari_socket_follows_both_switches() {
        let dir = socket_folder("f");
        let dir = &dir.0;
        let settings = store(dir);
        let group = dir.join("group");
        let signed = Signed {
            team: "ABCDE12345".into(),
            group: group.clone(),
        };
        let b = Browsers::with(
            settings.clone(),
            &dir.join("home"),
            dir,
            Some(signed),
            crate::bridge_vaults::handler(std::sync::Weak::new()),
        );
        assert!(b.page().safari_allowed);
        let socket = group.join(larsal_browser::SAFARI_SOCKET);
        for (json, on) in [
            (r#"{"browser.enabled":true}"#, false),
            (r#"{"browser.safari":true}"#, false),
            (r#"{"browser.enabled":true,"browser.safari":true}"#, true),
            (r#"{"browser.enabled":true}"#, false),
            (r#"{"browser.enabled":true,"browser.safari":true}"#, true),
        ] {
            stored(dir, &settings, json);
            b.apply();
            assert_eq!(socket.exists(), on, "{json}");
        }
        b.stop();
        assert!(!socket.exists());
    }

    /// APP-01.30: a browser switch writes and removes Larsal's setup file
    /// under the test home only; a browser that never ran gives MI01-07.
    #[test]
    fn e7s6_browser_switch_writes_under_the_test_home() {
        // In a test folder, as every test socket and setup file is (INT-01.10).
        let dir = socket_folder("w");
        let dir = &dir.0;
        let b = Browsers::in_folder(store(dir), dir.display().to_string());
        let chrome = dir.join("home/Library/Application Support/Google/Chrome");
        assert_eq!(
            b.set("Chrome".into(), true).map(|n| n.id),
            Some("MI01-07".into())
        );
        std::fs::create_dir_all(&chrome).unwrap();
        assert_eq!(b.set("Chrome".into(), true), None);
        assert!(
            chrome
                .join("NativeMessagingHosts/app.larsal.browser.json")
                .is_file()
        );
        let on: Vec<_> = b.page().switches.into_iter().filter(|s| s.on).collect();
        assert_eq!(
            on,
            [BrowserSwitch {
                browser: "Chrome".into(),
                on: true
            }]
        );
        assert_eq!(b.set("Chrome".into(), false), None);
        assert!(
            !chrome
                .join("NativeMessagingHosts/app.larsal.browser.json")
                .exists()
        );
        assert!(
            b.set("Opera".into(), true).is_some(),
            "Opera waits for V-INT01-1"
        );
    }

    /// INT-01.11 and APP-01.30 (T23, T24, T74): at launch Larsal writes its
    /// setup files again only while S-BRW-01 and S-BRW-21 are both on; with
    /// S-BRW-21 off it only shows MI01-02, and with S-BRW-01 off the page
    /// shows no browser message at all.
    #[test]
    fn e7s6_start_rewrites_only_with_s_brw_21_on() {
        let dir = socket_folder("t");
        let dir = &dir.0;
        let settings = store(dir);
        let b = Browsers::in_folder(settings.clone(), dir.display().to_string());
        std::fs::create_dir_all(dir.join("home/Library/Application Support/Google/Chrome"))
            .unwrap();
        let old = Manifests::new(
            &dir.join("home"),
            Path::new("/Applications/Old/Larsal.app/Contents/MacOS/larsal-bridge"),
            &STORE_IDS,
            ADDON_ID,
        );
        old.turn_on(Browser::Chrome).unwrap();
        let file = old.file(Browser::Chrome);
        let before = std::fs::read(&file).unwrap();
        b.start();
        assert_eq!(std::fs::read(&file).unwrap(), before, "S-BRW-01 off");
        assert!(b.page().notes.is_empty(), "a note with S-BRW-01 off");
        stored(
            dir,
            &settings,
            r#"{"browser.enabled":true,"browser.rewrite_manifests":false}"#,
        );
        let notes = b.start();
        assert_eq!(std::fs::read(&file).unwrap(), before, "S-BRW-21 off");
        assert!(notes.iter().any(|n| n.id == "MI01-02"));
        stored(dir, &settings, r#"{"browser.enabled":true}"#);
        b.start();
        assert_ne!(std::fs::read(&file).unwrap(), before, "S-BRW-21 on");
        b.stop();
    }

    /// INT-01.10 and INT-01.11 (T23, F-257): a setup file the rewrite at
    /// start cannot write shows MI01-01 naming the browser while S-BRW-01 is
    /// on, until that browser is set again; another browser's note stays.
    #[test]
    fn e7s6_a_failed_rewrite_at_start_shows_mi01_01() {
        let dir = socket_folder("r");
        let dir = &dir.0;
        let settings = store(dir);
        let b = Browsers::in_folder(settings.clone(), dir.display().to_string());
        let support = dir.join("home/Library/Application Support");
        std::fs::create_dir_all(support.join("Google/Chrome")).unwrap();
        std::fs::create_dir_all(support.join("Microsoft Edge")).unwrap();
        let old = Manifests::new(
            &dir.join("home"),
            Path::new("/Applications/Old/Larsal.app/Contents/MacOS/larsal-bridge"),
            &STORE_IDS,
            ADDON_ID,
        );
        let both = [Browser::Chrome, Browser::Edge];
        for browser in both {
            old.turn_on(browser).unwrap();
        }
        let mode = |m| {
            both.iter().try_for_each(|&browser| {
                std::fs::set_permissions(old.folder(browser), std::fs::Permissions::from_mode(m))
            })
        };
        let shown = |name: &str| {
            b.page()
                .notes
                .iter()
                .any(|n| n.id == "MI01-01" && n.text.contains(name))
        };
        mode(0o555).unwrap();
        stored(dir, &settings, r#"{"browser.enabled":true}"#);
        b.start();
        let at_start = (shown("Chrome"), shown("Edge"));
        stored(dir, &settings, r#"{"browser.enabled":false}"#);
        let off = b.page().notes;
        stored(dir, &settings, r#"{"browser.enabled":true}"#);
        mode(0o755).unwrap();
        assert_eq!(
            at_start,
            (true, true),
            "a failed rewrite at start shows nothing"
        );
        assert_eq!(off, [], "a note with S-BRW-01 off");
        assert_eq!(b.set("Chrome".into(), true), None);
        assert_eq!(
            (shown("Chrome"), shown("Edge")),
            (false, true),
            "setting Chrome changed another browser's MI01-01"
        );
        assert_eq!(b.set("Edge".into(), true), None);
        assert!(
            !b.page().notes.iter().any(|n| n.id == "MI01-01"),
            "MI01-01 stays after the browser is set"
        );
        b.stop();
    }

    /// INT-01.10 (F-258): a launch started by a test keeps the Safari
    /// socket in its own folder, never the app-group container Swift names.
    #[test]
    fn e7s6_a_test_launch_keeps_the_safari_socket_in_its_folder() {
        const NAME: &str =
            "browser::tests::e7s6_a_test_launch_keeps_the_safari_socket_in_its_folder";
        if !cfg!(debug_assertions) {
            return; // a release build never reads the test variable
        }
        let Some(dir) = std::env::var_os(instance::TEST_DIR_VARIABLE).map(PathBuf::from) else {
            // A test may not set a variable (no unsafe code), so the check
            // runs in a child of this test binary that has it.
            let dir = socket_folder("g");
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--test-threads=1"])
                .env(instance::TEST_DIR_VARIABLE, &dir.0)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "the child's check failed: {text}");
            assert!(text.contains("1 passed"), "the child ran no test: {text}");
            return;
        };
        let container = dir.join("container");
        let b = Browsers::new(
            store(&dir),
            Some("ABCDE12345".into()),
            Some(container.display().to_string()),
        );
        assert_eq!(
            b.state().listeners.safari_socket(),
            Some(dir.join("group").join(larsal_browser::SAFARI_SOCKET))
        );
        assert!(!container.exists());
    }

    // ---- E7-S6 last round: the debug id, the app's session, the notices ----

    const DEMO_PASSWORD: &str = "demo-pass-7";

    /// A fresh folder for a test's sockets and setup files: in the run's own
    /// temp folder when that is a folder under /private/tmp, as a guarded
    /// run's is, else under /tmp (the per-user temp folder's long path leaves
    /// no room for a socket's name within 104 bytes). Short names, one tag
    /// per test: `larsal-ffi-e7s6-‹tag›-‹pid›`.
    fn socket_folder(tag: &str) -> Short {
        let own = std::env::temp_dir();
        let root = if own.starts_with("/private/tmp") && own.components().count() > 3 {
            own
        } else {
            PathBuf::from("/tmp")
        };
        let dir = root.join(format!("larsal-ffi-e7s6-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Short(dir)
    }

    /// A copy of the demo vault (testdata, demo data only) at `path`.
    fn demo_vault(path: &Path) {
        let demo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/option-a-personal.larsalvault");
        std::fs::copy(demo, path).unwrap();
    }

    fn b64(bytes: &[u8]) -> String {
        base64::encode(Form::Padded, bytes)
    }

    fn send(stream: &mut UnixStream, body: &str) {
        let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
        frame.extend_from_slice(body.as_bytes());
        stream.write_all(&frame).unwrap();
    }

    /// One frame from Larsal; `None` when none comes before the read times out.
    fn receive(stream: &mut UnixStream) -> Option<Value> {
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).ok()?;
        let mut body = vec![0u8; usize::try_from(u32::from_le_bytes(head)).unwrap()];
        stream.read_exact(&mut body).ok()?;
        Some(json::from_slice(&body).unwrap())
    }

    /// The extension's side of one bridge-socket session (INT-11.7), with
    /// larsal-crypto's channel functions: hello, boxed requests, a proven
    /// identification key and the notices Larsal sends on its own.
    struct Client {
        stream: UnixStream,
        key: [u8; 32],
        app: [u8; 32],
        sid: String,
        request: SecretBytes,
        reply: SecretBytes,
        nonce: u8,
        /// The nonces of this session's requests and of Larsal's notices so far.
        seen: Vec<[u8; 12]>,
    }

    impl Client {
        fn hello(socket: &Path) -> Self {
            let mut stream = UnixStream::connect(socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let secret = Secret::generate().unwrap();
            let key = secret.public();
            let hello = format!(
                r#"{{"type":"hello","versions":[1],"key":"{}","browser":"Chrome"}}"#,
                b64(&key)
            );
            send(&mut stream, &hello);
            let reply = receive(&mut stream).unwrap();
            let text = |k: &str| reply.get(k).and_then(Value::as_str).unwrap().to_owned();
            let app: [u8; 32] = base64::decode(Form::Padded, text("key"))
                .unwrap()
                .try_into()
                .unwrap();
            let z = secret.agree(&app).unwrap();
            Self {
                request: bridge::request_key(&z, &key, &app).unwrap(),
                reply: bridge::reply_key(&z, &key, &app).unwrap(),
                sid: text("sid"),
                stream,
                key,
                app,
                nonce: 0,
                seen: Vec::new(),
            }
        }

        /// Sends `content` boxed under a fresh nonce and opens the reply.
        fn ask(&mut self, content: &str) -> Value {
            self.nonce += 1;
            let nonce = [self.nonce; 12];
            self.seen.push(nonce);
            let sealed = bridge::seal(&self.request, &nonce, content.as_bytes()).unwrap();
            let message = format!(
                r#"{{"type":"box","sid":"{}","nonce":"{}","box":"{}"}}"#,
                self.sid,
                b64(&nonce),
                b64(&sealed)
            );
            send(&mut self.stream, &message);
            let reply = receive(&mut self.stream).unwrap();
            self.open(&reply)
        }

        /// Opens a boxed message from Larsal: a reply or a notice.
        fn open(&self, message: &Value) -> Value {
            let opened =
                bridge::open(&self.reply, &nonce(message), &field(message, "box")).unwrap();
            json::from_slice(opened.expose()).unwrap()
        }

        /// Proves `id` as this session's identification key (a `check`,
        /// INT-01.28): Larsal then knows the session by it.
        fn prove(&mut self, id: &Secret) {
            let z_id = id.agree(&self.app).unwrap();
            let key = bridge::proof_key(&z_id, &self.key, &self.app, &id.public()).unwrap();
            let nonce = [self.nonce + 1; 12];
            let proof = bridge::seal(&key, &nonce, &self.key).unwrap();
            let check = format!(
                r#"{{"type":"check","req":5,"id_key":"{}","proof":"{}"}}"#,
                b64(&id.public()),
                b64(&proof)
            );
            let reply = self.ask(&check);
            assert_eq!(reply.get("type").and_then(Value::as_str), Some("check"));
        }

        /// The next notice Larsal sends on its own within `wait`, opened
        /// with the reply key. Its nonce is fresh (T63): no request of this
        /// session and no notice before it used it.
        fn notice(&mut self, wait: Duration) -> Option<String> {
            self.stream.set_read_timeout(Some(wait)).unwrap();
            let got = receive(&mut self.stream)?;
            let used = nonce(&got);
            assert!(!self.seen.contains(&used), "a nonce used before: {used:?}");
            self.seen.push(used);
            Some(json::to_string(&self.open(&got)))
        }
    }

    /// The base64 member `name` of a message from Larsal, decoded.
    fn field(message: &Value, name: &str) -> Vec<u8> {
        let text = message.get(name).and_then(Value::as_str).unwrap();
        base64::decode(Form::Padded, text).unwrap()
    }

    fn nonce(message: &Value) -> [u8; 12] {
        field(message, "nonce").try_into().unwrap()
    }

    fn notice(event: &str) -> Option<String> {
        Some(format!(r#"{{"event":"{event}","type":"notice"}}"#))
    }

    /// INT-01.9, LD-556 (a): a debug build lists S-DEBUG-01's developer id
    /// in a Chromium-family setup file, and a release build never does: it
    /// has no such setting. No build lists a text that is not an extension
    /// id, and Firefox's file lists only Larsal's add-on.
    #[test]
    fn ld556_a_the_debug_extension_id_is_listed_by_a_debug_build_only() {
        const DEV: &str = "ahgbmchdgnehohlelgpibhgjfgmhhfim";
        let dir = TempDir::new("e7s6-dev");
        let settings = store(&dir);
        let b = Browsers::in_folder(Arc::clone(&settings), dir.display().to_string());
        let support = dir.join("home/Library/Application Support");
        for own in ["Google/Chrome", "Mozilla"] {
            std::fs::create_dir_all(support.join(own)).unwrap();
        }
        let file = |own: &str| {
            let path = support
                .join(own)
                .join("NativeMessagingHosts/app.larsal.browser.json");
            std::fs::read_to_string(path).unwrap()
        };
        for (id, listed) in [
            (DEV, cfg!(debug_assertions)),
            ("*", false),
            ("ahgbmchdgnehohlelgpibhgjfgmhhfiq", false),
        ] {
            let json = format!(r#"{{"browser.debug_extension_id":"{id}"}}"#);
            stored(&dir, &settings, &json);
            assert_eq!(b.set("Chrome".into(), true), None);
            assert_eq!(b.set("Firefox".into(), true), None);
            let chrome = file("Google/Chrome");
            let origin = format!("chrome-extension://{id}/");
            assert_eq!(chrome.contains(&origin), listed, "{id}: {chrome}");
            assert_eq!(
                chrome.matches("chrome-extension://").count(),
                usize::from(listed)
            );
            assert!(!file("Mozilla").contains(id), "{id}");
        }
    }

    /// LD-609 (lead ruling 7): the app's bridge answers over the app's one
    /// session (`Session::shared()`, `app_vaults()`): a vault open there is
    /// listed by `status` on the bridge socket of `Browsers::in_folder`.
    #[test]
    fn ld609_the_apps_bridge_answers_over_the_shared_session() {
        let dir = socket_folder("a");
        let dir = &dir.0;
        let settings = store(dir);
        stored(dir, &settings, r#"{"browser.enabled":true}"#);
        let b = Browsers::in_folder(settings, dir.display().to_string());
        b.apply();
        let path = dir.join("ld609-shared-demo.larsalvault");
        demo_vault(&path);
        let s = Session::shared();
        let v = s.open(path.display().to_string()).unwrap();
        let mut client = Client::hello(&dir.join(larsal_browser::BRIDGE_SOCKET));
        let status = client.ask(r#"{"type":"status","req":1}"#);
        s.close(v).unwrap();
        b.stop();
        let names: Vec<&str> = status
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"ld609-shared-demo"), "{status}");
    }

    /// T63, INT-01.46 (lead ruling 6 (b)): a lock and an unlock in Larsal's
    /// session reach, through the bridge socket's notify, the session proven
    /// with a key the vault stores, as boxed `locked` and `unlocked` notices
    /// sealed with its reply key under fresh nonces (none of its requests'):
    /// a lock, the Lock command's lock of every vault and a close each send
    /// `locked`, an unlock `unlocked`. A session proven with another key gets
    /// none.
    #[test]
    fn t63_int01_46_a_lock_and_an_unlock_reach_the_proven_session() {
        let dir = socket_folder("n");
        let dir = &dir.0;
        let settings = store(dir);
        stored(dir, &settings, r#"{"browser.enabled":true}"#);
        let b = Browsers::in_folder(settings, dir.display().to_string());
        b.apply();
        let socket = dir.join(larsal_browser::BRIDGE_SOCKET);
        let (mut proven, mut other) = (Client::hello(&socket), Client::hello(&socket));
        let (id, stranger) = (Secret::generate().unwrap(), Secret::generate().unwrap());
        proven.prove(&id);
        other.prove(&stranger);
        // The demo vault stores the proven session's key (INT-02.1), saved.
        let path = dir.join("notice-demo.larsalvault");
        demo_vault(&path);
        let s = Session::new();
        let v = s.open(path.display().to_string()).unwrap();
        let unlock = || {
            let done = s.unlock(v, Some(DEMO_PASSWORD.into()), None).unwrap();
            assert_eq!(done, UnlockResult::Unlocked);
        };
        unlock();
        s.with_edit(v, |vault, _, _, _| {
            let (key, now) = (b64(&id.public()), crate::views::now());
            let created = "2026-11-01T00:00:00Z";
            assert!(larsal_core::settings::add_association(
                vault, "demo", &key, created, now
            ));
            Ok(())
        })
        .unwrap();
        s.save(v).unwrap();
        let wait = Duration::from_secs(10);
        s.lock(v).unwrap();
        assert_eq!(proven.notice(wait), notice("locked"), "lock");
        unlock();
        assert_eq!(proven.notice(wait), notice("unlocked"), "unlock");
        s.lock_all();
        assert_eq!(proven.notice(wait), notice("locked"), "lock every vault");
        unlock();
        assert_eq!(proven.notice(wait), notice("unlocked"), "unlock again");
        s.close(v).unwrap();
        assert_eq!(proven.notice(wait), notice("locked"), "close");
        let quiet = Duration::from_millis(500);
        assert_eq!(other.notice(quiet), None, "a session of another key");
        b.stop();
    }
}
