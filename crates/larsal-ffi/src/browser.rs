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

use crate::instance;
use crate::larsal_settings::LarsalSettingsStore;
use larsal_browser::{
    ADDON_ID, Bridge, Browser, Clock, Handler, Listeners, MI01_04, Manifests, Request, STORE_IDS,
    Signed, Trouble,
};
use larsal_model::json::Map;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

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

/// The vault side until E7-S2: `status` lists no vault; every other
/// request gets error 1 (no vault the request may use is unlocked).
struct NoVaults;

impl Handler for NoVaults {
    fn handle(&mut self, request: &Request<'_>) -> Result<Map, u8> {
        if request.kind != "status" {
            return Err(1);
        }
        let mut reply = Map::new();
        reply.insert(
            "vaults".into(),
            larsal_model::json::Value::Array(Vec::new()),
        );
        Ok(reply)
    }
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
        Arc::new(Self::with(settings, &home, &temp, signed))
    }

    /// Tests and Mac QA: a throwaway `folder`; the sockets go in it, the
    /// setup files under `folder/home`; unsigned.
    #[uniffi::constructor]
    #[must_use]
    pub fn in_folder(settings: Arc<LarsalSettingsStore>, folder: String) -> Arc<Self> {
        let folder = PathBuf::from(folder);
        Arc::new(Self::with(settings, &folder.join("home"), &folder, None))
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
        self.apply()
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
    ) -> Self {
        let bridge = Arc::new(Mutex::new(Bridge::new(
            env!("CARGO_PKG_VERSION"),
            Box::new(NoVaults),
        )));
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
    fn manifests(&self) -> Manifests {
        let program = if self.flag("browser.custom_proxy") {
            PathBuf::from(self.settings.text("browser.custom_proxy.path".into()))
        } else {
            std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map(|exe| exe.with_file_name("larsal-bridge"))
                .unwrap_or_default()
        };
        Manifests::new(&self.home, &program, &STORE_IDS, ADDON_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;

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
        // Under /tmp: the user temp folder's long path leaves no room for
        // a socket name within macOS's 104 bytes.
        let dir = Short(PathBuf::from(format!(
            "/tmp/larsal-ffi-e7s6-{}",
            std::process::id()
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir(&dir.0).unwrap();
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
        let dir = Short(PathBuf::from(format!(
            "/tmp/larsal-ffi-e7s6-safari-{}",
            std::process::id()
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir(&dir.0).unwrap();
        let dir = &dir.0;
        let settings = store(dir);
        let group = dir.join("group");
        let signed = Signed {
            team: "ABCDE12345".into(),
            group: group.clone(),
        };
        let b = Browsers::with(settings.clone(), &dir.join("home"), dir, Some(signed));
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
        // Under /tmp, as every test socket and setup file is (INT-01.10).
        let dir = Short(PathBuf::from(format!(
            "/tmp/larsal-ffi-e7s6-switch-{}",
            std::process::id()
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir(&dir.0).unwrap();
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
        let dir = Short(PathBuf::from(format!(
            "/tmp/larsal-ffi-e7s6-start-{}",
            std::process::id()
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir(&dir.0).unwrap();
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
        let dir = Short(PathBuf::from(format!(
            "/tmp/larsal-ffi-e7s6-rewrite-{}",
            std::process::id()
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir(&dir.0).unwrap();
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
            let dir = Short(PathBuf::from(format!(
                "/tmp/larsal-ffi-e7s6-group-{}",
                std::process::id()
            )));
            let _ = std::fs::remove_dir_all(&dir.0);
            std::fs::create_dir(&dir.0).unwrap();
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
}
