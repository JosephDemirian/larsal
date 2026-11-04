//! Native messaging setup (story E7-S6): when and where App's two sockets
//! listen (INT-01.6, INT-01.7, INT-01.13 to INT-01.15) and the setup file
//! each browser reads to start `app-bridge` (INT-01.8 to INT-01.11).
//!
//! Guarantees:
//! - the bridge socket listens only while S-BRW-01 is on, the Safari socket
//!   only while S-BRW-01 and the Safari switch are on in a build signed with
//!   a team id; both keep [`crate::Server`]'s owner, mode and leftover-file
//!   rules, and a socket that cannot start gives MI01-06 and no listener;
//! - in a signed build each connection must be one of App's two relays,
//!   signed by App's team (INT-01.7); an unsigned build skips that check
//!   and says so once in the debug log;
//! - a setup file is written only into the last folder level of
//!   INT-01.8's folders under the given home folder, never through a
//!   symbolic link, never over another program's file, and removed only
//!   when it is App's (`name` is [`HOST`]).

use crate::channel::{Bridge, Route};
use crate::server::{Clock, Program, Server};
use app_model::json::{self, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The host id: the setup files' `name` and file name (INT-01.9).
pub const HOST: &str = "com.app.browser";
/// The app group's name after the team id: `‹team id›.com.app.browser`.
pub const GROUP: &str = "com.app.browser";
/// The Safari socket's name in the app-group container (INT-01.13).
pub const SAFARI_SOCKET: &str = "bridge.sock";
/// The bridge socket's name in the user temp folder; debug builds have
/// their own (INT-01.6, the edge case "Two copies of App").
pub const BRIDGE_SOCKET: &str = if cfg!(debug_assertions) {
    "com.app.browser-debug.sock"
} else {
    "com.app.browser.sock"
};
/// The signing identifiers of App's two relays (INT-01.7): `app-bridge`
/// and the Safari app extension.
pub const RELAYS: [&str; 2] = ["com.app.desktop.bridge", "com.app.desktop.safari"];
/// App's store ids (INT-01.9, INT-11.4): fixed at the first publish (E7-S7n).
pub const STORE_IDS: [&str; 0] = [];
/// App's Firefox add-on id (INT-01.9): a placeholder in the reserved
/// `.invalid` domain until the first publish (E7-S7n).
pub const ADDON_ID: &str = "browser@app.invalid";
/// The largest setup file App reads back.
const MAX_FILE: u64 = 65_536;

/// A message for the settings page: its id and App's text (INT-01's table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trouble {
    /// `MI01-01` and so on.
    pub id: &'static str,
    /// App's words, with the browser, folder or path filled in.
    pub text: String,
}

impl Trouble {
    fn new(id: &'static str, text: String) -> Self {
        Self { id, text }
    }

    fn not_written(browser: Browser, folder: &Path) -> Self {
        Self::new(
            "MI01-01",
            format!(
                "App couldn't set up {}. Check that its folder {} can be written, then try again.",
                browser.name(),
                folder.display()
            ),
        )
    }
}

/// MI01-04 (INT-01.15): the Safari switch is disabled until App is signed
/// with a team id.
pub const MI01_04: &str = "Safari needs a signed copy of App. This build is not signed.";

/// The browsers App writes a setup file for (INT-01.8, D-INT01-6). Opera
/// waits for V-INT01-1; Chromium and Arc come with E7-S7l.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    /// `Google/Chrome/NativeMessagingHosts/`.
    Chrome,
    /// `Mozilla/NativeMessagingHosts/`.
    Firefox,
    /// `Microsoft Edge/NativeMessagingHosts/`.
    Edge,
    /// `BraveSoftware/Brave-Browser/NativeMessagingHosts/`.
    Brave,
    /// `Vivaldi/NativeMessagingHosts/`.
    Vivaldi,
}

impl Browser {
    /// Every browser of INT-01.8 but Safari, which has no file (INT-01.12).
    pub const ALL: [Self; 5] = [
        Self::Chrome,
        Self::Firefox,
        Self::Edge,
        Self::Brave,
        Self::Vivaldi,
    ];

    /// The name the settings page and its messages use.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
            Self::Edge => "Edge",
            Self::Brave => "Brave",
            Self::Vivaldi => "Vivaldi",
        }
    }

    /// The browser's own folder under `Library/Application Support/`, which
    /// App never creates (INT-01.10).
    fn own_folder(self) -> &'static str {
        match self {
            Self::Chrome => "Google/Chrome",
            Self::Firefox => "Mozilla",
            Self::Edge => "Microsoft Edge",
            Self::Brave => "BraveSoftware/Brave-Browser",
            Self::Vivaldi => "Vivaldi",
        }
    }
}

/// The setup files of INT-01.8 to INT-01.11 under one home folder.
#[derive(Debug, Clone)]
pub struct Manifests {
    home: PathBuf,
    program: PathBuf,
    origins: Vec<String>,
    addon: String,
}

impl Manifests {
    /// The files under `home` (the user's home folder; a test's own folder
    /// in tests, INT-01.10), naming `program` (the resolved `app-bridge`, or
    /// S-BRW-24), for the Chrome-family ids `ids` and the Firefox add-on id
    /// `addon`. Only ids of Chrome's form (32 letters `a` to `p`) are kept,
    /// so a file never holds a wildcard (INT-01.9).
    #[must_use]
    pub fn new(home: &Path, program: &Path, ids: &[&str], addon: &str) -> Self {
        let origins = ids
            .iter()
            .filter(|id| id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)))
            .map(|id| format!("chrome-extension://{id}/"))
            .collect();
        Self {
            home: home.to_owned(),
            program: program.to_owned(),
            origins,
            addon: addon.to_owned(),
        }
    }

    /// The folder App writes `browser`'s file into.
    #[must_use]
    pub fn folder(&self, browser: Browser) -> PathBuf {
        self.own_folder(browser).join("NativeMessagingHosts")
    }

    fn own_folder(&self, browser: Browser) -> PathBuf {
        self.home
            .join("Library/Application Support")
            .join(browser.own_folder())
    }

    /// `browser`'s setup file.
    #[must_use]
    pub fn file(&self, browser: Browser) -> PathBuf {
        self.folder(browser).join(format!("{HOST}.json"))
    }

    /// The file App writes for `browser` (INT-01.9): these members in this
    /// order, two-space indent, a final line feed.
    #[must_use]
    pub fn content(&self, browser: Browser) -> String {
        let text = |s: &str| json::to_string(&Value::String(s.to_owned()));
        let (key, ids) = if browser == Browser::Firefox {
            ("allowed_extensions", vec![self.addon.clone()])
        } else {
            ("allowed_origins", self.origins.clone())
        };
        let list = if ids.is_empty() {
            "[]".to_owned()
        } else {
            let items: Vec<String> = ids.iter().map(|id| format!("    {}", text(id))).collect();
            format!("[\n{}\n  ]", items.join(",\n"))
        };
        format!(
            "{{\n  \"name\": {},\n  \"description\": {},\n  \"path\": {},\n  \"type\": \"stdio\",\n  \"{key}\": {list}\n}}\n",
            text(HOST),
            text("App browser bridge"),
            text(&self.program.to_string_lossy()),
        )
    }

    /// The switch of INT-01.8: on exactly when App's file is in the folder.
    #[must_use]
    pub fn is_on(&self, browser: Browser) -> bool {
        ours(&self.file(browser)).is_some()
    }

    /// Turns `browser` on: writes its file to a temporary file in the same
    /// folder and renames it over the old one (INT-01.10).
    ///
    /// # Errors
    /// MI01-07 when the browser's own folder is missing (App makes only the
    /// last level, LD-191 R01-2); MI01-01 when the file cannot be written
    /// and does not already hold what App would write, when the folder or
    /// the file is a symbolic link, or when the file is another program's.
    pub fn turn_on(&self, browser: Browser) -> Result<(), Trouble> {
        let folder = self.folder(browser);
        let failed = || Trouble::not_written(browser, &folder);
        if !self.home.is_absolute() {
            return Err(failed()); // no home folder: never a path relative to here
        }
        if fs::symlink_metadata(&folder).is_err() {
            if !fs::symlink_metadata(self.own_folder(browser)).is_ok_and(|m| m.is_dir()) {
                return Err(Trouble::new(
                    "MI01-07",
                    format!(
                        "{} wasn't found on this Mac. Open it once, then turn it on here.",
                        browser.name()
                    ),
                ));
            }
            fs::DirBuilder::new()
                .mode(0o755)
                .create(&folder)
                .map_err(|_| failed())?;
        }
        if !fs::symlink_metadata(&folder).is_ok_and(|m| m.is_dir()) {
            return Err(failed());
        }
        let file = self.file(browser);
        let content = self.content(browser);
        if let Ok(meta) = fs::symlink_metadata(&file)
            && (!meta.is_file() || ours(&file).is_none())
        {
            return Err(failed());
        }
        if write_new(&folder, &file, &content).is_ok() {
            return Ok(());
        }
        // INT-01.10: the same JSON already there counts as written.
        let same = ours(&file).is_some_and(|v| json::from_str(&content).is_ok_and(|c| c == v));
        if same { Ok(()) } else { Err(failed()) }
    }

    /// Turns `browser` off: removes its file only when it is App's (its
    /// `name` is [`HOST`]); another program's file stays (INT-01.10).
    ///
    /// # Errors
    /// MI01-01 when App's file is there but cannot be removed.
    pub fn turn_off(&self, browser: Browser) -> Result<(), Trouble> {
        let file = self.file(browser);
        if ours(&file).is_none() {
            return Ok(());
        }
        fs::remove_file(&file).map_err(|_| Trouble::not_written(browser, &self.folder(browser)))
    }

    /// INT-01.11 with S-BRW-21 on, at start: every file of App's that
    /// names another program path is written again with the current one.
    #[must_use]
    pub fn rewrite(&self) -> Vec<Trouble> {
        Browser::ALL
            .into_iter()
            .filter(|&b| {
                ours(&self.file(b))
                    .is_some_and(|v| json::from_str(&self.content(b)).ok() != Some(v))
            })
            .filter_map(|b| self.turn_on(b).err())
            .collect()
    }

    /// INT-01.11 with S-BRW-21 off: MI01-02 for each browser whose file
    /// names no existing `app-bridge`.
    #[must_use]
    pub fn stale(&self) -> Vec<Trouble> {
        Browser::ALL
            .into_iter()
            .filter(|&b| {
                ours(&self.file(b)).is_some_and(|v| {
                    let path = v.get("path").and_then(Value::as_str).map(Path::new);
                    !path.is_some_and(|p| {
                        p.file_name().is_some_and(|n| n == "app-bridge") && p.is_file()
                    })
                })
            })
            .map(|b| {
                Trouble::new(
                    "MI01-02",
                    format!(
                        "The setup for {} points to an old copy of App. Turn the browser off and on again here, or turn on \"Rewrite the browser setup files at start\".",
                        b.name()
                    ),
                )
            })
            .collect()
    }

    /// MI01-05 (INT-01.11, APP-01.30): the program the files name is missing.
    #[must_use]
    pub fn program_missing(&self) -> Option<Trouble> {
        (!self.program.is_file()).then(|| {
            Trouble::new(
                "MI01-05",
                format!(
                    "The proxy program at {} is missing. Browsers can't reach App until it is back or the setting is turned off.",
                    self.program.display()
                ),
            )
        })
    }
}

/// The JSON of `path` when it is a regular file (never through a link) of
/// at most [`MAX_FILE`] bytes whose `name` is [`HOST`].
fn ours(path: &Path) -> Option<Value> {
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_FILE)
        .read_to_end(&mut bytes)
        .ok()?;
    let value = json::from_slice(&bytes).ok()?;
    (value.get("name").and_then(Value::as_str) == Some(HOST)).then_some(value)
}

/// A new temporary file in `folder` (never an existing one, so never
/// through a planted link), mode 0644, renamed over `file`.
fn write_new(folder: &Path, file: &Path, content: &str) -> io::Result<()> {
    let temp = folder.join(format!(".{HOST}.json.{}.tmp", std::process::id()));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp)
        .and_then(|mut f| {
            f.set_permissions(fs::Permissions::from_mode(0o644))?;
            f.write_all(content.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&temp, file));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

/// INT-01.7's code requirement for `team`: Apple-issued signing, App's
/// team, one of App's [`RELAYS`]. `None` unless `team` has Apple's form
/// (10 upper-case letters and digits), so nothing else ever goes into the
/// requirement's text.
#[must_use]
pub fn requirement(team: &str) -> Option<String> {
    let valid = team.len() == 10
        && team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    valid.then(|| {
        format!(
            r#"anchor apple generic and certificate leaf[subject.OU] = "{team}" and (identifier "{}" or identifier "{}")"#,
            RELAYS[0], RELAYS[1]
        )
    })
}

/// Checks a peer against a code requirement: app-platform's code
/// signature check in App; tests give their own reader.
pub type Signature = Arc<dyn Fn(&UnixStream, &str) -> bool + Send + Sync>;

/// App's team id and its app-group container `‹team id›.com.app.browser`
/// (a test group folder in tests, INT-01.10), from a build signed with a
/// team id.
#[derive(Debug, Clone)]
pub struct Signed {
    /// The team id App is signed with.
    pub team: String,
    /// The app-group container, where the Safari socket lives.
    pub group: PathBuf,
}

/// App's two listeners, on and off as the settings say.
pub struct Listeners {
    bridge: Arc<Mutex<Bridge>>,
    clock: Clock,
    port_socket: PathBuf,
    signed: Option<(Signed, String)>,
    signature: Signature,
    log: Box<dyn Fn(&str) + Send>,
    logged: bool,
    port: Option<Server>,
    safari: Option<Server>,
}

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listeners")
            .field("port", &self.port)
            .field("safari", &self.safari)
            .finish_non_exhaustive()
    }
}

impl Listeners {
    /// The listeners of a bridge: the bridge socket in `temp` (the user temp
    /// folder from the OS, INT-01.6), the Safari socket in `signed`'s group
    /// container. `signed` is `None` in a build without a team id, or with
    /// one not of Apple's form: the Safari socket then never listens
    /// (INT-01.15). The peer program check is app-platform's; the debug
    /// log line goes to standard error in debug builds.
    #[must_use]
    pub fn new(
        bridge: Arc<Mutex<Bridge>>,
        clock: Clock,
        temp: &Path,
        signed: Option<Signed>,
    ) -> Self {
        let signature: Signature = Arc::new(app_platform::macos::peer_meets);
        let log = Box::new(|line: &str| {
            if cfg!(debug_assertions) {
                eprintln!("{line}");
            }
        });
        Self::with(bridge, clock, temp, signed, signature, log)
    }

    /// [`Listeners::new`] with the signature check and the debug log given
    /// (tests: INT-01.7 without a signed build).
    #[must_use]
    pub fn with(
        bridge: Arc<Mutex<Bridge>>,
        clock: Clock,
        temp: &Path,
        signed: Option<Signed>,
        signature: Signature,
        log: Box<dyn Fn(&str) + Send>,
    ) -> Self {
        let signed = signed.and_then(|s| requirement(&s.team).map(|r| (s, r)));
        Self {
            bridge,
            clock,
            port_socket: temp.join(BRIDGE_SOCKET),
            signed,
            signature,
            log,
            logged: false,
            port: None,
            safari: None,
        }
    }

    /// INT-01.15: whether the Safari switch may be used; when not, the page
    /// shows it disabled with [`MI01_04`].
    #[must_use]
    pub fn safari_allowed(&self) -> bool {
        self.signed.is_some()
    }

    /// The bridge socket's path.
    #[must_use]
    pub fn port_socket(&self) -> &Path {
        &self.port_socket
    }

    /// The Safari socket's path, in a signed build.
    #[must_use]
    pub fn safari_socket(&self) -> Option<PathBuf> {
        self.signed
            .as_ref()
            .map(|(s, _)| s.group.join(SAFARI_SOCKET))
    }

    /// Whether each socket listens now: (bridge, Safari).
    #[must_use]
    pub fn listening(&self) -> (bool, bool) {
        (self.port.is_some(), self.safari.is_some())
    }

    /// Makes the listeners follow S-BRW-01 (`enabled`) and the Safari
    /// switch (`safari`): a socket starts when it should listen and does
    /// not, and stops (closing every connection and ending its sessions)
    /// when it should not. Returns MI01-06 for each socket that should
    /// listen but cannot start; the next call tries again.
    pub fn apply(&mut self, enabled: bool, safari: bool) -> Vec<Trouble> {
        let mut trouble = Vec::new();
        if !enabled {
            self.port = None;
        } else if self.port.is_none() {
            let path = self.port_socket.clone();
            match self.start(&path, Route::Port) {
                Ok(server) => self.port = Some(server),
                Err(()) => trouble.push(in_the_way(&path)),
            }
        }
        let safari_path = self.safari_socket().filter(|_| enabled && safari);
        match safari_path {
            None => self.safari = None,
            Some(_) if self.safari.is_some() => {}
            Some(path) => {
                if let Some(group) = path.parent() {
                    // The container's last level only, owner-only.
                    let _ = fs::DirBuilder::new().mode(0o700).create(group);
                }
                match self.start(&path, Route::Safari) {
                    Ok(server) => self.safari = Some(server),
                    Err(()) => trouble.push(in_the_way(&path)),
                }
            }
        }
        trouble
    }

    fn start(&mut self, path: &Path, route: Route) -> Result<Server, ()> {
        let (bridge, clock) = (self.bridge.clone(), self.clock.clone());
        let started = match &self.signed {
            Some((_, requirement)) => {
                let (signature, requirement) = (self.signature.clone(), requirement.clone());
                let program: Program = Arc::new(move |peer| signature(peer, &requirement));
                Server::start_checked(path, route, bridge, clock, program)
            }
            None => {
                if !self.logged {
                    self.logged = true;
                    (self.log)("browser bridge: unsigned build, the peer program check is off");
                }
                Server::start(path, route, bridge, clock)
            }
        };
        started.map_err(|_| ())
    }
}

/// MI01-06 (INT-01.6).
fn in_the_way(path: &Path) -> Trouble {
    Trouble::new(
        "MI01-06",
        format!(
            "App can't open its browser connection: {} is in the way. Remove it, then turn browser integration off and on.",
            path.display()
        ),
    )
}
