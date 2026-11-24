//! INT-01's setup cases (story E7-S6): the setup file of each browser
//! (INT-01.8 to INT-01.11), the two sockets' places and switches (INT-01.6,
//! INT-01.13 to INT-01.15), the peer program check of signed builds
//! (INT-01.7) and the Safari session cap (INT-01.44, LD-318 (3)).
//!
//! Every file and socket lives in a fresh folder under /tmp: a test home,
//! a test temp folder and a test group folder (INT-01.10), never the
//! owner's Library, a browser's folder or the real app-group container.
//! The signed build's check runs with an injected signature reader; the
//! real signed run waits for D7.

use larsal_browser::{
    ADDON_ID, BRIDGE_SOCKET, Bridge, Browser, Clock, Handler, Listeners, MAX_SAFARI, Manifests,
    RELAYS, Request, Route, SAFARI_SOCKET, Signature, Signed, requirement,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::{self, Secret};
use larsal_crypto::secret::SecretBytes;
use larsal_model::json::{self, Map, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static FOLDERS: AtomicU64 = AtomicU64::new(0);

/// A fresh owner-only folder under /tmp, removed when dropped (also after
/// a test made parts of it read-only).
struct Folder(PathBuf);

impl Folder {
    fn new() -> Self {
        let n = FOLDERS.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("/tmp/larsal-e7s6-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        for entry in walk(&self.0) {
            let _ = fs::set_permissions(&entry, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![dir.to_owned()];
    if let Ok(read) = fs::read_dir(dir) {
        for e in read.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                out.extend(walk(&e.path()));
            }
        }
    }
    out
}

const ID_A: &str = "abcdefghijklmnopabcdefghijklmnop";
const ID_B: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";

/// A test home with the browsers' own folders (as each browser makes them
/// on its first start) and a test `larsal-bridge` file.
struct Home {
    folder: Folder,
    program: PathBuf,
}

impl Home {
    fn new() -> Self {
        let folder = Folder::new();
        for own in [
            "Google/Chrome",
            "Mozilla",
            "Microsoft Edge",
            "BraveSoftware/Brave-Browser",
            "Vivaldi",
        ] {
            folder.sub(&format!("home/Library/Application Support/{own}"));
        }
        let program = folder
            .sub("Larsal.app/Contents/MacOS")
            .join("larsal-bridge");
        fs::write(&program, b"#!/bin/sh\n").unwrap();
        Self { folder, program }
    }

    fn home(&self) -> PathBuf {
        self.folder.0.join("home")
    }

    fn manifests(&self) -> Manifests {
        Manifests::new(&self.home(), &self.program, &[ID_A, ID_B], ADDON_ID)
    }

    fn support(&self, rest: &str) -> PathBuf {
        self.home().join("Library/Application Support").join(rest)
    }
}

fn read_only(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
}

/// T16 INT-01.8: Chrome on writes Larsal's file into Chrome's folder under the
/// test home; Larsal made only the last folder level (INT-01.10).
#[test]
fn t16_chrome_on_writes_its_file_under_the_test_home() {
    let h = Home::new();
    let m = h.manifests();
    assert!(!h.support("Google/Chrome/NativeMessagingHosts").exists());
    assert!(!m.is_on(Browser::Chrome));
    m.turn_on(Browser::Chrome).unwrap();
    let file = h.support("Google/Chrome/NativeMessagingHosts/app.larsal.browser.json");
    assert_eq!(m.file(Browser::Chrome), file);
    assert!(file.is_file());
    assert!(m.is_on(Browser::Chrome));
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o644);
    // Only the file and the one folder level; no temporary file left.
    let names: Vec<_> = fs::read_dir(file.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["app.larsal.browser.json"]);
}

/// INT-01.8: the folders of Firefox, Edge, Brave and Vivaldi.
#[test]
fn int01_8_each_browser_has_its_own_folder() {
    let h = Home::new();
    let m = h.manifests();
    for (browser, folder) in [
        (Browser::Firefox, "Mozilla/NativeMessagingHosts"),
        (Browser::Edge, "Microsoft Edge/NativeMessagingHosts"),
        (
            Browser::Brave,
            "BraveSoftware/Brave-Browser/NativeMessagingHosts",
        ),
        (Browser::Vivaldi, "Vivaldi/NativeMessagingHosts"),
    ] {
        m.turn_on(browser).unwrap();
        assert!(
            h.support(folder).join("app.larsal.browser.json").is_file(),
            "{folder}"
        );
        assert!(m.is_on(browser));
    }
    assert!(!m.is_on(Browser::Chrome), "one switch per browser");
}

/// LD-191 (R01-2), INT-01.10: Larsal never makes a browser's own folder; a
/// browser that never ran gives MI01-07 and nothing is made.
#[test]
fn int01_10_a_missing_browser_folder_gives_mi01_07_and_makes_nothing() {
    let h = Home::new();
    fs::remove_dir_all(h.support("Vivaldi")).unwrap();
    let err = h.manifests().turn_on(Browser::Vivaldi).unwrap_err();
    assert_eq!(err.id, "MI01-07");
    assert!(err.text.contains("Vivaldi"), "{}", err.text);
    assert!(!h.support("Vivaldi").exists());
}

/// T18 INT-01.9: the members in order, two-space indent, final LF, the
/// resolved program path, Larsal's ids only, and no `*` anywhere: an id that
/// is not of Chrome's form (a wildcard) is never written.
#[test]
fn t18_chrome_file_content_is_exact() {
    let h = Home::new();
    let m = Manifests::new(&h.home(), &h.program, &[ID_A, "*", "x", ID_B], ADDON_ID);
    m.turn_on(Browser::Chrome).unwrap();
    let text = fs::read_to_string(m.file(Browser::Chrome)).unwrap();
    let want = format!(
        "{{\n  \"name\": \"app.larsal.browser\",\n  \"description\": \"Larsal browser bridge\",\n  \"path\": \"{}\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://{ID_A}/\",\n    \"chrome-extension://{ID_B}/\"\n  ]\n}}\n",
        h.program.display()
    );
    assert_eq!(text, want);
    assert!(!text.contains('*'));
    let v = json::from_str(&text).unwrap();
    assert!(v.get("allowed_extensions").is_none());
}

/// T19 INT-01.9: Firefox's file lists Larsal's add-on id under
/// `allowed_extensions` and has no `allowed_origins`.
#[test]
fn t19_firefox_file_lists_the_add_on_id() {
    let h = Home::new();
    let m = h.manifests();
    m.turn_on(Browser::Firefox).unwrap();
    let file = h.support("Mozilla/NativeMessagingHosts/app.larsal.browser.json");
    let v = json::from_slice(&fs::read(file).unwrap()).unwrap();
    let ids = v
        .get("allowed_extensions")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(ids, &[Value::String(ADDON_ID.into())]);
    assert!(v.get("allowed_origins").is_none());
    assert_eq!(v.get("type").and_then(Value::as_str), Some("stdio"));
}

/// T20 INT-01.10: Chrome's folder read-only with a file that holds the same
/// JSON Larsal would write, members in another order: success, no message.
#[test]
fn t20_read_only_folder_with_the_same_json_is_success() {
    let h = Home::new();
    let m = h.manifests();
    m.turn_on(Browser::Chrome).unwrap();
    let file = m.file(Browser::Chrome);
    let v = json::from_slice(&fs::read(&file).unwrap()).unwrap();
    fs::write(&file, json::to_string(&v)).unwrap(); // compact, members sorted
    read_only(&m.folder(Browser::Chrome));
    assert_eq!(m.turn_on(Browser::Chrome), Ok(()));
}

/// T21 INT-01.10: a read-only folder whose file holds other content (an
/// old path): MI01-01 naming Chrome and its folder; the file is unchanged.
#[test]
fn t21_read_only_folder_with_other_content_gives_mi01_01() {
    let h = Home::new();
    let m = h.manifests();
    m.turn_on(Browser::Chrome).unwrap();
    let file = m.file(Browser::Chrome);
    let old = fs::read_to_string(&file).unwrap().replace(
        &h.program.display().to_string(),
        "/Applications/Old/Larsal.app/Contents/MacOS/larsal-bridge",
    );
    fs::write(&file, &old).unwrap();
    read_only(&m.folder(Browser::Chrome));
    let err = m.turn_on(Browser::Chrome).unwrap_err();
    assert_eq!(err.id, "MI01-01");
    assert!(err.text.contains("Chrome"), "{}", err.text);
    assert!(
        err.text
            .contains(&m.folder(Browser::Chrome).display().to_string())
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), old);
}

/// T22 INT-01.10: another program's file (`name` `other.host`) is never
/// removed, and never written over; its switch shows off.
#[test]
fn t22_another_programs_file_is_neither_removed_nor_replaced() {
    let h = Home::new();
    let m = h.manifests();
    let folder = m.folder(Browser::Chrome);
    fs::create_dir(&folder).unwrap();
    let theirs = br#"{"name":"other.host","path":"/bin/other","type":"stdio"}"#;
    fs::write(m.file(Browser::Chrome), theirs).unwrap();
    assert!(!m.is_on(Browser::Chrome));
    assert_eq!(m.turn_off(Browser::Chrome), Ok(()));
    assert_eq!(m.turn_on(Browser::Chrome).unwrap_err().id, "MI01-01");
    assert_eq!(fs::read(m.file(Browser::Chrome)).unwrap(), theirs);
}

/// INT-01.10: turning a browser off removes Larsal's own file.
#[test]
fn int01_10_off_removes_apps_file() {
    let h = Home::new();
    let m = h.manifests();
    m.turn_on(Browser::Edge).unwrap();
    m.turn_off(Browser::Edge).unwrap();
    assert!(!m.file(Browser::Edge).exists());
    assert!(!m.is_on(Browser::Edge));
    assert_eq!(m.turn_off(Browser::Edge), Ok(()), "already off");
}

/// "What must never happen": a file written outside the folders of
/// INT-01.8. A folder that is a link to elsewhere, a setup file that is a
/// link, and a planted link at the temporary file's name are refused, and
/// the place they point to is untouched.
#[test]
fn int01_10_links_never_lead_a_write_outside_the_folders() {
    let h = Home::new();
    let m = h.manifests();
    let elsewhere = h.folder.sub("elsewhere");
    // 1. The folder itself is a link.
    std::os::unix::fs::symlink(&elsewhere, m.folder(Browser::Chrome)).unwrap();
    assert_eq!(m.turn_on(Browser::Chrome).unwrap_err().id, "MI01-01");
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    // 2. The setup file is a link to a file elsewhere.
    let target = elsewhere.join("target.json");
    fs::write(&target, b"{}").unwrap();
    fs::create_dir(m.folder(Browser::Edge)).unwrap();
    std::os::unix::fs::symlink(&target, m.file(Browser::Edge)).unwrap();
    assert_eq!(m.turn_on(Browser::Edge).unwrap_err().id, "MI01-01");
    assert_eq!(m.turn_off(Browser::Edge), Ok(()));
    assert!(
        fs::symlink_metadata(m.file(Browser::Edge)).is_ok(),
        "the link was removed"
    );
    assert_eq!(fs::read(&target).unwrap(), b"{}");
    // 3. A link planted at the temporary file's name.
    fs::create_dir(m.folder(Browser::Brave)).unwrap();
    let temp = m.folder(Browser::Brave).join(format!(
        ".app.larsal.browser.json.{}.tmp",
        std::process::id()
    ));
    std::os::unix::fs::symlink(&target, &temp).unwrap();
    assert_eq!(m.turn_on(Browser::Brave).unwrap_err().id, "MI01-01");
    assert_eq!(fs::read(&target).unwrap(), b"{}");
}

/// INT-01.10: with no home folder (an empty `HOME`), nothing is written
/// relative to the current folder.
#[test]
fn int01_10_no_home_folder_writes_nothing() {
    let h = Home::new();
    let m = Manifests::new(Path::new(""), &h.program, &[], ADDON_ID);
    assert_eq!(m.turn_on(Browser::Chrome).unwrap_err().id, "MI01-01");
    assert!(!Path::new("Library").exists());
}

/// T23 INT-01.11 (S-BRW-21 on): a file that names an old copy of Larsal is
/// written again with the current path at start; a current one is left.
#[test]
fn t23_rewrite_at_start_puts_the_current_path() {
    let h = Home::new();
    let old = Manifests::new(
        &h.home(),
        Path::new("/Applications/Old/Larsal.app/Contents/MacOS/larsal-bridge"),
        &[ID_A],
        ADDON_ID,
    );
    old.turn_on(Browser::Chrome).unwrap();
    old.turn_on(Browser::Firefox).unwrap();
    let m = h.manifests();
    assert!(m.rewrite().is_empty());
    for b in [Browser::Chrome, Browser::Firefox] {
        assert_eq!(fs::read_to_string(m.file(b)).unwrap(), m.content(b));
    }
    assert!(!m.is_on(Browser::Edge), "rewrite turns no browser on");
}

/// T24 INT-01.11 (S-BRW-21 off): MI01-02 for the browser whose file names
/// no existing `larsal-bridge`; none for a current file.
#[test]
fn t24_stale_file_gives_mi01_02() {
    let h = Home::new();
    let old = Manifests::new(
        &h.home(),
        Path::new("/Applications/Old/Larsal.app/Contents/MacOS/larsal-bridge"),
        &[],
        ADDON_ID,
    );
    old.turn_on(Browser::Brave).unwrap();
    let m = h.manifests();
    m.turn_on(Browser::Chrome).unwrap();
    let stale = m.stale();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].id, "MI01-02");
    assert!(stale[0].text.contains("Brave"), "{}", stale[0].text);
}

/// T74 INT-01.11, APP-01.30: the program the files name is missing: MI01-05
/// naming that path.
#[test]
fn t74_missing_program_gives_mi01_05() {
    let h = Home::new();
    let missing = h.folder.0.join("missing-proxy");
    let m = Manifests::new(&h.home(), &missing, &[], ADDON_ID);
    let t = m.program_missing().unwrap();
    assert_eq!(t.id, "MI01-05");
    assert!(t.text.contains(&missing.display().to_string()));
    assert!(h.manifests().program_missing().is_none());
}

// ---- The two sockets (INT-01.6, INT-01.7, INT-01.13 to INT-01.15) ----

struct Nothing;

impl Handler for Nothing {
    fn handle(&mut self, _: &Request<'_>) -> Result<Map, u8> {
        Ok(Map::new())
    }
}

fn bridge() -> Arc<Mutex<Bridge>> {
    Arc::new(Mutex::new(Bridge::new("1.0", Box::new(Nothing))))
}

fn now() -> Clock {
    Arc::new(Instant::now)
}

const TEAM: &str = "ABCDE12345";

/// The signature reader of a signed test build: notes each requirement it
/// is asked about, and answers `pass`.
fn reader(pass: bool, asked: Arc<Mutex<Vec<String>>>) -> Signature {
    Arc::new(move |_: &UnixStream, req: &str| {
        asked.lock().unwrap().push(req.to_owned());
        pass
    })
}

fn quiet_log() -> Box<dyn Fn(&str) + Send> {
    Box::new(|_| {})
}

/// A test temp folder and a test group folder, and listeners over them.
struct Sockets {
    /// Kept for its removal at the end.
    _folder: Folder,
    temp: PathBuf,
    group: PathBuf,
}

impl Sockets {
    fn new() -> Self {
        let folder = Folder::new();
        let temp = folder.sub("T");
        let group = folder.0.join(format!("{TEAM}.app.larsal.browser"));
        Self {
            _folder: folder,
            temp,
            group,
        }
    }

    fn signed(&self) -> Option<Signed> {
        Some(Signed {
            team: TEAM.into(),
            group: self.group.clone(),
        })
    }

    fn listeners(&self, signed: bool, signature: Signature) -> Listeners {
        let signed = if signed { self.signed() } else { None };
        Listeners::with(bridge(), now(), &self.temp, signed, signature, quiet_log())
    }
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut f = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

fn hello_body() -> Vec<u8> {
    let key = base64::encode(Form::Padded, &Secret::generate().unwrap().public());
    format!(r#"{{"type":"hello","versions":[1],"key":"{key}","browser":"Safari"}}"#).into_bytes()
}

/// One message on a new connection; `None` when Larsal closed it with no reply.
fn ask(path: &Path, body: &[u8]) -> Option<Value> {
    let mut s = UnixStream::connect(path).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = s.write_all(&frame(body));
    let mut head = [0u8; 4];
    s.read_exact(&mut head).ok()?;
    let mut reply = vec![0u8; u32::from_le_bytes(head) as usize];
    s.read_exact(&mut reply).ok()?;
    Some(json::from_slice(&reply).unwrap())
}

fn is_hello(v: &Option<Value>) -> bool {
    v.as_ref()
        .and_then(|v| v.get("type"))
        .and_then(Value::as_str)
        == Some("hello")
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o777
}

/// T12 INT-01.6: the bridge socket listens in the temp folder only while
/// S-BRW-01 is on, mode 0600; off closes the listener and removes it.
#[test]
fn t12_bridge_socket_listens_only_while_integration_is_on() {
    let s = Sockets::new();
    let mut l = s.listeners(false, reader(true, Arc::default()));
    let path = s.temp.join(BRIDGE_SOCKET);
    assert_eq!(l.port_socket(), path);
    assert!(l.apply(false, true).is_empty());
    assert!(!path.exists());
    assert!(l.apply(true, false).is_empty());
    assert_eq!(l.listening(), (true, false));
    assert_eq!(mode(&path), 0o600);
    assert!(is_hello(&ask(&path, &hello_body())));
    assert!(l.apply(false, false).is_empty());
    assert_eq!(l.listening(), (false, false));
    assert!(!path.exists());
}

/// T13 INT-01.6: a regular file where the socket goes: MI01-06 naming the
/// path, the file untouched, no listener; once it is gone, the next apply
/// listens.
#[test]
fn t13_something_in_the_way_gives_mi01_06_and_no_listener() {
    let s = Sockets::new();
    let path = s.temp.join(BRIDGE_SOCKET);
    fs::write(&path, b"not a socket").unwrap();
    let mut l = s.listeners(false, reader(true, Arc::default()));
    let trouble = l.apply(true, false);
    assert_eq!(trouble.len(), 1);
    assert_eq!(trouble[0].id, "MI01-06");
    assert!(trouble[0].text.contains(&path.display().to_string()));
    assert_eq!(fs::read(&path).unwrap(), b"not a socket");
    assert_eq!(l.listening(), (false, false));
    fs::remove_file(&path).unwrap();
    assert!(l.apply(true, false).is_empty());
    assert_eq!(l.listening(), (true, false));
}

/// T27 INT-01.15: an unsigned build has no team id: the Safari switch is
/// not allowed (the page shows it disabled with MI01-04) and the Safari
/// socket never listens, whatever the settings say.
#[test]
fn t27_unsigned_build_never_listens_on_the_safari_socket() {
    let s = Sockets::new();
    let mut l = s.listeners(false, reader(true, Arc::default()));
    assert!(!l.safari_allowed());
    assert_eq!(l.safari_socket(), None);
    assert!(l.apply(true, true).is_empty());
    assert_eq!(l.listening(), (true, false));
    assert!(!s.group.exists());
    assert_eq!(
        larsal_browser::MI01_04,
        "Safari needs a signed copy of Larsal. This build is not signed."
    );
}

/// INT-01.15: a team id not of Apple's form counts as none.
#[test]
fn int01_15_a_malformed_team_id_counts_as_unsigned() {
    let s = Sockets::new();
    let signed = Some(Signed {
        team: "abc\" or always".into(),
        group: s.group.clone(),
    });
    let l = Listeners::with(
        bridge(),
        now(),
        &s.temp,
        signed,
        reader(true, Arc::default()),
        quiet_log(),
    );
    assert!(!l.safari_allowed());
}

/// The epic's Safari check (INT-01.13): in a signed build Larsal listens on
/// `bridge.sock` in the (test) group folder only while S-BRW-01 and the
/// Safari switch are both on, mode 0600 in an owner-only folder; turning
/// either off removes it.
#[test]
fn int01_13_safari_socket_listens_only_while_both_switches_are_on() {
    let s = Sockets::new();
    let mut l = s.listeners(true, reader(true, Arc::default()));
    let path = s.group.join(SAFARI_SOCKET);
    assert!(l.safari_allowed());
    assert_eq!(l.safari_socket(), Some(path.clone()));
    for (enabled, safari) in [(false, true), (true, false), (false, false)] {
        assert!(l.apply(enabled, safari).is_empty());
        assert!(!l.listening().1, "{enabled} {safari}");
        assert!(!path.exists(), "{enabled} {safari}");
    }
    assert!(l.apply(true, true).is_empty());
    assert_eq!(l.listening(), (true, true));
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&s.group), 0o700);
    assert!(is_hello(&ask(&path, &hello_body())));
    assert!(l.apply(true, false).is_empty());
    assert!(!path.exists());
    assert_eq!(l.listening(), (true, false));
    assert!(l.apply(true, true).is_empty());
    assert!(l.apply(false, true).is_empty());
    assert!(!path.exists());
    assert_eq!(l.listening(), (false, false));
}

/// INT-01.13 with INT-01.6's leftover rules on the Safari socket: a
/// leftover socket of the user's is replaced; anything else is MI01-06,
/// untouched, no listener.
#[test]
fn int01_13_safari_socket_keeps_the_leftover_file_rules() {
    let s = Sockets::new();
    fs::create_dir(&s.group).unwrap();
    fs::set_permissions(&s.group, fs::Permissions::from_mode(0o700)).unwrap();
    let path = s.group.join(SAFARI_SOCKET);
    drop(UnixListener::bind(&path).unwrap()); // a leftover socket file
    let mut l = s.listeners(true, reader(true, Arc::default()));
    assert!(l.apply(true, true).is_empty());
    assert!(is_hello(&ask(&path, &hello_body())));
    assert!(l.apply(true, false).is_empty());
    fs::write(&path, b"a file").unwrap();
    let trouble = l.apply(true, true);
    assert_eq!(trouble.len(), 1);
    assert_eq!(trouble[0].id, "MI01-06");
    assert_eq!(fs::read(&path).unwrap(), b"a file");
    assert_eq!(l.listening(), (true, false));
}

/// INT-01.6 and INT-01.13 against planted links: a link at either
/// socket's path, even to a live socket of the user's, is in the way
/// (MI01-06, the link and its target untouched, no listener); a temp
/// folder that is a link is not the user's folder, and nothing is made
/// where it points.
#[test]
fn int01_6_a_planted_link_is_in_the_way() {
    let s = Sockets::new();
    let root = s.temp.parent().unwrap().to_owned();
    fs::create_dir(&s.group).unwrap();
    fs::set_permissions(&s.group, fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.join("elsewhere.sock");
    let _other = UnixListener::bind(&target).unwrap();
    let paths = [s.temp.join(BRIDGE_SOCKET), s.group.join(SAFARI_SOCKET)];
    for path in &paths {
        std::os::unix::fs::symlink(&target, path).unwrap();
    }
    let mut l = s.listeners(true, reader(true, Arc::default()));
    let trouble = l.apply(true, true);
    assert_eq!(trouble.len(), 2, "{trouble:?}");
    assert!(trouble.iter().all(|t| t.id == "MI01-06"), "{trouble:?}");
    assert_eq!(l.listening(), (false, false));
    for path in &paths {
        assert_eq!(fs::read_link(path).unwrap(), target);
    }
    assert!(
        UnixStream::connect(&target).is_ok(),
        "the target still listens"
    );
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let linked = root.join("linked");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let signature = reader(true, Arc::default());
    let mut l = Listeners::with(bridge(), now(), &linked, None, signature, quiet_log());
    assert_eq!(l.apply(true, false).len(), 1);
    assert_eq!(l.listening(), (false, false));
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
}

/// INT-01.14: turning the Safari switch off ends the Safari sessions: a
/// box for an old `sid` gets error 3 once the socket is back.
#[test]
fn int01_14_safari_switch_off_ends_its_sessions() {
    let s = Sockets::new();
    let mut l = s.listeners(true, reader(true, Arc::default()));
    l.apply(true, true);
    let path = s.group.join(SAFARI_SOCKET);
    let mut c = Client::hello(&path);
    assert_eq!(kind(&c.status(&path)), Some("box"));
    l.apply(true, false);
    l.apply(true, true);
    assert_eq!(c.status(&path), Some(plain(3)));
}

/// T15 INT-01.7 (signed test build, injected reader): a peer whose code
/// does not meet the requirement is closed with no reply, on both sockets;
/// one that does is served. The requirement names Larsal's team and Larsal's
/// two relays, and nothing else.
#[test]
fn t15_signed_build_closes_a_peer_signed_differently() {
    let s = Sockets::new();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let mut l = s.listeners(true, reader(false, asked.clone()));
    l.apply(true, true);
    for path in [s.temp.join(BRIDGE_SOCKET), s.group.join(SAFARI_SOCKET)] {
        assert_eq!(ask(&path, &hello_body()), None, "{}", path.display());
    }
    let want = requirement(TEAM).unwrap();
    assert_eq!(
        asked.lock().unwrap().as_slice(),
        [want.clone(), want.clone()]
    );
    assert_eq!(
        want,
        format!(
            r#"anchor apple generic and certificate leaf[subject.OU] = "{TEAM}" and (identifier "{}" or identifier "{}")"#,
            RELAYS[0], RELAYS[1]
        )
    );
    drop(l);
    let mut l = s.listeners(true, reader(true, Arc::default()));
    l.apply(true, true);
    assert!(is_hello(&ask(&s.temp.join(BRIDGE_SOCKET), &hello_body())));
    assert!(is_hello(&ask(&s.group.join(SAFARI_SOCKET), &hello_body())));
}

/// T15 INT-01.7 (unsigned build): no signature check at all, the peer is
/// served, and the build says so once in the debug log, however often the
/// socket starts.
#[test]
fn t15_unsigned_build_serves_the_peer_and_logs_once() {
    let s = Sockets::new();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let lines = Arc::new(AtomicUsize::new(0));
    let count = lines.clone();
    let log: Box<dyn Fn(&str) + Send> = Box::new(move |line: &str| {
        assert!(line.contains("unsigned"), "{line}");
        count.fetch_add(1, Ordering::SeqCst);
    });
    let mut l = Listeners::with(
        bridge(),
        now(),
        &s.temp,
        None,
        reader(false, asked.clone()),
        log,
    );
    for _ in 0..3 {
        l.apply(true, true);
        assert!(is_hello(&ask(&s.temp.join(BRIDGE_SOCKET), &hello_body())));
        l.apply(false, false);
    }
    assert!(
        asked.lock().unwrap().is_empty(),
        "an unsigned build checked a signature"
    );
    assert_eq!(lines.load(Ordering::SeqCst), 1);
}

/// INT-01.7: only a team id of Apple's form goes into the requirement's
/// text (no quote, space or lower case can change its meaning).
#[test]
fn int01_7_requirement_takes_only_apples_team_id_form() {
    assert!(requirement(TEAM).is_some());
    for bad in [
        "",
        "ABCDE1234",
        "ABCDE123456",
        "abcde12345",
        "ABCDE\"1234",
        "ABCDE 1234",
        "ÄBCDE1234",
    ] {
        assert_eq!(requirement(bad), None, "{bad}");
    }
}

/// The real check (larsal-platform's) in an unsigned test build: this test
/// process is ad hoc signed, so it never meets Larsal's team requirement and
/// a signed Larsal would close it.
#[test]
fn int01_7_real_check_refuses_an_unsigned_peer() {
    let (a, _b) = UnixStream::pair().unwrap();
    assert!(!larsal_platform::macos::peer_meets(
        &a,
        &requirement(TEAM).unwrap()
    ));
}

// ---- T89: at most 32 Safari sessions (INT-01.44, LD-318 (3)) ----

fn plain(n: u64) -> Value {
    json::from_str(&format!(r#"{{"type":"error","error":{n}}}"#)).unwrap()
}

fn kind(v: &Option<Value>) -> Option<&str> {
    v.as_ref()
        .and_then(|v| v.get("type"))
        .and_then(Value::as_str)
}

/// The extension's side of one session, enough for a boxed `status`.
struct Client {
    sid: String,
    request: SecretBytes,
    nonce: u8,
}

impl Client {
    fn from_reply(secret: &Secret, reply: &Value) -> Self {
        let key = secret.public();
        let app: [u8; 32] =
            base64::decode(Form::Padded, reply.get("key").unwrap().as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let z = secret.agree(&app).unwrap();
        Self {
            sid: reply.get("sid").unwrap().as_str().unwrap().to_owned(),
            request: bridge::request_key(&z, &key, &app).unwrap(),
            nonce: 0,
        }
    }

    fn hello(path: &Path) -> Self {
        let secret = Secret::generate().unwrap();
        let body = format!(
            r#"{{"type":"hello","versions":[1],"key":"{}","browser":"Safari"}}"#,
            base64::encode(Form::Padded, &secret.public())
        );
        Self::from_reply(&secret, &ask(path, body.as_bytes()).unwrap())
    }

    fn status_box(&mut self) -> Vec<u8> {
        self.nonce += 1;
        let nonce = [self.nonce; 12];
        let sealed = bridge::seal(&self.request, &nonce, br#"{"type":"status","req":1}"#).unwrap();
        format!(
            r#"{{"type":"box","sid":"{}","nonce":"{}","box":"{}"}}"#,
            self.sid,
            base64::encode(Form::Padded, &nonce),
            base64::encode(Form::Padded, &sealed)
        )
        .into_bytes()
    }

    fn status(&mut self, path: &Path) -> Option<Value> {
        ask(path, &self.status_box())
    }
}

/// T89 INT-01.44: 33 Safari hellos, one per second (injected clock), then a
/// box for the first session and one for the 33rd: 32 sessions live after
/// the 33rd hello; the first gets error 3; the 33rd is answered. A
/// bridge-socket session never counts against the Safari cap.
#[test]
fn t89_at_most_32_safari_sessions_the_idlest_ends() {
    let bridge = bridge();
    let t0 = Instant::now();
    let port_secret = Secret::generate().unwrap();
    let port_hello = format!(
        r#"{{"type":"hello","versions":[1],"key":"{}"}}"#,
        base64::encode(Form::Padded, &port_secret.public())
    );
    let mut b = bridge.lock().unwrap();
    assert!(
        b.take(9_999, Route::Port, port_hello.as_bytes(), t0)
            .is_some()
    );
    let mut clients = Vec::new();
    for i in 0..=MAX_SAFARI as u64 {
        let secret = Secret::generate().unwrap();
        let body = format!(
            r#"{{"type":"hello","versions":[1],"key":"{}","browser":"Safari"}}"#,
            base64::encode(Form::Padded, &secret.public())
        );
        let at = t0 + Duration::from_secs(i);
        let reply =
            json::from_slice(&b.take(i, Route::Safari, body.as_bytes(), at).unwrap()).unwrap();
        clients.push(Client::from_reply(&secret, &reply));
    }
    assert_eq!(clients.len(), 33);
    assert_eq!(
        b.sessions(),
        MAX_SAFARI + 1,
        "32 Safari sessions and the bridge one"
    );
    let later = t0 + Duration::from_secs(40);
    let first = clients[0].status_box();
    let reply = json::from_slice(&b.take(100, Route::Safari, &first, later).unwrap()).unwrap();
    assert_eq!(reply, plain(3));
    let last = clients[32].status_box();
    let reply = json::from_slice(&b.take(101, Route::Safari, &last, later).unwrap()).unwrap();
    assert_eq!(reply.get("type").and_then(Value::as_str), Some("box"));
    // The second session is still live: only the idlest one ended.
    let second = clients[1].status_box();
    let reply = json::from_slice(&b.take(102, Route::Safari, &second, later).unwrap()).unwrap();
    assert_eq!(reply.get("type").and_then(Value::as_str), Some("box"));
}

/// LD-318 (3): "idle the longest", not "oldest": a session that made a
/// request lately stays, and the idlest other one ends.
#[test]
fn int01_44_the_cap_ends_the_idlest_not_the_oldest() {
    let bridge = bridge();
    let t0 = Instant::now();
    let mut b = bridge.lock().unwrap();
    let mut clients = Vec::new();
    for i in 0..MAX_SAFARI as u64 {
        let secret = Secret::generate().unwrap();
        let body = format!(
            r#"{{"type":"hello","versions":[1],"key":"{}"}}"#,
            base64::encode(Form::Padded, &secret.public())
        );
        let reply = json::from_slice(
            &b.take(
                i,
                Route::Safari,
                body.as_bytes(),
                t0 + Duration::from_secs(i),
            )
            .unwrap(),
        )
        .unwrap();
        clients.push(Client::from_reply(&secret, &reply));
    }
    // The first session asks something at t0 + 100 s: now the second is idlest.
    let at = t0 + Duration::from_secs(100);
    let busy = clients[0].status_box();
    assert!(b.take(200, Route::Safari, &busy, at).is_some());
    let secret = Secret::generate().unwrap();
    let body = format!(
        r#"{{"type":"hello","versions":[1],"key":"{}"}}"#,
        base64::encode(Form::Padded, &secret.public())
    );
    assert!(b.take(201, Route::Safari, body.as_bytes(), at).is_some());
    let reply = |b: &mut Bridge, c: &mut Client| {
        json::from_slice(&b.take(202, Route::Safari, &c.status_box(), at).unwrap()).unwrap()
    };
    assert_eq!(reply(&mut b, &mut clients[1]), plain(3));
    let v: Value = reply(&mut b, &mut clients[0]);
    assert_eq!(v.get("type").and_then(Value::as_str), Some("box"));
}
