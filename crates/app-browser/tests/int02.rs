//! INT-02's cases on the vault side (story E7-S2), with INT-03's cases
//! that run "through `logins.find`" (T71 to T76, T86) and INT-01's T59.
//! No browser and no socket: requests go straight to [`VaultSide`] over a
//! demo set of vaults; dialogs are answered by a scripted answerer thread
//! through [`Prompts`]; a fake clock drives the dialog times. The demo
//! vault V is the card's: groups Web, Hidden (hidden), Laptop (restricted
//! to `laptop`) and the recycle bin, entries E1 to E10. Demo data only.

use app_browser::{
    Answer, Changed, Live, MAX_QUEUE, OpenVault, Options, Prompts, Question, Request,
    SharedHandler, State, VaultSide, Vaults, entry_id, last_use, names, pairing_words,
    read_entry_id, vault_id,
};
use app_crypto::base64::{self, Form};
use app_crypto::secret::SecretString;
use app_model::json::{self, Map, Value};
use app_model::{CustomDataItem, Entry, Field, Group, Time, Uuid, Vault};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const K1: [u8; 32] = [1; 32];
const K2: [u8; 32] = [2; 32];
const K3: [u8; 32] = [3; 32];
const APP: [u8; 32] = [0xA0; 32];
const CLIENT: [u8; 32] = [0xC0; 32];
/// 2026-10-28T09:12:00Z.
const T: i64 = 1_793_178_720;
/// The association prefix, stored encoded (AGENTS.md rule 1).
const PREFIX: [u8; 13] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F,
];
/// The site access item's key, stored encoded.
const SITE: [u8; 26] = [
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73, 0x65,
    0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
];

fn prefix() -> String {
    String::from_utf8(PREFIX.to_vec()).unwrap()
}

fn site_key() -> String {
    String::from_utf8(SITE.to_vec()).unwrap()
}

fn time(secs: i64) -> Time {
    Time::from_unix(secs).unwrap()
}

fn item(key: &str, value: &str) -> CustomDataItem {
    CustomDataItem {
        key: key.into(),
        value: value.into(),
        last_modified: None,
        unknown: Vec::new(),
    }
}

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected: name == "Password",
        },
    );
}

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

fn entry(n: u8, title: &str, user: &str, pass: &str, url: &str) -> Entry {
    let mut e = Entry::new(id(n), time(T - 86_400 * 30));
    set(&mut e, "Title", title);
    set(&mut e, "UserName", user);
    set(&mut e, "Password", pass);
    set(&mut e, "URL", url);
    e
}

fn group(n: u8, name: &str) -> Group {
    Group::new(Uuid([0x80 | n; 16]), name.into(), time(T - 86_400 * 30))
}

fn flag(data: &mut app_model::CustomData, key: &str, value: &str) {
    data.items.push(item(key, value));
}

fn associate(v: &mut Vault, name: &str, key: &[u8; 32]) {
    let b = base64::encode(Form::Padded, key);
    flag(&mut v.meta.custom_data, &format!("{}{name}", prefix()), &b);
    flag(
        &mut v.meta.custom_data,
        &format!("_CREATED_{name}"),
        "2026-10-24T08:11:00Z",
    );
}

/// Demo vault V of INT-02's test cases.
fn vault_v() -> Vault {
    let mut root = group(0, "V");
    let mut web = group(1, "Web");
    let mut e1 = entry(
        1,
        "Example Mail",
        "alex",
        "demo-mail-pass",
        "https://mail.example.com/login",
    );
    set(&mut e1, "TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
    web.entries.push(e1);
    web.entries.push(entry(
        2,
        "Example (work)",
        "work-bot",
        "demo-mail-pass-2",
        "https://example.com",
    ));
    let mut e3 = entry(3, "Hidden one", "", "x3", "https://example.com");
    flag(&mut e3.custom_data, "BrowserHideEntry", "true");
    web.entries.push(e3);
    let mut e4 = entry(4, "Expired one", "", "x4", "https://example.com");
    e4.times.expires = true;
    e4.times.expiry = time(T - 86_400);
    web.entries.push(e4);
    let mut e5 = entry(5, "Router", "admin", "x5", "http://192.168.1.1");
    flag(&mut e5.custom_data, "BrowserOnlyHttpAuth", "true");
    web.entries.push(e5);
    let mut e6 = entry(6, "Shop", "", "x6", "https://shop.example.org");
    set(&mut e6, "KPH: pin", "1234");
    flag(&mut e6.custom_data, "BrowserSkipAutoSubmit", "true");
    web.entries.push(e6);
    web.entries.push(entry(
        7,
        "Ref user",
        &format!("{{REF:U@I:{}}}", entry_id(id(1))),
        "demo-net-pass",
        "https://example.net",
    ));
    let mut hidden = group(2, "Hidden");
    flag(&mut hidden.custom_data, "BrowserHideEntry", "true");
    hidden
        .entries
        .push(entry(8, "E8", "", "x8", "https://example.com"));
    let mut laptop = group(3, "Laptop");
    flag(&mut laptop.custom_data, "BrowserRestrictKey", "laptop");
    laptop
        .entries
        .push(entry(9, "E9", "", "x9", "https://example.com"));
    let mut bin = group(4, "Recycle Bin");
    bin.entries
        .push(entry(10, "E10", "", "x10", "https://example.com"));
    let bin_id = bin.uuid;
    root.groups = vec![web, hidden, laptop, bin];
    let mut v = Vault::new(root, time(T - 86_400 * 30));
    v.meta.name = "Access demo".into();
    v.meta.recycle_bin = Some(bin_id);
    associate(&mut v, "demo", &K1);
    associate(&mut v, "laptop", &K2);
    v
}

/// Demo vault W: `demo` = K1; E11 `https://example.com`.
fn vault_w() -> Vault {
    let mut root = group(9, "W");
    root.entries
        .push(entry(11, "E11", "w", "x11", "https://example.com"));
    let mut v = Vault::new(root, time(T - 86_400 * 30));
    associate(&mut v, "demo", &K1);
    v
}

struct Slot {
    id: u64,
    name: String,
    shown: bool,
    unlocked: bool,
    vault: Vault,
    changes: Vec<Changed>,
}

/// App's open vaults for the tests, with a fake clock.
struct Demo {
    slots: Mutex<Vec<Slot>>,
    options: Mutex<Options>,
    now: AtomicU64,
    notes: Mutex<Vec<String>>,
}

impl Vaults for Demo {
    fn list(&self) -> Vec<OpenVault> {
        self.slots
            .lock()
            .unwrap()
            .iter()
            .map(|s| OpenVault {
                id: s.id,
                name: s.name.clone(),
                shown: s.shown,
                unlocked: s.unlocked,
            })
            .collect()
    }
    fn with(&self, id: u64, f: &mut dyn FnMut(&mut Vault, &str) -> Changed) -> bool {
        let mut slots = self.slots.lock().unwrap();
        let Some(s) = slots.iter_mut().find(|s| s.id == id && s.unlocked) else {
            return false;
        };
        let c = f(&mut s.vault, "/tmp/demo");
        s.changes.push(c);
        true
    }
    fn options(&self) -> Options {
        *self.options.lock().unwrap()
    }
    fn now(&self) -> Time {
        time(i64::try_from(self.now.load(Ordering::SeqCst)).unwrap())
    }
    fn computer(&self) -> String {
        "Test Mac".into()
    }
    fn notify(&self, text: &str) {
        self.notes.lock().unwrap().push(text.into());
    }
}

/// The vault side with V shown and unlocked and W locked, a dialog line
/// on a fake clock, and how many times the dialog on screen changed.
struct Fixture {
    demo: Arc<Demo>,
    prompts: Arc<Prompts>,
    side: VaultSide,
    added: Arc<AtomicU64>,
    shows: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let demo = Arc::new(Demo {
            slots: Mutex::new(vec![
                Slot {
                    id: 1,
                    name: "access-demo".into(),
                    shown: true,
                    unlocked: true,
                    vault: vault_v(),
                    changes: Vec::new(),
                },
                Slot {
                    id: 2,
                    name: "second-demo".into(),
                    shown: false,
                    unlocked: false,
                    vault: vault_w(),
                    changes: Vec::new(),
                },
            ]),
            options: Mutex::new(Options::default()),
            now: AtomicU64::new(u64::try_from(T).unwrap()),
            notes: Mutex::default(),
        });
        let added = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let clock_added = added.clone();
        let shows = Arc::new(AtomicUsize::new(0));
        let counted = shows.clone();
        let prompts = Arc::new(Prompts::new(
            Arc::new(move || start + Duration::from_secs(clock_added.load(Ordering::SeqCst))),
            Box::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            }),
        ));
        let side = VaultSide::new(demo.clone(), prompts.clone());
        Self {
            demo,
            prompts,
            side,
            added,
            shows,
        }
    }

    fn options(&self, f: impl FnOnce(&mut Options)) {
        f(&mut self.demo.options.lock().unwrap());
    }

    fn unlock_w(&self) {
        self.demo.slots.lock().unwrap()[1].unlocked = true;
    }

    fn lock_v(&self) {
        self.demo.slots.lock().unwrap()[0].unlocked = false;
    }

    fn v<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> R {
        f(&mut self.demo.slots.lock().unwrap()[0].vault)
    }

    fn changes(&self) -> Vec<Changed> {
        self.demo.slots.lock().unwrap()[0].changes.clone()
    }

    fn e<R>(&self, n: u8, f: impl FnOnce(&mut Entry) -> R) -> R {
        self.v(|v| {
            let mut stack = vec![&mut v.root];
            while let Some(g) = stack.pop() {
                if let Some(e) = g.entries.iter_mut().find(|e| e.uuid == id(n)) {
                    return f(e);
                }
                stack.extend(g.groups.iter_mut());
            }
            panic!("no entry {n}");
        })
    }

    fn vid(&self, slot: usize) -> String {
        vault_id(&self.demo.slots.lock().unwrap()[slot].vault)
    }

    /// A request of `kind` with `fields` from session `live`, proven with
    /// `key`.
    fn send(
        &self,
        live: &Live,
        key: Option<&[u8; 32]>,
        kind: &str,
        fields: &str,
    ) -> Result<Map, u8> {
        let text = format!(
            r#"{{"type":"{kind}","req":7{}{fields}}}"#,
            if fields.is_empty() { "" } else { "," }
        );
        let Ok(Value::Object(content)) = json::from_str(&text) else {
            panic!("bad test request {text}");
        };
        let request = Request {
            kind,
            content: &content,
            browser: "Firefox",
            identity: key,
            session: live,
            keys: (&APP, &CLIENT),
        };
        self.side.handle(&request)
    }

    fn k1(&self, kind: &str, fields: &str) -> Result<Map, u8> {
        self.send(&Live::default(), Some(&K1), kind, fields)
    }

    fn find(&self, url: &str) -> Result<Vec<Map>, u8> {
        self.k1(
            "logins.find",
            &format!(r#""url":"{url}","top_url":"{url}""#),
        )
        .map(|m| list(&m))
    }

    fn ids(&self, ns: &[u8]) -> String {
        let vid = self.vid(0);
        let ids: Vec<String> = ns
            .iter()
            .map(|n| format!(r#"{{"vault":"{vid}","id":"{}"}}"#, entry_id(id(*n))))
            .collect();
        format!(r#""ids":[{}]"#, ids.join(","))
    }

    fn get(&self, ns: &[u8], page: &str) -> Result<Vec<Map>, u8> {
        self.k1(
            "logins.get",
            &format!(r#"{},"url":"{page}","top_url":"{page}""#, self.ids(ns)),
        )
        .map(|m| list(&m))
    }

    /// Answers the next dialog with what `answer` makes of its question,
    /// on a thread of its own, the way the screen does.
    fn answer(
        &self,
        answer: impl FnOnce(&Question) -> Answer + Send + 'static,
    ) -> std::thread::JoinHandle<Question> {
        let prompts = self.prompts.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some((n, q)) = prompts.current() {
                    assert!(prompts.answer(n, answer(&q)));
                    return q;
                }
                assert!(Instant::now() < deadline, "no dialog came");
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    }
}

fn list(m: &Map) -> Vec<Map> {
    m["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_object().unwrap().clone())
        .collect()
}

fn titles(entries: &[Map]) -> Vec<String> {
    entries
        .iter()
        .map(|e| e["title"].as_str().unwrap().to_owned())
        .collect()
}

fn s<'a>(m: &'a Map, key: &str) -> &'a str {
    m[key].as_str().unwrap()
}

fn allow_all(q: &Question) -> Answer {
    let Question::Access(a) = q else {
        panic!("not a site access prompt")
    };
    Answer::Allow {
        checked: vec![true; a.rows.len()],
        remember: false,
    }
}

fn site_item(f: &Fixture, n: u8) -> Option<String> {
    f.e(n, |e| e.custom_data.get(&site_key()).map(str::to_owned))
}

/// After 10 s, moves the fake clock past every dialog time, so a dialog
/// that never closes fails its test instead of hanging it.
struct Watchdog {
    done: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<bool>,
}

impl Watchdog {
    fn new(f: &Fixture) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let (stop, added) = (done.clone(), f.added.clone());
        let thread = std::thread::spawn(move || {
            for _ in 0..1_000 {
                if stop.load(Ordering::SeqCst) {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            added.fetch_add(3_600, Ordering::SeqCst);
            true
        });
        Self { done, thread }
    }

    /// `true` when the clock had to move.
    fn fired(self) -> bool {
        self.done.store(true, Ordering::SeqCst);
        self.thread.join().unwrap()
    }
}

fn set_site(f: &Fixture, n: u8, text: &str) {
    f.e(n, |e| e.custom_data.items.push(item(&site_key(), text)));
}

// ---------------------------------------------------------------------------
// Associations (INT-02.1 to INT-02.8).

#[test]
fn t01_t07_int02_1_4_connect_dialog_names_the_vault_and_writes_the_association_on_connect() {
    let f = Fixture::new();
    let screen = f.answer(|_| Answer::Connect("Chrome on Test".into()));
    let reply = f.send(&Live::default(), Some(&K3), "connect", "").unwrap();
    let Question::Connect(q) = screen.join().unwrap() else {
        panic!("not the Connect dialog")
    };
    // T07: the default name and the vault's name; the four words (INT-02.5).
    assert_eq!(q.name, "Firefox on Test Mac");
    assert!(q.text.contains("“Access demo”"), "{}", q.text);
    assert_eq!(
        q.words,
        format!(
            "Check that the extension shows: {}",
            pairing_words(&APP, &CLIENT, &K3)
        )
    );
    assert_eq!(s(&reply, "name"), "Chrome on Test");
    assert_eq!(s(&reply, "vault"), f.vid(0));
    f.v(|v| {
        let cd = &v.meta.custom_data;
        let key = base64::encode(Form::Padded, &K3);
        assert_eq!(
            cd.get(&format!("{}Chrome on Test", prefix())),
            Some(key.as_str())
        );
        assert_eq!(
            cd.get("_CREATED_Chrome on Test"),
            Some("2026-10-28T09:12:00Z")
        );
    });
    assert!(f.changes().contains(&Changed::Data));
}

#[test]
fn t05_int02_3_a_stored_key_is_answered_at_once_without_a_dialog() {
    let f = Fixture::new();
    let reply = f.k1("connect", "").unwrap();
    assert_eq!(
        (s(&reply, "name"), s(&reply, "vault")),
        ("demo", f.vid(0).as_str())
    );
    assert_eq!(f.shows.load(Ordering::SeqCst), 0);
}

#[test]
fn t04_int02_3_connect_on_a_locked_vault_gets_1_and_no_dialog() {
    let f = Fixture::new();
    f.lock_v();
    assert_eq!(f.send(&Live::default(), Some(&K3), "connect", ""), Err(1));
    // No proven key: error 8 (T06's proof fails in the channel first).
    assert_eq!(f.send(&Live::default(), None, "connect", ""), Err(8));
    assert_eq!(f.shows.load(Ordering::SeqCst), 0);
}

#[test]
fn t03_int02_2_the_default_name_skips_taken_and_invalid_names() {
    let f = Fixture::new();
    f.v(|v| associate(v, "Firefox on Test Mac", &K2));
    let screen = f.answer(|_| Answer::Deny { remember: false });
    let _ = f.send(&Live::default(), Some(&K3), "connect", r#""name":"demo""#);
    let Question::Connect(q) = screen.join().unwrap() else {
        panic!()
    };
    // `demo` is taken, so is "Firefox on Test Mac": the next free one.
    assert_eq!(q.name, "Firefox 2");
    assert!(app_browser::valid_name("   ").is_none());
    assert!(app_browser::valid_name(&"a".repeat(65)).is_none());
    assert!(app_browser::valid_name("a\u{7}").is_none());
    assert_eq!(
        app_browser::valid_name("  Firefox on Mac "),
        Some("Firefox on Mac")
    );
}

#[test]
fn int02_2_connect_never_overwrites_a_taken_name() {
    let f = Fixture::new();
    let screen = f.answer(|_| Answer::Connect("demo".into()));
    assert_eq!(f.send(&Live::default(), Some(&K3), "connect", ""), Err(6));
    screen.join().unwrap();
    f.v(|v| assert_eq!(names(v, &K1), ["demo"]));
    f.v(|v| assert!(names(v, &K3).is_empty()));
}

#[test]
fn t12_int02_6_deny_gives_6_and_writes_nothing() {
    let f = Fixture::new();
    let before = f.v(|v| v.meta.custom_data.items.len());
    let screen = f.answer(|_| Answer::Deny { remember: false });
    assert_eq!(f.send(&Live::default(), Some(&K3), "connect", ""), Err(6));
    screen.join().unwrap();
    assert_eq!(f.v(|v| v.meta.custom_data.items.len()), before);
    assert!(!f.changes().contains(&Changed::Data));
}

#[test]
fn t08_int02_4_connect_dialog_ends_as_deny_after_120_seconds() {
    let f = Fixture::new();
    let prompts = f.prompts.clone();
    let added = f.added.clone();
    let timer = std::thread::spawn(move || {
        while prompts.current().is_none() {
            std::thread::sleep(Duration::from_millis(2));
        }
        added.fetch_add(119, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(prompts.current().is_some(), "closed before 120 s");
        added.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(f.send(&Live::default(), Some(&K3), "connect", ""), Err(6));
    timer.join().unwrap();
    assert!(f.prompts.current().is_none());
    assert!(!f.changes().contains(&Changed::Data));
}

#[test]
fn t09_sr16_a_lock_closes_the_connect_dialog_and_writes_nothing() {
    let f = Fixture::new();
    let demo = f.demo.clone();
    let prompts = f.prompts.clone();
    let locker = std::thread::spawn(move || {
        while prompts.current().is_none() {
            std::thread::sleep(Duration::from_millis(2));
        }
        demo.slots.lock().unwrap()[0].unlocked = false;
    });
    let watchdog = Watchdog::new(&f);
    assert_eq!(f.send(&Live::default(), Some(&K3), "connect", ""), Err(6));
    locker.join().unwrap();
    assert!(!watchdog.fired(), "the dialog stayed open after the lock");
    assert!(f.prompts.current().is_none());
    assert!(!f.changes().contains(&Changed::Data));
}

#[test]
fn t31_int01_45_a_session_that_ends_closes_its_dialog_and_stores_nothing() {
    let f = Fixture::new();
    let live = Arc::new(Live::default());
    let ender = live.clone();
    let prompts = f.prompts.clone();
    let end = std::thread::spawn(move || {
        while prompts.current().is_none() {
            std::thread::sleep(Duration::from_millis(2));
        }
        ender.end();
    });
    let watchdog = Watchdog::new(&f);
    // The reply is dropped by the channel (Work::finish) once the session
    // ended; the vault side writes nothing.
    assert!(f.send(&live, Some(&K3), "connect", "").is_err());
    end.join().unwrap();
    assert!(
        !watchdog.fired(),
        "the dialog stayed open after the session ended"
    );
    assert!(f.prompts.current().is_none());
    assert!(!f.changes().contains(&Changed::Data));
}

#[test]
fn t10_int02_5_pairing_words_of_the_int01_demo_keys() {
    let hex = |h: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    };
    let a = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let c = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let i = hex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
    // INT-01.50's current A, C and I give SHA-256 476bfcad…411f7e; T10's
    // listed digest e5c612d6… is of earlier demo keys (the card's words
    // for it, "suspense bagginess crucial mongoose", follow from the same
    // word step). Both computed outside App with the shipped word list.
    let d = app_crypto::hash::sha256(&[b"browser-bridge pairing v1", &a, &c, &i]);
    assert_eq!(
        d.expose()[..8],
        [0x47, 0x6b, 0xfc, 0xad, 0xf9, 0x8c, 0x72, 0x6d]
    );
    assert_eq!(
        pairing_words(&a, &c, &i),
        "nutshell speech regretful pretense"
    );
    // The order is App's key, then the client's (INT-02.5).
    assert_ne!(pairing_words(&c, &a, &i), pairing_words(&a, &c, &i));
}

#[test]
fn t13_t14_int02_7_check_lists_every_unlocked_vault_holding_the_key() {
    let f = Fixture::new();
    f.unlock_w();
    let reply = f.k1("check", "").unwrap();
    let vaults = reply["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 2);
    for v in vaults {
        assert_eq!(v.as_object().unwrap()["connection"].as_str(), Some("demo"));
    }
    assert_eq!(f.send(&Live::default(), Some(&K3), "check", ""), Err(8));
}

#[test]
fn t86_int01_30_disconnect_removes_the_items_and_names_the_locked_vaults() {
    let f = Fixture::new();
    f.v(|v| {
        flag(
            &mut v.meta.custom_data,
            "_LAST_USED_demo",
            "2026-10-28T09:12:00Z",
        )
    });
    let reply = f.k1("disconnect", "").unwrap();
    assert_eq!(reply["unchanged"], Value::from(vec!["second-demo"]));
    f.v(|v| {
        let cd = &v.meta.custom_data;
        for k in [
            format!("{}demo", prefix()),
            "_CREATED_demo".into(),
            "_LAST_USED_demo".into(),
        ] {
            assert!(cd.get(&k).is_none(), "{k} stayed");
        }
        assert!(cd.get(&format!("{}laptop", prefix())).is_some());
    });
    // INT-02.8: the session's next request gets error 8.
    assert_eq!(f.find("https://example.com/"), Err(8));
}

#[test]
fn t15_int02_8_disconnect_in_vault_settings_removes_last_used_too() {
    let mut v = vault_v();
    flag(
        &mut v.meta.custom_data,
        "_LAST_USED_laptop",
        "2026-10-28T09:12:00Z",
    );
    assert_eq!(
        app_core::settings::remove_associations(&mut v, &["laptop"], time(T)),
        1
    );
    assert!(v.meta.custom_data.get("_LAST_USED_laptop").is_none());
    assert!(names(&v, &K2).is_empty());
}

// ---------------------------------------------------------------------------
// Which vaults and entries (INT-02.10 to INT-02.14).

#[test]
fn t18_t19_int02_10_one_vault_unless_search_all() {
    let f = Fixture::new();
    f.unlock_w();
    let only_v = f.find("https://example.com/").unwrap();
    assert_eq!(titles(&only_v), ["Example (work)"]);
    f.options(|o| o.search_all = true);
    let both = f.find("https://example.com/").unwrap();
    assert_eq!(titles(&both), ["Example (work)", "E11"]);
    assert_eq!(s(&both[1], "vault"), f.vid(1));
}

#[test]
fn int02_10_no_unlocked_vault_gives_1_and_an_unknown_key_gives_8() {
    let f = Fixture::new();
    assert_eq!(
        f.send(
            &Live::default(),
            Some(&K3),
            "logins.find",
            r#""url":"https://example.com/""#
        ),
        Err(8)
    );
    assert_eq!(
        f.send(
            &Live::default(),
            None,
            "logins.find",
            r#""url":"https://example.com/""#
        ),
        Err(8)
    );
    f.lock_v();
    assert_eq!(f.find("https://example.com/"), Err(1));
}

#[test]
fn t23_t24_int02_12_13_only_e2_reaches_example_com() {
    let f = Fixture::new();
    // E1 is below the page host, E3 hidden, E4 expired, E8 in a hidden
    // group, E9 restricted to `laptop`, E10 in the recycle bin.
    assert_eq!(
        titles(&f.find("https://example.com/login").unwrap()),
        ["Example (work)"]
    );
}

#[test]
fn t25_int02_13_a_restricted_group_reaches_its_browser() {
    let f = Fixture::new();
    let found = f
        .send(
            &Live::default(),
            Some(&K2),
            "logins.find",
            r#""url":"https://example.com/login""#,
        )
        .unwrap();
    assert_eq!(titles(&list(&found)), ["Example (work)", "E9"]);
}

#[test]
fn t26_int02_13_expired_entries_with_s_brw_13() {
    let f = Fixture::new();
    f.options(|o| o.allow_expired = true);
    let found = f.find("https://example.com/login").unwrap();
    assert_eq!(titles(&found), ["Example (work)", "Expired one"]);
    assert_eq!(found[1]["expired"], Value::Bool(true));
    assert!(!found[0].contains_key("expired"));
}

#[test]
fn t27_t28_t29_int02_13_14_http_sign_in_options() {
    let f = Fixture::new();
    let page = r#""url":"http://192.168.1.1/","top_url":"http://192.168.1.1/""#;
    assert_eq!(f.k1("logins.find", page), Err(15));
    let found = f
        .k1("logins.find", &format!(r#"{page},"http_auth":true"#))
        .unwrap();
    let found = list(&found);
    assert_eq!(titles(&found), ["Router"]);
    assert_eq!(s(&found[0], "access"), "ask");
    // T29: the group decides when it has the key.
    f.v(|v| {
        flag(
            &mut v.root.groups[0].custom_data,
            "BrowserOnlyHttpAuth",
            "false",
        )
    });
    assert_eq!(
        titles(&list(&f.k1("logins.find", page).unwrap())),
        ["Router"]
    );
}

#[test]
fn t30_int02_14_skip_submit_from_the_group() {
    let f = Fixture::new();
    f.v(|v| {
        flag(
            &mut v.root.groups[0].custom_data,
            "BrowserSkipAutoSubmit",
            "true",
        )
    });
    let found = f.find("https://example.com/").unwrap();
    assert_eq!(found[0]["skip_submit"], Value::Bool(true));
}

#[test]
fn int02_12_the_template_group_is_never_offered() {
    let f = Fixture::new();
    f.v(|v| v.meta.entry_templates_group = Some(v.root.groups[0].uuid));
    assert_eq!(f.find("https://example.com/"), Err(15));
}

// ---------------------------------------------------------------------------
// INT-03 through logins.find (LD-322 (7), SI-03's bridge half).

fn matcher_vault(f: &Fixture, entries: Vec<(u8, &str, Vec<&str>)>) {
    f.v(|v| {
        let web = &mut v.root.groups[0];
        web.entries.clear();
        for (n, main, extra) in entries {
            let mut e = entry(n, &format!("R{n}"), "", "p", main);
            for (i, x) in extra.iter().enumerate() {
                set(
                    &mut e,
                    &if i == 0 {
                        "KP2A_URL".into()
                    } else {
                        format!("KP2A_URL_{i}")
                    },
                    x,
                );
            }
            web.entries.push(e);
        }
    });
}

#[test]
fn t71_int03_1_a_page_app_cannot_match_gets_14() {
    let f = Fixture::new();
    assert_eq!(f.find("chrome://settings"), Err(14));
    assert_eq!(f.k1("logins.find", ""), Err(14));
    assert_eq!(
        f.k1(
            "logins.find",
            r#""url":"https://example.com/","top_url":"chrome://newtab""#
        ),
        Err(14)
    );
}

#[test]
fn t72_t73_int03_14_15_ranks_and_best_only() {
    let f = Fixture::new();
    matcher_vault(
        &f,
        vec![
            (21, "https://example.com/login", vec![]),
            (22, "https://example.com", vec![]),
            (23, "https://example.com/other", vec![]),
            (24, "https://example.com/login?x=1", vec![]),
        ],
    );
    let page = "https://example.com/login?x=1";
    assert_eq!(titles(&f.find(page).unwrap()), ["R24", "R21", "R22", "R23"]);
    f.options(|o| o.best_only = true);
    assert_eq!(titles(&f.find(page).unwrap()), ["R24"]);
}

#[test]
fn t74_t75_int03_14_page_and_form_ranks() {
    let f = Fixture::new();
    matcher_vault(
        &f,
        vec![
            (26, "https://example.com", vec![]),
            (25, "https://mail.example.com", vec![]),
        ],
    );
    assert_eq!(
        titles(&f.find("https://mail.example.com/").unwrap()),
        ["R25", "R26"]
    );
    matcher_vault(
        &f,
        vec![
            (28, "https://example.com/other", vec![]),
            (27, "https://example.com/session", vec![]),
        ],
    );
    let found = f
        .k1(
            "logins.find",
            r#""url":"https://www.example.com/login","top_url":"https://www.example.com/login","form_url":"https://example.com/session""#,
        )
        .unwrap();
    assert_eq!(titles(&list(&found)), ["R27", "R28"]);
}

#[test]
fn t76_int03_16_equal_ranks_keep_tree_order() {
    let f = Fixture::new();
    f.v(|v| {
        v.root.groups[0].entries.clear();
        v.root.groups[1].custom_data.items.clear();
        v.root.groups[1].entries = vec![entry(31, "G1 entry", "", "p", "https://example.com")];
        v.root.groups[2].custom_data.items.clear();
        v.root.groups[2].entries = vec![entry(32, "G2 entry", "", "p", "https://example.com")];
    });
    assert_eq!(
        titles(&f.find("https://example.com/").unwrap()),
        ["G1 entry", "G2 entry"]
    );
}

#[test]
fn t86_at_f05_lookalike_pages_get_15() {
    let f = Fixture::new();
    matcher_vault(&f, vec![(33, "https://bank.example.com", vec![])]);
    for page in [
        "https://bank.example.com.evil.example/",
        "https://xn--bnk-6cd.example.com/",
        "https://evil-bank.example.com/",
        "http://bank.example.com/",
        "https://bank.example.com:8443/",
    ] {
        assert_eq!(f.find(page), Err(15), "{page}");
    }
    assert!(f.find("https://bank.example.com/").is_ok());
}

// ---------------------------------------------------------------------------
// Site access (INT-02.15 to INT-02.19).

#[test]
fn t34_t36_int02_16_allowed_hosts_compare_in_ascii_form() {
    let f = Fixture::new();
    set_site(&f, 2, r#"{"Allow":["Example.COM"],"Deny":[]}"#);
    let got = f.get(&[2], "https://example.com/").unwrap();
    assert_eq!(s(&got[0], "password"), "demo-mail-pass-2");
    assert_eq!(f.shows.load(Ordering::SeqCst), 0);
    // T36: a Unicode host in Allow fits its Punycode page.
    f.e(2, |e| set(e, "URL", "https://bücher.example"));
    f.e(2, |e| e.custom_data.items.clear());
    set_site(&f, 2, r#"{"Allow":["bücher.example"],"Deny":[]}"#);
    let got = f.get(&[2], "https://xn--bcher-kva.example/").unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(f.shows.load(Ordering::SeqCst), 0);
}

#[test]
fn t35_t37_int02_16_remember_replaces_a_broken_item_with_the_card_form() {
    let f = Fixture::new();
    set_site(&f, 2, "{not json");
    let modified = f.e(2, |e| e.times.last_modification);
    let screen = f.answer(|_| Answer::Allow {
        checked: vec![true],
        remember: true,
    });
    assert_eq!(f.get(&[2], "https://example.com/").unwrap().len(), 1);
    screen.join().unwrap();
    assert_eq!(
        site_item(&f, 2).as_deref(),
        Some(r#"{"Allow":["example.com"],"Deny":[],"Realm":""}"#)
    );
    assert_ne!(f.e(2, |e| e.times.last_modification), modified);
    assert!(f.e(2, |e| e.history.is_empty()));
    // Now allowed: no dialog next time.
    let shows = f.shows.load(Ordering::SeqCst);
    assert_eq!(f.get(&[2], "https://example.com/").unwrap().len(), 1);
    assert_eq!(f.shows.load(Ordering::SeqCst), shows);
}

#[test]
fn t38_int02_17_a_denied_page_host_hides_the_entry() {
    let f = Fixture::new();
    set_site(&f, 2, r#"{"Allow":[],"Deny":["example.com"]}"#);
    assert_eq!(f.find("https://example.com/"), Err(15));
}

#[test]
fn ld322_7_int02_17_a_denied_form_host_hides_the_entry() {
    let f = Fixture::new();
    set_site(
        &f,
        2,
        r#"{"Allow":["example.com"],"Deny":["login.example.com"]}"#,
    );
    let page = r#""url":"https://example.com/","top_url":"https://example.com/","form_url":"https://login.example.com/x""#;
    assert_eq!(f.k1("logins.find", page), Err(15));
    assert_eq!(
        f.k1("logins.get", &format!("{},{page}", f.ids(&[2]))),
        Err(15)
    );
    // Without the form URL the entry is allowed.
    assert_eq!(
        s(&f.find("https://example.com/").unwrap()[0], "access"),
        "allowed"
    );
}

#[test]
fn t39_int02_17_a_form_host_not_in_allow_asks() {
    let f = Fixture::new();
    set_site(&f, 2, r#"{"Allow":["example.com"],"Deny":[]}"#);
    let screen = f.answer(allow_all);
    let got = f
        .k1(
            "logins.get",
            &format!(r#"{},"url":"https://example.com/","top_url":"https://example.com/","form_url":"https://login.example.com/x""#, f.ids(&[2])),
        )
        .unwrap();
    assert_eq!(list(&got).len(), 1);
    let Question::Access(q) = screen.join().unwrap() else {
        panic!()
    };
    assert_eq!(q.remember.as_deref(), Some("Remember for example.com"));
}

#[test]
fn t40_t72_int02_17_31_never_ask_gives_at_once_and_notifies_once_in_10_minutes() {
    let f = Fixture::new();
    f.options(|o| o.never_ask = true);
    assert_eq!(f.get(&[2], "https://example.com/").unwrap().len(), 1);
    assert_eq!(f.shows.load(Ordering::SeqCst), 0);
    f.demo.now.fetch_add(60, Ordering::SeqCst);
    f.get(&[2], "https://example.com/").unwrap();
    f.demo.now.fetch_add(11 * 60, Ordering::SeqCst);
    f.get(&[2], "https://example.com/").unwrap();
    let notes = f.demo.notes.lock().unwrap().clone();
    assert_eq!(notes, ["Firefox filled a sign-in on example.com."; 2]);
    for n in &notes {
        assert!(!n.contains("Example (work)") && !n.contains("work-bot"));
    }
}

#[test]
fn t41_t42_int02_17_http_sign_in_asks_unless_s_brw_17() {
    let f = Fixture::new();
    set_site(&f, 5, r#"{"Allow":["192.168.1.1"],"Deny":[]}"#);
    let page = r#""url":"http://192.168.1.1/","top_url":"http://192.168.1.1/","http_auth":true"#;
    let screen = f.answer(allow_all);
    assert!(
        f.k1("logins.get", &format!("{},{page}", f.ids(&[5])))
            .is_ok()
    );
    let Question::Access(q) = screen.join().unwrap() else {
        panic!()
    };
    assert_eq!(q.remember, None, "no Remember for HTTP sign-in");
    f.options(|o| o.skip_http_ask = true);
    let shows = f.shows.load(Ordering::SeqCst);
    assert!(
        f.k1("logins.get", &format!("{},{page}", f.ids(&[5])))
            .is_ok()
    );
    assert_eq!(f.shows.load(Ordering::SeqCst), shows);
}

#[test]
fn t43_int02_18_remember_allows_the_checked_and_denies_the_unchecked() {
    let f = Fixture::new();
    f.v(|v| {
        let mut b = entry(12, "Example (copy)", "copy", "x12", "https://example.com");
        b.uuid = id(12);
        v.root.groups[0].entries.push(b);
    });
    let screen = f.answer(|q| {
        let Question::Access(a) = q else { panic!() };
        assert_eq!(a.rows.len(), 2);
        Answer::Allow {
            checked: vec![true, false],
            remember: true,
        }
    });
    let got = f.get(&[2, 12], "https://example.com/").unwrap();
    screen.join().unwrap();
    assert_eq!(titles(&got), ["Example (work)"]);
    assert!(
        site_item(&f, 2)
            .unwrap()
            .starts_with(r#"{"Allow":["example.com"]"#)
    );
    assert!(
        site_item(&f, 12)
            .unwrap()
            .contains(r#""Deny":["example.com"]"#)
    );
}

#[test]
fn t44_int02_18_deny_with_remember_denies_every_row() {
    let f = Fixture::new();
    let screen = f.answer(|_| Answer::Deny { remember: true });
    assert_eq!(f.get(&[2], "https://example.com/"), Err(6));
    screen.join().unwrap();
    assert!(
        site_item(&f, 2)
            .unwrap()
            .contains(r#""Deny":["example.com"]"#)
    );
    assert_eq!(f.find("https://example.com/"), Err(15));
}

#[test]
fn t45_int02_18_rows_show_resolved_titles_and_user_names() {
    let f = Fixture::new();
    let screen = f.answer(|_| Answer::Deny { remember: false });
    let _ = f.get(&[7], "https://example.net/");
    let Question::Access(q) = screen.join().unwrap() else {
        panic!()
    };
    assert_eq!(
        (q.rows[0].title.as_str(), q.rows[0].username.as_str()),
        ("Ref user", "alex")
    );
    assert_eq!(q.title, "Firefox asks for a sign-in on example.net");
}

#[test]
fn t33_int02_15_a_prompt_ends_as_deny_after_60_seconds_and_remembers_nothing() {
    let f = Fixture::new();
    let prompts = f.prompts.clone();
    let added = f.added.clone();
    let timer = std::thread::spawn(move || {
        while prompts.current().is_none() {
            std::thread::sleep(Duration::from_millis(2));
        }
        added.fetch_add(60, Ordering::SeqCst);
    });
    assert_eq!(f.get(&[2], "https://example.com/"), Err(6));
    timer.join().unwrap();
    assert_eq!(site_item(&f, 2), None);
}

#[test]
fn sr16_a_lock_closes_the_site_access_prompt_and_gives_nothing() {
    let f = Fixture::new();
    let demo = f.demo.clone();
    let prompts = f.prompts.clone();
    let locker = std::thread::spawn(move || {
        while prompts.current().is_none() {
            std::thread::sleep(Duration::from_millis(2));
        }
        demo.slots.lock().unwrap()[0].unlocked = false;
    });
    let watchdog = Watchdog::new(&f);
    assert_eq!(f.get(&[2], "https://example.com/"), Err(6));
    locker.join().unwrap();
    assert!(!watchdog.fired(), "the dialog stayed open after the lock");
    assert!(f.prompts.current().is_none());
}

#[test]
fn t31_int02_15_two_sessions_get_one_prompt_after_the_other() {
    let f = Arc::new(Fixture::new());
    let second = {
        let f = f.clone();
        std::thread::spawn(move || {
            while f.prompts.current().is_none() {
                std::thread::sleep(Duration::from_millis(2));
            }
            f.get(&[2], "https://example.com/")
        })
    };
    let screen = {
        let prompts = f.prompts.clone();
        std::thread::spawn(move || {
            let mut answered = 0;
            let mut last = None;
            while answered < 2 {
                if let Some((n, q)) = prompts.current()
                    && last != Some(n)
                {
                    // Only one dialog is ever on screen; each one is new.
                    last = Some(n);
                    std::thread::sleep(Duration::from_millis(30));
                    assert!(prompts.answer(n, allow_all(&q)));
                    answered += 1;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    assert_eq!(f.get(&[2], "https://example.com/").unwrap().len(), 1);
    assert_eq!(second.join().unwrap().unwrap().len(), 1);
    screen.join().unwrap();
    // Shown twice and closed twice.
    assert_eq!(f.shows.load(Ordering::SeqCst), 4);
}

#[test]
fn t32_int02_15_the_17th_waiting_request_gets_42() {
    let f = Arc::new(Fixture::new());
    let sessions: Vec<Arc<Live>> = (0..=MAX_QUEUE).map(|_| Arc::new(Live::default())).collect();
    let mut waiting = Vec::new();
    for live in sessions.iter().take(MAX_QUEUE + 1) {
        let (f, live) = (f.clone(), live.clone());
        waiting.push(std::thread::spawn(move || {
            let ids = f.ids(&[2]);
            f.send(
                &live,
                Some(&K1),
                "logins.get",
                &format!(r#"{ids},"url":"https://example.com/""#),
            )
        }));
        std::thread::sleep(Duration::from_millis(5));
    }
    // One shows and 16 wait; the 18th gets 42 at once (a late one that
    // waits instead ends after 2 s with 6).
    let late_live = Arc::new(Live::default());
    let ender = late_live.clone();
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        ender.end();
    });
    let late = f.send(
        &late_live,
        Some(&K1),
        "logins.get",
        &format!(r#"{},"url":"https://example.com/""#, f.ids(&[2])),
    );
    assert_eq!(late, Err(42));
    watchdog.join().unwrap();
    for live in &sessions {
        live.end();
    }
    for w in waiting {
        assert!(w.join().unwrap().is_err());
    }
}

#[test]
fn t59_int01_44_a_session_has_at_most_4_requests_waiting() {
    let f = Fixture::new();
    let live = Live::default();
    let held: Vec<_> = (0..4).map(|_| live.wait().unwrap()).collect();
    assert_eq!(
        f.send(
            &live,
            Some(&K1),
            "logins.get",
            &format!(r#"{},"url":"https://example.com/""#, f.ids(&[2]))
        ),
        Err(42)
    );
    drop(held);
    let again: Vec<_> = (0..4).map(|_| live.wait()).collect();
    assert!(again.iter().all(Option::is_some));
}

#[test]
fn t46_at_f06_int02_19_a_frame_of_another_site_always_asks_without_remember() {
    let f = Fixture::new();
    set_site(&f, 2, r#"{"Allow":["example.com"],"Deny":[]}"#);
    f.options(|o| o.never_ask = true);
    let screen = f.answer(|_| Answer::Allow {
        checked: vec![true],
        remember: true,
    });
    let got = f.k1(
        "logins.get",
        &format!(
            r#"{},"url":"https://example.com/login","top_url":"https://other.example.org/""#,
            f.ids(&[2])
        ),
    );
    assert!(got.is_ok());
    let Question::Access(q) = screen.join().unwrap() else {
        panic!()
    };
    assert_eq!(q.remember, None);
    assert_eq!(
        q.line.as_deref(),
        Some("This sign-in form is inside a frame from example.com on other.example.org.")
    );
    // Remember is ignored: the item is unchanged.
    assert_eq!(
        site_item(&f, 2).as_deref(),
        Some(r#"{"Allow":["example.com"],"Deny":[]}"#)
    );
    // logins.find marks it ask too.
    let found = f
        .k1(
            "logins.find",
            r#""url":"https://example.com/login","top_url":"https://other.example.org/""#,
        )
        .unwrap();
    assert_eq!(s(&list(&found)[0], "access"), "ask");
}

#[test]
fn t47_int02_19_a_form_to_another_site_asks_and_remembers_nothing() {
    let f = Fixture::new();
    f.options(|o| o.never_ask = true);
    let screen = f.answer(|_| Answer::Allow {
        checked: vec![true],
        remember: true,
    });
    let got = f.k1(
        "logins.get",
        &format!(r#"{},"url":"https://example.com/","top_url":"https://example.com/","form_url":"https://collector.example.org/post""#, f.ids(&[2])),
    );
    assert!(got.is_ok());
    let Question::Access(q) = screen.join().unwrap() else {
        panic!()
    };
    assert_eq!(
        q.line.as_deref(),
        Some("This form sends what you type to collector.example.org.")
    );
    assert_eq!(site_item(&f, 2), None);
}

#[test]
fn t75_int02_19_hosts_without_a_registrable_domain_compare_whole() {
    let f = Fixture::new();
    set_site(&f, 5, r#"{"Allow":["192.168.1.1"],"Deny":[]}"#);
    f.options(|o| o.skip_http_ask = true);
    let screen = f.answer(allow_all);
    let got = f.k1(
        "logins.get",
        &format!(
            r#"{},"url":"http://192.168.1.1/","top_url":"http://192.168.1.2/","http_auth":true"#,
            f.ids(&[5])
        ),
    );
    assert!(got.is_ok());
    let Question::Access(q) = screen.join().unwrap() else {
        panic!()
    };
    assert!(
        q.line
            .unwrap()
            .starts_with("This sign-in form is inside a frame")
    );
    assert_eq!(q.remember, None);
}

// ---------------------------------------------------------------------------
// Summaries and full entries (INT-02.20 to INT-02.23).

#[test]
fn t48_int02_20_summaries_carry_no_secret() {
    let f = Fixture::new();
    let reply = f
        .k1(
            "logins.find",
            r#""url":"https://shop.example.org/","top_url":"https://shop.example.org/""#,
        )
        .unwrap();
    let e6 = &list(&reply)[0];
    assert_eq!(s(e6, "title"), "Shop");
    assert_eq!(s(e6, "username"), "");
    assert_eq!(e6["code"], Value::Bool(false));
    assert_eq!(e6["skip_submit"], Value::Bool(true));
    assert_eq!(s(e6, "access"), "ask");
    assert_eq!(s(e6, "group"), "Web");
    assert_eq!(read_entry_id(s(e6, "id")), Some(id(6)));
    let text = json::to_string(&Value::Object(reply));
    assert!(!text.contains("password") && !text.contains("x6") && !text.contains("1234"));
}

#[test]
fn r02_2_a_user_name_that_reads_a_password_is_sent_empty_with_hidden_value() {
    let f = Fixture::new();
    f.e(7, |e| {
        set(e, "UserName", &format!("{{REF:P@I:{}}}", entry_id(id(1))))
    });
    let found = f.find("https://example.net/").unwrap();
    assert_eq!(s(&found[0], "username"), "");
    assert_eq!(found[0]["hidden_value"], Value::Bool(true));
    f.e(7, |e| set(e, "UserName", "{PASSWORD}"));
    let found = f.find("https://example.net/").unwrap();
    assert_eq!(found[0]["hidden_value"], Value::Bool(true));
    let text = json::to_string(&Value::Array(
        found.into_iter().map(Value::Object).collect(),
    ));
    assert!(!text.contains("demo-mail-pass") && !text.contains("demo-net-pass"));
    // A title holding {TOTP} never sends the code.
    f.e(7, |e| {
        set(e, "Title", "{TOTP}");
        set(e, "TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
    });
    let found = f.find("https://example.net/").unwrap();
    assert_eq!(s(&found[0], "title"), "");
}

#[test]
fn t49_int02_20_best_only_keeps_the_best_group() {
    let f = Fixture::new();
    f.v(|v| {
        v.root.groups[0]
            .entries
            .push(entry(13, "E12", "", "p", "https://example.com/login"))
    });
    f.options(|o| o.best_only = true);
    assert_eq!(
        titles(&f.find("https://example.com/login").unwrap()),
        ["E12"]
    );
}

#[test]
fn int02_20_at_most_200_summaries() {
    let f = Fixture::new();
    f.v(|v| {
        for n in 0..250u32 {
            let mut e = entry(0, "many", "", "p", "https://example.com");
            e.uuid = Uuid(
                [n.to_be_bytes(), [0x77; 4], [0x77; 4], [1; 4]]
                    .concat()
                    .try_into()
                    .unwrap(),
            );
            v.root.groups[0].entries.push(e);
        }
    });
    assert_eq!(f.find("https://example.com/").unwrap().len(), 200);
}

#[test]
fn t50_int02_21_extra_fields_with_s_brw_18() {
    let f = Fixture::new();
    set_site(&f, 6, r#"{"Allow":["shop.example.org"],"Deny":[]}"#);
    let got = f.get(&[6], "https://shop.example.org/").unwrap();
    assert_eq!(
        json::to_string(&got[0]["fields"]),
        r#"[{"name":"pin","value":"1234"}]"#
    );
    assert_eq!(got[0]["skip_submit"], Value::Bool(true));
    f.options(|o| o.extra_fields = false);
    assert!(!f.get(&[6], "https://shop.example.org/").unwrap()[0].contains_key("fields"));
}

#[test]
fn t16_t51_int02_9_21_get_gives_password_and_code_and_records_last_use() {
    let f = Fixture::new();
    set_site(&f, 1, r#"{"Allow":["mail.example.com"],"Deny":[]}"#);
    let modified = f.e(1, |e| e.times.last_modification);
    let got = f.get(&[1], "https://mail.example.com/login").unwrap();
    assert_eq!(s(&got[0], "password"), "demo-mail-pass");
    let expected = f.e(1, |e| app_core::totp::code_for(e, time(T)).unwrap());
    assert_eq!(s(&got[0], "code"), expected.expose());
    // INT-02.9: a view-state change only.
    assert_eq!(
        f.v(|v| v.meta.custom_data.get("_LAST_USED_demo").map(str::to_owned))
            .as_deref(),
        Some("2026-10-28T09:12:00Z")
    );
    assert_eq!(
        f.e(1, |e| last_use(e, &["demo".into()])).as_deref(),
        Some("2026-10-28T09:12:00Z")
    );
    assert_eq!(f.e(1, |e| e.times.last_modification), modified);
    assert!(f.e(1, |e| e.history.is_empty()));
    assert_eq!(f.changes().last(), Some(&Changed::View));
    assert!(!f.changes().contains(&Changed::Data));
}

#[test]
fn t52_int02_21_a_hidden_entry_is_never_given() {
    let f = Fixture::new();
    f.options(|o| o.never_ask = true);
    assert_eq!(f.get(&[8], "https://example.com/"), Err(15));
    assert_eq!(f.get(&[10], "https://example.com/"), Err(15));
}

#[test]
fn int02_21_ids_must_be_1_to_20_well_formed_pairs() {
    let f = Fixture::new();
    let page = r#""url":"https://example.com/""#;
    assert_eq!(f.k1("logins.get", page), Err(18));
    assert_eq!(f.k1("logins.get", &format!(r#""ids":[],{page}"#)), Err(18));
    assert_eq!(
        f.k1(
            "logins.get",
            &format!(r#""ids":[{{"vault":"x","id":"ZZ"}}],{page}"#)
        ),
        Err(18)
    );
    assert_eq!(
        f.k1("logins.get", &format!(r#"{},{page}"#, f.ids(&[2; 21]))),
        Err(43)
    );
    // An unknown vault or entry is left out: nothing fit, error 15.
    let unknown = format!(
        r#""ids":[{{"vault":"x","id":"{}"}}],{page}"#,
        entry_id(id(2))
    );
    assert_eq!(f.k1("logins.get", &unknown), Err(15));
}

#[test]
fn t17_int02_9_recent_gives_the_newest_uses_first() {
    let f = Fixture::new();
    f.options(|o| o.never_ask = true);
    f.get(&[1], "https://mail.example.com/login").unwrap();
    f.demo.now.fetch_add(1, Ordering::SeqCst);
    f.get(&[6], "https://shop.example.org/").unwrap();
    let recent = list(&f.k1("logins.recent", "").unwrap());
    assert_eq!(titles(&recent), ["Shop", "Example Mail"]);
    assert!(!json::to_string(&Value::Object(recent[0].clone())).contains("password"));
}

#[test]
fn t53_r02_1_int02_22_search_is_one_plain_term_over_title_user_and_host() {
    let f = Fixture::new();
    let found = list(
        &f.k1(
            "logins.search",
            r#""text":"SHOP","url":"https://example.com/""#,
        )
        .unwrap(),
    );
    assert_eq!(titles(&found), ["Shop"]);
    assert_eq!(s(&found[0], "access"), "ask");
    // Host part, user name part.
    assert_eq!(
        titles(&list(
            &f.k1("logins.search", r#""text":"mail.example""#).unwrap()
        )),
        ["Example Mail"]
    );
    assert_eq!(
        titles(&list(
            &f.k1("logins.search", r#""text":"work-bot""#).unwrap()
        )),
        ["Example (work)"]
    );
    // R02-1: no query syntax, no passwords, no custom fields.
    for probe in [
        "pw:demo-mail-pass",
        "*pw:^demo",
        "attribute:1234",
        "demo-mail-pass",
        "1234",
    ] {
        let reply = f
            .k1("logins.search", &format!(r#""text":"{probe}""#))
            .unwrap();
        assert!(list(&reply).is_empty(), "{probe}");
    }
    // A password stored without protection is still never searched.
    f.e(2, |e| {
        e.set_field(
            "Password".into(),
            Field {
                value: SecretString::new("plain-demo-secret".into()),
                protected: false,
            },
        );
    });
    assert!(list(&f.k1("logins.search", r#""text":"plain-demo""#).unwrap()).is_empty());
    // Hidden, restricted, recycle bin and expired entries never show.
    let all = titles(&list(&f.k1("logins.search", r#""text":"e""#).unwrap()));
    for gone in ["Hidden one", "E8", "E9", "E10", "Expired one"] {
        assert!(!all.iter().any(|t| t == gone), "{gone}");
    }
}

#[test]
fn t54_int02_22_an_outside_fill_always_asks_and_remember_makes_it_fit() {
    let f = Fixture::new();
    f.options(|o| o.never_ask = true);
    let screen = f.answer(|_| Answer::Allow {
        checked: vec![true],
        remember: true,
    });
    assert_eq!(f.get(&[6], "https://example.com/").unwrap().len(), 1);
    screen.join().unwrap();
    assert!(
        site_item(&f, 6)
            .unwrap()
            .starts_with(r#"{"Allow":["example.com"]"#)
    );
    assert!(titles(&f.find("https://example.com/").unwrap()).contains(&"Shop".to_owned()));
}

#[test]
fn t55_t56_int02_23_code_get_asks_and_gives_the_code_only_where_the_entry_fits() {
    let f = Fixture::new();
    let vid = f.vid(0);
    let ask = |page: &str| {
        f.k1(
            "code.get",
            &format!(
                r#""vault":"{vid}","id":"{}","url":"{page}","top_url":"{page}""#,
                entry_id(id(1))
            ),
        )
    };
    // T56: E1 does not fit: 18, no prompt.
    let watchdog = Watchdog::new(&f);
    assert_eq!(ask("https://example.org/"), Err(18));
    assert!(!watchdog.fired());
    assert_eq!(f.shows.load(Ordering::SeqCst), 0);
    let screen = f.answer(allow_all);
    let reply = ask("https://mail.example.com/").unwrap();
    screen.join().unwrap();
    let expected = f.e(1, |e| app_core::totp::code_for(e, time(T)).unwrap());
    assert_eq!(s(&reply, "code"), expected.expose());
    assert_eq!(reply["period"].as_u64(), Some(30));
    assert!((1..=30).contains(&reply["remaining"].as_u64().unwrap()));
    // No valid settings: 15, before any prompt.
    f.e(1, |e| {
        e.remove_field("TimeOtp-Secret-Base32");
    });
    let shows = f.shows.load(Ordering::SeqCst);
    assert_eq!(ask("https://mail.example.com/"), Err(15));
    assert_eq!(f.shows.load(Ordering::SeqCst), shows);
    assert_eq!(
        f.k1("code.get", r#""url":"https://mail.example.com/""#),
        Err(18)
    );
}

#[test]
fn status_names_vaults_and_gives_ids_only_to_a_holder() {
    let f = Fixture::new();
    let reply = f.k1("status", "").unwrap();
    let v = reply["vaults"].as_array().unwrap();
    let v0 = v[0].as_object().unwrap();
    assert_eq!(
        (s(v0, "name"), s(v0, "state"), s(v0, "connection")),
        ("access-demo", "unlocked", "demo")
    );
    assert_eq!(s(v0, "id"), f.vid(0));
    assert_eq!(s(v[1].as_object().unwrap(), "state"), "locked");
    let stranger = f.send(&Live::default(), Some(&K3), "status", "").unwrap();
    assert!(
        !stranger["vaults"].as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .contains_key("id")
    );
}

#[test]
fn later_requests_check_the_association_then_answer_12() {
    let f = Fixture::new();
    assert_eq!(f.k1("logins.save", ""), Err(12));
    assert_eq!(
        f.send(&Live::default(), Some(&K3), "logins.save", ""),
        Err(8)
    );
}

#[test]
fn site_access_state_of_int02_17() {
    let lists = |allow: &[&str], deny: &[&str]| {
        let mut e = Entry::new(id(1), time(T));
        let text = format!(
            r#"{{"Allow":{},"Deny":{}}}"#,
            json::to_string(&Value::from(allow.to_vec())),
            json::to_string(&Value::from(deny.to_vec()))
        );
        e.custom_data.items.push(item(&site_key(), &text));
        app_browser::Lists::of(&e)
    };
    // A host in both lists counts as denied (INT-02.16).
    assert_eq!(
        State::of(&lists(&["a.example"], &["a.example"]), "a.example", None),
        State::Denied
    );
    assert_eq!(
        State::of(&lists(&["a.example"], &[]), "a.example", None),
        State::Allowed
    );
    assert_eq!(
        State::of(&lists(&["a.example"], &[]), "a.example", Some("b.example")),
        State::Ask
    );
    assert_eq!(
        State::of(
            &lists(&["a.example"], &["b.example"]),
            "a.example",
            Some("b.example")
        ),
        State::Denied
    );
}
