//! E16-S7a's full runs: two Macs (two sessions, two devices of one account,
//! each with its own settings folder and test clock) against Larsal's server
//! in process on 127.0.0.1:0 with its first-start certificate, pinned
//! (LD-327 (6)). The second device comes from the server's test helper
//! (SYN-04.11); the device keys are test-seam keys (LD-317 (2)). Timing
//! runs on the test clocks; no test sleeps.

use super::*;
use crate::edit::EditText;
use crate::test_dir::TempDir;
use crate::views::ListView;
use larsal_sync::test_server::{LarsalServer, Scripted, TestClock, larsal_server};

const DEMO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/option-a-personal.larsalvault"
);
const PASSWORD: &str = "demo-pass-7";

struct Mac {
    dir: TempDir,
    s: Arc<Session>,
    v: u64,
    clock: Arc<TestClock>,
}

impl Mac {
    /// A Mac with its own settings folder and clock; with `vault`, the
    /// demo vault copied in and unlocked.
    fn new(tag: &str, vault: bool) -> Self {
        let dir = TempDir::new(&format!("sync-{tag}"));
        let s = Session::new();
        s.settings()
            .use_folder(dir.join("settings").display().to_string());
        let clock = TestClock::at(1_000_000);
        s.sync.set_clock(clock.clone());
        let mut m = Self {
            dir,
            s,
            v: 0,
            clock,
        };
        if vault {
            let path = m.dir.join("Personal.larsalvault");
            std::fs::copy(DEMO, &path).unwrap();
            m.open(&path);
        }
        m
    }

    fn open(&mut self, path: &Path) {
        self.v = self.s.open(path.display().to_string()).unwrap();
        self.unlock();
    }

    fn unlock(&self) {
        let r = self.s.unlock(self.v, Some(PASSWORD.into()), None).unwrap();
        assert_eq!(r, crate::session::UnlockResult::Unlocked);
    }

    fn tick(&self, ms: u64) -> Vec<SyncState> {
        self.clock.advance(ms);
        self.s.sync_tick()
    }

    fn status(&self) -> Option<SyncStatus> {
        self.s.sync_state(self.v).map(|s| s.status)
    }

    fn titles(&self) -> Vec<String> {
        let mut t: Vec<String> = self
            .s
            .list(self.v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.title)
            .collect();
        t.sort();
        t
    }

    fn id_of(&self, title: &str) -> String {
        self.s
            .list(self.v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == title)
            .unwrap()
            .id
    }

    /// Every entry id in the vault, the bin and history included.
    fn ids(&self) -> Vec<String> {
        fn walk(g: &larsal_model::Group, out: &mut Vec<String>) {
            for e in &g.entries {
                out.push(e.uuid.0.iter().map(|b| format!("{b:02x}")).collect());
            }
            for c in &g.groups {
                walk(c, out);
            }
        }
        self.s
            .with_vault(self.v, |v| {
                let mut out = Vec::new();
                walk(&v.root, &mut out);
                Ok(out)
            })
            .unwrap()
    }

    /// Renames entry `from` to `to` and saves.
    fn rename(&self, from: &str, to: &str) {
        self.s.begin_edit(self.v, self.id_of(from)).unwrap();
        self.s.set_text(self.v, EditText::Title, to.into()).unwrap();
        self.s.commit_edit(self.v).unwrap();
        self.save();
    }

    fn save(&self) {
        let st = self.s.save(self.v).unwrap();
        assert_eq!((st.changes, &st.failure), (0, &None), "{st:?}");
    }

    fn runs(&self) -> Vec<u64> {
        self.s
            .sync_with(|i| i.runs.iter().map(|(_, t)| *t).collect())
    }
}

/// Mac A: adds the server after comparing its fingerprint, signs up and
/// puts its demo vault on the server (version 1).
fn first(app_address: &str, pin: [u8; 32], tag: &str) -> Mac {
    let a = Mac::new(tag, true);
    let shown = a.s.sync_fingerprint(app_address.to_owned()).unwrap();
    assert_eq!(client::read_printed(&shown), Some(pin));
    a.s.sync_add_server(app_address.to_owned(), shown).unwrap();
    a.s.sync_sign_up(app_address.to_owned()).unwrap();
    a
}

fn put(a: &Mac, address: &str) {
    let st = a.s.sync_put_vault(a.v, address.to_owned()).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
}

/// Mac B: the server added, a second device of A's account registered by
/// the server's test helper (SYN-04.11), the vault downloaded and
/// unlocked.
fn second(app: &LarsalServer, address: &str, pin: [u8; 32], a: &Mac, tag: &str) -> Mac {
    let mut b = Mac::new(tag, false);
    b.s.sync_add_server(address.to_owned(), client::printed(&pin))
        .unwrap();
    let account =
        a.s.sync_with(|i| i.state.servers[0].account.clone())
            .unwrap()
            .account;
    let key = DeviceKey::test_seam().unwrap();
    let public_key = key.public_key().unwrap();
    let device = app
        .seams
        .add_device(&account, &public_key, "Mac")
        .unwrap()
        .unwrap();
    let mut c = Client::new(address, pin).unwrap();
    c.sign_for_port(app.port);
    c.set_device(device, key);
    b.s.sync_with(|i| {
        i.state.servers[0].account = Some(Account {
            account,
            device,
            label: random_hex().unwrap(),
            public_key,
        });
        i.servers
            .insert(address.to_owned(), Arc::new(Mutex::new(c)));
        i.save();
    });
    let listed = b.s.sync_server_vaults(address.to_owned()).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].linked);
    let path = b.dir.join("Personal.larsalvault");
    b.s.sync_download(
        address.to_owned(),
        listed[0].id.clone(),
        path.display().to_string(),
    )
    .unwrap();
    b.open(&path);
    b
}

/// E16-S7a check 2, SYN-03.5, SYN-03 T04: A and B each change a different
/// entry of the demo vault and save; both sync at once. After the runs
/// both hold both changes, and the server holds version 3.
#[test]
fn syn03_5_t04_two_macs_change_two_entries_at_once_and_both_keep_both() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "t04-a");
    put(&a, &address);
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    let b = second(&app, &address, app.pin, &a, "t04-b");
    let states = b.tick(0);
    assert_eq!(states.len(), 1);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert_eq!(a.titles(), b.titles());

    let t = a.titles();
    a.rename(&t[0], "E1 by A");
    b.rename(&t[1], "E2 by B");
    a.clock.advance(2_000);
    b.clock.advance(2_000);
    std::thread::scope(|scope| {
        scope.spawn(|| a.s.sync_tick());
        scope.spawn(|| b.s.sync_tick());
    });
    for m in [&a, &b, &a] {
        m.s.sync_now(m.v).unwrap();
        m.tick(0);
        assert_eq!(m.status(), Some(SyncStatus::Synced));
    }
    let both = a.titles();
    assert!(both.contains(&"E1 by A".to_owned()), "{both:?}");
    assert!(both.contains(&"E2 by B".to_owned()), "{both:?}");
    assert!(!both.contains(&t[0]) && !both.contains(&t[1]));
    assert_eq!(b.titles(), both);
    let listed = a.s.sync_server_vaults(address).unwrap();
    assert_eq!(listed[0].version, 3);
    assert!(listed[0].linked);
    for m in [&a, &b] {
        assert!(m.s.sync_state(m.v).unwrap().messages.is_empty());
    }
}

/// E16-S7a check 3, SYN-03.5, SYN-03 T05 (E15-S2's deletion pass): A
/// deletes an entry for good and syncs; on B it is gone after its sync,
/// and B's next upload does not bring it back.
#[test]
fn syn03_5_t05_a_deletion_stays_deleted_on_the_other_mac() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "t05-a");
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, "t05-b");
    b.tick(0);
    let t = a.titles();
    let gone = a.id_of(&t[2]);
    assert!(b.ids().contains(&gone));
    // Into the bin, then out of it for good.
    let mut for_good = 0;
    for _ in 0..2 {
        for_good += a.s.delete_entry(a.v, gone.clone()).unwrap().for_good;
    }
    assert_eq!(for_good, 1);
    a.save();
    assert!(!a.ids().contains(&gone));
    a.tick(2_000);
    assert_eq!(a.status(), Some(SyncStatus::Synced));

    b.s.sync_now(b.v).unwrap();
    b.tick(0);
    assert!(!b.ids().contains(&gone), "gone on B");
    b.rename(&t[3], "B after the deletion");
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    assert!(a.titles().contains(&"B after the deletion".to_owned()));
    assert!(!a.ids().contains(&gone), "B's upload did not bring it back");
    assert_eq!(a.s.sync_server_vaults(address).unwrap()[0].version, 3);
}

/// E16-S7a check 6, SYN-03.4, SYN-03 T09 (through the session): with a
/// test clock, runs start at the unlock, once 2 s after the second of two
/// saves 1 s apart, once at 60 s; none while locked, and Sync now does
/// nothing while locked.
#[test]
fn syn03_4_t09_the_session_runs_on_unlock_after_saves_every_60_s_never_locked() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "t09");
    put(&a, &address);
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.runs.clear());
    let start = a.clock.now_ms();
    a.unlock();
    let t = a.titles();
    for step in 0..=146_u64 {
        let at = step * 500;
        if at == 10_000 {
            a.rename(&t[0], "first save");
        }
        if at == 11_000 {
            a.rename("first save", "second save");
        }
        if at == 71_000 {
            a.s.lock(a.v).unwrap();
            a.s.sync_now(a.v).unwrap();
        }
        a.s.sync_tick();
        a.clock.advance(500);
    }
    let runs: Vec<u64> = a.runs().iter().map(|t| t - start).collect();
    assert_eq!(runs, [0, 13_000, 60_000]);
    assert_eq!(a.s.sync_server_vaults(address).unwrap()[0].version, 2);
}

/// SYN-04 T13 and SYN-03 T24 (a full E16-S7a run through a test proxy
/// that reads every request): no password, no value made from one, no
/// entry title in any request. SYN-04 T08: the session token is in no
/// file of either Mac (state, settings, vault). SYN-01 T20 (the client
/// half): the sync code logs nothing.
#[test]
fn syn04_t13_t08_no_password_in_any_request_and_no_token_in_any_file() {
    let app = larsal_server();
    let proxy = Scripted::proxy(&app);
    let address = proxy.address();
    let a = first(&address, proxy.pin, "t13-a");
    a.s.sync_with(|i| {
        i.servers[&address].lock().unwrap().sign_for_port(app.port);
    });
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, proxy.pin, &a, "t13-b");
    b.tick(0);
    let t = a.titles();
    a.rename(&t[0], "Secret title A");
    b.rename(&t[1], "Secret title B");
    a.tick(2_000);
    b.tick(2_000);
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    assert!(a.titles().contains(&"Secret title B".to_owned()));
    assert!(b.titles().contains(&"Secret title B".to_owned()));

    let seen = proxy.seen.lock().unwrap().clone();
    assert!(seen.iter().any(|(r, _)| r.path == "/v1/signin"));
    assert!(seen.iter().filter(|(r, _)| r.method == "PUT").count() >= 3);
    let utf16: Vec<u8> = PASSWORD.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut needles: Vec<Vec<u8>> = vec![PASSWORD.as_bytes().to_vec(), utf16];
    // Titles of 6 bytes or more: a shorter one could appear by chance in
    // the encrypted bytes.
    let mut titles = t.clone();
    titles.extend(["Secret title A".to_owned(), "Secret title B".to_owned()]);
    needles.extend(
        titles
            .iter()
            .filter(|s| s.len() >= 6)
            .map(|s| s.as_bytes().to_vec()),
    );
    // SYN-04.10: a value made from the password, the vault's key, would
    // be 32 bytes; no request carries the vault's key material: only
    // encrypted bytes, ids, versions and signatures (SYN-03.14).
    for (request, reply) in &seen {
        for n in &needles {
            assert!(
                !request.raw.windows(n.len()).any(|w| w == &n[..]),
                "{} {} holds {:?}",
                request.method,
                request.path,
                String::from_utf8_lossy(n)
            );
            assert!(!reply.windows(n.len()).any(|w| w == &n[..]));
        }
    }

    let tokens: BTreeSet<String> = seen
        .iter()
        .filter_map(|(r, _)| r.header("authorization"))
        .map(|h| h.strip_prefix("Bearer ").unwrap().to_owned())
        .collect();
    assert_eq!(tokens.len(), 2, "one session per Mac");
    let mut files = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    walk(&a.dir, &mut files);
    walk(&b.dir, &mut files);
    assert!(files.iter().any(|f| f.ends_with("sync-state_debug.json")));
    for token in &tokens {
        let raw = larsal_crypto::base64::decode(larsal_crypto::base64::Form::Url, token).unwrap();
        for f in &files {
            let bytes = std::fs::read(f).unwrap();
            for n in [token.as_bytes(), &raw[..]] {
                assert!(
                    !bytes.windows(n.len()).any(|w| w == n),
                    "{} holds the token",
                    f.display()
                );
            }
        }
    }
    let src = include_str!("../sync.rs");
    for word in ["println!", "eprintln!", "dbg!", "log::"] {
        assert!(!src.contains(word), "{word}");
    }
}

/// SYN-03.3, SYN-03 T26: the state file has mode 0600 and holds the
/// fields of SYN-03.3, and no password or token; a Mac that only added the
/// server holds its address and pin and no link.
#[test]
fn syn03_3_t26_the_state_file_holds_its_fields_and_no_secret() {
    use std::os::unix::fs::PermissionsExt;
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "t26-a");
    put(&a, &address);
    a.tick(0);
    let file = a.dir.join("settings/sync-state_debug.json");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let state = State::load(&file).unwrap();
    assert_eq!(state.servers.len(), 1);
    let server = &state.servers[0];
    assert_eq!(
        (server.address.as_str(), server.pin),
        (address.as_str(), app.pin)
    );
    let account = server.account.as_ref().unwrap();
    assert_eq!(account.label.len(), 32, "16 random bytes as hex");
    let link = &state.links[0];
    assert_eq!(link.highest, 1);
    assert_eq!(
        link.file,
        a.dir.join("Personal.larsalvault").display().to_string()
    );
    assert_eq!(link.local_sha, link.server_sha);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains(PASSWORD));
    for word in ["token", "password", "secret"] {
        assert!(!text.to_lowercase().contains(word), "{word}");
    }

    let c = Mac::new("t26-c", false);
    c.s.sync_add_server(address.clone(), client::printed(&app.pin))
        .unwrap();
    let state = State::load(&c.dir.join("settings/sync-state_debug.json")).unwrap();
    assert_eq!(state.servers[0].address, address);
    assert_eq!(state.servers[0].account, None);
    assert!(state.links.is_empty());
    // SYN-01.14: a server that is not Larsal's is never stored.
    let other = Scripted::new(|_| larsal_sync::test_server::Response::new(404, b"{}"));
    let err =
        c.s.sync_add_server(other.address(), client::printed(&other.pin))
            .unwrap_err();
    assert!(
        err.to_string().contains("is not a Larsal sync server"),
        "{err}"
    );
    let state = State::load(&c.dir.join("settings/sync-state_debug.json")).unwrap();
    assert_eq!(state.servers.len(), 1);
}

/// The demo vault, opened with its password and saved again under
/// `password` after `change`.
fn resaved(password: &str, change: impl FnOnce(&mut Vault)) -> Vec<u8> {
    use larsal_format::keys::Credentials;
    use larsal_format::limits::Limits;
    use larsal_format::{Opened, Saved};
    let demo = larsal_crypto::secret::SecretString::new(PASSWORD.to_owned());
    let given = larsal_crypto::secret::SecretString::new(password.to_owned());
    let read = Credentials {
        password: Some(&demo),
        key_file: None,
        hardware_key: None,
    };
    let write = Credentials {
        password: Some(&given),
        key_file: None,
        hardware_key: None,
    };
    let s = Session::new();
    let mut host = s.host.lock().unwrap();
    let bytes = std::fs::read(DEMO).unwrap();
    let mut opened = None;
    let mut approval = None;
    while opened.is_none() {
        match larsal_format::open(
            &bytes,
            &read,
            &mut host,
            &Limits::DEFAULT,
            approval.as_ref(),
        )
        .unwrap()
        {
            Opened::Vault(o) => opened = Some(o),
            Opened::Ask(r) => approval = Some(r),
        }
    }
    let mut v = opened.unwrap().vault;
    change(&mut v);
    let mut approval = None;
    loop {
        match larsal_format::save(
            &v,
            &write,
            None,
            &mut host,
            &Limits::DEFAULT,
            approval.as_ref(),
        )
        .unwrap()
        {
            Saved::File(f) => return f.bytes,
            Saved::Ask(r) => approval = Some(r),
        }
    }
}

/// SYN-03.8, SYN-03 T17: a server copy with another root group id merges
/// nothing (`MSG-SYNC-OTHER-VAULT`); a copy under other credentials is
/// `WrongKey` (Needs password; the sheet comes with E16-S7b); the open
/// vault is unchanged. The same vault merges.
#[test]
fn syn03_8_t17_another_vault_or_another_key_merges_nothing() {
    let a = Mac::new("t17", true);
    let before = (a.titles(), a.ids());
    let other = resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
    assert!(matches!(a.s.merge_server(a.v, &other), Merge::OtherVault));
    let other_key = resaved("another password", |_| {});
    assert!(matches!(a.s.merge_server(a.v, &other_key), Merge::WrongKey));
    assert!(matches!(
        a.s.merge_server(a.v, b"not a vault"),
        Merge::Failed
    ));
    assert_eq!((a.titles(), a.ids()), before);
    let same = resaved(PASSWORD, |_| {});
    assert!(matches!(
        a.s.merge_server(a.v, &same),
        Merge::Done { changed: false, .. }
    ));
}

/// SYN-03.4 and its edge case: unsaved changes, an open entry editor or an
/// open group editor hold every run (the merge too refuses a vault that
/// became busy); the run that waited starts once the vault is saved.
#[test]
fn syn03_4_unsaved_changes_or_an_open_editor_hold_the_run() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "busy");
    put(&a, &address);
    a.tick(0);
    a.s.sync_with(|i| i.runs.clear());
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    let t = a.titles();

    a.s.begin_edit(a.v, a.id_of(&t[0])).unwrap();
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    a.tick(60_000);
    assert!(a.runs().is_empty(), "the entry editor is open");
    assert!(matches!(a.s.merge_server(a.v, &file), Merge::Busy));
    assert!(a.s.sync_read(a.v).is_none());
    a.s.set_text(a.v, EditText::Title, "unsaved".into())
        .unwrap();
    a.s.commit_edit(a.v).unwrap();
    a.tick(1_000);
    assert!(a.runs().is_empty(), "an unsaved change");
    a.save();

    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let root: String = root.0.iter().map(|b| format!("{b:02x}")).collect();
    a.s.share_edit(a.v, root).unwrap();
    a.tick(0);
    assert!(a.runs().is_empty(), "the group editor is open");
    assert!(matches!(a.s.merge_server(a.v, &file), Merge::Busy));
    a.s.share_edit_cancel(a.v).unwrap();
    a.tick(0);
    assert_eq!(a.runs().len(), 1, "the run that waited");
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert!(a.titles().contains(&"unsaved".to_owned()));
}

thread_local! {
    static DOWNLOAD_COMMITTED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static DOWNLOAD_STARTED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static SERVER_OPENED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn download_committed() {
    if let Some(f) = DOWNLOAD_COMMITTED.with(|m| m.borrow_mut().take()) {
        f();
    }
}

pub(crate) fn download_started() {
    if let Some(f) = DOWNLOAD_STARTED.with(|m| m.borrow_mut().take()) {
        f();
    }
}

pub(crate) fn server_opened() {
    if let Some(f) = SERVER_OPENED.with(|m| m.borrow_mut().take()) {
        f();
    }
}

/// F-283: every kept credential is rechecked after opening off the save lock.
#[test]
fn f283_changed_key_parts_merge_nothing() {
    for part in 0..3 {
        let a = Mac::new(&format!("f283-{part}"), true);
        let copy = resaved(PASSWORD, |v| {
            v.meta.name = "Demo stale credentials".into();
            v.meta.name_changed = larsal_model::Time(i64::MAX / 4);
        });
        let before = a.s.with_vault(a.v, |v| Ok(v.meta.name.clone())).unwrap();
        let file = a.dir.join("Personal.larsalvault");
        let bytes = std::fs::read(&file).unwrap();
        let saver = a.s.with_edit_state(a.v, |e| e.saver.clone()).unwrap();
        SERVER_OPENED.with(|m| {
            *m.borrow_mut() = Some(Box::new(move || {
                let mut s = saver.try_lock().expect("copy opens off the save lock");
                match part {
                    0 => {
                        s.password = Some(larsal_crypto::secret::SecretString::new(
                            "demo replacement".into(),
                        ))
                    }
                    1 => {
                        s.key_file = Some(
                            larsal_format::keyfile::read_key_file(
                                std::io::Cursor::new([7u8; 32]),
                                &larsal_format::limits::Limits::DEFAULT,
                            )
                            .unwrap(),
                        )
                    }
                    _ => {
                        s.hardware = crate::hwkey::Choice::of(crate::hwkey::KeyPick {
                            serial: 123,
                            slot: 1,
                            needs_touch: false,
                        })
                    }
                }
            }));
        });
        assert!(
            matches!(a.s.merge_server(a.v, &copy), Merge::Busy),
            "part {part}"
        );
        assert_eq!(
            a.s.with_vault(a.v, |v| Ok(v.meta.name.clone())).unwrap(),
            before
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
    }
}

/// F-284: duplicate downloads, including pending downloads, never create
/// a second file or replace the existing link.
#[test]
fn f284_one_server_vault_links_to_one_file() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f284-a");
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, "f284-b");
    let pending = b.s.sync_with(|i| i.pending[0].clone());
    let again = b.dir.join("Again.larsalvault");
    assert!(
        b.s.sync_download(
            address.clone(),
            pending.vault_id.to_string(),
            again.display().to_string()
        )
        .is_err()
    );
    assert!(!again.exists());
    b.tick(0);
    let links = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(links.len(), 1);
    assert!(
        b.s.sync_download(
            address,
            pending.vault_id.to_string(),
            again.display().to_string()
        )
        .is_err()
    );
    assert!(!again.exists());
    // A pending download that raced another link must also be dropped.
    let bytes = std::fs::read(&pending.path).unwrap();
    std::fs::write(&again, bytes).unwrap();
    let mut other = pending;
    other.path = again.clone();
    b.s.sync_with(|i| i.pending.push(other.clone()));
    let id = b.s.open(again.display().to_string()).unwrap();
    assert_eq!(
        b.s.unlock(id, Some(PASSWORD.into()), None).unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    assert!(b.s.sync_link_download(id, &other).is_none());
    assert!(b.s.sync_with(|i| i.pending.is_empty()));
    assert_eq!(b.s.sync_with(|i| i.state.links.clone()), links);
}

/// F-288: changed downloaded bytes cannot acquire a sync link, even if
/// they are another valid file with the same vault root and password.
#[test]
fn f288_download_hash_is_checked_before_linking() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f288-hash-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "f288-hash-b");
    let p = b.s.sync_with(|i| i.pending[0].clone());
    b.s.lock(b.v).unwrap();
    let changed = resaved(PASSWORD, |v| v.meta.name = "Demo changed download".into());
    assert_ne!(larsal_sync::sync::hash(&changed), p.sha);
    std::fs::write(&p.path, changed).unwrap();
    b.unlock();
    b.tick(0);
    assert!(b.s.sync_with(|i| i.state.links.is_empty()));
    assert_eq!(a.s.sync_server_vaults(address).unwrap()[0].version, 1);
}

/// F-288: putting a linked vault a second time sends no upload and keeps
/// both the server's list and the local link unchanged.
#[test]
fn f288_second_put_is_refused() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f288-put");
    put(&a, &address);
    let links = a.s.sync_with(|i| i.state.links.clone());
    assert!(a.s.sync_put_vault(a.v, address.clone()).is_err());
    assert_eq!(a.s.sync_with(|i| i.state.links.clone()), links);
    assert_eq!(a.s.sync_server_vaults(address).unwrap().len(), 1);
}

/// F-286: sync neither merges nor uploads an old-format file until its
/// existing notice has been confirmed and a normal save wrote version 4.
#[test]
fn f286_old_format_waits_for_notice_and_save() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f286");
    let path = a.dir.join("Rich.larsalvault");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/rich-v3.larsalvault"
        ),
        &path,
    )
    .unwrap();
    let id = a.s.open(path.display().to_string()).unwrap();
    assert_eq!(
        a.s.unlock(id, Some("demo-pass-4".into()), None).unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    let bytes = std::fs::read(&path).unwrap();
    assert!(matches!(a.s.merge_server(id, &bytes), Merge::Busy));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(a.s.sync_put_vault(id, address.clone()).is_err());
    assert!(a.s.sync_server_vaults(address.clone()).unwrap().is_empty());
    assert!(a.s.save(id).unwrap().format_notice);
    a.s.confirm_format_notice(id).unwrap();
    assert!(
        a.s.sync_put_vault(id, address.clone()).is_err(),
        "confirmation alone is not a converted file"
    );
    assert!(!a.s.save(id).unwrap().format_notice);
    assert_eq!(
        a.s.with_vault(id, |v| Ok(v.read_version.unwrap().major))
            .unwrap(),
        4
    );
    a.s.sync_put_vault(id, address).unwrap();
    assert!(matches!(
        a.s.merge_server(id, &std::fs::read(path).unwrap()),
        Merge::Done { .. }
    ));
}

/// F-287: Session's unlock keeps the active schedule as well as Schedule itself.
#[test]
fn f287_session_lock_unlock_allows_no_second_run() {
    let a = Mac::new("f287", true);
    let start = || {
        a.s.sync_with(|i| {
            i.vaults
                .get_mut(&a.v)
                .unwrap()
                .schedule
                .start(a.clock.now_ms(), false)
        })
    };
    assert!(start());
    a.s.lock(a.v).unwrap();
    a.unlock();
    assert!(!start());
    a.s.sync_with(|i| i.vaults.get_mut(&a.v).unwrap().schedule.finished());
    assert!(start());
}

/// F-284 / F-287: a stale completion cannot replace another file/root or
/// lower the version/hash pair or newest time already stored for its link.
#[test]
fn f287_write_back_keeps_identity_and_monotonic_guards() {
    let a = Mac::new("f287-write-back", true);
    let (root, seen) =
        a.s.with_vault(a.v, |v| Ok((v.root.uuid, measures(v))))
            .unwrap();
    let current = Link {
        server: "https://127.0.0.1:8443".into(),
        vault_id: larsal_sync::state::VaultId::from_bytes([3; 16]),
        file: a.dir.join("Personal.larsalvault").display().to_string(),
        root,
        highest: 9,
        server_sha: [9; 32],
        local_sha: [8; 32],
        seen,
    };
    a.s.sync_with(|i| {
        i.state.links = vec![current.clone()];
        for field in 0..4 {
            let mut stale = current.clone();
            stale.highest = 10;
            stale.server_sha = [7; 32];
            match field {
                0 => stale.file.push_str(".other"),
                1 => stale.root = Uuid([0x65; 16]),
                2 => stale.server = "https://127.0.0.1:9443".into(),
                _ => stale.vault_id = larsal_sync::state::VaultId::from_bytes([4; 16]),
            }
            i.write_back(stale);
            assert_eq!(
                i.state.links.as_slice(),
                std::slice::from_ref(&current),
                "identity field {field}"
            );
        }
        let mut stale = current.clone();
        stale.highest = 8;
        stale.server_sha = [7; 32];
        stale.seen.newest = larsal_model::Time(0);
        i.write_back(stale.clone());
        assert_eq!(
            i.state.links.as_slice(),
            std::slice::from_ref(&current),
            "the version and its hash stay together"
        );
        stale.highest = 10;
        stale.seen.version.major = 3;
        i.write_back(stale.clone());
        stale.seen.newest = current.seen.newest;
        assert_eq!(i.state.links, [stale]);
        assert_eq!(
            State::load(&a.dir.join("settings/sync-state_debug.json"))
                .unwrap()
                .links,
            i.state.links
        );
    });
}

/// F-283: replacing an existing key-file part also invalidates the opened
/// copy; two present parts must be compared by their secret bytes.
#[test]
fn f283_replacing_an_existing_key_file_merges_nothing() {
    let dir = TempDir::new("sync-f283-existing");
    let path = dir.join("Demo.larsalvault");
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    std::fs::copy(data.join("password-and-keyfile.larsalvault"), &path).unwrap();
    let s = Session::new();
    s.settings()
        .use_folder(dir.join("settings").display().to_string());
    let id = s.open(path.display().to_string()).unwrap();
    assert_eq!(
        s.unlock(
            id,
            Some("demo-pass-2".into()),
            Some(data.join("key-hex64.larsalkey").display().to_string())
        )
        .unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    s.confirm_format_notice(id).unwrap();
    let saved = s.save(id).unwrap();
    assert_eq!((saved.changes, saved.failure), (0, None));
    let copy = std::fs::read(&path).unwrap();
    assert!(matches!(s.merge_server(id, &copy), Merge::Done { .. }));
    let before = std::fs::read(&path).unwrap();
    let saver = s.with_edit_state(id, |e| e.saver.clone()).unwrap();
    SERVER_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            let mut kept = saver.try_lock().unwrap();
            assert!(kept.key_file.is_some());
            kept.key_file = Some(
                larsal_format::keyfile::read_key_file(
                    std::io::Cursor::new([7u8; 32]),
                    &larsal_format::limits::Limits::DEFAULT,
                )
                .unwrap(),
            );
        }));
    });
    assert!(matches!(s.merge_server(id, &before), Merge::Busy));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

/// F-284: another download can finish after the initial duplicate check;
/// recheck at the write boundary before creating a second local file.
#[test]
fn f284_a_duplicate_appearing_during_download_creates_no_file() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f284-race-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "f284-race-b");
    let pending = b.s.sync_with(|i| i.pending.remove(0));
    let id = pending.vault_id.to_string();
    let session = b.s.clone();
    DOWNLOAD_STARTED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            session.sync_with(|i| i.pending.push(pending));
        }));
    });
    let again = b.dir.join("Again.larsalvault");
    assert!(
        b.s.sync_download(address, id, again.display().to_string())
            .is_err()
    );
    assert!(!again.exists());
    assert_eq!(b.s.sync_with(|i| i.pending.len()), 1);
}

// Through-Session regressions from Checker1 round 2.
fn c1_scripted_mac(tag: &str, body: Vec<u8>) -> (Mac, Scripted) {
    use larsal_sync::test_server::Response;
    let a = Mac::new(tag, true);
    let server = Scripted::new(move |r| match r.path.as_str() {
        "/v1/signin/challenge" => Response::new(
            200,
            format!(
                "{{\"nonce\":\"{}\",\"expires\":4000000000}}",
                larsal_crypto::base64::encode(larsal_crypto::base64::Form::Url, &[1; 32])
            )
            .as_bytes(),
        ),
        "/v1/signin" => Response::new(
            200,
            format!(
                "{{\"token\":\"{}\",\"idle_seconds\":900,\"expires\":4000000000}}",
                larsal_crypto::base64::encode(larsal_crypto::base64::Form::Url, &[2; 32])
            )
            .as_bytes(),
        ),
        _ if r.method == "GET" => Response::new(200, &body).with("ETag", "\"6\""),
        _ => Response::new(412, b"{}"),
    });
    let mut c = Client::new(&server.address(), server.pin).unwrap();
    c.set_device(
        larsal_sync::state::DeviceId::from_bytes([9; 16]),
        DeviceKey::test_seam().unwrap(),
    );
    let (root, mut seen) =
        a.s.with_vault(a.v, |v| Ok((v.root.uuid, measures(v))))
            .unwrap();
    seen.newest = larsal_model::Time(seen.newest.0 + 1000);
    a.s.sync_with(|i| {
        i.state.servers.push(larsal_sync::state::Server {
            address: server.address(),
            pin: server.pin,
            account: None,
        });
        i.servers.insert(server.address(), Arc::new(Mutex::new(c)));
        i.state.links.push(Link {
            server: server.address(),
            vault_id: larsal_sync::state::VaultId::from_bytes([3; 16]),
            file: a.dir.join("Personal.larsalvault").display().to_string(),
            root,
            highest: 5,
            server_sha: [5; 32],
            local_sha: [0; 32],
            seen,
        });
        i.vaults.get_mut(&a.v).unwrap().report = Some(Report {
            status: Some(Status::Synced(0)),
            messages: Vec::new(),
        });
        i.save();
    });
    (a, server)
}

fn busy_retry_keeps_warning(prior: Option<Status>, expected: SyncStatus) {
    struct EditOnWait {
        clock: Arc<TestClock>,
        s: Arc<Session>,
        id: u64,
        entry: String,
    }
    impl Clock for EditOnWait {
        fn now_ms(&self) -> u64 {
            self.clock.now_ms()
        }
        fn sleep_ms(&self, ms: u64) {
            self.clock.advance(ms);
            self.s.begin_edit(self.id, self.entry.clone()).unwrap();
        }
    }
    let body = resaved(PASSWORD, |_| {});
    let (a, server) = c1_scripted_mac(&format!("c1-busy-{expected:?}"), body);
    a.rename(&a.titles()[0], "Checker local change");
    let clock = Arc::new(EditOnWait {
        clock: a.clock.clone(),
        s: a.s.clone(),
        id: a.v,
        entry: a.id_of("Checker local change"),
    });
    a.s.sync.set_clock(clock);
    a.s.sync_with(|i| {
        i.vaults.get_mut(&a.v).unwrap().report = prior.map(|status| Report {
            status: Some(status),
            messages: Vec::new(),
        })
    });
    a.tick(0);
    assert_eq!(
        server.count("PUT"),
        1,
        "one merged attempt before the retry became busy"
    );
    assert_eq!(
        a.s.sync_with(|i| i.state.links[0].highest),
        6,
        "the warned copy was accepted"
    );
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(st.status, expected);
    assert!(
        st.messages.iter().any(|m| m.id == "MSG-SYNC-WENT-BACK"),
        "earlier warning vanished: {st:?}"
    );
}

#[test]
fn c1_busy_retry_keeps_earlier_merge_warning_in_session() {
    busy_retry_keeps_warning(Some(Status::Synced(77)), SyncStatus::Synced);
    busy_retry_keeps_warning(Some(Status::Offline), SyncStatus::Offline);
}

#[test]
fn f282_busy_retry_without_prior_report_still_shows_warning() {
    busy_retry_keeps_warning(None, SyncStatus::Error);
}

fn scripted_transfer(
    f: impl Fn(&larsal_sync::test_server::Request) -> larsal_sync::test_server::Response
    + Send
    + Sync
    + 'static,
) -> Scripted {
    use larsal_sync::test_server::Response;
    Scripted::new(move |r| match r.path.as_str() {
        "/v1/signin/challenge" => Response::new(
            200,
            format!(
                "{{\"nonce\":\"{}\",\"expires\":4000000000}}",
                larsal_crypto::base64::encode(larsal_crypto::base64::Form::Url, &[1; 32])
            )
            .as_bytes(),
        ),
        "/v1/signin" => Response::new(
            200,
            format!(
                "{{\"token\":\"{}\",\"idle_seconds\":900,\"expires\":4000000000}}",
                larsal_crypto::base64::encode(larsal_crypto::base64::Form::Url, &[2; 32])
            )
            .as_bytes(),
        ),
        _ => f(r),
    })
}

fn add_scripted(a: &Mac, server: &Scripted) {
    let mut c = Client::new(&server.address(), server.pin).unwrap();
    c.set_device(
        larsal_sync::state::DeviceId::from_bytes([9; 16]),
        DeviceKey::test_seam().unwrap(),
    );
    a.s.sync_with(|i| {
        i.state.servers.push(larsal_sync::state::Server {
            address: server.address(),
            pin: server.pin,
            account: None,
        });
        i.servers.insert(server.address(), Arc::new(Mutex::new(c)));
        i.save();
    });
}

fn concurrent_first_puts(other_server: bool, other_file: bool) {
    use larsal_sync::test_server::Response;
    let server = scripted_transfer(|_| Response::new(201, b"{}").with("ETag", "\"1\""));
    let another = scripted_transfer(|_| Response::new(201, b"{}").with("ETag", "\"1\""));
    let a = Mac::new(&format!("c1-parallel-{other_server}-{other_file}"), true);
    add_scripted(&a, &server);
    add_scripted(&a, &another);
    let second_id = if other_file {
        let alias = a.dir.join("Alias.larsalvault");
        std::fs::copy(a.dir.join("Personal.larsalvault"), &alias).unwrap();
        let id = a.s.open(alias.display().to_string()).unwrap();
        assert_eq!(
            a.s.unlock(id, Some(PASSWORD.into()), None).unwrap(),
            crate::session::UnlockResult::Unlocked
        );
        id
    } else {
        a.v
    };
    let second_address = if other_server {
        another.address()
    } else {
        server.address()
    };
    let ready = Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();
        let b = ready.clone();
        let ss = a.s.clone();
        let address = server.address();
        let v = a.v;
        let first = scope.spawn(move || {
            DOWNLOAD_STARTED.with(|m| {
                *m.borrow_mut() = Some(Box::new(move || {
                    tx.send(()).unwrap();
                    b.wait();
                }))
            });
            ss.sync_put_vault(v, address)
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let b = ready.clone();
        let ss = a.s.clone();
        let address = second_address;
        let second = scope.spawn(move || {
            DOWNLOAD_STARTED.with(|m| {
                *m.borrow_mut() = Some(Box::new(move || {
                    b.wait();
                }))
            });
            ss.sync_put_vault(second_id, address)
        });
        vec![first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "only one concurrent put may link the file"
    );
    assert_eq!(server.count("PUT") + another.count("PUT"), 1);
    assert_eq!(a.s.sync_with(|i| i.state.links.len()), 1);
    assert!(a.s.sync_with(|i| i.transfers.is_empty()));
}

#[test]
fn c1_concurrent_first_puts_link_one_local_file_once() {
    concurrent_first_puts(false, false);
}

#[test]
fn f284_first_put_reserves_across_servers() {
    concurrent_first_puts(true, false);
}

#[test]
fn f284_first_put_reserves_the_root_across_files_and_servers() {
    concurrent_first_puts(true, true);
}

#[test]
fn c1_download_disk_io_does_not_hold_up_session_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1-io-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "c1-io-b");
    let pending = b.s.sync_with(|i| i.pending.remove(0));
    let responsive = Arc::new(AtomicBool::new(false));
    let worker = Arc::new(Mutex::new(None));
    let observed = responsive.clone();
    let w = worker.clone();
    let session = b.s.clone();
    let v = b.v;
    SERVER_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            // Pause at the real download fd, immediately before write_all/fsync.
            let (tx, rx) = std::sync::mpsc::channel();
            *w.lock().unwrap() = Some(std::thread::spawn(move || {
                let _ = session.sync_state(v);
                session.lock(v).unwrap();
                let _ = tx.send(());
            }));
            observed.store(
                rx.recv_timeout(std::time::Duration::from_millis(300))
                    .is_ok(),
                Ordering::SeqCst,
            );
        }))
    });
    let path = b.dir.join("Again.larsalvault");
    b.s.sync_download(
        address,
        pending.vault_id.to_string(),
        path.display().to_string(),
    )
    .unwrap();
    worker.lock().unwrap().take().unwrap().join().unwrap();
    assert!(
        responsive.load(Ordering::SeqCst),
        "Session::lock waited on the download disk IO mutex"
    );
}

#[test]
fn f284_failed_upload_releases_its_claim_for_retry() {
    use larsal_sync::test_server::Response;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let server = scripted_transfer(move |_| {
        if n.fetch_add(1, Ordering::SeqCst) == 0 {
            Response::new(500, b"{}")
        } else {
            Response::new(201, b"{}").with("ETag", "\"1\"")
        }
    });
    let a = Mac::new("f284-put-retry", true);
    add_scripted(&a, &server);
    assert!(a.s.sync_put_vault(a.v, server.address()).is_err());
    assert!(a.s.sync_with(|i| i.transfers.is_empty() && i.state.links.is_empty()));
    a.s.sync_put_vault(a.v, server.address()).unwrap();
    assert_eq!(server.count("PUT"), 2);
    assert_eq!(a.s.sync_with(|i| i.state.links.len()), 1);
    assert!(a.s.sync_with(|i| i.transfers.is_empty()));
}

#[test]
fn f284_upload_rechecks_the_local_file_and_root_before_commit() {
    use larsal_sync::test_server::Response;
    for change_file in [false, true] {
        let a = Mac::new(&format!("f284-put-identity-{change_file}"), true);
        let path = a.dir.join("Personal.larsalvault");
        let session = a.s.clone();
        let id = a.v;
        let server = scripted_transfer(move |_| {
            if change_file {
                std::fs::rename(&path, path.with_extension("saved")).unwrap();
                std::fs::write(&path, b"demo replacement").unwrap();
            } else {
                session
                    .with_edit(id, |v, _, _, _| {
                        v.root.uuid = Uuid([0x71; 16]);
                        Ok(())
                    })
                    .unwrap();
            }
            Response::new(201, b"{}").with("ETag", "\"1\"")
        });
        add_scripted(&a, &server);
        assert!(a.s.sync_put_vault(a.v, server.address()).is_err());
        assert_eq!(server.count("PUT"), 1);
        assert!(a.s.sync_with(|i| i.transfers.is_empty() && i.state.links.is_empty()));
        if change_file {
            assert_eq!(
                std::fs::read(a.dir.join("Personal.larsalvault")).unwrap(),
                b"demo replacement"
            );
        }
    }
}

#[test]
fn f297_download_reserves_remote_and_destination_across_callers() {
    use larsal_sync::test_server::Response;
    let body = std::fs::read(DEMO).unwrap();
    let server = scripted_transfer(move |_| Response::new(200, &body).with("ETag", "\"1\""));
    let another = scripted_transfer(|_| Response::new(200, b"demo").with("ETag", "\"1\""));
    let a = Mac::new("f297-competing", true);
    add_scripted(&a, &server);
    add_scripted(&a, &another);
    let id = larsal_sync::state::VaultId::from_bytes([3; 16]).to_string();
    let path = a.dir.join("Download.larsalvault");
    let other_path = a.dir.join("Other.larsalvault");
    let session = a.s.clone();
    let base = server.address();
    let base2 = another.address();
    let remote = id.clone();
    let destination = path.display().to_string();
    let other = other_path.clone();
    DOWNLOAD_STARTED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            assert!(
                session
                    .sync_download(base, remote, other.display().to_string())
                    .is_err()
            );
            assert!(
                session
                    .sync_download(
                        base2,
                        larsal_sync::state::VaultId::from_bytes([4; 16]).to_string(),
                        destination
                    )
                    .is_err()
            );
        }))
    });
    a.s.sync_download(server.address(), id, path.display().to_string())
        .unwrap();
    assert_eq!(server.count("GET"), 1);
    assert_eq!(another.count("GET"), 0);
    assert!(!other_path.exists());
    assert!(a.s.sync_with(|i| i.pending.len() == 1 && i.transfers.is_empty()));
}

#[test]
fn f297_network_and_create_errors_release_download_for_retry() {
    use larsal_sync::test_server::Response;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = Arc::new(AtomicUsize::new(0));
    let calls = n.clone();
    let body = std::fs::read(DEMO).unwrap();
    let server = scripted_transfer(move |_| {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Response::new(404, b"{}")
        } else {
            Response::new(200, &body).with("ETag", "\"1\"")
        }
    });
    let a = Mac::new("f297-errors", true);
    add_scripted(&a, &server);
    let id = larsal_sync::state::VaultId::from_bytes([3; 16]).to_string();
    let path = a.dir.join("Download.larsalvault");
    assert!(
        a.s.sync_download(server.address(), id.clone(), path.display().to_string())
            .is_err()
    );
    assert!(!path.exists());
    assert!(a.s.sync_with(|i| i.pending.is_empty() && i.transfers.is_empty()));
    std::fs::write(&path, b"demo existing file").unwrap();
    assert!(
        a.s.sync_download(server.address(), id.clone(), path.display().to_string())
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"demo existing file");
    assert!(a.s.sync_with(|i| i.pending.is_empty() && i.transfers.is_empty()));
    std::fs::remove_file(&path).unwrap();
    a.s.sync_download(server.address(), id, path.display().to_string())
        .unwrap();
    assert_eq!(n.load(Ordering::SeqCst), 3);
    assert!(a.s.sync_with(|i| i.pending.len() == 1 && i.transfers.is_empty()));
}

#[test]
fn f297_replaced_destination_is_neither_linked_nor_deleted() {
    use larsal_sync::test_server::Response;
    let body = std::fs::read(DEMO).unwrap();
    let bytes = body.clone();
    let server = scripted_transfer(move |_| Response::new(200, &body).with("ETag", "\"1\""));
    let a = Mac::new("f297-replaced", true);
    add_scripted(&a, &server);
    let path = a.dir.join("Download.larsalvault");
    let moved = a.dir.join("Moved.larsalvault");
    let p = path.clone();
    let old = moved.clone();
    SERVER_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(p.clone(), old).unwrap();
            std::fs::write(p, b"demo replacement").unwrap();
        }))
    });
    assert!(
        a.s.sync_download(
            server.address(),
            larsal_sync::state::VaultId::from_bytes([3; 16]).to_string(),
            path.display().to_string()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"demo replacement");
    assert_eq!(
        std::fs::read(moved).unwrap(),
        bytes,
        "the actual opened fd was written and synced"
    );
    assert!(a.s.sync_with(|i| i.pending.is_empty() && i.transfers.is_empty()));
}

#[test]
fn f297_cancelled_download_cannot_commit_or_cancel_another_claim() {
    use larsal_sync::test_server::Response;
    let body = std::fs::read(DEMO).unwrap();
    let server = scripted_transfer(move |_| Response::new(200, &body).with("ETag", "\"1\""));
    let a = Mac::new("f297-cancel", true);
    add_scripted(&a, &server);
    let other =
        a.s.sync_reserve(Claim {
            path: a.dir.join("Other.larsalvault"),
            root: None,
            remote: None,
        })
        .unwrap();
    let path = a.dir.join("Download.larsalvault");
    let p = path.clone();
    let session = a.s.clone();
    SERVER_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            session.sync_with(|i| i.transfers.retain(|c| c.path != p));
        }))
    });
    assert!(
        a.s.sync_download(
            server.address(),
            larsal_sync::state::VaultId::from_bytes([3; 16]).to_string(),
            path.display().to_string()
        )
        .is_err()
    );
    a.s.sync_with(|i| {
        assert!(i.pending.is_empty());
        assert_eq!(i.transfers.len(), 1);
        assert!(Arc::ptr_eq(&i.transfers[0], &other.claim));
    });
    drop(other);
    assert!(a.s.sync_with(|i| i.transfers.is_empty()));
    assert_eq!(std::fs::read(path).unwrap(), std::fs::read(DEMO).unwrap());
}

#[test]
fn f297_unwinding_releases_only_the_owned_claim_and_retry_works() {
    use larsal_sync::test_server::Response;
    let body = std::fs::read(DEMO).unwrap();
    let server = scripted_transfer(move |_| Response::new(200, &body).with("ETag", "\"1\""));
    let a = Mac::new("f297-unwind", true);
    add_scripted(&a, &server);
    let other =
        a.s.sync_reserve(Claim {
            path: a.dir.join("Other.larsalvault"),
            root: None,
            remote: None,
        })
        .unwrap();
    let path = a.dir.join("Download.larsalvault");
    let id = larsal_sync::state::VaultId::from_bytes([3; 16]).to_string();
    DOWNLOAD_STARTED.with(|m| *m.borrow_mut() = Some(Box::new(|| panic!("demo cancellation"))));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.s.sync_download(
            server.address(),
            id.clone(),
            path.display().to_string()
        )))
        .is_err()
    );
    assert!(!path.exists());
    assert_eq!(server.count("GET"), 0);
    a.s.sync_with(|i| {
        assert_eq!(i.transfers.len(), 1);
        assert!(Arc::ptr_eq(&i.transfers[0], &other.claim));
    });
    a.s.sync_download(server.address(), id, path.display().to_string())
        .unwrap();
    drop(other);
    assert!(a.s.sync_with(|i| i.pending.len() == 1 && i.transfers.is_empty()));
}

#[test]
fn f297_duplicate_at_the_open_fd_boundary_cannot_commit() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f297-final-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "f297-final-b");
    let pending = b.s.sync_with(|i| i.pending.remove(0));
    let id = pending.vault_id.to_string();
    let session = b.s.clone();
    let original = pending.path.clone();
    SERVER_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            session.sync_with(|i| i.pending.push(pending))
        }))
    });
    let path = b.dir.join("Again.larsalvault");
    assert!(
        b.s.sync_download(address, id, path.display().to_string())
            .is_err()
    );
    b.s.sync_with(|i| {
        assert_eq!(i.pending.len(), 1);
        assert_eq!(i.pending[0].path, original);
        assert!(i.transfers.is_empty());
    });
    assert_eq!(
        std::fs::read(path).unwrap(),
        std::fs::read(original).unwrap()
    );
}

#[test]
fn f297_published_download_can_link_before_the_call_returns() {
    use larsal_sync::test_server::Response;
    let body = std::fs::read(DEMO).unwrap();
    let server = scripted_transfer(move |_| Response::new(200, &body).with("ETag", "\"1\""));
    let a = Mac::new("f297-published", false);
    add_scripted(&a, &server);
    let path = a.dir.join("Download.larsalvault");
    let p = path.clone();
    let session = a.s.clone();
    DOWNLOAD_COMMITTED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            let id = session.open(p.display().to_string()).unwrap();
            assert_eq!(
                session.unlock(id, Some(PASSWORD.into()), None).unwrap(),
                crate::session::UnlockResult::Unlocked
            );
            session.sync_tick();
            session.sync_with(|i| {
                assert!(i.pending.is_empty() && i.transfers.is_empty());
                assert_eq!(i.state.links.len(), 1);
            });
        }))
    });
    a.s.sync_download(
        server.address(),
        larsal_sync::state::VaultId::from_bytes([3; 16]).to_string(),
        path.display().to_string(),
    )
    .unwrap();
    assert_eq!(server.count("PUT"), 0);
}

#[test]
fn f284_downloaded_alias_cannot_link_an_existing_root_across_servers() {
    let one = larsal_server();
    let two = larsal_server();
    let a = first(&one.address(), one.pin, "root-link-receiver");
    put(&a, &one.address());
    let b = first(&two.address(), two.pin, "root-link-source");
    put(&b, &two.address());
    a.s.sync_add_server(two.address(), client::printed(&two.pin))
        .unwrap();
    let account =
        b.s.sync_with(|i| i.state.servers[0].account.as_ref().unwrap().account);
    let key = DeviceKey::test_seam().unwrap();
    let public = key.public_key().unwrap();
    let device = two
        .seams
        .add_device(&account, &public, "Mac")
        .unwrap()
        .unwrap();
    let mut c = Client::new(&two.address(), two.pin).unwrap();
    c.set_device(device, key);
    a.s.sync_with(|i| {
        i.state.server_mut(&two.address()).unwrap().account = Some(Account {
            account,
            device,
            label: random_hex().unwrap(),
            public_key: public,
        });
        i.servers.insert(two.address(), Arc::new(Mutex::new(c)));
        i.save();
    });
    let listed = a.s.sync_server_vaults(two.address()).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].linked);
    let alias = a.dir.join("Remote-alias.larsalvault");
    a.s.sync_download(
        two.address(),
        listed[0].id.clone(),
        alias.display().to_string(),
    )
    .unwrap();
    let id = a.s.open(alias.display().to_string()).unwrap();
    assert_eq!(
        a.s.unlock(id, Some(PASSWORD.into()), None).unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    let root = a.s.with_vault(id, |v| Ok(v.root.uuid)).unwrap();
    assert_eq!(root, a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap());
    a.s.sync_tick();
    let links = a.s.sync_with(|i| i.state.links.clone());
    assert_eq!(
        links.len(),
        1,
        "two real servers linked the same root twice: {links:?}"
    );
    assert!(!a.s.sync_server_vaults(two.address()).unwrap()[0].linked);
}
