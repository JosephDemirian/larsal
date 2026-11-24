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
