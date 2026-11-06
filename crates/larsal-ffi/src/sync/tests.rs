//! E16-S7a's full runs: two Macs (two sessions, two devices of one account,
//! each with its own settings folder and test clock) against Larsal's server
//! in process on 127.0.0.1:0 with its first-start certificate, pinned
//! (LD-327 (6)). The second device comes from the server's test helper
//! (SYN-04.11); the device keys are test-seam keys (LD-317 (2)). Timing
//! runs on the test clocks; no test sleeps.

use super::*;
use crate::edit::EditText;
use crate::saving::{DiskChoice, DiskEvent};
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

/// SYN-03.2, SYN-03 T03: another Mac picks the vault from the list, saves it and
/// opens it. Its state links the vault, its file holds the server's bytes, and its
/// later unlocks ask only for the password. T01's key-file part comes with
/// E16-S7b, which runs this row again with it.
#[test]
fn syn03_2_t03_another_mac_takes_the_vault_and_links_it() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "t03-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "t03-b");
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    let path = b.dir.join("Personal.larsalvault");
    let links = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].file, path.display().to_string());
    assert!(b.s.sync_server_vaults(address).unwrap()[0].linked);
    assert_eq!(std::fs::read(&path).unwrap(), stored(&a).1);
    b.s.lock(b.v).unwrap();
    b.unlock();
    assert_eq!(a.titles(), b.titles());
}

/// SYN-03 T04's run: A and B each changed a different entry of the demo vault,
/// saved and synced at once, and then twice more. The titles before it come back.
fn t04_done(tag: &str) -> (LarsalServer, String, Mac, Mac, Vec<String>) {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, &format!("{tag}-a"));
    put(&a, &address);
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    let b = second(&app, &address, app.pin, &a, &format!("{tag}-b"));
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
    (app, address, a, b, t)
}

/// E16-S7a check 2, SYN-03.5, SYN-03 T04: A and B each change a different
/// entry of the demo vault and save; both sync at once. After the runs
/// both hold both changes, and the server holds version 3.
#[test]
fn syn03_5_t04_two_macs_change_two_entries_at_once_and_both_keep_both() {
    let (_app, address, a, b, t) = t04_done("t04");
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
/// entry title or entry password, raw or encoded, in any request. SYN-03
/// T24's `demo2`, part bytes and SYN-03 T13's run are E16-S7b's. SYN-04 T08:
/// the session token is in no file of either Mac (state, settings, vault).
/// SYN-01 T20 (the client half): the sync code logs nothing.
#[test]
fn syn04_t13_t08_syn03_t24_no_password_in_any_request_and_no_token_in_any_file() {
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
    // Every entry's, the bin and history included.
    let (mut titles, passwords): (Vec<String>, Vec<String>) =
        a.s.with_vault(a.v, |v| {
            Ok(v.root
                .all_entries()
                .flat_map(|e| std::iter::once(e).chain(&e.history))
                .map(|e| (e.value("Title").to_owned(), e.value("Password").to_owned()))
                .unzip())
        })
        .unwrap();
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
    // Titles and passwords of 6 bytes or more: a shorter one could appear by
    // chance in the encrypted bytes. No demo password is that short.
    let passwords: Vec<String> = passwords.into_iter().filter(|p| !p.is_empty()).collect();
    assert!(!passwords.is_empty() && passwords.iter().all(|p| p.len() >= 6));
    titles.extend(["Secret title A".to_owned(), "Secret title B".to_owned()]);
    needles.extend(
        titles
            .iter()
            .chain(&passwords)
            .filter(|s| s.len() >= 6)
            .flat_map(|s| encoded(s.as_bytes())),
    );
    // SYN-04.10: a value made from the password, the vault's key, would
    // be 32 bytes; no request carries the vault's key material: only
    // encrypted bytes, ids, versions and signatures (SYN-03.14).
    needles.extend(made_from_the_password(&a));
    needles.extend(made_from_the_password(&b));
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

/// SYN-04 T13's forms of a value: raw, as hex and as base64.
fn encoded(value: &[u8]) -> Vec<Vec<u8>> {
    use larsal_crypto::base64::{Form, encode};
    let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        value.to_vec(),
        hex.to_uppercase().into_bytes(),
        hex.into_bytes(),
        encode(Form::Padded, value).into_bytes(),
        encode(Form::Url, value).into_bytes(),
    ]
}

/// SYN-04.10, SYN-04 T13: the password and the values made from it that a test
/// can work out, each raw, as hex and as base64: `P` (FMT-04.1), the composite
/// key (FMT-04.5) and the transformed key of `m`'s last save (FMT-04.11).
fn made_from_the_password(m: &Mac) -> Vec<Vec<u8>> {
    use larsal_crypto::kdf::{Verdict, assess, derive};
    use larsal_format::keys::{composite_key, password_part};
    use larsal_format::limits::Limits;
    let password = larsal_crypto::secret::SecretString::new(PASSWORD.to_owned());
    let part = password_part(&password);
    let composite = composite_key(Some(&part), None, None);
    let saver = m.s.with_edit_state(m.v, |e| e.saver.clone()).unwrap();
    let kept = saver.lock().unwrap();
    let mut host = m.s.host.lock().unwrap();
    let limits = Limits::DEFAULT;
    let params = kept.key.kdf();
    let cleared = match assess(params, &mut host, &limits.kdf, None).unwrap() {
        Verdict::Run(cleared) => cleared,
        Verdict::Ask(report) => match assess(params, &mut host, &limits.kdf, Some(&report)) {
            Ok(Verdict::Run(cleared)) => cleared,
            _ => panic!("the demo vault's KDF settings ran before"),
        },
    };
    let transformed = derive(&composite, &cleared).unwrap();
    // The real T: the session's own key gives the same digest.
    let digest = larsal_crypto::hash::sha256(&[b"T13", transformed.expose()]);
    assert_eq!(digest.expose(), kept.key.salted_digest(b"T13"));
    let mut out = Vec::new();
    for value in [
        PASSWORD.as_bytes(),
        part.expose(),
        composite.expose(),
        transformed.expose(),
    ] {
        out.extend(encoded(value));
    }
    out
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

/// How long [`t26_kill_child`] lives if nothing kills it, so it cannot outlive a
/// parent that died.
const T26_CHILD_LIFE: std::time::Duration = std::time::Duration::from_secs(10);

/// A state of `n` servers: the old one is small, the new one is big enough for a
/// kill to land while it is written.
fn t26_state(n: u16) -> State {
    State {
        servers: (0..n)
            .map(|i| larsal_sync::state::Server {
                address: format!("https://127.0.0.1:{}", i + 1),
                pin: [7; 32],
                account: None,
            })
            .collect(),
        links: Vec::new(),
    }
}

/// The child of T26's kill test: saves the two states in turn at the path it is
/// given. With no path, as under a plain `--ignored`, it does nothing.
#[test]
#[ignore = "run by syn03_3_t26_a_kill_while_the_state_is_written_leaves_old_or_new"]
fn t26_kill_child() {
    let Some(path) = std::env::var_os("LARSAL_T26_STATE") else {
        return;
    };
    let path = Path::new(&path);
    let (old, new) = (t26_state(1), t26_state(2_000));
    let start = std::time::Instant::now();
    while start.elapsed() < T26_CHILD_LIFE {
        old.save(path).unwrap();
        new.save(path).unwrap();
    }
}

/// SYN-03.3, SYN-03 T26's last clause: the test's own child saves the state in a
/// loop, through the one save there is, and is killed by its handle while it does.
/// What a restart reads is then the old state or the new one, never a mix. Bounded
/// to 100 rounds or 15 s. Checker 1's P8.
#[test]
fn syn03_3_t26_a_kill_while_the_state_is_written_leaves_old_or_new() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    /// Kills and reaps its child when dropped, also when the test panics.
    struct Killed(Child);
    impl Drop for Killed {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = TempDir::new("t26-kill");
    let path = dir.join("sync-state_debug.json");
    let (old, new) = (t26_state(1), t26_state(2_000));
    let (mut olds, mut news, mut round) = (0, 0, 0_u64);
    let start = Instant::now();
    while round < 100 && start.elapsed() < Duration::from_secs(15) {
        old.save(&path).unwrap();
        let old_len = std::fs::metadata(&path).unwrap().len();
        let child = Killed(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "sync::tests::t26_kill_child"])
                .env("LARSAL_T26_STATE", &path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        // Another length at the path: the child is in its loop.
        let waited = Instant::now();
        while std::fs::metadata(&path).unwrap().len() == old_len {
            assert!(waited.elapsed() < T26_CHILD_LIFE, "the child never wrote");
        }
        std::thread::sleep(Duration::from_millis(round % 40));
        drop(child);
        match State::load(&path) {
            Ok(s) if s == old => olds += 1,
            Ok(s) if s == new => news += 1,
            other => panic!("round {round}: neither state: {:?}", other.err()),
        }
        round += 1;
    }
    println!("T26: {round} kills: {olds} old, {news} new");
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
    static SAVE_LOCK_FREE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
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

pub(crate) fn save_lock_free() {
    if let Some(f) = SAVE_LOCK_FREE.with(|m| m.borrow_mut().take()) {
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
    add_client(a, &server.address(), server.pin);
}

fn add_client(a: &Mac, address: &str, pin: [u8; 32]) {
    let mut c = Client::new(address, pin).unwrap();
    c.set_device(
        larsal_sync::state::DeviceId::from_bytes([9; 16]),
        DeviceKey::test_seam().unwrap(),
    );
    a.s.sync_with(|i| {
        i.state.servers.push(larsal_sync::state::Server {
            address: address.to_owned(),
            pin,
            account: None,
        });
        i.servers
            .insert(address.to_owned(), Arc::new(Mutex::new(c)));
        i.save();
    });
}

/// The open vault linked at version 5 to the server at `address`, its file's hash
/// recorded as `local_sha`. The link comes back.
fn link_to(a: &Mac, address: &str, local_sha: [u8; 32]) -> Link {
    let (root, seen) =
        a.s.with_vault(a.v, |v| Ok((v.root.uuid, measures(v))))
            .unwrap();
    let link = Link {
        server: address.to_owned(),
        vault_id: larsal_sync::state::VaultId::from_bytes([3; 16]),
        file: a.dir.join("Personal.larsalvault").display().to_string(),
        root,
        highest: 5,
        server_sha: [5; 32],
        local_sha,
        seen,
    };
    a.s.sync_with(|i| {
        i.state.links.push(link.clone());
        i.save();
    });
    link
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

// SYN-03.14, SYN-03.5 step 2: only the encrypted vault this session has open
// goes up. Verify's probes of V2-1 as tests: every kind of file, on every path
// to an upload, with the server's stored bytes checked each time.

/// 59 bytes of demo plain text.
const PLAIN: &[u8] = b"Demo plain text: site shop.example, user demo, note hello.\n";
/// Another demo vault's file, under another password.
const OTHER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/rich-v4.larsalvault"
);

/// `good` with one bit changed at `at`.
fn flipped(good: &[u8], at: usize) -> Vec<u8> {
    let mut bad = good.to_vec();
    bad[at] ^= 1;
    bad
}

fn ids(st: &SyncState) -> Vec<&str> {
    st.messages.iter().map(|m| m.id.as_str()).collect()
}

/// Mac A with its demo vault linked and synced, through the test proxy, so
/// every request can be counted.
struct Linked {
    app: LarsalServer,
    proxy: Scripted,
    address: String,
    a: Mac,
}

impl Linked {
    fn new(tag: &str) -> Self {
        let app = larsal_server();
        let proxy = Scripted::proxy(&app);
        let address = proxy.address();
        let a = first(&address, proxy.pin, tag);
        a.s.sync_with(|i| {
            i.servers[&address].lock().unwrap().sign_for_port(app.port);
        });
        put(&a, &address);
        a.tick(0);
        assert_eq!(a.status(), Some(SyncStatus::Synced));
        let l = Self {
            app,
            proxy,
            address,
            a,
        };
        assert_eq!(l.stored(), (1, l.file()));
        l
    }

    fn path(&self) -> PathBuf {
        self.a.dir.join("Personal.larsalvault")
    }

    fn file(&self) -> Vec<u8> {
        std::fs::read(self.path()).unwrap()
    }

    /// What the server stores for the link: its version and bytes.
    fn stored(&self) -> (u64, Vec<u8>) {
        stored(&self.a)
    }

    /// Sync now and the next 60-second tick each find the file at the path
    /// refused: Error with `MSG-SYNC-LOCAL-FILE`, no PUT, and the server's
    /// bytes and this Mac's link as they were.
    fn refuses_at_a_run(&self) {
        self.refused_with("MSG-SYNC-LOCAL-FILE");
    }

    /// The same with `MSG-SYNC-SAVE-FIRST`: the file opened, and its form may
    /// not go up.
    fn needs_a_save_at_a_run(&self) {
        self.refused_with("MSG-SYNC-SAVE-FIRST");
    }

    fn refused_with(&self, id: &str) {
        let before = self.stored();
        let puts = self.proxy.count("PUT");
        let link = self.a.s.sync_with(|i| i.state.links.clone());
        self.a.s.sync_now(self.a.v).unwrap();
        for ms in [0, 60_000] {
            let states = self.a.tick(ms);
            assert_eq!(states.len(), 1);
            assert_eq!(states[0].status, SyncStatus::Error, "{states:?}");
            assert_eq!(ids(&states[0]), [id]);
            let text = &states[0].messages[0].text;
            assert!(
                !text.contains("Personal") && !text.contains("Demo") && !text.contains("/"),
                "{text}"
            );
            assert_eq!(self.a.status(), Some(SyncStatus::Error));
        }
        assert_eq!(self.proxy.count("PUT"), puts, "no PUT");
        assert_eq!(self.stored(), before, "the server's bytes stay");
        assert_eq!(self.a.s.sync_with(|i| i.state.links.clone()), link);
    }

    /// The next run uploads the file: Synced, one more PUT, and the server
    /// holds the file's bytes as `version`.
    fn uploads_at_a_run(&self, version: u64) {
        let puts = self.proxy.count("PUT");
        self.a.s.sync_now(self.a.v).unwrap();
        self.a.tick(0);
        assert_eq!(self.a.status(), Some(SyncStatus::Synced));
        assert_eq!(self.proxy.count("PUT"), puts + 1);
        assert_eq!(self.stored(), (version, self.file()));
    }
}

/// SYN-03.14, SYN-03 T31: plain text overwrites the file while unlocked.
/// Sync now and the tick send nothing, the status is Error, and no request
/// holds the text. Verify's first probe (V2-1).
#[test]
fn syn03_14_t31_a_plain_file_at_the_path_never_goes_up() {
    let l = Linked::new("t31");
    std::fs::write(l.path(), PLAIN).unwrap();
    l.refuses_at_a_run();
    assert!(
        l.proxy
            .requests()
            .iter()
            .all(|r| !r.raw.windows(PLAIN.len()).any(|w| w == PLAIN))
    );
}

/// SYN-03.14, SYN-03 T32: another vault's file, under another password and
/// under this vault's own, is refused at a run. Verify's second probe.
#[test]
fn syn03_14_t32_another_vaults_file_at_the_path_never_goes_up() {
    let l = Linked::new("t32");
    for other in [
        std::fs::read(OTHER).unwrap(),
        resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16])),
    ] {
        std::fs::write(l.path(), other).unwrap();
        l.refuses_at_a_run();
    }
}

/// SYN-03.14, SYN-03 T33: another vault under this vault's own password that
/// the disk check opened and loaded is what the session has open, and it is
/// still not this link's vault: neither its file nor a later save of it goes
/// up under the link.
#[test]
fn syn03_14_t33_another_vault_the_disk_check_loaded_never_goes_up() {
    let l = Linked::new("t33");
    std::fs::write(
        l.path(),
        resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16])),
    )
    .unwrap();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.refuses_at_a_run();
    l.a.rename(&l.a.titles()[0], "Saved in the other vault");
    l.refuses_at_a_run();
}

/// SYN-03.14, SYN-03 T34: a corrupt copy is refused, in the header and past
/// what the disk check reads (the first 1,024 bytes and the length). The disk
/// check cannot see the second; the next save writes a good file over it,
/// and that file goes up.
#[test]
fn syn03_14_t34_a_corrupt_copy_at_the_path_never_goes_up() {
    let l = Linked::new("t34");
    let good = l.file();
    std::fs::write(l.path(), flipped(&good, 200)).unwrap();
    l.refuses_at_a_run();
    std::fs::write(l.path(), flipped(&good, good.len() - 1)).unwrap();
    l.refuses_at_a_run();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::None);
    let t = l.a.titles();
    l.a.rename(&t[0], "Saved over the corrupt copy");
    l.uploads_at_a_run(2);
}

/// SYN-03.14, SYN-03.1 step 3, SYN-03 T35: the first upload of each kind of
/// file is refused: no PUT, nothing on the server, no link, no claim left,
/// never Synced, and the error names nothing of the file. The saved vault then
/// goes up as usual.
#[test]
fn syn03_14_t35_first_upload_of_a_plain_file_another_vault_or_a_corrupt_copy_is_refused() {
    let good = std::fs::read(DEMO).unwrap();
    for (n, bad) in [
        PLAIN.to_vec(),
        std::fs::read(OTHER).unwrap(),
        resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16])),
        flipped(&good, 200),
        flipped(&good, good.len() - 1),
    ]
    .into_iter()
    .enumerate()
    {
        // A fresh server each time: it limits how often one address signs in.
        let app = larsal_server();
        let proxy = Scripted::proxy(&app);
        let address = proxy.address();
        let a = first(&address, proxy.pin, &format!("t35-{n}"));
        a.s.sync_with(|i| {
            i.servers[&address].lock().unwrap().sign_for_port(app.port);
        });
        let path = a.dir.join("Personal.larsalvault");
        std::fs::write(&path, &bad).unwrap();
        let puts = proxy.count("PUT");
        let err = a.s.sync_put_vault(a.v, address.clone()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Nothing was uploaded"), "{n}: {text}");
        assert!(
            !text.contains("Personal") && !text.contains("Demo") && !text.contains("/"),
            "{n}: {text}"
        );
        assert_eq!(proxy.count("PUT"), puts, "{n}: no PUT");
        assert!(
            a.s.sync_server_vaults(address.clone()).unwrap().is_empty(),
            "{n}: the server holds nothing"
        );
        assert!(a.s.sync_with(|i| i.state.links.is_empty() && i.transfers.is_empty()));
        assert_eq!(a.status(), None, "{n}: never Synced");

        std::fs::write(&path, &good).unwrap();
        put(&a, &address);
        let listed = a.s.sync_server_vaults(address.clone()).unwrap();
        assert_eq!((listed.len(), listed[0].version), (1, 1), "{n}");
        assert_eq!(listed[0].size, good.len() as u64, "{n}");
    }
}

/// SYN-03.14, SYN-03 T36: after a legitimate save the file still goes up, as
/// bytes equal to what this Mac wrote.
#[test]
fn syn03_14_t36_after_a_legitimate_save_the_file_still_goes_up() {
    let l = Linked::new("t36");
    let t = l.a.titles();
    l.a.rename(&t[0], "Saved by this Mac");
    l.a.tick(2_000);
    assert_eq!(l.a.status(), Some(SyncStatus::Synced));
    assert_eq!(l.proxy.count("PUT"), 2);
    assert_eq!(l.stored(), (2, l.file()));
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(0);
    assert_eq!(
        l.proxy.count("PUT"),
        2,
        "the next run sees 304 and equal hashes"
    );
}

/// SYN-03.14, SYN-03 T37: a run before the disk check is refused and leaves
/// the disk check its event: plain text gives `Unreadable`, not `None`. A good
/// copy of this vault from another writer waits until the disk check has
/// opened it with this Mac's key, then goes up.
#[test]
fn syn03_14_t37_a_run_before_the_disk_check_is_refused_and_the_event_still_comes() {
    let l = Linked::new("t37-plain");
    std::fs::write(l.path(), PLAIN).unwrap();
    l.refuses_at_a_run();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Unreadable);

    let l = Linked::new("t37-good");
    std::fs::write(
        l.path(),
        resaved(PASSWORD, |v| {
            v.meta.name = "Demo other writer".into();
            v.meta.name_changed = larsal_model::Time(i64::MAX / 4);
        }),
    )
    .unwrap();
    l.refuses_at_a_run();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.uploads_at_a_run(2);
}

/// SYN-03.14, SYN-03.4, SYN-03 T38: the disk check first: its question holds
/// the run, so nothing is read or sent, and no new Synced time appears.
#[test]
fn syn03_14_t38_the_disk_check_first_holds_the_run() {
    let l = Linked::new("t38");
    let before = l.stored();
    let synced_at = l.a.s.sync_state(l.a.v).unwrap().synced_at;
    std::fs::write(l.path(), PLAIN).unwrap();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Unreadable);
    l.a.s.sync_with(|i| i.runs.clear());
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(0);
    l.a.tick(60_000);
    assert!(l.a.runs().is_empty(), "the question holds the run");
    assert_eq!(l.proxy.count("PUT"), 1, "only the first upload");
    assert_eq!(l.stored(), before);
    assert_eq!(l.a.s.sync_state(l.a.v).unwrap().synced_at, synced_at);
}

/// SYN-03.14, APP-05.28, SYN-03 T39: the way back from a refusal. Keep mine
/// writes the open vault over the plain file; that save ends the question, so
/// the runs start again and the vault goes up.
#[test]
fn syn03_14_t39_keep_mine_writes_the_vault_and_it_goes_up() {
    let l = Linked::new("t39");
    std::fs::write(l.path(), PLAIN).unwrap();
    l.refuses_at_a_run();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Unreadable);
    assert_eq!(
        l.a.s.resolve_disk(l.a.v, DiskChoice::KeepMine).unwrap(),
        DiskEvent::None
    );
    l.a.save();
    assert_ne!(l.file(), PLAIN);
    l.uploads_at_a_run(2);
}

/// SYN-03.14, SYN-03 T40: a file that is gone proves nothing: Error, not the
/// last run's Synced. A save brings it back (APP-05's missing file), and it
/// goes up.
#[test]
fn syn03_14_t40_a_missing_file_is_an_error_and_a_save_brings_it_back() {
    let l = Linked::new("t40");
    std::fs::remove_file(l.path()).unwrap();
    l.refuses_at_a_run();
    let t = l.a.titles();
    l.a.rename(&t[0], "Saved after the file left");
    l.uploads_at_a_run(2);
}

/// SYN-03.14, SYN-03.5 step 3, SYN-03 T41: a newer server copy over a plain
/// file: the save of the merge meets the changed file and fails, so nothing
/// goes up and the file stays as it is for the disk check.
#[test]
fn syn03_14_t41_a_newer_server_copy_over_a_plain_file_uploads_nothing() {
    let l = Linked::new("t41");
    let b = second(&l.app, &l.address, l.proxy.pin, &l.a, "t41-b");
    b.tick(0);
    let t = b.titles();
    b.rename(&t[1], "By B");
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    let before = l.stored();
    assert_eq!(before.0, 2);
    std::fs::write(l.path(), PLAIN).unwrap();
    let puts = l.proxy.count("PUT");
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(0);
    assert_eq!(l.a.status(), Some(SyncStatus::Error));
    assert_eq!(l.proxy.count("PUT"), puts, "no PUT");
    assert_eq!(l.stored(), before);
    assert_eq!(l.file(), PLAIN);
}

/// SYN-03.3, SYN-03 T42 (V2-5): after Save As the new file has no link: its
/// saves send nothing, the state of the old link stays, and a second link for
/// the same vault is refused. The old file keeps its link when it is opened
/// again. Moving the link to the new file is E16-S9's (LD-355).
#[test]
fn syn03_3_t42_save_as_leaves_the_link_on_the_old_file() {
    let mut l = Linked::new("t42");
    let before = l.stored();
    let link = l.a.s.sync_with(|i| i.state.links.clone());
    let moved = l.a.dir.join("Moved.larsalvault");
    let st = l.a.s.save_as(l.a.v, moved.display().to_string()).unwrap();
    assert_eq!((st.changes, st.failure), (0, None));
    let t = l.a.titles();
    l.a.rename(&t[0], "Only in the new file");
    l.a.tick(2_000);
    l.a.s.sync_now(l.a.v).unwrap();
    assert!(l.a.tick(60_000).is_empty(), "no linked open vault");
    assert_eq!(l.a.status(), None, "not linked");
    assert_eq!(l.proxy.count("PUT"), 1, "only the first upload");
    assert_eq!(l.stored(), before);
    assert_eq!(l.a.s.sync_with(|i| i.state.links.clone()), link);
    assert!(l.a.s.sync_put_vault(l.a.v, l.address.clone()).is_err());
    assert_eq!(l.proxy.count("PUT"), 1);

    l.a.s.close(l.a.v).unwrap();
    let old = l.path();
    l.a.open(&old);
    let states = l.a.tick(0);
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].status, SyncStatus::Synced);
    assert_eq!(l.proxy.count("PUT"), 1);
    assert_eq!(l.stored(), before);
}

/// 59 bytes of demo plain text after the final block of a good file.
const TAIL: &[u8] = b"Demo plain tail: site shop.example, user demo, note hello.\n";

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The Mac's server copy of its one link: its version and bytes.
fn stored(a: &Mac) -> (u64, Vec<u8>) {
    let (client, id) = a.s.sync_with(|i| {
        let link = &i.state.links[0];
        (i.servers[&link.server].clone(), link.vault_id)
    });
    let reply = client.lock().unwrap().get(&id, 0).unwrap();
    (reply.version.unwrap(), reply.body)
}

/// A Mac with a signed-in server through the test proxy, nothing on it yet.
fn unlinked(tag: &str) -> (LarsalServer, Scripted, String, Mac) {
    let app = larsal_server();
    let proxy = Scripted::proxy(&app);
    let address = proxy.address();
    let a = first(&address, proxy.pin, tag);
    a.s.sync_with(|i| {
        i.servers[&address].lock().unwrap().sign_for_port(app.port);
    });
    (app, proxy, address, a)
}

/// `file` with its outer header changed by `room`, and its header hash and HMAC
/// made again under the demo vault's key: what someone who holds the key can
/// write, and it opens (FMT-05). The block stream stays, so the vault is the same.
fn with_room(file: &[u8], room: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    use larsal_crypto::kdf::{Verdict, assess, derive};
    use larsal_format::keys::{composite_key, final_keys, password_part};
    use larsal_format::limits::Limits;
    let limits = Limits::DEFAULT;
    let h = larsal_format::header::read_header(file, &limits).unwrap();
    let password = larsal_crypto::secret::SecretString::new(PASSWORD.to_owned());
    let part = password_part(&password);
    let composite = composite_key(Some(&part), None, None);
    let s = Session::new();
    let mut host = s.host.lock().unwrap();
    let cleared = match assess(&h.kdf, &mut host, &limits.kdf, None).unwrap() {
        Verdict::Run(cleared) => cleared,
        Verdict::Ask(report) => match assess(&h.kdf, &mut host, &limits.kdf, Some(&report)) {
            Ok(Verdict::Run(cleared)) => cleared,
            _ => panic!("the demo vault's KDF settings ran before"),
        },
    };
    let keys = final_keys(&h.master_seed, &derive(&composite, &cleared).unwrap());
    let mut head = file[..h.len].to_vec();
    room(&mut head);
    let mut out = head.clone();
    out.extend_from_slice(larsal_crypto::hash::sha256(&[&head]).expose());
    out.extend_from_slice(larsal_format::integrity::header_hmac(&keys.hmac_key, &head).expose());
    out.extend_from_slice(&file[h.len + 64..]);
    out
}

/// One outer header field with demo plain text.
fn plain_field(id: u8) -> Vec<u8> {
    let mut field = vec![id];
    field.extend_from_slice(&u32::try_from(PLAIN.len()).unwrap().to_le_bytes());
    field.extend_from_slice(PLAIN);
    field
}

impl Linked {
    /// `TAIL` after the file's last byte.
    fn append_tail(&self) {
        let mut f = self.file();
        f.extend_from_slice(TAIL);
        std::fs::write(self.path(), f).unwrap();
    }

    /// Neither the server's bytes nor any request ever sent holds `needle`. The
    /// server keeps old versions (SYN-02.5), so every request counts.
    fn never_sent(&self, needle: &[u8]) {
        assert!(!has(&self.stored().1, needle), "on the server");
        assert!(
            self.proxy.requests().iter().all(|r| !has(&r.raw, needle)),
            "in a request"
        );
    }

    /// The way back: a save with no unsaved change writes the vault without the
    /// room, and that file goes up as `version`.
    fn a_save_heals_it(&self, version: u64, needle: &[u8]) {
        self.a.save();
        assert!(!has(&self.file(), needle), "the save drops it");
        self.uploads_at_a_run(version);
        self.never_sent(needle);
    }
}

/// SYN-03.14, SYN-03.5 step 2, FMT-01.20, SYN-03 T45: plain bytes appended after
/// the final block while unlocked. A run refuses the changed file; the disk check
/// still opens it (LD-01), and the runs after it refuse its form. Nothing goes
/// up until a save writes the vault without the tail. Checker 1's first probe.
#[test]
fn syn03_14_t45_a_tail_appended_while_unlocked_never_goes_up() {
    let l = Linked::new("t45");
    let clean = l.stored();
    l.append_tail();
    l.refuses_at_a_run();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.needs_a_save_at_a_run();
    assert_eq!(l.stored(), clean);
    l.never_sent(TAIL);
    l.a_save_heals_it(2, TAIL);
}

/// SYN-03.14, SYN-03 T46: the same tail is there when the vault unlocks, with no
/// disk check at all: it opens (LD-01) and its form is refused.
#[test]
fn syn03_14_t46_a_tail_present_at_unlock_never_goes_up() {
    let l = Linked::new("t46");
    let clean = l.stored();
    l.a.s.lock(l.a.v).unwrap();
    l.append_tail();
    l.a.unlock();
    l.needs_a_save_at_a_run();
    assert_eq!(l.stored(), clean);
    l.never_sent(TAIL);
    l.a_save_heals_it(2, TAIL);
}

/// SYN-03.14, SYN-03.1 step 3, SYN-03 T47: the same tail at a first upload, after
/// an unlock and after the disk check: refused, nothing on the server, no link,
/// and the words say what to do. After a save the vault goes up without it.
#[test]
fn syn03_14_t47_a_tail_at_the_first_upload_never_goes_up() {
    for disk_check in [false, true] {
        let (_app, proxy, address, a) = unlinked(&format!("t47-{disk_check}"));
        let path = a.dir.join("Personal.larsalvault");
        let mut f = std::fs::read(&path).unwrap();
        f.extend_from_slice(TAIL);
        if disk_check {
            std::fs::write(&path, &f).unwrap();
            assert_eq!(a.s.check_disk(a.v).unwrap(), DiskEvent::Reloaded);
        } else {
            a.s.lock(a.v).unwrap();
            std::fs::write(&path, &f).unwrap();
            a.unlock();
        }
        let err = a.s.sync_put_vault(a.v, address.clone()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Save the vault"), "{text}");
        assert!(text.contains("Nothing was uploaded"), "{text}");
        assert!(!text.contains("Personal") && !text.contains("/"), "{text}");
        assert_eq!(proxy.count("PUT"), 0);
        assert!(a.s.sync_server_vaults(address.clone()).unwrap().is_empty());
        assert!(a.s.sync_with(|i| i.state.links.is_empty() && i.transfers.is_empty()));

        a.save();
        put(&a, &address);
        assert_eq!(stored(&a), (1, std::fs::read(&path).unwrap()));
        assert!(proxy.requests().iter().all(|r| !has(&r.raw, TAIL)));
    }
}

/// SYN-03.14, SYN-03.5 step 2, FMT-02.3, FMT-02.21, SYN-03 T48: plain bytes in the
/// outer header of a file made with the key, so it opens: a comment at unlock, an
/// unknown field the disk check loads, end field data at a first upload. Opening
/// alone does not let them up; a Larsal save drops them, and then the vault goes.
#[test]
fn syn03_14_t48_room_in_the_outer_header_goes_up_only_after_a_save() {
    let l = Linked::new("t48-comment");
    let clean = l.stored();
    let planted = with_room(&l.file(), |head| {
        head.splice(12..12, plain_field(1));
    });
    l.a.s.lock(l.a.v).unwrap();
    std::fs::write(l.path(), planted).unwrap();
    l.a.unlock();
    l.needs_a_save_at_a_run();
    assert_eq!(l.stored(), clean);
    l.never_sent(PLAIN);
    l.a_save_heals_it(2, PLAIN);

    let l = Linked::new("t48-unknown");
    let planted = with_room(&l.file(), |head| {
        head.splice(12..12, plain_field(200));
    });
    std::fs::write(l.path(), planted).unwrap();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.needs_a_save_at_a_run();
    l.never_sent(PLAIN);
    l.a_save_heals_it(2, PLAIN);

    let (_app, proxy, address, a) = unlinked("t48-end");
    let path = a.dir.join("Personal.larsalvault");
    let planted = with_room(&std::fs::read(&path).unwrap(), |head| {
        let end = head.len() - 9;
        head.truncate(end);
        head.extend_from_slice(&plain_field(0));
    });
    a.s.lock(a.v).unwrap();
    std::fs::write(&path, planted).unwrap();
    a.unlock();
    let text =
        a.s.sync_put_vault(a.v, address.clone())
            .unwrap_err()
            .to_string();
    assert!(text.contains("Save the vault"), "{text}");
    assert_eq!(proxy.count("PUT"), 0);
    a.save();
    put(&a, &address);
    assert_eq!(stored(&a), (1, std::fs::read(&path).unwrap()));
    assert!(proxy.requests().iter().all(|r| !has(&r.raw, PLAIN)));
}

/// A vault the new vault wizard made at `name` in `a`'s folder, under the
/// password `wizard`.
fn wizard_vault(a: &Mac, name: &str, wizard: &str) -> (u64, PathBuf) {
    use crate::wizard::{Answer, CipherChoice, EncryptionChoice, KdfChoice, Outcome, Wizard};
    let small = || EncryptionChoice {
        cipher: CipherChoice::Aes256,
        kdf: KdfChoice::Argon2id,
        memory_mib: 1,
        lanes: 1,
        unlock_ms: 100,
    };
    let path = a.dir.join(format!("{name}.larsalvault"));
    let w = Wizard::new(Arc::clone(&a.s));
    assert!(w.measure(small()).unwrap());
    w.set_password(wizard.into()).unwrap();
    w.set_repeat(wizard.into()).unwrap();
    let out = w
        .create(
            name.into(),
            String::new(),
            path.display().to_string(),
            small(),
            false,
            vec![Answer::SafeMinimum],
        )
        .unwrap();
    let Outcome::Created { vault } = out else {
        panic!("{out:?}")
    };
    (vault, path)
}

/// SYN-03.5 step 2, SYN-03 T49: a vault the wizard made has its unlock root like
/// any other: its own file goes up and runs on its schedule, and another vault
/// under its password that the disk check loaded stays off. With no root known
/// the read refuses: it fails closed.
#[test]
fn syn03_14_t49_a_wizard_vault_has_its_root_and_another_root_stays_off() {
    const WIZARD: &str = "4v8Nq2LmZ7rT1xKc9WbP";
    let (_app, proxy, address, a) = unlinked("t49");
    let (own, _) = wizard_vault(&a, "Own", WIZARD);
    let root = a.s.with_vault(own, |v| Ok(v.root.uuid)).unwrap();
    assert_eq!(a.s.sync.root(own), Some(root));
    let st = a.s.sync_put_vault(own, address.clone()).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
    assert_eq!(proxy.count("PUT"), 1);
    a.s.sync_now(own).unwrap();
    a.tick(0);
    assert_eq!(a.s.sync_state(own).unwrap().status, SyncStatus::Synced);

    let (other, path) = wizard_vault(&a, "Other", WIZARD);
    std::fs::write(&path, resaved(WIZARD, |v| v.root.uuid = Uuid([0x65; 16]))).unwrap();
    assert_eq!(a.s.check_disk(other).unwrap(), DiskEvent::Reloaded);
    let text =
        a.s.sync_put_vault(other, address.clone())
            .unwrap_err()
            .to_string();
    assert!(text.contains("Nothing was uploaded"), "{text}");
    assert_eq!(proxy.count("PUT"), 1, "only the wizard's own file");

    a.s.sync.inner().vaults.remove(&a.v);
    assert!(matches!(
        a.s.sync_read(a.v),
        Some(Err(Unproven(Message::LocalFile)))
    ));
}

/// Sets its flag when dropped: a thread that loops on the flag ends when the test's
/// body panics, so the test goes red and never hangs.
struct Stop<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// SYN-03.5 step 2, SYN-03 T50: the read every upload crosses, against saves and
/// Save As on another thread: it answers busy or proven, never refused. The
/// new path and the new hash move together, under the save lock: the moment that
/// lock opens inside a Save As, the read is proven.
#[test]
fn syn03_3_t50_saves_and_save_as_racing_the_read_are_never_refused() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let a = Mac::new("t50", true);
    let done = AtomicBool::new(false);
    let (ok, refused) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let id = a.id_of(&a.titles()[0]);
    std::thread::scope(|scope| {
        let _stop = Stop(&done);
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                match a.s.sync_read(a.v) {
                    Some(Ok(_)) => ok.fetch_add(1, Ordering::SeqCst),
                    Some(Err(_)) => refused.fetch_add(1, Ordering::SeqCst),
                    None => 0,
                };
            }
        });
        for n in 0..20 {
            a.s.begin_edit(a.v, id.clone()).unwrap();
            a.s.set_text(a.v, EditText::Title, format!("Race {n}"))
                .unwrap();
            a.s.commit_edit(a.v).unwrap();
            a.save();
            let to = a.dir.join(format!("Moved-{n}.larsalvault"));
            a.s.save_as(a.v, to.display().to_string()).unwrap();
        }
    });
    assert!(ok.load(Ordering::SeqCst) > 0);
    assert_eq!(refused.load(Ordering::SeqCst), 0);

    let read = Arc::new(Mutex::new(None));
    let (s, v, seen) = (a.s.clone(), a.v, read.clone());
    SAVE_LOCK_FREE.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            *seen.lock().unwrap() = Some(s.sync_read(v).map(|r| r.is_ok()));
        }));
    });
    let to = a.dir.join("Moved-last.larsalvault");
    a.s.save_as(a.v, to.display().to_string()).unwrap();
    assert_eq!(read.lock().unwrap().take(), Some(Some(true)));
}

/// A Mac linked to a scripted server whose first `on` request runs `act` on its
/// session, vault and folder before `reply` answers: something that lands during
/// a run. The run has ended when this returns. The link before the run comes back
/// too.
fn during_a_run(
    tag: &str,
    on: &'static str,
    act: impl FnOnce(&Session, u64, &Path) + Send + 'static,
    reply: impl Fn(&larsal_sync::test_server::Request) -> larsal_sync::test_server::Response
    + Send
    + Sync
    + 'static,
) -> (Mac, Scripted, Link) {
    let a = Mac::new(tag, true);
    let hook = Mutex::new(Some((a.s.clone(), a.v, a.dir.to_path_buf(), act)));
    let server = scripted_transfer(move |r| {
        if r.method == on
            && r.path.starts_with("/v1/vaults/")
            && let Some((s, v, dir, act)) = hook.lock().unwrap().take()
        {
            act(&s, v, &dir);
        }
        reply(r)
    });
    add_scripted(&a, &server);
    let link = link_to(&a, &server.address(), [0; 32]);
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    assert!(!a.s.sync.left(a.v), "the mark ends with the run");
    (a, server, link)
}

/// A Save As to a new path during a run ([`during_a_run`]).
fn save_as_during_a_run(
    tag: &str,
    on: &'static str,
    reply: impl Fn(&larsal_sync::test_server::Request) -> larsal_sync::test_server::Response
    + Send
    + Sync
    + 'static,
) -> (Mac, Scripted, Link) {
    during_a_run(
        tag,
        on,
        |s, v, dir| {
            let to = dir.join("Moved.larsalvault");
            s.save_as(v, to.display().to_string()).unwrap();
        },
        reply,
    )
}

/// SYN-03.3, SYN-03 T51: a Save As that lands during a run. A run that has not
/// read yet sends nothing, on the 304 branch and on the merge branch: the new
/// file has no link. A run whose upload was on its way sent the old file, as it
/// read it, and the old link records that; its report is not the new file's.
#[test]
fn syn03_3_t51_a_save_as_during_a_run_sends_nothing_more_and_reports_nothing() {
    use larsal_sync::test_server::Response;
    let (a, server, link) = save_as_during_a_run("t51-304", "GET", |_| {
        Response::new(304, b"").with("ETag", "\"5\"")
    });
    assert_eq!(server.count("PUT"), 0);
    assert_eq!(a.status(), None);
    assert_eq!(a.s.sync_with(|i| i.state.links.clone()), [link]);

    let copy = resaved(PASSWORD, |_| {});
    let (a, server, link) = save_as_during_a_run("t51-200", "GET", move |_| {
        Response::new(200, &copy).with("ETag", "\"6\"")
    });
    assert_eq!(server.count("PUT"), 0, "the merge stops before its save");
    assert_eq!(a.status(), None);
    assert_eq!(a.s.sync_with(|i| i.state.links[0].highest), link.highest);

    let (a, server, link) = save_as_during_a_run("t51-put", "PUT", |r| match r.method.as_str() {
        "GET" => Response::new(304, b"").with("ETag", "\"5\""),
        _ => Response::new(200, b"{}").with("ETag", "\"6\""),
    });
    let old = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    let sent: Vec<_> = server
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT")
        .collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].body, old,
        "the old file, as read before the Save As"
    );
    assert_eq!(a.status(), None, "its report stays off the new file");
    let after = a.s.sync_with(|i| i.state.links[0].clone());
    assert_eq!(
        (after.file, after.highest, after.local_sha),
        (link.file, 6, larsal_sync::sync::hash(&old))
    );

    // A Save As just before a run: the run finds no link and the mark ends.
    let a = Mac::new("t51-before", true);
    a.s.sync
        .inner()
        .vaults
        .get_mut(&a.v)
        .unwrap()
        .schedule
        .sync_now();
    let now = a.clock.now_ms();
    assert!(
        a.s.sync
            .inner()
            .vaults
            .get_mut(&a.v)
            .unwrap()
            .schedule
            .start(now, false)
    );
    let to = a.dir.join("Moved.larsalvault");
    a.s.save_as(a.v, to.display().to_string()).unwrap();
    assert!(a.s.sync.left(a.v));
    a.s.sync_run(a.v);
    assert!(!a.s.sync.left(a.v));
}

/// SYN-03.14, SYN-03 T52: each shape a path can hold is refused, none hangs, and
/// the good bytes back are Synced with no upload.
#[test]
fn syn03_14_t52_every_shape_of_file_is_refused_and_the_good_bytes_come_back() {
    let l = Linked::new("t52");
    let good = l.file();
    let plain = l.a.dir.join("plain.txt");
    std::fs::write(&plain, PLAIN).unwrap();
    let copy = l.a.dir.join("copy.larsalvault");
    std::fs::write(&copy, &good).unwrap();
    let path = l.path();
    let clear = || match std::fs::symlink_metadata(&path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir(&path).unwrap(),
        Ok(_) => std::fs::remove_file(&path).unwrap(),
        Err(_) => {}
    };
    for bytes in [&b""[..], &good[..good.len() / 2], &good[..good.len() - 1]] {
        std::fs::write(&path, bytes).unwrap();
        l.refuses_at_a_run();
    }
    clear();
    std::os::unix::fs::symlink(&plain, &path).unwrap();
    l.refuses_at_a_run();
    clear();
    std::os::unix::fs::symlink(l.a.dir.join("gone"), &path).unwrap();
    l.refuses_at_a_run();
    clear();
    std::fs::create_dir(&path).unwrap();
    l.refuses_at_a_run();
    clear();
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    l.refuses_at_a_run();
    clear();
    std::os::unix::fs::symlink(&copy, &path).unwrap();
    let puts = l.proxy.count("PUT");
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(0);
    assert_eq!(l.a.status(), Some(SyncStatus::Synced), "the same bytes");
    clear();
    std::fs::write(&path, &good).unwrap();
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(0);
    assert_eq!(l.a.status(), Some(SyncStatus::Synced));
    assert_eq!(l.proxy.count("PUT"), puts);
    assert_eq!(l.stored(), (1, good));
    l.never_sent(PLAIN);
}

/// SYN-03.14, SYN-03 T53: another root under this vault's password, loaded by the
/// disk check: refused at a first upload; and a linked vault that was locked and
/// unlocked on it sends nothing, so the server keeps its bytes.
#[test]
fn syn03_14_t53_another_root_stays_off_at_a_first_upload_and_after_a_relock() {
    let (_app, proxy, address, a) = unlinked("t53-first");
    let other = resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
    std::fs::write(a.dir.join("Personal.larsalvault"), &other).unwrap();
    assert_eq!(a.s.check_disk(a.v).unwrap(), DiskEvent::Reloaded);
    let text = a.s.sync_put_vault(a.v, address).unwrap_err().to_string();
    assert!(text.contains("Nothing was uploaded"), "{text}");
    assert_eq!(proxy.count("PUT"), 0);

    let l = Linked::new("t53-relock");
    let before = l.stored();
    std::fs::write(l.path(), &other).unwrap();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.a.s.lock(l.a.v).unwrap();
    l.a.unlock();
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(0);
    let t = l.a.titles();
    l.a.rename(&t[0], "Saved after the relock");
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(2_000);
    assert_eq!(l.proxy.count("PUT"), 1, "only the first upload");
    assert_eq!(l.stored(), before);
}

/// SYN-03.14, SYN-03 T54: a key change on this Mac is its own save, and goes up.
#[test]
fn syn03_14_t54_a_key_change_on_this_mac_goes_up() {
    let l = Linked::new("t54");
    let saver = l.a.s.with_edit_state(l.a.v, |e| e.saver.clone()).unwrap();
    {
        let mut sv = saver.lock().unwrap();
        l.a.s
            .with_edit(l.a.v, |_, _, _, s| {
                s.set_key(
                    &mut sv,
                    Some(Some(larsal_crypto::secret::SecretString::new(
                        "demo-new-pass-8".to_owned(),
                    ))),
                    None,
                );
                s.changes = 1;
                Ok(())
            })
            .unwrap();
    }
    l.a.save();
    l.uploads_at_a_run(2);
}

/// SYN-03.14, SYN-03 T55: a key change on disk by another writer: refused, held
/// while the question is up, and once the new key has opened it, it goes up.
#[test]
fn syn03_14_t55_a_key_change_on_disk_goes_up_after_the_new_key() {
    let l = Linked::new("t55");
    std::fs::write(
        l.path(),
        resaved("demo-new-pass-8", |v| {
            v.meta.name = "Demo other writer".into();
            v.meta.name_changed = larsal_model::Time(i64::MAX / 4);
        }),
    )
    .unwrap();
    l.refuses_at_a_run();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::NewKey);
    let puts = l.proxy.count("PUT");
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(60_000);
    assert_eq!(l.proxy.count("PUT"), puts, "held while asked");
    l.a.s
        .resolve_disk_with_key(
            l.a.v,
            DiskChoice::Reload,
            Some("demo-new-pass-8".into()),
            None,
        )
        .unwrap();
    l.uploads_at_a_run(2);
}

/// SYN-03.3, SYN-03 T56: Save As and back: the link comes back and the save goes
/// up.
#[test]
fn syn03_3_t56_save_as_and_back_resumes_the_link() {
    let l = Linked::new("t56");
    let moved = l.a.dir.join("Moved.larsalvault");
    l.a.s.save_as(l.a.v, moved.display().to_string()).unwrap();
    assert_eq!(l.a.status(), None);
    l.a.s
        .save_as(l.a.v, l.path().display().to_string())
        .unwrap();
    l.uploads_at_a_run(2);
}

/// SYN-03.3, SYN-03 T57: Save As of a vault with no link, then a first upload: it
/// works, the link is on the new file and its saves go up.
#[test]
fn syn03_3_t57_save_as_then_a_first_upload_links_the_new_file() {
    let (_app, proxy, address, a) = unlinked("t57");
    let moved = a.dir.join("Moved.larsalvault");
    a.s.save_as(a.v, moved.display().to_string()).unwrap();
    put(&a, &address);
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    let t = a.titles();
    a.rename(&t[0], "After Save As");
    a.tick(2_000);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert_eq!(proxy.count("PUT"), 2);
    assert_eq!(stored(&a), (2, std::fs::read(&moved).unwrap()));
}

/// SYN-03.14, SYN-03 T58: an older copy of this vault at the path: refused, the
/// disk check merges and holds the run until the merged save, so the old bytes
/// never go up again; the merged save does.
#[test]
fn syn03_14_t58_an_older_copy_never_goes_up() {
    let l = Linked::new("t58");
    let old = l.file();
    let t = l.a.titles();
    l.a.rename(&t[0], "Newer than the old copy");
    l.a.tick(2_000);
    assert_eq!(l.stored().0, 2);
    std::fs::write(l.path(), &old).unwrap();
    l.refuses_at_a_run();
    l.a.s.check_disk(l.a.v).unwrap();
    let puts = l.proxy.count("PUT");
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(60_000);
    assert_eq!(l.proxy.count("PUT"), puts, "held until the merged save");
    assert_ne!(l.stored().1, old);
    l.a.save();
    l.a.s.sync_now(l.a.v).unwrap();
    l.a.tick(2_000);
    assert_eq!(l.a.status(), Some(SyncStatus::Synced));
    assert_eq!(l.stored().1, l.file());
    assert_ne!(l.stored().1, old);
}

/// SYN-03.5 step 2, SYN-03 T59: the clear path for a vault Larsal never wrote. A
/// file the reference app's command line tool made has an exact frame, so after
/// an open it goes up untouched. The same file with room waits for one save.
#[test]
fn syn03_14_t59_a_vault_larsal_never_wrote_has_a_clear_path_up() {
    let open = |tag: &str, tail: &[u8]| {
        let (app, proxy, address, a) = unlinked(tag);
        let path = a.dir.join("Rich.larsalvault");
        let mut file = std::fs::read(OTHER).unwrap();
        file.extend_from_slice(tail);
        std::fs::write(&path, file).unwrap();
        let id = a.s.open(path.display().to_string()).unwrap();
        assert_eq!(
            a.s.unlock(id, Some("demo-pass-5".into()), None).unwrap(),
            crate::session::UnlockResult::Unlocked
        );
        (app, proxy, address, a, id, path)
    };

    let (_app, _proxy, address, a, id, path) = open("t59-exact", b"");
    let st = a.s.sync_put_vault(id, address).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
    assert_eq!(stored(&a), (1, std::fs::read(OTHER).unwrap()));
    assert_eq!(std::fs::read(&path).unwrap(), std::fs::read(OTHER).unwrap());

    let (_app, proxy, address, a, id, path) = open("t59-room", TAIL);
    let text =
        a.s.sync_put_vault(id, address.clone())
            .unwrap_err()
            .to_string();
    assert!(text.contains("Save the vault"), "{text}");
    assert_eq!(proxy.count("PUT"), 0);
    a.s.save(id).unwrap();
    a.s.sync_put_vault(id, address).unwrap();
    assert_eq!(stored(&a), (1, std::fs::read(&path).unwrap()));
    assert!(proxy.requests().iter().all(|r| !has(&r.raw, TAIL)));
}

/// SYN-03.7, SYN-03 T44: `GET /v1/vaults` listing a linked vault lower than
/// the highest seen puts `MSG-SYNC-ROLLBACK` on the open vault (Error), and
/// nothing is downloaded or uploaded. The highest seen listed changes nothing.
#[test]
fn syn03_7_t44_a_listed_rollback_reaches_the_open_vault_and_downloads_nothing() {
    let list = |version: u64| {
        let id = larsal_sync::state::VaultId::from_bytes([3; 16]);
        format!(r#"{{"vaults":[{{"id":"{id}","version":{version},"size":2}}]}}"#).into_bytes()
    };
    let (a, server) = c1_scripted_mac("t44-lower", list(4));
    let rows = a.s.sync_server_vaults(server.address()).unwrap();
    assert_eq!((rows.len(), rows[0].version, rows[0].linked), (1, 4, true));
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(st.status, SyncStatus::Error);
    assert_eq!(ids(&st), ["MSG-SYNC-ROLLBACK"]);
    assert_eq!(server.count("PUT"), 0);
    assert!(
        server
            .requests()
            .iter()
            .all(|r| !r.path.starts_with("/v1/vaults/")),
        "nothing downloaded"
    );

    let (a, server) = c1_scripted_mac("t44-same", list(5));
    a.s.sync_server_vaults(server.address()).unwrap();
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
    assert!(st.messages.is_empty());
}

/// SYN-03.3, SYN-03 T61: an unlock during a run. The run began under the unlock
/// before it, so it reads and merges nothing more and its report stays off, whatever
/// that unlock found. A Save As and a relock (Checker 2's P1) send the new file under
/// no link; another root's file and a relock (Checker 1's p23) send nothing under
/// the old link. After a plain relock the next run reads as usual.
#[test]
fn syn03_3_t61_an_unlock_during_a_run_sends_nothing_more() {
    use larsal_sync::test_server::{Request, Response};
    fn relock(s: &Session, v: u64) {
        s.lock(v).unwrap();
        let r = s.unlock(v, Some(PASSWORD.into()), None).unwrap();
        assert_eq!(r, crate::session::UnlockResult::Unlocked);
    }
    fn reply(r: &Request) -> Response {
        match r.method.as_str() {
            "GET" => Response::new(304, b"").with("ETag", "\"5\""),
            _ => Response::new(200, b"{}").with("ETag", "\"6\""),
        }
    }
    let (a, server, link) = during_a_run(
        "t61-save-as",
        "GET",
        |s, v, dir| {
            let to = dir.join("Moved.larsalvault");
            s.save_as(v, to.display().to_string()).unwrap();
            relock(s, v);
        },
        reply,
    );
    assert_eq!(server.count("PUT"), 0);
    assert_eq!(a.status(), None);
    assert_eq!(a.s.sync_with(|i| i.state.links.clone()), [link]);

    let other = resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
    let (a, server, link) = during_a_run(
        "t61-root",
        "GET",
        move |s, v, dir| {
            std::fs::write(dir.join("Personal.larsalvault"), &other).unwrap();
            relock(s, v);
        },
        reply,
    );
    assert_eq!(server.count("PUT"), 0);
    let open = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    assert_eq!(open, Uuid([0x65; 16]), "the unlock took the other root");
    assert_eq!(a.status(), None);
    assert_eq!(a.s.sync_with(|i| i.state.links.clone()), [link]);

    let (a, server, link) = during_a_run("t61-plain", "GET", |s, v, _| relock(s, v), reply);
    assert_eq!(server.count("PUT"), 0);
    assert_eq!(a.status(), None);
    assert_eq!(a.s.sync_with(|i| i.state.links.clone()), [link]);
    a.tick(0);
    assert_eq!(server.count("PUT"), 1, "the run the unlock asked for");
    assert_eq!(a.status(), Some(SyncStatus::Synced));
}

/// SYN-03.5 step 2, SYN-03 T62: the bytes that come back are the bytes checked. A
/// writer swaps plain text and the good file at the path while a read runs in a
/// loop: nothing but the good bytes ever comes back, and plain text is only ever
/// `MSG-SYNC-LOCAL-FILE`. A second read of the file, for the hash or for the frame
/// check, would show here. Checker 1's p25.
#[test]
fn syn03_5_t62_the_file_is_read_once_and_those_bytes_come_back() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let l = Linked::new("t62");
    let (good, path) = (l.file(), l.path());
    let (plain_file, good_file, tmp) = (
        l.a.dir.join("swap-plain"),
        l.a.dir.join("swap-good"),
        l.a.dir.join("swap-tmp"),
    );
    std::fs::write(&plain_file, PLAIN).unwrap();
    std::fs::write(&good_file, &good).unwrap();
    let done = AtomicBool::new(false);
    let mut proven = 0;
    std::thread::scope(|scope| {
        let _stop = Stop(&done);
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                for from in [&plain_file, &good_file] {
                    std::fs::hard_link(from, &tmp).unwrap();
                    std::fs::rename(&tmp, &path).unwrap();
                }
            }
        });
        let start = std::time::Instant::now();
        while proven < 2_000 && start.elapsed() < std::time::Duration::from_secs(20) {
            match l.a.s.sync_read(l.a.v) {
                Some(Ok((bytes, _))) => {
                    assert!(bytes == good, "other bytes than those checked came back");
                    proven += 1;
                }
                Some(Err(Unproven(m))) => assert_eq!(m, Message::LocalFile, "a second read"),
                None => {}
            }
        }
    });
    assert!(proven > 0, "the good file passed at least once");
}

/// SYN-03.13, SYN-03 T63: a report belongs to its root. A relock keeps it. A new
/// vault the wizard made at a path that was linked has no link and reads no
/// status, and nothing is sent. Checker 2's P5.
#[test]
fn syn03_13_t63_a_wizard_vault_at_a_formerly_linked_path_reads_no_status() {
    let l = Linked::new("t63");
    let before = l.stored();
    l.a.s.lock(l.a.v).unwrap();
    l.a.unlock();
    assert_eq!(l.a.status(), Some(SyncStatus::Synced), "the same root");
    l.a.s.lock(l.a.v).unwrap();
    std::fs::remove_file(l.path()).unwrap();
    let (id, _) = wizard_vault(&l.a, "Personal", "4v8Nq2LmZ7rT1xKc9WbP");
    assert_eq!(id, l.a.v, "the same slot");
    l.a.s.sync_now(id).unwrap();
    l.a.tick(0);
    l.a.tick(60_000);
    assert_eq!(l.a.s.sync_state(id), None);
    assert_eq!(l.proxy.count("PUT"), 1, "only the first upload");
    assert_eq!(l.stored(), before);
}

/// SYN-03.2, SYN-03.14, SYN-03 T64: a download with a tail, from a hostile server. It
/// opens (LD-01), and the read every upload crosses refuses it, so it never links,
/// after the unlock or after a save, and nothing goes up. Today it stays pending in
/// silence: what the status line says of it is E16-S9's. Checker 2's P2.
#[test]
fn syn03_2_t64_a_download_with_a_tail_never_links() {
    use larsal_sync::test_server::Response;
    let mut body = std::fs::read(DEMO).unwrap();
    body.extend_from_slice(TAIL);
    let server = scripted_transfer(move |r| {
        if r.method == "GET" {
            Response::new(200, &body).with("ETag", "\"3\"")
        } else {
            Response::new(200, b"{}").with("ETag", "\"4\"")
        }
    });
    let mut b = Mac::new("t64", false);
    add_scripted(&b, &server);
    let path = b.dir.join("Down.larsalvault");
    b.s.sync_download(
        server.address(),
        larsal_sync::state::VaultId::from_bytes([7; 16]).to_string(),
        path.display().to_string(),
    )
    .unwrap();
    b.open(&path);
    let not_linked = |m: &Mac| {
        let (links, pending) = m.s.sync_with(|i| (i.state.links.len(), i.pending.len()));
        assert_eq!((links, pending, m.status()), (0, 1, None));
        assert_eq!(server.count("PUT"), 0);
    };
    b.s.sync_now(b.v).unwrap();
    b.tick(0);
    not_linked(&b);
    let t = b.titles();
    b.rename(&t[0], "Saved after the tail download");
    b.tick(2_000);
    not_linked(&b);
    assert!(server.requests().iter().all(|r| !has(&r.raw, TAIL)));
}

/// `bytes` opened with the demo password, as a run opens a server copy.
fn opened(s: &Session, bytes: &[u8]) -> Vault {
    let password = larsal_crypto::secret::SecretString::new(PASSWORD.to_owned());
    let credentials = larsal_format::keys::Credentials {
        password: Some(&password),
        key_file: None,
        hardware_key: None,
    };
    s.open_bytes(bytes, &credentials, false)
        .unwrap()
        .unwrap()
        .vault
}

/// SYN-03.7, MOD-11.19 limit 1, LD-269 (4), SYN-03 T12, both runs on real vaults. A's
/// sync state and open vault hold Argon2id 64 MiB; the server copy has 16 MiB. Both
/// runs merge and warn by name, with no value. A copy with a newer settings time
/// keeps its 16 MiB; with an older one, A's settings group wins and its 64 MiB pass
/// limit 1's compare. The result is checked in the open vault and in the saved file.
#[test]
fn syn03_7_t12_both_runs_warn_and_the_settings_time_picks_the_result() {
    use larsal_model::{Argon2Kind, Kdf, Time};
    use larsal_sync::test_server::Response;
    let argon = |memory_kib| Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 2,
        memory_kib,
        lanes: 2,
    };
    // Older than everything in the demo vault, so the newest change time stays
    // the entries' and neither run reads as gone back.
    let settings = Time::from_unix(1_000_000_000).unwrap();
    for (run, copy_settings, result) in [
        ("newer", Time(settings.0 + 100), 16_384),
        ("older", Time(settings.0 - 100), 65_536),
    ] {
        let mut a = Mac::new(&format!("t12-{run}"), false);
        let path = a.dir.join("Personal.larsalvault");
        let own = resaved(PASSWORD, |v| {
            v.encryption.kdf = argon(65_536);
            v.meta.settings_changed = settings;
        });
        std::fs::write(&path, own).unwrap();
        a.open(&path);
        let copy = resaved(PASSWORD, |v| {
            v.encryption.kdf = argon(16_384);
            v.meta.settings_changed = copy_settings;
        });
        let server = scripted_transfer(move |r| match r.method.as_str() {
            "GET" => Response::new(200, &copy).with("ETag", "\"6\""),
            _ => Response::new(200, b"{}").with("ETag", "\"7\""),
        });
        add_scripted(&a, &server);
        let link = link_to(&a, &server.address(), [0; 32]);
        assert_eq!(link.seen.kdf, argon(65_536), "A's sync state");
        a.tick(0);
        let st = a.s.sync_state(a.v).unwrap();
        assert_eq!(st.status, SyncStatus::Synced, "{run}: {st:?}");
        assert_eq!(ids(&st), ["MSG-SYNC-WEAKER"], "{run}");
        let text = &st.messages[0].text;
        assert!(text.contains("key derivation"), "{text}");
        assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text}");
        let open = a.s.with_vault(a.v, |v| Ok(v.encryption.kdf)).unwrap();
        assert_eq!(open, argon(result), "{run}: the open vault");
        let saved = opened(&a.s, &std::fs::read(&path).unwrap());
        assert_eq!(saved.encryption.kdf, argon(result), "{run}: the saved file");
    }
}

/// SYN-03.7, SYN-03 T28: this Mac's own edit is no rollback. After T04, A's sync
/// state holds version 3. B edits E2 at 10:00:00 and uploads version 4; A edits E1
/// at 10:00:05 and saves before its next run. Version 4's newest change time is
/// earlier than A's APP-05.26 record and later than A's sync state, and the guard
/// compares with the sync state only: A merges, uploads version 5 with both edits,
/// and shows no message.
#[test]
fn syn03_7_t28_this_macs_own_edit_is_no_rollback() {
    use larsal_model::{Group, Time};
    fn stamp(g: &mut Group, id: &str, at: Time) {
        for e in &mut g.entries {
            let hex: String = e.uuid.0.iter().map(|b| format!("{b:02x}")).collect();
            if hex == id {
                e.times.last_modification = at;
            }
        }
        for c in &mut g.groups {
            stamp(c, id, at);
        }
    }
    let edit_at = |m: &Mac, from: &str, to: &str, at: Time| {
        let id = m.id_of(from);
        m.s.begin_edit(m.v, id.clone()).unwrap();
        m.s.set_text(m.v, EditText::Title, to.into()).unwrap();
        m.s.commit_edit(m.v).unwrap();
        m.s.with_edit(m.v, |v, _, _, _| {
            stamp(&mut v.root, &id, at);
            Ok(())
        })
        .unwrap();
        m.save();
    };
    let (_app, address, a, b, _) = t04_done("t28");
    let state = a.s.sync_with(|i| i.state.links[0].clone());
    assert_eq!(state.highest, 3);
    // The sync state's newest change time reads as 09:59:00.
    let ten = Time(state.seen.newest.0 + 60);
    let ten_05 = Time(ten.0 + 5);

    edit_at(&b, "E2 by B", "E2 at 10:00:00", ten);
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    let (version, bytes) = stored(&b);
    assert_eq!(version, 4);

    edit_at(&a, "E1 by A", "E1 at 10:00:05", ten_05);
    let copy = opened(&a.s, &bytes);
    assert_eq!(measures(&copy).newest, ten);
    assert!(
        a.s.guard(&copy, &bytes).older,
        "earlier than A's APP-05.26 record"
    );
    assert!(ten > state.seen.newest, "later than A's sync state");

    a.tick(2_000);
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
    assert!(st.messages.is_empty(), "{st:?}");
    assert_eq!(
        stored(&a),
        (
            5,
            std::fs::read(a.dir.join("Personal.larsalvault")).unwrap()
        )
    );
    assert_eq!(a.s.sync_with(|i| i.state.links[0].highest), 5);
    assert_eq!(a.s.sync_server_vaults(address).unwrap()[0].version, 5);
    b.s.sync_now(b.v).unwrap();
    b.tick(0);
    for m in [&a, &b] {
        let titles = m.titles();
        assert!(titles.contains(&"E1 at 10:00:05".to_owned()), "{titles:?}");
        assert!(titles.contains(&"E2 at 10:00:00".to_owned()), "{titles:?}");
    }
}

/// SYN-03.13, SYN-03 T27: what each case shows. T06 and a run that ended well: Synced
/// with the time, and Syncing while the run is open. T08: Error with `MSG-SYNC-BUSY`.
/// T18's status: Needs password. T19: Signed out. T21: Offline. T13's run comes with
/// E16-S7b; the status it sets reads through here.
#[test]
fn syn03_13_t27_each_case_shows_its_status() {
    use larsal_sync::test_server::Response;
    let file_sha = |a: &Mac| {
        larsal_sync::sync::hash(&std::fs::read(a.dir.join("Personal.larsalvault")).unwrap())
    };
    let scripted =
        |tag: &str,
         reply: Box<dyn Fn(&larsal_sync::test_server::Request) -> Response + Send + Sync>| {
            let a = Mac::new(tag, true);
            let server = scripted_transfer(reply);
            add_scripted(&a, &server);
            link_to(&a, &server.address(), [0; 32]);
            (a, server)
        };

    let a = Mac::new("t27-synced", true);
    let during = Arc::new(Mutex::new(None));
    let (s, v, seen) = (a.s.clone(), a.v, during.clone());
    let server = scripted_transfer(move |_| {
        *seen.lock().unwrap() = s.sync_state(v).map(|st| st.status);
        Response::new(304, b"").with("ETag", "\"5\"")
    });
    add_scripted(&a, &server);
    link_to(&a, &server.address(), file_sha(&a));
    a.tick(0);
    assert_eq!(*during.lock().unwrap(), Some(SyncStatus::Syncing));
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
    assert_eq!(st.synced_at, Some(a.clock.now_ms()));
    assert!(st.messages.is_empty());

    let (a, server) = scripted(
        "t27-busy",
        Box::new(|r| match r.method.as_str() {
            "GET" => Response::new(304, b"").with("ETag", "\"5\""),
            _ => Response::new(412, b"{}"),
        }),
    );
    a.tick(0);
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(
        (st.status, ids(&st)),
        (SyncStatus::Error, vec!["MSG-SYNC-BUSY"])
    );
    assert_eq!(server.count("PUT"), 3);

    let copy = resaved("another password", |_| {});
    let (a, server) = scripted(
        "t27-password",
        Box::new(move |_| Response::new(200, &copy).with("ETag", "\"6\"")),
    );
    a.tick(0);
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(
        (st.status, ids(&st)),
        (SyncStatus::NeedsPassword, vec!["MSG-SYNC-OTHER-KEY"])
    );
    assert_eq!(server.count("PUT"), 0);

    let a = Mac::new("t27-signed-out", true);
    let server = Scripted::new(|_| Response::new(401, br#"{"error":"unauthorized"}"#));
    add_scripted(&a, &server);
    link_to(&a, &server.address(), [0; 32]);
    a.tick(0);
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(
        (st.status, ids(&st)),
        (SyncStatus::SignedOut, vec!["MSG-SYNC-SIGNED-OUT"])
    );

    let a = Mac::new("t27-offline", true);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = format!("https://127.0.0.1:{port}");
    add_client(&a, &address, [0; 32]);
    link_to(&a, &address, [0; 32]);
    a.tick(0);
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(st.status, SyncStatus::Offline);
    assert!(st.messages.is_empty());

    a.s.sync_with(|i| {
        i.vaults.get_mut(&a.v).unwrap().report = Some(Report {
            status: Some(Status::ReplacedPassword),
            messages: Vec::new(),
        });
    });
    assert_eq!(a.status(), Some(SyncStatus::ReplacedPassword));
}

/// SYN-03.5 step 3, SYN-03 T07 on real vaults, past larsal-sync's stand-in: B
/// uploaded and A has no change of its own. A's vault holds B's change, A sends no
/// PUT, and A's state has B's version. Checker 1's P3.
#[test]
fn syn03_5_t07_on_real_vaults_a_takes_bs_change_and_sends_nothing() {
    let l = Linked::new("t07");
    let b = second(&l.app, &l.address, l.proxy.pin, &l.a, "t07-b");
    b.tick(0);
    let t = b.titles();
    b.rename(&t[1], "By B");
    b.tick(2_000);
    let puts = l.proxy.count("PUT");
    for _ in 0..2 {
        l.a.s.sync_now(l.a.v).unwrap();
        l.a.tick(0);
        assert_eq!(l.proxy.count("PUT"), puts, "no PUT from A");
        assert!(l.a.titles().contains(&"By B".to_owned()));
        assert_eq!(l.a.s.sync_with(|i| i.state.links[0].highest), 2);
        assert_eq!(l.a.status(), Some(SyncStatus::Synced));
    }
}

/// SYN-03.7, SYN-03 T11 on real vaults, past larsal-sync's stand-in: version 6 holds
/// the old demo file and A has a newer edit. It merges, nothing newer is lost, the
/// result goes up, and `MSG-SYNC-WENT-BACK` shows. Checker 1's P2.
#[test]
fn syn03_7_t11_on_real_vaults_an_old_file_loses_nothing_newer() {
    use larsal_sync::test_server::Response;
    let a = Mac::new("t11", true);
    let old = std::fs::read(DEMO).unwrap();
    let t = a.titles();
    a.rename(&t[0], "Newer than the old file");
    let server = scripted_transfer(move |r| match r.method.as_str() {
        "GET" => Response::new(200, &old).with("ETag", "\"6\""),
        _ => Response::new(200, b"{}").with("ETag", "\"7\""),
    });
    add_scripted(&a, &server);
    link_to(&a, &server.address(), [0; 32]);
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    let st = a.s.sync_state(a.v).unwrap();
    assert_eq!(
        (st.status, ids(&st)),
        (SyncStatus::Synced, vec!["MSG-SYNC-WENT-BACK"])
    );
    assert!(a.titles().contains(&"Newer than the old file".to_owned()));
    let sent: Vec<_> = server
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT")
        .collect();
    assert_eq!(sent.len(), 1);
    let up = opened(&a.s, &sent[0].body);
    assert!(
        up.root
            .all_entries()
            .any(|e| e.value("Title") == "Newer than the old file")
    );
}
