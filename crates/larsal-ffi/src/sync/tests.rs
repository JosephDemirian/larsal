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
/// The key-file part of a vault a test links by hand to a scripted server.
const TEST_PART: [u8; 32] = [0x5a; 32];

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

    /// The key-file part this unlock holds, as bytes.
    fn part(&self) -> Vec<u8> {
        let saver = self.s.with_edit_state(self.v, |e| e.saver.clone()).unwrap();
        let sv = saver.lock().unwrap();
        sv.key_file.as_ref().unwrap().key().expose().to_vec()
    }

    /// The vault keyed with [`TEST_PART`] and saved, as SYN-03.1 step 1 leaves a
    /// vault, for a test that links it by hand. A keyed vault stays as it is.
    fn keyed(&self) {
        let saver = self.s.with_edit_state(self.v, |e| e.saver.clone()).unwrap();
        let mut sv = saver.lock().unwrap();
        if sv.key_file.is_some() {
            return;
        }
        let part = SecretBytes::new(TEST_PART.to_vec());
        let key = part_key(&part).unwrap();
        let label = "test part";
        self.s.part_put(label, &part).unwrap();
        let (file, root) = self
            .s
            .with_edit(self.v, |v, path, _, s| {
                s.set_key(&mut sv, None, Some(Some((key, PART_NAME.to_owned()))));
                v.public_custom_data.clear();
                Ok((path.to_string_lossy().into_owned(), v.root.uuid))
            })
            .unwrap();
        self.s
            .sync_with(|i| {
                i.keep_part(Part {
                    file,
                    root,
                    label: label.to_owned(),
                })
            })
            .unwrap();
        drop(sv);
        self.save();
    }

    /// The demo vault saved again under `password` and this Mac's part.
    fn resaved(&self, password: &str, change: impl FnOnce(&mut Vault)) -> Vec<u8> {
        resaved_with(password, Some(&self.part()), change)
    }

    /// Changes the master password as the settings page does, and saves.
    fn change_password(&self, password: &str) {
        let vs = crate::vault_settings::VaultSettings::new(self.s.clone(), self.v);
        vs.set_password(password.to_owned()).unwrap();
        vs.set_repeat(password.to_owned()).unwrap();
        let outcome = vs
            .change_password(vec![crate::wizard::Answer::WeakPassword])
            .unwrap();
        assert_eq!(outcome, Outcome::Done);
        self.save();
    }

    /// Unlocks with `password` alone, as a screen does: true when it opened.
    fn unlocks(&self, password: &str) -> bool {
        self.s.unlock(self.v, Some(password.into()), None).unwrap()
            == crate::session::UnlockResult::Unlocked
    }
}

/// LD-266 (2), tests only: the parts reach `to`'s device store; E17-S1 replaces
/// this with the wrap through the server.
fn copy_parts(from: &Mac, to: &Mac) {
    let store: Vec<(String, Vec<u8>)> = from.s.sync_with(|i| {
        i.device_store
            .iter()
            .map(|(label, part)| (label.clone(), part.expose().to_vec()))
            .collect()
    });
    to.s.sync_with(|i| {
        for (label, part) in store {
            i.device_store.insert(label, SecretBytes::new(part));
        }
    });
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
    copy_parts(a, &b);
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
/// opens it, with the key-file part the test helper copied (LD-266 (2)). Its state
/// links the vault, its file holds the server's bytes, and its later unlocks ask
/// only for the password.
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
    assert_eq!(b.part(), a.part());
    b.s.lock(b.v).unwrap();
    b.unlock();
    assert_eq!(a.titles(), b.titles());
    assert_eq!(b.part(), a.part());
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
/// T24 on T13's run with `demo2` and the part is
/// `syn03_14_t24_nothing_in_plain_on_the_key_change_run`. SYN-04 T08:
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
    let alone = composite_key(Some(&part), None, None);
    let key_part = SecretBytes::new(m.part());
    let composite = composite_key(Some(&part), Some(&key_part), None);
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
        alone.expose(),
        key_part.expose(),
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
        ..State::default()
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
    resaved_with(password, None, change)
}

/// [`resaved`] under [`TEST_PART`] too: a copy of a vault linked by hand.
fn resaved_keyed(password: &str, change: impl FnOnce(&mut Vault)) -> Vec<u8> {
    resaved_with(password, Some(&TEST_PART), change)
}

/// [`resaved`] under `password` (none when empty) and `part`; with a part, as a
/// copy of a vault on the server is, with no field 12 unless `change` adds it
/// (LD-427).
fn resaved_with(password: &str, part: Option<&[u8]>, change: impl FnOnce(&mut Vault)) -> Vec<u8> {
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
    let part = part.map(|part| part_key(&SecretBytes::new(part.to_vec())).unwrap());
    let write = Credentials {
        password: (!password.is_empty()).then_some(&given),
        key_file: part.as_ref(),
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
    if part.is_some() {
        v.public_custom_data.clear();
    }
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
/// nothing (`MSG-SYNC-OTHER-VAULT`), under the kept key or under a password the
/// user gave, a retired one too: the root is read before the records. A copy
/// under other credentials is `WrongKey` until they are given; the open vault is
/// unchanged. The same vault merges.
#[test]
fn syn03_8_t17_another_vault_or_another_key_merges_nothing() {
    let a = Mac::new("t17", true);
    a.keyed();
    let before = (a.titles(), a.ids());
    let other = resaved_keyed(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
    assert!(matches!(
        a.s.merge_server(a.v, &other, 1),
        Merge::OtherVault
    ));
    let other_key = resaved_keyed("another password", |_| {});
    assert!(matches!(
        a.s.merge_server(a.v, &other_key, 1),
        Merge::WrongKey
    ));
    assert!(matches!(
        a.s.merge_server(a.v, b"not a vault", 1),
        Merge::Failed
    ));
    assert_eq!((a.titles(), a.ids()), before);
    let other_given = resaved_keyed("another password", |v| v.root.uuid = Uuid([0x65; 16]));
    a.s.sync_open_copy(a.v, "another password".into()).unwrap();
    assert!(matches!(
        a.s.merge_server(a.v, &other_given, 1),
        Merge::OtherVault
    ));
    assert_eq!((a.titles(), a.ids()), before);
    let same = resaved_keyed(PASSWORD, |_| {});
    assert!(matches!(
        a.s.merge_server(a.v, &same, 1),
        Merge::Done { changed: false, .. }
    ));

    // Another vault under a key this Mac retired is another vault: the root is
    // tested before the records, with no key derivation, and nothing waits.
    a.change_password("demo-new-pass-8");
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    assert_eq!(a.s.sync_retired(root).len(), 1);
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    let under_old = resaved_keyed(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
    assert!(matches!(
        a.s.merge_server(a.v, &under_old, 1),
        Merge::OtherVault
    ));
    assert!(a.s.with_edit_state(a.v, |e| e.sync_held.is_none()));
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
    assert!(matches!(a.s.merge_server(a.v, &file, 1), Merge::Busy));
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
    assert!(matches!(a.s.merge_server(a.v, &file, 1), Merge::Busy));
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
    static COPY_OPENED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static PUT_KEYED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// A server copy opened with the given password, before its retired test.
pub(crate) fn copy_opened() {
    if let Some(f) = COPY_OPENED.with(|m| m.borrow_mut().take()) {
        f();
    }
}

/// A put's key part is in the vault, before the read that goes up.
pub(crate) fn put_keyed() {
    if let Some(f) = PUT_KEYED.with(|m| m.borrow_mut().take()) {
        f();
    }
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
        a.keyed();
        let copy = resaved_keyed(PASSWORD, |v| {
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
            matches!(a.s.merge_server(a.v, &copy, 1), Merge::Busy),
            "part {part}"
        );
        assert_eq!(
            a.s.with_vault(a.v, |v| Ok(v.meta.name.clone())).unwrap(),
            before
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
    }
}

/// F-284: duplicate downloads, including downloads not yet run, never create
/// a second file or replace the existing link.
#[test]
fn f284_one_server_vault_links_to_one_file() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f284-a");
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, "f284-b");
    let download = b.s.sync_with(|i| i.state.links[0].clone());
    assert_eq!(
        download.root, UNKNOWN_ROOT,
        "the root comes at the first run"
    );
    let again = b.dir.join("Again.larsalvault");
    assert!(
        b.s.sync_download(
            address.clone(),
            download.vault_id.to_string(),
            again.display().to_string()
        )
        .is_err()
    );
    assert!(!again.exists());
    b.tick(0);
    let links = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(links.len(), 1);
    assert_ne!(links[0].root, UNKNOWN_ROOT);
    assert!(
        b.s.sync_download(
            address,
            download.vault_id.to_string(),
            again.display().to_string()
        )
        .is_err()
    );
    assert!(!again.exists());
    // A download link that raced another link must also be dropped.
    let bytes = std::fs::read(&download.file).unwrap();
    std::fs::write(&again, bytes).unwrap();
    let file = again.display().to_string();
    b.s.sync_with(|i| {
        i.state.links.push(Link {
            file: file.clone(),
            ..download.clone()
        });
        i.state.parts.push(Part {
            file,
            root: UNKNOWN_ROOT,
            label: part_label(&download.server, download.vault_id),
        });
    });
    let id = b.s.open(again.display().to_string()).unwrap();
    assert_eq!(
        b.s.unlock(id, Some(PASSWORD.into()), None).unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    b.tick(0);
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
    let p = b.s.sync_with(|i| i.state.links[0].clone());
    b.s.lock(b.v).unwrap();
    let changed = resaved(PASSWORD, |v| v.meta.name = "Demo changed download".into());
    assert_ne!(larsal_sync::sync::hash(&changed), p.local_sha);
    std::fs::write(&p.file, changed).unwrap();
    b.unlock();
    b.tick(0);
    assert!(b.s.sync_with(|i| i.state.links.is_empty()));
    assert_eq!(
        b.s.sync_with(|i| i.state.parts.len()),
        1,
        "the pointer stays"
    );
    assert_eq!(a.s.sync_server_vaults(address).unwrap()[0].version, 1);
}

/// F-288 beside C1R2-03's drop (round 2's mutant D3): B unlocks other bytes at
/// its download's path, then the downloaded bytes come back on disk before the
/// first run. The file holds the download, so the link is not dropped as stale,
/// but the unlock opened other bytes: the run drops the link and the pointer stays.
#[test]
fn f288_download_hash_is_checked_after_the_download_comes_back() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f288-back-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "f288-back-b");
    let p = b.s.sync_with(|i| i.state.links[0].clone());
    let download = std::fs::read(&p.file).unwrap();
    b.s.lock(b.v).unwrap();
    let changed = resaved(PASSWORD, |v| v.meta.name = "Demo changed download".into());
    std::fs::write(&p.file, changed).unwrap();
    b.unlock();
    std::fs::write(&p.file, &download).unwrap();
    b.tick(0);
    assert!(b.s.sync_with(|i| i.state.links.is_empty()));
    assert_eq!(
        b.s.sync_with(|i| i.state.parts.len()),
        1,
        "the pointer stays"
    );
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
    assert!(matches!(a.s.merge_server(id, &bytes, 1), Merge::Busy));
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
        a.s.merge_server(id, &std::fs::read(path).unwrap(), 1),
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
    assert!(matches!(s.merge_server(id, &copy, 1), Merge::Done { .. }));
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
    assert!(matches!(s.merge_server(id, &before, 1), Merge::Busy));
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
    let download = b.s.sync_with(|i| i.state.links.remove(0));
    let id = download.vault_id.to_string();
    let session = b.s.clone();
    DOWNLOAD_STARTED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            session.sync_with(|i| i.state.links.push(download));
        }));
    });
    let again = b.dir.join("Again.larsalvault");
    assert!(
        b.s.sync_download(address, id, again.display().to_string())
            .is_err()
    );
    assert!(!again.exists());
    assert_eq!(b.s.sync_with(|i| i.state.links.len()), 1);
}

// Through-Session regressions from Checker1 round 2.
fn c1_scripted_mac(tag: &str, body: Vec<u8>) -> (Mac, Scripted) {
    use larsal_sync::test_server::Response;
    let a = Mac::new(tag, true);
    a.keyed();
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
    let body = resaved_keyed(PASSWORD, |_| {});
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
    a.keyed();
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
    let pending = b.s.sync_with(|i| i.state.links.remove(0));
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
    assert!(a.s.sync_with(|i| i.state.links.len() == 1 && i.transfers.is_empty()));
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
    assert!(a.s.sync_with(|i| i.state.links.is_empty() && i.transfers.is_empty()));
    std::fs::write(&path, b"demo existing file").unwrap();
    assert!(
        a.s.sync_download(server.address(), id.clone(), path.display().to_string())
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"demo existing file");
    assert!(a.s.sync_with(|i| i.state.links.is_empty() && i.state.parts.is_empty()));
    assert!(a.s.sync_with(|i| i.transfers.is_empty()));
    std::fs::remove_file(&path).unwrap();
    a.s.sync_download(server.address(), id, path.display().to_string())
        .unwrap();
    assert_eq!(n.load(Ordering::SeqCst), 3);
    assert!(a.s.sync_with(|i| i.state.links.len() == 1 && i.transfers.is_empty()));
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
    assert!(a.s.sync_with(|i| i.state.links.is_empty() && i.state.parts.is_empty()));
    assert!(a.s.sync_with(|i| i.transfers.is_empty()));
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
            replaces: Vec::new(),
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
        assert!(i.state.links.is_empty() && i.state.parts.is_empty());
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
            replaces: Vec::new(),
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
    assert!(a.s.sync_with(|i| i.state.links.len() == 1 && i.transfers.is_empty()));
}

#[test]
fn f297_duplicate_at_the_open_fd_boundary_cannot_commit() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "f297-final-a");
    put(&a, &address);
    let b = second(&app, &address, app.pin, &a, "f297-final-b");
    let download = b.s.sync_with(|i| i.state.links.remove(0));
    let id = download.vault_id.to_string();
    let session = b.s.clone();
    let original = PathBuf::from(&download.file);
    SERVER_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            session.sync_with(|i| i.state.links.push(download))
        }))
    });
    let path = b.dir.join("Again.larsalvault");
    assert!(
        b.s.sync_download(address, id, path.display().to_string())
            .is_err()
    );
    b.s.sync_with(|i| {
        assert_eq!(i.state.links.len(), 1);
        assert_eq!(Path::new(&i.state.links[0].file), original);
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
    let body = resaved_keyed(PASSWORD, |_| {});
    let server = scripted_transfer(move |_| Response::new(200, &body).with("ETag", "\"1\""));
    let a = Mac::new("f297-published", false);
    add_scripted(&a, &server);
    a.s.part_put(
        &part_label(
            &server.address(),
            larsal_sync::state::VaultId::from_bytes([3; 16]),
        ),
        &SecretBytes::new(TEST_PART.to_vec()),
    )
    .unwrap();
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
                assert!(i.transfers.is_empty());
                assert_eq!(i.state.links.len(), 1);
                assert_ne!(i.state.links[0].root, UNKNOWN_ROOT);
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
    copy_parts(&b, &a);
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
        l.a.resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16])),
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
        l.a.resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16])),
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
        let saved = std::fs::read(&path).unwrap();
        assert_eq!(listed[0].size, saved.len() as u64, "{n}");
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
        l.a.resaved(PASSWORD, |v| {
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
fn with_room(file: &[u8], key_part: Option<&[u8]>, room: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    use larsal_crypto::kdf::{Verdict, assess, derive};
    use larsal_format::keys::{composite_key, final_keys, password_part};
    use larsal_format::limits::Limits;
    let limits = Limits::DEFAULT;
    let h = larsal_format::header::read_header(file, &limits).unwrap();
    let password = larsal_crypto::secret::SecretString::new(PASSWORD.to_owned());
    let part = password_part(&password);
    let key_part = key_part.map(|p| SecretBytes::new(p.to_vec()));
    let composite = composite_key(Some(&part), key_part.as_ref(), None);
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
    let planted = with_room(&l.file(), Some(&l.a.part()), |head| {
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
    let planted = with_room(&l.file(), Some(&l.a.part()), |head| {
        head.splice(12..12, plain_field(200));
    });
    std::fs::write(l.path(), planted).unwrap();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.needs_a_save_at_a_run();
    l.never_sent(PLAIN);
    l.a_save_heals_it(2, PLAIN);

    let (_app, proxy, address, a) = unlinked("t48-end");
    let path = a.dir.join("Personal.larsalvault");
    let planted = with_room(&std::fs::read(&path).unwrap(), None, |head| {
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
    a.keyed();
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

    let copy = resaved_keyed(PASSWORD, |_| {});
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
    let other = l.a.resaved(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
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
        l.a.resaved("demo-new-pass-8", |v| {
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
    let old = l.a.resaved(PASSWORD, |_| {});
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

/// SYN-03.5 step 2, SYN-03.1 step 1, SYN-03 T59: the clear path for a vault Larsal
/// never wrote. A file the reference app's command line tool made has an exact
/// frame, so after an open it takes its part and goes up as that save wrote it.
/// The same file with room waits for one save first.
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
    assert_eq!(stored(&a), (1, std::fs::read(&path).unwrap()));
    assert_ne!(std::fs::read(&path).unwrap(), std::fs::read(OTHER).unwrap());

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

    let other = resaved_keyed(PASSWORD, |v| v.root.uuid = Uuid([0x65; 16]));
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
/// opens (LD-01) with its pointer, and its bytes are more than the file's frame, so it
/// never links, after the unlock or after a save, and nothing goes up. It stays not
/// linked in silence: what the status line says of it is E16-S9's. Checker 2's P2.
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
        let (links, parts) =
            m.s.sync_with(|i| (i.state.links.len(), i.state.parts.len()));
        assert_eq!((links, parts, m.status()), (0, 1, None));
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

/// `bytes` opened with `password` and `part`: the opened vault, or `Err` for
/// `WrongKey`.
fn open_copy(m: &Mac, bytes: &[u8], password: &str, part: Option<&[u8]>) -> Result<Vault, ()> {
    let password = larsal_crypto::secret::SecretString::new(password.to_owned());
    let part = part.map(|part| part_key(&SecretBytes::new(part.to_vec())).unwrap());
    let credentials = larsal_format::keys::Credentials {
        password: Some(&password),
        key_file: part.as_ref(),
        hardware_key: None,
    };
    m.s.open_bytes(bytes, &credentials, false)
        .unwrap()
        .map(|o| o.vault)
}

/// `bytes` opened with the demo password and `m`'s part, as a run opens a server
/// copy.
fn opened(m: &Mac, bytes: &[u8]) -> Vault {
    open_copy(m, bytes, PASSWORD, Some(&m.part())).unwrap()
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
        let copy = resaved_keyed(PASSWORD, |v| {
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
        let saved = opened(&a, &std::fs::read(&path).unwrap());
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
    let copy = opened(&a, &bytes);
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
/// T18's status: Needs password. T19: Signed out. T21: Offline. T13's status:
/// `syn03_8_t13_ld264_a_key_change_and_an_upload_under_the_old_key_keep_both_edits`.
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
    a.keyed();
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

    let copy = resaved_keyed("another password", |_| {});
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
    let old = resaved_keyed(PASSWORD, |_| {});
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
    let up = opened(&a, &sent[0].body);
    assert!(
        up.root
            .all_entries()
            .any(|e| e.value("Title") == "Newer than the old file")
    );
}

/// The run of SYN-03 T13 up to `MSG-SYNC-OLD-KEY` on A, on Larsal's server through
/// a test proxy: T03 done; A changes the password to `demo2` and saves, and B,
/// still under `demo`, edits E2 and uploads first. A, at its run, finds a copy
/// that does not open, is given `demo`, and holds the copy.
struct KeyChange {
    _app: LarsalServer,
    proxy: Scripted,
    a: Mac,
    b: Mac,
    /// Titles before the run: the entries the steps change.
    t: Vec<String>,
}

const DEMO2: &str = "demo2-new-pass-9";

impl KeyChange {
    fn new(tag: &str) -> Self {
        let app = larsal_server();
        let proxy = Scripted::proxy(&app);
        let address = proxy.address();
        let a = first(&address, proxy.pin, &format!("{tag}-a"));
        a.s.sync_with(|i| {
            i.servers[&address].lock().unwrap().sign_for_port(app.port);
        });
        put(&a, &address);
        a.tick(0);
        let b = second(&app, &address, proxy.pin, &a, &format!("{tag}-b"));
        b.tick(0);
        assert_eq!(b.status(), Some(SyncStatus::Synced));
        let t = a.titles();
        Self {
            _app: app,
            proxy,
            a,
            b,
            t,
        }
    }

    /// A's change and edit, B's edit and upload under `demo`.
    fn changes(&self) {
        self.a.rename(&self.t[0], "E1 by A");
        self.a.change_password(DEMO2);
        self.b.rename(&self.t[1], "E2 by B");
        self.b.tick(2_000);
        assert_eq!(self.b.status(), Some(SyncStatus::Synced));
        assert_eq!(self.server_version(), 2);
    }

    fn server_version(&self) -> u64 {
        stored(&self.a).0
    }

    /// A's run after [`KeyChange::changes`]: `MSG-SYNC-OTHER-KEY`, no PUT; given
    /// `demo`, `MSG-SYNC-OLD-KEY`, no PUT, nothing of the copy taken.
    fn to_old_key(&self) {
        let a = &self.a;
        let puts = self.proxy.count("PUT");
        let states = a.tick(2_000);
        assert_eq!(states[0].status, SyncStatus::NeedsPassword, "{states:?}");
        assert_eq!(ids(&states[0]), ["MSG-SYNC-OTHER-KEY"]);
        assert!(states[0].ask_key, "the sheet comes up");
        a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
        let states = a.tick(0);
        assert_eq!(states[0].status, SyncStatus::ReplacedPassword, "{states:?}");
        assert_eq!(ids(&states[0]), ["MSG-SYNC-OLD-KEY"]);
        assert!(a.titles().contains(&"E1 by A".to_owned()));
        assert!(
            !a.titles().contains(&"E2 by B".to_owned()),
            "merged nothing"
        );
        // SYN-03.9: the 60-second timer never answers it.
        a.s.sync_with(|i| i.runs.clear());
        let states = a.tick(60_000);
        assert_eq!(states[0].status, SyncStatus::ReplacedPassword);
        assert!(a.runs().is_empty(), "no run while the answer waits");
        assert_eq!(self.proxy.count("PUT"), puts, "no PUT");
    }

    /// B's next run after A's upload: `MSG-SYNC-OTHER-KEY`, the sheet, no PUT.
    fn b_asks(&self) {
        let b = &self.b;
        let puts = self.proxy.count("PUT");
        b.s.sync_now(b.v).unwrap();
        let states = b.tick(0);
        assert_eq!(states[0].status, SyncStatus::NeedsPassword, "{states:?}");
        assert_eq!(ids(&states[0]), ["MSG-SYNC-OTHER-KEY"]);
        assert!(!states[0].messages[0].text.contains("new"));
        assert_eq!(self.proxy.count("PUT"), puts, "B uploads nothing");
    }

    /// The server's copy opens with `demo2` and the part, and no longer with `demo`.
    fn the_server_has_as_new_key(&self) {
        let (_, bytes) = stored(&self.a);
        let part = self.a.part();
        assert!(open_copy(&self.a, &bytes, PASSWORD, Some(&part)).is_err());
        assert!(open_copy(&self.a, &bytes, DEMO2, Some(&part)).is_ok());
    }
}

/// Every test below runs on the server in process, with the demo vault and demo
/// passwords only.
fn titled(m: &Mac, title: &str) -> bool {
    m.titles().contains(&title.to_owned())
}

/// SYN-03.1 step 1, FMT-04.5, SYN-03 T01, F-321, Verify's probe vr_p10: a vault
/// added to the server opens only with its master password plus the key-file part.
/// With only the server's bytes a guess of the right password gives the same
/// `WrongKey` as a wrong one, so nothing on the server tells them apart. The part is
/// in the device store, in no request and in no state file. `MasterKeyChanged` moved
/// (by the system clock, as every credential change's: `views::now`, not the run's
/// test clock). Without the part in the device store the file does not open.
#[test]
fn syn03_1_t01_f321_a_guess_of_the_right_password_cannot_open_the_server_copy() {
    let l = Linked::new("t01");
    let (version, bytes) = l.stored();
    assert_eq!(version, 1);
    assert_eq!(bytes, l.file());
    // The probe: the server's bytes alone, the right password and a wrong one.
    assert!(
        open_copy(&l.a, &bytes, PASSWORD, None).is_err(),
        "the right password opened the server's bytes alone"
    );
    assert!(open_copy(&l.a, &bytes, "a wrong guess", None).is_err());
    let part = l.a.part();
    assert_eq!(part.len(), 32);
    assert!(open_copy(&l.a, &bytes, "a wrong guess", Some(&part)).is_err());
    let copy = open_copy(&l.a, &bytes, PASSWORD, Some(&part)).unwrap();
    let demo = open_copy(&l.a, &std::fs::read(DEMO).unwrap(), PASSWORD, None).unwrap();
    assert!(copy.meta.master_key_changed > demo.meta.master_key_changed);
    let root = l.a.s.with_vault(l.a.v, |v| Ok(v.root.uuid)).unwrap();
    assert_eq!(copy.root.uuid, root);

    let (label, kept) = l.a.s.sync_with(|i| {
        let link = &i.state.links[0];
        let label = part_label(&link.server, link.vault_id);
        (label.clone(), i.device_store[&label].expose().to_vec())
    });
    assert_eq!(kept, part);
    let parts = l.a.s.sync_with(|i| i.state.parts.clone());
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].label, label);
    assert_eq!(parts[0].file, l.path().display().to_string());
    let needles = encoded(&part);
    for r in l.proxy.requests() {
        for n in &needles {
            assert!(!has(&r.raw, n), "{} {} holds the part", r.method, r.path);
        }
    }
    let state = std::fs::read(l.a.dir.join("settings/sync-state_debug.json")).unwrap();
    for n in &needles {
        assert!(!has(&state, n), "the state holds the part");
    }

    // This Mac's later unlocks take the part from the device store.
    l.a.s.lock(l.a.v).unwrap();
    assert!(l.a.unlocks(PASSWORD));
    assert_eq!(l.a.part(), part);
    assert_eq!(
        crate::vault_settings::VaultSettings::new(l.a.s.clone(), l.a.v)
            .view()
            .unwrap()
            .key_file
            .as_deref(),
        Some("Kept for sync")
    );
    l.a.s.lock(l.a.v).unwrap();
    l.a.s.sync_with(|i| i.device_store.clear());
    assert!(!l.a.unlocks(PASSWORD), "the file needs the part");
}

/// SYN-03.1 step 1, FMT-04.5, SYN-03 T02: a vault with a key file gets no second
/// part: its key, its `MasterKeyChanged` and its file stay, its bytes go up as they
/// are, and its `F` is the part in the device store.
#[test]
fn syn03_1_t02_a_vault_with_a_key_file_keeps_it_and_its_f_goes_with_it() {
    let (_app, proxy, address, mut a) = unlinked("t02");
    let f = [0x11u8; 32];
    let key = a.dir.join("own.larsalkey");
    std::fs::write(&key, f).unwrap();
    let path = a.dir.join("Keyed.larsalvault");
    let file = resaved_with(PASSWORD, Some(&f), |_| {});
    std::fs::write(&path, &file).unwrap();
    a.v = a.s.open(path.display().to_string()).unwrap();
    let typed = Some(key.display().to_string());
    assert_eq!(
        a.s.unlock(a.v, Some(PASSWORD.into()), typed.clone())
            .unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    let vs = crate::vault_settings::VaultSettings::new(a.s.clone(), a.v);
    let name = vs.view().unwrap().key_file;
    assert_eq!(name.as_deref(), Some("own.larsalkey"));
    let changed =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    put(&a, &address);
    assert_eq!(std::fs::read(&path).unwrap(), file, "the file stays");
    assert_eq!(stored(&a), (1, file.clone()), "as it is on the server");
    assert_eq!(a.part(), f);
    assert_eq!(vs.view().unwrap().key_file, name);
    let after =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert_eq!(after, changed);
    let kept = a.s.sync_with(|i| {
        let link = &i.state.links[0];
        i.device_store[&part_label(&link.server, link.vault_id)]
            .expose()
            .to_vec()
    });
    assert_eq!(kept, f);
    assert!(proxy.requests().iter().all(|r| !has(&r.raw, &f)));

    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(PASSWORD), "the device store gives it");
    a.s.lock(a.v).unwrap();
    assert!(!a.unlocks("a wrong guess"));
}

/// SYN-03.2: the device store gives the part, never the whole unlock: a vault keyed
/// by its key file alone, with nothing typed, stays locked and asks for that file.
#[test]
fn syn03_2_nothing_typed_opens_nothing_when_the_part_is_the_whole_key() {
    let (_app, _proxy, address, mut a) = unlinked("part-alone");
    let f = [0x55u8; 32];
    let key = a.dir.join("own.larsalkey");
    std::fs::write(&key, f).unwrap();
    let path = a.dir.join("Keyed.larsalvault");
    std::fs::write(&path, resaved_with("", Some(&f), |_| {})).unwrap();
    a.v = a.s.open(path.display().to_string()).unwrap();
    let typed = Some(key.display().to_string());
    let unlocked = crate::session::UnlockResult::Unlocked;
    assert_eq!(a.s.unlock(a.v, None, typed.clone()).unwrap(), unlocked);
    put(&a, &address);
    a.s.lock(a.v).unwrap();
    assert_ne!(a.s.unlock(a.v, None, None).unwrap(), unlocked);
    assert_eq!(a.s.unlock(a.v, None, typed).unwrap(), unlocked);
}

/// SYN-03.8: the password given is for one run: a run that ends before a merge
/// (here a 304) drops it, so no later run tries it.
#[test]
fn syn03_8_the_password_given_lives_for_one_run() {
    let l = Linked::new("given-once");
    l.a.s
        .sync_open_copy(l.a.v, "demo-given-once".into())
        .unwrap();
    let given = |l: &Linked| l.a.s.with_edit_state(l.a.v, |s| s.sync_given.is_some());
    assert!(given(&l));
    l.a.tick(0);
    assert_eq!(l.a.status(), Some(SyncStatus::Synced));
    assert!(!given(&l));
}

/// SYN-03.12, APP-05.17: the copy sheet of a linked vault's folder asks for the
/// password alone, and the copy opens with it and the kept part.
#[test]
fn syn03_12_a_copy_sheet_takes_the_part() {
    let l = Linked::new("copy-part");
    let copy = l.a.dir.join("Personal (copy).larsalvault");
    let other = "demo-copy-pass-3";
    std::fs::write(
        &copy,
        l.a.resaved(other, |v| v.meta.name = "Demo copy".into()),
    )
    .unwrap();
    assert_eq!(
        l.a.s
            .merge_copy(
                l.a.v,
                copy.display().to_string(),
                Some(other.into()),
                None,
                false
            )
            .unwrap(),
        crate::copies::CopyState::Merged
    );
}

/// SYN-03.1 step 2: the device store refuses, or the state does not reach the disk:
/// the put is refused before the vault's key changes, so it opens as before and
/// nothing goes up. A save that fails leaves a file that opens without the part.
#[test]
fn syn03_1_a_refused_part_changes_nothing_and_a_failed_save_leaves_a_vault_that_opens() {
    use std::os::unix::fs::PermissionsExt;
    let (_app, proxy, address, a) = unlinked("part-refused");
    let path = a.dir.join("Personal.larsalvault");
    let file = std::fs::read(&path).unwrap();
    let unchanged = |a: &Mac| {
        assert_eq!(std::fs::read(&path).unwrap(), file);
        assert_eq!(proxy.count("PUT"), 0);
        assert!(a.s.sync_with(|i| i.state.links.is_empty()));
        let saver = a.s.with_edit_state(a.v, |e| e.saver.clone()).unwrap();
        assert!(saver.lock().unwrap().key_file.is_none());
    };
    a.s.sync_with(|i| i.store_refuses = true);
    assert!(a.s.sync_put_vault(a.v, address.clone()).is_err());
    unchanged(&a);
    a.s.sync_with(|i| {
        assert!(i.state.parts.is_empty() && i.transfers.is_empty());
        i.store_refuses = false;
        i.unread = true;
    });
    let text =
        a.s.sync_put_vault(a.v, address.clone())
            .unwrap_err()
            .to_string();
    assert!(text.contains("could not write"), "{text}");
    unchanged(&a);
    a.s.sync_with(|i| {
        assert!(i.state.parts.is_empty() && i.device_store.is_empty());
        i.unread = false;
    });

    let dir = path.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let text = a.s.sync_put_vault(a.v, address.clone());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(text.unwrap_err().to_string().contains("could not be saved"));
    assert_eq!(std::fs::read(&path).unwrap(), file);
    assert_eq!(proxy.count("PUT"), 0);
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(PASSWORD), "the file on disk has no part yet");
    put(&a, &address);
    assert_eq!(stored(&a), (1, std::fs::read(&path).unwrap()));
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(PASSWORD));
    assert_eq!(
        a.s.sync_with(|i| (i.state.parts.len(), i.device_store.len())),
        (1, 1)
    );
}

/// SYN-03.1: a failed first upload leaves the vault with its part, opening as
/// before; the next try sends that same part under a new `vault_id`.
#[test]
fn syn03_1_a_failed_upload_keeps_the_part_and_the_next_try_sends_it() {
    use larsal_sync::test_server::Response;
    let a = Mac::new("part-retry", true);
    let server = scripted_transfer(|_| Response::new(500, b"{}"));
    add_scripted(&a, &server);
    assert!(a.s.sync_put_vault(a.v, server.address()).is_err());
    let part = a.part();
    let parts = a.s.sync_with(|i| i.state.parts.clone());
    assert_eq!(parts.len(), 1);
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(PASSWORD));
    assert_eq!(a.part(), part);
    let replied = scripted_transfer(|_| Response::new(201, b"{}").with("ETag", "\"1\""));
    add_scripted(&a, &replied);
    a.s.sync_put_vault(a.v, replied.address()).unwrap();
    assert_eq!(a.part(), part, "one key-file slot: the same part");
    let parts = a.s.sync_with(|i| i.state.parts.clone());
    assert_eq!(parts.len(), 1);
    a.s.sync_with(|i| {
        assert_eq!(i.device_store.len(), 1, "the old label is gone");
        assert!(i.device_store.contains_key(&parts[0].label));
    });
}

/// SYN-03.1 step 1, F-321: this unlock holds no part, because a password-only copy
/// with the vault's root came to the linked path and opened without one: it goes
/// up neither by the 304 branch nor through a merge, even of a planted server copy
/// it opens.
#[test]
fn syn03_1_f321_a_password_only_file_at_a_linked_path_never_goes_up() {
    let l = Linked::new("no-part");
    let before = l.stored();
    let root = l.a.s.with_vault(l.a.v, |v| Ok(v.root.uuid)).unwrap();
    let alone = resaved(PASSWORD, |v| {
        v.root.uuid = root;
        v.public_custom_data.clear();
    });
    l.a.s.lock(l.a.v).unwrap();
    std::fs::write(l.path(), &alone).unwrap();
    assert!(l.a.unlocks(PASSWORD), "it opens without the part");
    l.refuses_at_a_run();
    assert_eq!(l.stored(), before);

    // The merge branch: a server copy under the password alone.
    let a = Mac::new("no-part-merge", true);
    let copy = resaved(PASSWORD, |v| v.public_custom_data.clear());
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    assert!(matches!(a.s.merge_server(a.v, &copy, 1), Merge::Failed));
    assert_eq!(
        std::fs::read(a.dir.join("Personal.larsalvault")).unwrap(),
        file
    );
}

/// SYN-03.1 step 2: Save As while on the server: the new file has the vault's key,
/// so it opens with the same part from the device store. The old file keeps its
/// link.
#[test]
fn syn03_1_save_as_takes_the_part_along() {
    let mut l = Linked::new("part-save-as");
    let part = l.a.part();
    let to = l.a.dir.join("Moved.larsalvault");
    l.a.s.save_as(l.a.v, to.display().to_string()).unwrap();
    let to = std::fs::canonicalize(&to).unwrap();
    l.a.s.lock(l.a.v).unwrap();
    assert!(l.a.unlocks(PASSWORD));
    assert_eq!(l.a.part(), part);
    let path = l.path();
    l.a.open(&path);
    assert_eq!(l.a.part(), part);
    assert!(
        l.a.s
            .sync_with(|i| i.state.parts.iter().any(|p| Path::new(&p.file) == to))
    );
}

/// LD-264, LD-267 (2), MOD-11.31, SYN-03.8, SYN-03.9, SYN-03 T13, T27, the story's
/// key-change check. A changes the password while B uploads an edit under the old
/// one. A opens the server copy with the old password and says the copy uses a
/// replaced password. Merge anyway: both edits survive and the result has A's new
/// key. B then asks for the new password, never "the new one" in words, and uploads
/// nothing until it opens. A wrong password asks again.
#[test]
fn syn03_8_t13_ld264_a_key_change_and_an_upload_under_the_old_key_keep_both_edits() {
    let k = KeyChange::new("t13-ld264");
    k.changes();
    let (a, b) = (&k.a, &k.b);
    k.to_old_key();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    assert_eq!(
        a.s.sync_retired(root).len(),
        2,
        "the state keeps the records"
    );
    a.s.sync_old_key(a.v, true).unwrap();
    assert!(titled(a, "E1 by A") && titled(a, "E2 by B"), "both edits");
    assert_eq!(a.s.sync_state(a.v).unwrap().status, SyncStatus::Syncing);
    let puts = k.proxy.count("PUT");
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert_eq!(k.proxy.count("PUT"), puts + 1);
    assert_eq!(k.server_version(), 3);
    k.the_server_has_as_new_key();
    a.s.lock(a.v).unwrap();
    assert!(!a.unlocks(PASSWORD), "A's own file has the new key");
    assert!(a.unlocks(DEMO2));
    a.tick(0);

    k.b_asks();
    b.s.sync_open_copy(b.v, "a wrong guess".into()).unwrap();
    let states = b.tick(0);
    assert_eq!(states[0].status, SyncStatus::NeedsPassword);
    assert!(states[0].ask_key, "the wrong password asks again");
    let puts = k.proxy.count("PUT");
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert!(
        titled(b, "E1 by A") && titled(b, "E2 by B"),
        "both edits on B"
    );
    assert_eq!(k.proxy.count("PUT"), puts, "B had nothing new");
    b.s.lock(b.v).unwrap();
    assert!(
        !b.unlocks(PASSWORD),
        "B took the newer key and retired its own"
    );
    assert!(b.unlocks(DEMO2));
    assert_eq!(b.s.sync_retired(root).len(), 1);
}

/// SYN-03 T24 on T13's run (LD-426): the master passwords, the part and every
/// entry title and password of the run, raw and encoded (SYN-04 T13's forms: raw,
/// upper and lower hex, padded and URL base64), in no request and no reply. It
/// still does not search user names, URLs or notes, titles and passwords under 6
/// bytes, any other encoding, or what is inside the encrypted file; the outer header
/// goes in clear by format (SYN-03.14).
#[test]
fn syn03_14_t24_nothing_in_plain_on_the_key_change_run() {
    let k = KeyChange::new("t24");
    let (a, b) = (&k.a, &k.b);
    let part = a.part();
    let (mut titles, passwords): (Vec<String>, Vec<String>) =
        a.s.with_vault(a.v, |v| {
            Ok(v.root
                .all_entries()
                .flat_map(|e| std::iter::once(e).chain(&e.history))
                .map(|e| (e.value("Title").to_owned(), e.value("Password").to_owned()))
                .unzip())
        })
        .unwrap();
    k.changes();
    k.to_old_key();
    a.s.sync_old_key(a.v, true).unwrap();
    a.tick(0);
    k.b_asks();
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    b.rename("E2 by B", "E2 again by B");
    b.tick(2_000);
    assert_eq!(k.server_version(), 4);

    let seen = k.proxy.seen.lock().unwrap().clone();
    assert!(seen.iter().filter(|(r, _)| r.method == "PUT").count() >= 4);
    let mut needles = encoded(PASSWORD.as_bytes());
    needles.extend(encoded(DEMO2.as_bytes()));
    for password in [PASSWORD, DEMO2] {
        let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        needles.push(utf16);
    }
    needles.extend(encoded(&part));
    titles.extend(["E1 by A".to_owned(), "E2 by B".to_owned()]);
    titles.push("E2 again by B".to_owned());
    needles.extend(
        titles
            .iter()
            .chain(&passwords)
            .filter(|s| s.len() >= 6)
            .flat_map(|s| encoded(s.as_bytes())),
    );
    for (request, reply) in &seen {
        for n in &needles {
            assert!(
                !has(&request.raw, n),
                "{} {} holds {:?}",
                request.method,
                request.path,
                String::from_utf8_lossy(n)
            );
            assert!(
                !has(reply, n),
                "a reply holds {:?}",
                String::from_utf8_lossy(n)
            );
        }
    }
}

/// CRY-05.19, CRY-05 T29 (E25-S3, LD-340): E13-S8's stored-bytes search after
/// E25-S3, on T13's key-change run (SYN-03 T24's method and LD-426's needles: both
/// master passwords and their UTF-16, the key-file part, every entry title and
/// password of 6 bytes or more), with this story's needles added: an account's
/// `S_acct`, its composite identity private key and each half of it, its X-Wing
/// receiving seed and the blob's plaintext, the keys wrapped to it (the key-file
/// part, P7, and a group key, P8) and the KEM shared secret of each wrap; each raw,
/// in upper and lower hex, in padded and URL base64 (SYN-04 T13's forms) and, for
/// this story's needles, as its SHA-256. A searches every request and reply of the
/// run, every file the server stored, and the public bytes E17-S1's keys row and
/// E18's wrap routes will store (each wrap record's fields, the identity and
/// receiving keys, the binding, raw and in base64url). No route of this story sends
/// them, so their run through Larsal's server, and `S_acct`'s through a real
/// sign-up, is E17-S1's (T29's account needles run again there).
#[test]
fn cry05_19_t29_no_key_in_any_stored_byte_after_e25s3() {
    use larsal_crypto::account::{AccountKeys, check_kem_binding};
    use larsal_crypto::base64::{Form, encode};
    use larsal_crypto::{pq, wrap_record};
    let k = KeyChange::new("t29");
    let (a, b) = (&k.a, &k.b);
    let part = a.part();
    let (mut titles, passwords): (Vec<String>, Vec<String>) =
        a.s.with_vault(a.v, |v| {
            Ok(v.root
                .all_entries()
                .flat_map(|e| std::iter::once(e).chain(&e.history))
                .map(|e| (e.value("Title").to_owned(), e.value("Password").to_owned()))
                .unzip())
        })
        .unwrap();

    // This story's secrets, made as E17-S1 and E18-S2 will make them: A's account
    // keys, their binding and blob, and hybrid wraps of the part and of a group
    // key to the account's receiving key; B restores the keys from S_acct and the
    // blob's plaintext, checks the binding and opens both wraps.
    let account = AccountKeys::new().unwrap();
    let account_id = [0x29; 16];
    let binding = account.kem_signature(&account_id).unwrap();
    let blob = account.blob_plaintext();
    let group_key = larsal_crypto::random::bytes(32).unwrap();
    let infos: [&[u8]; 2] = [
        b"demo P7 info: the key-file part of vault 1",
        b"demo P8 info: vault 1, epoch 1, reader 2",
    ];
    let wrapped: [&[u8]; 2] = [&part, group_key.expose()];
    let wraps: Vec<wrap_record::WrapRecord> = infos
        .iter()
        .zip(wrapped)
        .map(|(info, key)| {
            let signer = account.identity_private_key();
            wrap_record::make(account.kem_public_key(), info, key, account_id, signer).unwrap()
        })
        .collect();
    let restored = AccountKeys::from_blob(
        SecretBytes::new(account.account_secret().expose().to_vec()),
        &blob,
    )
    .unwrap();
    let (identity_key, kem_key) = (account.identity_public_key(), account.kem_public_key());
    assert_eq!(
        check_kem_binding(identity_key, &account_id, kem_key, &binding),
        Ok(())
    );
    for ((w, info), key) in wraps.iter().zip(infos).zip(wrapped) {
        let opened = wrap_record::open(w, identity_key, info, restored.kem_seed()).unwrap();
        assert_eq!(opened.expose(), key);
    }
    let shared: Vec<SecretBytes> = wraps
        .iter()
        .map(|w| pq::kem_shared_secret(account.kem_seed(), &w.enc).unwrap())
        .collect();

    // T13's run, as SYN-03 T24 runs it.
    k.changes();
    k.to_old_key();
    a.s.sync_old_key(a.v, true).unwrap();
    a.tick(0);
    k.b_asks();
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    b.rename("E2 by B", "E2 again by B");
    b.tick(2_000);
    assert_eq!(k.server_version(), 4);

    // LD-426's needles.
    let mut needles: Vec<(&str, Vec<u8>)> = Vec::new();
    for password in [PASSWORD, DEMO2] {
        needles.extend(
            encoded(password.as_bytes())
                .into_iter()
                .map(|n| ("a password", n)),
        );
        let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        needles.push(("a password in UTF-16", utf16));
    }
    titles.extend(["E1 by A", "E2 by B", "E2 again by B"].map(str::to_owned));
    for s in titles.iter().chain(&passwords).filter(|s| s.len() >= 6) {
        needles.extend(
            encoded(s.as_bytes())
                .into_iter()
                .map(|n| ("a title or password", n)),
        );
    }
    let ld426 = needles.len();
    // This story's needles.
    let identity = account.identity_private_key().expose();
    let story: [(&str, &[u8]); 10] = [
        ("the key-file part", &part),
        ("S_acct", account.account_secret().expose()),
        ("the identity private key", identity),
        ("the ML-DSA-65 seed", &identity[..32]),
        ("the Ed25519 seed", &identity[32..]),
        ("the receiving seed", account.kem_seed().expose()),
        ("the blob's plaintext", blob.expose()),
        ("the group key", group_key.expose()),
        ("a KEM shared secret", shared[0].expose()),
        ("a KEM shared secret", shared[1].expose()),
    ];
    for (what, value) in story {
        needles.extend(encoded(value).into_iter().map(|n| (what, n)));
        needles.push((
            what,
            larsal_crypto::hash::sha256(&[value]).expose().to_vec(),
        ));
    }

    // The stored bytes: every request and reply, every file of the server's data
    // folder, and the public bytes the later routes will store.
    let seen = k.proxy.seen.lock().unwrap().clone();
    assert!(seen.iter().filter(|(r, _)| r.method == "PUT").count() >= 4);
    let mut hays: Vec<(String, Vec<u8>)> = Vec::new();
    for (request, reply) in &seen {
        hays.push((
            format!("{} {}", request.method, request.path),
            request.raw.clone(),
        ));
        hays.push((
            format!("the reply to {} {}", request.method, request.path),
            reply.clone(),
        ));
    }
    let mut files = Vec::new();
    let mut dirs = vec![k._app._data.0.clone()];
    while let Some(dir) = dirs.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else {
                files.push(p);
            }
        }
    }
    let mut stored = 0;
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        stored += bytes.len();
        hays.push((f.display().to_string(), bytes));
    }
    assert!(stored > 0, "the server stored nothing");
    let mut public: Vec<(&str, &[u8])> = vec![
        ("identity_public_key", identity_key),
        ("kem_public_key", kem_key),
        ("kem_signature", &binding[..]),
    ];
    for w in &wraps {
        public.extend([
            ("a wrap's enc", &w.enc[..]),
            ("a wrap's ct", &w.ct[..]),
            ("a wrap's info", &w.info[..]),
            ("a wrap's signature", &w.signature[..]),
        ]);
    }
    for (what, value) in &public {
        hays.push(((*what).to_owned(), value.to_vec()));
        hays.push((
            format!("{what} in base64url"),
            encode(Form::Url, value).into_bytes(),
        ));
    }
    for (place, hay) in &hays {
        for (what, n) in &needles {
            assert!(!has(hay, n), "{place} holds {what}");
        }
    }
    println!(
        "CRY-05 T29: {} needles ({ld426} of LD-426, {} of this story's 10 values), \
         {} requests and replies, {} stored files ({stored} bytes), {} public forms: none found",
        needles.len(),
        needles.len() - ld426,
        seen.len() * 2,
        files.len(),
        public.len() * 2,
    );
}

/// LD-267 (2), LD-269 (3), MOD-11.31, SYN-03 T14, the story's deletion check: B also
/// deleted E4 for good under the old key, as its last change. A's Merge anyway takes
/// no deletions, so E4 is in A's result. When B opens that result with `demo2` it
/// merges it, uploads and shows `MSG-SYNC-WENT-BACK` (10:00:05 is earlier than the
/// 10:00:10 B uploaded), and E4 is gone on the server and, after A's next run, on A.
#[test]
fn syn03_8_t14_bs_deletion_under_the_old_key_is_deleted_everywhere() {
    let k = KeyChange::new("t14");
    let (a, b) = (&k.a, &k.b);
    let ten = stamp_after_link(a);
    a.rename(&k.t[0], "E1 by A");
    a.change_password(DEMO2);
    a.s.with_edit(a.v, |v, _, _, _| {
        v.meta.master_key_changed = ten;
        Ok(())
    })
    .unwrap();
    a.save();
    let gone = b.id_of(&k.t[2]);
    edit_at(b, &k.t[1], "E2 by B", larsal_model::Time(ten.0 + 5));
    delete_at(b, &gone, larsal_model::Time(ten.0 + 10));
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert!(!b.ids().contains(&gone));
    k.to_old_key();
    a.s.sync_old_key(a.v, true).unwrap();
    assert!(
        a.ids().contains(&gone),
        "A's Merge anyway takes no deletions"
    );
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    k.b_asks();
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    let puts = k.proxy.count("PUT");
    let states = b.tick(0);
    assert_eq!(states[0].status, SyncStatus::Synced, "{states:?}");
    assert_eq!(ids(&states[0]), ["MSG-SYNC-WENT-BACK"]);
    assert_eq!(k.proxy.count("PUT"), puts + 1, "B's merge goes up");
    assert!(!b.ids().contains(&gone), "still gone on B");
    let (_, bytes) = stored(b);
    let server = open_copy(b, &bytes, DEMO2, Some(&b.part())).unwrap();
    let hex = |e: &larsal_model::Entry| -> String {
        e.uuid.0.iter().map(|x| format!("{x:02x}")).collect()
    };
    assert!(
        server.root.all_entries().all(|e| hex(e) != gone),
        "gone on the server"
    );
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert!(!a.ids().contains(&gone), "gone on A");
    assert!(titled(a, "E2 by B") && titled(a, "E1 by A"));
}

/// SYN-03.9, SYN-03 T15: Skip takes nothing of B's copy and A uploads its own vault;
/// the server copy opens with `demo2`. B then: `MSG-SYNC-OTHER-KEY`; given `demo2`
/// it merges, uploads and shows `MSG-SYNC-WENT-BACK`, and E2 comes back in its result.
#[test]
fn syn03_9_t15_skip_takes_nothing_and_bs_edit_comes_back_through_b() {
    let k = KeyChange::new("t15");
    let (a, b) = (&k.a, &k.b);
    let ten = stamp_after_link(a);
    a.rename(&k.t[0], "E1 by A");
    a.change_password(DEMO2);
    a.s.with_edit(a.v, |v, _, _, _| {
        v.meta.master_key_changed = ten;
        Ok(())
    })
    .unwrap();
    a.save();
    edit_at(b, &k.t[1], "E2 by B", larsal_model::Time(ten.0 + 5));
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    k.to_old_key();
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    a.s.sync_old_key(a.v, false).unwrap();
    assert!(!titled(a, "E2 by B"), "nothing of the copy");
    assert_eq!(
        std::fs::read(a.dir.join("Personal.larsalvault")).unwrap(),
        file
    );
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert_eq!(stored(a), (3, file));
    k.the_server_has_as_new_key();
    k.b_asks();
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    let states = b.tick(0);
    assert_eq!(states[0].status, SyncStatus::Synced, "{states:?}");
    assert_eq!(ids(&states[0]), ["MSG-SYNC-WENT-BACK"]);
    assert!(titled(b, "E2 by B"), "B's edit in B's result");
    let (version, bytes) = stored(b);
    assert_eq!(version, 4);
    assert!(open_copy(b, &bytes, DEMO2, Some(&b.part())).is_ok());
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    assert!(titled(a, "E2 by B"));
}

/// A scripted server for T16: the planted copy's GET as version 6 until the upload,
/// 304 once A has answered, and 200 to each PUT.
fn t16_server(planted: Vec<u8>) -> Scripted {
    use larsal_sync::test_server::Response;
    scripted_transfer(move |r| match r.method.as_str() {
        "GET" if r.header("if-none-match") == Some("\"6\"") => {
            Response::new(304, b"").with("ETag", "\"6\"")
        }
        "GET" => Response::new(200, &planted).with("ETag", "\"6\""),
        _ => Response::new(200, b"{}").with("ETag", "\"7\""),
    })
}

/// LD-264, LD-269 (3), MOD-11.31, AT-L04, SYN-03.9, SYN-03 T16, the story's planted
/// copy: under A's old password, with a key-change time in 2099, a deletion of E1
/// dated 2099 and the name `Evil`. It merges nothing on its own. With Merge anyway
/// and with Skip the key stays A's, nothing is deleted, the name stays, and the
/// time does not reach the rollback guard's record. A copy under the password alone,
/// with no part, stays `WrongKey`.
#[test]
fn syn03_9_t16_a_planted_copy_under_the_old_password_brings_nothing_back() {
    use larsal_model::{DeletedObject, Time};
    let year_2099 = Time::from_unix(4_070_908_800).unwrap();
    for merge_anyway in [true, false] {
        let a = Mac::new(&format!("t16-{merge_anyway}"), true);
        a.keyed();
        let e1 =
            a.s.with_vault(a.v, |v| Ok(v.root.all_entries().next().unwrap().uuid))
                .unwrap();
        let e1_title =
            a.s.with_vault(a.v, |v| {
                Ok(v.root
                    .all_entries()
                    .next()
                    .unwrap()
                    .value("Title")
                    .to_owned())
            })
            .unwrap();
        let planted = resaved_keyed(PASSWORD, |v| {
            v.meta.master_key_changed = year_2099;
            v.meta.name = "Evil".into();
            v.meta.name_changed = year_2099;
            v.deleted_objects.push(DeletedObject {
                uuid: e1,
                deleted_at: year_2099,
                unknown: Vec::new(),
            });
        });
        let server = t16_server(planted.clone());
        add_scripted(&a, &server);
        link_to(&a, &server.address(), [0; 32]);
        let name = a.s.with_vault(a.v, |v| Ok(v.meta.name.clone())).unwrap();
        a.change_password(DEMO2);
        // A's upload of its key change is done: this file is the last one it sent.
        let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
        a.s.sync_with(|i| i.state.links[0].local_sha = larsal_sync::sync::hash(&file));
        let changed =
            a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
                .unwrap();
        let ids_before = a.ids();

        // Under the password alone, and before the password is given: nothing.
        assert!(matches!(
            a.s.merge_server(a.v, &resaved(PASSWORD, |_| {}), 6),
            Merge::WrongKey
        ));
        let states = a.tick(0);
        assert_eq!(states[0].status, SyncStatus::NeedsPassword);
        a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
        let states = a.tick(0);
        assert_eq!(states[0].status, SyncStatus::ReplacedPassword, "{states:?}");
        assert_eq!(ids(&states[0]), ["MSG-SYNC-OLD-KEY"]);
        assert_eq!(server.count("PUT"), 0);
        assert_eq!(a.ids(), ids_before, "nothing yet");

        a.s.sync_old_key(a.v, merge_anyway).unwrap();
        a.tick(0);
        assert_eq!(a.status(), Some(SyncStatus::Synced));
        let sent: Vec<_> = server
            .requests()
            .into_iter()
            .filter(|r| r.method == "PUT")
            .collect();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].header("if-match"), Some("\"6\""));
        assert!(open_copy(&a, &sent[0].body, PASSWORD, Some(&TEST_PART)).is_err());
        let up = open_copy(&a, &sent[0].body, DEMO2, Some(&TEST_PART)).unwrap();
        for v in [&up, &a.s.with_vault(a.v, |v| Ok(v.duplicate())).unwrap()] {
            assert_eq!(
                v.meta.master_key_changed, changed,
                "the old key is not back"
            );
            assert_eq!(v.meta.name, name);
            assert!(
                v.root.all_entries().any(|e| e.uuid == e1),
                "nothing deleted"
            );
            assert!(v.deleted_objects.iter().all(|d| d.uuid != e1));
        }
        assert!(titled(&a, &e1_title));
        a.s.lock(a.v).unwrap();
        assert!(!a.unlocks(PASSWORD));
        assert!(a.unlocks(DEMO2));
        let seen = a.s.sync_with(|i| i.state.links[0].seen.newest);
        assert!(seen < year_2099, "the time reached no record");
    }
}

/// LD-264, the story's check: the copy B uploaded under the old password opens with
/// it until A's next upload, and after that upload it no longer does.
#[test]
fn syn03_9_after_as_next_upload_the_old_password_no_longer_opens_the_server_copy() {
    let k = KeyChange::new("old-gone");
    let a = &k.a;
    let part = a.part();
    k.changes();
    let (_, bytes) = stored(a);
    assert!(open_copy(a, &bytes, PASSWORD, Some(&part)).is_ok());
    k.to_old_key();
    a.s.sync_old_key(a.v, true).unwrap();
    assert!(
        open_copy(a, &stored(a).1, PASSWORD, Some(&part)).is_ok(),
        "no upload yet"
    );
    a.tick(0);
    assert_eq!(k.server_version(), 3);
    k.the_server_has_as_new_key();
}

/// SYN-03.8, SYN-03 T18: Cancel calls nothing. B asks once; two 60-second ticks ask
/// no more and send nothing, and the status stays. Sync now asks again.
#[test]
fn syn03_8_t18_cancel_uploads_nothing_and_the_ticks_ask_no_more() {
    let k = KeyChange::new("t18");
    let (a, b) = (&k.a, &k.b);
    k.changes();
    k.to_old_key();
    a.s.sync_old_key(a.v, true).unwrap();
    a.tick(0);
    let puts = k.proxy.count("PUT");
    let states = b.tick(60_000);
    assert_eq!(states[0].status, SyncStatus::NeedsPassword);
    assert!(states[0].ask_key, "the first run asks");
    assert!(!b.s.sync_tick()[0].ask_key, "once");
    for _ in 0..2 {
        let states = b.tick(60_000);
        assert_eq!(states[0].status, SyncStatus::NeedsPassword);
        assert!(!states[0].ask_key, "no sheet on a tick");
    }
    assert_eq!(k.proxy.count("PUT"), puts);
    b.s.sync_now(b.v).unwrap();
    assert!(b.tick(0)[0].ask_key, "Sync now shows it");
    b.s.lock(b.v).unwrap();
    assert!(b.unlocks(PASSWORD));
    assert!(b.tick(0)[0].ask_key, "the unlock's run shows it");
}

/// LD-264, MOD-11.19 limit 2, SYN-03's edge line: a copy under another password,
/// given by the user, with an older `MasterKeyChanged`: not a retired key, so it
/// merges, the result keeps this Mac's key, nothing of this Mac's is retired, and
/// the result goes up.
#[test]
fn syn03_8_an_older_key_given_by_the_user_keeps_this_macs_key() {
    use larsal_sync::test_server::Response;
    let a = Mac::new("older-key", true);
    a.keyed();
    let copy = resaved_keyed("the password of an older copy", |v| {
        v.meta.master_key_changed = larsal_model::Time(1);
        v.meta.name = "Demo older".into();
    });
    let server = scripted_transfer(move |r| match r.method.as_str() {
        "GET" => Response::new(200, &copy).with("ETag", "\"6\""),
        _ => Response::new(200, b"{}").with("ETag", "\"7\""),
    });
    add_scripted(&a, &server);
    link_to(&a, &server.address(), [0; 32]);
    assert_eq!(a.tick(0)[0].status, SyncStatus::NeedsPassword);
    a.s.sync_open_copy(a.v, "the password of an older copy".into())
        .unwrap();
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert_eq!(
        server.count("PUT"),
        1,
        "the result goes up: the key changed"
    );
    let sent = server
        .requests()
        .into_iter()
        .find(|r| r.method == "PUT")
        .unwrap();
    assert!(open_copy(&a, &sent.body, PASSWORD, Some(&TEST_PART)).is_ok());
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    assert!(a.s.sync_retired(root).is_empty());
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(PASSWORD));
}

/// LD-267 (2): a key retired before the vault went up is in the state from the
/// link, so the copy under it waits for the answer as any other. A vault with a key
/// file, whose old key and part make that copy possible.
#[test]
fn syn03_3_ld267_2_a_key_retired_before_the_put_comes_to_the_state() {
    let (_app, _proxy, address, mut a) = unlinked("retired-first");
    let f = [0x22u8; 32];
    let key = a.dir.join("own.larsalkey");
    std::fs::write(&key, f).unwrap();
    let path = a.dir.join("Keyed.larsalvault");
    std::fs::write(&path, resaved_with(PASSWORD, Some(&f), |_| {})).unwrap();
    a.v = a.s.open(path.display().to_string()).unwrap();
    assert_eq!(
        a.s.unlock(a.v, Some(PASSWORD.into()), Some(key.display().to_string()))
            .unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    a.change_password(DEMO2);
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    assert!(a.s.sync_retired(root).is_empty(), "no link, no part yet");
    put(&a, &address);
    assert_eq!(a.s.sync_retired(root).len(), 1);
    let old = resaved_with(PASSWORD, Some(&f), |v| v.root.uuid = root);
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    assert!(matches!(a.s.merge_server(a.v, &old, 2), Merge::OldKey));
}

/// SYN-03.12, SYN-03 T23: a linked vault's password changes and the part stays;
/// Vault Settings shows "Kept for sync" and offers no way to drop the part or change
/// it. Save as key file writes the part in FMT-18.20's layout, mode 0400, never over
/// a file, and it opens the vault with the new password (the reference tool's half
/// is Verify's, rule 2).
#[test]
fn syn03_12_t23_the_part_stays_and_saves_as_a_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let l = Linked::new("t23");
    let a = &l.a;
    let part = a.part();
    a.change_password(DEMO2);
    assert_eq!(a.part(), part);
    let vs = crate::vault_settings::VaultSettings::new(a.s.clone(), a.v);
    assert_eq!(
        vs.view().unwrap().key_file.as_deref(),
        Some("Kept for sync")
    );
    let kept = |o: &Outcome| matches!(o, Outcome::Refused { id, .. } if id == "MSG-SYNC-PART-KEPT");
    assert!(kept(&vs.remove_key_file(vec![]).unwrap()));
    let other = a.dir.join("other.larsalkey");
    std::fs::write(&other, [0x33u8; 32]).unwrap();
    let chosen = vs
        .choose_key_file(other.display().to_string(), vec![])
        .unwrap();
    assert!(matches!(&chosen, crate::wizard::KeyFileOutcome::Then { outcome } if kept(outcome)));
    let new = a.dir.join("new.larsalkey");
    let made = vs.new_key_file(new.display().to_string(), vec![]).unwrap();
    assert!(matches!(&made, crate::wizard::KeyFileOutcome::Then { outcome } if kept(outcome)));
    assert!(!new.exists(), "no file left behind");
    assert_eq!(a.part(), part);
    l.uploads_at_a_run(2);

    let saved = a.dir.join("part.larsalkey");
    let to = saved.display().to_string();
    assert_eq!(a.s.sync_save_part(a.v, to.clone()).unwrap(), Outcome::Done);
    let mode = std::fs::metadata(&saved).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o400);
    let read = larsal_format::keyfile::read_key_file(
        std::fs::File::open(&saved).unwrap(),
        &Limits::DEFAULT,
    )
    .unwrap();
    assert_eq!(read.kind(), larsal_format::keyfile::KeyFileKind::Xml2);
    assert_eq!(read.key().expose(), &part[..]);
    let before = std::fs::read(&saved).unwrap();
    assert!(matches!(
        a.s.sync_save_part(a.v, to.clone()).unwrap(),
        Outcome::Refused { id, .. } if id == "M07-26"
    ));
    assert_eq!(std::fs::read(&saved).unwrap(), before);

    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    assert!(!a.unlocks(DEMO2));
    // C1R3B-02: with no part from the device store, the saved file with the new
    // password unlocks the linked vault, and the device store keeps the part again.
    assert!(unlocked_ok(
        a.s.unlock(a.v, Some(DEMO2.into()), Some(to)).unwrap()
    ));
    assert_eq!(a.part(), part);
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(DEMO2), "the device store gives the part again");
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    assert!(open_copy(a, &file, DEMO2, Some(&part)).is_ok());

    let plain = Mac::new("t23-plain", true);
    assert!(plain.s.sync_save_part(plain.v, "/nowhere".into()).is_err());
}

/// The newest change time of A's link, plus a minute: T14's and T15's 10:00:00.
fn stamp_after_link(a: &Mac) -> larsal_model::Time {
    let newest = a.s.sync_with(|i| i.state.links[0].seen.newest);
    larsal_model::Time(newest.0 + 60)
}

/// Sets every id-matching entry's change time.
fn stamp_entry(g: &mut larsal_model::Group, id: &str, at: larsal_model::Time) {
    for e in &mut g.entries {
        let hex: String = e.uuid.0.iter().map(|b| format!("{b:02x}")).collect();
        if hex == id {
            e.times.last_modification = at;
        }
    }
    for c in &mut g.groups {
        stamp_entry(c, id, at);
    }
}

/// Renames entry `from` to `to` at the time `at` and saves.
fn edit_at(m: &Mac, from: &str, to: &str, at: larsal_model::Time) {
    let id = m.id_of(from);
    m.s.begin_edit(m.v, id.clone()).unwrap();
    m.s.set_text(m.v, EditText::Title, to.into()).unwrap();
    m.s.commit_edit(m.v).unwrap();
    m.s.with_edit(m.v, |v, _, _, _| {
        stamp_entry(&mut v.root, &id, at);
        Ok(())
    })
    .unwrap();
    m.save();
}

/// Deletes entry `id` for good at the time `at` and saves.
fn delete_at(m: &Mac, id: &str, at: larsal_model::Time) {
    let mut for_good = 0;
    for _ in 0..2 {
        for_good += m.s.delete_entry(m.v, id.to_owned()).unwrap().for_good;
    }
    assert_eq!(for_good, 1);
    m.s.with_edit(m.v, |v, _, _, _| {
        for d in &mut v.deleted_objects {
            let hex: String = d.uuid.0.iter().map(|b| format!("{b:02x}")).collect();
            if hex == id {
                d.deleted_at = at;
            }
        }
        Ok(())
    })
    .unwrap();
    m.save();
}

/// A demo public name, in clear in the outer header (FMT-03.22).
const PUBLIC: &str = "Demo public name of a bank";

/// Sets the vault's public name as the settings page does.
fn set_public_name(m: &Mac) {
    m.s.with_edit(m.v, |v, _, _, s| {
        let changes = Changes {
            public_name: Some(Some(PUBLIC.to_owned())),
            ..Changes::default()
        };
        let mut host = m.s.host.lock().unwrap();
        settings::apply(
            v,
            &changes,
            &mut host,
            &Limits::DEFAULT.kdf,
            crate::views::now(),
        )
        .map_err(|_| refused("public name"))?;
        s.changes = s.changes.max(1);
        Ok(())
    })
    .unwrap();
    m.save();
}

fn has_public(file: &[u8]) -> bool {
    larsal_format::integrity::has_public_data(file, &Limits::DEFAULT)
}

/// LD-427, F-322, FMT-03.22 as amended: linking a vault with a public name takes
/// it away with the first save: it is on no request and in none of the server's
/// bytes. Every later save of the linked vault writes none, even when the page sets
/// it again.
#[test]
fn ld427_f322_a_public_name_is_on_no_request_and_in_no_server_bytes() {
    let (_app, proxy, address, a) = unlinked("ld427-link");
    let path = a.dir.join("Personal.larsalvault");
    set_public_name(&a);
    let file = std::fs::read(&path).unwrap();
    assert!(has_public(&file) && has(&file, PUBLIC.as_bytes()));
    put(&a, &address);
    let (version, bytes) = stored(&a);
    assert_eq!(version, 1);
    assert_eq!(bytes, std::fs::read(&path).unwrap());
    assert!(!has_public(&bytes));
    let empty =
        a.s.with_vault(a.v, |v| Ok(v.public_custom_data.is_empty()))
            .unwrap();
    assert!(empty, "linking took it from the open vault");
    let needles = encoded(PUBLIC.as_bytes());
    for r in proxy.requests() {
        for n in &needles {
            assert!(!has(&r.raw, n), "{} {}", r.method, r.path);
        }
    }
    set_public_name(&a);
    assert!(!has_public(&std::fs::read(&path).unwrap()), "a later save");
    a.tick(2_000);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    let (version, bytes) = stored(&a);
    assert_eq!(version, 2);
    assert!(!has_public(&bytes));
    for r in proxy.requests() {
        for n in &needles {
            assert!(!has(&r.raw, n), "{} {}", r.method, r.path);
        }
    }
    // A vault with a key file and a public name saves too, or its name would go up.
    let (_app, proxy, address, mut a) = unlinked("ld427-key-file");
    let f = [0x44u8; 32];
    let key = a.dir.join("own.larsalkey");
    std::fs::write(&key, f).unwrap();
    let path = a.dir.join("Keyed.larsalvault");
    let keyed = resaved_with(PASSWORD, Some(&f), |v| {
        v.public_custom_data.push(larsal_model::PublicItem {
            kind: 0x18,
            name: b"NAME".to_vec(),
            value: PUBLIC.as_bytes().to_vec(),
        });
    });
    assert!(has_public(&keyed));
    std::fs::write(&path, keyed).unwrap();
    a.v = a.s.open(path.display().to_string()).unwrap();
    a.s.unlock(a.v, Some(PASSWORD.into()), Some(key.display().to_string()))
        .unwrap();
    put(&a, &address);
    assert!(!has_public(&stored(&a).1));
    assert!(
        proxy
            .requests()
            .iter()
            .all(|r| !has(&r.raw, PUBLIC.as_bytes()))
    );
}

/// LD-427, `Session::sync_read`: a file with any field 12 entry, however it came, does
/// not go up and gives `MSG-SYNC-SAVE-FIRST`: present at an unlock, or loaded by the
/// disk check. A Larsal save writes it without and that goes up.
#[test]
fn ld427_a_file_with_field_12_gives_save_first_and_a_save_heals_it() {
    let with_public = |l: &Linked| {
        let changed =
            l.a.s
                .with_vault(l.a.v, |v| Ok(v.meta.master_key_changed))
                .unwrap();
        l.a.resaved(PASSWORD, |v| {
            v.meta.master_key_changed = changed;
            v.public_custom_data.push(larsal_model::PublicItem {
                kind: 0x18,
                name: b"NAME".to_vec(),
                value: PUBLIC.as_bytes().to_vec(),
            });
        })
    };
    let l = Linked::new("ld427-unlock");
    let planted = with_public(&l);
    assert!(larsal_format::integrity::exact_frame(
        &planted,
        &Limits::DEFAULT
    ));
    assert!(has_public(&planted));
    l.a.s.lock(l.a.v).unwrap();
    std::fs::write(l.path(), &planted).unwrap();
    l.a.unlock();
    l.needs_a_save_at_a_run();
    l.never_sent(PUBLIC.as_bytes());
    l.a_save_heals_it(2, PUBLIC.as_bytes());

    let l = Linked::new("ld427-disk");
    let planted = with_public(&l);
    std::fs::write(l.path(), &planted).unwrap();
    assert_eq!(l.a.s.check_disk(l.a.v).unwrap(), DiskEvent::Reloaded);
    l.needs_a_save_at_a_run();
    l.never_sent(PUBLIC.as_bytes());
    l.a_save_heals_it(2, PUBLIC.as_bytes());
}

/// LD-427: a server copy that holds field 12 (another writer's) is saved here
/// without it, and the upload of a merge holds none.
#[test]
fn ld427_a_merge_of_a_server_copy_with_field_12_writes_none() {
    let a = Mac::new("ld427-merge", true);
    a.keyed();
    let copy = resaved_keyed(PASSWORD, |v| {
        v.public_custom_data.push(larsal_model::PublicItem {
            kind: 0x18,
            name: b"NAME".to_vec(),
            value: PUBLIC.as_bytes().to_vec(),
        });
    });
    let (root, seen) =
        a.s.with_vault(a.v, |v| Ok((v.root.uuid, measures(v))))
            .unwrap();
    a.s.sync_with(|i| {
        i.state.links.push(Link {
            server: "https://127.0.0.1:1".to_owned(),
            vault_id: VaultId::from_bytes([3; 16]),
            file: a.dir.join("Personal.larsalvault").display().to_string(),
            root,
            highest: 1,
            server_sha: [0; 32],
            local_sha: [0; 32],
            seen,
        });
    });
    let Merge::Done { saved, .. } = a.s.merge_server(a.v, &copy, 2) else {
        panic!("merged");
    };
    assert!(!has_public(&saved));
    assert!(!has(&saved, PUBLIC.as_bytes()));
    assert_eq!(
        saved,
        std::fs::read(a.dir.join("Personal.larsalvault")).unwrap()
    );
}

/// LD-427: a vault not linked keeps FMT-03.22 as written: its saves keep field 12,
/// the same as with `sync` off.
#[test]
fn ld427_a_vault_not_linked_keeps_field_12() {
    let a = Mac::new("ld427-plain", true);
    set_public_name(&a);
    a.save();
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    assert!(has_public(&file) && has(&file, PUBLIC.as_bytes()));
    let to = a.dir.join("Moved.larsalvault");
    a.s.save_as(a.v, to.display().to_string()).unwrap();
    assert!(has_public(&std::fs::read(&to).unwrap()));
}

// E16-S7b round 2: the Checkers' findings, as tests.

const DEMO3: &str = "demo3-third-pass-1";

fn year_2099() -> larsal_model::Time {
    larsal_model::Time::from_unix(4_070_908_800).unwrap()
}

fn unlocked_ok(r: crate::session::UnlockResult) -> bool {
    r == crate::session::UnlockResult::Unlocked
}

/// A restart of `old`'s app: a new session on the same settings folder and
/// device store, with the server's client, and the vault file opened (locked).
fn restart(old: &Mac, address: Option<&str>) -> Mac {
    let store: Vec<(String, Vec<u8>)> = old.s.sync_with(|i| {
        i.device_store
            .iter()
            .map(|(l, p)| (l.clone(), p.expose().to_vec()))
            .collect()
    });
    let client = address.map(|x| old.s.sync_with(|i| (x.to_owned(), i.servers[x].clone())));
    if old.s.with_vault(old.v, |_| Ok(())).is_ok() {
        old.s.lock(old.v).unwrap();
    }
    let s = Session::new();
    s.settings()
        .use_folder(old.dir.join("settings").display().to_string());
    s.sync.set_clock(old.clock.clone());
    s.sync_with(|i| {
        for (l, p) in store {
            i.device_store.insert(l, SecretBytes::new(p));
        }
        if let Some((x, c)) = client {
            i.servers.insert(x, c);
        }
    });
    let v = s
        .open(old.dir.join("Personal.larsalvault").display().to_string())
        .unwrap();
    Mac {
        dir: TempDir::new(&format!(
            "restart-spare-{}",
            old.dir.file_name().unwrap().to_string_lossy()
        )),
        s,
        v,
        clock: old.clock.clone(),
    }
}

/// The password removed on the settings page, as a screen does.
fn remove_password(m: &Mac) -> Outcome {
    let vs = crate::vault_settings::VaultSettings::new(m.s.clone(), m.v);
    vs.set_password(String::new()).unwrap();
    vs.set_repeat(String::new()).unwrap();
    vs.change_password(vec![crate::wizard::Answer::NoPassword])
        .unwrap()
}

fn refused_id(outcome: &Outcome) -> &str {
    match outcome {
        Outcome::Refused { id, .. } => id,
        _ => "",
    }
}

/// SYN-03.12, C1-A1: a linked vault keeps a typed factor: removing its password is
/// refused with words, nothing changes, and it opens with the password as before.
#[test]
fn syn03_12_c1_a1_a_linked_vault_keeps_its_password() {
    let k = KeyChange::new("c1-a1");
    let a = &k.a;
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    let outcome = remove_password(a);
    assert_eq!(refused_id(&outcome), "MSG-SYNC-TYPED-KEPT");
    assert_eq!(
        a.s.with_edit_state(a.v, |s| s.changes),
        0,
        "nothing changed"
    );
    a.tick(2_000);
    assert_eq!(
        std::fs::read(a.dir.join("Personal.larsalvault")).unwrap(),
        file
    );
    a.s.lock(a.v).unwrap();
    assert!(!unlocked_ok(a.s.unlock(a.v, None, None).unwrap()));
    assert!(a.unlocks(PASSWORD));
    // A new password is a typed factor: allowed.
    a.change_password(DEMO2);
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(DEMO2));
}

/// SYN-03.12, C1-A1's evidence: Save as key file before a lock gives a file that,
/// with the password, opens the vault after the lock; after the lock it is refused.
/// With the device store emptied the saved file alone takes nothing (C1R2-02), and
/// the saved file with the password unlocks the linked vault and puts the part back
/// in the device store (C1R3B-02).
#[test]
fn syn03_12_c1_a1b_the_saved_part_and_the_password_open_the_vault() {
    let k = KeyChange::new("c1-a1b");
    let a = &k.a;
    assert_eq!(refused_id(&remove_password(a)), "MSG-SYNC-TYPED-KEPT");
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let part = a.part();
    a.s.lock(a.v).unwrap();
    let later = a.dir.join("later.larsalkey");
    assert!(
        a.s.sync_save_part(a.v, later.display().to_string())
            .is_err()
    );
    let with_saved = || {
        a.s.unlock(
            a.v,
            Some(PASSWORD.into()),
            Some(saved.display().to_string()),
        )
        .unwrap()
    };
    assert!(unlocked_ok(with_saved()));
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    let alone =
        a.s.unlock(a.v, None, Some(saved.display().to_string()))
            .unwrap();
    assert_eq!(unlock_id(alone), "MSG-SYNC-PART-UNREAD");
    assert!(unlocked_ok(with_saved()));
    assert_eq!(a.part(), part);
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(PASSWORD), "the device store gives the part again");
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    let read = larsal_format::keyfile::read_key_file(
        std::fs::File::open(&saved).unwrap(),
        &Limits::DEFAULT,
    )
    .unwrap();
    assert_eq!(read.key().expose(), part.as_slice());
    assert!(open_copy(a, &file, PASSWORD, Some(&part)).is_ok());
}

/// The message id of a failed unlock, which is about the key file.
fn unlock_id(r: crate::session::UnlockResult) -> String {
    match r {
        crate::session::UnlockResult::Failed { message } => {
            assert!(message.about_key_file, "{message:?}");
            message.id
        }
        other => panic!("{other:?}"),
    }
}

/// SYN-03.12, C1-A1, the same after a failed first upload: the vault has a pointer
/// and no link; removing the password is refused, it opens with the password and the
/// part, and Save as key file works.
#[test]
fn syn03_12_c1_a1c_after_a_failed_first_upload() {
    use larsal_sync::test_server::Response;
    let a = Mac::new("c1-a1c", true);
    let server = scripted_transfer(|_| Response::new(500, b"{}"));
    add_scripted(&a, &server);
    assert!(a.s.sync_put_vault(a.v, server.address()).is_err());
    assert!(!a.s.sync_linked(a.v));
    assert_eq!(refused_id(&remove_password(&a)), "MSG-SYNC-TYPED-KEPT");
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    a.s.lock(a.v).unwrap();
    assert!(!unlocked_ok(a.s.unlock(a.v, None, None).unwrap()));
    assert!(a.unlocks(PASSWORD));
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    assert!(!a.unlocks(PASSWORD));
    assert!(unlocked_ok(
        a.s.unlock(
            a.v,
            Some(PASSWORD.into()),
            Some(saved.display().to_string())
        )
        .unwrap()
    ));
}

/// SYN-03.12 (C1-T1, M4): Save as key file needs a part kept for sync: a vault with
/// its own key file and no pointer is refused.
#[test]
fn syn03_12_save_as_key_file_needs_a_part_kept_for_sync() {
    let mut a = Mac::new("save-part-own", true);
    let f = [0x44u8; 32];
    let key = a.dir.join("own.larsalkey");
    std::fs::write(&key, f).unwrap();
    let path = a.dir.join("Keyed.larsalvault");
    std::fs::write(&path, resaved_with(PASSWORD, Some(&f), |_| {})).unwrap();
    a.v = a.s.open(path.display().to_string()).unwrap();
    assert!(unlocked_ok(
        a.s.unlock(a.v, Some(PASSWORD.into()), Some(key.display().to_string()))
            .unwrap()
    ));
    let to = a.dir.join("out.larsalkey");
    assert!(a.s.sync_save_part(a.v, to.display().to_string()).is_err());
    assert!(!to.exists());
}

/// LD-264 (C1-A26): B's clock runs a month ahead at its key change, and A takes that
/// key and time. A's later real change goes one second past it, so it reaches B.
#[test]
fn ld264_c1_a26_a_key_change_after_a_future_key_time_still_reaches_both_macs() {
    let k = KeyChange::new("c1-a26");
    let (a, b) = (&k.a, &k.b);
    b.change_password(DEMO2);
    let future =
        b.s.with_vault(b.v, |v| {
            Ok(larsal_model::Time(
                v.meta.master_key_changed.0 + 86_400 * 30,
            ))
        })
        .unwrap();
    b.s.with_edit(b.v, |v, _, _, s| {
        v.meta.master_key_changed = future;
        s.count_change();
        Ok(())
    })
    .unwrap();
    b.save();
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert_eq!(a.tick(2_000)[0].status, SyncStatus::NeedsPassword);
    a.s.sync_open_copy(a.v, DEMO2.into()).unwrap();
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    let adopted =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert_eq!(adopted, future, "A took the key and its time");
    a.rename(&k.t[0], "E1 by A");
    a.change_password(DEMO3);
    let after =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert_eq!(after, larsal_model::Time(future.0 + 1));
    a.tick(2_000);
    b.rename(&k.t[1], "E2 by B");
    b.tick(2_000);
    b.s.sync_open_copy(b.v, DEMO3.into()).unwrap();
    b.tick(0);
    b.tick(2_000);
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    let (_, bytes) = stored(a);
    let part = a.part();
    assert!(open_copy(a, &bytes, DEMO3, Some(&part)).is_ok());
    assert!(open_copy(a, &bytes, DEMO2, Some(&part)).is_err());
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert!(titled(a, "E2 by B") && titled(b, "E1 by A"));
}

/// LD-264 (C1-A26b): a copy under the password both Macs hold, with a key time in
/// 2099, merged on both. The user then changes the password: the change lands, the
/// old password opens neither the server copy nor B, and the ping-pong ends.
#[test]
fn ld264_c1_a26b_a_planted_future_key_time_before_the_change_does_not_undo_it() {
    let k = KeyChange::new("c1-a26b");
    let (a, b) = (&k.a, &k.b);
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let planted = resaved_with(PASSWORD, Some(&part), |v| {
        v.root.uuid = root;
        v.meta.master_key_changed = year_2099();
    });
    assert!(matches!(
        a.s.merge_server(a.v, &planted, 2),
        Merge::Done { .. }
    ));
    assert!(matches!(
        b.s.merge_server(b.v, &planted, 2),
        Merge::Done { .. }
    ));
    for m in [a, b] {
        let t =
            m.s.with_vault(m.v, |v| Ok(v.meta.master_key_changed))
                .unwrap();
        assert_eq!(t, year_2099());
    }
    a.s.sync_now(a.v).unwrap();
    a.tick(2_000);
    b.s.sync_now(b.v).unwrap();
    b.tick(2_000);
    a.rename(&k.t[0], "E1 by A");
    a.change_password(DEMO2);
    let t =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert!(
        t > year_2099(),
        "the real change goes past the planted time"
    );
    a.tick(2_000);
    let (_, bytes) = stored(a);
    assert!(open_copy(a, &bytes, PASSWORD, Some(&part)).is_err());
    b.rename(&k.t[1], "E2 by B");
    b.tick(2_000);
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    b.tick(0);
    b.tick(2_000);
    for _ in 0..3 {
        a.s.sync_now(a.v).unwrap();
        assert_ne!(a.tick(2_000)[0].status, SyncStatus::NeedsPassword);
        b.s.sync_now(b.v).unwrap();
        assert_ne!(b.tick(2_000)[0].status, SyncStatus::NeedsPassword);
    }
    let (_, bytes) = stored(a);
    assert!(open_copy(a, &bytes, PASSWORD, Some(&part)).is_err());
    assert!(open_copy(a, &bytes, DEMO2, Some(&part)).is_ok());
    b.s.lock(b.v).unwrap();
    assert!(!b.unlocks(PASSWORD), "B stays on the old password");
    assert!(b.unlocks(DEMO2));
    assert!(titled(b, "E1 by A") && titled(a, "E2 by B"));
}

/// LD-264 (ruling 2): a copy with a key time in 2099 that this Mac only held (Skip),
/// never merged, still counts as seen: A's next real change goes past it.
#[test]
fn ld264_a_key_time_seen_on_a_skipped_copy_counts() {
    let a = Mac::new("seen-skip", true);
    a.keyed();
    let planted = resaved_keyed(PASSWORD, |v| v.meta.master_key_changed = year_2099());
    let server = t16_server(planted);
    add_scripted(&a, &server);
    link_to(&a, &server.address(), [0; 32]);
    a.change_password(DEMO2);
    a.tick(0);
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    assert_eq!(a.tick(0)[0].status, SyncStatus::ReplacedPassword);
    a.s.sync_old_key(a.v, false).unwrap();
    a.tick(0);
    let kept =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert!(kept < year_2099(), "Skip takes nothing of the copy");
    a.change_password(DEMO3);
    let t =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert_eq!(t, larsal_model::Time(year_2099().0 + 1));
}

/// SYN-03.2 (C1-A18): B edits and saves its download, a run links it, and after a
/// restart the file opens and its link holds.
#[test]
fn syn03_2_c1_a18_a_download_edited_before_a_restart_still_opens() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1-a18-a");
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, "c1-a18-b");
    let t = b.titles();
    b.rename(&t[0], "B before the first run");
    b.tick(2_000);
    let b2 = restart(&b, Some(&address));
    assert!(
        b2.unlocks(PASSWORD),
        "the file B edited opens after a restart"
    );
    assert!(titled(&b2, "B before the first run"));
    b2.tick(0);
    assert_eq!(b2.status(), Some(SyncStatus::Synced));
    a.s.sync_now(a.v).unwrap();
    a.tick(0);
    assert!(titled(&a, "B before the first run"));
}

/// SYN-03.2 (C1-A18): the link and the pointer reach the state file when the
/// download commits. A download closed before any run opens after a restart, and
/// its first run links it.
#[test]
fn syn03_2_c1_a18b_a_download_closed_before_any_run_still_opens_and_links() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1-a18b-a");
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, "c1-a18b-b");
    let saved = State::load(&b.dir.join("settings/sync-state_debug.json")).unwrap();
    assert_eq!((saved.links.len(), saved.parts.len()), (1, 1));
    assert_eq!(saved.links[0].root, UNKNOWN_ROOT);
    let b2 = restart(&b, Some(&address));
    assert!(b2.unlocks(PASSWORD), "the download opens after a restart");
    b2.tick(0);
    assert_eq!(b2.status(), Some(SyncStatus::Synced));
    let root = b2.s.with_vault(b2.v, |v| Ok(v.root.uuid)).unwrap();
    let roots =
        b2.s.sync_with(|i| (i.state.links[0].root, i.state.parts[0].root));
    assert_eq!(roots, (root, root));
}

/// SYN-03.2 (C1-T1, M19): a download replaces an older pointer for its file, so the
/// file opens with the part it came with.
#[test]
fn syn03_2_a_download_replaces_an_older_pointer_for_its_file() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "stale-ptr-a");
    put(&a, &address);
    a.tick(0);
    let mut b = Mac::new("stale-ptr-b", false);
    let path = b.dir.join("Personal.larsalvault");
    b.s.sync_with(|i| {
        i.state.parts.push(Part {
            file: path.display().to_string(),
            root: Uuid([9; 16]),
            label: "stale".to_owned(),
        });
        i.device_store
            .insert("stale".to_owned(), SecretBytes::new(vec![0x66; 32]));
    });
    b.s.sync_add_server(address.clone(), client::printed(&app.pin))
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
    let mut c = Client::new(&address, app.pin).unwrap();
    c.sign_for_port(app.port);
    c.set_device(device, key);
    b.s.sync_with(|i| {
        i.state.servers[0].account = Some(Account {
            account,
            device,
            label: random_hex().unwrap(),
            public_key,
        });
        i.servers.insert(address.clone(), Arc::new(Mutex::new(c)));
    });
    copy_parts(&a, &b);
    let listed = b.s.sync_server_vaults(address.clone()).unwrap();
    b.s.sync_download(address, listed[0].id.clone(), path.display().to_string())
        .unwrap();
    let file = path.display().to_string();
    assert_eq!(
        b.s.sync_with(|i| i.state.parts.iter().filter(|p| p.file == file).count()),
        1
    );
    b.open(&path);
    assert_eq!(b.part(), a.part());
}

/// SYN-03.3, LD-267 (2) (C2-2, C1-T1 M3): B changes the password of its download
/// before the first run, so the record of the key it left is this Mac's only; the
/// run that links the download takes it into the sync state.
#[test]
fn syn03_3_c2_2_a_download_link_takes_the_keys_retired_before_it() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c2-2-a");
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, "c2-2-b");
    let root = b.s.with_vault(b.v, |v| Ok(v.root.uuid)).unwrap();
    b.change_password(DEMO2);
    assert_eq!(b.s.retired_records(root).len(), 1);
    assert!(b.s.sync_retired(root).is_empty(), "not linked yet");
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert!(b.s.sync_retired(root) == b.s.retired_records(root));
    let saved = State::load(&b.dir.join("settings/sync-state_debug.json")).unwrap();
    assert_eq!(saved.retired.get(&root).map(Vec::len), Some(1));
}

/// SYN-03.3, LD-267 (2) (C1-T1, M1): a key retired while linked reaches the state
/// file; after a restart the pointer, the records and the link come back, and the
/// old key's copy is still asked about.
#[test]
fn syn03_3_c1_a5_after_a_restart_the_parts_and_the_retired_keys_still_hold() {
    let k = KeyChange::new("c1-a5");
    k.changes();
    let a = &k.a;
    let address = k.proxy.address();
    let part = a.part();
    let a2 = restart(a, Some(&address));
    a2.s.sync_with(|i| {
        assert_eq!(i.state.parts.len(), 1, "the pointer came back");
        assert_eq!(i.state.retired.len(), 1, "the records came back");
        assert!(
            i.state.retired.values().all(|r| r.len() == 2),
            "P7 and the change"
        );
        assert_eq!(i.state.links.len(), 1);
    });
    assert!(a2.unlocks(DEMO2));
    assert_eq!(a2.part(), part);
    assert_eq!(a2.tick(2_000)[0].status, SyncStatus::NeedsPassword);
    a2.s.sync_open_copy(a2.v, PASSWORD.into()).unwrap();
    assert_eq!(a2.tick(0)[0].status, SyncStatus::ReplacedPassword);
    a2.s.sync_old_key(a2.v, true).unwrap();
    a2.tick(0);
    assert_eq!(a2.status(), Some(SyncStatus::Synced));
    assert!(titled(&a2, "E1 by A") && titled(&a2, "E2 by B"));
}

/// SYN-03.3 (C1-T1, M2): Save As of a linked vault: after a restart both files open
/// with the password alone.
#[test]
fn syn03_3_c1_a13_save_as_of_a_linked_vault_after_a_restart() {
    let l = Linked::new("c1-a13");
    let moved = l.a.dir.join("Moved.larsalvault");
    l.a.s.save_as(l.a.v, moved.display().to_string()).unwrap();
    let a2 = restart(&l.a, Some(&l.address));
    assert!(a2.unlocks(PASSWORD), "the file with the link opens");
    a2.s.lock(a2.v).unwrap();
    let v = a2.s.open(moved.display().to_string()).unwrap();
    assert!(unlocked_ok(
        a2.s.unlock(v, Some(PASSWORD.into()), None).unwrap()
    ));
}

/// SYN-03.3, LD-267 (2) (C2-4): both Macs move to `demo2`; then the sync state
/// cannot be written when A retires `demo2`. After a restart, B's upload under
/// `demo2` is still caught, from this Mac's vault state.
#[test]
fn syn03_3_c2_4_a_state_that_was_not_written_still_catches_the_old_key() {
    let k = KeyChange::new("c2-4");
    let (a, b) = (&k.a, &k.b);
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    a.change_password(DEMO2);
    a.tick(2_000);
    k.b_asks();
    b.s.sync_open_copy(b.v, DEMO2.into()).unwrap();
    b.tick(0);
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    let before = a.s.sync_retired(root).len();
    a.s.sync_with(|i| i.unread = true);
    a.change_password(DEMO3);
    b.rename(&k.t[1], "E2 by B");
    b.tick(2_000);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    let a2 = restart(a, Some(&k.proxy.address()));
    assert_eq!(
        a2.s.sync_retired(root).len(),
        before,
        "the state file missed it"
    );
    assert!(a2.unlocks(DEMO3));
    assert_eq!(a2.tick(2_000)[0].status, SyncStatus::NeedsPassword);
    a2.s.sync_open_copy(a2.v, DEMO2.into()).unwrap();
    assert_eq!(a2.tick(0)[0].status, SyncStatus::ReplacedPassword);
    assert!(!titled(&a2, "E2 by B"), "nothing taken");
}

/// SYN-03.12 (C1-A11): a sheet's password goes with the part, then alone: a copy
/// from before the link, under another password and no part, gets the content merge,
/// so its newer key time and name are not taken and the vault keeps its key. One
/// under the password P7 retired is the old key's.
#[test]
fn syn03_12_c1_a11_a_copy_from_before_the_link_merges_its_content() {
    let l = Linked::new("c1-a11");
    let part = l.a.part();
    let copy = l.a.dir.join("Personal (old).larsalvault");
    let pw = "demo-old-pass-2";
    let added = Uuid([0x77; 16]);
    std::fs::write(
        &copy,
        resaved(pw, |v| {
            v.public_custom_data.clear();
            let at = v.root.times.last_modification;
            v.root.entries.push(larsal_model::Entry::new(added, at));
            v.meta.master_key_changed = year_2099();
            v.meta.name = "Demo old copy name".into();
            v.meta.name_changed = year_2099();
        }),
    )
    .unwrap();
    let state =
        l.a.s
            .merge_copy(
                l.a.v,
                copy.display().to_string(),
                Some(pw.into()),
                None,
                false,
            )
            .unwrap();
    assert_eq!(state, crate::copies::CopyState::Merged);
    let hex: String = added.0.iter().map(|b| format!("{b:02x}")).collect();
    assert!(l.a.ids().contains(&hex), "the copy's content came");
    let name =
        l.a.s
            .with_vault(l.a.v, |v| Ok(v.meta.name.clone()))
            .unwrap();
    assert_ne!(name, "Demo old copy name", "the copy's metadata came");
    assert_eq!(l.a.part(), part, "the vault keeps its key");
    l.a.save();
    l.a.s.lock(l.a.v).unwrap();
    assert!(!l.a.unlocks(pw));
    assert!(l.a.unlocks(PASSWORD));
    let retired = l.a.dir.join("Personal (before).larsalvault");
    std::fs::write(
        &retired,
        resaved(PASSWORD, |v| v.public_custom_data.clear()),
    )
    .unwrap();
    assert_eq!(
        l.a.s
            .merge_copy(
                l.a.v,
                retired.display().to_string(),
                Some(PASSWORD.into()),
                None,
                false
            )
            .unwrap(),
        crate::copies::CopyState::OldKey
    );
}

/// SYN-03.12 (C1-A12): a key file typed for a linked vault that is not its part is
/// refused with words in the copy sheet, the disk sheet and at unlock; the part
/// stays. The saved part itself is taken.
#[test]
fn syn03_12_c1_a12_a_typed_key_file_never_replaces_the_part() {
    let l = Linked::new("c1-a12");
    let part = l.a.part();
    let k = [0x31u8; 32];
    let key = l.a.dir.join("typed.larsalkey");
    std::fs::write(&key, k).unwrap();
    let typed = Some(key.display().to_string());
    let copy = l.a.dir.join("Personal (typed).larsalvault");
    let pw = "demo-typed-pass-4";
    std::fs::write(
        &copy,
        resaved_with(pw, Some(&k), |v| v.meta.master_key_changed = year_2099()),
    )
    .unwrap();
    let text = crate::sync::PART_OTHER.1;
    let got = l.a.s.merge_copy(
        l.a.v,
        copy.display().to_string(),
        Some(pw.into()),
        typed.clone(),
        false,
    );
    assert!(matches!(got, Err(LarsalError::Refused(t)) if t == text));
    assert_eq!(l.a.part(), part);
    let got = l.a.s.resolve_disk_with_key(
        l.a.v,
        DiskChoice::Merge,
        Some(PASSWORD.into()),
        typed.clone(),
    );
    assert!(matches!(got, Err(LarsalError::Refused(t)) if t == text));
    assert_eq!(l.a.part(), part);
    let saved = l.a.dir.join("saved.larsalkey");
    assert_eq!(
        l.a.s
            .sync_save_part(l.a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    l.a.s.lock(l.a.v).unwrap();
    match l.a.s.unlock(l.a.v, Some(PASSWORD.into()), typed).unwrap() {
        crate::session::UnlockResult::Failed { message } => {
            assert_eq!(message.id, "MSG-SYNC-PART-OTHER");
            assert!(message.about_key_file);
        }
        other => panic!("{other:?}"),
    }
    assert!(unlocked_ok(
        l.a.s
            .unlock(
                l.a.v,
                Some(PASSWORD.into()),
                Some(saved.display().to_string())
            )
            .unwrap()
    ));
    assert_eq!(l.a.part(), part);
}

/// SYN-03.12 (C1-A12) with two Macs: the copy sheet refused, A and B stay on one
/// key and both stay Synced.
#[test]
fn syn03_12_c1_a12b_a_refused_key_file_leaves_both_macs_synced() {
    let k = KeyChange::new("c1-a12b");
    let (a, b) = (&k.a, &k.b);
    let key_bytes = [0x31u8; 32];
    let key = a.dir.join("typed.larsalkey");
    std::fs::write(&key, key_bytes).unwrap();
    let copy = a.dir.join("Personal (typed).larsalvault");
    let pw = "demo-typed-pass-4";
    std::fs::write(
        &copy,
        resaved_with(pw, Some(&key_bytes), |v| {
            v.meta.master_key_changed = year_2099();
        }),
    )
    .unwrap();
    assert!(
        a.s.merge_copy(
            a.v,
            copy.display().to_string(),
            Some(pw.into()),
            Some(key.display().to_string()),
            false
        )
        .is_err()
    );
    a.rename(&k.t[0], "E1 by A");
    a.tick(2_000);
    b.s.sync_now(b.v).unwrap();
    b.tick(0);
    assert_eq!(
        (a.status(), b.status()),
        (Some(SyncStatus::Synced), Some(SyncStatus::Synced))
    );
    assert!(titled(b, "E1 by A"));
    assert_eq!(a.part(), b.part());
}

/// SYN-03.9 (C1-A7b): a planted copy whose entries carry 2099 times, answered Merge
/// anyway: the upload after the answer records the vault's measures from before it.
#[test]
fn syn03_9_c1_a7b_a_planted_entry_time_reaches_no_record() {
    let a = Mac::new("c1-a7b", true);
    a.keyed();
    let y = year_2099();
    let planted = resaved_keyed(PASSWORD, |v| {
        fn stamp(g: &mut larsal_model::Group, y: larsal_model::Time) {
            for e in &mut g.entries {
                e.times.last_modification = y;
            }
            for c in &mut g.groups {
                stamp(c, y);
            }
        }
        stamp(&mut v.root, y);
    });
    let server = t16_server(planted);
    add_scripted(&a, &server);
    link_to(&a, &server.address(), [0; 32]);
    a.change_password(DEMO2);
    a.tick(0);
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    assert_eq!(a.tick(0)[0].status, SyncStatus::ReplacedPassword);
    a.s.sync_old_key(a.v, true).unwrap();
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    assert_eq!(server.count("PUT"), 1);
    let seen = a.s.sync_with(|i| i.state.links[0].seen.newest);
    assert!(seen < y, "a planted time reached the link record");
}

/// SYN-03.9 (C1-T1, M6, M6b, M7, M40): the answer records the copy's version and
/// hash, never an older version over a newer one, and Merge anyway's result is in
/// the file before the upload.
#[test]
fn syn03_9_the_answer_records_the_copy_and_saves_the_merge() {
    let k = KeyChange::new("answer-record");
    k.changes();
    k.to_old_key();
    let a = &k.a;
    let (version, bytes) = stored(a);
    a.s.sync_old_key(a.v, true).unwrap();
    let link = a.s.sync_with(|i| i.state.links[0].clone());
    assert_eq!(link.highest, version);
    assert_eq!(link.server_sha, larsal_sync::sync::hash(&bytes));
    let file = std::fs::read(a.dir.join("Personal.larsalvault")).unwrap();
    let saved = open_copy(a, &file, DEMO2, Some(&a.part())).unwrap();
    assert!(
        saved
            .root
            .all_entries()
            .any(|e| e.value("Title") == "E2 by B")
    );

    let k = KeyChange::new("answer-older");
    k.changes();
    k.to_old_key();
    let a = &k.a;
    a.s.sync_with(|i| i.state.links[0].highest = 9);
    let before = a.s.sync_with(|i| i.state.links[0].server_sha);
    a.s.sync_old_key(a.v, false).unwrap();
    let link = a.s.sync_with(|i| i.state.links[0].clone());
    assert_eq!((link.highest, link.server_sha), (9, before));
}

/// SYN-03.9 (C1-T1, M5): a lock and unlock while the copy opens: the copy is held by
/// neither unlock.
#[test]
fn syn03_9_a_relock_while_the_copy_opens_holds_nothing() {
    let k = KeyChange::new("relock-held");
    k.changes();
    let a = &k.a;
    assert_eq!(a.tick(2_000)[0].status, SyncStatus::NeedsPassword);
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    let (s, v) = (a.s.clone(), a.v);
    COPY_OPENED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            s.lock(v).unwrap();
            assert!(unlocked_ok(s.unlock(v, Some(DEMO2.into()), None).unwrap()));
        }))
    });
    a.tick(0);
    let held =
        a.s.with_draft_state(a.v, |_, s| Ok(s.sync_held.is_some()))
            .unwrap();
    assert!(!held, "the new unlock holds a copy it never opened");
}

/// SYN-03.9, carried item 12: Merge anyway after a Save As refuses before it merges:
/// the copy goes and the moved vault takes nothing of it.
#[test]
fn syn03_9_an_answer_after_a_save_as_takes_nothing() {
    let k = KeyChange::new("answer-moved");
    k.changes();
    k.to_old_key();
    let a = &k.a;
    let moved = a.dir.join("Moved.larsalvault");
    a.s.save_as(a.v, moved.display().to_string()).unwrap();
    assert!(a.s.sync_old_key(a.v, true).is_err());
    assert!(!titled(a, "E2 by B"));
    let held =
        a.s.with_draft_state(a.v, |_, s| Ok(s.sync_held.is_some()))
            .unwrap();
    assert!(!held);
    let file = std::fs::read(&moved).unwrap();
    let saved = open_copy(a, &file, DEMO2, Some(&a.part())).unwrap();
    assert!(
        !saved
            .root
            .all_entries()
            .any(|e| e.value("Title") == "E2 by B")
    );
}

/// MOD-13.11 (C1-A15): the part is no key change the user confirmed: a forced key
/// change set before the put stays.
#[test]
fn syn03_1_c1_a15_the_part_keeps_a_forced_key_change() {
    let (_app, _proxy, address, a) = unlinked("c1-a15");
    a.s.with_edit(a.v, |v, _, _, s| {
        v.meta.master_key_change_force_once = true;
        s.count_change();
        Ok(())
    })
    .unwrap();
    a.save();
    put(&a, &address);
    let flag =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_change_force_once))
            .unwrap();
    assert!(flag, "the put cleared the forced key change");
}

/// MOD-11.31 (C1-T1, M13): a key change, then a reload of another writer's file
/// under a third password, leaves the change's key never saved: the put's part
/// then retires no record of the key in use.
#[test]
fn syn03_1_the_part_retires_nothing_while_an_earlier_change_is_unsaved() {
    let (_app, _proxy, address, a) = unlinked("pending-key");
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let vs = crate::vault_settings::VaultSettings::new(a.s.clone(), a.v);
    vs.set_password(DEMO2.to_owned()).unwrap();
    vs.set_repeat(DEMO2.to_owned()).unwrap();
    assert_eq!(
        vs.change_password(vec![crate::wizard::Answer::WeakPassword])
            .unwrap(),
        Outcome::Done
    );
    assert_eq!(a.s.retired_records(root).len(), 1);
    std::fs::write(
        a.dir.join("Personal.larsalvault"),
        resaved(DEMO3, |v| v.meta.name = "Demo other writer".into()),
    )
    .unwrap();
    a.s.check_disk(a.v).unwrap();
    assert_eq!(
        a.s.resolve_disk(a.v, DiskChoice::Reload).unwrap(),
        DiskEvent::NewKey
    );
    a.s.resolve_disk_with_key(a.v, DiskChoice::Reload, Some(DEMO3.into()), None)
        .unwrap();
    assert!(a.s.with_edit_state(a.v, |s| s.changes == 0 && s.disk.new_key));
    put(&a, &address);
    assert_eq!(a.s.retired_records(root).len(), 1);
    a.s.lock(a.v).unwrap();
    assert!(a.unlocks(DEMO3));
}

/// LD-427 (C1-T1, M10): field 12 that comes between the put's key part and its read
/// never goes up.
#[test]
fn ld427_field_12_after_the_part_never_goes_up() {
    let (_app, proxy, address, a) = unlinked("put-keyed");
    let (s, v) = (a.s.clone(), a.v);
    PUT_KEYED.with(|m| {
        *m.borrow_mut() = Some(Box::new(move || {
            s.with_edit(v, |v, _, _, e| {
                let changes = Changes {
                    public_name: Some(Some(PUBLIC.to_owned())),
                    ..Changes::default()
                };
                let mut host = s.host.lock().unwrap();
                settings::apply(
                    v,
                    &changes,
                    &mut host,
                    &Limits::DEFAULT.kdf,
                    crate::views::now(),
                )
                .map_err(|_| refused("public name"))?;
                e.changes = e.changes.max(1);
                Ok(())
            })
            .unwrap();
            assert_eq!(s.save(v).unwrap().changes, 0);
        }))
    });
    assert!(a.s.sync_put_vault(a.v, address).is_err());
    assert_eq!(proxy.count("PUT"), 0);
}

/// F-321, SYN-03.1 step 1 (C2-1, Checker 2's probe 4): each put draws its own part;
/// two vaults with one password get two parts, and no part is the password's hash.
#[test]
fn syn03_1_c2_1_each_put_draws_its_own_part() {
    let one = Linked::new("c2-part-1");
    let two = Linked::new("c2-part-2");
    let (p1, p2) = (one.a.part(), two.a.part());
    assert_eq!((p1.len(), p2.len()), (32, 32));
    assert_ne!(p1, p2, "two vaults with one password got one part");
    let pw = SecretString::new(PASSWORD.to_owned());
    let made = larsal_format::keys::password_part(&pw);
    assert_ne!(
        p1.as_slice(),
        made.expose(),
        "the part is made of the password"
    );
    let hashed = larsal_crypto::hash::sha256(&[PASSWORD.as_bytes()]);
    assert_ne!(
        p1.as_slice(),
        hashed.expose(),
        "the part is SHA-256 of the password"
    );
}

/// SYN-03.8, MOD-11.31 (C1-A28): a password retired before the put has no part in
/// its record; a copy under it and the part, with a 2099 key time, is still the old
/// key's, and that password never comes back.
#[test]
fn syn03_8_c1_a28_a_key_retired_before_the_put_stays_retired() {
    let (_app, _proxy, address, a) = unlinked("c1-a28");
    a.change_password(DEMO2);
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let planted = resaved_with(PASSWORD, Some(&part), |v| {
        v.root.uuid = root;
        v.meta.master_key_changed = year_2099();
    });
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    assert!(matches!(a.s.merge_server(a.v, &planted, 9), Merge::OldKey));
    a.s.lock(a.v).unwrap();
    assert!(!a.unlocks(PASSWORD));
    assert!(a.unlocks(DEMO2));
}

/// LD-264 (ruling 2): the part's key change at the put goes past a key time this
/// Mac has seen for the vault.
#[test]
fn ld264_the_part_goes_past_a_key_time_seen() {
    let (_app, _proxy, address, a) = unlinked("seen-put");
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    a.s.key_seen(root, year_2099());
    put(&a, &address);
    let t =
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap();
    assert_eq!(t, larsal_model::Time(year_2099().0 + 1));
}

/// SYN-03.9 (C1-T1, M7): Merge anyway counts a change, so a save that fails after
/// it is an error and the merge waits as an unsaved change.
#[test]
fn syn03_9_merge_anyway_that_cannot_save_is_an_error() {
    use std::os::unix::fs::PermissionsExt;
    let k = KeyChange::new("answer-unsaved");
    k.changes();
    k.to_old_key();
    let a = &k.a;
    let file = a.dir.join("Personal.larsalvault");
    let folder = file.parent().unwrap().to_path_buf();
    let mode = |p: &std::path::Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    mode(&file, 0o400);
    mode(&folder, 0o500);
    let got = a.s.sync_old_key(a.v, true);
    mode(&folder, 0o700);
    mode(&file, 0o600);
    assert!(got.is_err(), "a merge that was not saved was answered");
    assert!(a.s.with_edit_state(a.v, |s| s.changes >= 1));
    assert!(titled(a, "E2 by B"));
}

/// A sheet's answer refused with `text`.
fn refused_with<T: std::fmt::Debug>(got: Result<T, LarsalError>, text: &str) -> bool {
    matches!(&got, Err(LarsalError::Refused(t)) if t == text)
}

/// The demo vault under `password` with `part` (none: the password alone) and a
/// 2099 key time.
fn planted(password: &str, part: Option<&[u8]>) -> Vec<u8> {
    resaved_with(password, part, |v| v.meta.master_key_changed = year_2099())
}

/// SYN-03.8, MOD-11.31 (C1R2-01, C2R2-1; Checker 2's probe 9, Checker 1's
/// c1r2_a28c): `demo` retired before the put has no part in its record. The copy
/// sheet runs the server copy's check: a sibling copy under `demo` and the part,
/// with a 2099 key time, is the old key's, and so is one under `demo` alone, from
/// before the put. Neither gives its key; the server road agrees.
#[test]
fn syn03_8_c1r2_01_the_copy_sheet_keeps_a_key_retired_before_the_put() {
    let (_app, _proxy, address, a) = unlinked("c1r2-01-copy");
    a.change_password(DEMO2);
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let with_part = planted(PASSWORD, Some(&part));
    for (name, bytes) in [
        ("with the part", &with_part),
        ("alone", &planted(PASSWORD, None)),
    ] {
        let copy = a.dir.join(format!("Personal ({name}).larsalvault"));
        std::fs::write(&copy, bytes).unwrap();
        let got = a.s.merge_copy(
            a.v,
            copy.display().to_string(),
            Some(PASSWORD.into()),
            None,
            false,
        );
        assert!(
            matches!(got, Ok(crate::copies::CopyState::OldKey)),
            "{name}: {got:?}"
        );
    }
    assert_eq!(a.part(), part);
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    assert!(matches!(
        a.s.merge_server(a.v, &with_part, 9),
        Merge::OldKey
    ));
    let (_, bytes) = stored(&a);
    assert!(open_copy(&a, &bytes, PASSWORD, Some(&part)).is_err());
    a.s.lock(a.v).unwrap();
    assert!(!a.unlocks(PASSWORD));
    assert!(a.unlocks(DEMO2));
}

/// SYN-03.8, APP-05.29, MOD-11.31 (C1R2-01, C2R2-1; probe 10, c1r2_a28d): the same
/// on the disk sheet. Another writer's version of the vault's own file under `demo`
/// and the part is the old key's; Skip, and A's save writes its own key. A version
/// under `demo` alone does not open with the part the sheet adds: `NewKey`, and
/// nothing of it is taken.
#[test]
fn syn03_8_c1r2_01_the_disk_sheet_keeps_a_key_retired_before_the_put() {
    let (_app, _proxy, address, a) = unlinked("c1r2-01-disk");
    a.change_password(DEMO2);
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let path = a.dir.join("Personal.larsalvault");
    std::fs::write(&path, planted(PASSWORD, Some(&part))).unwrap();
    assert_eq!(a.s.check_disk(a.v).unwrap(), DiskEvent::NewKey);
    let got =
        a.s.resolve_disk_with_key(a.v, DiskChoice::Merge, Some(PASSWORD.into()), None);
    assert!(matches!(got, Ok(DiskEvent::OldKey)), "{got:?}");
    a.s.resolve_old_key(a.v, false).unwrap();
    a.save();
    let file = std::fs::read(&path).unwrap();
    assert!(open_copy(&a, &file, PASSWORD, Some(&part)).is_err());
    assert!(open_copy(&a, &file, DEMO2, Some(&part)).is_ok());

    std::fs::write(&path, planted(PASSWORD, None)).unwrap();
    assert_eq!(a.s.check_disk(a.v).unwrap(), DiskEvent::NewKey);
    let got =
        a.s.resolve_disk_with_key(a.v, DiskChoice::Merge, Some(PASSWORD.into()), None);
    assert!(matches!(got, Ok(DiskEvent::NewKey)), "{got:?}");
    assert_eq!(a.part(), part);
    a.s.resolve_disk(a.v, DiskChoice::KeepMine).unwrap();
    a.save();
    a.s.lock(a.v).unwrap();
    assert!(!a.unlocks(PASSWORD));
    assert!(a.unlocks(DEMO2));
}

/// SYN-03.3, LD-267 (2) (C2R2-1; Checker 2's probe 6): this Mac's vault state does
/// not read after a restart, and the sync state holds the records. The copy sheet,
/// the disk sheet and the server road all read the union: a copy under the old
/// password and the part is the old key's on each.
#[test]
fn syn03_3_c2r2_1_every_sheet_reads_the_sync_state_records() {
    let (_app, _proxy, address, a) = unlinked("c2r2-1-union");
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    a.change_password(DEMO2);
    a.s.lock(a.v).unwrap();
    std::fs::write(a.dir.join("settings/vault-state_debug.json"), b"not json").unwrap();
    let a2 = restart(&a, None);
    assert_eq!(
        (
            a2.s.sync_retired(root).len(),
            a2.s.retired_records(root).len()
        ),
        (2, 0)
    );
    assert!(a2.unlocks(DEMO2));
    let old = planted(PASSWORD, Some(&part));
    let copy = a.dir.join("Personal (planted).larsalvault");
    std::fs::write(&copy, &old).unwrap();
    let got = a2.s.merge_copy(
        a2.v,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        None,
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::OldKey)),
        "{got:?}"
    );
    std::fs::write(a.dir.join("Personal.larsalvault"), &old).unwrap();
    assert_eq!(a2.s.check_disk(a2.v).unwrap(), DiskEvent::NewKey);
    let got =
        a2.s.resolve_disk_with_key(a2.v, DiskChoice::Merge, Some(PASSWORD.into()), None);
    assert!(matches!(got, Ok(DiskEvent::OldKey)), "{got:?}");
    a2.s.resolve_old_key(a2.v, false).unwrap();
    a2.s.sync_open_copy(a2.v, PASSWORD.into()).unwrap();
    assert!(matches!(a2.s.merge_server(a2.v, &old, 9), Merge::OldKey));
    a2.save();
    a2.s.lock(a2.v).unwrap();
    assert!(!a2.unlocks(PASSWORD));
    assert!(a2.unlocks(DEMO2));
}

/// SYN-03.12 (C1R2-02, C2R2-7; Checker 1's c1r2_a12c): fail closed. While the
/// device store gives no part, emptied or failing, a linked vault takes nothing
/// typed: a key file or a password alone in the copy sheet and in the disk sheet,
/// and a key file with no typed factor at unlock, get `MSG-SYNC-PART-UNREAD`, and
/// the vault keeps its part. At unlock another key file with the password opens
/// nothing; the saved part with the password is the way back (C1R3B-02, T66): it
/// unlocks, and an emptied device store keeps the part again.
#[test]
fn syn03_12_c1r2_02_with_the_part_unread_nothing_typed_is_taken() {
    for failing in [false, true] {
        let l = Linked::new(if failing {
            "c1r2-02-fails"
        } else {
            "c1r2-02-empty"
        });
        let a = &l.a;
        let part = a.part();
        let saved = a.dir.join("saved.larsalkey");
        assert_eq!(
            a.s.sync_save_part(a.v, saved.display().to_string())
                .unwrap(),
            Outcome::Done
        );
        let k = [0x31u8; 32];
        let key = a.dir.join("typed.larsalkey");
        std::fs::write(&key, k).unwrap();
        let pw = "demo-typed-pass-4";
        let keyed = a.dir.join("Personal (typed).larsalvault");
        std::fs::write(&keyed, planted(pw, Some(&k))).unwrap();
        let plain = a.dir.join("Personal (plain).larsalvault");
        std::fs::write(&plain, planted(pw, None)).unwrap();
        let store: Vec<(String, Vec<u8>)> = a.s.sync_with(|i| {
            let store = i
                .device_store
                .iter()
                .map(|(l, p)| (l.clone(), p.expose().to_vec()))
                .collect();
            if failing {
                i.store_refuses = true;
            } else {
                i.device_store.clear();
            }
            store
        });
        let text = crate::sync::PART_UNREAD.1;
        let typed = Some(key.display().to_string());
        for (copy, key_file) in [(&keyed, typed.clone()), (&plain, None)] {
            let got = a.s.merge_copy(
                a.v,
                copy.display().to_string(),
                Some(pw.into()),
                key_file,
                false,
            );
            assert!(refused_with(got, text), "copy sheet, failing {failing}");
        }
        for key_file in [typed.clone(), None] {
            let got =
                a.s.resolve_disk_with_key(a.v, DiskChoice::Merge, Some(pw.into()), key_file);
            assert!(refused_with(got, text), "disk sheet, failing {failing}");
        }
        assert_eq!(a.part(), part);
        a.s.lock(a.v).unwrap();
        let alone = a.s.unlock(a.v, None, Some(saved.display().to_string()));
        assert_eq!(unlock_id(alone.unwrap()), "MSG-SYNC-PART-UNREAD");
        let other =
            a.s.unlock(a.v, Some(PASSWORD.into()), Some(key.display().to_string()))
                .unwrap();
        assert!(!unlocked_ok(other), "another key file, failing {failing}");
        let back =
            a.s.unlock(
                a.v,
                Some(PASSWORD.into()),
                Some(saved.display().to_string()),
            )
            .unwrap();
        assert!(unlocked_ok(back), "the way back, failing {failing}");
        assert_eq!(a.part(), part);
        let kept = a.s.sync_with(|i| {
            i.device_store
                .values()
                .any(|p| p.expose() == part.as_slice())
        });
        assert!(kept, "the device store keeps the part, failing {failing}");
        a.s.lock(a.v).unwrap();
        a.s.sync_with(|i| {
            i.store_refuses = false;
            for (l, p) in store {
                i.device_store.insert(l, SecretBytes::new(p));
            }
        });
        assert!(unlocked_ok(
            a.s.unlock(
                a.v,
                Some(PASSWORD.into()),
                Some(saved.display().to_string())
            )
            .unwrap()
        ));
        assert_eq!(a.part(), part);
    }
}

/// SYN-03.2 (C1R2-03; Checker 1's c1r2_a18d): B's download, moved, deleted or
/// written over with other bytes before its first run, with no unlock of it open,
/// leaves a link with no root yet that no run can take. It blocks nothing: the list
/// shows the server vault as not linked, the next run drops the link, and the vault
/// downloads again. The pointer stays.
fn a_download_gone_before_its_first_run(tag: &str, how: &str) {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, &format!("{tag}-a"));
    put(&a, &address);
    a.tick(0);
    let mut b = second(&app, &address, app.pin, &a, &format!("{tag}-b"));
    b.s.lock(b.v).unwrap();
    b.s.close(b.v).unwrap();
    let path = b.dir.join("Personal.larsalvault");
    match how {
        "moved" => std::fs::rename(&path, b.dir.join("Moved by the user.larsalvault")).unwrap(),
        "deleted" => std::fs::remove_file(&path).unwrap(),
        _ => std::fs::write(&path, resaved(PASSWORD, |_| {})).unwrap(),
    }
    let stale = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].root, UNKNOWN_ROOT);
    let listed = b.s.sync_server_vaults(address.clone()).unwrap();
    assert!(!listed[0].linked, "listed as linked");
    assert!(b.s.sync_with(|i| i.state.links.is_empty()));

    b.s.sync_with(|i| i.state.links.clone_from(&stale));
    let other = b.dir.join("Other.larsalvault");
    std::fs::copy(DEMO, &other).unwrap();
    b.open(&other);
    b.tick(0);
    assert!(
        b.s.sync_with(|i| i.state.links.is_empty()),
        "the next run keeps it"
    );

    b.s.sync_with(|i| i.state.links.clone_from(&stale));
    let again = b.dir.join("Personal again.larsalvault");
    b.s.sync_download(address, listed[0].id.clone(), again.display().to_string())
        .unwrap();
    let links = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(links.len(), 1);
    assert!(links[0].file.ends_with("Personal again.larsalvault"));
    let file = stale[0].file.clone();
    assert!(b.s.sync_with(|i| i.state.parts.iter().any(|p| p.file == file)));
    let v = b.s.open(again.display().to_string()).unwrap();
    assert!(unlocked_ok(
        b.s.unlock(v, Some(PASSWORD.into()), None).unwrap()
    ));
}

#[test]
fn syn03_2_c1r2_03_a_download_moved_before_its_first_run_blocks_nothing() {
    a_download_gone_before_its_first_run("c1r2-03-moved", "moved");
}

#[test]
fn syn03_2_c1r2_03_a_download_deleted_before_its_first_run_blocks_nothing() {
    a_download_gone_before_its_first_run("c1r2-03-deleted", "deleted");
}

#[test]
fn syn03_2_c1r2_03_a_download_written_over_before_its_first_run_blocks_nothing() {
    a_download_gone_before_its_first_run("c1r2-03-other", "other bytes");
}

/// SYN-03.2 (C1R2-03, mutant D2): B's download is deleted before its first run and
/// another vault is saved at its path and unlocked. The put of that vault drops
/// the waiting link first, so the path is free: the put links the new vault.
#[test]
fn syn03_2_c1r2_03_a_put_at_the_path_of_a_download_gone_before_its_first_run() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1r2-03-put-a");
    put(&a, &address);
    a.tick(0);
    let (mut b, path, _) = second_without_the_part(&app, &address, &a, "c1r2-03-put-b");
    copy_parts(&a, &b);
    std::fs::remove_file(&path).unwrap();
    let root = Uuid([0x43; 16]);
    std::fs::write(&path, resaved_with(PASSWORD, None, |v| v.root.uuid = root)).unwrap();
    b.open(&path);
    put(&b, &address);
    let links = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].root, root);
}

/// LD-264 (C1R2-04, mutant K6): an unlock counts its file's key time as seen,
/// even for a file the rollback guard finds older (APP-05.26), whose measures it
/// does not take. A saves an edit dated 2099. Another writer's file with older
/// entries and a key time a day before that is unlocked: older, so only the unlock
/// sees its key time. A's own file comes back and A changes its password: one
/// second past that key time.
#[test]
fn ld264_c1r2_04_an_unlock_counts_its_key_time_as_seen() {
    let a = Mac::new("c1r2-k6", true);
    let path = a.dir.join("Personal.larsalvault");
    edit_at(&a, &a.titles()[0], "E1 dated 2099", year_2099());
    let own = std::fs::read(&path).unwrap();
    let key_time = || {
        a.s.with_vault(a.v, |v| Ok(v.meta.master_key_changed))
            .unwrap()
    };
    let ahead = larsal_model::Time(year_2099().0 - 86_400);
    assert!(key_time() < ahead);
    a.s.lock(a.v).unwrap();
    let theirs = resaved(PASSWORD, |v| v.meta.master_key_changed = ahead);
    // Read on another Mac: an open here would count its key time as seen.
    let vault = open_copy(&Mac::new("c1r2-k6-reader", false), &theirs, PASSWORD, None).unwrap();
    assert!(a.s.guard(&vault, &theirs).older, "the guard finds it older");
    std::fs::write(&path, &theirs).unwrap();
    assert!(a.unlocks(PASSWORD));
    assert_eq!(key_time(), ahead);
    a.s.lock(a.v).unwrap();
    std::fs::write(&path, &own).unwrap();
    assert!(a.unlocks(PASSWORD));
    assert!(key_time() < ahead);
    a.change_password(DEMO2);
    assert_eq!(key_time(), larsal_model::Time(ahead.0 + 1));
}

/// SYN-03.12 (C1R2-04, mutant A1c): a hardware key is a typed factor too. A linked
/// vault with a password and a hardware key may drop the password; it keeps the
/// hardware key beside its part, and saves.
#[test]
fn syn03_12_c1r2_04_a_hardware_key_is_a_typed_factor() {
    let (_app, _proxy, address, a) = unlinked("c1r2-a1c");
    let vs = crate::vault_settings::VaultSettings::new(a.s.clone(), a.v);
    assert_eq!(
        vs.set_security_key(Some(crate::hwkey::tests::PICK), vec![])
            .unwrap(),
        Outcome::Done
    );
    a.save();
    put(&a, &address);
    assert_eq!(remove_password(&a), Outcome::Done);
    let saver = a.s.with_edit_state(a.v, |e| e.saver.clone()).unwrap();
    {
        let sv = saver.lock().unwrap();
        assert!(sv.password.is_none() && sv.hardware.is_some() && sv.key_file.is_some());
    }
    a.save();
}

/// SYN-03.9 (C1R2-04, mutant W2): after Merge anyway the next upload records the
/// vault's measures from before the answer, until a save of the user's own: that
/// save measures the vault as it is, so its edit's time reaches the record.
#[test]
fn syn03_9_c1r2_04_a_save_after_merge_anyway_records_the_vault_as_it_is() {
    let k = KeyChange::new("c1r2-w2");
    k.changes();
    k.to_old_key();
    let a = &k.a;
    a.s.sync_old_key(a.v, true).unwrap();
    let kept =
        a.s.sync_with(|i| i.vaults[&a.v].answered.map(|m| m.newest))
            .expect("the answer keeps the measures from before it");
    let later = larsal_model::Time(kept.0 + 3_600);
    edit_at(a, "E1 by A", "E1 after the answer", later);
    a.tick(2_000);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
    let seen = a.s.sync_with(|i| i.state.links[0].seen.newest);
    assert!(
        seen >= later,
        "the record kept the measures from before the answer"
    );
}

/// F-321, SYN-03.1 step 1 (C2R2-4, mutant C5c): a part is drawn, never made of
/// what the put knows. One password, one server and one vault id, keyed from
/// fresh state twice (two fresh Macs), give two parts.
#[test]
fn syn03_1_c2r2_4_one_label_from_fresh_state_twice_gives_two_parts() {
    let label = part_label(
        "https://127.0.0.1:8443",
        larsal_sync::state::VaultId::from_bytes([3; 16]),
    );
    let parts: Vec<Vec<u8>> = ["c2r2-4-one", "c2r2-4-two"]
        .into_iter()
        .map(|tag| {
            let a = Mac::new(tag, true);
            let (file, root) =
                a.s.with_edit(a.v, |v, path, _, _| {
                    Ok((path.to_string_lossy().into_owned(), v.root.uuid))
                })
                .unwrap();
            a.s.sync_key_part(a.v, file, root, label.clone()).unwrap();
            a.part()
        })
        .collect();
    assert_eq!((parts[0].len(), parts[1].len()), (32, 32));
    assert_ne!(parts[0], parts[1], "one label gave one part");
}

/// F-321, SYN-03.1 step 1 (C2R2-4, mutant C5e; Checker 2's probe 8): one Mac puts
/// two vaults with one password; each gets its own part, and neither is made of the
/// password and its label.
#[test]
fn syn03_1_c2r2_4_two_vaults_on_one_mac_get_two_parts() {
    use crate::wizard::{Answer, CipherChoice, EncryptionChoice, KdfChoice, Wizard};
    let (_app, _proxy, address, a) = unlinked("c2r2-4-p8");
    put(&a, &address);
    let p1 = a.part();
    let small = || EncryptionChoice {
        cipher: CipherChoice::Aes256,
        kdf: KdfChoice::Argon2id,
        memory_mib: 1,
        lanes: 1,
        unlock_ms: 100,
    };
    let path = a.dir.join("Second.larsalvault");
    let w = Wizard::new(Arc::clone(&a.s));
    assert!(w.measure(small()).unwrap());
    w.set_password(PASSWORD.into()).unwrap();
    w.set_repeat(PASSWORD.into()).unwrap();
    let out = w
        .create(
            "Second".into(),
            String::new(),
            path.display().to_string(),
            small(),
            false,
            vec![Answer::SafeMinimum, Answer::WeakPassword],
        )
        .unwrap();
    let crate::wizard::Outcome::Created { vault: two } = out else {
        panic!("{out:?}")
    };
    let st = a.s.sync_put_vault(two, address).unwrap();
    assert_eq!(st.status, SyncStatus::Synced);
    let saver = a.s.with_edit_state(two, |e| e.saver.clone()).unwrap();
    let p2 = saver
        .lock()
        .unwrap()
        .key_file
        .as_ref()
        .unwrap()
        .key()
        .expose()
        .to_vec();
    assert_eq!((p1.len(), p2.len()), (32, 32));
    assert_ne!(p1, p2, "one Mac gave two vaults one part");
    let labels: Vec<String> =
        a.s.sync_with(|i| i.state.parts.iter().map(|p| p.label.clone()).collect());
    assert_eq!(labels.len(), 2);
    for l in &labels {
        let made = larsal_crypto::hash::sha256(&[PASSWORD.as_bytes(), l.as_bytes()]);
        assert_ne!(p1.as_slice(), made.expose());
        assert_ne!(p2.as_slice(), made.expose());
    }
}

/// `demo` retired before the put (its record has no part), then the part saved as a
/// key file and the vault locked: A, the vault's root and the saved file.
fn retired_before_the_put(tag: &str) -> (LarsalServer, Scripted, Mac, Uuid, PathBuf) {
    let (app, proxy, address, a) = unlinked(tag);
    a.change_password(DEMO2);
    put(&a, &address);
    a.tick(0);
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    a.s.lock(a.v).unwrap();
    (app, proxy, a, root, saved)
}

/// SYN-03.3, MOD-11.31 (C1R3B-01; Checker 1's c1r3_p11): a Finder copy of the linked
/// vault has no pointer, and it opens with `demo2` and the saved part. The part is
/// known by its bytes, so a copy under `demo`, retired before the put, plus the part
/// is the old key's in the copy sheet and in the disk sheet, with no state file lost.
#[test]
fn syn03_3_c1r3b_01_a_finder_copy_keeps_a_key_retired_before_the_put() {
    let (_app, _proxy, a, root, saved) = retired_before_the_put("c1r3b-01-copy");
    assert_eq!(
        (
            a.s.sync_retired(root).len(),
            a.s.retired_records(root).len()
        ),
        (2, 2)
    );
    let label = a.s.sync_with(|i| i.state.parts[0].label.clone());
    let part = a.s.part_get(&label).unwrap().expose().to_vec();
    let key = Some(saved.display().to_string());
    let main = a.dir.join("Personal.larsalvault");
    let unlocked = |path: &Path, password: &str| {
        let v = a.s.open(path.display().to_string()).unwrap();
        let r = a.s.unlock(v, Some(password.into()), key.clone()).unwrap();
        (v, unlocked_ok(r))
    };

    let one = a.dir.join("Personal backup one.larsalvault");
    std::fs::copy(&main, &one).unwrap();
    let (v1, ok) = unlocked(&one, DEMO2);
    assert!(ok);
    let copy = a.dir.join("Personal (c1r3b-01).larsalvault");
    std::fs::write(&copy, planted(PASSWORD, Some(&part))).unwrap();
    let got = a.s.merge_copy(
        v1,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        key.clone(),
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::OldKey)),
        "{got:?}"
    );
    a.s.save(v1).unwrap();
    a.s.lock(v1).unwrap();
    assert!(!unlocked_ok(
        a.s.unlock(v1, Some(PASSWORD.into()), key.clone()).unwrap()
    ));

    let two = a.dir.join("Personal backup two.larsalvault");
    std::fs::copy(&main, &two).unwrap();
    let (v2, ok) = unlocked(&two, DEMO2);
    assert!(ok);
    std::fs::write(&two, planted(PASSWORD, Some(&part))).unwrap();
    assert_eq!(a.s.check_disk(v2).unwrap(), DiskEvent::NewKey);
    let got =
        a.s.resolve_disk_with_key(v2, DiskChoice::Merge, Some(PASSWORD.into()), key.clone());
    assert!(matches!(got, Ok(DiskEvent::OldKey)), "{got:?}");
    a.s.resolve_old_key(v2, false).unwrap();
    let st = a.s.save(v2).unwrap();
    assert_eq!((st.changes, st.failure), (0, None));
    let file = std::fs::read(&two).unwrap();
    let only = |password: &str| {
        let password = SecretString::new(password.to_owned());
        let k = part_key(&SecretBytes::new(part.clone())).unwrap();
        let c = larsal_format::keys::Credentials {
            password: Some(&password),
            key_file: Some(&k),
            hardware_key: None,
        };
        matches!(a.s.open_bytes(&file, &c, false), Some(Ok(_)))
    };
    assert!(!only(PASSWORD) && only(DEMO2));
}

/// SYN-03.3, MOD-11.31 (C1R3B-01; Checker 1's c1r3_p10): the sync state does not read
/// after a restart, and this Mac's vault state holds the records and the part's
/// label. The saved part with `demo2` opens the vault; a copy under `demo`, retired
/// before the put, plus the part is the old key's, and `demo` never opens the vault.
#[test]
fn syn03_3_c1r3b_01_a_lost_sync_state_keeps_a_key_retired_before_the_put() {
    let (_app, _proxy, a, root, saved) = retired_before_the_put("c1r3b-01-lost");
    let label = a.s.sync_with(|i| i.state.parts[0].label.clone());
    let part = a.s.part_get(&label).unwrap().expose().to_vec();
    std::fs::write(a.dir.join("settings/sync-state_debug.json"), b"not json").unwrap();
    let a2 = restart(&a, None);
    assert_eq!(
        (
            a2.s.sync_retired(root).len(),
            a2.s.retired_records(root).len()
        ),
        (0, 2)
    );
    assert_eq!(a2.s.part_labels(root), [label]);
    let key = Some(saved.display().to_string());
    assert!(unlocked_ok(
        a2.s.unlock(a2.v, Some(DEMO2.into()), key.clone()).unwrap()
    ));
    let copy = a.dir.join("Personal (c1r3b-01-lost).larsalvault");
    std::fs::write(&copy, planted(PASSWORD, Some(&part))).unwrap();
    let got = a2.s.merge_copy(
        a2.v,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        key.clone(),
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::OldKey)),
        "{got:?}"
    );
    a2.s.save(a2.v).unwrap();
    a2.s.lock(a2.v).unwrap();
    assert!(!unlocked_ok(
        a2.s.unlock(a2.v, Some(PASSWORD.into()), key).unwrap()
    ));
}

/// SYN-03.3, MOD-11.31 (C1R3B-01, the control; Checker 1's c1r3_p13): `demo` retired
/// after the put, so its record has the part: a Finder copy, and the linked file
/// after the sync state is lost, call a copy under `demo` plus the part the old key's.
#[test]
fn syn03_3_c1r3b_01_a_key_retired_after_the_put_stays_retired_on_both() {
    let (_app, _proxy, address, a) = unlinked("c1r3b-01-after");
    put(&a, &address);
    a.tick(0);
    a.change_password(DEMO2);
    let part = a.part();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    a.s.lock(a.v).unwrap();
    let key = Some(saved.display().to_string());
    let copy = a.dir.join("Personal (c1r3b-01-after).larsalvault");
    std::fs::write(&copy, planted(PASSWORD, Some(&part))).unwrap();
    let one = a.dir.join("Personal backup.larsalvault");
    std::fs::copy(a.dir.join("Personal.larsalvault"), &one).unwrap();
    let v1 = a.s.open(one.display().to_string()).unwrap();
    assert!(unlocked_ok(
        a.s.unlock(v1, Some(DEMO2.into()), key.clone()).unwrap()
    ));
    let got = a.s.merge_copy(
        v1,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        key.clone(),
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::OldKey)),
        "{got:?}"
    );
    a.s.lock(v1).unwrap();
    std::fs::write(a.dir.join("settings/sync-state_debug.json"), b"not json").unwrap();
    let a2 = restart(&a, None);
    assert!(unlocked_ok(
        a2.s.unlock(a2.v, Some(DEMO2.into()), key.clone()).unwrap()
    ));
    let got = a2.s.merge_copy(
        a2.v,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        key,
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::OldKey)),
        "{got:?}"
    );
}

/// MOD-11.31 (C1R3B-05, mutant R4; Checker 1's c1r3_p8): a key file this Mac never
/// kept is never taken for the part. A vault whose first upload failed (a pointer,
/// no link) takes a sibling copy under its current password and another key file
/// K, typed in the copy sheet: K is not a part, so the retired check never tries the
/// password without it, and the copy is no old key's.
#[test]
fn syn03_3_c1r3b_05_a_key_file_this_mac_never_kept_is_not_the_part() {
    use larsal_sync::test_server::Response;
    let a = Mac::new("c1r3b-05", true);
    let server = scripted_transfer(|_| Response::new(500, b"{}"));
    add_scripted(&a, &server);
    assert!(a.s.sync_put_vault(a.v, server.address()).is_err());
    assert!(!a.s.sync_linked(a.v));
    let k = [0x37u8; 32];
    let key = a.dir.join("other.larsalkey");
    std::fs::write(&key, k).unwrap();
    let copy = a.dir.join("Personal (c1r3b-05).larsalvault");
    std::fs::write(&copy, planted(PASSWORD, Some(&k))).unwrap();
    let got = a.s.merge_copy(
        a.v,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        Some(key.display().to_string()),
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::Merged)),
        "{got:?}"
    );
}

/// B as `second` makes it, but its device store has no part: a real second Mac
/// before E17-S1. The download is made; nothing is opened. B, the file and the
/// server vault's id.
fn second_without_the_part(
    app: &LarsalServer,
    address: &str,
    a: &Mac,
    tag: &str,
) -> (Mac, PathBuf, String) {
    let b = Mac::new(tag, false);
    b.s.sync_add_server(address.to_owned(), client::printed(&app.pin))
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
    let mut c = Client::new(address, app.pin).unwrap();
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
    let path = b.dir.join("Personal.larsalvault");
    b.s.sync_download(
        address.to_owned(),
        listed[0].id.clone(),
        path.display().to_string(),
    )
    .unwrap();
    (b, path, listed[0].id.clone())
}

/// SYN-03.12, SYN-03.2 (C1R3B-02, mutant Y1; Checker 1's c1r3_p4): a second Mac has
/// no part in its device store. Its download opens with neither the password alone
/// nor the saved key file alone, whose message names the way back. A new download of
/// the same server vault replaces the link that has no root yet (its pointer stays).
/// The password with the saved key file proves the part: the unlock opens, the device
/// store keeps it, the first run links the download, and the password alone opens it
/// after a lock.
#[test]
fn syn03_12_c1r3b_02_a_second_mac_without_the_part_gets_it_back_at_unlock() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1r3b-02-a");
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let key = Some(saved.display().to_string());
    let (mut b, path, id) = second_without_the_part(&app, &address, &a, "c1r3b-02-b");
    let v = b.s.open(path.display().to_string()).unwrap();
    assert!(!unlocked_ok(
        b.s.unlock(v, Some(PASSWORD.into()), None).unwrap()
    ));
    let alone = b.s.unlock(v, None, key.clone()).unwrap();
    assert_eq!(unlock_id(alone), "MSG-SYNC-PART-UNREAD");
    assert!(crate::sync::PART_UNREAD.1.contains("Save as key file"));

    let again = b.dir.join("Personal again.larsalvault");
    b.s.sync_download(address.clone(), id, again.display().to_string())
        .unwrap();
    let links = b.s.sync_with(|i| i.state.links.clone());
    assert_eq!(links.len(), 1, "the new download replaces the waiting link");
    assert!(links[0].file.ends_with("Personal again.larsalvault"));
    assert!(
        b.s.sync_with(|i| i
            .state
            .parts
            .iter()
            .any(|p| p.file.ends_with("Personal.larsalvault"))),
        "the old pointer stays"
    );

    b.v = b.s.open(again.display().to_string()).unwrap();
    assert!(unlocked_ok(
        b.s.unlock(b.v, Some(PASSWORD.into()), key).unwrap()
    ));
    let label = part_label(&links[0].server, links[0].vault_id);
    let kept =
        b.s.sync_with(|i| i.device_store.get(&label).map(|p| p.expose().to_vec()));
    assert_eq!(kept, Some(part));
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    b.s.lock(b.v).unwrap();
    assert!(b.unlocks(PASSWORD));
}

/// SYN-03.2 (C1R3B-03; Checker 1's c1r3_p5): a download's file that does not read
/// for a moment (no permission) keeps its link that has no root yet, before any
/// unlock and while an unlock of it is open, and so does one gone while that unlock
/// is open. The first run then links it.
#[test]
fn syn03_2_c1r3b_03_a_file_unreadable_for_a_moment_keeps_its_link() {
    use std::os::unix::fs::PermissionsExt;
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1r3b-03-a");
    put(&a, &address);
    a.tick(0);
    let (mut b, path, _) = second_without_the_part(&app, &address, &a, "c1r3b-03-b");
    copy_parts(&a, &b);
    let bytes = std::fs::read(&path).unwrap();
    let mode = |m| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).unwrap();
    let listed_linked = |b: &Mac| b.s.sync_server_vaults(address.clone()).unwrap()[0].linked;
    mode(0o000);
    let before_unlock = listed_linked(&b);
    mode(0o600);
    assert!(before_unlock, "unreadable before any unlock");
    b.open(&path);
    mode(0o000);
    let while_open = listed_linked(&b);
    mode(0o600);
    assert!(while_open, "unreadable while unlocked");
    std::fs::remove_file(&path).unwrap();
    assert!(listed_linked(&b), "gone while unlocked");
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(b.s.sync_with(|i| i.state.links.len()), 1);
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert!(b.s.sync_with(|i| i.state.links[0].root != UNKNOWN_ROOT));
}

/// SYN-03.2 (C1R3B-04 and C2bR3-4, mutants Y7 and N13; Checker 1's c1r3b_q1): B
/// downloads, then the list and a run of another open vault come before B first
/// unlocks the download. The file still holds the download, so the waiting link
/// stays; B then unlocks and its first run links it.
#[test]
fn syn03_2_c1r3b_04_a_list_and_another_run_before_the_first_unlock_keep_the_download() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1r3b-04-a");
    put(&a, &address);
    a.tick(0);
    let (mut b, path, _) = second_without_the_part(&app, &address, &a, "c1r3b-04-b");
    copy_parts(&a, &b);
    let listed = b.s.sync_server_vaults(address.clone()).unwrap();
    assert!(listed[0].linked);
    let other = b.dir.join("Other.larsalvault");
    std::fs::copy(DEMO, &other).unwrap();
    b.open(&other);
    b.tick(0);
    assert_eq!(b.s.sync_with(|i| i.state.links.len()), 1);
    b.open(&path);
    b.tick(0);
    assert!(b.s.sync_with(|i| i.state.links.iter().any(|l| l.root != UNKNOWN_ROOT)));
    assert_eq!(b.status(), Some(SyncStatus::Synced));
}

/// SYN-03.12 (C1R3B-04, mutant Y2): a vault whose first upload failed has a pointer
/// and no link; the copy sheet given a password alone adds its part, so a copy under
/// that password plus the part opens and merges, and the vault keeps its part.
#[test]
fn syn03_12_c1r3b_04_a_pointer_with_no_link_gives_its_part_to_a_sheet() {
    use larsal_sync::test_server::Response;
    let a = Mac::new("c1r3b-04-y2", true);
    let server = scripted_transfer(|_| Response::new(500, b"{}"));
    add_scripted(&a, &server);
    assert!(a.s.sync_put_vault(a.v, server.address()).is_err());
    assert!(!a.s.sync_linked(a.v));
    let part = a.part();
    let other = "demo-other-pass-5";
    let copy = a.dir.join("Personal (y2).larsalvault");
    std::fs::write(&copy, planted(other, Some(&part))).unwrap();
    let got = a.s.merge_copy(
        a.v,
        copy.display().to_string(),
        Some(other.into()),
        None,
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::Merged)),
        "{got:?}"
    );
    assert_eq!(a.part(), part, "the vault keeps its part");
}

/// F-321, SYN-03.1 step 1 (C2bR3-3, mutant C5h): a part is drawn, never made of the
/// file's path. One vault at one path, keyed from fresh state twice (the demo file
/// back at that path, no sync state, no part kept), gets two parts.
#[test]
fn syn03_1_c2br3_3_one_path_from_fresh_state_twice_gives_two_parts() {
    let a = Mac::new("c2br3-3", true);
    let path = a.dir.join("Personal.larsalvault");
    let label = part_label(
        "https://127.0.0.1:8443",
        larsal_sync::state::VaultId::from_bytes([3; 16]),
    );
    let keyed = |a: &Mac| {
        let (file, root) =
            a.s.with_edit(a.v, |v, path, _, _| {
                Ok((path.to_string_lossy().into_owned(), v.root.uuid))
            })
            .unwrap();
        a.s.sync_key_part(a.v, file, root, label.clone()).unwrap();
        a.part()
    };
    let one = keyed(&a);
    a.s.lock(a.v).unwrap();
    std::fs::copy(DEMO, &path).unwrap();
    a.s.sync_with(|i| {
        i.state = State::default();
        i.device_store.clear();
    });
    a.unlock();
    let two = keyed(&a);
    assert_eq!((one.len(), two.len()), (32, 32));
    assert_ne!(one, two, "one path gave one part");
}

/// The first entry of `g` and its groups renamed `title` at 2099.
fn renamed_first(g: &mut larsal_model::Group, title: &str) -> bool {
    if let Some(e) = g.entries.first_mut() {
        e.set_field(
            "Title".into(),
            larsal_model::Field {
                value: SecretString::new(title.to_owned()),
                protected: false,
            },
        );
        e.times.last_modification = year_2099();
        return true;
    }
    g.groups.iter_mut().any(|c| renamed_first(c, title))
}

/// SYN-03.12 (C2bR3-1; Checker 2's probes 12a and 12b): B, linked, keeps a typed
/// factor. A copy of B's vault keyed by the part alone, with a 2099 key time and an
/// entry renamed at 2099, is given only the saved part's key file in the copy sheet
/// or, as another writer's version of B's file, in the disk sheet. Its content is
/// merged, never its key: `MSG-SYNC-TYPED-KEPT`, B keeps its password and part, B's
/// saved file and, after B's run, the server copy do not open with the part alone.
fn the_part_alone_never_takes_the_key(tag: &str, disk: bool) {
    let k = KeyChange::new(tag);
    let b = &k.b;
    let part = b.part();
    let root = b.s.with_vault(b.v, |v| Ok(v.root.uuid)).unwrap();
    let saved = b.dir.join("saved part.larsalkey");
    assert_eq!(
        b.s.sync_save_part(b.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let title = "Renamed in a part-alone copy";
    let planted = resaved_with("", Some(&part), |v| {
        v.root.uuid = root;
        v.meta.master_key_changed = year_2099();
        assert!(renamed_first(&mut v.root, title));
    });
    let typed = Some(saved.display().to_string());
    let got = if disk {
        std::fs::write(b.dir.join("Personal.larsalvault"), &planted).unwrap();
        assert_eq!(b.s.check_disk(b.v).unwrap(), DiskEvent::NewKey);
        b.s.resolve_disk_with_key(b.v, DiskChoice::Merge, None, typed)
            .map(|_| ())
    } else {
        let copy = b.dir.join("Personal (part alone).larsalvault");
        std::fs::write(&copy, &planted).unwrap();
        b.s.merge_copy(b.v, copy.display().to_string(), None, typed, false)
            .map(|_| ())
    };
    assert!(refused_with(got, crate::sync::TYPED_KEPT.1), "disk {disk}");
    assert!(titled(b, title), "the content merge, disk {disk}");
    {
        let saver = b.s.with_edit_state(b.v, |e| e.saver.clone()).unwrap();
        let sv = saver.lock().unwrap();
        assert!(sv.password.is_some(), "B keeps its password, disk {disk}");
        assert_eq!(sv.key_file.as_ref().unwrap().key().expose(), &part[..]);
    }
    b.save();
    let key = part_key(&SecretBytes::new(part.clone())).unwrap();
    let alone = larsal_format::keys::Credentials {
        password: None,
        key_file: Some(&key),
        hardware_key: None,
    };
    let file = std::fs::read(b.dir.join("Personal.larsalvault")).unwrap();
    assert!(!matches!(b.s.open_bytes(&file, &alone, false), Some(Ok(_))));
    assert!(open_copy(b, &file, PASSWORD, Some(&part)).is_ok());
    b.s.sync_now(b.v).unwrap();
    b.tick(2_000);
    let (_, server) = stored(&k.a);
    assert!(!matches!(
        b.s.open_bytes(&server, &alone, false),
        Some(Ok(_))
    ));
}

#[test]
fn syn03_12_c2br3_1_the_copy_sheet_never_takes_a_key_of_the_part_alone() {
    the_part_alone_never_takes_the_key("c2br3-1-copy", false);
}

#[test]
fn syn03_12_c2br3_1_the_disk_sheet_never_takes_a_key_of_the_part_alone() {
    the_part_alone_never_takes_the_key("c2br3-1-disk", true);
}

/// SYN-03.12 (C1R3B-02, C1R4-01): the way back keeps only the linked vault's part.
/// With the device store emptied, another vault at A's linked path, keyed by the
/// password and its own key file K, is not the file as it was last synced: the
/// unlock fails closed with `MSG-SYNC-PART-UNREAD`, and K is not kept as the part.
#[test]
fn syn03_12_c1r3b_02_another_vault_at_the_linked_path_gives_no_part() {
    let l = Linked::new("c1r3b-02-other");
    let a = &l.a;
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    let k = [0x29u8; 32];
    let key = a.dir.join("own.larsalkey");
    std::fs::write(&key, k).unwrap();
    let other = resaved_with(PASSWORD, Some(&k), |v| {
        v.root.uuid = Uuid([0x29; 16]);
    });
    std::fs::write(l.path(), other).unwrap();
    let got =
        a.s.unlock(a.v, Some(PASSWORD.into()), Some(key.display().to_string()))
            .unwrap();
    assert_eq!(unlock_id(got), "MSG-SYNC-PART-UNREAD");
    assert!(
        a.s.sync_with(|i| i.device_store.is_empty()),
        "another vault's key file became the part"
    );
}

/// Runs and saves as Checker 2's probes 15 and 18 do after an unlock that opened:
/// Sync now and a tick, the server sheet or a save, another Sync now and a tick.
fn runs_after(a: &Mac) {
    a.s.sync_now(a.v).unwrap();
    a.tick(2_000);
    let _ = a.s.sync_open_copy(a.v, PASSWORD.into());
    let _ = a.s.save(a.v);
    a.s.sync_now(a.v).unwrap();
    a.tick(2_000);
}

/// SYN-03.12 (C1R4-01, C2R4-1; Checker 2's c2r4_probe15): the same vault (same root)
/// at A's linked path, keyed by the password and a key file K this Mac never kept,
/// is not the file as it was last synced. With the part kept K is another key file;
/// with the device store emptied the unlock fails closed: `MSG-SYNC-PART-UNREAD`,
/// the vault stays locked, the store keeps nothing, nothing is sent, and the server
/// copy still opens with the real part. The last-synced file put back opens with the
/// password and the saved part, which the store keeps again.
#[test]
fn syn03_12_c1r4_01_another_key_file_of_the_same_vault_fails_closed() {
    let (_app, proxy, address, a) = unlinked("c1r4-01-k");
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let k = [0x37u8; 32];
    let key = a.dir.join("other.larsalkey");
    std::fs::write(&key, k).unwrap();
    a.s.lock(a.v).unwrap();
    let path = a.dir.join("Personal.larsalvault");
    let real = std::fs::read(&path).unwrap();
    std::fs::write(
        &path,
        resaved_with(PASSWORD, Some(&k), |v| v.root.uuid = root),
    )
    .unwrap();
    let typed = || Some(key.display().to_string());
    let kept = a.s.unlock(a.v, Some(PASSWORD.into()), typed()).unwrap();
    assert_eq!(unlock_id(kept), "MSG-SYNC-PART-OTHER");
    a.s.sync_with(|i| i.device_store.clear());
    let puts = proxy.count("PUT");
    let got = a.s.unlock(a.v, Some(PASSWORD.into()), typed()).unwrap();
    let opened = got == crate::session::UnlockResult::Unlocked;
    if opened {
        runs_after(&a);
        a.s.lock(a.v).unwrap();
    }
    let took_k =
        a.s.sync_with(|i| i.device_store.values().any(|p| p.expose() == &k[..]));
    assert!(!took_k, "K became the part");
    assert_eq!(proxy.count("PUT"), puts, "no PUT");
    let (_, server) = stored(&a);
    assert!(open_copy(&a, &server, PASSWORD, Some(&part)).is_ok());
    assert!(open_copy(&a, &server, PASSWORD, Some(&k)).is_err());
    assert!(!opened, "{got:?}");
    assert_eq!(unlock_id(got), "MSG-SYNC-PART-UNREAD");
    assert!(a.s.with_vault(a.v, |_| Ok(())).is_err(), "still locked");

    std::fs::write(&path, &real).unwrap();
    assert!(unlocked_ok(
        a.s.unlock(
            a.v,
            Some(PASSWORD.into()),
            Some(saved.display().to_string())
        )
        .unwrap()
    ));
    assert!(a.s.sync_with(|i| i.device_store.values().any(|p| p.expose() == &part[..])));
    a.tick(0);
    assert_eq!(a.status(), Some(SyncStatus::Synced));
}

/// SYN-03.3, LD-267 (2) (C1R4-01, C2R4-1; Checker 2's c2r4_probe18): K1 retired
/// before the put, so the part is K2. An old copy under `demo` and K1 at the linked
/// path, the device store emptied: the unlock with `demo` and K1 fails closed, K1 is
/// not kept, nothing is sent, and the server copy opens with the part, not with K1.
#[test]
fn syn03_3_c1r4_01_a_key_file_this_mac_retired_fails_closed() {
    let (_app, proxy, address, a) = unlinked("c1r4-01-k1");
    let vs = crate::vault_settings::VaultSettings::new(a.s.clone(), a.v);
    let (k1, k2) = ([0x61u8; 32], [0x62u8; 32]);
    let (f1, f2) = (a.dir.join("k1.larsalkey"), a.dir.join("k2.larsalkey"));
    std::fs::write(&f1, k1).unwrap();
    std::fs::write(&f2, k2).unwrap();
    vs.choose_key_file(f1.display().to_string(), vec![])
        .unwrap();
    a.save();
    let path = a.dir.join("Personal.larsalvault");
    let old = std::fs::read(&path).unwrap();
    vs.choose_key_file(f2.display().to_string(), vec![])
        .unwrap();
    a.save();
    put(&a, &address);
    a.tick(0);
    assert_eq!(a.part(), k2);
    a.s.lock(a.v).unwrap();
    std::fs::write(&path, &old).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    let puts = proxy.count("PUT");
    let got =
        a.s.unlock(a.v, Some(PASSWORD.into()), Some(f1.display().to_string()))
            .unwrap();
    let opened = got == crate::session::UnlockResult::Unlocked;
    if opened {
        runs_after(&a);
        a.s.lock(a.v).unwrap();
    }
    let took_k1 =
        a.s.sync_with(|i| i.device_store.values().any(|p| p.expose() == &k1[..]));
    assert!(!took_k1, "the retired K1 became the part");
    assert_eq!(proxy.count("PUT"), puts, "no PUT");
    let (_, server) = stored(&a);
    assert!(open_copy(&a, &server, PASSWORD, Some(&k2)).is_ok());
    assert!(open_copy(&a, &server, PASSWORD, Some(&k1)).is_err());
    assert!(!opened, "{got:?}");
    assert_eq!(unlock_id(got), "MSG-SYNC-PART-UNREAD");
}

/// SYN-03.12, LD-264 (C1R4-01; Checker 1's c1r4_p2): A's linked file replaced by the
/// same vault under the password and another key file Y (an old backup, or a 2099
/// key time), the device store emptied. The unlock with the password and Y fails
/// closed before any key work: Y is not kept, no key time of that file counts as
/// seen, nothing is sent, the server copy opens with the part. With the real file
/// back, the password and the saved part open it and the store keeps the part.
fn c1r4_01_another_key_file(tag: &str, future: bool) {
    let l = Linked::new(tag);
    let a = &l.a;
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let real = l.file();
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    let y = [0x44u8; 32];
    let ypath = a.dir.join("old.larsalkey");
    std::fs::write(&ypath, y).unwrap();
    std::fs::write(
        l.path(),
        resaved_with(PASSWORD, Some(&y), |v| {
            if future {
                v.meta.master_key_changed = year_2099();
            }
        }),
    )
    .unwrap();
    let puts = l.proxy.count("PUT");
    let got =
        a.s.unlock(
            a.v,
            Some(PASSWORD.into()),
            Some(ypath.display().to_string()),
        )
        .unwrap();
    let opened = got == crate::session::UnlockResult::Unlocked;
    if opened {
        runs_after(a);
        a.s.lock(a.v).unwrap();
    }
    let took_y =
        a.s.sync_with(|i| i.device_store.values().any(|p| p.expose() == &y[..]));
    assert!(!took_y, "{tag}: Y became the part");
    assert_eq!(l.proxy.count("PUT"), puts, "{tag}: no PUT");
    let (_, server) = l.stored();
    assert!(open_copy(a, &server, PASSWORD, Some(&part)).is_ok());
    assert!(!opened, "{tag}: {got:?}");
    assert_eq!(unlock_id(got), "MSG-SYNC-PART-UNREAD");
    assert!(a.s.key_floor(root) < year_2099(), "{tag}: a key time seen");

    std::fs::write(l.path(), &real).unwrap();
    assert!(!a.unlocks(PASSWORD), "{tag}: the password alone");
    assert!(unlocked_ok(
        a.s.unlock(
            a.v,
            Some(PASSWORD.into()),
            Some(saved.display().to_string())
        )
        .unwrap()
    ));
    let label = a.s.sync_with(|i| i.state.parts[0].label.clone());
    let kept =
        a.s.sync_with(|i| i.device_store.get(&label).map(|p| p.expose().to_vec()));
    assert_eq!(kept, Some(part), "{tag}");
}

#[test]
fn syn03_12_c1r4_01_an_old_file_under_another_key_file_fails_closed() {
    c1r4_01_another_key_file("c1r4-01-old", false);
}

#[test]
fn syn03_12_c1r4_01_a_2099_file_under_another_key_file_fails_closed() {
    c1r4_01_another_key_file("c1r4-01-2099", true);
}

/// SYN-03.5 step 2, F-321 (C1R4-01, the belt): an unlock holds the part, then the
/// device store holds another key file under the link's label, or none. A saved edit
/// never goes up: `MSG-SYNC-LOCAL-FILE`, no PUT, the server's bytes as they were.
/// With the part back in the store the edit goes up.
#[test]
fn syn03_5_c1r4_01_an_unlock_key_not_the_stores_part_never_goes_up() {
    let l = Linked::new("c1r4-01-belt");
    let a = &l.a;
    let label = a.s.sync_with(|i| i.state.parts[0].label.clone());
    let part = a.part();
    let first = a.titles()[0].clone();
    a.rename(&first, "Renamed while the store changed");
    a.s.sync_with(|i| {
        i.device_store
            .insert(label.clone(), SecretBytes::new(vec![0x44; 32]));
    });
    l.refuses_at_a_run();
    a.s.sync_with(|i| i.device_store.clear());
    l.refuses_at_a_run();
    a.s.sync_with(|i| i.device_store.insert(label, SecretBytes::new(part)));
    l.uploads_at_a_run(2);
}

/// SYN-03.12 (C1R4-01): the way back after the cost question (APP-06.14). The file
/// as it was last synced is in the ask band: the unlock with the password and the
/// saved part asks, and the answer opens it and keeps the part. A file swapped in at
/// the path before the answer fails closed and keeps nothing.
#[test]
fn syn03_12_c1r4_01_the_way_back_after_the_cost_question() {
    let l = Linked::new("c1r4-01-ask");
    let a = &l.a;
    let part = a.part();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let asks = |v: &mut Vault| {
        v.encryption.kdf = larsal_model::Kdf::Argon2 {
            kind: larsal_model::Argon2Kind::Id,
            iterations: 1,
            memory_kib: 8 * 129,
            lanes: 129,
        };
    };
    let synced = a.resaved(PASSWORD, asks);
    let swapped = a.resaved(PASSWORD, |v| {
        asks(v);
        assert!(renamed_first(&mut v.root, "Swapped in"));
    });
    a.s.lock(a.v).unwrap();
    std::fs::write(l.path(), &synced).unwrap();
    a.s.sync_with(|i| {
        i.state.links[0].local_sha = larsal_sync::sync::hash(&synced);
        i.save();
        i.device_store.clear();
    });
    let typed = || Some(saved.display().to_string());
    let asked = a.s.unlock(a.v, Some(PASSWORD.into()), typed()).unwrap();
    assert!(
        matches!(asked, crate::session::UnlockResult::Ask { .. }),
        "{asked:?}"
    );
    std::fs::write(l.path(), &swapped).unwrap();
    let got = a.s.approve_unlock(a.v).unwrap();
    assert_eq!(unlock_id(got), "MSG-SYNC-PART-UNREAD");
    assert!(a.s.sync_with(|i| i.device_store.is_empty()));

    std::fs::write(l.path(), &synced).unwrap();
    let asked = a.s.unlock(a.v, Some(PASSWORD.into()), typed()).unwrap();
    assert!(
        matches!(asked, crate::session::UnlockResult::Ask { .. }),
        "{asked:?}"
    );
    assert_eq!(
        a.s.approve_unlock(a.v).unwrap(),
        crate::session::UnlockResult::Unlocked
    );
    assert!(a.s.sync_with(|i| i.device_store.values().any(|p| p.expose() == &part[..])));
}

/// MOD-11.31, LD-267 (2) (C1R4-02; Checker 1's c1r4_p1): `demo` retired before the
/// put; the vault stays unlocked and linked, then the device store refuses the read
/// or has lost the item. A server copy under `demo` plus the part, with a 2099 key
/// time and `demo` given in the server sheet, is the old key's (`OldKey`), and after
/// the save `demo` never opens the vault; `demo2` does.
fn c1r4_02_server_road(tag: &str, refuse: bool) {
    let (_app, _proxy, address, a) = unlinked(tag);
    a.change_password(DEMO2);
    put(&a, &address);
    a.tick(0);
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let planted = resaved_with(PASSWORD, Some(&part), |v| {
        v.root.uuid = root;
        v.meta.master_key_changed = year_2099();
    });
    a.s.sync_with(|i| {
        if refuse {
            i.store_refuses = true;
        } else {
            i.device_store.clear();
        }
    });
    a.s.sync_open_copy(a.v, PASSWORD.into()).unwrap();
    let got = a.s.merge_server(a.v, &planted, 9);
    assert!(matches!(got, Merge::OldKey), "{tag}: {got:?}");
    let _ = a.s.save(a.v);
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| {
        i.store_refuses = false;
        let label = i.state.parts[0].label.clone();
        i.device_store.insert(label, SecretBytes::new(part));
    });
    assert!(
        !a.unlocks(PASSWORD),
        "{tag}: the retired password came back"
    );
    assert!(a.unlocks(DEMO2), "{tag}");
}

#[test]
fn syn03_8_c1r4_02_the_server_road_keeps_a_retired_key_while_the_store_refuses() {
    c1r4_02_server_road("c1r4-02-refuse", true);
}

#[test]
fn syn03_8_c1r4_02_the_server_road_keeps_a_retired_key_with_the_store_item_gone() {
    c1r4_02_server_road("c1r4-02-gone", false);
}

/// A Finder copy of the vault file in `dir`, opened by `s` with the password and the
/// `saved` part, given in the copy sheet only the saved part for a copy keyed by
/// `part` alone: the sheet's answer, after which the Finder copy, saved and locked,
/// must not open with the part alone.
fn part_alone_in_a_finder_copy(
    s: &Session,
    dir: &Path,
    saved: &Path,
    part: &[u8],
    tag: &str,
) -> Result<crate::copies::CopyState, LarsalError> {
    let one = dir.join(format!("Personal finder {tag}.larsalvault"));
    std::fs::copy(dir.join("Personal.larsalvault"), &one).unwrap();
    let key = Some(saved.display().to_string());
    let v1 = s.open(one.display().to_string()).unwrap();
    assert!(unlocked_ok(
        s.unlock(v1, Some(PASSWORD.into()), key.clone()).unwrap()
    ));
    let copy = dir.join(format!("Personal part alone {tag}.larsalvault"));
    std::fs::write(&copy, planted("", Some(part))).unwrap();
    let got = s.merge_copy(v1, copy.display().to_string(), None, key.clone(), false);
    let _ = s.save(v1);
    s.lock(v1).unwrap();
    assert!(
        !unlocked_ok(s.unlock(v1, None, key).unwrap()),
        "{tag}: the Finder copy took a key of the part alone"
    );
    got
}

/// SYN-03.12 (C1R4-04; Checker 1's c1r4_p3): a Finder copy of A's linked vault while
/// the device store has no item. In the copy sheet a copy keyed by the part alone
/// gives `MSG-SYNC-PART-UNREAD` and no key; a copy under the Finder copy's own key
/// gives its content and the same words. In the disk sheet the Finder copy's file
/// keyed by the part alone gives the same words, and the vault keeps its password and
/// its key file; a version under the vault's own key gives its content and the same
/// words.
#[test]
fn syn03_12_c1r4_04_a_finder_copy_with_the_part_unread_fails_closed() {
    let l = Linked::new("c1r4-04");
    let a = &l.a;
    let part = a.part();
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    a.s.lock(a.v).unwrap();
    a.s.sync_with(|i| i.device_store.clear());
    let got = part_alone_in_a_finder_copy(&a.s, &a.dir, &saved, &part, "c1r4-04");
    assert!(refused_with(got, crate::sync::PART_UNREAD.1));

    let key = Some(saved.display().to_string());
    let one = a.dir.join("Personal finder content.larsalvault");
    std::fs::copy(l.path(), &one).unwrap();
    let v1 = a.s.open(one.display().to_string()).unwrap();
    assert!(unlocked_ok(
        a.s.unlock(v1, Some(PASSWORD.into()), key.clone()).unwrap()
    ));
    let title = "Renamed in a copy under the Finder copy's key";
    let copy = a.dir.join("Personal content copy.larsalvault");
    std::fs::write(
        &copy,
        resaved_with(PASSWORD, Some(&part), |v| {
            v.root.uuid = root;
            assert!(renamed_first(&mut v.root, title));
        }),
    )
    .unwrap();
    let got = a.s.merge_copy(
        v1,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        key.clone(),
        false,
    );
    assert!(refused_with(got, crate::sync::PART_UNREAD.1));
    let titles: Vec<String> =
        a.s.list(v1, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.title)
            .collect();
    assert!(titles.contains(&title.to_owned()), "the content merge");
    let st = a.s.save(v1).unwrap();
    assert_eq!((st.changes, st.failure), (0, None));

    let two = a.dir.join("Personal finder disk.larsalvault");
    std::fs::copy(l.path(), &two).unwrap();
    let v2 = a.s.open(two.display().to_string()).unwrap();
    assert!(unlocked_ok(
        a.s.unlock(v2, Some(PASSWORD.into()), key.clone()).unwrap()
    ));
    std::fs::write(&two, planted("", Some(&part))).unwrap();
    assert_eq!(a.s.check_disk(v2).unwrap(), DiskEvent::NewKey);
    let got =
        a.s.resolve_disk_with_key(v2, DiskChoice::Merge, None, key.clone());
    assert!(refused_with(got, crate::sync::PART_UNREAD.1));
    {
        let saver = a.s.with_edit_state(v2, |e| e.saver.clone()).unwrap();
        let sv = saver.lock().unwrap();
        assert!(sv.password.is_some(), "the Finder copy keeps its password");
        assert_eq!(sv.key_file.as_ref().unwrap().key().expose(), &part[..]);
    }
    let title = "Renamed in a disk version under the Finder copy's key";
    std::fs::write(
        &two,
        resaved_with(PASSWORD, Some(&part), |v| {
            v.root.uuid = root;
            assert!(renamed_first(&mut v.root, title));
        }),
    )
    .unwrap();
    let got = a.s.resolve_disk_with_key(v2, DiskChoice::Merge, None, key);
    assert!(refused_with(got, crate::sync::PART_UNREAD.1));
    let titles: Vec<String> =
        a.s.list(v2, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.title)
            .collect();
    assert!(
        titles.contains(&title.to_owned()),
        "the disk version's content"
    );
}

/// A second Mac B, linked by its first run, its part saved as a key file and locked:
/// the app, A, B, the saved file and the part. B retired no key.
fn second_saved(tag: &str) -> (LarsalServer, Mac, Mac, PathBuf, Vec<u8>) {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, &format!("{tag}-a"));
    put(&a, &address);
    a.tick(0);
    let b = second(&app, &address, app.pin, &a, &format!("{tag}-b"));
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    let saved = b.dir.join("saved.larsalkey");
    assert_eq!(
        b.s.sync_save_part(b.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let part = b.part();
    b.s.lock(b.v).unwrap();
    (app, a, b, saved, part)
}

/// SYN-03.12 (C1R4-05, mutant M17): with the part in the device store, a Finder copy
/// (no pointer) given the part alone in the copy sheet is known by its bytes:
/// `MSG-SYNC-TYPED-KEPT` and no key.
#[test]
fn syn03_12_c1r4_05_a_finder_copy_knows_the_part_by_its_bytes() {
    let (_app, _a, b, saved, part) = second_saved("c1r4-05-m17");
    let got = part_alone_in_a_finder_copy(&b.s, &b.dir, &saved, &part, "m17");
    assert!(refused_with(got, crate::sync::TYPED_KEPT.1));
}

/// MOD-11.31, C1R3B-01 (C1R4-05, mutant M2): this Mac's vault state does not read
/// after a restart; the sync state's pointer and link still name the part's label and
/// hold the records, so a copy under `demo`, retired before the put, plus the part is
/// the old key's.
#[test]
fn syn03_3_c1r4_05_a_lost_vault_state_still_knows_the_part() {
    let (_app, _proxy, a, root, saved) = retired_before_the_put("c1r4-05-m2");
    let label = a.s.sync_with(|i| i.state.parts[0].label.clone());
    let part = a.s.part_get(&label).unwrap().expose().to_vec();
    std::fs::write(a.dir.join("settings/vault-state_debug.json"), b"not json").unwrap();
    let a2 = restart(&a, None);
    assert!(a2.s.part_labels(root).is_empty());
    assert_eq!(a2.s.sync_retired(root).len(), 2);
    old_key_in_the_copy_sheet(&a2, &a.dir, &saved, &part, "m2");
}

/// After a restart `m` unlocks its vault with `demo2` and the `saved` part; the copy
/// sheet given `demo` and the part for a copy under them is `OldKey`, and after a
/// save `demo` never opens the vault.
fn old_key_in_the_copy_sheet(m: &Mac, dir: &Path, saved: &Path, part: &[u8], tag: &str) {
    let key = Some(saved.display().to_string());
    assert!(unlocked_ok(
        m.s.unlock(m.v, Some(DEMO2.into()), key.clone()).unwrap()
    ));
    let copy = dir.join(format!("Personal ({tag}).larsalvault"));
    std::fs::write(&copy, planted(PASSWORD, Some(part))).unwrap();
    let got = m.s.merge_copy(
        m.v,
        copy.display().to_string(),
        Some(PASSWORD.into()),
        key.clone(),
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::OldKey)),
        "{tag}: {got:?}"
    );
    m.s.save(m.v).unwrap();
    m.s.lock(m.v).unwrap();
    assert!(!unlocked_ok(
        m.s.unlock(m.v, Some(PASSWORD.into()), key).unwrap()
    ));
}

/// MOD-11.31, C1R3B-01 (C2R4-3, mutants D16 and M20): vault state keeps the part's
/// label at the put, before any run. The sync state then does not read after a
/// restart: a copy under `demo`, retired before the put, plus the part is the old
/// key's.
#[test]
fn syn03_3_c1r4_05_the_put_names_the_part_before_any_run() {
    let (_app, _proxy, address, a) = unlinked("c1r4-05-d16");
    a.change_password(DEMO2);
    put(&a, &address);
    assert!(a.runs().is_empty(), "no run yet");
    let root = a.s.with_vault(a.v, |v| Ok(v.root.uuid)).unwrap();
    let part = a.part();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    a.s.lock(a.v).unwrap();
    std::fs::write(a.dir.join("settings/sync-state_debug.json"), b"not json").unwrap();
    let a2 = restart(&a, None);
    assert_eq!(a2.s.retired_records(root).len(), 2);
    old_key_in_the_copy_sheet(&a2, &a.dir, &saved, &part, "d16");
}

/// SYN-03.12, C1R3B-01 (C1R4-05, mutant M19): a second Mac never puts; its first run
/// names the part's label in its vault state. Its sync state then does not read after
/// a restart: a Finder copy given the part alone gets `MSG-SYNC-TYPED-KEPT`.
#[test]
fn syn03_12_c1r4_05_a_second_macs_first_run_names_the_part() {
    let (_app, _a, b, saved, part) = second_saved("c1r4-05-m19");
    std::fs::write(b.dir.join("settings/sync-state_debug.json"), b"not json").unwrap();
    let b2 = restart(&b, None);
    let got = part_alone_in_a_finder_copy(&b2.s, &b.dir, &saved, &part, "m19");
    assert!(refused_with(got, crate::sync::TYPED_KEPT.1));
}

/// SYN-03.12 (C2R4-3, mutant D18): a vault with a hardware key, no password and its
/// part keeps a typed factor, the hardware key: a sibling copy of its file given the
/// saved part in the copy sheet merges as usual.
#[test]
fn syn03_12_c1r4_05_a_hardware_key_is_a_typed_factor_in_the_copy_sheet() {
    let (_app, _proxy, address, a) = unlinked("c1r4-05-d18");
    let vs = crate::vault_settings::VaultSettings::new(a.s.clone(), a.v);
    assert_eq!(
        vs.set_security_key(Some(crate::hwkey::tests::PICK), vec![])
            .unwrap(),
        Outcome::Done
    );
    a.save();
    put(&a, &address);
    assert_eq!(remove_password(&a), Outcome::Done);
    a.save();
    let saved = a.dir.join("saved.larsalkey");
    assert_eq!(
        a.s.sync_save_part(a.v, saved.display().to_string())
            .unwrap(),
        Outcome::Done
    );
    let copy = a.dir.join("Personal (hardware).larsalvault");
    std::fs::copy(a.dir.join("Personal.larsalvault"), &copy).unwrap();
    let got = a.s.merge_copy(
        a.v,
        copy.display().to_string(),
        None,
        Some(saved.display().to_string()),
        false,
    );
    assert!(
        matches!(got, Ok(crate::copies::CopyState::Merged)),
        "{got:?}"
    );
}

/// SYN-03.2 (C1R4-03; Checker 1's c1r4_p4): B downloads, with the part in its device
/// store, and asks for the same server vault again at the same path, which exists:
/// that download is refused and B's first download keeps its link; its first run
/// links it.
#[test]
fn syn03_2_c1r4_03_a_refused_second_download_keeps_the_waiting_link() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1r4-03-a");
    put(&a, &address);
    a.tick(0);
    let (mut b, path, id) = second_without_the_part(&app, &address, &a, "c1r4-03-b");
    copy_parts(&a, &b);
    let again =
        b.s.sync_download(address.clone(), id, path.display().to_string());
    assert!(again.is_err(), "the file exists");
    assert_eq!(b.s.sync_with(|i| i.state.links.len()), 1);
    b.open(&path);
    b.tick(0);
    assert_eq!(b.status(), Some(SyncStatus::Synced));
    assert!(b.s.sync_server_vaults(address).unwrap()[0].linked);
}

/// SYN-03.2 (C1R4-05, mutant M14): a new download replaces only the waiting link of
/// its own server vault: B's download of A's other vault keeps its link.
#[test]
fn syn03_2_c1r4_05_a_new_download_keeps_another_server_vaults_link() {
    let app = larsal_server();
    let address = app.address();
    let a = first(&address, app.pin, "c1r4-05-m14-a");
    put(&a, &address);
    a.tick(0);
    let work = a.dir.join("Work.larsalvault");
    std::fs::write(
        &work,
        resaved_with(PASSWORD, None, |v| v.root.uuid = Uuid([0x14; 16])),
    )
    .unwrap();
    let w = a.s.open(work.display().to_string()).unwrap();
    assert!(unlocked_ok(
        a.s.unlock(w, Some(PASSWORD.into()), None).unwrap()
    ));
    assert_eq!(
        a.s.sync_put_vault(w, address.clone()).unwrap().status,
        SyncStatus::Synced
    );
    let (b, _path, id) = second_without_the_part(&app, &address, &a, "c1r4-05-m14-b");
    let other =
        b.s.sync_server_vaults(address.clone())
            .unwrap()
            .into_iter()
            .find(|v| v.id != id)
            .unwrap()
            .id;
    let other_path = b.dir.join("Other.larsalvault");
    b.s.sync_download(address.clone(), other, other_path.display().to_string())
        .unwrap();
    let again = b.dir.join("Personal again.larsalvault");
    b.s.sync_download(address, id, again.display().to_string())
        .unwrap();
    let files: Vec<String> =
        b.s.sync_with(|i| i.state.links.iter().map(|l| l.file.clone()).collect());
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(files.iter().any(|f| f.ends_with("Other.larsalvault")));
    assert!(
        files
            .iter()
            .any(|f| f.ends_with("Personal again.larsalvault"))
    );
    assert!(!files.iter().any(|f| f.ends_with("/Personal.larsalvault")));
}
