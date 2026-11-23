//! E17-S2's client checks of SYN-05 and SYN-06.11 (with SYN-06.14): two
//! test clients, E with a new account's keys and N with none, against
//! Larsal's server in process with a release server's rule
//! (`larsal_server_strict`), through the test proxy or a relay in the
//! middle (`Scripted::relay`) where a test reads or changes what passes.
//! Device stores are maps (`Memory`, LD-317 (2)); device keys are the test
//! seam's. The clients' clocks are test clocks; the server's clock is fixed
//! and moved a minute on before the sign-in routes are used again
//! (SYN-01.12); no test sleeps or reads the wall clock for a result.
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use crate::account::{Kit, make_blob};
use crate::state::{Link, Measures};
use crate::sync::{Local, Merge, Status, Unproven, first_upload, hash, run};
use crate::test_server::{
    LarsalServer, Memory, Request, Scripted, TestClock, approve, larsal_server_strict,
};
use larsal_crypto::account::AccountKeys;
use larsal_crypto::base64::{self, Form};
use larsal_crypto::wrap_record::WrapRecord;
use larsal_model::{Argon2Kind, FileVersion, Kdf, Time, Uuid};
use larsal_platform::device_key::DeviceKey;
use larsal_proto::account::AccountKeys as KeysRecord;
use larsal_proto::messages::{AccountCreated, VaultId};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const PASSWORD: &str = "demo-approval-pw";
/// The demo vault of testdata (master password `demo-pass-1`, its one entry
/// "Demo login", `demo-user`, `demo-entry-pass-1`).
const VAULT: &[u8] = include_bytes!("../../../../testdata/password-only.larsalvault");

fn password() -> SecretString {
    SecretString::new(PASSWORD.to_owned())
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

/// A value raw, as upper and lower hex, padded and URL base64 (LD-426).
fn encoded(value: &[u8]) -> Vec<Vec<u8>> {
    let hex = hex(value);
    vec![
        value.to_vec(),
        hex.to_uppercase().into_bytes(),
        hex.into_bytes(),
        base64::encode(Form::Padded, value).into_bytes(),
        base64::encode(Form::Url, value).into_bytes(),
    ]
}

/// Every file under `dir`, with its bytes.
fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out
}

fn measures() -> Measures {
    Measures {
        newest: Time(1_000),
        version: FileVersion { major: 4, minor: 1 },
        kdf: Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: 65_536,
            lanes: 2,
        },
    }
}

/// The open vault of a Mac: a merge takes the server copy as it is.
struct OpenVault {
    file: Mutex<Vec<u8>>,
    merges: AtomicUsize,
}

impl OpenVault {
    fn new(file: &[u8]) -> Self {
        Self {
            file: Mutex::new(file.to_vec()),
            merges: AtomicUsize::new(0),
        }
    }
}

impl Local for OpenVault {
    fn read(&self) -> Option<Result<(Vec<u8>, Measures), Unproven>> {
        Some(Ok((self.file.lock().unwrap().clone(), measures())))
    }

    fn merge(&self, server: &[u8], _version: u64) -> Merge {
        self.merges.fetch_add(1, Ordering::SeqCst);
        *self.file.lock().unwrap() = server.to_vec();
        Merge::Done {
            copy: measures(),
            result: measures(),
            changed: false,
            saved: server.to_vec(),
        }
    }
}

fn link(c: &Server<DeviceKey>, vault: VaultId) -> Link {
    Link {
        server: c.address().to_owned(),
        vault_id: vault,
        file: "demo.larsalvault".into(),
        root: Uuid([1; 16]),
        highest: 0,
        server_sha: [0; 32],
        local_sha: [0; 32],
        seen: measures(),
    }
}

/// A strict server, the proxy or relay before it, the server's clock:
/// `t0`, a minute on for each [`World::later`], plus the seconds skipped.
struct World {
    app: LarsalServer,
    proxy: Scripted,
    t0: u64,
    minute: Cell<u64>,
    skipped: Cell<u64>,
}

/// Mac E: a client with a new account and its keys.
struct Mac {
    c: Server<DeviceKey>,
    keep: Memory,
    made: AccountCreated,
    kit: Kit,
}

impl World {
    fn new(proxy_of: impl FnOnce(&LarsalServer) -> Scripted) -> Self {
        let app = larsal_server_strict();
        let t0 = now_seconds();
        app.seams.set_clock(t0);
        let proxy = proxy_of(&app);
        Self {
            app,
            proxy,
            t0,
            minute: Cell::new(0),
            skipped: Cell::new(0),
        }
    }

    fn plain() -> Self {
        Self::new(Scripted::proxy)
    }

    /// The server's clock now, in seconds.
    fn server_now(&self) -> u64 {
        self.t0 + 61 * self.minute.get() + self.skipped.get()
    }

    /// A new minute on the server's clock (SYN-01.12's sign-in bucket).
    fn later(&self) {
        self.minute.set(self.minute.get() + 1);
        self.app.seams.set_clock(self.server_now());
    }

    /// `seconds` on, on the server's clock only (the clients' own clocks
    /// stay).
    fn skip(&self, seconds: u64) {
        self.skipped.set(self.skipped.get() + seconds);
        self.app.seams.set_clock(self.server_now());
    }

    fn client(&self) -> Server<DeviceKey> {
        let mut c = Server::new(&self.proxy.address(), self.proxy.pin).unwrap();
        c.sign_for_port(self.app.port);
        c
    }

    /// Mac E: sign-up, then the account keys with [`PASSWORD`].
    fn e(&self) -> Mac {
        self.later();
        let mut c = self.client();
        let made = c.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
        let keep = Memory::default();
        let kit = c
            .sign_up_account(&made.account_id, &password(), &keep)
            .unwrap();
        Mac { c, keep, made, kit }
    }

    /// The requests and replies seen so far.
    fn seen(&self) -> Vec<(Request, Vec<u8>)> {
        self.proxy.seen.lock().unwrap().clone()
    }
}

/// The reply's body after its head.
fn body_of(reply: &[u8]) -> &[u8] {
    let at = reply.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    &reply[at..]
}

fn waiting<W, R>(p: Polled<W, R>) -> W {
    match p {
        Polled::Waiting(w) => w,
        Polled::Ready(_) => panic!("ready too early"),
    }
}

fn ready<W, R>(p: Polled<W, R>) -> R {
    match p {
        Polled::Ready(r) => r,
        Polled::Waiting(_) => panic!("still waiting"),
    }
}

/// N's view of the request: its requests carry the approval code.
fn is_n(q: &Request) -> bool {
    q.header("authorization")
        .is_some_and(|a| a.starts_with("Approval "))
}

/// SYN-05.1, SYN-05.4, T01; SYN-06.11, SYN-06 T09: E and N through the
/// test proxy. Both show the same 6 digits, and the code made again from
/// the logged messages is the same; before either user's Codes match
/// nothing is sealed, signed or pinned and `n_R` was drawn once, after the
/// commitment; after both, N holds the account's keys (its pinned identity
/// key is E's), signs in with its own device and syncs E's signed vault.
/// The proxy finds only the code's SHA-256 in `POST /v1/approvals` and the
/// code nowhere but in the `Authorization` line of N's approval requests.
#[test]
#[allow(clippy::too_many_lines)]
fn syn05_t01_syn06_11_t09_one_code_on_both_screens_and_n_joins_and_syncs() {
    let w = World::plain();
    let mut e = w.e();
    let account = e.made.account_id;
    let vault = VaultId::from_bytes([0x61; 16]);
    assert_eq!(first_upload(&mut e.c, &vault, VAULT), Ok(1));
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(1_000);
    let before = probe::counts();

    let approver = e.c.approval_start(&*clock).unwrap();
    let typed = approver.code();
    let groups: Vec<&str> = typed.expose().split('-').collect();
    assert_eq!(groups.len(), 7, "26 characters in groups of 4");
    assert!(groups[..6].iter().all(|g| g.len() == 4) && groups[6].len() == 2);
    // Typed case-blind with spaces: the same code.
    let retyped = SecretString::new(typed.expose().to_lowercase().replace('-', " "));
    let claimant = n
        .approval_claim(&retyped, DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    assert_eq!(
        probe::counts()[0],
        before[0],
        "no n_R before the commitment"
    );
    let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
    assert_eq!(
        probe::counts()[0],
        before[0] + 1,
        "n_R drawn once it was held"
    );
    let n_side = ready(claimant.poll(&mut n, &*clock).unwrap());
    let e_side = ready(approver.poll(&mut e.c, &*clock).unwrap());
    assert_eq!(e_side.code(), n_side.code(), "SYN-05 T01: one code");
    let code = e_side.code();
    assert!(
        code.len() == 7
            && code.as_bytes()[3] == b' '
            && code.bytes().filter(u8::is_ascii_digit).count() == 6,
        "{code}"
    );
    assert_eq!(
        &probe::counts()[1..],
        &before[1..],
        "nothing sealed, signed or pinned before Codes match"
    );

    // The code again from the logged messages (SYN-05 T01).
    let seen = w.seen();
    let find = |pred: &dyn Fn(&Request) -> bool| seen.iter().find(|(q, _)| pred(q)).unwrap();
    let (_, claimed) = find(&|q| q.path == "/v1/approvals/claim");
    let claimed = ApprovalClaimed::read(body_of(claimed)).unwrap();
    let step = |tail: &'static str| {
        move |q: &Request| q.path.starts_with("/v1/approvals/") && q.path.ends_with(tail)
    };
    let (commit_q, _) = find(&step("/commit"));
    let (keys_q, _) = find(&step("/keys"));
    let (reveal_q, _) = find(&step("/reveal"));
    let commit = CompareCommit::read(&commit_q.body).unwrap().commit;
    let m2 = CompareKeys::read(&keys_q.body, KEYS_R).unwrap();
    let m3 = CompareKeys::read(&reveal_q.body, KEYS_C).unwrap();
    let ctx = wire::ctx(&account, &claimed.approval_id).unwrap();
    assert_eq!(
        wire::commitment(&ctx, &m3.keys, &m3.nonce)
            .unwrap()
            .expose(),
        commit
    );
    let again = wire::code(&ctx, &m2.keys, &m3.keys, &m2.nonce, &m3.nonce).unwrap();
    assert_eq!(wire::shown(again), code);

    // Codes match on E, then on N.
    e_side.codes_match().seal(&mut e.c, &*clock).unwrap();
    let after = probe::counts();
    assert_eq!((after[1], after[2]), (before[1] + 1, before[2] + 1));
    let sealed = ready(n_side.codes_match().poll(&mut n, &*clock).unwrap());
    let n_keep = Memory::default();
    sealed.finish(&mut n, &password(), &n_keep).unwrap();
    assert_eq!(probe::counts()[3], before[3] + 1, "pinned once, after both");
    assert_eq!(n.account_id(), Some(account));
    let (_, e_keys) = e.c.account.as_ref().unwrap();
    let (_, n_keys) = n.account.as_ref().unwrap();
    assert_eq!(n_keys.identity_public_key(), e_keys.identity_public_key());
    assert_eq!(
        n_keep.get(&n.label(&account)).unwrap().expose(),
        e.keep.get(&e.c.label(&account)).unwrap().expose()
    );

    // N syncs E's signed version.
    let open = OpenVault::new(b"");
    let mut l = link(&n, vault);
    assert_eq!(
        run(&mut n, &mut l, &open, &*clock).status,
        Some(Status::Synced(1_000))
    );
    assert_eq!(*open.file.lock().unwrap(), VAULT);
    assert_eq!(l.highest, 1);

    // The proxy view (SYN-06 T09, ruling (10)).
    let raw = wire::read_code(typed.expose()).unwrap();
    let (create_q, _) = find(&|q| q.method == "POST" && q.path == "/v1/approvals");
    assert_eq!(
        create_q.body,
        format!(
            "{{\"code_hash\":\"{}\"}}",
            base64::encode(Form::Url, &wire::code_hash(&raw).unwrap())
        )
        .into_bytes()
    );
    let flat = typed.expose().replace('-', "");
    let mut forms = encoded(raw.expose());
    forms.push(flat.clone().into_bytes());
    forms.push(flat.to_lowercase().into_bytes());
    forms.push(typed.expose().as_bytes().to_vec());
    let mut n_lines = 0;
    for (q, reply) in &w.seen() {
        let text = String::from_utf8_lossy(&q.raw).into_owned();
        let mut rest = String::new();
        for line in text.split("\r\n") {
            if line.starts_with("Authorization: Approval ")
                || line.starts_with("authorization: Approval ")
            {
                assert!(q.path.starts_with("/v1/approvals/"), "{}", q.path);
                assert_eq!(line.split(' ').nth(2), Some(flat.as_str()));
                n_lines += 1;
            } else {
                rest.push_str(line);
                rest.push_str("\r\n");
            }
        }
        for form in &forms {
            assert!(!has(rest.as_bytes(), form), "{} {}", q.method, q.path);
            assert!(!has(reply, form), "reply to {} {}", q.method, q.path);
        }
    }
    assert!(
        n_lines >= 5,
        "N's claim, commit, polls and reveal: {n_lines}"
    );
}

/// The parts of an approval a relay in the middle learns as they pass, and
/// its own SYN-05 roles.
#[derive(Default)]
struct Middle {
    claimed: Option<ApprovalClaimed>,
    n_device: Option<[u8; DEVICE_KEY]>,
    n_commit: Option<[u8; 32]>,
    n_xwing: Option<Vec<u8>>,
    e_keys: Option<CompareKeys>,
    /// Its own C toward E (SYN-05 T04, SYN-06 T10).
    mine_c: Option<Committer>,
    /// Its own message (2) toward N (SYN-05 T04).
    mine_r: Option<CompareKeys>,
    /// Whether E has answered (SYN-05 T05's changed commitment).
    e_answered: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Attack {
    /// SYN-05 T03: `K_C` changed in message (3).
    SwapRevealKey,
    /// SYN-06 T10: its own C toward E, N's one-request key swapped.
    OwnC,
    /// SYN-05 T04: its own C toward E and its own R toward N.
    Both,
    /// SYN-05 T05: E's view of the commitment changed after E answered.
    OtherCommit,
}

fn ctx_of(m: &Middle) -> Vec<u8> {
    let c = m.claimed.as_ref().unwrap();
    wire::ctx(&c.account_id, &c.approval_id).unwrap()
}

/// A relay that runs `attack` on every approval that passes.
fn relay(attack: Attack) -> World {
    let middle: Arc<Mutex<Middle>> = Arc::default();
    let (m1, m2) = (middle.clone(), middle);
    let (_, own_xwing) = pq::xwing_keypair().unwrap();
    let (_, own_identity) = pq::identity_keypair().unwrap();
    World::new(move |app| {
        Scripted::relay(
            app,
            move |q| {
                let mut m = m1.lock().unwrap();
                if q.method != "POST" {
                    return None;
                }
                if q.path == "/v1/approvals/claim" {
                    *m = Middle {
                        n_device: Some(ApprovalClaim::read(&q.body).unwrap().device_public_key),
                        ..Middle::default()
                    };
                    return None;
                }
                if q.path.ends_with("/commit") {
                    let commit = CompareCommit::read(&q.body).unwrap().commit;
                    m.n_commit = Some(commit);
                    if matches!(attack, Attack::OwnC | Attack::Both) {
                        let keys = wire::keys_c(&m.n_device.unwrap(), &own_xwing).unwrap();
                        let mine = Committer::new(ctx_of(&m), keys).unwrap();
                        let body = CompareCommit {
                            commit: mine.commit().unwrap(),
                        }
                        .to_json();
                        m.mine_c = Some(mine);
                        return Some(body);
                    }
                    return None;
                }
                if q.path.ends_with("/keys") {
                    m.e_keys = Some(CompareKeys::read(&q.body, KEYS_R).unwrap());
                    m.e_answered = true;
                    return None;
                }
                if q.path.ends_with("/reveal") {
                    let mut reveal = CompareKeys::read(&q.body, KEYS_C).unwrap();
                    m.n_xwing = wire::split_keys_c(&reveal.keys).map(|(_, x)| x);
                    match attack {
                        Attack::SwapRevealKey => {
                            let device = m.n_device.unwrap();
                            reveal.keys = wire::keys_c(&device, &own_xwing).unwrap();
                            return Some(reveal.to_json());
                        }
                        Attack::OwnC | Attack::Both => {
                            let e_keys = m.e_keys.clone().unwrap();
                            let mine = m.mine_c.take().unwrap();
                            let (message, _) = mine.reveal(&e_keys.keys, &e_keys.nonce).unwrap();
                            return Some(message.to_json());
                        }
                        Attack::OtherCommit => return None,
                    }
                }
                None
            },
            move |q, body| {
                let mut m = m2.lock().unwrap();
                if q.path == "/v1/approvals/claim" {
                    m.claimed = ApprovalClaimed::read(body).ok();
                    return None;
                }
                let is_state = q.method == "GET"
                    && q.path.starts_with("/v1/approvals/")
                    && q.path.len() == "/v1/approvals/".len() + 32;
                if !is_state {
                    return None;
                }
                let mut state = ApprovalState::read(body).ok()?;
                if is_n(q) {
                    if matches!(attack, Attack::OwnC | Attack::Both) {
                        // N sees its own commitment, as the server would.
                        state.commit = m.n_commit;
                    }
                    if attack == Attack::Both && state.keys_r.is_some() {
                        if m.mine_r.is_none() {
                            let e_keys = m.e_keys.clone().unwrap();
                            let (_, e_device) = wire::split_keys_r(&e_keys.keys).unwrap();
                            let keys = wire::keys_r(&own_identity, &e_device).unwrap();
                            let (_, message) =
                                Responder::answer(ctx_of(&m), keys, &m.n_commit.unwrap()).unwrap();
                            m.mine_r = Some(message);
                        }
                        let mine = m.mine_r.clone().unwrap();
                        state.keys_r = Some((mine.keys, mine.nonce));
                    }
                } else if attack == Attack::OtherCommit && m.e_answered {
                    state.commit = Some([0x0c; 32]);
                }
                Some(state.to_json())
            },
        )
    })
}

/// SYN-05.3, T03: a relay replaces `K_C` in message (3) (N's one-request
/// key). E's check refuses it: `MSG-CODE-FAILED`, no code shown, nothing
/// sealed; E ends the request, so N's next look fails too.
#[test]
fn syn05_t03_a_relay_that_swaps_k_c_in_message_3_fails_e_s_check() {
    let w = relay(Attack::SwapRevealKey);
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let before = probe::counts();
    let approver = e.c.approval_start(&*clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
    let n_side = ready(claimant.poll(&mut n, &*clock).unwrap());
    let got = approver.poll(&mut e.c, &*clock);
    assert_eq!(got.err(), Some(AccountFail::CodeFailed), "no code on E");
    assert_eq!(AccountFail::CodeFailed.message().id(), "MSG-CODE-FAILED");
    assert_eq!(
        n_side.codes_match().poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed),
        "the request ended"
    );
    assert_eq!(
        &probe::counts()[1..],
        &before[1..],
        "nothing sealed, signed or pinned"
    );
    assert!(
        w.seen()
            .iter()
            .any(|(q, _)| q.method == "DELETE" && !is_n(q))
    );
}

/// One run of SYN-05 with a party in the middle that runs its own C
/// toward R and its own R toward C, in memory (no server, no Argon2id):
/// whether the two codes matched.
fn middle_run(ctx: &[u8], k_c: &[u8], k_r: &[u8], own_c: &[u8], own_r: &[u8]) -> bool {
    let c = Committer::new(ctx.to_vec(), k_c.to_vec()).unwrap();
    let mine_c = Committer::new(ctx.to_vec(), own_c.to_vec()).unwrap();
    // R answers the commitment it holds: the middle's.
    let (r, to_middle) =
        Responder::answer(ctx.to_vec(), k_r.to_vec(), &mine_c.commit().unwrap()).unwrap();
    // The middle answers C's commitment with its own R before it learns n_C.
    let (_, to_c) = Responder::answer(ctx.to_vec(), own_r.to_vec(), &c.commit().unwrap()).unwrap();
    let (_, c_code) = c.reveal(&to_c.keys, &to_c.nonce).unwrap();
    let (to_r, _) = mine_c.reveal(&to_middle.keys, &to_middle.nonce).unwrap();
    let r_code = r.check(&to_r.keys, &to_r.nonce).unwrap();
    c_code.code() == r_code.code()
}

/// SYN-05.7, T04: a relay in the middle with its own keys. 10,000 runs in
/// memory with fresh nonces, then 20 through the test server: the codes
/// match by chance only (the test fails on more than 2 in 10,000; 0.01
/// expected), and in no run did either side seal, sign or pin before its
/// user's Codes match (every run ends with Codes differ).
#[test]
fn syn05_t04_a_relay_in_the_middle_matches_by_chance_only() {
    let before = probe::counts();
    let ctx = wire::ctx(
        &AccountId::from_bytes([0x11; 16]),
        &Id::from_bytes([0x12; 16]),
    )
    .unwrap();
    let (k_c, k_r) = (vec![0x22; KEYS_C], vec![0x33; KEYS_R]);
    let (own_c, own_r) = (vec![0x66; KEYS_C], vec![0x77; KEYS_R]);
    let matches = (0..10_000)
        .filter(|_| middle_run(&ctx, &k_c, &k_r, &own_c, &own_r))
        .count();
    println!("SYN-05 T04: {matches} matches in 10,000 runs in memory");
    assert!(matches <= 2, "{matches}");
    assert_eq!(&probe::counts()[1..], &before[1..]);

    let w = relay(Attack::Both);
    let mut e = w.e();
    let mut server_matches = 0;
    for run in 0..20 {
        w.later();
        let mut n = w.client();
        let clock = TestClock::at(0);
        let approver = e.c.approval_start(&*clock).unwrap();
        let claimant = n
            .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
            .unwrap();
        let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
        let n_side = ready(claimant.poll(&mut n, &*clock).unwrap());
        let e_side = ready(approver.poll(&mut e.c, &*clock).unwrap());
        if e_side.code() == n_side.code() {
            server_matches += 1;
        }
        e_side.codes_differ(&mut e.c);
        n_side.codes_differ(&mut n);
        assert_eq!(&probe::counts()[1..], &before[1..], "run {run}");
    }
    println!("SYN-05 T04: {server_matches} matches in 20 runs through the test server");
    assert!(server_matches <= 2);
}

/// SYN-05.2, T05; SYN-06 T11's last case: N sends a second commitment:
/// 409, and the request is over for E too. And R refuses it itself: when
/// E's view of the commitment changes after E answered, E ends the request.
#[test]
fn syn05_t05_syn06_11_t11_a_second_commitment_ends_the_request() {
    let w = World::plain();
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let approver = e.c.approval_start(&*clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    let again = CompareCommit { commit: [0x0d; 32] }.to_json();
    let auth = wire::authorization(&claimant.code);
    let a = n
        .send(
            Method::Post(&again),
            &path(&claimant.id, "/commit"),
            &[JSON, ("authorization", auth.expose())],
            MAX_JSON as u64,
        )
        .unwrap();
    assert_eq!(a.status, 409);
    assert_eq!(
        approver.poll(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        claimant.poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );

    let w = relay(Attack::OtherCommit);
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let approver = e.c.approval_start(&*clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
    assert_eq!(
        approver.poll(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        claimant.poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
}

/// SYN-05.2, T06: message (3) before message (2) is refused and ends the
/// request; a commitment E never saw gets no answer.
#[test]
fn syn05_t06_a_reveal_before_message_2_ends_the_request() {
    let w = World::plain();
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let approver = e.c.approval_start(&*clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    let early = CompareKeys {
        keys: claimant.committer.keys.clone(),
        nonce: nonce_of(&claimant.committer.nonce).unwrap(),
    }
    .to_json();
    let auth = wire::authorization(&claimant.code);
    let a = n
        .send(
            Method::Post(&early),
            &path(&claimant.id, "/reveal"),
            &[JSON, ("authorization", auth.expose())],
            MAX_JSON as u64,
        )
        .unwrap();
    assert_eq!(a.status, 409);
    assert_eq!(
        approver.poll(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        claimant.poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
}

/// Both sides with their codes, through the test proxy.
fn to_codes(
    w: &World,
    e: &mut Mac,
    n: &mut Server<DeviceKey>,
    clock: &TestClock,
) -> (ECompared, NCompared<DeviceKey>) {
    let approver = e.c.approval_start(clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), clock)
        .unwrap();
    let approver = waiting(approver.poll(&mut e.c, clock).unwrap());
    let n_side = ready(claimant.poll(n, clock).unwrap());
    let e_side = ready(approver.poll(&mut e.c, clock).unwrap());
    let _ = w;
    (e_side, n_side)
}

/// SYN-05.5, T08: one user picks Codes differ, the other Codes match:
/// both sides end and nothing is sealed, signed or pinned, either way
/// round.
#[test]
fn syn05_t08_codes_differ_on_either_side_ends_both_with_nothing_done() {
    let w = World::plain();
    let mut e = w.e();
    let clock = TestClock::at(0);
    let before = probe::counts();
    // E differs; N matches.
    w.later();
    let mut n = w.client();
    let (e_side, n_side) = to_codes(&w, &mut e, &mut n, &clock);
    e_side.codes_differ(&mut e.c);
    assert_eq!(
        n_side.codes_match().poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    // N differs; E matches.
    w.later();
    let mut n = w.client();
    let (e_side, n_side) = to_codes(&w, &mut e, &mut n, &clock);
    n_side.codes_differ(&mut n);
    assert_eq!(
        e_side.codes_match().seal(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        &probe::counts()[1..],
        &before[1..],
        "nothing sealed, signed or pinned"
    );
    assert!(
        !w.seen().iter().any(|(q, _)| q.path.ends_with("/seal")),
        "no seal sent"
    );
}

/// Ruling (5), SYN-06.6: E's account stops between the codes and the seal
/// (a check of the account's keys finds others on the server): E's seal
/// gives `MSG-ACCOUNT-KEYS-CHANGED`, seals and signs nothing, and ends the
/// request with `DELETE`, so N's next look ends too and no device is
/// registered.
#[test]
fn syn05_5_a_stop_between_the_codes_and_the_seal_ends_the_request() {
    let lie: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let served = lie.clone();
    let w = World::new(move |app| {
        Scripted::proxy_with(app, move |q| {
            let body = served.lock().unwrap().clone()?;
            (q.method == "GET" && q.path == "/v1/account/keys")
                .then(|| crate::test_server::Response::new(200, &body))
        })
    });
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let (e_side, n_side) = to_codes(&w, &mut e, &mut n, &clock);
    let (_, other) = pq::identity_keypair().unwrap();
    let real = e.c.get_keys().unwrap();
    *lie.lock().unwrap() = Some(
        KeysRecord {
            identity_public_key: other,
            ..real
        }
        .to_json(),
    );
    assert_eq!(e.c.check_keys(&e.keep), Err(AccountFail::KeysChanged));
    assert!(e.c.stopped());
    let e_deletes = || {
        w.seen()
            .iter()
            .filter(|(q, _)| q.method == "DELETE" && !is_n(q))
            .count()
    };
    let deletes = e_deletes();
    let before = probe::counts();
    assert_eq!(
        e_side.codes_match().seal(&mut e.c, &*clock).err(),
        Some(AccountFail::KeysChanged)
    );
    assert_eq!(e_deletes(), deletes + 1, "E ended it");
    assert_eq!(probe::counts(), before, "nothing sealed, signed or pinned");
    assert!(
        !w.seen().iter().any(|(q, _)| q.path.ends_with("/seal")),
        "no seal sent"
    );
    assert_eq!(
        n_side.codes_match().poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed),
        "N's next look ends"
    );
    assert_eq!(n.sign_in(), Err(Fail::Key), "no device registered");
}

/// SYN-06.11, T10: a relay swaps N's one-request X-Wing key: it commits
/// toward E to its own `K_C'` and reveals that. E's check passes, but the
/// codes differ; with Codes differ chosen, nothing is sealed and no device
/// is registered.
#[test]
fn syn06_11_t10_a_relay_that_swaps_n_s_one_request_key_gives_other_codes() {
    let w = relay(Attack::OwnC);
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let before = probe::counts();
    let (e_side, n_side) = to_codes(&w, &mut e, &mut n, &clock);
    assert_ne!(e_side.code(), n_side.code());
    e_side.codes_differ(&mut e.c);
    n_side.codes_differ(&mut n);
    assert_eq!(&probe::counts()[1..], &before[1..]);
    assert!(!w.seen().iter().any(|(q, _)| q.path.ends_with("/seal")));
    // No device was registered: N has none to sign in with.
    assert_eq!(n.sign_in(), Err(Fail::Key));
}

/// SYN-06.11, T11, ruling (9): a claim after 15 min 1 s on the server's
/// clock gets 401; a second claim gets 409 and ends the request; and each
/// client refuses after its own 15 minutes, ending the request.
#[test]
fn syn06_11_t11_an_expired_or_claimed_code_is_refused_on_both_clocks() {
    let w = World::plain();
    let mut e = w.e();
    let clock = TestClock::at(0);

    let last_claim = || {
        w.seen()
            .into_iter()
            .rev()
            .find(|(q, _)| q.path == "/v1/approvals/claim")
            .map(|(_, reply)| reply)
            .unwrap()
    };

    // The server's 15 minutes: a claim 15 min 1 s after the start gets
    // 401 and the request is gone.
    let approver = e.c.approval_start(&*clock).unwrap();
    w.skip(901);
    let mut n = w.client();
    let got = n.approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock);
    assert_eq!(got.err(), Some(AccountFail::CodeFailed));
    assert!(last_claim().starts_with(b"HTTP/1.1 401"));
    assert_eq!(
        approver.poll(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );

    // Claimed twice: 201, then 409, and the request is over for both.
    w.later();
    let mut n = w.client();
    let approver = e.c.approval_start(&*clock).unwrap();
    let code = approver.code();
    let first = n
        .approval_claim(&code, DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    let mut other = w.client();
    let second = other.approval_claim(&code, DeviceKey::test_seam().unwrap(), &*clock);
    assert_eq!(second.err(), Some(AccountFail::CodeFailed));
    assert!(last_claim().starts_with(b"HTTP/1.1 409"));
    assert_eq!(
        approver.poll(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        first.poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );

    // E's own 15 minutes.
    w.later();
    let mut n = w.client();
    let e_clock = TestClock::at(0);
    let approver = e.c.approval_start(&*e_clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    e_clock.advance(LIFE_MS);
    assert_eq!(
        approver.poll(&mut e.c, &*e_clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        claimant.poll(&mut n, &*clock).err(),
        Some(AccountFail::CodeFailed),
        "E ended it"
    );

    // N's own 15 minutes: one millisecond short, N goes on; at 15 minutes
    // N ends the request, so E's seal is never made.
    w.later();
    let mut n = w.client();
    let n_clock = TestClock::at(0);
    let approver = e.c.approval_start(&*clock).unwrap();
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*n_clock)
        .unwrap();
    let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
    n_clock.advance(LIFE_MS - 1);
    let n_side = ready(claimant.poll(&mut n, &*n_clock).unwrap());
    let e_side = ready(approver.poll(&mut e.c, &*clock).unwrap());
    let n_deletes = || {
        w.seen()
            .iter()
            .filter(|(q, _)| q.method == "DELETE" && is_n(q))
            .count()
    };
    let deletes = n_deletes();
    n_clock.advance(1);
    assert_eq!(
        n_side.codes_match().poll(&mut n, &*n_clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(n_deletes(), deletes + 1, "N ended it");
    let before = probe::counts();
    assert_eq!(
        e_side.codes_match().seal(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(probe::counts(), before, "nothing sealed");
}

/// A world whose relay replaces the seal N reads with `forge`'s record,
/// made from what the relay learned (N's one-request key, the ids).
fn forged(
    forge: impl Fn(&ApprovalClaimed, &[u8; DEVICE_KEY], &[u8], &WrapRecord) -> WrapRecord
    + Send
    + Sync
    + 'static,
) -> World {
    let middle: Arc<Mutex<Middle>> = Arc::default();
    let (m1, m2) = (middle.clone(), middle);
    World::new(move |app| {
        Scripted::relay(
            app,
            move |q| {
                let mut m = m1.lock().unwrap();
                if q.path == "/v1/approvals/claim" {
                    m.n_device = Some(ApprovalClaim::read(&q.body).unwrap().device_public_key);
                } else if q.path.ends_with("/reveal") {
                    let reveal = CompareKeys::read(&q.body, KEYS_C).unwrap();
                    m.n_xwing = wire::split_keys_c(&reveal.keys).map(|(_, x)| x);
                }
                None
            },
            move |q, body| {
                let mut m = m2.lock().unwrap();
                if q.path == "/v1/approvals/claim" {
                    m.claimed = ApprovalClaimed::read(body).ok();
                    return None;
                }
                if !(q.method == "GET" && is_n(q)) {
                    return None;
                }
                let mut state = ApprovalState::read(body).ok()?;
                let (sealed, device) = state.seal.take()?;
                let real = record::read(&sealed).unwrap();
                let fake = forge(
                    m.claimed.as_ref().unwrap(),
                    m.n_device.as_ref().unwrap(),
                    m.n_xwing.as_ref().unwrap(),
                    &real,
                );
                state.seal = Some((record::to_json(&fake), device));
                Some(state.to_json())
            },
        )
    })
}

/// What N's look at the seal gives.
type SealLook = Result<Polled<NMatched<DeviceKey>, NSealed>, AccountFail>;

/// One approval to N's look at the seal: what that look gives, and N.
fn to_seal(w: &World, e: &mut Mac) -> (SealLook, Server<DeviceKey>) {
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let (e_side, n_side) = to_codes(w, e, &mut n, &clock);
    e_side.codes_match().seal(&mut e.c, &*clock).unwrap();
    let got = n_side.codes_match().poll(&mut n, &*clock);
    (got, n)
}

/// SYN-06.11 step 6, T12: a test server replaces the sealed record with
/// one sealed (to N's real one-request key, with the right info) and
/// signed by its own identity key: N refuses it, takes no device and pins
/// nothing. (The server's own check of E's device signature, 403, is
/// larsal-server's T12.)
#[test]
fn syn06_11_t12_a_seal_signed_by_another_key_is_refused() {
    let (attacker, _) = pq::identity_keypair().unwrap();
    let w = forged(move |claimed, device, xwing, _| {
        let info = wire::seal_info(&claimed.account_id, &claimed.approval_id, device).unwrap();
        wrap_record::make(
            xwing,
            &info,
            &[0x5e; 32],
            *claimed.account_id.as_bytes(),
            &attacker,
        )
        .unwrap()
    });
    let mut e = w.e();
    let before = probe::counts();
    let (got, mut n) = to_seal(&w, &mut e);
    assert_eq!(got.err(), Some(AccountFail::CodeFailed));
    assert_eq!(n.sign_in(), Err(Fail::Key), "no device taken");
    assert_eq!(n.account_id(), None);
    assert_eq!(probe::counts()[3], before[3], "nothing pinned");
}

/// SYN-06.14, T19 (the approval half), ruling (6): N refuses a classical
/// record (the suite ids `[32, 1, 2]` on a hybrid record, and the
/// classical form with a 32-byte enc), records signed by the account's own
/// identity key whose info names another approval, another account or
/// another device, and one that names another signer; and an Ed25519-only
/// binding in the account keys after the seal.
#[test]
fn syn06_14_t19_n_refuses_a_classical_record_other_info_and_an_ed25519_binding() {
    let other = Id::from_bytes([0x0e; 16]);
    for case in 0..6 {
        let keys: Arc<Mutex<Option<AccountKeys>>> = Arc::default();
        let held = keys.clone();
        let w = forged(move |claimed, device, xwing, real| {
            let mut classical = real.clone();
            classical.suite = [32, 1, 2];
            match case {
                0 => return classical,
                1 => {
                    classical.enc = vec![0x09; 32];
                    classical.ct.truncate(48);
                    return classical;
                }
                _ => {}
            }
            let (account, approval) = (claimed.account_id, claimed.approval_id);
            let (mut device, mut signer) = (*device, *account.as_bytes());
            let (account, approval) = match case {
                2 => (account, other),
                3 => (other, approval),
                4 => {
                    device[64] ^= 1;
                    (account, approval)
                }
                _ => {
                    signer = *other.as_bytes();
                    (account, approval)
                }
            };
            let info = wire::seal_info(&account, &approval, &device).unwrap();
            let k = held.lock().unwrap();
            let k = k.as_ref().unwrap();
            wrap_record::make(
                xwing,
                &info,
                k.account_secret().expose(),
                signer,
                k.identity_private_key(),
            )
            .unwrap()
        });
        let mut e = w.e();
        let (_, k) = e.c.account.as_ref().unwrap();
        *keys.lock().unwrap() = Some(
            AccountKeys::from_blob(
                SecretBytes::new(k.account_secret().expose().to_vec()),
                &k.blob_plaintext(),
            )
            .unwrap(),
        );
        let (got, n) = to_seal(&w, &mut e);
        assert_eq!(got.err(), Some(AccountFail::CodeFailed), "case {case}");
        assert_eq!(n.account_id(), None);
    }

    // An Ed25519-only binding offered after the seal: refused, nothing kept.
    let lie: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let served = lie.clone();
    let w = World::new(move |app| {
        Scripted::proxy_with(app, move |q| {
            let body = served.lock().unwrap().clone()?;
            (q.method == "GET" && q.path == "/v1/account/keys")
                .then(|| crate::test_server::Response::new(200, &body))
        })
    });
    let mut e = w.e();
    let mut record = e.c.get_keys().unwrap();
    record.kem_signature.truncate(64);
    *lie.lock().unwrap() = Some(record.to_json());
    let (got, mut n) = to_seal(&w, &mut e);
    let sealed = ready(got.unwrap());
    let keep = Memory::default();
    assert_eq!(
        sealed.finish(&mut n, &password(), &keep).err(),
        Some(AccountFail::Net(Fail::Protocol))
    );
    assert!(keep.0.lock().unwrap().is_empty());
    assert_eq!(n.account_id(), None);
}

/// SYN-06.11 step 6, ruling (6): the server sends keys whose blob opens
/// with `S_acct` and the password but holds another identity seed (a
/// record of other keys under the same secret, bound to this account):
/// N refuses them (`MSG-ACCOUNT-KEYS-CHANGED`), keeps and pins nothing; the
/// real keys then pass, and a wrong password first gives
/// `MSG-ACCOUNT-RESTORE-FAILED` with N still registered (SYN-06.11's edge
/// case).
#[test]
fn syn06_11_n_pins_only_the_identity_key_it_compared() {
    let lie: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let served = lie.clone();
    let w = World::new(move |app| {
        Scripted::proxy_with(app, move |q| {
            let body = served.lock().unwrap().clone()?;
            (q.method == "GET" && q.path == "/v1/account/keys")
                .then(|| crate::test_server::Response::new(200, &body))
        })
    });
    let mut e = w.e();
    let account = e.made.account_id;
    let real = e.c.get_keys().unwrap();
    let (_, k) = e.c.account.as_ref().unwrap();
    let other = AccountKeys::from_blob(
        SecretBytes::new(k.account_secret().expose().to_vec()),
        &AccountKeys::new().unwrap().blob_plaintext(),
    )
    .unwrap();
    assert_ne!(other.identity_public_key(), k.identity_public_key());
    let swapped = KeysRecord {
        identity_public_key: other.identity_public_key().to_vec(),
        kem_public_key: other.kem_public_key().to_vec(),
        kem_signature: other.kem_signature(account.as_bytes()).unwrap(),
        recovery_public_key: real.recovery_public_key,
        blob: make_blob(&other, &account, &password()).unwrap(),
    };
    *lie.lock().unwrap() = Some(swapped.to_json());
    let (got, mut n) = to_seal(&w, &mut e);
    let sealed = ready(got.unwrap());
    let keep = Memory::default();
    let before = probe::counts();
    assert_eq!(
        sealed.finish(&mut n, &password(), &keep).err(),
        Some(AccountFail::KeysChanged)
    );
    assert!(keep.0.lock().unwrap().is_empty());
    assert_eq!(n.account_id(), None);
    assert_eq!(probe::counts()[3], before[3]);
    *lie.lock().unwrap() = None;
    let wrong = SecretString::new("demo-approval-pv".to_owned());
    assert_eq!(
        sealed.finish(&mut n, &wrong, &keep).err(),
        Some(AccountFail::RestoreFailed)
    );
    sealed.finish(&mut n, &password(), &keep).unwrap();
    assert_eq!(n.account_id(), Some(account));
}

/// SYN-06.12 at the approval's side, ruling (1): N joins by approval, and
/// the `approve` helper the E16 tests use gives a device that signs in.
#[test]
fn syn06_11_the_approve_helper_gives_a_device_that_signs_in() {
    let w = World::plain();
    let mut e = w.e();
    w.later();
    let mut n = w.client();
    let keep = Memory::default();
    let device = approve(
        &mut e.c,
        &mut n,
        DeviceKey::test_seam().unwrap(),
        &*TestClock::at(0),
        &password(),
        &keep,
    )
    .unwrap();
    assert_ne!(device, e.made.device_id);
    n.sign_in().unwrap();
    assert_eq!(n.account_id(), Some(e.made.account_id));
    drop(e.kit);
}

/// SYN-02 T14, SYN-03 T24's method, LD-340, LD-426, ruling (10): three
/// approvals (one with Codes match, N signed in and synced; one ended by
/// Codes differ; one expired), then every byte the server stored and every
/// request and reply through the proxy (N's `Authorization: Approval`
/// lines aside, the code's one place) is searched for the approval codes
/// (raw, base32 with and without groups, hex, base64), `S_acct`, the
/// one-request private seeds and the X-Wing shared secret, the account's
/// private keys and seeds, `A`'s inputs (the account password), the
/// recovery seed and LD-426's values of the demo vault (its master
/// password, its entry's title, user name and password), each raw, as
/// upper and lower hex, padded and URL base64, and the same of its SHA-256
/// (the code's SHA-256 aside: the server stores it by design).
#[test]
#[allow(clippy::too_many_lines)]
fn syn02_t14_syn06_11_no_secret_in_any_stored_byte_after_three_approvals() {
    let w = World::plain();
    let mut e = w.e();
    let account = e.made.account_id;
    let vault = VaultId::from_bytes([0x62; 16]);
    assert_eq!(first_upload(&mut e.c, &vault, VAULT), Ok(1));
    let mut codes = Vec::new();
    let mut seeds = Vec::new();
    let mut shared = Vec::new();

    // 1: Codes match; N signs in and syncs.
    w.later();
    let mut n = w.client();
    let clock = TestClock::at(0);
    let approver = e.c.approval_start(&*clock).unwrap();
    codes.push(SecretBytes::new(approver.code.expose().to_vec()));
    let claimant = n
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    seeds.push(SecretBytes::new(claimant.seed.expose().to_vec()));
    let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
    let n_side = ready(claimant.poll(&mut n, &*clock).unwrap());
    let e_side = ready(approver.poll(&mut e.c, &*clock).unwrap());
    e_side.codes_match().seal(&mut e.c, &*clock).unwrap();
    let seal = w
        .seen()
        .into_iter()
        .find(|(q, _)| q.path.ends_with("/seal"))
        .map(|(q, _)| ApprovalSeal::read(&q.body).unwrap())
        .unwrap();
    shared.push(pq::kem_shared_secret(seeds.last().unwrap(), &seal.seal.enc).unwrap());
    let sealed = ready(n_side.codes_match().poll(&mut n, &*clock).unwrap());
    let n_keep = Memory::default();
    sealed.finish(&mut n, &password(), &n_keep).unwrap();
    let open = OpenVault::new(b"");
    let mut l = link(&n, vault);
    assert_eq!(
        run(&mut n, &mut l, &open, &*clock).status,
        Some(Status::Synced(0))
    );

    // 2: Codes differ.
    w.later();
    let mut n2 = w.client();
    let approver = e.c.approval_start(&*clock).unwrap();
    codes.push(SecretBytes::new(approver.code.expose().to_vec()));
    let claimant = n2
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    seeds.push(SecretBytes::new(claimant.seed.expose().to_vec()));
    let approver = waiting(approver.poll(&mut e.c, &*clock).unwrap());
    let n_side = ready(claimant.poll(&mut n2, &*clock).unwrap());
    let e_side = ready(approver.poll(&mut e.c, &*clock).unwrap());
    n_side.codes_differ(&mut n2);
    e_side.codes_differ(&mut e.c);

    // 3: expired on the server's clock after the commitment.
    w.later();
    let mut n3 = w.client();
    let approver = e.c.approval_start(&*clock).unwrap();
    codes.push(SecretBytes::new(approver.code.expose().to_vec()));
    let claimant = n3
        .approval_claim(&approver.code(), DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    seeds.push(SecretBytes::new(claimant.seed.expose().to_vec()));
    w.skip(901);
    assert_eq!(
        claimant.poll(&mut n3, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );
    assert_eq!(
        approver.poll(&mut e.c, &*clock).err(),
        Some(AccountFail::CodeFailed)
    );

    let (_, keys) = e.c.account.as_ref().unwrap();
    let identity = keys.identity_private_key().expose();
    let mut needles: Vec<(String, Vec<u8>)> = vec![
        ("S_acct".into(), keys.account_secret().expose().to_vec()),
        ("the identity private key".into(), identity.to_vec()),
        ("its ML-DSA seed".into(), identity[..32].to_vec()),
        ("its Ed25519 seed".into(), identity[32..].to_vec()),
        (
            "the receiving seed".into(),
            keys.kem_seed().expose().to_vec(),
        ),
        (
            "the blob's plaintext".into(),
            keys.blob_plaintext().expose().to_vec(),
        ),
        (
            "the recovery seed".into(),
            crate::account::recovery_seed(&account, keys.account_secret())
                .unwrap()
                .expose()
                .to_vec(),
        ),
        ("the account password".into(), PASSWORD.as_bytes().to_vec()),
        ("the master password".into(), b"demo-pass-1".to_vec()),
        ("the entry title".into(), b"Demo login".to_vec()),
        ("the entry user name".into(), b"demo-user".to_vec()),
        ("the entry password".into(), b"demo-entry-pass-1".to_vec()),
    ];
    for (i, s) in seeds.iter().enumerate() {
        needles.push((format!("run {i}'s one-request seed"), s.expose().to_vec()));
    }
    for (i, s) in shared.iter().enumerate() {
        needles.push((
            format!("run {i}'s X-Wing shared secret"),
            s.expose().to_vec(),
        ));
    }
    let mut forms: Vec<(String, Vec<u8>)> = Vec::new();
    for (what, value) in &needles {
        for form in encoded(value) {
            forms.push((what.clone(), form));
        }
        for form in encoded(&hash(value)) {
            forms.push((format!("{what}'s SHA-256"), form));
        }
    }
    for (i, code) in codes.iter().enumerate() {
        let grouped = wire::code_shown(code);
        let flat = grouped.expose().replace('-', "");
        for form in encoded(code.expose()) {
            forms.push((format!("run {i}'s approval code"), form));
        }
        for text in [
            grouped.expose().to_owned(),
            flat.clone(),
            flat.to_lowercase(),
        ] {
            forms.push((
                format!("run {i}'s approval code in base32"),
                text.into_bytes(),
            ));
        }
    }

    let mut hay: Vec<(String, Vec<u8>)> = Vec::new();
    for (q, reply) in &w.seen() {
        let text = String::from_utf8_lossy(&q.raw).into_owned();
        let rest: Vec<&str> = text
            .split("\r\n")
            .filter(|l| {
                !(is_n(q)
                    && l.to_ascii_lowercase()
                        .starts_with("authorization: approval "))
            })
            .collect();
        // The body may hold bytes that are not UTF-8: search it as sent.
        let mut bytes = rest.join("\r\n").into_bytes();
        bytes.extend_from_slice(&q.body);
        hay.push((format!("request {} {}", q.method, q.path), bytes));
        hay.push((format!("reply to {} {}", q.method, q.path), reply.clone()));
    }
    let exchanges = hay.len() / 2;
    let stored = files(&w.app._data.0);
    let server_files = stored.len();
    for (p, b) in stored {
        hay.push((p.display().to_string(), b));
    }
    assert!(
        hay.iter().any(|(_, b)| has(b, VAULT)),
        "the search sees the vault"
    );
    let hash_of_code = wire::code_hash(&codes[0]).unwrap();
    assert!(
        hay.iter().any(|(_, b)| has(b, &hash_of_code)
            || has(b, base64::encode(Form::Url, &hash_of_code).as_bytes())),
        "the search sees the code's SHA-256, stored by design"
    );
    let bytes: usize = hay.iter().map(|(_, b)| b.len()).sum();
    let mut found = Vec::new();
    for (place, b) in &hay {
        for (what, form) in &forms {
            if has(b, form) {
                found.push(format!("{what} in {place}"));
            }
        }
    }
    println!(
        "SYN-02 T14, SYN-06.11: {} needles ({} codes in 8 forms), {} forms, {} places ({exchanges} proxied exchanges as request and reply, {server_files} server files), {bytes} bytes searched, {} found",
        needles.len() + codes.len(),
        codes.len(),
        forms.len(),
        hay.len(),
        found.len()
    );
    assert!(found.is_empty(), "{found:?}");
    drop(e.kit);
}

/// SYN-05.3: the commitment is compared whole: a stored one that differs
/// in its last byte only is refused (a check of a prefix would pass it).
#[test]
fn syn05_3_the_commitment_is_compared_whole() {
    let ctx = b"ctx".to_vec();
    let c = Committer::new(ctx.clone(), vec![0x22; KEYS_C]).unwrap();
    let mut commit = c.commit().unwrap();
    commit[31] ^= 1;
    let (r, m2) = Responder::answer(ctx.clone(), vec![0x33; KEYS_R], &commit).unwrap();
    let (m3, _) = c.reveal(&m2.keys, &m2.nonce).unwrap();
    assert_eq!(
        r.check(&m3.keys, &m3.nonce).err(),
        Some(AccountFail::CodeFailed)
    );
    // The same with the first byte changed, and the control.
    let c = Committer::new(ctx.clone(), vec![0x22; KEYS_C]).unwrap();
    let good = c.commit().unwrap();
    let mut first = good;
    first[0] ^= 1;
    let (r, m2) = Responder::answer(ctx.clone(), vec![0x33; KEYS_R], &first).unwrap();
    let (m3, _) = Committer {
        ctx: c.ctx.clone(),
        keys: c.keys.clone(),
        nonce: SecretBytes::new(c.nonce.expose().to_vec()),
        commit: SecretBytes::new(good.to_vec()),
    }
    .reveal(&m2.keys, &m2.nonce)
    .unwrap();
    assert_eq!(
        r.check(&m3.keys, &m3.nonce).err(),
        Some(AccountFail::CodeFailed)
    );
    let (r, m2) = Responder::answer(ctx, vec![0x33; KEYS_R], &good).unwrap();
    let (m3, c_code) = c.reveal(&m2.keys, &m2.nonce).unwrap();
    assert_eq!(r.check(&m3.keys, &m3.nonce).unwrap().code(), c_code.code());
}

/// Rule 4: no value of the request is printed by `Debug`.
#[test]
fn syn06_11_debug_names_no_secret() {
    let c = Committer::new(b"ctx".to_vec(), vec![0x22; KEYS_C]).unwrap();
    assert_eq!(format!("{c:?}"), "[hidden]");
    let (r, _) = Responder::answer(b"ctx".to_vec(), vec![0x33; KEYS_R], &[1; 32]).unwrap();
    assert_eq!(format!("{r:?}"), "[hidden]");
}
