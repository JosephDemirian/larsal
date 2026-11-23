//! SYN-06.11, E17-S2's ruling (11), AGENTS.md rule 4, the way
//! tests/account_wipe.rs works. All memory of this process (heap, freed
//! blocks and stacks, larsal-server's in process included) is searched
//! after three approvals, one ended each way: Codes match on both Macs (N
//! joins and finishes), Codes differ on N (E's seal is then refused), and
//! 15 minutes and 1 s on the server's clock after N's commitment, before
//! any reveal. After each, on both sides, the approval code, the
//! one-request X-Wing seed and the X-Wing shared secret of the seal are in
//! no byte of memory, nor `n_C` of the request that ended before its
//! reveal (a revealed nonce is public); `S_acct` is only in its owners
//! (each Mac's account keys and device store item), and once those are
//! dropped, nowhere.
//!
//! One test only: the probe reads all of this process's memory, so nothing
//! else may run beside it. The search looks for whole spans kept XOR a
//! mask, so it never finds its own needle.

use larsal_crypto::pq;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_platform::device_key::DeviceKey;
use larsal_platform::memory::{Probe, Seen, copies_in_memory};
use larsal_proto::approval::{ApprovalSeal, read_code};
use larsal_sync::account::Keep;
use larsal_sync::approval::Polled;
use larsal_sync::client::Server;
use larsal_sync::test_server::{Memory, Scripted, TestClock, larsal_server_strict};
use std::alloc::System;
use std::cell::Cell;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const PASSWORD: &str = "E17demoS2-account-pw";
/// Every span this test searches all memory for is kept XOR this mask.
const MASK: u8 = 0x5a;

/// `values` masked, on a thread of its own that has ended before any count
/// (as tests/account_wipe.rs's `learn`); the values are wiped there.
fn learn(values: Vec<(String, SecretBytes)>) -> Vec<(String, Vec<u8>)> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(4 << 20)
            .spawn_scoped(scope, move || {
                values
                    .into_iter()
                    .map(|(name, v)| (name, v.expose().iter().map(|b| b ^ MASK).collect()))
                    .collect()
            })
            .unwrap()
            .join()
            .unwrap()
    })
}

fn ready<W, R>(p: Polled<W, R>) -> R {
    match p {
        Polled::Ready(r) => r,
        Polled::Waiting(_) => panic!("still waiting"),
    }
}

fn waiting<W, R>(p: Polled<W, R>) -> W {
    match p {
        Polled::Waiting(w) => w,
        Polled::Ready(_) => panic!("ready too early"),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn e17s2_approvals_leave_no_request_secret_in_memory() {
    let password = || SecretString::new(String::from(PASSWORD));
    let app = larsal_server_strict();
    let t0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let seconds = Cell::new(0);
    let on = |s: u64| {
        seconds.set(seconds.get() + s);
        app.seams.set_clock(t0 + seconds.get());
    };
    app.seams.set_clock(t0);
    let proxy = Scripted::proxy(&app);
    let client = || {
        let mut c = Server::new(&proxy.address(), proxy.pin).unwrap();
        c.sign_for_port(app.port);
        c
    };
    let clock = TestClock::at(0);

    // E: sign-up and the account keys; the kit is dropped at once.
    let mut e = client();
    let account = e
        .sign_up(DeviceKey::test_seam().unwrap())
        .unwrap()
        .account_id;
    let e_keep = Memory::default();
    drop(e.sign_up_account(&account, &password(), &e_keep).unwrap());
    let label = format!("{} account {account}", e.address());
    let item = e_keep.get(&label).unwrap();
    let s_acct = learn(vec![(
        "S_acct".to_owned(),
        SecretBytes::new(item.expose()[..32].to_vec()),
    )]);
    drop(item);
    let mut needles = Vec::new();
    let mut counts = Vec::new();
    let mut count = |after: &'static str, needles: &[(String, Vec<u8>)]| {
        let found: Vec<usize> = needles
            .iter()
            .map(|(_, span)| copies_in_memory(span, MASK))
            .collect();
        let s = copies_in_memory(&s_acct[0].1, MASK);
        println!("RESIDUE after {after}: request needles {found:?}, S_acct {s}");
        counts.push((after, found, s));
    };

    // 1: Codes match on both; N finishes with the password.
    on(61);
    let mut n = client();
    let approver = e.approval_start(&*clock).unwrap();
    let typed = approver.code();
    let code = read_code(typed.expose()).unwrap();
    let claimant = n
        .approval_claim(&typed, DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    drop(typed);
    let [kept_code, _, seed] = claimant.test_secrets();
    assert_eq!(kept_code.expose(), code.expose());
    drop(kept_code);
    let approver = waiting(approver.poll(&mut e, &*clock).unwrap());
    let n_side = ready(claimant.poll(&mut n, &*clock).unwrap());
    let e_side = ready(approver.poll(&mut e, &*clock).unwrap());
    assert_eq!(e_side.code(), n_side.code());
    e_side.codes_match().seal(&mut e, &*clock).unwrap();
    let sealed = ready(n_side.codes_match().poll(&mut n, &*clock).unwrap());
    let n_keep = Memory::default();
    sealed.finish(&mut n, &password(), &n_keep).unwrap();
    drop(sealed);
    let enc = proxy
        .seen
        .lock()
        .unwrap()
        .iter()
        .find(|(q, _)| q.method == "POST" && q.path.ends_with("/seal"))
        .map(|(q, _)| ApprovalSeal::read(&q.body).unwrap().seal.enc)
        .unwrap();
    let shared = pq::kem_shared_secret(&seed, &enc).unwrap();
    needles.extend(learn(vec![
        ("1: the approval code".to_owned(), code),
        ("1: the one-request seed".to_owned(), seed),
        ("1: the X-Wing shared secret".to_owned(), shared),
    ]));
    count("Codes match on both, N finished", &needles);

    // 2: Codes differ on N; E's seal is then refused.
    on(61);
    let mut n2 = client();
    let approver = e.approval_start(&*clock).unwrap();
    let typed = approver.code();
    let code = read_code(typed.expose()).unwrap();
    let claimant = n2
        .approval_claim(&typed, DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    drop(typed);
    let [_, _, seed] = claimant.test_secrets();
    let approver = waiting(approver.poll(&mut e, &*clock).unwrap());
    let n_side = ready(claimant.poll(&mut n2, &*clock).unwrap());
    let e_side = ready(approver.poll(&mut e, &*clock).unwrap());
    n_side.codes_differ(&mut n2);
    assert!(e_side.codes_match().seal(&mut e, &*clock).is_err());
    drop(n2);
    needles.extend(learn(vec![
        ("2: the approval code".to_owned(), code),
        ("2: the one-request seed".to_owned(), seed),
    ]));
    count("Codes differ on N", &needles);

    // 3: 15 minutes and 1 s on the server's clock after the commitment.
    on(61);
    let mut n3 = client();
    let approver = e.approval_start(&*clock).unwrap();
    let typed = approver.code();
    let code = read_code(typed.expose()).unwrap();
    let claimant = n3
        .approval_claim(&typed, DeviceKey::test_seam().unwrap(), &*clock)
        .unwrap();
    drop(typed);
    let [_, nonce_c, seed] = claimant.test_secrets();
    on(901);
    assert!(claimant.poll(&mut n3, &*clock).is_err());
    assert!(approver.poll(&mut e, &*clock).is_err());
    drop(n3);
    needles.extend(learn(vec![
        ("3: the approval code".to_owned(), code),
        ("3: n_C, never revealed".to_owned(), nonce_c),
        ("3: the one-request seed".to_owned(), seed),
    ]));
    count("15 minutes after the commitment", &needles);

    // The owners dropped.
    drop(e);
    drop(e_keep);
    drop(n);
    drop(n_keep);
    count("both Macs' keys and device stores dropped", &needles);

    // The control: an unwiped copy of request 1's code is found.
    let control = std::hint::black_box(needles[0].1.iter().map(|b| b ^ MASK).collect::<Vec<u8>>());
    let seen = copies_in_memory(&needles[0].1, MASK);
    drop(control);
    println!("RESIDUE control, an unwiped copy of 1's code: {seen}");

    // Every count was printed before any is checked.
    let names: Vec<&str> = needles.iter().map(|(name, _)| name.as_str()).collect();
    println!("RESIDUE needles: {names:?}");
    assert!(seen >= 1, "the search found no unwiped copy");
    let last = counts.len() - 1;
    for (i, (after, found, s)) in counts.into_iter().enumerate() {
        assert!(
            found.iter().all(|n| *n == 0),
            "copies after {after}: {found:?}"
        );
        let owners = if i == last { 0 } else { 4 };
        assert_eq!(
            s, owners,
            "S_acct after {after}: E's and N's keys and items"
        );
    }
}
