//! Story E4-S11, card FEA-06: breach check. One test per case
//! (`fea06_NN_…`), 06-01 to 06-30, on the card's demo vault V.
//!
//! The online cases test the core parts: which requests, their headers,
//! reading answers, findings, errors and state. Sending them is
//! larsal-platform's (E6-S7, with a local test server), the screen is E5-S7's
//! and the `analyze` command E12-S1's; the cases name what stays for them.
//! Hashes: SHA-1 of the UTF-8 text, as the card lists them (`python3`).

mod common;

use common::at;
use larsal_core::breach::{
    self, AnswerError, Check, FileError, HashFile, MAX_BODY, MAX_PARALLEL, NONE_FOUND,
    OfflineFinding, exposure, hash, offline_check, parse_range,
};
use larsal_core::refs;
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Field, Group, Uuid, Vault};
use std::io::{BufReader, Read};

const PASSWORD: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
const P123456: &str = "7C4A8D09CA3762AF61E59520943DC26494F8941B";
const EMPTY: &str = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
const CAFE: &str = "F424452A9673918C6F09B0CDD35B20BE8E6AE7D7";
const TROUB: &str = "874572E7A5AE6A49466A6AC578B98ADBA78C6AA6";

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn ent(b: u8, title: &str, pw: &str) -> Entry {
    let mut e = Entry::new(uid(b), at(2026, 1, 1, 0, 0, 0));
    for (n, v) in [("Title", title), ("Password", pw)] {
        e.set_field(
            n.to_owned(),
            Field {
                value: SecretString::new(v.to_owned()),
                protected: n == "Password",
            },
        );
    }
    e
}

/// Demo vault V: Root/Alpha `password`, Beta `password`, Gamma `123456`,
/// Delta empty, Eps `Tr0ub4dor&3`, Zeta `café`.
fn v() -> Vault {
    let mut root = Group::new(uid(0x01), "Root".into(), at(2026, 1, 1, 0, 0, 0));
    for (b, t, p) in [
        (0x0a, "Alpha", "password"),
        (0x0b, "Beta", "password"),
        (0x0c, "Gamma", "123456"),
        (0x0d, "Delta", ""),
        (0x0e, "Eps", "Tr0ub4dor&3"),
        (0x0f, "Zeta", "café"),
    ] {
        root.entries.push(ent(b, t, p));
    }
    Vault::new(root, at(2026, 1, 1, 0, 0, 0))
}

fn urls(c: &Check) -> Vec<String> {
    c.requests().into_iter().map(|r| r.url).collect()
}

fn suffix(full: &str) -> &str {
    &full[5..]
}

fn titles(f: &[breach::Finding]) -> Vec<&str> {
    f.iter().map(|x| x.title.as_str()).collect()
}

#[test]
fn fea06_01_nothing_before_the_press() {
    // The core never sends: building a check only lists what the press
    // would ask. The 10-second wait on a test server is E5-S7's and
    // E6-S7's; the network code lives only in larsal-platform (Rust rule 12).
    let c = Check::new(&v());
    assert!(c.findings(&v()).is_empty());
    let src = include_str!("../src/breach.rs");
    for word in ["TcpStream", "ureq", "std::net"] {
        assert!(!src.contains(word), "{word}");
    }
}

#[test]
fn fea06_02_requests() {
    let c = Check::new(&v());
    assert_eq!(
        urls(&c),
        [
            "https://api.pwnedpasswords.com/range/5BAA6",
            "https://api.pwnedpasswords.com/range/7C4A8",
            "https://api.pwnedpasswords.com/range/87457",
            "https://api.pwnedpasswords.com/range/F4244",
        ]
    );
    for r in c.requests() {
        assert_eq!(
            r.headers,
            [("User-Agent", "Larsal"), ("Add-Padding", "true")]
        );
    }
    assert_eq!(MAX_PARALLEL, 6);
    let h = hash("password");
    assert_eq!(
        (h.prefix.as_str(), h.suffix.expose()),
        ("5BAA6", suffix(PASSWORD))
    );
    assert_eq!(hash("café").suffix.expose(), suffix(CAFE));
    assert_eq!(hash("Tr0ub4dor&3").prefix, &TROUB[..5]);
}

#[test]
fn fea06_03_shared_prefix() {
    let mut root = Group::new(uid(0x01), "Root".into(), at(2026, 1, 1, 0, 0, 0));
    root.entries.push(ent(0x0a, "One", "demo-415"));
    root.entries.push(ent(0x0b, "Two", "demo-733"));
    let vault = Vault::new(root, at(2026, 1, 1, 0, 0, 0));
    let mut c = Check::new(&vault);
    assert_eq!(urls(&c), ["https://api.pwnedpasswords.com/range/1E5F1"]);
    let body = "93CF5FFC3EDA845A505F2A28E76A1490111:3\r\n7AEB095DB8B7AD022CBBE5DA2385D263637:9\r\n";
    c.answer("1E5F1", 200, body.as_bytes()).unwrap();
    let f = c.findings(&vault);
    assert_eq!(
        f.iter()
            .map(|x| (x.title.as_str(), x.count))
            .collect::<Vec<_>>(),
        [("Two", 9), ("One", 3)]
    );
    assert!(c.requests().is_empty());
}

#[test]
fn fea06_04_answer_parsing() {
    let body =
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n";
    assert_eq!(
        parse_range(body.as_bytes(), suffix(PASSWORD)),
        Ok(10_434_004)
    );
}

#[test]
fn fea06_05_not_found_padding() {
    let body =
        "0018A45C4D1DEF81644B54AB7F969B88D65:12\r\nD09CA3762AF61E59520943DC26494F8941B:0\r\n";
    assert_eq!(parse_range(body.as_bytes(), suffix(P123456)), Ok(0));
    let vault = v();
    let mut c = Check::new(&vault);
    c.answer("7C4A8", 200, body.as_bytes()).unwrap();
    assert!(!titles(&c.findings(&vault)).contains(&"Gamma"));
}

#[test]
fn fea06_06_case_and_lf() {
    let body = b"1e4c9b93f3f0682250b6cf8331b7ee68fd8:7\n";
    assert_eq!(parse_range(body, suffix(PASSWORD)), Ok(7));
    // Spaces around the count are trimmed; a missing line gives 0.
    assert_eq!(
        parse_range(
            b"1E4C9B93F3F0682250B6CF8331B7EE68FD8: 12 \r\n",
            suffix(PASSWORD)
        ),
        Ok(12)
    );
    assert_eq!(parse_range(b"", suffix(PASSWORD)), Ok(0));
}

#[test]
fn fea06_07_bad_count() {
    let body = b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:x\r\n";
    assert_eq!(parse_range(body, suffix(PASSWORD)), Ok(0));
    assert_eq!(
        parse_range(
            b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:-4\r\n",
            suffix(PASSWORD)
        ),
        Ok(0)
    );
}

/// Answers for V's four prefixes with the counts of case 06-08.
fn answer_all(c: &mut Check) {
    let line = |full: &str, n: u64| {
        format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:2\r\n{}:{n}\r\n",
            suffix(full)
        )
    };
    c.answer("5BAA6", 200, line(PASSWORD, 10_434_004).as_bytes())
        .unwrap();
    c.answer("7C4A8", 200, line(P123456, 37_359_195).as_bytes())
        .unwrap();
    c.answer("87457", 200, line(TROUB, 1).as_bytes()).unwrap();
    c.answer("F4244", 200, line(CAFE, 0).as_bytes()).unwrap();
}

#[test]
fn fea06_08_results() {
    let vault = v();
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    let f = c.findings(&vault);
    let got: Vec<(&str, u64, &str, &str)> = f
        .iter()
        .map(|x| {
            (
                x.title.as_str(),
                x.count,
                exposure(x.count).1,
                x.path.as_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("Gamma", 37_359_195, "Seen over 1,000,000 times", "Root"),
            ("Alpha", 10_434_004, "Seen over 1,000,000 times", "Root"),
            ("Beta", 10_434_004, "Seen over 1,000,000 times", "Root"),
            ("Eps", 1, "Seen once", "Root"),
        ]
    );
}

#[test]
fn fea06_09_count_texts() {
    let want = [
        (1, "Seen once"),
        (2, "Seen 2 to 10 times"),
        (10, "Seen 2 to 10 times"),
        (11, "Seen 11 to 100 times"),
        (100, "Seen 11 to 100 times"),
        (101, "Seen 101 to 1,000 times"),
        (1000, "Seen 101 to 1,000 times"),
        (1001, "Seen 1,001 to 10,000 times"),
        (10_000, "Seen 1,001 to 10,000 times"),
        (10_001, "Seen 10,001 to 100,000 times"),
        (100_000, "Seen 10,001 to 100,000 times"),
        (100_001, "Seen 100,001 to 1,000,000 times"),
        (1_000_000, "Seen 100,001 to 1,000,000 times"),
        (1_000_001, "Seen over 1,000,000 times"),
    ];
    for (n, text) in want {
        assert_eq!(exposure(n).1, text, "{n}");
    }
    assert_eq!(exposure(1_000_001).0, "MSG-BREACH-COUNT-MORE");
}

#[test]
fn fea06_10_nothing_found() {
    let vault = v();
    let mut c = Check::new(&vault);
    for r in c.requests() {
        let prefix = r.url.rsplit('/').next().unwrap().to_owned();
        c.answer(&prefix, 200, b"0018A45C4D1DEF81644B54AB7F969B88D65:2\r\n")
            .unwrap();
    }
    assert!(c.findings(&vault).is_empty());
    assert_eq!(
        NONE_FOUND,
        "None of your passwords turned up in known leaks."
    );
}

#[test]
fn fea06_11_empty_vault() {
    let mut vault = v();
    vault.root.entries.retain(|e| e.value("Title") == "Delta");
    let c = Check::new(&vault);
    assert!(c.is_empty() && c.requests().is_empty() && c.findings(&vault).is_empty());
}

#[test]
fn fea06_12_error() {
    let vault = v();
    let mut c = Check::new(&vault);
    let line = format!("{}:1\r\n", suffix(TROUB));
    c.answer("87457", 200, line.as_bytes()).unwrap();
    let body = b"secret server text";
    let err = c.answer("5BAA6", 500, body).unwrap_err();
    assert_eq!(err, AnswerError::Status(500));
    let msg = err.message();
    assert!(msg.starts_with("The online check stopped early:") && msg.contains("status 500"));
    assert!(
        !msg.contains("secret server text"),
        "the body is never shown"
    );
    assert_eq!(titles(&c.findings(&vault)), ["Eps"], "findings so far kept");
}

#[test]
fn fea06_13_body_limit() {
    let big = vec![b'A'; 2 << 20];
    assert_eq!(
        parse_range(&big, suffix(PASSWORD)),
        Err(AnswerError::TooLarge)
    );
    let mut c = Check::new(&v());
    assert_eq!(c.answer("5BAA6", 200, &big), Err(AnswerError::TooLarge));
    assert_eq!(
        c.suffixes_held(),
        4,
        "nothing read: the suffix stays for a retry"
    );
    // Exactly 1 MiB is read.
    assert_eq!(parse_range(&vec![b'\n'; MAX_BODY], suffix(PASSWORD)), Ok(0));
}

#[test]
fn fea06_14_excluded_and_references() {
    let mut vault = v();
    let mut ex = ent(0x10, "Ex", "hunter2");
    ex.exclude_from_reports = true;
    vault.root.entries.push(ex);
    let reference = refs::reference('P', uid(0x0a));
    vault.root.entries.push(ent(0x11, "Ref", &reference));
    let c = Check::new(&vault);
    let sent = urls(&c);
    for text in ["hunter2", reference.as_str()] {
        let p = hash(text).prefix;
        assert!(!sent.iter().any(|u| u.ends_with(&p)), "{text}");
    }
    assert_eq!(sent.len(), 4);
}

#[test]
fn fea06_15_recycle_bin_and_history() {
    let mut vault = v();
    let mut bin = Group::new(uid(0x02), "Recycle Bin".into(), at(2026, 1, 1, 0, 0, 0));
    bin.entries.push(ent(0x12, "Old", "letmein"));
    vault.root.groups.push(bin);
    vault.meta.recycle_bin = Some(uid(0x02));
    vault.root.entries[0]
        .history
        .push(ent(0x0a, "Alpha", "iloveyou"));
    let sent = urls(&Check::new(&vault));
    for text in ["letmein", "iloveyou"] {
        let p = hash(text).prefix;
        assert!(!sent.iter().any(|u| u.ends_with(&p)), "{text}");
    }
}

#[test]
fn fea06_16_edit_from_results() {
    let mut vault = v();
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    vault.root.entries[0].set_field(
        "Password".into(),
        Field {
            value: SecretString::new("4v8Nq2LmZ7rT1xKc9WbP".into()),
            protected: true,
        },
    );
    let req = c
        .after_edit(&vault, uid(0x0a), true)
        .expect("one new request");
    assert_eq!(
        req.url,
        format!(
            "https://api.pwnedpasswords.com/range/{}",
            hash("4v8Nq2LmZ7rT1xKc9WbP").prefix
        )
    );
    assert_eq!(c.requests(), [req], "exactly one");
    assert!(!titles(&c.findings(&vault)).contains(&"Alpha"));
    assert!(titles(&c.findings(&vault)).contains(&"Beta"));
    // The new answer finds it again.
    let prefix = hash("4v8Nq2LmZ7rT1xKc9WbP").prefix;
    let line = format!("{}:4\r\n", hash("4v8Nq2LmZ7rT1xKc9WbP").suffix.expose());
    c.answer(&prefix, 200, line.as_bytes()).unwrap();
    assert!(
        c.findings(&vault)
            .iter()
            .any(|f| f.title == "Alpha" && f.count == 4)
    );
    // Edited to an empty password: no request, Alpha leaves.
    vault.root.entries[0].set_field("Password".into(), Field::empty());
    assert_eq!(c.after_edit(&vault, uid(0x0a), true), None);
    assert!(!titles(&c.findings(&vault)).contains(&"Alpha"));
    // Unchanged password: nothing.
    assert_eq!(c.after_edit(&vault, uid(0x0b), false), None);
    assert!(titles(&c.findings(&vault)).contains(&"Beta"));
}

#[test]
fn fea06_17_lock() {
    // Lock drops the check: every hash, suffix and count goes with it
    // (they wipe when dropped). After unlock a new check starts with no
    // findings. Cancelling requests in flight is E6-S7's.
    let vault = v();
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    drop(c);
    let fresh = Check::new(&vault);
    assert!(fresh.findings(&vault).is_empty());
    assert_eq!(fresh.requests().len(), 4);
}

#[test]
fn fea06_18_memory() {
    let vault = v();
    let mut c = Check::new(&vault);
    assert_eq!(c.suffixes_held(), 4, "one per distinct password");
    answer_all(&mut c);
    assert_eq!(c.suffixes_held(), 0, "every suffix wiped once read");
    // The state holds ids, prefixes, suffixes and counts only (no field
    // for a password or a full hash): see `Checked` in breach.rs.
    let src = include_str!("../src/breach.rs");
    let state = &src[src.find("struct Checked {").unwrap()..];
    let state = &state[..state.find('}').unwrap()];
    assert!(
        !state.contains("password") && !state.contains("digest"),
        "{state}"
    );
}

fn file_check(vault: &Vault, text: &str) -> Result<Vec<OfflineFinding>, FileError> {
    offline_check(vault, text.as_bytes())
}

fn shown(f: &[OfflineFinding]) -> Vec<(String, u64)> {
    f.iter().map(|x| (x.path.clone(), x.count)).collect()
}

#[test]
fn fea06_19_offline_basic() {
    let text = format!(
        "{P123456}:37359195\n{}:10434004\r\n{EMPTY}:5\n{CAFE}:0\n",
        PASSWORD.to_ascii_lowercase()
    );
    let f = file_check(&v(), &text).unwrap();
    assert_eq!(
        shown(&f),
        [
            ("Gamma".into(), 37_359_195),
            ("Beta".into(), 10_434_004),
            ("Alpha".into(), 10_434_004),
            ("Delta".into(), 5),
            ("Zeta".into(), 0),
        ]
    );
}

#[test]
fn fea06_20_offline_missing_final_line_end() {
    let text = format!("{P123456}:37359195\n{PASSWORD}:10");
    assert_eq!(file_check(&v(), &text), Err(FileError::Parse(2)));
    assert_eq!(
        FileError::Parse(2).message(),
        "Could not read record 2 of the hash file."
    );
}

#[test]
fn fea06_21_offline_blank_lines_and_plus() {
    let text = format!("{P123456}:37359195\n\n\n{PASSWORD}:+10\n");
    assert_eq!(file_check(&v(), &text), Err(FileError::Parse(2)));
}

#[test]
fn fea06_22_offline_no_colon_or_space() {
    assert_eq!(
        file_check(&v(), &format!("{P123456}37359195\n")),
        Err(FileError::Parse(1))
    );
    assert_eq!(
        file_check(&v(), &format!("{P123456} :1\n")),
        Err(FileError::Parse(1))
    );
    assert_eq!(
        file_check(&v(), &format!("{P123456}:1 \n")),
        Err(FileError::Parse(1))
    );
    assert_eq!(
        file_check(&v(), &format!("{P123456}:-1\n")),
        Err(FileError::Parse(1))
    );
    assert_eq!(file_check(&v(), &P123456[..30]), Err(FileError::Parse(1)));
}

#[test]
fn fea06_23_offline_empty_count() {
    let f = file_check(&v(), &format!("{P123456}:\n")).unwrap();
    assert_eq!(shown(&f), [("Gamma".into(), 0)]);
}

#[test]
fn fea06_24_offline_line_ends() {
    let f = file_check(&v(), &format!("{P123456}:12\r{PASSWORD}:3\r\n")).unwrap();
    assert_eq!(
        shown(&f),
        [
            ("Gamma".into(), 12),
            ("Beta".into(), 3),
            ("Alpha".into(), 3)
        ]
    );
}

#[test]
fn fea06_25_offline_empty_file() {
    assert_eq!(file_check(&v(), ""), Ok(Vec::new()));
}

#[test]
fn fea06_26_offline_non_hex() {
    let text = format!("{}Z:9\n", &P123456[..39]);
    assert_eq!(file_check(&v(), &text), Err(FileError::Parse(1)));
}

#[test]
fn fea06_27_offline_big_count() {
    let f = file_check(&v(), &format!("{PASSWORD}:4294967297\n")).unwrap();
    assert_eq!(
        shown(&f),
        [
            ("Beta".into(), 4_294_967_297),
            ("Alpha".into(), 4_294_967_297)
        ]
    );
    // Past the 64-bit maximum it stops there.
    let f = file_check(&v(), &format!("{PASSWORD}:99999999999999999999999\n")).unwrap();
    assert_eq!(f[0].count, u64::MAX);
}

#[test]
fn fea06_28_offline_path_text() {
    let mut vault = v();
    let mut work = Group::new(uid(0x02), "Work".into(), at(2026, 1, 1, 0, 0, 0));
    let mut mail = Group::new(uid(0x03), "Mail".into(), at(2026, 1, 1, 0, 0, 0));
    mail.entries.push(ent(0x10, "Site", "123456"));
    work.groups.push(mail);
    vault.root.entries.retain(|e| e.value("Title") != "Gamma");
    vault.root.groups.push(work);
    let f = file_check(&vault, &format!("{P123456}:3\n")).unwrap();
    assert_eq!(shown(&f), [("Work/Mail/Site".into(), 3)]);
}

/// Hash-file records made on the fly: `n` records cycling through a block
/// of 1,024 random-looking ones, then the `123456` record; never held in
/// memory beyond the block.
struct Records {
    block: Vec<u8>,
    left: u64,
    at: usize,
    last: Vec<u8>,
}

const LINE: usize = 48;

impl Records {
    fn new(n: u64) -> Self {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut block = Vec::with_capacity(1024 * LINE);
        for _ in 0..1024 {
            for _ in 0..40 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                block.push(b"0123456789ABCDEF"[(state % 16) as usize]);
            }
            block.extend_from_slice(b":12345\r\n");
        }
        Self {
            block,
            left: n.saturating_sub(1) * LINE as u64,
            at: 0,
            last: format!("{P123456}:3\r\n").into_bytes(),
        }
    }
}

impl Read for Records {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            let n = buf.len().min(self.last.len());
            buf[..n].copy_from_slice(&self.last[..n]);
            self.last.drain(..n);
            return Ok(n);
        }
        let room = (self.block.len() - self.at)
            .min(buf.len())
            .min(self.left as usize);
        buf[..room].copy_from_slice(&self.block[self.at..self.at + room]);
        self.at = (self.at + room) % self.block.len();
        self.left -= room as u64;
        Ok(room)
    }
}

/// Held by the tests that measure or use much memory, so the stream test's
/// memory reading is its own.
static HEAVY: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The resident memory of this process in KiB.
#[cfg(target_os = "macos")]
fn rss_kib() -> u64 {
    larsal_platform::macos::resident_bytes().unwrap() / 1024
}

#[cfg(not(target_os = "macos"))]
fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

#[test]
fn fea06_29_offline_streams() {
    // 06-29: 5 GB in release (about 104 million 48-byte records); a
    // smaller stream in debug builds. Memory stays flat either way.
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let records: u64 = if cfg!(debug_assertions) {
        200_000
    } else {
        5_000_000_000 / LINE as u64
    };
    let before = rss_kib();
    let t = std::time::Instant::now();
    let f = offline_check(
        &v(),
        BufReader::with_capacity(64 << 10, Records::new(records)),
    )
    .unwrap();
    let after = rss_kib();
    println!(
        "STREAM {records} records ({} MB) in {:.1} s; RSS {before} -> {after} KiB",
        records * LINE as u64 / 1_000_000,
        t.elapsed().as_secs_f64()
    );
    assert_eq!(shown(&f), [("Gamma".into(), 3)]);
    assert!(
        after < 100 * 1024 || after.saturating_sub(before) < 16 * 1024,
        "{before} -> {after} KiB"
    );
}

#[test]
fn fea06_30_no_outside_program() {
    // D-06-10: nothing in the breach code can start a process.
    let src = include_str!("../src/breach.rs");
    for word in ["std::process", "Command::new", "spawn("] {
        assert!(!src.contains(word), "{word}");
    }
}

#[test]
fn fea06_hash_file_reader_records() {
    // Records one by one: lowercase and uppercase hex, CR, LF and CR LF.
    let text = format!("{}:1\r\n\r\n{P123456}:\n", PASSWORD.to_ascii_lowercase());
    let mut r = HashFile::new(text.as_bytes());
    let mut h = [0u8; 20];
    assert_eq!(r.next_record(&mut h), Ok(Some(1)));
    assert_eq!((h[0], h[19]), (0x5B, 0xD8));
    assert_eq!(r.next_record(&mut h), Ok(Some(0)));
    assert_eq!(h[0], 0x7C);
    assert_eq!(r.next_record(&mut h), Ok(None));
    // A blank line before the first record is not "after a line end".
    assert_eq!(
        HashFile::new(format!("\n{P123456}:1\n").as_bytes()).next_record(&mut h),
        Err(FileError::Parse(1))
    );
}

#[test]
fn fea06_ld137_findings_drop_entries_excluded_since() {
    // LD-137 (5), FEA-06.9: an entry excluded after the run is not listed.
    let mut vault = v();
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    vault.root.entries[1].exclude_from_reports = true;
    assert_eq!(titles(&c.findings(&vault)), ["Gamma", "Alpha", "Eps"]);
}

#[test]
fn fea06_ld137_indexes_with_100000_passwords() {
    // LD-137 (6): requests and answers by index, not by scanning.
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let mut root = Group::new(uid(0x01), "Root".into(), at(2026, 1, 1, 0, 0, 0));
    for i in 0..100_000u32 {
        let mut e = Entry::new(
            Uuid([
                (i % 251) as u8,
                (i / 251) as u8,
                (i / 63_001) as u8,
                3,
                3,
                3,
                3,
                3,
                3,
                3,
                3,
                3,
                3,
                3,
                3,
                1,
            ]),
            at(2026, 1, 1, 0, 0, 0),
        );
        e.set_field(
            "Password".into(),
            Field {
                value: SecretString::new(format!("demo-{i}")),
                protected: true,
            },
        );
        root.entries.push(e);
    }
    let vault = Vault::new(root, at(2026, 1, 1, 0, 0, 0));
    let t = std::time::Instant::now();
    let mut c = Check::new(&vault);
    let requests = c.requests();
    for r in &requests {
        let prefix = r.url.rsplit('/').next().unwrap().to_owned();
        c.answer(&prefix, 200, b"0018A45C4D1DEF81644B54AB7F969B88D65:2\r\n")
            .unwrap();
    }
    assert!(c.requests().is_empty() && c.suffixes_held() == 0);
    assert!(c.findings(&vault).is_empty());
    let ms = t.elapsed().as_millis();
    println!(
        "TIMING 100,000 passwords, {} prefixes: {ms} ms",
        requests.len()
    );
    assert!(requests.len() > 60_000);
    assert!(
        ms < if cfg!(debug_assertions) {
            30_000
        } else {
            3_000
        },
        "{ms} ms"
    );
}

#[test]
fn fea06_ld137_online_count_saturates() {
    // LD-135 (7): an online count past the 64-bit maximum stops there.
    let body = b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:99999999999999999999999\r\n";
    assert_eq!(parse_range(body, suffix(PASSWORD)), Ok(u64::MAX));
}

#[test]
fn fea06_ld137_offline_checks_excluded_entries() {
    // D-06-9: offline, excluded entries are checked and listed too.
    let mut vault = v();
    vault.root.entries[2].exclude_from_reports = true;
    let f = file_check(&vault, &format!("{P123456}:3\n")).unwrap();
    assert_eq!(shown(&f), [("Gamma".into(), 3)]);
}

#[test]
fn fea06_ld137_edit_skip_paths() {
    // FEA-06.11: an entry that became excluded or now holds a field
    // reference sends nothing and leaves the findings.
    let mut vault = v();
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    vault.root.entries[0].exclude_from_reports = true;
    assert_eq!(c.after_edit(&vault, uid(0x0a), false), None);
    assert!(!titles(&c.findings(&vault)).contains(&"Alpha"));
    vault.root.entries[1].set_field(
        "Password".into(),
        Field {
            value: SecretString::new(refs::reference('P', uid(0x0c))),
            protected: true,
        },
    );
    assert_eq!(c.after_edit(&vault, uid(0x0b), true), None);
    assert!(!titles(&c.findings(&vault)).contains(&"Beta"));
    assert!(c.requests().is_empty());
}

/// LD-207, LD-208 (9): Gamma's Title protected by its own flag or by the
/// vault's flag for the Title.
fn protected_title(own_flag: bool) -> Vault {
    let mut vault = v();
    if own_flag {
        vault.root.entries[2].set_field(
            "Title".into(),
            Field {
                value: SecretString::new("Gamma".into()),
                protected: true,
            },
        );
    } else {
        vault.meta.memory_protection.title = true;
    }
    vault
}

#[test]
fn fea06_ld207_own_flag_masks_the_title() {
    let mask = larsal_core::health::MASKED_TITLE;
    let vault = protected_title(true);
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    let f = c.findings(&vault);
    assert_eq!(titles(&f), [mask, "Alpha", "Beta", "Eps"]);
    assert_eq!(f[0].entry, uid(0x0c), "the finding keeps the id");
    let off = file_check(&vault, &format!("{P123456}:3\n")).unwrap();
    assert_eq!(shown(&off), [(mask.into(), 3)]);
}

#[test]
fn fea06_ld207_vault_flag_masks_every_title() {
    let mask = larsal_core::health::MASKED_TITLE;
    let mut vault = protected_title(false);
    let mut c = Check::new(&vault);
    answer_all(&mut c);
    assert_eq!(titles(&c.findings(&vault)), [mask; 4]);
    let off = file_check(&vault, &format!("{P123456}:3\n")).unwrap();
    assert_eq!(shown(&off), [(mask.into(), 3)]);
    // Below the root group the path ends in the mask too.
    let gamma = vault.root.entries.remove(2);
    let mut sub = Group::new(uid(0x02), "Sub".into(), at(2026, 1, 1, 0, 0, 0));
    sub.entries.push(gamma);
    vault.root.groups.push(sub);
    let off = file_check(&vault, &format!("{P123456}:3\n")).unwrap();
    assert_eq!(shown(&off), [(format!("Sub/{mask}"), 3)]);
}
