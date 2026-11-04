//! Breach check (FEA-06, story E4-S11): the online range query's core parts
//! (which passwords, hash, prefix and suffix, the request description, the
//! answer reader, the findings) and the offline hash-file check. The HTTPS
//! call is app-platform's (E6-S7): nothing here touches the network.
//!
//! Guarantees:
//! - Only the 5-character prefix of a hash is plain text. Full hashes and
//!   suffixes live in secret types; a suffix is wiped as soon as its answer
//!   is read, and a check never keeps a password as a key (FEA-06.13).
//! - Every read is bounded: an answer body over 1 MiB is an error
//!   (D-06-6), and the hash file is read once as a stream with fixed
//!   memory, never loaded (FEA-06.19).
//! - Results hold entry ids, titles, paths and counts only.
//! - No outside program is ever run (D-06-10).

use crate::edit::holds_reference;
use crate::health::{Item, live_items};
use crate::text::Text;
use app_crypto::hash::sha1;
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::{Uuid, Vault};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, ErrorKind};

/// The service's range address; the prefix follows (FEA-06.4).
pub const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
/// The user agent: the product name only (FEA-06.4).
pub const USER_AGENT: &str = "App";
/// The most bytes of one answer body App reads (D-06-6).
pub const MAX_BODY: usize = 1 << 20;
/// Requests running at the same time, at most (FEA-06.4).
pub const MAX_PARALLEL: usize = 6;
/// `MSG-BREACH-NONE` (FEA-06.10).
pub const NONE_FOUND: &str = "None of your passwords turned up in known leaks.";

/// The hash of a password: its plain prefix and its secret suffix
/// (FEA-06.3).
pub struct Hashed {
    /// The first 5 uppercase hex characters.
    pub prefix: String,
    /// The other 35, uppercase.
    pub suffix: SecretString,
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn digest(password: &str) -> SecretBytes {
    sha1(&[password.as_bytes()])
}

fn split(d: &SecretBytes) -> Hashed {
    let mut hex = Text::new();
    for &b in d.expose() {
        for nibble in [b >> 4, b & 0x0F] {
            hex.push(char::from(
                HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    let prefix = hex.as_str().get(..5).unwrap_or("").to_owned();
    let mut suffix = Text::new();
    suffix.push_str(hex.as_str().get(5..).unwrap_or(""));
    Hashed {
        prefix,
        suffix: suffix.into_secret(),
    }
}

/// SHA-1 of the UTF-8 bytes of `password`, as prefix and suffix (FEA-06.3).
#[must_use]
pub fn hash(password: &str) -> Hashed {
    split(&digest(password))
}

/// One GET the network client sends (FEA-06.4): no cookies, no
/// `Referer`, no `Accept-Language`, no authentication, no body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `RANGE_URL` + the prefix.
    pub url: String,
    /// The only headers App sets.
    pub headers: [(&'static str, &'static str); 2],
}

/// The request for one prefix.
#[must_use]
pub fn request(prefix: &str) -> Request {
    Request {
        url: format!("{RANGE_URL}{prefix}"),
        headers: [("User-Agent", USER_AGENT), ("Add-Padding", "true")],
    }
}

/// Why an answer was not read (FEA-06.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
    /// A status other than 200.
    Status(u16),
    /// A body over [`MAX_BODY`].
    TooLarge,
}

impl AnswerError {
    /// `MSG-BREACH-FAILED` with the plain reason; never the body.
    #[must_use]
    pub fn message(&self) -> String {
        let reason = match self {
            Self::Status(code) => format!("the service answered with status {code}"),
            Self::TooLarge => "the service's answer was too large".to_owned(),
        };
        format!("The online check stopped early: {reason}")
    }
}

/// Digits after `:` with spaces trimmed, saturating at the 64-bit maximum;
/// anything else is 0 (FEA-06.6).
fn count_of(text: &[u8]) -> u64 {
    let start = text.iter().position(|&b| b != b' ').unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(start, |e| e.saturating_add(1));
    let digits = text.get(start..end).unwrap_or(&[]);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return 0;
    }
    digits.iter().fold(0u64, |n, d| {
        n.saturating_mul(10)
            .saturating_add(u64::from(d.saturating_sub(b'0')))
    })
}

/// Reads a range answer for `suffix` (FEA-06.5, FEA-06.6): lines
/// `SUFFIX:COUNT` split by LF (a CR before it is dropped); the first line
/// whose suffix equals ours without case gives the count. No such line, a
/// count that is not a number, and padding lines all give 0.
///
/// # Errors
/// [`AnswerError::TooLarge`] for a body over [`MAX_BODY`].
pub fn parse_range(body: &[u8], suffix: &str) -> Result<u64, AnswerError> {
    if body.len() > MAX_BODY {
        return Err(AnswerError::TooLarge);
    }
    for line in body.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (key, rest) = line.split_at(colon);
        if key.eq_ignore_ascii_case(suffix.as_bytes()) {
            return Ok(count_of(rest.get(1..).unwrap_or(&[])));
        }
    }
    Ok(0)
}

/// What an entry's password must be to be checked online (FEA-06.2).
fn online_candidate(e: &app_model::Entry) -> bool {
    let pw = e.value("Password");
    !pw.is_empty() && !e.exclude_from_reports && !holds_reference(pw)
}

/// One checked password: its entries, prefix, suffix and count only.
struct Checked {
    entries: Vec<Uuid>,
    prefix: String,
    suffix: Option<SecretString>,
    count: Option<u64>,
}

/// An online breach check's state (FEA-06.2 to FEA-06.13). Dropping it (on
/// lock or close) drops every hash and count (FEA-06.12).
pub struct Check {
    passwords: Vec<Checked>,
    /// LD-137 (6): each prefix's passwords, by index.
    by_prefix: HashMap<String, Vec<usize>>,
}

/// One finding to list (FEA-06.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The entry.
    pub entry: Uuid,
    /// Its title, masked when protected (LD-207, LD-208 (9)).
    pub title: String,
    /// Its group path, root group included, joined with `/`.
    pub path: String,
    /// Times the password was seen, more than 0.
    pub count: u64,
}

/// Groups items by password hash: (digest, item indices in tree order),
/// sorted by digest. The digests are secret and wiped when dropped.
fn by_hash(
    items: &[Item<'_>],
    take: impl Fn(&app_model::Entry) -> bool,
) -> Vec<(SecretBytes, Vec<usize>)> {
    let mut hashed: Vec<(SecretBytes, usize)> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| take(it.e))
        .map(|(i, it)| (digest(it.e.value("Password")), i))
        .collect();
    // Stable: equal hashes keep tree order.
    hashed.sort_by(|a, b| a.0.expose().cmp(b.0.expose()));
    let mut out: Vec<(SecretBytes, Vec<usize>)> = Vec::new();
    for (d, i) in hashed {
        match out.last_mut() {
            Some((last, list)) if last.expose() == d.expose() => list.push(i),
            _ => out.push((d, vec![i])),
        }
    }
    out
}

impl Check {
    /// The passwords to check (FEA-06.2): live entries in tree order outside
    /// the recycle bin, not empty, not excluded (D-06-2), no field reference
    /// (D-06-3); equal passwords once.
    #[must_use]
    pub fn new(vault: &Vault) -> Self {
        let items = live_items(vault);
        let mut groups = by_hash(&items, online_candidate);
        // First-seen tree order.
        groups.sort_by_key(|(_, list)| list.first().copied().unwrap_or(usize::MAX));
        let passwords = groups
            .into_iter()
            .map(|(d, list)| {
                let h = split(&d);
                Checked {
                    entries: list
                        .iter()
                        .filter_map(|&i| items.get(i))
                        .map(|it| it.e.uuid)
                        .collect(),
                    prefix: h.prefix,
                    suffix: Some(h.suffix),
                    count: None,
                }
            })
            .collect();
        let mut check = Self {
            passwords,
            by_prefix: HashMap::new(),
        };
        check.reindex();
        check
    }

    fn reindex(&mut self) {
        self.by_prefix.clear();
        for (i, p) in self.passwords.iter().enumerate() {
            self.by_prefix.entry(p.prefix.clone()).or_default().push(i);
        }
    }

    /// Nothing to check: show the result at once (FEA-06.7).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passwords.is_empty()
    }

    /// Entries whose password is checked (FEA-06.2): the report's "not
    /// found" count is this minus the findings.
    #[must_use]
    pub fn entries_checked(&self) -> usize {
        self.passwords.iter().map(|p| p.entries.len()).sum()
    }

    /// The requests still to send: one per distinct prefix of a password
    /// not yet answered, in first-seen order (D-06-4).
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        let mut seen: HashSet<&str> = HashSet::new();
        self.passwords
            .iter()
            .filter(|p| p.count.is_none() && seen.insert(p.prefix.as_str()))
            .map(|p| request(&p.prefix))
            .collect()
    }

    /// Reads the answer for `prefix` (FEA-06.6): every waiting password with
    /// that prefix gets its count, and its suffix is wiped.
    ///
    /// # Errors
    /// A status other than 200 or a body over 1 MiB (FEA-06.8); the
    /// findings so far stay.
    pub fn answer(&mut self, prefix: &str, status: u16, body: &[u8]) -> Result<(), AnswerError> {
        if status != 200 {
            return Err(AnswerError::Status(status));
        }
        if body.len() > MAX_BODY {
            return Err(AnswerError::TooLarge);
        }
        let Some(list) = self.by_prefix.get(prefix) else {
            return Ok(());
        };
        for &i in list {
            let Some(p) = self.passwords.get_mut(i).filter(|p| p.count.is_none()) else {
                continue;
            };
            if let Some(suffix) = p.suffix.take() {
                p.count = Some(parse_range(body, suffix.expose())?);
            }
        }
        Ok(())
    }

    /// Suffixes still held (the FEA-06.13 test hook): 0 once every answer
    /// is read.
    #[must_use]
    pub fn suffixes_held(&self) -> usize {
        self.passwords.iter().filter(|p| p.suffix.is_some()).count()
    }

    /// The findings (FEA-06.9): every checked entry whose password was
    /// found and that is not excluded now, count highest first, equal
    /// counts in tree order (D-06-7).
    #[must_use]
    pub fn findings(&self, vault: &Vault) -> Vec<Finding> {
        let items = live_items(vault);
        let place: HashMap<Uuid, usize> = items
            .iter()
            .enumerate()
            .map(|(i, it)| (it.e.uuid, i))
            .collect();
        let mut out: Vec<(usize, Finding)> = Vec::new();
        for p in &self.passwords {
            let Some(count) = p.count.filter(|&c| c > 0) else {
                continue;
            };
            for id in &p.entries {
                // FEA-06.9, LD-137 (5): an entry excluded since the run
                // is never listed.
                let found = place.get(id).and_then(|&at| Some((at, items.get(at)?)));
                if let Some((at, it)) = found.filter(|(_, it)| !it.e.exclude_from_reports) {
                    out.push((
                        at,
                        Finding {
                            entry: *id,
                            title: it.title.to_owned(),
                            path: it.path.clone(),
                            count,
                        },
                    ));
                }
            }
        }
        out.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(&b.0)));
        out.into_iter().map(|(_, f)| f).collect()
    }

    /// After entry `id` was edited from the results (FEA-06.11): it leaves
    /// its old password's findings when the password changed or it can no
    /// longer be checked; a changed password that can be checked gets one
    /// new request. An empty password, an excluded entry or a field
    /// reference sends nothing.
    pub fn after_edit(
        &mut self,
        vault: &Vault,
        id: Uuid,
        password_changed: bool,
    ) -> Option<Request> {
        let entry = live_items(vault)
            .into_iter()
            .find(|it| it.e.uuid == id)
            .map(|it| it.e);
        let checkable = entry.is_some_and(online_candidate);
        if !password_changed && checkable {
            return None;
        }
        for p in &mut self.passwords {
            p.entries.retain(|e| *e != id);
        }
        self.passwords.retain(|p| !p.entries.is_empty());
        self.reindex();
        let e = entry.filter(|_| checkable)?;
        let h = hash(e.value("Password"));
        let req = request(&h.prefix);
        self.by_prefix
            .entry(h.prefix.clone())
            .or_default()
            .push(self.passwords.len());
        self.passwords.push(Checked {
            entries: vec![id],
            prefix: h.prefix,
            suffix: Some(h.suffix),
            count: None,
        });
        Some(req)
    }
}

/// The exposure band of a count (FEA-06.9): its message id and App's text.
#[must_use]
pub fn exposure(count: u64) -> (&'static str, &'static str) {
    match count {
        0 | 1 => ("MSG-BREACH-COUNT-1", "Seen once"),
        2..=10 => ("MSG-BREACH-COUNT-10", "Seen 2 to 10 times"),
        11..=100 => ("MSG-BREACH-COUNT-100", "Seen 11 to 100 times"),
        101..=1_000 => ("MSG-BREACH-COUNT-1K", "Seen 101 to 1,000 times"),
        1_001..=10_000 => ("MSG-BREACH-COUNT-10K", "Seen 1,001 to 10,000 times"),
        10_001..=100_000 => ("MSG-BREACH-COUNT-100K", "Seen 10,001 to 100,000 times"),
        100_001..=1_000_000 => ("MSG-BREACH-COUNT-1M", "Seen 100,001 to 1,000,000 times"),
        _ => ("MSG-BREACH-COUNT-MORE", "Seen over 1,000,000 times"),
    }
}

// ---------------------------------------------------------------------------
// Offline (FEA-06.14 to FEA-06.20).

/// Why the hash file check stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// `MSG-BREACH-FILE-PARSE` for record N, counted from 1 (FEA-06.15).
    Parse(u64),
    /// The file could not be read.
    Io(ErrorKind),
}

impl FileError {
    /// `MSG-BREACH-FILE-PARSE` for a parse error.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Parse(n) => format!("Could not read record {n} of the hash file."),
            Self::Io(kind) => format!("Could not read the hash file: {kind}."),
        }
    }
}

/// A streaming reader of hash file records (FEA-06.14 to FEA-06.17):
/// fixed memory whatever the file's size.
pub struct HashFile<R> {
    reader: R,
    record: u64,
    after_line_end: bool,
}

impl<R: BufRead> HashFile<R> {
    /// Reads records from `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            record: 0,
            after_line_end: false,
        }
    }

    /// The next record: its 20 hash bytes go into `hash` (a buffer the
    /// caller wipes, LD-137 (7)) and its count comes back (empty count 0,
    /// saturating at the 64-bit maximum); `None` at the end of the file.
    /// `hash` must hold at least 20 bytes.
    ///
    /// # Errors
    /// [`FileError::Parse`] with the record number: fewer than 40 hex
    /// characters (a non-hex one included, D-06-8), no `:`, anything but
    /// digits before the line end, or no line end before the end of the
    /// file. [`FileError::Io`] when reading fails.
    pub fn next_record(&mut self, hash: &mut [u8]) -> Result<Option<u64>, FileError> {
        // Stages: 0 before the record (blank lines skipped only after a
        // line end), 1 to 40 the hex characters read, 41 the `:` read.
        let mut stage = 0usize;
        let mut count = 0u64;
        loop {
            let buf = match self.reader.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(FileError::Io(e.kind())),
            };
            if buf.is_empty() {
                return if stage == 0 {
                    Ok(None)
                } else {
                    Err(FileError::Parse(self.record))
                };
            }
            let mut used = 0usize;
            let mut done = false;
            for &b in buf {
                used = used.saturating_add(1);
                if stage == 0 {
                    if self.after_line_end && matches!(b, b'\r' | b'\n') {
                        continue;
                    }
                    self.record = self.record.saturating_add(1);
                }
                let bad = FileError::Parse(self.record);
                if stage < 40 {
                    let nibble = match b {
                        b'0'..=b'9' => b.saturating_sub(b'0'),
                        b'a'..=b'f' => b.saturating_sub(b'a').saturating_add(10),
                        b'A'..=b'F' => b.saturating_sub(b'A').saturating_add(10),
                        _ => return Err(bad),
                    };
                    if let Some(byte) = hash.get_mut(stage / 2) {
                        *byte = if stage.is_multiple_of(2) {
                            nibble << 4
                        } else {
                            *byte | nibble
                        };
                    }
                } else if stage == 40 {
                    if b != b':' {
                        return Err(bad);
                    }
                } else {
                    match b {
                        b'0'..=b'9' => {
                            count = count
                                .saturating_mul(10)
                                .saturating_add(u64::from(b.saturating_sub(b'0')));
                        }
                        b'\r' | b'\n' => {
                            done = true;
                            break;
                        }
                        _ => return Err(bad),
                    }
                    continue;
                }
                stage = stage.saturating_add(1);
            }
            self.reader.consume(used);
            if done {
                self.after_line_end = true;
                return Ok(Some(count));
            }
        }
    }
}

/// One offline finding (FEA-06.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineFinding {
    /// The entry.
    pub entry: Uuid,
    /// The group names below the root group and the title, joined with `/`.
    pub path: String,
    /// The record's count; 0 means leaked, without a number.
    pub count: u64,
}

/// The offline check (FEA-06.18, FEA-06.19): every live entry outside the
/// recycle bin is hashed first, empty and excluded ones included (D-06-9);
/// then the file is read once. Findings come in file order; entries
/// sharing a hash in reverse tree order.
///
/// # Errors
/// The first [`FileError`]; no findings then (FEA-06.15).
pub fn offline_check<R: BufRead>(vault: &Vault, file: R) -> Result<Vec<OfflineFinding>, FileError> {
    let items = live_items(vault);
    let hashes = by_hash(&items, |_| true);
    let root = vault.root.name.as_str();
    let path_of = |it: &Item<'_>| {
        let below = it
            .path
            .strip_prefix(root)
            .and_then(|p| p.strip_prefix('/'))
            .unwrap_or("");
        if below.is_empty() {
            it.title.to_owned()
        } else {
            format!("{below}/{}", it.title)
        }
    };
    let mut file = HashFile::new(file);
    let mut out = Vec::new();
    // LD-137 (7): one wiped buffer holds each record's hash in turn.
    let mut hash = SecretBytes::zeroed(20);
    while let Some(count) = file.next_record(hash.expose_mut())? {
        let Ok(at) = hashes.binary_search_by(|(d, _)| d.expose().cmp(hash.expose())) else {
            continue;
        };
        if let Some((_, list)) = hashes.get(at) {
            for it in list.iter().rev().filter_map(|&i| items.get(i)) {
                out.push(OfflineFinding {
                    entry: it.e.uuid,
                    path: path_of(it),
                    count,
                });
            }
        }
    }
    Ok(out)
}
