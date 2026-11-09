//! Encrypt File and Decrypt File in the Mac app (FIL-02, E22-S4) over
//! larsal-files. Swift sends paths, a vault and group id, an entry id, a
//! title, public recipient text, and a passphrase only as the user typed it,
//! once, in the call that starts the work. It gets back progress (a step and
//! byte counts), one fixed message, a cleaned label of the saved file, the
//! public recipient of a new file key, and the generated passphrase only by
//! Show. No file key, private key, payload key or plaintext ever crosses.
//!
//! One operation runs at a time (FIL-02.17), on its own thread. Its gate is a
//! mutex the worker holds from one safe point to the next, so a write starts
//! only under a pass no revoke has ended: [`FileJob::revoke`] marks the job,
//! then takes the gate, and returns once no write can start (FIL-02.13). A
//! lock, a close or a quit marks every job at once (FIL-02.14). The worker
//! lets the gate go before each key derivation and while it waits for an
//! answer, so a revoke never waits on either.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use larsal_core::generator::{passphrase, wordlist};
use larsal_core::{edit, recycle};
use larsal_crypto::secret::SecretString;
use larsal_files::limits::{CHUNK, MAX_PASSPHRASE, TAG};
use larsal_files::{
    Error, Identities, Lock, OutputFolder, Phase, Recipient, ScratchRoot, SourceFile, Unlock,
    Validation, clean_label, encrypt_file, generate_identity,
};
use larsal_model::Uuid;
use larsal_model::entry::Field;

use crate::session::{LarsalError, MAX_TEXT, Session};
use crate::views::{find, hex, now, parse_id};

/// The longest path a file export takes, in bytes.
const MAX_PATH: usize = 4096;
/// FIL-03.12: room for an encrypted file's header and last chunk, in the estimate.
const OVERHEAD: u64 = 65_536;
/// The folder for ciphertext scratch under Larsal's settings folder.
const SCRATCH: &str = "file-scratch";
/// FIL-01.6: ten lower-case words of the built-in list, one space.
const WORDS: u32 = 10;
/// The protected field of a file key (FIL-01.17).
pub const KEY_FIELD: &str = "File key";
/// Its public recipient, plain.
pub const RECIPIENT_FIELD: &str = "File key recipient";

/// MSG-FILE-BUSY.
pub const BUSY: &str = "A file operation is already running.";
/// MSG-FILE-SAVED-KEY.
pub const SAVED_KEY: &str =
    "The passphrase is saved in your vault. No encrypted file was completed.";
/// Proposed, E22-S4 (FIL-02.5, FIL-02-T05): the entry did not save.
pub const ENTRY_UNSAVED: &str = "The passphrase could not be saved in your vault, so no file was encrypted. Save the vault, then try again.";
/// Proposed, E22-S4 (FIL-02.9, FIL-02-T09): the file key did not save.
pub const KEY_UNSAVED: &str = "The file key could not be saved in your vault, so it was not created. Save the vault, then try again.";
/// MSG-FILE-REPEAT.
pub const REPEAT: &str = "The passphrases do not match.";

/// Which long step a file operation is in (FIL-02.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileStep {
    /// Encrypt with a generated passphrase: the entry and the vault's save.
    SavingPassphrase,
    /// Encrypt: the encrypted copy is written.
    Encrypting,
    /// Decrypt: the encrypted file is copied to private scratch.
    Preparing,
    /// Decrypt: every chunk is checked; nothing readable is kept.
    Checking,
    /// Decrypt: the readable file is written.
    Saving,
}

impl FileStep {
    fn of(n: u8) -> Self {
        match n {
            0 => Self::SavingPassphrase,
            1 => Self::Encrypting,
            2 => Self::Preparing,
            3 => Self::Checking,
            _ => Self::Saving,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::SavingPassphrase => 0,
            Self::Encrypting => 1,
            Self::Preparing => 2,
            Self::Checking => 3,
            Self::Saving => 4,
        }
    }
}

/// How a job ended, or what it waits for.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FileEnd {
    /// MSG-FILE-WEAK: the whole file checked, with a low work factor. Answer
    /// with [`FileJob::answer_weak`] and this `question`; Cancel is the default.
    AskWeak {
        /// This question's number in the job: only an answer to it counts.
        question: u64,
    },
    /// MSG-FILE-UNPROTECTED's warned consent (E22-S4): the chosen disk cannot
    /// keep the readable file private; nothing is written yet. Answer with
    /// [`FileJob::answer_weak`] and this `question`; Cancel is the default.
    AskUnprotected {
        /// This question's number in the job: only an answer to it counts.
        question: u64,
    },
    /// The output is complete under its chosen name.
    Done {
        /// The folder's name and the file's, as cleaned plain text.
        saved_to: String,
        /// The readable or encrypted bytes written.
        bytes: u64,
    },
    /// A failure or a cancel, in FIL-03's words.
    Failed {
        /// The message's id, `MSG-FILE-…`.
        id: String,
        /// Its fixed words; never a path, a value or a system's text.
        text: String,
        /// FIL-02.6: the generated passphrase is saved in the vault
        /// (MSG-FILE-SAVED-KEY goes with it).
        saved_key: bool,
    },
}

/// What Swift reads while a job runs. No content, only counts.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileProgress {
    /// The step now.
    pub step: FileStep,
    /// Bytes of this step done.
    pub done: u64,
    /// This step's whole, 0 when not known (shown without a measure).
    pub total: u64,
    /// The end, or the question, once there is one.
    pub end: Option<FileEnd>,
    /// The worker is over: every cleanup ran.
    pub finished: bool,
}

/// What starting a job gave.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FileStart {
    /// It runs; poll it.
    Started {
        /// The job.
        job: Arc<FileJob>,
    },
    /// MSG-FILE-BUSY: another one runs; nothing was replaced.
    Busy,
    /// FIL-01.7: a typed passphrase below Excellent, not yet confirmed.
    Weak,
    /// Refused before any work, in plain words (a missing repeat, an
    /// invalid key, a locked vault).
    Refused {
        /// The words.
        text: String,
    },
}

/// Where a passphrase or a file key is saved (FIL-02.5, FIL-02.7, FIL-02.9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileSave {
    /// The open, unlocked vault.
    pub vault: u64,
    /// The group, 32 hex digits; `None` for the root.
    pub group: Option<String>,
    /// The new entry's title.
    pub title: String,
}

/// The credential of a decrypt (FIL-02.10). Rust only: the sheet sends typed text
/// through [`FileTyped`] (S2-04). Typed text stays in wiping types (C2R3-04).
pub enum FileCredential {
    /// A typed passphrase.
    Passphrase {
        /// As typed.
        text: SecretString,
    },
    /// An entry of an open vault, by id: its file key when it has one,
    /// else its password.
    Entry {
        /// The vault.
        vault: u64,
        /// The entry, 32 hex digits.
        entry: String,
    },
    /// A key file the user chose, and the passphrase it may need.
    KeyFile {
        /// Its path.
        path: String,
        /// A typed passphrase for an encrypted key file.
        passphrase: Option<SecretString>,
    },
}

impl Clone for FileCredential {
    /// A typed text is copied into a new wiping buffer.
    fn clone(&self) -> Self {
        let copy = |s: &SecretString| SecretString::from(s.expose());
        match self {
            Self::Passphrase { text } => Self::Passphrase { text: copy(text) },
            Self::Entry { vault, entry } => Self::Entry {
                vault: *vault,
                entry: entry.clone(),
            },
            Self::KeyFile { path, passphrase } => Self::KeyFile {
                path: path.clone(),
                passphrase: passphrase.as_ref().map(copy),
            },
        }
    }
}

impl std::fmt::Debug for FileCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Passphrase { .. } => "Passphrase(<hidden>)",
            Self::Entry { .. } => "Entry",
            Self::KeyFile { .. } => "KeyFile",
        })
    }
}

/// An entry that can decrypt or that is one's own file key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileKeyChoice {
    /// The entry, 32 hex digits.
    pub entry: String,
    /// Its title, plain.
    pub title: String,
    /// Its public file key recipient; `None` for a passphrase entry.
    pub recipient: Option<String>,
}

/// The generated passphrase of an Encrypt sheet (FIL-02.3, FIL-01.6). It stays
/// here; [`FileDraft::show`] gives it once per Show.
#[derive(uniffi::Object)]
pub struct FileDraft {
    phrase: Mutex<Option<SecretString>>,
}

#[uniffi::export]
impl FileDraft {
    /// A fresh one: ten words of the built-in list, lower case, one space,
    /// whatever the generator's saved options are.
    ///
    /// # Errors
    /// `Refused` when the random source fails.
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, LarsalError> {
        let options = passphrase::Options {
            words: WORDS,
            separator: " ".to_owned(),
            case: passphrase::Case::Lower,
        };
        let phrase = passphrase::generate(&options, wordlist::builtin())
            .map_err(|_| LarsalError::Refused(error_text(Error::Io)))?;
        Ok(Arc::new(Self {
            phrase: Mutex::new(Some(phrase)),
        }))
    }

    /// Show (rule 4's one exception, LD-220): the value, for as long as the
    /// sheet shows it. `None` once a job took it or it was dropped.
    pub fn show(&self) -> Option<String> {
        lock(&self.phrase).as_ref().map(|p| p.expose().to_owned())
    }

    /// Drops the value now (sheet closed, lock).
    pub fn forget(&self) {
        *lock(&self.phrase) = None;
    }
}

/// A secure field of the file sheet (S2-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileSlot {
    /// Choose My Own Passphrase…: the passphrase.
    Passphrase,
    /// Its repeat.
    Repeated,
    /// Decrypt: the passphrase, or the passphrase of a chosen key file.
    Decrypt,
}

/// What the user types in the file sheet's secure fields (FIL-02.7, FIL-02.10),
/// here from the first keystroke: Swift keeps no copy (the wizard's pattern,
/// APP-07.11; S2-04). Wiped when set again, cleared or dropped.
#[derive(Default, uniffi::Object)]
pub struct FileTyped {
    slots: Mutex<[Option<SecretString>; 3]>,
}

#[uniffi::export]
impl FileTyped {
    /// Empty slots.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The field's whole text after a keystroke; true when it is not empty.
    pub fn set(&self, slot: FileSlot, text: String) -> bool {
        let filled = !text.is_empty();
        lock(&self.slots)[slot as usize] = filled.then(|| SecretString::new(text));
        filled
    }

    /// Every slot goes (a start, a cancel, a lock).
    pub fn clear(&self) {
        *lock(&self.slots) = Default::default();
    }
}

impl FileTyped {
    /// The slot's text, copied into a new wiping buffer (C2R3-04).
    fn text(&self, slot: FileSlot) -> SecretString {
        lock(&self.slots)[slot as usize].as_ref().map_or_else(
            || SecretString::new(String::new()),
            |s| SecretString::from(s.expose()),
        )
    }
}

/// A running file operation.
#[derive(Debug, uniffi::Object)]
pub struct FileJob {
    job: Arc<Job>,
}

#[uniffi::export]
impl FileJob {
    /// Where it is: the step, its counts and the end once there is one.
    pub fn progress(&self) -> FileProgress {
        self.job.progress()
    }

    /// Cancel, or a lock (FIL-02.13, FIL-02.14): no new write starts once
    /// this returns. A write the system already has may finish; a key
    /// derivation that runs ends at its safe point. Call it off the screen
    /// thread: it waits for the chunk in hand.
    pub fn revoke(&self) {
        self.job.revoke();
        drop(lock(&self.job.gate));
    }

    /// Quit (FIL-02.14, C1-01): marks the job, then waits at most `ms`
    /// milliseconds for its safe cleanup; true once the worker is over. Unlike
    /// [`Self::revoke`] it never waits on the gate, so the bound holds even for a
    /// worker that cannot reach its next safe point. Call it off the screen thread.
    pub fn end_within(&self, ms: u64) -> bool {
        self.job.revoke();
        let until = Instant::now() + Duration::from_millis(ms);
        // ponytail: a 5 ms poll; a condition variable if a quit ever needs less.
        while !self.job.finished.load(Ordering::SeqCst) {
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// FIL-02.6: the entry, 32 hex digits, that holds this job's passphrase once it
    /// is saved on disk (or the entry it encrypted with); `None` before or without.
    pub fn saved_entry(&self) -> Option<String> {
        lock(&self.job.saved).clone()
    }

    /// The answer to [`FileEnd::AskWeak`] or [`FileEnd::AskUnprotected`] number
    /// `question`, the one the user saw: true for Save Readable File. An answer to
    /// another question, or a second answer, is not taken (C2R3-05). Once an
    /// answer is taken the job no longer reports the question (C1R5-02).
    pub fn answer_weak(&self, question: u64, save: bool) {
        let mut asking = lock(&self.job.weak);
        if asking.open && asking.id == question && asking.answer.is_none() {
            asking.answer = Some(save);
            *lock(&self.job.end) = None;
            self.job.asked.notify_all();
        }
    }
}

/// The job's question: its number, whether it waits, and its one answer.
#[derive(Debug, Default)]
struct Asking {
    id: u64,
    open: bool,
    answer: Option<bool>,
}

#[derive(Debug, Default)]
struct Job {
    /// The session that started it: only its lock, close or quit revokes it.
    owner: usize,
    revoked: AtomicBool,
    finished: AtomicBool,
    gate: Mutex<()>,
    step: AtomicU8,
    done: AtomicU64,
    total: AtomicU64,
    end: Mutex<Option<FileEnd>>,
    /// Taken before `end` when both are.
    weak: Mutex<Asking>,
    asked: Condvar,
    /// FIL-02.6: the entry holding this job's passphrase, once saved.
    saved: Mutex<Option<String>>,
}

impl Job {
    /// One consistent reading (C1R5-03): the worker stores `end` before
    /// `finished`, so `finished` is read first and a finished reading always
    /// carries its end.
    fn progress(&self) -> FileProgress {
        let finished = self.finished.load(Ordering::SeqCst);
        #[cfg(test)]
        if let Some(hook) = lock(&BETWEEN_READS).take() {
            hook();
        }
        let end = lock(&self.end).clone();
        FileProgress {
            step: FileStep::of(self.step.load(Ordering::SeqCst)),
            done: self.done.load(Ordering::SeqCst),
            total: self.total.load(Ordering::SeqCst),
            end,
            finished,
        }
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        let _held = lock(&self.weak);
        self.asked.notify_all();
    }

    fn set_step(&self, step: FileStep, total: u64) {
        self.done.store(0, Ordering::SeqCst);
        self.total.store(total, Ordering::SeqCst);
        self.step.store(step.code(), Ordering::SeqCst);
    }
}

/// The worker's hold on the gate: from one safe point to the next.
struct Pass<'a> {
    job: &'a Job,
    held: Option<MutexGuard<'a, ()>>,
}

impl<'a> Pass<'a> {
    fn new(job: &'a Job) -> Self {
        Self { job, held: None }
    }

    /// A safe point: the write before it is over, and the next may start
    /// only if no revoke came. Checked under the gate a revoke takes.
    fn pass(&mut self) -> bool {
        self.held = None;
        let guard = lock(&self.job.gate);
        if self.job.revoked.load(Ordering::SeqCst) {
            return false;
        }
        self.held = Some(guard);
        true
    }

    /// No write until the next pass: a key derivation or a question.
    fn release(&mut self) {
        self.held = None;
    }

    /// The progress callback larsal-files calls after each chunk.
    fn control(&mut self, phase: Phase, bytes: u64) -> bool {
        let step = match phase {
            Phase::Capture => FileStep::Preparing,
            Phase::Validate => FileStep::Checking,
            Phase::Write => FileStep::Saving,
            Phase::Encrypt => FileStep::Encrypting,
        };
        if self.job.step.load(Ordering::SeqCst) == step.code() {
            self.job.done.store(bytes, Ordering::SeqCst);
        }
        #[cfg(test)]
        if step == FileStep::Saving && bytes > 0 {
            let hook = lock(&AT_WRITE).take();
            if let Some(hook) = hook {
                self.held = None;
                hook();
            }
        }
        self.pass()
    }
}

static ACTIVE: Mutex<Option<Arc<Job>>> = Mutex::new(None);

/// Test-only: runs once in the worker, after a readable chunk is written and
/// before its safe point takes the gate.
#[cfg(test)]
type Hook = Box<dyn FnOnce() + Send>;
#[cfg(test)]
static AT_WRITE: Mutex<Option<Hook>> = Mutex::new(None);
/// Test-only: runs once in the next [`Job::progress`], between its two reads.
#[cfg(test)]
static BETWEEN_READS: Mutex<Option<Hook>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// FIL-02.14: a lock, a close or a quit marks the running job of that
/// session, at once; its next safe point stops it.
pub(crate) fn revoke_all(session: &Session) {
    if let Some(job) = lock(&ACTIVE).as_ref().filter(|j| j.owner == owner(session)) {
        job.revoke();
    }
}

fn owner(session: &Session) -> usize {
    std::ptr::from_ref(session).addr()
}

/// FIL-03's id of an error.
fn error_id(e: Error) -> &'static str {
    match e {
        Error::Decrypt => "MSG-FILE-DECRYPT",
        Error::Input => "MSG-FILE-INPUT",
        Error::Passphrase => "MSG-FILE-PASSPHRASE",
        Error::Recipient => "MSG-FILE-RECIPIENT",
        Error::Exists => "MSG-FILE-EXISTS",
        Error::Destination => "MSG-FILE-DESTINATION",
        Error::Changed => "MSG-FILE-CHANGED",
        Error::Space => "MSG-FILE-SPACE",
        Error::Io => "MSG-FILE-IO",
        Error::Unprotected => "MSG-FILE-UNPROTECTED",
        Error::Cleanup => "MSG-FILE-CLEANUP",
        Error::CleanupEmpty => "MSG-FILE-CLEANUP-EMPTY",
        Error::Uncertain => "MSG-FILE-UNCERTAIN",
        Error::Cancelled => "MSG-FILE-CANCELLED",
    }
}

fn error_text(e: Error) -> String {
    e.to_string()
}

fn failed(e: Error, saved_key: bool) -> FileEnd {
    FileEnd::Failed {
        id: error_id(e).to_owned(),
        text: error_text(e),
        saved_key,
    }
}

fn own(id: &str, text: &str) -> FileEnd {
    FileEnd::Failed {
        id: id.to_owned(),
        text: text.to_owned(),
        saved_key: false,
    }
}

/// Starts `work` on its own thread, if no other job runs.
fn spawn(
    session: &Session,
    first: FileStep,
    work: impl FnOnce(&Job) -> FileEnd + Send + 'static,
) -> FileStart {
    let mut active = lock(&ACTIVE);
    if active
        .as_ref()
        .is_some_and(|j| !j.finished.load(Ordering::SeqCst))
    {
        return FileStart::Busy;
    }
    let job = Arc::new(Job {
        owner: owner(session),
        ..Job::default()
    });
    job.set_step(first, 0);
    *active = Some(job.clone());
    drop(active);
    let worker = job.clone();
    let started = std::thread::Builder::new()
        .name("larsal-file".to_owned())
        .spawn(move || {
            let end = work(&worker);
            *lock(&worker.end) = Some(end);
            worker.finished.store(true, Ordering::SeqCst);
        });
    if started.is_err() {
        *lock(&job.end) = Some(failed(Error::Io, false));
        job.finished.store(true, Ordering::SeqCst);
    }
    FileStart::Started {
        job: Arc::new(FileJob { job }),
    }
}

/// A job that ended before it began: a source or folder refused at the
/// choice, with its own words, and nothing written.
fn ended(session: &Session, first: FileStep, end: FileEnd) -> FileStart {
    spawn(session, first, move |_| end)
}

/// The size of a chosen file, for the bar only: 0 when unknown.
fn size_of(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.len())
}

fn check_path(text: &str) -> Result<PathBuf, LarsalError> {
    if text.len() > MAX_PATH {
        return Err(LarsalError::TooLong);
    }
    Ok(PathBuf::from(text))
}

/// FIL-02.11: the saved file as the frame shows it, the folder's own name and
/// the file's, cleaned plain text.
fn saved_label(folder: &Path, name: &OsStr) -> String {
    let folder = folder.file_name().map(clean_label).unwrap_or_default();
    let file = clean_label(name);
    if folder.is_empty() {
        file
    } else {
        format!("{folder} / {file}")
    }
}

/// The source, folder and new name, bound at the confirmation (FIL-02.23).
struct Chosen {
    source: SourceFile,
    folder: OutputFolder,
    folder_path: PathBuf,
    name: std::ffi::OsString,
    size: u64,
}

fn choose(source: &str, folder: &str, name: &str) -> Result<Result<Chosen, Error>, LarsalError> {
    let source = check_path(source)?;
    let folder_path = check_path(folder)?;
    if name.len() > MAX_TEXT {
        return Err(LarsalError::TooLong);
    }
    Ok((|| {
        let size = size_of(&source);
        Ok(Chosen {
            source: SourceFile::open(&source)?,
            folder: OutputFolder::open(&folder_path)?,
            folder_path,
            name: name.into(),
            size,
        })
    })())
}

/// The new entry of a passphrase or file key, in `save`'s group.
fn add_entry(
    session: &Session,
    save: &FileSave,
    fields: Vec<(&str, SecretString, bool)>,
) -> Result<Uuid, LarsalError> {
    if save.title.len() > MAX_TEXT {
        return Err(LarsalError::TooLong);
    }
    session.with_edit(save.vault, |v, _, _, _| {
        let group = match &save.group {
            Some(g) => parse_id(g, LarsalError::UnknownGroup)?,
            None => v.root.uuid,
        };
        let mut e = edit::new_entry(v, group, false).map_err(|e| crate::edit::refused(&e))?;
        e.set_field(
            "Title".to_owned(),
            Field {
                value: SecretString::new(save.title.clone()),
                protected: false,
            },
        );
        for (name, value, protected) in fields {
            e.set_field(name.to_owned(), Field { value, protected });
        }
        edit::add_entry(v, group, e, now()).map_err(|e| crate::edit::refused(&e))
    })
}

/// FIL-02.5: the vault on disk, not queued: the save wrote, with nothing left
/// to save and nothing to ask.
fn saved_durably(session: &Session, vault: u64) -> bool {
    session.save(vault).is_ok_and(|s| {
        s.changes == 0
            && s.failure.is_none()
            && s.on_disk.is_none()
            && !s.format_notice
            && !s.ask_unsafe
    })
}

/// FIL-01.7: below Excellent asks.
fn weak(text: &str) -> bool {
    crate::wizard::rate_master(text).is_none_or(|r| r.segments < 4)
}

/// FIL-02.4: the new name a save panel starts with. Encrypt: the cleaned
/// name and `.age`. Decrypt: one final `.age` or `.asc` taken off, else
/// "Decrypted file". A suggestion only, never a path or a format check.
#[uniffi::export]
pub fn file_name_suggestion(source_name: String, encrypt: bool) -> String {
    let base = clean_label(OsStr::new(&source_name)).replace(['/', ':'], "-");
    if encrypt {
        return format!("{base}.age");
    }
    for ext in [".age", ".asc"] {
        if let Some(stem) = base.strip_suffix(ext)
            && !stem.is_empty()
            && !stem.starts_with('.')
        {
            return stem.to_owned();
        }
    }
    "Decrypted file".to_owned()
}

/// FIL-02.8: a valid native X25519 recipient (FIL-01.9); no lookup.
#[uniffi::export]
pub fn file_recipient_valid(text: String) -> bool {
    text.len() <= MAX_TEXT && Recipient::parse(text.trim()).is_ok()
}

/// FIL-02.17: a file operation runs (its cleanup included).
#[uniffi::export]
pub fn file_busy() -> bool {
    lock(&ACTIVE)
        .as_ref()
        .is_some_and(|j| !j.finished.load(Ordering::SeqCst))
}

#[uniffi::export]
impl Session {
    /// FIL-02.5, FIL-02.6: encrypts with `draft`'s generated passphrase. First
    /// the passphrase goes into a new protected entry and the vault is saved
    /// to disk; only then is a byte of the output written. The draft's value
    /// is taken: a new attempt is a new generation and a new entry.
    ///
    /// # Errors
    /// `TooLong` for a path or a name over the limit.
    pub fn encrypt_file_generated(
        &self,
        draft: Arc<FileDraft>,
        save: FileSave,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        if file_busy() {
            return Ok(FileStart::Busy);
        }
        let chosen = match choose(&source, &folder, &name)? {
            Ok(c) => c,
            Err(e) => return Ok(ended(self, FileStep::SavingPassphrase, failed(e, false))),
        };
        if save.title.len() > MAX_TEXT {
            return Err(LarsalError::TooLong);
        }
        let Some(phrase) = lock(&draft.phrase).take() else {
            return Ok(FileStart::Refused {
                text: error_text(Error::Passphrase),
            });
        };
        let Some(session) = self.me.upgrade() else {
            return Err(LarsalError::UnknownVault);
        };
        Ok(spawn(self, FileStep::SavingPassphrase, move |job| {
            let mut pass = Pass::new(job);
            if !pass.pass() {
                return failed(Error::Cancelled, false);
            }
            pass.release();
            let note = SecretString::new(
                "The passphrase of an encrypted file. Larsal made it and saved it here before encrypting."
                    .to_owned(),
            );
            let added = add_entry(
                &session,
                &save,
                vec![
                    (
                        "Password",
                        SecretString::new(phrase.expose().to_owned()),
                        true,
                    ),
                    ("Notes", note, false),
                ],
            );
            if added.is_err() || !saved_durably(&session, save.vault) {
                return own("MSG-FILE-ENTRY-UNSAVED", ENTRY_UNSAVED);
            }
            *lock(&job.saved) = added.ok().map(hex);
            encrypt_with(job, &mut pass, chosen, &Lock::Passphrase(&phrase), true)
        }))
    }

    /// FIL-02.7 from the sheet: [`Self::encrypt_file_passphrase`] with what the
    /// user typed in `typed`'s passphrase and repeat (S2-04).
    ///
    /// # Errors
    /// `TooLong` for a path or a name over the limit.
    pub fn encrypt_file_typed(
        &self,
        typed: Arc<FileTyped>,
        accept_weak: bool,
        save: Option<FileSave>,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        let passphrase = typed.text(FileSlot::Passphrase);
        let repeated = typed.text(FileSlot::Repeated);
        self.encrypt_secret(
            passphrase,
            repeated,
            accept_weak,
            save,
            source,
            folder,
            name,
        )
    }

    /// FIL-02.6: encrypts again with the passphrase an earlier attempt saved, in
    /// the entry the sheet shows as chosen (an explicit, visible existing-entry
    /// selection): no new generation and no new entry. The value is read at the
    /// call (FIL-02.23) and never crosses.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `TooLong` for a path or a name
    /// over the limit.
    pub fn encrypt_file_entry(
        &self,
        vault: u64,
        entry: String,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        let id = parse_id(&entry, LarsalError::UnknownEntry)?;
        let phrase = self.with_vault(vault, |v| {
            let e = find(&v.root, id, &mut Vec::new()).ok_or(LarsalError::UnknownEntry)?;
            Ok(SecretString::new(e.value("Password").to_owned()))
        })?;
        if phrase.expose().is_empty() {
            return Ok(FileStart::Refused {
                text: error_text(Error::Passphrase),
            });
        }
        if file_busy() {
            return Ok(FileStart::Busy);
        }
        let chosen = match choose(&source, &folder, &name)? {
            Ok(c) => c,
            Err(e) => return Ok(ended(self, FileStep::Encrypting, failed(e, true))),
        };
        Ok(spawn(self, FileStep::Encrypting, move |job| {
            *lock(&job.saved) = Some(entry);
            let mut pass = Pass::new(job);
            encrypt_with(job, &mut pass, chosen, &Lock::Passphrase(&phrase), true)
        }))
    }

    /// FIL-02.8: encrypts to public recipients (FIL-01.8: 1 to 1,024
    /// distinct keys). The recovery choice and the recipient-only
    /// acknowledgement are the sheet's.
    ///
    /// # Errors
    /// `TooLong` for a path, a name or a key over the limit.
    pub fn encrypt_file_recipients(
        &self,
        recipients: Vec<String>,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        if recipients.iter().any(|r| r.len() > MAX_TEXT) {
            return Err(LarsalError::TooLong);
        }
        let Ok(keys) = recipients
            .iter()
            .map(|r| Recipient::parse(r.trim()))
            .collect::<Result<Vec<_>, _>>()
        else {
            return Ok(FileStart::Refused {
                text: error_text(Error::Recipient),
            });
        };
        if file_busy() {
            return Ok(FileStart::Busy);
        }
        let chosen = match choose(&source, &folder, &name)? {
            Ok(c) => c,
            Err(e) => return Ok(ended(self, FileStep::Encrypting, failed(e, false))),
        };
        Ok(spawn(self, FileStep::Encrypting, move |job| {
            let mut pass = Pass::new(job);
            encrypt_with(job, &mut pass, chosen, &Lock::Recipients(&keys), false)
        }))
    }

    /// FIL-02.9, FIL-01.17: a new file key, its private string saved as a
    /// protected field of a new entry, its public recipient as a plain one.
    /// The recipient comes back only once the vault is saved on disk. Runs
    /// the vault's key derivation: call it off the screen thread.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup`, `TooLong`; `Refused` with
    /// the words of a save that did not reach the disk (the entry stays in
    /// the vault, unsaved, and the key is not given out).
    pub fn create_file_key(&self, save: FileSave) -> Result<String, LarsalError> {
        let (private, public) =
            generate_identity().map_err(|e| LarsalError::Refused(error_text(e)))?;
        let recipient = public
            .to_text()
            .map_err(|e| LarsalError::Refused(error_text(e)))?;
        let fields = vec![
            (KEY_FIELD, private, true),
            (RECIPIENT_FIELD, SecretString::new(recipient.clone()), false),
        ];
        add_entry(self, &save, fields)?;
        if !saved_durably(self, save.vault) {
            return Err(LarsalError::Refused(KEY_UNSAVED.to_owned()));
        }
        Ok(recipient)
    }

    /// FIL-02.8, FIL-02.10: the vault's file keys and passphrase entries, by
    /// id and title, with a key's public recipient. Never a value.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn file_key_choices(&self, vault: u64) -> Result<Vec<FileKeyChoice>, LarsalError> {
        self.with_vault(vault, |v| {
            let mut out = Vec::new();
            let mut stack = vec![&v.root];
            while let Some(g) = stack.pop() {
                if recycle::group_in_bin(v, g.uuid) {
                    continue;
                }
                stack.extend(g.groups.iter().rev());
                for e in &g.entries {
                    let recipient = e
                        .field(KEY_FIELD)
                        .map(|_| e.value(RECIPIENT_FIELD).to_owned());
                    if recipient.is_some() || !e.value("Password").is_empty() {
                        out.push(FileKeyChoice {
                            entry: hex(e.uuid),
                            title: e.value("Title").to_owned(),
                            recipient,
                        });
                    }
                }
            }
            Ok(out)
        })
    }

    /// FIL-02.10 from the sheet: a decrypt with what the user typed in `typed`'s
    /// decrypt slot (S2-04): the passphrase, or with `key_file` that key file's
    /// passphrase when one was typed.
    ///
    /// # Errors
    /// `TooLong` for a path or a name over the limit.
    pub fn decrypt_file_typed(
        &self,
        typed: Arc<FileTyped>,
        key_file: Option<String>,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        let text = typed.text(FileSlot::Decrypt);
        let credential = match key_file {
            Some(path) => FileCredential::KeyFile {
                path,
                passphrase: (!text.is_empty()).then_some(text),
            },
            None => FileCredential::Passphrase { text },
        };
        self.decrypt_file(credential, source, folder, name)
    }

    /// FIL-02.10 from the sheet: a decrypt with an entry of an open vault, its
    /// file key when it has one, else its password, read at the call.
    ///
    /// # Errors
    /// `TooLong`; `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn decrypt_file_entry(
        &self,
        vault: u64,
        entry: String,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        self.decrypt_file(FileCredential::Entry { vault, entry }, source, folder, name)
    }

    /// FIL-03.12's estimate, advisory only (C1-06): true when the chosen folder's
    /// volume has less free room than the work needs, the output and, for a
    /// decrypt, the ciphertext copy in scratch (on its own volume, or on the same
    /// one). Unknown counts as enough. A full disk during the work still says
    /// MSG-FILE-SPACE.
    pub fn file_space_short(&self, source: String, folder: String, encrypt: bool) -> bool {
        use std::os::unix::fs::MetadataExt;
        let free = |p: &Path| {
            let f = std::fs::File::open(p).ok()?;
            Some((
                larsal_platform::macos::free_bytes(&f).ok()?,
                f.metadata().ok()?.dev(),
            ))
        };
        let size = size_of(Path::new(&source));
        let Some((out_free, out_dev)) = free(Path::new(&folder)) else {
            return false;
        };
        if encrypt {
            let sealed = size / CHUNK as u64 * TAG as u64 + OVERHEAD;
            return out_free < size.saturating_add(sealed);
        }
        let scratch = self.scratch_folder();
        match scratch.ancestors().find(|p| p.exists()).and_then(free) {
            Some((_, dev)) if dev == out_dev => out_free < size.saturating_mul(2),
            Some((scratch_free, _)) => out_free < size || scratch_free < size,
            None => out_free < size,
        }
    }
}

/// A decrypt's resolved credential, in Rust only.
enum Key {
    Phrase(SecretString),
    Ids(Identities),
    /// A key file, opened at the confirmation and read in the worker, with
    /// its passphrase. `None`: it could not be opened.
    File(Option<std::fs::File>, Option<SecretString>),
}

impl Session {
    /// FIL-02.7: encrypts with a typed passphrase, after its repeat matched
    /// and, below Excellent, after Use Anyway (`accept_weak`). With `save`,
    /// the passphrase is saved as a protected entry and the vault written to
    /// disk first.
    ///
    /// Rust only: the Mac app calls [`Self::encrypt_file_typed`].
    ///
    /// # Errors
    /// `TooLong` for a path or a name over the limit.
    // One call from the sheet's confirmation: the typed pair, the consent,
    // the save and the three choices, bound together (FIL-02.23).
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_file_passphrase(
        &self,
        passphrase: String,
        repeated: String,
        accept_weak: bool,
        save: Option<FileSave>,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        self.encrypt_secret(
            SecretString::new(passphrase),
            SecretString::new(repeated),
            accept_weak,
            save,
            source,
            folder,
            name,
        )
    }

    /// [`Self::encrypt_file_passphrase`] with the typed pair already in wiping types.
    #[allow(clippy::too_many_arguments)]
    fn encrypt_secret(
        &self,
        phrase: SecretString,
        repeated: SecretString,
        accept_weak: bool,
        save: Option<FileSave>,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        // FIL-03.1, C1-07: 1 to 1,048,576 bytes, else MSG-FILE-PASSPHRASE.
        if phrase.expose().is_empty() || phrase.expose().len() > MAX_PASSPHRASE {
            return Ok(FileStart::Refused {
                text: error_text(Error::Passphrase),
            });
        }
        if phrase.expose() != repeated.expose() {
            return Ok(FileStart::Refused {
                text: REPEAT.to_owned(),
            });
        }
        if weak(phrase.expose()) && !accept_weak {
            return Ok(FileStart::Weak);
        }
        if file_busy() {
            return Ok(FileStart::Busy);
        }
        let chosen = match choose(&source, &folder, &name)? {
            Ok(c) => c,
            Err(e) => return Ok(ended(self, FileStep::Encrypting, failed(e, false))),
        };
        let session = self.me.upgrade();
        let first = if save.is_some() {
            FileStep::SavingPassphrase
        } else {
            FileStep::Encrypting
        };
        Ok(spawn(self, first, move |job| {
            let mut pass = Pass::new(job);
            let mut saved = false;
            if let (Some(save), Some(session)) = (save, session) {
                if !pass.pass() {
                    return failed(Error::Cancelled, false);
                }
                pass.release();
                let fields = vec![(
                    "Password",
                    SecretString::new(phrase.expose().to_owned()),
                    true,
                )];
                let added = add_entry(&session, &save, fields);
                if added.is_err() || !saved_durably(&session, save.vault) {
                    return own("MSG-FILE-ENTRY-UNSAVED", ENTRY_UNSAVED);
                }
                *lock(&job.saved) = added.ok().map(hex);
                saved = true;
            }
            encrypt_with(job, &mut pass, chosen, &Lock::Passphrase(&phrase), saved)
        }))
    }

    /// FIL-02.10, FIL-02.11: decrypts a chosen file to a new readable file.
    /// The source is copied to private scratch, checked whole, and only then
    /// written; a low work factor asks first ([`FileEnd::AskWeak`]).
    ///
    /// Rust only: the Mac app calls [`Self::decrypt_file_typed`] and
    /// [`Self::decrypt_file_entry`].
    ///
    /// # Errors
    /// `TooLong`; `UnknownVault`, `Locked`, `UnknownEntry` for an entry
    /// credential.
    pub fn decrypt_file(
        &self,
        credential: FileCredential,
        source: String,
        folder: String,
        name: String,
    ) -> Result<FileStart, LarsalError> {
        // FIL-03.1, C1-07: a typed passphrase over 1,048,576 bytes runs nothing.
        let typed = match &credential {
            FileCredential::Passphrase { text } => Some(text.len()),
            FileCredential::KeyFile { passphrase, .. } => {
                passphrase.as_ref().map(SecretString::len)
            }
            FileCredential::Entry { .. } => None,
        };
        if typed.is_some_and(|n| n > MAX_PASSPHRASE) {
            return Ok(FileStart::Refused {
                text: error_text(Error::Passphrase),
            });
        }
        if file_busy() {
            return Ok(FileStart::Busy);
        }
        let key = self.credential(credential)?;
        let chosen = match choose(&source, &folder, &name)? {
            Ok(c) => c,
            Err(e) => return Ok(ended(self, FileStep::Preparing, failed(e, false))),
        };
        let scratch = self.scratch_folder();
        Ok(spawn(self, FileStep::Preparing, move |job| {
            let mut pass = Pass::new(job);
            match decrypt_with(job, &mut pass, chosen, &key, &scratch) {
                Ok(end) | Err(end) => end,
            }
        }))
    }
    /// FIL-02.23: the credential as it is at the confirmation.
    fn credential(&self, credential: FileCredential) -> Result<Key, LarsalError> {
        match credential {
            FileCredential::Passphrase { text } => Ok(Key::Phrase(text)),
            FileCredential::Entry { vault, entry } => {
                let id = parse_id(&entry, LarsalError::UnknownEntry)?;
                self.with_vault(vault, |v| {
                    let e = find(&v.root, id, &mut Vec::new()).ok_or(LarsalError::UnknownEntry)?;
                    if let Some(key) = e.field(KEY_FIELD) {
                        return Identities::single(&key.value)
                            .map(Key::Ids)
                            .map_err(|e| LarsalError::Refused(error_text(e)));
                    }
                    Ok(Key::Phrase(SecretString::new(
                        e.value("Password").to_owned(),
                    )))
                })
            }
            FileCredential::KeyFile { path, passphrase } => {
                let path = check_path(&path)?;
                // FIL-02.10: only the chosen key file, by a handle that
                // follows no link, taken now (FIL-02.23).
                let file = larsal_platform::macos::open_regular_nofollow(&path).ok();
                Ok(Key::File(file, passphrase))
            }
        }
    }

    /// Ciphertext scratch: `file-scratch` (0700) in Larsal's settings folder,
    /// or, for a memory-only store, in the system's temporary folder.
    fn scratch_folder(&self) -> PathBuf {
        self.settings.folder().map_or_else(
            || std::env::temp_dir().join(format!("larsal-{SCRATCH}-{}", std::process::id())),
            |f| f.join(SCRATCH),
        )
    }
}

fn encrypt_with(
    job: &Job,
    pass: &mut Pass<'_>,
    chosen: Chosen,
    lock: &Lock<'_>,
    saved_key: bool,
) -> FileEnd {
    job.set_step(FileStep::Encrypting, chosen.size);
    pass.release();
    let result = encrypt_file(
        chosen.source,
        &chosen.folder,
        &chosen.name,
        lock,
        &mut |phase, bytes| pass.control(phase, bytes),
    );
    pass.release();
    match result {
        Ok(bytes) => FileEnd::Done {
            saved_to: saved_label(&chosen.folder_path, &chosen.name),
            bytes,
        },
        Err(e) => failed(e, saved_key),
    }
}

fn decrypt_with(
    job: &Job,
    pass: &mut Pass<'_>,
    chosen: Chosen,
    key: &Key,
    scratch: &Path,
) -> Result<FileEnd, FileEnd> {
    job.set_step(FileStep::Preparing, chosen.size);
    let fail = |e: Error| failed(e, false);
    let root = private_folder(scratch).map_err(fail)?;
    // FIL-03.11: crash leftovers of an earlier run go first.
    let _ = root.sweep();
    let snapshot = root
        .capture_file(chosen.source, &mut |phase, bytes| {
            pass.control(phase, bytes)
        })
        .map_err(fail)?;
    // No write until the derivation ends; check before and after it.
    if !pass.pass() {
        return Err(fail(Error::Cancelled));
    }
    pass.release();
    let unwrapped = match key {
        Key::Phrase(p) => snapshot.unlock(&Unlock::Passphrase(p)),
        Key::Ids(ids) => snapshot.unlock(&Unlock::Identities(ids)),
        Key::File(file, phrase) => {
            let mut file = file.as_ref().ok_or_else(|| fail(Error::Input))?;
            let ids = Identities::read_key_file(&mut file, phrase.as_ref()).map_err(fail)?;
            // C2R2-06: a key file under a low work factor asks, as a data
            // file does, before it opens anything.
            if ids.from_weak_file() && !consent(job) {
                return Err(fail(Error::Cancelled));
            }
            snapshot.unlock(&Unlock::Identities(&ids))
        }
    }
    .map_err(fail)?;
    job.set_step(FileStep::Checking, chosen.size);
    if !pass.pass() {
        return Err(fail(Error::Cancelled));
    }
    let validation = unwrapped
        .validate(&mut |phase, bytes| pass.control(phase, bytes))
        .map_err(fail)?;
    pass.release();
    let plain = job.done.load(Ordering::SeqCst);
    let validated = match validation {
        Validation::Ready(v) => v,
        Validation::Weak(w) if consent(job) => w.accept(),
        Validation::Weak(_) => return Err(fail(Error::Cancelled)),
    };
    job.set_step(FileStep::Saving, plain);
    let bytes = validated
        .save_new_warned(
            &chosen.folder,
            &chosen.name,
            &mut |phase, bytes| pass.control(phase, bytes),
            &mut || consent_to(job, |question| FileEnd::AskUnprotected { question }),
        )
        .map_err(fail)?;
    pass.release();
    Ok(FileEnd::Done {
        saved_to: saved_label(&chosen.folder_path, &chosen.name),
        bytes,
    })
}

/// MSG-FILE-WEAK, asked and answered: true only for Save Readable File. The
/// answer is for this one question; a revoke is a no.
fn consent(job: &Job) -> bool {
    consent_to(job, |question| FileEnd::AskWeak { question })
}

/// A new question, `ask` with its number, asked and answered, as [`consent`]: only
/// an answer to this number counts (C2R3-05), and a revoke is a no.
fn consent_to(job: &Job, ask: fn(u64) -> FileEnd) -> bool {
    {
        let mut asking = lock(&job.weak);
        asking.id = asking.id.wrapping_add(1);
        asking.open = true;
        asking.answer = None;
        *lock(&job.end) = Some(ask(asking.id));
    }
    let answer = wait_answer(job);
    let mut asking = lock(&job.weak);
    asking.open = false;
    *lock(&job.end) = None;
    answer == Some(true)
}

/// The question's answer, or `None` once revoked.
fn wait_answer(job: &Job) -> Option<bool> {
    let mut asking = lock(&job.weak);
    loop {
        if job.revoked.load(Ordering::SeqCst) {
            return None;
        }
        if let Some(a) = asking.answer {
            return Some(a);
        }
        asking = job
            .asked
            .wait(asking)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// The scratch root, made 0700 when missing.
fn private_folder(path: &Path) -> Result<ScratchRoot, Error> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|_| Error::Destination)?;
    }
    ScratchRoot::open(path)
}

#[cfg(test)]
mod tests;
