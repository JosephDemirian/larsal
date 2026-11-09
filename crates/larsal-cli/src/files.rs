//! `larsal encrypt` and `larsal decrypt` (E22-S5; FIL-02.18 to FIL-02.21):
//! one file in the public file format, through larsal-files, the same code
//! the Mac app calls.
//!
//! Guarantees:
//! - the grammar of FIL-02.18: an explicit new `--output` and exactly one
//!   credential mode, checked before any file is opened, any prompt or any
//!   key derivation; a usage error exits 2 and never repeats an argument, so
//!   a passphrase typed as one is not printed;
//! - a passphrase only from the terminal with echo off (asked twice to
//!   encrypt), a named file or a vault entry (FIL-02.19); never from an
//!   argument or an environment variable; every prompt prints, also with
//!   `--quiet`. The environment these commands read is TMPDIR alone, through
//!   the standard temp folder (`std::env::temp_dir`): it places the
//!   decrypt's ciphertext scratch and, with `--generate`, the vault save's temp
//!   file. A debug build also reads LARSAL_TEST_SELF_TEST_FAIL (INT-10.1-a).
//!   Neither gives a secret;
//! - a passphrase typed or read from a file to encrypt gets FIL-01.7's
//!   strength check: below Excellent it is used only after a yes on a
//!   terminal, and refused with no terminal;
//! - the output is a new file, never replaced, never standard output, never
//!   a folder; it exists only once the whole input is proven (larsal-files);
//! - at start, the scratch a crash left in this tool's own scratch folders is
//!   swept (FIL-03.11);
//! - exit 0 only after the output is complete and synced and every line was
//!   written to stdout and stderr, 1 for an error, 130 for a handled cancel.
//!   A quit signal (SIGINT, SIGTERM, SIGHUP, SIGQUIT) during the work or at a
//!   yes or no question cancels it at the next chunk, larsal-files
//!   removes what it made, and the process then ends by that signal
//!   (FIL-02.21). At a prompt, the echo-off guard restores the terminal first.
//! - stderr carries only FIL-03's own words and this file's fixed texts: no
//!   path, no OS reason, no secret (FIL-03.13, FIL-03.14).

use crate::args::{self, Cmd, Parsed, Problem};
use crate::term::{self, Fail};
use crate::vault::{self, find_entry, find_group, now};
use larsal_core::generator::{passphrase, wordlist};
use larsal_core::{edit, health};
use larsal_crypto::secret::{SecretBytes, SecretString, ct_eq};
use larsal_files::limits::{MAX_IDENTITY_FILE, MAX_PASSPHRASE};
use larsal_files::{
    Error, Identities, Lock, OutputFolder, Phase, Recipient, ScratchRoot, SourceFile, Unlock,
    Validation, clean_label,
};
use larsal_model::Field;
use larsal_platform::macos::{QuitGuard, catch_quit};
use std::ffi::{OsStr, OsString};
use std::fs::{DirBuilder, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// FIL-02.21's exit codes.
const FAILED: u8 = 1;
const USAGE: u8 = 2;
const CANCELLED: u8 = 130;

/// FIL-01.7: the warning for a manual passphrase below Excellent, and its
/// question; no is the default.
const WEAK_PASSPHRASE: &str = "This passphrase may be easy to guess. Anyone with the encrypted file can test guesses offline, with no limit on tries.";
const USE_ANYWAY: &str = "Use this passphrase anyway? [y/N] ";

/// The protected field of a file key the Mac app made (FIL-01.17).
const FILE_KEY: &str = "File key";

/// The start of a scratch folder's name; 32 lowercase hex digits follow.
const SCRATCH: &str = "larsal-scratch-";

/// FIL-01.6: the default passphrase is ten words of the built-in list.
const GENERATED_WORDS: u32 = 10;

/// How the credential comes (FIL-02.18): exactly one per command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Prompt,
    File,
    Entry,
    Recipients,
    IdentityFile,
    IdentityEntry,
}

/// What opens or locks the file, read before any work.
enum Credential {
    Passphrase(SecretString),
    Recipients(Vec<Recipient>),
    Identities(Identities),
}

/// Runs `larsal encrypt` or `larsal decrypt` from the words after the command
/// name, and returns the exit code (FIL-02.21).
pub fn run(cmd: &'static Cmd, words: &[String]) -> u8 {
    let p = match args::parse(cmd, words, false) {
        Ok(p) => p,
        Err(Problem::Help) => {
            print!("{}", args::command_help(cmd));
            return 0;
        }
        // Its words hold nothing the user typed (args::Problem).
        Err(problem) => return usage(cmd, &problem.to_string()),
    };
    // INT-10.1 (5): the crypto self-test, before any prompt.
    if let Err(message) = crate::self_test() {
        term::err(&message);
        return FAILED;
    }
    let mode = match check(&p) {
        Ok(mode) => mode,
        Err(problem) => return usage(cmd, problem),
    };
    sweep_scratch();
    match start(&p, mode) {
        Ok(code) => code,
        Err(Fail) => FAILED,
    }
}

/// A usage error: the fixed words of M10-02's form, exit 2.
fn usage(cmd: &Cmd, problem: &str) -> u8 {
    term::err(&format!(
        "larsal {0}: {problem}. Run larsal help {0} to see its options.",
        cmd.name
    ));
    USAGE
}

/// FIL-02.18 and FIL-02.20: the grammar, before anything is opened or read.
fn check(p: &Parsed) -> Result<Mode, &'static str> {
    let given = |long: &str| p.value(long).is_some();
    let modes = [
        (p.flag("generate"), Mode::Generate),
        (p.flag("passphrase"), Mode::Prompt),
        (given("passphrase-file"), Mode::File),
        (given("passphrase-entry"), Mode::Entry),
        (given("recipient"), Mode::Recipients),
        (given("identity-file"), Mode::IdentityFile),
        (given("identity-entry"), Mode::IdentityEntry),
    ];
    let mut chosen = modes.iter().filter(|(on, _)| *on).map(|(_, m)| *m);
    let mode = match (chosen.next(), chosen.next()) {
        (Some(mode), None) => mode,
        _ => return Err("give exactly one way to the passphrase or key"),
    };
    if p.text("output").is_none_or(|o| o == "-") {
        return Err("--output must name a new file");
    }
    let vault_mode = matches!(mode, Mode::Generate | Mode::Entry | Mode::IdentityEntry);
    if vault_mode != given("vault") {
        return Err(if vault_mode {
            "--vault is missing"
        } else {
            "--vault is only for a passphrase or key kept in a vault"
        });
    }
    let unlock_options = ["key-file", "no-password", "hw-key", "allow-slow-unlock"];
    if !vault_mode && unlock_options.iter().any(|o| p.flag(o)) {
        return Err("the unlock options are only for --vault");
    }
    if mode == Mode::Generate {
        if !given("group") {
            return Err("--group is missing");
        }
        if p.text("title").is_none() {
            return Err("--title is missing");
        }
    } else if given("group") || given("title") {
        return Err("--group and --title are only for --generate");
    }
    if p.arg(0) == Some("-") {
        if p.cmd.name == "encrypt" {
            return Err("encrypt reads a named file, not standard input");
        }
        if term::stdin_tty() {
            return Err("standard input is a terminal, not an encrypted file");
        }
        if mode == Mode::Prompt || (vault_mode && !p.flag("no-password")) {
            return Err("the data and a password cannot both come from standard input");
        }
    }
    Ok(mode)
}

/// The output's folder, bound to its descriptor, and its new name. A path
/// that names a folder (`d/`, `d/.`, an existing folder) is no new file name.
fn output(path: &str) -> Result<(OutputFolder, OsString), Error> {
    let at = Path::new(path);
    let folder = path.ends_with('/') || path.ends_with("/.") || at.is_dir();
    let name = at.file_name().filter(|_| !folder);
    let name = name.ok_or(Error::Destination)?;
    let parent = at
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let folder = OutputFolder::open(parent)?;
    // An early answer before any prompt; the exclusive create decides.
    if at.symlink_metadata().is_ok() {
        return Err(Error::Exists);
    }
    Ok((folder, name.to_owned()))
}

/// A file error in FIL-03's words.
fn said(e: Error) -> Fail {
    term::fail(e.to_string())
}

/// The checks that need no secret, then the credential, then the work.
fn start(p: &Parsed, mode: Mode) -> Result<u8, Fail> {
    let input = p.arg(0).unwrap_or_default();
    let source = if input == "-" {
        None
    } else {
        Some(SourceFile::open(Path::new(input)).map_err(said)?)
    };
    let (folder, name) = output(p.value("output").unwrap_or_default()).map_err(said)?;
    let mut recipients = Vec::new();
    for text in p.values("recipient") {
        recipients.push(Recipient::parse(text).map_err(said)?);
    }
    let vault_path = p.value("vault").unwrap_or_default();
    if matches!(mode, Mode::Generate | Mode::Entry | Mode::IdentityEntry) {
        vault::check_unlock(vault_path, &unlock_options(p))?;
    }
    if mode == Mode::Prompt && !term::stdin_tty() {
        return Err(term::fail(
            "--passphrase needs a terminal to type on. Use --passphrase-file or --passphrase-entry.",
        ));
    }
    // Opened once: the handle checked is the handle read.
    let credential_file = match p.value("passphrase-file").or(p.value("identity-file")) {
        Some(path) => Some(open_named(path).map_err(said)?),
        None => None,
    };
    if input == "-" && credential_file.as_ref().is_some_and(is_stdin) {
        return Err(term::fail(
            "the data and the passphrase or key cannot both come from standard input.",
        ));
    }
    let encrypt = p.cmd.name == "encrypt";
    let credential = match (mode, credential_file) {
        (Mode::Generate, _) => Credential::Passphrase(generate(p, vault_path)?),
        (Mode::Prompt, _) => Credential::Passphrase(prompted(encrypt)?),
        (Mode::File, Some(file)) => Credential::Passphrase(passphrase_file(file).map_err(said)?),
        (Mode::IdentityFile, Some(file)) => Credential::Identities(identity_file(file)?),
        (Mode::File | Mode::IdentityFile, None) => return Err(said(Error::Input)),
        (Mode::Entry, _) => {
            let entry = p.value("passphrase-entry").unwrap_or_default();
            let session = vault::unlock(vault_path, &unlock_options(p))?;
            let value = password_of(&session, entry)?;
            Credential::Passphrase(checked(SecretString::new(value.to_owned())).map_err(said)?)
        }
        (Mode::Recipients, _) => Credential::Recipients(recipients),
        (Mode::IdentityEntry, _) => {
            let entry = p.value("identity-entry").unwrap_or_default();
            let session = vault::unlock(vault_path, &unlock_options(p))?;
            let list = keys_of(&session, entry)?;
            Credential::Identities(Identities::from_list(list.as_bytes()).map_err(said)?)
        }
    };
    // FIL-01.7: a passphrase the user chose, typed or from a file, below
    // Excellent; a generated one and a vault entry are not asked about.
    let ask = encrypt
        && matches!(mode, Mode::Prompt | Mode::File)
        && matches!(&credential, Credential::Passphrase(s) if weak(s));
    if ask && !term::stdin_tty() {
        term::err(WEAK_PASSPHRASE);
        return Err(term::fail(
            "a passphrase that may be easy to guess needs a terminal to confirm it. Use a stronger passphrase.",
        ));
    }
    let guard = catch_quit().map_err(|_| said(Error::Io))?;
    if ask && let Err(e) = consent(&guard, WEAK_PASSPHRASE, USE_ANYWAY) {
        // Wiped before the guard goes, which may end the process.
        drop(credential);
        term::err(&format!("larsal: {e}"));
        return Ok(if e == Error::Cancelled {
            CANCELLED
        } else {
            FAILED
        });
    }
    Ok(work(p, &guard, credential, source, &folder, &name, mode))
}

/// The unlock options of `--vault`, with every prompt printed also with
/// `--quiet` (FIL-02.19).
fn unlock_options(p: &Parsed) -> vault::Unlock<'_> {
    vault::Unlock {
        quiet: false,
        ..vault::Unlock::of(p)
    }
}

/// FIL-01.7 with FEA-05's estimate: below Excellent.
fn weak(s: &SecretString) -> bool {
    let bits = health::bits_with(&health::zxcvbn_bits, s.expose(), &[]);
    health::Level::of(health::score(bits)) < health::Level::Excellent
}

/// True when `file` is this process's standard input (`/dev/stdin`, a file
/// also given with `<`; `-` is a file name here): one stream cannot carry
/// both the data and a secret.
fn is_stdin(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    let stdin = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(File::from)
        .and_then(|f| f.metadata());
    match (stdin, file.metadata()) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// The Password of the entry at `path` (INT-10.17).
fn password_of<'v>(session: &'v vault::Session, path: &str) -> Result<&'v str, Fail> {
    find_entry(&session.vault, path)
        .map(|(e, _)| e.value("Password"))
        .ok_or_else(|| term::fail(format!("no entry at {path}.")))
}

/// The keys of the entry at `path`: its protected field "File key", where
/// the Mac app saves a file key (FIL-02.9), else its Password, as the app's
/// own decrypt by entry reads them (larsal-ffi).
fn keys_of<'v>(session: &'v vault::Session, path: &str) -> Result<&'v str, Fail> {
    find_entry(&session.vault, path)
        .map(|(e, _)| match e.field(FILE_KEY) {
            Some(key) => key.value.expose(),
            None => e.value("Password"),
        })
        .ok_or_else(|| term::fail(format!("no entry at {path}.")))
}

/// FIL-01.5, FIL-03.1: an empty or over-limit passphrase is refused before
/// any work.
fn checked(s: SecretString) -> Result<SecretString, Error> {
    if s.is_empty() || s.len() > MAX_PASSPHRASE {
        Err(Error::Passphrase)
    } else {
        Ok(s)
    }
}

/// FIL-02.19: typed on the terminal with echo off; twice to encrypt. The
/// prompts are written even with `--quiet`.
fn prompted(encrypt: bool) -> Result<SecretString, Fail> {
    let first = term::read_secret("Passphrase: ", false);
    if encrypt {
        let again = term::read_secret("Repeat passphrase: ", false);
        if !ct_eq(first.expose().as_bytes(), again.expose().as_bytes()) {
            return Err(term::fail("The passphrases do not match."));
        }
    }
    checked(first).map_err(said)
}

/// Reads at most `limit` bytes of `input` into wiping memory; `None` when
/// there are more.
fn bounded(input: &mut impl Read, limit: usize) -> Result<Option<SecretBytes>, Error> {
    let mut buf = SecretBytes::zeroed(limit + 1);
    let mut got = 0;
    while got <= limit {
        match input.read(&mut buf.expose_mut()[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::Input),
            Err(_) => return Err(Error::Io),
        }
    }
    if got > limit {
        return Ok(None);
    }
    Ok(Some(SecretBytes::new(buf.expose()[..got].to_vec())))
}

fn open_named(path: &str) -> Result<File, Error> {
    File::open(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => Error::Input,
        _ => Error::Io,
    })
}

/// FIL-02.19: the file's bytes as UTF-8, one final LF and the CR before it
/// removed, everything else kept: spaces, NUL, other line ends.
fn passphrase_file(mut file: File) -> Result<SecretString, Error> {
    let bytes = bounded(&mut file, MAX_PASSPHRASE + 2)?.ok_or(Error::Passphrase)?;
    let mut text = bytes.expose();
    if let Some(rest) = text.strip_suffix(b"\n") {
        text = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    let text = std::str::from_utf8(text).map_err(|_| Error::Passphrase)?;
    checked(SecretString::new(text.to_owned()))
}

/// FIL-01.15, FIL-01.16: an explicitly chosen key file, a plain list or one
/// encrypted to a passphrase, which is asked for on the terminal.
fn identity_file(mut file: File) -> Result<Identities, Fail> {
    let data = bounded(&mut file, MAX_IDENTITY_FILE)
        .map_err(said)?
        .ok_or_else(|| said(Error::Decrypt))?;
    let start = data.expose().trim_ascii_start();
    let encrypted = start.starts_with(b"age-encryption.org/")
        || start.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----");
    let passphrase = if encrypted {
        if !term::stdin_tty() {
            return Err(term::fail(
                "the key file is encrypted, and its passphrase needs a terminal to type on.",
            ));
        }
        Some(checked(term::read_secret("Passphrase of the key file: ", false)).map_err(said)?)
    } else {
        None
    };
    Identities::read_key_file(&mut data.expose(), passphrase.as_ref()).map_err(said)
}

/// FIL-01.6, FIL-02.5: ten fresh words of the built-in list, saved as a new
/// protected entry before any encryption; the passphrase is never printed.
fn generate(p: &Parsed, vault_path: &str) -> Result<SecretString, Fail> {
    let group = p.value("group").unwrap_or_default();
    let title = p.value("title").unwrap_or_default();
    let mut s = vault::unlock(vault_path, &unlock_options(p))?;
    let gid = find_group(&s.vault, group)
        .map(|g| g.uuid)
        .ok_or_else(|| term::fail(format!("no group at {group}.")))?;
    let path = format!("{}/{title}", group.trim_end_matches('/'));
    if find_entry(&s.vault, &path).is_some() {
        return Err(term::fail(format!(
            "an entry is already found at {path}. Choose another --title."
        )));
    }
    let options = passphrase::Options::command_line(GENERATED_WORDS);
    let phrase = passphrase::generate(&options, wordlist::builtin())
        .map_err(|_| term::fail("could not get random numbers from macOS."))?;
    let failed = |e: larsal_core::Error| term::fail(format!("{e}."));
    let mut e = edit::new_entry(&s.vault, gid, false).map_err(failed)?;
    e.set_field("UserName".into(), Field::empty());
    let mp = &s.vault.meta.memory_protection;
    let title_protected = mp.for_field("Title");
    for (name, value, protected) in [
        ("Title", title, title_protected),
        (
            "Notes",
            "The passphrase of a file made with larsal encrypt.",
            mp.for_field("Notes"),
        ),
    ] {
        e.set_field(
            name.into(),
            Field {
                value: SecretString::new(value.to_owned()),
                protected,
            },
        );
    }
    e.set_field(
        "Password".into(),
        Field {
            value: SecretString::new(phrase.expose().to_owned()),
            protected: true,
        },
    );
    edit::add_entry(&mut s.vault, gid, e, now()).map_err(failed)?;
    if !p.quiet() {
        term::err("Saving passphrase");
    }
    s.save()?;
    if !p.quiet() {
        let shown = if title_protected {
            larsal_core::health::MASKED_TITLE
        } else {
            title
        };
        term::out(&format!("New entry {shown} saved."));
    }
    Ok(phrase)
}

/// FIL-02.12's phase words, on stderr unless `--quiet`.
fn phase_text(phase: Phase) -> &'static str {
    match phase {
        Phase::Capture => "Preparing encrypted copy",
        Phase::Validate => "Checking the whole file",
        Phase::Write => "Saving readable file",
        Phase::Encrypt => "Encrypting file",
    }
}

/// The work under the quit guard; the credential is wiped before the guard
/// goes, and a noted quit signal then ends the process.
fn work(
    p: &Parsed,
    guard: &QuitGuard,
    credential: Credential,
    source: Option<SourceFile>,
    folder: &OutputFolder,
    name: &OsStr,
    mode: Mode,
) -> u8 {
    let quiet = p.quiet();
    let mut last = None;
    let mut control = |phase: Phase, _done: u64| {
        if guard.caught().is_some() {
            return false;
        }
        if !quiet && last != Some(phase) {
            last = Some(phase);
            term::err(phase_text(phase));
        }
        true
    };
    let result = if p.cmd.name == "encrypt" {
        let lock = match &credential {
            Credential::Passphrase(s) => Lock::Passphrase(s),
            Credential::Recipients(list) => Lock::Recipients(list),
            Credential::Identities(_) => return FAILED,
        };
        match source {
            Some(source) => larsal_files::encrypt_file(source, folder, name, &lock, &mut control),
            None => Err(Error::Input),
        }
    } else {
        let unlock = match &credential {
            Credential::Passphrase(s) => Unlock::Passphrase(s),
            Credential::Identities(ids) => Unlock::Identities(ids),
            Credential::Recipients(_) => return FAILED,
        };
        let weak_key = matches!(&credential, Credential::Identities(ids) if ids.from_weak_file());
        decrypt(source, &unlock, weak_key, guard, folder, name, &mut control)
    };
    drop(credential);
    match result {
        Ok(_) => {
            if !quiet {
                term::out(&format!(
                    "Done. Saved {}.",
                    clean_label(OsStr::new(p.value("output").unwrap_or_default()))
                ));
            }
            for note in notes(p, mode) {
                term::err(note);
            }
            // FIL-02.21: a line that could not be written is a failure; the
            // complete output stays.
            if term::broken() || io::stdout().flush().is_err() {
                term::err("larsal: standard output or standard error could not be written.");
                return FAILED;
            }
            0
        }
        Err(e) => {
            term::err(&format!("larsal: {e}"));
            if mode == Mode::Generate {
                term::err(
                    "larsal: The passphrase is saved in your vault. No encrypted file was completed.",
                );
            }
            if e == Error::Cancelled {
                CANCELLED
            } else {
                FAILED
            }
        }
    }
}

/// What stays true after a success (FIL-02.11, FIL-02.22, MSG-FILE-LIMITS,
/// MSG-FILE-QUANTUM): said every time, also with `--quiet`.
fn notes(p: &Parsed, mode: Mode) -> &'static [&'static str] {
    if p.cmd.name == "decrypt" {
        &["The saved file is not encrypted. Keep it somewhere private."]
    } else if mode == Mode::Recipients {
        &[
            "These public keys do not protect against a future quantum computer.",
            "This does not prove who sent the file.",
        ]
    } else {
        &[
            "No server is contacted. Anyone with this encrypted file can test passphrase guesses. Names, sizes and dates may still be visible.",
        ]
    }
}

/// A fresh private scratch folder for one decrypt's ciphertext, in the
/// standard temp folder (TMPDIR), locked while this run uses it and removed
/// when dropped. It is empty by then: the capture seals its copy to a
/// nameless handle and removes its own folder (FIL-03.5, FIL-03.6). What a
/// crash leaves, the next run sweeps (FIL-03.11).
struct Scratch {
    path: PathBuf,
    lock: File,
}

impl Scratch {
    /// Another run's sweep may take a new folder in the moment between its
    /// making and its lock: then another is made, at most three in all.
    fn new() -> Result<(Self, ScratchRoot), Error> {
        let mut tries = 1;
        loop {
            match Self::make() {
                Err(_) if tries < 3 => tries += 1,
                made => return made,
            }
        }
    }

    fn make() -> Result<(Self, ScratchRoot), Error> {
        let id = larsal_crypto::random::bytes(16).map_err(|_| Error::Io)?;
        let hex: String = id.expose().iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("{SCRATCH}{hex}"));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| Error::Io)?;
        let lock = File::open(&path).map_err(|_| Error::Io)?;
        let scratch = Self { path, lock };
        scratch.lock.try_lock().map_err(|_| Error::Io)?;
        // Gone if a sweep took it before the lock: then this fails.
        let root = ScratchRoot::open(&scratch.path)?;
        Ok((scratch, root))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// FIL-03.11 at the start of each run: what a crash left before the seal is
/// removed from this tool's own scratch folders in the temp folder. A folder
/// is looked into only when its name is exactly this tool's form, it is a
/// real folder (not a link, not a FIFO) of this user with mode 0700 and no
/// access list,
/// and no live run holds its lock. Inside it, larsal-files' own sweep removes
/// only its own unsealed ciphertext; the folder then goes only if it is
/// empty. Nothing else is touched and nothing is judged by its age. An owned
/// leftover that could not be removed is said.
fn sweep_scratch() {
    let Ok(list) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    let mut failed = false;
    for entry in list.flatten() {
        if is_scratch_name(&entry.file_name()) {
            failed |= sweep_one(&entry.path()).is_err();
        }
    }
    if failed {
        term::err(
            "Note: Larsal could not remove the encrypted scratch an earlier run left behind.",
        );
    }
}

fn is_scratch_name(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    name.len() == SCRATCH.len() + 32
        && name.starts_with(SCRATCH.as_bytes())
        && name
            .iter()
            .skip(SCRATCH.len())
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One folder; `Err` only for an owned leftover that could not be removed.
/// First the name is opened as a folder only, never through a link and never
/// waiting (C1R2-01): a FIFO, a file or a link is left alone unopened. Then
/// ScratchRoot checks the folder is this user's, mode 0700, with no access
/// list, and its sweep refuses a name that no longer leads to the folder it
/// opened: both leave the folder alone.
fn sweep_one(path: &Path) -> Result<(), ()> {
    // ponytail: a live run holds this lock only on its own folder; the
    // capture inside it holds larsal-files' own lock. Equal in every test: it
    // guards only the moment between a run's making the folder and its lock.
    let Ok(lock) = larsal_platform::macos::open_dir(path) else {
        return Ok(());
    };
    let Ok(root) = ScratchRoot::open(path) else {
        return Ok(());
    };
    if lock.try_lock().is_err() {
        return Ok(());
    }
    match root.sweep() {
        Ok(_) => {}
        Err(Error::Io) => return Err(()),
        Err(_) => return Ok(()),
    }
    match std::fs::remove_dir(path) {
        Err(e) if !matches!(e.kind(), ErrorKind::DirectoryNotEmpty | ErrorKind::NotFound) => {
            Err(())
        }
        _ => Ok(()),
    }
}

/// FIL-03.4's order: capture and seal, unlock, check the whole file, ask
/// about a low work factor, and only then make the output.
fn decrypt(
    source: Option<SourceFile>,
    unlock: &Unlock<'_>,
    weak_key: bool,
    guard: &QuitGuard,
    folder: &OutputFolder,
    name: &OsStr,
    control: &mut dyn FnMut(Phase, u64) -> bool,
) -> Result<u64, Error> {
    let snapshot = {
        let (scratch, root) = Scratch::new()?;
        let snapshot = match source {
            Some(source) => root.capture_file(source, control),
            None => root.capture_stream(&mut io::stdin().lock(), control),
        };
        drop(scratch);
        snapshot?
    };
    let validated = match snapshot.unlock(unlock)?.validate(control)? {
        Validation::Ready(v) if !weak_key => v,
        Validation::Ready(v) => {
            consent(guard, WEAK_FILE, SAVE_READABLE)?;
            v
        }
        Validation::Weak(w) => {
            consent(guard, WEAK_FILE, SAVE_READABLE)?;
            w.accept()
        }
    };
    validated.save_new(folder, name, control)
}

/// MSG-FILE-WEAK (FIL-03.2) and its question.
const WEAK_FILE: &str =
    "This file uses a low passphrase work factor. Only save its contents if you trust the file.";
const SAVE_READABLE: &str = "Save the readable file? [y/N] ";

/// A warning, then a yes or no question on stderr, also with `--quiet`: only
/// a yes, read as a line from stdin, goes on; no answer is no. A quit signal
/// while waiting is a no. Used for a file with a low work factor (FIL-03.2)
/// and a weak passphrase (FIL-01.7).
fn consent(guard: &QuitGuard, warning: &str, question: &str) -> Result<(), Error> {
    term::err(warning);
    term::prompt(question, false);
    let mut stdin = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|_| Error::Io)?;
    let mut first = None;
    let mut byte = [0u8; 1];
    loop {
        match stdin.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                first.get_or_insert(byte[0]);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted && guard.caught().is_none() => {}
            Err(_) => return Err(Error::Cancelled),
        }
    }
    if guard.caught().is_none() && matches!(first, Some(b'y' | b'Y')) {
        Ok(())
    } else {
        Err(Error::Cancelled)
    }
}
