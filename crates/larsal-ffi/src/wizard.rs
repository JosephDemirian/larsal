//! The new vault wizard (E5-S8, APP-07) and the parts the vault settings
//! share with it (APP-07.20): the measurement of this Mac (CRY-02.28), the
//! encryption checks (APP-07.9), the password pair with its meter (FEA-05.7,
//! FEA-05.20) and key files (FMT-18.20 to FMT-18.24).
//!
//! Guarantees:
//! - the typed passwords go from Swift into `SecretString`s at once and stay
//!   here; Swift gets them back only as the Show the user asked for
//!   ([`Wizard::password`]) and a generated value it shows (FEA-02.23). A
//!   key file's bytes never leave Rust (AGENTS.md rule 4);
//! - every check is larsal-core's (`settings::apply`), run on a copy, in the
//!   card's order; the file is built by larsal-format and written through
//!   larsal-core's safe save (APP-05.11), mode 0600; nothing is left at the path
//!   when it fails (APP-07.17);
//! - the measurement runs on the caller's thread (Swift calls it off the
//!   screen thread); one at a time; a cancel drops its result (APP-07.8);
//! - a new key file is 32 fresh random bytes from `larsal-crypto` in the XML 2.0
//!   layout, mode 0400, never over an existing file (LD-99), read back
//!   before use (FMT-18.20 to FMT-18.23).

use crate::edit::Keep;
use crate::hwkey::{Choice, KeyPick};
use crate::messages;
use crate::session::{LarsalError, MAX_TEXT, Session, file_name, read_key};
use crate::views::{Rating, count, now};
use larsal_core::health::{Level, bits_with, score, zxcvbn_bits};
use larsal_core::settings::{
    self, Changes, Confirm, EncryptionEdit, KeyChange, PasswordPart, Refusal,
};
use larsal_core::storage::{self, SaveRequest};
use larsal_crypto::kdf::{self, Argon2Type, CostReport, KdfParams};
use larsal_crypto::secret::{SecretString, ct_eq};
use larsal_format::keyfile::{KeyFileKey, create_key_file, read_key_file};
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Error, Saved};
use larsal_model::{Argon2Kind, Cipher, Kdf, Vault};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The cipher of a vault (CRY-01.19), in the screen's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CipherChoice {
    /// AES-256, Larsal's default (LD-20).
    Aes256,
    /// Twofish-256.
    Twofish256,
    /// ChaCha20.
    ChaCha20,
}

/// The key derivation of a vault (CRY-02), in the screen's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KdfChoice {
    /// Argon2id, Larsal's default (LD-18).
    Argon2id,
    /// Argon2d.
    Argon2d,
    /// AES-KDF.
    AesKdf,
}

/// The encryption controls (APP-07.6, APP-07.7, MOD-12.11, MOD-12.12): the
/// iterations or rounds come from the measurement for `unlock_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct EncryptionChoice {
    /// The cipher.
    pub cipher: CipherChoice,
    /// The key derivation.
    pub kdf: KdfChoice,
    /// Argon2 memory in MiB, 1 to 1,048,576 (ignored for AES-KDF).
    pub memory_mib: u64,
    /// Argon2 lanes, 1 to 128 (ignored for AES-KDF).
    pub lanes: u64,
    /// The unlock time, 100 to 5,000 ms in steps of 100.
    pub unlock_ms: u32,
}

/// What the user said yes to (APP-07.9, APP-07.16, MOD-12.10, MOD-12.12,
/// FMT-18.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Answer {
    /// M07-33: below Larsal's safe minimum.
    SafeMinimum,
    /// M07-31: Argon2 iterations above 10,000.
    SlowArgon2,
    /// M07-32: AES-KDF rounds below 100,000.
    WeakAesKdf,
    /// M07-34: the cost question (CRY-02.14).
    Cost,
    /// M07-21: no password.
    NoPassword,
    /// M07-23: a password below Good (FEA-05.20).
    WeakPassword,
    /// M06-31: a key file with a vault file name.
    VaultLikeKeyFile,
}

/// An alert: its message, details and the button that answers yes; Cancel
/// is always the other button and the default.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Question {
    /// The card's message id, for example `M07-31`.
    pub id: String,
    /// The message.
    pub message: String,
    /// The details; may be empty.
    pub details: String,
    /// The yes button.
    pub confirm: String,
    /// What a yes adds to the answers of the next call.
    pub answer: Answer,
}

/// What a step, a create or a settings change gave.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Outcome {
    /// Done; the vault changed or the step may go on.
    Done,
    /// The new vault is written and open, unlocked and shown (APP-07.18).
    Created {
        /// Its session id.
        vault: u64,
    },
    /// Ask first; call again with the answer when the user says yes.
    Ask {
        /// The alert.
        question: Question,
    },
    /// Refused; nothing changed. `id` names the card's message.
    Refused {
        /// For example `M07-20`.
        id: String,
        /// The text, no secret.
        text: String,
    },
}

/// A key file the user chose or made: its name and path (not secret).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyFileView {
    /// The file name, cleaned (APP-06.18).
    pub name: String,
    /// The full path.
    pub path: String,
    /// M07-28 for a key file of an early kind; `None` otherwise.
    pub note: Option<String>,
}

/// What choosing or making a key file gave.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum KeyFileOutcome {
    /// The key file is the key part now.
    Chosen {
        /// The file.
        file: KeyFileView,
    },
    /// The result of the key change that followed (vault settings).
    Then {
        /// The outcome.
        outcome: Outcome,
    },
}

// ---------------------------------------------------------------------------
// The measurement (APP-07.8, CRY-02.28).

/// What one measurement was made with: the family, memory and lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Template {
    aes: bool,
    memory_kib: u64,
    lanes: u64,
}

impl Template {
    fn of(c: &EncryptionChoice) -> Self {
        if c.kdf == KdfChoice::AesKdf {
            Self {
                aes: true,
                memory_kib: 0,
                lanes: 1,
            }
        } else {
            Self {
                aes: false,
                memory_kib: c.memory_mib.saturating_mul(1024),
                lanes: c.lanes,
            }
        }
    }

    fn params(self) -> KdfParams {
        if self.aes {
            KdfParams::AesKdf {
                rounds: 1,
                seed: vec![0; 32],
            }
        } else {
            KdfParams::Argon2 {
                kind: Argon2Type::Id,
                version: 0x13,
                iterations: 1,
                memory_kib: self.memory_kib,
                lanes: self.lanes,
                salt: vec![0; 32],
            }
        }
    }
}

/// The last measurement: what it was made with and the count for one
/// second, so any unlock time needs no new run (APP-07.8).
#[derive(Default)]
pub(crate) struct Tuning {
    /// Moves on every cancel: a measurement that started before drops its
    /// result.
    epoch: u64,
    running: bool,
    measured: Option<(Template, u64)>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The clock of [`measure`] (CRY-02.28, LD-72): the thread's CPU time, so
/// a busy Mac cannot tune a weaker KDF.
const MEASURE_CLOCK: kdf::Clock = larsal_platform::macos::thread_cpu_time;

/// APP-07.8: measures `choice`'s family, memory and lanes once (a repeat of
/// the last one is kept) and stores the speed record (CRY-02.14). True when
/// the measurement is there; false when one already runs or a cancel came.
pub(crate) fn measure(
    session: &Session,
    tuning: &Mutex<Tuning>,
    choice: &EncryptionChoice,
) -> Result<bool, LarsalError> {
    let template = Template::of(choice);
    let epoch = {
        let mut t = lock(tuning);
        if t.running {
            return Ok(false);
        }
        if t.measured.is_some_and(|(m, _)| m == template) {
            return Ok(true);
        }
        t.running = true;
        t.epoch
    };
    let host = lock(&session.host).clone();
    let result = kdf::benchmark(&template.params(), 1_000, &host, MEASURE_CLOCK);
    let mut t = lock(tuning);
    t.running = false;
    let b = match result {
        Ok(b) => b,
        Err(larsal_crypto::Error::KdfCost) => {
            return Err(LarsalError::Refused(physical_note(host.physical_memory)));
        }
        Err(_) => return Err(LarsalError::Refused(KDF_UNCHANGED.to_owned())),
    };
    if t.epoch != epoch {
        return Ok(false);
    }
    let per_second = match b.params {
        KdfParams::AesKdf { rounds, .. } => rounds,
        KdfParams::Argon2 { iterations, .. } => iterations,
    };
    t.measured = Some((template, per_second));
    let mut host = lock(&session.host);
    if template.aes {
        host.aes_record = Some(b.record);
    } else {
        host.argon2_record = Some(b.record);
    }
    Ok(true)
}

/// A cancel (APP-07.8, Cancel of the wizard): a running measurement drops
/// its result.
pub(crate) fn cancel(tuning: &Mutex<Tuning>) {
    let mut t = lock(tuning);
    t.epoch = t.epoch.wrapping_add(1);
    t.running = false;
}

/// The count for one second when `choice` was measured.
fn per_second(tuning: &Mutex<Tuning>, choice: &EncryptionChoice) -> Option<u64> {
    let t = lock(tuning);
    t.measured
        .filter(|(m, _)| *m == Template::of(choice))
        .map(|(_, n)| n)
}

/// The measured run for 1,000 ms, as an unlock time of `count` iterations
/// (or rounds): count × 1,000 / per second, in steps of 100 ms, 100 to
/// 5,000 (the slider of MOD-12.11 for a vault without the unlock time item).
pub(crate) fn estimate_ms(
    tuning: &Mutex<Tuning>,
    choice: &EncryptionChoice,
    count: u64,
) -> Option<u32> {
    let n = per_second(tuning, choice).filter(|n| *n > 0)?;
    let ms = u128::from(count).saturating_mul(1_000) / u128::from(n);
    let steps = (ms.saturating_add(50) / 100).clamp(1, 50);
    u32::try_from(steps.saturating_mul(100)).ok()
}

/// The KDF of `choice` with the iterations or rounds for its unlock time:
/// ceiling(count for 1 s × time / 1,000) (CRY-02.28), at least 1; Argon2 at
/// most the refuse ceiling (CRY-02.14), AES-KDF at most 2,147,483,646.
fn kdf_for(choice: &EncryptionChoice, per_second: u64) -> Kdf {
    let n = u128::from(per_second)
        .saturating_mul(u128::from(choice.unlock_ms))
        .div_ceil(1_000);
    let n = u64::try_from(n).unwrap_or(u64::MAX);
    match choice.kdf {
        KdfChoice::AesKdf => Kdf::AesKdf {
            rounds: n.clamp(1, 2_147_483_646),
        },
        KdfChoice::Argon2id | KdfChoice::Argon2d => Kdf::Argon2 {
            kind: if choice.kdf == KdfChoice::Argon2d {
                Argon2Kind::D
            } else {
                Argon2Kind::Id
            },
            iterations: n.clamp(1, Limits::DEFAULT.kdf.refuse_iterations),
            memory_kib: choice.memory_mib.saturating_mul(1024),
            lanes: choice.lanes,
        },
    }
}

pub(crate) fn cipher_of(c: CipherChoice) -> Cipher {
    match c {
        CipherChoice::Aes256 => Cipher::Aes256,
        CipherChoice::Twofish256 => Cipher::Twofish256,
        CipherChoice::ChaCha20 => Cipher::ChaCha20,
    }
}

pub(crate) fn choice_of(c: Cipher) -> CipherChoice {
    match c {
        Cipher::Aes256 => CipherChoice::Aes256,
        Cipher::Twofish256 => CipherChoice::Twofish256,
        Cipher::ChaCha20 => CipherChoice::ChaCha20,
    }
}

/// The encryption edit of `choice` (the unlock time item with its time,
/// MOD-12.11), or M07-08 while it is not measured yet.
pub(crate) fn edit_for(
    tuning: &Mutex<Tuning>,
    choice: &EncryptionChoice,
) -> Result<EncryptionEdit, Outcome> {
    let n = per_second(tuning, choice).ok_or_else(|| refused("M07-08", "Measuring this Mac…"))?;
    Ok(EncryptionEdit {
        cipher: cipher_of(choice.cipher),
        kdf: kdf_for(choice, n),
        unlock_time_ms: Some(choice.unlock_ms.clamp(100, 5_000)),
    })
}

/// M07-35: more memory than this Mac has.
fn physical_note(physical: u64) -> String {
    format!(
        "This Mac has {} of memory. Choose less.",
        messages::memory(physical)
    )
}

/// M07-35 for `memory_mib` on this Mac; `None` when it fits.
pub(crate) fn memory_note(session: &Session, memory_mib: u64) -> Option<String> {
    let physical = lock(&session.host).physical_memory;
    let bytes = memory_mib.checked_mul(1 << 20);
    bytes
        .is_none_or(|b| b > physical)
        .then(|| physical_note(physical))
}

// ---------------------------------------------------------------------------
// Messages (APP-07 M07-20 to M07-35, FEA-05.20, MOD-12).

const KDF_UNCHANGED: &str =
    "Larsal could not use these key settings on this Mac. Nothing was changed.";
const MISMATCH: &str = "The two passwords are different.";

pub(crate) fn refused(id: &str, text: &str) -> Outcome {
    Outcome::Refused {
        id: id.to_owned(),
        text: text.to_owned(),
    }
}

fn ask(id: &str, message: String, details: &str, confirm: &str, answer: Answer) -> Outcome {
    Outcome::Ask {
        question: Question {
            id: id.to_owned(),
            message,
            details: details.to_owned(),
            confirm: confirm.to_owned(),
            answer,
        },
    }
}

/// A count with thousands separators, as the screen shows numbers.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len().saturating_sub(i)) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// One alert or refusal for each of larsal-core's refusals; a cost report is
/// kept in `cost` for the yes.
pub(crate) fn outcome_of(
    refusal: Refusal,
    edit: Option<&EncryptionEdit>,
    session: &Session,
    cost: &mut Option<CostReport>,
) -> Outcome {
    let count = edit.map_or(0, |e| match e.kdf {
        Kdf::AesKdf { rounds } => rounds,
        Kdf::Argon2 { iterations, .. } => iterations,
    });
    let time = messages::duration(u64::from(
        edit.and_then(|e| e.unlock_time_ms).unwrap_or(1_000),
    ));
    match refusal {
        Refusal::Confirm(Confirm::BelowSafeMinimum) => ask(
            "M07-33",
            format!(
                "These settings are below Larsal's safe minimum of 19 MiB and 2 iterations, so guessing the password gets faster. Each unlock would take about {time}. Use them anyway?"
            ),
            "",
            "Use Anyway",
            Answer::SafeMinimum,
        ),
        Refusal::Confirm(Confirm::SlowArgon2) => ask(
            "M07-31",
            format!(
                "{} iterations make each unlock very slow on most Macs. Use them anyway?",
                thousands(count)
            ),
            "",
            "Use Anyway",
            Answer::SlowArgon2,
        ),
        Refusal::Confirm(Confirm::WeakAesKdf) => ask(
            "M07-32",
            format!(
                "{} rounds make the password much easier to find by trying many guesses. Use them anyway?",
                thousands(count)
            ),
            "",
            "Use Anyway",
            Answer::WeakAesKdf,
        ),
        Refusal::Cost(report) => {
            let time = messages::duration(report.estimated_ms());
            let text = if report.memory_bytes() == 0 {
                format!(
                    "With these settings each unlock needs about {time} on this Mac. Use them anyway?"
                )
            } else {
                format!(
                    "With these settings each unlock needs about {} of memory and about {time} on this Mac. Use them anyway?",
                    messages::memory(report.memory_bytes())
                )
            };
            *cost = Some(report);
            ask("M07-34", text, "", "Use Anyway", Answer::Cost)
        }
        Refusal::Confirm(Confirm::NoPassword) => ask(
            "M07-21",
            "Use no password for this vault?".to_owned(),
            "Then the key file or security key alone opens the vault, so anyone who gets hold of it can open it. Adding a password is safer.",
            "Use No Password",
            Answer::NoPassword,
        ),
        Refusal::Confirm(Confirm::WeakPassword) => ask(
            "M07-23",
            "This password is easy to guess, so your vault is less safe. Use it anyway?".to_owned(),
            "",
            "Use this password",
            Answer::WeakPassword,
        ),
        Refusal::PasswordMismatch => refused("M07-20", MISMATCH),
        Refusal::BelowMinimum => refused(
            "M07-22",
            "This password is weaker than Larsal allows. Choose a stronger one.",
        ),
        Refusal::NoKeyPart => refused(
            "M07-24",
            "Add a password, a key file or a security key. A vault needs at least one.",
        ),
        Refusal::KdfUnchanged => {
            let memory = edit.map_or(0, |e| match e.kdf {
                Kdf::Argon2 { memory_kib, .. } => memory_kib.saturating_mul(1024),
                Kdf::AesKdf { .. } => 0,
            });
            let physical = lock(&session.host).physical_memory;
            if memory > physical {
                refused("M07-35", &physical_note(physical))
            } else {
                refused("vault.msg.kdf_unchanged", KDF_UNCHANGED)
            }
        }
        Refusal::OutOfRange(id) => refused(id, "This value is out of range. Nothing was changed."),
        Refusal::Failed(_) => refused(
            "vault.msg.failed",
            "The vault changed meanwhile. Nothing was changed; try again.",
        ),
    }
}

/// larsal-core's confirmations for the answers given.
pub(crate) fn confirms(answers: &[Answer]) -> Vec<Confirm> {
    answers
        .iter()
        .filter_map(|a| match a {
            Answer::SafeMinimum => Some(Confirm::BelowSafeMinimum),
            Answer::SlowArgon2 => Some(Confirm::SlowArgon2),
            Answer::WeakAesKdf => Some(Confirm::WeakAesKdf),
            Answer::NoPassword => Some(Confirm::NoPassword),
            Answer::WeakPassword => Some(Confirm::WeakPassword),
            Answer::Cost | Answer::VaultLikeKeyFile => None,
        })
        .collect()
}

/// S-CFG-02 `security.min_master_quality` (FEA-05.7, 0 to 4; the store
/// clamps it): a new password below it is refused with M07-22.
pub(crate) fn min_quality(session: &Session) -> u8 {
    let n = session
        .settings()
        .number("security.min_master_quality".into());
    u8::try_from(n.clamp(0, 4)).unwrap_or(0)
}

/// APP-06.30: the words for an operating system reason.
fn io_reason(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded => "no space left on the disk",
        ErrorKind::PermissionDenied => "Larsal is not allowed to write there",
        ErrorKind::NotFound => "the folder no longer exists",
        ErrorKind::ReadOnlyFilesystem => "the disk cannot be written",
        _ => "an unexpected system error",
    }
}

/// APP-06.30: the reason of a create that larsal-format refused.
fn format_reason(e: &Error) -> String {
    match e {
        Error::NoCredentials => "the vault has no password, key file or security key".to_owned(),
        Error::TooLarge(limit) => format!("the vault is over Larsal's {} limit", limit.name()),
        Error::Unsupported => "Larsal cannot write this setting".to_owned(),
        Error::Io(kind) => io_reason(*kind).to_owned(),
        Error::HardwareKey(larsal_format::error::HardwareKeyReason::TimedOut) => {
            "the security key was not touched in time".to_owned()
        }
        Error::HardwareKey(_) => "Larsal could not use the security key".to_owned(),
        _ => "an unexpected system error".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// The password pair (APP-07.11, MOD-12.10).

/// The password and its repeat, as typed; wiped on drop.
#[derive(Default)]
pub(crate) struct Pair {
    password: Option<SecretString>,
    repeat: Option<SecretString>,
}

fn secret(text: String) -> Result<Option<SecretString>, LarsalError> {
    let s = SecretString::new(text);
    if s.len() > MAX_TEXT {
        return Err(LarsalError::TooLong);
    }
    Ok((!s.is_empty()).then_some(s))
}

fn text(s: Option<&SecretString>) -> &str {
    s.map_or("", SecretString::expose)
}

impl Pair {
    /// The meter (FEA-05.7): nothing for an empty field.
    pub(crate) fn set_password(&mut self, typed: String) -> Result<Option<Rating>, LarsalError> {
        self.password = secret(typed)?;
        Ok(rate_master(text(self.password.as_ref())))
    }

    /// M07-20 and the check mark: `None` while the repeat is empty.
    pub(crate) fn set_repeat(&mut self, typed: String) -> Result<Option<bool>, LarsalError> {
        self.repeat = secret(typed)?;
        Ok(self.match_state())
    }

    /// The check mark (`Some(true)`) or M07-20 (`Some(false)`); `None`
    /// while the repeat field is empty.
    pub(crate) fn match_state(&self) -> Option<bool> {
        self.repeat.is_some().then(|| self.matches())
    }

    pub(crate) fn matches(&self) -> bool {
        ct_eq(
            text(self.password.as_ref()).as_bytes(),
            text(self.repeat.as_ref()).as_bytes(),
        )
    }

    /// The one value of a Show (APP-07.11): the field's text.
    pub(crate) fn shown(&self, repeat: bool) -> String {
        text(if repeat {
            self.repeat.as_ref()
        } else {
            self.password.as_ref()
        })
        .to_owned()
    }

    /// FEA-02.17: a generated value fills both fields.
    fn fill(&mut self, value: &SecretString) {
        self.password = Some(SecretString::new(value.expose().to_owned()));
        self.repeat = Some(SecretString::new(value.expose().to_owned()));
    }

    /// The credentials part for larsal-core's checks (MOD-12.10): an empty
    /// password is no password (M07-21), never the empty password.
    pub(crate) fn part(&self) -> PasswordPart {
        match &self.password {
            None => PasswordPart::Removed,
            Some(p) => PasswordPart::New {
                typed: SecretString::new(p.expose().to_owned()),
                repeat: SecretString::new(text(self.repeat.as_ref()).to_owned()),
                quality: quality(p.expose()),
            },
        }
    }

    fn take(&mut self) -> Option<SecretString> {
        self.repeat = None;
        self.password.take()
    }
}

/// FEA-05.4's quality, 0 (Bad) to 4 (Excellent), of a master password; no
/// user inputs around it.
fn quality(password: &str) -> u8 {
    Level::of(score(bits_with(&zxcvbn_bits, password, &[]))).quality()
}

/// The meter under a new master password (FEA-05.7): level and bits.
pub(crate) fn rate_master(password: &str) -> Option<Rating> {
    if password.is_empty() {
        return None;
    }
    let bits = bits_with(&zxcvbn_bits, password, &[]);
    let level = Level::of(score(bits));
    Some(Rating {
        level: level.name().to_owned(),
        word: level.name().to_owned(),
        segments: level.quality(),
        attention: false,
        expired: false,
        issue: String::new(),
        reasons: Vec::new(),
        chars: count(password.chars().count()),
        // `as` saturates; E is never negative.
        bits: bits.round() as u32,
    })
}

// ---------------------------------------------------------------------------
// Key files (FMT-18.20 to FMT-18.24, APP-07.13, APP-07.14).

/// FMT-18.24: the reference's vault extension, as bytes (AGENTS.md rule 1).
const OTHER_VAULT_EXT: [u8; 5] = [0x2E, 0x6B, 0x64, 0x62, 0x78];

fn vault_like(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".larsalvault") || lower.as_bytes().ends_with(&OTHER_VAULT_EXT)
}

/// APP-07.13: writes a new XML 2.0 key file at `path` (mode 0400, never
/// over an existing file, LD-99), then reads it back (FMT-18.23).
pub(crate) fn make_key_file(path: &Path) -> Result<(KeyFileKey, String), Outcome> {
    let name = messages::clean_name(&file_name(path));
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(refused(
            "M07-26",
            &format!(
                "A file named \"{name}\" already exists there. Larsal never replaces a file with a new key file, because it may be another vault's key. Choose another name."
            ),
        ));
    }
    let failed = |kind: ErrorKind| {
        refused(
            "M07-25",
            &format!(
                "The new key file \"{name}\" was not written: {}.",
                io_reason(kind)
            ),
        )
    };
    let bytes = create_key_file().map_err(|_| failed(ErrorKind::Other))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|e| failed(e.kind()))?;
    let written = file
        .write_all(bytes.expose())
        .and_then(|()| file.sync_all());
    drop(file);
    drop(bytes);
    let key = written.map_err(|e| e.kind()).and_then(|()| {
        let f = std::fs::File::open(path).map_err(|e| e.kind())?;
        read_key_file(f, &Limits::DEFAULT).map_err(|_| ErrorKind::InvalidData)
    });
    match key {
        Ok(key) => Ok((key, name)),
        Err(kind) => {
            // No partial key file is left (APP-07.13).
            let _ = std::fs::remove_file(path);
            Err(failed(kind))
        }
    }
}

/// APP-07.14 and FMT-18.24: reads a chosen key file; `vault` is the vault's
/// own file when there is one (M06-30). A vault-like name asks M06-31 until
/// the answers hold [`Answer::VaultLikeKeyFile`].
pub(crate) fn choose_key_file(
    path: &Path,
    vault: Option<&Path>,
    answers: &[Answer],
) -> Result<(KeyFileKey, KeyFileView), Outcome> {
    let name = messages::clean_name(&file_name(path));
    if vault_like(&name) && !answers.contains(&Answer::VaultLikeKeyFile) {
        return Err(ask(
            "M06-31",
            format!(
                "\"{name}\" has a vault file name. A vault changes with every save, and a key file that changes stops the vault from opening. Use this file anyway?"
            ),
            "",
            "Use Anyway",
            Answer::VaultLikeKeyFile,
        ));
    }
    let typed = path.to_string_lossy();
    let (key, name) = read_key(vault.unwrap_or(Path::new("")), &typed).map_err(|m| {
        let id = if m.id == "M06-30" { "M06-30" } else { "M07-27" };
        refused(id, &m.text)
    })?;
    let note = key.kind().old_format().then(|| {
        format!("\"{name}\" is a key file of an early kind. It still works, but a future version of Larsal may no longer read it; a new key file is safer.")
    });
    let view = KeyFileView {
        name: name.clone(),
        path: typed.into_owned(),
        note,
    };
    Ok((key, view))
}

// ---------------------------------------------------------------------------
// The wizard.

/// The new vault wizard (APP-07): one per open wizard; Swift drops it on
/// Cancel and after the vault is made, which wipes what it holds
/// (APP-07.3, APP-07.18).
#[derive(uniffi::Object)]
pub struct Wizard {
    session: Arc<Session>,
    tuning: Mutex<Tuning>,
    state: Mutex<WizardState>,
}

#[derive(Default)]
struct WizardState {
    pair: Pair,
    /// The key file part: the key, its name and its path.
    key_file: Option<(KeyFileKey, String, PathBuf)>,
    /// The hardware key part (APP-07.15, F-126): a key and slot, not secret.
    hardware: Option<KeyPick>,
    /// The last cost report, for its yes (CRY-02.14).
    cost: Option<CostReport>,
}

impl Wizard {
    fn state(&self) -> MutexGuard<'_, WizardState> {
        lock(&self.state)
    }

    /// APP-07.17 steps 3 to 5: builds the vault and writes it to `path`;
    /// with a hardware key, its challenge runs now with the new seed
    /// (FMT-04.17), and the vault keeps the key for every save.
    fn write(
        &self,
        st: &mut WizardState,
        vault: Vault,
        path: &Path,
        approval: Option<&CostReport>,
        hardware: Option<Choice>,
    ) -> Result<u64, Outcome> {
        let fail = |reason: String| {
            refused(
                "M07-30",
                &format!("The vault could not be created: {reason}."),
            )
        };
        let part = hardware.map(Choice::part);
        let built = {
            let credentials = Credentials {
                password: st.pair.password.as_ref(),
                key_file: st.key_file.as_ref().map(|k| &k.0),
                hardware_key: part.as_deref(),
            };
            let mut host = lock(&self.session.host);
            larsal_format::save(
                &vault,
                &credentials,
                None,
                &mut host,
                &Limits::DEFAULT,
                approval,
            )
        };
        let file = match built {
            Ok(Saved::File(file)) => file,
            Ok(Saved::Ask(report)) => {
                return Err(outcome_of(
                    Refusal::Cost(report),
                    None,
                    &self.session,
                    &mut st.cost,
                ));
            }
            Err(e) => return Err(fail(format_reason(&e))),
        };
        let temp = std::env::temp_dir();
        storage::save(&SaveRequest::plain(path, &file.bytes, None, &temp)).map_err(|e| {
            let kind = match e {
                storage::SaveError::CannotRead(kind) | storage::SaveError::Write { kind, .. } => {
                    kind
                }
                storage::SaveError::ChangedOnDisk(_) => ErrorKind::Other,
            };
            fail(io_reason(kind).to_owned())
        })?;
        // SD-09: a new vault is the owner's only, also over a replaced file.
        let _ =
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(storage::OWNER_ONLY));
        let key_file = st.key_file.take().map(|(k, name, _)| (k, name));
        let keep =
            Keep::new(st.pair.take(), key_file, file.key, &file.bytes).with_hardware(hardware);
        self.session
            .adopt(path, Box::new(vault), keep)
            .map_err(|e| fail(e.to_string()))
    }
}

#[uniffi::export]
impl Wizard {
    /// A new wizard on step 1 with fresh values (APP-07.1).
    #[uniffi::constructor]
    #[must_use]
    pub fn new(session: Arc<Session>) -> Arc<Self> {
        Arc::new(Self {
            session,
            tuning: Mutex::default(),
            state: Mutex::default(),
        })
    }

    /// Step 2's values (APP-07.6): AES-256, Argon2id with 64 MiB and
    /// min(4, logical processors) lanes, 1.0 s.
    #[must_use]
    pub fn defaults(&self) -> EncryptionChoice {
        let cores = lock(&self.session.host).logical_processors;
        EncryptionChoice {
            cipher: CipherChoice::Aes256,
            kdf: KdfChoice::Argon2id,
            memory_mib: 64,
            lanes: cores.clamp(1, 4),
            unlock_ms: 1_000,
        }
    }

    /// APP-07.8: measures this Mac for `choice`'s family, memory and lanes
    /// (call it off the screen thread). False when one already runs or a
    /// cancel came; the step waits for the next.
    ///
    /// # Errors
    /// `Refused` with M07-35 for more memory than this Mac has, or the
    /// settings the KDF refuses.
    pub fn measure(&self, choice: EncryptionChoice) -> Result<bool, LarsalError> {
        measure(&self.session, &self.tuning, &choice)
    }

    /// Drops the result of a running measurement (Cancel, APP-07.3).
    pub fn cancel_measure(&self) {
        cancel(&self.tuning);
    }

    /// M07-35 under the Memory field; `None` when it fits.
    #[must_use]
    pub fn memory_note(&self, memory_mib: u64) -> Option<String> {
        memory_note(&self.session, memory_mib)
    }

    /// APP-07.9: the checks when leaving step 2, in the card's order; with
    /// `recommended` (simple mode) none. Each alert's yes goes in
    /// `answers` for the next call.
    #[must_use]
    pub fn check_encryption(
        &self,
        choice: EncryptionChoice,
        recommended: bool,
        answers: Vec<Answer>,
    ) -> Outcome {
        if recommended {
            return Outcome::Done;
        }
        if let Some(note) = memory_note(&self.session, choice.memory_mib)
            .filter(|_| choice.kdf != KdfChoice::AesKdf)
        {
            return refused("M07-35", &note);
        }
        let edit = match edit_for(&self.tuning, &choice) {
            Ok(edit) => edit,
            Err(outcome) => return outcome,
        };
        let mut st = self.state();
        let changes = Changes {
            encryption: Some(edit),
            confirmed: confirms(&answers),
            cost_approval: answers
                .contains(&Answer::Cost)
                .then(|| st.cost.clone())
                .flatten(),
            ..Changes::default()
        };
        let cores = lock(&self.session.host).logical_processors;
        let Ok(mut scratch) = settings::new_vault("", now(), cores) else {
            return refused(
                "M07-30",
                "The vault could not be created: an unexpected system error.",
            );
        };
        let result = {
            let mut host = lock(&self.session.host);
            settings::apply(
                &mut scratch,
                &changes,
                &mut host,
                &Limits::DEFAULT.kdf,
                now(),
            )
        };
        match result {
            Ok(_) => Outcome::Done,
            Err(r) => outcome_of(r, Some(&edit), &self.session, &mut st.cost),
        }
    }

    /// The Password field changed (APP-07.11): the meter, nothing for an
    /// empty field.
    ///
    /// # Errors
    /// `TooLong` over 64 KiB.
    pub fn set_password(&self, text: String) -> Result<Option<Rating>, LarsalError> {
        self.state().pair.set_password(text)
    }

    /// The Verify password field changed: `Some(true)` for the check mark,
    /// `Some(false)` for M07-20, `None` while it is empty.
    ///
    /// # Errors
    /// `TooLong` over 64 KiB.
    pub fn set_repeat(&self, text: String) -> Result<Option<bool>, LarsalError> {
        self.state().pair.set_repeat(text)
    }

    /// The repeat field's state after the Password field changed: the
    /// check mark, M07-20, or `None` while it is empty.
    #[must_use]
    pub fn repeat_matches(&self) -> Option<bool> {
        self.state().pair.match_state()
    }

    /// Show (APP-07.11): the Password field's text (a crossing of LD-220
    /// while the wizard is open).
    #[must_use]
    pub fn password(&self) -> String {
        self.state().pair.shown(false)
    }

    /// Show: the Verify password field's text (LD-220, as `password`).
    #[must_use]
    pub fn repeat(&self) -> String {
        self.state().pair.shown(true)
    }

    /// The dice button (APP-07.11, FEA-02.17): a password with the
    /// generator's saved options fills both fields; returned to be shown (a
    /// crossing of LD-220: the generator's value).
    ///
    /// # Errors
    /// `Refused` with the generator's reason when the options make nothing.
    pub fn generate(&self) -> Result<String, LarsalError> {
        let options = self.session.generator_options(None);
        let (value, _) = crate::generator::make(&options).map_err(LarsalError::Refused)?;
        self.state().pair.fill(&value);
        Ok(value.expose().to_owned())
    }

    /// "New Key File…" (APP-07.13) at `path`: written, read back, and the
    /// key file part. M07-26 for an existing file, M07-25 when it fails.
    ///
    /// # Errors
    /// `TooLong` for a path over 4,096 bytes.
    pub fn new_key_file(&self, path: String) -> Result<KeyFileOutcome, LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let path = PathBuf::from(path);
        Ok(match make_key_file(&path) {
            Ok((key, name)) => {
                let file = KeyFileView {
                    name: name.clone(),
                    path: path.to_string_lossy().into_owned(),
                    note: None,
                };
                self.state().key_file = Some((key, name, path));
                KeyFileOutcome::Chosen { file }
            }
            Err(outcome) => KeyFileOutcome::Then { outcome },
        })
    }

    /// "Choose Key File…" (APP-07.14): read at once; M06-31 for a
    /// vault-like name, M07-27 for an error (the field stays empty), M07-28
    /// as the note of an early kind.
    ///
    /// # Errors
    /// `TooLong` for a path over 4,096 bytes.
    pub fn choose_key_file(
        &self,
        path: String,
        answers: Vec<Answer>,
    ) -> Result<KeyFileOutcome, LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let path = PathBuf::from(path);
        Ok(match choose_key_file(&path, None, &answers) {
            Ok((key, file)) => {
                self.state().key_file = Some((key, file.name.clone(), path));
                KeyFileOutcome::Chosen { file }
            }
            Err(outcome) => KeyFileOutcome::Then { outcome },
        })
    }

    /// "Remove": the key file part is empty again.
    pub fn remove_key_file(&self) {
        self.state().key_file = None;
    }

    /// The hardware key part (APP-07.15, F-126): the key and slot chosen
    /// from a look, or `None` for "Remove". No challenge runs before
    /// Create Vault (APP-07.17), so the user touches the key once.
    pub fn set_security_key(&self, pick: Option<KeyPick>) {
        self.state().hardware = pick;
    }

    /// "Create Vault" (APP-07.16, APP-07.17): the checks in the card's
    /// order; with an empty `path` that is all (`Done`: open the save
    /// panel). With the panel's path the vault is built with the MOD-12.22
    /// values, `name`,
    /// `description`, `choice` and the key parts, written to `path` (the
    /// save panel's) through the safe save, and opened unlocked as the
    /// shown vault. Runs the KDF on the calling thread: call it off the
    /// screen thread. Cancel in an alert keeps every value.
    ///
    /// # Errors
    /// `TooLong` for text over 64 KiB or a path over 4,096 bytes.
    pub fn create(
        &self,
        name: String,
        description: String,
        path: String,
        choice: EncryptionChoice,
        recommended: bool,
        answers: Vec<Answer>,
    ) -> Result<Outcome, LarsalError> {
        if name.len() > MAX_TEXT || description.len() > MAX_TEXT || path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let path = PathBuf::from(path);
        let mut st = self.state();
        // 1. The match first, so a text typed only in the repeat field is
        // never dropped silently (APP-07.16).
        if !st.pair.matches() {
            return Ok(refused("M07-20", MISMATCH));
        }
        let edit = match edit_for(&self.tuning, &choice) {
            Ok(edit) => edit,
            Err(outcome) => return Ok(outcome),
        };
        let mut confirmed = confirms(&answers);
        if recommended {
            // APP-07.9: simple mode is Larsal's own measurement, no warnings.
            confirmed.extend([Confirm::BelowSafeMinimum, Confirm::SlowArgon2]);
        }
        let approval = answers
            .contains(&Answer::Cost)
            .then(|| st.cost.clone())
            .flatten();
        // 2 to 4 and 7: larsal-core's checks (MOD-12.10), with step 2's.
        let changes = Changes {
            name: Some(name),
            description: Some(description),
            encryption: Some(edit),
            key: Some(KeyChange {
                password: st.pair.part(),
                had_password: false,
                key_file: st.key_file.is_some(),
                hardware: st.hardware.is_some(),
                min_quality: min_quality(&self.session),
            }),
            confirmed,
            cost_approval: approval.clone(),
            ..Changes::default()
        };
        let cores = lock(&self.session.host).logical_processors;
        let mut vault = match settings::new_vault("", now(), cores) {
            Ok(v) => v,
            Err(_) => {
                return Ok(refused(
                    "M07-30",
                    "The vault could not be created: an unexpected system error.",
                ));
            }
        };
        let applied = {
            let mut host = lock(&self.session.host);
            settings::apply(&mut vault, &changes, &mut host, &Limits::DEFAULT.kdf, now())
        };
        drop(changes);
        if let Err(r) = applied {
            return Ok(outcome_of(r, Some(&edit), &self.session, &mut st.cost));
        }
        // 5. The key file must read now (FMT-18).
        if let Some((_, _, key_path)) = &st.key_file {
            let typed = key_path.to_string_lossy();
            if let Err(m) = read_key(Path::new(""), &typed) {
                return Ok(refused("M07-27", &m.text));
            }
        }
        // 6. The chosen key must be plugged in now (INT-07): M06-17.
        let hardware = match st.hardware.map(crate::hwkey::plugged) {
            None => None,
            Some(Ok(choice)) => Some(choice),
            Some(Err(m)) => return Ok(refused(m.id, &m.text)),
        };
        // Every check passed: an empty path asks no more, so the save panel
        // opens now (APP-07.16 step 8).
        if path.as_os_str().is_empty() {
            return Ok(Outcome::Done);
        }
        // The save panel's path (APP-07.17 step 1): never the key file.
        if let Some((_, _, key_path)) = &st.key_file {
            let target = path
                .parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .zip(path.file_name())
                .map(|(dir, n)| dir.join(n));
            if target.is_some() && target == std::fs::canonicalize(key_path).ok() {
                return Ok(refused(
                    "M07-29",
                    "The vault cannot be saved over its own key file. Choose another name or place.",
                ));
            }
        }
        Ok(
            match self.write(&mut st, vault, &path, approval.as_ref(), hardware) {
                Ok(id) => Outcome::Created { vault: id },
                Err(outcome) => outcome,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app07_8_iterations_for_any_time_from_one_run() {
        let c = |ms| EncryptionChoice {
            cipher: CipherChoice::Aes256,
            kdf: KdfChoice::Argon2id,
            memory_mib: 64,
            lanes: 4,
            unlock_ms: ms,
        };
        // T08: 2.5 s from the run for 1 s, rounded up; no new run.
        assert_eq!(
            kdf_for(&c(2_500), 13),
            Kdf::Argon2 {
                kind: Argon2Kind::Id,
                iterations: 33,
                memory_kib: 65_536,
                lanes: 4
            }
        );
        // T13: an absurd count is capped at the refuse ceiling.
        assert!(matches!(
            kdf_for(&c(5_000), u64::MAX),
            Kdf::Argon2 {
                iterations: 1_000_000_000,
                ..
            }
        ));
        // At least one.
        assert!(matches!(
            kdf_for(&c(100), 0),
            Kdf::Argon2 { iterations: 1, .. }
        ));
    }

    /// APP-07.8: a cancel while the measurement runs drops its result. The
    /// test holds the host lock, so the run waits inside `measure` until the
    /// cancel has come.
    #[test]
    fn app07_8_a_cancel_during_the_run_drops_its_result() {
        let session = Session::new();
        let tuning = Mutex::<Tuning>::default();
        let choice = EncryptionChoice {
            cipher: CipherChoice::Aes256,
            kdf: KdfChoice::Argon2id,
            memory_mib: 1,
            lanes: 1,
            unlock_ms: 100,
        };
        let result = std::thread::scope(|scope| {
            let host = lock(&session.host);
            let run = scope.spawn(|| measure(&session, &tuning, &choice));
            while !lock(&tuning).running {
                std::thread::yield_now();
            }
            cancel(&tuning);
            drop(host);
            run.join().unwrap()
        });
        assert!(matches!(result, Ok(false)));
        assert_eq!(per_second(&tuning, &choice), None);
        // The next run is kept.
        assert!(matches!(measure(&session, &tuning, &choice), Ok(true)));
        assert!(per_second(&tuning, &choice).is_some());
    }

    #[test]
    fn fmt18_24_vault_like_names() {
        assert!(vault_like("demo.larsalvault"));
        assert!(vault_like("DEMO.LARSALVAULT"));
        let other =
            format!("x{}", String::from_utf8(OTHER_VAULT_EXT.to_vec()).unwrap()).to_uppercase();
        assert!(vault_like(&other));
        assert!(!vault_like("demo.larsalkey"));
    }

    /// F-126 (APP-07 edge cases): a security key not touched during the
    /// write gives M07-30 with the APP-06.30 reason.
    #[test]
    fn f_126_m07_30_names_a_missed_touch() {
        use larsal_format::error::HardwareKeyReason;
        assert_eq!(
            format_reason(&Error::HardwareKey(HardwareKeyReason::TimedOut)),
            "the security key was not touched in time"
        );
        assert_eq!(
            format_reason(&Error::HardwareKey(HardwareKeyReason::Failed)),
            "Larsal could not use the security key"
        );
    }

    #[test]
    fn numbers_with_separators() {
        assert_eq!(thousands(20_000), "20,000");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000_000_000), "1,000,000,000");
    }

    fn argon2(kdf: KdfChoice, memory_mib: u64, lanes: u64, unlock_ms: u32) -> EncryptionChoice {
        EncryptionChoice {
            cipher: CipherChoice::Aes256,
            kdf,
            memory_mib,
            lanes,
            unlock_ms,
        }
    }

    /// LD-72, CRY-02.28: `measure` times the KDF with this thread's CPU time
    /// (`thread_cpu_time`), so other work on a busy Mac cannot make the
    /// count weaker: its clock stands still while the thread sleeps, where
    /// a wall clock would move 200 ms.
    #[test]
    fn ld_72_the_measurement_clock_is_the_threads_cpu_time() {
        let before = MEASURE_CLOCK();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let slept = MEASURE_CLOCK().saturating_sub(before);
        assert!(slept < std::time::Duration::from_millis(50), "{slept:?}");
    }

    /// LD-241 (2), LD-72: the KDF call inside `measure` times with
    /// `MEASURE_CLOCK` (ld_72 pins the clock itself, not this call): a wall
    /// clock passed there would let a busy Mac tune a weaker KDF.
    #[test]
    fn ld_241_measure_passes_measure_clock_to_the_benchmark() {
        let body = include_str!("wizard.rs")
            .split("pub(crate) fn measure(")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .unwrap();
        let calls: Vec<String> = body
            .split("kdf::benchmark(")
            .skip(1)
            .map(|call| call.split(';').next().unwrap().split_whitespace().collect())
            .collect();
        assert_eq!(calls, ["&template.params(),1_000,&host,MEASURE_CLOCK)"]);
    }

    /// APP-07 T08, CRY-02.28 (LD-224 (2)): with a fake measurement of N = 13
    /// for 1 s, the slider at 2.5 s gives ceiling(13 × 2,500 / 1,000) = 33
    /// iterations with no new run, and the unlock time item holds 2,500.
    #[test]
    fn app07_t08_the_slider_scales_the_one_measured_count() {
        let tuning = Mutex::<Tuning>::default();
        let choice = argon2(KdfChoice::Argon2id, 64, 4, 2_500);
        lock(&tuning).measured = Some((Template::of(&choice), 13));
        let edit = edit_for(&tuning, &choice).unwrap();
        assert_eq!(
            edit.kdf,
            Kdf::Argon2 {
                kind: Argon2Kind::Id,
                iterations: 33,
                memory_kib: 65_536,
                lanes: 4
            }
        );
        assert_eq!(edit.unlock_time_ms, Some(2_500));
        assert!(!lock(&tuning).running, "no new run");
    }

    /// APP-07 T14 (CRY-02.14): a measurement keeps the speed record of its
    /// run in the session's host (the record the cost check reads): the
    /// family, the run's count, memory and lanes, and its time.
    #[test]
    fn app07_t14_a_measurement_keeps_the_speed_record() {
        let session = Session::new();
        let tuning = Mutex::<Tuning>::default();
        let choice = argon2(KdfChoice::Argon2id, 1, 1, 100);
        assert_eq!(lock(&session.host).argon2_record, None);
        assert!(matches!(measure(&session, &tuning, &choice), Ok(true)));
        let host = lock(&session.host);
        let record = host.argon2_record.expect("the speed record");
        assert_eq!((record.memory_kib, record.lanes), (1_024, 1));
        assert!(record.count >= 1 && record.ms >= 1, "{record:?}");
        assert_eq!(host.aes_record, None, "only the measured family");
    }

    /// APP-07 T18, APP-07.10 (LD-224 (1)): "Custom" (Argon2d, 128 MiB, 0.3 s)
    /// on a fake measurement of N = 7 writes the unlock time item `300`
    /// under CRY-02.25's key and ceiling(7 × 300 / 1,000) = 3 iterations;
    /// "Recommended" (1.0 s, N = 2) writes `1000` and 2 iterations.
    #[test]
    fn app07_t18_custom_and_recommended_write_the_unlock_time_item() {
        // CRY-02.25's key, as bytes (AGENTS.md rule 1).
        const KEY: [u8; 31] = [
            0x4B, 0x50, 0x58, 0x43, 0x5F, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4F,
            0x4E, 0x5F, 0x54, 0x49, 0x4D, 0x45, 0x5F, 0x50, 0x52, 0x45, 0x46, 0x45, 0x52, 0x45,
            0x4E, 0x43, 0x45,
        ];
        let key = std::str::from_utf8(&KEY).unwrap();
        let dir =
            std::env::temp_dir().join(format!("larsal-ffi-wizard-t18-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "4v8Nq2LmZ7rT1xKc9WbP";
        for (recommended, n, item, iterations) in [(false, 7, "300", 3), (true, 2, "1000", 2)] {
            let w = Wizard::new(Session::new());
            let choice = if recommended {
                w.defaults()
            } else {
                argon2(KdfChoice::Argon2d, 128, 1, 300)
            };
            lock(&w.tuning).measured = Some((Template::of(&choice), n));
            w.set_password(password.into()).unwrap();
            w.set_repeat(password.into()).unwrap();
            let path = dir.join(format!("{item}.larsalvault"));
            let out = w
                .create(
                    "T18".into(),
                    String::new(),
                    path.to_string_lossy().into(),
                    choice,
                    recommended,
                    vec![],
                )
                .unwrap();
            assert!(matches!(out, Outcome::Created { .. }), "{out:?}");
            let bytes = std::fs::read(&path).unwrap();
            let typed = SecretString::new(password.to_owned());
            let creds = Credentials {
                password: Some(&typed),
                key_file: None,
                hardware_key: None,
            };
            let mut host = lock(&w.session.host).clone();
            let Ok(larsal_format::Opened::Vault(opened)) =
                larsal_format::open(&bytes, &creds, &mut host, &Limits::DEFAULT, None)
            else {
                panic!("the new vault opens")
            };
            let v = opened.vault;
            assert_eq!(v.meta.custom_data.get(key), Some(item));
            let Kdf::Argon2 {
                kind,
                iterations: got,
                ..
            } = v.encryption.kdf
            else {
                panic!("Argon2")
            };
            let kind_wanted = if recommended {
                Argon2Kind::Id
            } else {
                Argon2Kind::D
            };
            assert_eq!((kind, got), (kind_wanted, iterations));
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
