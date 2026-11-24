//! One plain message per error of an open (spec APP-06, the message table
//! M06-01 to M06-26; story E3-S9).
//!
//! Guarantees (APP-06.18, SF-18):
//! - every value of `larsal_format::Error` maps to exactly one message, by an
//!   exhaustive match: a new kind or reason fails to build until it has one;
//! - no message holds a secret or text taken from the vault file or the key
//!   file, except the key file version text of M06-08, which `larsal-format`
//!   keeps only when it is at most 16 digits and dots (LD-87);
//! - a file is named only by its file name, cleaned by [`clean_name`];
//! - an `io::ErrorKind` picks the message; no operating system text is shown;
//! - user-facing text says "security key" (LD-101).

use larsal_format::Error;
use larsal_format::error::{HardwareKeyReason, KeyFileReason};
use larsal_format::limits::Limit;
use std::io::ErrorKind;

/// What the unlock form offers next to the message (APP-06 table, "Where").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// M06-02: an "Import…" button.
    Import,
    /// M06-05: the link "Unlock with a blank password" (APP-06.12).
    BlankPassword,
}

/// A message for the unlock form's error line (UL-ERR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The table's ID, for example `M06-06`.
    pub id: &'static str,
    /// The text, in our words.
    pub text: String,
    /// M06-23's smaller second line, "Limit reached: <limit>".
    pub detail: Option<String>,
    /// A button or link the form shows with the message.
    pub action: Option<Action>,
}

/// The longest file name shown in full (APP-06.18).
const MAX_NAME: usize = 64;
/// Characters kept at each end of a longer name.
const KEEP: usize = 30;

/// A file name as messages show it (APP-06.18): control characters, the
/// direction marks U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to
/// U+2069, and the zero-width characters U+200B to U+200D and U+FEFF
/// (LD-108) removed; a name longer than 64 characters keeps its first 30 and last
/// 30 characters with "…" between. Pass the file name only, never a path.
#[must_use]
pub fn clean_name(name: &str) -> String {
    let kept: Vec<char> = name
        .chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{061C}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                )
        })
        .collect();
    if kept.len() <= MAX_NAME {
        return kept.into_iter().collect();
    }
    let head = kept.iter().take(KEEP);
    let tail = kept.iter().skip(kept.len().saturating_sub(KEEP));
    head.chain(std::iter::once(&'…')).chain(tail).collect()
}

fn line(id: &'static str, text: String) -> Message {
    Message {
        id,
        text,
        detail: None,
        action: None,
    }
}

/// The message for `error` from an open of the vault file named `file`
/// with the key file named `key_file` (empty when there is none). Both are
/// file names from the file system; they are cleaned here.
#[must_use]
pub fn for_open_error(error: &Error, file: &str, key_file: &str) -> Message {
    let file = clean_name(file);
    let key = clean_name(key_file);
    match error {
        Error::NotAVault => line(
            "M06-01",
            format!("\"{file}\" is not a vault file. Open the file that holds your vault."),
        ),
        Error::OldFormat => Message {
            action: Some(Action::Import),
            ..line(
                "M06-02",
                format!(
                    "\"{file}\" is in the first vault format. Larsal can only import it: Import… makes a new vault from its contents."
                ),
            )
        },
        Error::Unsupported => line(
            "M06-03",
            "This vault uses a file version or setting that Larsal does not support yet. A Larsal update may open it.".into(),
        ),
        Error::Corrupt => line(
            "M06-04",
            format!("\"{file}\" is damaged and cannot be unlocked. If you have a backup copy, open that instead."),
        ),
        Error::NoCredentials => Message {
            action: Some(Action::BlankPassword),
            ..line("M06-05", "Enter the password for this vault.".into())
        },
        Error::WrongKey => line(
            "M06-06",
            "Wrong password, key file or security key. Check them and try again.".into(),
        ),
        Error::KeyFile(reason) => key_file_message(reason, &key),
        Error::HardwareKey(reason) => hardware_key_message(*reason),
        Error::TooLarge(limit) => too_large_message(*limit, &file),
        Error::Io(kind) => match kind {
            ErrorKind::NotFound => line(
                "M06-24",
                format!("\"{file}\" cannot be found. It may have been moved, renamed or deleted. Open it from its new place."),
            ),
            ErrorKind::PermissionDenied => line(
                "M06-25",
                format!("Larsal is not allowed to read \"{file}\". Check its permissions in Finder, then try again."),
            ),
            _ => line(
                "M06-26",
                format!("Larsal could not read \"{file}\". Check that its disk is connected, then try again."),
            ),
        },
    }
}

fn key_file_message(reason: &KeyFileReason, key: &str) -> Message {
    match reason {
        KeyFileReason::Empty => line(
            "M06-07",
            format!("The key file \"{key}\" is empty. Choose the right key file."),
        ),
        KeyFileReason::UnsupportedVersion(version) => {
            // LD-87: only a short text of digits and dots ever reaches here;
            // checked again so no other file text can be shown.
            let plain = !version.is_empty()
                && version.chars().count() <= 16
                && version.chars().all(|c| c.is_ascii_digit() || c == '.');
            let text = if plain {
                format!(
                    "The key file \"{key}\" has version {version}, which Larsal cannot read. Choose another key file."
                )
            } else {
                format!(
                    "The key file \"{key}\" has a version Larsal cannot read. Choose another key file."
                )
            };
            line("M06-08", text)
        }
        KeyFileReason::CheckValueMismatch => line(
            "M06-09",
            format!(
                "The key file \"{key}\" is damaged: its built-in check failed. Use a backup copy of the key file."
            ),
        ),
        KeyFileReason::DataUnreadable => line(
            "M06-10",
            format!(
                "The key file \"{key}\" is damaged: Larsal cannot read the key in it. Use a backup copy of the key file."
            ),
        ),
        KeyFileReason::Io(kind) => match kind {
            ErrorKind::NotFound => line(
                "M06-11",
                format!("The key file \"{key}\" cannot be found. Choose it again."),
            ),
            ErrorKind::PermissionDenied => line(
                "M06-12",
                format!(
                    "Larsal is not allowed to read the key file \"{key}\". Check its permissions in Finder, then try again."
                ),
            ),
            _ => line(
                "M06-13",
                format!(
                    "Larsal could not read the key file \"{key}\". Check that its disk is connected, then try again."
                ),
            ),
        },
        KeyFileReason::NotRegularFile => line(
            "M06-14",
            format!(
                "\"{key}\" is a folder or a special file. Choose a normal file as the key file."
            ),
        ),
        KeyFileReason::Dtd => line(
            "M06-15",
            format!(
                "Larsal does not accept the key file \"{key}\" because it declares a document type. Choose another key file."
            ),
        ),
        // Every key file limit shares one message (APP-06.18).
        KeyFileReason::TooLarge(_) => line(
            "M06-16",
            format!(
                "The key file \"{key}\" is too complex for Larsal to read safely. Choose another key file."
            ),
        ),
    }
}

fn hardware_key_message(reason: HardwareKeyReason) -> Message {
    match reason {
        HardwareKeyReason::Missing => line(
            "M06-17",
            "Your security key is not connected. Plug it in, then try again.".into(),
        ),
        HardwareKeyReason::TimedOut => line(
            "M06-18",
            "The security key was not touched in time. Try again, and touch the key when it flashes.".into(),
        ),
        HardwareKeyReason::SlotNotConfigured => line(
            "M06-19",
            "The chosen slot of your security key is not set up for challenge-response. Choose another slot.".into(),
        ),
        HardwareKeyReason::NotPermitted => line("MI07-01", "macOS did not let Larsal reach your security key. Allow Larsal under System Settings › Privacy & Security › Input Monitoring, then try again.".into()),
        // The user's next step is the same for both (APP-06.18).
        HardwareKeyReason::BadAnswer | HardwareKeyReason::Failed => line(
            "M06-20",
            "Larsal could not use your security key. Unplug it, plug it in again, then try again.".into(),
        ),
    }
}

fn too_large_message(limit: Limit, file: &str) -> Message {
    match limit {
        Limit::KdfCost => line(
            "M06-21",
            "This vault's unlock settings ask for more than this Mac can do. Lower them in the app that made the vault, then try again.".into(),
        ),
        Limit::TotalFile => line(
            "M06-22",
            format!(
                "\"{file}\" is larger than Larsal can open (about 1 GiB). Make it smaller in the app that made it, for example by removing large attachments."
            ),
        ),
        // Every other limit shares M06-23 and names itself for support.
        Limit::Header
        | Limit::Block
        | Limit::Total
        | Limit::Document
        | Limit::Depth
        | Limit::Elements
        | Limit::Text
        | Limit::Groups
        | Limit::Entries
        | Limit::EntryElements
        | Limit::History
        | Limit::Strings
        | Limit::Attachments
        | Limit::Associations
        | Limit::KeptUnknown
        | Limit::PoolItems
        | Limit::OneAttachment
        | Limit::AllAttachments
        | Limit::Icons
        | Limit::CustomDataItems
        | Limit::CustomDataItemsAll
        | Limit::DeletedObjects
        | Limit::Model
        | Limit::KeyFileAttributes
        | Limit::KeyFileText
        | Limit::KeyFileDepth => Message {
            detail: Some(format!("Limit reached: {}", limit.name())),
            ..line(
                "M06-23",
                format!("\"{file}\" holds more than Larsal can open safely. Make it smaller in the app that made it."),
            )
        },
    }
}

/// M06-30 (FMT-18.24): the chosen key file is the vault file itself.
#[must_use]
pub fn vault_as_key_file() -> Message {
    line(
        "M06-30",
        "This is the vault file itself, so it cannot also be its key file. Leave the key file empty if the vault has none.".into(),
    )
}

/// M06-34 (APP-06.14): the alert's message and its details for a KDF cost
/// in the ask band. Holds numbers only, no secret and no file text.
#[must_use]
pub fn cost_question(report: &larsal_crypto::kdf::CostReport) -> (String, String) {
    let time = duration(report.estimated_ms());
    let mut details = if report.memory_bytes() == 0 {
        format!("Unlocking it needs about {time} on this Mac. Unlock anyway?")
    } else {
        format!(
            "Unlocking it needs about {} of memory and about {time} on this Mac. Unlock anyway?",
            memory(report.memory_bytes())
        )
    };
    if report.over_lanes() {
        details.push_str(&format!(
            " It also asks for {} parallel lanes, more than Larsal expects.",
            report.lanes()
        ));
    }
    ("This vault is slow to unlock.".into(), details)
}

/// APP-06.14: MiB below 1 GiB, else GiB with one decimal.
pub(crate) fn memory(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes < GIB {
        format!("{} MiB", bytes / MIB)
    } else {
        // Tenths of a GiB, rounded; integer maths keeps the lint rules.
        let tenths = bytes.saturating_mul(10).saturating_add(GIB / 2) / GIB;
        format!("{}.{} GiB", tenths / 10, tenths % 10)
    }
}

/// APP-06.14: one decimal under 10 seconds, whole seconds up to 120, then
/// whole minutes.
pub(crate) fn duration(ms: u64) -> String {
    let tenths = ms.saturating_add(50) / 100;
    if tenths < 100 {
        format!("{}.{} seconds", tenths / 10, tenths % 10)
    } else if ms <= 120_000 {
        format!("{} seconds", ms.saturating_add(500) / 1000)
    } else {
        format!("{} minutes", ms.saturating_add(30_000) / 60_000)
    }
}

/// APP-05.26 at unlock: the rollback guard only warns.
/// `MSG-DISK-ROLLBACK-UNLOCK` for an older file, `MSG-DISK-WEAKER` with the
/// settings' names (never a value) for a weaker one; both when both hold.
#[must_use]
pub(crate) fn unlock_guard(file: &str, older: bool, weaker: &[&str]) -> Option<String> {
    let file = clean_name(file);
    let mut lines = Vec::new();
    if older {
        lines.push(format!(
            "\"{file}\" is older than a version Larsal has seen on this Mac, so newer changes may be missing. If you have a newer copy, open that one."
        ));
    }
    if !weaker.is_empty() {
        lines.push(format!(
            "\"{file}\" is saved with weaker settings than Larsal has seen for this vault: {}. Check them in Vault Settings.",
            weaker.join(", ")
        ));
    }
    (!lines.is_empty()).then(|| lines.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app06_14_numbers_in_the_cost_question() {
        assert_eq!(memory(2 << 30), "2.0 GiB");
        assert_eq!(memory(512 << 20), "512 MiB");
        assert_eq!(duration(2_340), "2.3 seconds");
        assert_eq!(duration(40_000), "40 seconds");
        assert_eq!(duration(300_000), "5 minutes");
    }
}
