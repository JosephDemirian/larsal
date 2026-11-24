//! E3-S9: the APP-06 message table (M06-01 to M06-26) and the rules of
//! APP-06.18. Each test names its card row.

use larsal_ffi::messages::{Action, Message, clean_name, for_open_error};
use larsal_format::Error;
use larsal_format::error::{HardwareKeyReason, KeyFileReason};
use larsal_format::limits::{Limit, Limits};
use std::io::ErrorKind;

/// Every limit. The match below has no wildcard, so a new `Limit` fails to
/// build here until it is listed (and has a message).
fn all_limits() -> Vec<Limit> {
    let all = vec![
        Limit::TotalFile,
        Limit::Header,
        Limit::Block,
        Limit::KdfCost,
        Limit::Total,
        Limit::Document,
        Limit::Depth,
        Limit::Elements,
        Limit::Text,
        Limit::Groups,
        Limit::Entries,
        Limit::EntryElements,
        Limit::History,
        Limit::Strings,
        Limit::Attachments,
        Limit::Associations,
        Limit::KeptUnknown,
        Limit::PoolItems,
        Limit::OneAttachment,
        Limit::AllAttachments,
        Limit::Icons,
        Limit::CustomDataItems,
        Limit::CustomDataItemsAll,
        Limit::DeletedObjects,
        Limit::Model,
        Limit::KeyFileAttributes,
        Limit::KeyFileText,
        Limit::KeyFileDepth,
    ];
    for l in &all {
        match l {
            Limit::TotalFile
            | Limit::Header
            | Limit::Block
            | Limit::KdfCost
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
            | Limit::KeyFileDepth => {}
        }
    }
    all
}

const IO_KINDS: [ErrorKind; 4] = [
    ErrorKind::NotFound,
    ErrorKind::PermissionDenied,
    ErrorKind::Other,
    ErrorKind::TimedOut,
];

/// Every error value with the message ID the table gives it (T39). The
/// matches have no wildcard, so a new kind or reason fails to build here.
fn table() -> Vec<(Error, &'static str)> {
    let mut out = Vec::new();
    let kinds = [
        Error::NotAVault,
        Error::OldFormat,
        Error::Unsupported,
        Error::Corrupt,
        Error::NoCredentials,
        Error::KeyFile(KeyFileReason::Empty),
        Error::HardwareKey(HardwareKeyReason::Missing),
        Error::TooLarge(Limit::Total),
        Error::WrongKey,
        Error::Io(ErrorKind::NotFound),
    ];
    for e in kinds {
        match e {
            Error::NotAVault => out.push((e, "M06-01")),
            Error::OldFormat => out.push((e, "M06-02")),
            Error::Unsupported => out.push((e, "M06-03")),
            Error::Corrupt => out.push((e, "M06-04")),
            Error::NoCredentials => out.push((e, "M06-05")),
            Error::WrongKey => out.push((e, "M06-06")),
            Error::KeyFile(_) => {
                let reasons = [
                    KeyFileReason::Empty,
                    KeyFileReason::UnsupportedVersion("2.0.1".into()),
                    KeyFileReason::UnsupportedVersion(String::new()),
                    KeyFileReason::CheckValueMismatch,
                    KeyFileReason::DataUnreadable,
                    KeyFileReason::NotRegularFile,
                    KeyFileReason::Dtd,
                    KeyFileReason::Io(ErrorKind::NotFound),
                    KeyFileReason::TooLarge(Limit::KeyFileText),
                ];
                for r in reasons {
                    match &r {
                        KeyFileReason::Empty => out.push((Error::KeyFile(r), "M06-07")),
                        KeyFileReason::UnsupportedVersion(_) => {
                            out.push((Error::KeyFile(r), "M06-08"))
                        }
                        KeyFileReason::CheckValueMismatch => {
                            out.push((Error::KeyFile(r), "M06-09"))
                        }
                        KeyFileReason::DataUnreadable => out.push((Error::KeyFile(r), "M06-10")),
                        KeyFileReason::Io(_) => {
                            for k in IO_KINDS {
                                let id = match k {
                                    ErrorKind::NotFound => "M06-11",
                                    ErrorKind::PermissionDenied => "M06-12",
                                    _ => "M06-13",
                                };
                                out.push((Error::KeyFile(KeyFileReason::Io(k)), id));
                            }
                        }
                        KeyFileReason::NotRegularFile => out.push((Error::KeyFile(r), "M06-14")),
                        KeyFileReason::Dtd => out.push((Error::KeyFile(r), "M06-15")),
                        KeyFileReason::TooLarge(_) => {
                            for l in all_limits() {
                                out.push((Error::KeyFile(KeyFileReason::TooLarge(l)), "M06-16"));
                            }
                        }
                    }
                }
            }
            Error::HardwareKey(_) => {
                for r in [
                    HardwareKeyReason::Missing,
                    HardwareKeyReason::TimedOut,
                    HardwareKeyReason::SlotNotConfigured,
                    HardwareKeyReason::BadAnswer,
                    HardwareKeyReason::Failed,
                    HardwareKeyReason::NotPermitted,
                ] {
                    let id = match r {
                        HardwareKeyReason::Missing => "M06-17",
                        HardwareKeyReason::TimedOut => "M06-18",
                        HardwareKeyReason::SlotNotConfigured => "M06-19",
                        HardwareKeyReason::BadAnswer | HardwareKeyReason::Failed => "M06-20",
                        HardwareKeyReason::NotPermitted => "MI07-01",
                    };
                    out.push((Error::HardwareKey(r), id));
                }
            }
            Error::TooLarge(_) => {
                for l in all_limits() {
                    let id = match l {
                        Limit::KdfCost => "M06-21",
                        Limit::TotalFile => "M06-22",
                        _ => "M06-23",
                    };
                    out.push((Error::TooLarge(l), id));
                }
            }
            Error::Io(_) => {
                for k in IO_KINDS {
                    let id = match k {
                        ErrorKind::NotFound => "M06-24",
                        ErrorKind::PermissionDenied => "M06-25",
                        _ => "M06-26",
                    };
                    out.push((Error::Io(k), id));
                }
            }
        }
    }
    out
}

fn msg(e: &Error) -> Message {
    for_open_error(e, "demo.larsalvault", "demo.larsalkey")
}

#[test]
fn t39_app_06_18_every_kind() {
    let rows = table();
    assert_eq!(all_limits().len(), 28);
    for (e, id) in &rows {
        let m = msg(e);
        assert_eq!(m.id, *id, "{e:?}");
        assert!(
            !m.text.is_empty() && m.text.ends_with('.') || m.text.ends_with('?'),
            "{e:?}: one sentence ending the next step"
        );
        match m.id {
            "M06-23" => {
                let Error::TooLarge(l) = e else { panic!() };
                assert_eq!(
                    m.detail.as_deref(),
                    Some(format!("Limit reached: {}", l.name()).as_str())
                );
            }
            _ => assert_eq!(m.detail, None, "{e:?}"),
        }
    }
    // Every table ID from M06-01 to M06-26 is reached, and INT-07's MI07-01.
    let ids: std::collections::BTreeSet<&str> = rows.iter().map(|(_, id)| *id).collect();
    assert_eq!(ids.len(), 27);
}

#[test]
fn m06_texts_match_the_table() {
    let k = "demo.larsalkey";
    let f = "demo.larsalvault";
    let cases: [(Error, String); 27] = [
        (Error::NotAVault, format!("\"{f}\" is not a vault file. Open the file that holds your vault.")),
        (Error::OldFormat, format!("\"{f}\" is in the first vault format. Larsal can only import it: Import… makes a new vault from its contents.")),
        (Error::Unsupported, "This vault uses a file version or setting that Larsal does not support yet. A Larsal update may open it.".into()),
        (Error::Corrupt, format!("\"{f}\" is damaged and cannot be unlocked. If you have a backup copy, open that instead.")),
        (Error::NoCredentials, "Enter the password for this vault.".into()),
        (Error::WrongKey, "Wrong password, key file or security key. Check them and try again.".into()),
        (Error::KeyFile(KeyFileReason::Empty), format!("The key file \"{k}\" is empty. Choose the right key file.")),
        (Error::KeyFile(KeyFileReason::UnsupportedVersion("2.0.1".into())), format!("The key file \"{k}\" has version 2.0.1, which Larsal cannot read. Choose another key file.")),
        (Error::KeyFile(KeyFileReason::CheckValueMismatch), format!("The key file \"{k}\" is damaged: its built-in check failed. Use a backup copy of the key file.")),
        (Error::KeyFile(KeyFileReason::DataUnreadable), format!("The key file \"{k}\" is damaged: Larsal cannot read the key in it. Use a backup copy of the key file.")),
        (Error::KeyFile(KeyFileReason::Io(ErrorKind::NotFound)), format!("The key file \"{k}\" cannot be found. Choose it again.")),
        (Error::KeyFile(KeyFileReason::Io(ErrorKind::PermissionDenied)), format!("Larsal is not allowed to read the key file \"{k}\". Check its permissions in Finder, then try again.")),
        (Error::KeyFile(KeyFileReason::Io(ErrorKind::Other)), format!("Larsal could not read the key file \"{k}\". Check that its disk is connected, then try again.")),
        (Error::KeyFile(KeyFileReason::NotRegularFile), format!("\"{k}\" is a folder or a special file. Choose a normal file as the key file.")),
        (Error::KeyFile(KeyFileReason::Dtd), format!("Larsal does not accept the key file \"{k}\" because it declares a document type. Choose another key file.")),
        (Error::KeyFile(KeyFileReason::TooLarge(Limit::KeyFileDepth)), format!("The key file \"{k}\" is too complex for Larsal to read safely. Choose another key file.")),
        (Error::HardwareKey(HardwareKeyReason::Missing), "Your security key is not connected. Plug it in, then try again.".into()),
        (Error::HardwareKey(HardwareKeyReason::TimedOut), "The security key was not touched in time. Try again, and touch the key when it flashes.".into()),
        (Error::HardwareKey(HardwareKeyReason::SlotNotConfigured), "The chosen slot of your security key is not set up for challenge-response. Choose another slot.".into()),
        (Error::HardwareKey(HardwareKeyReason::Failed), "Larsal could not use your security key. Unplug it, plug it in again, then try again.".into()),
        (Error::HardwareKey(HardwareKeyReason::NotPermitted), "macOS did not let Larsal reach your security key. Allow Larsal under System Settings › Privacy & Security › Input Monitoring, then try again.".into()),
        (Error::TooLarge(Limit::KdfCost), "This vault's unlock settings ask for more than this Mac can do. Lower them in the app that made the vault, then try again.".into()),
        (Error::TooLarge(Limit::TotalFile), format!("\"{f}\" is larger than Larsal can open (about 1 GiB). Make it smaller in the app that made it, for example by removing large attachments.")),
        (Error::TooLarge(Limit::Model), format!("\"{f}\" holds more than Larsal can open safely. Make it smaller in the app that made it.")),
        (Error::Io(ErrorKind::NotFound), format!("\"{f}\" cannot be found. It may have been moved, renamed or deleted. Open it from its new place.")),
        (Error::Io(ErrorKind::PermissionDenied), format!("Larsal is not allowed to read \"{f}\". Check its permissions in Finder, then try again.")),
        (Error::Io(ErrorKind::Other), format!("Larsal could not read \"{f}\". Check that its disk is connected, then try again.")),
    ];
    for (e, text) in cases {
        assert_eq!(msg(&e).text, text, "{e:?}");
    }
    assert_eq!(
        msg(&Error::KeyFile(KeyFileReason::UnsupportedVersion(
            String::new()
        )))
        .text,
        format!("The key file \"{k}\" has a version Larsal cannot read. Choose another key file.")
    );
    assert_eq!(msg(&Error::OldFormat).action, Some(Action::Import));
    assert_eq!(
        msg(&Error::NoCredentials).action,
        Some(Action::BlankPassword)
    );
    assert_eq!(msg(&Error::WrongKey).action, None);
    assert_eq!(
        msg(&Error::TooLarge(Limit::Model)).detail.as_deref(),
        Some("Limit reached: model")
    );
}

#[test]
fn t40_app_06_18_no_secret() {
    let password = "demo-pass-1";
    let key_bytes = "4D8D274F";
    let mut rows = table();
    rows.push((
        Error::KeyFile(KeyFileReason::UnsupportedVersion("2.0.1".into())),
        "M06-08",
    ));
    for (e, _) in rows {
        let m = msg(&e);
        let all = format!("{} {:?} {:?}", m.text, m.detail, m);
        assert!(!all.contains(password) && !all.contains(key_bytes), "{e:?}");
        assert!(!all.contains("os error"), "never a raw system text");
    }
    // Even a reason that carried file text could not show it (LD-87 checked
    // again here): only digits and dots of at most 16 characters pass.
    for crafted in [
        "2.0<b>x</b>",
        "1.0\u{202E}evil",
        "1.0\n2.0",
        "12345678901234567",
        "demo-pass-1",
    ] {
        let m = msg(&Error::KeyFile(KeyFileReason::UnsupportedVersion(
            crafted.into(),
        )));
        assert!(!m.text.contains(crafted), "{crafted:?}");
        assert!(m.text.contains("has a version Larsal cannot read"));
    }
}

#[test]
fn t40_app_06_18_crafted_files_show_no_file_text() {
    // Key files whose texts Larsal reads: none of their content reaches a message.
    let secret_text = "demo-secret-text";
    let crafted = [
        format!("<KeyFile><Meta><Version>9.{secret_text}</Version></Meta></KeyFile>"),
        format!(
            "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"00000000\">{secret_text}</Data></Key></KeyFile>"
        ),
        format!("<!DOCTYPE KeyFile><KeyFile>{secret_text}</KeyFile>"),
    ];
    for doc in crafted {
        let Err(e) = larsal_format::keyfile::read_key_file(
            std::io::Cursor::new(doc.into_bytes()),
            &Limits::DEFAULT,
        ) else {
            continue;
        };
        let m = for_open_error(&e, "v.larsalvault", "k.larsalkey");
        assert!(
            !m.text.contains(secret_text) && !m.text.contains("9."),
            "{e:?}: {}",
            m.text
        );
    }
    // A vault file whose header holds text: the error kind carries none.
    let mut file = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 4, 0];
    file.extend_from_slice(b"\x01\x10\x00\x00\x00demo-secret-text");
    let e = larsal_format::header::read_header(&file, &Limits::DEFAULT).unwrap_err();
    let m = for_open_error(&e, "v.larsalvault", "");
    assert!(!m.text.contains(secret_text), "{}", m.text);
}

#[test]
fn t41_app_06_18_names() {
    let base: String = "a".repeat(30);
    let name = format!("{base}\u{202E}\n{}{}", "b".repeat(20), "c".repeat(30));
    assert_eq!(name.chars().count(), 82);
    let cleaned = clean_name(&name);
    assert!(!cleaned.contains('\u{202E}') && !cleaned.contains('\n'));
    assert_eq!(cleaned, format!("{base}…{}", "c".repeat(30)));
    let m = for_open_error(&Error::Corrupt, &name, "");
    assert!(m.text.starts_with(&format!("\"{base}…")));
    for mark in [
        '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{2066}',
        '\u{2067}', '\u{2068}', '\u{2069}', '\u{7}', // LD-108:
        '\u{061C}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}',
    ] {
        assert_eq!(
            clean_name(&format!("x{mark}y.larsalvault")),
            "xy.larsalvault",
            "{:?}",
            mark
        );
    }
    assert_eq!(
        clean_name(&"n".repeat(64)),
        "n".repeat(64),
        "64 characters stay whole"
    );
    let long = format!("{}m{}", "a".repeat(32), "z".repeat(32));
    assert_eq!(
        clean_name(&long),
        format!("{}…{}", "a".repeat(30), "z".repeat(30)),
        "65 characters are shortened"
    );
    // The key file name is cleaned too.
    let m = for_open_error(
        &Error::KeyFile(KeyFileReason::Empty),
        "v.larsalvault",
        "k\u{202E}\u{200B}ey.larsalkey",
    );
    assert!(m.text.contains("\"key.larsalkey\""), "{}", m.text);
}

#[test]
fn app_06_18_io_kind_picks_the_message() {
    for k in [
        ErrorKind::Other,
        ErrorKind::TimedOut,
        ErrorKind::Interrupted,
        ErrorKind::UnexpectedEof,
    ] {
        assert_eq!(msg(&Error::Io(k)).id, "M06-26");
        assert_eq!(msg(&Error::KeyFile(KeyFileReason::Io(k))).id, "M06-13");
    }
}

#[test]
fn ld_101_security_key_wording() {
    for (e, _) in table() {
        let m = msg(&e);
        assert!(!m.text.to_lowercase().contains("hardware key"), "{e:?}");
    }
    assert!(msg(&Error::WrongKey).text.contains("security key"));
}
