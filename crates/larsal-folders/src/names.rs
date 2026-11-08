//! Names and directory paths (FIL-04.9, FIL-04.10, FIL-06.2). SHA-1 here is the format's
//! addressing step, no security construction of ours. Clear names are in wiping types.

use crate::error::Error;
use crate::keys::MasterKeys;
use crate::limits::MAX_NAME;
use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{hash, siv, text};

pub(crate) const PLAIN_EXT: &str = ".c9r";
pub(crate) const SHORT_EXT: &str = ".c9s";
pub(crate) const INFLATED: &str = "name.c9s";
pub(crate) const CONTENTS: &str = "contents.c9r";
pub(crate) const DIR_FILE: &str = "dir.c9r";
pub(crate) const LINK_FILE: &str = "symlink.c9r";
pub(crate) const BACKUP: &str = "dirid.c9r";

/// Lower case hex of public or local-only bytes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// RFC 4648 base32, upper case with no padding: the format's own step for 20 bytes.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(32);
    let (mut held, mut bits) = (0u32, 0u32);
    let mut push = |value: u32| {
        let at = usize::try_from(value & 31).unwrap_or(0);
        out.push(char::from(*ALPHABET.get(at).unwrap_or(&b'A')));
    };
    for b in bytes {
        held = (held << 8) | u32::from(*b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            push(held >> bits);
            held &= (1u32 << bits).saturating_sub(1);
        }
    }
    if bits > 0 {
        push(held << 5u32.saturating_sub(bits));
    }
    out
}

/// The two path parts of a directory: `d/<first>/<second>`.
pub(crate) fn dir_path(keys: &MasterKeys, id: &[u8]) -> Result<(String, String), Error> {
    // Absent associated data: not one empty component (FIL-04.9).
    let none: [&[u8]; 0] = [];
    let sealed = siv::seal(&keys.siv, &none, id).map_err(|_| Error::Io)?;
    let digest = hash::sha1(&[&sealed]);
    let text = base32(digest.expose());
    let (first, second) = text.split_at_checked(2).ok_or(Error::Io)?;
    Ok((first.to_owned(), second.to_owned()))
}

/// The stored form of `name` below the directory `parent`, with its extension.
pub(crate) fn seal_name(keys: &MasterKeys, parent: &[u8], name: &str) -> Result<String, Error> {
    let sealed = siv::seal(&keys.siv, &[parent], name.as_bytes()).map_err(|_| Error::Io)?;
    Ok(format!(
        "{}{PLAIN_EXT}",
        base64::encode(Form::UrlPadded, &sealed)
    ))
}

/// The clear name of `stored` (with its extension) below `parent`.
///
/// # Errors
/// [`Error::Open`] for a wrong extension, a non-canonical encoding, any failed proof
/// (another parent's name too) and text that is not UTF-8.
pub(crate) fn open_name(
    keys: &MasterKeys,
    parent: &[u8],
    stored: &str,
) -> Result<SecretString, Error> {
    let body = stored.strip_suffix(PLAIN_EXT).ok_or(Error::Open)?;
    let sealed = base64::decode(Form::UrlPadded, body).map_err(|_| Error::Open)?;
    let plain: SecretBytes = siv::open(&keys.siv, &[parent], &sealed).map_err(|_| Error::Open)?;
    let name = std::str::from_utf8(plain.expose()).map_err(|_| Error::Open)?;
    Ok(SecretString::new(name.to_owned()))
}

/// The shortened form of a stored name: its SHA-1 in padded base64url.
pub(crate) fn deflate(stored: &str) -> String {
    let digest = hash::sha1(&[stored.as_bytes()]);
    format!(
        "{}{SHORT_EXT}",
        base64::encode(Form::UrlPadded, digest.expose())
    )
}

/// Where a name is kept: its own stored name, or a shortened node holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    Plain(String),
    Short { deflated: String, inflated: String },
}

impl Stored {
    /// The stored form of a clear name under `threshold`.
    pub(crate) fn of(
        keys: &MasterKeys,
        parent: &[u8],
        name: &str,
        threshold: usize,
    ) -> Result<Self, Error> {
        let sealed = seal_name(keys, parent, name)?;
        Ok(if sealed.len() > threshold {
            Self::Short {
                deflated: deflate(&sealed),
                inflated: sealed,
            }
        } else {
            Self::Plain(sealed)
        })
    }

    /// The name in the parent's folder.
    pub(crate) fn entry(&self) -> &str {
        match self {
            Self::Plain(name) => name,
            Self::Short { deflated, .. } => deflated,
        }
    }

    /// The stored name the clear name opens from.
    pub(crate) fn sealed(&self) -> &str {
        match self {
            Self::Plain(name) => name,
            Self::Short { inflated, .. } => inflated,
        }
    }
}

/// Checks a shortened node's mapping (FIL-04.10): the stored name must be canonical
/// ASCII, past the threshold, and hash to the node's own name. No repair.
///
/// # Errors
/// [`Error::Open`] for any mismatch.
pub(crate) fn check_mapping(
    deflated: &str,
    inflated: &[u8],
    threshold: usize,
) -> Result<String, Error> {
    let text = std::str::from_utf8(inflated).map_err(|_| Error::Open)?;
    let long_enough = text.len() > threshold;
    if !long_enough || !text.ends_with(PLAIN_EXT) || deflate(text) != deflated {
        return Err(Error::Open);
    }
    Ok(text.to_owned())
}

const BIDI_FORMAT: [char; 12] = [
    '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

fn reserved_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        other => {
            let digit = other
                .strip_prefix("COM")
                .or_else(|| other.strip_prefix("LPT"));
            digit.is_some_and(|d| matches!(d, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
        }
    }
}

/// FIL-06.2 on a name that is in NFC already: true when it is one safe component.
pub(crate) fn is_safe_component(name: &str) -> bool {
    !(name.is_empty()
        || name.len() > MAX_NAME
        || name == "."
        || name == ".."
        || name.ends_with('.')
        || name.ends_with(' ')
        || reserved_device(name)
        || name
            .chars()
            .any(|c| matches!(c, '/' | '\\' | ':') || c.is_control() || BIDI_FORMAT.contains(&c)))
}

/// A foreign name as it stands: safe here, and already in NFC.
pub(crate) fn is_safe_stored(name: &str) -> bool {
    text::is_nfc(name) && is_safe_component(name)
}

/// A new name: bounded, normalized once, and then one safe component. Characters are
/// never stripped to make a different name.
///
/// # Errors
/// [`Error::Name`] for anything else.
pub(crate) fn check_new(name: &str) -> Result<SecretString, Error> {
    // NFC never makes a name shorter than a quarter of it.
    if name.len() > MAX_NAME.saturating_mul(4) {
        return Err(Error::Name);
    }
    let normal = text::nfc_bounded(name, MAX_NAME).map_err(|_| Error::Name)?;
    if is_safe_component(normal.expose()) {
        Ok(normal)
    } else {
        Err(Error::Name)
    }
}

/// How a file system may see two names as one: lower case of the NFC form. Goes
/// through wiping memory, like the names.
pub(crate) fn fold(name: &str) -> SecretString {
    let mut out = String::with_capacity(name.len().saturating_mul(3));
    let wanted: usize = name
        .chars()
        .flat_map(char::to_lowercase)
        .map(char::len_utf8)
        .sum();
    if wanted > out.capacity() {
        return SecretString::new(String::new());
    }
    out.extend(name.chars().flat_map(char::to_lowercase));
    SecretString::new(out)
}
