//! Public recipient keys and private identities (FIL-01.8, FIL-01.9,
//! FIL-01.15, FIL-01.16, FIL-01.20). A private key lives only in a wiping type.
//! Only what the caller hands in is read: no home folder, agent, Keychain,
//! plugin or key store is ever looked at.

use crate::decrypt::{Unlock, open_bounded};
use crate::error::Error;
use crate::limits::{MAX_IDENTITIES, MAX_IDENTITY_FILE, MAX_IDENTITY_LIST};
use larsal_crypto::bech32;
use larsal_crypto::bridge::Secret;
use larsal_crypto::secret::{SecretBytes, SecretString};
use std::io::{ErrorKind, Read};

const RECIPIENT_HRP: &str = "age";
const IDENTITY_HRP: &str = "AGE-SECRET-KEY-";
const KEY: usize = 32;

/// A native X25519 public key: exactly what its text says, public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Recipient(pub(crate) [u8; KEY]);

impl Recipient {
    /// Reads recipient text: original Bech32, all lower or all upper case, with
    /// the right prefix and 32 bytes. Nothing else is accepted, and no other
    /// algorithm is tried: a post-quantum or tagged key is refused here
    /// (FIL-01.20).
    ///
    /// # Errors
    /// [`Error::Recipient`] for anything else.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let bytes = bech32::decode(RECIPIENT_HRP, text, KEY).map_err(|_| Error::Recipient)?;
        let key = bytes.expose().try_into().map_err(|_| Error::Recipient)?;
        Ok(Self(key))
    }

    /// The canonical lower case text of this key.
    ///
    /// # Errors
    /// [`Error::Recipient`] never in practice: the length is fixed.
    pub fn to_text(&self) -> Result<String, Error> {
        bech32::encode_lower(RECIPIENT_HRP, &self.0).map_err(|_| Error::Recipient)
    }
}

/// One private identity.
pub(crate) struct Identity {
    pub(crate) secret: Secret,
    pub(crate) public: [u8; KEY],
}

/// The private identities one operation may use, from protected vault fields
/// or an explicitly chosen key file (FIL-01.15).
///
/// Guarantees: at most 64; each key's bytes live only in wiping memory; `Debug`
/// says only how many there are.
pub struct Identities {
    pub(crate) keys: Vec<Identity>,
    weak_file: bool,
}

impl std::fmt::Debug for Identities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identities({})", self.keys.len())
    }
}

fn read_identity(text: &str) -> Result<Identity, Error> {
    let bytes = bech32::decode(IDENTITY_HRP, text, KEY).map_err(|_| Error::Decrypt)?;
    let secret = Secret::from_bytes(bytes).map_err(|_| Error::Decrypt)?;
    let public = secret.public();
    Ok(Identity { secret, public })
}

impl Identities {
    /// One identity, from a protected vault field.
    ///
    /// # Errors
    /// [`Error::Decrypt`] for anything but a valid native identity.
    pub fn single(text: &SecretString) -> Result<Self, Error> {
        Ok(Self {
            keys: vec![read_identity(text.expose())?],
            weak_file: false,
        })
    }

    /// A plain identity list: UTF-8 lines, blank lines and `#` comments are
    /// skipped, every other line must be a valid native identity. It is only
    /// ever read as this list, never as a command, a path or a config format.
    ///
    /// # Errors
    /// [`Error::Decrypt`] for over 65,536 bytes, over 64 identities, none at
    /// all, or a line that is not a valid identity.
    pub fn from_list(list: &[u8]) -> Result<Self, Error> {
        if list.len() > MAX_IDENTITY_LIST {
            return Err(Error::Decrypt);
        }
        let text = std::str::from_utf8(list).map_err(|_| Error::Decrypt)?;
        let mut keys = Vec::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if keys.len() >= MAX_IDENTITIES {
                return Err(Error::Decrypt);
            }
            keys.push(read_identity(line)?);
        }
        if keys.is_empty() {
            return Err(Error::Decrypt);
        }
        Ok(Self {
            keys,
            weak_file: false,
        })
    }

    /// An explicitly chosen key file, read through a bounded stream into wiping
    /// memory. A plain list is read as [`Self::from_list`]. A file encrypted to
    /// a passphrase is fully validated first and its content, at most 64 KiB in
    /// wiping memory, is then read as a plain list: never decrypted again, so a
    /// nested encrypted file is refused (FIL-01.16).
    ///
    /// # Errors
    /// [`Error::Decrypt`] for every fault of the file, and for an encrypted file
    /// with no passphrase given; [`Error::Passphrase`] for one empty or over the
    /// limit; [`Error::Io`] or [`Error::Space`] for an actual read fault.
    pub fn read_key_file(
        input: &mut dyn Read,
        passphrase: Option<&SecretString>,
    ) -> Result<Self, Error> {
        let limit = MAX_IDENTITY_FILE.saturating_add(1);
        let mut buf = SecretBytes::zeroed(limit);
        let mut got = 0usize;
        while let Some(rest) = buf.expose_mut().get_mut(got..).filter(|r| !r.is_empty()) {
            match input.read(rest) {
                Ok(0) => break,
                Ok(n) => got = got.saturating_add(n),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(crate::error::io_error(&e)),
            }
        }
        if got >= limit {
            return Err(Error::Decrypt);
        }
        let data = buf.expose().get(..got).ok_or(Error::Decrypt)?;
        if !looks_encrypted(data) {
            return Self::from_list(data);
        }
        let passphrase = passphrase.ok_or(Error::Decrypt)?;
        let (plain, weak_file) =
            open_bounded(data, &Unlock::Passphrase(passphrase), MAX_IDENTITY_LIST)?;
        let mut list = Self::from_list(plain.expose())?;
        list.weak_file = weak_file;
        Ok(list)
    }

    /// True when these keys came from an encrypted key file with a low work
    /// factor (FIL-03.2): a policy warning for the screen, not an error.
    #[must_use]
    pub const fn from_weak_file(&self) -> bool {
        self.weak_file
    }
}

/// Encrypted key files start with the format's version line or strict armor, and
/// only those go on to the readers, whose buffers do not wipe: they hold
/// ciphertext. Anything else stays in wiping memory, as a plain list, a private
/// key in another format included, and is refused there.
fn looks_encrypted(data: &[u8]) -> bool {
    data.starts_with(b"age-encryption.org/") || crate::armor::starts_as_armor(data)
}

/// Makes a new native identity from larsal-crypto's random source, for an
/// explicit Create File Key (FIL-01.17). Saving it is the caller's job, before
/// any use.
///
/// # Errors
/// [`Error::Io`] if the OS random source fails: no key is returned.
pub fn generate_identity() -> Result<(SecretString, Recipient), Error> {
    let bytes = larsal_crypto::random::bytes(KEY).map_err(|_| Error::Io)?;
    let text = bech32::encode_upper_secret(IDENTITY_HRP, &bytes).map_err(|_| Error::Io)?;
    let secret = Secret::from_bytes(bytes).map_err(|_| Error::Io)?;
    Ok((text, Recipient(secret.public())))
}
