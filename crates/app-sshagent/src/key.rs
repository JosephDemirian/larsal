//! Reading an SSH private key and unlocking it (INT-06.5 to INT-06.9).

use crate::Error;
use app_crypto::secret::SecretString;
use app_crypto::ssh::{AgentKey, OpenSshKey};

/// Largest key App reads, in bytes (INT-06.5): 1 MiB.
pub const MAX_KEY_SIZE: usize = 1_048_576;

/// Most bcrypt-pbkdf rounds App runs for a protected key (D-INT06-3).
pub const MAX_ROUNDS: u32 = 1_000;

/// The key types App reads (INT-06.6) and their names on screen (INT-06.7).
/// `ssh-rsa` adds the bit length.
const TYPES: [(&str, &str); 7] = [
    ("ssh-ed25519", "ED25519"),
    ("ecdsa-sha2-nistp256", "ECDSA"),
    ("ecdsa-sha2-nistp384", "ECDSA P-384"),
    ("ecdsa-sha2-nistp521", "ECDSA P-521"),
    ("ssh-rsa", "RSA"),
    ("sk-ssh-ed25519@openssh.com", "ED25519-SK"),
    ("sk-ecdsa-sha2-nistp256@openssh.com", "ECDSA-SK"),
];

/// PEM labels of the older forms that get the convert message (MI06-11).
const OLD_LABELS: [&[u8]; 5] = [
    b"RSA PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"EC PRIVATE KEY",
    b"PRIVATE KEY",
    b"ENCRYPTED PRIVATE KEY",
];

/// An SSH private key App can use: OpenSSH format, a type of INT-06.6.
///
/// Guarantees: its public parts are readable without the passphrase; an
/// unprotected key's private part stays in self-wiping types; no `Clone`.
#[derive(Debug)]
pub struct SshKey(OpenSshKey);

impl SshKey {
    /// Reads a key file or key attachment, in this order: over
    /// [`MAX_KEY_SIZE`] is [`Error::TooLarge`] (nothing parsed); no bytes is
    /// [`Error::Empty`]; a PuTTY file or an older PEM or PKCS#8 label is
    /// [`Error::OldFormat`]; anything that is not one OpenSSH private key is
    /// [`Error::NotAKey`]; a DSA key is [`Error::Dsa`]; another type outside
    /// INT-06.6 is [`Error::Unsupported`] with its name. Never decrypts.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_KEY_SIZE {
            return Err(Error::TooLarge);
        }
        if bytes.is_empty() {
            return Err(Error::Empty);
        }
        if bytes.starts_with(b"PuTTY-User-Key-File-") {
            return Err(Error::OldFormat);
        }
        match pem_label(bytes) {
            Some(b"OPENSSH PRIVATE KEY") => {}
            Some(label) if OLD_LABELS.contains(&label) => return Err(Error::OldFormat),
            _ => return Err(Error::NotAKey),
        }
        let key = OpenSshKey::parse(bytes).ok_or(Error::NotAKey)?;
        match key.algorithm() {
            "ssh-dss" => Err(Error::Dsa),
            name if TYPES.iter().any(|(t, _)| *t == name) => Ok(Self(key)),
            name => Err(Error::Unsupported(shown(name)?)),
        }
    }

    /// The type name as stored, for example `ssh-ed25519`.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        self.0.algorithm()
    }

    /// The type as the screen shows it (INT-06.7): `ED25519`, `ECDSA`,
    /// `ECDSA P-384`, `ECDSA P-521`, `RSA 3072`, `ED25519-SK`, `ECDSA-SK`.
    #[must_use]
    pub fn type_label(&self) -> String {
        let label = TYPES
            .iter()
            .find(|(t, _)| *t == self.0.algorithm())
            .map_or("", |(_, l)| l);
        match self.0.rsa_bits() {
            Some(bits) => format!("{label} {bits}"),
            None => label.to_owned(),
        }
    }

    /// The public key blob, as agents list it and as remove sends it.
    #[must_use]
    pub fn public_blob(&self) -> &[u8] {
        self.0.public_blob()
    }

    /// `SHA256:` fingerprint, as `ssh-keygen -l` prints it (INT-06.7).
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        self.0.fingerprint()
    }

    /// The `.pub` line; with the comment only when the key is unprotected.
    #[must_use]
    pub fn public_line(&self) -> &str {
        self.0.public_line()
    }

    /// The stored comment; `None` until the key is decrypted (INT-06.8).
    #[must_use]
    pub fn comment(&self) -> Option<&str> {
        self.0.comment()
    }

    /// True when the key is protected by a passphrase.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.0.is_encrypted()
    }

    /// The private key, decrypted in memory when protected, ready for
    /// [`crate::Agent::add`] (INT-06.9). For a protected key, in this order
    /// and before any key derivation: an empty `passphrase` is
    /// [`Error::NoPassphrase`]; a cipher App cannot decrypt is
    /// [`Error::Unsupported`] with its name; rounds outside 1 to
    /// [`MAX_ROUNDS`] are [`Error::TooManyRounds`]. Then a wrong passphrase
    /// is [`Error::WrongPassphrase`]. An unprotected key ignores
    /// `passphrase`. The result wipes itself on drop.
    pub fn unlock(&self, passphrase: &SecretString) -> Result<AgentKey, Error> {
        let key = &self.0;
        if key.is_encrypted() {
            if passphrase.is_empty() {
                return Err(Error::NoPassphrase);
            }
            if !key.can_decrypt() {
                return Err(Error::Unsupported(key.cipher_name().to_owned()));
            }
            if let Some(rounds) = key.kdf_rounds()
                && !(1..=MAX_ROUNDS).contains(&rounds)
            {
                return Err(Error::TooManyRounds(rounds));
            }
        }
        key.agent_key(passphrase, MAX_ROUNDS).map_err(|e| match e {
            app_crypto::Error::Decrypt => Error::WrongPassphrase,
            _ => Error::NotAKey,
        })
    }
}

/// The label of the first `-----BEGIN ` line, if any.
fn pem_label(bytes: &[u8]) -> Option<&[u8]> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let start = bytes.windows(BEGIN.len()).position(|w| w == BEGIN)?;
    let rest = bytes.get(start.checked_add(BEGIN.len())?..)?;
    let end = rest.windows(5).position(|w| w == b"-----")?;
    rest.get(..end)
}

/// A type name from the file, shown only when it is short printable ASCII;
/// anything else is treated as a broken file (no file text of other shapes
/// reaches a message).
fn shown(name: &str) -> Result<String, Error> {
    if name.len() <= 64 && name.bytes().all(|b| b.is_ascii_graphic()) {
        Ok(name.to_owned())
    } else {
        Err(Error::NotAKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        /// Hostile key files: any bytes after an OpenSSH label give a typed
        /// error or a key, never a panic.
        #[test]
        fn hostile_key_files_never_panic(body in proptest::collection::vec(0u8..=255, 0..2000)) {
            let mut file = b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec();
            file.extend_from_slice(&body);
            if let Ok(key) = SshKey::read(&file) {
                let _ = key.unlock(&SecretString::new("demo".into()));
            }
        }
    }
}
