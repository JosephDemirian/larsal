//! The master keys of one session, and the way from a password to them (FIL-04.3,
//! FIL-04.13). The password, its normalized copy and the key-encryption key live only
//! inside these functions, in wiping types.

use crate::error::Error;
use crate::format::KeyFile;
use crate::limits::MAX_PASSWORD;
use larsal_crypto::keywrap;
use larsal_crypto::mac;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{kdf, text};
use larsal_platform::memory::{Locked, lock};
use std::sync::Mutex;

/// One key derivation at a time in this process (FIL-06.1).
static KDF: Mutex<()> = Mutex::new(());

/// The two master keys and the two arrangements of them the format uses.
///
/// Guarantees: every key is in wiping memory on pages kept in RAM where the system
/// allows it; the keys are declared before the pages, so each key is wiped before its
/// page is let go; no `Clone`, and `Debug` says nothing.
pub(crate) struct MasterKeys {
    pub(crate) enc: SecretBytes,
    pub(crate) mac: SecretBytes,
    /// The AES-SIV key: the MAC key, then the encryption key.
    pub(crate) siv: SecretBytes,
    /// The raw key that signs a configuration: the encryption key, then the MAC key.
    pub(crate) raw: SecretBytes,
    _pages: [Option<Locked>; 4],
}

impl std::fmt::Debug for MasterKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKeys([hidden])")
    }
}

fn joined(a: &SecretBytes, b: &SecretBytes) -> Result<SecretBytes, Error> {
    let len = a.len().checked_add(b.len()).ok_or(Error::Open)?;
    let mut out = SecretBytes::zeroed(len);
    let (x, y) = out
        .expose_mut()
        .split_at_mut_checked(a.len())
        .ok_or(Error::Open)?;
    x.copy_from_slice(a.expose());
    y.copy_from_slice(b.expose());
    Ok(out)
}

impl MasterKeys {
    pub(crate) fn new(enc: SecretBytes, mac: SecretBytes) -> Result<Self, Error> {
        let siv = joined(&mac, &enc)?;
        let raw = joined(&enc, &mac)?;
        let pages = [
            lock(enc.expose()),
            lock(mac.expose()),
            lock(siv.expose()),
            lock(raw.expose()),
        ];
        Ok(Self {
            enc,
            mac,
            siv,
            raw,
            _pages: pages,
        })
    }

    /// A key for one local purpose, under the MAC key. Never written anywhere.
    pub(crate) fn derived(&self, label: &[u8]) -> Result<SecretBytes, Error> {
        mac::hmac_sha256(self.mac.expose(), &[label]).map_err(|_| Error::Io)
    }

    /// Says which keys a local store belongs to, and nothing of any folder.
    pub(crate) fn store_id(&self) -> Result<String, Error> {
        let id = self.derived(b"larsal-folders store id v1")?;
        Ok(crate::names::hex(id.expose()))
    }
}

/// NFC, then UTF-8, bounded before and after; no trim, no folding, nothing added
/// (FIL-04.4). No other form is ever tried.
///
/// # Errors
/// [`Error::Open`] for a password over the bound, with no work done.
pub(crate) fn normalized_password(password: &SecretString) -> Result<SecretString, Error> {
    if password.len() > MAX_PASSWORD {
        return Err(Error::Open);
    }
    text::nfc_bounded(password.expose(), MAX_PASSWORD).map_err(|_| Error::Open)
}

/// The key-encryption key, one at a time.
pub(crate) fn derive_kek(
    password: &SecretString,
    salt: &[u8],
    log_n: u8,
    r: u32,
) -> Result<SecretBytes, Error> {
    let _one = KDF
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(test)]
    crate::seam::count_kdf();
    kdf::scrypt(
        password.expose().as_bytes(),
        salt,
        log_n,
        r,
        1,
        keywrap::KEK,
    )
    .map_err(|_| Error::Open)
}

/// Both keys out of a key file, or [`Error::Open`] with no key data.
pub(crate) fn unwrap_keys(
    kek: &SecretBytes,
    file: &KeyFile,
) -> Result<(SecretBytes, SecretBytes), Error> {
    let enc = keywrap::unwrap(kek, &file.wrapped_enc).map_err(|_| Error::Open)?;
    let mac = keywrap::unwrap(kek, &file.wrapped_mac).map_err(|_| Error::Open)?;
    Ok((enc, mac))
}
