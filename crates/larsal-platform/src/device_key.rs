//! The device's P-256 sign-in key for Larsal's sync server (SYN-04.1; P5;
//! E16-S6), through `security-framework`'s safe API (architecture, "Rules
//! for this part" 7): this file has no `unsafe`.
//!
//! Guarantees:
//! - No call returns the private key's bytes. A [`DeviceKey`] only signs
//!   (ECDSA with SHA-256 over the message, an X9.62 DER signature, CRY-04.4)
//!   and gives its public key as 65 SEC1 bytes. It holds a reference to the
//!   key in its store, never the key's bytes, and its `Debug` shows nothing.
//! - [`Store::SecureEnclave`]: the key is made in the Secure Enclave
//!   (`kSecAttrTokenIDSecureEnclave`), usable only on this Mac and only
//!   while it is unlocked (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
//!   with `kSecAccessControlPrivateKeyUsage`), in the data protection
//!   keychain. An Intel Mac without a Secure Enclave gets a software P-256
//!   key in the data protection keychain with the same this-device-only
//!   access. Both stores need the keychain entitlement W-02 gives (TN3137);
//!   until then they fail.
//! - [`Store::LoginKeychain`]: until W-02, the app's software P-256 key in
//!   the user's default file-based keychain, the login keychain (TN3137).
//!   It is not this-device-only; that check stays open until W-02.
//! - LD-325 (5) (a): [`DeviceKey::make`] always makes a new key, so the
//!   public key registered at sign-up is the one made in that call; the
//!   caller names it with a label of 16 random bytes and keeps the label
//!   and the public key in local state. [`DeviceKey::open`] takes only a
//!   key whose public key equals the stored one, so a key another program
//!   planted under the label can only stop sign-in, never sign in as this
//!   Mac.
//! - `DeviceKey::test_seam` (tests only): a software key in memory that no
//!   keychain holds (`kSecAttrIsPermanent` false, no keychain named), so no
//!   test touches a real keychain (LD-317 (2)).
//!
//! The Secure Enclave and keychain paths are built and reviewed here; they
//! run first in Mac QA (W-08), and no cargo or Swift test calls them.

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::os::macos::keychain::SecKeychain;
use std::fmt;

/// `kSecAccessControlPrivateKeyUsage` (`SecAccessControl.h`): the key may
/// sign; Apple asks for it on every Secure Enclave key.
const PRIVATE_KEY_USAGE: usize = 1 << 30;

/// `errSecItemNotFound` (`SecBase.h`).
const NOT_FOUND: i32 = -25300;

/// The length of the public key: SEC1 uncompressed, `04 ‖ X ‖ Y`.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Where a device key lives (SYN-04.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store {
    /// The Secure Enclave, this device only; on an Intel Mac without one, a
    /// software key in the data protection keychain, this device only.
    /// Needs the keychain entitlement of W-02.
    SecureEnclave,
    /// The login keychain: the app's store until W-02 gives the entitlement.
    LoginKeychain,
}

/// Why a device key call failed, in plain words. Never holds key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// macOS refused: its error code (`SecBase.h`), for the debug log.
    Os(i64),
    /// The key's public part is not a P-256 point in the 65-byte form.
    NotP256,
    /// No key in the store has the label and the stored public key
    /// (LD-325 (5) (a)): this Mac's key is gone, or another was planted.
    Missing,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os(code) => write!(f, "macOS refused the device key (error {code})"),
            Self::NotP256 => f.write_str("the device key is not a P-256 key"),
            Self::Missing => f.write_str("this Mac's device key is not in its store"),
        }
    }
}

impl std::error::Error for KeyError {}

fn os(code: impl Into<i64>) -> KeyError {
    KeyError::Os(code.into())
}

/// This Mac's sign-in key for one server account.
pub struct DeviceKey(SecKey);

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKey")
    }
}

impl DeviceKey {
    /// A new key named `label` in `store` (sign-up, SYN-04.2): never a key
    /// found there, so the public key the caller registers is this one's
    /// (LD-325 (5) (a)). The caller draws the label (16 random bytes) and
    /// keeps it with the public key.
    ///
    /// # Errors
    /// [`KeyError::Os`] when macOS refuses to make the key (before W-02,
    /// every [`Store::SecureEnclave`] call).
    pub fn make(store: Store, label: &str) -> Result<Self, KeyError> {
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_label(label);
        match store {
            Store::LoginKeychain => {
                options.set_location(Location::DefaultFileKeychain);
                make(&options)
            }
            Store::SecureEnclave => {
                options
                    .set_location(Location::DataProtectionKeychain)
                    .set_access_control(this_device_only(PRIVATE_KEY_USAGE)?)
                    .set_token(Token::SecureEnclave);
                match make(&options) {
                    // ponytail: an Intel Mac falls back on any Secure Enclave
                    // failure; narrow it to the "no Secure Enclave" code once
                    // W-08 sees it on such a Mac. Every Apple silicon Mac has
                    // one, so there a failure is an error, never a weaker key.
                    Err(_) if cfg!(target_arch = "x86_64") => {
                        options
                            .set_access_control(this_device_only(0)?)
                            .set_token(Token::Software);
                        make(&options)
                    }
                    made => made,
                }
            }
        }
    }

    /// The key named `label` in `store` whose public key is `public`, the
    /// one [`DeviceKey::make`] gave at sign-up (LD-325 (5) (a)). A key
    /// under the label with another public key is never used. Makes no key.
    ///
    /// # Errors
    /// [`KeyError::Missing`] when no key there has that public key;
    /// [`KeyError::Os`] when macOS refuses the search.
    pub fn open(
        store: Store,
        label: &str,
        public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Self, KeyError> {
        Self::pick(find(store, label)?, public)
    }

    /// The first of `keys` whose public key is `public`.
    fn pick(
        keys: impl IntoIterator<Item = SecKey>,
        public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Self, KeyError> {
        keys.into_iter()
            .map(Self)
            .find(|key| key.public_key().is_ok_and(|p| p == *public))
            .ok_or(KeyError::Missing)
    }

    /// Tests only (LD-317 (2)): a new software P-256 key in memory. No
    /// keychain holds it (`kSecAttrIsPermanent` false, no keychain named),
    /// it is never written, and it is gone when dropped.
    ///
    /// # Errors
    /// [`KeyError::Os`] when macOS cannot make the key.
    #[cfg(any(test, feature = "test-device-key"))]
    pub fn test_seam() -> Result<Self, KeyError> {
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256);
        make(&options)
    }

    /// The public key as 65 SEC1 bytes, `04 ‖ X ‖ Y` (CRY-04.4).
    ///
    /// # Errors
    /// [`KeyError::NotP256`] when macOS gives no public key of that form.
    pub fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN], KeyError> {
        let public = self.0.public_key().ok_or(KeyError::NotP256)?;
        let bytes = public.external_representation().ok_or(KeyError::NotP256)?;
        match <[u8; PUBLIC_KEY_LEN]>::try_from(bytes.bytes()) {
            Ok(key) if key.first() == Some(&0x04) => Ok(key),
            _ => Err(KeyError::NotP256),
        }
    }

    /// Signs `message`: ECDSA P-256 with SHA-256 over the message, as an
    /// X9.62 DER signature (SYN-04.1, CRY-04.4); larsal-crypto's
    /// `sign::p256_verify` checks it.
    ///
    /// # Errors
    /// [`KeyError::Os`] when macOS refuses to sign.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.0
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| os(e.code() as i64))
    }
}

/// Access only while this Mac is unlocked, only on this Mac.
fn this_device_only(flags: usize) -> Result<SecAccessControl, KeyError> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        flags,
    )
    .map_err(|e| os(e.code()))
}

fn make(options: &GenerateKeyOptions) -> Result<DeviceKey, KeyError> {
    SecKey::new(options)
        .map(DeviceKey)
        .map_err(|e| os(e.code() as i64))
}

/// Every private key named `label` in `store`.
fn find(store: Store, label: &str) -> Result<Vec<SecKey>, KeyError> {
    let mut search = ItemSearchOptions::new();
    search
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(Limit::All);
    match store {
        // The data protection keychain, where Secure Enclave keys live.
        Store::SecureEnclave => search.ignore_legacy_keychains(),
        Store::LoginKeychain => {
            search.keychains(&[SecKeychain::default().map_err(|e| os(e.code()))?])
        }
    };
    match search.search() {
        Ok(found) => Ok(found
            .into_iter()
            .filter_map(|r| match r {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            })
            .collect()),
        Err(e) if e.code() == NOT_FOUND => Ok(Vec::new()),
        Err(e) => Err(os(e.code())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use larsal_crypto::sign::{field_list, p256_verify};

    /// SYN-04.4's message shape: the CRY-04.2 field list.
    fn challenge() -> Vec<u8> {
        field_list(&[
            b"sync-signin-v1",
            b"https://127.0.0.1:8443",
            &[7u8; 32],
            &[9u8; 16],
        ])
        .unwrap()
    }

    /// SYN-04 T01, the story's first Check: the test-seam key signs through
    /// this file and larsal-crypto's P-256 verify accepts it (CRY-04.4); a
    /// changed message or signature byte is refused.
    #[test]
    fn syn04_t01_test_seam_key_signs_and_larsal_crypto_verifies() {
        let key = DeviceKey::test_seam().unwrap();
        let public = key.public_key().unwrap();
        assert_eq!(public[0], 0x04);
        let message = challenge();
        let signature = key.sign(&message).unwrap();
        assert!(signature.len() <= 72, "{}", signature.len());
        p256_verify(&public, &message, &signature).unwrap();

        let mut changed = message.clone();
        changed[40] ^= 1;
        assert!(p256_verify(&public, &changed, &signature).is_err());
        let mut forged = signature.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(p256_verify(&public, &message, &forged).is_err());
        // Another key's signature does not verify with this public key.
        let other = DeviceKey::test_seam().unwrap();
        assert_ne!(other.public_key().unwrap(), public);
        assert!(p256_verify(&public, &message, &other.sign(&message).unwrap()).is_err());
    }

    /// SYN-04.1: no call returns the private key's bytes. The only call
    /// that gives a key's bytes (`external_representation`) is made once,
    /// on the public key; the key reference is a private field, and `Debug`
    /// shows nothing.
    #[test]
    fn syn04_1_no_call_returns_the_private_key() {
        let src = include_str!("device_key.rs");
        let code = &src[..src.find("#[cfg(test)]\nmod tests").unwrap()];
        assert_eq!(code.matches(".external_representation()").count(), 1);
        let at = code.find(".external_representation()").unwrap();
        assert!(code[..at].trim_end().ends_with("let bytes = public"));
        assert!(code.contains("let public = self.0.public_key()"));
        assert!(code.contains("pub struct DeviceKey(SecKey);"));
        for word in [
            "impl Deref",
            "impl AsRef",
            "fn inner",
            "pub fn key",
            ".attributes()",
        ] {
            assert!(!code.contains(word), "{word}");
        }
        let key = DeviceKey::test_seam().unwrap();
        assert_eq!(format!("{key:?}"), "DeviceKey");
    }

    /// LD-325 (5) (a): a later open takes only the key whose public key is
    /// the stored one. A key planted under the label with another public
    /// key is passed over, and with no key of that public key the open is
    /// `Missing`: a planted key can stop sign-in, never sign in as this
    /// Mac. Proven with test-seam keys (LD-317 (2)): `open` is this pick
    /// over the keychain search, and `make` never searches.
    #[test]
    fn ld325_5a_open_takes_only_the_stored_public_key() {
        let mine = DeviceKey::test_seam().unwrap();
        let stored = mine.public_key().unwrap();
        let DeviceKey(planted) = DeviceKey::test_seam().unwrap();
        let DeviceKey(raw) = mine;
        let picked = DeviceKey::pick([planted.clone(), raw], &stored).unwrap();
        assert_eq!(picked.public_key().unwrap(), stored);
        assert_eq!(
            DeviceKey::pick([planted], &stored).unwrap_err(),
            KeyError::Missing
        );
        assert_eq!(
            DeviceKey::pick(Vec::new(), &stored).unwrap_err(),
            KeyError::Missing
        );
        let src = include_str!("device_key.rs");
        let body = |name: &str| {
            let start = src.find(name).unwrap();
            let end = start + src[start..].find("\n    }\n").unwrap();
            src[start..end].split_whitespace().collect::<String>()
        };
        assert!(body("pub fn open(").ends_with("{Self::pick(find(store,label)?,public)"));
        assert!(!body("pub fn make(").contains("find("));
    }

    /// LD-317 (2): the test seam names no keychain and no token, and asks
    /// for no permanent key, so macOS keeps it in memory only. The Secure
    /// Enclave and login keychain calls are not reached from any test.
    #[test]
    fn ld317_test_seam_names_no_keychain() {
        let src = include_str!("device_key.rs");
        let start = src.find("pub fn test_seam()").unwrap();
        let seam = &src[start..start + src[start..].find("\n    }\n").unwrap()];
        // F-238: the whole body, not only banned words, so a seam that calls
        // `open` or any other keychain path fails here.
        let exact: String = seam.split_whitespace().collect();
        assert_eq!(
            exact,
            "pubfntest_seam()->Result<Self,KeyError>{letmutoptions=GenerateKeyOptions::default();options.set_key_type(KeyType::ec_sec_prime_random()).set_size_in_bits(256);make(&options)"
        );
        for word in [
            "set_location",
            "set_token",
            "set_access_control",
            "set_label",
            "find(",
        ] {
            assert!(!seam.contains(word), "{word}");
        }
        let tests = &src[src.find("#[cfg(test)]\nmod tests").unwrap()..];
        for call in [
            "DeviceKey::open(",
            "Store::SecureEnclave",
            "Store::LoginKeychain",
        ] {
            assert!(
                !tests.replace(&format!("\"{call}\""), "").contains(call),
                "{call}"
            );
        }
    }
}
