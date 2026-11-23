//! OpenSSH private keys for the SSH agent (E9-S1; spec INT-06.6 to INT-06.10).
//!
//! Reads the OpenSSH private key format (`openssh-key-v1`) through the
//! approved `ssh-key` crate and, for a protected key, runs that crate's
//! bcrypt-pbkdf and cipher. Our code only arranges them (AGENTS rule 3).
//!
//! Guarantees:
//! - no input makes these functions panic; a file this module cannot read
//!   is `None` from [`OpenSshKey::parse`];
//! - the round count of a protected key is checked against the caller's
//!   ceiling before any key derivation runs (D-INT06-3);
//! - decrypted key material lives only in `ssh-key`'s private key types,
//!   which wipe themselves on drop, and in [`SecretBytes`]; the stack used by
//!   parsing and decryption is overwritten afterwards;
//! - errors are the plain tags of [`Error`]; none holds a key byte or the
//!   passphrase.

use crate::Error;
use crate::secret::{SecretBytes, SecretString, scrubbed, scrubbed_deep};
use core::fmt;
use ssh_key::encoding::Encode;
use ssh_key::{Cipher, HashAlg, Kdf, PrivateKey};
use zeroize::Zeroizing;

/// The ciphers [`OpenSshKey::agent_key`] decrypts (INT-06.9): every cipher
/// `ssh-keygen -Z` offers except `3des-cbc`.
const DECRYPTABLE: [Cipher; 9] = [
    Cipher::Aes128Cbc,
    Cipher::Aes192Cbc,
    Cipher::Aes256Cbc,
    Cipher::Aes128Ctr,
    Cipher::Aes192Ctr,
    Cipher::Aes256Ctr,
    Cipher::Aes128Gcm,
    Cipher::Aes256Gcm,
    Cipher::ChaCha20Poly1305,
];

/// One OpenSSH private key, parsed but not decrypted.
///
/// Guarantees: its public parts (type, public key blob, fingerprint, public
/// key line) are known without the passphrase, because the format stores
/// them outside the protected part (INT-06.7). An unprotected key's private
/// part is held in `ssh-key`'s self-wiping types, behind a `Box` made while
/// the parse's stack is still to be overwritten: moving an `OpenSshKey` (or
/// a [`NewSshKey`]) copies only the pointer, never a key byte (rule 4,
/// INT-06.E24.02). No `Clone`; `Debug` shows only the type and fingerprint.
pub struct OpenSshKey {
    key: Box<PrivateKey>,
    algorithm: String,
    public_blob: Vec<u8>,
    public_line: String,
    fingerprint: String,
}

impl OpenSshKey {
    /// Parses a PEM file labelled `OPENSSH PRIVATE KEY` holding exactly one
    /// key. `None` for anything else: another label, broken base64 or
    /// structure, unknown cipher or KDF names, or several keys. Never runs a
    /// key derivation.
    #[must_use]
    pub fn parse(pem: &[u8]) -> Option<Self> {
        scrubbed(|| {
            let key = PrivateKey::from_openssh(pem).ok()?;
            let public = key.public_key();
            let public_blob = public.to_bytes().ok()?;
            let public_line = public.to_openssh().ok()?;
            let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
            let algorithm = key.algorithm().as_str().to_owned();
            Some(Self {
                key: Box::new(key),
                algorithm,
                public_blob,
                public_line,
                fingerprint,
            })
        })
    }

    /// The key type name as the file stores it, for example `ssh-ed25519`
    /// or `ecdsa-sha2-nistp256`.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The RSA modulus size in bits; `None` for other key types.
    #[must_use]
    pub fn rsa_bits(&self) -> Option<u32> {
        self.key
            .public_key()
            .key_data()
            .rsa()
            .map(ssh_key::public::RsaPublicKey::key_size)
    }

    /// The public key blob (RFC 4253 section 6.6), as agents list it.
    #[must_use]
    pub fn public_blob(&self) -> &[u8] {
        &self.public_blob
    }

    /// `SHA256:` and the unpadded base64 SHA-256 of the public key blob, as
    /// `ssh-keygen -l` prints it.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The `.pub` line: type, base64 blob, and the comment when it is known
    /// and not empty.
    #[must_use]
    pub fn public_line(&self) -> &str {
        &self.public_line
    }

    /// The comment stored with the key; `None` while the key is protected
    /// (the comment sits in the protected part).
    #[must_use]
    pub fn comment(&self) -> Option<&str> {
        (!self.key.is_encrypted()).then(|| self.key.comment().as_str_lossy())
    }

    /// True when the private part is protected by a passphrase.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.key.is_encrypted()
    }

    /// The cipher name the file stores, for example `aes256-ctr`; `none`
    /// for an unprotected key.
    #[must_use]
    pub fn cipher_name(&self) -> &'static str {
        self.key.cipher().as_str()
    }

    /// True when the key is unprotected or its cipher is one this module
    /// decrypts.
    #[must_use]
    pub fn can_decrypt(&self) -> bool {
        !self.key.is_encrypted() || DECRYPTABLE.contains(&self.key.cipher())
    }

    /// The bcrypt-pbkdf round count of a protected key; `None` without a KDF.
    #[must_use]
    pub fn kdf_rounds(&self) -> Option<u32> {
        match self.key.kdf() {
            Kdf::Bcrypt { rounds, .. } => Some(*rounds),
            _ => None,
        }
    }

    /// The private key in the form an SSH agent's add message carries
    /// (INT-06.15): its type name and private fields, encoded exactly as in
    /// the file's private section. Decrypts first when the key is protected.
    ///
    /// For a protected key, in this order and before any key derivation:
    /// an empty `passphrase` is [`Error::KdfSettings`]; a cipher outside the
    /// decryptable set is [`Error::Unsupported`]; a KDF other than bcrypt,
    /// an empty salt or zero rounds is [`Error::KdfSettings`]; more rounds
    /// than `max_rounds` is [`Error::KdfCost`]. Then a wrong passphrase (or
    /// any failure that depends on the protected data) is [`Error::Decrypt`].
    /// An unprotected key ignores `passphrase`.
    pub fn agent_key(&self, passphrase: &SecretString, max_rounds: u32) -> Result<AgentKey, Error> {
        if !self.key.is_encrypted() {
            return scrubbed(|| agent_form(&self.key));
        }
        if passphrase.is_empty() {
            return Err(Error::KdfSettings);
        }
        if !self.can_decrypt() {
            return Err(Error::Unsupported);
        }
        match self.key.kdf() {
            Kdf::Bcrypt { salt, rounds } if !salt.is_empty() && *rounds > 0 => {
                if *rounds > max_rounds {
                    return Err(Error::KdfCost);
                }
            }
            _ => return Err(Error::KdfSettings),
        }
        scrubbed_deep(|| {
            let plain = self
                .key
                .decrypt(passphrase.expose().as_bytes())
                .map_err(|_| Error::Decrypt)?;
            agent_form(&plain)
        })
    }
}

impl fmt::Debug for OpenSshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpenSshKey({} {})", self.algorithm, self.fingerprint)
    }
}

/// A decrypted private key ready for an agent's add message.
///
/// Guarantees: the private fields sit only in [`SecretBytes`] (wiped on
/// drop); no `Clone`; `Debug` shows only the type.
pub struct AgentKey {
    fields: SecretBytes,
    algorithm: String,
    comment: String,
}

impl AgentKey {
    /// `string` key type followed by the private key fields (INT-06.15's
    /// table), in the SSH wire encoding. Secret.
    #[must_use]
    pub fn fields(&self) -> &SecretBytes {
        &self.fields
    }

    /// The key type name, for example `ssh-ed25519`.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The comment stored in the key's private part; may be empty. Not secret.
    #[must_use]
    pub fn comment(&self) -> &str {
        &self.comment
    }
}

impl AgentKey {
    /// Signs `data` for Larsal's own SSH agent (E9-S2, INT-06.33) and returns
    /// the SSH signature: `string` algorithm name, `string` signature blob.
    /// Ed25519 signs `data` itself (RFC 8709); ECDSA P-256 signs its SHA-256
    /// with a deterministic nonce (RFC 6979; blob `mpint r`, `mpint s`, RFC
    /// 5656). Any other key type is [`Error::Unsupported`]; private fields
    /// that do not parse, or whose public half does not match, are
    /// [`Error::KeyLength`]. The signing key lives in the signing crates'
    /// self-wiping types; the stack is overwritten afterwards.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        scrubbed(|| sign_fields(self.fields.expose(), data))
    }
}

/// True when Larsal's own agent can sign with keys of this type (INT-06.33):
/// `ssh-ed25519` and `ecdsa-sha2-nistp256`. Others get MI06-33.
#[must_use]
pub fn can_sign(algorithm: &str) -> bool {
    algorithm == ED25519 || algorithm == NISTP256
}

/// Checks an SSH signature (`string` algorithm, `string` blob) over `data`
/// with a public key blob (RFC 4253 section 6.6), for the host key in a
/// `session-bind@openssh.com` request (INT-06.33). `Some(true)` or
/// `Some(false)` for Ed25519 and ECDSA P-256 keys; `None` for any other key
/// type, which Larsal does not check. A signature of another algorithm than
/// the key, or trailing bytes, is `Some(false)`. Public data only.
#[must_use]
pub fn verify(public_blob: &[u8], data: &[u8], signature: &[u8]) -> Option<bool> {
    use ed25519_dalek::Verifier as _;
    let mut key = public_blob;
    let kind = take(&mut key)?;
    let mut sig = signature;
    let kind_of_sig = take(&mut sig);
    let blob = take(&mut sig);
    let blob = blob.filter(|_| kind_of_sig == Some(kind) && sig.is_empty());
    if kind == ED25519.as_bytes() {
        let public: [u8; 32] = take(&mut key)?.try_into().ok()?;
        if !key.is_empty() {
            return Some(false);
        }
        let Some(blob) = blob else {
            return Some(false);
        };
        let ok = ed25519_dalek::VerifyingKey::from_bytes(&public).is_ok_and(|k| {
            ed25519_dalek::Signature::from_slice(blob)
                .is_ok_and(|s| k.verify_strict(data, &s).is_ok())
        });
        return Some(ok);
    }
    if kind == NISTP256.as_bytes() {
        if take(&mut key)? != b"nistp256" {
            return Some(false);
        }
        let point = take(&mut key)?;
        if !key.is_empty() {
            return Some(false);
        }
        let Some(mut blob) = blob else {
            return Some(false);
        };
        let (Some(r), Some(s)) = (mpint32(take(&mut blob)), mpint32(take(&mut blob))) else {
            return Some(false);
        };
        let ok = blob.is_empty()
            && p256::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok_and(|k| {
                p256::ecdsa::Signature::from_scalars(r, s).is_ok_and(|s| k.verify(data, &s).is_ok())
            });
        return Some(ok);
    }
    None
}

const ED25519: &str = "ssh-ed25519";
const NISTP256: &str = "ecdsa-sha2-nistp256";

/// Signs with the agent form of a key: `string` type, then the private
/// fields of INT-06.15's table. Every copy of secret bytes is wiped.
fn sign_fields(fields: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::signature::Signer as _;
    let mut rest = fields;
    let kind = take(&mut rest).ok_or(Error::KeyLength)?;
    let mut out = Vec::new();
    if kind == ED25519.as_bytes() {
        let public = take(&mut rest).ok_or(Error::KeyLength)?;
        let pair = take(&mut rest).ok_or(Error::KeyLength)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            pair.get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::KeyLength)?,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        if pair.len() != 64 || key.verifying_key().as_bytes() != public {
            return Err(Error::KeyLength);
        }
        put(&mut out, ED25519.as_bytes());
        put(&mut out, &key.sign(data).to_bytes());
        return Ok(out);
    }
    if kind == NISTP256.as_bytes() {
        if take(&mut rest) != Some(b"nistp256".as_slice()) {
            return Err(Error::KeyLength);
        }
        let public = take(&mut rest).ok_or(Error::KeyLength)?;
        let scalar = Zeroizing::new(mpint32(take(&mut rest)).ok_or(Error::KeyLength)?);
        let key =
            p256::ecdsa::SigningKey::from_bytes(&(*scalar).into()).map_err(|_| Error::KeyLength)?;
        if p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .ok()
            .as_ref()
            != Some(key.verifying_key())
        {
            return Err(Error::KeyLength);
        }
        let sig: p256::ecdsa::Signature = key.sign(data);
        let (r, s) = sig.split_bytes();
        let mut blob = Vec::new();
        put_mpint(&mut blob, &r);
        put_mpint(&mut blob, &s);
        put(&mut out, NISTP256.as_bytes());
        put(&mut out, &blob);
        return Ok(out);
    }
    Err(Error::Unsupported)
}

/// Takes one SSH `string` from the front of `rest`.
fn take<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<4>()?;
    let (head, tail) = tail.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)?;
    *rest = tail;
    Some(head)
}

/// Appends an SSH `string`. Lengths here are a few dozen bytes.
fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A non-negative `mpint` (RFC 4251) of at most 32 value bytes, left-padded
/// to 32. Negative values and longer ones are `None`.
fn mpint32(bytes: Option<&[u8]>) -> Option<[u8; 32]> {
    let bytes = bytes?;
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let value = bytes.get(bytes.iter().take_while(|b| **b == 0).count()..)?;
    let mut out = [0u8; 32];
    out.get_mut(32usize.checked_sub(value.len())?..)?
        .copy_from_slice(value);
    Some(out)
}

/// Appends a non-negative number of 32 big-endian bytes as an SSH `mpint`:
/// no leading zero bytes, one zero byte when the top bit is set.
fn put_mpint(out: &mut Vec<u8>, value: &[u8]) {
    let trimmed = value
        .get(value.iter().take_while(|b| **b == 0).count()..)
        .unwrap_or_default();
    let mut m = Vec::with_capacity(trimmed.len().saturating_add(1));
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        m.push(0);
    }
    m.extend_from_slice(trimmed);
    put(out, &m);
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentKey({} [hidden])", self.algorithm)
    }
}

/// Encodes an unprotected key's type and private fields into a buffer that
/// is wiped on every path. Encoding a key that parsed does not fail; if it
/// ever did, the answer is the data-dependent [`Error::Decrypt`].
fn agent_form(key: &PrivateKey) -> Result<AgentKey, Error> {
    let data = key.key_data();
    let len = data.encoded_len().map_err(|_| Error::Decrypt)?;
    // Exact capacity: the buffer never grows, so no unwiped copy is left behind.
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    data.encode(&mut *out).map_err(|_| Error::Decrypt)?;
    Ok(AgentKey {
        fields: SecretBytes::new(core::mem::take(&mut *out)),
        algorithm: key.algorithm().as_str().to_owned(),
        comment: key.comment().as_str_lossy().to_owned(),
    })
}

// ------------------------------------------------------------ New SSH Key

/// The key types New SSH Key makes (E24-S2, INT-06.E24.01), in the dialog's
/// order. Guarantees: no other type or size exists here: no RSA under 3072
/// bits, no DSA, no security-key or hybrid type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewKeyKind {
    /// Ed25519 (RFC 8709): a 32-byte random seed, a 256-bit public key; the
    /// default, with no size to choose.
    Ed25519,
    /// ECDSA on NIST P-256 (RFC 5656).
    EcdsaP256,
    /// ECDSA on NIST P-384 (RFC 5656).
    EcdsaP384,
    /// ECDSA on NIST P-521 (RFC 5656).
    EcdsaP521,
    /// RSA, 3072-bit modulus, exponent 65537 (RFC 8332); the RSA size first
    /// selected.
    Rsa3072,
    /// RSA, 4096-bit modulus, exponent 65537.
    Rsa4096,
}

impl NewKeyKind {
    /// Every kind New SSH Key offers, the default first.
    pub const ALL: [Self; 6] = [
        Self::Ed25519,
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::Rsa3072,
        Self::Rsa4096,
    ];

    /// The default kind (INT-06.E24.01).
    pub const DEFAULT: Self = Self::Ed25519;

    /// Type and size as the screen names them: `ED25519`, `ECDSA P-256`,
    /// `ECDSA P-384`, `ECDSA P-521`, `RSA 3072`, `RSA 4096`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "ED25519",
            Self::EcdsaP256 => "ECDSA P-256",
            Self::EcdsaP384 => "ECDSA P-384",
            Self::EcdsaP521 => "ECDSA P-521",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
        }
    }

    /// The public key's type name in the OpenSSH line: `ssh-ed25519`,
    /// `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521`, `ssh-rsa`.
    #[must_use]
    pub fn algorithm(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519,
            Self::EcdsaP256 => NISTP256,
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
            Self::EcdsaP521 => "ecdsa-sha2-nistp521",
            Self::Rsa3072 | Self::Rsa4096 => "ssh-rsa",
        }
    }

    /// The file name OpenSSH gives this type: `id_ed25519`, `id_ecdsa`,
    /// `id_rsa` (the attachment's name).
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 => "id_ecdsa",
            Self::Rsa3072 | Self::Rsa4096 => "id_rsa",
        }
    }
}

/// The longest public comment of a new key, in UTF-8 bytes (INT-06.E24.03).
pub const MAX_COMMENT: usize = 256;

/// True when `comment` may label a new key (INT-06.E24.03): at most
/// [`MAX_COMMENT`] UTF-8 bytes; no control character (line breaks and tabs
/// among them), no line or paragraph separator, and no direction mark,
/// embedding, override or isolate (U+061C, U+200E, U+200F, U+202A to
/// U+202E, U+2066 to U+2069). Empty is allowed. Nothing is rewritten: a
/// comment either passes as it is or is refused.
#[must_use]
pub fn comment_ok(comment: &str) -> bool {
    comment.len() <= MAX_COMMENT
        && !comment.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '\u{2028}'
                        | '\u{2029}'
                        | '\u{061C}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
}

/// A key New SSH Key made (INT-06.E24.02, .04): the private key as a
/// one-key, unprotected `openssh-key-v1` file text, and its public parts.
///
/// Guarantees: the private text lives only in a [`SecretBytes`]; the key
/// read back from it lives in `ssh-key`'s self-wiping types behind the
/// `Box` of [`OpenSshKey`], and every by-value copy of the key while it was
/// made sat on the worker of [`new_key`], whose stack is overwritten before
/// it ends (rule 4, INT-06.E24.02: a move of a `NewSshKey` copies pointers
/// only). The public line, blob and fingerprint are read back from that
/// same text by [`OpenSshKey::parse`], so they belong to that key. No
/// `Clone`; `Debug` shows the type and fingerprint only.
pub struct NewSshKey {
    kind: NewKeyKind,
    private: SecretBytes,
    key: OpenSshKey,
}

impl NewSshKey {
    /// The kind it was made as.
    #[must_use]
    pub fn kind(&self) -> NewKeyKind {
        self.kind
    }

    /// The public line: type, base64 blob, and the comment after one space
    /// when it is not empty. Public.
    #[must_use]
    pub fn public_line(&self) -> &str {
        self.key.public_line()
    }

    /// `SHA256:` and the unpadded base64 SHA-256 of the public blob. Public.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        self.key.fingerprint()
    }

    /// The public key blob (RFC 4253 section 6.6). Public.
    #[must_use]
    pub fn public_blob(&self) -> &[u8] {
        self.key.public_blob()
    }

    /// The private key file text. Secret: it goes only into the vault.
    #[must_use]
    pub fn private(&self) -> &SecretBytes {
        &self.private
    }

    /// The private key file text, moved out (no copy) into the vault's
    /// attachment. Secret.
    #[must_use]
    pub fn into_private(self) -> SecretBytes {
        self.private
    }
}

impl fmt::Debug for NewSshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NewSshKey({} {})", self.kind.label(), self.fingerprint())
    }
}

/// Makes a new key of `kind` labelled `comment` with the OS random source
/// (E24-S2; INT-06.E24.01 to .03). Call it off the screen thread: an RSA key
/// takes seconds.
///
/// Guarantees: every random byte of the key came from the OS source, through
/// this crate's random module; if any draw failed, the key made from it is
/// wiped and nothing is returned. The comment is stored as given.
///
/// # Errors
/// [`Error::Unsupported`] when `comment` breaks [`comment_ok`], before any
/// work, or if the key cannot be encoded and read back (or the worker
/// cannot run); [`Error::RandomSource`] when the OS source failed.
pub fn new_key(kind: NewKeyKind, comment: &str) -> Result<NewSshKey, Error> {
    new_key_from(kind, comment, crate::random::os_unfailing())
}

/// [`new_key`] with `rng` as the generator (tests pass failing ones).
fn new_key_from<R>(
    kind: NewKeyKind,
    comment: &str,
    mut rng: crate::random::Unfailing<R>,
) -> Result<NewSshKey, Error>
where
    R: crate::random::TrySource + Send,
{
    if !comment_ok(comment) {
        return Err(Error::Unsupported);
    }
    crate::secret::scrubbed_thread(Error::Unsupported, move || {
        let made = make_key(kind, comment, &mut rng);
        // A failed draw anywhere: the key (if any) is dropped and wiped.
        if rng.failed() {
            return Err(Error::RandomSource);
        }
        made
    })?
}

/// The key itself, through `ssh-key`'s own key makers, then encoded as
/// `openssh-key-v1` and read back.
fn make_key<R: crate::random::Source + ?Sized>(
    kind: NewKeyKind,
    comment: &str,
    rng: &mut R,
) -> Result<NewSshKey, Error> {
    use ssh_key::EcdsaCurve;
    use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
    let ecdsa = |rng: &mut R, curve| {
        EcdsaKeypair::random(rng, curve)
            .map(KeypairData::from)
            .map_err(|_| Error::Unsupported)
    };
    let rsa = |rng: &mut R, bits| {
        RsaKeypair::random(rng, bits)
            .map(KeypairData::from)
            .map_err(|_| Error::Unsupported)
    };
    let data = match kind {
        NewKeyKind::Ed25519 => KeypairData::from(Ed25519Keypair::random(rng)),
        NewKeyKind::EcdsaP256 => ecdsa(rng, EcdsaCurve::NistP256)?,
        NewKeyKind::EcdsaP384 => ecdsa(rng, EcdsaCurve::NistP384)?,
        NewKeyKind::EcdsaP521 => ecdsa(rng, EcdsaCurve::NistP521)?,
        NewKeyKind::Rsa3072 => rsa(rng, 3072)?,
        NewKeyKind::Rsa4096 => rsa(rng, 4096)?,
    };
    let key = PrivateKey::new(data, comment).map_err(|_| Error::Unsupported)?;
    let mut text = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|_| Error::Unsupported)?;
    // The String's own buffer moves into the wiping type: no copy is left.
    let private = SecretBytes::new(core::mem::take(&mut *text).into_bytes());
    let parsed = OpenSshKey::parse(private.expose()).ok_or(Error::Unsupported)?;
    Ok(NewSshKey {
        kind,
        private,
        key: parsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Demo key K1 of spec INT-06 (made by `ssh-keygen` for the card).
    const K1: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhgAAAJCFFnN8hRZz
fAAAAAtzc2gtZWQyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhg
AAAEBFcbeDr4WGNkaX3X0F79RKibjugiw6qJhq2wgi7SoGGRcFDq2T71wERCeKk/6BZCGH
ILdNQmAt+6GVCObXA9mGAAAACGRlbW9AYXBwAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn k1_public_parts_match_the_card() {
        let key = OpenSshKey::parse(K1.as_bytes()).unwrap();
        assert_eq!(key.algorithm(), "ssh-ed25519");
        assert_eq!(
            key.fingerprint(),
            "SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc"
        );
        assert_eq!(
            key.public_line(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcFDq2T71wERCeKk/6BZCGHILdNQmAt+6GVCObXA9mG demo@app"
        );
        assert_eq!(key.comment(), Some("demo@app"));
        assert!(!key.is_encrypted() && key.can_decrypt());
        assert_eq!(key.kdf_rounds(), None);
        assert_eq!(format!("{key:?}").matches("hidden").count(), 0);
    }

    #[test]
    fn k1_agent_form_is_type_public_and_seed_with_public() {
        let key = OpenSshKey::parse(K1.as_bytes()).unwrap();
        let out = key
            .agent_key(&SecretString::new(String::new()), 1000)
            .unwrap();
        let f = out.fields().expose();
        // string "ssh-ed25519", string public (32), string seed||public (64).
        assert_eq!(f.len(), 4 + 11 + 4 + 32 + 4 + 64);
        assert_eq!(&f[..15], b"\0\0\0\x0bssh-ed25519");
        assert_eq!(&f[19..51], &key.public_blob()[19..51]);
        // The card's seed of K1 (T24).
        let seed: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"4571b783af8586364697dd7d05efd44a89b8ee822c3aa8986adb0822ed2a0619"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(&f[55..87], seed.as_slice());
        assert_eq!(&f[87..119], &key.public_blob()[19..51]);
        assert_eq!(out.comment(), "demo@app");
        assert_eq!(format!("{out:?}"), "AgentKey(ssh-ed25519 [hidden])");
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn agent_key(fields: Vec<u8>, algorithm: &str) -> AgentKey {
        AgentKey {
            fields: SecretBytes::new(fields),
            algorithm: algorithm.into(),
            comment: String::new(),
        }
    }

    /// E9-S2: RFC 8032 section 7.1 test 1 (empty message), through the
    /// agent form and back through `verify`.
    #[test]
    fn sign_ed25519_rfc8032_test_1() {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let mut fields = Vec::new();
        put(&mut fields, b"ssh-ed25519");
        put(&mut fields, &public);
        put(&mut fields, &[seed, public.clone()].concat());
        let sig = agent_key(fields, ED25519).sign(b"").unwrap();
        let mut want = Vec::new();
        put(&mut want, b"ssh-ed25519");
        put(
            &mut want,
            &hex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
        );
        assert_eq!(sig, want);
        let mut blob = Vec::new();
        put(&mut blob, b"ssh-ed25519");
        put(&mut blob, &public);
        assert_eq!(verify(&blob, b"", &sig), Some(true));
        assert_eq!(verify(&blob, b"x", &sig), Some(false));
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(verify(&blob, b"", &bad), Some(false));
        assert_eq!(
            verify(&blob, b"", &[sig.as_slice(), b"\0"].concat()),
            Some(false)
        );
    }

    /// E9-S2: RFC 6979 appendix A.2.5, P-256 with SHA-256, message
    /// "sample"; `r` and `s` have their top bit set, so each `mpint` gets a
    /// zero byte.
    #[test]
    fn sign_p256_rfc6979_sample() {
        let x = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let point = [
            vec![4],
            hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"),
            hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"),
        ]
        .concat();
        let mut fields = Vec::new();
        put(&mut fields, NISTP256.as_bytes());
        put(&mut fields, b"nistp256");
        put(&mut fields, &point);
        put(&mut fields, &[vec![0], x].concat()); // mpint: top bit set
        let sig = agent_key(fields, NISTP256).sign(b"sample").unwrap();
        let r = hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let s = hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        let mut inner = Vec::new();
        put(&mut inner, &[vec![0], r].concat());
        put(&mut inner, &[vec![0], s].concat());
        let mut want = Vec::new();
        put(&mut want, NISTP256.as_bytes());
        put(&mut want, &inner);
        assert_eq!(sig, want);
        let mut blob = Vec::new();
        put(&mut blob, NISTP256.as_bytes());
        put(&mut blob, b"nistp256");
        put(&mut blob, &point);
        assert_eq!(verify(&blob, b"sample", &sig), Some(true));
        assert_eq!(verify(&blob, b"sample!", &sig), Some(false));
    }

    #[test]
    fn sign_refuses_other_types_and_broken_fields() {
        let key = OpenSshKey::parse(K1.as_bytes()).unwrap();
        let k1 = key
            .agent_key(&SecretString::new(String::new()), 1000)
            .unwrap();
        let sig = k1.sign(b"demo").unwrap();
        assert_eq!(verify(key.public_blob(), b"demo", &sig), Some(true));
        assert!(can_sign("ssh-ed25519") && can_sign("ecdsa-sha2-nistp256"));
        assert!(!can_sign("ssh-rsa") && !can_sign("ecdsa-sha2-nistp384"));
        let mut rsa = Vec::new();
        put(&mut rsa, b"ssh-rsa");
        assert_eq!(
            agent_key(rsa.clone(), "ssh-rsa").sign(b""),
            Err(Error::Unsupported)
        );
        assert_eq!(verify(&rsa, b"", &sig), None);
        // A public half that does not match the seed.
        let mut f = k1.fields().expose().to_vec();
        f[20] ^= 1;
        assert_eq!(agent_key(f, ED25519).sign(b""), Err(Error::KeyLength));
        assert_eq!(
            agent_key(vec![0, 0], ED25519).sign(b""),
            Err(Error::KeyLength)
        );
    }

    proptest::proptest! {
        /// Hostile session bindings: any key and signature bytes give an
        /// answer, never a panic.
        #[test]
        fn hostile_verify_never_panics(key in proptest::collection::vec(0u8..=255, 0..200), sig in proptest::collection::vec(0u8..=255, 0..200)) {
            let mut blob = Vec::new();
            put(&mut blob, if key.first() == Some(&0) { b"ssh-ed25519" } else { b"ecdsa-sha2-nistp256" });
            blob.extend_from_slice(&key);
            let _ = verify(&blob, b"id", &sig);
            let _ = verify(&key, b"id", &sig);
        }
    }

    #[test]
    fn other_labels_and_garbage_are_none() {
        assert!(OpenSshKey::parse(b"").is_none());
        assert!(OpenSshKey::parse(K1.replace("OPENSSH", "RSA").as_bytes()).is_none());
        assert!(OpenSshKey::parse(K1.replace("b3Bl", "c3Bl").as_bytes()).is_none());
        assert!(OpenSshKey::parse(&[0xff; 4096]).is_none());
    }

    // ------------------------------------------------ New SSH Key (E24-S2)

    use crate::random::Unfailing;

    /// A source that serves `ok` draws from the OS source, then fails; it
    /// counts the draws asked for, the failed ones included.
    struct FailsAfter(usize, std::sync::Arc<std::sync::atomic::AtomicUsize>);

    fn fails_after(ok: usize) -> (FailsAfter, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (FailsAfter(ok, std::sync::Arc::clone(&n)), n)
    }

    impl crate::random::TryDraw for FailsAfter {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.0 == 0 {
                return Err(std::io::Error::other("demo: source down"));
            }
            self.0 = self.0.saturating_sub(1);
            crate::random::fill(dst).map_err(|_| std::io::Error::other("os"))
        }
    }
    impl crate::random::TrySource for FailsAfter {}

    /// The fields of a one-key `openssh-key-v1` file after its magic.
    fn header(private: &SecretBytes) -> (Vec<u8>, Vec<u8>, Vec<u8>, u32) {
        let text = std::str::from_utf8(private.expose()).unwrap();
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(text.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let raw = crate::base64::decode(crate::base64::Form::Padded, body).unwrap();
        let mut rest = raw.strip_prefix(b"openssh-key-v1\0".as_slice()).unwrap();
        let cipher = take(&mut rest).unwrap().to_vec();
        let kdf = take(&mut rest).unwrap().to_vec();
        let options = take(&mut rest).unwrap().to_vec();
        let count = u32::from_be_bytes(rest[..4].try_into().unwrap());
        (cipher, kdf, options, count)
    }

    #[test]
    fn e24_s01_exactly_ed25519_by_default_three_curves_and_two_rsa_sizes() {
        assert_eq!(NewKeyKind::DEFAULT, NewKeyKind::Ed25519);
        assert_eq!(NewKeyKind::ALL[0], NewKeyKind::DEFAULT);
        let labels: Vec<&str> = NewKeyKind::ALL.iter().map(|k| k.label()).collect();
        assert_eq!(
            labels,
            [
                "ED25519",
                "ECDSA P-256",
                "ECDSA P-384",
                "ECDSA P-521",
                "RSA 3072",
                "RSA 4096"
            ],
            "nothing else: no RSA under 3072 bits, no DSA, no security-key type"
        );
        // Each kind makes a key of its own type and size.
        for kind in NewKeyKind::ALL {
            let key = new_key(kind, "").unwrap();
            let read = OpenSshKey::parse(key.private().expose()).unwrap();
            assert_eq!(read.algorithm(), kind.algorithm(), "{kind:?}");
            assert_eq!(
                read.rsa_bits(),
                match kind {
                    NewKeyKind::Rsa3072 => Some(3072),
                    NewKeyKind::Rsa4096 => Some(4096),
                    _ => None,
                },
                "{kind:?}"
            );
            let curve = |name: &str| {
                let mut blob = key.public_blob();
                take(&mut blob);
                take(&mut blob) == Some(name.as_bytes())
            };
            match kind {
                // RFC 8709: string type, string 32-byte key.
                NewKeyKind::Ed25519 => assert_eq!(key.public_blob().len(), 4 + 11 + 4 + 32),
                NewKeyKind::EcdsaP256 => assert!(curve("nistp256")),
                NewKeyKind::EcdsaP384 => assert!(curve("nistp384")),
                NewKeyKind::EcdsaP521 => assert!(curve("nistp521")),
                NewKeyKind::Rsa3072 | NewKeyKind::Rsa4096 => {}
            }
        }
    }

    #[test]
    fn e24_s02_a_failing_random_source_makes_no_key_of_any_kind() {
        use std::sync::atomic::Ordering::SeqCst;
        for kind in NewKeyKind::ALL {
            // How many draws a key of this kind takes, with a working source.
            let (source, draws) = fails_after(usize::MAX);
            assert!(new_key_from(kind, "demo", Unfailing::new(source)).is_ok());
            let n = draws.load(SeqCst);
            assert!(n >= 1, "{kind:?}");
            // The first draw failing, and the last one.
            for ok in [0, n - 1] {
                let (source, _) = fails_after(ok);
                assert_eq!(
                    new_key_from(kind, "demo", Unfailing::new(source)).err(),
                    Some(Error::RandomSource),
                    "{kind:?} with the source down after {ok} of {n} draws"
                );
            }
        }
    }

    #[test]
    fn e24_s02_each_key_is_new_and_its_public_half_is_its_own() {
        for kind in NewKeyKind::ALL {
            let (a, b) = (new_key(kind, "").unwrap(), new_key(kind, "").unwrap());
            assert_ne!(
                a.public_blob(),
                b.public_blob(),
                "{kind:?}: never a fixed key"
            );
            assert_ne!(a.private().expose(), b.private().expose(), "{kind:?}");
            assert_ne!(a.fingerprint(), b.fingerprint(), "{kind:?}");
        }
        // Signing with the private text verifies with the public blob.
        for kind in [NewKeyKind::Ed25519, NewKeyKind::EcdsaP256] {
            let key = new_key(kind, "demo@larsal").unwrap();
            let agent = OpenSshKey::parse(key.private().expose())
                .unwrap()
                .agent_key(&SecretString::new(String::new()), 1)
                .unwrap();
            let sig = agent.sign(b"E24-S02 demo data").unwrap();
            assert_eq!(
                verify(key.public_blob(), b"E24-S02 demo data", &sig),
                Some(true)
            );
            let other = new_key(kind, "").unwrap();
            assert_eq!(
                verify(other.public_blob(), b"E24-S02 demo data", &sig),
                Some(false)
            );
        }
    }

    #[test]
    fn e24_s03_the_comment_is_kept_exactly_or_refused() {
        let at_limit = "é".repeat(MAX_COMMENT / 2);
        assert_eq!(at_limit.len(), 256);
        for good in [
            "",
            "demo@larsal",
            "Développement · 鍵 🔑",
            at_limit.as_str(),
        ] {
            assert!(comment_ok(good), "{good:?}");
            let key = new_key(NewKeyKind::Ed25519, good).unwrap();
            let read = OpenSshKey::parse(key.private().expose()).unwrap();
            assert_eq!(read.comment(), Some(good), "stored as given");
            let mut parts = key.public_line().splitn(3, ' ');
            assert_eq!(parts.next(), Some("ssh-ed25519"));
            assert!(parts.next().is_some());
            assert_eq!(
                parts.next(),
                (!good.is_empty()).then_some(good),
                "after one space, only when not empty: {:?}",
                key.public_line()
            );
        }
        let over = format!("{at_limit}a");
        for bad in [
            over.as_str(),
            "two\nlines",
            "cr\r",
            "tab\there",
            "nul\0",
            "del\u{7f}",
            "next\u{85}line",
            "line\u{2028}sep",
            "rlo\u{202E}moc.elpmaxe",
            "isolate\u{2066}x\u{2069}",
            "mark\u{200F}",
        ] {
            assert!(!comment_ok(bad), "{bad:?}");
            assert_eq!(
                new_key_from(NewKeyKind::Ed25519, bad, Unfailing::new(fails_after(0).0)).err(),
                Some(Error::Unsupported),
                "refused before any draw: {bad:?}"
            );
        }
    }

    #[test]
    fn e24_s04_the_private_text_is_one_unprotected_openssh_v1_key() {
        for kind in [
            NewKeyKind::Ed25519,
            NewKeyKind::EcdsaP521,
            NewKeyKind::Rsa3072,
        ] {
            let key = new_key(kind, "c").unwrap();
            let (cipher, kdf, options, count) = header(key.private());
            assert_eq!(cipher, b"none");
            assert_eq!(kdf, b"none");
            assert!(options.is_empty());
            assert_eq!(count, 1, "one key");
            // The parser checks the two check values are equal and the padding.
            let read = OpenSshKey::parse(key.private().expose()).unwrap();
            assert!(!read.is_encrypted());
            assert_eq!(read.public_blob(), key.public_blob());
            assert_eq!(read.fingerprint(), key.fingerprint());
            assert_eq!(read.public_line(), key.public_line());
            assert!(format!("{key:?}").starts_with("NewSshKey("));
            assert!(!format!("{key:?}").contains("PRIVATE"));
        }
    }

    /// E24-S03 (Checker 1 C1-F2, lead ruling (2)): every line, control and
    /// text direction character the comment rule names is refused alone, at
    /// the start, in the middle and at the end; the 256 limit counts bytes.
    #[test]
    fn e24_s03_c1_comment_refuses_each_named_character_alone() {
        let named = [
            '\u{0B}', '\u{0C}', '\u{1B}', '\u{85}', '\u{2028}', '\u{2029}', '\u{061C}', '\u{200E}',
            '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}',
            '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        for c in named {
            for s in [format!("{c}"), format!("a{c}b"), format!("ab{c}")] {
                assert!(!comment_ok(&s), "U+{:04X} in {s:?}", c as u32);
            }
        }
        let three = "\u{20AC}".repeat(85);
        assert_eq!(three.len(), 255);
        assert!(comment_ok(&format!("{three}a")), "256 bytes");
        assert!(!comment_ok(&format!("{three}ab")), "257 bytes");
        assert!(
            !comment_ok(&format!("{three}\u{e9}")),
            "257 bytes, last char 2 bytes"
        );
    }

    // ------------------------------------------------ rule 4 (E24-S2, round 3)

    const MASK: u8 = 0x5a;
    /// Set only in the process the worker test starts for its child.
    const CHILD: &str = "LARSAL_E24_WORKER_CHILD";

    /// When the thread that registered it ends (a thread-local's drop: after
    /// `scrubbed_thread`'s wipe, before the stack is given back), the copies
    /// of each masked marker in all writable memory.
    struct AtExit(Vec<Vec<u8>>, std::sync::mpsc::Sender<Vec<usize>>);

    impl Drop for AtExit {
        fn drop(&mut self) {
            let seen = self
                .0
                .iter()
                .map(|m| larsal_platform::memory::copies_in_memory(m, MASK))
                .collect();
            let _ = self.1.send(seen);
        }
    }

    std::thread_local! {
        static AT_EXIT: std::cell::RefCell<Option<AtExit>> =
            const { std::cell::RefCell::new(None) };
    }

    /// A replayable stream (splitmix64), so that the same key can be made
    /// twice; on its first draw it registers its [`AtExit`] on the thread
    /// that draws. A test tool only: keys in Larsal come from the OS source.
    struct Replay(u64, Option<AtExit>);

    impl crate::random::TryDraw for Replay {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            if let Some(at_exit) = self.1.take() {
                AT_EXIT.with(|a| *a.borrow_mut() = Some(at_exit));
            }
            for byte in dst {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                *byte = (z ^ (z >> 31)) as u8;
            }
            Ok(())
        }
    }
    impl crate::random::TrySource for Replay {}

    /// The masked private values of a key text: the Ed25519 seed, or d in
    /// big-endian (ssh-key's form) and little-endian order.
    fn masked_values(text: &[u8]) -> Vec<Vec<u8>> {
        let key = PrivateKey::from_openssh(text).unwrap();
        let masked = |b: &[u8]| -> Vec<u8> { b.iter().map(|x| x ^ MASK).collect() };
        if let Some(pair) = key.key_data().ed25519() {
            return vec![masked(pair.private.as_ref())];
        }
        let be = masked(key.key_data().ecdsa().unwrap().private_key_bytes());
        let mut le = be.clone();
        le.reverse();
        vec![be, le]
    }

    /// The child: for each kind, the markers of the key the replayed stream
    /// makes (worked out on a thread that has ended), then that key made
    /// again by `new_key_from`; the worker counts when it ends.
    #[test]
    #[ignore = "a child of e24_s02_rule4_int06_e24_02_the_key_worker_stack_is_wiped_when_it_ends"]
    fn worker_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let kinds = [
            NewKeyKind::Ed25519,
            NewKeyKind::EcdsaP256,
            NewKeyKind::EcdsaP384,
            NewKeyKind::EcdsaP521,
        ];
        for (i, kind) in kinds.into_iter().enumerate() {
            let seed = 0x0e24_5203 + i as u64;
            let markers = std::thread::scope(|s| {
                s.spawn(|| {
                    let key = new_key_from(kind, "demo", Unfailing::new(Replay(seed, None)));
                    masked_values(key.unwrap().private().expose())
                })
                .join()
                .unwrap()
            });
            let (tx, rx) = std::sync::mpsc::channel();
            let source = Replay(seed, Some(AtExit(markers.clone(), tx)));
            let key = new_key_from(kind, "demo", Unfailing::new(source)).unwrap();
            let at_exit = rx.try_recv().expect("the key's worker counted as it ended");
            // The key handed back holds one copy, in ssh-key's big-endian form.
            let held: Vec<usize> = (0..markers.len()).map(|m| usize::from(m == 0)).collect();
            println!(
                "ROW {} worker at its end: {at_exit:?} (the key handed back holds {held:?})",
                kind.label()
            );
            assert_eq!(
                at_exit,
                held,
                "{}: the worker's stack kept a copy",
                kind.label()
            );
            drop(key);
        }
    }

    /// E24-S02, rule 4, INT-06.E24.02 (lead ruling (10) of round 3): the
    /// worker `new_key` makes a key on wipes its stack before it ends; when
    /// it ends, the key it hands back holds the only copy of the seed or d.
    /// Reads all memory, so the child runs alone in a new process.
    #[test]
    fn e24_s02_rule4_int06_e24_02_the_key_worker_stack_is_wiped_when_it_ends() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ssh::tests::worker_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("{text}");
        assert!(
            out.status.success() && text.contains("1 passed") && text.matches("ROW ").count() == 4,
            "{text}"
        );
    }
}
