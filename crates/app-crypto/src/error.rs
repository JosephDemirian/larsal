//! The crate's single error type (Rust rule 8).
//!
//! No variant holds data: no key, IV, nonce, plaintext, password or other
//! secret can ever reach an error value, its text or a log line through it.

/// Every way an `app-crypto` function can fail.
///
/// Guarantees: each value is a plain tag with a fixed message; it holds no
/// bytes of any input. Other modules may add variants; a new variant must
/// keep this guarantee. Not `non_exhaustive` on purpose: a new variant breaks
/// every exhaustive match outside the crate, so its mapping gets reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The operating system's random source failed. No weak value is ever
    /// returned in its place (E2-S2).
    RandomSource,
    /// Decryption failed. One value for every failure that depends on the
    /// data (ciphertext length, padding, any other cipher failure), so
    /// callers cannot tell the causes apart (spec/decisions.md LD-04, spec
    /// CRY-01.11). A wrong key or IV length is `KeyLength` or `IvLength`.
    Decrypt,
    /// A key has the wrong length for the chosen algorithm. Depends only on
    /// public lengths, is checked before any cipher work, and is the same for
    /// encrypt and decrypt.
    KeyLength,
    /// An IV or nonce has the wrong length for the chosen cipher (spec
    /// CRY-01.9). Depends only on public lengths, is checked before any
    /// cipher work, and is the same for encrypt and decrypt.
    IvLength,
    /// A keystream would pass its limit for one key and nonce, for example
    /// ChaCha20 past 2^32 - 1 blocks (spec CRY-01.13). Nothing is processed
    /// past it.
    StreamLimit,
    /// Key derivation settings are out of range, or the KDF crate refused
    /// them. Raised before any KDF work starts where the check allows
    /// (spec CRY-02.5, CRY-02.16).
    KdfSettings,
    /// The key derivation cost (memory or time) is above the ceiling.
    /// Raised before any KDF work starts (spec CRY-02.14). The caller passes
    /// the ceiling in: it lives in app-format's limits, and app-crypto
    /// depends on no crate of ours.
    KdfCost,
    /// A random number was asked for from an empty range (`random::below(0)`).
    /// No random value is drawn.
    EmptyRange,
    /// The input names an algorithm this crate does not run, for example an
    /// SSH key cipher outside the ones `ssh::OpenSshKey` decrypts. Depends
    /// only on public header fields and is checked before any work (E9-S1).
    Unsupported,
    /// Text is not valid base64 in the form asked for (`base64::Form`).
    /// Holds nothing of the text (E0-S7 R5).
    Base64,
    /// A signature does not verify, or its public key or signature does not
    /// decode (CRY-04.3, CRY-04.4). One value for every cause.
    SignatureInvalid,
    /// A wrap does not open: an HPKE wrap, a signed wrap record or an
    /// AES-256-GCM key wrap (CRY-04.5 to CRY-04.7). One value for every
    /// cause, with no detail, so callers cannot tell the causes apart.
    WrapInvalid,
    /// An input is above the size limit of the function it was passed to,
    /// for example an HPKE plaintext over 1 KiB (CRY-04). Checked before any
    /// work; depends only on public lengths.
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RandomSource => f.write_str("the system random source failed"),
            Self::Decrypt => f.write_str("decryption failed"),
            Self::KeyLength => f.write_str("wrong key length"),
            Self::IvLength => f.write_str("wrong IV or nonce length"),
            Self::StreamLimit => f.write_str("keystream limit reached for this key and nonce"),
            Self::KdfSettings => f.write_str("key derivation settings out of range"),
            Self::KdfCost => f.write_str("key derivation cost above the ceiling"),
            Self::EmptyRange => f.write_str("empty random range"),
            Self::Unsupported => f.write_str("algorithm not supported"),
            Self::Base64 => f.write_str("invalid base64 text"),
            Self::SignatureInvalid => f.write_str("the signature is not valid"),
            Self::WrapInvalid => f.write_str("the wrapped data does not open"),
            Self::TooLarge => f.write_str("input above the size limit"),
        }
    }
}

impl std::error::Error for Error {}
