//! The vault's encryption settings (LD-82, MOD-12.12): cipher, KDF with its
//! parameters, and compression, plus the public custom data of the outer
//! header (FMT-03.22). The reader fills them from the file header and the
//! writer writes them. Values drawn fresh on every save (master seed, IV,
//! KDF salt, stream key; CRY-03) are not settings and are not kept here.

/// The payload cipher (CRY-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256 in CBC mode, App's default (LD-20).
    Aes256,
    /// Twofish with a 256-bit key in CBC mode.
    Twofish256,
    /// ChaCha20.
    ChaCha20,
}

/// The Argon2 type (CRY-02.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Kind {
    /// Argon2d.
    D,
    /// Argon2id, App's default for new vaults (CRY-02.23).
    Id,
}

/// KDF settings without the salt, which every save draws fresh (CRY-03.3).
/// Argon2 is always written as version 0x13 (LD-17), so no version is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// AES-KDF (CRY-02.1).
    AesKdf {
        /// Rounds R.
        rounds: u64,
    },
    /// Argon2d or Argon2id (CRY-02.2).
    Argon2 {
        /// Which type.
        kind: Argon2Kind,
        /// Iterations I.
        iterations: u64,
        /// Memory in KiB.
        memory_kib: u64,
        /// Lanes P.
        lanes: u64,
    },
}

/// The payload compression (FMT-08.3, MOD-12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Stored as it is.
    None,
    /// One gzip member, App's default.
    Gzip,
}

/// The encryption settings a save uses (LD-82).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encryption {
    /// The payload cipher.
    pub cipher: Cipher,
    /// The KDF and its parameters.
    pub kdf: Kdf,
    /// The payload compression.
    pub compression: Compression,
}

impl Default for Encryption {
    /// CRY-02.23 for a new vault: AES-256, Argon2id with 64 MiB and 4 lanes,
    /// gzip. The iterations are 2, the safe minimum (MOD-12.12), until vault
    /// creation (E4) sets them from the benchmark.
    fn default() -> Self {
        Encryption {
            cipher: Cipher::Aes256,
            kdf: Kdf::Argon2 {
                kind: Argon2Kind::Id,
                iterations: 2,
                memory_kib: 65_536,
                lanes: 4,
            },
            compression: Compression::Gzip,
        }
    }
}

/// One public custom data item of the outer header (FMT-03.22), kept
/// exactly as stored: type byte, name bytes, value bytes. Public by design
/// (SF-12): anyone with the file can read it, so it is never a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicItem {
    /// The type byte (FMT-03.8).
    pub kind: u8,
    /// The name bytes, compared as exact bytes.
    pub name: Vec<u8>,
    /// The value bytes as stored.
    pub value: Vec<u8>,
}

/// The type only: a name or value may be text the user typed (LD-88).
impl core::fmt::Debug for PublicItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicItem")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
