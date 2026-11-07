//! Every size and count of FIL-03.1 and FIL-03.2, checked before the work or
//! the allocation it bounds.

/// Bytes of a binary header, framing, MAC and newlines included.
pub const MAX_HEADER: usize = 2_097_152;
/// Stanzas in a header, ignored types included.
pub const MAX_STANZAS: usize = 1024;
/// Distinct recipients of one file (FIL-01.8).
pub const MAX_RECIPIENTS: usize = 1024;
/// Bytes of a decoded identity list.
pub const MAX_IDENTITY_LIST: usize = 65_536;
/// Identities in a list.
pub const MAX_IDENTITIES: usize = 64;
/// Bytes of a passphrase, as UTF-8.
pub const MAX_PASSPHRASE: usize = 1_048_576;
/// Bytes of white space before, and bytes after, an armored file.
pub const MAX_ARMOR_SPACE: usize = 16_384;
/// scrypt work factor every new file gets.
pub const WRITE_LOG_N: u8 = 18;
/// Highest scrypt work factor read. Above it a file is refused before any
/// key derivation or allocation.
pub const READ_MAX_LOG_N: u8 = 20;
/// Plaintext bytes in every chunk but the last.
pub const CHUNK: usize = 65_536;
/// Bytes of a chunk's tag.
pub const TAG: usize = 16;
/// Bytes of a full chunk as stored.
pub const SEALED_CHUNK: usize = CHUNK + TAG;
/// Bytes of an encrypted identity file: a whole header, a nonce and one full
/// chunk, in armor with CRLF line ends, plus its outer white space.
pub const MAX_IDENTITY_FILE: usize = 4_194_304;
/// Files, plaintext or ciphertext, stay within signed 64-bit offsets (FIL-03.12).
pub const MAX_FILE: u64 = i64::MAX as u64;
