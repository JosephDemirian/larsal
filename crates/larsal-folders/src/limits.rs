//! Every size and count of FIL-04 and FIL-06, checked before the work or the
//! allocation it bounds.

/// Bytes of a configuration file or a key file (FIL-06.1).
pub const MAX_METADATA: usize = 65_536;
/// JSON nesting (FIL-06.1).
pub const MAX_JSON_DEPTH: usize = 16;
/// Members of one JSON object or array (FIL-06.1).
pub const MAX_JSON_MEMBERS: usize = 64;
/// Bytes of one JSON string (FIL-06.1).
pub const MAX_JSON_SCALAR: usize = 16_384;
/// Bytes of a password, before and after normalization (FIL-06.1).
pub const MAX_PASSWORD: usize = 1_048_576;
/// scrypt cost a new folder gets: N = 2^18 (FIL-04.3).
pub const CREATE_LOG_N: u8 = 18;
/// scrypt block size a new folder gets (FIL-04.3).
pub const CREATE_R: u32 = 8;
/// Bytes of salt a new folder gets (FIL-04.3).
pub const CREATE_SALT: usize = 32;
/// Shortening threshold a new folder gets (FIL-04.1).
pub const CREATE_THRESHOLD: usize = 220;
/// Lowest threshold read: every shortened name is at least this long (a SHA-1 in
/// base64 with its extension).
pub const MIN_THRESHOLD: u64 = 32;
/// Highest threshold read: no volume keeps a longer name.
pub const MAX_THRESHOLD: u64 = 255;
/// Bytes of scrypt salt read (FIL-04.3).
pub const SALT_RANGE: std::ops::RangeInclusive<usize> = 8..=64;
/// Highest scrypt block size read (FIL-04.3).
pub const MAX_R: u64 = 32;
/// Worker threads of one pass (FIL-06.1).
pub const MAX_WORKERS: usize = 4;
/// Chunks in flight at once (FIL-06.1). All the chunk buffers there are.
pub const QUEUE: usize = 8;
/// Plaintext bytes in every chunk but the last (FIL-04.5).
pub const CHUNK: usize = 32_768;
/// Items of one page of a listing (FIL-06.3).
pub const MAX_PAGE: usize = 256;
/// Folders on the way down a tree (FIL-06.3).
pub const MAX_DEPTH: usize = 128;
/// Nodes of a tree (FIL-06.3).
pub const MAX_NODES: usize = 1_000_000;
/// Items of one folder (FIL-06.3). A longer listing is a visible refusal.
pub const MAX_CHILDREN: usize = 10_000;
/// Bytes of a clear name after normalization (FIL-06.2).
pub const MAX_NAME: usize = 255;
/// Bytes of a stored inflated name: far past the longest a 255-byte name makes.
pub const MAX_INFLATED: usize = 4_096;
/// Bytes of a directory ID (the format's "at most 36").
pub const MAX_DIR_ID: usize = 36;
/// Recovery copies kept for one set of keys (FIL-06.13).
pub const RECOVERY_CEILING: u64 = 10 * 1024 * 1024 * 1024;
/// GCM invocations under one key (FIL-06.16, NIST SP 800-38D section 8.3).
pub const GCM_INVOCATIONS: u64 = 1 << 32;
/// Header invocations reserved durably at once (FIL-06.16); what a session does not
/// use is never given back.
pub const RESERVE_BLOCK: u64 = 4_096;
