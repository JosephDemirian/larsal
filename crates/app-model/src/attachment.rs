//! Entry attachments (MOD-05, FMT-13).

use app_crypto::secret::SecretBytes;
use std::sync::Arc;

/// One attachment: a name and its content.
///
/// Guarantees: the content is always in `SecretBytes`, whatever the pool's
/// flag byte says (FMT-13.3), so it is wiped when the last holder drops it.
/// Identical content is stored once and shared (`Arc`), so a vault with many
/// references to one item holds one copy (FMT-13.1, architecture
/// `attachments.rs`). The flag byte is not kept: App ignores it on read and
/// always writes `01`.
#[derive(Debug, PartialEq, Eq)]
pub struct Attachment {
    /// Name, case-sensitive; may be empty when read from a file (FMT-13.12).
    pub name: String,
    /// Content bytes, may be empty; compared by content.
    pub data: Arc<SecretBytes>,
}
