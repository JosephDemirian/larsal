//! The shared budget of the encryption master key (FIL-06.16): NIST SP 800-38D section
//! 8.3 allows 2^32 random-nonce GCM invocations per key, and every header and directory
//! ID backup is one, with any content key. The count is reserved durably before any
//! encryption, in blocks, and what a session does not use is never given back, so a
//! crash, a failed attempt, a cancel or a concurrent instance can only waste budget.
//!
//! The ledger is two local copies with a MAC under a derived key; the higher valid copy
//! wins, so rolling one back moves nothing. Both invalid stops writes. Disclosed limits,
//! not defended: rolling back both copies together (restoring the whole local store) is
//! undetectable; deleting both copies (or the whole local store) starts the count at 0
//! again; a second stores folder for the same keys keeps its own ledger, which starts at
//! 0; and the count knows nothing of another Mac or another tool.

use crate::error::{Error, io};
use crate::keys::MasterKeys;
use crate::limits::{GCM_INVOCATIONS, RESERVE_BLOCK};
use larsal_crypto::mac;
use larsal_crypto::secret::SecretBytes;
use larsal_platform::macos::{create_in, open_regular_in, remove_in, rename_in};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Mutex;

const COPIES: [&str; 2] = ["ledger.a", "ledger.b"];
const SCRATCH: &str = "ledger.new";
const LOCK: &str = "ledger.lock";
const LABEL: &[u8] = b"larsal-folders ledger v1";
const MAX_LEDGER: u64 = 256;

/// What this Mac has counted for one master key. `peer_history_certified` is always
/// false: local accounting cannot know what other instances or tools did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetReport {
    /// Invocations reserved so far on this Mac, used or not.
    pub reserved: u64,
    /// The limit.
    pub limit: u64,
    /// Whether other Macs' and tools' use is known. Never.
    pub peer_history_certified: bool,
}

#[derive(Debug)]
pub(crate) struct Budget {
    dir: File,
    /// The next invocation of the block held, and the block's end.
    held: Mutex<(u64, u64)>,
}

fn text_of(high: u64, key: &SecretBytes) -> Result<String, Error> {
    let tag = mac::hmac_sha256(key.expose(), &[&high.to_be_bytes()]).map_err(|_| Error::Io)?;
    Ok(format!("{high}\n{}\n", crate::names::hex(tag.expose())))
}

/// `None` for a copy that is missing, `Some(None)` for one that does not prove itself.
fn read_copy(dir: &File, name: &str, key: &SecretBytes) -> Result<Option<Option<u64>>, Error> {
    let file = match open_regular_in(dir, OsStr::new(name)) {
        Ok(f) => f,
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound) => return Ok(None),
        Err(_) => return Ok(Some(None)),
    };
    let mut text = String::new();
    if file.take(MAX_LEDGER).read_to_string(&mut text).is_err() {
        return Ok(Some(None));
    }
    // One text per count, "<decimal with no leading zero>\n<lower case hex MAC>\n"; the MAC
    // is checked by larsal-crypto in constant time, and nothing here uses an ordinary
    // equality (the scan in tests::content_rules).
    let Some((count, tag)) = text.strip_suffix('\n').and_then(|t| t.split_once('\n')) else {
        return Ok(Some(None));
    };
    let canonical = count.bytes().all(|b| b.is_ascii_digit())
        && matches!(count.as_bytes(), [b'0'] | [b'1'..=b'9', ..]);
    let high = count.parse::<u64>().ok().filter(|_| canonical);
    let lower = tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let tag = crate::recovery::unhex(tag).filter(|_| lower);
    let (Some(high), Some(tag)) = (high, tag) else {
        return Ok(Some(None));
    };
    let proven = high <= GCM_INVOCATIONS
        && mac::verify_hmac_sha256(key.expose(), &[&high.to_be_bytes()], &tag);
    Ok(Some(proven.then_some(high)))
}

impl Budget {
    pub(crate) fn new(dir: File) -> Self {
        Self {
            dir,
            held: Mutex::new((0, 0)),
        }
    }

    fn write_copy(&self, name: &str, text: &str) -> Result<(), Error> {
        let scratch = OsStr::new(SCRATCH);
        // A file left by a crash here is only ever our own: this name is private.
        let _ = remove_in(&self.dir, scratch);
        let mut file = create_in(&self.dir, scratch, 0o600).map_err(|e| io(&e))?;
        file.write_all(text.as_bytes()).map_err(|e| io(&e))?;
        file.sync_all().map_err(|e| io(&e))?;
        rename_in(&self.dir, scratch, OsStr::new(name)).map_err(|e| io(&e))?;
        self.dir.sync_all().map_err(|e| io(&e))
    }

    /// Under the lock file: the highest proven count, or [`Error::Budget`] when no copy
    /// proves itself but one exists.
    fn locked_high(&self, key: &SecretBytes) -> Result<(File, u64), Error> {
        let lock = match open_regular_in(&self.dir, OsStr::new(LOCK)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match create_in(&self.dir, OsStr::new(LOCK), 0o600) {
                    Ok(f) => f,
                    // Another instance made it first.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        open_regular_in(&self.dir, OsStr::new(LOCK)).map_err(|e| io(&e))?
                    }
                    Err(e) => return Err(io(&e)),
                }
            }
            Err(_) => return Err(Error::Budget),
        };
        lock.lock().map_err(|e| io(&e))?;
        let [a, b] = COPIES;
        let (a, b) = (read_copy(&self.dir, a, key)?, read_copy(&self.dir, b, key)?);
        let high = match (a, b) {
            (None, None) => 0,
            (Some(None) | None, Some(None)) | (Some(None), None) => return Err(Error::Budget),
            (x, y) => x.flatten().unwrap_or(0).max(y.flatten().unwrap_or(0)),
        };
        Ok((lock, high))
    }

    /// Takes one invocation, before any encryption. Reserves the next block durably when
    /// the one held is used up: first both copies say so, then the first use.
    pub(crate) fn take(&self, keys: &MasterKeys) -> Result<(), Error> {
        let mut held = self.held.lock().map_err(|_| Error::Budget)?;
        if held.0 >= held.1 {
            let key = keys.derived(LABEL)?;
            let (lock, high) = self.locked_high(&key)?;
            let end = high.saturating_add(RESERVE_BLOCK).min(GCM_INVOCATIONS);
            if end <= high {
                return Err(Error::Budget);
            }
            let text = text_of(end, &key)?;
            let [a, b] = COPIES;
            self.write_copy(a, &text)?;
            crate::seam::hit("budget.after_first_copy")?;
            self.write_copy(b, &text)?;
            drop(lock);
            *held = (high, end);
        }
        held.0 = held.0.checked_add(1).ok_or(Error::Budget)?;
        Ok(())
    }

    pub(crate) fn report(&self, keys: &MasterKeys) -> Result<BudgetReport, Error> {
        let key = keys.derived(LABEL)?;
        let (_lock, high) = self.locked_high(&key)?;
        Ok(BudgetReport {
            reserved: high,
            limit: GCM_INVOCATIONS,
            peer_history_certified: false,
        })
    }

    /// Sets the ledger, as if this count had been reserved long ago.
    #[cfg(test)]
    pub(crate) fn set_for_tests(&self, keys: &MasterKeys, high: u64) -> Result<(), Error> {
        let key = keys.derived(LABEL)?;
        let text = text_of(high, &key)?;
        let [a, b] = COPIES;
        self.write_copy(a, &text)?;
        self.write_copy(b, &text)?;
        *self.held.lock().map_err(|_| Error::Budget)? = (0, 0);
        Ok(())
    }
}
