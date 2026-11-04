//! The version 4 inner header (FMT-09.1 to FMT-09.8): the protected-field
//! stream algorithm and key, and the attachment pool (FMT-13.2 to FMT-13.4).
//!
//! Guarantees: each field is read in the steps of FMT-09.6 (the limit check
//! before the truncation check, nothing allocated for a length before it is
//! checked); the stream key is copied straight into [`SecretBytes`] in
//! locked pages ([`LockedKey`]); pool
//! items stay ranges of the decompressed payload, never copied here (LD-90);
//! the pool limits of FMT-13.20 are counted as items are read.

use crate::buffer::Grow;
use crate::error::Error;
use crate::keys::LockedKey;
use crate::limits::{Limit, Limits};
use app_crypto::secret::SecretBytes;
use app_crypto::stream::FieldStream;

/// The protected-field stream algorithm of inner header field 1 (FMT-09.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAlgorithm {
    /// Id 2, Salsa20 (FMT-09.10). Accepted in version 4, never written.
    Salsa20,
    /// Id 3, ChaCha20 (FMT-09.9). What App writes.
    ChaCha20,
}

/// One attachment pool item (FMT-13.2, FMT-13.3).
#[derive(Debug)]
pub struct PoolItem {
    /// Bit 0 of the flags byte ("keep protected in memory"). App keeps every
    /// item in secret memory whatever it says, and writes `01`.
    pub protected: bool,
    /// Where the content (the bytes after the flags byte; may be empty,
    /// FMT-13.4) lies in the decompressed payload the header was read from.
    pub range: core::ops::Range<usize>,
}

/// A parsed inner header.
#[derive(Debug)]
pub struct InnerHeader {
    /// The stream algorithm (field 1; the last valid copy wins, FMT-09.5).
    pub stream: StreamAlgorithm,
    /// The stream key (field 2; at least 1 byte, FMT-09.7), in locked
    /// pages while it lives (APP-11.9).
    pub stream_key: LockedKey,
    /// The pool items in file order; item n has pool key "n" (FMT-13.2).
    pub pool: Vec<PoolItem>,
    /// Bytes of the inner header: the document starts at this offset (FMT-09.1).
    pub len: usize,
}

impl InnerHeader {
    /// The protected-field keystream, positioned at byte 0 (FMT-09.9 to FMT-09.11).
    ///
    /// # Errors
    /// `Corrupt` only if the stream cannot be set up, which the fixed key
    /// and nonce lengths rule out.
    pub fn field_stream(&self) -> Result<FieldStream, Error> {
        match self.stream {
            StreamAlgorithm::ChaCha20 => FieldStream::chacha20_from_stream_key(&self.stream_key),
            StreamAlgorithm::Salsa20 => FieldStream::salsa20_from_stream_key(&self.stream_key),
        }
        .map_err(|_| Error::Corrupt)
    }
}

/// Reads the inner header at the start of the decompressed payload `u`
/// (FMT-09.2 to FMT-09.7, FMT-13.2 to FMT-13.4, FMT-13.20).
///
/// # Errors
/// `TooLarge` for a field ending past the total limit or a pool limit
/// passed; `Corrupt` for a cut, a field 1 not 4 bytes, an empty field 3, or
/// a missing field 1 or 2; `Unsupported` for a stream id other than 2 or 3.
pub fn read_inner(u: &[u8], limits: &Limits) -> Result<InnerHeader, Error> {
    let mut pos: usize = 0;
    let (mut stream, mut key) = (None, None);
    let mut pool = Vec::new();
    let mut all_attachments: usize = 0;
    loop {
        let rest = u.get(pos..).ok_or(Error::Corrupt)?;
        let (&id, rest) = rest.split_first().ok_or(Error::Corrupt)?;
        let (len, rest) = rest.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
        let len =
            usize::try_from(u32::from_le_bytes(*len)).map_err(|_| Error::TooLarge(Limit::Total))?;
        let end = pos
            .checked_add(5)
            .and_then(|p| p.checked_add(len))
            .ok_or(Error::TooLarge(Limit::Total))?;
        if end > limits.total {
            return Err(Error::TooLarge(Limit::Total));
        }
        let data = rest.get(..len).ok_or(Error::Corrupt)?;
        pos = end;
        match id {
            0 => break,
            1 => {
                let v: [u8; 4] = data.try_into().map_err(|_| Error::Corrupt)?;
                stream = Some(match u32::from_le_bytes(v) {
                    2 => StreamAlgorithm::Salsa20,
                    3 => StreamAlgorithm::ChaCha20,
                    _ => return Err(Error::Unsupported),
                });
            }
            2 => key = Some(data),
            3 => {
                let (&flags, content) = data.split_first().ok_or(Error::Corrupt)?;
                let start = end.saturating_sub(content.len());
                all_attachments = all_attachments.saturating_add(content.len());
                let passed = if pool.len() >= limits.pool_items {
                    Some(Limit::PoolItems)
                } else if content.len() > limits.one_attachment {
                    Some(Limit::OneAttachment)
                } else if all_attachments > limits.all_attachments {
                    Some(Limit::AllAttachments)
                } else {
                    None
                };
                if let Some(limit) = passed {
                    return Err(Error::TooLarge(limit));
                }
                pool.push(PoolItem {
                    protected: flags & 1 == 1,
                    range: start..end,
                });
            }
            _ => {} // unknown fields are skipped (FMT-09.3)
        }
    }
    let (Some(stream), Some(key)) = (stream, key.filter(|k| !k.is_empty())) else {
        return Err(Error::Corrupt);
    };
    Ok(InnerHeader {
        stream,
        stream_key: LockedKey::new(SecretBytes::new(key.to_vec())),
        pool,
        len: pos,
    })
}

/// Writes the inner header App writes (FMT-09.4) into `out`: field 1 with
/// stream id 3 (ChaCha20), field 2 with the 64-byte `stream_key`, one field
/// 3 record per pool item in index order with flags `01` (FMT-13.3,
/// FMT-13.16), then the end field `00 00 00 00 00`. Everything goes into
/// the wiping buffer; nothing is copied elsewhere.
///
/// # Errors
/// `TooLarge(OneAttachment)` for an item over 4 GiB, which no field holds.
pub(crate) fn write_inner(
    out: &mut Grow,
    stream_key: &SecretBytes,
    pool: &[&SecretBytes],
) -> Result<(), Error> {
    out.extend(&[0x01, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
    let key_len = u32::try_from(stream_key.len()).map_err(|_| Error::Corrupt)?;
    out.push(0x02);
    out.extend(&key_len.to_le_bytes());
    out.extend(stream_key.expose());
    for item in pool {
        let len = item
            .len()
            .checked_add(1)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(Error::TooLarge(Limit::OneAttachment))?;
        out.push(0x03);
        out.extend(&len.to_le_bytes());
        out.push(0x01);
        out.extend(item.expose());
    }
    out.extend(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    Ok(())
}
