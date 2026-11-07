//! The chunked payload (FIL-01.12, FIL-03.16): the STREAM arrangement of the
//! format over ChaCha20-Poly1305 from larsal-crypto. Two chunk buffers, whatever
//! the file's size (FIL-03.3). A chunk is the last one exactly when the file
//! ends right after it, which needs one chunk of read-ahead on both sides.

use crate::armor::Source;
use crate::error::{Error, Failure, io_error};
use crate::limits::{CHUNK, MAX_FILE, SEALED_CHUNK, TAG};
use crate::{Control, Phase};
use larsal_crypto::aead;
use larsal_crypto::secret::SecretBytes;
use std::io::{ErrorKind, Read, Write};

/// The chunk counter. Its wrap is refused before a nonce could repeat; the
/// format's 88 bits hold every value a u64 can.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Counter(pub(crate) u64);

impl Counter {
    /// Eleven bytes of big-endian counter, then the last-chunk flag.
    pub(crate) fn nonce(&self, last: bool) -> [u8; aead::NONCE] {
        let mut nonce = [0u8; aead::NONCE];
        let [_, _, _, c @ .., flag] = &mut nonce;
        *c = self.0.to_be_bytes();
        *flag = u8::from(last);
        nonce
    }

    pub(crate) fn advance(&mut self) -> Result<(), Failure> {
        self.0 = self.0.checked_add(1).ok_or(Failure::Payload)?;
        Ok(())
    }
}

/// Adds `n` to a file's byte count, within signed 64-bit offsets (FIL-03.12).
pub(crate) fn count(total: u64, n: usize) -> Result<u64, Failure> {
    u64::try_from(n)
        .ok()
        .and_then(|n| total.checked_add(n))
        .filter(|t| *t <= MAX_FILE)
        .ok_or(Failure::Other(Error::Io))
}

/// Checks every chunk from where `src` stands to the end of the file, in order,
/// with the last-chunk flag and the end of the file proven, and passes each
/// plaintext to `sink` only after its tag has held. Returns the plaintext length.
pub(crate) fn open_chunks<R: Read>(
    src: &mut Source<R>,
    key: &SecretBytes,
    phase: Phase,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), Failure>,
    control: Control<'_>,
) -> Result<u64, Failure> {
    let mut cur = SecretBytes::zeroed(SEALED_CHUNK);
    let mut next = SecretBytes::zeroed(SEALED_CHUNK);
    let mut counter = Counter(0);
    let mut total = 0u64;
    let mut cur_len = src.read_full(cur.expose_mut())?;
    loop {
        // A full chunk is the last only if nothing at all comes after it. A
        // short read means the file has ended.
        let next_len = if cur_len == SEALED_CHUNK {
            src.read_full(next.expose_mut())?
        } else {
            0
        };
        let last = next_len == 0;
        let plain_len = cur_len.checked_sub(TAG).ok_or(Failure::Payload)?;
        // Only an empty file has an empty chunk; never a last chunk after others.
        if plain_len == 0 && counter.0 != 0 {
            return Err(Failure::Payload);
        }
        let (plain, tag) = cur
            .expose_mut()
            .get_mut(..cur_len)
            .ok_or(Failure::Payload)?
            .split_at_mut_checked(plain_len)
            .ok_or(Failure::Payload)?;
        let tag: &[u8; TAG] = (&*tag).try_into().map_err(|_| Failure::Payload)?;
        if aead::open_in_place(key, &counter.nonce(last), b"", plain, tag).is_err() {
            // FIL-03.17: the published files hash all a reader could decrypt, and a
            // full chunk there may carry either flag. Only the discard pass counts
            // it, for its internal hash; the file is refused all the same.
            if phase == Phase::Validate
                && cur_len == SEALED_CHUNK
                && aead::open_in_place(key, &counter.nonce(!last), b"", plain, tag).is_ok()
            {
                sink(plain)?;
            }
            return Err(Failure::Payload);
        }
        sink(plain)?;
        total = count(total, plain_len)?;
        if !control(phase, total) {
            return Err(Failure::Other(Error::Cancelled));
        }
        if last {
            return Ok(total);
        }
        counter.advance()?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
}

/// Fills `buf` from a plaintext source unless it ends first.
fn read_plain(input: &mut dyn Read, buf: &mut [u8]) -> Result<usize, Failure> {
    let mut done = 0usize;
    while let Some(rest) = buf.get_mut(done..).filter(|r| !r.is_empty()) {
        match input.read(rest) {
            Ok(0) => break,
            Ok(n) => done = done.saturating_add(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(Failure::Other(io_error(&e))),
        }
    }
    Ok(done)
}

/// Seals `input` chunk by chunk into `output`, in the wiped buffers only.
/// Returns the plaintext length. An empty input gives one empty last chunk.
pub(crate) fn seal_chunks(
    input: &mut dyn Read,
    output: &mut dyn FnMut(&[u8]) -> Result<(), Failure>,
    key: &SecretBytes,
    control: Control<'_>,
) -> Result<u64, Failure> {
    let mut cur = SecretBytes::zeroed(SEALED_CHUNK);
    let mut next = SecretBytes::zeroed(SEALED_CHUNK);
    let mut counter = Counter(0);
    let mut total = 0u64;
    let mut cur_len = read_plain(input, plain_part(&mut cur)?)?;
    loop {
        let next_len = if cur_len == CHUNK {
            read_plain(input, plain_part(&mut next)?)?
        } else {
            0
        };
        let last = next_len == 0;
        let sealed_len = cur_len.checked_add(TAG).ok_or(Failure::Payload)?;
        let (plain, rest) = cur
            .expose_mut()
            .split_at_mut_checked(cur_len)
            .ok_or(Failure::Payload)?;
        let tag = aead::seal_in_place(key, &counter.nonce(last), b"", plain)
            .map_err(|_| Failure::Other(Error::Io))?;
        rest.get_mut(..TAG)
            .ok_or(Failure::Payload)?
            .copy_from_slice(&tag);
        output(cur.expose().get(..sealed_len).ok_or(Failure::Payload)?)?;
        total = count(total, cur_len)?;
        if !control(Phase::Encrypt, total) {
            return Err(Failure::Other(Error::Cancelled));
        }
        if last {
            return Ok(total);
        }
        counter.advance()?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
}

fn plain_part(buf: &mut SecretBytes) -> Result<&mut [u8], Failure> {
    buf.expose_mut().get_mut(..CHUNK).ok_or(Failure::Payload)
}

/// Writes all of `bytes`, mapping the OS error to its fixed message.
pub(crate) fn write_all(out: &mut dyn Write, bytes: &[u8]) -> Result<(), Failure> {
    out.write_all(bytes)
        .map_err(|e| Failure::Other(io_error(&e)))
}
