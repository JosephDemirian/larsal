//! The file header and the chunks (FIL-04.5, FIL-04.6): the public layout, with the
//! bounded parallel pipeline of FIL-06.1. A chunk's worker owns its buffer until it
//! hands it back, and the reader takes results strictly in order, so there is no queue
//! to grow: 8 buffers are all there are.

use crate::Phase;
use crate::error::{Error, io};
use crate::keys::MasterKeys;
use crate::limits::{CHUNK, GCM_INVOCATIONS, MAX_WORKERS, QUEUE};
use crate::seam;
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::{gcm, random};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, sync_channel};

/// Bytes of a file header.
pub(crate) const HEADER: usize = 68;
const NONCE: usize = gcm::NONCE;
const TAG: usize = gcm::TAG;
const OVERHEAD: usize = NONCE + TAG;
/// Bytes of a full chunk as stored.
pub(crate) const SLOT: usize = CHUNK + OVERHEAD;
const SLOT_U64: u64 = SLOT as u64;
const CHUNK_U64: u64 = CHUNK as u64;
/// Bytes of the sealed header payload: 8 reserved bytes, then the content key.
const HEADER_PAYLOAD: usize = 40;
const RESERVED: [u8; 8] = [0xFF; 8];

/// The legal shape of a stored file: how many chunks and how much plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) chunks: u64,
    pub(crate) plain: u64,
}

/// The shape of `stored` bytes, or [`Error::Open`] for an illegal fragment. A chunk
/// with no payload is legal only as the only chunk: the format's empty file from
/// another writer. Above the signed 64-bit range or the per-key budget is refused.
pub(crate) fn plan(stored: u64) -> Result<Plan, Error> {
    if i64::try_from(stored).is_err() {
        return Err(Error::Open);
    }
    let rest = stored.checked_sub(HEADER as u64).ok_or(Error::Open)?;
    if rest == 0 {
        return Ok(Plan {
            chunks: 0,
            plain: 0,
        });
    }
    let full = rest / SLOT_U64;
    let tail = rest % SLOT_U64;
    let (chunks, last) = if tail == 0 {
        (full, 0)
    } else {
        let payload = tail.checked_sub(OVERHEAD as u64).ok_or(Error::Open)?;
        if payload == 0 && full > 0 {
            return Err(Error::Open);
        }
        (full.checked_add(1).ok_or(Error::Open)?, payload)
    };
    if chunks > GCM_INVOCATIONS {
        return Err(Error::Open);
    }
    let plain = full
        .checked_mul(CHUNK_U64)
        .and_then(|p| p.checked_add(last))
        .ok_or(Error::Open)?;
    Ok(Plan { chunks, plain })
}

/// The stored size of `plain` bytes as this crate writes them.
pub(crate) fn stored_len(plain: u64) -> Result<u64, Error> {
    let full = plain / CHUNK_U64;
    let tail = plain % CHUNK_U64;
    let last = if tail == 0 {
        0
    } else {
        tail.checked_add(OVERHEAD as u64).ok_or(Error::Input)?
    };
    let total = full
        .checked_mul(SLOT_U64)
        .and_then(|b| b.checked_add(last))
        .and_then(|b| b.checked_add(HEADER as u64))
        .ok_or(Error::Input)?;
    if i64::try_from(total).is_err() {
        return Err(Error::Input);
    }
    Ok(total)
}

/// Draws random bytes, or stops: a failed source gives no usable output (FIL-04.12).
fn draw(buf: &mut [u8]) -> Result<(), Error> {
    if seam::rng_fails() {
        return Err(Error::Io);
    }
    random::fill(buf).map_err(|_| Error::Io)
}

/// A fresh sealed header. The caller has taken one from the shared budget already.
pub(crate) fn new_header(
    keys: &MasterKeys,
) -> Result<([u8; HEADER], SecretBytes, [u8; NONCE]), Error> {
    let mut nonce = [0u8; NONCE];
    draw(&mut nonce)?;
    let mut payload = SecretBytes::zeroed(HEADER_PAYLOAD);
    let (reserved, key_part) = payload
        .expose_mut()
        .split_at_mut_checked(RESERVED.len())
        .ok_or(Error::Io)?;
    reserved.copy_from_slice(&RESERVED);
    draw(key_part)?;
    let mut content_key = SecretBytes::zeroed(gcm::KEY);
    content_key.expose_mut().copy_from_slice(key_part);
    let mut sealed = [0u8; HEADER_PAYLOAD];
    sealed.copy_from_slice(payload.expose());
    let tag = gcm::seal_in_place(&keys.enc, &nonce, b"", &mut sealed).map_err(|_| Error::Io)?;
    let mut header = [0u8; HEADER];
    let (a, rest) = header.split_at_mut_checked(NONCE).ok_or(Error::Io)?;
    let (b, c) = rest.split_at_mut_checked(HEADER_PAYLOAD).ok_or(Error::Io)?;
    a.copy_from_slice(&nonce);
    b.copy_from_slice(&sealed);
    c.copy_from_slice(&tag);
    Ok((header, content_key, nonce))
}

/// The content key and nonce of a stored header.
///
/// # Errors
/// [`Error::Open`] for any changed byte, and for reserved bytes the format does not
/// name.
pub(crate) fn open_header(
    keys: &MasterKeys,
    header: &[u8; HEADER],
) -> Result<(SecretBytes, [u8; NONCE]), Error> {
    let (nonce, rest) = header.split_at_checked(NONCE).ok_or(Error::Open)?;
    let (sealed, tag) = rest.split_at_checked(HEADER_PAYLOAD).ok_or(Error::Open)?;
    let nonce: [u8; NONCE] = nonce.try_into().map_err(|_| Error::Open)?;
    let tag: [u8; TAG] = tag.try_into().map_err(|_| Error::Open)?;
    let mut payload = SecretBytes::new(sealed.to_vec());
    gcm::open_in_place(&keys.enc, &nonce, b"", payload.expose_mut(), &tag)
        .map_err(|_| Error::Open)?;
    let (reserved, key) = payload
        .expose()
        .split_at_checked(RESERVED.len())
        .ok_or(Error::Open)?;
    if reserved != RESERVED {
        return Err(Error::Open);
    }
    let mut content_key = SecretBytes::zeroed(gcm::KEY);
    content_key.expose_mut().copy_from_slice(key);
    Ok((content_key, nonce))
}

fn aad(index: u64, header_nonce: &[u8; NONCE]) -> [u8; 20] {
    let mut out = [0u8; 20];
    let (a, b) = out.split_at_mut(8);
    a.copy_from_slice(&index.to_be_bytes());
    b.copy_from_slice(header_nonce);
    out
}

/// What stops a pass at its next chunk: the session's flag and the caller's answer.
pub(crate) struct Gate<'a> {
    pub(crate) revoked: &'a AtomicBool,
    pub(crate) control: crate::Control<'a>,
    pub(crate) phase: Phase,
    pub(crate) done: u64,
}

impl Gate<'_> {
    pub(crate) fn pass(&mut self, bytes: u64) -> Result<(), Error> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(Error::Locked);
        }
        self.done = self.done.saturating_add(bytes);
        if (self.control)(self.phase, self.done) {
            Ok(())
        } else {
            Err(Error::Cancelled)
        }
    }
}

struct Job {
    index: u64,
    payload: usize,
    buf: SecretBytes,
    done: bool,
}

/// The one loop of both directions: `fill` gives the next job on this thread, `work`
/// runs on up to 4 threads, `take` gets results strictly in order on this thread.
fn pipeline<W, F, T>(workers: usize, work: W, mut fill: F, mut take: T) -> Result<(), Error>
where
    W: Fn(&mut Job) -> bool + Sync,
    F: FnMut(u64, &mut SecretBytes) -> Result<Option<usize>, Error>,
    T: FnMut(&Job) -> Result<(), Error>,
{
    let workers = workers.clamp(1, MAX_WORKERS);
    let (job_tx, job_rx) = sync_channel::<Job>(QUEUE);
    let job_rx = Mutex::new(job_rx);
    let (done_tx, done_rx) = channel::<Job>();
    std::thread::scope(|scope| {
        // Owned by this closure: when it returns, the workers see the end of the line.
        let job_tx = job_tx;
        for _ in 0..workers {
            let (done_tx, job_rx, work) = (done_tx.clone(), &job_rx, &work);
            scope.spawn(move || {
                loop {
                    let got = job_rx.lock().map(|rx| rx.recv());
                    let Ok(Ok(mut job)) = got else { return };
                    #[cfg(test)]
                    crate::tests::slow_first_chunk(job.index);
                    job.done = work(&mut job);
                    if done_tx.send(job).is_err() {
                        return;
                    }
                }
            });
        }
        drop(done_tx);
        let mut free: Vec<SecretBytes> = (0..QUEUE).map(|_| SecretBytes::zeroed(SLOT)).collect();
        let mut held: Vec<Option<Job>> = (0..QUEUE).map(|_| None).collect();
        let (mut sent, mut taken, mut eof) = (0u64, 0u64, false);
        let queue = QUEUE as u64;
        loop {
            while !eof {
                let Some(mut buf) = free.pop() else { break };
                match fill(sent, &mut buf)? {
                    Some(payload) => {
                        let job = Job {
                            index: sent,
                            payload,
                            buf,
                            done: false,
                        };
                        job_tx.send(job).map_err(|_| Error::Io)?;
                        sent = sent.checked_add(1).ok_or(Error::Io)?;
                    }
                    None => {
                        eof = true;
                        free.push(buf);
                    }
                }
            }
            if taken == sent {
                return Ok(());
            }
            let want = usize::try_from(taken.checked_rem(queue).ok_or(Error::Io)?)
                .map_err(|_| Error::Io)?;
            let mut job = loop {
                if let Some(job) = held.get_mut(want).and_then(Option::take) {
                    break job;
                }
                let job = done_rx.recv().map_err(|_| Error::Io)?;
                let at = usize::try_from(job.index.checked_rem(queue).ok_or(Error::Io)?)
                    .map_err(|_| Error::Io)?;
                *held.get_mut(at).ok_or(Error::Io)? = Some(job);
            };
            if !job.done {
                return Err(Error::Open);
            }
            take(&job)?;
            job.done = false;
            free.push(job.buf);
            taken = taken.checked_add(1).ok_or(Error::Io)?;
        }
    })
}

/// Fills a buffer from storage at a byte offset.
pub(crate) type ReadAt<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), Error> + 'a;

/// Checks and opens every chunk of a file of the shape `plan`, in order. `read` fills a
/// chunk from storage; `sink` gets each plaintext in order, in its buffer only.
pub(crate) fn open_chunks(
    key: &SecretBytes,
    header_nonce: &[u8; NONCE],
    plan: Plan,
    workers: usize,
    read: &mut ReadAt<'_>,
    gate: &mut Gate<'_>,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let header = HEADER as u64;
    let plain = plan.plain;
    let chunks = plan.chunks;
    pipeline(
        workers,
        |job: &mut Job| {
            let total = job.payload.saturating_add(OVERHEAD);
            let aad = aad(job.index, header_nonce);
            let Some(slot) = job.buf.expose_mut().get_mut(..total) else {
                return false;
            };
            let Some((nonce, rest)) = slot.split_at_mut_checked(NONCE) else {
                return false;
            };
            let Some((data, tag)) = rest.split_at_mut_checked(job.payload) else {
                return false;
            };
            let (Ok(nonce), Ok(tag)) = (
                <[u8; NONCE]>::try_from(&*nonce),
                <[u8; TAG]>::try_from(&*tag),
            ) else {
                return false;
            };
            gcm::open_in_place(key, &nonce, &aad, data, &tag).is_ok()
        },
        |index, buf| {
            if index >= chunks {
                return Ok(None);
            }
            let payload = if index.saturating_add(1) == chunks {
                match plain.checked_sub(index.saturating_mul(CHUNK_U64)) {
                    Some(n) => usize::try_from(n).map_err(|_| Error::Open)?,
                    None => return Err(Error::Open),
                }
            } else {
                CHUNK
            };
            let total = payload.checked_add(OVERHEAD).ok_or(Error::Open)?;
            let at = index
                .checked_mul(SLOT_U64)
                .and_then(|o| o.checked_add(header))
                .ok_or(Error::Open)?;
            read(at, buf.expose_mut().get_mut(..total).ok_or(Error::Open)?)?;
            Ok(Some(payload))
        },
        |job| {
            let plaintext = job
                .buf
                .expose()
                .get(NONCE..NONCE.saturating_add(job.payload))
                .ok_or(Error::Open)?;
            sink(plaintext)?;
            gate.pass(u64::try_from(job.payload).map_err(|_| Error::Open)?)
        },
    )
}

/// Fills `room` from `input` as far as it goes.
fn fill_from(input: &mut dyn std::io::Read, room: &mut [u8]) -> Result<usize, Error> {
    let mut got = 0usize;
    while got < room.len() {
        let target = room.get_mut(got..).ok_or(Error::Io)?;
        match input.read(target) {
            Ok(0) => break,
            Ok(n) => got = got.checked_add(n).ok_or(Error::Io)?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(&e)),
        }
    }
    Ok(got)
}

/// Seals `input` into chunks in order, with a fresh random nonce each, drawn on this
/// thread. Stops before chunk `limit` (FIL-06.16: no enormous key lifetime). Returns the
/// plaintext bytes. No plaintext reaches `out`.
pub(crate) fn seal_chunks(
    key: &SecretBytes,
    header_nonce: &[u8; NONCE],
    workers: usize,
    limit: u64,
    input: &mut dyn std::io::Read,
    gate: &mut Gate<'_>,
    out: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<u64, Error> {
    let mut last = false;
    let mut plain = 0u64;
    pipeline(
        workers,
        |job: &mut Job| {
            let total = job.payload.saturating_add(OVERHEAD);
            let aad = aad(job.index, header_nonce);
            let Some(slot) = job.buf.expose_mut().get_mut(..total) else {
                return false;
            };
            let Some((nonce, rest)) = slot.split_at_mut_checked(NONCE) else {
                return false;
            };
            let Some((data, tag_room)) = rest.split_at_mut_checked(job.payload) else {
                return false;
            };
            let Ok(nonce) = <[u8; NONCE]>::try_from(&*nonce) else {
                return false;
            };
            match gcm::seal_in_place(key, &nonce, &aad, data) {
                Ok(tag) => {
                    tag_room.copy_from_slice(&tag);
                    true
                }
                Err(_) => false,
            }
        },
        |index, buf| {
            if last {
                return Ok(None);
            }
            let (nonce, room) = buf
                .expose_mut()
                .split_at_mut_checked(NONCE)
                .ok_or(Error::Io)?;
            let room = room.get_mut(..CHUNK).ok_or(Error::Io)?;
            let got = fill_from(input, room)?;
            if got < CHUNK {
                last = true;
            }
            if got == 0 {
                return Ok(None);
            }
            if index >= limit {
                return Err(Error::Budget);
            }
            draw(nonce)?;
            plain = plain
                .checked_add(u64::try_from(got).map_err(|_| Error::Io)?)
                .ok_or(Error::Input)?;
            Ok(Some(got))
        },
        |job| {
            let total = job.payload.saturating_add(OVERHEAD);
            out(job.buf.expose().get(..total).ok_or(Error::Io)?)?;
            gate.pass(u64::try_from(job.payload).map_err(|_| Error::Io)?)
        },
    )?;
    Ok(plain)
}

/// A small object sealed whole: the file format's form of a directory ID backup, always
/// one chunk, even an empty one, as the peers write it.
pub(crate) fn seal_small(keys: &MasterKeys, plain: &[u8]) -> Result<Vec<u8>, Error> {
    if plain.len() > CHUNK {
        return Err(Error::Io);
    }
    let (header, content_key, header_nonce) = new_header(keys)?;
    let mut nonce = [0u8; NONCE];
    draw(&mut nonce)?;
    let mut data = plain.to_vec();
    let tag = gcm::seal_in_place(&content_key, &nonce, &aad(0, &header_nonce), &mut data)
        .map_err(|_| Error::Io)?;
    let mut out = Vec::with_capacity(HEADER.saturating_add(OVERHEAD).saturating_add(plain.len()));
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&data);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// A whole stored file in memory, opened: the fuzz door's way in, and the reader of a
/// small object.
#[cfg(any(test, feature = "fuzz-door"))]
pub(crate) fn open_bytes(
    keys: &MasterKeys,
    stored: &[u8],
    workers: usize,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let shape = plan(u64::try_from(stored.len()).map_err(|_| Error::Open)?)?;
    let header: &[u8; HEADER] = stored
        .get(..HEADER)
        .and_then(|h| h.try_into().ok())
        .ok_or(Error::Open)?;
    let (key, nonce) = open_header(keys, header)?;
    let revoked = AtomicBool::new(false);
    let mut go = |_: Phase, _: u64| true;
    let mut gate = Gate {
        revoked: &revoked,
        control: &mut go,
        phase: Phase::Validate,
        done: 0,
    };
    open_chunks(
        &key,
        &nonce,
        shape,
        workers,
        &mut |at, room| {
            let at = usize::try_from(at).map_err(|_| Error::Open)?;
            let end = at.checked_add(room.len()).ok_or(Error::Open)?;
            room.copy_from_slice(stored.get(at..end).ok_or(Error::Open)?);
            Ok(())
        },
        &mut gate,
        sink,
    )
}
