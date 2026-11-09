//! The decrypt flow, as states (FIL-03.4 to FIL-03.7, FIL-01.12). Each state is
//! made only from the one before it and consumes it, and only [`Validated`]
//! can hand plaintext out. Every failure until then has created no output.
//!
//! | State | What it holds |
//! |---|---|
//! | [`Snapshot`] | One read handle on sealed ciphertext; no name, no writer |
//! | [`Unwrapped`] | The same, the accepted header bytes, its nonce, the payload key and the work factor |
//! | [`Validated`] | The same, and the plaintext length a complete check proved |
//! | [`WeakFile`] | A `Validated` the user has not yet agreed to (FIL-03.2) |
//!
//! Both passes read the same handle, and the second also checks the header
//! and every tag again, so a changed snapshot fails rather than give other bytes.

use crate::armor::Source;
use crate::error::{Error, Failure};
use crate::fsio::{Holds, NewOutput, OutputFolder, SealedFile};
use crate::header::{self, BODY, Stanza};
use crate::keys::Identities;
use crate::limits::{MAX_PASSPHRASE, WRITE_LOG_N};
use crate::{Control, Phase, payload};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{aead, kdf, mac, wrap};
use std::ffi::OsStr;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

pub(crate) const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
pub(crate) const X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";
pub(crate) const HEADER_LABEL: &[u8] = b"header";
pub(crate) const PAYLOAD_LABEL: &[u8] = b"payload";
pub(crate) const NONCE: usize = 16;
pub(crate) const ZERO_NONCE: [u8; aead::NONCE] = [0; aead::NONCE];
/// scrypt's fixed block size and parallelism in this format.
pub(crate) const SCRYPT_R: u32 = 8;
pub(crate) const SCRYPT_P: u32 = 1;
const KEY: usize = 32;

/// The credential a decrypt may use: one the user chose, nothing ambient.
pub enum Unlock<'a> {
    /// A passphrase, as exact UTF-8.
    Passphrase(&'a SecretString),
    /// Explicitly selected private identities.
    Identities(&'a Identities),
}

/// Sealed ciphertext: the state after capture. As [`crate::ScratchRoot`] makes it,
/// it holds one read handle and nothing else, so no writer and no name can reach it
/// through this type. A user's file only ever comes this way (FIL-03.5, FIL-03.6).
/// Inside the crate, a key file already in memory comes through `in_memory`.
pub struct Snapshot<R = SealedFile> {
    pub(crate) src: R,
}

/// The header is bound and parsed, the file key unwrapped and the MAC proven.
/// No payload has been read.
pub struct Unwrapped<R = SealedFile> {
    src: R,
    header: Vec<u8>,
    pub(crate) nonce: [u8; NONCE],
    pub(crate) payload_key: SecretBytes,
    log_n: Option<u8>,
}

/// The file passed a complete check of every chunk, the final marker and EOF.
/// Only this state hands out plaintext.
pub struct Validated<R = SealedFile> {
    state: Unwrapped<R>,
    plain_len: u64,
}

/// A validated file with a low work factor. It reaches a [`Validated`] only
/// through [`WeakFile::accept`], which stands for the user's consent.
pub struct WeakFile<R = SealedFile>(Validated<R>);

/// What a complete check found: a policy question, never a second decrypt error.
pub enum Validation<R = SealedFile> {
    /// Ready to write.
    Ready(Validated<R>),
    /// Valid, with a work factor below the one new files get: ask first.
    Weak(WeakFile<R>),
}

macro_rules! opaque_debug {
    ($($t:ident),*) => {$(
        impl<R> std::fmt::Debug for $t<R> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($t))
            }
        }
    )*};
}
opaque_debug!(Snapshot, Unwrapped, Validated, WeakFile, Validation);

fn check_credential(unlock: &Unlock<'_>) -> Result<(), Error> {
    match unlock {
        Unlock::Passphrase(p) => check_passphrase(p),
        Unlock::Identities(_) => Ok(()),
    }
}

/// FIL-01.5, FIL-03.1: not empty and within the limit, with no change to it.
pub(crate) fn check_passphrase(p: &SecretString) -> Result<(), Error> {
    if p.is_empty() || p.len() > MAX_PASSPHRASE {
        return Err(Error::Passphrase);
    }
    Ok(())
}

/// The one key derivation of the crate, for reads and writes.
pub(crate) fn derive_wrap_key(
    passphrase: &SecretString,
    salt: &[u8],
    log_n: u8,
) -> Result<SecretBytes, larsal_crypto::Error> {
    #[cfg(test)]
    kdf_probe::count();
    let mut full = SCRYPT_LABEL.to_vec();
    full.extend_from_slice(salt);
    kdf::scrypt(
        passphrase.expose().as_bytes(),
        &full,
        log_n,
        SCRYPT_R,
        SCRYPT_P,
        KEY,
    )
}

fn open_file_key(wrap: &SecretBytes, body: &[u8; BODY]) -> Result<SecretBytes, Failure> {
    let (sealed, tag) = body.split_at(header::FILE_KEY);
    let tag: &[u8; aead::TAG] = tag.try_into().map_err(|_| Failure::Header)?;
    let mut key = SecretBytes::new(sealed.to_vec());
    aead::open_in_place(wrap, &ZERO_NONCE, b"", key.expose_mut(), tag)
        .map_err(|_| Failure::NoMatch)?;
    Ok(key)
}

/// The file key from the stanzas, with the work factor that guarded it. Every
/// stanza's shape was checked when it was read, before any primitive here.
fn unwrap_file_key(
    stanzas: &[Stanza],
    unlock: &Unlock<'_>,
) -> Result<(SecretBytes, Option<u8>), Failure> {
    let has_scrypt = stanzas.iter().any(|s| matches!(s, Stanza::Scrypt { .. }));
    if has_scrypt && stanzas.len() != 1 {
        return Err(Failure::Header);
    }
    match unlock {
        Unlock::Passphrase(passphrase) => {
            let [Stanza::Scrypt { salt, log_n, body }] = stanzas else {
                return Err(Failure::NoMatch);
            };
            let wrap = derive_wrap_key(passphrase, salt, *log_n).map_err(|_| Failure::Header)?;
            Ok((open_file_key(&wrap, body)?, Some(*log_n)))
        }
        Unlock::Identities(ids) => {
            for stanza in stanzas {
                let Stanza::X25519 { share, body } = stanza else {
                    continue;
                };
                for id in &ids.keys {
                    // An all-zero result (a low-order share) fails the file.
                    let shared = id.secret.agree(share).ok_or(Failure::Header)?;
                    let mut salt = share.to_vec();
                    salt.extend_from_slice(&id.public);
                    let wrap = wrap::hkdf_sha256(&salt, &shared, X25519_LABEL)
                        .map_err(|_| Failure::Header)?;
                    if let Ok(key) = open_file_key(&wrap, body) {
                        return Ok((key, None));
                    }
                }
            }
            Err(Failure::NoMatch)
        }
    }
}

fn rewind<R: Seek>(src: &mut R) -> Result<(), Failure> {
    src.seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|e| Failure::Other(crate::error::io_error(&e)))
}

impl<'a> Snapshot<Cursor<&'a [u8]>> {
    /// Ciphertext already in memory, borrowed, so it cannot change between the
    /// passes. It goes through the same states, consent included. Not public: a
    /// user's file goes through capture, for its sealed custody.
    pub(crate) const fn in_memory(data: &'a [u8]) -> Self {
        Self {
            src: Cursor::new(data),
        }
    }

    /// The fuzz target's way to the same, and no one else's: this feature is never
    /// on in a product build.
    #[cfg(feature = "fuzz-door")]
    #[must_use]
    pub const fn for_fuzzing(data: &'a [u8]) -> Self {
        Self::in_memory(data)
    }
}

impl<R: Read + Seek> Snapshot<R> {
    /// Reads the bounded header, unwraps the file key with `unlock` and proves
    /// the header's MAC over the bytes as they were read. Any cost above the
    /// limit was refused when the header was read, before any key derivation.
    ///
    /// # Errors
    /// [`Error::Decrypt`] for every fault of the file or a credential that does
    /// not open it; [`Error::Passphrase`] for one empty or over the limit, with
    /// no work done; [`Error::Io`] for an actual read fault.
    pub fn unlock(self, unlock: &Unlock<'_>) -> Result<Unwrapped<R>, Error> {
        check_credential(unlock)?;
        Ok(self.unlock_inner(unlock)?)
    }

    pub(crate) fn unlock_inner(mut self, unlock: &Unlock<'_>) -> Result<Unwrapped<R>, Failure> {
        rewind(&mut self.src)?;
        let mut src = Source::detect(&mut self.src)?;
        let head = header::read(&mut src)?;
        let (file_key, log_n) = unwrap_file_key(&head.stanzas, unlock)?;
        let mac_key =
            wrap::hkdf_sha256(&[], &file_key, HEADER_LABEL).map_err(|_| Failure::Header)?;
        if !mac::verify_hmac_sha256(mac_key.expose(), &[head.covered()], &head.mac) {
            return Err(Failure::Mac);
        }
        let mut nonce = [0u8; NONCE];
        if src.read_full(&mut nonce)? != NONCE {
            return Err(Failure::Header);
        }
        let payload_key =
            wrap::hkdf_sha256(&nonce, &file_key, PAYLOAD_LABEL).map_err(|_| Failure::Payload)?;
        drop(src);
        Ok(Unwrapped {
            src: self.src,
            header: head.raw,
            nonce,
            payload_key,
            log_n,
        })
    }
}

impl<R: Read + Seek> Unwrapped<R> {
    /// Checks the whole payload with the plaintext thrown away: every chunk in
    /// order, the final marker and the end of the file. Plaintext reaches only
    /// the wiped chunk buffers. On any failure there is no output to clean up.
    ///
    /// # Errors
    /// [`Error::Decrypt`] for a changed, cut, swapped or appended byte;
    /// [`Error::Cancelled`] if `control` said stop; [`Error::Io`] for a read fault.
    pub fn validate(self, control: Control<'_>) -> Result<Validation<R>, Error> {
        Ok(self.validate_inner(&mut |_| Ok(()), control)?)
    }

    pub(crate) fn validate_inner(
        mut self,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), Failure>,
        control: Control<'_>,
    ) -> Result<Validation<R>, Failure> {
        let plain_len = self.pass(Phase::Validate, sink, control)?;
        let weak = self.log_n.is_some_and(|n| n < WRITE_LOG_N);
        let state = Validated {
            state: self,
            plain_len,
        };
        Ok(if weak {
            Validation::Weak(WeakFile(state))
        } else {
            Validation::Ready(state)
        })
    }

    /// One whole pass over the same handle, the same header and the same nonce.
    fn pass(
        &mut self,
        phase: Phase,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), Failure>,
        control: Control<'_>,
    ) -> Result<u64, Failure> {
        rewind(&mut self.src)?;
        let mut src = Source::detect(&mut self.src)?;
        for byte in &self.header {
            if src.next_byte()? != Some(*byte) {
                return Err(Failure::Header);
            }
        }
        let mut nonce = [0u8; NONCE];
        if src.read_full(&mut nonce)? != NONCE || nonce != self.nonce {
            return Err(Failure::Payload);
        }
        payload::open_chunks(&mut src, &self.payload_key, phase, sink, control)
    }
}

impl<R> WeakFile<R> {
    /// The user agreed to read this low work factor file (FIL-03.2).
    #[must_use]
    pub fn accept(self) -> Validated<R> {
        self.0
    }
}

impl<R: Read + Seek> Validated<R> {
    /// The plaintext length the check proved. Sizes are public.
    #[must_use]
    pub const fn plain_len(&self) -> u64 {
        self.plain_len
    }

    fn second_pass(
        &mut self,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), Failure>,
        control: Control<'_>,
    ) -> Result<u64, Failure> {
        let n = self.state.pass(Phase::Write, sink, control)?;
        if n != self.plain_len {
            return Err(Failure::Payload);
        }
        Ok(n)
    }

    /// Writes the plaintext to a stream the caller owns. Bytes can have been
    /// written when a later read or write fails (FIL-03.7): cleaning up is the
    /// caller's. Returns the plaintext length.
    ///
    /// # Errors
    /// [`Error::Decrypt`] if the snapshot changed since the check; [`Error::Io`]
    /// or [`Error::Space`] for an actual fault; [`Error::Cancelled`] if `control`
    /// said stop.
    pub fn write_to(mut self, out: &mut dyn Write, control: Control<'_>) -> Result<u64, Error> {
        let mut sink = |bytes: &[u8]| payload::write_all(out, bytes);
        Ok(self.second_pass(&mut sink, control)?)
    }

    /// Creates a new file `name` in `folder`, and writes the plaintext there.
    /// This is the first moment any output exists. The file is exclusive, 0600,
    /// made through the folder's descriptor, and never replaces anything
    /// (FIL-03.8). A folder that passes an access list on to it gets not one
    /// byte, and neither does a disk that cannot keep the file private. A failed
    /// or cancelled write empties it through its own descriptor and tries to
    /// remove its name. Returns the plaintext length.
    ///
    /// # Errors
    /// [`Error::Exists`], [`Error::Destination`] or [`Error::Unprotected`] before
    /// any write; [`Error::CleanupEmpty`] if an incomplete output was emptied but
    /// its name was not as expected or could not be removed; [`Error::Cleanup`] if
    /// it could not be emptied;
    /// [`Error::Uncertain`] if every byte was written but its sync failed: the
    /// file is kept. Otherwise as [`Self::write_to`].
    pub fn save_new(
        self,
        folder: &OutputFolder,
        name: &OsStr,
        control: Control<'_>,
    ) -> Result<u64, Error> {
        self.save_new_warned(folder, name, control, &mut || false)
    }

    /// As [`Self::save_new`], but on a disk that cannot keep the new file private
    /// `warned` is asked first, before any byte (MSG-FILE-UNPROTECTED's warned
    /// consent, E22-S4): true writes there anyway, false is
    /// [`Error::Unprotected`] with nothing left.
    ///
    /// # Errors
    /// As [`Self::save_new`].
    pub fn save_new_warned(
        mut self,
        folder: &OutputFolder,
        name: &OsStr,
        control: Control<'_>,
        warned: &mut dyn FnMut() -> bool,
    ) -> Result<u64, Error> {
        // FIL-02.13: a safe point before the output exists.
        if !control(Phase::Write, 0) {
            return Err(Error::Cancelled);
        }
        let mut out = NewOutput::create(folder, name, Holds::Plaintext, warned)?;
        let mut sink = |bytes: &[u8]| out.write(bytes).map_err(Failure::Other);
        let written = self.second_pass(&mut sink, control);
        match written {
            Ok(n) => out.finish().map(|()| n),
            Err(failure) => {
                out.abort()?;
                Err(failure.into())
            }
        }
    }
}

/// A key file's text (FIL-01.16), at most `max_plain` bytes, in wiping memory,
/// and whether its work factor is low, which the caller passes on as a warning.
/// Not public: this goes past the consent state, and nothing but a key file may.
pub(crate) fn open_bounded(
    data: &[u8],
    unlock: &Unlock<'_>,
    max_plain: usize,
) -> Result<(SecretBytes, bool), Error> {
    let snapshot = Snapshot::in_memory(data);
    let keep_going = &mut |_: Phase, _: u64| true;
    let (checked, weak) = match snapshot.unlock(unlock)?.validate(keep_going)? {
        Validation::Ready(v) => (v, false),
        Validation::Weak(w) => (w.accept(), true),
    };
    let len = usize::try_from(checked.plain_len())
        .ok()
        .filter(|n| *n <= max_plain)
        .ok_or(Error::Decrypt)?;
    let mut plain = SecretBytes::zeroed(len);
    let mut to: &mut [u8] = plain.expose_mut();
    checked.write_to(&mut to, keep_going)?;
    Ok((plain, weak))
}

/// Test-only: how many key derivations ran on this thread.
#[cfg(test)]
pub(crate) mod kdf_probe {
    use std::cell::Cell;
    thread_local! { static CALLS: Cell<usize> = const { Cell::new(0) }; }
    pub(crate) fn count() {
        CALLS.with(|n| n.set(n.get().wrapping_add(1)));
    }
    pub(crate) fn take() -> usize {
        CALLS.with(Cell::take)
    }
}
