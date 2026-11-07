//! The encrypt flow (FIL-01.3, FIL-01.4, FIL-01.8): every random draw and the
//! key derivation come first, so a failure there leaves no output at all.

use crate::decrypt::{
    HEADER_LABEL, NONCE, PAYLOAD_LABEL, X25519_LABEL, ZERO_NONCE, check_passphrase, derive_wrap_key,
};
use crate::error::{Error, Failure};
use crate::fsio::{Holds, NewOutput, OutputFolder, SourceFile};
use crate::header::{self, BODY, FILE_KEY, SALT, SCRYPT, X25519};
use crate::keys::Recipient;
use crate::limits::{MAX_RECIPIENTS, WRITE_LOG_N};
use crate::{Control, payload};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::Secret;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{aead, mac, random, wrap};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{Read, Write};

/// Who may open a new file.
pub enum Lock<'a> {
    /// One passphrase: exactly one scrypt stanza (FIL-01.4).
    Passphrase(&'a SecretString),
    /// 1 to 1,024 distinct native recipients, each opening the same file. No
    /// recovery key is added: the sender may not be able to reopen the file.
    Recipients(&'a [Recipient]),
}

/// One random source for a whole encryption: the OS's, except in unit tests.
pub(crate) type Draw<'a> = &'a mut dyn FnMut(usize) -> Result<SecretBytes, larsal_crypto::Error>;

/// All a new file's bytes before its chunks, with its payload key.
struct Prepared {
    head: Vec<u8>,
    payload_key: SecretBytes,
}

pub(crate) fn seal_file_key(
    wrap: &SecretBytes,
    file_key: &SecretBytes,
) -> Result<[u8; BODY], Error> {
    let mut sealed = SecretBytes::new(file_key.expose().to_vec());
    let tag =
        aead::seal_in_place(wrap, &ZERO_NONCE, b"", sealed.expose_mut()).map_err(|_| Error::Io)?;
    let mut body = [0u8; BODY];
    let (first, second) = body.split_at_mut(FILE_KEY);
    first.copy_from_slice(sealed.expose());
    second.copy_from_slice(&tag);
    Ok(body)
}

fn prepare(draw: Draw<'_>, lock: &Lock<'_>, log_n: u8) -> Result<Prepared, Error> {
    let recipients = match lock {
        Lock::Passphrase(p) => {
            check_passphrase(p)?;
            BTreeSet::new()
        }
        Lock::Recipients(list) => {
            let distinct: BTreeSet<Recipient> = list.iter().copied().collect();
            if distinct.is_empty() || distinct.len() > MAX_RECIPIENTS {
                return Err(Error::Recipient);
            }
            distinct
        }
    };
    let file_key = draw(FILE_KEY).map_err(|_| Error::Io)?;
    let mut head = header::start();
    if let Lock::Passphrase(passphrase) = lock {
        let salt = draw(SALT).map_err(|_| Error::Io)?;
        let wrap = derive_wrap_key(passphrase, salt.expose(), log_n).map_err(|_| Error::Io)?;
        let body = seal_file_key(&wrap, &file_key)?;
        let salt_text = base64::encode(Form::Unpadded, salt.expose());
        let cost = log_n.to_string();
        header::push_stanza(&mut head, &[SCRYPT, &salt_text, &cost], &body);
    }
    for recipient in &recipients {
        let ephemeral =
            Secret::from_bytes(draw(32).map_err(|_| Error::Io)?).map_err(|_| Error::Io)?;
        let share = ephemeral.public();
        let shared = ephemeral.agree(&recipient.0).ok_or(Error::Recipient)?;
        let mut salt = share.to_vec();
        salt.extend_from_slice(&recipient.0);
        let wrap = wrap::hkdf_sha256(&salt, &shared, X25519_LABEL).map_err(|_| Error::Io)?;
        let body = seal_file_key(&wrap, &file_key)?;
        let share_text = base64::encode(Form::Unpadded, &share);
        header::push_stanza(&mut head, &[X25519, &share_text], &body);
    }
    header::push_footer(&mut head);
    let mac_key = wrap::hkdf_sha256(&[], &file_key, HEADER_LABEL).map_err(|_| Error::Io)?;
    let tag = mac::hmac_sha256(mac_key.expose(), &[&head]).map_err(|_| Error::Io)?;
    header::push_mac(&mut head, tag.expose());
    let nonce = draw(NONCE).map_err(|_| Error::Io)?;
    head.extend_from_slice(nonce.expose());
    let payload_key =
        wrap::hkdf_sha256(nonce.expose(), &file_key, PAYLOAD_LABEL).map_err(|_| Error::Io)?;
    Ok(Prepared { head, payload_key })
}

/// Encrypts `input` to `output` as a stream in the binary format, with fresh
/// keys and nonce. Working memory does not grow with the input. `output` is the
/// caller's, as is any cleanup of it after a failure. Returns the plaintext
/// length.
///
/// # Errors
/// [`Error::Passphrase`] or [`Error::Recipient`] before any work; [`Error::Io`]
/// if the OS random source fails, before any write; [`Error::Io`] or
/// [`Error::Space`] for an actual fault; [`Error::Cancelled`] if `control` said
/// stop.
pub fn encrypt_stream(
    input: &mut dyn Read,
    output: &mut dyn Write,
    lock: &Lock<'_>,
    control: Control<'_>,
) -> Result<u64, Error> {
    encrypt_stream_with(
        &mut random::bytes,
        WRITE_LOG_N,
        input,
        output,
        lock,
        control,
    )
}

pub(crate) fn encrypt_stream_with(
    draw: Draw<'_>,
    log_n: u8,
    input: &mut dyn Read,
    output: &mut dyn Write,
    lock: &Lock<'_>,
    control: Control<'_>,
) -> Result<u64, Error> {
    let prepared = prepare(draw, lock, log_n)?;
    payload::write_all(output, &prepared.head)?;
    let mut sink = |bytes: &[u8]| payload::write_all(output, bytes);
    Ok(payload::seal_chunks(
        input,
        &mut sink,
        &prepared.payload_key,
        control,
    )?)
}

/// Encrypts an opened file to a new file `name` in `folder`, under the same
/// output rules as [`crate::Validated::save_new`], and refuses a source that
/// changes while it is read. The source itself is never changed. Returns the
/// plaintext length.
///
/// # Errors
/// As [`encrypt_stream`] and `save_new`; [`Error::Changed`] for a changed
/// source. No output exists after an error, unless it is [`Error::Cleanup`],
/// [`Error::CleanupEmpty`] or [`Error::Uncertain`].
pub fn encrypt_file(
    source: SourceFile,
    folder: &OutputFolder,
    name: &OsStr,
    lock: &Lock<'_>,
    control: Control<'_>,
) -> Result<u64, Error> {
    encrypt_file_with(
        &mut random::bytes,
        WRITE_LOG_N,
        source,
        folder,
        name,
        lock,
        control,
    )
}

pub(crate) fn encrypt_file_with(
    draw: Draw<'_>,
    log_n: u8,
    source: SourceFile,
    folder: &OutputFolder,
    name: &OsStr,
    lock: &Lock<'_>,
    control: Control<'_>,
) -> Result<u64, Error> {
    let prepared = prepare(draw, lock, log_n)?;
    let mut out = NewOutput::create(folder, name, Holds::Ciphertext)?;
    let result = (|| {
        out.write(&prepared.head).map_err(Failure::Other)?;
        let mut sink = |bytes: &[u8]| out.write(bytes).map_err(Failure::Other);
        let n = payload::seal_chunks(
            &mut source.reader(),
            &mut sink,
            &prepared.payload_key,
            control,
        )?;
        source.check_unchanged(n).map_err(Failure::Other)?;
        Ok::<u64, Failure>(n)
    })();
    match result {
        Ok(n) => out.finish().map(|()| n),
        Err(failure) => {
            out.abort()?;
            Err(failure.into())
        }
    }
}
