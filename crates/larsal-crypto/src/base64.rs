//! Base64 text (RFC 4648 sections 4 and 5) for Larsal's crates, from `base64ct`
//! (E0-S7 R5, LD-258 (2)): no lookup tables and no branches on the data,
//! so key bytes and other secrets can pass through it.
//!
//! - Every read returns a `Result`; no input makes it panic. The error is
//!   [`Error::Base64`], which holds nothing of the text.
//! - A [`Form`] says the alphabet and the padding, for writing and reading.
//! - The `_secret` functions write into buffers that are wiped on drop and
//!   run under `secret::scrubbed`, which zeroes the stack where `base64ct`
//!   keeps its last group, so a key never sits in an unwiped copy on the way
//!   in or out.
//! - Timing depends on the length of the text, its run of trailing `=` and
//!   whether it is valid, never on which characters it holds.

use crate::Error;
use crate::secret::{SecretBytes, SecretString, scrubbed};
use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};

/// The base64 forms Larsal writes and reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// The standard alphabet (`+`, `/`) with `=` padding. Written with it.
    /// Read: the length is a multiple of 4 and the padding is exactly what
    /// the encoding writes; the unused low bits of the last character are
    /// ignored, as RFC 4648 section 3.5 allows (key files, FMT-18.12).
    Padded,
    /// The standard alphabet. Written with `=` padding, as [`Form::Padded`].
    /// Read with the padding, without it or with part of it, never more `=`
    /// than the encoding writes; the unused low bits must be zero (imported
    /// files, FEA-08.35, FEA-08.50).
    PaddingOptional,
    /// The URL-safe alphabet (`-`, `_`, RFC 4648 section 5). Written without
    /// padding. Read as [`Form::PaddingOptional`] reads (FEA-08.47).
    Url,
    /// The standard alphabet, never with `=`. Read: a `=` is refused and the
    /// unused low bits must be zero, so one byte string has exactly one text
    /// (the file header, FIL-01.2).
    Unpadded,
    /// The URL-safe alphabet with `=` padding, written and read. Read: the padding is
    /// exactly what the encoding writes and the unused low bits must be zero, so one
    /// byte string has exactly one text (folder names, FIL-04.10).
    UrlPadded,
}

/// `bytes` as base64 text in `form`.
///
/// Guarantees: never fails for bytes that fit in memory. Input over
/// `usize::MAX / 4` bytes, which no machine can hold, gives empty text.
#[must_use]
pub fn encode(form: Form, bytes: &[u8]) -> String {
    String::from_utf8(encoded(form, bytes)).unwrap_or_default()
}

/// [`encode`] into a [`SecretString`], for secret bytes: the text is
/// written once, into the buffer the result wipes.
#[must_use]
pub fn encode_secret(form: Form, bytes: &[u8]) -> SecretString {
    scrubbed(|| match String::from_utf8(encoded(form, bytes)) {
        Ok(text) => SecretString::new(text),
        // Never happens (base64 is ASCII); the bytes are wiped all the same.
        Err(e) => {
            drop(SecretBytes::new(e.into_bytes()));
            SecretString::new(String::new())
        }
    })
}

/// The bytes of base64 `text` in `form`.
///
/// # Errors
/// [`Error::Base64`] when `text` is not valid in `form`: a character
/// outside the alphabet (white space too), a wrong length, padding where
/// `form` does not allow it, or set low bits where they must be zero.
pub fn decode(form: Form, text: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    let text = text.as_ref();
    let mut buf = vec![0; text.len()];
    let n = decode_in(form, text, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// [`decode`] into a [`SecretBytes`] of the exact length, for secret bytes.
/// Every buffer it uses is wiped.
///
/// # Errors
/// [`Error::Base64`], as [`decode`].
pub fn decode_secret(form: Form, text: impl AsRef<[u8]>) -> Result<SecretBytes, Error> {
    let text = text.as_ref();
    scrubbed(|| {
        let mut buf = SecretBytes::zeroed(text.len());
        let n = decode_in(form, text, buf.expose_mut())?;
        let mut exact = SecretBytes::zeroed(n);
        exact
            .expose_mut()
            .copy_from_slice(buf.expose().get(..n).ok_or(Error::Base64)?);
        Ok(exact)
    })
}

/// [`decode`] in [`Form::Unpadded`] into the front of `out`, with no
/// allocation, for the many short lines of a file. Returns the decoded length.
///
/// # Errors
/// [`Error::Base64`] as [`decode`], also when `out` is too short.
pub fn decode_unpadded_into(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    Base64Unpadded::decode(text, out)
        .map(<[u8]>::len)
        .map_err(|_| Error::Base64)
}

/// The exact base64 bytes of `bytes` in `form`; empty only for empty input
/// or input too long to encode.
fn encoded(form: Form, bytes: &[u8]) -> Vec<u8> {
    let len = match form {
        Form::Padded | Form::PaddingOptional => Base64::encoded_len(bytes),
        Form::Url => Base64UrlUnpadded::encoded_len(bytes),
        Form::Unpadded => Base64Unpadded::encoded_len(bytes),
        Form::UrlPadded => Base64Url::encoded_len(bytes),
    };
    let mut out = vec![0; len];
    let n = match form {
        Form::Padded | Form::PaddingOptional => Base64::encode(bytes, &mut out),
        Form::Url => Base64UrlUnpadded::encode(bytes, &mut out),
        Form::Unpadded => Base64Unpadded::encode(bytes, &mut out),
        Form::UrlPadded => Base64Url::encode(bytes, &mut out),
    }
    .map_or(0, str::len);
    out.truncate(n);
    out
}

/// Decodes `text` into the front of `buf` and returns the decoded length.
/// `buf` is as long as `text`, which is never shorter than its bytes.
fn decode_in(form: Form, text: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
    let n = match form {
        // decode_in_place checks the alphabet, the length and the padding
        // but does not re-encode the last block, so its unused bits pass.
        Form::Padded => {
            let buf = buf.get_mut(..text.len()).ok_or(Error::Base64)?;
            buf.copy_from_slice(text);
            Base64::decode_in_place(buf).map(<[u8]>::len).ok()
        }
        Form::PaddingOptional => Base64Unpadded::decode(unpadded(text)?, buf)
            .map(<[u8]>::len)
            .ok(),
        Form::Url => Base64UrlUnpadded::decode(unpadded(text)?, buf)
            .map(<[u8]>::len)
            .ok(),
        Form::Unpadded => Base64Unpadded::decode(text, buf).map(<[u8]>::len).ok(),
        Form::UrlPadded => Base64Url::decode(text, buf).map(<[u8]>::len).ok(),
    };
    n.ok_or(Error::Base64)
}

/// `text` without its trailing `=`, when there are no more of them than the
/// encoding writes: 2 after a last group of 2 characters, 1 after one of 3,
/// none after a whole group of 4.
fn unpadded(text: &[u8]) -> Result<&[u8], Error> {
    let pad = text.iter().rev().take_while(|&&b| b == b'=').count();
    let body = text
        .get(..text.len().saturating_sub(pad))
        .ok_or(Error::Base64)?;
    match (body.len() % 4, pad) {
        (_, 0) | (2, 1 | 2) | (3, 1) => Ok(body),
        _ => Err(Error::Base64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpadded_counts_only_the_padding_the_encoding_writes() {
        assert_eq!(unpadded(b"QQ=="), Ok(&b"QQ"[..]));
        assert_eq!(unpadded(b"QQ="), Ok(&b"QQ"[..]));
        assert_eq!(unpadded(b"QUI="), Ok(&b"QUI"[..]));
        assert_eq!(unpadded(b"QUJD"), Ok(&b"QUJD"[..]));
        assert_eq!(unpadded(b""), Ok(&b""[..]));
        for bad in [&b"QQ==="[..], b"QUI==", b"QUJD=", b"=", b"==", b"Q="] {
            assert_eq!(unpadded(bad), Err(Error::Base64), "{bad:?}");
        }
    }
}
