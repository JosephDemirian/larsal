//! Bech32 text (BIP-173), original checksum only, for the file format's keys
//! (E22-S3, FIL-01.9). Never Bech32m: the checksum is named in every call, so
//! the crate's accept-both decoder is not reachable from here.
//!
//! Guarantees: text over [`MAX_TEXT`] bytes is refused before any work; a read
//! gives exactly the bytes asked for, in a [`SecretBytes`] made once, or
//! [`Error::Bech32`], which holds nothing of the text; 32 KiB of stack below
//! each call is zeroed after it. Mixed case, a wrong checksum, prefix, padding
//! or length are all refused. All-lower and all-upper spellings are both read.

use crate::Error;
use crate::secret::{SecretBytes, SecretString, scrubbed};
use ::bech32::primitives::decode::CheckedHrpstring;
use ::bech32::{Bech32, Hrp};

/// The longest text read, in bytes: far above any key of the file format.
pub const MAX_TEXT: usize = 256;

/// `data` as lower case Bech32 text with prefix `hrp`, for a public value.
///
/// # Errors
/// [`Error::Bech32`] for a prefix that is not valid, or text over the limit.
pub fn encode_lower(hrp: &str, data: &[u8]) -> Result<String, Error> {
    let hrp = Hrp::parse(hrp).map_err(|_| Error::Bech32)?;
    let cap = ::bech32::encoded_length::<Bech32>(hrp, data).map_err(|_| Error::Bech32)?;
    let mut text = String::with_capacity(cap);
    ::bech32::encode_lower_to_fmt::<Bech32, _>(&mut text, hrp, data).map_err(|_| Error::Bech32)?;
    Ok(text)
}

/// `data` as upper case Bech32 text with prefix `hrp`, for a secret value: the
/// text is written once, into the buffer the result wipes.
///
/// # Errors
/// [`Error::Bech32`] for a prefix that is not valid, or text over the limit.
pub fn encode_upper_secret(hrp: &str, data: &SecretBytes) -> Result<SecretString, Error> {
    scrubbed(|| {
        let hrp = Hrp::parse(hrp).map_err(|_| Error::Bech32)?;
        let cap =
            ::bech32::encoded_length::<Bech32>(hrp, data.expose()).map_err(|_| Error::Bech32)?;
        let mut text = String::with_capacity(cap);
        let done = ::bech32::encode_upper_to_fmt::<Bech32, _>(&mut text, hrp, data.expose());
        let text = SecretString::new(text);
        done.map(|()| text).map_err(|_| Error::Bech32)
    })
}

/// The `len` bytes of `text`, read as Bech32 with prefix `hrp` in either case.
///
/// # Errors
/// [`Error::Bech32`] for anything else, including Bech32m.
pub fn decode(hrp: &str, text: &str, len: usize) -> Result<SecretBytes, Error> {
    if text.len() > MAX_TEXT {
        return Err(Error::Bech32);
    }
    scrubbed(|| {
        let checked = CheckedHrpstring::new::<Bech32>(text).map_err(|_| Error::Bech32)?;
        let same = checked
            .hrp()
            .lowercase_char_iter()
            .eq(hrp.chars().map(|c| c.to_ascii_lowercase()));
        if !same || checked.validate_segwit_padding().is_err() {
            return Err(Error::Bech32);
        }
        let bytes = checked.byte_iter();
        if bytes.len() != len {
            return Err(Error::Bech32);
        }
        let mut out = SecretBytes::zeroed(len);
        out.expose_mut()
            .iter_mut()
            .zip(bytes)
            .for_each(|(o, b)| *o = b);
        Ok(out)
    })
}
