//! The binary header of the format (FIL-01.2, FIL-01.4, FIL-01.11, FIL-01.14,
//! FIL-03.1, FIL-03.2): read strictly and bounded before anything is buffered,
//! written canonically. The bytes accepted are kept, so the MAC runs over the
//! original bytes, never over a repaired copy.

use crate::armor::Source;
use crate::error::Failure;
use crate::limits::{MAX_HEADER, MAX_STANZAS, READ_MAX_LOG_N};
use larsal_crypto::base64::{self, Form};
use std::io::Read;
use std::ops::Range;

const VERSION: &[u8] = b"age-encryption.org/v1";
/// Everything the MAC covers ends with this, without the space after it.
const FOOTER: &[u8] = b"---";
const STANZA: &[u8] = b"-> ";
const WIDTH: usize = 64;
/// `--- ` and the 43 characters of a 32-byte MAC.
const FOOTER_LINE: usize = 47;

pub(crate) const X25519: &str = "X25519";
pub(crate) const SCRYPT: &str = "scrypt";
pub(crate) const FILE_KEY: usize = 16;
/// A wrapped file key: 16 bytes and a tag.
pub(crate) const BODY: usize = 32;
pub(crate) const SALT: usize = 16;

/// What the flow needs of one stanza. A stanza of another type is checked and
/// counted, and matches no credential (FIL-01.14).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stanza {
    Scrypt {
        salt: [u8; SALT],
        log_n: u8,
        body: [u8; BODY],
    },
    X25519 {
        share: [u8; 32],
        body: [u8; BODY],
    },
    Other,
}

pub(crate) struct Header {
    /// Every accepted byte, through the footer's newline.
    pub(crate) raw: Vec<u8>,
    /// How much of `raw` the MAC covers.
    covered: usize,
    pub(crate) mac: [u8; 32],
    pub(crate) stanzas: Vec<Stanza>,
}

impl Header {
    pub(crate) fn covered(&self) -> &[u8] {
        self.raw.get(..self.covered).unwrap_or(&[])
    }
}

/// Reads one line into `raw`, and gives its range without the newline. The
/// header's limit is checked on every byte, so a hostile file is refused at
/// byte 2,097,153 whatever it advertises.
fn read_line<R: Read>(src: &mut Source<R>, raw: &mut Vec<u8>) -> Result<Range<usize>, Failure> {
    let start = raw.len();
    loop {
        let Some(b) = src.next_byte()? else {
            return Err(Failure::Header);
        };
        if raw.len() >= MAX_HEADER {
            return Err(Failure::Header);
        }
        raw.push(b);
        if b == b'\n' {
            return Ok(start..raw.len().saturating_sub(1));
        }
    }
}

/// Reads a stanza body: canonical unpadded base64, every line 64 columns but
/// the last, which is shorter and may be empty. When `keep` is given, the
/// decoded bytes go there, and any more or fewer than it holds is refused.
fn read_body<R: Read>(
    src: &mut Source<R>,
    raw: &mut Vec<u8>,
    mut keep: Option<&mut [u8; BODY]>,
) -> Result<(), Failure> {
    let mut total = 0usize;
    loop {
        let range = read_line(src, raw)?;
        let line = raw.get(range).ok_or(Failure::Header)?;
        if line.len() > WIDTH {
            return Err(Failure::Header);
        }
        let mut decoded = [0u8; 48];
        let n = base64::decode_unpadded_into(line, &mut decoded).map_err(|_| Failure::Header)?;
        if let Some(keep) = keep.as_deref_mut() {
            let end = total.saturating_add(n);
            keep.get_mut(total..end)
                .ok_or(Failure::Header)?
                .copy_from_slice(decoded.get(..n).ok_or(Failure::Header)?);
        }
        total = total.saturating_add(n);
        if line.len() < WIDTH {
            return if keep.is_some() && total != BODY {
                Err(Failure::Header)
            } else {
                Ok(())
            };
        }
    }
}

/// The strict decimal work factor of FIL-03.2: digits only, no sign, no
/// leading zero, bounded before it is parsed, 1 to the ceiling. Refused here,
/// so it never reaches a key derivation.
fn work_factor(arg: &[u8]) -> Result<u8, Failure> {
    let log_n = match *arg {
        [d @ b'1'..=b'9'] => d.saturating_sub(b'0'),
        [t @ b'1'..=b'9', d @ b'0'..=b'9'] => t
            .saturating_sub(b'0')
            .saturating_mul(10)
            .saturating_add(d.saturating_sub(b'0')),
        _ => return Err(Failure::Header),
    };
    if log_n > READ_MAX_LOG_N {
        return Err(Failure::Header);
    }
    Ok(log_n)
}

/// `text` as exactly `N` bytes of canonical base64.
fn exact<const N: usize>(text: &[u8]) -> Result<[u8; N], Failure> {
    let mut out = [0u8; N];
    match base64::decode_unpadded_into(text, &mut out) {
        Ok(n) if n == N => Ok(out),
        _ => Err(Failure::Header),
    }
}

/// Checks a stanza line after its `-> ` and reads its body. A malformed known
/// stanza fails the whole file before any primitive runs (FIL-01.11).
fn read_stanza<R: Read>(
    src: &mut Source<R>,
    raw: &mut Vec<u8>,
    line: Range<usize>,
) -> Result<Stanza, Failure> {
    let line = raw.get(line).ok_or(Failure::Header)?;
    let args_ok = line.iter().all(|b| *b == b' ' || (0x21..=0x7E).contains(b))
        && line.split(|b| *b == b' ').all(|a| !a.is_empty());
    if !args_ok {
        return Err(Failure::Header);
    }
    let mut args = line.split(|b| *b == b' ');
    let kind = args.next().ok_or(Failure::Header)?;
    if kind == SCRYPT.as_bytes() {
        let (Some(salt), Some(cost), None) = (args.next(), args.next(), args.next()) else {
            return Err(Failure::Header);
        };
        let salt = exact::<SALT>(salt)?;
        let log_n = work_factor(cost)?;
        let mut body = [0u8; BODY];
        read_body(src, raw, Some(&mut body))?;
        Ok(Stanza::Scrypt { salt, log_n, body })
    } else if kind == X25519.as_bytes() {
        let (Some(share), None) = (args.next(), args.next()) else {
            return Err(Failure::Header);
        };
        let share = exact::<32>(share)?;
        let mut body = [0u8; BODY];
        read_body(src, raw, Some(&mut body))?;
        Ok(Stanza::X25519 { share, body })
    } else {
        read_body(src, raw, None)?;
        Ok(Stanza::Other)
    }
}

/// Reads the whole header from the start of `src`.
pub(crate) fn read<R: Read>(src: &mut Source<R>) -> Result<Header, Failure> {
    let mut raw = Vec::new();
    let mut stanzas = Vec::new();
    let line = read_line(src, &mut raw)?;
    if raw.get(line) != Some(VERSION) {
        return Err(Failure::Header);
    }
    loop {
        let range = read_line(src, &mut raw)?;
        let line = raw.get(range.clone()).ok_or(Failure::Header)?;
        if line.starts_with(STANZA) {
            if stanzas.len() >= MAX_STANZAS {
                return Err(Failure::Header);
            }
            let args = range.start.saturating_add(STANZA.len())..range.end;
            stanzas.push(read_stanza(src, &mut raw, args)?);
        } else if line.len() == FOOTER_LINE && line.starts_with(b"--- ") {
            let mac = exact::<32>(line.get(4..).ok_or(Failure::Header)?)?;
            return Ok(Header {
                covered: range.start.saturating_add(FOOTER.len()),
                raw,
                mac,
                stanzas,
            });
        } else {
            return Err(Failure::Header);
        }
    }
}

/// Starts a canonical header with its version line.
pub(crate) fn start() -> Vec<u8> {
    let mut out = VERSION.to_vec();
    out.push(b'\n');
    out
}

/// Appends a stanza with a body of one short line.
pub(crate) fn push_stanza(out: &mut Vec<u8>, args: &[&str], body: &[u8; BODY]) {
    out.extend_from_slice(STANZA);
    out.extend_from_slice(args.join(" ").as_bytes());
    out.push(b'\n');
    out.extend_from_slice(base64::encode(Form::Unpadded, body).as_bytes());
    out.push(b'\n');
}

/// Appends what the MAC covers after the stanzas.
pub(crate) fn push_footer(out: &mut Vec<u8>) {
    out.extend_from_slice(FOOTER);
}

/// Appends the MAC, which finishes the header.
pub(crate) fn push_mac(out: &mut Vec<u8>, mac: &[u8]) {
    out.push(b' ');
    out.extend_from_slice(base64::encode(Form::Unpadded, mac).as_bytes());
    out.push(b'\n');
}
