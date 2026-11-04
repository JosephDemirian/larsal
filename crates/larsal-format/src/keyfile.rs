//! Key files (spec FMT-18): read every kind, create XML 2.0 key files (LD-31).
//!
//! The content decides the kind, never the file name. Reading is streaming:
//! the XML attempt reads 8,192-byte blocks only as far as its walk goes, and
//! the hashed kind is hashed in pieces, so memory stays flat for any size
//! (D-18-3, AT-A12). Every buffer that held file content is a wiped secret
//! type (FMT-18.26).

use crate::error::{Error, KeyFileReason};
use crate::keys::LockedKey;
use crate::limits::Limits;
use larsal_crypto::hash::{self, Algorithm, Hasher};
use larsal_crypto::random;
use larsal_crypto::secret::{SecretBytes, ct_eq};
use std::io::{ErrorKind, Read, Seek, SeekFrom};

/// The five key file kinds of FMT-18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileKind {
    /// XML document, version 2.0, hex data with a check value.
    Xml2,
    /// XML document, version 1.0, base64 data.
    Xml1,
    /// Exactly 32 bytes, used as they are.
    Raw32,
    /// Exactly 64 hex digits.
    Hex64,
    /// Any other file: SHA-256 of all its bytes.
    Hashed,
}

impl KeyFileKind {
    /// True for the kinds that get the old-format warning (FMT-18.18):
    /// XML 1.0, Raw 32 and Hex 64.
    #[must_use]
    pub fn old_format(self) -> bool {
        matches!(self, Self::Xml1 | Self::Raw32 | Self::Hex64)
    }
}

/// The key file component `F` (32 bytes, secret) and the kind it was read as.
#[derive(Debug)]
pub struct KeyFileKey {
    kind: KeyFileKind,
    /// In locked pages while it lives (APP-11.9).
    pub(crate) key: LockedKey,
}

impl KeyFileKey {
    /// The kind the file was read as.
    #[must_use]
    pub fn kind(&self) -> KeyFileKind {
        self.kind
    }

    /// `F`: always exactly 32 bytes.
    #[must_use]
    pub fn key(&self) -> &SecretBytes {
        &self.key
    }

    /// A second copy of `F` with its kind, in its own locked pages and
    /// wiped on drop: for an open that runs without the lock this key
    /// lives under (F-227).
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            kind: self.kind,
            key: LockedKey::new(SecretBytes::new(self.key().expose().to_vec())),
        }
    }
}

/// Reads a key file and returns `F` with its kind (FMT-18.1): length 0 is
/// an error, then the XML attempt (which may end in a fatal error), then
/// Raw 32, Hex 64, and Hashed for everything else.
///
/// # Errors
/// `KeyFile` with the reason of FMT-18.19; a read or seek failure of `src`
/// is `KeyFile(Io(kind))`, never the vault's `Io`. No error holds file content.
pub fn read_key_file<R: Read + Seek>(mut src: R, limits: &Limits) -> Result<KeyFileKey, Error> {
    read(&mut src, limits).map_err(Error::KeyFile)
}

fn read<R: Read + Seek>(src: &mut R, limits: &Limits) -> Result<KeyFileKey, KeyFileReason> {
    let len = src.seek(SeekFrom::End(0)).map_err(io)?;
    if len == 0 {
        return Err(KeyFileReason::Empty);
    }
    rewind(src)?;
    if let Some(key) = xml::attempt(src, limits)? {
        return Ok(key);
    }
    if len == 32 || len == 64 {
        rewind(src)?;
        let mut raw = SecretBytes::zeroed(if len == 32 { 32 } else { 64 });
        src.read_exact(raw.expose_mut()).map_err(io)?;
        if len == 32 {
            return Ok(KeyFileKey {
                kind: KeyFileKind::Raw32,
                key: LockedKey::new(raw),
            });
        }
        if let Some(key) = hex_decode(raw.expose()) {
            return Ok(KeyFileKey {
                kind: KeyFileKind::Hex64,
                key: LockedKey::new(key),
            });
        }
    }
    hashed(src)
}

/// FMT-18.5: SHA-256 of every byte, read in 16 KiB pieces.
fn hashed<R: Read + Seek>(src: &mut R) -> Result<KeyFileKey, KeyFileReason> {
    rewind(src)?;
    let mut h = Hasher::new(Algorithm::Sha256);
    let mut buf = SecretBytes::zeroed(16 * 1024);
    loop {
        let n = match src.read(buf.expose_mut()) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(e)),
        };
        h.update(buf.expose().get(..n).unwrap_or(&[]));
    }
    Ok(KeyFileKey {
        kind: KeyFileKind::Hashed,
        key: LockedKey::new(h.finalize()),
    })
}

fn rewind<R: Seek>(src: &mut R) -> Result<(), KeyFileReason> {
    src.seek(SeekFrom::Start(0)).map(|_| ()).map_err(io)
}

fn io(e: std::io::Error) -> KeyFileReason {
    KeyFileReason::Io(e.kind())
}

/// The exact 278-byte XML 2.0 layout of FMT-18.20 for `data`.
#[must_use]
pub fn xml2_layout(data: &[u8; 32]) -> SecretBytes {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let check = hash::sha256(&[data]);
    let mut out = Vec::with_capacity(278);
    let hex = |out: &mut Vec<u8>, bytes: &[u8]| {
        for b in bytes {
            out.push(
                UPPER
                    .get(usize::from(b.wrapping_shr(4)))
                    .copied()
                    .unwrap_or(b'0'),
            );
            out.push(UPPER.get(usize::from(b & 15)).copied().unwrap_or(b'0'));
        }
    };
    out.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n    <Meta>\n");
    out.extend_from_slice(b"        <Version>2.0</Version>\n    </Meta>\n    <Key>\n");
    out.extend_from_slice(b"        <Data Hash=\"");
    hex(&mut out, check.expose().get(..4).unwrap_or(&[]));
    out.extend_from_slice(b"\">\n");
    for line in data.chunks(16) {
        out.extend_from_slice(b"            ");
        for (i, group) in line.chunks(4).enumerate() {
            if i > 0 {
                out.push(b' ');
            }
            hex(&mut out, group);
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b"        </Data>\n    </Key>\n</KeyFile>\n");
    SecretBytes::new(out)
}

/// A new XML 2.0 key file with 32 bytes from the OS random source
/// (FMT-18.21, LD-31, AT-B04). The caller writes it to disk (mode 0400,
/// FMT-18.22) and reads it back with [`read_key_file`] (FMT-18.23).
///
/// # Errors
/// [`Error::Io`] with kind `Other` if the OS random source fails.
pub fn create_key_file() -> Result<SecretBytes, Error> {
    let data = random::bytes(32).map_err(|_| Error::Io(ErrorKind::Other))?;
    let data: &[u8; 32] = data
        .expose()
        .try_into()
        .map_err(|_| Error::Io(ErrorKind::Other))?;
    Ok(xml2_layout(data))
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Hex digits to bytes, high nibble first; an odd count decodes as if a `0`
/// stood in front (FMT-18.13). `None` if any byte is not a hex digit.
fn hex_decode(digits: &[u8]) -> Option<SecretBytes> {
    let mut out = SecretBytes::zeroed(digits.len().div_ceil(2));
    let mut hi = (digits.len() & 1 == 1).then_some(0u8);
    let mut slots = out.expose_mut().iter_mut();
    for &d in digits {
        let v = nibble(d)?;
        match hi.take() {
            None => hi = Some(v),
            Some(h) => *slots.next()? = h.wrapping_shl(4) | v,
        }
    }
    Some(out)
}

use crate::buffer::Grow;

/// The key file's XML attempt (FMT-18.6 to FMT-18.17), in its own module
/// because it is most of this file.
mod xml {
    use super::{
        Grow, KeyFileKey, KeyFileKind, KeyFileReason, Limits, SecretBytes, ct_eq, hash, hex_decode,
        io, nibble,
    };
    use crate::limits::Limit;
    use larsal_crypto::base64::{Form, decode_secret};
    use std::collections::{HashMap, HashSet};
    use std::io::{ErrorKind, Read};

    /// A name or namespace value by its SHA-256: tokens are compared by
    /// digest, so the stack and the sets never hold their text (R2-B2).
    type Id = [u8; 32];

    fn id(u: &Units) -> Id {
        let d = hash::sha256(&[u.0.as_slice()]);
        d.expose().try_into().unwrap_or([0; 32])
    }

    fn units_of(s: &str) -> Units {
        let mut u = Units::new();
        s.bytes().for_each(|b| u.push(u16::from(b)));
        u
    }

    /// UTF-16 code units in a wiped buffer (all text here is counted in
    /// code units, FMT-18.7).
    struct Units(Grow);

    impl Units {
        fn new() -> Self {
            Self(Grow::new())
        }
        fn len(&self) -> usize {
            self.0.len / 2
        }
        fn is_empty(&self) -> bool {
            self.0.len == 0
        }
        fn push(&mut self, u: u16) {
            let [a, b] = u.to_le_bytes();
            self.0.push(a);
            self.0.push(b);
        }
        /// One value of the UTF-32 rule of FMT-18.7: below 10000 one unit,
        /// otherwise two (also above 10FFFF), so a code point gives its pair.
        fn push_value(&mut self, v: u32) {
            if v < 0x1_0000 {
                self.push(v as u16);
            } else {
                self.push((v.wrapping_shr(10).wrapping_add(0xD7C0) & 0xFFFF) as u16);
                self.push(((v & 0x3FF) | 0xDC00) as u16);
            }
        }
        fn get(&self, i: usize) -> Option<u16> {
            let at = i.checked_mul(2)?;
            let b = self.0.as_slice().get(at..at.checked_add(2)?)?;
            Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
        }
        fn iter(&self) -> impl Iterator<Item = u16> + '_ {
            self.0
                .as_slice()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_le_bytes(*p))
        }
        fn append(&mut self, other: &Self) {
            for &b in other.0.as_slice() {
                self.0.push(b);
            }
        }
        fn clear(&mut self) {
            self.0.len = 0;
        }
        fn truncate(&mut self, units: usize) {
            self.0.truncate(units.saturating_mul(2));
        }
        fn drain_front(&mut self, units: usize) {
            self.0.drain_front(units.saturating_mul(2));
        }
        fn is(&self, s: &str) -> bool {
            self.len() == s.len() && self.iter().zip(s.bytes()).all(|(u, b)| u == u16::from(b))
        }
        fn is_ignore_case(&self, s: &str) -> bool {
            self.len() == s.len()
                && self
                    .iter()
                    .zip(s.bytes())
                    .all(|(u, b)| u8::try_from(u).is_ok_and(|c| c.eq_ignore_ascii_case(&b)))
        }
        fn starts_with(&self, s: &str) -> bool {
            self.len() >= s.len() && self.iter().zip(s.bytes()).all(|(u, b)| u == u16::from(b))
        }
        /// The units from `from` on, as a new buffer.
        fn tail(&self, from: usize) -> Self {
            let mut out = Self::new();
            for u in self.iter().skip(from) {
                out.push(u);
            }
            out
        }
        fn copy(&self) -> Self {
            self.tail(0)
        }
        fn lossy(&self) -> String {
            char::decode_utf16(self.iter())
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
    }

    /// Why the walk stopped early: a parse problem (the file falls back) or
    /// a fatal key file error.
    enum Stop {
        Parse,
        Fatal(KeyFileReason),
    }

    impl From<KeyFileReason> for Stop {
        fn from(r: KeyFileReason) -> Self {
            Self::Fatal(r)
        }
    }

    /// The eight decoders of FMT-18.7 (LD-32). UTF-16 and UTF-32 without a
    /// suffix are the generic decoders, which take the byte order from a mark.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Enc {
        Utf8,
        Utf16,
        Utf16Le,
        Utf16Be,
        Utf32,
        Utf32Le,
        Utf32Be,
        Latin1,
    }

    /// The *Detection* table of FMT-18.7.
    fn detect(b: &[u8]) -> Enc {
        if b.starts_with(&[0xFF, 0xFE, 0, 0]) || b.starts_with(&[0, 0, 0xFE, 0xFF]) {
            Enc::Utf32
        } else if b.starts_with(&[0x3C, 0, 0, 0]) {
            Enc::Utf32Le
        } else if b.starts_with(&[0, 0, 0, 0x3C]) {
            Enc::Utf32Be
        } else if b.starts_with(&[0xFF, 0xFE]) || b.starts_with(&[0xFE, 0xFF]) {
            Enc::Utf16
        } else if b.starts_with(&[0x3C, 0]) {
            Enc::Utf16Le
        } else if b.starts_with(&[0, 0x3C]) {
            Enc::Utf16Be
        } else {
            Enc::Utf8
        }
    }

    /// A declared encoding name (FMT-18.7 *Names*): the EncName check first,
    /// then case folded with every non-alphanumeric character dropped.
    fn enc_by_name(name: &Units) -> Option<Enc> {
        let mut folded = String::new();
        for (i, u) in name.iter().enumerate() {
            let c = char::from_u32(u32::from(u)).filter(char::is_ascii)?;
            let ok =
                c.is_ascii_alphabetic() || (i > 0 && (c.is_ascii_digit() || "._-".contains(c)));
            if !ok {
                return None;
            }
            if c.is_ascii_alphanumeric() {
                folded.push(c.to_ascii_lowercase());
            }
        }
        match folded.as_str() {
            "utf8" => Some(Enc::Utf8),
            "utf16" => Some(Enc::Utf16),
            "utf16le" => Some(Enc::Utf16Le),
            "utf16be" => Some(Enc::Utf16Be),
            "utf32" => Some(Enc::Utf32),
            "utf32le" => Some(Enc::Utf32Le),
            "utf32be" => Some(Enc::Utf32Be),
            "iso88591" | "latin1" => Some(Enc::Latin1),
            _ => None,
        }
    }

    /// One decoder with its state across blocks.
    struct Decoder {
        enc: Enc,
        started: bool,
        big: bool,
        /// Bytes of a UTF-16 or UTF-32 unit not complete yet.
        pend: SecretBytes,
        npend: usize,
        /// UTF-8: bytes still needed, the allowed range of the next one, and
        /// the code point so far.
        need: u8,
        lo: u8,
        hi: u8,
        cp: u32,
    }

    impl Decoder {
        fn new(enc: Enc) -> Self {
            Self {
                enc,
                started: false,
                big: false,
                pend: SecretBytes::zeroed(4),
                npend: 0,
                need: 0,
                lo: 0x80,
                hi: 0xBF,
                cp: 0,
            }
        }

        /// Decodes the next bytes of the stream into `out`. True when an
        /// invalid byte sequence was found (only UTF-8 has them).
        fn feed(&mut self, mut b: &[u8], out: &mut Units) -> bool {
            if !self.started {
                self.started = true;
                let (mark, big): (&[u8], bool) = match self.enc {
                    Enc::Utf8 => (&[0xEF, 0xBB, 0xBF], false),
                    Enc::Utf16Le => (&[0xFF, 0xFE], false),
                    Enc::Utf16Be => (&[0xFE, 0xFF], true),
                    Enc::Utf32Le => (&[0xFF, 0xFE, 0, 0], false),
                    Enc::Utf32Be => (&[0, 0, 0xFE, 0xFF], true),
                    Enc::Utf16 if b.starts_with(&[0xFE, 0xFF]) => (&[0xFE, 0xFF], true),
                    Enc::Utf16 => (&[0xFF, 0xFE], false),
                    Enc::Utf32 if b.starts_with(&[0, 0, 0xFE, 0xFF]) => (&[0, 0, 0xFE, 0xFF], true),
                    Enc::Utf32 => (&[0xFF, 0xFE, 0, 0], false),
                    Enc::Latin1 => (&[], false),
                };
                self.big = big;
                if let Some(rest) = b.strip_prefix(mark) {
                    b = rest;
                }
            }
            match self.enc {
                Enc::Utf8 => self.utf8(b, out),
                Enc::Latin1 => {
                    for &x in b {
                        out.push(u16::from(x));
                    }
                    false
                }
                Enc::Utf16 | Enc::Utf16Le | Enc::Utf16Be => self.wide(b, 2, out),
                Enc::Utf32 | Enc::Utf32Le | Enc::Utf32Be => self.wide(b, 4, out),
            }
        }

        fn wide(&mut self, b: &[u8], width: usize, out: &mut Units) -> bool {
            for &x in b {
                if let Some(slot) = self.pend.expose_mut().get_mut(self.npend) {
                    *slot = x;
                }
                self.npend = self.npend.saturating_add(1);
                if self.npend == width {
                    self.npend = 0;
                    let p = self.pend.expose();
                    let at = |i: usize| u32::from(p.get(i).copied().unwrap_or(0));
                    let v = match (width, self.big) {
                        (2, false) => at(0) | at(1).wrapping_shl(8),
                        (2, true) => at(1) | at(0).wrapping_shl(8),
                        (_, false) => {
                            at(0)
                                | at(1).wrapping_shl(8)
                                | at(2).wrapping_shl(16)
                                | at(3).wrapping_shl(24)
                        }
                        (_, true) => {
                            at(3)
                                | at(2).wrapping_shl(8)
                                | at(1).wrapping_shl(16)
                                | at(0).wrapping_shl(24)
                        }
                    };
                    // UTF-16 gives each unit as it is; UTF-32 by the value rule.
                    if width == 2 {
                        out.push(v as u16);
                    } else {
                        out.push_value(v);
                    }
                }
            }
            false
        }

        /// Strict UTF-8 (RFC 3629). A sequence cut by the end of the input
        /// stays pending and is not an error; one split between two blocks
        /// is completed by the next block.
        fn utf8(&mut self, b: &[u8], out: &mut Units) -> bool {
            let mut invalid = false;
            let mut i = 0usize;
            while let Some(&x) = b.get(i) {
                if self.need > 0 {
                    if (self.lo..=self.hi).contains(&x) {
                        self.cp = self.cp.wrapping_shl(6) | u32::from(x & 0x3F);
                        self.need = self.need.saturating_sub(1);
                        self.lo = 0x80;
                        self.hi = 0xBF;
                        if self.need == 0 {
                            out.push_value(self.cp);
                        }
                        i = i.saturating_add(1);
                    } else {
                        // Bad continuation: replace, then read this byte again as a start.
                        invalid = true;
                        out.push(0xFFFD);
                        self.need = 0;
                    }
                    continue;
                }
                let (need, lo, hi, bits) = match x {
                    0x00..=0x7F => (0, 0x80, 0xBF, x),
                    0xC2..=0xDF => (1, 0x80, 0xBF, x & 0x1F),
                    0xE0 => (2, 0xA0, 0xBF, x & 0x0F),
                    0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF, x & 0x0F),
                    0xED => (2, 0x80, 0x9F, x & 0x0F),
                    0xF0 => (3, 0x90, 0xBF, x & 0x07),
                    0xF1..=0xF3 => (3, 0x80, 0xBF, x & 0x07),
                    0xF4 => (3, 0x80, 0x8F, x & 0x07),
                    _ => {
                        invalid = true;
                        out.push(0xFFFD);
                        i = i.saturating_add(1);
                        continue;
                    }
                };
                if need == 0 {
                    out.push(u16::from(x));
                } else {
                    (self.need, self.lo, self.hi, self.cp) = (need, lo, hi, u32::from(bits));
                }
                i = i.saturating_add(1);
            }
            invalid
        }
    }

    const BLOCK: usize = 8192;

    /// The input as decoded text, taken in block by block (FMT-18.7
    /// *Invalid byte sequences*). `text` holds the units from `base` on;
    /// positions are absolute unit indexes.
    struct Input<'r, R> {
        src: &'r mut R,
        done: bool,
        dec: Decoder,
        text: Units,
        base: usize,
        pos: usize,
        /// Raw bytes of the last block taken in, for a decoder switch.
        raw: SecretBytes,
        raw_len: usize,
        /// Where the last block's text starts.
        cur_start: usize,
        /// The decoding now in use found an invalid sequence in the last block.
        cur_invalid: bool,
        /// While the declaration is read, the block check waits (step 5 of
        /// *Switching the decoder*).
        defer: bool,
    }

    impl<'r, R: Read> Input<'r, R> {
        fn new(src: &'r mut R) -> Result<Self, Stop> {
            let mut inp = Self {
                src,
                done: false,
                dec: Decoder::new(Enc::Utf8),
                text: Units::new(),
                base: 0,
                pos: 0,
                raw: SecretBytes::zeroed(BLOCK),
                raw_len: 0,
                cur_start: 0,
                cur_invalid: false,
                defer: true,
            };
            inp.fill_raw()?;
            inp.dec = Decoder::new(detect(inp.raw.expose().get(..inp.raw_len).unwrap_or(&[])));
            let raw = inp.raw.expose().get(..inp.raw_len).unwrap_or(&[]);
            inp.cur_invalid = inp.dec.feed(raw, &mut inp.text);
            Ok(inp)
        }

        /// Reads the next block (up to 8,192 bytes) into `raw`.
        fn fill_raw(&mut self) -> Result<(), Stop> {
            let mut n = 0usize;
            while n < BLOCK {
                let buf = self.raw.expose_mut().get_mut(n..).unwrap_or(&mut []);
                match self.src.read(buf) {
                    Ok(0) => {
                        self.done = true;
                        break;
                    }
                    Ok(k) => n = n.saturating_add(k),
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(Stop::Fatal(io(e))),
                }
            }
            self.raw_len = n;
            Ok(())
        }

        /// Takes in the next block; false at the end of the input.
        fn load(&mut self) -> Result<bool, Stop> {
            if self.done {
                return Ok(false);
            }
            self.fill_raw()?;
            if self.raw_len == 0 {
                return Ok(false);
            }
            self.cur_start = self.base.saturating_add(self.text.len());
            let raw = self.raw.expose().get(..self.raw_len).unwrap_or(&[]);
            self.cur_invalid = self.dec.feed(raw, &mut self.text);
            if self.cur_invalid && !self.defer {
                return Err(Stop::Parse);
            }
            Ok(true)
        }

        /// The unit `k` places after the position; `None` at the end.
        fn unit(&mut self, k: usize) -> Result<Option<u16>, Stop> {
            let want = self.pos.saturating_add(k);
            while want >= self.base.saturating_add(self.text.len()) {
                if !self.load()? {
                    return Ok(None);
                }
            }
            Ok(self.text.get(want.saturating_sub(self.base)))
        }

        /// Moves on `n` units and drops text that is no longer needed. While
        /// the declaration is read, the current block's text stays whole for
        /// a decoder switch; text before it is dropped (Checker R2-B2).
        fn bump(&mut self, n: usize) {
            self.pos = self.pos.saturating_add(n);
            let keep = if self.defer {
                self.pos.min(self.cur_start)
            } else {
                self.pos
            };
            let used = keep.saturating_sub(self.base);
            if used > 65_536 {
                self.text.drain_front(used);
                self.base = keep;
            }
        }

        /// A declared encoding takes over (FMT-18.7 *Switching the decoder*):
        /// UTF-8 adds its decoding of the current block after the old text;
        /// every other decoder replaces the block's text, and parsing goes on
        /// at the same unit offset `P` in the new text.
        fn switch(&mut self, enc: Enc) {
            let mut d = Decoder::new(enc);
            let raw = self.raw.expose().get(..self.raw_len).unwrap_or(&[]);
            if enc == Enc::Utf8 {
                self.cur_invalid = d.feed(raw, &mut self.text);
            } else {
                let p = self.pos.saturating_sub(self.cur_start);
                self.text.truncate(self.cur_start.saturating_sub(self.base));
                self.cur_invalid = d.feed(raw, &mut self.text);
                self.pos = self.cur_start.saturating_add(p);
            }
            self.dec = d;
        }
    }

    const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
    const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Ver {
        V1,
        V2,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Look {
        Meta,
        Key,
    }

    /// The local names the walk cares about (FMT-18.8, exact case).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Known {
        KeyFile,
        Meta,
        Key,
        Version,
        Data,
        Other,
    }

    struct Tag {
        kind: Known,
        empty: bool,
        hash: Option<Units>,
    }

    struct Elem {
        name: Id,
        scope_len: usize,
    }

    /// One namespace declaration of a start tag, judged after the tag's
    /// last attribute (FMT-18.6).
    struct Decl {
        prefix: Option<Id>,
        prefix_xmlns: bool,
        prefix_xml: bool,
        uri: Id,
        uri_xml: bool,
        uri_xmlns: bool,
        uri_empty: bool,
    }

    enum Ref {
        Char(u32),
        Undeclared,
        Broken,
    }

    fn is_ws(u: u16) -> bool {
        matches!(u, 0x20 | 0x09 | 0x0D | 0x0A)
    }

    /// A character XML allows (XML 1.0 Char), with unpaired surrogates
    /// allowed as ordinary characters (FMT-18.6 exception 2).
    fn allowed(u: u16) -> bool {
        matches!(u, 0x09 | 0x0A | 0x0D | 0x20..=0xFFFD)
    }

    /// XML 1.0 Char, for character references (no surrogates there).
    fn xml_char(v: u32) -> bool {
        matches!(v, 0x09 | 0x0A | 0x0D | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x1_0000..=0x10_FFFF)
    }

    fn name_start(c: u32) -> bool {
        matches!(c,
            0x3A | 0x41..=0x5A | 0x5F | 0x61..=0x7A | 0xC0..=0xD6 | 0xD8..=0xF6 | 0xF8..=0x2FF
            | 0x370..=0x37D | 0x37F..=0x1FFF | 0x200C..=0x200D | 0x2070..=0x218F
            | 0x2C00..=0x2FEF | 0x3001..=0xD7FF | 0xF900..=0xFDCF | 0xFDF0..=0xFFFD
            | 0x1_0000..=0xE_FFFF)
    }

    fn name_char(c: u32) -> bool {
        name_start(c)
            || matches!(c, 0x2D | 0x2E | 0x30..=0x39 | 0xB7 | 0x300..=0x36F | 0x203F..=0x2040)
    }

    /// Whitespace removed from a `Data` text (FMT-18.11).
    fn data_space(u: u16) -> bool {
        matches!(u,
            0x09..=0x0D | 0x20 | 0x85 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029
            | 0x202F | 0x205F | 0x3000)
    }

    /// Where a qualified name has its colon; a parse problem for two colons,
    /// an empty prefix or an empty local part (Namespaces in XML).
    fn qname_colon(name: &Units) -> Result<Option<usize>, Stop> {
        let mut colon = None;
        for (i, u) in name.iter().enumerate() {
            if u == u16::from(b':') {
                if colon.is_some() || i == 0 || i.saturating_add(1) == name.len() {
                    return Err(Stop::Parse);
                }
                colon = Some(i);
            }
        }
        Ok(colon)
    }

    fn split(name: &Units, colon: Option<usize>) -> (Option<Units>, Units) {
        match colon {
            None => (None, name.copy()),
            Some(c) => {
                let mut p = name.copy();
                p.truncate(c);
                (Some(p), name.tail(c.saturating_add(1)))
            }
        }
    }

    struct Parser<'r, 'l, R> {
        inp: Input<'r, R>,
        limits: &'l Limits,
        stack: Vec<Elem>,
        /// Prefix bindings in scope: each prefix's namespace values, innermost
        /// last, and the order they were bound in, for unbinding at end tags.
        scope: HashMap<Id, Vec<Id>>,
        scope_log: Vec<Id>,
        xml_ns: Id,
        /// The root is `KeyFile`: from here an over-long token is fatal.
        in_keyfile: bool,
        /// The prolog held a DOCTYPE.
        doctype: bool,
        /// The last start tag was an empty-element tag: its end tag is next.
        empty_end: bool,
        version: Option<Ver>,
        data: Option<SecretBytes>,
    }

    /// Runs the XML attempt: `Some` key, `None` for "not an XML key file",
    /// or a fatal key file error.
    pub(super) fn attempt<R: Read>(
        src: &mut R,
        limits: &Limits,
    ) -> Result<Option<KeyFileKey>, KeyFileReason> {
        let inp = match Input::new(src) {
            Ok(inp) => inp,
            Err(Stop::Parse) => return Ok(None),
            Err(Stop::Fatal(r)) => return Err(r),
        };
        let mut p = Parser {
            inp,
            limits,
            stack: Vec::new(),
            scope: HashMap::new(),
            scope_log: Vec::new(),
            xml_ns: id(&units_of(XML_NS)),
            in_keyfile: false,
            doctype: false,
            empty_end: false,
            version: None,
            data: None,
        };
        match p.run() {
            Ok(()) => Ok(p.finish()),
            Err(Stop::Parse) => Ok(None),
            Err(Stop::Fatal(r)) => Err(r),
        }
    }

    impl<R: Read> Parser<'_, '_, R> {
        fn run(&mut self) -> Result<(), Stop> {
            self.declaration()?;
            self.inp.defer = false;
            if self.inp.cur_invalid {
                return Err(Stop::Parse);
            }
            self.doctype = self.prolog()?;
            let root = self.start_tag(None)?;
            self.empty_end = root.empty;
            self.walk()
        }

        /// FMT-18.16: a key only with no parse problem and non-empty data.
        fn finish(&mut self) -> Option<KeyFileKey> {
            let data = self.data.take().filter(|d| !d.is_empty())?;
            let mut key = SecretBytes::zeroed(32);
            for (k, d) in key.expose_mut().iter_mut().zip(data.expose()) {
                *k = *d;
            }
            let kind = match self.version {
                Some(Ver::V1) => KeyFileKind::Xml1,
                _ => KeyFileKind::Xml2,
            };
            Some(KeyFileKey {
                kind,
                key: crate::keys::LockedKey::new(key),
            })
        }

        // ----- reading helpers -----

        fn peek(&mut self, k: usize) -> Result<Option<u16>, Stop> {
            self.inp.unit(k)
        }

        fn is(&mut self, k: usize, c: u8) -> Result<bool, Stop> {
            Ok(self.peek(k)? == Some(u16::from(c)))
        }

        fn starts(&mut self, s: &str) -> Result<bool, Stop> {
            for (k, b) in s.bytes().enumerate() {
                if !self.is(k, b)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn bump(&mut self, n: usize) {
            self.inp.bump(n);
        }

        fn expect(&mut self, c: u8) -> Result<(), Stop> {
            if self.is(0, c)? {
                self.bump(1);
                Ok(())
            } else {
                Err(Stop::Parse)
            }
        }

        fn skip_ws(&mut self) -> Result<usize, Stop> {
            let mut n = 0usize;
            while self.peek(0)?.is_some_and(is_ws) {
                self.bump(1);
                n = n.saturating_add(1);
            }
            Ok(n)
        }

        /// The character at `k`: a surrogate pair joins into one code point;
        /// an unpaired surrogate stays a unit of its own.
        fn char_at(&mut self, k: usize) -> Result<Option<(u32, usize)>, Stop> {
            let Some(u) = self.peek(k)? else {
                return Ok(None);
            };
            if (0xD800..=0xDBFF).contains(&u)
                && let Some(lo) = self.peek(k.saturating_add(1))?
                && (0xDC00..=0xDFFF).contains(&lo)
            {
                let c = 0x1_0000u32
                    .wrapping_add(u32::from(u.wrapping_sub(0xD800)).wrapping_shl(10))
                    .wrapping_add(u32::from(lo.wrapping_sub(0xDC00)));
                return Ok(Some((c, 2)));
            }
            Ok(Some((u32::from(u), 1)))
        }

        /// An over-long token, naming `which` limit: fatal inside a
        /// `KeyFile` document, a parse problem (the file falls back) before
        /// the root is known (R2-B2).
        fn too_long(&self, which: Limit) -> Stop {
            if self.in_keyfile {
                Stop::Fatal(KeyFileReason::TooLarge(which))
            } else {
                Stop::Parse
            }
        }

        /// An XML Name of at most the key file text limit; false (nothing
        /// read) when no name starts here.
        fn read_name(&mut self, out: &mut Units) -> Result<bool, Stop> {
            match self.char_at(0)? {
                Some((c, n)) if name_start(c) => {
                    out.push_value(c);
                    self.bump(n);
                }
                _ => return Ok(false),
            }
            while let Some((c, n)) = self.char_at(0)?.filter(|(c, _)| name_char(*c)) {
                out.push_value(c);
                self.bump(n);
                if out.len() > self.limits.key_file_text {
                    return Err(self.too_long(Limit::KeyFileAttributes));
                }
            }
            Ok(true)
        }

        // ----- document start -----

        /// The XML declaration at the very start (FMT-18.7 *Declaration
        /// syntax*), then each declared encoding in the order written.
        fn declaration(&mut self) -> Result<(), Stop> {
            if !self.starts("<?")? {
                return Ok(());
            }
            // The target is `xml` in some case, and not a longer name such
            // as `xml-stylesheet` (that is an ordinary processing instruction).
            let mut letters = [0u16; 3];
            for (k, slot) in letters.iter_mut().enumerate() {
                *slot = self.peek(k.saturating_add(2))?.unwrap_or(0);
            }
            let xml_any_case = letters
                .iter()
                .zip(b"xml")
                .all(|(u, b)| u8::try_from(*u).is_ok_and(|c| c.eq_ignore_ascii_case(b)));
            if !xml_any_case || self.char_at(5)?.is_some_and(|(c, _)| name_char(c)) {
                return Ok(());
            }
            if letters != [0x78, 0x6D, 0x6C] {
                return Err(Stop::Parse);
            }
            self.bump(5);
            // 0: version next; 1: encodings or standalone; 2: standalone only.
            let mut stage = 0u8;
            let mut encs = Vec::new();
            loop {
                let ws = self.skip_ws()?;
                if self.starts("?>")? {
                    self.bump(2);
                    break;
                }
                let mut name = Units::new();
                if ws == 0 || !self.read_name(&mut name)? {
                    return Err(Stop::Parse);
                }
                self.skip_ws()?;
                self.expect(b'=')?;
                self.skip_ws()?;
                let value = self.decl_value()?;
                if stage == 0 && name.is("version") && value.is("1.0") {
                    stage = 1;
                } else if stage == 1 && name.is("encoding") {
                    encs.push(enc_by_name(&value).ok_or(Stop::Parse)?);
                } else if stage >= 1 && name.is("standalone") && (value.is("yes") || value.is("no"))
                {
                    stage = 2;
                } else {
                    return Err(Stop::Parse);
                }
            }
            if stage == 0 {
                return Err(Stop::Parse);
            }
            for enc in encs {
                if enc != self.inp.dec.enc {
                    self.inp.switch(enc);
                }
            }
            Ok(())
        }

        fn decl_value(&mut self) -> Result<Units, Stop> {
            let q = self
                .peek(0)?
                .filter(|&u| u == 0x22 || u == 0x27)
                .ok_or(Stop::Parse)?;
            self.bump(1);
            let mut v = Units::new();
            loop {
                match self.peek(0)? {
                    None => return Err(Stop::Parse),
                    Some(u) if u == q => {
                        self.bump(1);
                        return Ok(v);
                    }
                    Some(u) => {
                        v.push(u);
                        self.bump(1);
                        if v.len() > self.limits.key_file_text {
                            return Err(self.too_long(Limit::KeyFileAttributes));
                        }
                    }
                }
            }
        }

        /// Everything before the root element; true if it held a DOCTYPE.
        fn prolog(&mut self) -> Result<bool, Stop> {
            let mut doctype = false;
            loop {
                self.skip_ws()?;
                if !self.is(0, b'<')? {
                    return Err(Stop::Parse);
                }
                if self.starts("<?")? {
                    self.pi()?;
                } else if self.starts("<!--")? {
                    self.comment()?;
                } else if self.starts("<!DOCTYPE")? && !doctype {
                    self.doctype()?;
                    doctype = true;
                } else if self.starts("<!")? || self.starts("</")? {
                    return Err(Stop::Parse);
                } else {
                    return Ok(doctype);
                }
            }
        }

        /// Skips a DOCTYPE without processing it, in constant memory
        /// (FMT-18.17, LD-30): quotes, an internal subset, and comments and
        /// processing instructions inside it.
        fn doctype(&mut self) -> Result<(), Stop> {
            self.bump(9);
            let mut name = Units::new();
            if self.skip_ws()? == 0 || !self.read_name(&mut name)? {
                return Err(Stop::Parse);
            }
            let mut quote: Option<u16> = None;
            let mut subset = false;
            let mut decl = false; // inside a markup declaration of the subset
            loop {
                let u = self.peek(0)?.ok_or(Stop::Parse)?;
                if !allowed(u) {
                    return Err(Stop::Parse);
                }
                if let Some(q) = quote {
                    if u == q {
                        quote = None;
                    }
                    self.bump(1);
                    continue;
                }
                match u {
                    0x22 | 0x27 => quote = Some(u),
                    0x3C if subset && !decl => {
                        if self.starts("<!--")? {
                            self.comment()?;
                            continue;
                        }
                        if self.starts("<?")? {
                            self.pi()?;
                            continue;
                        }
                        if !self.starts("<!")? {
                            return Err(Stop::Parse);
                        }
                        decl = true;
                    }
                    0x3E if decl => decl = false,
                    0x5B if !subset => subset = true,
                    0x5D if subset && !decl => subset = false,
                    0x3E if !subset => {
                        self.bump(1);
                        return Ok(());
                    }
                    _ => {}
                }
                self.bump(1);
            }
        }

        fn comment(&mut self) -> Result<(), Stop> {
            self.bump(4);
            loop {
                match self.peek(0)? {
                    None => return Err(Stop::Parse),
                    Some(0x2D) if self.is(1, b'-')? => {
                        if self.is(2, b'>')? {
                            self.bump(3);
                            return Ok(());
                        }
                        return Err(Stop::Parse);
                    }
                    Some(u) if allowed(u) => self.bump(1),
                    Some(_) => return Err(Stop::Parse),
                }
            }
        }

        /// A processing instruction: a target without a colon that is not
        /// `xml` in any case (only the declaration may use it).
        fn pi(&mut self) -> Result<(), Stop> {
            self.bump(2);
            let mut target = Units::new();
            if !self.read_name(&mut target)?
                || target.iter().any(|u| u == u16::from(b':'))
                || target.is_ignore_case("xml")
            {
                return Err(Stop::Parse);
            }
            if self.starts("?>")? {
                self.bump(2);
                return Ok(());
            }
            if self.skip_ws()? == 0 {
                return Err(Stop::Parse);
            }
            loop {
                if self.starts("?>")? {
                    self.bump(2);
                    return Ok(());
                }
                match self.peek(0)? {
                    Some(u) if allowed(u) => self.bump(1),
                    _ => return Err(Stop::Parse),
                }
            }
        }

        /// A reference at `&`: a character, one of the five predefined ones,
        /// an undeclared entity, or a broken reference.
        fn reference(&mut self) -> Result<Ref, Stop> {
            self.bump(1);
            if self.is(0, b'#')? {
                self.bump(1);
                let hex = self.is(0, b'x')?;
                if hex {
                    self.bump(1);
                }
                let radix = if hex { 16 } else { 10 };
                let mut v: u32 = 0;
                let mut digits = 0usize;
                loop {
                    let u = self.peek(0)?;
                    let d = u
                        .and_then(|u| char::from_u32(u32::from(u)))
                        .and_then(|c| c.to_digit(radix));
                    match (d, u) {
                        (Some(d), _) => {
                            v = v.saturating_mul(radix).saturating_add(d).min(0x11_0000);
                            digits = digits.saturating_add(1);
                            self.bump(1);
                        }
                        (None, Some(0x3B)) if digits > 0 => {
                            self.bump(1);
                            break;
                        }
                        _ => return Ok(Ref::Broken),
                    }
                }
                return Ok(if xml_char(v) {
                    Ref::Char(v)
                } else {
                    Ref::Broken
                });
            }
            let mut name = Units::new();
            if !self.read_name(&mut name)? || !self.is(0, b';')? {
                return Ok(Ref::Broken);
            }
            self.bump(1);
            let c = [
                ("lt", '<'),
                ("gt", '>'),
                ("amp", '&'),
                ("apos", '\''),
                ("quot", '"'),
            ]
            .iter()
            .find(|(n, _)| name.is(n))
            .map(|(_, c)| *c);
            Ok(c.map_or(Ref::Undeclared, |c| Ref::Char(u32::from(c))))
        }

        /// An attribute value; kept in `keep` when given, with `limit` units
        /// at most (D-18-3: more is fatal, naming `which`).
        fn attr_value(
            &mut self,
            mut keep: Option<&mut Units>,
            limit: usize,
            which: Limit,
        ) -> Result<(), Stop> {
            let q = self
                .peek(0)?
                .filter(|&u| u == 0x22 || u == 0x27)
                .ok_or(Stop::Parse)?;
            self.bump(1);
            loop {
                let u = self.peek(0)?.ok_or(Stop::Parse)?;
                if u == q {
                    self.bump(1);
                    return Ok(());
                }
                if u == 0x3C || !allowed(u) {
                    return Err(Stop::Parse);
                }
                if u == 0x26 {
                    match self.reference()? {
                        Ref::Char(c) => {
                            if let Some(k) = keep.as_deref_mut() {
                                k.push_value(c);
                            }
                        }
                        _ => return Err(Stop::Parse),
                    }
                } else {
                    if let Some(k) = keep.as_deref_mut() {
                        k.push(u);
                    }
                    self.bump(1);
                }
                if keep.as_deref().is_some_and(|k| k.len() > limit) {
                    return Err(self.too_long(which));
                }
            }
        }

        /// The namespace value bound to a prefix now, by digest.
        fn lookup(&self, prefix: &Id) -> Option<Id> {
            self.scope.get(prefix).and_then(|v| v.last()).copied()
        }

        fn unbind_to(&mut self, len: usize) {
            while self.scope_log.len() > len {
                let Some(p) = self.scope_log.pop() else {
                    break;
                };
                if let Some(v) = self.scope.get_mut(&p) {
                    v.pop();
                    if v.is_empty() {
                        self.scope.remove(&p);
                    }
                }
            }
        }

        /// A start tag at `<`, with the namespace checks of FMT-18.6.
        /// `look` is the walk's look, which decides whether a `Data` tag's
        /// `Hash` attribute is taken. The root's name is judged before its
        /// attributes are read: any other root falls back at once (FMT-18.8),
        /// and a `KeyFile` root after a DOCTYPE is fatal (FMT-18.17, LD-30).
        /// Attribute names, expanded names and prefix bindings are kept by
        /// digest in hashed sets, at most `key_file_attributes` per tag
        /// (Checker R2-B1).
        fn start_tag(&mut self, look: Option<Look>) -> Result<Tag, Stop> {
            self.bump(1);
            let mut name = Units::new();
            if !self.read_name(&mut name)? {
                return Err(Stop::Parse);
            }
            let colon = qname_colon(&name)?;
            let (prefix, local) = split(&name, colon);
            let kind = [
                ("KeyFile", Known::KeyFile),
                ("Meta", Known::Meta),
                ("Key", Known::Key),
                ("Version", Known::Version),
                ("Data", Known::Data),
            ]
            .iter()
            .find(|(n, _)| local.is(n))
            .map_or(Known::Other, |(_, k)| *k);
            if self.stack.is_empty() {
                if kind != Known::KeyFile {
                    return Err(Stop::Parse);
                }
                if self.doctype {
                    return Err(Stop::Fatal(KeyFileReason::Dtd));
                }
                self.in_keyfile = true;
            }
            let name_id = id(&name);
            let prefix_bad = prefix.as_ref().is_some_and(|p| p.is("xmlns"));
            let prefix_id = prefix.as_ref().filter(|p| !p.is("xml")).map(id);
            drop((name, prefix, local));
            let want_hash = look == Some(Look::Key) && kind == Known::Data;
            let limit = self.limits.key_file_text;
            let mut written: HashSet<Id> = HashSet::new();
            // Prefixed attributes: (prefix digest, or None for `xml`; local digest).
            let mut prefixed: Vec<(Option<Id>, Id)> = Vec::new();
            let mut decls: Vec<Decl> = Vec::new();
            let mut count = 0usize;
            let mut hash = None;
            let empty = loop {
                let ws = self.skip_ws()?;
                if self.is(0, b'>')? {
                    self.bump(1);
                    break false;
                }
                if self.starts("/>")? {
                    self.bump(2);
                    break true;
                }
                count = count.saturating_add(1);
                if count > self.limits.key_file_attributes {
                    return Err(self.too_long(Limit::KeyFileAttributes));
                }
                let mut an = Units::new();
                if ws == 0 || !self.read_name(&mut an)? {
                    return Err(Stop::Parse);
                }
                let acolon = qname_colon(&an)?;
                self.skip_ws()?;
                self.expect(b'=')?;
                self.skip_ws()?;
                if an.is("xmlns") || an.starts_with("xmlns:") {
                    // Namespace declarations may repeat (FMT-18.6 exception 1).
                    let mut uri = Units::new();
                    // A namespace value is a token of LD-83.
                    self.attr_value(Some(&mut uri), limit, Limit::KeyFileAttributes)?;
                    let p = acolon.map(|c| an.tail(c.saturating_add(1)));
                    decls.push(Decl {
                        prefix: p.as_ref().map(id),
                        prefix_xmlns: p.as_ref().is_some_and(|p| p.is("xmlns")),
                        prefix_xml: p.as_ref().is_some_and(|p| p.is("xml")),
                        uri: id(&uri),
                        uri_xml: uri.is(XML_NS),
                        uri_xmlns: uri.is(XMLNS_NS),
                        uri_empty: uri.is_empty(),
                    });
                    continue;
                }
                if !written.insert(id(&an)) {
                    return Err(Stop::Parse);
                }
                if let (Some(p), l) = split(&an, acolon) {
                    prefixed.push(((!p.is("xml")).then(|| id(&p)), id(&l)));
                }
                if want_hash && an.is("Hash") {
                    let mut v = Units::new();
                    // The `Hash` text is a key file text of D-18-3.
                    self.attr_value(Some(&mut v), limit, Limit::KeyFileText)?;
                    hash = Some(v);
                } else {
                    self.attr_value(None, limit, Limit::KeyFileText)?;
                }
            };
            let scope_len = self.scope_log.len();
            for d in decls {
                let reserved = d.uri_xml || d.uri_xmlns;
                match d.prefix {
                    None if reserved => return Err(Stop::Parse),
                    None => {}
                    Some(p) => {
                        let bad = if d.prefix_xmlns {
                            true
                        } else if d.prefix_xml {
                            !d.uri_xml
                        } else {
                            reserved || d.uri_empty
                        };
                        if bad {
                            return Err(Stop::Parse);
                        }
                        self.scope.entry(p).or_default().push(d.uri);
                        self.scope_log.push(p);
                    }
                }
            }
            if prefix_bad || prefix_id.is_some_and(|p| self.lookup(&p).is_none()) {
                return Err(Stop::Parse);
            }
            let mut expanded: HashSet<(Id, Id)> = HashSet::new();
            for (p, l) in prefixed {
                let uri = match p {
                    None => self.xml_ns,
                    Some(p) => self.lookup(&p).ok_or(Stop::Parse)?,
                };
                if !expanded.insert((uri, l)) {
                    return Err(Stop::Parse);
                }
            }
            self.stack.push(Elem {
                name: name_id,
                scope_len,
            });
            if self.stack.len() > self.limits.key_file_depth {
                return Err(Stop::Fatal(KeyFileReason::TooLarge(Limit::KeyFileDepth)));
            }
            Ok(Tag { kind, empty, hash })
        }

        /// An end tag at `</`: its written name must equal the start tag's.
        fn end_tag(&mut self) -> Result<(), Stop> {
            self.bump(2);
            let mut name = Units::new();
            if !self.read_name(&mut name)? {
                return Err(Stop::Parse);
            }
            self.skip_ws()?;
            self.expect(b'>')?;
            let name = id(&name);
            match self.stack.pop() {
                Some(top) if top.name == name => {
                    self.unbind_to(top.scope_len);
                    Ok(())
                }
                _ => Err(Stop::Parse),
            }
        }

        fn pop_empty(&mut self) {
            self.empty_end = false;
            if let Some(top) = self.stack.pop() {
                self.unbind_to(top.scope_len);
            }
        }

        // ----- the walk (FMT-18.9) -----

        /// One move: skips text, comments, processing instructions and
        /// CDATA sections; `Some` for a start tag found, `None` for an end
        /// tag met.
        fn next_event(&mut self, look: Option<Look>) -> Result<Option<Tag>, Stop> {
            if self.empty_end {
                self.pop_empty();
                return Ok(None);
            }
            loop {
                match self.peek(0)?.ok_or(Stop::Parse)? {
                    0x3C => {
                        if self.starts("</")? {
                            self.end_tag()?;
                            return Ok(None);
                        } else if self.starts("<?")? {
                            self.pi()?;
                        } else if self.starts("<!--")? {
                            self.comment()?;
                        } else if self.starts("<![CDATA[")? {
                            self.bump(9);
                            loop {
                                if self.starts("]]>")? {
                                    self.bump(3);
                                    break;
                                }
                                match self.peek(0)? {
                                    Some(u) if allowed(u) => self.bump(1),
                                    _ => return Err(Stop::Parse),
                                }
                            }
                        } else if self.starts("<!")? {
                            return Err(Stop::Parse);
                        } else {
                            let tag = self.start_tag(look)?;
                            self.empty_end = tag.empty;
                            return Ok(Some(tag));
                        }
                    }
                    0x26 => {
                        if !matches!(self.reference()?, Ref::Char(_)) {
                            return Err(Stop::Parse);
                        }
                    }
                    0x5D if self.starts("]]>")? => return Err(Stop::Parse),
                    u if allowed(u) => self.bump(1),
                    _ => return Err(Stop::Parse),
                }
            }
        }

        fn walk(&mut self) -> Result<(), Stop> {
            let mut look = None;
            loop {
                match self.next_event(look)? {
                    None if look.is_some() => look = None,
                    None => return Ok(()),
                    Some(tag) => match (look, tag.kind) {
                        (None, Known::Meta) => look = Some(Look::Meta),
                        (None, Known::Key) => look = Some(Look::Key),
                        (Some(Look::Meta), Known::Version) => {
                            let (text, problem) = self.gather()?;
                            self.version = Some(check_version(&text)?);
                            if problem {
                                return Err(Stop::Parse);
                            }
                        }
                        (Some(Look::Key), Known::Data) => {
                            let (text, problem) = self.gather()?;
                            let ver = self.version.ok_or(KeyFileReason::DataUnreadable)?;
                            self.data = Some(decode_data(ver, &text, tag.hash.as_ref())?);
                            if problem {
                                return Err(Stop::Parse);
                            }
                        }
                        _ => {}
                    },
                }
            }
        }

        /// Gathers the text of the element just found, up to its own end
        /// tag, in text runs (FMT-18.9). On a parse problem it returns the
        /// runs completed so far, with the current run added or dropped as
        /// FMT-18.9 says, and `true`.
        fn gather(&mut self) -> Result<(Units, bool), Stop> {
            let mut text = Units::new();
            if self.empty_end {
                self.pop_empty();
                return Ok((text, false));
            }
            let mut run = Units::new();
            let limit = self.limits.key_file_text;
            loop {
                if text.len().saturating_add(run.len()) > limit {
                    return Err(Stop::Fatal(KeyFileReason::TooLarge(Limit::KeyFileText)));
                }
                // The end of the input, or a block with an invalid byte
                // sequence, drops the current run.
                let u = match self.peek(0) {
                    Ok(Some(u)) => u,
                    Ok(None) | Err(Stop::Parse) => return Ok((text, true)),
                    Err(e) => return Err(e),
                };
                match u {
                    0x3C => {
                        text.append(&run);
                        run.clear();
                        match self.markup_in_text(&mut text, limit) {
                            Ok(true) => return Ok((text, false)),
                            Ok(false) => {}
                            Err(Stop::Parse) => return Ok((text, true)),
                            Err(e) => return Err(e),
                        }
                    }
                    0x26 => match self.reference() {
                        Ok(Ref::Char(c)) => run.push_value(c),
                        Ok(Ref::Undeclared) => {
                            text.append(&run);
                            return Ok((text, true));
                        }
                        Ok(Ref::Broken) | Err(Stop::Parse) => return Ok((text, true)),
                        Err(e) => return Err(e),
                    },
                    0x5D => match self.starts("]]>") {
                        Ok(true) | Err(Stop::Parse) => return Ok((text, true)),
                        Ok(false) => {
                            run.push(u);
                            self.bump(1);
                        }
                        Err(e) => return Err(e),
                    },
                    u if allowed(u) => {
                        run.push(u);
                        self.bump(1);
                    }
                    _ => {
                        text.append(&run);
                        return Ok((text, true));
                    }
                }
            }
        }

        /// Markup inside a gathered text, at `<` (the current run is already
        /// complete): true at the element's own end tag, false after a
        /// comment, processing instruction or CDATA section (whose content is
        /// a run of its own), a parse problem for anything else.
        fn markup_in_text(&mut self, text: &mut Units, limit: usize) -> Result<bool, Stop> {
            if self.starts("</")? {
                self.end_tag()?;
                return Ok(true);
            }
            if self.starts("<!--")? {
                self.comment()?;
                return Ok(false);
            }
            if self.starts("<?")? {
                self.pi()?;
                return Ok(false);
            }
            if !self.starts("<![CDATA[")? {
                return Err(Stop::Parse);
            }
            self.bump(9);
            let mut run = Units::new();
            loop {
                if text.len().saturating_add(run.len()) > limit {
                    return Err(Stop::Fatal(KeyFileReason::TooLarge(Limit::KeyFileText)));
                }
                if self.starts("]]>")? {
                    self.bump(3);
                    text.append(&run);
                    return Ok(false);
                }
                match self.peek(0)? {
                    None => return Err(Stop::Parse),
                    Some(u) if allowed(u) => {
                        run.push(u);
                        self.bump(1);
                    }
                    Some(_) => {
                        text.append(&run);
                        return Err(Stop::Parse);
                    }
                }
            }
        }
    }

    /// FMT-18.10: starts with `1.0`, or exactly `2.0`; else fatal. The
    /// error keeps the version text only when it is at most 16 characters
    /// of ASCII digits and dots (LD-87), so no file text, line break or
    /// direction mark reaches the screen through it.
    fn check_version(text: &Units) -> Result<Ver, Stop> {
        if text.starts_with("1.0") {
            Ok(Ver::V1)
        } else if text.is("2.0") {
            Ok(Ver::V2)
        } else {
            let plain = text.len() <= 16
                && text
                    .iter()
                    .all(|u| u == u16::from(b'.') || (0x30..=0x39).contains(&u));
            let shown = if plain { text.lossy() } else { String::new() };
            Err(Stop::Fatal(KeyFileReason::UnsupportedVersion(shown)))
        }
    }

    /// FMT-18.11 to FMT-18.13: clean, decode by version, check the 2.0 value.
    fn decode_data(ver: Ver, text: &Units, hash_attr: Option<&Units>) -> Result<SecretBytes, Stop> {
        let mut clean = Grow::new();
        for u in text.iter().filter(|u| !data_space(*u)) {
            clean.push(u8::try_from(u).map_err(|_| KeyFileReason::DataUnreadable)?);
        }
        let unreadable = Stop::Fatal(KeyFileReason::DataUnreadable);
        match ver {
            Ver::V1 => base64_strict(clean.as_slice()).ok_or(unreadable),
            Ver::V2 => {
                let data = hex_decode(clean.as_slice()).ok_or(unreadable)?;
                let mut digits = Grow::new();
                for u in hash_attr.into_iter().flat_map(Units::iter) {
                    if let Ok(b) = u8::try_from(u)
                        && nibble(b).is_some()
                    {
                        digits.push(b);
                    }
                }
                let want =
                    hex_decode(digits.as_slice()).ok_or(KeyFileReason::CheckValueMismatch)?;
                let got = hash::sha256(&[data.expose()]);
                if !ct_eq(want.expose(), got.expose().get(..4).unwrap_or(&[])) {
                    return Err(Stop::Fatal(KeyFileReason::CheckValueMismatch));
                }
                Ok(data)
            }
        }
    }

    /// FMT-18.12: strict base64 (alphabet, length a multiple of 4, `=` only
    /// at the end); the unused low bits of the last character are ignored.
    fn base64_strict(s: &[u8]) -> Option<SecretBytes> {
        let pad = s.iter().rev().take_while(|&&b| b == b'=').count();
        let body = s.get(..s.len().saturating_sub(pad))?;
        if s.len() & 3 != 0
            || pad > 2
            || !body
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
        {
            return None;
        }
        decode_secret(Form::Padded, s).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn units(s: &str) -> Units {
            let mut u = Units::new();
            s.encode_utf16().for_each(|x| u.push(x));
            u
        }

        #[test]
        fn utf8_split_and_invalid() {
            let mut d = Decoder::new(Enc::Utf8);
            let mut out = Units::new();
            assert!(!d.feed(&[0x41, 0xC3], &mut out));
            assert!(!d.feed(&[0xA9], &mut out));
            assert_eq!(out.lossy(), "Aé");
            for bad in [
                &[0xFF][..],
                &[0xC0, 0xAF],
                &[0xED, 0xA0, 0x80],
                &[0xF4, 0x90, 0x80, 0x80],
            ] {
                assert!(
                    Decoder::new(Enc::Utf8).feed(bad, &mut Units::new()),
                    "{bad:x?}"
                );
            }
        }

        #[test]
        fn utf32_value_rule() {
            let mut out = Units::new();
            Decoder::new(Enc::Utf32Le).feed(&[0x00, 0xC0, 0xA1, 0x00], &mut out);
            assert_eq!(out.iter().collect::<Vec<_>>(), [0x30, 0xDC00]);
        }

        #[test]
        fn encoding_names() {
            for (n, e) in [
                ("u-t_f.8", Some(Enc::Utf8)),
                ("Latin-1", Some(Enc::Latin1)),
                ("_utf8", None),
                ("UTF+8", None),
                ("", None),
            ] {
                assert_eq!(enc_by_name(&units(n)), e, "{n}");
            }
        }

        #[test]
        fn base64_rules() {
            assert_eq!(
                base64_strict(b"QUJ=").map(|d| d.expose().to_vec()),
                Some(vec![0x41, 0x42])
            );
            assert_eq!(
                base64_strict(b"QR==").map(|d| d.expose().to_vec()),
                Some(vec![0x41])
            );
            assert!(base64_strict(b"QUJD=").is_none());
            assert!(base64_strict(b"Q===").is_none());
            assert!(base64_strict(b"").is_some_and(|d| d.is_empty()));
        }
    }
}
