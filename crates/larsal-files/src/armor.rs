//! Where a file's bytes come from: binary as it is, or decoded from strict
//! armor (FIL-01.13, RFC 7468's strict form), both streamed. Holds ciphertext
//! only, never plaintext, so its buffers need no wiping.

use crate::error::{Failure, io_error};
use crate::limits::MAX_ARMOR_SPACE;
use larsal_crypto::base64;
use std::io::{BufRead, BufReader, ErrorKind, Read};

const BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const END: &[u8] = b"-----END AGE ENCRYPTED FILE-----";
/// A full base64 line.
const LINE: usize = 64;
/// One byte past the longest legal line: 64 characters, CR and LF.
const LINE_READ: u64 = 67;
const BUFFER: usize = 65_536;

const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// True for bytes that start, after any white space, with the armor's first line.
pub(crate) fn starts_as_armor(data: &[u8]) -> bool {
    let space = data.iter().take_while(|b| is_space(**b)).count();
    data.get(space..)
        .is_some_and(|rest| rest.starts_with(BEGIN))
}

/// A file's bytes, in the order the format reads them.
pub(crate) enum Source<R> {
    Binary(BufReader<R>),
    Armor(Box<Armor<R>>),
}

impl<R: Read> Source<R> {
    /// Looks at the first bytes. Binary files start at once with the version
    /// line; anything with leading white space or a dash must be strict armor.
    pub(crate) fn detect(reader: R) -> Result<Self, Failure> {
        Self::start(reader, false)
    }

    /// The armor route whatever comes first, for a published row marked as armor.
    #[cfg(test)]
    pub(crate) fn armored(reader: R) -> Result<Self, Failure> {
        Self::start(reader, true)
    }

    fn start(reader: R, armored: bool) -> Result<Self, Failure> {
        let mut r = BufReader::with_capacity(BUFFER, reader);
        let mut space = 0usize;
        let first = loop {
            let buf = fill(&mut r)?;
            if buf.is_empty() {
                return Err(if space == 0 {
                    Failure::Header
                } else {
                    Failure::Armor
                });
            }
            let n = buf.iter().take_while(|b| is_space(**b)).count();
            let first = buf.get(n).copied();
            r.consume(n);
            space = space.saturating_add(n);
            if space > MAX_ARMOR_SPACE {
                return Err(Failure::Armor);
            }
            if let Some(b) = first {
                break b;
            }
        };
        if !armored && space == 0 && first != b'-' {
            return Ok(Self::Binary(r));
        }
        let mut armor = Armor::new(r);
        if !armor.read_line()? || armor.body() != BEGIN {
            return Err(Failure::Armor);
        }
        Ok(Self::Armor(Box::new(armor)))
    }

    /// The next byte, or `None` at the end of a well-formed file.
    pub(crate) fn next_byte(&mut self) -> Result<Option<u8>, Failure> {
        match self {
            Self::Binary(r) => {
                let b = fill(r)?.first().copied();
                if b.is_some() {
                    r.consume(1);
                }
                Ok(b)
            }
            Self::Armor(a) => a.next_byte(),
        }
    }

    /// Fills `buf` unless the file ends first, and says how many bytes came. A
    /// short count means the file has ended, and for armor that it ended well.
    pub(crate) fn read_full(&mut self, buf: &mut [u8]) -> Result<usize, Failure> {
        let mut done = 0usize;
        while let Some(rest) = buf.get_mut(done..).filter(|r| !r.is_empty()) {
            let n = match self {
                Self::Binary(r) => match r.read(rest) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(Failure::Other(io_error(&e))),
                },
                Self::Armor(a) => a.read(rest)?,
            };
            if n == 0 {
                break;
            }
            done = done.saturating_add(n);
        }
        Ok(done)
    }
}

fn fill<R: Read>(r: &mut BufReader<R>) -> Result<&[u8], Failure> {
    loop {
        // A borrow checker limit: the buffer is read again after the loop.
        match r.fill_buf() {
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(Failure::Other(io_error(&e))),
        }
    }
    r.fill_buf().map_err(|e| Failure::Other(io_error(&e)))
}

/// Strict armor being read: `decoded[at..len]` waits to be handed out.
pub(crate) struct Armor<R> {
    r: BufReader<R>,
    line: Vec<u8>,
    decoded: [u8; 48],
    at: usize,
    len: usize,
    /// The last data line was short or padded: only the end line may follow.
    last: bool,
    ended: bool,
}

impl<R: Read> Armor<R> {
    fn new(r: BufReader<R>) -> Self {
        Self {
            r,
            line: Vec::with_capacity(70),
            decoded: [0; 48],
            at: 0,
            len: 0,
            last: false,
            ended: false,
        }
    }

    /// Reads one bounded line, and says whether it ended in LF.
    fn read_line(&mut self) -> Result<bool, Failure> {
        self.line.clear();
        let got = loop {
            match (&mut self.r)
                .take(LINE_READ)
                .read_until(b'\n', &mut self.line)
            {
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                got => break got,
            }
        };
        got.map_err(|e| Failure::Other(io_error(&e)))?;
        if self.line.last() == Some(&b'\n') {
            return Ok(true);
        }
        if self.line.len() >= usize::try_from(LINE_READ).unwrap_or(usize::MAX) {
            return Err(Failure::Armor);
        }
        Ok(false)
    }

    /// The line without its LF or CRLF.
    fn body(&self) -> &[u8] {
        let line = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
        if self.line.last() == Some(&b'\n') {
            line.strip_suffix(b"\r").unwrap_or(line)
        } else {
            line
        }
    }

    /// Only white space, bounded, may follow the end line.
    fn trailing_space(&mut self) -> Result<(), Failure> {
        let mut space = 0usize;
        loop {
            let buf = fill(&mut self.r)?;
            let n = buf.len();
            if n == 0 {
                return Ok(());
            }
            if !buf.iter().copied().all(is_space) {
                return Err(Failure::Armor);
            }
            self.r.consume(n);
            space = space.saturating_add(n);
            if space > MAX_ARMOR_SPACE {
                return Err(Failure::Armor);
            }
        }
    }

    fn refill(&mut self) -> Result<(), Failure> {
        let has_lf = self.read_line()?;
        if self.body() == END {
            self.trailing_space()?;
            self.ended = true;
            return Ok(());
        }
        if !has_lf || self.last {
            return Err(Failure::Armor);
        }
        let body = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        if body.is_empty() || body.len() > LINE || !body.len().is_multiple_of(4) {
            return Err(Failure::Armor);
        }
        let pad = body.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 {
            return Err(Failure::Armor);
        }
        let text = body
            .get(..body.len().saturating_sub(pad))
            .ok_or(Failure::Armor)?;
        let n =
            base64::decode_unpadded_into(text, &mut self.decoded).map_err(|_| Failure::Armor)?;
        self.last = pad > 0 || body.len() < LINE;
        self.at = 0;
        self.len = n;
        Ok(())
    }

    fn next_byte(&mut self) -> Result<Option<u8>, Failure> {
        let mut one = [0u8; 1];
        Ok((self.read(&mut one)? == 1).then_some(one[0]))
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, Failure> {
        while self.at >= self.len && !self.ended {
            self.refill()?;
        }
        let have = self.decoded.get(self.at..self.len).unwrap_or(&[]);
        let n = have.len().min(out.len());
        if let (Some(to), Some(from)) = (out.get_mut(..n), have.get(..n)) {
            to.copy_from_slice(from);
        }
        self.at = self.at.saturating_add(n);
        Ok(n)
    }
}
