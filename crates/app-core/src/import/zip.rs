//! App's own small ZIP reader for the .1pux import (LD-142 (2)) and the
//! shared-group containers of app-share (INT-08.9, LD-267 (5)), from the
//! public ZIP file format note (APPNOTE.TXT): the end of central directory
//! record, the central directory and the local headers.
//!
//! Guarantees:
//! - Stored and deflate members only; ZIP64, encryption, several disks and
//!   every other method are refused as [`ImportError::ZipUnsupported`].
//! - Every offset and length is checked against the file before it is used;
//!   the member count is checked against the central directory's size
//!   before the list is allocated.
//! - A member's declared size is checked against the caller's limit before
//!   anything is inflated; inflating counts the output in a fixed buffer
//!   first and stops past the declared size or the limit, so a bomb is
//!   stopped before its output buffer exists; the second pass fills a
//!   buffer of the exact size. The CRC-32 must match.
//! - Output lives only in `SecretBytes`. Limit: the inflate window inside
//!   flate2 holds up to 32 KiB of output and is freed without a wipe (as in
//!   app-format's gunzip); the crate offers no way to wipe it.

use super::{ImportError, Limit};
use app_crypto::secret::SecretBytes;
use flate2::{Crc, Decompress, FlushDecompress, Status};

const EOCD: u32 = 0x0605_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;
const EOCD_LEN: usize = 22;
const CENTRAL_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
/// Inflate output piece.
const PIECE: usize = 64 * 1024;

type R<T> = Result<T, ImportError>;

/// One member of the archive, from the central directory.
#[derive(Debug)]
pub struct Member {
    /// The name as written (not secret: a path inside the archive).
    pub name: String,
    deflate: bool,
    crc: u32,
    compressed: usize,
    size: usize,
    local: usize,
}

/// An opened archive: the file and its member list.
pub struct Archive<'a> {
    data: &'a [u8],
    members: Vec<Member>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(s))
}

fn size(v: u32) -> R<usize> {
    usize::try_from(v).map_err(|_| ImportError::ZipUnsupported)
}

/// Opens an archive (FEA-08.29). Not a ZIP: [`ImportError::OnePuxNotZip`]
/// (also for a damaged directory).
pub fn open(data: &[u8]) -> R<Archive<'_>> {
    let not_zip = ImportError::OnePuxNotZip;
    // The last end record whose comment fits the file; the comment is at
    // most 65,535 bytes.
    let last = data.len().checked_sub(EOCD_LEN).ok_or(not_zip)?;
    let first = last.saturating_sub(65_535);
    let at = (first..=last)
        .rev()
        .find(|&i| {
            u32_at(data, i) == Some(EOCD)
                && u16_at(data, i.saturating_add(20)).is_some_and(|c| {
                    i.saturating_add(EOCD_LEN).saturating_add(usize::from(c)) <= data.len()
                })
        })
        .ok_or(not_zip)?;
    let field16 = |o: usize| u16_at(data, at.saturating_add(o)).ok_or(not_zip);
    let field32 = |o: usize| u32_at(data, at.saturating_add(o)).ok_or(not_zip);
    let (disk, cd_disk, here, total) = (field16(4)?, field16(6)?, field16(8)?, field16(10)?);
    let (cd_size, cd_offset) = (field32(12)?, field32(16)?);
    let zip64 = total == 0xFFFF
        || cd_size == u32::MAX
        || cd_offset == u32::MAX
        || at
            .checked_sub(20)
            .is_some_and(|l| u32_at(data, l) == Some(ZIP64_LOCATOR));
    if zip64 || disk != 0 || cd_disk != 0 || here != total {
        return Err(ImportError::ZipUnsupported);
    }
    let (cd_size, cd_offset, total) = (size(cd_size)?, size(cd_offset)?, usize::from(total));
    let cd_end = cd_offset.checked_add(cd_size).ok_or(not_zip)?;
    if cd_end > at || total > cd_size / CENTRAL_LEN {
        return Err(not_zip);
    }
    let cd = data.get(cd_offset..cd_end).ok_or(not_zip)?;
    let mut members = Vec::with_capacity(total);
    let mut pos = 0usize;
    for _ in 0..total {
        let f16 = |o: usize| u16_at(cd, pos.saturating_add(o)).ok_or(not_zip);
        let f32 = |o: usize| u32_at(cd, pos.saturating_add(o)).ok_or(not_zip);
        if f32(0)? != CENTRAL {
            return Err(not_zip);
        }
        let (flags, method) = (f16(8)?, f16(10)?);
        let (crc, compressed, uncompressed) = (f32(16)?, f32(20)?, f32(24)?);
        let (name_len, extra_len, comment_len) = (
            usize::from(f16(28)?),
            usize::from(f16(30)?),
            usize::from(f16(32)?),
        );
        let local = f32(42)?;
        // Bit 0 encrypted, bit 6 strong encryption, bit 13 masked header.
        if flags & (1 | 1 << 6 | 1 << 13) != 0 || !matches!(method, 0 | 8) {
            return Err(ImportError::ZipUnsupported);
        }
        if [compressed, uncompressed, local].contains(&u32::MAX) || f16(34)? != 0 {
            return Err(ImportError::ZipUnsupported);
        }
        let name_at = pos.checked_add(CENTRAL_LEN).ok_or(not_zip)?;
        let name_end = name_at.checked_add(name_len).ok_or(not_zip)?;
        let name = cd.get(name_at..name_end).ok_or(not_zip)?;
        members.push(Member {
            name: String::from_utf8_lossy(name).into_owned(),
            deflate: method == 8,
            crc,
            compressed: size(compressed)?,
            size: size(uncompressed)?,
            local: size(local)?,
        });
        pos = name_end
            .checked_add(extra_len)
            .and_then(|p| p.checked_add(comment_len))
            .ok_or(not_zip)?;
    }
    Ok(Archive { data, members })
}

impl Archive<'_> {
    /// Every member, in central directory order.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The first member named `name`, compared exactly or ignoring ASCII
    /// case.
    pub fn find(&self, name: &str, ignore_case: bool) -> Option<&Member> {
        self.members.iter().find(|m| {
            if ignore_case {
                m.name.eq_ignore_ascii_case(name)
            } else {
                m.name == name
            }
        })
    }

    /// The content of `m`, at most `limit` bytes (`over` names the limit).
    /// A damaged member (bad local header, short data, wrong size or CRC)
    /// is [`ImportError::OnePuxNotZip`].
    pub fn read(&self, m: &Member, limit: usize, over: Limit) -> R<SecretBytes> {
        let bad = ImportError::OnePuxNotZip;
        if m.size > limit {
            return Err(ImportError::TooLarge(over));
        }
        let d = self.data;
        if u32_at(d, m.local) != Some(LOCAL) {
            return Err(bad);
        }
        let n = usize::from(u16_at(d, m.local.saturating_add(26)).ok_or(bad)?);
        let e = usize::from(u16_at(d, m.local.saturating_add(28)).ok_or(bad)?);
        let start = m
            .local
            .checked_add(LOCAL_LEN)
            .and_then(|s| s.checked_add(n))
            .and_then(|s| s.checked_add(e))
            .ok_or(bad)?;
        let end = start.checked_add(m.compressed).ok_or(bad)?;
        let body = d.get(start..end).ok_or(bad)?;
        let out = if m.deflate {
            let n = inflate(body, m.size, None)?;
            let mut out = SecretBytes::zeroed(n);
            inflate(body, m.size, Some(out.expose_mut()))?;
            out
        } else {
            if body.len() != m.size {
                return Err(bad);
            }
            let mut out = SecretBytes::zeroed(m.size);
            out.expose_mut().copy_from_slice(body);
            out
        };
        let mut crc = Crc::new();
        crc.update(out.expose());
        if crc.sum() != m.crc || out.len() != m.size {
            return Err(bad);
        }
        Ok(out)
    }
}

/// One pass of raw deflate over `body`, producing exactly `size` bytes;
/// copies them into `out` when given. Stops as soon as the output would
/// pass `size`.
fn inflate(body: &[u8], size: usize, mut out: Option<&mut [u8]>) -> R<usize> {
    let bad = ImportError::OnePuxNotZip;
    let mut d = Decompress::new(false);
    let mut scratch = SecretBytes::zeroed(PIECE);
    let mut produced = 0usize;
    loop {
        let (in_before, out_before) = (d.total_in(), d.total_out());
        let at = usize::try_from(in_before).map_err(|_| bad)?;
        let input = body.get(at..).ok_or(bad)?;
        let status = d
            .decompress(input, scratch.expose_mut(), FlushDecompress::None)
            .map_err(|_| bad)?;
        let wrote = usize::try_from(d.total_out().saturating_sub(out_before)).map_err(|_| bad)?;
        let end = produced.checked_add(wrote).ok_or(bad)?;
        if end > size {
            return Err(bad);
        }
        if let Some(out) = out.as_deref_mut() {
            let chunk = scratch.expose().get(..wrote).ok_or(bad)?;
            out.get_mut(produced..end)
                .ok_or(bad)?
                .copy_from_slice(chunk);
        }
        produced = end;
        match status {
            Status::StreamEnd => break,
            _ if wrote == 0 && d.total_in() == in_before => return Err(bad),
            _ => {}
        }
    }
    if produced != size {
        return Err(bad);
    }
    Ok(produced)
}
