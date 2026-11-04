//! Version 1 import (FEA-08 section G): the older file format with second
//! signature `65 FB 4B B5`, AES-256 or Twofish-256 in CBC mode, a key from
//! the version 3 AES-KDF.
//!
//! Guarantees:
//! - The key derivation's cost is checked by app-crypto's `assess` before
//!   any derivation; above its ask threshold the reader returns the cost
//!   ([`Outcome::Ask`]) and derives nothing until called again with the
//!   approval (FEA-08.68, CRY-02.14).
//! - Every field size is checked against the bytes left before the field
//!   is read (FEA-08.55): no allocation follows a size from the file. The
//!   reference reads sizes up to 2 GiB before any check.
//! - The content hash is compared in constant time; every key, try and the
//!   plaintext live in `SecretBytes` and are wiped when the reader returns.

use super::{Builder, Context, ImportError, Imported, R};
use crate::text::{Bytes, Text};
use app_crypto::cipher::{self, Cipher};
use app_crypto::hash;
use app_crypto::kdf::{self, Ceilings, CostReport, Host, KdfParams, Verdict};
use app_crypto::secret::{SecretBytes, SecretString, ct_eq};
use app_model::times::Civil;
use app_model::{Association, Icon, Switch, Time};
use std::collections::HashMap;

const SIG1: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
const SIG2: [u8; 4] = [0x65, 0xFB, 0x4B, 0xB5];
const HEADER: usize = 124;
/// "Never" in a packed time (FEA-08.56).
const NEVER: [u8; 5] = [0x2E, 0xDF, 0x39, 0x7E, 0xFB];
/// The group tree state meta record's notes, stored encoded (name rule).
const TREE_STATE: &[u8] = &[
    0x4B, 0x50, 0x58, 0x5F, 0x47, 0x52, 0x4F, 0x55, 0x50, 0x5F, 0x54, 0x52, 0x45, 0x45, 0x5F, 0x53,
    0x54, 0x41, 0x54, 0x45,
];
/// The custom icons meta record's notes, stored encoded (name rule).
const CUSTOM_ICONS: &[u8] = &[
    0x4B, 0x50, 0x58, 0x5F, 0x43, 0x55, 0x53, 0x54, 0x4F, 0x4D, 0x5F, 0x49, 0x43, 0x4F, 0x4E, 0x53,
    0x5F, 0x34,
];

/// The result's root group name (FEA-08.60).
pub const ROOT: &str = "Root";

/// The credentials of a version 1 file.
#[derive(Debug, Clone, Copy, Default)]
pub struct Keys<'a> {
    /// The password; with no key file either, the empty password is tried.
    pub password: Option<&'a SecretString>,
    /// The key file's bytes.
    pub key_file: Option<&'a SecretBytes>,
}

/// What [`read`] gives back when it does not fail.
#[derive(Debug)]
pub enum Outcome {
    /// The import result.
    Imported(Box<Imported>),
    /// The key derivation needs the user's approval first: show the cost,
    /// then call again with it (CRY-02.14).
    Ask(CostReport),
}

/// Reads a version 1 file. `host` and `ceilings` drive the cost check of
/// CRY-02.14; `approval` is an earlier [`Outcome::Ask`] report the user
/// approved.
///
/// # Errors
/// `MSG-V1-NOTVAULT`, `-CIPHER`, `-VERSION`, `-KEYFILE`, `-DAMAGED`,
/// `MSG-WRONG-CREDENTIALS`, `MSG-KDF-COST`, `MSG-TOO-LARGE`; `Cancelled`.
pub fn read(
    bytes: &[u8],
    keys: &Keys<'_>,
    host: &mut Host,
    ceilings: &Ceilings,
    approval: Option<&CostReport>,
    ctx: &Context<'_>,
) -> Result<Outcome, ImportError> {
    let get = |r: core::ops::Range<usize>| bytes.get(r).ok_or(ImportError::V1Damaged);
    // LD-146 (12): the bytes present are compared with the signatures, also
    // in a file shorter than them.
    let signatures = [SIG1, SIG2].concat();
    let present = bytes.len().min(signatures.len());
    if bytes.get(..present) != signatures.get(..present) {
        return Err(ImportError::V1NotVault);
    }
    if bytes.len() < HEADER {
        return Err(ImportError::V1Damaged);
    }
    let u32_at = |at: usize| -> R<u32> {
        let b: [u8; 4] = get(at..at.saturating_add(4))?
            .try_into()
            .map_err(|_| ImportError::V1Damaged)?;
        Ok(u32::from_le_bytes(b))
    };
    let flags = u32_at(8)?;
    let cipher = if flags & 8 != 0 {
        Cipher::Twofish256Cbc
    } else if flags & 2 != 0 {
        Cipher::Aes256Cbc
    } else {
        return Err(ImportError::V1Cipher);
    };
    if u32_at(12)? & 0xFFFF_FF00 != 0x0003_0000 {
        return Err(ImportError::V1Version);
    }
    let (master_seed, iv) = (get(16..32)?, get(32..48)?);
    let (group_count, entry_count) = (u32_at(48)?, u32_at(52)?);
    let (content_hash, transform_seed) = (get(56..88)?, get(88..120)?);
    let rounds = u32_at(120)?;
    let key_file = keys.key_file.map(key_file_data).transpose()?;
    let params = KdfParams::AesKdf {
        rounds: u64::from(rounds),
        seed: transform_seed.to_vec(),
    };
    let cleared = match kdf::assess(&params, host, ceilings, approval) {
        Ok(Verdict::Run(c)) => c,
        Ok(Verdict::Ask(report)) => return Ok(Outcome::Ask(report)),
        Err(_) => return Err(ImportError::KdfCost),
    };
    let content = get(HEADER..bytes.len())?;
    let mut plain = None;
    for raw in raw_keys(keys.password, key_file.as_ref()) {
        ctx.check_cancel()?;
        let transformed = kdf::derive(&raw, &cleared).map_err(|_| ImportError::KdfCost)?;
        let key = hash::sha256(&[master_seed, transformed.expose()]);
        if let Ok(p) = cipher::decrypt(cipher, &key, iv, content)
            && ct_eq(hash::sha256(&[p.expose()]).expose(), content_hash)
        {
            plain = Some(p);
            break;
        }
    }
    ctx.check_cancel()?;
    let plain = plain.ok_or(ImportError::WrongCredentials)?;
    let imported = build(plain.expose(), group_count, entry_count, ctx)?;
    Ok(Outcome::Imported(Box::new(imported)))
}

/// FEA-08.54 key file data: 32 bytes as is, 64 hex digits decoded, any
/// other file hashed; an empty file is refused.
fn key_file_data(b: &SecretBytes) -> R<SecretBytes> {
    let b = b.expose();
    match b.len() {
        0 => Err(ImportError::V1KeyFile),
        32 => Ok(SecretBytes::new(b.to_vec())),
        64 if b.iter().all(u8::is_ascii_hexdigit) => {
            let mut out = SecretBytes::zeroed(32);
            for (slot, pair) in out.expose_mut().iter_mut().zip(b.chunks(2)) {
                let digit = |c: &u8| {
                    char::from(*c)
                        .to_digit(16)
                        .and_then(|d| u8::try_from(d).ok())
                        .unwrap_or(0)
                };
                *slot =
                    pair.first().map_or(0, digit).wrapping_shl(4) | pair.get(1).map_or(0, digit);
            }
            Ok(out)
        }
        _ => Ok(hash::sha256(&[b])),
    }
}

/// The raw keys to try, in order (FEA-08.54): the password as
/// Windows-1252, ISO-8859-1 and UTF-8, a try skipped when its encoding
/// cannot hold the text or its bytes equal an earlier try.
fn raw_keys(password: Option<&SecretString>, key_file: Option<&SecretBytes>) -> Vec<SecretBytes> {
    let combine = |pw: &[u8]| match key_file {
        None => hash::sha256(&[pw]),
        Some(k) => hash::sha256(&[hash::sha256(&[pw]).expose(), k.expose()]),
    };
    let text = match (password, key_file) {
        (Some(p), _) => p.expose(),
        (None, Some(k)) => return vec![SecretBytes::new(k.expose().to_vec())],
        (None, None) => "",
    };
    let mut tries: Vec<SecretBytes> = Vec::new();
    for bytes in [encode(text, true), encode(text, false), Some(utf8(text))]
        .into_iter()
        .flatten()
    {
        if !tries.iter().any(|t| t.expose() == bytes.expose()) {
            tries.push(bytes);
        }
    }
    tries.iter().map(|b| combine(b.expose())).collect()
}

fn utf8(text: &str) -> SecretBytes {
    let mut b = Bytes::new();
    b.extend(text.as_bytes());
    SecretBytes::new(b.as_slice().to_vec())
}

/// Windows-1252 (`cp1252`) or ISO-8859-1 bytes; `None` when a character
/// does not fit.
fn encode(text: &str, cp1252: bool) -> Option<SecretBytes> {
    let mut out = SecretBytes::zeroed(text.chars().count());
    for (slot, c) in out.expose_mut().iter_mut().zip(text.chars()) {
        let u = u32::from(c);
        *slot = match u {
            0..=0x7F | 0xA0..=0xFF => u8::try_from(u).ok()?,
            0x80..=0x9F if !cp1252 => u8::try_from(u).ok()?,
            _ if cp1252 => {
                let i = super::CP1252_HIGH.iter().position(|&h| u32::from(h) == u)?;
                0x80u8.checked_add(u8::try_from(i).ok()?)?
            }
            _ => return None,
        };
    }
    Some(out)
}

/// FEA-08.56: a packed time; `None` for "never" and impossible dates.
fn packed(b: &[u8]) -> Option<Time> {
    let [b0, b1, b2, b3, b4]: [u8; 5] = b.try_into().ok()?;
    if [b0, b1, b2, b3, b4] == NEVER {
        return None;
    }
    let (b0, b1, b2, b3, b4) = (
        u32::from(b0),
        u32::from(b1),
        u32::from(b2),
        u32::from(b3),
        u32::from(b4),
    );
    Time::from_civil(Civil {
        year: i64::from(b0.checked_mul(64)?.checked_add(b1 >> 2)?),
        month: (b1 & 3).checked_mul(4)?.checked_add(b2 >> 6)?,
        day: (b2 >> 1) & 31,
        hour: (b2 & 1).checked_mul(16)?.checked_add(b3 >> 4)?,
        minute: (b3 & 15).checked_mul(4)?.checked_add(b4 >> 6)?,
        second: b4 & 63,
    })
}

/// One record: its fields up to the end field 0xFFFF (FEA-08.55). Every
/// size is checked against the bytes left before the field is taken.
fn record<'a>(data: &'a [u8], at: &mut usize) -> R<Vec<(u16, &'a [u8])>> {
    let bad = ImportError::V1Damaged;
    let mut out = Vec::new();
    loop {
        let head = data.get(*at..at.checked_add(6).ok_or(bad)?).ok_or(bad)?;
        let kind = u16::from_le_bytes([*head.first().ok_or(bad)?, *head.get(1).ok_or(bad)?]);
        let size: [u8; 4] = head.get(2..6).ok_or(bad)?.try_into().map_err(|_| bad)?;
        let size = usize::try_from(u32::from_le_bytes(size)).map_err(|_| bad)?;
        let start = at.checked_add(6).ok_or(bad)?;
        let end = start.checked_add(size).ok_or(bad)?;
        let body = data.get(start..end).ok_or(bad)?;
        *at = end;
        if kind == 0xFFFF {
            return Ok(out);
        }
        out.push((kind, body));
    }
}

/// A text field: UTF-8 up to the first NUL, bad sequences as U+FFFD, in a
/// wiping buffer.
fn text(b: &[u8]) -> SecretString {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let mut raw = Bytes::new();
    raw.extend(b.get(..end).unwrap_or(&[]));
    let mut t = Text::new();
    raw.utf8_lossy_into(&mut t);
    t.into_secret()
}

/// A name field (group or attachment names are plain text in the model).
fn name_text(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(b.get(..end).unwrap_or(&[])).into_owned()
}

fn fixed<const N: usize>(b: &[u8]) -> R<[u8; N]> {
    b.try_into().map_err(|_| ImportError::V1Damaged)
}

fn icon(b: &[u8]) -> R<i32> {
    let n = u32::from_le_bytes(fixed::<4>(b)?);
    Ok(i32::try_from(n)
        .ok()
        .filter(|n| (0..crate::icons::STANDARD_COUNT).contains(n))
        .unwrap_or(0))
}

struct GroupRec {
    id: u32,
    level: u16,
    name: String,
    times: [Option<Time>; 4],
    icon: i32,
}

struct EntryRec {
    file_id: Option<[u8; 16]>,
    group: Option<u32>,
    icon: i32,
    values: [SecretString; 5],
    times: [Option<Time>; 4],
    attachment: Option<(String, SecretBytes)>,
}

fn group_rec(fields: &[(u16, &[u8])]) -> R<GroupRec> {
    let (mut id, mut level) = (None, None);
    let mut g = GroupRec {
        id: 0,
        level: 0,
        name: String::new(),
        times: [None; 4],
        icon: 0,
    };
    for &(kind, b) in fields {
        match kind {
            0 | 9 => {}
            1 => id = Some(u32::from_le_bytes(fixed::<4>(b)?)),
            2 => g.name = name_text(b),
            3..=6 => {
                let slot = g
                    .times
                    .get_mut(usize::from(kind).saturating_sub(3))
                    .ok_or(ImportError::V1Damaged)?;
                *slot = packed(&fixed::<5>(b)?);
            }
            7 => g.icon = icon(b)?,
            8 => level = Some(u16::from_le_bytes(fixed::<2>(b)?)),
            _ => return Err(ImportError::V1Damaged),
        }
    }
    g.id = id.ok_or(ImportError::V1Damaged)?;
    g.level = level.ok_or(ImportError::V1Damaged)?;
    Ok(g)
}

fn entry_rec(fields: &[(u16, &[u8])]) -> R<EntryRec> {
    let mut e = EntryRec {
        file_id: None,
        group: None,
        icon: 0,
        values: core::array::from_fn(|_| SecretString::new(String::new())),
        times: [None; 4],
        attachment: None,
    };
    let mut name = String::new();
    for &(kind, b) in fields {
        match kind {
            0 => {}
            1 => e.file_id = Some(fixed::<16>(b)?),
            2 => e.group = Some(u32::from_le_bytes(fixed::<4>(b)?)),
            3 => e.icon = icon(b)?,
            4..=8 => {
                let slot = e
                    .values
                    .get_mut(usize::from(kind).saturating_sub(4))
                    .ok_or(ImportError::V1Damaged)?;
                *slot = text(b);
            }
            9..=12 => {
                let slot = e
                    .times
                    .get_mut(usize::from(kind).saturating_sub(9))
                    .ok_or(ImportError::V1Damaged)?;
                *slot = packed(&fixed::<5>(b)?);
            }
            13 => name = name_text(b),
            // The name as read so far: content before its name gets an
            // empty name (FEA-08.55 edge case).
            14 if !b.is_empty() => {
                e.attachment = Some((name.clone(), SecretBytes::new(b.to_vec())))
            }
            14 => {}
            _ => return Err(ImportError::V1Damaged),
        }
    }
    Ok(e)
}

/// FEA-08.55 to FEA-08.60: records, tree, meta records, Auto-Type lines.
/// The header's record counts drive no allocation: each group goes into the
/// result as it is read (the builder stops at the groups limit), meta
/// records are applied as they are read, and kept entries stop at the
/// entries limit.
fn build(plain: &[u8], group_count: u32, entry_count: u32, ctx: &Context<'_>) -> R<Imported> {
    let mut at = 0usize;
    let mut b = Builder::new(ctx, ROOT)?;
    // FEA-08.57: each level n > 0 under the nearest earlier group with a
    // lower level, which must be n - 1.
    let mut stack: Vec<(u16, usize)> = Vec::new();
    let mut by_id: HashMap<u32, usize> = HashMap::new();
    for _ in 0..group_count {
        let g = group_rec(&record(plain, &mut at)?)?;
        while stack.last().is_some_and(|(l, _)| *l >= g.level) {
            stack.pop();
        }
        let parent = match (g.level, stack.last()) {
            (0, _) => 0,
            (n, Some(&(l, idx))) if l.checked_add(1) == Some(n) => idx,
            _ => return Err(ImportError::V1Damaged),
        };
        let idx = b.new_child(parent, &g.name, None)?;
        stack.push((g.level, idx));
        by_id.entry(g.id).or_insert(idx);
        if let Some(group) = b.group_mut(idx) {
            group.icon = Icon::Standard(g.icon);
            let [created, modified, accessed, expiry] = g.times;
            set_times(&mut group.times, created, modified, accessed, expiry);
            if g.level == 0 && g.name == "Backup" {
                group.searching = Switch::Off;
                group.auto_type = Switch::Off;
            }
        }
    }
    // FEA-08.58: meta records are applied, not imported.
    let mut entry_icons: HashMap<[u8; 16], app_model::Uuid> = HashMap::new();
    let mut kept = Vec::new();
    for _ in 0..entry_count {
        let e = entry_rec(&record(plain, &mut at)?)?;
        if !is_meta(&e) {
            if kept.len() >= ctx.limits.entries {
                return Err(ImportError::TooLarge(super::Limit::Entries));
            }
            kept.push(e);
            continue;
        }
        let Some((_, data)) = &e.attachment else {
            continue;
        };
        let notes = e.values[4].expose().as_bytes();
        if notes == TREE_STATE {
            tree_state(&mut b, &by_id, data.expose());
        } else if notes == CUSTOM_ICONS {
            custom_icons(
                &mut b,
                &by_id,
                &mut entry_icons,
                data.expose(),
                ctx.limits.entries,
            )?;
        }
    }
    for e in kept {
        let mut d = b.draft()?;
        let [title, url, user, password, notes] = e.values;
        d.set("Title", title, false)?;
        d.set("URL", url, false)?;
        d.set("UserName", user, false)?;
        d.set("Password", password, true)?;
        let (rest, auto) = auto_type(notes.expose());
        d.set("Notes", rest, false)?;
        let entry = d.entry_mut();
        entry.icon = match e.file_id.and_then(|f| entry_icons.get(&f)) {
            Some(id) => Icon::Custom(*id),
            None => Icon::Standard(e.icon),
        };
        entry.auto_type.default_sequence = auto.default;
        entry.auto_type.associations = auto.associations;
        let [created, modified, accessed, expiry] = e.times;
        set_times(&mut entry.times, created, modified, accessed, expiry);
        if let Some((name, data)) = e.attachment {
            d.attach(&name, data)?;
        }
        let g = e.group.and_then(|id| by_id.get(&id).copied()).unwrap_or(0);
        b.add(g, d)?;
    }
    Ok(b.finish())
}

fn set_times(
    t: &mut app_model::Times,
    c: Option<Time>,
    m: Option<Time>,
    a: Option<Time>,
    x: Option<Time>,
) {
    if let Some(c) = c {
        t.creation = c;
    }
    if let Some(m) = m {
        t.last_modification = m;
    }
    if let Some(a) = a {
        t.last_access = a;
    }
    if let Some(x) = x {
        t.expires = true;
        t.expiry = x;
    }
}

/// FEA-08.58: attachment `bin-stream`, non-empty Notes, Title `Meta-Info`,
/// User name `SYSTEM`, URL `$`, icon 0.
fn is_meta(e: &EntryRec) -> bool {
    let [title, url, user, _, notes] = &e.values;
    e.attachment
        .as_ref()
        .is_some_and(|(n, _)| n == "bin-stream")
        && !notes.is_empty()
        && title.expose() == "Meta-Info"
        && user.expose() == "SYSTEM"
        && url.expose() == "$"
        && e.icon == 0
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The group tree state: a count n, then n records of a group id and an
/// expanded byte; the size must be exactly 4 + 5n.
fn tree_state(b: &mut Builder<'_>, by_id: &HashMap<u32, usize>, data: &[u8]) {
    let Some(n) = le32(data, 0).and_then(|n| usize::try_from(n).ok()) else {
        return;
    };
    if n.checked_mul(5).and_then(|v| v.checked_add(4)) != Some(data.len()) {
        return;
    }
    for i in 0..n {
        let at = i.saturating_mul(5).saturating_add(4);
        let (Some(id), Some(&flag)) = (le32(data, at), data.get(at.saturating_add(4))) else {
            return;
        };
        if let Some(g) = by_id.get(&id).and_then(|&g| b.group_mut(g)) {
            g.expanded = flag != 0;
        }
    }
}

/// The custom icons record: counts, PNG images, then entry and group
/// links; any size past the end stops the reading (what was read stays).
fn custom_icons(
    b: &mut Builder<'_>,
    by_id: &HashMap<u32, usize>,
    entry_icons: &mut HashMap<[u8; 16], app_model::Uuid>,
    data: &[u8],
    max_links: usize,
) -> R<()> {
    let (Some(icons), Some(entries), Some(groups)) = (le32(data, 0), le32(data, 4), le32(data, 8))
    else {
        return Ok(());
    };
    let mut at = 12usize;
    let mut ids = Vec::new();
    for _ in 0..icons {
        let Some(size) = le32(data, at).and_then(|s| usize::try_from(s).ok()) else {
            return Ok(());
        };
        let start = at.saturating_add(4);
        let Some(png) = start.checked_add(size).and_then(|end| data.get(start..end)) else {
            return Ok(());
        };
        ids.push(b.icon(png)?);
        at = start.saturating_add(size);
    }
    for _ in 0..entries {
        let Some(file_id) = data
            .get(at..at.saturating_add(16))
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
        else {
            return Ok(());
        };
        let Some(index) = le32(data, at.saturating_add(16)) else {
            return Ok(());
        };
        if let Some(id) = usize::try_from(index).ok().and_then(|i| ids.get(i)) {
            // Links beyond the entries limit can name no kept entry.
            if entry_icons.len() < max_links || entry_icons.contains_key(&file_id) {
                entry_icons.insert(file_id, *id);
            }
        }
        at = at.saturating_add(20);
    }
    for _ in 0..groups {
        let (Some(group), Some(index)) = (le32(data, at), le32(data, at.saturating_add(4))) else {
            return Ok(());
        };
        if let (Some(id), Some(g)) = (
            usize::try_from(index).ok().and_then(|i| ids.get(i)),
            by_id.get(&group).and_then(|&g| b.group_mut(g)),
        ) {
            g.icon = Icon::Custom(*id);
        }
        at = at.saturating_add(8);
    }
    Ok(())
}

struct AutoType {
    default: String,
    associations: Vec<Association>,
}

/// FEA-08.59: Auto-Type lines at the start of a line, removed from the
/// notes with an empty line right after one; associations in ascending n,
/// the unnumbered first, windows of one n in file order.
fn auto_type(notes: &str) -> (SecretString, AutoType) {
    let mut kept = Text::new();
    let mut auto = AutoType {
        default: String::new(),
        associations: Vec::new(),
    };
    let mut sequences: HashMap<u64, String> = HashMap::new();
    let mut windows: Vec<(Option<u64>, String)> = Vec::new();
    let mut after_recognized = false;
    let mut first = true;
    for raw in notes.split('\n') {
        let mut line_text = Text::new();
        for c in raw.chars().filter(|&c| c != '\r') {
            line_text.push(c);
        }
        let line = line_text.as_str();
        let recognized = match parse_line(line) {
            Some(Line::Default(s)) => {
                auto.default = s;
                true
            }
            Some(Line::Sequence(n, s)) => {
                sequences.insert(n, s);
                true
            }
            Some(Line::Window(n, w)) => {
                windows.push((n, w));
                true
            }
            None => false,
        };
        if recognized {
            after_recognized = true;
            continue;
        }
        if after_recognized && line.is_empty() {
            after_recognized = false;
            continue;
        }
        after_recognized = false;
        if !first {
            kept.push('\n');
        }
        kept.push_str(line);
        first = false;
    }
    windows.sort_by_key(|(n, _)| n.map_or(0, |v| v.saturating_add(1)));
    for (n, window) in windows {
        let sequence = n
            .and_then(|n| sequences.get(&n).cloned())
            .unwrap_or_default();
        auto.associations.push(Association {
            window,
            sequence,
            unknown: Vec::new(),
        });
    }
    (kept.into_secret(), auto)
}

enum Line {
    Default(String),
    Sequence(u64, String),
    Window(Option<u64>, String),
}

fn parse_line(line: &str) -> Option<Line> {
    let head = line.get(..9)?;
    if !head.eq_ignore_ascii_case("auto-type") {
        return None;
    }
    let rest = line.get(9..)?;
    // `: ` and at least one character; the rest is kept as it is (LD-148).
    let value = |r: &str| {
        r.strip_prefix(' ')
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    if let Some(r) = rest.strip_prefix(':') {
        return Some(Line::Default(value(r)?));
    }
    let r = rest.strip_prefix('-')?;
    if r.get(..6).is_some_and(|w| w.eq_ignore_ascii_case("window")) {
        let r = r.get(6..)?;
        if let Some(v) = r.strip_prefix(':') {
            return Some(Line::Window(None, value(v)?));
        }
        let (n, v) = r.strip_prefix('-')?.split_once(':')?;
        return Some(Line::Window(Some(number(n)?), value(v)?));
    }
    let (n, v) = r.split_once(':')?;
    Some(Line::Sequence(number(n)?, value(v)?))
}

fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // A number that does not fit a signed 32-bit value counts as 0 (LD-149).
    Some(
        s.parse::<i32>()
            .ok()
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0),
    )
}

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn packed_times() {
        let t = |b: [u8; 5]| packed(&b);
        let when = Time::from_civil(Civil {
            year: 2012,
            month: 5,
            day: 9,
            hour: 10,
            minute: 32,
            second: 0,
        });
        assert_eq!(t([0x1F, 0x71, 0x52, 0xA8, 0x00]), when);
        assert_eq!(t(NEVER), None);
        assert_eq!(t([0x1F, 0x70, 0x02, 0x00, 0x00]), None, "month 0");
    }

    #[test]
    fn auto_type_lines() {
        let (notes, a) = auto_type(
            "first\r\nAuto-Type: {USERNAME}{ENTER}\n\nauto-type-window-2: W2\nAuto-Type-Window: W0\nAuto-Type-2: {PASSWORD}\nAuto-Type-Window-1: W1\nlast line\nsee Auto-Type: x",
        );
        assert_eq!(notes.expose(), "first\nlast line\nsee Auto-Type: x");
        assert_eq!(a.default, "{USERNAME}{ENTER}");
        let pairs: Vec<(&str, &str)> = a
            .associations
            .iter()
            .map(|x| (x.window.as_str(), x.sequence.as_str()))
            .collect();
        assert_eq!(pairs, [("W0", ""), ("W1", ""), ("W2", "{PASSWORD}")]);
        // LD-148: `: ` and a value are needed; further spaces are kept.
        let (notes, a) = auto_type(
            "Auto-Type:
Auto-Type:x
Auto-Type-Window:  W",
        );
        assert_eq!(notes.expose(), "Auto-Type:\nAuto-Type:x");
        assert_eq!(a.associations.len(), 1);
        assert_eq!(
            a.associations.first().map(|x| x.window.as_str()),
            Some(" W")
        );
        // LD-149: a number above 2,147,483,647 counts as 0.
        let (notes, a) = auto_type(
            "Auto-Type-0: zero\nAuto-Type-Window-4294967296: W32\nAuto-Type-99999999999999999999: big\nend",
        );
        assert_eq!(notes.expose(), "end");
        let pairs: Vec<(&str, &str)> = a
            .associations
            .iter()
            .map(|x| (x.window.as_str(), x.sequence.as_str()))
            .collect();
        assert_eq!(pairs, [("W32", "big")]);
    }

    #[test]
    fn password_encodings() {
        let pw = SecretString::new("\u{201E}password\u{201D}".into());
        let tries = raw_keys(Some(&pw), None);
        // Windows-1252 holds both quotes; ISO-8859-1 cannot; UTF-8 differs.
        assert_eq!(tries.len(), 2);
        assert_eq!(
            tries[0].expose(),
            hash::sha256(&[b"\x84password\x94"]).expose()
        );
        let ascii = SecretString::new("abc".into());
        assert_eq!(raw_keys(Some(&ascii), None).len(), 1);
        assert_eq!(
            raw_keys(None, None)[0].expose(),
            hash::sha256(&[b""]).expose()
        );
    }
}
