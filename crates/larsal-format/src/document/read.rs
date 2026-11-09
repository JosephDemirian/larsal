//! Reads the vault document (FMT-10 to FMT-15) into an `larsal_model::Vault`.
//!
//! Guarantees:
//! - XML 1.0 in UTF-8 only; a DOCTYPE or an undefined entity is refused, no
//!   entity is ever expanded (FMT-10.8, FMT-10.9, AT-A07).
//! - Every count and size is checked against [`Limits`] when the element that
//!   would pass it starts, before anything is stored for it (FMT-11.48).
//! - Protected values take keystream bytes in document order, exactly for the
//!   value elements of FMT-12.29; kept unknown elements take none (FMT-09.14).
//! - Protected values go straight into `SecretString` or `SecretBytes`;
//!   attachment content always goes into `SecretBytes`.
//! - No panic, no hang, no recursion deeper than a fixed bound: groups and
//!   unknown elements are read with explicit stacks; duplicate ids are placed
//!   with bounded work (FMT-11.35, FMT-11.36).
//! - Errors and warnings name elements, limits or ids, never a value.

use super::encode::{
    attr_true, base64_decode_bytes, base64_decoded_len_bytes, decode_protected_text, is_xml_char,
    parse_bool, parse_i32, parse_switch, parse_time, parse_uuid, uuid_from_bytes,
};
use crate::buffer::Grow;
use crate::error::Error;
use crate::limits::{Limits, model_cost};
use larsal_crypto::secret::{SecretBytes, SecretString, ct_eq};
use larsal_crypto::stream::FieldStream;
use larsal_model::custom_data::clean_key;
use larsal_model::entry::{STANDARD_FIELDS, parse_tags};
use larsal_model::{
    Association, Attachment, AutoType, CustomData, CustomDataItem, CustomIcon, DeletedObject,
    Entry, Field, Group, Icon, Meta, Time, Times, UnknownElement, UnknownNode, Uuid, Vault,
};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::{QName, ResolveResult};
use quick_xml::reader::NsReader;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// The document's root element name, 11 ASCII bytes (stored encoded, name rule).
pub(crate) const ROOT_NAME: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
];

/// The legacy report flag key in entry custom data (FMT-14.19).
const KNOWN_BAD: &str = "KnownBad";
/// The container time item (FMT-14.18).
const LAST_MODIFIED: &str = "_LAST_MODIFIED";

/// What one read needs besides the document bytes.
pub struct Options<'a> {
    /// One UTC time, taken once when the read starts (FMT-11 "open time").
    pub open_time: Time,
    /// The limits of this read.
    pub limits: &'a Limits,
    /// For version 3 files, the outer header bytes the `HeaderHash` element
    /// covers (FMT-10.21); `None` for version 4, where it is ignored.
    pub v3_header: Option<&'a [u8]>,
}

/// Something the user or the debug log should know. Never holds a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// An attachment `Ref` matched no pool item; it has 0 bytes (FMT-13.11).
    DanglingAttachment {
        /// Owner entry.
        entry: Uuid,
    },
    /// A second attachment with a name already used got a new name (FMT-13.13).
    AttachmentRenamed {
        /// Owner entry.
        entry: Uuid,
    },
    /// A group or entry reference resolved to none (FMT-10.16, FMT-11.37).
    UnresolvedReference {
        /// Element name of the reference.
        element: &'static str,
    },
}

/// The result of a read.
#[derive(Debug)]
pub struct Document {
    /// The vault. `read_version` is left `None` for the caller to set.
    pub vault: Vault,
    /// Warnings, in the order they arose.
    pub warnings: Vec<Warning>,
}

pub use crate::limits::Limit;

/// Why a read failed: the detail for the debug log. [`Reason::kind`] gives
/// the `Error` the caller returns. Holds no value from the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Not well-formed XML (FMT-11.41, FMT-12.24, FMT-10.8 broken declaration).
    NotXml,
    /// A DOCTYPE or an undefined entity reference (FMT-10.9, FMT-11.42).
    ForbiddenDeclaration,
    /// UTF-16, UTF-32 or a declared encoding other than UTF-8 (FMT-10.8).
    UnsupportedEncoding,
    /// A declared XML version other than 1.0 of the 1.x shape (FMT-10.8).
    UnsupportedXmlVersion,
    /// No root element of the right name, no `Root`, or `Root` without `Group`.
    NoRootGroup,
    /// Two `Root` elements, or two `Group` children of `Root`.
    TwoRootGroups,
    /// A boolean that is not empty, `true` or `false` (FMT-12.10).
    InvalidBoolean,
    /// An integer that is not a 32-bit decimal (FMT-12.15).
    InvalidNumber,
    /// A group switch that is not `null`, `true` or `false` (FMT-12.12).
    InvalidSwitch,
    /// `String` without `Key` or `Value` (FMT-11.17).
    IncompleteField,
    /// A second `String` with a key whose value is not empty (FMT-11.18).
    DuplicateField,
    /// `Binary` without `Key` or `Value` (FMT-13.10).
    IncompleteAttachment,
    /// `Association` without `Window` or `KeystrokeSequence` (FMT-11.24).
    IncompleteAssociation,
    /// `History` inside a history item (FMT-11.31).
    NestedHistory,
    /// A child element inside a value element (FMT-12.23).
    ChildInValue,
    /// A custom data item without key or value (FMT-14.16).
    IncompleteCustomData,
    /// A custom icon without a usable id or without data (FMT-14.6).
    IncompleteIcon,
    /// A placement would put a group inside itself (FMT-11.36, LD-26).
    GroupInsideItself,
    /// A compressed pool item that does not gunzip (FMT-13.5).
    BadCompressedAttachment,
    /// Version 3 `HeaderHash` does not match the header (FMT-10.21).
    HeaderHashMismatch,
    /// The protected-field stream reached its limit.
    ProtectedStream,
    /// The system random source failed while making a fresh id.
    RandomSource,
    /// A limit of FMT-08.12 was passed.
    Limit(Limit),
    /// A `Protected="True"` value in a plain document, which has no
    /// protected-value stream ([`read_plain`]; FEA-08.62).
    ProtectedInPlain,
}

impl Reason {
    /// The error kind of FMT-01.33 for this reason.
    #[must_use]
    pub fn kind(self) -> Error {
        match self {
            Reason::Limit(l) => Error::TooLarge(l),
            Reason::UnsupportedEncoding | Reason::UnsupportedXmlVersion => Error::Unsupported,
            Reason::RandomSource => Error::Io(std::io::ErrorKind::Other),
            _ => Error::Corrupt,
        }
    }
}

impl From<Reason> for Error {
    fn from(r: Reason) -> Error {
        r.kind()
    }
}

type R<T> = Result<T, Reason>;

/// Reads a vault document.
///
/// `xml` is the decrypted, decompressed document; `stream` the protected-field
/// stream at byte 0 (FMT-09.11); `pool` the version 4 inner header pool items
/// in order (keys "0", "1", …; empty for version 3), as slices of the
/// decompressed payload: an item is copied out only when a `Ref` first uses
/// it, and that copy is charged to the model budget (LD-90).
///
/// Guarantees: see the module docs. On error nothing of the document is
/// returned.
///
/// # Errors
/// A [`Reason`]; its [`Reason::kind`] is `Corrupt`, `Unsupported`, `TooLarge`
/// or (random source failure) `Io`.
pub fn read<'a>(
    xml: &'a [u8],
    stream: &mut FieldStream,
    pool: &[&'a [u8]],
    opts: &Options<'a>,
) -> R<Document> {
    read_with(xml, stream, pool, opts, false)
}

/// Reads a plain XML document (the XML export, FEA-08.61, FEA-08.62): the
/// same rules with no protected-value stream. `ProtectInMemory="True"`
/// sets the protected flag; a `Meta/Binaries` pool resolves `Ref` numbers;
/// any value marked `Protected="True"` is refused with
/// [`Reason::ProtectedInPlain`] before it is decoded.
///
/// # Errors
/// As [`read`], plus [`Reason::ProtectedInPlain`].
pub fn read_plain<'a>(xml: &'a [u8], opts: &Options<'a>) -> R<Document> {
    // Never applied: a protected value is refused first.
    let zero = SecretBytes::zeroed(32);
    let mut stream =
        FieldStream::chacha20_from_stream_key(&zero).map_err(|_| Reason::ProtectedStream)?;
    read_with(xml, &mut stream, &[], opts, true)
}

fn read_with<'a>(
    xml: &'a [u8],
    stream: &mut FieldStream,
    pool: &[&'a [u8]],
    opts: &Options<'a>,
    plain: bool,
) -> R<Document> {
    if xml.len() > opts.limits.document {
        return Err(Reason::Limit(Limit::Document));
    }
    let body = prolog(xml)?;
    let mut p = Parser::new(body, stream, opts)?;
    p.plain = plain;
    p.pool.reserve(pool.len());
    for (i, item) in pool.iter().enumerate() {
        p.count_attachment_bytes(item.len())?;
        p.pool.insert(i.to_string(), Pooled::Payload(item));
    }
    p.pool_items = p.pool.len();
    p.document()?;
    p.finish(opts.v3_header)
}

// ---------------------------------------------------------------------------
// Prolog: encoding detection and the XML declaration (FMT-10.8).

/// Checks the start of the document and returns the bytes after the XML
/// declaration (or after a dropped `EF BB BF`).
fn prolog(xml: &[u8]) -> R<&[u8]> {
    const WIDE: [&[u8]; 8] = [
        &[0xFF, 0xFE, 0, 0],
        &[0, 0, 0xFE, 0xFF],
        &[0x3C, 0, 0, 0],
        &[0, 0, 0, 0x3C],
        &[0xFF, 0xFE],
        &[0xFE, 0xFF],
        &[0x3C, 0],
        &[0, 0x3C],
    ];
    if WIDE.iter().any(|w| xml.starts_with(w)) {
        return Err(Reason::UnsupportedEncoding);
    }
    let xml = xml.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(xml);
    let Some(rest) = xml.strip_prefix(b"<?") else {
        return Ok(xml);
    };
    let target_len = rest
        .iter()
        .position(|c| is_xml_space(*c) || *c == b'?')
        .unwrap_or(rest.len());
    let (target, after) = rest.split_at(target_len);
    if !target.eq_ignore_ascii_case(b"xml") {
        return Ok(xml); // an ordinary processing instruction
    }
    if target != b"xml" {
        return Err(Reason::NotXml);
    }
    let end = after
        .windows(2)
        .position(|w| w == b"?>")
        .ok_or(Reason::NotXml)?;
    let (decl, tail) = after.split_at(end);
    declaration(decl)?;
    Ok(tail.get(2..).unwrap_or(&[]))
}

fn is_xml_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn skip_space(s: &[u8]) -> (usize, &[u8]) {
    let n = s.iter().take_while(|c| is_xml_space(**c)).count();
    (n, s.get(n..).unwrap_or(&[]))
}

/// The pseudo-attributes of the XML declaration, strict form (FMT-10.8 steps
/// 3 to 5): `version` first, then any `encoding`, then any `standalone`.
fn declaration(mut s: &[u8]) -> R<()> {
    let mut stage = 0u8;
    let mut bad_version = false;
    let mut bad_encoding = false;
    loop {
        let (n, rest) = skip_space(s);
        s = rest;
        if s.is_empty() {
            break;
        }
        if n == 0 {
            return Err(Reason::NotXml);
        }
        let name_len = s
            .iter()
            .position(|c| *c == b'=' || is_xml_space(*c))
            .unwrap_or(s.len());
        let (name, rest) = s.split_at(name_len);
        let (_, rest) = skip_space(rest);
        let rest = rest.strip_prefix(b"=").ok_or(Reason::NotXml)?;
        let (_, rest) = skip_space(rest);
        let (&quote, rest) = rest.split_first().ok_or(Reason::NotXml)?;
        if quote != b'"' && quote != b'\'' {
            return Err(Reason::NotXml);
        }
        let close = rest
            .iter()
            .position(|c| *c == quote)
            .ok_or(Reason::NotXml)?;
        let (value, rest) = rest.split_at(close);
        s = rest.get(1..).unwrap_or(&[]);
        match (name, stage) {
            (b"version", 0) => {
                if value != b"1.0" {
                    let digits = value.strip_prefix(b"1.").unwrap_or(&[]);
                    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                        return Err(Reason::NotXml);
                    }
                    bad_version = true;
                }
                stage = 1;
            }
            (b"encoding", 1) => {
                let ok_shape = value.first().is_some_and(u8::is_ascii_alphabetic)
                    && value
                        .iter()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
                if !ok_shape {
                    return Err(Reason::NotXml);
                }
                let folded: Vec<u8> = value
                    .iter()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(u8::to_ascii_lowercase)
                    .collect();
                if folded != b"utf8" {
                    bad_encoding = true;
                }
            }
            (b"standalone", 1 | 2) => {
                if value != b"yes" && value != b"no" {
                    return Err(Reason::NotXml);
                }
                stage = 2;
            }
            _ => return Err(Reason::NotXml),
        }
    }
    if stage == 0 {
        Err(Reason::NotXml)
    } else if bad_version {
        Err(Reason::UnsupportedXmlVersion)
    } else if bad_encoding {
        Err(Reason::UnsupportedEncoding)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Events.

/// One start tag: its local name and its attributes (full names, values
/// after XML attribute normalization).
struct Tag<'a> {
    start: BytesStart<'a>,
    attrs: Vec<(String, String)>,
}

impl Tag<'_> {
    fn name(&self) -> &str {
        self.start.local_name().into_inner()
    }

    /// An attribute by its full name as written, prefix included (FMT-12.13).
    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn flag(&self, key: &str) -> bool {
        self.attr(key).is_some_and(attr_true)
    }
}

enum Ev<'a> {
    Start(Tag<'a>),
    End,
    Text(Cow<'a, str>),
    /// A character reference or predefined entity: one character, no heap
    /// block per reference (F-036).
    Char(char),
    Eof,
}

/// Raw content of a value element: plain text, or the XORed plaintext of a
/// protected value.
enum Raw<'a> {
    Plain(Text<'a>),
    Secret(SecretBytes),
}

/// One element's text as it is read (F-036, LD-85): a single borrowed slice
/// of the decrypted document when the parser gives the text in one piece (no
/// copy at all), otherwise one wiping buffer that each piece is appended to
/// as it arrives. Never a list of pieces, so memory stays a small multiple
/// of the text however many references, comments or CDATA sections split it.
/// Owned pieces (normalized line ends) are wiped as soon as they are copied.
struct Text<'a> {
    one: Option<&'a str>,
    buf: Grow,
}

impl<'a> Text<'a> {
    fn new() -> Self {
        Text {
            one: None,
            buf: Grow::new(),
        }
    }

    fn len(&self) -> usize {
        self.one.map_or(self.buf.len, str::len)
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Moves a held slice into the buffer before more text is added.
    fn spill(&mut self) {
        if let Some(b) = self.one.take() {
            self.buf.extend(b.as_bytes());
        }
    }

    fn push(&mut self, s: Cow<'a, str>) {
        match s {
            Cow::Borrowed(b) if self.one.is_none() && self.buf.len == 0 => self.one = Some(b),
            other => {
                self.spill();
                self.buf.extend(other.as_bytes());
                if let Cow::Owned(o) = other {
                    drop(SecretString::new(o)); // wiped, spare capacity included
                }
            }
        }
    }

    fn push_char(&mut self, c: char) {
        self.spill();
        let mut tmp = [0u8; 4];
        self.buf.extend(c.encode_utf8(&mut tmp).as_bytes());
    }

    fn bytes(&self) -> &[u8] {
        self.one.map_or_else(|| self.buf.as_slice(), str::as_bytes)
    }

    /// The text in one string of exactly its length.
    fn join(self) -> String {
        let b = self.bytes();
        let mut out = String::with_capacity(b.len());
        // Every piece came in as UTF-8 text, so the bytes are valid UTF-8.
        out.push_str(core::str::from_utf8(b).unwrap_or_default());
        out
    }

    /// Lenient base64 (FMT-12.20) straight into a buffer of its exact size.
    fn decode(&self) -> SecretBytes {
        let b = self.bytes();
        let mut buf = SecretBytes::zeroed(base64_decoded_len_bytes(b.iter().copied()));
        let mut slots = buf.expose_mut().iter_mut();
        base64_decode_bytes(b.iter().copied(), |x| {
            if let Some(s) = slots.next() {
                *s = x;
            }
        });
        buf
    }
}

// ---------------------------------------------------------------------------
// Reading state.

/// A pool item: still a slice of the payload, or its content copied out.
enum Pooled<'a> {
    Payload(&'a [u8]),
    Copied(Arc<SecretBytes>),
}

/// One `Bin` per `Binary` element of an entry, in document order.
enum Bin {
    Inline(String, Arc<SecretBytes>),
    Ref(String, String),
}

/// One `Entry` element, before ids and attachments are resolved.
struct EntryOcc {
    uuid: Uuid,
    entry: Entry,
    bins: Vec<Bin>,
    history: Vec<EntryOcc>,
}

/// One group element being read.
struct GroupState {
    uuid: Uuid,
    group: Group,
    cd: CdBuilder,
    child_groups: Vec<usize>,
    child_entries: Vec<usize>,
    /// Bytes of stray direct text, held to the text limit (LD-80).
    text: usize,
}

/// Attachment content keyed by its bytes: identical contents share one `Arc`
/// (one stored copy), so equality checks are pointer compares and each
/// content is hashed and compared once, however often it is referenced.
struct Content(Arc<SecretBytes>);

impl Hash for Content {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write(self.0.expose());
    }
}

impl PartialEq for Content {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for Content {}

/// One custom data container being read (FMT-14.16): items in read order
/// with an index by key, so merging, the legacy flag and the limits all take
/// constant time per item, however hostile the order.
#[derive(Default)]
struct CdBuilder {
    items: Vec<Option<CustomDataItem>>,
    index: HashMap<String, usize>,
    live: usize,
    /// `Item` elements read into this container, duplicates included.
    count: usize,
    unknown: Vec<UnknownElement>,
}

impl CdBuilder {
    /// A later item with the same key replaces the earlier one in place when
    /// the values differ; equal values keep the first item and its time.
    fn add(&mut self, item: CustomDataItem) {
        match self
            .index
            .get(&item.key)
            .and_then(|&i| self.items.get_mut(i))
        {
            Some(Some(old)) if old.value != item.value => *old = item,
            Some(_) => {}
            None => {
                self.index.insert(item.key.clone(), self.items.len());
                self.items.push(Some(item));
                self.live = self.live.saturating_add(1);
            }
        }
    }

    fn take(&mut self, key: &str) -> Option<CustomDataItem> {
        let i = self.index.remove(key)?;
        self.live = self.live.saturating_sub(1);
        self.items.get_mut(i).and_then(Option::take)
    }

    fn finish(self) -> CustomData {
        CustomData {
            items: self.items.into_iter().flatten().collect(),
            unknown: self.unknown,
        }
    }
}

/// Nodes kept in fixed-size chunks: growing never moves the nodes already
/// read, so no large buffer is copied and left behind; and a chunk is freed
/// as soon as it has been consumed (F-041, LD-90: a doubling list kept its
/// old buffer resident, about 270 MiB at the budget).
struct Nodes<T> {
    chunks: Vec<Vec<T>>,
    len: usize,
}

/// Nodes per chunk.
const CHUNK: usize = 4096;

impl<T> Nodes<T> {
    fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, node: T) {
        match self.chunks.last_mut() {
            Some(c) if c.len() < CHUNK => c.push(node),
            _ => {
                let mut c = Vec::with_capacity(CHUNK);
                c.push(node);
                self.chunks.push(c);
            }
        }
        self.len = self.len.saturating_add(1);
    }

    fn get(&self, i: usize) -> Option<&T> {
        self.chunks.get(i / CHUNK)?.get(i % CHUNK)
    }

    fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        self.chunks.get_mut(i / CHUNK)?.get_mut(i % CHUNK)
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.chunks.iter().flatten()
    }
}

impl<T> IntoIterator for Nodes<T> {
    type Item = T;
    type IntoIter = core::iter::Flatten<std::vec::IntoIter<Vec<T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter().flatten()
    }
}

/// One group object (all occurrences of one id).
struct GNode {
    group: Group,
    parent: Option<usize>,
    stamp: u32,
    /// `(child, stamp)` in placement order; stale items are skipped at the end.
    groups: Vec<(usize, u32)>,
    entries: Vec<(usize, u32)>,
}

/// One live entry object (all occurrences of one id).
struct ENode {
    last: EntryOcc,
    /// `Ref` attachments of earlier occurrences (FMT-11.35).
    earlier_refs: Vec<Bin>,
    /// History items of every occurrence, in document order.
    history: Vec<EntryOcc>,
    group: Option<usize>,
    stamp: u32,
}

struct Parser<'a, 's> {
    xml: NsReader<&'a [u8]>,
    /// A plain document: no stream, `Protected="True"` refused.
    plain: bool,
    pending_end: bool,
    open_elements: usize,
    stream: &'s mut FieldStream,
    lim: &'a Limits,
    open: Time,

    elements: usize,
    kept: usize,
    groups: usize,
    entries: usize,
    entry_elements: usize,
    pool_items: usize,
    attachment_bytes: usize,
    icons: usize,
    cd_items_all: usize,
    deleted: usize,
    /// Bytes charged to the model budget (LD-85).
    model: usize,

    meta: Meta,
    vault_cd: CdBuilder,
    icon_ids: HashSet<Uuid>,
    contents: HashSet<Content>,
    header_hash: Option<Vec<u8>>,
    pool: HashMap<String, Pooled<'a>>,
    gnodes: Nodes<GNode>,
    enodes: Nodes<ENode>,
    group_ids: HashMap<Uuid, usize>,
    entry_ids: HashMap<Uuid, usize>,
    root: Option<usize>,
    root_seen: bool,
    deleted_objects: Vec<DeletedObject>,
    unknown_document: Vec<UnknownElement>,
    unknown_root: Vec<UnknownElement>,
    unknown_deleted: Vec<UnknownElement>,
    warnings: Vec<Warning>,
}

/// Adds one to `count`; `TooLarge` naming `which` when it passes `limit`.
fn bump(count: &mut usize, limit: usize, which: Limit) -> R<()> {
    *count = count.saturating_add(1);
    if *count > limit {
        Err(Reason::Limit(which))
    } else {
        Ok(())
    }
}

fn fresh_id() -> R<Uuid> {
    larsal_crypto::random::uuid_v4()
        .map(Uuid)
        .map_err(|_| Reason::RandomSource)
}

impl<'a, 's> Parser<'a, 's> {
    fn new(body: &'a [u8], stream: &'s mut FieldStream, opts: &Options<'a>) -> R<Self> {
        let mut xml = NsReader::from_reader(body);
        let cfg = xml.config_mut();
        cfg.check_comments = true;
        cfg.check_end_names = true;
        cfg.expand_empty_elements = false;
        cfg.trim_text(false);
        Ok(Parser {
            xml,
            plain: false,
            pending_end: false,
            open_elements: 0,
            stream,
            lim: opts.limits,
            open: opts.open_time,
            elements: 0,
            kept: 0,
            groups: 0,
            entries: 0,
            entry_elements: 0,
            pool_items: 0,
            attachment_bytes: 0,
            icons: 0,
            cd_items_all: 0,
            deleted: 0,
            model: 0,
            meta: Meta::new(opts.open_time),
            vault_cd: CdBuilder::default(),
            icon_ids: HashSet::new(),
            contents: HashSet::new(),
            header_hash: None,
            pool: HashMap::new(),
            gnodes: Nodes::new(),
            enodes: Nodes::new(),
            group_ids: HashMap::new(),
            entry_ids: HashMap::new(),
            root: None,
            root_seen: false,
            deleted_objects: Vec::new(),
            unknown_document: Vec::new(),
            unknown_root: Vec::new(),
            unknown_deleted: Vec::new(),
            warnings: Vec::new(),
        })
    }

    // -- events ------------------------------------------------------------

    fn next(&mut self) -> R<Ev<'a>> {
        if self.pending_end {
            self.pending_end = false;
            self.open_elements = self.open_elements.saturating_sub(1);
            return Ok(Ev::End);
        }
        loop {
            let (res, event) = self.xml.read_resolved_event().map_err(|_| Reason::NotXml)?;
            let unknown_prefix = matches!(res, ResolveResult::Unknown(_));
            match event {
                Event::Start(e) => return self.start(e, false, unknown_prefix),
                Event::Empty(e) => return self.start(e, true, unknown_prefix),
                Event::End(_) => {
                    self.open_elements = self.open_elements.saturating_sub(1);
                    return Ok(Ev::End);
                }
                Event::Text(t) => return checked_text(t.xml10_content()).map(Ev::Text),
                Event::CData(c) => return checked_text(c.xml10_content()).map(Ev::Text),
                Event::GeneralRef(r) => return Ok(Ev::Char(general_ref(&r)?)),
                Event::Comment(_) => {}
                Event::PI(pi) => {
                    if pi.target().eq_ignore_ascii_case("xml") {
                        return Err(Reason::NotXml);
                    }
                }
                Event::Decl(_) => return Err(Reason::NotXml),
                Event::DocType(_) => return Err(Reason::ForbiddenDeclaration),
                Event::Eof => return Ok(Ev::Eof),
            }
        }
    }

    fn start(&mut self, e: BytesStart<'a>, empty: bool, unknown_prefix: bool) -> R<Ev<'a>> {
        if unknown_prefix || !is_qname(e.name().into_inner()) {
            return Err(Reason::NotXml);
        }
        bump(&mut self.elements, self.lim.elements, Limit::Elements)?;
        if self.open_elements > self.lim.depth {
            return Err(Reason::Limit(Limit::Depth));
        }
        self.open_elements = self.open_elements.saturating_add(1);
        let mut attrs = Vec::new();
        for a in e.attributes().with_checks(true) {
            let a = a.map_err(|_| Reason::NotXml)?;
            let key = a.key.into_inner();
            if !is_qname(key) {
                return Err(Reason::NotXml);
            }
            if let Some((prefix, _)) = key.split_once(':')
                && prefix != "xmlns"
                && prefix != "xml"
                && matches!(
                    self.xml.resolver().resolve_attribute(QName(key)).0,
                    ResolveResult::Unknown(_)
                )
            {
                return Err(Reason::NotXml);
            }
            let value = a
                .normalized_value(XmlVersion::Explicit1_0)
                .map_err(|_| Reason::NotXml)?;
            if value.len() > self.lim.text {
                return Err(Reason::Limit(Limit::Text));
            }
            if !value.chars().all(is_xml_char) {
                return Err(Reason::NotXml);
            }
            attrs.push((key.to_owned(), value.into_owned()));
        }
        if empty {
            self.pending_end = true;
        }
        Ok(Ev::Start(Tag { start: e, attrs }))
    }

    /// Calls `f` for each child start tag until the end tag of the current
    /// element; text between children is stray and ignored (FMT-11.43), but
    /// held to the text limit (LD-80).
    fn children(&mut self, mut f: impl FnMut(&mut Self, Tag<'a>) -> R<()>) -> R<()> {
        let mut text = 0usize;
        loop {
            match self.next()? {
                Ev::Start(t) => f(self, t)?,
                Ev::End => return Ok(()),
                Ev::Text(s) => self.count_text(&mut text, s.len())?,
                Ev::Char(c) => self.count_text(&mut text, c.len_utf8())?,
                Ev::Eof => return Err(Reason::NotXml),
            }
        }
    }

    /// Adds `n` bytes to the model budget (FMT-08.12 `model`, LD-85):
    /// `TooLarge` the moment it passes, before the object is stored.
    fn charge(&mut self, n: usize) -> R<()> {
        self.model = self.model.saturating_add(n);
        if self.model > self.lim.model {
            return Err(Reason::Limit(Limit::Model));
        }
        Ok(())
    }

    /// A kept unknown element for `tag`, charged to the model budget with
    /// its kept attributes.
    fn kept_element(&mut self, tag: &Tag<'a>) -> R<UnknownElement> {
        let el = new_unknown(tag);
        let attrs = el
            .attributes
            .iter()
            .map(|(k, v)| {
                k.len()
                    .saturating_add(v.len())
                    .saturating_add(model_cost::STRING_PAIR)
            })
            .fold(
                model_cost::UNKNOWN.saturating_add(el.name.len()),
                usize::saturating_add,
            );
        self.charge(attrs)?;
        Ok(el)
    }

    /// Adds `n` bytes to one element's direct text; `TooLarge` past the text
    /// limit (FMT-08.12, LD-80).
    fn count_text(&self, text: &mut usize, n: usize) -> R<()> {
        *text = text.saturating_add(n);
        if *text > self.lim.text {
            return Err(Reason::Limit(Limit::Text));
        }
        Ok(())
    }

    /// Consumes the rest of an element without keeping anything; dropped
    /// unknown children take no keystream bytes (FMT-11.45). Each element's
    /// direct text is still held to the text limit (LD-80).
    fn skip(&mut self) -> R<()> {
        let mut text: Vec<usize> = vec![0];
        loop {
            match self.next()? {
                Ev::Start(_) => text.push(0),
                Ev::End => {
                    text.pop();
                    if text.is_empty() {
                        return Ok(());
                    }
                }
                Ev::Text(s) => {
                    let mut n = text.pop().ok_or(Reason::NotXml)?;
                    self.count_text(&mut n, s.len())?;
                    text.push(n);
                }
                Ev::Char(c) => {
                    let mut n = text.pop().ok_or(Reason::NotXml)?;
                    self.count_text(&mut n, c.len_utf8())?;
                    text.push(n);
                }
                Ev::Eof => return Err(Reason::NotXml),
            }
        }
    }

    /// Keeps an unknown element and everything inside it (FMT-10.20,
    /// FMT-10.27, FMT-11.45). Reads no protected value.
    fn unknown(&mut self, tag: Tag<'a>) -> R<UnknownElement> {
        bump(&mut self.kept, self.lim.kept_unknown, Limit::KeptUnknown)?;
        let first = self.kept_element(&tag)?;
        let mut stack: Vec<(UnknownElement, usize)> = vec![(first, 0)];
        loop {
            match self.next()? {
                Ev::Start(t) => {
                    bump(&mut self.kept, self.lim.kept_unknown, Limit::KeptUnknown)?;
                    let el = self.kept_element(&t)?;
                    stack.push((el, 0));
                }
                Ev::Text(s) => {
                    self.charge(s.len())?;
                    let (el, text_len) = stack.last_mut().ok_or(Reason::NotXml)?;
                    *text_len = text_len.saturating_add(s.len());
                    if *text_len > self.lim.text {
                        return Err(Reason::Limit(Limit::Text));
                    }
                    match el.content.last_mut() {
                        Some(UnknownNode::Text(prev)) => prev.push_str(&s),
                        _ => el.content.push(UnknownNode::Text(s.into_owned())),
                    }
                }
                Ev::Char(c) => {
                    self.charge(c.len_utf8())?;
                    let (el, text_len) = stack.last_mut().ok_or(Reason::NotXml)?;
                    *text_len = text_len.saturating_add(c.len_utf8());
                    if *text_len > self.lim.text {
                        return Err(Reason::Limit(Limit::Text));
                    }
                    match el.content.last_mut() {
                        Some(UnknownNode::Text(prev)) => prev.push(c),
                        _ => el.content.push(UnknownNode::Text(c.to_string())),
                    }
                }
                Ev::End => {
                    let (el, _) = stack.pop().ok_or(Reason::NotXml)?;
                    match stack.last_mut() {
                        Some((parent, _)) => parent.content.push(UnknownNode::Element(el)),
                        None => {
                            let mut el = el;
                            drop_layout_whitespace(&mut el);
                            return Ok(el);
                        }
                    }
                }
                Ev::Eof => return Err(Reason::NotXml),
            }
        }
    }

    // -- values ------------------------------------------------------------

    /// The text of a value element up to its end tag (FMT-12.23). `limit`
    /// is the text limit, or `None` for base64 attachment text (exempt,
    /// bounded by the document size, FMT-08.12).
    /// Text values held to the text limit are model text and are charged to
    /// the model budget as they are read; base64 attachment text is bounded
    /// by the attachment limits instead.
    fn text(&mut self, limit: Option<usize>) -> R<Text<'a>> {
        let mut out = Text::new();
        loop {
            let n = match self.next()? {
                Ev::Text(s) => {
                    let n = s.len();
                    if limit.is_some_and(|l| out.len().saturating_add(n) > l) {
                        return Err(Reason::Limit(Limit::Text));
                    }
                    out.push(s);
                    n
                }
                Ev::Char(c) => {
                    if limit.is_some_and(|l| out.len().saturating_add(c.len_utf8()) > l) {
                        return Err(Reason::Limit(Limit::Text));
                    }
                    out.push_char(c);
                    c.len_utf8()
                }
                Ev::End => return Ok(out),
                Ev::Start(_) => return Err(Reason::ChildInValue),
                Ev::Eof => return Err(Reason::NotXml),
            };
            if limit.is_some() {
                self.charge(n)?;
            }
        }
    }

    /// A value element's content, decrypted with the next keystream bytes
    /// when its `Protected` attribute is true and its text decodes to at
    /// least one byte (FMT-12.22).
    fn raw(&mut self, tag: &Tag<'a>, limit: Option<usize>) -> R<Raw<'a>> {
        if self.plain && tag.flag("Protected") {
            return Err(Reason::ProtectedInPlain);
        }
        let text = self.text(limit)?;
        if !tag.flag("Protected") || text.is_empty() {
            return Ok(Raw::Plain(text));
        }
        let mut buf = text.decode();
        if buf.is_empty() {
            return Ok(Raw::Plain(Text::new()));
        }
        self.stream
            .apply(buf.expose_mut())
            .map_err(|_| Reason::ProtectedStream)?;
        Ok(Raw::Secret(buf))
    }

    /// A text-group value as plain text.
    fn text_value(&mut self, tag: &Tag<'a>) -> R<String> {
        Ok(match self.raw(tag, Some(self.lim.text))? {
            Raw::Plain(p) => p.join(),
            Raw::Secret(b) => decode_protected_text(b.expose()),
        })
    }

    /// A text-group value straight into a secret string: one allocation of
    /// the exact size either way, so no unwiped copy is left behind.
    fn secret_value(&mut self, tag: &Tag<'a>) -> R<SecretString> {
        Ok(SecretString::new(
            match self.raw(tag, Some(self.lim.text))? {
                Raw::Plain(p) => p.join(),
                Raw::Secret(b) => decode_protected_text(b.expose()),
            },
        ))
    }

    /// A byte-group value (FMT-12.22): lenient base64, XOR when protected;
    /// decoded from the text pieces straight into its buffer (B4).
    fn bytes_value(&mut self, tag: &Tag<'a>, limit: Option<usize>) -> R<SecretBytes> {
        Ok(match self.raw(tag, limit)? {
            Raw::Secret(b) => b,
            Raw::Plain(p) => p.decode(),
        })
    }

    fn uuid_value(&mut self, tag: &Tag<'a>) -> R<Uuid> {
        Ok(match self.raw(tag, Some(self.lim.text))? {
            Raw::Plain(p) => parse_uuid(&p.join()),
            Raw::Secret(b) => uuid_from_bytes(b.expose()),
        })
    }

    fn bool_value(&mut self, tag: &Tag<'a>) -> R<bool> {
        parse_bool(&self.text_value(tag)?).ok_or(Reason::InvalidBoolean)
    }

    fn int_value(&mut self, tag: &Tag<'a>) -> R<i32> {
        parse_i32(&self.text_value(tag)?).ok_or(Reason::InvalidNumber)
    }

    fn time_value(&mut self, tag: &Tag<'a>) -> R<Time> {
        Ok(parse_time(&self.text_value(tag)?, self.open))
    }

    fn count_attachment_bytes(&mut self, n: usize) -> R<()> {
        if n > self.lim.one_attachment {
            return Err(Reason::Limit(Limit::OneAttachment));
        }
        self.attachment_bytes = self.attachment_bytes.saturating_add(n);
        if self.attachment_bytes > self.lim.all_attachments {
            return Err(Reason::Limit(Limit::AllAttachments));
        }
        Ok(())
    }

    /// The shared copy of `data`: an earlier identical content, or `data`.
    fn intern(&mut self, data: SecretBytes) -> Arc<SecretBytes> {
        let c = Content(Arc::new(data));
        if let Some(old) = self.contents.get(&c) {
            return Arc::clone(&old.0);
        }
        let shared = Arc::clone(&c.0);
        self.contents.insert(c);
        shared
    }

    // -- document frame ----------------------------------------------------

    fn document(&mut self) -> R<()> {
        let tag = loop {
            match self.next()? {
                Ev::Start(t) => break t,
                Ev::Text(s) if s.bytes().all(is_xml_space) => {}
                Ev::Text(_) | Ev::Char(_) => return Err(Reason::NotXml),
                Ev::End | Ev::Eof => return Err(Reason::NoRootGroup),
            }
        };
        if tag.name().as_bytes() != ROOT_NAME {
            return Err(Reason::NoRootGroup);
        }
        // Reading stops at the root end tag; what follows is never read (FMT-10.5).
        self.children(|p, t| match t.name() {
            "Meta" => p.meta_el(),
            "Root" => p.root_el(),
            _ => {
                let u = p.unknown(t)?;
                p.unknown_document.push(u);
                Ok(())
            }
        })?;
        if !self.root_seen {
            return Err(Reason::NoRootGroup);
        }
        Ok(())
    }

    fn root_el(&mut self) -> R<()> {
        if self.root_seen {
            return Err(Reason::TwoRootGroups);
        }
        self.root_seen = true;
        self.children(|p, t| match t.name() {
            "Group" => {
                if p.root.is_some() {
                    return Err(Reason::TwoRootGroups);
                }
                let idx = p.group_tree()?;
                p.root = Some(idx);
                Ok(())
            }
            "DeletedObjects" => p.deleted_objects_el(),
            _ => {
                let u = p.unknown(t)?;
                p.unknown_root.push(u);
                Ok(())
            }
        })?;
        if self.root.is_none() {
            return Err(Reason::NoRootGroup);
        }
        Ok(())
    }

    // -- Meta (FMT-10) -----------------------------------------------------

    fn meta_el(&mut self) -> R<()> {
        self.children(|p, t| {
            match t.name() {
                "Generator" => p.meta.generator = p.text_value(&t)?,
                "HeaderHash" => {
                    p.header_hash = Some(p.bytes_value(&t, Some(p.lim.text))?.expose().to_vec());
                }
                "DatabaseName" => p.meta.name = p.text_value(&t)?,
                "DatabaseNameChanged" => p.meta.name_changed = p.time_value(&t)?,
                "DatabaseDescription" => p.meta.description = p.text_value(&t)?,
                "DatabaseDescriptionChanged" => p.meta.description_changed = p.time_value(&t)?,
                "DefaultUserName" => p.meta.default_user_name = p.text_value(&t)?,
                "DefaultUserNameChanged" => p.meta.default_user_name_changed = p.time_value(&t)?,
                "MaintenanceHistoryDays" => p.meta.maintenance_history_days = p.int_value(&t)?,
                "Color" => p.meta.color = p.text_value(&t)?,
                "MasterKeyChanged" => p.meta.master_key_changed = p.time_value(&t)?,
                "MasterKeyChangeRec" => p.meta.master_key_change_rec = p.int_value(&t)?,
                "MasterKeyChangeForce" => p.meta.master_key_change_force = p.int_value(&t)?,
                "MasterKeyChangeForceOnce" => {
                    // Known only to Larsal: never decrypted, never rejects (MOD-13.13).
                    let text = p.text(Some(p.lim.text))?.join();
                    p.meta.master_key_change_force_once = parse_bool(&text) == Some(true);
                }
                "MemoryProtection" => p.memory_protection()?,
                "CustomIcons" => p.custom_icons()?,
                "RecycleBinEnabled" => p.meta.recycle_bin_enabled = p.bool_value(&t)?,
                "RecycleBinUUID" => p.meta.recycle_bin = p.uuid_value(&t)?.non_zero(),
                "RecycleBinChanged" => p.meta.recycle_bin_changed = p.time_value(&t)?,
                "EntryTemplatesGroup" => {
                    p.meta.entry_templates_group = p.uuid_value(&t)?.non_zero()
                }
                "EntryTemplatesGroupChanged" => {
                    p.meta.entry_templates_group_changed = p.time_value(&t)?;
                }
                "LastSelectedGroup" => p.meta.last_selected_group = p.uuid_value(&t)?.non_zero(),
                "LastTopVisibleGroup" => {
                    p.meta.last_top_visible_group = p.uuid_value(&t)?.non_zero();
                }
                "HistoryMaxItems" => {
                    let v = p.int_value(&t)?;
                    if v >= -1 {
                        p.meta.history_max_items = v;
                    }
                }
                "HistoryMaxSize" => {
                    let v = p.int_value(&t)?;
                    if v >= -1 {
                        p.meta.history_max_size = v;
                    }
                }
                "SettingsChanged" => p.meta.settings_changed = p.time_value(&t)?,
                "Binaries" => p.binaries()?,
                "CustomData" => {
                    let mut cd = core::mem::take(&mut p.vault_cd);
                    p.custom_data(&mut cd)?;
                    p.vault_cd = cd;
                }
                _ => {
                    let u = p.unknown(t)?;
                    p.meta.unknown.push(u);
                }
            }
            Ok(())
        })
    }

    fn memory_protection(&mut self) -> R<()> {
        self.children(|p, t| {
            match t.name() {
                "ProtectTitle" => p.meta.memory_protection.title = p.bool_value(&t)?,
                "ProtectUserName" => p.meta.memory_protection.user_name = p.bool_value(&t)?,
                "ProtectPassword" => p.meta.memory_protection.password = p.bool_value(&t)?,
                "ProtectURL" => p.meta.memory_protection.url = p.bool_value(&t)?,
                "ProtectNotes" => p.meta.memory_protection.notes = p.bool_value(&t)?,
                _ => {
                    let u = p.unknown(t)?;
                    p.meta.memory_protection.unknown.push(u);
                }
            }
            Ok(())
        })
    }

    fn custom_icons(&mut self) -> R<()> {
        self.children(|p, t| {
            if t.name() != "Icon" {
                let u = p.unknown(t)?;
                p.meta.custom_icons_unknown.push(u);
                return Ok(());
            }
            bump(&mut p.icons, p.lim.icons, Limit::Icons)?;
            p.charge(model_cost::ICON)?;
            let mut uuid = None;
            let mut data = None;
            let mut icon = CustomIcon {
                uuid: Uuid::ZERO,
                name: String::new(),
                last_modified: None,
                data: Vec::new(),
                unknown: Vec::new(),
            };
            p.children(|p, t| {
                match t.name() {
                    "UUID" => uuid = Some(p.uuid_value(&t)?),
                    "Name" => icon.name = p.text_value(&t)?,
                    "LastModificationTime" => icon.last_modified = Some(p.time_value(&t)?),
                    "Data" => data = Some(p.bytes_value(&t, Some(p.lim.text))?.expose().to_vec()),
                    _ => {
                        let u = p.unknown(t)?;
                        icon.unknown.push(u);
                    }
                }
                Ok(())
            })?;
            icon.uuid = uuid
                .and_then(Uuid::non_zero)
                .ok_or(Reason::IncompleteIcon)?;
            icon.data = data.ok_or(Reason::IncompleteIcon)?;
            if !p.icon_ids.insert(icon.uuid) {
                icon.uuid = fresh_id()?; // FMT-14.7
                p.icon_ids.insert(icon.uuid);
            }
            p.meta.custom_icons.push(icon);
            Ok(())
        })
    }

    /// `Meta/Binaries` items join the pool (FMT-13.5 to FMT-13.7).
    fn binaries(&mut self) -> R<()> {
        self.children(|p, t| {
            if t.name() != "Binary" {
                return p.skip();
            }
            bump(&mut p.pool_items, p.lim.pool_items, Limit::PoolItems)?;
            let key = t.attr("ID").unwrap_or("").to_owned();
            let compressed = t.flag("Compressed");
            let raw = p.bytes_value(&t, None)?;
            let data = if compressed && !raw.is_empty() {
                // The shared strict gunzip (FMT-08.6), bounded while inflating
                // by the room left under both attachment limits (FMT-13.20).
                let room = p.lim.all_attachments.saturating_sub(p.attachment_bytes);
                let cap = p.lim.one_attachment.min(room);
                crate::payload::gunzip(raw.expose(), cap).map_err(|e| match e {
                    Error::TooLarge(_) if cap < p.lim.one_attachment => {
                        Reason::Limit(Limit::AllAttachments)
                    }
                    Error::TooLarge(_) => Reason::Limit(Limit::OneAttachment),
                    _ => Reason::BadCompressedAttachment,
                })?
            } else {
                raw
            };
            p.count_attachment_bytes(data.len())?;
            p.charge(data.len())?;
            let shared = p.intern(data);
            p.pool.insert(key, Pooled::Copied(shared));
            Ok(())
        })
    }

    /// One `CustomData` block into `cd` (FMT-14.16).
    fn custom_data(&mut self, cd: &mut CdBuilder) -> R<()> {
        self.children(|p, t| {
            if t.name() != "Item" {
                let u = p.unknown(t)?;
                cd.unknown.push(u);
                return Ok(());
            }
            bump(
                &mut cd.count,
                p.lim.custom_data_items,
                Limit::CustomDataItems,
            )?;
            bump(
                &mut p.cd_items_all,
                p.lim.custom_data_items_all,
                Limit::CustomDataItemsAll,
            )?;
            p.charge(model_cost::CUSTOM_DATA_ITEM)?;
            let mut key = None;
            let mut value = None;
            let mut item = CustomDataItem {
                key: String::new(),
                value: SecretString::new(String::new()),
                last_modified: None,
                unknown: Vec::new(),
            };
            p.children(|p, t| {
                match t.name() {
                    "Key" => key = Some(p.text_value(&t)?),
                    "Value" => value = Some(p.secret_value(&t)?),
                    "LastModificationTime" => item.last_modified = Some(p.time_value(&t)?),
                    _ => {
                        let u = p.unknown(t)?;
                        item.unknown.push(u);
                    }
                }
                Ok(())
            })?;
            // FMT-14.10: the key as a save would write it, so two spellings are one key.
            item.key = clean_key(&key.ok_or(Reason::IncompleteCustomData)?);
            item.value = value.ok_or(Reason::IncompleteCustomData)?;
            cd.add(item);
            Ok(())
        })
    }

    // -- groups (FMT-11.6 to FMT-11.11, FMT-11.33 to FMT-11.37) -------------

    /// Reads the root group and everything in it with an explicit stack;
    /// returns its node.
    fn group_tree(&mut self) -> R<usize> {
        bump(&mut self.groups, self.lim.groups, Limit::Groups)?;
        self.charge(model_cost::GROUP)?;
        let mut stack = vec![self.new_group_state()];
        loop {
            match self.next()? {
                Ev::Start(t) if t.name() == "Group" => {
                    bump(&mut self.groups, self.lim.groups, Limit::Groups)?;
                    self.charge(model_cost::GROUP)?;
                    stack.push(self.new_group_state());
                }
                Ev::Start(t) => {
                    let top = stack.last_mut().ok_or(Reason::NotXml)?;
                    self.group_child(top, t)?;
                }
                Ev::Text(s) => {
                    let top = stack.last_mut().ok_or(Reason::NotXml)?;
                    top.text = top.text.saturating_add(s.len());
                    if top.text > self.lim.text {
                        return Err(Reason::Limit(Limit::Text));
                    }
                }
                Ev::Char(c) => {
                    let top = stack.last_mut().ok_or(Reason::NotXml)?;
                    top.text = top.text.saturating_add(c.len_utf8());
                    if top.text > self.lim.text {
                        return Err(Reason::Limit(Limit::Text));
                    }
                }
                Ev::End => {
                    let st = stack.pop().ok_or(Reason::NotXml)?;
                    let idx = self.close_group(st)?;
                    match stack.last_mut() {
                        Some(parent) => parent.child_groups.push(idx),
                        None => return Ok(idx),
                    }
                }
                Ev::Eof => return Err(Reason::NotXml),
            }
        }
    }

    fn new_group_state(&self) -> GroupState {
        GroupState {
            uuid: Uuid::ZERO,
            group: Group::new(Uuid::ZERO, String::new(), self.open),
            cd: CdBuilder::default(),
            child_groups: Vec::new(),
            child_entries: Vec::new(),
            text: 0,
        }
    }

    fn group_child(&mut self, st: &mut GroupState, t: Tag<'a>) -> R<()> {
        let g = &mut st.group;
        match t.name() {
            "UUID" => st.uuid = self.uuid_value(&t)?,
            "Name" => g.name = self.text_value(&t)?,
            "Notes" => g.notes = self.text_value(&t)?,
            "Tags" => g.tags = self.text_value(&t)?,
            "IconID" => g.icon = Icon::Standard(self.int_value(&t)?.max(0)),
            "CustomIconUUID" => {
                if let Some(id) = self.uuid_value(&t)?.non_zero() {
                    g.icon = Icon::Custom(id);
                }
            }
            "Times" => g.times = self.times()?,
            "IsExpanded" => g.expanded = self.bool_value(&t)?,
            "DefaultAutoTypeSequence" => g.default_sequence = self.text_value(&t)?,
            "EnableAutoType" => {
                g.auto_type = parse_switch(&self.text_value(&t)?).ok_or(Reason::InvalidSwitch)?;
            }
            "EnableSearching" => {
                g.searching = parse_switch(&self.text_value(&t)?).ok_or(Reason::InvalidSwitch)?;
            }
            "LastTopVisibleEntry" => g.last_top_visible_entry = self.uuid_value(&t)?.non_zero(),
            "CustomData" => {
                let mut cd = core::mem::take(&mut st.cd);
                self.custom_data(&mut cd)?;
                st.cd = cd;
            }
            "PreviousParentGroup" => g.previous_parent = self.uuid_value(&t)?.non_zero(),
            "Entry" => {
                bump(&mut self.entries, self.lim.entries, Limit::Entries)?;
                bump(
                    &mut self.entry_elements,
                    self.lim.entry_elements,
                    Limit::EntryElements,
                )?;
                self.charge(model_cost::ENTRY_NODE)?;
                let occ = self.entry(false)?;
                let idx = self.register_entry(occ)?;
                st.child_entries.push(idx);
            }
            _ => {
                let u = self.unknown(t)?;
                st.group.unknown.push(u);
            }
        }
        Ok(())
    }

    /// Ends a group element: gives it its id, merges it with an earlier
    /// occurrence of the id, and places its children (FMT-11.35, FMT-11.36).
    fn close_group(&mut self, st: GroupState) -> R<usize> {
        let GroupState {
            uuid,
            mut group,
            cd,
            child_groups,
            child_entries,
            ..
        } = st;
        let id = match uuid.non_zero() {
            Some(id) => id,
            None => fresh_id()?,
        };
        group.uuid = id;
        group.custom_data = cd.finish();
        let p = if let Some(&i) = self.group_ids.get(&id) {
            let node = self.gnodes.get_mut(i).ok_or(Reason::NotXml)?;
            node.group = group;
            i
        } else {
            let i = self.gnodes.len();
            self.gnodes.push(GNode {
                group,
                parent: None,
                stamp: 0,
                groups: Vec::new(),
                entries: Vec::new(),
            });
            self.group_ids.insert(id, i);
            i
        };
        for c in child_groups {
            // Cycle check on the tree as it is now (FMT-11.36); the walk is
            // bounded: a chain longer than the depth limit is TooLarge.
            let mut at = Some(p);
            let mut steps = 0usize;
            while let Some(x) = at {
                if x == c {
                    return Err(Reason::GroupInsideItself);
                }
                bump(&mut steps, self.lim.depth, Limit::Depth)?;
                at = self.gnodes.get(x).and_then(|n| n.parent);
            }
            let child = self.gnodes.get_mut(c).ok_or(Reason::NotXml)?;
            child.stamp = child.stamp.wrapping_add(1);
            child.parent = Some(p);
            let stamp = child.stamp;
            self.gnodes
                .get_mut(p)
                .ok_or(Reason::NotXml)?
                .groups
                .push((c, stamp));
        }
        for e in child_entries {
            let node = self.enodes.get_mut(e).ok_or(Reason::NotXml)?;
            if node.group == Some(p) {
                continue; // stays at its current place
            }
            node.stamp = node.stamp.wrapping_add(1);
            node.group = Some(p);
            let stamp = node.stamp;
            self.gnodes
                .get_mut(p)
                .ok_or(Reason::NotXml)?
                .entries
                .push((e, stamp));
        }
        Ok(p)
    }

    // -- entries (FMT-11.15 to FMT-11.32) ----------------------------------

    fn register_entry(&mut self, occ: EntryOcc) -> R<usize> {
        let id = match occ.uuid.non_zero() {
            Some(id) => id,
            None => fresh_id()?,
        };
        let mut occ = occ;
        occ.uuid = id;
        occ.entry.uuid = id;
        let history = core::mem::take(&mut occ.history);
        if let Some(&i) = self.entry_ids.get(&id) {
            let node = self.enodes.get_mut(i).ok_or(Reason::NotXml)?;
            let old = core::mem::replace(&mut node.last, occ);
            node.earlier_refs
                .extend(old.bins.into_iter().filter(|b| matches!(b, Bin::Ref(..))));
            node.history.extend(history);
            // The per-entry limits apply to the merged entry (LD-86).
            if node.earlier_refs.len().saturating_add(node.last.bins.len()) > self.lim.attachments {
                return Err(Reason::Limit(Limit::Attachments));
            }
            if node.history.len() > self.lim.history {
                return Err(Reason::Limit(Limit::History));
            }
            Ok(i)
        } else {
            let i = self.enodes.len();
            self.enodes.push(ENode {
                last: occ,
                earlier_refs: Vec::new(),
                history,
                group: None,
                stamp: 0,
            });
            self.entry_ids.insert(id, i);
            Ok(i)
        }
    }

    fn entry(&mut self, history_item: bool) -> R<EntryOcc> {
        self.charge(model_cost::ENTRY)?;
        let mut occ = EntryOcc {
            uuid: Uuid::ZERO,
            entry: Entry::new(Uuid::ZERO, self.open),
            bins: Vec::new(),
            history: Vec::new(),
        };
        let mut strings = 0usize;
        let mut associations = 0usize;
        let mut history_items = 0usize;
        let mut cd = CdBuilder::default();
        // Fields in read order with an index by name; sorted once at the end.
        let mut fields: Vec<(String, Field)> = Vec::with_capacity(STANDARD_FIELDS.len());
        let mut names: HashMap<String, usize> = HashMap::new();
        for name in STANDARD_FIELDS {
            names.insert(name.to_owned(), fields.len());
            fields.push((name.to_owned(), Field::empty()));
        }
        self.children(|p, t| {
            let e = &mut occ.entry;
            match t.name() {
                "UUID" => occ.uuid = p.uuid_value(&t)?,
                "IconID" => e.icon = Icon::Standard(p.int_value(&t)?.max(0)),
                "CustomIconUUID" => {
                    if let Some(id) = p.uuid_value(&t)?.non_zero() {
                        e.icon = Icon::Custom(id);
                    }
                }
                "ForegroundColor" => e.foreground_color = p.text_value(&t)?,
                "BackgroundColor" => e.background_color = p.text_value(&t)?,
                "OverrideURL" => e.override_url = p.text_value(&t)?,
                "Tags" => {
                    let text = p.text_value(&t)?;
                    // Every tag read is charged before the set is built
                    // (LD-85), duplicates included.
                    let read = text
                        .split([',', ';', '\t'])
                        .filter(|x| !x.trim().is_empty())
                        .count();
                    p.charge(model_cost::TAG.saturating_mul(read))?;
                    e.set_tags(parse_tags(&text));
                }
                "Times" => e.times = p.times()?,
                "QualityCheck" => e.exclude_from_reports = !p.bool_value(&t)?,
                "PreviousParentGroup" => e.previous_parent = p.uuid_value(&t)?.non_zero(),
                "String" => {
                    bump(&mut strings, p.lim.strings, Limit::Strings)?;
                    p.charge(model_cost::FIELD)?;
                    let (key, field) = p.string_el()?;
                    match names.get(&key).and_then(|&i| fields.get_mut(i)) {
                        Some((_, f)) if !f.value.is_empty() => return Err(Reason::DuplicateField),
                        Some((_, f)) => *f = field,
                        None => {
                            names.insert(key.clone(), fields.len());
                            fields.push((key, field));
                        }
                    }
                }
                "Binary" => {
                    let mut n = occ.bins.len();
                    bump(&mut n, p.lim.attachments, Limit::Attachments)?;
                    p.charge(model_cost::ATTACHMENT)?;
                    let bin = p.binary_el()?;
                    occ.bins.push(bin);
                }
                "AutoType" => p.auto_type(&mut e.auto_type, &mut associations)?,
                "CustomData" => {
                    p.custom_data(&mut cd)?;
                    convert_known_bad(&mut cd, &mut e.exclude_from_reports);
                }
                "History" => {
                    if history_item {
                        return Err(Reason::NestedHistory);
                    }
                    let mut items = Vec::new();
                    p.children(|p, t| {
                        if t.name() != "Entry" {
                            return p.skip();
                        }
                        bump(&mut history_items, p.lim.history, Limit::History)?;
                        bump(
                            &mut p.entry_elements,
                            p.lim.entry_elements,
                            Limit::EntryElements,
                        )?;
                        items.push(p.entry(true)?);
                        Ok(())
                    })?;
                    occ.history = items; // only the last block counts (LD-28)
                }
                _ => {
                    let u = p.unknown(t)?;
                    occ.entry.unknown.push(u);
                }
            }
            Ok(())
        })?;
        occ.entry.custom_data = cd.finish();
        occ.entry.replace_fields(fields);
        Ok(occ)
    }

    /// `String`: `Key` and `Value`, the last of each wins (FMT-11.17,
    /// FMT-11.19).
    fn string_el(&mut self) -> R<(String, Field)> {
        let mut key = None;
        let mut field = None;
        self.children(|p, t| {
            match t.name() {
                "Key" => key = Some(p.text_value(&t)?),
                "Value" => {
                    let protected = t.flag("Protected") || t.flag("ProtectInMemory");
                    field = Some(Field {
                        value: p.secret_value(&t)?,
                        protected,
                    });
                }
                _ => p.skip()?,
            }
            Ok(())
        })?;
        match (key, field) {
            (Some(k), Some(f)) => Ok((k, f)),
            _ => Err(Reason::IncompleteField),
        }
    }

    /// `Binary` in an entry (FMT-13.8 to FMT-13.10): the last `Key` names it;
    /// the last `Value` with `Ref` wins, else the last inline `Value`.
    fn binary_el(&mut self) -> R<Bin> {
        let mut name = None;
        let mut reference = None;
        let mut inline = None;
        self.children(|p, t| {
            match t.name() {
                "Key" => name = Some(p.text_value(&t)?),
                "Value" => {
                    if let Some(r) = t.attr("Ref") {
                        // The Ref wins; its text is ignored, no keystream (FMT-13.9).
                        reference = Some(r.to_owned());
                        p.skip()?;
                    } else {
                        let data = p.bytes_value(&t, None)?;
                        p.count_attachment_bytes(data.len())?;
                        p.charge(data.len())?;
                        inline = Some(data);
                    }
                }
                _ => p.skip()?,
            }
            Ok(())
        })?;
        let name = name.ok_or(Reason::IncompleteAttachment)?;
        match (reference, inline) {
            (Some(r), _) => Ok(Bin::Ref(name, r)),
            (None, Some(d)) => Ok(Bin::Inline(name, self.intern(d))),
            (None, None) => Err(Reason::IncompleteAttachment),
        }
    }

    /// One `AutoType` block merged into `at` (FMT-11.24).
    fn auto_type(&mut self, at: &mut AutoType, associations: &mut usize) -> R<()> {
        self.children(|p, t| {
            match t.name() {
                "Enabled" => at.enabled = p.bool_value(&t)?,
                "DataTransferObfuscation" => at.obfuscation = p.int_value(&t)?,
                "DefaultSequence" => at.default_sequence = p.text_value(&t)?,
                "Association" => {
                    bump(associations, p.lim.associations, Limit::Associations)?;
                    p.charge(model_cost::ASSOCIATION)?;
                    let mut window = None;
                    let mut sequence = None;
                    let mut unknown = Vec::new();
                    p.children(|p, t| {
                        match t.name() {
                            "Window" => window = Some(p.text_value(&t)?),
                            "KeystrokeSequence" => sequence = Some(p.text_value(&t)?),
                            _ => unknown.push(p.unknown(t)?),
                        }
                        Ok(())
                    })?;
                    at.associations.push(Association {
                        window: window.ok_or(Reason::IncompleteAssociation)?,
                        sequence: sequence.ok_or(Reason::IncompleteAssociation)?,
                        unknown,
                    });
                }
                _ => {
                    let u = p.unknown(t)?;
                    at.unknown.push(u);
                }
            }
            Ok(())
        })
    }

    /// One `Times` block; each block starts from the defaults (FMT-11.12).
    fn times(&mut self) -> R<Times> {
        let mut times = Times::all(self.open);
        self.children(|p, t| {
            match t.name() {
                "LastModificationTime" => times.last_modification = p.time_value(&t)?,
                "CreationTime" => times.creation = p.time_value(&t)?,
                "LastAccessTime" => times.last_access = p.time_value(&t)?,
                "ExpiryTime" => times.expiry = p.time_value(&t)?,
                "Expires" => times.expires = p.bool_value(&t)?,
                "UsageCount" => times.usage_count = p.int_value(&t)?,
                "LocationChanged" => times.location_changed = p.time_value(&t)?,
                _ => {
                    let u = p.unknown(t)?;
                    times.unknown.push(u);
                }
            }
            Ok(())
        })?;
        Ok(times)
    }

    // -- deleted objects (FMT-15) ------------------------------------------

    fn deleted_objects_el(&mut self) -> R<()> {
        self.children(|p, t| {
            if t.name() != "DeletedObject" {
                let u = p.unknown(t)?;
                p.unknown_deleted.push(u);
                return Ok(());
            }
            bump(&mut p.deleted, p.lim.deleted_objects, Limit::DeletedObjects)?;
            p.charge(model_cost::DELETED_OBJECT)?;
            let mut uuid = None;
            let mut time = None;
            let mut unknown = Vec::new();
            p.children(|p, t| {
                match t.name() {
                    "UUID" => {
                        // An unusable id never replaces a usable one (FMT-15.4).
                        if let Some(id) = p.uuid_value(&t)?.non_zero() {
                            uuid = Some(id);
                        }
                    }
                    "DeletionTime" => time = Some(p.time_value(&t)?),
                    _ => unknown.push(p.unknown(t)?),
                }
                Ok(())
            })?;
            if let (Some(uuid), Some(deleted_at)) = (uuid, time) {
                p.deleted_objects.push(DeletedObject {
                    uuid,
                    deleted_at,
                    unknown,
                });
            }
            Ok(())
        })
    }

    // -- after the document --------------------------------------------------

    fn finish(mut self, v3_header: Option<&[u8]>) -> R<Document> {
        if let (Some(header), Some(hash)) = (v3_header, &self.header_hash)
            && !hash.is_empty()
            && !ct_eq(hash, larsal_crypto::hash::sha256(&[header]).expose())
        {
            return Err(Reason::HeaderHashMismatch);
        }
        let root = self.root.ok_or(Reason::NoRootGroup)?;
        let mut place: Vec<(Option<usize>, u32)> = Vec::with_capacity(self.enodes.len());
        place.extend(self.enodes.iter().map(|n| (n.group, n.stamp)));
        let mut entries: Vec<Option<Entry>> = Vec::with_capacity(self.enodes.len());
        for node in core::mem::replace(&mut self.enodes, Nodes::new()) {
            entries.push(Some(self.finish_entry(node)?));
        }
        let root_group = self.build_tree(root, &mut entries, &place)?;
        let mut vault = Vault::new(root_group, self.open);
        vault.meta = core::mem::replace(&mut self.meta, Meta::new(self.open));
        vault.meta.custom_data = core::mem::take(&mut self.vault_cd).finish();
        vault.deleted_objects = core::mem::take(&mut self.deleted_objects);
        vault.unknown_document = core::mem::take(&mut self.unknown_document);
        vault.unknown_root = core::mem::take(&mut self.unknown_root);
        vault.unknown_deleted_objects = core::mem::take(&mut self.unknown_deleted);
        self.resolve_references(&mut vault);
        Ok(Document {
            vault,
            warnings: self.warnings,
        })
    }

    fn finish_entry(&mut self, node: ENode) -> R<Entry> {
        let ENode {
            last,
            earlier_refs,
            history,
            ..
        } = node;
        let EntryOcc {
            uuid,
            mut entry,
            bins,
            ..
        } = last;
        let all: Vec<Bin> = earlier_refs.into_iter().chain(bins).collect();
        entry.attachments = self.resolve_bins(uuid, all)?;
        entry.history.reserve_exact(history.len());
        for item in history {
            let mut h = item.entry;
            h.uuid = uuid; // FMT-11.32
            h.attachments = self.resolve_bins(uuid, item.bins)?;
            entry.history.push(h);
        }
        Ok(entry)
    }

    /// Resolves an entry's `Binary` list in document order with the
    /// duplicate name rule of FMT-13.13 (LD-29).
    fn resolve_bins(&mut self, entry: Uuid, bins: Vec<Bin>) -> R<Vec<Attachment>> {
        let mut out: Vec<Attachment> = Vec::with_capacity(bins.len());
        let mut by_name: HashMap<String, usize> = HashMap::with_capacity(bins.len());
        for bin in bins {
            let (name, data) = match bin {
                Bin::Inline(name, data) => (name, data),
                // An empty `Ref` is never resolved (FMT-13.6, FMT-13.11).
                Bin::Ref(name, key) => match self.pooled(&key)? {
                    Some(d) => (name, d),
                    None => {
                        self.warnings.push(Warning::DanglingAttachment { entry });
                        (name, self.intern(SecretBytes::new(Vec::new())))
                    }
                },
            };
            match by_name.get(&name).and_then(|&i| out.get(i)) {
                None => {
                    by_name.insert(name.clone(), out.len());
                    out.push(Attachment { name, data });
                }
                // Interned: equal content is the same allocation.
                Some(a) if Arc::ptr_eq(&a.data, &data) => {}
                Some(_) => {
                    let name = loop {
                        let r =
                            larsal_crypto::random::bytes(4).map_err(|_| Reason::RandomSource)?;
                        let hex: String = r.expose().iter().map(|b| format!("{b:02x}")).collect();
                        let candidate = format!("{hex}_{name}");
                        if !by_name.contains_key(&candidate) {
                            break candidate;
                        }
                    };
                    self.warnings.push(Warning::AttachmentRenamed { entry });
                    by_name.insert(name.clone(), out.len());
                    out.push(Attachment { name, data });
                }
            }
        }
        Ok(out)
    }

    /// The content of pool key `key` (never the empty key): copied out of
    /// the payload on its first use and charged to the model (LD-90).
    fn pooled(&mut self, key: &str) -> R<Option<Arc<SecretBytes>>> {
        let bytes = match self.pool.get(key).filter(|_| !key.is_empty()) {
            None => return Ok(None),
            Some(Pooled::Copied(d)) => return Ok(Some(Arc::clone(d))),
            Some(Pooled::Payload(b)) => *b,
        };
        self.charge(bytes.len())?;
        let shared = self.intern(SecretBytes::new(bytes.to_vec()));
        self.pool
            .insert(key.to_owned(), Pooled::Copied(Arc::clone(&shared)));
        Ok(Some(shared))
    }

    /// Builds the owned tree from the nodes, dropping stale placements.
    /// The nesting is checked against the depth limit first, so the build
    /// (and later drops and walks) recurse at most that deep.
    fn build_tree(
        &mut self,
        root: usize,
        entries: &mut [Option<Entry>],
        place: &[(Option<usize>, u32)],
    ) -> R<Group> {
        let max_level = self.lim.depth.saturating_sub(2);
        let mut level = vec![usize::MAX; self.gnodes.len()];
        let mut order = vec![root];
        if let Some(l) = level.get_mut(root) {
            *l = 0;
        }
        let mut i = 0usize;
        while let Some(&g) = order.get(i) {
            i = i.saturating_add(1);
            let lv = level.get(g).copied().unwrap_or(0);
            let kids: Vec<usize> = self.live_groups(g);
            for c in kids {
                let next = lv.saturating_add(1);
                if next > max_level {
                    return Err(Reason::Limit(Limit::Depth));
                }
                if let Some(l) = level.get_mut(c) {
                    *l = next;
                }
                order.push(c);
            }
        }
        // Children before parents: build in reverse breadth-first order. A
        // built group goes back into its node, where its parent takes it; the
        // lists get their exact size first, so no group is held twice.
        for &g in order.iter().rev() {
            let kids = self.live_groups(g);
            let live_entries = self.live_entries(g, place);
            let mut group = self.take_group(g)?;
            group.groups.reserve_exact(kids.len());
            for c in kids {
                group.groups.push(self.take_group(c)?);
            }
            group.entries.reserve_exact(live_entries.len());
            for e in live_entries {
                if let Some(entry) = entries.get_mut(e).and_then(Option::take) {
                    group.entries.push(entry);
                }
            }
            self.gnodes.get_mut(g).ok_or(Reason::NotXml)?.group = group;
        }
        self.take_group(root)
    }

    /// Moves a group out of its node, leaving an empty one.
    fn take_group(&mut self, g: usize) -> R<Group> {
        let node = self.gnodes.get_mut(g).ok_or(Reason::NoRootGroup)?;
        Ok(core::mem::replace(
            &mut node.group,
            Group::new(Uuid::ZERO, String::new(), Time(0)),
        ))
    }

    fn live_groups(&self, g: usize) -> Vec<usize> {
        self.gnodes.get(g).map_or_else(Vec::new, |n| {
            n.groups
                .iter()
                .filter(|(c, s)| {
                    self.gnodes
                        .get(*c)
                        .is_some_and(|k| k.parent == Some(g) && k.stamp == *s)
                })
                .map(|(c, _)| *c)
                .collect()
        })
    }

    /// `place` holds each entry node's final group and stamp.
    fn live_entries(&self, g: usize, place: &[(Option<usize>, u32)]) -> Vec<usize> {
        self.gnodes.get(g).map_or_else(Vec::new, |n| {
            n.entries
                .iter()
                .filter(|(e, s)| place.get(*e) == Some(&(Some(g), *s)))
                .map(|(e, _)| *e)
                .collect()
        })
    }

    /// Group and entry references resolve after the whole document
    /// (FMT-10.16, FMT-11.37); unresolved ones become none, with a warning.
    fn resolve_references(&mut self, vault: &mut Vault) {
        let warnings = &mut self.warnings;
        let groups = &self.group_ids;
        let mut check = |r: &mut Option<Uuid>, element: &'static str| {
            if r.is_some_and(|id| !groups.contains_key(&id)) {
                *r = None;
                warnings.push(Warning::UnresolvedReference { element });
            }
        };
        let m = &mut vault.meta;
        check(&mut m.recycle_bin, "RecycleBinUUID");
        check(&mut m.entry_templates_group, "EntryTemplatesGroup");
        check(&mut m.last_selected_group, "LastSelectedGroup");
        check(&mut m.last_top_visible_group, "LastTopVisibleGroup");
        // The root group is a valid target and is kept (FMT-10.16), also
        // for the recycle bin; MOD-04 decides how Larsal acts on that.
        let entries = &self.entry_ids;
        let mut stack = vec![&mut vault.root];
        while let Some(g) = stack.pop() {
            if g.last_top_visible_entry
                .is_some_and(|id| !entries.contains_key(&id))
            {
                g.last_top_visible_entry = None;
                self.warnings.push(Warning::UnresolvedReference {
                    element: "LastTopVisibleEntry",
                });
            }
            stack.extend(g.groups.iter_mut());
        }
    }
}

/// Drops layout whitespace in a complete kept element, top-down (FMT-10.27,
/// LD-81): an element that holds child elements and, besides them, only
/// whitespace keeps just the elements, and its children are judged the same
/// way; a mixed element (text that is not only whitespace) keeps its whole
/// subtree as read. So the same document, indented or flat, gives the same
/// model, and nothing inside mixed content changes. Iterative: no recursion.
fn drop_layout_whitespace(root: &mut UnknownElement) {
    let mut stack = vec![root];
    while let Some(el) = stack.pop() {
        let only_space = el.content.iter().all(|n| match n {
            UnknownNode::Text(t) => t.bytes().all(is_xml_space),
            UnknownNode::Element(_) => true,
        });
        if !only_space {
            continue; // mixed: nothing inside it is dropped
        }
        if el
            .content
            .iter()
            .any(|n| matches!(n, UnknownNode::Element(_)))
        {
            el.content.retain(|n| matches!(n, UnknownNode::Element(_)));
        }
        let UnknownElement { content, .. } = el;
        for n in content.iter_mut() {
            if let UnknownNode::Element(c) = n {
                stack.push(c);
            }
        }
    }
}

fn new_unknown(tag: &Tag<'_>) -> UnknownElement {
    UnknownElement {
        name: tag.name().to_owned(),
        // Only attributes without a prefix, and no `xmlns` (FMT-10.20).
        attributes: tag
            .attrs
            .iter()
            .filter(|(k, _)| !k.contains(':') && k != "xmlns")
            .cloned()
            .collect(),
        content: Vec::new(),
    }
}

/// The legacy report flag (FMT-14.19), checked after each entry
/// `CustomData` block. Never touches `_LAST_MODIFIED`.
fn convert_known_bad(cd: &mut CdBuilder, excluded: &mut bool) {
    if let Some(item) = cd.take(KNOWN_BAD) {
        *excluded = item.value.expose() == "true";
        if cd.live == 1 && cd.index.contains_key(LAST_MODIFIED) {
            cd.items.clear();
            cd.index.clear();
            cd.live = 0;
        }
    }
}

/// Text after XML decoding must hold only XML 1.0 characters (FMT-12.24).
fn checked_text(s: Cow<'_, str>) -> R<Cow<'_, str>> {
    if s.chars().all(is_xml_char) {
        Ok(s)
    } else {
        Err(Reason::NotXml)
    }
}

/// A character reference or one of the five predefined entities; any other
/// entity is undefined (FMT-11.42).
fn general_ref(r: &BytesRef<'_>) -> R<char> {
    if r.is_char_ref() {
        return match r.resolve_char_ref() {
            Ok(Some(c)) if is_xml_char(c) => Ok(c),
            _ => Err(Reason::NotXml),
        };
    }
    match &**r {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ => Err(Reason::ForbiddenDeclaration),
    }
}

/// An XML Name with at most one `:`, not at either end (Namespaces in XML).
fn is_qname(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let colons = name.matches(':').count();
    is_name_start(first)
        && first != ':'
        && chars.all(is_name_char)
        && colons <= 1
        && !name.ends_with(':')
}

fn is_name_start(c: char) -> bool {
    matches!(c,
        ':' | 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}'
        | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}'
        | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}'
        | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}
