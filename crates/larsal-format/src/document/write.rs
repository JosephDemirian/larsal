//! Writes the vault document (FMT-10 to FMT-15) from an `larsal_model::Vault`,
//! and picks the file version it needs (FMT-16.19, FMT-16.24).
//!
//! Guarantees:
//! - The layout of FMT-10.2 for the whole document: one element per line,
//!   one TAB per depth, LF line ends, `<Name/>` for empty values; elements in
//!   the write orders of FMT-10.10, FMT-11.6, FMT-11.12, FMT-11.15, FMT-11.24,
//!   FMT-14.1, FMT-14.10 and FMT-15.1; kept unknown elements after the known
//!   children of their parent, in the layout of FMT-10.27.
//! - Text loses the characters of FMT-12.25 and is escaped per FMT-12.26;
//!   attribute values per FMT-10.28. Protected values are never stripped.
//! - Protected values take keystream bytes in document order, starting at
//!   byte 0 (FMT-09.11, FMT-09.17); nothing else takes any, kept unknown
//!   elements included (FMT-09.14).
//! - The document lives only in a wiping buffer; protected plaintext only in
//!   `SecretBytes` (Rust rule 3).
//! - Attachments become pool items in the order of FMT-13.16, equal content
//!   once (FMT-13.17, one namespace); unused content is never written
//!   (FMT-13.15).
//! - [`write_plain`] (the XML export, FEA-09.13, FEA-09.14) writes the same
//!   document with no keystream: protected values in clear marked
//!   `ProtectInMemory="True"`, the pool as `Meta/Binaries` in base64, and
//!   the vault custom data as it is in memory (no padding item, no save
//!   time). It draws no random value and changes nothing.

use super::encode::{base64_each, base64_encode, time_to_binary, uuid_to_text};
use super::read::ROOT_NAME;
use crate::buffer::Grow;
use crate::error::Error;
use crate::limits::Limit;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::stream::FieldStream;
use larsal_model::entry::{STANDARD_FIELDS, cmp_utf16};
use larsal_model::{
    AutoType, CustomData, CustomDataItem, Entry, Group, Icon, Switch, Time, Times, UnknownElement,
    UnknownNode, Uuid, Vault,
};
use std::collections::HashMap;

/// The key of the random padding item, stored encoded (name rule; CRY-03.7,
/// FMT-14.21).
pub const PADDING_KEY: &[u8] = &[
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x52, 0x41, 0x4E, 0x44, 0x4F, 0x4D, 0x5F, 0x53, 0x4C, 0x55, 0x47,
];

/// The container change time item (FMT-14.18).
const LAST_MODIFIED: &str = "_LAST_MODIFIED";

/// The XML declaration and its line feed (FMT-10.1).
const DECLARATION: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";

/// What one save adds to the vault custom data (FMT-14.21, FMT-14.18 (c)).
#[derive(Debug, Clone)]
pub struct SaveStamp {
    /// The padding item value: lowercase hex of 64 to 511 random bytes.
    pub padding_hex: String,
    /// The save time.
    pub time: Time,
}

/// A written document and the pool its `Ref` values point into.
pub struct Written<'v> {
    /// The document bytes, in a wiping buffer.
    pub(crate) xml: Grow,
    /// The pool items in index order: item n has pool key "n".
    pub pool: Vec<&'v SecretBytes>,
}

impl Written<'_> {
    /// The document bytes.
    #[must_use]
    pub fn xml(&self) -> &[u8] {
        self.xml.as_slice()
    }
}

/// The minor version Larsal writes for `vault` (FMT-16.19, FMT-16.24): 1 when
/// any value only a 4.1 file can keep is present, else 0; raised to the
/// version the file was read as while the vault keeps unknown parts.
#[must_use]
pub fn minor_version(vault: &Vault) -> u16 {
    let groups = vault.root.subtree();
    let group_needs = |g: &&Group| !g.tags.is_empty() || g.previous_parent.is_some();
    let entry_needs = |e: &Entry| e.exclude_from_reports || e.previous_parent.is_some();
    let icon_needs = vault
        .meta
        .custom_icons
        .iter()
        .any(|i| !i.name.is_empty() || i.last_modified.is_some());
    let needs = icon_needs
        || groups.iter().any(group_needs)
        || groups
            .iter()
            .flat_map(|g| g.entries.iter())
            .any(|e| entry_needs(e) || e.history.iter().any(entry_needs));
    let minor = u16::from(needs);
    match vault.read_version {
        Some(v) if v.major == 4 && holds_unknown(vault) => minor.max(v.minor),
        _ => minor,
    }
}

/// True when the vault keeps at least one unknown document part (FMT-16.24).
#[must_use]
pub fn holds_unknown(vault: &Vault) -> bool {
    let m = &vault.meta;
    let cd =
        |c: &CustomData| !c.unknown.is_empty() || c.items.iter().any(|i| !i.unknown.is_empty());
    let entry = |e: &Entry| {
        !e.unknown.is_empty()
            || !e.times.unknown.is_empty()
            || !e.auto_type.unknown.is_empty()
            || e.auto_type
                .associations
                .iter()
                .any(|a| !a.unknown.is_empty())
            || cd(&e.custom_data)
    };
    !vault.unknown_document.is_empty()
        || !vault.unknown_root.is_empty()
        || !vault.unknown_deleted_objects.is_empty()
        || !m.unknown.is_empty()
        || !m.memory_protection.unknown.is_empty()
        || !m.custom_icons_unknown.is_empty()
        || m.custom_icons.iter().any(|i| !i.unknown.is_empty())
        || cd(&m.custom_data)
        || vault.deleted_objects.iter().any(|d| !d.unknown.is_empty())
        || vault.root.subtree().iter().any(|g| {
            !g.unknown.is_empty()
                || !g.times.unknown.is_empty()
                || cd(&g.custom_data)
                || g.entries
                    .iter()
                    .any(|e| entry(e) || e.history.iter().any(entry))
        })
}

/// Writes `vault` as a version 4.`minor` document (FMT-10 to FMT-15), with
/// the padding item and `_LAST_MODIFIED` of `stamp` in the vault custom data
/// and protected values encrypted with `stream` from its current position.
///
/// # Errors
/// `TooLarge(Total)` only if the keystream runs out (more than 256 GiB of
/// protected values).
pub fn write<'v>(
    vault: &'v Vault,
    minor: u16,
    stream: &mut FieldStream,
    stamp: &SaveStamp,
) -> Result<Written<'v>, Error> {
    let (pool, index) = build_pool(vault);
    let mut w = Writer {
        out: Grow::new(),
        depth: 0,
        v41: minor >= 1,
        stream: Some(stream),
        binaries: None,
        index,
        vault,
    };
    w.document(Some(stamp))?;
    Ok(Written { xml: w.out, pool })
}

/// The plain XML document of the XML export (FEA-09.13, FEA-09.14) at the
/// version a save picks ([`minor_version`]): every value a save would
/// protect in clear with `ProtectInMemory="True"`, a `Meta/Binaries` pool
/// numbered like the file pool, and no stamp. The document is in a wiping
/// buffer; attachment content and protected values never pass through a
/// plain string.
///
/// # Errors
/// None in practice: kept so the shared writer code needs no panic.
pub fn write_plain(vault: &Vault) -> Result<Written<'_>, Error> {
    let (pool, index) = build_pool(vault);
    let out = {
        let mut w = Writer {
            out: Grow::new(),
            depth: 0,
            v41: minor_version(vault) >= 1,
            stream: None,
            binaries: Some(&pool),
            index,
            vault,
        };
        w.document(None)?;
        w.out
    };
    Ok(Written { xml: out, pool })
}

/// The pool in the order of FMT-13.16: per group, its entries, then their
/// history items, then its child groups, depth first from the root; inside
/// one entry by name. Equal content gets one item (FMT-13.17).
fn build_pool(vault: &Vault) -> (Vec<&SecretBytes>, HashMap<&[u8], usize>) {
    let mut pool: Vec<&SecretBytes> = Vec::new();
    let mut index: HashMap<&[u8], usize> = HashMap::new();
    let mut stack: Vec<&Group> = vec![&vault.root];
    while let Some(g) = stack.pop() {
        let entries = g.entries.iter();
        let history = g.entries.iter().flat_map(|e| e.history.iter());
        for e in entries.chain(history) {
            for a in sorted_attachments(e) {
                let bytes: &[u8] = a.data.expose();
                if !index.contains_key(bytes) {
                    index.insert(bytes, pool.len());
                    pool.push(&a.data);
                }
            }
        }
        // Child groups in order, depth first: push in reverse.
        stack.extend(g.groups.iter().rev());
    }
    (pool, index)
}

/// An entry's attachments sorted by name in UTF-16 code units (FMT-11.23).
fn sorted_attachments(e: &Entry) -> Vec<&larsal_model::Attachment> {
    let mut v: Vec<&larsal_model::Attachment> = e.attachments.iter().collect();
    v.sort_by(|a, b| cmp_utf16(&a.name, &b.name));
    v
}

struct Writer<'v, 's> {
    out: Grow,
    depth: usize,
    /// Version 4.1 or a higher minor: the 4.1 element gates are open.
    v41: bool,
    /// The keystream of a save; `None` writes protected values in clear.
    stream: Option<&'s mut FieldStream>,
    /// The pool to write as `Meta/Binaries` (plain document only).
    binaries: Option<&'s [&'v SecretBytes]>,
    index: HashMap<&'v [u8], usize>,
    vault: &'v Vault,
}

impl Writer<'_, '_> {
    fn document(&mut self, stamp: Option<&SaveStamp>) -> Result<(), Error> {
        let vault = self.vault;
        self.out.extend(DECLARATION);
        self.open_raw(ROOT_NAME);
        self.meta(stamp)?;
        self.open("Root");
        self.group(&vault.root)?;
        self.deleted_objects();
        self.unknown_children(&vault.unknown_root);
        self.close("Root");
        self.unknown_children(&vault.unknown_document);
        self.close_raw(ROOT_NAME);
        Ok(())
    }

    // -- layout (FMT-10.2) --------------------------------------------------

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.out.push(b'\t');
        }
    }

    fn open_raw(&mut self, name: &[u8]) {
        self.indent();
        self.out.push(b'<');
        self.out.extend(name);
        self.out.extend(b">\n");
        self.depth = self.depth.saturating_add(1);
    }

    fn close_raw(&mut self, name: &[u8]) {
        self.depth = self.depth.saturating_sub(1);
        self.indent();
        self.out.extend(b"</");
        self.out.extend(name);
        self.out.extend(b">\n");
    }

    fn open(&mut self, name: &str) {
        self.open_raw(name.as_bytes());
    }

    fn close(&mut self, name: &str) {
        self.close_raw(name.as_bytes());
    }

    /// `<name/>` on its own line.
    fn empty(&mut self, name: &str) {
        self.indent();
        self.out.push(b'<');
        self.out.extend(name.as_bytes());
        self.out.extend(b"/>\n");
    }

    /// A text value on one line, stripped and escaped (FMT-12.25 to
    /// FMT-12.27); `<name/>` when nothing is left.
    fn text(&mut self, name: &str, value: &str) {
        if !value.chars().any(keep) {
            return self.empty(name);
        }
        self.indent();
        self.out.push(b'<');
        self.out.extend(name.as_bytes());
        self.out.push(b'>');
        escape_text(&mut self.out, value);
        self.out.extend(b"</");
        self.out.extend(name.as_bytes());
        self.out.extend(b">\n");
    }

    /// A value that needs no escaping (numbers, base64, fixed words).
    fn plain(&mut self, name: &str, value: &str) {
        self.text(name, value);
    }

    fn boolean(&mut self, name: &str, b: bool) {
        self.plain(name, if b { "True" } else { "False" });
    }

    fn number(&mut self, name: &str, n: impl core::fmt::Display) {
        self.plain(name, &n.to_string());
    }

    fn time(&mut self, name: &str, t: Time) {
        self.plain(name, &time_to_binary(t));
    }

    fn uuid(&mut self, name: &str, u: Uuid) {
        self.plain(name, &uuid_to_text(u));
    }

    fn uuid_ref(&mut self, name: &str, u: Option<Uuid>) {
        self.uuid(name, u.unwrap_or(Uuid::ZERO));
    }

    // -- Meta (FMT-10.10) ---------------------------------------------------

    fn meta(&mut self, stamp: Option<&SaveStamp>) -> Result<(), Error> {
        let m = &self.vault.meta;
        self.open("Meta");
        self.text("Generator", &m.generator);
        self.text("DatabaseName", &m.name);
        self.time("DatabaseNameChanged", m.name_changed);
        self.text("DatabaseDescription", &m.description);
        self.time("DatabaseDescriptionChanged", m.description_changed);
        self.text("DefaultUserName", &m.default_user_name);
        self.time("DefaultUserNameChanged", m.default_user_name_changed);
        self.number("MaintenanceHistoryDays", m.maintenance_history_days);
        self.text("Color", &m.color);
        self.time("MasterKeyChanged", m.master_key_changed);
        self.number("MasterKeyChangeRec", m.master_key_change_rec);
        self.number("MasterKeyChangeForce", m.master_key_change_force);
        if m.master_key_change_force_once {
            self.boolean("MasterKeyChangeForceOnce", true); // row 28, LD-62
        }
        let p = &m.memory_protection;
        self.open("MemoryProtection");
        self.boolean("ProtectTitle", p.title);
        self.boolean("ProtectUserName", p.user_name);
        self.boolean("ProtectPassword", p.password);
        self.boolean("ProtectURL", p.url);
        self.boolean("ProtectNotes", p.notes);
        self.unknown_children(&p.unknown);
        self.close("MemoryProtection");
        self.custom_icons();
        self.boolean("RecycleBinEnabled", m.recycle_bin_enabled);
        self.uuid_ref("RecycleBinUUID", m.recycle_bin);
        self.time("RecycleBinChanged", m.recycle_bin_changed);
        self.uuid_ref("EntryTemplatesGroup", m.entry_templates_group);
        self.time(
            "EntryTemplatesGroupChanged",
            m.entry_templates_group_changed,
        );
        self.uuid_ref("LastSelectedGroup", m.last_selected_group);
        self.uuid_ref("LastTopVisibleGroup", m.last_top_visible_group);
        self.number("HistoryMaxItems", m.history_max_items);
        self.number("HistoryMaxSize", m.history_max_size);
        self.time("SettingsChanged", m.settings_changed);
        if let Some(pool) = self.binaries {
            self.binaries(pool);
        }
        let cd = stamp.map(|s| stamped(&m.custom_data, s));
        self.custom_data(cd.as_ref().unwrap_or(&m.custom_data));
        self.unknown_children(&m.unknown);
        self.close("Meta");
        Ok(())
    }

    /// FEA-09.14: each pool item as `<Binary ID="n">` with its content in
    /// base64, uncompressed, written straight into the wiping buffer.
    fn binaries(&mut self, pool: &[&SecretBytes]) {
        if pool.is_empty() {
            return self.empty("Binaries");
        }
        self.open("Binaries");
        for (n, item) in pool.iter().enumerate() {
            self.indent();
            self.out.extend(b"<Binary ID=\"");
            self.out.extend(n.to_string().as_bytes());
            if item.is_empty() {
                self.out.extend(b"\"/>\n");
                continue;
            }
            self.out.extend(b"\">");
            let out = &mut self.out;
            base64_each(item.expose(), |c| out.push(c));
            self.out.extend(b"</Binary>\n");
        }
        self.close("Binaries");
    }

    fn custom_icons(&mut self) {
        let m = &self.vault.meta;
        if m.custom_icons.is_empty() && m.custom_icons_unknown.is_empty() {
            return self.empty("CustomIcons");
        }
        self.open("CustomIcons");
        for icon in &m.custom_icons {
            self.open("Icon");
            self.uuid("UUID", icon.uuid);
            if self.v41 && !icon.name.is_empty() {
                self.text("Name", &icon.name);
            }
            if let (true, Some(t)) = (self.v41, icon.last_modified) {
                self.time("LastModificationTime", t);
            }
            self.plain("Data", &base64_encode(&icon.data));
            self.unknown_children(&icon.unknown);
            self.close("Icon");
        }
        self.unknown_children(&m.custom_icons_unknown);
        self.close("CustomIcons");
    }

    /// A custom data block, not written when empty (FMT-14.10 to FMT-14.13).
    fn custom_data(&mut self, cd: &CustomData) {
        if cd.is_empty() {
            return;
        }
        self.open("CustomData");
        for item in &cd.items {
            self.open("Item");
            self.text("Key", &item.key);
            self.text("Value", item.value.expose());
            if let (true, Some(t)) = (self.v41, item.last_modified) {
                self.time("LastModificationTime", t);
            }
            self.unknown_children(&item.unknown);
            self.close("Item");
        }
        self.unknown_children(&cd.unknown);
        self.close("CustomData");
    }

    // -- groups and entries (FMT-11) ----------------------------------------

    fn group(&mut self, root: &Group) -> Result<(), Error> {
        // Explicit stack: `Ok(g)` opens a group, `Err(g)` writes its kept
        // unknown children (after its child groups, FMT-11.45) and closes it.
        let mut stack: Vec<Result<&Group, &Group>> = vec![Ok(root)];
        while let Some(next) = stack.pop() {
            let g = match next {
                Ok(g) => g,
                Err(g) => {
                    self.unknown_children(&g.unknown);
                    self.close("Group");
                    continue;
                }
            };
            self.open("Group");
            self.uuid("UUID", g.uuid);
            self.text("Name", &g.name);
            self.text("Notes", &g.notes);
            if !g.tags.is_empty() {
                self.text("Tags", &g.tags);
            }
            self.icon(g.icon);
            self.times(&g.times);
            self.boolean("IsExpanded", g.expanded);
            self.text("DefaultAutoTypeSequence", &g.default_sequence);
            self.plain("EnableAutoType", switch(g.auto_type));
            self.plain("EnableSearching", switch(g.searching));
            self.uuid_ref("LastTopVisibleEntry", g.last_top_visible_entry);
            self.custom_data(&g.custom_data);
            if let (true, Some(p)) = (self.v41, g.previous_parent) {
                self.uuid("PreviousParentGroup", p);
            }
            for e in &g.entries {
                self.entry(e, None)?;
            }
            stack.push(Err(g));
            stack.extend(g.groups.iter().rev().map(Ok));
        }
        Ok(())
    }

    fn icon(&mut self, icon: Icon) {
        match icon {
            Icon::Standard(n) => self.number("IconID", n),
            Icon::Custom(id) => {
                self.number("IconID", 0);
                self.uuid("CustomIconUUID", id);
            }
        }
    }

    fn times(&mut self, t: &Times) {
        self.open("Times");
        self.time("LastModificationTime", t.last_modification);
        self.time("CreationTime", t.creation);
        self.time("LastAccessTime", t.last_access);
        self.time("ExpiryTime", t.expiry);
        self.boolean("Expires", t.expires);
        self.number("UsageCount", t.usage_count);
        self.time("LocationChanged", t.location_changed);
        self.unknown_children(&t.unknown);
        self.close("Times");
    }

    /// One entry (FMT-11.15); `owner` is the live entry of a history item,
    /// whose id the item carries (FMT-11.32).
    fn entry(&mut self, e: &Entry, owner: Option<&Entry>) -> Result<(), Error> {
        self.open("Entry");
        self.uuid("UUID", owner.map_or(e.uuid, |o| o.uuid));
        self.icon(e.icon);
        self.text("ForegroundColor", &e.foreground_color);
        self.text("BackgroundColor", &e.background_color);
        self.text("OverrideURL", &e.override_url);
        self.text("Tags", &e.tags().join(","));
        self.times(&e.times);
        if self.v41 && e.exclude_from_reports {
            self.boolean("QualityCheck", false);
        }
        if let (true, Some(p)) = (self.v41, e.previous_parent) {
            self.uuid("PreviousParentGroup", p);
        }
        let flags = &self.vault.meta.memory_protection;
        for (name, field) in e.fields() {
            let protect =
                field.protected || (STANDARD_FIELDS.contains(&name) && flags.for_field(name));
            self.open("String");
            self.text("Key", name);
            if protect {
                self.protected(field.value.expose())?;
            } else {
                self.text("Value", field.value.expose());
            }
            self.close("String");
        }
        for a in sorted_attachments(e) {
            let at = self.index.get(a.data.expose()).copied().unwrap_or(0);
            self.open("Binary");
            self.text("Key", &a.name);
            self.indent();
            self.out.extend(b"<Value Ref=\"");
            self.out.extend(at.to_string().as_bytes());
            self.out.extend(b"\"/>\n");
            self.close("Binary");
        }
        self.auto_type(&e.auto_type);
        self.custom_data(&e.custom_data);
        if owner.is_none() {
            if e.history.is_empty() {
                self.empty("History");
            } else {
                self.open("History");
                for h in &e.history {
                    self.entry(h, Some(e))?;
                }
                self.close("History");
            }
        }
        self.unknown_children(&e.unknown);
        self.close("Entry");
        Ok(())
    }

    /// A protected `Value` (FMT-09.17, FMT-11.20): the UTF-8 bytes, with one
    /// extra `EF BB BF` before a leading U+FEFF, XORed with the next
    /// keystream bytes, as base64. Empty: no text and no keystream.
    fn protected(&mut self, value: &str) -> Result<(), Error> {
        if self.stream.is_none() {
            // FEA-09.13: in clear, marked, an empty value as an empty element.
            self.indent();
            if !value.chars().any(keep) {
                self.out.extend(b"<Value ProtectInMemory=\"True\"/>\n");
                return Ok(());
            }
            self.out.extend(b"<Value ProtectInMemory=\"True\">");
            escape_text(&mut self.out, value);
            self.out.extend(b"</Value>\n");
            return Ok(());
        }
        self.indent();
        if value.is_empty() {
            self.out.extend(b"<Value Protected=\"True\"/>\n");
            return Ok(());
        }
        let bom: &[u8] = if value.starts_with('\u{FEFF}') {
            &[0xEF, 0xBB, 0xBF]
        } else {
            &[]
        };
        let mut bytes = SecretBytes::new([bom, value.as_bytes()].concat());
        self.stream
            .as_deref_mut()
            .ok_or(Error::TooLarge(Limit::Total))?
            .apply(bytes.expose_mut())
            .map_err(|_| Error::TooLarge(Limit::Total))?;
        self.out.extend(b"<Value Protected=\"True\">");
        self.out.extend(base64_encode(bytes.expose()).as_bytes());
        self.out.extend(b"</Value>\n");
        Ok(())
    }

    fn auto_type(&mut self, at: &AutoType) {
        self.open("AutoType");
        self.boolean("Enabled", at.enabled);
        self.number("DataTransferObfuscation", at.obfuscation);
        self.text("DefaultSequence", &at.default_sequence);
        for a in &at.associations {
            self.open("Association");
            self.text("Window", &a.window);
            self.text("KeystrokeSequence", &a.sequence);
            self.unknown_children(&a.unknown);
            self.close("Association");
        }
        self.unknown_children(&at.unknown);
        self.close("AutoType");
    }

    // -- deleted objects (FMT-15) -------------------------------------------

    fn deleted_objects(&mut self) {
        let v = self.vault;
        if v.deleted_objects.is_empty() && v.unknown_deleted_objects.is_empty() {
            return self.empty("DeletedObjects");
        }
        self.open("DeletedObjects");
        for d in &v.deleted_objects {
            self.open("DeletedObject");
            self.uuid("UUID", d.uuid);
            self.time("DeletionTime", d.deleted_at);
            self.unknown_children(&d.unknown);
            self.close("DeletedObject");
        }
        self.unknown_children(&v.unknown_deleted_objects);
        self.close("DeletedObjects");
    }

    // -- kept unknown elements (FMT-10.27, FMT-10.28) -----------------------

    fn unknown_children(&mut self, list: &[UnknownElement]) {
        for u in list {
            self.unknown(u);
        }
    }

    /// One kept element in its layout kind: empty, text only, elements only
    /// (layout whitespace already dropped by the reader, LD-81), or mixed,
    /// written inline. Iterative, so depth costs no stack.
    fn unknown(&mut self, root: &UnknownElement) {
        enum Step<'a> {
            Open(&'a UnknownElement),
            Close(&'a str),
        }
        let mut stack = vec![Step::Open(root)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Close(name) => self.close(name),
                Step::Open(u) => {
                    let has_elements = u
                        .content
                        .iter()
                        .any(|n| matches!(n, UnknownNode::Element(_)));
                    let has_text = u.content.iter().any(|n| matches!(n, UnknownNode::Text(_)));
                    if has_elements && has_text {
                        self.indent();
                        inline(&mut self.out, u);
                        self.out.push(b'\n');
                    } else if has_elements {
                        self.indent();
                        start_tag(&mut self.out, u, false);
                        self.out.push(b'\n');
                        self.depth = self.depth.saturating_add(1);
                        stack.push(Step::Close(&u.name));
                        for n in u.content.iter().rev() {
                            if let UnknownNode::Element(c) = n {
                                stack.push(Step::Open(c));
                            }
                        }
                    } else if has_text {
                        self.indent();
                        start_tag(&mut self.out, u, false);
                        for n in &u.content {
                            if let UnknownNode::Text(t) = n {
                                escape_text(&mut self.out, t);
                            }
                        }
                        end_tag(&mut self.out, &u.name);
                        self.out.push(b'\n');
                    } else {
                        self.indent();
                        start_tag(&mut self.out, u, true);
                        self.out.push(b'\n');
                    }
                }
            }
        }
    }
}

/// A whole mixed element inline: every text part kept, nothing added
/// (FMT-10.27 kind 4). Iterative.
fn inline(out: &mut Grow, root: &UnknownElement) {
    enum Step<'a> {
        Node(&'a UnknownNode),
        Open(&'a UnknownElement),
        Close(&'a str),
    }
    let mut stack = vec![Step::Open(root)];
    while let Some(step) = stack.pop() {
        match step {
            Step::Node(UnknownNode::Text(t)) => escape_text(out, t),
            Step::Node(UnknownNode::Element(e)) => stack.push(Step::Open(e)),
            Step::Close(name) => end_tag(out, name),
            Step::Open(e) if e.content.is_empty() => start_tag(out, e, true),
            Step::Open(e) => {
                start_tag(out, e, false);
                stack.push(Step::Close(&e.name));
                stack.extend(e.content.iter().rev().map(Step::Node));
            }
        }
    }
}

fn start_tag(out: &mut Grow, u: &UnknownElement, empty: bool) {
    out.push(b'<');
    out.extend(u.name.as_bytes());
    for (k, v) in &u.attributes {
        out.push(b' ');
        out.extend(k.as_bytes());
        out.extend(b"=\"");
        escape_attr(out, v);
        out.push(b'"');
    }
    out.extend(if empty { b"/>".as_slice() } else { b">" });
}

fn end_tag(out: &mut Grow, name: &str) {
    out.extend(b"</");
    out.extend(name.as_bytes());
    out.push(b'>');
}

/// True for a character a written text keeps (FMT-12.25).
fn keep(c: char) -> bool {
    !matches!(c,
        '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}'
        | '\u{7F}'..='\u{84}' | '\u{86}'..='\u{9F}' | '\u{FFFE}' | '\u{FFFF}')
}

/// Text: the FMT-12.25 removals, then `& < > "` as entities and CR as
/// `&#13;` (FMT-12.26); everything else raw UTF-8.
fn escape_text(out: &mut Grow, s: &str) {
    for c in s.chars().filter(|&c| keep(c)) {
        match c {
            '&' => out.extend(b"&amp;"),
            '<' => out.extend(b"&lt;"),
            '>' => out.extend(b"&gt;"),
            '"' => out.extend(b"&quot;"),
            '\r' => out.extend(b"&#13;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

/// Attribute values (FMT-10.28): as text, plus TAB and LF as references.
fn escape_attr(out: &mut Grow, s: &str) {
    for c in s.chars().filter(|&c| keep(c)) {
        match c {
            '\t' => out.extend(b"&#9;"),
            '\n' => out.extend(b"&#10;"),
            _ => {
                let mut buf = [0u8; 4];
                escape_text(out, c.encode_utf8(&mut buf));
            }
        }
    }
}

fn switch(s: Switch) -> &'static str {
    match s {
        Switch::Inherit => "null",
        Switch::On => "true",
        Switch::Off => "false",
    }
}

/// The vault custom data as this save writes it: the padding item replaced
/// in place or added at the end (FMT-14.21, LD-16), then `_LAST_MODIFIED`
/// set to the save time the same way (FMT-14.18 (c)).
fn stamped(cd: &CustomData, stamp: &SaveStamp) -> CustomData {
    let padding_key = String::from_utf8_lossy(PADDING_KEY).into_owned();
    let mut out = cd.clone();
    set_item(
        &mut out,
        padding_key,
        stamp.padding_hex.clone(),
        Some(stamp.time),
    );
    set_item(
        &mut out,
        LAST_MODIFIED.to_owned(),
        last_modified_text(stamp.time),
        None,
    );
    out
}

fn set_item(cd: &mut CustomData, key: String, value: String, time: Option<Time>) {
    let value = SecretString::new(value);
    match cd.items.iter_mut().find(|i| i.key == key) {
        Some(item) => {
            item.value = value;
            item.last_modified = time;
        }
        None => cd.items.push(CustomDataItem {
            key,
            value,
            last_modified: time,
            unknown: Vec::new(),
        }),
    }
}

/// The `_LAST_MODIFIED` text form (FMT-14.18): `Sat Oct 24 19:17:16 2026 GMT`.
#[must_use]
pub fn last_modified_text(t: Time) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let Some(c) = t.to_civil() else {
        return String::new();
    };
    // 0001-01-01 was a Monday in the proleptic Gregorian calendar.
    let weekday = usize::try_from(t.0.div_euclid(86_400).rem_euclid(7)).unwrap_or(0);
    let month = usize::try_from(c.month).unwrap_or(1).saturating_sub(1);
    format!(
        "{} {} {} {:02}:{:02}:{:02} {:04} GMT",
        DAYS.get(weekday).copied().unwrap_or("Mon"),
        MONTHS.get(month).copied().unwrap_or("Jan"),
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.year
    )
}
