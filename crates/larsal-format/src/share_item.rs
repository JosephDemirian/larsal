//! A group's share settings item (INT-08.1 to INT-08.4, FMT-14.20): the
//! custom data item that makes a group a share and its base64 XML value.
//! It sits here, under larsal-core, because two crates read it: larsal-share runs
//! the share, and larsal-core's references keep to what the share sends
//! (MOD-08.32). One reader for both.

use crate::document::encode::{base64_decode_into, base64_decoded_len};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::{Group, Uuid, Vault};
use quick_xml::events::{BytesRef, Event};

/// The custom data key of a share group, stored encoded (AGENTS rule 1;
/// FMT-13.17, INT-08.1).
pub const KEY: &[u8] = &[
    0x4B, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x2F, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E,
    0x63, 0x65,
];

/// The root element name of the settings XML (INT-08.3), stored encoded
/// (AGENTS rule 1).
pub const ROOT: &[u8] = &[0x4B, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65];

/// [`ROOT`] as text, for the writer.
const ROOT_TEXT: &str = match core::str::from_utf8(ROOT) {
    Ok(s) => s,
    Err(_) => "",
};

/// The declaration both apps write (INT-08.3): no encoding attribute.
const DECLARATION: &str = "<?xml version=\"1.0\"?>";

/// What a share does with its container (INT-08.3 `Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Neither `Import` nor `Export`.
    Inactive,
    /// `Import` only.
    Import,
    /// `Export` only.
    Export,
    /// Both.
    Synchronize,
}

/// One share's settings (INT-08.3).
///
/// Guarantees: the password lives only in a [`SecretString`]; `Debug`
/// prints neither it nor the path (LD-67).
pub struct Settings {
    /// `Import` in `Type`.
    pub import: bool,
    /// `Export` in `Type`.
    pub export: bool,
    /// `Group`: 16 zero bytes when the item has none (or not 16 bytes);
    /// [`Settings::write`] then gives it a random id.
    pub group: Uuid,
    /// `Path`, as stored (INT-08.5).
    pub path: String,
    /// `Password`, the share password (INT-08.39).
    pub password: SecretString,
    /// `KeepGroups`: true only for the exact text `True`.
    pub keep_groups: bool,
}

impl core::fmt::Debug for Settings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Settings")
            .field("mode", &self.mode())
            .field("group", &self.group)
            .field("path_len", &self.path.len())
            .field("password", &self.password)
            .field("keep_groups", &self.keep_groups)
            .finish()
    }
}

/// What a group's share item holds (INT-08.4).
#[derive(Debug)]
pub enum Item {
    /// Readable settings.
    Settings(Settings),
    /// An item that decodes to nothing usable: the group is a share, but
    /// it never imports or exports (label MI08-25).
    Invalid,
}

/// The longest path a share keeps, in bytes: the group editor's limit
/// (INT-08.4, F-268).
pub const MAX_PATH: usize = 4096;

/// The longest item value read (INT-08.4, F-268). The editor writes at
/// most a [`MAX_PATH`] path and a 64 KiB password: about 121 KiB once
/// encoded twice.
pub const MAX_VALUE: usize = 256 * 1024;

/// The share item of `group` itself (INT-08.1); `None` when it has none,
/// so it is not a share group. A value over [`MAX_VALUE`] is invalid before
/// any decoding, and so is a path over [`MAX_PATH`] (F-268: such an item
/// from outside Larsal would stall every caller, and the path names no file).
#[must_use]
pub fn of(group: &Group) -> Option<Item> {
    let key = core::str::from_utf8(KEY).ok()?;
    let value = group.custom_data.get(key)?;
    let s = (value.len() <= MAX_VALUE).then(|| read(value)).flatten();
    Some(
        s.filter(|s| s.path.len() <= MAX_PATH)
            .map_or(Item::Invalid, Item::Settings),
    )
}

/// The share group of group `id` (INT-08.1, MOD-02.18): the nearest group
/// at or above it, the root included, that carries a share item. `None`
/// when `id` is not shared or not in the vault.
#[must_use]
pub fn share_group(vault: &Vault, id: Uuid) -> Option<Uuid> {
    let key = core::str::from_utf8(KEY).ok()?;
    let mut stack = vec![(&vault.root, None)];
    while let Some((g, above)) = stack.pop() {
        let here = if g.custom_data.get(key).is_some() {
            Some(g.uuid)
        } else {
            above
        };
        if g.uuid == id {
            return here;
        }
        stack.extend(g.groups.iter().map(|c| (c, here)));
    }
    None
}

impl Settings {
    /// New settings as the group editor starts them (INT-08.21): Inactive,
    /// no path, empty password, keep group structure on, no `Group` id yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            import: false,
            export: false,
            group: Uuid::ZERO,
            path: String::new(),
            password: SecretString::new(String::new()),
            keep_groups: true,
        }
    }

    /// The mode the two flags give.
    #[must_use]
    pub fn mode(&self) -> Mode {
        match (self.import, self.export) {
            (false, false) => Mode::Inactive,
            (true, false) => Mode::Import,
            (false, true) => Mode::Export,
            (true, true) => Mode::Synchronize,
        }
    }

    /// INT-08.4: Import flag set and a path.
    #[must_use]
    pub fn importing(&self) -> bool {
        self.import && !self.path.is_empty()
    }

    /// INT-08.4: Export flag set and a path.
    #[must_use]
    pub fn exporting(&self) -> bool {
        self.export && !self.path.is_empty()
    }

    /// INT-08.4: not Inactive and a path.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.mode() != Mode::Inactive && !self.path.is_empty()
    }

    /// The item value (INT-08.2, INT-08.3): standard base64 with padding of
    /// the XML text, written exactly as the card gives it (declaration
    /// without encoding, children in card order, `Import` before `Export`,
    /// `<X/>` for an empty `Type` or flag, `<Password></Password>` for an
    /// empty password, no white space). A zero `Group` id first becomes a
    /// random one (CRY-03), kept in `self`. The XML text, which holds the
    /// password, is built in one buffer of its exact size and wiped.
    ///
    /// # Errors
    /// `RandomSource` when a new id cannot be drawn.
    pub fn write(&mut self) -> Result<String, larsal_crypto::Error> {
        if self.group.is_zero() {
            self.group = Uuid(larsal_crypto::random::uuid_v4()?);
        }
        let root = ROOT_TEXT;
        let kind = match self.mode() {
            Mode::Inactive => "<Type/>",
            Mode::Import => "<Type><Import/></Type>",
            Mode::Export => "<Type><Export/></Type>",
            Mode::Synchronize => "<Type><Import/><Export/></Type>",
        };
        let group = base64::encode(Form::Padded, &self.group.0);
        let path = base64::encode(Form::Padded, self.path.as_bytes());
        let password = base64::encode_secret(Form::Padded, self.password.expose().as_bytes());
        let keep = if self.keep_groups { "True" } else { "False" };
        let parts = [
            DECLARATION,
            "<",
            root,
            ">",
            kind,
            "<Group>",
            &group,
            "</Group><Path>",
            &path,
            "</Path><Password>",
            password.expose(),
            "</Password><KeepGroups>",
            keep,
            "</KeepGroups></",
            root,
            ">",
        ];
        let size = parts.iter().fold(0usize, |n, p| n.saturating_add(p.len()));
        let mut xml = String::with_capacity(size);
        parts.iter().for_each(|p| xml.push_str(p));
        let xml = SecretString::new(xml);
        Ok(base64::encode(Form::Padded, xml.expose().as_bytes()))
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads an item value (INT-08.2, INT-08.3). `None` means invalid
/// (INT-08.4): no root named [`ROOT`] first, text that is not UTF-8 or not
/// well-formed XML, a DTD or an entity other than the five XML ones and
/// character references, or an element inside a value element.
///
/// The value is decoded leniently: characters outside the base64 alphabet
/// are skipped (FMT-12.20), here and in `Group`, `Path` and `Password`.
/// Children come in any order, a later one wins (a later `Type` too, so its
/// flags replace the earlier ones), unknown ones are skipped with their
/// content; inside `Type`, `Import` and `Export` set their flag until the
/// first other child; the reading stops when the root closes.
/// Every buffer that holds the password, decoded or not, is wiped.
#[must_use]
pub fn read(value: &str) -> Option<Settings> {
    let xml = lenient(value);
    let text = core::str::from_utf8(xml.expose()).ok()?;
    let mut reader = quick_xml::Reader::from_str(text);
    let cfg = reader.config_mut();
    cfg.check_end_names = true;
    cfg.check_comments = true;
    cfg.expand_empty_elements = false;
    cfg.trim_text(false);
    let mut out = Settings {
        keep_groups: false,
        ..Settings::new()
    };
    // The text of the open value element; never longer than the document.
    let mut buf = SecretBytes::zeroed(text.len());
    let mut len = 0usize;
    let mut depth = 0usize;
    let mut child = Child::Other;
    let mut type_done = false;
    loop {
        let (open, name) = match reader.read_event().ok()? {
            Event::Start(e) => (true, e.name().into_inner().as_bytes().to_owned()),
            Event::Empty(e) => (false, e.name().into_inner().as_bytes().to_owned()),
            Event::End(_) => {
                depth = depth.checked_sub(1)?;
                match depth {
                    0 => return Some(out),
                    1 => out.set(child, buf.expose().get(..len)?),
                    _ => {}
                }
                continue;
            }
            Event::Text(t) => {
                if depth == 0 && !t.trim().is_empty() {
                    return None;
                }
                push(&mut buf, &mut len, depth, child, t.as_bytes())?;
                continue;
            }
            Event::CData(c) => {
                if depth == 0 {
                    return None;
                }
                push(&mut buf, &mut len, depth, child, c.as_bytes())?;
                continue;
            }
            Event::GeneralRef(r) => {
                let mut c = [0u8; 4];
                let c = general_ref(&r)?.encode_utf8(&mut c);
                if depth == 0 {
                    return None;
                }
                push(&mut buf, &mut len, depth, child, c.as_bytes())?;
                continue;
            }
            Event::DocType(_) | Event::Eof => return None,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => continue,
        };
        match depth {
            0 if name != ROOT => return None,
            0 if !open => return Some(out),
            1 => {
                child = Child::of(&name);
                len = 0;
                type_done = false;
                if child == Child::Type {
                    // A later Type wins, as every other child does.
                    out.import = false;
                    out.export = false;
                }
                if !open {
                    out.set(child, &[]);
                }
            }
            2 if child == Child::Type && !type_done => match name.as_slice() {
                b"Import" => out.import = true,
                b"Export" => out.export = true,
                _ => type_done = true,
            },
            2 if child.is_value() => return None,
            _ => {}
        }
        if open {
            depth = depth.checked_add(1)?;
        }
    }
}

/// A child of the root element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Child {
    Type,
    Group,
    Path,
    Password,
    KeepGroups,
    /// Unknown: skipped with its content.
    Other,
}

impl Child {
    fn of(name: &[u8]) -> Self {
        match name {
            b"Type" => Self::Type,
            b"Group" => Self::Group,
            b"Path" => Self::Path,
            b"Password" => Self::Password,
            b"KeepGroups" => Self::KeepGroups,
            _ => Self::Other,
        }
    }

    /// An element whose text is a value.
    fn is_value(self) -> bool {
        !matches!(self, Self::Type | Self::Other)
    }
}

impl Settings {
    /// Stores the text of a closed value element.
    fn set(&mut self, child: Child, text: &[u8]) {
        let text = core::str::from_utf8(text).unwrap_or_default();
        match child {
            Child::Group => {
                let id = lenient(text);
                self.group = id.expose().try_into().map_or(Uuid::ZERO, Uuid);
            }
            Child::Path => {
                self.path = String::from_utf8_lossy(lenient(text).expose()).into_owned();
            }
            Child::Password => {
                let bytes = lenient(text);
                self.password = SecretString::new(match String::from_utf8_lossy(bytes.expose()) {
                    std::borrow::Cow::Owned(s) => s,
                    std::borrow::Cow::Borrowed(s) => s.to_owned(),
                });
            }
            Child::KeepGroups => self.keep_groups = text == "True",
            Child::Type | Child::Other => {}
        }
    }
}

/// Adds text of the open value element to `buf`; other text is dropped.
fn push(
    buf: &mut SecretBytes,
    len: &mut usize,
    depth: usize,
    child: Child,
    s: &[u8],
) -> Option<()> {
    if depth != 2 || !child.is_value() {
        return Some(());
    }
    let end = len.checked_add(s.len())?;
    buf.expose_mut().get_mut(*len..end)?.copy_from_slice(s);
    *len = end;
    Some(())
}

/// Lenient base64 (FMT-12.20) straight into a wiping buffer.
fn lenient(text: &str) -> SecretBytes {
    let mut out = SecretBytes::zeroed(base64_decoded_len(text));
    let mut at = 0usize;
    base64_decode_into(text, |b| {
        if let Some(slot) = out.expose_mut().get_mut(at) {
            *slot = b;
        }
        at = at.saturating_add(1);
    });
    out
}

/// A character reference or one of the five XML entities; any other
/// entity is undefined, so the item is invalid.
fn general_ref(r: &BytesRef<'_>) -> Option<char> {
    if r.is_char_ref() {
        return r.resolve_char_ref().ok().flatten();
    }
    match &**r {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "apos" => Some('\''),
        "quot" => Some('"'),
        _ => None,
    }
}
