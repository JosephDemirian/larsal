//! Import (FEA-08, story E4-S13): readers that turn another tool's file into
//! an import result, and the placement of that result into a new vault or
//! a group of an open vault.
//!
//! Part 1 readers: [`csv`] (section B), [`bitwarden`] (section E, plain and
//! password-protected) and [`proton`] (section F). The .1pux, OPVault,
//! version 1 and XML readers (part 2) plug in the same way: a function that
//! takes the file bytes, its credentials and a [`Context`], builds through
//! the crate's `Builder`, and returns an [`Imported`] or an [`ImportError`].
//!
//! Guarantees, for every reader:
//! - Hostile input never panics, hangs or exhausts memory (FEA-08.65):
//!   sizes are checked against the FEA-08.67 limits before anything is
//!   allocated for them; wrong JSON types read as empty or missing values.
//! - A reader that fails returns no result and wipes what it made
//!   (FEA-08.64): every value lives in a secret type from the moment it is
//!   read (FEA-08.66), so dropping the partial result wipes it.
//! - Errors name at most a limit, a record number or a byte offset, never
//!   text from the file (FEA-08.66).
//! - Every group and entry gets a fresh random id, unique in the result;
//!   times a file does not give are the import time; expiry off, history
//!   empty (FEA-08.9). `Password` fields are protected (MOD-12.17).
//! - The result keeps the FMT-08.12 count limits, so it can always be saved
//!   (FEA-08.67).
//!
//! Placement ([`into_new_vault`], [`into_group`]) checks everything before
//! it changes the target, so a refused placement changes nothing.

pub mod bitwarden;
pub mod csv;
mod json;
pub mod onepux;
pub mod opvault;
pub mod proton;
pub mod v1;
pub mod xml;
pub mod zip;

use crate::clone::Limits as CountLimits;
use crate::edit::MAX_GROUP_LEVEL;
use crate::merge::{self, Kind as MergeKind, Options as MergeOptions};
use crate::recycle::{self, BIN_ICON, BIN_NAME};
use crate::text::Text;
use crate::time::Zone;
use crate::{Error, refs, totp, tree};
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::entry::STANDARD_FIELDS;
use app_model::times::Civil;
use app_model::{Entry, Field, Group, Icon, Switch, Time, Uuid, Vault};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// One CSV, JSON or XML file, `profile.js`, `folders.js` or band file
/// (FEA-08.67): 256 MiB.
pub const MAX_FILE: u64 = 256 << 20;
/// One .1pux file (FEA-08.67, LD-146): 2 GiB, the model limit.
pub const MAX_PUX_FILE: u64 = 2 << 30;
/// One CSV field or JSON text (FEA-08.67, the FMT-08.12 text limit): 64 MiB.
pub const MAX_TEXT: usize = 64 << 20;
/// CSV columns per record (FEA-08.67).
pub const MAX_COLUMNS: usize = 10_000;
/// CSV records (FEA-08.67).
pub const MAX_RECORDS: usize = 1_000_000;

/// A size limit of FEA-08.67, named in `MSG-TOO-LARGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The file itself.
    File,
    /// One CSV field or one JSON text.
    Text,
    /// JSON nesting depth, or the group depth of the result.
    Depth,
    /// Values in one JSON document (App's memory bound, see the json module).
    JsonValues,
    /// CSV columns per record.
    Columns,
    /// CSV records.
    Records,
    /// Groups of the result.
    Groups,
    /// Entries of the result.
    Entries,
    /// Entries plus history items of the result.
    EntryElements,
    /// Fields of one entry.
    Strings,
    /// History items of one entry.
    History,
    /// Attachments of one entry.
    Attachments,
    /// One attachment, or one ZIP member or OPVault attachment file.
    OneAttachment,
    /// All attachments of the result.
    AllAttachments,
    /// Custom icons of the result.
    Icons,
    /// Attachments and custom icons together (FMT-08.12 total).
    Total,
}

impl Limit {
    /// The limit's name for `MSG-TOO-LARGE`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::File => "file size (256 MiB)",
            Self::Text => "one text (64 MiB)",
            Self::Depth => "nesting depth",
            Self::JsonValues => "JSON values",
            Self::Columns => "CSV columns per record (10,000)",
            Self::Records => "CSV records (1,000,000)",
            Self::Groups => "groups",
            Self::Entries => "entries",
            Self::EntryElements => "entries and history items",
            Self::Strings => "fields of one entry",
            Self::History => "history items of one entry",
            Self::Attachments => "attachments of one entry",
            Self::OneAttachment => "one attachment (1 GiB)",
            Self::AllAttachments => "all attachments (1 GiB)",
            Self::Icons => "custom icons",
            Self::Total => "attachments and icons together (1 GiB)",
        }
    }
}

/// Why a JSON file is not valid JSON (`MSG-JSON` reason). Fixed texts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonReason {
    /// The file ends inside a value.
    End,
    /// A character that cannot start a value.
    Unexpected,
    /// A `,`, `:`, `]`, `}` or key is missing.
    Expected,
    /// A number does not follow RFC 8259.
    Number,
    /// A bad escape in a string.
    Escape,
    /// A control character inside a string.
    Control,
    /// A string that is not UTF-8.
    Utf8,
    /// Something after the value.
    Trailing,
}

impl std::fmt::Display for JsonReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::End => f.write_str("the file ends too early"),
            Self::Unexpected => f.write_str("unexpected character"),
            Self::Expected => f.write_str("a separator or closing bracket is missing"),
            Self::Number => f.write_str("bad number"),
            Self::Escape => f.write_str("bad escape"),
            Self::Control => f.write_str("control character in a string"),
            Self::Utf8 => f.write_str("text is not UTF-8"),
            Self::Trailing => f.write_str("data after the end"),
        }
    }
}

impl std::error::Error for JsonReason {}

/// Every way a reader can fail (FEA-08 "Edge cases and errors"). Holds no
/// text from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// `MSG-IMP-NOFILE`.
    NoFile,
    /// `MSG-IMP-OPEN`, with the system's reason.
    Open(std::io::ErrorKind),
    /// `MSG-JSON`.
    Json {
        /// Byte offset where the problem starts.
        offset: usize,
        /// What is wrong there.
        reason: JsonReason,
    },
    /// `MSG-WRONG-PASSWORD`.
    WrongPassword,
    /// `MSG-BW-ACCOUNT`: protected by the account key, not a file password.
    BwAccount,
    /// `MSG-BW-KDF`.
    BwKdf,
    /// `MSG-BW-DAMAGED`.
    BwDamaged,
    /// `MSG-PROTON-ENCRYPTED`.
    ProtonEncrypted,
    /// `MSG-1PUX-NOTZIP`: not a ZIP archive, or a damaged one.
    OnePuxNotZip,
    /// `MSG-1PUX-NODATA`: no `export.data` member.
    OnePuxNoData,
    /// A ZIP feature App does not read: ZIP64, encryption, several disks,
    /// a method other than stored or deflate (LD-142 (2)).
    ZipUnsupported,
    /// `MSG-OPV-LAYOUT`.
    OpvLayout,
    /// `MSG-OPV-DAMAGED`.
    OpvDamaged,
    /// `MSG-V1-NOTVAULT`.
    V1NotVault,
    /// `MSG-V1-CIPHER`.
    V1Cipher,
    /// `MSG-V1-VERSION`.
    V1Version,
    /// `MSG-V1-KEYFILE`.
    V1KeyFile,
    /// `MSG-V1-DAMAGED`.
    V1Damaged,
    /// `MSG-WRONG-CREDENTIALS`: every password try failed (version 1).
    WrongCredentials,
    /// `MSG-XML-EXISTS`.
    XmlExists,
    /// `MSG-XML-NOKEY`.
    XmlNoKey,
    /// `MSG-XML-PROTECTED`.
    XmlProtected,
    /// `MSG-XML-NOROOT`.
    XmlNoRoot,
    /// Any other problem of the XML document (not well-formed, a DTD, a
    /// limit): App's own message, the card names none.
    XmlInvalid,
    /// `MSG-TOO-LARGE`, naming the limit.
    TooLarge(Limit),
    /// `MSG-KDF-COST` (FEA-08.68).
    KdfCost,
    /// The user cancelled (FEA-08.12); nothing is kept.
    Cancelled,
    /// The random source failed while making an id.
    RandomSource,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFile => f.write_str("file or folder missing"),
            Self::Open(v) => write!(f, "cannot read the file: {v:?}"),
            Self::Json { offset, reason } => write!(f, "not valid JSON at byte {offset}: {reason}"),
            Self::WrongPassword => f.write_str("wrong password"),
            Self::BwAccount => f.write_str("export protected by the account key"),
            Self::BwKdf => f.write_str("unsupported key derivation"),
            Self::BwDamaged => f.write_str("the encrypted export is damaged"),
            Self::ProtonEncrypted => f.write_str("the export is encrypted"),
            Self::OnePuxNotZip => f.write_str("not a valid .1pux file: not a ZIP archive"),
            Self::OnePuxNoData => f.write_str("not a valid .1pux file: export data missing"),
            Self::ZipUnsupported => f.write_str("the ZIP file uses a feature App does not read"),
            Self::OpvLayout => f.write_str("not a valid OPVault folder"),
            Self::OpvDamaged => f.write_str("the OPVault data is damaged"),
            Self::V1NotVault => f.write_str("not a version 1 file"),
            Self::V1Cipher => f.write_str("unsupported cipher"),
            Self::V1Version => f.write_str("unsupported version"),
            Self::V1KeyFile => f.write_str("cannot read the key file"),
            Self::V1Damaged => f.write_str("the file is damaged"),
            Self::WrongCredentials => {
                f.write_str("the password or key file is wrong, or the file is damaged")
            }
            Self::XmlExists => f.write_str("file already exists"),
            Self::XmlNoKey => f.write_str("no key set, nothing created"),
            Self::XmlProtected => {
                f.write_str("encrypted values are not allowed in a plain XML document")
            }
            Self::XmlNoRoot => f.write_str("no root group"),
            Self::XmlInvalid => f.write_str("the XML document cannot be read"),
            Self::TooLarge(v) => write!(f, "too large: {}", v.name()),
            Self::KdfCost => f.write_str("key derivation settings out of range"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::RandomSource => f.write_str("random source failed"),
        }
    }
}

impl std::error::Error for ImportError {}

/// The import kinds of the assistant, in list order (FEA-08.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// IMP-CSV.
    Csv,
    /// IMP-1PUX.
    OnePux,
    /// IMP-OPVAULT.
    OpVault,
    /// IMP-BITWARDEN.
    Bitwarden,
    /// IMP-PROTON.
    Proton,
    /// IMP-REMOTE (INT-09).
    Remote,
    /// IMP-V1.
    V1,
}

/// The kinds in the order the assistant lists them; the first is selected
/// at start (FEA-08.1). IMP-REMOTE stays out until remote sync is built
/// (INT-09.30, D-INT09-1, F-112); [`Kind::Remote`] is kept for that day.
pub const KINDS: [Kind; 6] = [
    Kind::Csv,
    Kind::OnePux,
    Kind::OpVault,
    Kind::Bitwarden,
    Kind::Proton,
    Kind::V1,
];

/// The fields the Select step shows for a kind (FEA-08.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fields {
    /// The file (or folder) field; IMP-REMOTE shows INT-09's fields instead.
    pub file: bool,
    /// A password field.
    pub password: bool,
    /// A key file field.
    pub key_file: bool,
}

impl Kind {
    /// FEA-08.2.
    #[must_use]
    pub fn fields(self) -> Fields {
        let (password, key_file) = match self {
            Kind::Bitwarden | Kind::OpVault => (true, false),
            Kind::V1 => (true, true),
            Kind::Csv | Kind::OnePux | Kind::Proton | Kind::Remote => (false, false),
        };
        Fields {
            file: self != Kind::Remote,
            password,
            key_file,
        }
    }
}

/// What every reader needs besides the file.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The import time (FEA-08.9).
    pub now: Time,
    /// The limits the result keeps ([`ResultLimits::DEFAULT`]; tests lower
    /// them).
    pub limits: ResultLimits,
    /// The Mac's time zone, for times without a zone (FEA-08.28).
    pub zone: &'a dyn Zone,
    /// Set by the screen's Cancel (FEA-08.12). A reader looks at it before
    /// each key derivation and each item and then stops with
    /// [`ImportError::Cancelled`]; a derivation already running finishes
    /// first and its result is wiped.
    pub cancel: &'a AtomicBool,
}

impl<'a> Context<'a> {
    /// A context with the default result limits.
    #[must_use]
    pub fn new(now: Time, zone: &'a dyn Zone, cancel: &'a AtomicBool) -> Self {
        Self {
            now,
            limits: ResultLimits::DEFAULT,
            zone,
            cancel,
        }
    }

    fn check_cancel(&self) -> Result<(), ImportError> {
        if self.cancel.load(Ordering::Relaxed) {
            Err(ImportError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// The FMT-08.12 limits an import result keeps, so it can always be saved
/// (FEA-08.67). [`ResultLimits::DEFAULT`] holds the decided values (LD-22);
/// a test ties them to app-format's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultLimits {
    /// `groups`.
    pub groups: usize,
    /// `entries`.
    pub entries: usize,
    /// `entry elements`: entries plus history items.
    pub entry_elements: usize,
    /// The deepest group level, the root at 0 ([`MAX_GROUP_LEVEL`]).
    pub depth: usize,
    /// `strings`: fields of one entry.
    pub strings: usize,
    /// `history`: history items of one entry.
    pub history: usize,
    /// `attachments`: attachments of one entry.
    pub attachments: usize,
    /// `one attachment`, bytes.
    pub one_attachment: usize,
    /// `all attachments`, bytes.
    pub all_attachments: usize,
    /// `icons`: custom icons.
    pub icons: usize,
    /// `total`, bytes of the decompressed payload a save writes: here the
    /// attachments plus the custom icons at their base64 size, one running
    /// budget for both.
    pub total: usize,
}

impl ResultLimits {
    /// The decided values.
    pub const DEFAULT: Self = Self {
        groups: 1_000_000,
        entries: 1_000_000,
        entry_elements: 4_000_000,
        depth: MAX_GROUP_LEVEL,
        strings: 100_000,
        history: 100_000,
        attachments: 100_000,
        one_attachment: 1 << 30,
        all_attachments: 1 << 30,
        icons: 100_000,
        total: 1 << 30,
    };
}

/// Why a reader skipped one item or attachment (not an error, FEA-08.64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The item's check value did not match (LD-45).
    CheckFailed,
    /// Something inside the item was missing or damaged (FEA-08.37).
    Damaged,
    /// One attachment of an imported entry failed (FEA-08.42).
    Attachment,
}

/// One line of the import report: what was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The item's id as the file writes it (never a value).
    pub item: String,
    /// Why.
    pub reason: SkipReason,
}

/// An import result: a temporary vault with one root group (FEA-08 "What it
/// does"). Dropping it wipes every value it holds.
#[derive(Debug)]
pub struct Imported {
    /// The temporary vault: the root group and the custom icons its groups
    /// and entries use; every other setting is the default.
    pub vault: Vault,
    /// Entries the reader marked as trashed (FEA-08.8; OPVault only). They
    /// sit in the result's tree; placement moves them to the target's bin.
    pub trashed: Vec<Uuid>,
    /// The import report: items and attachments skipped (LD-45).
    pub skipped: Vec<Skipped>,
}

/// Reads an import file whole, refusing one over `max` ([`MAX_FILE`], or
/// [`MAX_PUX_FILE`] for a .1pux file) before anything is allocated
/// (FEA-08.67). The bytes are in a [`SecretBytes`] (FEA-08.66).
///
/// # Errors
/// [`ImportError::NoFile`], [`ImportError::TooLarge`] (file) or
/// [`ImportError::Open`] with the system's reason.
pub fn read_file(path: &Path, max: u64) -> Result<SecretBytes, ImportError> {
    crate::storage::read_limited(path, max).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ImportError::NoFile,
        std::io::ErrorKind::FileTooLarge => ImportError::TooLarge(Limit::File),
        kind => ImportError::Open(kind),
    })
}

// ---------------------------------------------------------------------------
// Building a result.

type R<T> = Result<T, ImportError>;

/// The result tree while a reader builds it: groups in a flat list (index
/// 0 is the root) so lookups by path and adding entries cost no tree walk.
pub(crate) struct Builder<'c> {
    ctx: Context<'c>,
    groups: Vec<Group>,
    parents: Vec<usize>,
    levels: Vec<usize>,
    by_name: HashMap<(usize, String), usize>,
    ids: HashSet<Uuid>,
    entries: usize,
    elements: usize,
    attachment_bytes: usize,
    icon_bytes: usize,
    icons: Vec<app_model::CustomIcon>,
    trashed: Vec<Uuid>,
    skipped: Vec<Skipped>,
    drop_empty: bool,
}

impl<'c> Builder<'c> {
    pub(crate) fn new(ctx: &Context<'c>, root_name: &str) -> R<Self> {
        let mut b = Self {
            ctx: *ctx,
            groups: Vec::new(),
            parents: Vec::new(),
            levels: Vec::new(),
            by_name: HashMap::new(),
            ids: HashSet::new(),
            entries: 0,
            elements: 0,
            attachment_bytes: 0,
            icon_bytes: 0,
            icons: Vec::new(),
            trashed: Vec::new(),
            skipped: Vec::new(),
            drop_empty: false,
        };
        let id = b.fresh()?;
        b.groups.push(Group::new(id, root_name.to_owned(), ctx.now));
        b.parents.push(0);
        b.levels.push(0);
        Ok(b)
    }

    pub(crate) fn ctx(&self) -> &Context<'c> {
        &self.ctx
    }

    fn fresh(&mut self) -> R<Uuid> {
        let ids = &self.ids;
        let id = tree::fresh_id(|u| ids.contains(&u)).map_err(|_| ImportError::RandomSource)?;
        self.ids.insert(id);
        Ok(id)
    }

    /// `want` when the file gave a usable id (not zero, not used in this
    /// result yet), else a fresh one.
    fn take_id(&mut self, want: Option<Uuid>) -> R<Uuid> {
        match want {
            Some(id) if !id.is_zero() && self.ids.insert(id) => Ok(id),
            _ => self.fresh(),
        }
    }

    /// Gives the root group the file's id when it is usable (FEA-08.40).
    pub(crate) fn root_id(&mut self, id: Uuid) {
        if !id.is_zero() && !self.ids.contains(&id) {
            if let Some(root) = self.groups.first_mut() {
                self.ids.remove(&root.uuid);
                root.uuid = id;
            }
            self.ids.insert(id);
        }
    }

    pub(crate) fn group_mut(&mut self, g: usize) -> Option<&mut Group> {
        self.groups.get_mut(g)
    }

    /// The first child of `parent` named exactly `name`, made when missing.
    pub(crate) fn child(&mut self, parent: usize, name: &str) -> R<usize> {
        if let Some(&g) = self.by_name.get(&(parent, name.to_owned())) {
            return Ok(g);
        }
        self.new_child(parent, name, None)
    }

    /// A new child of `parent` named `name`, also when one has that name,
    /// with the file's id `id` when usable.
    pub(crate) fn new_child(&mut self, parent: usize, name: &str, id: Option<Uuid>) -> R<usize> {
        let level = self
            .levels
            .get(parent)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if level > self.ctx.limits.depth {
            return Err(ImportError::TooLarge(Limit::Depth));
        }
        if self.groups.len() >= self.ctx.limits.groups {
            return Err(ImportError::TooLarge(Limit::Groups));
        }
        let id = self.take_id(id)?;
        let g = self.groups.len();
        self.groups
            .push(Group::new(id, name.to_owned(), self.ctx.now));
        self.parents.push(parent);
        self.levels.push(level);
        self.by_name.entry((parent, name.to_owned())).or_insert(g);
        Ok(g)
    }

    /// Walks `parts` down from `parent` with [`Builder::child`].
    pub(crate) fn path<'p>(
        &mut self,
        parent: usize,
        parts: impl Iterator<Item = &'p str>,
    ) -> R<usize> {
        let mut g = parent;
        for part in parts {
            g = self.child(g, part)?;
        }
        Ok(g)
    }

    /// A new entry with a fresh id and every time the import time.
    pub(crate) fn draft(&mut self) -> R<Draft> {
        self.draft_with(None)
    }

    /// [`Builder::draft`] with the file's id `id` when usable.
    pub(crate) fn draft_with(&mut self, id: Option<Uuid>) -> R<Draft> {
        self.ctx.check_cancel()?;
        let id = self.take_id(id)?;
        Ok(Draft::new(Entry::new(id, self.ctx.now), self.ctx.limits))
    }

    /// Adds a finished draft at the end of group `g`.
    pub(crate) fn add(&mut self, g: usize, d: Draft) -> R<Uuid> {
        let e = d.finish();
        let limits = self.ctx.limits;
        self.entries = self.entries.saturating_add(1);
        self.elements = self
            .elements
            .saturating_add(1)
            .saturating_add(e.history.len());
        if self.entries > limits.entries {
            return Err(ImportError::TooLarge(Limit::Entries));
        }
        if self.elements > limits.entry_elements {
            return Err(ImportError::TooLarge(Limit::EntryElements));
        }
        // The readers asked for the room before reading each attachment
        // (`Builder::room`); this is the last guard.
        for a in &e.attachments {
            self.attachment_bytes = self.attachment_bytes.saturating_add(a.data.len());
        }
        if self.attachment_bytes > limits.all_attachments {
            return Err(ImportError::TooLarge(Limit::AllAttachments));
        }
        if self.attachment_bytes.saturating_add(self.icon_bytes) > limits.total {
            return Err(ImportError::TooLarge(Limit::Total));
        }
        let id = e.uuid;
        let group = self
            .groups
            .get_mut(g)
            .ok_or(ImportError::TooLarge(Limit::Groups))?;
        group.entries.push(e);
        Ok(id)
    }

    /// A custom icon for the result (FEA-08.29, FEA-08.58): equal bytes
    /// give the same icon; its id is unique in the result.
    pub(crate) fn icon(&mut self, data: &[u8]) -> R<Uuid> {
        if let Some(i) = self.icons.iter().find(|i| i.data == data) {
            return Ok(i.uuid);
        }
        if self.icons.len() >= self.ctx.limits.icons {
            return Err(ImportError::TooLarge(Limit::Icons));
        }
        let cost = base64_len(data.len());
        let used = self.attachment_bytes.saturating_add(self.icon_bytes);
        if used.saturating_add(cost) > self.ctx.limits.total {
            return Err(ImportError::TooLarge(Limit::Total));
        }
        self.icon_bytes = self.icon_bytes.saturating_add(cost);
        let uuid = self.fresh()?;
        self.icons.push(app_model::CustomIcon {
            uuid,
            name: String::new(),
            last_modified: None,
            data: data.to_vec(),
            unknown: Vec::new(),
        });
        Ok(uuid)
    }

    /// The most bytes one more attachment of draft `d` may have, and the
    /// limit that sets it: the one-attachment limit, what is left of the
    /// attachments budget, or what is left of the total budget after every
    /// attachment added so far (this draft's too) and the icons. Readers
    /// pass it to `Archive::read` and `Folder::file`, so nothing over the
    /// budget is read or inflated.
    pub(crate) fn room(&self, d: &Draft) -> (usize, Limit) {
        let l = self.ctx.limits;
        let att = self.attachment_bytes.saturating_add(d.attachment_bytes);
        let used = att.saturating_add(self.icon_bytes);
        [
            (l.one_attachment, Limit::OneAttachment),
            (l.all_attachments.saturating_sub(att), Limit::AllAttachments),
            (l.total.saturating_sub(used), Limit::Total),
        ]
        .into_iter()
        .min_by_key(|(room, _)| *room)
        .unwrap_or((0, Limit::Total))
    }

    /// The most bytes one more custom icon may have (its base64 text must
    /// fit the total budget), and the limit that sets it.
    pub(crate) fn icon_room(&self) -> (usize, Limit) {
        let l = self.ctx.limits;
        let used = self.attachment_bytes.saturating_add(self.icon_bytes);
        let left = (l.total.saturating_sub(used) / 4).saturating_mul(3);
        if left < l.one_attachment {
            (left, Limit::Total)
        } else {
            (l.one_attachment, Limit::OneAttachment)
        }
    }

    /// Marks an added entry as trashed (FEA-08.8).
    pub(crate) fn trash(&mut self, id: Uuid) {
        self.trashed.push(id);
    }

    /// Lists a skipped item in the import report (LD-45).
    pub(crate) fn skip(&mut self, item: &str, reason: SkipReason) {
        self.skipped.push(Skipped {
            item: item.to_owned(),
            reason,
        });
    }

    /// At the end, drop every child group of the root that holds nothing
    /// (FEA-08.39).
    pub(crate) fn drop_empty_top_groups(&mut self) {
        self.drop_empty = true;
    }

    /// The finished result. Children were made after their parents, so
    /// moving each group into its parent from the last one up builds the
    /// tree with every child list in making order.
    pub(crate) fn finish(mut self) -> Imported {
        while self.groups.len() > 1 {
            let Some(mut g) = self.groups.pop() else {
                break;
            };
            g.groups.reverse();
            let parent = self.parents.get(self.groups.len()).copied().unwrap_or(0);
            if let Some(p) = self.groups.get_mut(parent) {
                p.groups.push(g);
            }
        }
        let mut root = self
            .groups
            .pop()
            .unwrap_or_else(|| Group::new(Uuid([1; 16]), String::new(), self.ctx.now));
        root.groups.reverse();
        if self.drop_empty {
            root.groups
                .retain(|g| !(g.entries.is_empty() && g.groups.is_empty()));
        }
        let mut vault = Vault::new(root, self.ctx.now);
        vault.meta.custom_icons = self.icons;
        Imported {
            vault,
            trashed: self.trashed,
            skipped: self.skipped,
        }
    }
}

/// One entry while a reader fills it: fields collected with a name index,
/// so many fields cost no per-field insert into the sorted list.
pub(crate) struct Draft {
    entry: Entry,
    fields: Vec<(String, Field)>,
    index: HashMap<String, usize>,
    extra_urls: usize,
    limits: ResultLimits,
    /// Bytes of this draft's attachments (for `Builder::room`).
    attachment_bytes: usize,
    /// This draft's attachment names, so a clash check costs no scan.
    attachment_names: HashSet<String>,
}

impl Draft {
    fn new(entry: Entry, limits: ResultLimits) -> Self {
        let mut d = Self {
            entry,
            fields: Vec::new(),
            index: HashMap::new(),
            extra_urls: 0,
            limits,
            attachment_bytes: 0,
            attachment_names: HashSet::new(),
        };
        for n in STANDARD_FIELDS {
            d.index.insert(n.to_owned(), d.fields.len());
            d.fields.push((n.to_owned(), Field::empty()));
        }
        d
    }

    /// Adds a history item (FEA-08.48), within the `history` limit.
    pub(crate) fn history(&mut self, item: Entry) -> R<()> {
        if self.entry.history.len() >= self.limits.history {
            return Err(ImportError::TooLarge(Limit::History));
        }
        self.entry.history.push(item);
        Ok(())
    }

    /// Adds an attachment within the attachment limits. A name the entry
    /// already has gets 5 random hex digits and `_` in front (FEA-08.42;
    /// names stay unique in an entry).
    pub(crate) fn attach(&mut self, name: &str, data: SecretBytes) -> R<()> {
        if data.len() > self.limits.one_attachment {
            return Err(ImportError::TooLarge(Limit::OneAttachment));
        }
        if self.entry.attachments.len() >= self.limits.attachments {
            return Err(ImportError::TooLarge(Limit::Attachments));
        }
        let mut n = name.to_owned();
        while self.attachment_names.contains(&n) {
            n = format!("{}_{name}", random_hex(5)?);
        }
        self.attachment_names.insert(n.clone());
        self.attachment_bytes = self.attachment_bytes.saturating_add(data.len());
        self.entry.attachments.push(app_model::Attachment {
            name: n,
            data: std::sync::Arc::new(data),
        });
        Ok(())
    }

    /// True when the entry has a one-time password field (FEA-04 forms).
    pub(crate) fn has_totp(&self) -> bool {
        [totp::OTP, totp::SEED, totp::SETTINGS]
            .iter()
            .any(|n| self.has(n))
    }

    /// The entry's times, icon, tags and history.
    pub(crate) fn entry_mut(&mut self) -> &mut Entry {
        &mut self.entry
    }

    /// The value of field `name`, `""` when there is none.
    pub(crate) fn value(&self, name: &str) -> &str {
        self.index
            .get(name)
            .and_then(|&i| self.fields.get(i))
            .map_or("", |(_, f)| f.value.expose())
    }

    pub(crate) fn has(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    /// Sets field `name`, replacing an existing one. `Password` is always
    /// protected (MOD-12.17).
    pub(crate) fn set(&mut self, name: &str, value: SecretString, protected: bool) -> R<()> {
        let field = Field {
            value,
            protected: protected || name == "Password",
        };
        if let Some(slot) = self.index.get(name).and_then(|&i| self.fields.get_mut(i)) {
            slot.1 = field;
            return Ok(());
        }
        if self.fields.len() >= self.limits.strings {
            return Err(ImportError::TooLarge(Limit::Strings));
        }
        self.index.insert(name.to_owned(), self.fields.len());
        self.fields.push((name.to_owned(), field));
        Ok(())
    }

    /// Removes field `name` when it is there (standard fields stay).
    pub(crate) fn remove(&mut self, name: &str) {
        if STANDARD_FIELDS.contains(&name) {
            return;
        }
        let Some(i) = self.index.remove(name) else {
            return;
        };
        if i < self.fields.len() {
            self.fields.swap_remove(i);
            if let Some((moved, _)) = self.fields.get(i) {
                self.index.insert(moved.clone(), i);
            }
        }
    }

    /// A custom field with "suffix on clash" (FEA-08.11): a taken name gets
    /// `_` and 5 random lowercase hex digits.
    pub(crate) fn custom(&mut self, name: &str, value: SecretString, protected: bool) -> R<()> {
        let mut n = name.to_owned();
        while self.has(&n) {
            n = format!("{name}_{}", random_hex(5)?);
        }
        self.set(&n, value, protected)
    }

    /// One extra URL into `KP2A_URL_1`, `KP2A_URL_2` … in call order
    /// (FEA-08.11).
    pub(crate) fn extra_url(&mut self, url: SecretString) -> R<()> {
        loop {
            self.extra_urls = self.extra_urls.saturating_add(1);
            let n = format!("KP2A_URL_{}", self.extra_urls);
            if !self.has(&n) {
                return self.set(&n, url, false);
            }
        }
    }

    /// Adds one tag, normalized per MOD-07 (FEA-08.9).
    pub(crate) fn tag(&mut self, t: &str) {
        crate::tags::add_to(&mut self.entry, t);
    }

    /// FEA-08.10 "TOTP value V": a bare secret becomes an `otpauth://` link
    /// from the title and user name as they are now; a link that parses
    /// with a secret is stored in its form.
    pub(crate) fn totp(&mut self, v: &str) -> R<()> {
        if v.is_empty() {
            return Ok(());
        }
        let settings = totp::from_text(self.totp_link(v).expose(), "");
        match settings {
            Some(s) if s.has_secret() => self.store_totp(&s),
            _ => Ok(()),
        }
    }

    /// FEA-08.10's link for V: V when it starts with `otpauth://`, else
    /// `otpauth://totp/` + E(title) + `:` + E(user name) + `?secret=` + E(V).
    pub(crate) fn totp_link(&self, v: &str) -> SecretString {
        if v.starts_with("otpauth://") {
            return Text::from(v).into_secret();
        }
        let mut uri = Text::from("otpauth://totp/");
        totp::percent_encode(&mut uri, self.value("Title"));
        uri.push(':');
        totp::percent_encode(&mut uri, self.value("UserName"));
        uri.push_str("?secret=");
        totp::percent_encode(&mut uri, v);
        uri.into_secret()
    }

    /// The first free name `base_1`, `base_2` … (FEA-08.31, FEA-08.41).
    pub(crate) fn numbered(&self, base: &str) -> String {
        let mut n = 1u32;
        loop {
            let name = format!("{base}_{n}");
            if !self.has(&name) {
                return name;
            }
            n = n.saturating_add(1);
        }
    }

    /// FEA-08.26: any storage form; when that fails or gives no secret,
    /// the whole text as a bare secret with the defaults, form L.
    pub(crate) fn totp_any(&mut self, v: &str) -> R<()> {
        if v.is_empty() {
            return Ok(());
        }
        match totp::from_text(v, "") {
            Some(s) if s.has_secret() => self.store_totp(&s),
            _ => match totp::from_text("", v) {
                Some(s) => self.store_totp(&s),
                None => Ok(()),
            },
        }
    }

    /// FEA-08.10 storing: the fields FEA-04.16 writes for the form the
    /// settings were read in, labels from the title and user name with
    /// placeholders resolved.
    pub(crate) fn store_totp(&mut self, s: &totp::Settings) -> R<()> {
        let now = self.entry.times.creation;
        let mut probe = Entry::new(Uuid::ZERO, now);
        for n in STANDARD_FIELDS {
            probe.set_field(
                n.to_owned(),
                Field {
                    value: Text::from(self.value(n)).into_secret(),
                    protected: false,
                },
            );
        }
        let ctx = refs::Context::new(None, now);
        let title = refs::resolve(probe.value("Title"), &probe, &ctx).text;
        let user = refs::resolve(probe.value("UserName"), &probe, &ctx).text;
        for (name, f) in totp::stored_fields(s, title.expose(), user.expose()) {
            self.set(name, f.value, f.protected)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Entry {
        self.entry.replace_fields(self.fields);
        self.entry
    }
}

/// `n` random lowercase hex digits from app-crypto.
pub(crate) fn random_hex(n: usize) -> R<String> {
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let d = app_crypto::random::below(16).map_err(|_| ImportError::RandomSource)?;
        out.push(char::from_digit(d, 16).unwrap_or('0'));
    }
    Ok(out)
}

/// Windows-1252 bytes 0x80 to 0x9F (the WHATWG table: the five unassigned
/// bytes map to the C1 controls of the same number, as Windows does).
pub(crate) const CP1252_HIGH: [u16; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
];

/// The length of the padded base64 text of `n` bytes.
fn base64_len(n: usize) -> usize {
    n.div_ceil(3).saturating_mul(4)
}

/// Standard base64, padding optional, for ciphertext and other values
/// that are not secret (FEA-08.35, FEA-08.50).
pub(crate) fn b64(text: &str) -> Option<Vec<u8>> {
    app_crypto::base64::decode(app_crypto::base64::Form::PaddingOptional, text).ok()
}

/// Case-insensitive equality by Unicode lowercase mapping.
pub(crate) fn same_ignoring_case(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

/// FEA-08.28 times: digits only are Unix seconds (≤ 2,147,483,647) or
/// milliseconds (larger; a number too large for 64 bits is 0); otherwise
/// the ISO 8601 forms listed there, local time when no zone is given.
/// `None` for anything else.
pub(crate) fn parse_time(text: &str, zone: &dyn Zone) -> Option<Time> {
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        let v: i64 = text.parse().unwrap_or(0);
        let secs = if v <= 2_147_483_647 { v } else { v / 1000 };
        return Time::from_unix(secs);
    }
    iso_time(text.as_bytes(), zone)
}

fn iso_time(b: &[u8], zone: &dyn Zone) -> Option<Time> {
    let num = |at: usize, len: usize| -> Option<u32> {
        let s = b.get(at..at.checked_add(len)?)?;
        if !s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        core::str::from_utf8(s).ok()?.parse().ok()
    };
    let year = num(0, 4)?;
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let (month, day) = (num(5, 2)?, num(8, 2)?);
    let mut at = 10usize;
    let (mut hour, mut minute, mut second, mut zero_fraction) = (0u32, 0u32, 0u32, true);
    let mut offset: Option<i64> = None;
    if at < b.len() {
        if !matches!(b.get(at), Some(b'T' | b't' | b' ')) {
            return None;
        }
        hour = num(at.checked_add(1)?, 2)?;
        if b.get(at.checked_add(3)?) != Some(&b':') {
            return None;
        }
        minute = num(at.checked_add(4)?, 2)?;
        at = at.checked_add(6)?;
        if b.get(at) == Some(&b':') {
            second = num(at.checked_add(1)?, 2)?;
            at = at.checked_add(3)?;
            if matches!(b.get(at), Some(b'.' | b',')) {
                at = at.checked_add(1)?;
                let start = at;
                while b.get(at).is_some_and(u8::is_ascii_digit) {
                    zero_fraction &= b.get(at) == Some(&b'0');
                    at = at.checked_add(1)?;
                }
                if at == start {
                    return None;
                }
            }
        }
        match b.get(at) {
            None => {}
            Some(b'Z' | b'z') if at.checked_add(1)? == b.len() => offset = Some(0),
            Some(&sign @ (b'+' | b'-')) => {
                let oh = num(at.checked_add(1)?, 2)?;
                let rest = b.len().checked_sub(at.checked_add(3)?)?;
                let om = match rest {
                    0 => 0,
                    2 => num(at.checked_add(3)?, 2)?,
                    3 if b.get(at.checked_add(3)?) == Some(&b':') => num(at.checked_add(4)?, 2)?,
                    _ => return None,
                };
                if oh > 23 || om > 59 {
                    return None;
                }
                let secs = i64::from(oh.checked_mul(3600)?.checked_add(om.checked_mul(60)?)?);
                offset = Some(if sign == b'-' {
                    secs.checked_neg()?
                } else {
                    secs
                });
            }
            Some(_) => return None,
        }
    }
    // `24:00` is 00:00 of the next day.
    let next_day = hour == 24 && minute == 0 && second == 0 && zero_fraction;
    let civil = Civil {
        year: i64::from(year),
        month,
        day,
        hour: if next_day { 0 } else { hour },
        minute,
        second,
    };
    let mut t = Time::from_civil(civil)?;
    if next_day {
        t = Time(t.0.checked_add(86_400)?);
    }
    match offset {
        Some(o) => Some(Time(t.0.checked_sub(o)?)),
        None => zone.utc(t),
    }
}

// ---------------------------------------------------------------------------
// The assistant's lists (FEA-08.3, FEA-08.4).

/// One row of the Existing vault list (FEA-08.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRow {
    /// The group the import goes into.
    pub group: Uuid,
    /// The row text.
    pub text: String,
}

/// The rows of one unlocked vault (FEA-08.3): "<display name> (<root
/// name>)" for the root, then each group outside the recycle bin as
/// "  / A / B", depth first in stored order. Locked vaults are not passed.
#[must_use]
pub fn target_rows(display_name: &str, vault: &Vault) -> Vec<TargetRow> {
    let mut rows = vec![TargetRow {
        group: vault.root.uuid,
        text: format!("{display_name} ({})", vault.root.name),
    }];
    let bin = recycle::bin_id(vault);
    let mut stack: Vec<(&Group, String)> = vault
        .root
        .groups
        .iter()
        .rev()
        .map(|g| (g, String::from(" ")))
        .collect();
    while let Some((g, prefix)) = stack.pop() {
        if Some(g.uuid) == bin {
            continue;
        }
        let path = format!("{prefix} / {}", g.name);
        rows.push(TargetRow {
            group: g.uuid,
            text: path.clone(),
        });
        stack.extend(g.groups.iter().rev().map(|c| (c, path.clone())));
    }
    rows
}

/// The mask the preview shows for a non-empty password (FEA-08.4, L08-2).
pub const PASSWORD_MASK: &str = refs::MASK;

/// One preview row (FEA-08.4). The password is never in it: only the mask
/// or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    /// The entry's own group name.
    pub group: String,
    /// Title.
    pub title: String,
    /// User name.
    pub user_name: String,
    /// [`PASSWORD_MASK`] for a non-empty password, else empty.
    pub password: &'static str,
    /// URL.
    pub url: String,
}

/// The Review table (FEA-08.4): one row per entry of the result, recycle
/// bin included, history items not; its length is the "Entry count".
#[must_use]
pub fn preview(imported: &Imported) -> Vec<PreviewRow> {
    imported
        .vault
        .root
        .subtree()
        .into_iter()
        .flat_map(|g| g.entries.iter().map(move |e| (g, e)))
        .map(|(g, e)| PreviewRow {
            group: g.name.clone(),
            title: e.value("Title").to_owned(),
            user_name: e.value("UserName").to_owned(),
            password: if e.value("Password").is_empty() {
                ""
            } else {
                PASSWORD_MASK
            },
            url: e.value("URL").to_owned(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Placement (FEA-08.5 to FEA-08.8).

/// FEA-08.5: merges the result into `target`, the new empty vault APP-07
/// made (MOD-11 import wizard: keep-newer, no vault custom data; the new
/// root takes the result root's name and notes). Trashed entries go to the
/// target's recycle bin (FEA-08.8). Cipher, key derivation and credentials
/// stay APP-07's. Dropping an unused result instead (APP-07 cancelled)
/// wipes it.
///
/// # Errors
/// `TooLarge` past the FMT-08.12 counts; `RandomSource`. The caller drops
/// the new vault on an error.
pub fn into_new_vault(target: &mut Vault, imported: Imported, now: Time) -> Result<(), Error> {
    let Imported {
        mut vault, trashed, ..
    } = imported;
    let trashed = take_entries(&mut vault.root, &trashed);
    check_counts(target, &vault.root, &trashed)?;
    merge::merge(
        target,
        &vault,
        &MergeOptions::new(MergeKind::ImportWizard),
        now,
    )?;
    if !trashed.is_empty() {
        let root = target.root.uuid;
        let bin = bin_for(target, root, now)?;
        apply_bin(target, bin, trashed, now);
    }
    Ok(())
}

/// FEA-08.6 to FEA-08.8: the result's root group, with its name, notes,
/// child groups and entries, becomes the last child of `group` in
/// `target`. Ids the target already uses (groups, entries, deleted
/// objects) are replaced by fresh ones, history items following their
/// entry (L08-5). Every custom icon a moved group or entry uses is copied
/// into the target, reusing an equal icon there. Trashed entries go to the
/// target's bin, made per MOD-04.2 when missing, or, with the bin off, into
/// a normal group named like the bin as the last child of the moved root
/// (L08-6).
///
/// # Errors
/// `NoSuchGroup` (the vault changed: `MSG-IMP-TARGET-GONE`);
/// `InRecycleBin`; `TooDeep`; `TooLarge`; `RandomSource`. The target is
/// unchanged on every error.
pub fn into_group(
    target: &mut Vault,
    group: Uuid,
    imported: Imported,
    now: Time,
) -> Result<(), Error> {
    if tree::group(target, group).is_none() {
        return Err(Error::NoSuchGroup);
    }
    if recycle::group_in_bin(target, group) {
        return Err(Error::InRecycleBin);
    }
    let Imported {
        vault: source,
        trashed,
        ..
    } = imported;
    let mut root = source.root;
    let mut trashed = take_entries(&mut root, &trashed);
    let level = tree::level(target, group).ok_or(Error::NoSuchGroup)?;
    if level.saturating_add(1).saturating_add(tree::height(&root)) > MAX_GROUP_LEVEL {
        return Err(Error::TooDeep);
    }
    check_counts(target, &root, &trashed)?;

    // L08-5: fresh ids for clashes.
    let subtree = target.root.subtree();
    let mut groups: HashSet<Uuid> = subtree.iter().map(|g| g.uuid).collect();
    let mut entries: HashSet<Uuid> = subtree
        .iter()
        .flat_map(|g| g.entries.iter().map(|e| e.uuid))
        .collect();
    for d in &target.deleted_objects {
        groups.insert(d.uuid);
        entries.insert(d.uuid);
    }
    let mut problem = Ok(());
    for_each_group_mut(&mut root, &mut |g: &mut Group| {
        if problem.is_err() {
            return;
        }
        problem = renew(&mut g.uuid, &mut groups).and_then(|()| {
            g.entries
                .iter_mut()
                .try_for_each(|e| renew_entry(e, &mut entries))
        });
    });
    problem?;
    for e in &mut trashed {
        renew_entry(e, &mut entries)?;
    }

    // Custom icons, decided before anything changes.
    let icons = icon_plan(target, &source.meta.custom_icons, &root, &trashed)?;
    let bin = if trashed.is_empty() {
        None
    } else if target.meta.recycle_bin_enabled {
        Some(match recycle::bin_id(target) {
            Some(id) => BinPlace::Existing(id),
            None => BinPlace::NewBin(tree::fresh_id(|u| groups.contains(&u))?),
        })
    } else {
        Some(BinPlace::Plain(tree::fresh_id(|u| groups.contains(&u))?))
    };

    // Now change the target.
    remap_icons(&mut root, &icons.remap);
    for e in &mut trashed {
        remap_entry_icons(e, &icons.remap);
    }
    target.meta.custom_icons.extend(icons.add);
    if let Some(BinPlace::Plain(id)) = bin {
        let mut plain = plain_bin(id, now);
        plain.entries = core::mem::take(&mut trashed);
        root.groups.push(plain);
    }
    tree::group_mut(target, group)
        .ok_or(Error::NoSuchGroup)?
        .groups
        .push(root);
    match bin {
        Some(BinPlace::Existing(id)) => apply_bin(target, id, trashed, now),
        Some(BinPlace::NewBin(id)) => {
            add_bin(target, id, now);
            apply_bin(target, id, trashed, now);
        }
        Some(BinPlace::Plain(_)) | None => {}
    }
    Ok(())
}

enum BinPlace {
    Existing(Uuid),
    NewBin(Uuid),
    Plain(Uuid),
}

/// The bin for trashed entries in a vault that may not have one yet: an
/// existing bin, a new one (MOD-04.2), or with the bin off a plain group
/// named like the bin under `under`.
fn bin_for(target: &mut Vault, under: Uuid, now: Time) -> Result<Uuid, Error> {
    if target.meta.recycle_bin_enabled {
        return recycle::ensure_bin(target, now);
    }
    let taken: HashSet<Uuid> = target.root.subtree().iter().map(|g| g.uuid).collect();
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    tree::group_mut(target, under)
        .ok_or(Error::NoSuchGroup)?
        .groups
        .push(plain_bin(id, now));
    Ok(id)
}

/// The group for trashed entries when the target's bin is off: named like
/// the bin, with its icon and search and Auto-Type off (LD-148).
fn plain_bin(id: Uuid, now: Time) -> Group {
    let mut g = Group::new(id, BIN_NAME.to_owned(), now);
    g.icon = Icon::Standard(BIN_ICON);
    g.searching = Switch::Off;
    g.auto_type = Switch::Off;
    g
}

/// MOD-04.2 with an id drawn earlier.
fn add_bin(target: &mut Vault, id: Uuid, now: Time) {
    target.root.groups.push(plain_bin(id, now));
    target.meta.recycle_bin = Some(id);
    target.meta.recycle_bin_changed = now;
}

fn apply_bin(target: &mut Vault, bin: Uuid, trashed: Vec<Entry>, _now: Time) {
    if let Some(g) = tree::group_mut(target, bin) {
        g.entries.extend(trashed);
    }
}

/// Takes the entries with the listed ids out of the tree, in tree order.
fn take_entries(root: &mut Group, ids: &[Uuid]) -> Vec<Entry> {
    if ids.is_empty() {
        return Vec::new();
    }
    let wanted: HashSet<Uuid> = ids.iter().copied().collect();
    let mut out = Vec::new();
    for_each_group_mut(root, &mut |g: &mut Group| {
        let (take, keep): (Vec<Entry>, Vec<Entry>) = core::mem::take(&mut g.entries)
            .into_iter()
            .partition(|e| wanted.contains(&e.uuid));
        g.entries = keep;
        out.extend(take);
    });
    out
}

/// Every group of the subtree, parents first. Iterative.
fn for_each_group_mut(root: &mut Group, f: &mut dyn FnMut(&mut Group)) {
    let mut stack: Vec<&mut Group> = vec![root];
    while let Some(g) = stack.pop() {
        f(g);
        stack.extend(g.groups.iter_mut().rev());
    }
}

fn renew(id: &mut Uuid, taken: &mut HashSet<Uuid>) -> Result<(), Error> {
    if taken.contains(id) {
        *id = tree::fresh_id(|u| taken.contains(&u))?;
    }
    taken.insert(*id);
    Ok(())
}

fn renew_entry(e: &mut Entry, taken: &mut HashSet<Uuid>) -> Result<(), Error> {
    renew(&mut e.uuid, taken)?;
    let id = e.uuid;
    for h in &mut e.history {
        h.uuid = id;
    }
    Ok(())
}

/// The FMT-08.12 counts of the target plus what is placed.
fn check_counts(target: &Vault, root: &Group, trashed: &[Entry]) -> Result<(), Error> {
    let count = |g: &Group| {
        let groups = g.subtree();
        let entries: Vec<&Entry> = groups.iter().flat_map(|g| g.entries.iter()).collect();
        let items: usize = entries.iter().map(|e| e.history.len()).sum();
        (
            groups.len(),
            entries.len(),
            entries.len().saturating_add(items),
        )
    };
    let (g1, e1, i1) = count(&target.root);
    let (g2, e2, i2) = count(root);
    let e3 = trashed.len();
    let i3: usize = trashed
        .iter()
        .map(|e| e.history.len().saturating_add(1))
        .sum();
    let limits = CountLimits::DEFAULT;
    // One more group for a bin that may be made.
    if g1.saturating_add(g2).saturating_add(1) > limits.groups
        || e1.saturating_add(e2).saturating_add(e3) > limits.entries
        || i1.saturating_add(i2).saturating_add(i3) > limits.entry_elements
    {
        return Err(Error::TooLarge);
    }
    Ok(())
}

struct IconPlan {
    add: Vec<app_model::CustomIcon>,
    remap: HashMap<Uuid, Uuid>,
}

/// FEA-08.6 icons: each custom icon of the result used by a moved group or
/// entry (history items included): an equal icon in the target is reused;
/// otherwise it is added, with a fresh id when its id is taken.
fn icon_plan(
    target: &Vault,
    icons: &[app_model::CustomIcon],
    root: &Group,
    trashed: &[Entry],
) -> Result<IconPlan, Error> {
    let mut used: HashSet<Uuid> = HashSet::new();
    let mut note = |i: Icon| {
        if let Icon::Custom(id) = i {
            used.insert(id);
        }
    };
    for g in root.subtree() {
        note(g.icon);
        for e in g
            .entries
            .iter()
            .chain(g.entries.iter().flat_map(|e| e.history.iter()))
        {
            note(e.icon);
        }
    }
    for e in trashed
        .iter()
        .chain(trashed.iter().flat_map(|e| e.history.iter()))
    {
        note(e.icon);
    }
    let mut taken: HashSet<Uuid> = target.meta.custom_icons.iter().map(|i| i.uuid).collect();
    let mut plan = IconPlan {
        add: Vec::new(),
        remap: HashMap::new(),
    };
    for icon in icons.iter().filter(|i| used.contains(&i.uuid)) {
        if let Some(same) = target
            .meta
            .custom_icons
            .iter()
            .find(|t| t.data == icon.data)
        {
            plan.remap.insert(icon.uuid, same.uuid);
            continue;
        }
        let mut copy = icon.clone();
        if taken.contains(&copy.uuid) {
            copy.uuid = tree::fresh_id(|u| taken.contains(&u))?;
            plan.remap.insert(icon.uuid, copy.uuid);
        }
        taken.insert(copy.uuid);
        plan.add.push(copy);
    }
    Ok(plan)
}

fn remap_icon(icon: &mut Icon, remap: &HashMap<Uuid, Uuid>) {
    if let Icon::Custom(id) = icon
        && let Some(to) = remap.get(id)
    {
        *id = *to;
    }
}

fn remap_entry_icons(e: &mut Entry, remap: &HashMap<Uuid, Uuid>) {
    remap_icon(&mut e.icon, remap);
    for h in &mut e.history {
        remap_icon(&mut h.icon, remap);
    }
}

fn remap_icons(root: &mut Group, remap: &HashMap<Uuid, Uuid>) {
    if remap.is_empty() {
        return;
    }
    for_each_group_mut(root, &mut |g: &mut Group| {
        remap_icon(&mut g.icon, remap);
        for e in &mut g.entries {
            remap_entry_icons(e, remap);
        }
    });
}

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::time::Utc;

    #[test]
    fn iso_and_number_times() {
        let t = |s: &str| parse_time(s, &Utc);
        let at = |y, mo, d, h, mi, s| {
            Time::from_civil(Civil {
                year: y,
                month: mo,
                day: d,
                hour: h,
                minute: mi,
                second: s,
            })
        };
        assert_eq!(t("2024-12-25T12:00:00.000Z"), at(2024, 12, 25, 12, 0, 0));
        assert_eq!(t("2024-12-25t12:00z"), at(2024, 12, 25, 12, 0, 0));
        assert_eq!(t("2024-03-10T12:00:00+0230"), at(2024, 3, 10, 9, 30, 0));
        assert_eq!(t("2024-03-10T12:00:00-02"), at(2024, 3, 10, 14, 0, 0));
        assert_eq!(t("2024-03-10T24:00"), at(2024, 3, 11, 0, 0, 0));
        assert_eq!(t("2024-03-10T24:00:00,000"), at(2024, 3, 11, 0, 0, 0));
        assert_eq!(t("2024-03-10"), at(2024, 3, 10, 0, 0, 0));
        assert_eq!(t("99999999999999999999"), Time::from_unix(0));
        for bad in [
            "",
            "2024-3-10",
            "2024-03-10T12",
            "2024-03-10T12:00:00.",
            "2024-02-30",
            "2024-03-10T24:01",
            "2024-03-10Z",
            "2024-03-10T12:00+2400",
            "soon",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }
}
