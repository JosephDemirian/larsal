//! Attachments (MOD-05): the attachment set of an entry, names, adding,
//! renaming, removing, the command line import, export and remove, the
//! size limits, one shared copy of equal content, and the pure parts of
//! preview, open and save to disk.
//!
//! The editor works on a draft entry; every change here goes into a draft
//! (`put`, `rename`, `remove`) or runs as one edit session on the vault
//! (`import`, `remove_named`, `replace`), so attachment changes reach the
//! history like any other change (MOD-05.4, MOD-03.2). Files on disk are
//! written by app-platform; this module gives their names and checks.
//!
//! Guarantees: content stays in `SecretBytes`; equal content held anywhere
//! in the vault is one shared copy (MOD-05.17); a refused change changes
//! nothing; a name is never empty and never taken twice in one entry.

use crate::edit::edit_entry;
use crate::{Error, NameProblem, tree};
use app_crypto::secret::SecretBytes;
use app_model::entry::cmp_utf16;
use app_model::{Attachment, Entry, Time, Uuid, Vault};
use std::collections::HashSet;
use std::sync::Arc;

/// The size above which adding asks first (MOD-05.5): 5 MiB.
pub const BIG_FILE: u64 = 5 * 1024 * 1024;
/// The base name of a new text attachment (MOD-05.7), in the UI language.
pub const NEW_TEXT_BASE: &str = "New Attachment";

/// The attachment limits of FMT-08.12 that adding checks (MOD-05.16).
/// Tests lower them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `one attachment`: content bytes of one attachment.
    pub one: u64,
    /// `all attachments`: distinct content bytes of the whole vault.
    pub all: u64,
}

impl Limits {
    /// The decided values: 1 GiB each.
    pub const DEFAULT: Self = Self {
        one: 1 << 30,
        all: 1 << 30,
    };
}

// ---------------------------------------------------------------------------
// The set and its names.

/// The attachments as lists show them (MOD-05.1): by name in UTF-16 code
/// unit order, case-sensitive.
#[must_use]
pub fn sorted(e: &Entry) -> Vec<&Attachment> {
    let mut list: Vec<&Attachment> = e.attachments.iter().collect();
    list.sort_by(|a, b| cmp_utf16(&a.name, &b.name));
    list
}

/// A name as lists show it (MOD-05.2): an empty name read from a file shows
/// as `(no name)`; the stored name stays empty.
#[must_use]
pub fn shown_name(name: &str) -> &str {
    if name.is_empty() { "(no name)" } else { name }
}

/// The attachment of `e` named exactly `name`.
#[must_use]
pub fn find<'a>(e: &'a Entry, name: &str) -> Option<&'a Attachment> {
    e.attachments.iter().find(|a| a.name == name)
}

/// Whether adding `name` to the draft asks to overwrite first (MOD-05.5
/// step 2, MOD-05.6 for drops).
#[must_use]
pub fn asks_overwrite(draft: &Entry, name: &str) -> bool {
    find(draft, name).is_some()
}

/// Whether adding content of `size` bytes asks first (MOD-05.5 step 3,
/// MOD-05.6): more than 5,242,880 bytes.
#[must_use]
pub fn asks_big_file(size: u64) -> bool {
    size > BIG_FILE
}

/// The size in the big-file question (MOD-05.5): MiB with one decimal,
/// labelled "MB" (5,242,881 bytes gives `5.0 MB`).
#[must_use]
pub fn size_label(size: u64) -> String {
    const MIB: u64 = 1 << 20;
    let tenths = size.saturating_mul(10).saturating_add(MIB / 2) / MIB;
    format!("{}.{} MB", tenths / 10, tenths % 10)
}

/// The attachment name of a file from disk (MOD-05.5 step 1): the last
/// path component.
#[must_use]
pub fn name_from_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Adding, limits and shared content.

/// Every distinct content of the vault and of `draft`, each once
/// (FMT-13.16).
fn contents<'a>(vault: &'a Vault, draft: Option<&'a Entry>) -> Vec<&'a Arc<SecretBytes>> {
    let mut out: Vec<&Arc<SecretBytes>> = Vec::new();
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let entries = vault
        .root
        .subtree()
        .into_iter()
        .flat_map(|g| g.entries.iter())
        .chain(draft);
    for e in entries {
        for a in e
            .attachments
            .iter()
            .chain(e.history.iter().flat_map(|h| h.attachments.iter()))
        {
            if seen.insert(a.data.expose()) {
                out.push(&a.data);
            }
        }
    }
    out
}

/// Readies content for the draft (MOD-05.16, MOD-05.17): refuses an empty
/// name (MOD-05.2) and content past the one attachment limit or that would
/// push the vault's distinct content past the all attachments limit; equal
/// content already held in the vault or the draft is shared, not copied.
///
/// # Errors
/// `AttachmentName(Empty)`; `TooLarge`.
pub fn prepare(
    vault: &Vault,
    draft: &Entry,
    name: &str,
    data: SecretBytes,
    limits: &Limits,
) -> Result<Attachment, Error> {
    if name.is_empty() {
        return Err(Error::AttachmentName(NameProblem::Empty));
    }
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    if size > limits.one {
        return Err(Error::TooLarge);
    }
    let known = contents(vault, Some(draft));
    if let Some(same) = known.iter().find(|c| c.expose() == data.expose()) {
        return Ok(Attachment {
            name: name.to_owned(),
            data: Arc::clone(same),
        });
    }
    let total = known
        .iter()
        .map(|c| u64::try_from(c.len()).unwrap_or(u64::MAX))
        .fold(size, u64::saturating_add);
    if total > limits.all {
        return Err(Error::TooLarge);
    }
    Ok(Attachment {
        name: name.to_owned(),
        data: Arc::new(data),
    })
}

/// Puts an attachment into the draft (MOD-05.5): an existing name gets the
/// new content (the user answered Overwrite), else it is added.
pub fn put(draft: &mut Entry, a: Attachment) {
    match draft.attachments.iter_mut().find(|x| x.name == a.name) {
        Some(x) => x.data = a.data,
        None => draft.attachments.push(a),
    }
}

/// The name of a new text attachment (MOD-05.7): `New Attachment.txt`, or
/// `New Attachment_1.txt`, `_2` and so on, the first free one.
#[must_use]
pub fn new_text_name(draft: &Entry) -> String {
    let first = format!("{NEW_TEXT_BASE}.txt");
    if find(draft, &first).is_none() {
        return first;
    }
    (1u64..)
        .map(|n| format!("{NEW_TEXT_BASE}_{n}.txt"))
        .find(|n| find(draft, n).is_none())
        .unwrap_or_default()
}

/// Adds an empty text attachment to the draft (MOD-05.7); the screen then
/// starts renaming it. Returns its name.
pub fn new_text(draft: &mut Entry) -> String {
    let name = new_text_name(draft);
    draft.attachments.push(Attachment {
        name: name.clone(),
        data: Arc::new(SecretBytes::new(Vec::new())),
    });
    name
}

/// Renames an attachment in the draft (MOD-05.10): the typed name is
/// trimmed; empty or another attachment's exact name is refused (a change
/// of case only is allowed). The content moves to the new name.
///
/// # Errors
/// `AttachmentName(Empty)` or `AttachmentName(Taken)`; `NoSuchEntry` when
/// `old` is no attachment of the draft.
pub fn rename(draft: &mut Entry, old: &str, typed: &str) -> Result<(), Error> {
    let name = typed.trim();
    if name.is_empty() {
        return Err(Error::AttachmentName(NameProblem::Empty));
    }
    if name == old {
        return Ok(());
    }
    if find(draft, name).is_some() {
        return Err(Error::AttachmentName(NameProblem::Taken));
    }
    let a = draft
        .attachments
        .iter_mut()
        .find(|a| a.name == old)
        .ok_or(Error::NoSuchEntry)?;
    a.name = name.to_owned();
    Ok(())
}

/// Removes the named attachments from the draft (MOD-05.11), after the
/// user confirmed. No deleted-object record; history items keep them.
/// Returns how many were removed.
pub fn remove(draft: &mut Entry, names: &[&str]) -> usize {
    let before = draft.attachments.len();
    draft
        .attachments
        .retain(|a| !names.contains(&a.name.as_str()));
    before.saturating_sub(draft.attachments.len())
}

// ---------------------------------------------------------------------------
// Command line and changes from outside (edit sessions on the vault).

/// Command line import (MOD-05.15): adds `name` to live entry `id` as one
/// edit session; an existing name is refused unless `force`. Equal content
/// under an existing name is no change and makes no history item. Returns
/// whether the entry changed.
///
/// # Errors
/// `NoSuchEntry`; `AttachmentName(Empty)`; `AttachmentName(Taken)` without
/// `force`; `TooLarge`.
pub fn import(
    vault: &mut Vault,
    id: Uuid,
    name: &str,
    data: SecretBytes,
    force: bool,
    limits: &Limits,
    now: Time,
) -> Result<bool, Error> {
    let e = tree::entry(vault, id).ok_or(Error::NoSuchEntry)?;
    if !force && find(e, name).is_some() {
        return Err(Error::AttachmentName(NameProblem::Taken));
    }
    let a = prepare(vault, e, name, data, limits)?;
    edit_entry(vault, id, now, |d| put(d, a))
}

/// Saves content changed in another app (MOD-05.13) opened from the preview
/// panel: one edit session on the entry. Returns whether it changed.
///
/// # Errors
/// As [`import`] with `force`.
pub fn replace(
    vault: &mut Vault,
    id: Uuid,
    name: &str,
    data: SecretBytes,
    limits: &Limits,
    now: Time,
) -> Result<bool, Error> {
    import(vault, id, name, data, true, limits, now)
}

/// Command line remove (MOD-05.15): removes `name` from live entry `id` as
/// one edit session. Returns `false` when the entry has no such attachment.
///
/// # Errors
/// `NoSuchEntry`.
pub fn remove_named(vault: &mut Vault, id: Uuid, name: &str, now: Time) -> Result<bool, Error> {
    edit_entry(vault, id, now, |d| {
        remove(d, &[name]);
    })
}

/// Command line export (MOD-05.15): the content, never changing the vault.
#[must_use]
pub fn export(vault: &Vault, id: Uuid, name: &str) -> Option<Arc<SecretBytes>> {
    tree::entry(vault, id)
        .and_then(|e| find(e, name))
        .map(|a| Arc::clone(&a.data))
}

// ---------------------------------------------------------------------------
// Where attachments are managed (MOD-05.3).

/// The places that show attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The entry editor's Advanced page.
    Editor,
    /// The main screen's preview panel (read-only).
    PreviewPanel,
    /// The read-only view of a history item.
    HistoryItem,
}

/// What the user can do with attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Add from disk.
    Add,
    /// New text attachment.
    NewText,
    /// Rename.
    Rename,
    /// Edit (text only).
    Edit,
    /// Preview.
    Preview,
    /// Open in another app.
    Open,
    /// Save to disk.
    Save,
    /// Remove.
    Remove,
    /// Drop files from disk.
    Drop,
}

/// The actions a place offers (MOD-05.3).
#[must_use]
pub fn actions(place: Place) -> &'static [Action] {
    match place {
        Place::Editor => &[
            Action::Add,
            Action::NewText,
            Action::Rename,
            Action::Edit,
            Action::Preview,
            Action::Open,
            Action::Save,
            Action::Remove,
            Action::Drop,
        ],
        Place::PreviewPanel | Place::HistoryItem => &[Action::Preview, Action::Open, Action::Save],
    }
}

/// What a double-click does (MOD-05.3): Edit in the editor, Preview in
/// read-only places.
#[must_use]
pub fn double_click(place: Place) -> Action {
    match place {
        Place::Editor => Action::Edit,
        Place::PreviewPanel | Place::HistoryItem => Action::Preview,
    }
}

// ---------------------------------------------------------------------------
// Content type, preview and edit (MOD-05.8, MOD-05.9).

/// The media type guessed from the content bytes (the sniffed type):
/// `application/x-zerosize` for empty content, an image type for the
/// common image signatures, `text/plain` for UTF-8 text without control
/// characters other than TAB, LF, FF and CR, else
/// `application/octet-stream`.
// ponytail: signatures and a UTF-8 text test stand in for a full media type
// database; JSON, XML and HTML sniff as text/plain, which gives the same
// Edit and Preview choice. Add types here if a card needs a finer one.
#[must_use]
pub fn sniff(data: &[u8]) -> &'static str {
    const IMAGES: [(&[u8], &str); 7] = [
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF8", "image/gif"),
        (b"\x00\x00\x01\x00", "image/vnd.microsoft.icon"),
        (b"II*\x00", "image/tiff"),
        (b"MM\x00*", "image/tiff"),
        (b"BM", "image/bmp"),
    ];
    if data.is_empty() {
        return "application/x-zerosize";
    }
    if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        return "image/webp";
    }
    if let Some((_, t)) = IMAGES.iter().find(|(sig, _)| data.starts_with(sig)) {
        return t;
    }
    match core::str::from_utf8(data) {
        Ok(s)
            if !s
                .chars()
                .any(|c| c.is_control() && !"\t\n\x0c\r".contains(c)) =>
        {
            "text/plain"
        }
        _ => "application/octet-stream",
    }
}

/// Whether a sniffed type is text that Edit may change (MOD-05.8).
#[must_use]
pub fn is_text(media_type: &str) -> bool {
    media_type.starts_with("text/")
        || [
            "application/json",
            "application/xml",
            "application/soap+xml",
            "application/x-yaml",
            "application/protobuf",
            "application/x-zerosize",
        ]
        .contains(&media_type)
}

/// How text shows in Preview, picked from the name's extension (MOD-05.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextDisplay {
    /// Plain text.
    Plain,
    /// HTML, sanitized: no scripts, no remote loads, no forms, links inert
    /// (L05-3).
    Html,
    /// Markdown, sanitized the same way.
    Markdown,
}

/// What Preview shows (MOD-05.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preview {
    /// The image, with zoom.
    Image,
    /// Text.
    Text(TextDisplay),
    /// A note that the type cannot be shown.
    Unsupported,
}

/// The preview for an attachment (MOD-05.9).
#[must_use]
pub fn preview(a: &Attachment) -> Preview {
    let t = sniff(a.data.expose());
    if t.starts_with("image/") {
        return Preview::Image;
    }
    if !is_text(t) {
        return Preview::Unsupported;
    }
    let ext = extension(&a.name).unwrap_or("");
    Preview::Text(
        if [".html", ".htm"]
            .iter()
            .any(|x| x.eq_ignore_ascii_case(ext))
        {
            TextDisplay::Html
        } else if [".md", ".markdown"]
            .iter()
            .any(|x| x.eq_ignore_ascii_case(ext))
        {
            TextDisplay::Markdown
        } else {
            TextDisplay::Plain
        },
    )
}

/// Whether Edit is offered for an attachment (MOD-05.8): text content only.
#[must_use]
pub fn can_edit(a: &Attachment) -> bool {
    is_text(sniff(a.data.expose()))
}

// ---------------------------------------------------------------------------
// Open and save to disk (MOD-05.12, MOD-05.14).

/// The extension of a name (MOD-05.12): a dot and the text after the last
/// dot, when the name has a dot (`report.final.pdf` gives `.pdf`,
/// `.profile` gives `.profile`, `notes` none).
#[must_use]
pub fn extension(name: &str) -> Option<&str> {
    name.rfind('.').and_then(|i| name.get(i..))
}

/// The file name of an open copy (MOD-05.12, L05-4): 12 random letters and
/// digits from app-crypto random, then the extension without `/`, `\`, `:`
/// or control characters.
///
/// # Errors
/// `RandomSource`.
pub fn temp_name(name: &str) -> Result<String, Error> {
    const CHARS: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(24);
    for _ in 0..12 {
        let i = app_crypto::random::below(62).map_err(|_| Error::RandomSource)?;
        let c = usize::try_from(i).ok().and_then(|i| CHARS.get(i)).copied();
        out.push(char::from(c.unwrap_or(b'A')));
    }
    // The extension cleaned as save to disk cleans names (MOD-05.14): no
    // path separators, colons or control characters.
    for c in extension(name).unwrap_or("").chars() {
        if !"/\\:".contains(c) && !c.is_control() {
            out.push(c);
        }
    }
    Ok(out)
}

/// Whether opening asks first because the type can run code or commands,
/// or acts, when opened (MOD-05.12 step 3). App's one list, used by every
/// Open (F-103, LD-225 (1)): the card's 18; the types whose default app on
/// macOS 26 runs code or acts (a LaunchServices query, E13-S2 AT-E01 and
/// AT-E06: Terminal, the browser, Safari, Java, Finder's server and Screen
/// Sharing links, Mail, Automator, Shortcuts, Script Editor, the disk image
/// mounter); and the system's own quarantine list, the extensions and the
/// types' extensions of `LSRiskCategoryUnsafeExecutable` and
/// `LSRiskCategoryMayContainUnsafeExecutable` in
/// /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System;
/// and each listed type's kin: its other extensions (`UTType` tags) and
/// the other extensions of its document type in its default app's
/// Info.plist `CFBundleDocumentTypes` (AppTests `AttachmentKindsTests`
/// checks both on the Mac it runs on).
/// The extension is read as the open copy gets it ([`temp_name`]: no `/`,
/// `\`, `:` or control characters), in any case, lowercased with Unicode's
/// rules as LaunchServices does (`p\u{212A}g`, KELVIN SIGN, opens Installer).
#[must_use]
pub fn risky(name: &str) -> bool {
    const RISKY: [&str; 102] = [
        // MOD-05.12 rule 3.
        "app",
        "command",
        "terminal",
        "tool",
        "sh",
        "pkg",
        "mpkg",
        "dmg",
        "scpt",
        "applescript",
        "workflow",
        "webloc",
        "inetloc",
        "fileloc",
        "jar",
        "html",
        "htm",
        "svg",
        // LaunchServices' default apps (F-103).
        "term",
        "xhtml",
        "xht",
        "shtml",
        "webarchive",
        "url",
        "xsl",
        "jnlp",
        "class",
        "afploc",
        "ftploc",
        "atloc",
        "vncloc",
        "mailloc",
        "action",
        "wflow",
        "shortcut",
        "scptd",
        "osax",
        "svgz",
        "iso",
        "img",
        "cdr",
        "sparseimage",
        "toast",
        // The system's quarantine list (CoreTypes.bundle `System`).
        "cin",
        "gcx",
        "help",
        "ibplugin",
        "icp",
        "inputplugin",
        "menu",
        "nib",
        "service",
        "x11app",
        "ipg",
        "qtz",
        "ipa",
        // Types that conform to a listed one (UTType conformance).
        "dylib",
        "war",
        // The same kinds (F-103 Verify): a listed type's other extensions
        // (UTType tags) and the other extensions of its document type in
        // the default app (Safari, DiskImageMounter, Finder, System Settings).
        "shtm",
        "xhtm",
        "jhtml",
        "xslt",
        "xbl",
        "xml",
        "asif",
        "udif",
        "dvdr",
        "dmgpart",
        "nslloc",
        "webbookmark",
        "networkconnect",
        "internetconnect",
        // Code that System Settings, Safari and Automator install; a Safari
        // download that resumes and a history item that opens its URL; the
        // other sparse image bundle; the shells' scripts (public.shell-script).
        "prefpane",
        "sysprefex",
        "saver",
        "safariextz",
        "caction",
        "definition",
        "download",
        "webhistory",
        "sparsebundle",
        "backupbundle",
        "bash",
        "zsh",
        "csh",
        "ksh",
        "tcsh",
        // Under the quarantine list's installer and application types
        // (F-103 Verify round 2, LD-246): distribution files and app
        // placeholders.
        "dist",
        "distz",
        "placeholder",
        "remoteplaceholder",
        // The other scripts that conform to public.shell-script, asked for
        // the same reason as the shells' (LD-246).
        "py",
        "pl",
        "pm",
        "rb",
        "rbw",
        "php",
        "ph3",
        "ph4",
        "php3",
        "php4",
        "phtml",
    ];
    let ext: String = extension(name)
        .unwrap_or("")
        .chars()
        .filter(|c| !"/\\:".contains(*c) && !c.is_control())
        .flat_map(|c| c.to_lowercase())
        .collect();
    ext.get(1..).is_some_and(|x| RISKY.contains(&x))
}

/// The file name for save to disk (MOD-05.14, L05-1): the name with every
/// `/`, `\` and `:` removed; `None` (an error for that attachment) when the
/// result is empty, `.` or `..`.
#[must_use]
pub fn disk_name(name: &str) -> Option<String> {
    let out: String = name.chars().filter(|c| !"/\\:".contains(*c)).collect();
    (!matches!(out.as_str(), "" | "." | "..")).then_some(out)
}
