//! The entry's SSH settings attachment (INT-06.1 to INT-06.3).

use crate::Error;
use app_model::Entry;
use quick_xml::events::Event;

/// The settings attachment's name, as the card gives it: 17 ASCII bytes,
/// kept as bytes (AGENTS rule 1, FMT-14).
pub const SETTINGS_NAME: [u8; 17] = [
    0x4B, 0x65, 0x65, 0x41, 0x67, 0x65, 0x6E, 0x74, 0x2E, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67,
    0x73,
];

/// Largest settings attachment App reads (INT-06.2): 64 KiB.
pub const MAX_SETTINGS: usize = 65_536;

/// Where the key lives (`Location/SelectedType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    /// Another attachment of the same entry (`attachment`).
    Attachment,
    /// A file on this Mac (any other text; the default `file`).
    #[default]
    File,
}

/// One entry's SSH settings (INT-06.1). `Default` is the card's defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `AllowUseOfSshKey`: the editor's main switch.
    pub allow: bool,
    /// `AddAtDatabaseOpen`: add the key when the vault unlocks.
    pub add_at_open: bool,
    /// `RemoveAtDatabaseClose`: remove the key when the vault locks.
    pub remove_at_close: bool,
    /// `UseConfirmConstraintWhenAdding`: ask before each use (App's own
    /// agent, D-INT06-1 (b)).
    pub confirm: bool,
    /// `UseLifetimeConstraintWhenAdding`: the switch of "Remove the key after".
    pub use_lifetime: bool,
    /// `LifetimeConstraintDuration`, seconds, as read (may be below 1).
    pub lifetime: i64,
    /// `Location/SelectedType`.
    pub source: Source,
    /// `Location/AttachmentName`.
    pub attachment_name: String,
    /// `Location/SaveAttachmentToTempFile`: kept as read, never used.
    pub save_to_temp: bool,
    /// `Location/FileName`.
    pub file_name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow: false,
            add_at_open: false,
            remove_at_close: false,
            confirm: false,
            use_lifetime: false,
            lifetime: 600,
            source: Source::File,
            attachment_name: String::new(),
            save_to_temp: false,
            file_name: String::new(),
        }
    }
}

impl Settings {
    /// The settings of `entry`: `Ok(None)` without a settings attachment;
    /// [`Error::SettingsUnreadable`] (MI06-24) when it cannot be read.
    pub fn of(entry: &Entry) -> Result<Option<Self>, Error> {
        entry
            .attachments
            .iter()
            .find(|a| a.name.as_bytes() == SETTINGS_NAME)
            .map(|a| Self::read(a.data.expose()).ok_or(Error::SettingsUnreadable))
            .transpose()
    }

    /// Reads a settings document (INT-06.2). `None` ("cannot be read") for
    /// a document over [`MAX_SETTINGS`], one that is not well-formed UTF-8
    /// XML, one with a DTD, or one whose root is not `EntrySettings`. No
    /// entity is expanded besides the five XML ones and character
    /// references. Booleans are true when their text starts with `t` or `T`;
    /// the lifetime is decimal digits with an optional sign, else 0; unknown
    /// elements are skipped; a later duplicate wins.
    #[must_use]
    pub fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_SETTINGS {
            return None;
        }
        let text = std::str::from_utf8(bytes).ok()?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut xml = quick_xml::Reader::from_str(text);
        let cfg = xml.config_mut();
        cfg.check_end_names = true;
        cfg.check_comments = true;
        cfg.trim_text(false);
        let mut out = Self::default();
        // Element names from the root down; `done` once the root closed.
        let mut path: Vec<String> = Vec::new();
        let mut done = false;
        let mut value = String::new();
        loop {
            let event = xml.read_event().ok()?;
            match event {
                Event::Start(_) | Event::Empty(_) if done => return None,
                Event::Start(e) => {
                    let name = e.name().into_inner().to_owned();
                    if path.is_empty() && name != "EntrySettings" {
                        return None;
                    }
                    path.push(name);
                    value.clear();
                }
                Event::Empty(e) => {
                    let name = e.name().into_inner();
                    if path.is_empty() {
                        // An empty root is a valid document with defaults.
                        if name != "EntrySettings" {
                            return None;
                        }
                        done = true;
                        continue;
                    }
                    out.set(&path, name, "");
                }
                Event::End(_) => {
                    let name = path.pop()?;
                    out.set(&path, &name, &value);
                    value.clear();
                    done = path.is_empty();
                }
                Event::Text(t) => {
                    let t = t.xml10_content();
                    if path.is_empty() && !t.trim().is_empty() {
                        return None;
                    }
                    value.push_str(&t);
                }
                Event::CData(c) => {
                    if path.is_empty() {
                        return None;
                    }
                    value.push_str(&c.xml10_content());
                }
                Event::GeneralRef(r) => {
                    if path.is_empty() {
                        return None;
                    }
                    value.push(general_ref(&r)?);
                }
                Event::DocType(_) => return None,
                Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
                Event::Eof => return done.then_some(out),
            }
        }
    }

    /// Stores the text of element `name` whose parents are `parents`.
    fn set(&mut self, parents: &[String], name: &str, text: &str) {
        let flag = || text.starts_with(['t', 'T']);
        match (parents.len(), parents.last().map(String::as_str), name) {
            (1, _, "AllowUseOfSshKey") => self.allow = flag(),
            (1, _, "AddAtDatabaseOpen") => self.add_at_open = flag(),
            (1, _, "RemoveAtDatabaseClose") => self.remove_at_close = flag(),
            (1, _, "UseConfirmConstraintWhenAdding") => self.confirm = flag(),
            (1, _, "UseLifetimeConstraintWhenAdding") => self.use_lifetime = flag(),
            (1, _, "LifetimeConstraintDuration") => self.lifetime = integer(text),
            (2, Some("Location"), "SelectedType") => {
                self.source = if text == "attachment" {
                    Source::Attachment
                } else {
                    Source::File
                };
            }
            (2, Some("Location"), "AttachmentName") => self.attachment_name = text.to_owned(),
            (2, Some("Location"), "SaveAttachmentToTempFile") => self.save_to_temp = flag(),
            (2, Some("Location"), "FileName") => self.file_name = text.to_owned(),
            _ => {}
        }
    }

    /// The settings document App writes (INT-06.3): `None` when every value
    /// is its default, which means "remove the attachment". The layout is
    /// fixed: declaration, root with the two namespace declarations, the
    /// six values, `Location` with its four, two spaces per level, LF line
    /// ends, a final LF; text escaped; empty names as empty elements.
    #[must_use]
    pub fn write(&self) -> Option<Vec<u8>> {
        if *self == Self::default() {
            return None;
        }
        let b = |v: bool| if v { "true" } else { "false" };
        let el = |indent: &str, name: &str, text: &str| {
            if text.is_empty() {
                format!("{indent}<{name}/>\n")
            } else {
                format!("{indent}<{name}>{}</{name}>\n", escape(text))
            }
        };
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n");
        for (name, text) in [
            ("AllowUseOfSshKey", b(self.allow)),
            ("AddAtDatabaseOpen", b(self.add_at_open)),
            ("RemoveAtDatabaseClose", b(self.remove_at_close)),
            ("UseConfirmConstraintWhenAdding", b(self.confirm)),
            ("UseLifetimeConstraintWhenAdding", b(self.use_lifetime)),
        ] {
            out.push_str(&el("  ", name, text));
        }
        out.push_str(&el(
            "  ",
            "LifetimeConstraintDuration",
            &self.lifetime.to_string(),
        ));
        out.push_str("  <Location>\n");
        let kind = match self.source {
            Source::Attachment => "attachment",
            Source::File => "file",
        };
        out.push_str(&el("    ", "SelectedType", kind));
        out.push_str(&el("    ", "AttachmentName", &self.attachment_name));
        out.push_str(&el(
            "    ",
            "SaveAttachmentToTempFile",
            b(self.save_to_temp),
        ));
        out.push_str(&el("    ", "FileName", &self.file_name));
        out.push_str("  </Location>\n</EntrySettings>\n");
        Some(out.into_bytes())
    }

    /// The source is set (INT-06.4): a non-empty name for the selected one.
    #[must_use]
    pub fn source_set(&self) -> bool {
        match self.source {
            Source::Attachment => !self.attachment_name.is_empty(),
            Source::File => !self.file_name.is_empty(),
        }
    }
}

/// Decimal digits with an optional sign; anything else (or a value that
/// does not fit) is 0 (INT-06.2).
fn integer(text: &str) -> i64 {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return 0;
    }
    text.parse().unwrap_or(0)
}

/// The five XML entities and character references; any other is refused.
fn general_ref(r: &quick_xml::events::BytesRef<'_>) -> Option<char> {
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

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S1 of the card's demo vault.
    fn s1() -> Settings {
        Settings {
            allow: true,
            add_at_open: true,
            remove_at_close: true,
            source: Source::Attachment,
            attachment_name: "id_ed25519".into(),
            ..Settings::default()
        }
    }

    #[test]
    fn t01_s1_as_app_writes_it_reads_back() {
        let bytes = s1().write().unwrap();
        let read = Settings::read(&bytes).unwrap();
        assert_eq!(read, s1());
        assert!(read.allow && read.add_at_open && read.remove_at_close);
        assert!(!read.confirm && !read.use_lifetime && !read.save_to_temp);
        assert_eq!(read.lifetime, 600);
        assert_eq!(read.file_name, "");
    }

    fn doc(body: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><EntrySettings>{body}</EntrySettings>").into_bytes()
    }

    #[test]
    fn t02_booleans_and_lifetime_text() {
        for (text, want) in [("True", true), ("tRUE", true), ("yes", false), ("", false)] {
            let s = Settings::read(&doc(&format!(
                "<AllowUseOfSshKey>{text}</AllowUseOfSshKey>"
            )))
            .unwrap();
            assert_eq!(s.allow, want, "{text:?}");
        }
        for (text, want) in [("abc", 0), ("-5", -5), ("90", 90), ("+7", 7), (" 9", 0)] {
            let s = Settings::read(&doc(&format!(
                "<LifetimeConstraintDuration>{text}</LifetimeConstraintDuration>"
            )))
            .unwrap();
            assert_eq!(s.lifetime, want, "{text:?}");
        }
        assert_eq!(integer("99999999999999999999"), 0);
    }

    #[test]
    fn t03_exact_type_unknown_skipped_later_duplicate_wins() {
        let s = Settings::read(&doc("<Foo><AllowUseOfSshKey>true</AllowUseOfSshKey></Foo>\
             <AddAtDatabaseOpen>false</AddAtDatabaseOpen>\
             <AddAtDatabaseOpen>true</AddAtDatabaseOpen>\
             <Location><SelectedType>Attachment</SelectedType><Bar/>\
             <AttachmentName>a &amp; b&#33;</AttachmentName></Location>"))
        .unwrap();
        assert_eq!(s.source, Source::File, "exact match only");
        assert!(!s.allow, "Foo and what is inside it are skipped");
        assert!(s.add_at_open);
        assert_eq!(s.attachment_name, "a & b!");
    }

    #[test]
    fn t04_unreadable_settings() {
        let dtd = b"<?xml version=\"1.0\"?><!DOCTYPE EntrySettings [<!ENTITY x \"y\">]><EntrySettings><FileName>&x;</FileName></EntrySettings>";
        assert_eq!(Settings::read(dtd), None);
        let mut big = doc("<FileName>x</FileName>");
        big.resize(70 * 1024, b' ');
        assert_eq!(Settings::read(&big), None);
        assert_eq!(Settings::read(b"<Settings/>"), None);
        assert_eq!(
            Settings::read(b"<EntrySettings><a></b></EntrySettings>"),
            None
        );
        assert_eq!(
            Settings::read(b"<EntrySettings>&nope;</EntrySettings>"),
            None
        );
        assert_eq!(Settings::read(b"<EntrySettings/><EntrySettings/>"), None);
        assert_eq!(Settings::read(b"<EntrySettings>"), None);
        assert_eq!(Settings::read(b"\xff"), None);
        assert_eq!(Settings::read(b""), None);
        assert_eq!(
            Settings::read(b"<EntrySettings/>"),
            Some(Settings::default())
        );
        // Deep nesting stays bounded by the size limit; no recursion.
        let deep = format!(
            "<EntrySettings>{}{}</EntrySettings>",
            "<a>".repeat(9000),
            "</a>".repeat(9000)
        );
        assert_eq!(Settings::read(deep.as_bytes()), Some(Settings::default()));
    }

    #[test]
    fn t05_layout_app_writes() {
        let s = Settings {
            allow: true,
            source: Source::Attachment,
            attachment_name: "id_ecdsa".into(),
            ..Settings::default()
        };
        let want = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>false</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>false</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>id_ecdsa</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
    <FileName/>
  </Location>
</EntrySettings>
";
        assert_eq!(String::from_utf8(s.write().unwrap()).unwrap(), want);
        let odd = Settings {
            file_name: "a<b>&c".into(),
            ..Settings::default()
        };
        let back = Settings::read(&odd.write().unwrap()).unwrap();
        assert_eq!(back, odd);
    }

    #[test]
    fn t06_defaults_mean_remove() {
        assert_eq!(Settings::default().write(), None);
    }

    proptest::proptest! {
        /// Hostile settings documents never panic.
        #[test]
        fn hostile_settings_never_panic(body in "[<>/a-zA-Z&;#0-9 !\\[\\]-]{0,300}") {
            let _ = Settings::read(&doc(&body));
            let _ = Settings::read(body.as_bytes());
        }
    }
}
