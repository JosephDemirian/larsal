//! Entries: standard and custom fields, each with an own protected flag
//! (MOD-01; file form FMT-11.15).

use crate::attachment::Attachment;
use crate::autotype::AutoType;
use crate::custom_data::CustomData;
use crate::icon::{ENTRY_DEFAULT, Icon};
use crate::times::{Time, Times};
use crate::unknown::UnknownElement;
use crate::uuid::Uuid;
use core::cmp::Ordering;
use larsal_crypto::secret::SecretString;

/// The five standard field names, exact and case-sensitive (MOD-01.1).
pub const STANDARD_FIELDS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

/// One field value and its own protected flag (MOD-01.6).
///
/// Guarantees: every value lives in `SecretString`, protected or not
/// (MOD-01.7 allows it), so turning protection off never copies a value into
/// a plain string, and `Debug` never prints a value.
#[derive(Debug, PartialEq, Eq)]
pub struct Field {
    /// The value, kept exactly (no trimming).
    pub value: SecretString,
    /// The field's own protected flag. Effective protection on save also
    /// counts the vault flags for standard fields (FMT-11.20, MOD-12).
    pub protected: bool,
}

impl Field {
    /// An empty, unprotected field.
    #[must_use]
    pub fn empty() -> Field {
        Field {
            value: SecretString::new(String::new()),
            protected: false,
        }
    }

    /// A copy: the value goes straight into a new secret string (MOD-01.7),
    /// never through a plain one.
    #[must_use]
    pub fn duplicate(&self) -> Field {
        Field {
            value: SecretString::new(self.value.expose().to_owned()),
            protected: self.protected,
        }
    }
}

/// A live entry or a history item (MOD-01 property table).
///
/// Guarantees: the five standard fields always exist; field names are unique
/// and kept sorted by UTF-16 code units, the order FMT-11.22 writes; tags are
/// a sorted set (MOD-07.2).
#[derive(PartialEq, Eq)]
pub struct Entry {
    /// Never the zero id. History items carry their owner's id (FMT-11.32).
    pub uuid: Uuid,
    fields: Vec<(String, Field)>,
    /// Standard icon number or custom icon.
    pub icon: Icon,
    /// Text, empty means none; kept as read (FMT-11.25).
    pub foreground_color: String,
    /// Text, empty means none; kept as read.
    pub background_color: String,
    /// Carried only, never opened or run (MOD-01.15).
    pub override_url: String,
    tags: Vec<String>,
    /// The times block.
    pub times: Times,
    /// True when left out of password reports (FMT-11.29).
    pub exclude_from_reports: bool,
    /// Group the entry sat in before its last move, when set (FMT-11.30).
    pub previous_parent: Option<Uuid>,
    /// Attachments in stored order.
    pub attachments: Vec<Attachment>,
    /// The auto-type block.
    pub auto_type: AutoType,
    /// Plug-in data.
    pub custom_data: CustomData,
    /// Older copies, oldest first; empty in a history item (FMT-11.31).
    pub history: Vec<Entry>,
    /// Kept unknown children of `Entry` (FMT-11.45).
    pub unknown: Vec<UnknownElement>,
}

impl Entry {
    /// A new entry with the defaults of the MOD-01 table: five empty
    /// unprotected standard fields, icon 0, every time `now`.
    #[must_use]
    pub fn new(uuid: Uuid, now: Time) -> Entry {
        let mut fields: Vec<(String, Field)> = STANDARD_FIELDS
            .iter()
            .map(|n| ((*n).to_owned(), Field::empty()))
            .collect();
        fields.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
        Entry {
            uuid,
            fields,
            icon: ENTRY_DEFAULT,
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            tags: Vec::new(),
            times: Times::all(now),
            exclude_from_reports: false,
            previous_parent: None,
            attachments: Vec::new(),
            auto_type: AutoType::default(),
            custom_data: CustomData::default(),
            history: Vec::new(),
            unknown: Vec::new(),
        }
    }

    /// The field named `name`, compared exactly.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.position(name)
            .ok()
            .and_then(|i| self.fields.get(i))
            .map(|(_, f)| f)
    }

    /// The value of the field named `name`, or `""` when there is none.
    #[must_use]
    pub fn value(&self, name: &str) -> &str {
        self.field(name).map_or("", |f| f.value.expose())
    }

    /// Every field, sorted by UTF-16 code units.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &Field)> {
        self.fields.iter().map(|(n, f)| (n.as_str(), f))
    }

    /// Sets the field `name`, adding it in sorted place or replacing the old
    /// value and flag; returns the old field.
    pub fn set_field(&mut self, name: String, field: Field) -> Option<Field> {
        match self.position(&name) {
            Ok(i) => self
                .fields
                .get_mut(i)
                .map(|slot| core::mem::replace(&mut slot.1, field)),
            Err(i) => {
                self.fields.insert(i, (name, field));
                None
            }
        }
    }

    /// Replaces every field at once: sorted once (UTF-16 code units), a
    /// later duplicate name wins, missing standard fields are added empty.
    /// For readers that collect many fields: no per-field insert cost.
    pub fn replace_fields(&mut self, mut fields: Vec<(String, Field)>) {
        for n in STANDARD_FIELDS {
            if !fields.iter().any(|(k, _)| k == n) {
                fields.push((n.to_owned(), Field::empty()));
            }
        }
        // Stable sort keeps read order among equal names; keep the last.
        fields.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
        let mut out: Vec<(String, Field)> = Vec::with_capacity(fields.len());
        for f in fields {
            match out.last_mut() {
                Some(last) if last.0 == f.0 => *last = f,
                _ => out.push(f),
            }
        }
        self.fields = out;
    }

    /// Removes a custom field. Standard fields cannot be removed: `None`.
    pub fn remove_field(&mut self, name: &str) -> Option<Field> {
        if STANDARD_FIELDS.contains(&name) {
            return None;
        }
        let i = self.position(name).ok()?;
        Some(self.fields.remove(i).1)
    }

    /// The tags, sorted by UTF-16 code units, no duplicates.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Sets the tags; they are sorted and duplicates dropped (MOD-07.2).
    pub fn set_tags(&mut self, mut tags: Vec<String>) {
        tags.sort_by(|a, b| cmp_utf16(a, b));
        tags.dedup();
        self.tags = tags;
    }

    /// A copy of every stored value (MOD-03.1): fields with their flags,
    /// attachments (equal content stays one shared copy), custom data, icon,
    /// colors, override URL, tags, times, flags, auto-type, previous parent
    /// and kept unknown elements. The history is copied only when
    /// `with_history` is set; a history item never has one (FMT-11.31).
    #[must_use]
    pub fn duplicate(&self, with_history: bool) -> Entry {
        Entry {
            uuid: self.uuid,
            fields: self
                .fields
                .iter()
                .map(|(n, f)| (n.clone(), f.duplicate()))
                .collect(),
            icon: self.icon,
            foreground_color: self.foreground_color.clone(),
            background_color: self.background_color.clone(),
            override_url: self.override_url.clone(),
            tags: self.tags.clone(),
            times: self.times.clone(),
            exclude_from_reports: self.exclude_from_reports,
            previous_parent: self.previous_parent,
            attachments: self
                .attachments
                .iter()
                .map(|a| Attachment {
                    name: a.name.clone(),
                    data: std::sync::Arc::clone(&a.data),
                })
                .collect(),
            auto_type: self.auto_type.clone(),
            custom_data: self.custom_data.clone(),
            history: if with_history {
                self.history.iter().map(|h| h.duplicate(false)).collect()
            } else {
                Vec::new()
            },
            unknown: self.unknown.clone(),
        }
    }

    fn position(&self, name: &str) -> Result<usize, usize> {
        self.fields.binary_search_by(|(n, _)| cmp_utf16(n, name))
    }
}

/// Compares two texts as sequences of UTF-16 code units: binary,
/// case-sensitive, not code point order (FMT-11.22).
#[must_use]
pub fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Turns tag text into the tag set (FMT-11.26): split at `,`, `;` and TAB,
/// trim Unicode white space, drop empty pieces and duplicates, sort by UTF-16
/// code units.
#[must_use]
pub fn parse_tags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = text
        .split([',', ';', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();
    tags.sort_by(|a, b| cmp_utf16(a, b));
    tags.dedup();
    tags
}

/// Ids, counts and flags only, never user text (LD-88): no field names,
/// tags, URLs, sequences or custom data.
impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("uuid", &self.uuid)
            .field("fields", &self.fields.len())
            .field("attachments", &self.attachments.len())
            .field("history", &self.history.len())
            .field("tags", &self.tags.len())
            .field("custom_data", &self.custom_data.items.len())
            .field("associations", &self.auto_type.associations.len())
            .field("icon", &self.icon)
            .field("expires", &self.times.expires)
            .field("exclude_from_reports", &self.exclude_from_reports)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    // MOD-01.1 standard set.
    #[test]
    fn mod_01_1_standard_set() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        let names: Vec<&str> = e.fields().map(|(n, _)| n).collect();
        assert_eq!(names, ["Notes", "Password", "Title", "URL", "UserName"]);
        assert!(e.fields().all(|(_, f)| f.value.is_empty() && !f.protected));
        for n in STANDARD_FIELDS {
            assert!(e.remove_field(n).is_none());
            assert!(e.field(n).is_some());
        }
    }

    // MOD-01.2 case-distinct names.
    #[test]
    fn mod_01_2_case_distinct_names() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        e.set_field(
            "Title".into(),
            Field {
                value: secret("Bank"),
                protected: false,
            },
        );
        for (n, v) in [("title", "x"), ("Username", "y"), (" Title", "z")] {
            e.set_field(
                n.into(),
                Field {
                    value: secret(v),
                    protected: false,
                },
            );
        }
        assert_eq!(e.fields().count(), 8);
        assert_eq!(e.value("Title"), "Bank");
        assert_eq!(e.value(" Title"), "z");
    }

    // MOD-01.4: empty and spaced names are kept; the value of a missing field is "".
    #[test]
    fn mod_01_4_names_kept() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        e.set_field("".into(), Field::empty());
        e.set_field("x ".into(), Field::empty());
        assert!(e.field("").is_some());
        assert!(e.field("x ").is_some());
        assert!(e.field("x").is_none());
        assert_eq!(e.value("missing"), "");
        assert!(e.remove_field("x ").is_some());
    }

    // FMT-11.22 order (test 11-25).
    #[test]
    fn fmt_11_25_utf16_order() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        for n in [
            "zlower",
            "_under",
            "KP2A_URL",
            "Apple",
            " sp",
            "1",
            "Z",
            "a",
            "é",
            "\u{1F600}",
            "\u{FFFD}",
            "\u{E000}",
        ] {
            e.set_field(n.into(), Field::empty());
        }
        let names: Vec<&str> = e.fields().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                " sp",
                "1",
                "Apple",
                "KP2A_URL",
                "Notes",
                "Password",
                "Title",
                "URL",
                "UserName",
                "Z",
                "_under",
                "a",
                "zlower",
                "é",
                "\u{1F600}",
                "\u{E000}",
                "\u{FFFD}"
            ]
        );
    }

    // FMT-11.26 (tests 11-32, 11-59).
    #[test]
    fn fmt_11_32_tag_normalization() {
        assert_eq!(
            parse_tags("zeta; alpha,beta\talpha ,Alpha"),
            ["Alpha", "alpha", "beta", "zeta"]
        );
        assert_eq!(parse_tags("a, ,b;;c"), ["a", "b", "c"]);
        assert_eq!(parse_tags("\u{A0}x\u{A0},\u{3000}y"), ["x", "y"]);
        assert!(parse_tags("").is_empty());
    }

    #[test]
    fn replace_fields_sorts_adds_standard_and_keeps_last() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        let f = |v: &str| Field {
            value: secret(v),
            protected: false,
        };
        e.replace_fields(vec![
            ("z".into(), f("1")),
            ("Title".into(), f("T")),
            ("a".into(), f("first")),
            ("a".into(), f("last")),
        ]);
        let names: Vec<&str> = e.fields().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            ["Notes", "Password", "Title", "URL", "UserName", "a", "z"]
        );
        assert_eq!((e.value("a"), e.value("Title")), ("last", "T"));
    }

    #[test]
    fn set_tags_sorts_and_dedups() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        e.set_tags(vec!["b".into(), "a".into(), "b".into()]);
        assert_eq!(e.tags(), ["a", "b"]);
    }

    #[test]
    fn debug_hides_values() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        e.set_field(
            "Password".into(),
            Field {
                value: secret("DemoPass-7"),
                protected: true,
            },
        );
        assert!(!format!("{e:?}").contains("DemoPass-7"));
    }
}
