//! CSV import (FEA-08 section B): decoding, records and fields, column
//! names, the automatic mapping, and rows to entries.
//!
//! Guarantees: the text is decoded on the fly into one wiping buffer that
//! holds every field (no second copy of the file); shorter records are
//! padded only when read ([`Parsed::cell`]), so a hostile file cannot make
//! the padding allocate; the FEA-08.67 limits (64 MiB per field, 10,000
//! columns, 1,000,000 records) are checked as the parse goes. Parse
//! problems are recorded with their record number and never stop the
//! parse (FEA-08.16).

use super::{
    Builder, Context, ImportError, Imported, Limit, MAX_COLUMNS, MAX_RECORDS, MAX_TEXT, R,
};
use crate::icons::STANDARD_COUNT;
use crate::text::Bytes;
use app_model::Icon;
use app_model::entry::parse_tags;
use core::iter::Peekable;
use std::borrow::Cow;

/// The text encodings of the CSV screen (FEA-08.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-8, the default.
    Utf8,
    /// The real Windows-1252 table.
    Windows1252,
    /// UTF-16; little-endian without a byte order mark, as in the
    /// reference (LD-148).
    Utf16,
    /// UTF-16 little-endian.
    Utf16Le,
}

/// The CSV screen's parse controls (FEA-08.13). `Default` gives the
/// screen's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Encoding.
    pub encoding: Encoding,
    /// Text qualifier, one of [`QUALIFIERS`].
    pub qualifier: char,
    /// Field separator, one of [`SEPARATORS`].
    pub separator: char,
    /// Comment character, one of [`COMMENTS`].
    pub comment: char,
    /// Backslash escapes.
    pub backslash: bool,
    /// `CSV-FIRST-ROW-NAMES`.
    pub first_row_names: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            encoding: Encoding::Utf8,
            qualifier: '"',
            separator: ',',
            comment: '#',
            backslash: false,
            first_row_names: true,
        }
    }
}

/// Text qualifier choices, in screen order.
pub const QUALIFIERS: [char; 5] = ['"', '\'', ':', '.', '|'];
/// Field separator choices, in screen order.
pub const SEPARATORS: [char; 6] = [',', ';', '-', ':', '.', '\t'];
/// Comment character choices, in screen order.
pub const COMMENTS: [char; 4] = ['#', ';', ':', '@'];

/// A recorded parse problem (FEA-08.16), with its 1-based record number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// `MSG-CSV-MALFORMED`: a character other than the separator or a line
    /// end right after a closing qualifier.
    Malformed {
        /// The record.
        record: usize,
    },
    /// `MSG-CSV-UNCLOSED`: the input ends inside a quoted field.
    Unclosed {
        /// The record.
        record: usize,
    },
}

/// A parsed file: records, column names and problems.
pub struct Parsed {
    /// Every field's bytes, joined; whole characters only.
    text: Bytes,
    /// End offset in `text` of each field. Memory bound: every field but
    /// the last of a record ends at a separator, so there are at most as
    /// many fields as decoded characters plus records: 4 bytes per input
    /// character at worst, 1 GiB at the 256 MiB file limit, reached only by
    /// a file of separators (and the dropped empty records give theirs
    /// back).
    ends: Vec<u32>,
    /// End index in `ends` of each record.
    records: Vec<u32>,
    /// The column count: the longest record's length (FEA-08.18).
    pub columns: usize,
    /// The recorded problems, in order.
    pub problems: Vec<Problem>,
    /// The file size in bytes, for the info line.
    pub size: usize,
    /// `CSV-FIRST-ROW-NAMES` as parsed.
    first_row_names: bool,
}

impl core::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parsed")
            .field("rows", &self.rows())
            .field("columns", &self.columns)
            .field("problems", &self.problems)
            .finish_non_exhaustive()
    }
}

impl Parsed {
    /// The number of parsed records (the info line's rows).
    #[must_use]
    pub fn rows(&self) -> usize {
        self.records.len()
    }

    /// Field `col` of record `row`; `""` past the record's end (padding,
    /// FEA-08.18) or past the last record.
    #[must_use]
    pub fn cell(&self, row: usize, col: usize) -> &str {
        let at = |i: usize| -> Option<usize> {
            match i.checked_sub(1) {
                None => Some(0),
                Some(j) => self.records.get(j).and_then(|&v| usize::try_from(v).ok()),
            }
        };
        let (Some(first), Some(end)) = (at(row), at(row.saturating_add(1))) else {
            return "";
        };
        let Some(i) = first.checked_add(col).filter(|&i| i < end) else {
            return "";
        };
        let start = match i.checked_sub(1) {
            None => 0,
            Some(j) => self
                .ends
                .get(j)
                .and_then(|&v| usize::try_from(v).ok())
                .unwrap_or(0),
        };
        let stop = self
            .ends
            .get(i)
            .and_then(|&v| usize::try_from(v).ok())
            .unwrap_or(start);
        self.text
            .as_slice()
            .get(start..stop)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("")
    }

    /// The name of column `i` (FEA-08.19): row 1's field i with
    /// `CSV-FIRST-ROW-NAMES` on, else or when that field is empty
    /// "Column i". Row 1's text stays in the parse's wiping buffer; this
    /// borrows it, and only [`Parsed::screen_names`] copies names out.
    fn name(&self, i: usize) -> Cow<'_, str> {
        match self.cell(0, i) {
            n if self.first_row_names && !n.is_empty() => Cow::Borrowed(n),
            _ => Cow::Owned(format!("Column {i}")),
        }
    }

    /// The column names for the screen (FEA-08.19, LD-144): a column mapped
    /// to Password or TOTP (the targets stored protected) shows as the
    /// FEA-08.4 mask, so in a file without a header row row 1's password
    /// leaves the screen once its column is mapped (until then it shows,
    /// LD-144). Ask again after every mapping change.
    #[must_use]
    pub fn screen_names(&self, map: &Mapping) -> Vec<String> {
        let secret_cols: Vec<usize> = [Target::Password, Target::Totp]
            .iter()
            .filter_map(|t| TARGETS.iter().position(|x| x == t))
            .filter_map(|i| map.get(i).copied().flatten())
            .collect();
        (0..self.columns)
            .map(|i| {
                if secret_cols.contains(&i) {
                    super::PASSWORD_MASK.to_owned()
                } else {
                    self.name(i).into_owned()
                }
            })
            .collect()
    }

    /// The `CSV-SKIP-ROWS` range (FEA-08.13): minimum 1 with
    /// `CSV-FIRST-ROW-NAMES` on, else 0; maximum max(minimum, rows - 1).
    /// The minimum is the value after every parse.
    #[must_use]
    pub fn skip_range(&self) -> (usize, usize) {
        let min = usize::from(self.first_row_names);
        (min, min.max(self.rows().saturating_sub(1)))
    }
}

/// Decodes and parses a CSV file (FEA-08.14 to FEA-08.19).
///
/// # Errors
/// [`ImportError::TooLarge`] past a FEA-08.67 limit. Malformed text is not
/// an error: see [`Parsed::problems`].
pub fn parse(bytes: &[u8], o: &Options) -> Result<Parsed, ImportError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > super::MAX_FILE {
        return Err(ImportError::TooLarge(Limit::File));
    }
    let mut p = Parser {
        o,
        out: Bytes::new(),
        ends: Vec::new(),
        records: Vec::new(),
        columns: 0,
        problems: Vec::new(),
        record: 0,
    };
    let mut it = Lines(decode(bytes, o.encoding).peekable()).peekable();
    p.run(&mut it)?;
    let parsed = Parsed {
        text: p.out,
        ends: p.ends,
        records: p.records,
        columns: p.columns,
        problems: p.problems,
        size: bytes.len(),
        first_row_names: o.first_row_names,
    };
    Ok(parsed)
}

/// FEA-08.14: a leading byte order mark picks the encoding and is
/// removed; invalid sequences become U+FFFD.
fn decode(bytes: &[u8], chosen: Encoding) -> Box<dyn Iterator<Item = char> + '_> {
    // `le`: UTF-16 byte order; only the `FE FF` mark makes it big-endian.
    let (enc, le, rest) = if let Some(r) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        (Encoding::Utf8, true, r)
    } else if let Some(r) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        (Encoding::Utf16Le, true, r)
    } else if let Some(r) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        (Encoding::Utf16, false, r)
    } else {
        (chosen, true, bytes)
    };
    match enc {
        Encoding::Utf8 => Box::new(rest.utf8_chunks().flat_map(|c| {
            c.valid()
                .chars()
                .chain((!c.invalid().is_empty()).then_some('\u{FFFD}'))
        })),
        Encoding::Windows1252 => Box::new(rest.iter().map(|&b| cp1252(b))),
        Encoding::Utf16 | Encoding::Utf16Le => {
            let (pairs, rem) = rest.as_chunks::<2>();
            let odd = !rem.is_empty();
            let units = pairs.iter().map(move |&p| {
                if le {
                    u16::from_le_bytes(p)
                } else {
                    u16::from_be_bytes(p)
                }
            });
            Box::new(
                char::decode_utf16(units)
                    .map(|r| r.unwrap_or('\u{FFFD}'))
                    .chain(odd.then_some('\u{FFFD}')),
            )
        }
    }
}

/// Windows-1252 (the WHATWG table: the five unassigned bytes map to the C1
/// controls of the same number, as Windows does).
fn cp1252(b: u8) -> char {
    match b {
        0x80..=0x9F => super::CP1252_HIGH
            .get(usize::from(b.wrapping_sub(0x80)))
            .and_then(|&u| char::from_u32(u32::from(u)))
            .unwrap_or('\u{FFFD}'),
        _ => char::from(b),
    }
}

/// FEA-08.14: CR LF and lone CR become LF.
struct Lines<I: Iterator<Item = char>>(Peekable<I>);

impl<I: Iterator<Item = char>> Iterator for Lines<I> {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        match self.0.next()? {
            '\r' => {
                self.0.next_if_eq(&'\n');
                Some('\n')
            }
            c => Some(c),
        }
    }
}

struct Parser<'o> {
    o: &'o Options,
    out: Bytes,
    ends: Vec<u32>,
    records: Vec<u32>,
    columns: usize,
    problems: Vec<Problem>,
    record: usize,
}

/// How a field ended.
enum End {
    /// A separator: the record goes on.
    Field,
    /// A line end or the end of input: the record is done.
    Record,
}

impl Parser<'_> {
    fn run(&mut self, it: &mut Peekable<impl Iterator<Item = char>>) -> R<()> {
        while it.peek().is_some() {
            // FEA-08.15: a comment line, after any spaces and tabs.
            let mut lead = String::new();
            while let Some(&c) = it.peek().filter(|c| matches!(c, ' ' | '\t')) {
                lead.push(c);
                it.next();
            }
            if it.peek() == Some(&self.o.comment) {
                for c in it.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                continue;
            }
            self.record = self.record.saturating_add(1);
            self.one_record(it, lead)?;
        }
        Ok(())
    }

    fn one_record(&mut self, it: &mut Peekable<impl Iterator<Item = char>>, lead: String) -> R<()> {
        let (text_start, field_start) = (self.out.len(), self.ends.len());
        // The spaces and tabs the comment check read go through the field
        // logic first: a TAB separator among them ends a field (FEA-08.15).
        let mut lead = lead.chars();
        loop {
            let start = self.out.len();
            let mut in_lead = false;
            let mut ended = false;
            for c in lead.by_ref() {
                if c == self.o.separator {
                    ended = true;
                    break;
                }
                self.push(c, start)?;
                in_lead = true;
            }
            let end = if ended {
                End::Field
            } else if in_lead {
                // A field that starts with a space is plain.
                self.plain(it, start)?
            } else if it.peek() == Some(&self.o.qualifier) {
                it.next();
                self.quoted(it, start)?
            } else {
                self.plain(it, start)?
            };
            let end_at =
                u32::try_from(self.out.len()).map_err(|_| ImportError::TooLarge(Limit::File))?;
            self.ends.push(end_at);
            if self.ends.len().saturating_sub(field_start) > MAX_COLUMNS {
                return Err(ImportError::TooLarge(Limit::Columns));
            }
            if matches!(end, End::Record) {
                break;
            }
        }
        // FEA-08.18: a record whose fields are all empty (a lone LF counts
        // as empty) is dropped.
        let fields = self.ends.get(field_start..).unwrap_or(&[]);
        let mut prev = u32::try_from(text_start).unwrap_or(0);
        let mut empty = true;
        for &e in fields {
            let len = e.saturating_sub(prev);
            let field = self
                .out
                .as_slice()
                .get(usize::try_from(prev).unwrap_or(0)..usize::try_from(e).unwrap_or(0))
                .unwrap_or(&[]);
            empty &= len == 0 || field == b"\n";
            prev = e;
        }
        if empty {
            self.ends.truncate(field_start);
            self.out.truncate(text_start);
            return Ok(());
        }
        self.columns = self
            .columns
            .max(self.ends.len().saturating_sub(field_start));
        let end =
            u32::try_from(self.ends.len()).map_err(|_| ImportError::TooLarge(Limit::Records))?;
        self.records.push(end);
        if self.records.len() > MAX_RECORDS {
            return Err(ImportError::TooLarge(Limit::Records));
        }
        Ok(())
    }

    fn push(&mut self, c: char, start: usize) -> R<()> {
        self.out.extend(c.encode_utf8(&mut [0; 4]).as_bytes());
        self.check(start)
    }

    fn check(&self, start: usize) -> R<()> {
        if self.out.len().saturating_sub(start) > MAX_TEXT {
            return Err(ImportError::TooLarge(Limit::Text));
        }
        Ok(())
    }

    /// FEA-08.15: everything up to the next separator or LF, as written.
    fn plain(&mut self, it: &mut Peekable<impl Iterator<Item = char>>, start: usize) -> R<End> {
        loop {
            match it.next() {
                None | Some('\n') => return Ok(End::Record),
                Some(c) if c == self.o.separator => return Ok(End::Field),
                Some(c) => self.push(c, start)?,
            }
        }
    }

    /// FEA-08.16, FEA-08.17: a quoted field after its opening qualifier.
    fn quoted(&mut self, it: &mut Peekable<impl Iterator<Item = char>>, start: usize) -> R<End> {
        let q = self.o.qualifier;
        loop {
            match it.next() {
                None => {
                    self.problems.push(Problem::Unclosed {
                        record: self.record,
                    });
                    return Ok(End::Record);
                }
                Some('\\') if self.o.backslash => {
                    let c = it.next().unwrap_or('\\');
                    self.push(c, start)?;
                }
                Some(c) if c == q => {
                    if !self.o.backslash && it.peek() == Some(&q) {
                        it.next();
                        self.push(q, start)?;
                        continue;
                    }
                    return Ok(match it.peek() {
                        None => End::Record,
                        Some('\n') => {
                            it.next();
                            End::Record
                        }
                        Some(&c) if c == self.o.separator => {
                            it.next();
                            End::Field
                        }
                        // L08-7g: the character stays and starts the next record.
                        Some(_) => {
                            self.problems.push(Problem::Malformed {
                                record: self.record,
                            });
                            End::Record
                        }
                    });
                }
                Some(c) => self.push(c, start)?,
            }
        }
    }
}

/// The 11 target fields of the CSV screen, in order (FEA-08.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Group path.
    Group,
    /// Title.
    Title,
    /// User name.
    Username,
    /// Password.
    Password,
    /// URL.
    Url,
    /// Tags.
    Tags,
    /// Notes.
    Notes,
    /// One-time password.
    Totp,
    /// Standard icon number.
    Icon,
    /// Last modification time.
    LastModified,
    /// Creation time.
    Created,
}

/// The targets in screen order.
pub const TARGETS: [Target; 11] = [
    Target::Group,
    Target::Title,
    Target::Username,
    Target::Password,
    Target::Url,
    Target::Tags,
    Target::Notes,
    Target::Totp,
    Target::Icon,
    Target::LastModified,
    Target::Created,
];

impl Target {
    /// The English name the automatic mapping matches (FEA-08.20).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Target::Group => "Group",
            Target::Title => "Title",
            Target::Username => "Username",
            Target::Password => "Password",
            Target::Url => "URL",
            Target::Tags => "Tags",
            Target::Notes => "Notes",
            Target::Totp => "TOTP",
            Target::Icon => "Icon",
            Target::LastModified => "Last Modified",
            Target::Created => "Created",
        }
    }
}

/// The column chosen for each target, in [`TARGETS`] order; `None` is
/// "Not present".
pub type Mapping = [Option<usize>; 11];

/// FEA-08.20: each target takes the first column named like it, ignoring
/// case. A target with no such column keeps its `previous` choice when the
/// column names are the same as at the previous parse, else "Not present".
#[must_use]
pub fn auto_map(parsed: &Parsed, previous: Option<(&Parsed, &Mapping)>) -> Mapping {
    let mut map: Mapping = [None; 11];
    for (slot, t) in map.iter_mut().zip(TARGETS) {
        *slot = (0..parsed.columns).find(|&i| super::same_ignoring_case(&parsed.name(i), t.name()));
    }
    let same_names = |old: &Parsed| {
        old.columns == parsed.columns && (0..parsed.columns).all(|i| old.name(i) == parsed.name(i))
    };
    if let Some((old_parse, old)) = previous
        && same_names(old_parse)
    {
        for (slot, prev) in map.iter_mut().zip(old) {
            if slot.is_none() {
                *slot = *prev;
            }
        }
    }
    map
}

/// A question Finish asks first, in this order (FEA-08.22, FEA-08.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Question {
    /// `MSG-CSV-IMPORT-ANYWAY`: the file had parse problems (L08-3).
    ImportAnyway,
    /// `MSG-CSV-NOTITLE`: Title is "Not present".
    NoTitle,
}

/// The questions to ask before [`build`]; Cancel on any of them imports
/// nothing and returns to the CSV screen.
#[must_use]
pub fn questions(parsed: &Parsed, map: &Mapping) -> Vec<Question> {
    let mut q = Vec::new();
    if !parsed.problems.is_empty() {
        q.push(Question::ImportAnyway);
    }
    if map[1].is_none() {
        q.push(Question::NoTitle);
    }
    q
}

/// The default root name (FEA-08.24).
pub const DEFAULT_ROOT: &str = "Passwords";

/// FEA-08.21 to FEA-08.28: every record after the first `skip` becomes one
/// entry. `path` is the file's full path for the root notes.
///
/// # Errors
/// [`ImportError::TooLarge`] past a result limit; `Cancelled`;
/// `RandomSource`.
pub fn build(
    parsed: &Parsed,
    map: &Mapping,
    skip: usize,
    path: &str,
    ctx: &Context<'_>,
) -> Result<Imported, ImportError> {
    let rows = skip..parsed.rows();
    let col = |row: usize, t: usize| {
        map.get(t)
            .copied()
            .flatten()
            .map_or("", |c| parsed.cell(row, c))
    };
    // FEA-08.24: the common first path part.
    let first_part = |row: usize| col(row, 0).split('/').next().unwrap_or("");
    let common = match (map[0], rows.clone().next()) {
        (Some(_), Some(first)) => {
            let name = first_part(first);
            (!name.is_empty() && rows.clone().all(|r| first_part(r) == name)).then_some(name)
        }
        _ => None,
    };
    let mut b = Builder::new(ctx, common.unwrap_or(DEFAULT_ROOT))?;
    if let Some(root) = b.group_mut(0) {
        root.notes = format!("Imported from CSV file: {path}");
    }
    let secret = |s: &str| crate::text::Text::from(s).into_secret();
    for row in rows {
        let mut parts = col(row, 0).split('/').filter(|p| !p.is_empty()).peekable();
        if let (Some(c), Some(first)) = (common, parts.peek())
            && super::same_ignoring_case(first, c)
        {
            parts.next();
        }
        let group = b.path(0, parts)?;
        let mut d = b.draft()?;
        d.set("Title", secret(col(row, 1)), false)?;
        d.set("UserName", secret(col(row, 2)), false)?;
        d.set("Password", secret(col(row, 3)), true)?;
        d.set("URL", secret(col(row, 4)), false)?;
        d.set("Notes", secret(col(row, 6)), false)?;
        let tags = col(row, 5);
        if !tags.is_empty() {
            d.entry_mut().set_tags(parse_tags(tags));
        }
        d.totp_any(col(row, 7))?;
        // FEA-08.27, L08-7b: only the standard set.
        if let Ok(n) = col(row, 8).parse::<i64>()
            && (0..i64::from(STANDARD_COUNT)).contains(&n)
            && let Ok(n) = i32::try_from(n)
        {
            d.entry_mut().icon = Icon::Standard(n);
        }
        if let Some(t) = super::parse_time(col(row, 9), ctx.zone) {
            let times = &mut d.entry_mut().times;
            times.last_modification = t;
            times.last_access = t;
        }
        if let Some(t) = super::parse_time(col(row, 10), ctx.zone) {
            d.entry_mut().times.creation = t;
        }
        b.add(group, d)?;
    }
    Ok(b.finish())
}
