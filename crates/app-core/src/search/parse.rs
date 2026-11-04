//! The search language (FEA-01.1 to FEA-01.6): query text to terms.
//!
//! Guarantees: every text up to [`MAX_QUERY`] characters parses, without
//! panic, in one pass linear in its length (fuzz target `search_query`);
//! a longer text is refused before any work, and so is a query with more
//! than [`MAX_PATTERN_TERMS`] terms that become patterns.

/// The longest query, in characters (FEA-01.32).
pub const MAX_QUERY: usize = 1_024;
/// The most terms that become patterns in one query: plain, wildcard and
/// regular-expression terms; `is:` and `has:` terms do not count (LD-124,
/// LD-126 (5)).
pub const MAX_PATTERN_TERMS: usize = 16;

/// What a term looks at (FEA-01.5, FEA-01.13).
#[derive(Clone, PartialEq, Eq)]
pub enum Field {
    /// Title, user name, URL, tags and notes.
    Default,
    /// Attachment names.
    Attachment,
    /// Custom field names and values.
    Attribute,
    /// Notes.
    Notes,
    /// The password.
    Password,
    /// The title.
    Title,
    /// The user name.
    UserName,
    /// The URL.
    Url,
    /// The entry's own group (FEA-01.15).
    Group,
    /// Each tag, whole (FEA-01.14).
    Tag,
    /// Entry state: `expired`, `weak` (FEA-01.16, FEA-01.17).
    Is,
    /// Entry feature: `totp` (FEA-01.18).
    Has,
    /// The entry id as 32 lowercase hex digits.
    Uuid,
    /// The field with exactly this name (FEA-01.6).
    Named(String),
}

/// One term (FEA-01.2). No `Debug`: a value can hold a secret the user
/// typed (`pw:…`), and query text is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct Term {
    /// `-` or `!`: the term holds when its match fails (FEA-01.11).
    pub exclude: bool,
    /// `*`: the value is a regular expression (FEA-01.8).
    pub regex: bool,
    /// `+`: the whole text must match, with case (FEA-01.9).
    pub exact: bool,
    /// What the term looks at.
    pub field: Field,
    /// The value after unquoting; never empty.
    pub value: String,
}

/// A query App refuses: nothing runs and the current results stay
/// (FEA-01.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    /// Over [`MAX_QUERY`] characters.
    TooLong,
    /// Over [`MAX_PATTERN_TERMS`] terms that become patterns (LD-124).
    TooManyTerms,
}

/// Splits a query into terms (FEA-01.1 to FEA-01.5). Terms with an empty
/// value are dropped (FEA-01.4).
///
/// # Errors
/// [`QueryError`] for more than 1,024 characters or more than 16 pattern
/// terms.
pub fn parse(query: &str) -> Result<Vec<Term>, QueryError> {
    if query.chars().nth(MAX_QUERY).is_some() {
        return Err(QueryError::TooLong);
    }
    let mut terms: Vec<Term> = Vec::new();
    let mut rest = query;
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            let patterns = terms
                .iter()
                .filter(|t| !matches!(t.field, Field::Is | Field::Has))
                .count();
            if patterns > MAX_PATTERN_TERMS {
                return Err(QueryError::TooManyTerms);
            }
            return Ok(terms);
        }
        let (term, after) = one_term(rest);
        rest = after;
        if let Some(t) = term {
            terms.push(t);
        }
    }
}

/// Reads one term from the start of `s` (not a space); returns it (or
/// `None` for an empty value) and the text after it.
fn one_term(s: &str) -> (Option<Term>, &str) {
    let mods_end = s
        .find(|c| !matches!(c, '-' | '!' | '*' | '+'))
        .unwrap_or(s.len());
    let mods = s.get(..mods_end).unwrap_or("");
    let body = s.get(mods_end..).unwrap_or("");
    let run_end = body
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(body.len());
    let (field, value_part) = match body.get(run_end..).and_then(|r| r.strip_prefix(':')) {
        Some(after) => (field_named(body.get(..run_end).unwrap_or("")), after),
        None => (Field::Default, body),
    };
    let (value, after) = value(value_part);
    let term = (!value.is_empty()).then(|| Term {
        exclude: mods.contains(['-', '!']),
        regex: mods.contains('*'),
        exact: mods.contains('+'),
        field,
        value,
    });
    (term, after)
}

/// FEA-01.3: a quoted value when a closing `"` is followed by a space or
/// the end, with `\"` for `"`; else the text up to the next space.
fn value(s: &str) -> (String, &str) {
    if let Some(inner) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = inner.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some((_, '"')) => out.push('"'),
                    Some((_, n)) => {
                        out.push('\\');
                        out.push(n);
                    }
                    None => out.push('\\'),
                },
                '"' => {
                    let after = inner.get(i.saturating_add(1)..).unwrap_or("");
                    if after.is_empty() || after.starts_with(' ') {
                        return (out, after);
                    }
                    out.push('"');
                }
                _ => out.push(c),
            }
        }
    }
    let end = s.find(' ').unwrap_or(s.len());
    (
        s.get(..end).unwrap_or("").to_owned(),
        s.get(end..).unwrap_or(""),
    )
}

/// FEA-01.5: the first known name that starts with the typed name (case
/// ignored); `_name` names one field; anything else is the default.
fn field_named(typed: &str) -> Field {
    if let Some(name) = typed.strip_prefix('_') {
        return Field::Named(name.to_owned());
    }
    if typed.is_empty() {
        return Field::Default;
    }
    const NAMES: [&str; 13] = [
        "attachment",
        "attribute",
        "notes",
        "pw",
        "password",
        "title",
        "username",
        "url",
        "group",
        "tag",
        "is",
        "has",
        "uuid",
    ];
    let known = NAMES.iter().find(|n| {
        n.get(..typed.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(typed))
    });
    match known.copied() {
        Some("attachment") => Field::Attachment,
        Some("attribute") => Field::Attribute,
        Some("notes") => Field::Notes,
        Some("pw" | "password") => Field::Password,
        Some("title") => Field::Title,
        Some("username") => Field::UserName,
        Some("url") => Field::Url,
        Some("group") => Field::Group,
        Some("tag") => Field::Tag,
        Some("is") => Field::Is,
        Some("has") => Field::Has,
        Some("uuid") => Field::Uuid,
        _ => Field::Default,
    }
}
