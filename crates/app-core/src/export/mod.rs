//! Export (FEA-09, story E4-S13): the whole vault in clear as CSV, HTML or
//! the plain XML document.
//!
//! Guarantees: every exporter reads the vault in memory (unsaved changes
//! included) through `&Vault`, so it changes nothing, and draws no random
//! value (FEA-09.1, CRY-03). The text is built in a wiping buffer and
//! returned as `SecretBytes`; the caller writes it with
//! [`crate::storage::write_export`] (mode 0600, atomic, never through a
//! link; FEA-09.15) or to standard output, then drops it, which wipes it
//! (FEA-09.18). Nothing exported goes to a log or an error.

pub mod csv;
pub mod html;
pub mod passkey;
pub mod xml;

/// The three export formats (FEA-09.17: there are no others).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// ACT-EXPORT-CSV.
    Csv,
    /// ACT-EXPORT-HTML.
    Html,
    /// ACT-EXPORT-XML.
    Xml,
}

/// `MSG-EXP-CONFIRM` title (FEA-09.2).
pub const CONFIRM_TITLE: &str = "Export without encryption?";
/// `MSG-EXP-CONFIRM` text (FEA-09.2, SD-07).
pub const CONFIRM_TEXT: &str = "The file will hold every password and secret in this vault as plain text. Anyone who can open the file can read them.";
/// The extra CSV line (LD-43).
pub const FORMULA_NOTE: &str = "A spreadsheet may run values that start with =, +, - or @ as formulas. App writes every value exactly as it is stored.";

impl Format {
    /// The format's name in messages and dialog titles.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Format::Csv => "CSV",
            Format::Html => "HTML",
            Format::Xml => "XML",
        }
    }

    /// The save dialog's filter extension (FEA-09.15).
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Html => "html",
            Format::Xml => "xml",
        }
    }

    /// True when the desktop asks `MSG-EXP-CONFIRM` (buttons Yes and No,
    /// default No) before the save dialog; HTML shows [`warning`] as a
    /// banner in its dialog instead (FEA-09.2).
    #[must_use]
    pub fn asks_first(self) -> bool {
        self != Format::Html
    }

    /// The command line's format option (FEA-09.16): missing or empty is
    /// XML; `xml`, `csv` and `html` ignoring case. Exact names only: INT-10
    /// has not ruled on the reference's prefix matching.
    ///
    /// # Errors
    /// `MSG-EXP-FORMAT` text for any other value (exit status 1).
    pub fn from_option(value: Option<&str>) -> Result<Format, String> {
        match value.unwrap_or("") {
            "" => Ok(Format::Xml),
            v if v.eq_ignore_ascii_case("xml") => Ok(Format::Xml),
            v if v.eq_ignore_ascii_case("csv") => Ok(Format::Csv),
            v if v.eq_ignore_ascii_case("html") => Ok(Format::Html),
            v => Err(format!(
                "{v} is not an export format. Use xml, csv or html."
            )),
        }
    }
}

/// The not-encrypted warning for `format` (FEA-09.2): the question text,
/// plus the formula line for CSV (LD-43). The desktop shows it in the
/// question or the HTML banner; the command line prints it on standard
/// error before every plain export (LD-42).
#[must_use]
pub fn warning(format: Format) -> String {
    match format {
        Format::Csv => format!("{CONFIRM_TEXT}\n{FORMULA_NOTE}"),
        Format::Html | Format::Xml => CONFIRM_TEXT.to_owned(),
    }
}
