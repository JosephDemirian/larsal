//! The one error type of larsal-core (Rust rule 8). No variant holds a value
//! from the vault: messages come from larsal-ffi.

/// Why a typed field or attachment name was refused (MOD-01.3, MOD-05.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameProblem {
    /// Empty after trimming white space.
    Empty,
    /// One of the five standard names.
    Standard,
    /// Another field of the entry has it.
    Taken,
}

/// Every way an larsal-core operation can be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No group with that id.
    NoSuchGroup,
    /// No live entry with that id.
    NoSuchEntry,
    /// The root group cannot be moved, deleted or put in the recycle bin
    /// (MOD-02.2).
    RootGroup,
    /// A group cannot move into itself or its subtree (MOD-02.20).
    Cycle,
    /// A typed field name was refused (MOD-01.3).
    FieldName(NameProblem),
    /// A field value, a name or the field count passes the edit caps
    /// (MOD-01.9, LD-56).
    FieldTooLarge,
    /// An attachment name was refused: empty (MOD-05.2) or taken by
    /// another attachment of the entry (MOD-05.1, MOD-05.10, MOD-05.15).
    AttachmentName(NameProblem),
    /// The group would sit deeper than Larsal's reader accepts (LD-106).
    TooDeep,
    /// The change would pass one of the reader's count or size limits
    /// (FMT-08.12; MOD-05.16, MOD-10 security notes).
    TooLarge,
    /// Not allowed inside the recycle bin (MOD-04.15).
    InRecycleBin,
    /// No history item at that position (MOD-03.13).
    NoSuchHistoryItem,
    /// The random source failed while making a new id (CRY-03.11).
    RandomSource,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchGroup => f.write_str("no such group"),
            Self::NoSuchEntry => f.write_str("no such entry"),
            Self::RootGroup => f.write_str("the root group cannot be moved or deleted"),
            Self::Cycle => f.write_str("a group cannot move into itself"),
            Self::FieldName(v) => write!(f, "field name refused: {v:?}"),
            Self::FieldTooLarge => f.write_str("field too large"),
            Self::AttachmentName(v) => write!(f, "attachment name refused: {v:?}"),
            Self::TooDeep => f.write_str("groups nested too deep"),
            Self::TooLarge => f.write_str("over a vault limit"),
            Self::InRecycleBin => f.write_str("not allowed inside the recycle bin"),
            Self::NoSuchHistoryItem => f.write_str("no such history item"),
            Self::RandomSource => f.write_str("random source failed"),
        }
    }
}

impl std::error::Error for Error {}
