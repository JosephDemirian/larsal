//! Unknown document parts, kept exactly as read so a save loses nothing
//! (SD-06; FMT-10.20, FMT-10.27, FMT-11.45).

/// One kept unknown element: its local name (no namespace prefix), the
/// attributes whose name has no prefix, in read order, and its content.
///
/// Guarantees: never interpreted. A `Protected` attribute on it stays with
/// its raw text and takes no keystream bytes, on read or on write (FMT-09.14,
/// LD-24). Comments and processing instructions are not kept; the text on
/// both sides of one is joined (FMT-10.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownElement {
    /// Local name, as read.
    pub name: String,
    /// `(name, value)` pairs, values after XML attribute normalization.
    pub attributes: Vec<(String, String)>,
    /// Text and child elements in read order; adjacent text is one node.
    pub content: Vec<UnknownNode>,
}

/// A piece of a kept element's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownNode {
    /// Text, after XML decoding (FMT-12.23), white space included.
    Text(String),
    /// A child element.
    Element(UnknownElement),
}
