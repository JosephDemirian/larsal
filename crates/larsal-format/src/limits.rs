//! Every size and cost limit of `larsal-format` in one place (Rust rule 5;
//! spec/decisions.md LD-22). Every length read from a file is checked
//! against one of these before anything is allocated for it.
//!
//! [`Limits::DEFAULT`] holds the decided values. Every field is public, so a
//! test can lower any one limit (FMT-01.31, FMT-08.12 "tests must be able to
//! lower every limit"). Going over a limit is [`crate::Error::TooLarge`],
//! except the key file limits, which are `KeyFile(TooLarge)` (FMT-18.19).

use core::mem::size_of;
use larsal_crypto::kdf::Ceilings;
use larsal_model::entry::STANDARD_FIELDS;
use larsal_model::{
    Association, Attachment, CustomDataItem, CustomIcon, DeletedObject, Entry, Field, Group,
    UnknownNode,
};

/// The limits one read runs under. Copy it, change a field, pass it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes in a whole vault file: 1 GiB + 64 MiB (FMT-01.31).
    pub total_file: usize,
    /// Bytes of the raw outer header, preamble included: 1 MiB (FMT-02.25).
    pub header: usize,
    /// Largest data size of one version 4 block: the format maximum,
    /// 2^31 - 1, so it rejects no valid file (FMT-06.10, D-06-2).
    pub block: usize,

    /// Bytes of the decompressed payload: inner header plus document (FMT-08.12 "total").
    pub total: usize,
    /// Bytes of the XML document (FMT-08.12 "document").
    pub document: usize,
    /// Deepest element depth, root element at depth 0 (FMT-08.12 "depth").
    pub depth: usize,
    /// Start tags in the whole document (FMT-08.12 "elements").
    pub elements: usize,
    /// Bytes of one text value or attribute value, after references are
    /// replaced (FMT-08.12 "text").
    pub text: usize,
    /// `Group` elements, the root group included (FMT-08.12 "groups").
    pub groups: usize,
    /// Live entries (FMT-08.12 "entries").
    pub entries: usize,
    /// Live entries plus history items (FMT-08.12 "entry elements").
    pub entry_elements: usize,
    /// History items of one live entry (FMT-08.12 "history").
    pub history: usize,
    /// `String` elements in one entry or history item (FMT-08.12 "strings").
    pub strings: usize,
    /// `Binary` elements in one entry or history item (FMT-08.12 "attachments").
    pub attachments: usize,
    /// `Association` elements in one entry or history item (FMT-08.12 "associations").
    pub associations: usize,
    /// Elements kept as unknown, nested ones included (FMT-08.12 "kept unknown elements").
    pub kept_unknown: usize,
    /// Inner header pool items plus `Meta/Binaries` items (FMT-08.12 "pool items").
    pub pool_items: usize,
    /// Content bytes of one attachment (FMT-08.12 "one attachment").
    pub one_attachment: usize,
    /// Content bytes of all attachments together (FMT-08.12 "all attachments").
    pub all_attachments: usize,
    /// `Icon` elements in the whole document (FMT-08.12 "icons").
    pub icons: usize,
    /// Custom data items in one container (FMT-08.12 "custom data items").
    pub custom_data_items: usize,
    /// Custom data items of all containers (FMT-08.12 "custom data items in all").
    pub custom_data_items_all: usize,
    /// `DeletedObject` elements (FMT-08.12 "deleted objects").
    pub deleted_objects: usize,
    /// Bytes of model built while reading: each object read adds its cost
    /// from [`model_cost`] plus its text bytes, and attachment content adds
    /// its bytes once held (FMT-08.12 "model", LD-85, LD-89, LD-90).
    pub model: usize,

    /// UTF-16 code units in one key file `Version` text, `Data` text or
    /// `Hash` attribute the walk gathers: 1 MiB (FMT-18 D-18-3).
    pub key_file_text: usize,
    /// Deepest element in a key file document, root at depth 1 (FMT-18 D-18-3).
    pub key_file_depth: usize,
    /// Attributes, namespace declarations included, on one start tag of a
    /// key file document: 1,024. More is `KeyFile(TooLarge)` (spec/decisions.md
    /// LD-83; FMT-08.12 table row "key file attributes").
    pub key_file_attributes: usize,

    /// KDF cost ceilings of CRY-02.14: refuse above 1,000,000,000 Argon2
    /// iterations; ask above 1 GiB of memory, 128 lanes or 10 s estimated.
    pub kdf: Ceilings,
}

/// A limit by its name: the first column of FMT-08.12, or for the limits
/// outside that table the name their owning card gives (FMT-01.31
/// `total file`, FMT-02.25 `header`, FMT-06.10 `block`, CRY-02.14 `KDF
/// cost`, FMT-18 D-18-3 `key file text` and `key file depth`).
/// [`crate::Error::TooLarge`] and the key file `TooLarge` carry it, so a
/// message can say which limit was passed (APP-06). It holds no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// `total file`: bytes of the whole vault file (FMT-01.31).
    TotalFile,
    /// `header`: bytes of the raw outer header (FMT-02.25).
    Header,
    /// `block`: data bytes of one version 4 block, or the block count (FMT-06.10).
    Block,
    /// `KDF cost`: KDF settings above a refuse ceiling (CRY-02.14).
    KdfCost,
    /// `total`: bytes of the decompressed payload.
    Total,
    /// `document`: bytes of the XML document.
    Document,
    /// `depth`; also the nesting of the final group tree.
    Depth,
    /// `elements`: start tags in the document.
    Elements,
    /// `text`: bytes of one text value or attribute value.
    Text,
    /// `groups`.
    Groups,
    /// `entries`: live entries.
    Entries,
    /// `entry elements`: live entries plus history items.
    EntryElements,
    /// `history`: history items of one live entry.
    History,
    /// `strings`: fields of one entry or history item.
    Strings,
    /// `attachments`: attachments of one entry or history item.
    Attachments,
    /// `associations`: auto-type associations of one entry or history item.
    Associations,
    /// `kept unknown elements`.
    KeptUnknown,
    /// `pool items`.
    PoolItems,
    /// `one attachment`: content bytes of one attachment.
    OneAttachment,
    /// `all attachments`: content bytes of all attachments.
    AllAttachments,
    /// `icons`.
    Icons,
    /// `custom data items`: items of one container.
    CustomDataItems,
    /// `custom data items in all`.
    CustomDataItemsAll,
    /// `deleted objects`.
    DeletedObjects,
    /// `model`: the in-memory size of the model read so far (LD-85).
    Model,
    /// `key file attributes`: attributes on one key file tag, and each
    /// gathered key file token (LD-83).
    KeyFileAttributes,
    /// `key file text`: one key file `Version`, `Data` or `Hash` text.
    KeyFileText,
    /// `key file depth`: element depth in a key file document.
    KeyFileDepth,
}

impl Limit {
    /// The limit's name as the cards write it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::TotalFile => "total file",
            Self::Header => "header",
            Self::Block => "block",
            Self::KdfCost => "KDF cost",
            Self::Total => "total",
            Self::Document => "document",
            Self::Depth => "depth",
            Self::Elements => "elements",
            Self::Text => "text",
            Self::Groups => "groups",
            Self::Entries => "entries",
            Self::EntryElements => "entry elements",
            Self::History => "history",
            Self::Strings => "strings",
            Self::Attachments => "attachments",
            Self::Associations => "associations",
            Self::KeptUnknown => "kept unknown elements",
            Self::PoolItems => "pool items",
            Self::OneAttachment => "one attachment",
            Self::AllAttachments => "all attachments",
            Self::Icons => "icons",
            Self::CustomDataItems => "custom data items",
            Self::CustomDataItemsAll => "custom data items in all",
            Self::DeletedObjects => "deleted objects",
            Self::Model => "model",
            Self::KeyFileAttributes => "key file attributes",
            Self::KeyFileText => "key file text",
            Self::KeyFileDepth => "key file depth",
        }
    }
}

impl core::fmt::Display for Limit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

const MIB: usize = 1 << 20;
const GIB: usize = 1 << 30;

impl Limits {
    /// The decided values (LD-22; FMT-01.31, FMT-02.25, FMT-06.10,
    /// FMT-08.12, FMT-18 D-18-3, CRY-02.14).
    pub const DEFAULT: Self = Self {
        total_file: GIB + 64 * MIB,
        header: MIB,
        block: 2_147_483_647,
        total: GIB,
        document: 512 * MIB,
        depth: 512,
        elements: 67_108_864,
        text: 64 * MIB,
        groups: 1_000_000,
        entries: 1_000_000,
        entry_elements: 4_000_000,
        history: 100_000,
        strings: 100_000,
        attachments: 100_000,
        associations: 100_000,
        kept_unknown: 1_000_000,
        pool_items: 1_000_000,
        one_attachment: GIB,
        all_attachments: GIB,
        icons: 100_000,
        custom_data_items: 100_000,
        custom_data_items_all: 10_000_000,
        deleted_objects: 1_000_000,
        model: 2 * GIB,
        key_file_text: MIB,
        key_file_depth: 256,
        key_file_attributes: 1_024,
        kdf: Ceilings {
            refuse_iterations: 1_000_000_000,
            ask_memory_kib: 1_048_576,
            ask_lanes: 128,
            ask_ms: 10_000,
        },
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The in-memory cost of each model object, charged to [`Limits::model`]
/// as the object is read (LD-85). Each is the type's `size_of` plus the
/// heap blocks it typically holds (a short string's heap block is taken as
/// 16 bytes, the allocator's smallest); text bytes are charged on top as
/// they are read. Groups and live entries also pay for the extra parts of
/// their reading node (lists, id map slot, placement). The second copy the
/// tree build holds for a moment is not charged. `ENTRY` is the measured
/// cost, not the type sizes, because entries and history items are what a
/// crafted file can pile up most (LD-89). Measured on this build (64-bit macOS, Rust 1.99.1):
/// `Entry` 448, `Group` 368, a field slot `(String, Field)` 56,
/// `Attachment` 32, `CustomDataItem` 88, `Association` 72, `CustomIcon`
/// 104, `DeletedObject` 48, `UnknownNode` 72, `String` 24 bytes.
pub mod model_cost {
    use super::{
        Association, Attachment, CustomDataItem, CustomIcon, DeletedObject, Entry, Field, Group,
        STANDARD_FIELDS, UnknownNode, size_of,
    };

    /// The smallest heap block of a short string.
    const BLOCK: usize = 16;

    /// The type sizes of an entry with its five standard fields (each a slot
    /// and a key on the heap): 448 + 5 x (56 + 16) = 808 bytes.
    pub const ENTRY_TYPES: usize =
        size_of::<Entry>() + STANDARD_FIELDS.len() * (size_of::<(String, Field)>() + BLOCK);
    /// A live entry or a history item, as measured: peak memory per empty
    /// history item is about 1,400 bytes in a debug build and 920 in a
    /// release build (red team harness, F-037), above the 808 of the type
    /// sizes because of allocator and list slack (LD-89). A test keeps it at
    /// least `ENTRY_TYPES`.
    pub const ENTRY: usize = 1_400;
    /// What a live entry (not a history item) costs on top of `ENTRY`: the
    /// merge lists of its reading node (136), its id map slot, placement
    /// and child list (about 120): 256. With `ENTRY` that is 1,656 bytes,
    /// so 1,000,000 empty entries fit in the 2 GiB budget (FMT-11.66).
    pub const ENTRY_NODE: usize = 256;

    // Build-time checks: the measured entry cost never drops below the type
    // sizes, and 1,000,000 empty live entries fit in the budget (FMT-11.66).
    const _: () = assert!(ENTRY >= ENTRY_TYPES);
    const _: () = assert!(1_000_000 * (ENTRY + ENTRY_NODE) < super::Limits::DEFAULT.model);
    /// The type sizes of a group with its reading node's lists, id map slot
    /// and placement (about 190): 368 + 192 = 560.
    pub const GROUP_TYPES: usize = size_of::<Group>() + 192;
    /// A group, as measured (LD-90): peak memory per empty group, red team
    /// harness, 524,289 and 999,999 groups: 976 to 978 bytes in a release
    /// build, 976 to 980 in a debug build; its texts are charged as text.
    pub const GROUP: usize = 980;

    // Build-time checks: the measured group cost never drops below the type
    // sizes, and a full groups limit of empty groups fits in the budget.
    const _: () = assert!(GROUP >= GROUP_TYPES);
    const _: () = assert!(super::Limits::DEFAULT.groups * GROUP < super::Limits::DEFAULT.model);
    /// A custom field: its slot, key and value heap blocks: 56 + 32 = 88.
    pub const FIELD: usize = size_of::<(String, Field)>() + 2 * BLOCK;
    /// One entry tag: a string and its heap block: 24 + 16 = 40.
    pub const TAG: usize = size_of::<String>() + BLOCK;
    /// An attachment reference: 32 + 16 = 48. Its content is counted by the
    /// attachment limits, and charged by its bytes once held in the model
    /// (a pool item when a `Ref` first uses it, a `Meta/Binaries` item, an
    /// inline value; LD-90).
    pub const ATTACHMENT: usize = size_of::<Attachment>() + BLOCK;
    /// A custom data item with key and value blocks: 88 + 32 = 120.
    pub const CUSTOM_DATA_ITEM: usize = size_of::<CustomDataItem>() + 2 * BLOCK;
    /// An auto-type association with window and sequence blocks: 72 + 32 = 104.
    pub const ASSOCIATION: usize = size_of::<Association>() + 2 * BLOCK;
    /// A custom icon: 104 (its name and data are charged as text).
    pub const ICON: usize = size_of::<CustomIcon>();
    /// A deleted-object record: 48.
    pub const DELETED_OBJECT: usize = size_of::<DeletedObject>();
    /// A kept unknown element: its node in the parent and its name block:
    /// 72 + 16 = 88.
    pub const UNKNOWN: usize = size_of::<UnknownNode>() + BLOCK;
    /// A kept attribute of an unknown element: two strings and blocks: 80.
    pub const STRING_PAIR: usize = 2 * (size_of::<String>() + BLOCK);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decided_values() {
        let l = Limits::DEFAULT;
        assert_eq!(l.total_file, 1_140_850_688);
        assert_eq!(l.header, 1_048_576);
        assert_eq!(l.total, 1_073_741_824);
        assert_eq!(l.document, 536_870_912);
        assert_eq!(l.text, 67_108_864);
        assert_eq!(l.key_file_text, 1_048_576);
    }
}
