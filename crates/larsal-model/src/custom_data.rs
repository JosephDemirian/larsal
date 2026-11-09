//! Key and value pairs that plug-ins keep on the vault, groups and entries
//! (FMT-14.10 to FMT-14.24).

use crate::times::Time;
use crate::unknown::UnknownElement;
use larsal_crypto::secret::SecretString;

/// True for a character a saved text keeps (FMT-12.25). The one set: the writer, the
/// reader of custom data keys and every compare of a key below go through it.
#[must_use]
pub fn kept_char(c: char) -> bool {
    !matches!(c,
        '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}'
        | '\u{7F}'..='\u{84}' | '\u{86}'..='\u{9F}' | '\u{FFFE}' | '\u{FFFF}')
}

/// `key` as a save writes it (FMT-12.25, FMT-14.10).
#[must_use]
pub fn clean_key(key: &str) -> String {
    key.chars().filter(|c| kept_char(*c)).collect()
}

/// True when `key`, cleaned, is `held`: a key that differs only by what a save removes
/// is that key, on every read and every compare (INT-08.32).
#[must_use]
pub fn same_key(key: &str, held: &str) -> bool {
    key.chars().filter(|c| kept_char(*c)).eq(held.chars())
}

/// One custom data container.
///
/// Guarantees: items keep their stored order (read order; new keys at the
/// end, FMT-14.15). Keys are unique after a read (FMT-14.16).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CustomData {
    /// The items.
    pub items: Vec<CustomDataItem>,
    /// Kept unknown children of `CustomData` blocks.
    pub unknown: Vec<UnknownElement>,
}

/// One item: plain text key and value, optional time (FMT-14.13).
#[derive(PartialEq, Eq)]
pub struct CustomDataItem {
    /// Key, exact and case-sensitive.
    pub key: String,
    /// Value, wiped on drop and replacement, including serialized credentials.
    pub value: SecretString,
    /// `LastModificationTime`, when one was read or set.
    pub last_modified: Option<Time>,
    /// Kept unknown children of `Item`.
    pub unknown: Vec<UnknownElement>,
}

/// Copies go straight into wiping storage, as for entry fields.
impl Clone for CustomDataItem {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            value: SecretString::from(self.value.expose()),
            last_modified: self.last_modified,
            unknown: self.unknown.clone(),
        }
    }
}

/// The key and the value length only: a value may be a secret, for example
/// a share item holds the share password (INT-08.39, LD-279 (3)).
impl core::fmt::Debug for CustomDataItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CustomDataItem")
            .field("key", &self.key)
            .field("value_len", &self.value.len())
            .finish_non_exhaustive()
    }
}

impl CustomData {
    /// The value stored under `key`, if any.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|i| i.key == key)
            .map(|i| i.value.expose())
    }

    /// True when there are no items and nothing kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.unknown.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_item_independently_owns_value_and_keeps_metadata() {
        let item = CustomDataItem {
            key: "demo".into(),
            value: SecretString::from("démo\0🗝️"),
            last_modified: Some(Time(5)),
            unknown: vec![UnknownElement {
                name: "Demo".into(),
                attributes: vec![("a".into(), "b".into())],
                content: vec![crate::unknown::UnknownNode::Text("kept".into())],
            }],
        };
        let mut copy = item.clone();
        assert_eq!(copy, item);
        assert_ne!(copy.value.expose().as_ptr(), item.value.expose().as_ptr());
        copy.value = SecretString::from("");
        copy.unknown.clear();
        assert_eq!(item.value.expose(), "démo\0🗝️");
        assert_eq!(item.unknown.len(), 1);
    }

    // INT-08.32 (C2R3-01): a key that differs only by what a save removes is the key,
    // for every removed character in every position; anything else is not.
    #[test]
    fn int08_32_a_near_key_is_the_key() {
        let key = "app.larsal.share.moved";
        let removed = (0u32..=8)
            .chain([0xB, 0xC])
            .chain(0xE..=0x1F)
            .chain(0x7F..=0x84)
            .chain(0x86..=0x9F)
            .chain([0xFFFE, 0xFFFF])
            .filter_map(char::from_u32);
        for c in removed {
            for cut in [0, 3, key.len()] {
                let near = format!("{}{c}{}", &key[..cut], &key[cut..]);
                assert!(same_key(&near, key), "U+{:04X} at {cut}", u32::from(c));
                assert_eq!(clean_key(&near), key);
            }
        }
        for c in ['\t', '\n', '\r', '\u{85}', 'x', '\u{A0}'] {
            assert!(
                !same_key(&format!("{key}{c}"), key),
                "U+{:04X}",
                u32::from(c)
            );
        }
        assert!(
            !same_key(key, &format!("{key}\u{7f}")),
            "the held side is clean"
        );
    }

    // INT-08.39 by type: the value (a share item's value is the share
    // password in base64) never shows in Debug, in an item or a container.
    #[test]
    fn int08_39_debug_shows_the_key_and_the_value_length_only() {
        let item = CustomDataItem {
            key: "demo-key".into(),
            value: SecretString::new("ZGVtby1zaGFyZS0x".into()),
            last_modified: Some(Time(5)),
            unknown: Vec::new(),
        };
        let cd = CustomData {
            items: vec![item.clone()],
            unknown: Vec::new(),
        };
        for text in [format!("{item:?}"), format!("{item:#?}"), format!("{cd:?}")] {
            assert!(text.contains("demo-key"), "{text}");
            assert!(text.contains("value_len: 16"), "{text}");
            assert!(!text.contains("ZGVtby1zaGFyZS0x"), "{text}");
        }
        // LD-281 (6): the exact output, so no part of the value slips in.
        assert_eq!(
            format!("{item:?}"),
            "CustomDataItem { key: \"demo-key\", value_len: 16, .. }"
        );
        assert_eq!(
            format!("{cd:?}"),
            "CustomData { items: [CustomDataItem { key: \"demo-key\", value_len: 16, .. }], unknown: [] }"
        );
    }
}
