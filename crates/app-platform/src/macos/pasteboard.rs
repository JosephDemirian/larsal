//! The pasteboard calls under `clipboard.rs` (APP-03.9, APP-03.10,
//! APP-03.12). Safe objc2 calls only: no `unsafe` here. A pasteboard is
//! named by `None` (the general pasteboard) or by its name, because an
//! `NSPasteboard` handle may not move between threads (objc2 marks it
//! neither `Send` nor `Sync`); each call looks it up again.
//!
//! The markers are the published ones of nspasteboard.org, which clipboard
//! history tools honour; MacPass (`MPPasteBoardController.m`) writes both
//! when it will clear, Strongbox (`ClipboardManager.m`) the concealed one
//! (plan/native-app-research.md point 6, LD-156 (6)). Both clear with a
//! timer, as here.
#![forbid(unsafe_code)]

use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::ProtocolObject;
use objc2_app_kit::{
    NSPasteboard, NSPasteboardContentsOptions, NSPasteboardItem, NSPasteboardWriting,
};
use objc2_foundation::{NSArray, NSData, NSString};
use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

/// The type other apps paste as text (the value of `NSPasteboardTypeString`).
pub(crate) const TEXT: &str = "public.utf8-plain-text";
/// nspasteboard.org: the content is a password or similar; clipboard tools
/// must not show or store it.
pub(crate) const CONCEALED: &str = "org.nspasteboard.ConcealedType";
/// nspasteboard.org: the content is there only for a moment.
pub(crate) const TRANSIENT: &str = "org.nspasteboard.TransientType";

#[cfg(test)]
thread_local! {
    /// Unit tests only: the next writes on this thread are refused before
    /// the pasteboard is touched, as a failed item build would be.
    pub(crate) static REFUSE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// LD-206: the name of every pasteboard App wrote or cleared in this
/// process (names only, never content), so a test proves from App's own
/// record that the general pasteboard was never touched (AGENTS.md rule 10).
static WRITTEN: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn record(pb: &NSPasteboard) {
    WRITTEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(pb.name().to_string());
}

/// The names [`record`] kept, in order.
pub(crate) fn written() -> Vec<String> {
    WRITTEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .cloned()
        .collect()
}

fn board(name: Option<&str>) -> Retained<NSPasteboard> {
    match name {
        None => NSPasteboard::generalPasteboard(),
        Some(name) => NSPasteboard::pasteboardWithName(&NSString::from_str(name)),
    }
}

/// Replaces the whole content with one item: `text` as plain text, plus the
/// concealed and transient markers with empty data, prepared as "current
/// host only" so Universal Clipboard keeps it on this Mac (APP-03.9,
/// D-A03-2 (b)). The item is built first and written in one call, so no
/// reader ever sees the text without its markers. Returns the change count
/// right after the write (APP-03.10), or `None` when the system refused:
/// before the pasteboard was touched, or after, and then it is left empty.
pub(crate) fn write(name: Option<&str>, text: &str) -> Option<isize> {
    #[cfg(test)]
    if REFUSE_WRITE.get() {
        return None;
    }
    autoreleasepool(|_| {
        let item = NSPasteboardItem::new();
        let empty = NSData::new();
        let built = item.setData_forType(&empty, &NSString::from_str(CONCEALED))
            && item.setData_forType(&empty, &NSString::from_str(TRANSIENT))
            && item.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT));
        if !built {
            return None;
        }
        let pb = board(name);
        record(&pb);
        // The count the prepare returns is ours; reading it after the write
        // could record another app's write in between (AT-D02).
        let count =
            pb.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
        let items = NSArray::from_retained_slice(&[
            ProtocolObject::<dyn NSPasteboardWriting>::from_retained(item),
        ]);
        if pb.writeObjects(&items) {
            Some(count)
        } else {
            // Clear only what is still ours: a failed write usually means
            // another app owns the pasteboard now.
            if pb.changeCount() == count {
                pb.clearContents();
            }
            None
        }
    })
}

/// Empties the pasteboard only while its change count is still `count`, so
/// newer content from the user or another app stays (APP-03.12). Never
/// reads the content. Returns whether it emptied the pasteboard.
pub(crate) fn clear_if(name: Option<&str>, count: isize) -> bool {
    autoreleasepool(|_| {
        let pb = board(name);
        let ours = pb.changeCount() == count;
        if ours {
            record(&pb);
            pb.clearContents();
        }
        ours
    })
}

/// Tests only, for a named pasteboard: each item's types with their data.
pub(crate) fn items(name: &str) -> Vec<Vec<(String, Vec<u8>)>> {
    autoreleasepool(|_| {
        let Some(items) = board(Some(name)).pasteboardItems() else {
            return Vec::new();
        };
        items
            .to_vec()
            .iter()
            .map(|item| {
                item.types()
                    .to_vec()
                    .iter()
                    .map(|kind| {
                        let data = item.dataForType(kind).map(|d| d.to_vec());
                        (kind.to_string(), data.unwrap_or_default())
                    })
                    .collect()
            })
            .collect()
    })
}

/// Tests only, for a named pasteboard: writes `text` as plain text with no
/// marker, as another app would.
pub(crate) fn write_plain(name: &str, text: &str) {
    autoreleasepool(|_| {
        let pb = board(Some(name));
        record(&pb);
        pb.clearContents();
        pb.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT));
    });
}
