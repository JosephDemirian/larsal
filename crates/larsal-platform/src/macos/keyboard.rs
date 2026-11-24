//! Keyboard events for Auto-Type (INT-05.40 to INT-05.43, E8-S3) through
//! Quartz Event Services, linked from the CoreGraphics framework (no crate).
//!
//! Guarantees:
//! - Every event comes from Larsal's own private event source, so the
//!   physical keyboard's modifier state never mixes in, and carries the
//!   flags it is given and nothing else (INT-05.43).
//! - [`Keyboard::post`] is the only call here that reaches another app: it
//!   posts to the login session's keyboard input (`kCGSessionEventTap`),
//!   never to one process. macOS drops the event unless Larsal holds the
//!   Accessibility permission. Tests never call it (AGENTS.md rule 10); they
//!   make events with [`Keyboard::event`] and read them back.
//! - [`modifiers_held`] only reads the keyboard's state.

use std::ffi::{c_ulong, c_void};
use std::ptr::NonNull;

/// ⇧ (`kCGEventFlagMaskShift`, `NX_SHIFTMASK`).
pub const SHIFT: u64 = 0x0002_0000;
/// ⌃ (`kCGEventFlagMaskControl`).
pub const CONTROL: u64 = 0x0004_0000;
/// ⌥ (`kCGEventFlagMaskAlternate`).
pub const OPTION: u64 = 0x0008_0000;
/// ⌘ (`kCGEventFlagMaskCommand`).
pub const COMMAND: u64 = 0x0010_0000;

/// `kCGEventSourceStatePrivate`.
const PRIVATE_STATE: i32 = -1;
/// `kCGEventSourceStateHIDSystemState`: the physical keys.
const HID_STATE: i32 = 1;
/// `kCGSessionEventTap`.
const SESSION_TAP: u32 = 1;
/// `kCGKeyboardEventKeycode`.
const KEYCODE_FIELD: u32 = 9;
/// `kCGEventSourceStateID`.
const SOURCE_STATE_FIELD: u32 = 45;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSourceCreate(state: i32) -> *mut c_void;
    fn CGEventSourceGetSourceStateID(source: *mut c_void) -> i32;
    fn CGEventSourceFlagsState(state: i32) -> u64;
    fn CGEventCreateKeyboardEvent(source: *mut c_void, key: u16, down: bool) -> *mut c_void;
    fn CGEventSetFlags(event: *mut c_void, flags: u64);
    fn CGEventGetFlags(event: *mut c_void) -> u64;
    fn CGEventKeyboardSetUnicodeString(event: *mut c_void, len: c_ulong, text: *const u16);
    fn CGEventKeyboardGetUnicodeString(
        event: *mut c_void,
        max: c_ulong,
        len: *mut c_ulong,
        text: *mut u16,
    );
    fn CGEventGetIntegerValueField(event: *mut c_void, field: u32) -> i64;
    fn CGEventPost(tap: u32, event: *mut c_void);
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(object: *const c_void);
}

/// A Core Foundation object Larsal owns; released when dropped.
struct Owned(NonNull<c_void>);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Create call, so Larsal holds one
        // reference, and this is its only release.
        unsafe { CFRelease(self.0.as_ptr()) }
    }
}

/// Larsal's private event source (INT-05.43).
pub struct Keyboard(Owned);

/// One keyboard event made by [`Keyboard::event`], not posted.
pub struct Event(Owned);

impl Keyboard {
    /// A private event source; `None` when macOS refuses one.
    #[must_use]
    pub fn new() -> Option<Self> {
        // SAFETY: a plain call with a valid state id; it returns a new
        // source or null.
        let source = unsafe { CGEventSourceCreate(PRIVATE_STATE) };
        NonNull::new(source).map(|s| Self(Owned(s)))
    }

    /// Makes one key event from this source: `code` key-down or key-up
    /// with exactly `flags`, and `text` (at most 2 UTF-16 units: one
    /// character) as its Unicode string when not empty. Posts nothing.
    #[must_use]
    pub fn event(&self, code: u16, flags: u64, down: bool, text: &[u16]) -> Option<Event> {
        // SAFETY: the source is a live CGEventSource; the call returns a new
        // event or null.
        let raw = unsafe { CGEventCreateKeyboardEvent(self.0.0.as_ptr(), code, down) };
        let event = Event(Owned(NonNull::new(raw)?));
        let text = text.get(..text.len().min(2)).unwrap_or(&[]);
        // SAFETY: `event` is live; `text` is valid for reads of `text.len()`
        // units for the call, which copies them.
        unsafe {
            CGEventSetFlags(event.ptr(), flags);
            if !text.is_empty() {
                let len = c_ulong::try_from(text.len()).unwrap_or(0);
                CGEventKeyboardSetUnicodeString(event.ptr(), len, text.as_ptr());
            }
        }
        Some(event)
    }

    /// Makes the event as [`Keyboard::event`] does and posts it to the login
    /// session's keyboard input. Needs the Accessibility permission; without
    /// it macOS drops the event.
    pub fn post(&self, code: u16, flags: u64, down: bool, text: &[u16]) {
        if let Some(event) = self.event(code, flags, down, text) {
            // SAFETY: `event` is live for the call; posting does not take
            // Larsal's reference.
            unsafe { CGEventPost(SESSION_TAP, event.ptr()) }
        }
    }

    /// The source's own state id, which its events carry.
    #[must_use]
    pub fn state_id(&self) -> i32 {
        // SAFETY: the source is live.
        unsafe { CGEventSourceGetSourceStateID(self.0.0.as_ptr()) }
    }
}

impl Event {
    fn ptr(&self) -> *mut c_void {
        self.0.0.as_ptr()
    }

    /// The virtual key code.
    #[must_use]
    pub fn code(&self) -> i64 {
        // SAFETY: the event is live.
        unsafe { CGEventGetIntegerValueField(self.ptr(), KEYCODE_FIELD) }
    }

    /// The modifier flags.
    #[must_use]
    pub fn flags(&self) -> u64 {
        // SAFETY: the event is live.
        unsafe { CGEventGetFlags(self.ptr()) }
    }

    /// The id of the source state it came from.
    #[must_use]
    pub fn source_state(&self) -> i64 {
        // SAFETY: the event is live.
        unsafe { CGEventGetIntegerValueField(self.ptr(), SOURCE_STATE_FIELD) }
    }

    /// Its Unicode string (at most 4 units read).
    #[must_use]
    pub fn text(&self) -> Vec<u16> {
        let mut buf = [0u16; 4];
        let mut len: c_ulong = 0;
        // SAFETY: the event is live; `buf` holds 4 units and the call writes
        // at most `max` = 4 of them, and the count into `len`.
        unsafe { CGEventKeyboardGetUnicodeString(self.ptr(), 4, &mut len, buf.as_mut_ptr()) };
        let n = usize::try_from(len).unwrap_or(0).min(buf.len());
        buf.get(..n).unwrap_or(&[]).to_vec()
    }
}

/// True while ⇧, ⌃, ⌥ or ⌘ is physically held, Caps Lock aside
/// (INT-05.38 step 3). Reads the keyboard's state; posts nothing.
#[must_use]
pub fn modifiers_held() -> bool {
    // SAFETY: a plain call with a valid state id.
    let flags = unsafe { CGEventSourceFlagsState(HID_STATE) };
    flags & (SHIFT | CONTROL | OPTION | COMMAND) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INT-05.43, T102 on the real event type: made, read back, never
    /// posted (AGENTS.md rule 10).
    #[test]
    fn int_05_43_events_come_from_the_private_source_with_their_own_flags() {
        let kb = Keyboard::new().expect("a private event source");
        let v = kb.event(0x09, COMMAND, true, &[]).unwrap();
        assert_eq!((v.code(), v.flags() & 0x00FF_0000), (0x09, COMMAND));
        assert_eq!(v.source_state(), i64::from(kb.state_id()));
        assert!(
            ![0, 1].contains(&kb.state_id()),
            "a private source, not the combined session or HID state"
        );
        // INT-05.40: text with key code 0 and no flags; an emoji as one event.
        let emoji: Vec<u16> = "😀".encode_utf16().collect();
        let t = kb.event(0, 0, false, &emoji).unwrap();
        assert_eq!((t.code(), t.flags() & 0x00FF_0000), (0, 0));
        assert_eq!(t.text(), emoji);
        let e = kb.event(0, 0, true, &[0xE9]).unwrap();
        assert_eq!(e.text(), [0xE9]);
        let shifted = kb.event(0x0B, SHIFT | OPTION, true, &[]).unwrap();
        assert_eq!(shifted.flags() & 0x00FF_0000, SHIFT | OPTION);
    }
}
