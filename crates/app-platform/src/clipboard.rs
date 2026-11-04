//! Copy and timed clear (APP-03, SC-01 to SC-03): the one copy routine of
//! the Mac app (through `app-ffi`) and the command line tool (SC-07,
//! APP-03.20).
//!
//! Guarantees:
//! - a copy replaces the pasteboard's content with one item: the text plus
//!   the nspasteboard.org markers `org.nspasteboard.ConcealedType` and
//!   `org.nspasteboard.TransientType` (empty data), current host only
//!   (APP-03.9);
//! - only the change count after the write is kept, never the value, and the
//!   pasteboard is never read back (APP-03.10);
//! - a clear (end of the countdown, lock, quit) empties the pasteboard only
//!   while its change count is still the recorded one, so anything the user
//!   or another app put there since stays (APP-03.12, AT-D02); then the count
//!   is forgotten and the countdown stops;
//! - a new copy restarts the countdown (APP-03.11).
//!
//! The command line tool copies with `Clipboard::general().copy(value,
//! None)`, waits its own delay (cut short by a quit signal), then calls
//! [`Clipboard::clear`], whose answer says whether the copy was still there.
//!
//! Limits: the text also passes through an `NSString` in system memory that
//! App cannot wipe (SR-07); a killed App leaves its copy (APP-03.16).

use crate::macos::pasteboard;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// One pasteboard and App's copy on it.
pub struct Clipboard {
    inner: Arc<Inner>,
}

struct Inner {
    /// `None`: the general pasteboard; else a private named one.
    name: Option<String>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The change count right after App's last write, while it is tracked.
    owned: Option<isize>,
    /// Bumped by every copy and clear, so an older countdown does nothing.
    countdown: u64,
    /// When the running countdown ends (APP-02.8 `r`, F-078).
    deadline: Option<Instant>,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// True when App's copy was still there and is now gone.
    fn clear(&self, state: &mut State) -> bool {
        let emptied = state
            .owned
            .take()
            .is_some_and(|count| pasteboard::clear_if(self.name.as_deref(), count));
        state.countdown = state.countdown.wrapping_add(1);
        state.deadline = None;
        emptied
    }
}

impl Clipboard {
    /// The Mac's general pasteboard: the one other apps paste from.
    #[must_use]
    pub fn general() -> Self {
        Self::on(None)
    }

    /// A private pasteboard of this process, never the user's clipboard:
    /// for tests. A fresh name each time.
    #[must_use]
    pub fn private() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self::on(Some(format!(
            "com.app.clipboard.{}.{n}",
            std::process::id()
        )))
    }

    /// The name of this clipboard's private pasteboard; `None` for the
    /// general pasteboard.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.inner.name.as_deref()
    }

    /// LD-206: the name of every pasteboard App wrote or cleared in this
    /// process, in order; names only. Tests assert it holds only private
    /// pasteboards, never the general one (AGENTS.md rule 10).
    #[must_use]
    pub fn written() -> Vec<String> {
        pasteboard::written()
    }

    fn on(name: Option<String>) -> Self {
        Self {
            inner: Arc::new(Inner {
                name,
                state: Mutex::default(),
            }),
        }
    }

    /// Puts `value` on the pasteboard as App's tracked copy (APP-03.2): one
    /// item with the text and both markers, current host only. With
    /// `clear_after`, a countdown starts (a running one is replaced) and
    /// [`Clipboard::clear`] runs when it ends; with `None` the copy stays
    /// until a clear. `value` is written as given, also when empty; the
    /// caller decides what an empty value means (APP-03.5).
    ///
    /// # Errors
    /// The system refused the write, or the countdown could not start; then
    /// nothing of App's is on the pasteboard and no countdown runs
    /// (APP-03.21 `MSG-COPY-FAILED`).
    pub fn copy(&self, value: &str, clear_after: Option<Duration>) -> io::Result<()> {
        let mut state = self.inner.state();
        // The old copy goes first, while it is still ours: a write that fails
        // must not leave it on the pasteboard untracked (SC-03, APP-03.15).
        let _ = self.inner.clear(&mut state);
        state.owned = pasteboard::write(self.inner.name.as_deref(), value);
        if state.owned.is_none() {
            return Err(io::Error::other("the pasteboard refused the copy"));
        }
        let Some(after) = clear_after else {
            return Ok(());
        };
        state.deadline = Instant::now().checked_add(after);
        let (inner, countdown) = (Arc::clone(&self.inner), state.countdown);
        let started = thread::Builder::new()
            .name("clipboard clear".into())
            .spawn(move || {
                thread::sleep(after);
                let mut state = inner.state();
                if state.countdown == countdown {
                    let _ = inner.clear(&mut state);
                }
            });
        if let Err(e) = started {
            let _ = self.inner.clear(&mut state);
            return Err(e);
        }
        Ok(())
    }

    /// APP-03.12: empties the pasteboard if it still holds App's copy (same
    /// change count), else leaves it alone; then forgets the copy and stops
    /// the countdown. Does nothing when no copy is tracked. For lock, close
    /// and quit (APP-03.15). Returns true only when it emptied the
    /// pasteboard: false when another app's newer content was left, or no
    /// copy was tracked (the command line's M10-70 picks its form by it).
    pub fn clear(&self) -> bool {
        self.inner.clear(&mut self.inner.state())
    }

    /// APP-02.8 `r` (F-078): whole seconds left, rounded up, on the running
    /// countdown; 0 when none runs.
    #[must_use]
    pub fn seconds_left(&self) -> u64 {
        self.inner.state().deadline.map_or(0, |d| {
            let left = d.saturating_duration_since(Instant::now());
            left.as_secs() + u64::from(left.subsec_nanos() > 0)
        })
    }

    /// Tests only: each item on a private clipboard's pasteboard, as its
    /// types with their data. Empty for the general pasteboard: App never
    /// reads the user's clipboard (APP-03.10).
    #[doc(hidden)]
    #[must_use]
    pub fn peek(&self) -> Vec<Vec<(String, Vec<u8>)>> {
        self.inner
            .name
            .as_deref()
            .map(pasteboard::items)
            .unwrap_or_default()
    }

    /// Tests only: writes `text` to a private clipboard's pasteboard as
    /// another app would (plain text, no marker, not tracked). Does nothing
    /// to the general pasteboard.
    #[doc(hidden)]
    pub fn write_as_other_app(&self, text: &str) {
        if let Some(name) = &self.inner.name {
            pasteboard::write_plain(name, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::pasteboard::{CONCEALED, TEXT, TRANSIENT};

    /// The text item of a peek, if the pasteboard holds exactly one item.
    fn text(c: &Clipboard) -> Option<String> {
        let items = c.peek();
        let [item] = items.as_slice() else {
            return None;
        };
        let (_, data) = item.iter().find(|(kind, _)| kind == TEXT)?;
        Some(String::from_utf8(data.clone()).unwrap())
    }

    fn sleep_until(start: Instant, ms: u64) {
        let at = start + Duration::from_millis(ms);
        thread::sleep(at.saturating_duration_since(Instant::now()));
    }

    /// LD-206: App's own record names the private pasteboard a copy and
    /// its clear went to, and holds no other kind of pasteboard.
    #[test]
    fn ld_206_the_record_names_only_private_pasteboards() {
        let c = Clipboard::private();
        let name = c.name().unwrap().to_owned();
        c.copy("demo-pass-1", None).unwrap();
        assert!(c.clear());
        let written = Clipboard::written();
        assert!(written.contains(&name), "{written:?}");
        let private = format!("com.app.clipboard.{}.", std::process::id());
        assert!(
            written.iter().all(|n| n.starts_with(&private)),
            "{written:?}"
        );
        assert_eq!(Clipboard::general().name(), None);
    }

    /// APP-03.9, T16, SC-02: one item, the text and both empty markers.
    #[test]
    fn copy_writes_text_and_both_markers() {
        let c = Clipboard::private();
        c.copy("demo-pass-1", None).unwrap();
        let items = c.peek();
        assert_eq!(items.len(), 1, "one item");
        let mut types: Vec<&str> = items[0].iter().map(|(k, _)| k.as_str()).collect();
        types.sort_unstable();
        assert_eq!(types, [CONCEALED, TRANSIENT, TEXT]);
        for (kind, data) in &items[0] {
            let want: &[u8] = if kind == TEXT { b"demo-pass-1" } else { b"" };
            assert_eq!(data, want, "{kind}");
        }
        // Line breaks and non-ASCII text are copied exactly, as UTF-8.
        c.copy("zeile 1\nzweite Zeile é ✓", None).unwrap();
        assert_eq!(text(&c).as_deref(), Some("zeile 1\nzweite Zeile é ✓"));
        c.clear();
        assert!(c.peek().is_empty());
    }

    /// APP-03.10, APP-03.12, T21, T22, T30, AT-D02: a clear leaves newer
    /// content alone, even the same text, because the change count differs.
    #[test]
    fn clear_only_while_still_ours() {
        let c = Clipboard::private();
        c.copy("demo-pass-1", None).unwrap();
        c.write_as_other_app("other");
        assert!(!c.clear(), "newer content: not emptied");
        assert_eq!(text(&c).as_deref(), Some("other"));
        c.copy("demo-pass-1", None).unwrap();
        c.write_as_other_app("demo-pass-1");
        assert!(!c.clear());
        assert_eq!(text(&c).as_deref(), Some("demo-pass-1"), "same text, newer");
        // Nothing tracked: a clear touches nothing.
        assert!(!c.clear());
        assert_eq!(text(&c).as_deref(), Some("demo-pass-1"));
        // Ours: cleared, all types gone.
        c.copy("demo-pass-1", None).unwrap();
        assert!(c.clear(), "ours: emptied");
        assert!(c.peek().is_empty());
    }

    /// SC-03, APP-03.15, APP-03.21 (LD-170 (1)): a copy the system refuses
    /// leaves nothing of App's behind: the older copy is cleared, not left
    /// untracked; another app's newer content stays.
    #[test]
    fn refused_copy_leaves_nothing_of_ours() {
        let refused = |c: &Clipboard| {
            pasteboard::REFUSE_WRITE.set(true);
            let result = c.copy("demo@example.com", None);
            pasteboard::REFUSE_WRITE.set(false);
            assert!(result.is_err());
        };
        let c = Clipboard::private();
        c.copy("demo-pass-1", Some(Duration::from_secs(60)))
            .unwrap();
        refused(&c);
        assert!(c.peek().is_empty(), "old copy cleared");
        c.copy("demo-pass-1", None).unwrap();
        c.write_as_other_app("other");
        refused(&c);
        assert_eq!(text(&c).as_deref(), Some("other"));
    }

    /// APP-03.11, T18: cleared when the countdown ends, not before.
    #[test]
    fn countdown_clears() {
        let c = Clipboard::private();
        let start = Instant::now();
        c.copy("demo-pass-1", Some(Duration::from_millis(800)))
            .unwrap();
        sleep_until(start, 400);
        assert_eq!(text(&c).as_deref(), Some("demo-pass-1"));
        sleep_until(start, 1600);
        assert!(c.peek().is_empty());
    }

    /// APP-03.11, T19: a new copy restarts the countdown; the first one's
    /// end does nothing.
    #[test]
    fn new_copy_restarts_countdown() {
        let c = Clipboard::private();
        let start = Instant::now();
        let after = Some(Duration::from_millis(800));
        c.copy("demo-pass-1", after).unwrap();
        sleep_until(start, 400);
        c.copy("demo@example.com", after).unwrap();
        sleep_until(start, 1000);
        assert_eq!(text(&c).as_deref(), Some("demo@example.com"));
        sleep_until(start, 2000);
        assert!(c.peek().is_empty());
    }

    /// APP-03.12, T21: a countdown that ends after another app wrote leaves
    /// its content.
    #[test]
    fn countdown_leaves_newer_content() {
        let c = Clipboard::private();
        let start = Instant::now();
        c.copy("demo-pass-1", Some(Duration::from_millis(600)))
            .unwrap();
        c.write_as_other_app("other");
        sleep_until(start, 1400);
        assert_eq!(text(&c).as_deref(), Some("other"));
    }

    /// APP-03.12, APP-03.15: a clear (as on lock) stops the countdown, so a
    /// later copy is not cut short by it.
    #[test]
    fn clear_stops_countdown() {
        let c = Clipboard::private();
        let start = Instant::now();
        c.copy("demo-pass-1", Some(Duration::from_millis(600)))
            .unwrap();
        c.clear();
        assert!(c.peek().is_empty());
        c.copy("demo@example.com", None).unwrap();
        sleep_until(start, 1200);
        assert_eq!(text(&c).as_deref(), Some("demo@example.com"));
    }

    /// F-078, APP-02.8: the countdown's seconds left, rounded up; none
    /// without a countdown, after the clear and after the end.
    #[test]
    fn f_078_seconds_left_follows_the_countdown() {
        let c = Clipboard::private();
        c.copy("demo-pass-1", None).unwrap();
        assert_eq!(c.seconds_left(), 0, "no countdown");
        c.copy("demo-pass-1", Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(c.seconds_left(), 10);
        c.clear();
        assert_eq!(c.seconds_left(), 0, "cleared");
        let start = Instant::now();
        c.copy("demo-pass-1", Some(Duration::from_millis(300)))
            .unwrap();
        assert_eq!(c.seconds_left(), 1, "rounded up");
        sleep_until(start, 900);
        assert_eq!(c.seconds_left(), 0, "ended");
    }
}
