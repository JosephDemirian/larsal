//! Copy and timed clear (APP-03, SC-01 to SC-03): the one copy routine of
//! the Mac app (through `larsal-ffi`) and the command line tool (SC-07,
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
//! Larsal cannot wipe (SR-07); a killed Larsal leaves its copy (APP-03.16).

use crate::macos::pasteboard;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// One pasteboard and Larsal's copy on it.
pub struct Clipboard {
    inner: Arc<Inner>,
}

struct Inner {
    /// `None`: the general pasteboard; else a private named one.
    name: Option<String>,
    state: Mutex<State>,
    /// Tests only (F-439): a clock the test moves by hand for the
    /// countdown; `None` is the Mac's clock. A release build has no field.
    #[cfg(test)]
    manual: Option<tests::Manual>,
}

#[derive(Default)]
struct State {
    /// The change count right after Larsal's last write, while it is tracked.
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

    /// True when Larsal's copy was still there and is now gone.
    fn clear(&self, state: &mut State) -> bool {
        let emptied = state
            .owned
            .take()
            .is_some_and(|count| pasteboard::clear_if(self.name.as_deref(), count));
        state.countdown = state.countdown.wrapping_add(1);
        state.deadline = None;
        emptied
    }

    /// Now, on the countdown's clock: the Mac's (in tests, a manual clock
    /// when one is set).
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = &self.manual {
            return clock.now();
        }
        Instant::now()
    }

    /// The countdown's wait: `after` on the Mac's clock (in tests, until a
    /// manual clock is moved `after` past its time now).
    fn sleep(&self, after: Duration) {
        #[cfg(test)]
        if let Some(clock) = &self.manual {
            clock.sleep(after);
            return;
        }
        thread::sleep(after);
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
            "app.larsal.clipboard.{}.{n}",
            std::process::id()
        )))
    }

    /// The name of this clipboard's private pasteboard; `None` for the
    /// general pasteboard.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.inner.name.as_deref()
    }

    /// LD-206: the name of every pasteboard Larsal wrote or cleared in this
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
                #[cfg(test)]
                manual: None,
            }),
        }
    }

    /// Puts `value` on the pasteboard as Larsal's tracked copy (APP-03.2): one
    /// item with the text and both markers, current host only. With
    /// `clear_after`, a countdown starts (a running one is replaced) and
    /// [`Clipboard::clear`] runs when it ends; with `None` the copy stays
    /// until a clear. `value` is written as given, also when empty; the
    /// caller decides what an empty value means (APP-03.5).
    ///
    /// # Errors
    /// The system refused the write, or the countdown could not start; then
    /// nothing of Larsal's is on the pasteboard and no countdown runs
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
        state.deadline = self.inner.now().checked_add(after);
        let (inner, countdown) = (Arc::clone(&self.inner), state.countdown);
        let started = thread::Builder::new()
            .name("clipboard clear".into())
            .spawn(move || {
                inner.sleep(after);
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

    /// APP-03.12: empties the pasteboard if it still holds Larsal's copy (same
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
            let left = d.saturating_duration_since(self.inner.now());
            left.as_secs() + u64::from(left.subsec_nanos() > 0)
        })
    }

    /// Tests only: each item on a private clipboard's pasteboard, as its
    /// types with their data. Empty for the general pasteboard: Larsal never
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
    use std::sync::Condvar;

    /// F-439: a clock that stands still until the test moves it. The
    /// countdown's wait ends only once the clock passes its end, however
    /// late a busy Mac runs the threads; the clock knows the ends of the
    /// waits in progress, so a test can tell when every countdown whose end
    /// has come has acted (`settle`).
    pub(super) struct Manual {
        zero: Instant,
        waits: Mutex<Waits>,
        moved: Condvar,
    }

    #[derive(Default)]
    struct Waits {
        /// The clock's time, from `zero`.
        now: Duration,
        /// The end of each wait in progress, from `zero`.
        ends: Vec<Duration>,
    }

    impl Manual {
        fn waits(&self) -> MutexGuard<'_, Waits> {
            self.waits.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub(super) fn now(&self) -> Instant {
            self.zero + self.waits().now
        }

        /// Waits until the clock is `after` past its time now.
        pub(super) fn sleep(&self, after: Duration) {
            let mut w = self.waits();
            let end = w.now + after;
            w.ends.push(end);
            while w.now < end {
                w = self.moved.wait(w).unwrap_or_else(PoisonError::into_inner);
            }
            let at = w.ends.iter().position(|e| *e == end).unwrap();
            w.ends.swap_remove(at);
        }

        fn set(&self, to: Duration) {
            let mut w = self.waits();
            assert!(to >= w.now, "the clock only moves on");
            w.now = to;
            self.moved.notify_all();
        }

        /// The waits whose end has not come.
        fn ahead(&self) -> usize {
            let w = self.waits();
            w.ends.iter().filter(|e| **e > w.now).count()
        }
    }

    /// A private clipboard whose countdown runs on a manual clock at 0.
    fn manual() -> Clipboard {
        let name = Clipboard::private().name().map(str::to_owned);
        Clipboard {
            inner: Arc::new(Inner {
                name,
                state: Mutex::default(),
                manual: Some(Manual {
                    zero: Instant::now(),
                    waits: Mutex::default(),
                    moved: Condvar::new(),
                }),
            }),
        }
    }

    /// Waits until every countdown whose end has come on the manual clock
    /// has acted: each countdown's thread holds the clipboard's state until
    /// it is done, so the threads still alive must be exactly the waits
    /// whose end is ahead (a thread not yet waiting counts as not done).
    /// The wall clock only ends a hang, after 30 s: a busy Mac can delay
    /// the countdown's thread, never move its end.
    fn settle(c: &Clipboard) {
        let clock = c.inner.manual.as_ref().unwrap();
        let start = Instant::now();
        while Arc::strong_count(&c.inner) - 1 != clock.ahead() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "a countdown hangs"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Moves the manual clock to `ms` after the start and settles.
    fn at(c: &Clipboard, ms: u64) {
        settle(c);
        c.inner
            .manual
            .as_ref()
            .unwrap()
            .set(Duration::from_millis(ms));
        settle(c);
    }

    /// The text item of a peek, if the pasteboard holds exactly one item.
    fn text(c: &Clipboard) -> Option<String> {
        text_in(&c.peek())
    }

    fn text_in(items: &[Vec<(String, Vec<u8>)>]) -> Option<String> {
        let [item] = items else {
            return None;
        };
        let (_, data) = item.iter().find(|(kind, _)| kind == TEXT)?;
        Some(String::from_utf8(data.clone()).unwrap())
    }

    /// F-439: when the countdown of a copy just made ends, measured from the
    /// copy. The countdown keeps its end (`deadline`), set after the
    /// pasteboard write, and its clear thread sleeps `after` from a later
    /// moment, so no clear comes before it; however long a busy Mac took to
    /// write. `start` is read just before the copy, so `start + after` is
    /// the earliest end there can be: the later of the two holds even if
    /// the kept end were wrong.
    fn countdown_end(c: &Clipboard, start: Instant, after: Duration) -> Instant {
        let kept = c.inner.state().deadline;
        kept.map_or(start + after, |d| d.max(start + after))
    }

    /// F-439: watches a copy of `value` whose countdown ends at `end`
    /// (`countdown_end`), `start` read just before the copy. Every check
    /// that ends before `end` must see the copy, however late a busy Mac
    /// runs it. Then it waits for the clear itself, which a busy Mac can
    /// only delay, for up to 30 s from `start`: only a clear that never
    /// comes misses that. A check during the clear can see the item without
    /// its data, so after the end only the empty pasteboard counts. Returns
    /// how many checks ended before the end and when the clear was seen.
    fn watch_countdown(
        c: &Clipboard,
        value: &str,
        start: Instant,
        end: Instant,
    ) -> (usize, Duration) {
        let mut before = 0;
        loop {
            let items = c.peek();
            let now = Instant::now();
            let at = now - start;
            if now < end {
                let seen = text_in(&items);
                assert_eq!(seen.as_deref(), Some(value), "{at:?} in, before the end");
                before += 1;
            } else if items.is_empty() {
                return (before, at);
            }
            assert!(at < Duration::from_secs(30), "no clear {at:?} in");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// LD-206: Larsal's own record names the private pasteboard a copy and
    /// its clear went to, and holds no other kind of pasteboard.
    #[test]
    fn ld_206_the_record_names_only_private_pasteboards() {
        let c = Clipboard::private();
        let name = c.name().unwrap().to_owned();
        c.copy("demo-pass-1", None).unwrap();
        assert!(c.clear());
        let written = Clipboard::written();
        assert!(written.contains(&name), "{written:?}");
        let private = format!("app.larsal.clipboard.{}.", std::process::id());
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
    /// leaves nothing of Larsal's behind: the older copy is cleared, not left
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

    /// APP-03.11, T18 on the manual clock (F-439): a 10 s countdown still
    /// holds the copy at t = 9.5 and has cleared it by t = 10.5.
    #[test]
    fn countdown_clears() {
        let c = manual();
        c.copy("demo-pass-1", Some(Duration::from_secs(10)))
            .unwrap();
        at(&c, 9_500);
        assert_eq!(text(&c).as_deref(), Some("demo-pass-1"), "t = 9.5");
        at(&c, 10_500);
        assert!(c.peek().is_empty(), "t = 10.5");
    }

    /// APP-03.11, T19 on the manual clock (F-439): a copy at 0, a new copy
    /// at 4; at t = 10 the first countdown's end leaves the new copy, which
    /// is still there at 13.5 and gone by 14.5.
    #[test]
    fn new_copy_restarts_countdown() {
        let c = manual();
        let after = Some(Duration::from_secs(10));
        c.copy("demo-pass-1", after).unwrap();
        at(&c, 4_000);
        c.copy("demo@example.com", after).unwrap();
        at(&c, 10_000);
        assert_eq!(text(&c).as_deref(), Some("demo@example.com"), "t = 10");
        at(&c, 13_500);
        assert_eq!(text(&c).as_deref(), Some("demo@example.com"), "t = 13.5");
        at(&c, 14_500);
        assert!(c.peek().is_empty(), "t = 14.5");
    }

    /// APP-03.11 on the Mac's clock (F-439): the order of events, which no
    /// manual clock shows. Every check that ends before the countdown's end
    /// sees the copy, however late a busy Mac runs it; the clear comes
    /// after, within a 30 s backstop.
    #[test]
    fn countdown_clears_on_the_mac_clock() {
        let c = Clipboard::private();
        let after = Duration::from_millis(800);
        let start = Instant::now();
        c.copy("demo-pass-1", Some(after)).unwrap();
        let end = countdown_end(&c, start, after);
        let (before, cleared) = watch_countdown(&c, "demo-pass-1", start, end);
        eprintln!(
            "the countdown ends {:?} in; {before} checks before the end; cleared {cleared:?} in",
            end - start
        );
    }

    /// APP-03.12, T21 on the manual clock (F-439): a countdown that ends
    /// after another app wrote leaves its content.
    #[test]
    fn countdown_leaves_newer_content() {
        let c = manual();
        c.copy("demo-pass-1", Some(Duration::from_secs(10)))
            .unwrap();
        c.write_as_other_app("other");
        at(&c, 10_500);
        assert_eq!(text(&c).as_deref(), Some("other"));
    }

    /// APP-03.12, APP-03.15 on the manual clock (F-439): a clear (as on
    /// lock) stops the countdown, so a later copy is not cut short by it.
    #[test]
    fn clear_stops_countdown() {
        let c = manual();
        c.copy("demo-pass-1", Some(Duration::from_secs(10)))
            .unwrap();
        c.clear();
        assert!(c.peek().is_empty());
        c.copy("demo@example.com", None).unwrap();
        at(&c, 10_500);
        assert_eq!(text(&c).as_deref(), Some("demo@example.com"));
    }

    /// F-078, APP-03.11 (T20 remaining) on the manual clock (F-439): the countdown's
    /// seconds left, rounded up; none without a countdown, after the clear
    /// and after the end.
    #[test]
    fn f_078_seconds_left_follows_the_countdown() {
        let c = manual();
        c.copy("demo-pass-1", None).unwrap();
        assert_eq!(c.seconds_left(), 0, "no countdown");
        c.copy("demo-pass-1", Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(c.seconds_left(), 10, "t = 0");
        at(&c, 3_200);
        assert_eq!(c.seconds_left(), 7, "T20: t = 3.2");
        c.clear();
        assert_eq!(c.seconds_left(), 0, "cleared");
        c.copy("demo-pass-1", Some(Duration::from_millis(300)))
            .unwrap();
        assert_eq!(c.seconds_left(), 1, "rounded up");
        at(&c, 3_499);
        assert_eq!(c.seconds_left(), 1, "1 ms left");
        at(&c, 3_500);
        assert_eq!(c.seconds_left(), 0, "ended");
    }
}
