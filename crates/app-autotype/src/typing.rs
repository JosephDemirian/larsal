//! Typing a checked [`Plan`] (E8-S3, INT-05.38 to INT-05.43): its actions
//! become key events through a [`KeySink`]. App's sink is macOS's keyboard
//! input (app-ffi over app-platform); tests use a [`Recorder`], which posts
//! nothing and keeps a fake clock (AGENTS.md rule 10).
//!
//! Guarantees:
//! - Nothing goes out before `go_on` says the target is in front (asked
//!   every 50 ms, at most 2 s), the start delay has passed and no modifier
//!   key is held (asked every 50 ms, at most 2 s more); a run that cannot
//!   start types nothing (INT-05.38 steps 1 to 3).
//! - `go_on` is asked before every key press and the run ends at its first
//!   no: no further event goes out (AT-G02, INT-05.39). A press is a key-down
//!   and its key-up, posted together, so a stop never leaves a key held.
//! - Text: one key-down and key-up per character, carrying the character as
//!   its Unicode string (both UTF-16 units of one outside the Basic
//!   Multilingual Plane in one event), key code 0, no flags (INT-05.40). In
//!   key-code mode, the layout's key and modifiers for the character, else
//!   as text (INT-05.41). Named keys and key combinations: their key code
//!   with the token's flags (INT-05.42).
//! - The key pause follows every press, `{DELAY n}` waits, `{DELAY=n}` sets
//!   the pause; `{TOTP}` is computed from the sink's clock when typing
//!   reaches it (D-INT05-8).
//! - A plan with picks still to fill types nothing (D-INT05-9).
//! - The plan's bounds hold (INT-05.16), so a run always ends.
//!
//! A character goes from the plan's `SecretString` into the event only;
//! the [`Recorder`] keeps what it saw in `SecretString`s too (Rust rule 3).

use crate::{Action, Layout, Mods, Plan};
use app_crypto::secret::SecretString;
use app_model::Time;

/// The longest wait for the target to be in front, and then for the
/// modifier keys to be let go, in ms (INT-05.38).
pub const READY_MS: u32 = 2_000;
/// How often those two are asked, in ms.
pub const POLL_MS: u32 = 50;

/// One keyboard event (INT-05.40 to INT-05.43).
#[derive(Debug, Clone, Copy)]
pub struct Event<'a> {
    /// The virtual key code; 0 for text.
    pub code: u16,
    /// The modifier flags the event carries, set explicitly.
    pub mods: Mods,
    /// Key-down, else key-up.
    pub down: bool,
    /// The character a text event carries (one or two UTF-16 units);
    /// empty for a key press.
    pub text: &'a [u16],
}

/// Where key events go, and the clock that typing waits on.
pub trait KeySink {
    /// Posts one event.
    fn post(&mut self, event: &Event<'_>);
    /// Waits `ms` milliseconds.
    fn wait(&mut self, ms: u32);
    /// True while ⇧, ⌃, ⌥ or ⌘ is physically held, Caps Lock aside
    /// (INT-05.38 step 3).
    fn modifiers_held(&mut self) -> bool;
    /// Now, for `{TOTP}` (D-INT05-8).
    fn now(&self) -> Time;
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typed {
    /// Every key went out; the number of presses.
    Finished(usize),
    /// The run stopped after this many presses: the system alert sound
    /// (INT-05.38, INT-05.39), or nothing at all for [`Stop::Picks`].
    Stopped(usize, Stop),
}

/// Why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The target was not in front within 2 s (INT-05.38 step 1).
    NotInFront,
    /// A modifier key was still held 2 s after the start delay (step 3).
    Held,
    /// `go_on` said no before a key: another app or window in front, a
    /// lock, the shortcut again (INT-05.39).
    Changed,
    /// The plan still has picks to fill (INT-05.10): nothing was typed.
    Picks,
}

/// Types `plan` into `sink` (INT-05.38 to INT-05.43). `go_on` answers,
/// before the run and before every key press, whether the captured app and
/// window are still in front and the run was not stopped.
pub fn type_plan(plan: &Plan, sink: &mut dyn KeySink, go_on: &mut dyn FnMut() -> bool) -> Typed {
    if !plan.picks().is_empty() {
        return Typed::Stopped(0, Stop::Picks);
    }
    // INT-05.38 step 1: the target in front (made active by the caller).
    if !ready(sink, &mut |_| go_on()) {
        return Typed::Stopped(0, Stop::NotInFront);
    }
    // Step 2, then step 3: the user may still hold the shortcut's keys.
    sink.wait(plan.start_delay_ms);
    if !ready(sink, &mut |s| !s.modifiers_held()) {
        return Typed::Stopped(0, Stop::Held);
    }
    let mut t = Typer {
        sink,
        go_on,
        layout: &plan.layout,
        pause: plan.key_pause_ms,
        keys: 0,
    };
    match t.run(plan) {
        Ok(()) => Typed::Finished(t.keys),
        Err(stop) => Typed::Stopped(t.keys, stop),
    }
}

/// Asks `test` every [`POLL_MS`] until it holds, at most [`READY_MS`].
fn ready(sink: &mut dyn KeySink, test: &mut dyn FnMut(&mut dyn KeySink) -> bool) -> bool {
    let mut waited = 0u32;
    while !test(sink) {
        if waited >= READY_MS {
            return false;
        }
        sink.wait(POLL_MS);
        waited = waited.saturating_add(POLL_MS);
    }
    true
}

struct Typer<'t> {
    sink: &'t mut dyn KeySink,
    go_on: &'t mut dyn FnMut() -> bool,
    layout: &'t Layout,
    pause: u32,
    keys: usize,
}

impl Typer<'_> {
    fn run(&mut self, plan: &Plan) -> Result<(), Stop> {
        for action in plan.actions() {
            match action {
                Action::Text { text, by_key } => self.text(text, *by_key)?,
                Action::Key { code, mods } => self.press(*code, *mods, &[])?,
                Action::Wait(ms) => self.wait(*ms),
                Action::Pause(ms) => self.pause = *ms,
                Action::Otp { by_key } => {
                    if let Some(code) = plan.otp_code(self.sink.now()) {
                        self.text(&code, *by_key)?;
                    }
                }
                // Filled before typing (`type_plan` refuses a plan with one).
                Action::Pick { .. } => {}
            }
        }
        Ok(())
    }

    fn wait(&mut self, ms: u32) {
        if ms > 0 {
            self.sink.wait(ms);
        }
    }

    /// One key-down and its key-up after the check, then the key pause.
    fn press(&mut self, code: u16, mods: Mods, text: &[u16]) -> Result<(), Stop> {
        if !(self.go_on)() {
            return Err(Stop::Changed);
        }
        for down in [true, false] {
            self.sink.post(&Event {
                code,
                mods,
                down,
                text,
            });
        }
        self.keys = self.keys.saturating_add(1);
        self.wait(self.pause);
        Ok(())
    }

    /// INT-05.40 and INT-05.41.
    fn text(&mut self, text: &SecretString, by_key: bool) -> Result<(), Stop> {
        for c in text.expose().chars() {
            match self.layout.key(c).filter(|_| by_key) {
                Some((code, mods)) => self.press(code, mods, &[])?,
                None => self.press(0, Mods::NONE, c.encode_utf16(&mut [0; 2]))?,
            }
        }
        Ok(())
    }
}

/// One event a [`Recorder`] saw.
#[derive(Debug)]
pub struct Recorded {
    /// Its time on the fake clock, ms.
    pub at_ms: u64,
    /// Key-down, else key-up.
    pub down: bool,
    /// The key code (0 for text).
    pub code: u16,
    /// Its modifier flags.
    pub mods: Mods,
    /// The character it carries; empty for a key press.
    pub text: SecretString,
}

/// A [`KeySink`] that posts nothing: it records every event on a fake
/// clock, and waits take no real time. Tests use it, and App whenever
/// posting is off (a test or hidden launch, AGENTS.md rule 10).
#[derive(Debug, Default)]
pub struct Recorder {
    /// The clock's start, for `{TOTP}`: the time at `clock_ms` 0.
    pub start: Time,
    /// Ms on the fake clock.
    pub clock_ms: u64,
    /// The modifier keys stay held until the clock reaches this.
    pub held_until_ms: u64,
    /// What was posted, in order.
    pub events: Vec<Recorded>,
}

impl Recorder {
    /// A recorder whose clock starts at `start`.
    #[must_use]
    pub fn new(start: Time) -> Self {
        Self {
            start,
            ..Self::default()
        }
    }
}

impl KeySink for Recorder {
    fn post(&mut self, e: &Event<'_>) {
        self.events.push(Recorded {
            at_ms: self.clock_ms,
            down: e.down,
            code: e.code,
            mods: e.mods,
            text: SecretString::new(String::from_utf16_lossy(e.text)),
        });
    }

    fn wait(&mut self, ms: u32) {
        self.clock_ms = self.clock_ms.saturating_add(u64::from(ms));
    }

    fn modifiers_held(&mut self) -> bool {
        self.clock_ms < self.held_until_ms
    }

    fn now(&self) -> Time {
        let secs = i64::try_from(self.clock_ms / 1_000).unwrap_or(i64::MAX);
        Time(self.start.0.saturating_add(secs))
    }
}
