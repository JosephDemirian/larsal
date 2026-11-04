//! E8-S3 wiring (spec INT-05.37 to INT-05.46): the plan typed through
//! app-autotype's `type_plan`, with macOS's keyboard input as the sink
//! (app-platform `macos::keyboard`), the keyboard layout table from Swift,
//! and the run's stop flag.
//!
//! Guarantees (INT-05.45, D-INT05-15, AGENTS.md rules 4 and 10):
//! - every key event, the ones that carry secret characters included, is
//!   made and posted here in Rust; Swift sends only the layout table (no
//!   secret) and answers the window check;
//! - events reach macOS only after [`Session::autotype_post_events`], which
//!   App calls in its own launch and never in a hidden or test launch;
//!   otherwise a [`Recorder`] takes them on a fake clock and drops them,
//!   wiped, when the run ends;
//! - a lock, lock-all, close or [`Session::autotype_stop`] sets the run's
//!   stop flag: no key goes out after it, and waits end early (INT-05.39).

use crate::autotype::{AutoTypeEnd, AutoTypeFocus};
use crate::instance;
use crate::session::Session;
use crate::views;
use app_autotype::{Event, KeySink, Layout, Mods, Plan, Recorder, Stop, Typed, type_plan};
use app_model::Time;
use app_platform::macos::keyboard::{self, Keyboard};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// One key of the current keyboard layout (INT-05.41, INT-05.45): the
/// character it types with one press and the modifiers that press needs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutoTypeKey {
    /// One character.
    pub character: String,
    /// The virtual key code.
    pub code: u16,
    /// ⇧.
    pub shift: bool,
    /// ⌥.
    pub option: bool,
}

/// At most this many keys of a layout are read (128 key codes, 4 forms).
const MAX_LAYOUT_KEYS: usize = 4_096;

/// The longest slice of a wait between two looks at the stop flag, ms.
const WAIT_SLICE_MS: u32 = 20;

/// macOS's keyboard input, with the run's stop flag.
struct Quartz {
    keyboard: Keyboard,
    stop: Arc<AtomicBool>,
}

/// The Quartz flags of `mods`, those bits and no other (INT-05.43).
fn cg_flags(mods: Mods) -> u64 {
    [
        (Mods::SHIFT, keyboard::SHIFT),
        (Mods::CONTROL, keyboard::CONTROL),
        (Mods::OPTION, keyboard::OPTION),
        (Mods::COMMAND, keyboard::COMMAND),
    ]
    .iter()
    .filter(|(m, _)| mods.contains(*m))
    .fold(0, |f, (_, bit)| f | bit)
}

impl KeySink for Quartz {
    fn post(&mut self, e: &Event<'_>) {
        self.keyboard.post(e.code, cg_flags(e.mods), e.down, e.text);
    }

    fn wait(&mut self, ms: u32) {
        wait_unless_stopped(&self.stop, ms);
    }

    fn modifiers_held(&mut self) -> bool {
        keyboard::modifiers_held()
    }

    fn now(&self) -> Time {
        views::now()
    }
}

/// Sleeps `ms` in short slices and ends early once `stop` is up (LD-231
/// (3)): a lock or the shortcut ends even the longest wait at once.
fn wait_unless_stopped(stop: &AtomicBool, ms: u32) {
    let mut left = ms;
    while left > 0 && !stop.load(Ordering::SeqCst) {
        let slice = left.min(WAIT_SLICE_MS);
        std::thread::sleep(Duration::from_millis(u64::from(slice)));
        left = left.saturating_sub(slice);
    }
}

/// Types `plan` (the body of [`Session::autotype_type`]).
pub(crate) fn run(
    plan: &Plan,
    focus: &dyn AutoTypeFocus,
    stop: &Arc<AtomicBool>,
    post: bool,
) -> AutoTypeEnd {
    // The flag again after the check: a stop raised while Swift looked (an
    // Accessibility call on a busy target can take seconds) stops that key.
    let stopped_now = || stop.load(Ordering::SeqCst);
    let mut go_on = || !stopped_now() && focus.same_window() && !stopped_now();
    let typed = if !post {
        type_plan(plan, &mut Recorder::new(views::now()), &mut go_on)
    } else if let Some(keyboard) = Keyboard::new() {
        let stop = Arc::clone(stop);
        type_plan(plan, &mut Quartz { keyboard, stop }, &mut go_on)
    } else {
        return stopped(0, "no-event-source");
    };
    end(typed, stopped_now())
}

/// How a run ended, for Swift and the debug log (INT-05.47). A stop raised
/// during step 1's or step 3's wait is `stopped` too (LD-234 (1)).
fn end(typed: Typed, stopped_now: bool) -> AutoTypeEnd {
    match typed {
        Typed::Finished(n) => AutoTypeEnd::Finished { keys: count(n) },
        Typed::Stopped(_, Stop::Picks) => AutoTypeEnd::NeedsPicks,
        Typed::Stopped(n, _) if stopped_now => stopped(n, "stopped"),
        Typed::Stopped(n, Stop::NotInFront) => stopped(n, "not-in-front"),
        Typed::Stopped(n, Stop::Held) => stopped(n, "keys-held"),
        Typed::Stopped(n, Stop::Changed) => stopped(n, "window-changed"),
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// A stop with its reason code for the debug log (INT-05.47).
fn stopped(keys: usize, reason: &str) -> AutoTypeEnd {
    AutoTypeEnd::Stopped {
        keys: count(keys),
        reason: reason.to_owned(),
    }
}

/// The layout table as Rust keeps it: one character per key, the first
/// [`MAX_LAYOUT_KEYS`] only.
pub(crate) fn layout(keys: &[AutoTypeKey]) -> Layout {
    Layout::with_mods(keys.iter().take(MAX_LAYOUT_KEYS).filter_map(|k| {
        let mut chars = k.character.chars();
        let c = chars.next().filter(|_| chars.next().is_none())?;
        let shift = if k.shift { Mods::SHIFT } else { Mods::NONE };
        let option = if k.option { Mods::OPTION } else { Mods::NONE };
        Some((c, k.code, shift | option))
    }))
}

#[uniffi::export]
impl Session {
    /// The current keyboard layout as one table (INT-05.41, INT-05.45),
    /// read by Swift once per run before [`Session::autotype_start`]; the
    /// plans made after it keep it. No secret crosses: Swift never looks up
    /// a character.
    pub fn autotype_layout(&self, keys: Vec<AutoTypeKey>) {
        self.autotype().layout = layout(&keys);
    }

    /// Stops the run that is typing (the shortcut pressed again,
    /// INT-05.39, INT-05.46): no further key goes out. The stop flag is made
    /// with the plan, so a press before the typing thread starts stops that
    /// plan too; Swift calls this only while a run types.
    pub fn autotype_stop(&self) {
        self.autotype().stop.store(true, Ordering::SeqCst);
    }

    /// From now on, runs post their key events to macOS (App's own launch
    /// only). A hidden launch keeps the recorder whatever it asks
    /// (AGENTS.md rule 10).
    pub fn autotype_post_events(&self) {
        if !instance::hidden() {
            self.autotype().post = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_05_45_the_layout_table_keeps_single_characters_and_their_forms() {
        let key = |c: &str, code, shift, option| AutoTypeKey {
            character: c.into(),
            code,
            shift,
            option,
        };
        let l = layout(&[
            key("a", 0x00, false, false),
            key("A", 0x00, true, false),
            key("©", 0x05, false, true),
            key("±", 0x18, true, true),
            key("xy", 0x07, false, false),
            key("", 0x02, false, false),
        ]);
        assert_eq!(l.key('a'), Some((0x00, Mods::NONE)));
        assert_eq!(l.key('A'), Some((0x00, Mods::SHIFT)));
        assert_eq!(l.key('©'), Some((0x05, Mods::OPTION)));
        assert_eq!(l.key('±'), Some((0x18, Mods::OPTION | Mods::SHIFT)));
        assert_eq!(l.key('x'), None, "two characters are no key");
        assert_eq!(l.key('y'), None);
    }

    /// T102, INT-05.43: each modifier goes to macOS as its own Quartz bit.
    #[test]
    fn int_05_43_modifiers_map_to_their_quartz_flags() {
        assert_eq!(cg_flags(Mods::NONE), 0);
        assert_eq!(cg_flags(Mods::COMMAND), 0x10_0000);
        assert_eq!(cg_flags(Mods::CONTROL), 0x4_0000);
        assert_eq!(cg_flags(Mods::SHIFT | Mods::OPTION), 0x2_0000 | 0x8_0000);
    }

    /// LD-234 (1), INT-05.43: all 16 modifier sets give exactly their
    /// Quartz bits (`Events.h`: ⇧ 0x20000, ⌃ 0x40000, ⌥ 0x80000, ⌘
    /// 0x100000), so no two bits can trade places.
    #[test]
    fn ld_234_cg_flags_for_every_modifier_set() {
        let bits = [
            (Mods::SHIFT, 0x2_0000),
            (Mods::CONTROL, 0x4_0000),
            (Mods::OPTION, 0x8_0000),
            (Mods::COMMAND, 0x10_0000),
        ];
        for set in 0..16usize {
            let (mut mods, mut want) = (Mods::NONE, 0u64);
            for (i, (m, bit)) in bits.iter().enumerate() {
                if set >> i & 1 == 1 {
                    mods = mods | *m;
                    want |= bit;
                }
            }
            assert_eq!(cg_flags(mods), want, "set {set:04b}");
        }
    }

    /// LD-234 (1), INT-05.47: the debug line's reason for every end; a stop
    /// raised while step 1 or step 3 waited reads `stopped`.
    #[test]
    fn ld_234_not_in_front_and_keys_held_lines_and_a_stop_during_their_waits() {
        let reason = |typed, stop| match end(typed, stop) {
            AutoTypeEnd::Stopped { keys, reason } => format!("{reason} after {keys} keys"),
            other => format!("{other:?}"),
        };
        let waits = [
            (Stop::NotInFront, "not-in-front"),
            (Stop::Held, "keys-held"),
        ];
        for (why, line) in waits {
            assert_eq!(
                reason(Typed::Stopped(0, why), false),
                format!("{line} after 0 keys")
            );
            assert_eq!(reason(Typed::Stopped(0, why), true), "stopped after 0 keys");
        }
        let changed = Typed::Stopped(3, Stop::Changed);
        assert_eq!(reason(changed, false), "window-changed after 3 keys");
        assert_eq!(reason(changed, true), "stopped after 3 keys");
        assert_eq!(
            end(Typed::Stopped(0, Stop::Picks), true),
            AutoTypeEnd::NeedsPicks
        );
        let done = end(Typed::Finished(4), false);
        assert_eq!(done, AutoTypeEnd::Finished { keys: 4 });
    }

    /// LD-231 (3), LD-234 (1): the real sink's waits end at once on a stop,
    /// whether it was up before the wait or raised during it. No event
    /// source is made.
    #[test]
    fn ld_234_waits_end_at_once_on_a_stop() {
        let stop = Arc::new(AtomicBool::new(true));
        let start = std::time::Instant::now();
        wait_unless_stopped(&stop, 10_000);
        assert!(start.elapsed() < Duration::from_secs(1), "already up");
        stop.store(false, Ordering::SeqCst);
        let raiser = Arc::clone(&stop);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            raiser.store(true, Ordering::SeqCst);
        });
        let start = std::time::Instant::now();
        wait_unless_stopped(&stop, 10_000);
        assert!(start.elapsed() < Duration::from_secs(2), "raised during it");
        t.join().unwrap();
    }

    #[test]
    #[ignore = "run by ld_234_a_hidden_launch_never_posts"]
    fn ld_234_hidden_child() {
        assert!(instance::hidden());
        let s = Session::new();
        s.autotype_post_events();
        assert!(!s.autotype().post, "the recorder stays");
        println!("hidden: recorder kept");
    }

    /// LD-234 (1), AGENTS.md rule 10: in a launch with `APP_TEST_HIDDEN=1`
    /// `autotype_post_events` leaves posting off, so every event goes to the
    /// recorder; without it posting turns on (nothing is typed here). Debug
    /// builds only: a release build has no hidden launch (F-166, LD-48).
    #[test]
    #[cfg(debug_assertions)]
    fn ld_234_a_hidden_launch_never_posts() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "autotype_typing::tests::ld_234_hidden_child",
                "--ignored",
            ])
            .args(["--nocapture", "--test-threads=1"])
            .env(instance::HIDDEN_VARIABLE, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("hidden: recorder kept"), "{stdout}");
        if !instance::hidden() {
            let s = Session::new();
            s.autotype_post_events();
            assert!(s.autotype().post, "control: App's own launch posts");
        }
    }
}
