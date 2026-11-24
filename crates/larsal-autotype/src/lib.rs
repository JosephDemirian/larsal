//! Auto-Type (INT-05). E8-S1 reads a sequence and turns it into a checked
//! [`Plan`]: the list of key actions a run will type. E8-S2 adds
//! [`matching`]: candidates, window matching and the picker model. E8-S3
//! adds [`typing`]: the plan turned into key events through a [`KeySink`]
//! (Larsal's is macOS's keyboard input, tests' a [`Recorder`]). The plan never
//! reaches the screen layer: its events are made in Rust (INT-05.45,
//! D-INT05-15).
//!
//! Where a sequence comes from: the entry's effective sequence and the
//! group inheritance of MOD-02.15 and MOD-02.16 are
//! `larsal_core::edit::entry_sequence` (with `DEFAULT_SEQUENCE`); placeholders
//! resolve through `larsal_core::refs` (MOD-08); one-time codes through
//! `larsal_core::totp` (FEA-04).
//!
//! Guarantees:
//! - [`plan`] reads the whole sequence, resolves every placeholder and
//!   checks every limit before it returns (INT-05.15); any failure gives
//!   one [`Error`] and no plan, so nothing can be typed.
//! - Bounds (INT-05.16, D-INT05-7, AT-G03): at most 10,000 actions per plan
//!   (key presses, and every `{DELAY n}` and `{DELAY=n}`, zero ones too,
//!   LD-186 (2)) and 60,000 ms of `{DELAY n}` waits; counts, waits and pauses are
//!   checked even when their digits overflow (INT-05.17); brace nesting at
//!   most 32 deep (R05-2); reading is linear in the sequence length and
//!   its memory follows the number of braces, not the length (LD-184 (1));
//!   all placeholder resolutions of one plan share one work meter, so no
//!   sequence can hang the caller or fill memory.
//! - Every typed character (resolved values, picked fields, literal text)
//!   lives in a `SecretString`; the one-time code is computed only when
//!   typing reaches it, from settings the plan owns and wipes
//!   (INT-05.9, D-INT05-8; AGENTS.md rule 4).
#![forbid(unsafe_code)]
// Rust rule 4: no panics on input (a sequence comes from the vault).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

pub mod error;
pub mod matching;
mod read;
pub mod typing;

pub use error::Error;
pub use matching::{
    Actions, Memory, Open, Picker, Row, Scope, Settings, actions, is_candidate, type_login_enabled,
};
pub use typing::{Event, KeySink, Recorded, Recorder, Stop, Typed, type_plan};

use core::cell::Cell;
use larsal_core::refs::{self, Context, EntryIndex};
use larsal_core::{pattern, totp};
use larsal_crypto::secret::SecretString;
use larsal_model::entry::STANDARD_FIELDS;
use larsal_model::{Entry, Time};
use read::{Reader, Token};
use std::collections::HashMap;

/// Actions one run may take (INT-05.16): key presses, waits and pauses
/// (LD-186 (2)).
pub const MAX_KEYS: usize = 10_000;
/// The sum of `{DELAY n}` waits of one run, in ms (INT-05.16).
pub const MAX_WAITS_MS: u64 = 60_000;
/// The largest repeat count of a key token (INT-05.6).
pub const MAX_REPEAT: u64 = 100;
/// The longest `{DELAY n}`, in ms (INT-05.7).
pub const MAX_DELAY_MS: u64 = 10_000;
/// The longest key pause, `{DELAY=n}` and S-AT-10, in ms (INT-05.7).
pub const MAX_PAUSE_MS: u32 = 500;
/// The start delay S-AT-09 is used clamped to this range, in ms (INT-05.7).
pub const START_DELAY_MS: core::ops::RangeInclusive<u32> = 100..=10_000;
/// The most characters `{PICKCHARS}` picks from (INT-05.10).
pub const MAX_PICK: usize = 256;
/// The deepest brace nesting of a token (R05-2).
pub const MAX_NEST: u32 = 32;
/// The work meter of one plan for MOD-08 resolutions (LD-126 units, about
/// a nanosecond each on the build Mac).
pub const RUN_BUDGET: usize = 100_000_000;
/// Meter units each placeholder resolution costs besides its own work, so
/// a sequence of many placeholders that resolve to nothing stays short.
const RESOLVE_UNITS: usize = 1_000;

/// macOS virtual key codes (Carbon `HIToolbox/Events.h`).
const RETURN: u16 = 0x24;
const TAB: u16 = 0x30;
const DELETE: u16 = 0x33;

/// A set of modifier keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Mods(u8);

impl Mods {
    /// No modifier.
    pub const NONE: Mods = Mods(0);
    /// ⇧, written `+`.
    pub const SHIFT: Mods = Mods(1);
    /// ⌃, written `^`.
    pub const CONTROL: Mods = Mods(2);
    /// ⌥, written `%`.
    pub const OPTION: Mods = Mods(4);
    /// ⌘, written `#`.
    pub const COMMAND: Mods = Mods(8);

    /// True when every modifier of `other` is in `self`.
    #[must_use]
    pub fn contains(self, other: Mods) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Mods {
    type Output = Mods;
    fn bitor(self, other: Mods) -> Mods {
        Mods(self.0 | other.0)
    }
}

impl core::fmt::Display for Mods {
    /// The macOS symbols in the system's order: ⌃⌥⇧⌘.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (m, s) in [
            (Mods::CONTROL, "⌃"),
            (Mods::OPTION, "⌥"),
            (Mods::SHIFT, "⇧"),
            (Mods::COMMAND, "⌘"),
        ] {
            if self.contains(m) {
                f.write_str(s)?;
            }
        }
        Ok(())
    }
}

/// The current keyboard layout as one table (INT-05.45, LD-186 (3)): for
/// each character, the key that types it with one press and the modifiers
/// that press needs (none, ⇧, ⌥ or ⌥⇧; dead keys are not in it). A key
/// combination (`^a`, `{CLEARFIELD}`) presses a key that types the
/// character with no modifier (INT-05.42, D-INT05-5); key-code mode presses
/// any of them (INT-05.41).
#[derive(Debug, Clone, Default)]
pub struct Layout {
    keys: HashMap<char, (u16, Mods)>,
}

impl Layout {
    /// A layout from (character, virtual key code) pairs typed with no
    /// modifier.
    #[must_use]
    pub fn new(plain: impl IntoIterator<Item = (char, u16)>) -> Self {
        Self::with_mods(plain.into_iter().map(|(c, code)| (c, code, Mods::NONE)))
    }

    /// A layout from (character, key code, modifiers) triples. Only ⇧ and
    /// ⌥ count: a triple with ⌃ or ⌘ is left out. A character that several
    /// keys type keeps the one with the fewest modifiers (none, ⇧, ⌥, then
    /// ⌥⇧), the first given among equals.
    #[must_use]
    pub fn with_mods(keys: impl IntoIterator<Item = (char, u16, Mods)>) -> Self {
        let mut map: HashMap<char, (u16, Mods)> = HashMap::new();
        // The bits rank them: none 0, ⇧ 1, ⌥ 4, ⌥⇧ 5.
        for (c, code, mods) in keys.into_iter().filter(|k| k.2.0 & !5 == 0) {
            let kept = map.entry(c).or_insert((code, mods));
            if mods.0 < kept.1.0 {
                *kept = (code, mods);
            }
        }
        Self { keys: map }
    }

    /// The key and modifiers that type `c` with one press (INT-05.41).
    #[must_use]
    pub fn key(&self, c: char) -> Option<(u16, Mods)> {
        self.keys.get(&c).copied()
    }

    /// The key that types `c` with no modifier (INT-05.42).
    fn plain(&self, c: char) -> Option<u16> {
        self.key(c).filter(|k| k.1 == Mods::NONE).map(|k| k.0)
    }
}

/// Larsal's global shortcut (S-AT-07): a key code and its exact modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortcut {
    /// Virtual key code.
    pub code: u16,
    /// Modifiers.
    pub mods: Mods,
}

/// What a plan needs besides the sequence and its entry.
#[derive(Debug, Clone)]
pub struct Options<'a> {
    /// The current keyboard layout.
    pub layout: &'a Layout,
    /// Larsal's global shortcut, which a sequence must not type (R05-4).
    pub shortcut: Option<Shortcut>,
    /// S-AT-09, used clamped to 100 to 10,000 ms.
    pub start_delay_ms: u32,
    /// S-AT-10, used clamped to 0 to 500 ms.
    pub key_pause_ms: u32,
}

/// One step of a plan.
#[derive(Debug)]
pub enum Action {
    /// Characters typed one by one (INT-05.40); `by_key` is key-code mode
    /// (`{MODE=VIRTUAL}`, INT-05.41). Never holds a control character.
    Text {
        /// The characters.
        text: SecretString,
        /// Key-code mode.
        by_key: bool,
    },
    /// One key press with these modifiers (INT-05.6, INT-05.42).
    Key {
        /// Virtual key code.
        code: u16,
        /// Modifiers.
        mods: Mods,
    },
    /// `{DELAY n}`: wait n ms here (at most 10,000).
    Wait(u32),
    /// `{DELAY=n}`: the pause after each later key, n ms (at most 500).
    Pause(u32),
    /// `{TOTP}`: type [`Plan::otp_code`] at the moment typing reaches it.
    Otp {
        /// Key-code mode.
        by_key: bool,
    },
    /// `{PICKCHARS}` not yet picked: the dialog (INT-05.36) gets
    /// [`Plan::picks`], then [`Plan::fill_picks`] replaces this.
    Pick {
        /// The field's resolved value, 1 to 256 characters.
        value: SecretString,
        /// Key-code mode.
        by_key: bool,
    },
}

/// The characters picked in one pick dialog (INT-05.10).
#[derive(Debug, Clone, Default)]
pub struct Picked {
    /// 0-based character positions, in the order picked.
    pub positions: Vec<usize>,
    /// "Add a Tab after each character" (a Tab after every one but the last).
    pub tab_after: bool,
}

/// A checked run: what to type, in order (INT-05.15).
#[derive(Debug)]
pub struct Plan {
    /// The wait before the first key, ms (S-AT-09 clamped, INT-05.7).
    pub start_delay_ms: u32,
    /// The pause after each key until a `{DELAY=n}`, ms (S-AT-10 clamped).
    pub key_pause_ms: u32,
    actions: Vec<Action>,
    keys: usize,
    waits_ms: u64,
    otp: Option<totp::Settings>,
    /// The layout read once for this run (INT-05.41): key-code mode types
    /// with it.
    layout: Layout,
}

impl Plan {
    /// The steps in order.
    #[must_use]
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Actions counted toward [`MAX_KEYS`]: every key press (a `{TOTP}`
    /// counts its code length; picks count once filled) and every wait and
    /// pause (LD-186 (2)).
    #[must_use]
    pub fn keys(&self) -> usize {
        self.keys
    }

    /// The sum of its `{DELAY n}` waits (at most [`MAX_WAITS_MS`]).
    #[must_use]
    pub fn waits_ms(&self) -> u64 {
        self.waits_ms
    }

    /// The character count of each pick still to make, in sequence order:
    /// what each pick dialog shows (one button per character).
    #[must_use]
    pub fn picks(&self) -> Vec<usize> {
        self.actions
            .iter()
            .filter_map(|a| match a {
                Action::Pick { value, .. } => Some(value.expose().chars().count()),
                _ => None,
            })
            .collect()
    }

    /// Puts the picked characters in place of the picks, one [`Picked`]
    /// per pick in order (a pick without one types nothing; a position past
    /// the field's end is skipped). Cancel in a dialog means the run stops:
    /// the caller drops the plan instead (D-INT05-9). MI05-21 when the
    /// picked keys would pass [`MAX_KEYS`]; the plan is then unchanged.
    pub fn fill_picks(&mut self, picks: &[Picked]) -> Result<(), Error> {
        let used = picks.iter().take(self.picks().len());
        let extra = used.fold(0usize, |n, p| {
            let tabs = if p.tab_after {
                p.positions.len().saturating_sub(1)
            } else {
                0
            };
            n.saturating_add(p.positions.len()).saturating_add(tabs)
        });
        if self.keys.saturating_add(extra) > MAX_KEYS {
            return Err(Error::TooManyKeys);
        }
        let mut picks = picks.iter();
        let mut out = Vec::with_capacity(self.actions.len());
        for action in core::mem::take(&mut self.actions) {
            let Action::Pick { value, by_key } = action else {
                out.push(action);
                continue;
            };
            let Some(p) = picks.next() else { continue };
            let chars = p
                .positions
                .iter()
                .filter_map(|&at| value.expose().chars().nth(at));
            for (i, c) in chars.enumerate() {
                if i > 0 && p.tab_after {
                    out.push(Action::Key {
                        code: TAB,
                        mods: Mods::NONE,
                    });
                    self.keys = self.keys.saturating_add(1);
                }
                let mut one = String::with_capacity(4);
                one.push(c);
                out.push(Action::Text {
                    text: SecretString::new(one),
                    by_key,
                });
                self.keys = self.keys.saturating_add(1);
            }
        }
        self.actions = out;
        Ok(())
    }

    /// The entry's one-time code at `now` (FEA-04), for typing an
    /// [`Action::Otp`]: computed on each call, never stored.
    #[must_use]
    pub fn otp_code(&self, now: Time) -> Option<SecretString> {
        self.otp.as_ref()?.code(now)
    }
}

/// Reads `sequence` for `entry` and checks it (INT-05.1 to INT-05.18):
/// every token, every placeholder resolved through MOD-08 in `ctx`'s vault
/// (unmasked, whatever `ctx.display` says), every limit. `ctx` gives the
/// vault, its folder, the clock and the time zone; its one-time code,
/// index and meter are Larsal's own here. `entry` must be the vault's own
/// entry for references to resolve (MOD-08.29). The plan types nothing
/// itself.
pub fn plan(
    sequence: &str,
    entry: &Entry,
    ctx: &Context<'_>,
    opts: &Options<'_>,
) -> Result<Plan, Error> {
    build(sequence, entry, ctx, opts, false)
}

/// The editor's check (INT-05.15, INT-05.34): the same reading as [`plan`],
/// without dialogs; a pick field must exist but its length is not tested.
pub fn check(
    sequence: &str,
    entry: &Entry,
    ctx: &Context<'_>,
    opts: &Options<'_>,
) -> Result<(), Error> {
    build(sequence, entry, ctx, opts, true).map(|_| ())
}

fn build(
    sequence: &str,
    entry: &Entry,
    ctx: &Context<'_>,
    opts: &Options<'_>,
    editor: bool,
) -> Result<Plan, Error> {
    let own;
    let index = match ctx.index {
        Some(i) => Some(i),
        None => {
            own = ctx.vault.map(EntryIndex::new);
            own.as_ref()
        }
    };
    let meter = Cell::new(RUN_BUDGET);
    let ctx = Context {
        vault: ctx.vault,
        vault_dir: ctx.vault_dir,
        now: ctx.now,
        zone: ctx.zone,
        otp: otp_checked,
        display: false,
        index,
        meter: Some(&meter),
        hidden: ctx.hidden,
    };
    let mut b = Builder {
        opts,
        entry,
        ctx: &ctx,
        meter: &meter,
        editor,
        by_key: false,
        plan: Plan {
            start_delay_ms: opts
                .start_delay_ms
                .clamp(*START_DELAY_MS.start(), *START_DELAY_MS.end()),
            key_pause_ms: opts.key_pause_ms.min(MAX_PAUSE_MS),
            actions: Vec::new(),
            keys: 0,
            waits_ms: 0,
            otp: None,
            layout: opts.layout.clone(),
        },
    };
    for token in Reader::new(sequence)? {
        match token? {
            Token::Char { mods, ch, text } => b.char_token(mods, ch, text)?,
            Token::Brace {
                mods,
                content,
                text,
            } => b.brace(mods, &content, text)?,
        }
    }
    Ok(b.plan)
}

thread_local! {
    /// Set when a resolution reached a `{TOTP}` of an entry whose one-time
    /// settings are not valid (LD-184 (3)).
    static OTP_INVALID: Cell<bool> = const { Cell::new(false) };
}

/// `{TOTP}` met inside a resolution (MOD-08.12): computed when the plan is
/// made, as MOD-08 resolves the field; invalid settings are noted for
/// MI05-16 instead of typing nothing (LD-184 (3)). A `{TOTP}` written in
/// the sequence itself stays late (D-INT05-8).
fn otp_checked(entry: &Entry, now: Time) -> Option<SecretString> {
    let s = totp::settings(entry)?;
    if s.problem().is_some() {
        OTP_INVALID.with(|f| f.set(true));
        return None;
    }
    s.code(now)
}

/// What a key name presses (INT-05.6).
#[derive(Clone, Copy)]
enum Named {
    Code(u16),
    Char(char),
    Nothing,
}

/// The key names of INT-05.6, any case.
fn named(name: &str) -> Option<Named> {
    const F: [u16; 16] = [
        0x7A, 0x78, 0x63, 0x76, 0x60, 0x61, 0x62, 0x64, 0x65, 0x6D, 0x67, 0x6F, 0x69, 0x6B, 0x71,
        0x6A,
    ];
    const NUMPAD: [u16; 10] = [0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5B, 0x5C];
    const TABLE: [(&str, Named); 38] = [
        ("TAB", Named::Code(TAB)),
        ("ENTER", Named::Code(RETURN)),
        ("SPACE", Named::Code(0x31)),
        ("UP", Named::Code(0x7E)),
        ("DOWN", Named::Code(0x7D)),
        ("LEFT", Named::Code(0x7B)),
        ("RIGHT", Named::Code(0x7C)),
        ("HOME", Named::Code(0x73)),
        ("END", Named::Code(0x77)),
        ("PGUP", Named::Code(0x74)),
        ("PGDOWN", Named::Code(0x79)),
        ("PGDN", Named::Code(0x79)),
        ("BACKSPACE", Named::Code(DELETE)),
        ("BS", Named::Code(DELETE)),
        ("BKSP", Named::Code(DELETE)),
        ("DELETE", Named::Code(0x75)),
        ("DEL", Named::Code(0x75)),
        ("ESC", Named::Code(0x35)),
        ("HELP", Named::Code(0x72)),
        ("CAPSLOCK", Named::Code(0x39)),
        ("WIN", Named::Code(0x37)),
        ("LWIN", Named::Code(0x37)),
        ("RWIN", Named::Code(0x36)),
        ("ADD", Named::Code(0x45)),
        ("SUBTRACT", Named::Code(0x4E)),
        ("MULTIPLY", Named::Code(0x43)),
        ("DIVIDE", Named::Code(0x4B)),
        ("INSERT", Named::Nothing),
        ("INS", Named::Nothing),
        ("BREAK", Named::Nothing),
        ("NUMLOCK", Named::Nothing),
        ("PTRSC", Named::Nothing),
        ("SCROLLLOCK", Named::Nothing),
        ("APPS", Named::Nothing),
        ("LEFTBRACE", Named::Char('{')),
        ("RIGHTBRACE", Named::Char('}')),
        ("LEFTPAREN", Named::Char('(')),
        ("RIGHTPAREN", Named::Char(')')),
    ];
    if let Some((_, k)) = TABLE.iter().find(|(n, _)| name.eq_ignore_ascii_case(n)) {
        return Some(*k);
    }
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next())
        && "()[]+%^~#".contains(c)
    {
        return Some(Named::Char(c));
    }
    let numbered = |prefix: &str| -> Option<usize> {
        let digits = strip_ci(name, prefix)?;
        // LD-184 (2): no leading zero (`{F01}`, `{NUMPAD00}` are not keys).
        let plain = digits == "0" || !digits.starts_with('0');
        (plain && digits.len() <= 2 && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse().ok())
            .flatten()
    };
    if let Some(n) = numbered("NUMPAD") {
        return NUMPAD.get(n).map(|&c| Named::Code(c));
    }
    numbered("F")
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| F.get(i))
        .map(|&c| Named::Code(c))
}

/// `text` without `prefix`, compared ignoring ASCII case.
fn strip_ci<'t>(text: &'t str, prefix: &str) -> Option<&'t str> {
    text.get(..prefix.len())
        .filter(|h| h.eq_ignore_ascii_case(prefix))
        .and_then(|_| text.get(prefix.len()..))
}

/// Decimal digits as a number, saturating (INT-05.17); `None` when empty
/// or not all digits.
fn number(digits: &str) -> Option<u64> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(digits.bytes().fold(0u64, |n, d| {
        n.saturating_mul(10)
            .saturating_add(u64::from(d.saturating_sub(b'0')))
    }))
}

/// INT-05.5: a name, one or more spaces, then digits, gives the name and
/// the count; anything else is all name.
fn split_count(content: &str) -> (&str, Option<u64>) {
    let head = content.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = content.get(head.len()..).unwrap_or("");
    let name = head.trim_end_matches(' ');
    if digits.is_empty() || name.len() == head.len() || name.is_empty() {
        return (content, None);
    }
    (name, number(digits))
}

/// U+0000 to U+001F and U+007F (INT-05.14).
fn is_control(c: char) -> bool {
    c <= '\u{1f}' || c == '\u{7f}'
}

struct Builder<'b> {
    opts: &'b Options<'b>,
    entry: &'b Entry,
    ctx: &'b Context<'b>,
    meter: &'b Cell<usize>,
    editor: bool,
    by_key: bool,
    plan: Plan,
}

impl Builder<'_> {
    fn count(&mut self, n: usize) -> Result<(), Error> {
        self.plan.keys = self.plan.keys.saturating_add(n);
        if self.plan.keys > MAX_KEYS {
            return Err(Error::TooManyKeys);
        }
        Ok(())
    }

    /// One key press, refused when it is Larsal's own shortcut (R05-4).
    fn press(&mut self, code: u16, mods: Mods, token: &str) -> Result<(), Error> {
        if self.opts.shortcut == Some(Shortcut { code, mods }) {
            return Err(Error::Shortcut(error::shown(token)));
        }
        self.count(1)?;
        self.plan.actions.push(Action::Key { code, mods });
        Ok(())
    }

    /// A modifier with a character (INT-05.42): the key that types its
    /// lower-case form with no modifier, else MI05-23.
    fn combo(&mut self, ch: char, mods: Mods, token: &str) -> Result<(), Error> {
        let mut low = ch.to_lowercase();
        let key = match (low.next(), low.next()) {
            (Some(l), None) => l,
            _ => ch,
        };
        let code = self
            .opts
            .layout
            .plain(key)
            .ok_or(Error::NoKey { ch, mods })?;
        self.press(code, mods, token)
    }

    /// Text with no control character in it.
    fn text(&mut self, s: &str) -> Result<(), Error> {
        if s.is_empty() {
            return Ok(());
        }
        self.count(s.chars().count())?;
        self.plan.actions.push(Action::Text {
            text: SecretString::new(s.to_owned()),
            by_key: self.by_key,
        });
        Ok(())
    }

    /// A character of the sequence text (INT-05.4, R05-3): Tab presses Tab,
    /// other control characters (line feed and carriage return included)
    /// are dropped.
    fn char_token(&mut self, mods: Mods, ch: char, token: &str) -> Result<(), Error> {
        match ch {
            '\t' => self.press(TAB, mods, token),
            c if is_control(c) => Ok(()),
            c if mods == Mods::NONE => self.text(c.encode_utf8(&mut [0; 4])),
            c => self.combo(c, mods, token),
        }
    }

    /// A resolved value (INT-05.14): line feed, carriage return and the
    /// pair of both press Return once; Tab presses Tab; other control
    /// characters are dropped.
    fn typed(&mut self, s: &str, token: &str) -> Result<(), Error> {
        let mut from = 0usize;
        let mut after_cr = false;
        for (i, c) in s.char_indices() {
            if !is_control(c) {
                after_cr = false;
                continue;
            }
            self.text(s.get(from..i).unwrap_or(""))?;
            match c {
                '\n' if after_cr => {}
                '\n' | '\r' => self.press(RETURN, Mods::NONE, token)?,
                '\t' => self.press(TAB, Mods::NONE, token)?,
                _ => {}
            }
            after_cr = c == '\r';
            from = i.saturating_add(c.len_utf8());
        }
        self.text(s.get(from..).unwrap_or(""))
    }

    /// A brace token (INT-05.5): its content tested in the card's order.
    fn brace(&mut self, mods: Mods, content: &str, token: &str) -> Result<(), Error> {
        let shown = || error::shown(token);
        let (name, count) = split_count(content);
        if let Some(key) = named(name) {
            let n = count.unwrap_or(1);
            if n > MAX_REPEAT {
                return Err(Error::Repeat(shown()));
            }
            for _ in 0..n {
                match key {
                    Named::Code(code) => self.press(code, mods, token)?,
                    Named::Char(c) if mods == Mods::NONE => {
                        self.text(c.encode_utf8(&mut [0; 4]))?
                    }
                    Named::Char(c) => self.combo(c, mods, token)?,
                    Named::Nothing => {}
                }
            }
            return Ok(());
        }
        if name.eq_ignore_ascii_case("DELAY") {
            let n = count.ok_or_else(|| Error::Number(shown()))?;
            if n > MAX_DELAY_MS {
                return Err(Error::Wait(shown()));
            }
            self.plan.waits_ms = self.plan.waits_ms.saturating_add(n);
            if self.plan.waits_ms > MAX_WAITS_MS {
                return Err(Error::TooLong);
            }
            // LD-186 (2): a wait counts as an action, `{DELAY 0}` too.
            self.count(1)?;
            self.plan
                .actions
                .push(Action::Wait(u32::try_from(n).unwrap_or(u32::MAX)));
            return Ok(());
        }
        if let Some(rest) = strip_ci(content, "DELAY=") {
            let n = number(rest.trim_matches(' ')).ok_or_else(|| Error::Number(shown()))?;
            let n = u32::try_from(n).unwrap_or(u32::MAX);
            if n > MAX_PAUSE_MS {
                return Err(Error::Pause(shown()));
            }
            self.count(1)?;
            self.plan.actions.push(Action::Pause(n));
            return Ok(());
        }
        if name.eq_ignore_ascii_case("CLEARFIELD") {
            // D-INT05-6: ⌘A, then Delete.
            self.combo('a', Mods::COMMAND, token)?;
            return self.press(DELETE, Mods::NONE, token);
        }
        if name.eq_ignore_ascii_case("TOTP") || name.eq_ignore_ascii_case("TIMEOTP") {
            return self.otp();
        }
        if let Some(field) = strip_ci(content, "PICKCHARS:") {
            return self.pick(field, token);
        }
        if name.eq_ignore_ascii_case("PICKCHARS") {
            return self.pick("Password", token);
        }
        if let Some(mode) = strip_ci(name, "MODE=") {
            let tail = mode.len().saturating_sub("VIRTUAL".len());
            self.by_key = mode
                .get(tail..)
                .is_some_and(|t| t.eq_ignore_ascii_case("VIRTUAL"));
            return Ok(());
        }
        // INT-05.12, D-INT05-11: accepted, types nothing.
        if ["BEEP", "VKEY", "APPACTIVATE", "C:"]
            .iter()
            .any(|p| strip_ci(content, p).is_some())
        {
            return Ok(());
        }
        self.placeholder(content, token)
    }

    /// `{TOTP}` (INT-05.9): nothing without a one-time password, MI05-16
    /// with invalid settings, else a mark computed when typing reaches it.
    fn otp(&mut self) -> Result<(), Error> {
        if self.plan.otp.is_none() {
            let Some(s) = totp::settings(self.entry) else {
                return Ok(());
            };
            if s.problem().is_some() {
                return Err(Error::Otp);
            }
            self.plan.otp = Some(s);
        }
        let digits = self.plan.otp.as_ref().map_or(0, |s| s.digits);
        self.count(usize::try_from(digits).unwrap_or(usize::MAX))?;
        self.plan.actions.push(Action::Otp {
            by_key: self.by_key,
        });
        Ok(())
    }

    /// `{PICKCHARS}` (INT-05.10).
    fn pick(&mut self, name: &str, token: &str) -> Result<(), Error> {
        let raw = match self.entry.field(name) {
            Some(f) => f.value.expose(),
            None if STANDARD_FIELDS.contains(&name) => "",
            None => return Err(Error::NoField(error::shown(token))),
        };
        if self.editor {
            return Ok(());
        }
        let value = self.resolve(raw, token)?;
        let n = value.expose().chars().count();
        if n > MAX_PICK {
            return Err(Error::PickTooLong(error::shown(token)));
        }
        if n > 0 {
            self.plan.actions.push(Action::Pick {
                value,
                by_key: self.by_key,
            });
        }
        Ok(())
    }

    /// MOD-08 on `text`, paid from the plan's meter; MI05-27 when a depth or
    /// work bound was hit (R05-7); MI05-16 when it reached a `{TOTP}` whose
    /// one-time settings are not valid (LD-184 (3)).
    fn resolve(&mut self, text: &str, token: &str) -> Result<SecretString, Error> {
        let grows = || Error::Grows(error::shown(token));
        self.spend(RESOLVE_UNITS).ok_or_else(grows)?;
        OTP_INVALID.with(|f| f.set(false));
        let r = refs::resolve(text, self.entry, self.ctx);
        if r.depth_hit || r.bounded {
            return Err(grows());
        }
        if OTP_INVALID.with(Cell::get) {
            return Err(Error::Otp);
        }
        Ok(r.text)
    }

    fn spend(&self, units: usize) -> Option<()> {
        let left = self.meter.get().checked_sub(units)?;
        self.meter.set(left);
        Some(())
    }

    /// Any other brace token (INT-05.13).
    fn placeholder(&mut self, content: &str, token: &str) -> Result<(), Error> {
        let bad = || Error::Conversion(error::shown(token));
        // MOD-08.21 and MOD-08.22, checked before resolving.
        if let Some(body) = strip_ci(content, "T-CONV:") {
            let kind = third_part(content, body, 4).ok_or_else(bad)?;
            let first = kind.chars().next().map(|c| c.to_ascii_lowercase());
            if !(kind.eq_ignore_ascii_case("base64")
                || kind.eq_ignore_ascii_case("hex")
                || matches!(first, Some('u' | 'l')))
            {
                return Err(bad());
            }
        } else if let Some(body) = strip_ci(content, "T-REPLACE-RX:") {
            let pat = third_part(content, body, 5).ok_or_else(bad)?;
            self.spend(refs::COMPILE_UNITS)
                .ok_or_else(|| Error::Grows(error::shown(token)))?;
            if !matches!(pattern::compile_sized(pat), pattern::Compiled::Ok(..)) {
                return Err(bad());
            }
        }
        let span = format!("{{{content}}}");
        let value = self.resolve(&span, token)?;
        if value.expose() == span {
            return Err(Error::Unknown(error::shown(token)));
        }
        self.typed(value.expose(), token)
    }
}

/// Part 3 of a conversion body (MOD-08.21): split on its first character,
/// empty parts kept; `None` with fewer than `need` parts or a line feed in
/// the token.
fn third_part<'t>(content: &str, body: &'t str, need: usize) -> Option<&'t str> {
    let sep = body.chars().next()?;
    let ok = !content.contains('\n') && body.split(sep).nth(need.saturating_sub(1)).is_some();
    ok.then(|| body.split(sep).nth(2)).flatten()
}
