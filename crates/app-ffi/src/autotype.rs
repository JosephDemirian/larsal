//! E8-S2 wiring (spec INT-05.19 to INT-05.31): global Auto-Type over the
//! session's unlocked vaults on app-autotype's picker model. Swift captures
//! the window in front, shows the picker and sends back the user's choice;
//! Rust matches, lists, remembers the choice (S-AT-08) and makes the plan.
//!
//! Guarantees (INT-05.45, AGENTS.md rule 4, LD-191 R02-2):
//! - a picker row carries ids, a title, a user name and the logo's inputs,
//!   never a sequence or a value; a title or user name that is protected or
//!   reads a protected, one-time password or passkey value is the mask
//!   (LD-207);
//! - the plan stays in Rust behind a handle; only the typer reads it, and it
//!   checks the window before every key (AT-G02, INT-05.39);
//! - a lock, lock-all or close closes the picker, drops the plan and the
//!   remembered choice of that vault (SR-16, INT-05.31).

use crate::app_settings::AppSettingsStore;
use crate::session::{MAX_TEXT, Session};
use crate::views::{self, Offset};
use app_autotype::{
    Layout, Memory, Mods, Open, Options, Picker, Plan, Row, Scope, Settings, Shortcut,
};
use app_core::health::MASKED_TITLE;
use app_core::refs::Context;
use app_model::{Entry, Uuid, Vault};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::Instant;

/// One picker row (INT-05.26): what the frame draws. No secret, no sequence.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutoTypeRow {
    /// The vault's session id.
    pub vault: u64,
    /// The entry's id (32 hex digits).
    pub entry: String,
    /// The title resolved for display; the mask when hidden (LD-207).
    pub title: String,
    /// The user name, as the title.
    pub username: String,
    /// Expired (MOD-09.14): drawn struck through.
    pub expired: bool,
    /// The URL's host for the logo; empty when protected or missing.
    pub host: String,
    /// The standard icon number; -1 for a custom icon.
    pub icon: i32,
    /// The custom icon's name.
    pub custom_icon: Option<String>,
}

/// The picker's list and its highlighted row (INT-05.27, INT-05.28).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutoTypeList {
    /// Sorted rows; a choice names a row by its position.
    pub rows: Vec<AutoTypeRow>,
    /// The highlighted row (0 when the list is empty).
    pub highlight: u32,
}

/// What the global shortcut leads to (INT-05.25 steps 5 to 7).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AutoTypeStart {
    /// No vault is open: the system alert sound, nothing else.
    NoVault,
    /// The vault shown in App's window is locked: it must be unlocked first.
    Locked {
        /// The shown vault.
        vault: u64,
    },
    /// Open the picker with this list.
    Picker {
        /// The list for an empty search field.
        list: AutoTypeList,
    },
    /// S-AT-03 is off and exactly one row matched: type it.
    Type {
        /// The plan's handle for [`Session::autotype_type`].
        plan: u64,
    },
    /// The sequence cannot be typed: MI05-10 with this reason (INT-05.15).
    Failed {
        /// MI05-11 to MI05-27, never a value.
        reason: String,
        /// Its message id (`MI05-12`), for the debug log (INT-05.47).
        code: String,
    },
}

/// A type action of the picker (INT-05.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AutoTypeAction {
    /// Return: the row's sequence.
    Login,
    /// ⌘1: `{USERNAME}`.
    Username,
    /// ⇧Return and ⌘2: `{PASSWORD}`.
    Password,
    /// ⌘3: `{TOTP}`.
    Code,
    /// ⌘4: `{URL}`.
    Url,
    /// ⌘5: the row's sequence with key codes (INT-05.41).
    KeyCodes,
}

/// The answer to a choice; the picker is closed in every case.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AutoTypeChosen {
    /// Type this plan.
    Type {
        /// The plan's handle.
        plan: u64,
    },
    /// MI05-10 with this reason.
    Failed {
        /// MI05-11 to MI05-27.
        reason: String,
        /// Its message id (`MI05-12`), for the debug log (INT-05.47).
        code: String,
    },
    /// The row is gone (its entry was deleted, its vault locked): nothing is
    /// typed.
    Gone,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AutoTypeEnd {
    /// Every key went out.
    Finished {
        /// Key events made.
        keys: u32,
    },
    /// The run stopped (INT-05.38, INT-05.39): the system alert sound.
    Stopped {
        /// Key presses made before the stop.
        keys: u32,
        /// Why, for the debug log (INT-05.47): `not-in-front` (step 1),
        /// `keys-held` (step 3), `window-changed` (AT-G02), `stopped` (a
        /// lock, the shortcut again) or `no-event-source`.
        reason: String,
    },
    /// The plan has `{PICKCHARS}` and no pick dialog yet (W-06): nothing
    /// was typed.
    NeedsPicks,
    /// No such plan (typed already, or dropped by a lock).
    Gone,
}

/// The global shortcut S-AT-07 as Carbon's hot key service takes it: the
/// virtual key code and its modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct AutoTypeHotKey {
    /// The virtual key code (`kVK_ANSI_*`).
    pub code: u16,
    /// ⌃.
    pub control: bool,
    /// ⌥.
    pub option: bool,
    /// ⇧.
    pub shift: bool,
    /// ⌘.
    pub command: bool,
}

/// The typer's window check, implemented in Swift over the captured target
/// (INT-05.37, INT-05.39).
#[uniffi::export(with_foreign)]
pub trait AutoTypeFocus: Send + Sync {
    /// True while the captured app is the active app and its focused window
    /// is the captured window.
    fn same_window(&self) -> bool;
}

/// The session's Auto-Type state; no value outside the plan.
#[derive(Default)]
pub(crate) struct State {
    /// The open picker's matches and the list it shows.
    picker: Option<(Picker, Vec<Row>)>,
    /// S-AT-08.
    memory: Memory,
    /// One run at a time (INT-05.46): the last plan made, with its handle.
    plan: Option<(u64, Plan)>,
    next: u64,
    /// The keyboard layout of the run (INT-05.41), Swift's table (E8-S3).
    pub(crate) layout: Layout,
    /// The running plan's stop flag: a lock or the shortcut again sets it
    /// (INT-05.39).
    pub(crate) stop: Arc<AtomicBool>,
    /// Runs post their events to macOS (App's own launch only).
    pub(crate) post: bool,
}

/// S-AT-07 as E5-S9 stores it (`⌃⌥V`): the modifier signs, then one key
/// at its US position (`kVK_ANSI_*`, Carbon `Events.h`). `None` when empty,
/// unknown, or without ⌘ or ⌃ (INT-05.30). ponytail: letters, digits and
/// punctuation of the main block only; the recorder (W-06) stores others.
fn hot_key(text: &str) -> Option<Shortcut> {
    // Index = key code; `\0` marks codes that type no character here.
    const ANSI: &str = "ASDFHGZXCV\0BQWERYT123465=97-80]OU[IP\0LJ'K;\\,/NM.";
    let mut mods = Mods::NONE;
    let mut rest = text.trim().chars();
    let key = loop {
        match rest.next()? {
            '⌃' => mods = mods | Mods::CONTROL,
            '⌥' => mods = mods | Mods::OPTION,
            '⇧' => mods = mods | Mods::SHIFT,
            '⌘' => mods = mods | Mods::COMMAND,
            c => break c.to_ascii_uppercase(),
        }
    };
    let code = ANSI.chars().position(|k| k == key && k != '\0')?;
    let valid = mods.contains(Mods::COMMAND) || mods.contains(Mods::CONTROL);
    (rest.next().is_none() && valid).then_some(Shortcut {
        code: u16::try_from(code).ok()?,
        mods,
    })
}

fn settings(store: &AppSettingsStore) -> Settings {
    let flag = |key: &str| store.flag(key.to_owned());
    Settings {
        by_title: flag("autotype.match_title"),
        by_url: flag("autotype.match_url"),
        always_ask: flag("autotype.always_ask"),
        dont_ask_from_window: flag("autotype.skip_ask_main_window"),
        skip_expired: flag("autotype.hide_expired"),
        remember_secs: u32::try_from(store.number("autotype.retype_seconds".to_owned()))
            .unwrap_or(0),
    }
}

/// The vault folder for `{DB_DIR}`.
fn dir(path: &Path) -> String {
    path.parent().unwrap_or(path).to_string_lossy().into_owned()
}

/// The display record of `row`; `found` is its vault and live entry.
fn shown(row: &Row, found: Option<(&Vault, &Entry)>) -> AutoTypeRow {
    let masked = |hidden: bool, text: &str| {
        if hidden {
            MASKED_TITLE.to_owned()
        } else {
            text.to_owned()
        }
    };
    AutoTypeRow {
        vault: row.vault,
        entry: views::hex(row.entry),
        title: masked(row.title_hidden, &row.title),
        username: masked(row.username_hidden, &row.username),
        expired: row.expired,
        host: found
            .map(|(v, e)| views::plain_in(v, e, "URL"))
            .filter(|u| !u.is_empty())
            .map(|u| views::host(&u))
            .unwrap_or_default(),
        icon: found.map_or(0, |(_, e)| views::icon_number(e.icon)),
        custom_icon: found.and_then(|(v, e)| views::custom_icon_name(v, e.icon)),
    }
}

/// Every unlocked vault as matching takes it.
fn opens<'a>(slots: &[(u64, Option<&'a Vault>, &Path)], dirs: &'a [String]) -> Vec<Open<'a>> {
    slots
        .iter()
        .zip(dirs)
        .filter_map(|((id, vault, _), dir)| {
            vault.map(|vault| Open {
                id: *id,
                vault,
                dir,
            })
        })
        .collect()
}

impl Session {
    pub(crate) fn autotype(&self) -> MutexGuard<'_, State> {
        self.autotype.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A lock, lock-all (`None`) or close: the picker closes, the plan goes,
    /// and the remembered choice of that vault (SR-16, INT-05.31).
    pub(crate) fn autotype_locked(&self, vault: Option<u64>) {
        let mut at = self.autotype();
        at.picker = None;
        at.plan = None;
        at.stop.store(true, Ordering::SeqCst);
        match vault {
            Some(id) => at.memory.forget_vault(id),
            None => at.memory = Memory::default(),
        }
    }

    /// The plan of `sequence` for `entry` (INT-05.15), stored under a new
    /// handle in place of any earlier one.
    fn make_plan(
        &self,
        at: &mut State,
        open: &Open<'_>,
        entry: &Entry,
        sequence: &str,
        offset: i64,
    ) -> Result<u64, app_autotype::Error> {
        let store = &self.settings;
        let number = |key: &str| u32::try_from(store.number(key.to_owned())).unwrap_or(0);
        let layout = at.layout.clone();
        let opts = Options {
            layout: &layout,
            shortcut: hot_key(&store.text("autotype.global_shortcut".to_owned())),
            start_delay_ms: number("autotype.start_delay_ms"),
            key_pause_ms: number("autotype.key_delay_ms"),
        };
        let zone = Offset(offset);
        let ctx = Context {
            vault_dir: open.dir,
            zone: &zone,
            ..Context::new(Some(open.vault), views::now())
        };
        let plan = app_autotype::plan(sequence, entry, &ctx, &opts)?;
        at.next = at.next.wrapping_add(1);
        at.plan = Some((at.next, plan));
        // The run's stop flag is born with its plan, so the shortcut pressed
        // after Swift marks the run typing, before the typing thread starts,
        // still stops it (LD-234 (1)); an earlier stop never reaches it.
        at.stop = Arc::new(AtomicBool::new(false));
        Ok(at.next)
    }

    /// The sorted list for `search` with the remembered choice highlighted.
    fn picker_list(
        at: &mut State,
        picker: &Picker,
        search: &str,
        scope: &Scope<'_>,
    ) -> AutoTypeList {
        let (rows, _) = picker.rows(search, scope);
        let entries: HashMap<(u64, Uuid), (&Vault, &Entry)> = scope
            .vaults
            .iter()
            .flat_map(|o| {
                views::live(o.vault)
                    .into_iter()
                    .map(|e| ((o.id, e.uuid), (o.vault, e)))
            })
            .collect();
        let list = AutoTypeList {
            rows: rows
                .iter()
                .map(|r| shown(r, entries.get(&(r.vault, r.entry)).copied()))
                .collect(),
            highlight: u32::try_from(at.memory.highlight(&rows, Instant::now())).unwrap_or(0),
        };
        at.picker = Some((picker.clone(), rows));
        list
    }
}

#[uniffi::export]
impl Session {
    /// INT-05.25 steps 5 to 7 for the captured window `title` (its first
    /// 64 KiB; a longer one counts as empty, INT-05.22a): matches every
    /// unlocked vault, then says what to do. `utc_offset` is the screen's,
    /// for date placeholders. Steps 1 to 4 (App in front, a picker or run
    /// already open, the capture, the permission) are Swift's.
    #[must_use]
    pub fn autotype_start(&self, title: String, utc_offset: i32) -> AutoTypeStart {
        let title = if title.len() > MAX_TEXT {
            String::new()
        } else {
            title
        };
        let settings = settings(&self.settings);
        let offset = i64::from(utc_offset);
        let mut at = self.autotype();
        at.picker = None;
        self.with_slots(|slots, shown| {
            if slots.is_empty() {
                return AutoTypeStart::NoVault;
            }
            if let Some(vault) =
                shown.filter(|id| slots.iter().any(|(i, v, _)| i == id && v.is_none()))
            {
                return AutoTypeStart::Locked { vault };
            }
            let dirs: Vec<String> = slots.iter().map(|(_, _, p)| dir(p)).collect();
            let opens = opens(slots, &dirs);
            let zone = Offset(offset);
            let scope = Scope {
                vaults: &opens,
                now: views::now(),
                zone: &zone,
                settings: &settings,
            };
            let picker = Picker::open(&title, &scope);
            // INT-05.31: a single match typed without the picker is not
            // remembered.
            let single = picker.single("").and_then(|row| {
                let open = opens.iter().find(|o| o.id == row.vault)?;
                let entry = views::live(open.vault)
                    .into_iter()
                    .find(|e| e.uuid == row.entry)?;
                Some((open, entry, row.sequence.as_str()))
            });
            if let Some((open, entry, sequence)) = single {
                return match self.make_plan(&mut at, open, entry, sequence, offset) {
                    Ok(plan) => AutoTypeStart::Type { plan },
                    Err(e) => AutoTypeStart::Failed {
                        reason: e.to_string(),
                        code: e.id().to_owned(),
                    },
                };
            }
            AutoTypeStart::Picker {
                list: Self::picker_list(&mut at, &picker, "", &scope),
            }
        })
    }

    /// The open picker's list for the search field's text (INT-05.27,
    /// INT-05.28); empty when no picker is open (a lock closed it).
    #[must_use]
    pub fn autotype_rows(&self, search: String, utc_offset: i32) -> AutoTypeList {
        let empty = AutoTypeList {
            rows: Vec::new(),
            highlight: 0,
        };
        let mut at = self.autotype();
        let Some((picker, _)) = at.picker.clone() else {
            return empty;
        };
        if search.len() > MAX_TEXT {
            return empty;
        }
        let settings = settings(&self.settings);
        self.with_slots(|slots, _| {
            let dirs: Vec<String> = slots.iter().map(|(_, _, p)| dir(p)).collect();
            let opens = opens(slots, &dirs);
            let zone = Offset(i64::from(utc_offset));
            let scope = Scope {
                vaults: &opens,
                now: views::now(),
                zone: &zone,
                settings: &settings,
            };
            Self::picker_list(&mut at, &picker, &search, &scope)
        })
    }

    /// The user chose row `index` of the list last given with `action`
    /// (INT-05.29): the picker closes, the plan is made in Rust and the
    /// choice is remembered for S-AT-08 seconds (INT-05.31). Only the
    /// plan's handle comes back.
    #[must_use]
    pub fn autotype_choose(
        &self,
        index: u32,
        action: AutoTypeAction,
        utc_offset: i32,
    ) -> AutoTypeChosen {
        let settings = settings(&self.settings);
        let mut at = self.autotype();
        let row = at
            .picker
            .take()
            .and_then(|(_, rows)| rows.into_iter().nth(usize::try_from(index).ok()?));
        let Some(mut row) = row else {
            return AutoTypeChosen::Gone;
        };
        row.sequence = match action {
            AutoTypeAction::Login => row.sequence,
            AutoTypeAction::Username => "{USERNAME}".to_owned(),
            AutoTypeAction::Password => "{PASSWORD}".to_owned(),
            AutoTypeAction::Code => "{TOTP}".to_owned(),
            AutoTypeAction::Url => "{URL}".to_owned(),
            AutoTypeAction::KeyCodes => format!("{{MODE=VIRTUAL}}{}", row.sequence),
        };
        self.with_slots(|slots, _| {
            let dirs: Vec<String> = slots.iter().map(|(_, _, p)| dir(p)).collect();
            let opens = opens(slots, &dirs);
            let Some(open) = opens.iter().find(|o| o.id == row.vault) else {
                return AutoTypeChosen::Gone;
            };
            // Still a candidate (INT-05.19): not deleted, not in the bin. Its
            // effective sequence may be empty; the row has its own (R05-1).
            let now = views::now();
            let entry = views::live(open.vault)
                .into_iter()
                .find(|e| e.uuid == row.entry);
            let Some(entry) =
                entry.filter(|_| app_autotype::is_candidate(open, row.entry, &settings, now))
            else {
                return AutoTypeChosen::Gone;
            };
            match self.make_plan(&mut at, open, entry, &row.sequence, i64::from(utc_offset)) {
                Ok(plan) => {
                    at.memory
                        .remember(&row, settings.remember_secs, Instant::now());
                    AutoTypeChosen::Type { plan }
                }
                Err(e) => AutoTypeChosen::Failed {
                    reason: e.to_string(),
                    code: e.id().to_owned(),
                },
            }
        })
    }

    /// The picker closed without typing (Escape, another app active, the
    /// target quit; INT-05.29).
    pub fn autotype_close(&self) {
        self.autotype().picker = None;
    }

    /// Runs plan `plan` (INT-05.38 to INT-05.43, app-autotype `type_plan`):
    /// waits until `focus` says the captured window is in front (at most
    /// 2 s), the start delay, and until no modifier key is held (at most
    /// 2 s); then makes each key event in Rust. Before every key it asks
    /// `focus` and stops at the first no, or once a lock or
    /// [`Session::autotype_stop`] stopped the run (AT-G02, INT-05.39). The
    /// plan is used once. Events reach macOS only after
    /// [`Session::autotype_post_events`]; until then a recorder takes them
    /// and nothing is posted. It waits, so Swift calls it off the main
    /// thread.
    #[must_use]
    pub fn autotype_type(&self, plan: u64, focus: Arc<dyn AutoTypeFocus>) -> AutoTypeEnd {
        let taken = {
            let mut at = self.autotype();
            match at.plan.take() {
                Some((id, p)) if id == plan => Some((p, Arc::clone(&at.stop), at.post)),
                other => {
                    at.plan = other;
                    None
                }
            }
        };
        let Some((plan, stop, post)) = taken else {
            return AutoTypeEnd::Gone;
        };
        crate::autotype_typing::run(&plan, &*focus, &stop, post)
    }

    /// The global shortcut to register (S-AT-07, INT-05.30); `None` when
    /// it is cleared or not valid.
    #[must_use]
    pub fn autotype_hot_key(&self) -> Option<AutoTypeHotKey> {
        let key = hot_key(&self.settings.text("autotype.global_shortcut".to_owned()))?;
        Some(AutoTypeHotKey {
            code: key.code,
            control: key.mods.contains(Mods::CONTROL),
            option: key.mods.contains(Mods::OPTION),
            shift: key.mods.contains(Mods::SHIFT),
            command: key.mods.contains(Mods::COMMAND),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit::EditText;
    use app_model::Switch;
    use std::sync::Arc;

    /// The captured window stays in front.
    struct Same;

    impl AutoTypeFocus for Same {
        fn same_window(&self) -> bool {
            true
        }
    }

    /// The R05-1 vault: group Off > group On > entry Quiet with the window
    /// rule `*Quiet*` → `{PASSWORD}`. Gives the session, the vault, Quiet's
    /// id and the temp folder to delete.
    fn quiet(tag: &str) -> (Arc<Session>, u64, String, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("app-ffi-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Work.appvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-work.appvault"
            ),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-8".into()), None).unwrap();
        let off = s.add_group(v, None, "Off".into(), 0, None).unwrap();
        let on = s.add_group(v, Some(off), "On".into(), 0, None).unwrap();
        s.begin_new(v, Some(on)).unwrap();
        s.set_text(v, EditText::Title, "Quiet".into()).unwrap();
        s.set_password(v, "demo-quiet".into()).unwrap();
        s.add_window(v, "*Quiet*".into(), "{PASSWORD}".into())
            .unwrap();
        let quiet = s.commit_edit(v).unwrap();
        s.with_edit(v, |vault, _, _, _| {
            let off = vault.root.groups.iter_mut().find(|g| g.name == "Off");
            let off = off.ok_or(crate::session::AppError::UnknownGroup)?;
            off.auto_type = Switch::Off;
            off.groups[0].auto_type = Switch::On;
            Ok(())
        })
        .unwrap();
        (s, v, quiet, dir)
    }

    /// R05-1, INT-05.19, INT-05.29: an entry in a group set On below a
    /// group set Off has an empty effective sequence (E10's case), so Type
    /// Login is off, but its window rule `*Quiet*` → `{PASSWORD}` gives a
    /// row, and Return and ⇧Return in the picker type that row. The group
    /// switches have no bridge call yet, so the test sets them in the model.
    #[test]
    fn r05_1_the_row_of_an_empty_effective_sequence_is_typed() {
        let (s, _, quiet, dir) = quiet("r05-1");
        for action in [AutoTypeAction::Login, AutoTypeAction::Password] {
            let AutoTypeStart::Picker { list } = s.autotype_start("Quiet".into(), 0) else {
                panic!("always ask is on: a picker")
            };
            assert_eq!(list.rows.len(), 1);
            assert_eq!(list.rows[0].entry, quiet);
            let AutoTypeChosen::Type { plan } = s.autotype_choose(0, action, 0) else {
                panic!("{action:?} types the row")
            };
            // `{PASSWORD}`: the 10 characters of "demo-quiet".
            assert_eq!(
                s.autotype_type(plan, Arc::new(Same)),
                AutoTypeEnd::Finished { keys: 10 }
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// INT-05.19: a row is typed only while its entry is still a candidate.
    /// The picker is open for Quiet; then the entry's own Auto-Type switch
    /// goes off, or its group goes back to Inherit (so Off rules): Gone.
    #[test]
    fn int_05_19_a_row_that_is_no_longer_a_candidate_is_gone() {
        let (s, v, quiet, dir) = quiet("int-05-19");
        let open = || {
            let AutoTypeStart::Picker { list } = s.autotype_start("Quiet".into(), 0) else {
                panic!("always ask is on: a picker")
            };
            assert_eq!(list.rows.len(), 1);
        };
        open();
        s.begin_edit(v, quiet.clone()).unwrap();
        s.set_auto_type(v, false, String::new()).unwrap();
        s.commit_edit(v).unwrap();
        assert_eq!(
            s.autotype_choose(0, AutoTypeAction::Login, 0),
            AutoTypeChosen::Gone
        );

        s.begin_edit(v, quiet).unwrap();
        s.set_auto_type(v, true, String::new()).unwrap();
        s.commit_edit(v).unwrap();
        open();
        s.with_edit(v, |vault, _, _, _| {
            let off = vault.root.groups.iter_mut().find(|g| g.name == "Off");
            let off = off.ok_or(crate::session::AppError::UnknownGroup)?;
            off.groups[0].auto_type = Switch::Inherit;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            s.autotype_choose(0, AutoTypeAction::Login, 0),
            AutoTypeChosen::Gone
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
