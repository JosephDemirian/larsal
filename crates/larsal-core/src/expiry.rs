//! Expiry (MOD-09): expired and expires-within-N-days, the notice after
//! unlock, the `is:expired` search word, Expire now, the editors' expiry
//! controls and presets, and the expiry text and sort key.
//!
//! Guarantees: expiry is computed each time it is asked, never stored
//! (MOD-09.17); history items never count (MOD-09.5) and the recycle bin
//! is left out of every list (MOD-09.6); a stored time outside the calendar
//! range is compared as raw seconds and never converted (MOD-09.18).

use crate::edit::change_entry;
use crate::time::{Instant, Zone, add_local_days, add_local_months, local};
use crate::{Error, recycle};
use larsal_model::times::Civil;
use larsal_model::{Time, Times, Uuid, Vault};

/// The last second with a calendar date, 9999-12-31T23:59:59Z (FMT-12.8).
const MAX_CIVIL: i64 = 315_537_897_599;

/// Expired (MOD-09.2): `Expires` is on and `ExpiryTime` is strictly before
/// `now` at full precision; at exactly the stored second it is not yet. A
/// time below the calendar range is past; one above it never expires
/// (MOD-09.18).
#[must_use]
pub fn is_expired(t: &Times, now: Instant) -> bool {
    t.expires && Instant::from(t.expiry) < now
}

/// Expires within `days` days (MOD-09.3): expired, or `ExpiryTime` strictly
/// before local now plus `days` calendar days (the local time of day
/// stays). A window that reaches past what Larsal can compute holds every
/// in-range time (MOD-09.8); a time below the range is in every window and
/// one above it in none (MOD-09.18).
#[must_use]
pub fn expires_within(t: &Times, now: Instant, days: u32, zone: &dyn Zone) -> bool {
    if !t.expires || t.expiry.0 > MAX_CIVIL {
        return false;
    }
    // A time below the range is earlier than any clock time, so it is
    // already expired here.
    if is_expired(t, now) {
        return true;
    }
    match add_local_days(zone, now.secs, i64::from(days)) {
        Some(end) if end.0 <= MAX_CIVIL => {
            Instant::from(t.expiry)
                < Instant {
                    secs: end,
                    nanos: now.nanos,
                }
        }
        _ => true,
    }
}

/// The entries the `is:expired-N` search finds (MOD-09.3, MOD-09.8): live
/// entries within `days`, outside the recycle bin, in tree order. Group
/// expiry does not spread (MOD-09.4); history items never count (MOD-09.5).
#[must_use]
pub fn expired_entries(vault: &Vault, now: Instant, days: u32, zone: &dyn Zone) -> Vec<Uuid> {
    vault
        .root
        .subtree()
        .into_iter()
        .filter(|g| !recycle::group_in_bin(vault, g.uuid))
        .flat_map(|g| g.entries.iter())
        .filter(|e| expires_within(&e.times, now, days, zone))
        .map(|e| e.uuid)
        .collect()
}

/// The window of a search word after `is:` (MOD-09.8): `None` when the
/// word does not start with `expired` (any case); else N from the second
/// piece of the word split at `-` with empty pieces dropped, when it is a
/// whole number (a leading `+` allowed) that fits 32 signed bits; else 0.
#[must_use]
pub fn search_days(word: &str) -> Option<u32> {
    let head = word.get(..7)?;
    if !head.eq_ignore_ascii_case("expired") {
        return None;
    }
    let second = word.split('-').filter(|p| !p.is_empty()).nth(1);
    let digits = second.map(|p| p.strip_prefix('+').unwrap_or(p));
    Some(
        digits
            .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|d| d.parse::<u32>().ok())
            .filter(|&n| n <= 2_147_483_647)
            .unwrap_or(0),
    )
}

/// The notice after unlock (MOD-09.7, SR-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The search text put in the search field, `is:expired-N`.
    pub search: String,
    /// The matches, in tree order.
    pub entries: Vec<Uuid>,
    /// `MSG-09-1` (N = 0) or `MSG-09-2` (N > 0, with N).
    pub message: &'static str,
    /// N.
    pub days: u32,
}

/// The notice settings (MOD-09 settings table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoticeSettings {
    /// `expiry.notice_on_unlock`, default on.
    pub on: bool,
    /// `expiry.notice_days`, default 3, 0 to 90.
    pub days: u32,
}

impl Default for NoticeSettings {
    fn default() -> Self {
        Self { on: true, days: 3 }
    }
}

/// The notice to show after an unlock (MOD-09.7): only when the setting is
/// on, only on the first unlock since the vault was opened, and only when
/// the search finds something; over the whole vault, whatever limits search
/// to the current group.
#[must_use]
pub fn notice(
    vault: &Vault,
    settings: NoticeSettings,
    first_unlock: bool,
    now: Instant,
    zone: &dyn Zone,
) -> Option<Notice> {
    if !settings.on || !first_unlock {
        return None;
    }
    let days = settings.days.min(90);
    let entries = expired_entries(vault, now, days, zone);
    (!entries.is_empty()).then(|| Notice {
        search: format!("is:expired-{days}"),
        entries,
        message: if days == 0 { "MSG-09-1" } else { "MSG-09-2" },
        days,
    })
}

/// Expire now (MOD-09.9) for the selected entries, the recycle bin
/// included: `ExpiryTime` = now, `Expires` on, modification and access
/// times = now; no history item. One change batch. Returns how many
/// entries changed.
///
/// # Errors
/// `NoSuchEntry` for any id (nothing changes then).
pub fn expire_now(vault: &mut Vault, ids: &[Uuid], now: Time) -> Result<usize, Error> {
    if ids
        .iter()
        .any(|&id| crate::tree::entry(vault, id).is_none())
    {
        return Err(Error::NoSuchEntry);
    }
    let mut changed = 0usize;
    for &id in ids {
        let did = change_entry(vault, id, now, |e| {
            (e.times.expires, e.times.expiry) = (true, now);
        })?;
        changed = changed.saturating_add(usize::from(did));
    }
    Ok(changed)
}

/// The expiry controls of an editor (MOD-09.10, MOD-09.12): the box and the
/// date-time field. Saving writes both, also while the box is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Controls {
    /// The expires box.
    pub expires: bool,
    /// The field's value (UTC); kept while the box is off.
    pub time: Time,
}

impl Controls {
    /// Loaded from an item.
    #[must_use]
    pub fn load(t: &Times) -> Self {
        Self {
            expires: t.expires,
            time: t.expiry,
        }
    }

    /// Ticks the box in the entry editor: the field becomes now (MOD-09.10).
    pub fn tick_entry(&mut self, now: Time) {
        (self.expires, self.time) = (true, now);
    }

    /// Ticks the box in the group editor: the time does not change
    /// (MOD-09.12).
    pub fn tick_group(&mut self) {
        self.expires = true;
    }

    /// Unticks the box; the field keeps its value.
    pub fn untick(&mut self) {
        self.expires = false;
    }

    /// Chooses a preset (MOD-09.11): ticks the box and sets the field to
    /// local now plus the amount, whole seconds (MOD-09.13). `false` when
    /// the result is past what Larsal can compute (nothing changes then).
    pub fn preset(&mut self, p: Preset, now: Time, zone: &dyn Zone) -> bool {
        match p.apply(now, zone) {
            Some(t) => {
                (self.expires, self.time) = (true, t);
                true
            }
            None => false,
        }
    }

    /// Writes both values into an item's times (MOD-09.10 saving).
    pub fn save(&self, t: &mut Times) {
        (t.expires, t.expiry) = (self.expires, self.time);
    }
}

/// The presets menu of the entry editor (MOD-09.11), in menu order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Exact elapsed hours.
    Hours(u8),
    /// Calendar weeks in local time.
    Weeks(u8),
    /// Calendar months in local time, the day kept where possible.
    Months(u8),
    /// Calendar years in local time, the day kept where possible.
    Years(u8),
}

/// The 12 presets in 4 groups, in the menu's order (MOD-09.11).
pub const PRESETS: [Preset; 12] = [
    Preset::Hours(12),
    Preset::Hours(24),
    Preset::Weeks(1),
    Preset::Weeks(2),
    Preset::Weeks(3),
    Preset::Months(1),
    Preset::Months(2),
    Preset::Months(3),
    Preset::Months(6),
    Preset::Years(1),
    Preset::Years(2),
    Preset::Years(3),
];

impl Preset {
    /// `now` plus the amount (MOD-09.11).
    #[must_use]
    pub fn apply(self, now: Time, zone: &dyn Zone) -> Option<Time> {
        match self {
            Self::Hours(h) => now.0.checked_add(i64::from(h).checked_mul(3600)?).map(Time),
            Self::Weeks(w) => add_local_days(zone, now, i64::from(w).checked_mul(7)?),
            Self::Months(m) => add_local_months(zone, now, i64::from(m)),
            Self::Years(y) => add_local_months(zone, now, i64::from(y).checked_mul(12)?),
        }
    }
}

/// How an expiry is shown as text (MOD-09.15, MOD-09.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    /// `Expires` is off: the "never" text.
    Never,
    /// The local date and time, for the short format.
    Local(Civil),
    /// A time outside the calendar range: `MSG-09-3`.
    Invalid,
}

/// The expiry as the preview, the Expires column and the group preview show
/// it, in local time (MOD-09.15, D-09-2).
#[must_use]
pub fn shown(t: &Times, zone: &dyn Zone) -> Shown {
    if !t.expires {
        return Shown::Never;
    }
    local(zone, t.expiry)
        .and_then(Time::to_civil)
        .filter(|_| (0..=MAX_CIVIL).contains(&t.expiry.0))
        .map_or(Shown::Invalid, Shown::Local)
}

/// The Expires column's sort key (MOD-09.15, MOD-09.18): `ExpiryTime`, with
/// "never" as 9999-01-01 and times outside the range by their raw value.
#[must_use]
pub fn sort_key(t: &Times) -> i64 {
    /// 9999-01-01T00:00:00Z.
    const NEVER: i64 = 315_506_361_600;
    if t.expires { t.expiry.0 } else { NEVER }
}
