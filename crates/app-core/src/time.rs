//! The clock and local time: expiry windows (MOD-09.3), presets (MOD-09.11)
//! and date placeholders (MOD-08.10).
//!
//! app-core makes no OS calls, so the time zone comes in through [`Zone`]
//! (lead decision D-09-1 (b)); app-platform implements it with the
//! system's zone rules, tests with fixed rules.
//!
//! Guarantees: every conversion uses checked arithmetic and gives `None`
//! outside what it can compute, never a wrapped value (FMT-12.8).

use app_model::Time;
use app_model::times::Civil;

/// Local time zone rules.
pub trait Zone {
    /// Seconds to add to the UTC instant `t` to get the local wall-clock
    /// time there.
    fn offset(&self, t: Time) -> i64;

    /// The UTC instant of the local wall-clock time `local`. A local time
    /// that happens twice (clocks set back) takes the first; one that does
    /// not exist (clocks set forward) moves forward by the gap.
    fn utc(&self, local: Time) -> Option<Time> {
        let before = self.offset(Time(local.0.checked_sub(86_400)?));
        let after = self.offset(Time(local.0.checked_add(86_400)?));
        let fits = |o: i64| {
            local
                .0
                .checked_sub(o)
                .map(Time)
                .filter(|&t| self.offset(t) == o)
        };
        match (fits(before), fits(after)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => local.0.checked_sub(before).map(Time),
        }
    }
}

/// UTC itself, for `DT_UTC_` placeholders and tests.
#[derive(Debug, Clone, Copy)]
pub struct Utc;

impl Zone for Utc {
    fn offset(&self, _: Time) -> i64 {
        0
    }
}

/// An instant at full clock precision, for the strict expiry test of
/// MOD-09.2 (stored times have whole seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    /// Whole seconds.
    pub secs: Time,
    /// Nanoseconds past `secs`, below 1,000,000,000.
    pub nanos: u32,
}

impl From<Time> for Instant {
    fn from(secs: Time) -> Self {
        Self { secs, nanos: 0 }
    }
}

/// The local wall-clock time of the UTC instant `t`.
#[must_use]
pub fn local(zone: &dyn Zone, t: Time) -> Option<Time> {
    t.0.checked_add(zone.offset(t)).map(Time)
}

/// `t` plus `days` calendar days in local time: the local date moves, the
/// local time of day stays (MOD-09.3, MOD-09.11 weeks).
#[must_use]
pub fn add_local_days(zone: &dyn Zone, t: Time, days: i64) -> Option<Time> {
    let moved = local(zone, t)?.0.checked_add(days.checked_mul(86_400)?)?;
    zone.utc(Time(moved))
}

/// `t` plus `months` calendar months in local time, keeping the day where
/// the month has it and otherwise taking its last day (MOD-09.11:
/// 31 January + 1 month = 28 or 29 February). `None` outside year 1 to
/// 9999.
#[must_use]
pub fn add_local_months(zone: &dyn Zone, t: Time, months: i64) -> Option<Time> {
    let c = local(zone, t)?.to_civil()?;
    let index = c
        .year
        .checked_mul(12)?
        .checked_add(i64::from(c.month))?
        .checked_sub(1)?
        .checked_add(months)?;
    let year = index.div_euclid(12);
    let month = u32::try_from(index.rem_euclid(12)).ok()?.checked_add(1)?;
    // The last day that exists: day, or 30, 29 or 28 of a shorter month.
    let moved = [c.day, 30, 29, 28]
        .into_iter()
        .filter(|&d| d <= c.day)
        .find_map(|day| {
            Time::from_civil(Civil {
                year,
                month,
                day,
                ..c
            })
        })?;
    zone.utc(moved)
}
