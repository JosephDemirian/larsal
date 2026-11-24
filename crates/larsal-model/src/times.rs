//! Timestamps (FMT-12.1) and the times block of groups and entries (FMT-11.12).

use crate::unknown::UnknownElement;

/// Seconds since 0001-01-01T00:00:00 UTC, proleptic Gregorian calendar,
/// 86,400 seconds a day, no leap seconds (FMT-12.1).
///
/// Guarantees: any 64-bit value is kept as is (FMT-12.8); calendar
/// conversion is only done with checked arithmetic and only inside
/// 0001-01-01T00:00:00Z ..= 9999-12-31T23:59:59Z.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Time(pub i64);

/// A calendar date and time in UTC, year 1 to 9999.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Civil {
    /// 1 to 9999.
    pub year: i64,
    /// 1 to 12.
    pub month: u32,
    /// 1 to 31.
    pub day: u32,
    /// 0 to 23.
    pub hour: u32,
    /// 0 to 59.
    pub minute: u32,
    /// 0 to 59.
    pub second: u32,
}

/// 1970-01-01T00:00:00Z in seconds since year 1.
const UNIX_EPOCH: i64 = 62_135_596_800;
/// 9999-12-31T23:59:59Z, the last time with a calendar date.
const MAX_CIVIL: i64 = 315_537_897_599;
/// Days from 0000-03-01 to 0001-01-01 in the era arithmetic below.
const MARCH_OFFSET: i64 = 306;

impl Time {
    /// Unix seconds to a time. `None` only on 64-bit overflow.
    #[must_use]
    pub fn from_unix(secs: i64) -> Option<Time> {
        secs.checked_add(UNIX_EPOCH).map(Time)
    }

    /// The time of a calendar date and time of day, or `None` when a field is
    /// out of range or the date does not exist (2010-02-30).
    #[must_use]
    pub fn from_civil(c: Civil) -> Option<Time> {
        if !(1..=9999).contains(&c.year)
            || !(1..=12).contains(&c.month)
            || c.day < 1
            || c.day > days_in_month(c.year, c.month)
            || c.hour > 23
            || c.minute > 59
            || c.second > 59
        {
            return None;
        }
        let days = days_from_civil(c.year, c.month, c.day);
        let secs = days * 86_400 + i64::from(c.hour * 3600 + c.minute * 60 + c.second);
        Some(Time(secs))
    }

    /// The calendar date and time, or `None` outside year 1 to 9999.
    #[must_use]
    pub fn to_civil(self) -> Option<Civil> {
        if !(0..=MAX_CIVIL).contains(&self.0) {
            return None;
        }
        let days = self.0.div_euclid(86_400);
        let rest = self.0.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        // In range: rest < 86,400 fits u32.
        let rest = u32::try_from(rest).ok()?;
        Some(Civil {
            year,
            month,
            day,
            hour: rest / 3600,
            minute: rest / 60 % 60,
            second: rest % 60,
        })
    }
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 0001-01-01 for a valid date of year 1 to 9999 (era arithmetic
/// on a calendar that starts on March 1, so the leap day is last).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - MARCH_OFFSET
}

/// The date of a day count since 0001-01-01; the inverse of `days_from_civil`
/// for counts inside year 1 to 9999.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + MARCH_OFFSET;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    // d is 1..=31 and m is 1..=12 by construction.
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// The times block of a group, live entry or history item (FMT-11.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Times {
    /// `LastModificationTime`.
    pub last_modification: Time,
    /// `CreationTime`.
    pub creation: Time,
    /// `LastAccessTime`.
    pub last_access: Time,
    /// `ExpiryTime`.
    pub expiry: Time,
    /// `Expires`.
    pub expires: bool,
    /// `UsageCount`, kept as read, negative included (FMT-11.13).
    pub usage_count: i32,
    /// `LocationChanged`.
    pub location_changed: Time,
    /// Kept unknown children of `Times` (FMT-11.45).
    pub unknown: Vec<UnknownElement>,
}

impl Times {
    /// Every time set to `t`, expires false, usage count 0: a new item
    /// (MOD-01.25) or a block read with nothing in it (FMT-11.12).
    #[must_use]
    pub fn all(t: Time) -> Times {
        Times {
            last_modification: t,
            creation: t,
            last_access: t,
            expiry: t,
            expires: false,
            usage_count: 0,
            location_changed: t,
            unknown: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn civil(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Civil {
        Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    // FMT-12.1 epoch and limits.
    #[test]
    fn fmt_12_1_reference_points() {
        assert_eq!(Time::from_civil(civil(1, 1, 1, 0, 0, 0)), Some(Time(0)));
        assert_eq!(
            Time::from_civil(civil(1970, 1, 1, 0, 0, 0)),
            Some(Time(62_135_596_800))
        );
        assert_eq!(
            Time::from_civil(civil(9999, 12, 31, 23, 59, 59)),
            Some(Time(315_537_897_599))
        );
        assert_eq!(
            Time::from_civil(civil(2010, 8, 8, 17, 24, 53)),
            Some(Time(63_416_885_093))
        );
        assert_eq!(Time::from_unix(0), Some(Time(62_135_596_800)));
    }

    #[test]
    fn impossible_dates_are_refused() {
        assert_eq!(Time::from_civil(civil(2010, 2, 30, 0, 0, 0)), None);
        assert_eq!(Time::from_civil(civil(2100, 2, 29, 0, 0, 0)), None);
        assert!(Time::from_civil(civil(2000, 2, 29, 0, 0, 0)).is_some());
        assert_eq!(Time::from_civil(civil(0, 1, 1, 0, 0, 0)), None);
        assert_eq!(Time::from_civil(civil(2016, 12, 31, 23, 59, 60)), None);
    }

    #[test]
    fn civil_round_trips_and_stays_in_range() {
        for t in [0, 1, 86_399, 86_400, 63_416_885_093, 315_537_897_599] {
            let c = Time(t).to_civil().unwrap();
            assert_eq!(Time::from_civil(c), Some(Time(t)));
        }
        assert_eq!(Time(-1).to_civil(), None);
        assert_eq!(Time(315_537_897_600).to_civil(), None);
        assert_eq!(Time(i64::MAX).to_civil(), None);
        assert_eq!(Time(i64::MIN).to_civil(), None);
    }

    #[test]
    fn every_day_of_400_years_round_trips() {
        let mut t = Time::from_civil(civil(1999, 1, 1, 0, 0, 0)).unwrap().0;
        let end = Time::from_civil(civil(2399, 1, 1, 0, 0, 0)).unwrap().0;
        while t < end {
            let c = Time(t).to_civil().unwrap();
            assert_eq!(Time::from_civil(c), Some(Time(t)));
            t += 86_400;
        }
    }
}
