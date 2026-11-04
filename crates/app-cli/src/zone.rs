//! This Mac's local time zone, for db-info's RFC 3339 times (INT-10.31,
//! D-INT10-10) and the search language's local dates: macOS's own zone
//! rules through app-platform (LD-178), so `TZ` and every later year count.

use app_core::time::Zone;
use app_model::Time;

/// 1970-01-01T00:00:00Z in seconds since year 1 (FMT-12.1).
const UNIX_EPOCH: i64 = 62_135_596_800;

/// The local zone of this process.
pub struct Local;

impl Zone for Local {
    fn offset(&self, t: Time) -> i64 {
        app_platform::macos::utc_offset(t.0.saturating_sub(UNIX_EPOCH)).unwrap_or(0)
    }
}

/// RFC 3339 in the local zone, for example `2024-01-01T01:00:00+01:00`.
pub fn rfc3339(t: Time, zone: &dyn Zone) -> String {
    let off = zone.offset(t);
    let Some(c) = Time(t.0.saturating_add(off)).to_civil() else {
        return String::from("unknown");
    };
    let (sign, abs) = if off < 0 { ('-', -off) } else { ('+', off) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        abs / 3600,
        abs / 60 % 60
    )
}
