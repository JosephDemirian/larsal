//! Vault statistics (FEA-07, story E4-S11): one computation for the
//! Statistics tab and the command line's database info (FEA-07.21).
//!
//! Guarantees:
//! - The result holds numbers and the vault's name, description, file path
//!   and times only: never a password, hash or other protected value.
//! - Passwords are compared in place, by reference to the vault's own
//!   values; no copy, digest or map of them is made (FEA-07 security
//!   notes). The weak count runs the Health Check's own scoring (FEA-07.10).
//! - The recycle bin and everything in it are left out; history never
//!   counts (FEA-07.1). A bin reference naming the root means no bin
//!   (LD-76).

use crate::expiry::is_expired;
use crate::health::{self, Item, Ratings, Reuse, live_items};
use crate::search::run::PASSKEY;
use crate::time::{Instant, Zone};
use crate::{recycle, totp};
use larsal_model::{Time, Vault};

/// What storage knows about the vault's file (FEA-07.15).
#[derive(Debug, Clone, Copy, Default)]
pub struct FileInfo<'a> {
    /// The full path; `None` for a vault never saved.
    pub path: Option<&'a str>,
    /// The file's modification time on disk, read when the tab opens.
    pub modified: Option<Time>,
    /// Changes not yet written to disk.
    pub unsaved: bool,
}

/// The statistics record (FEA-07 output rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    /// `stat.entries`.
    pub entries: u64,
    /// `stat.groups`, the root included.
    pub groups: u64,
    /// `stat.unique_pw`.
    pub unique_pw: u64,
    /// `stat.reused_pw`.
    pub reused_pw: u64,
    /// `stat.max_reuse`.
    pub max_reuse: u64,
    /// `stat.weak_pw`.
    pub weak_pw: u64,
    /// `stat.short_pw`.
    pub short_pw: u64,
    /// `stat.expired`.
    pub expired: u64,
    /// `stat.totp`.
    pub totp: u64,
    /// `stat.passkeys`.
    pub passkeys: u64,
    /// `stat.avg_len`, in UTF-16 units (FEA-07.18).
    pub avg_len: u64,
    /// `stat.excluded`.
    pub excluded: u64,
    /// `info.name`.
    pub name: String,
    /// `info.description`.
    pub description: String,
    /// `info.location`; empty for a vault never saved.
    pub location: String,
    /// `info.created`: the root group's creation time.
    pub created: Time,
    /// `info.last_saved`: the file's modification time; `None` without one.
    pub last_saved: Option<Time>,
    /// `info.unsaved`.
    pub unsaved: bool,
}

/// FEA-07.18: lengths count UTF-16 code units.
fn units(s: &str) -> u64 {
    u64::try_from(s.encode_utf16().count()).unwrap_or(u64::MAX)
}

fn n(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// Computes every row (FEA-07.1 to FEA-07.15).
#[must_use]
pub fn statistics(
    ratings: &Ratings<'_>,
    vault: &Vault,
    file: &FileInfo<'_>,
    now: Instant,
    zone: &dyn Zone,
) -> Stats {
    let items = live_items(vault);
    let groups = n(vault.root.subtree().len().saturating_sub(bin_groups(vault)));
    let reuse = Reuse::new(&items);
    let with_pw: Vec<usize> = (0..items.len())
        .filter(|&i| {
            items
                .get(i)
                .is_some_and(|it| !it.e.value("Password").is_empty())
        })
        .collect();
    let (unique, max_reuse) = distinct(&items, &with_pw);
    let mut s = Stats {
        entries: n(items.len()),
        groups,
        unique_pw: unique,
        reused_pw: n(with_pw.len()).saturating_sub(unique),
        max_reuse,
        weak_pw: 0,
        short_pw: 0,
        expired: n(items
            .iter()
            .filter(|it| is_expired(&it.e.times, now))
            .count()),
        totp: n(items
            .iter()
            .filter(|it| totp::settings(it.e).is_some())
            .count()),
        passkeys: n(items
            .iter()
            .filter(|it| it.e.fields().any(|(name, _)| name.starts_with(PASSKEY)))
            .count()),
        avg_len: 0,
        excluded: 0,
        name: vault.meta.name.clone(),
        description: vault.meta.description.clone(),
        location: file.path.unwrap_or("").to_owned(),
        created: vault.root.times.creation,
        last_saved: file.modified,
        unsaved: file.unsaved,
    };
    let mut total: u64 = 0;
    for &i in &with_pw {
        let Some(it) = items.get(i) else { continue };
        let len = units(it.e.value("Password"));
        total = total.saturating_add(len);
        if len < 8 {
            s.short_pw = s.short_pw.saturating_add(1);
        }
        if it.e.exclude_from_reports {
            s.excluded = s.excluded.saturating_add(1);
        }
        // FEA-07.10: the Health Check score, for passwords under 25 units.
        if len < 25
            && health::evaluate(ratings, &items, &reuse, i, now, zone).is_some_and(|h| h.score < 75)
        {
            s.weak_pw = s.weak_pw.saturating_add(1);
        }
    }
    // FEA-07.12: rounded to the nearest whole number, halves up.
    let count = n(with_pw.len());
    if count > 0 {
        s.avg_len = total
            .saturating_mul(2)
            .saturating_add(count)
            .checked_div(count.saturating_mul(2))
            .unwrap_or(0);
    }
    s
}

/// Groups in the recycle bin's subtree, the bin included.
fn bin_groups(vault: &Vault) -> usize {
    recycle::bin_id(vault)
        .and_then(|bin| vault.root.find_group(bin))
        .map_or(0, |g| g.subtree().len())
}

/// FEA-07.6, FEA-07.8: different passwords among `with_pw` by exact text,
/// and the largest number sharing one.
fn distinct(items: &[Item<'_>], with_pw: &[usize]) -> (u64, u64) {
    let pw = |i: usize| items.get(i).map_or("", |it| it.e.value("Password"));
    let mut order = with_pw.to_vec();
    order.sort_by(|&a, &b| pw(a).cmp(pw(b)));
    let (mut unique, mut max, mut run) = (0u64, 0u64, 0u64);
    let mut last: Option<usize> = None;
    for i in order {
        if last.is_some_and(|l| pw(l) == pw(i)) {
            run = run.saturating_add(1);
        } else {
            unique = unique.saturating_add(1);
            run = 1;
        }
        max = max.max(run);
        last = Some(i);
    }
    (unique, max)
}

impl Stats {
    /// The rows with a warning mark (FEA-07.16), by row id.
    #[must_use]
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.unsaved {
            out.push("info.unsaved");
        }
        if self.expired > 0 {
            out.push("stat.expired");
        }
        if self.reused_pw > self.unique_pw / 10 {
            out.push("stat.reused_pw");
        }
        if self.max_reuse > 3 {
            out.push("stat.max_reuse");
        }
        if self.short_pw > 0 {
            out.push("stat.short_pw");
        }
        if self.weak_pw > 0 {
            out.push("stat.weak_pw");
        }
        if self.excluded > 0 {
            out.push("stat.excluded");
        }
        // Larsal: no average warning without any password (FEA-07.16).
        if self.avg_len < 10 && self.unique_pw > 0 {
            out.push("stat.avg_len");
        }
        out
    }

    /// The average as shown: "1 character" or "N characters" (FEA-07.12).
    #[must_use]
    pub fn avg_text(&self) -> String {
        if self.avg_len == 1 {
            "1 character".to_owned()
        } else {
            format!("{} characters", self.avg_len)
        }
    }
}
