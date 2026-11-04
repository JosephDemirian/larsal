//! Shared helpers for the app-core tests: a small demo vault and checks.
#![allow(dead_code)]

pub mod ico;

use app_crypto::secret::SecretString;
use app_model::{Entry, Field, Group, Time, Uuid, Vault};

/// The time a vault is built at.
pub const T0: Time = Time(63_900_000_000);
/// The time of the action under test.
pub const NOW: Time = Time(63_928_466_236);

pub fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

pub fn field(v: &str) -> Field {
    Field {
        value: SecretString::new(v.to_owned()),
        protected: false,
    }
}

pub fn entry(n: u8, title: &str) -> Entry {
    let mut e = Entry::new(id(n), T0);
    e.set_field("Title".into(), field(title));
    e
}

/// Root R (id 01) holds entries E1 (10), E2 (11); child groups G1 (02,
/// holding E3 (12) and child group G2 (03, holding E4 (13))) and G4 (04).
pub fn sample() -> Vault {
    let mut g2 = Group::new(id(3), "G2".into(), T0);
    g2.entries.push(entry(0x13, "E4"));
    let mut g1 = Group::new(id(2), "G1".into(), T0);
    g1.entries.push(entry(0x12, "E3"));
    g1.groups.push(g2);
    let g4 = Group::new(id(4), "G4".into(), T0);
    let mut root = Group::new(id(1), "R".into(), T0);
    root.entries.push(entry(0x10, "E1"));
    root.entries.push(entry(0x11, "E2"));
    root.groups.push(g1);
    root.groups.push(g4);
    Vault::new(root, T0)
}

/// Asserts the model invariants (app_model::invariants::check).
pub fn ok(v: &Vault) {
    assert_eq!(app_model::invariants::check(v), Ok(()));
}

/// The live entry with `id`, wherever it is.
pub fn find(v: &Vault, uuid: Uuid) -> &Entry {
    v.root
        .subtree()
        .into_iter()
        .flat_map(|g| g.entries.iter())
        .find(|e| e.uuid == uuid)
        .expect("entry present")
}

/// The group with `id`.
pub fn group(v: &Vault, uuid: Uuid) -> &Group {
    v.root
        .subtree()
        .into_iter()
        .find(|g| g.uuid == uuid)
        .expect("group present")
}

/// The id of the group holding entry `uuid`.
pub fn holder(v: &Vault, uuid: Uuid) -> Uuid {
    v.root
        .subtree()
        .into_iter()
        .find(|g| g.entries.iter().any(|e| e.uuid == uuid))
        .expect("entry present")
        .uuid
}

/// Titles of a group's entries, in stored order.
pub fn titles(g: &Group) -> Vec<&str> {
    g.entries.iter().map(|e| e.value("Title")).collect()
}

/// Names of a group's child groups, in stored order.
pub fn names(g: &Group) -> Vec<&str> {
    g.groups.iter().map(|c| c.name.as_str()).collect()
}

/// A UTC time from a calendar date and time.
pub fn at(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Time {
    Time::from_civil(app_model::times::Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
    .unwrap()
}

/// Europe/Berlin rules: CET (+1 h), and CEST (+2 h) from the last Sunday of
/// March 01:00 UTC to the last Sunday of October 01:00 UTC (D-09-1: tests
/// use a fixed Europe/Berlin implementation).
pub struct Berlin;

fn last_sunday(year: i64, month: u32) -> Time {
    let day31 = at(year, month, 31, 1, 0, 0);
    // 0001-01-01 was a Monday: day index % 7 == 6 is a Sunday.
    let weekday = (day31.0 / 86_400) % 7;
    Time(day31.0 - ((weekday + 1) % 7) * 86_400)
}

impl app_core::time::Zone for Berlin {
    fn offset(&self, t: Time) -> i64 {
        let Some(c) = t.to_civil() else { return 3600 };
        let (start, end) = (last_sunday(c.year, 3), last_sunday(c.year, 10));
        if start <= t && t < end { 7200 } else { 3600 }
    }
}

/// A fixed offset zone, for "a Mac at UTC+2".
pub struct Fixed(pub i64);

impl app_core::time::Zone for Fixed {
    fn offset(&self, _: Time) -> i64 {
        self.0
    }
}
