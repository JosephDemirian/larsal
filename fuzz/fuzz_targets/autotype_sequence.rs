//! Fuzz target `autotype_sequence` (E8-S1, INT-05 T40, AT-G03): the
//! Auto-Type sequence reader and planner on arbitrary text against a demo
//! entry. Must never panic or hang; every plan stays within INT-05.16 (at
//! most 10,000 actions, 60 s of waits, waits of at most 10 s, pauses of at
//! most 500 ms, picks of 1 to 256 characters, no control character left in
//! text), counts its actions exactly (waits and pauses too, LD-186 (2)),
//! and passes the editor's check too.
//!
//! Input: the sequence, then up to three values separated by byte 0x1E for
//! the entry's username, password and notes. Demo data only.
#![no_main]

use app_autotype::{
    Action, Layout, MAX_KEYS, MAX_PICK, MAX_WAITS_MS, Mods, Options, Picked, Shortcut, check, plan,
};
use app_core::refs::Context;
use app_crypto::secret::SecretString;
use app_model::{Entry, Field, Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;

const SEPARATOR: u8 = 0x1E;

fn set(e: &mut Entry, name: &str, value: String) {
    e.set_field(
        name.to_owned(),
        Field {
            value: SecretString::new(value),
            protected: false,
        },
    );
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&b| b == SEPARATOR);
    let seq = String::from_utf8_lossy(parts.next().unwrap_or(&[])).into_owned();
    let mut p = Entry::new(Uuid([0x50; 16]), Time(0));
    for name in ["UserName", "Password", "Notes"] {
        let value = String::from_utf8_lossy(parts.next().unwrap_or(&[])).into_owned();
        set(&mut p, name, value);
    }
    set(&mut p, "attr1", "value1".into());
    set(&mut p, "Grow", "{USERNAME}".repeat(16));
    set(
        &mut p,
        "otp",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into(),
    );
    let mut other = Entry::new(Uuid([0x03; 16]), Time(0));
    set(&mut other, "UserName", "demo@mail.example".into());
    let mut root = Group::new(Uuid([0x0F; 16]), "R".into(), Time(0));
    root.entries = vec![p, other];
    let v = Vault::new(root, Time(0));
    let entry = &v.root.entries[0];
    let ctx = Context::new(Some(&v), Time(63_928_466_236));
    let layout = Layout::new([('a', 0x00), ('v', 0x09), ('x', 0x07), ('1', 0x12)]);
    let opts = Options {
        layout: &layout,
        shortcut: Some(Shortcut {
            code: 0x09,
            mods: Mods::CONTROL | Mods::OPTION,
        }),
        start_delay_ms: 500,
        key_pause_ms: 25,
    };

    let Ok(mut plan) = plan(&seq, entry, &ctx, &opts) else {
        return;
    };
    assert!(
        check(&seq, entry, &ctx, &opts).is_ok(),
        "the editor check is more lenient"
    );
    assert!(plan.keys() <= MAX_KEYS);
    assert!(plan.waits_ms() <= MAX_WAITS_MS);
    let mut keys = 0usize;
    let mut waits = 0u64;
    for a in plan.actions() {
        match a {
            Action::Text { text, .. } => {
                let t = text.expose();
                assert!(!t.is_empty());
                assert!(!t.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}'));
                keys += t.chars().count();
            }
            Action::Key { .. } => keys += 1,
            Action::Otp { .. } => keys += 6,
            Action::Wait(ms) => {
                assert!(*ms <= 10_000);
                waits += u64::from(*ms);
                keys += 1;
            }
            Action::Pause(ms) => {
                assert!(*ms <= 500);
                keys += 1;
            }
            Action::Pick { value, .. } => {
                let n = value.expose().chars().count();
                assert!((1..=MAX_PICK).contains(&n));
            }
        }
    }
    assert_eq!(keys, plan.keys());
    assert_eq!(waits, plan.waits_ms());

    // Pick every character with a Tab after each: within the bound or MI05-21.
    let picks: Vec<Picked> = plan
        .picks()
        .into_iter()
        .map(|n| Picked {
            positions: (0..n).collect(),
            tab_after: true,
        })
        .collect();
    if plan.fill_picks(&picks).is_ok() {
        assert!(plan.picks().is_empty());
        assert!(plan.keys() <= MAX_KEYS);
    }
});
