//! E4-S1 to E4-S3: edits made through larsal-core survive a save and an open
//! through larsal-format unchanged.

mod common;

use common::*;
use larsal_core::edit::{
    Item, MAX_GROUP_LEVEL, Position, add_entry, add_group, copy_within, edit_entry, edit_group,
    move_entries, move_group, new_entry, new_group,
};
use larsal_core::{Error, history, recycle};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::{Limit, Limits};
use larsal_format::{Opened, Saved, open, save};
use larsal_model::entry::STANDARD_FIELDS;
use larsal_model::{Association, Field, Group, Kdf, Time, Uuid, Vault};

fn host() -> Host {
    let record = SpeedRecord {
        count: 100_000_000,
        memory_kib: 0,
        lanes: 1,
        ms: 1_000,
    };
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(record),
    }
}

fn without_save_stamp(v: &mut Vault) {
    let padding = String::from_utf8(larsal_format::document::write::PADDING_KEY.to_vec()).unwrap();
    v.meta
        .custom_data
        .items
        .retain(|i| i.key != padding && i.key != "_LAST_MODIFIED");
    v.read_version = None;
}

/// A standard field's own flag is set only by reading a file (MOD-01.6):
/// after a save and an open it is on wherever the vault's flag for that
/// field is on (FMT-11.20). Applied before the save, so the expected model
/// is the one the reader gives.
fn as_read(v: &mut Vault) {
    let flags = v.meta.memory_protection.clone();
    let mark = |x: &mut larsal_model::Entry| {
        for n in STANDARD_FIELDS.iter().filter(|n| flags.for_field(n)) {
            if let Some(f) = x.field(n).map(Field::duplicate) {
                x.set_field(
                    (*n).into(),
                    Field {
                        protected: true,
                        ..f
                    },
                );
            }
        }
    };
    let mut stack = vec![&mut v.root];
    while let Some(g) = stack.pop() {
        for e in &mut g.entries {
            mark(e);
            e.history.iter_mut().for_each(mark);
        }
        stack.extend(g.groups.iter_mut());
    }
}

#[test]
fn edits_survive_save_and_open() {
    let mut v = sample();
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let t = |n: i64| Time(NOW.0 + n);

    // MOD-01: a new entry with a protected password, then an edit session.
    let mut e = new_entry(&v, id(2), true).unwrap();
    e.set_field("Title".into(), field("Demo site"));
    e.set_field(
        "Password".into(),
        Field {
            value: SecretString::new("demo-pass-1".into()),
            protected: true,
        },
    );
    let new = add_entry(&mut v, id(2), e, t(1)).unwrap();
    ok(&v);
    edit_entry(&mut v, new, t(2), |e| {
        e.set_field(
            "Password".into(),
            Field {
                value: SecretString::new("demo-pass-2".into()),
                protected: true,
            },
        );
    })
    .unwrap();
    ok(&v);
    // MOD-02: rename a group, move and copy entries.
    edit_group(&mut v, id(4), t(3), |g| g.name = "Renamed".into()).unwrap();
    ok(&v);
    move_entries(&mut v, &[id(0x11)], id(4), t(4)).unwrap();
    ok(&v);
    copy_within(&mut v, Item::Entry(new), id(1), Position::End, t(5)).unwrap();
    ok(&v);
    // MOD-04: to the bin, back out, a group deleted for good.
    recycle::delete_entries(&mut v, &[id(0x10), id(0x12)], t(6), |_, _| {
        recycle::References::Delete
    })
    .unwrap();
    ok(&v);
    recycle::restore_entries(&mut v, &[id(0x12)], t(7)).unwrap();
    ok(&v);
    v.meta.recycle_bin_enabled = false;
    ok(&v);
    recycle::delete_group(&mut v, id(3), t(8)).unwrap();
    ok(&v);
    v.meta.recycle_bin_enabled = true;
    ok(&v);
    // MOD-03: tighter limits prune the history.
    edit_entry(&mut v, new, t(9), |e| {
        e.set_field("UserName".into(), field("demo-user"));
    })
    .unwrap();
    ok(&v);
    history::apply_limits(&mut v, 1, -1);
    ok(&v);
    assert_eq!(find(&v, new).history.len(), 1);
    assert!(!v.deleted_objects.is_empty() && recycle::bin_id(&v).is_some());

    same_after_save_and_open(&mut v);
}

/// Saves `v` with cheap settings, opens the file and checks the model is
/// the same.
fn same_after_save_and_open(v: &mut Vault) {
    as_read(v);
    let pw = SecretString::new("demo vault password".into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut host = host();
    let saved = match save(&*v, &creds, None, &mut host, &Limits::DEFAULT, None).unwrap() {
        Saved::File(f) => f,
        Saved::Ask(r) => panic!("cost question {r:?}"),
    };
    let back = match open(&saved.bytes, &creds, &mut host, &Limits::DEFAULT, None).unwrap() {
        Opened::Vault(o) => o.vault,
        Opened::Ask(r) => panic!("cost question {r:?}"),
    };
    // The model never holds the save stamp; only the file does.
    let mut b = back;
    without_save_stamp(&mut b);
    assert_eq!(*v, b);
    ok(&b);
}

fn group_mut(v: &mut Vault, uuid: Uuid) -> &mut Group {
    let mut stack = vec![&mut v.root];
    while let Some(g) = stack.pop() {
        if g.uuid == uuid {
            return g;
        }
        stack.extend(g.groups.iter_mut());
    }
    panic!("no group")
}

/// LD-106: groups nest down to level 504 (the root group is level 0) and no
/// deeper. At the boundary the deepest element Larsal writes, a history item's
/// `Window`, sits at depth 512 and the vault saves and reads back; one group
/// level more, built past larsal-core, fails the reader's depth limit.
#[test]
fn ld_106_group_depth_boundary() {
    assert_eq!(MAX_GROUP_LEVEL + 8, Limits::DEFAULT.depth);
    let mut v = sample();
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    // A chain under G4 (level 1) down to level 504.
    let mut chain = vec![id(4)];
    for _ in 2..=MAX_GROUP_LEVEL {
        let g = new_group(&v).unwrap();
        let parent = *chain.last().unwrap();
        chain.push(add_group(&mut v, parent, g, NOW).unwrap());
    }
    let (deepest, above) = (chain[chain.len() - 1], chain[chain.len() - 2]);
    let g = new_group(&v).unwrap();
    assert_eq!(add_group(&mut v, deepest, g, NOW), Err(Error::TooDeep));
    // G1 holds G2: under `above` G2 would land at level 505.
    assert_eq!(
        move_group(&mut v, id(2), above, Position::End, NOW),
        Err(Error::TooDeep)
    );
    let r = copy_within(&mut v, Item::Group(id(2)), above, Position::End, NOW);
    assert_eq!(r, Err(Error::TooDeep));
    assert_eq!(
        move_group(&mut v, id(3), deepest, Position::End, NOW),
        Err(Error::TooDeep)
    );
    // G2 alone fits under `above`, at level 504.
    assert_eq!(
        move_group(&mut v, id(3), above, Position::End, NOW),
        Ok(true)
    );
    ok(&v);
    // The deepest entry content in the level-504 group.
    let mut e = new_entry(&v, deepest, false).unwrap();
    e.auto_type.associations.push(Association {
        window: "demo window".into(),
        sequence: "{PASSWORD}".into(),
        unknown: Vec::new(),
    });
    let deep = add_entry(&mut v, deepest, e, NOW).unwrap();
    edit_entry(&mut v, deep, NOW, |e| {
        e.set_field("Title".into(), field("demo"));
    })
    .unwrap();
    assert_eq!(find(&v, deep).history[0].auto_type.associations.len(), 1);
    ok(&v);
    same_after_save_and_open(&mut v);
    // One level more, past larsal-core: the writer's own read-back refuses it.
    group_mut(&mut v, deepest)
        .groups
        .push(Group::new(id(0x99), "too deep".into(), NOW));
    move_entries(&mut v, &[deep], id(0x99), NOW).unwrap();
    let pw = SecretString::new("demo vault password".into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let r = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None);
    assert!(
        matches!(r, Err(larsal_format::Error::TooLarge(Limit::Depth))),
        "level 505 passes the depth limit"
    );
}

/// E4-S4 to E4-S7: attachments (shared content), a custom icon with name
/// and time, tags, Expire now, and clones (with references, and a group
/// clone) survive a save and an open.
#[test]
fn e4_s4_to_s7_edits_survive_save_and_open() {
    use larsal_core::{attachments, clone, expiry, icons, tags};
    let mut v = sample();
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let t = |n: i64| Time(NOW.0 + n);
    let limits = attachments::Limits::DEFAULT;
    let data = || larsal_crypto::secret::SecretBytes::new(b"demo attachment".to_vec());
    attachments::import(&mut v, id(0x10), "a.txt", data(), false, &limits, t(1)).unwrap();
    ok(&v);
    attachments::import(&mut v, id(0x11), "same.txt", data(), false, &limits, t(2)).unwrap();
    ok(&v);
    let (icon, _) =
        icons::add_png(&mut v, b"\x89PNG demo".to_vec(), "demo".into(), Some(t(3))).unwrap();
    edit_entry(&mut v, id(0x10), t(4), |e| {
        e.icon = larsal_model::Icon::Custom(icon)
    })
    .unwrap();
    ok(&v);
    tags::choose(&mut v, &[id(0x10), id(0x12)], "Work", t(5)).unwrap();
    ok(&v);
    expiry::expire_now(&mut v, &[id(0x11)], t(6)).unwrap();
    ok(&v);
    let refs = clone::Options {
        refs: true,
        ..clone::Options::default()
    };
    clone::clone_entry(
        &mut v,
        id(0x10),
        refs,
        &larsal_core::clone::Limits::DEFAULT,
        t(7),
    )
    .unwrap();
    ok(&v);
    let g = clone::clone_group(&v, id(2), &larsal_core::clone::Limits::DEFAULT, t(8)).unwrap();
    clone::add_group_clone(&mut v, id(2), g, t(8)).unwrap();
    ok(&v);
    same_after_save_and_open(&mut v);
}
