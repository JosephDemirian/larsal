//! The first checker's attacks of round 2 on what a share brought, ported to rule
//! R6 (INT-08.32). Every test prints what it saw and asserts the property the cards
//! claim, so red = finding. Assertions R6 changes say so where they stand.
#![allow(clippy::all, clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use larsal_core::edit::{self, Position};
use larsal_core::merge::{Change, ChangeKind, Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::secret::SecretString;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};

const T0: Time = Time(63_902_822_400);
const NOW: Time = Time(63_910_000_000);
fn at(n: i64) -> Time {
    Time(T0.0 + n)
}
fn far() -> Time {
    Time(T0.0 + 3_000_000_000)
}

const KINDS: [Kind; 6] = [
    Kind::ChangeOnDisk,
    Kind::ConflictCopy,
    Kind::ServerSync,
    Kind::Window,
    Kind::CommandLine,
    Kind::RemoteSync,
];

const TEAM: u8 = 0x20;
const PRIVATE: u8 = 0x30;
const E: u8 = 0x50;

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

fn entry(n: u8, password: &str, when: Time) -> Entry {
    let mut e = Entry::new(id(n), when);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(password.to_owned()),
            protected: true,
        },
    );
    e.times.location_changed = when;
    e
}

fn group(n: u8, name: &str, when: Time) -> Group {
    Group::new(id(n), name.into(), when)
}

/// Root(01) -> Team(20), Private(30).
fn common() -> Vault {
    let mut root = group(0x01, "Root", T0);
    root.groups.push(group(TEAM, "Team", T0));
    root.groups.push(group(PRIVATE, "Private", T0));
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = false;
    v
}

fn cont() -> Vault {
    Vault::new(group(0x66, "Share", T0), T0)
}

fn gm<'a>(g: &'a mut Group, n: u8) -> Option<&'a mut Group> {
    if g.uuid == id(n) {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| gm(c, n))
}

fn path_of(g: &Group, n: u8, trail: &mut Vec<String>) -> bool {
    trail.push(g.name.clone());
    if g.entries.iter().any(|e| e.uuid == id(n)) {
        return true;
    }
    for c in &g.groups {
        if path_of(c, n, trail) {
            return true;
        }
    }
    trail.pop();
    false
}

fn gpath_of(g: &Group, n: u8, trail: &mut Vec<String>) -> bool {
    trail.push(g.name.clone());
    if g.uuid == id(n) {
        return true;
    }
    for c in &g.groups {
        if gpath_of(c, n, trail) {
            return true;
        }
    }
    trail.pop();
    false
}

fn where_is(v: &Vault, n: u8) -> String {
    let mut t = Vec::new();
    if path_of(&v.root, n, &mut t) {
        t.join("/")
    } else {
        "GONE".into()
    }
}

fn where_group(v: &Vault, n: u8) -> String {
    let mut t = Vec::new();
    if gpath_of(&v.root, n, &mut t) {
        t.join("/")
    } else {
        "GONE".into()
    }
}

fn find(v: &Vault, n: u8) -> Option<&Entry> {
    v.root.all_entries().find(|e| e.uuid == id(n))
}

fn pw(v: &Vault, n: u8) -> Option<String> {
    find(v, n).map(|e| e.value("Password").to_owned())
}

fn hist(v: &Vault, n: u8) -> Vec<String> {
    find(v, n)
        .map(|e| {
            e.history
                .iter()
                .map(|h| h.value("Password").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn mark(v: &Vault, n: u8) -> bool {
    find(v, n).is_some_and(|e| origin::mark_of(&e.custom_data).is_some())
}

fn show(v: &Vault, n: u8) -> String {
    format!(
        "{}: at {} pw {:?} history {:?} marked {} records {} scoped {}",
        n,
        where_is(v, n),
        pw(v, n),
        hist(v, n),
        mark(v, n),
        v.deleted_objects.iter().filter(|d| d.uuid == id(n)).count(),
        origin::read_rows(&v.meta.custom_data)
            .keys()
            .any(|(x, _)| *x == id(n)),
    )
}

fn sm(t: &mut Vault, s: &Vault, kind: Kind) -> Vec<Change> {
    merge(t, s, &Options::new(kind), NOW)
        .expect("merge")
        .changes
}

fn import(v: &mut Vault, team: u8, c: &Vault) {
    run::merge_into(v, id(team), c, NOW).expect("import");
}

fn export_leaks(v: &Vault, team: u8, secret: &str) -> bool {
    container::build(id(team), true, v, NOW)
        .map(|c| {
            c.root.all_entries().any(|e| {
                e.value("Password") == secret
                    || e.history.iter().any(|h| h.value("Password") == secret)
            })
        })
        .unwrap_or(false)
}

fn record_of(n: u8, when: Time) -> DeletedObject {
    DeletedObject {
        uuid: id(n),
        deleted_at: when,
        unknown: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// A1: the user deletes the planted copy for good (bin off). Plain record.
#[test]
fn a1_user_deletes_the_planted_copy_for_good() {
    let mut bad = Vec::new();
    for kind in KINDS {
        let mut a = common();
        let mut b = common();
        gm(&mut b.root, PRIVATE)
            .unwrap()
            .entries
            .push(entry(E, "mac-b-demo", at(1000)));
        let mut c = cont();
        c.root.entries.push(entry(E, "planted-demo", at(500)));
        import(&mut a, TEAM, &c);
        assert!(mark(&a, E));
        recycle::delete_entries(&mut a, &[id(E)], at(9000), |_, _| References::Delete).unwrap();
        println!("A1 {kind:?} A after delete: {}", show(&a, E));
        sm(&mut b, &a, kind);
        println!("A1 {kind:?} B after merge: {}", show(&b, E));
        if pw(&b, E).as_deref() != Some("mac-b-demo") {
            bad.push(format!("{kind:?}"));
        }
    }
    assert!(bad.is_empty(), "Mac B's outside entry erased on {bad:?}");
}

// A2: the user deletes the planted copy to the bin.
#[test]
fn a2_user_deletes_the_planted_copy_to_the_bin() {
    let mut bad = Vec::new();
    for kind in KINDS {
        for when in [at(500), at(2000)] {
            let mut a = common();
            a.meta.recycle_bin_enabled = true;
            let mut b = common();
            b.meta.recycle_bin_enabled = true;
            gm(&mut b.root, PRIVATE)
                .unwrap()
                .entries
                .push(entry(E, "mac-b-demo", at(1000)));
            let mut c = cont();
            c.root.entries.push(entry(E, "planted-demo", when));
            import(&mut a, TEAM, &c);
            recycle::delete_entries(&mut a, &[id(E)], at(9000), |_, _| References::Delete).unwrap();
            println!(
                "A2 {kind:?} when {:?} A after delete: {}",
                when.0 - T0.0,
                show(&a, E)
            );
            sm(&mut b, &a, kind);
            println!(
                "A2 {kind:?} when {:?} B after merge: {}",
                when.0 - T0.0,
                show(&b, E)
            );
            if pw(&b, E).as_deref() != Some("mac-b-demo") || !where_is(&b, E).ends_with("Private") {
                bad.push(format!("{kind:?}/{}", when.0 - T0.0));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "Mac B's outside entry moved or changed on {bad:?}"
    );
}

// A1g: the user deletes the whole share group for good: plain records for what it holds.
#[test]
fn a1g_user_deletes_the_share_group_for_good() {
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    let mut c = cont();
    c.root.entries.push(entry(E, "planted-demo", at(500)));
    import(&mut a, TEAM, &c);
    recycle::delete_group(&mut a, id(TEAM), at(9000)).unwrap();
    println!("A1g A: {} team {}", show(&a, E), where_group(&a, TEAM));
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!("A1g B: {} team {}", show(&b, E), where_group(&b, TEAM));
    assert_eq!(
        pw(&b, E).as_deref(),
        Some("mac-b-demo"),
        "erased by deleting the share group"
    );
}

// ---------------------------------------------------------------------------
// A3: two shares. Mac A imports T1, Mac B imports T2, Mac C holds the real one.
#[test]
fn a3_two_shares_clear_the_marker_for_a_third_copy() {
    let mut bad = Vec::new();
    for kind in KINDS {
        let mut base = common();
        base.root.groups.push(group(0x22, "Team2", T0));
        let mut a = base.duplicate();
        let mut b = base.duplicate();
        let mut c3 = base.duplicate();
        gm(&mut c3.root, PRIVATE)
            .unwrap()
            .entries
            .push(entry(E, "mac-c-demo", at(1000)));
        let mut c1 = cont();
        c1.root.entries.push(entry(E, "planted-demo", at(2000)));
        let mut c2 = cont();
        c2.root.entries.push(entry(E, "planted-demo", at(2000)));
        import(&mut a, TEAM, &c1);
        import(&mut b, 0x22, &c2);
        assert!(mark(&a, E) && mark(&b, E));
        sm(&mut a, &b, kind);
        println!("A3 {kind:?} A after A<-B: {}", show(&a, E));
        sm(&mut c3, &a, kind);
        println!("A3 {kind:?} C after C<-A: {}", show(&c3, E));
        if pw(&c3, E).as_deref() != Some("mac-c-demo") || !where_is(&c3, E).ends_with("Private") {
            bad.push(format!(
                "{kind:?}: {} export leaks {}",
                show(&c3, E),
                export_leaks(&c3, TEAM, "mac-c-demo")
            ));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

// A4: nested shares. T0(20) holds T1(21). T1's container plants F; T0's moves it out of T1.
#[test]
fn a4_nested_shares_leave_a_marker_that_no_longer_counts() {
    let mut base = common();
    gm(&mut base.root, TEAM)
        .unwrap()
        .groups
        .push(group(0x21, "T1", T0));
    gm(&mut base.root, TEAM)
        .unwrap()
        .groups
        .push(group(0x23, "Sub", T0));
    let mut a = base.duplicate();
    let mut c3 = base.duplicate();
    gm(&mut c3.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-c-demo", at(1000)));
    // T1's container brings E: marked T1.
    let mut c1 = cont();
    c1.root.entries.push(entry(E, "planted-demo", at(2000)));
    import(&mut a, 0x21, &c1);
    println!("A4 A after T1 import: {}", show(&a, E));
    // T0's container holds E in Sub, later location: moved inside T0, out of T1.
    let mut c0 = cont();
    let mut sub = group(0x23, "Sub", T0);
    sub.entries.push(entry(E, "planted-demo", at(3000)));
    c0.root.groups.push(group(0x21, "T1", T0));
    c0.root.groups.push(sub);
    import(&mut a, TEAM, &c0);
    println!("A4 A after T0 import: {}", show(&a, E));
    sm(&mut c3, &a, Kind::ChangeOnDisk);
    println!(
        "A4 C after C<-A: {} export leaks {}",
        show(&c3, E),
        export_leaks(&c3, TEAM, "mac-c-demo")
    );
    assert_eq!(pw(&c3, E).as_deref(), Some("mac-c-demo"));
    assert!(where_is(&c3, E).ends_with("Private"));
}

// A4b: nested shares, two imports on two Macs: one marker leads, the winner's is cleared.
#[test]
fn a4b_nested_shares_two_macs_then_a_third_copy() {
    let mut base = common();
    gm(&mut base.root, TEAM)
        .unwrap()
        .groups
        .push(group(0x21, "T1", T0));
    let mut a = base.duplicate();
    let mut b = base.duplicate();
    let mut c3 = base.duplicate();
    gm(&mut c3.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-c-demo", at(1000)));
    let mut c1 = cont();
    c1.root.entries.push(entry(E, "planted-demo", at(2000)));
    import(&mut a, 0x21, &c1); // in T1, marked T1
    let mut c0 = cont();
    c0.root.entries.push(entry(E, "planted-demo", at(2000)));
    import(&mut b, TEAM, &c0); // in T0, marked T0
    sm(&mut a, &b, Kind::ChangeOnDisk);
    println!("A4b A after A<-B: {}", show(&a, E));
    let mut b2 = b.duplicate();
    sm(&mut b2, &a, Kind::ChangeOnDisk);
    println!("A4b B after B<-A: {}", show(&b2, E));
    sm(&mut c3, &a, Kind::ChangeOnDisk);
    println!(
        "A4b C after C<-A: {} export leaks {}",
        show(&c3, E),
        export_leaks(&c3, TEAM, "mac-c-demo")
    );
    assert_eq!(pw(&c3, E).as_deref(), Some("mac-c-demo"));
}

// ---------------------------------------------------------------------------
// A5: a member's own entry inside the share has no marker. On Mac B the member moves it
// out and gives it a new password. Mac A has not merged yet; its share import stamps the
// in-share copy with later times.
#[test]
fn a5_a_moved_out_entry_the_share_never_brought_is_pulled_back() {
    let mut bad = Vec::new();
    for kind in KINDS {
        let mut base = common();
        gm(&mut base.root, TEAM)
            .unwrap()
            .entries
            .push(entry(E, "shared-demo", at(100)));
        let mut a = base.duplicate();
        let mut b = base.duplicate();
        // Mac B: the member's own move out, then a new private password.
        edit::move_entries(&mut b, &[id(E)], id(PRIVATE), at(1000)).unwrap();
        {
            let e = gm(&mut b.root, PRIVATE)
                .unwrap()
                .entries
                .first_mut()
                .unwrap();
            e.set_field(
                "Password".into(),
                Field {
                    value: SecretString::new("private-demo".into()),
                    protected: true,
                },
            );
            e.times.last_modification = at(1001);
        }
        // The container's copy of E: later times than B's.
        let mut c = cont();
        c.root.entries.push(entry(E, "planted-demo", at(2000)));
        import(&mut a, TEAM, &c);
        println!("A5 {kind:?} A after import: {}", show(&a, E));
        sm(&mut b, &a, kind);
        println!(
            "A5 {kind:?} B after merge: {} export leaks private {}",
            show(&b, E),
            export_leaks(&b, TEAM, "private-demo")
        );
        if pw(&b, E).as_deref() != Some("private-demo")
            || !where_is(&b, E).ends_with("Private")
            || export_leaks(&b, TEAM, "private-demo")
        {
            bad.push(format!("{kind:?}: {}", show(&b, E)));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

// A5h: no forged time at all. Three real copies, three people's real actions, the container
// is a real export. H, an honest member, moves E inside the share; his export reaches Mac A.
// Mac B, the same user's other Mac, moved E out and gave it a private password earlier.
#[test]
fn a5h_an_honest_members_move_inside_the_share_pulls_back_what_b_moved_out() {
    let mut bad = Vec::new();
    for kind in KINDS {
        let mut base = common();
        gm(&mut base.root, TEAM)
            .unwrap()
            .entries
            .push(entry(E, "shared-demo", at(100)));
        gm(&mut base.root, TEAM)
            .unwrap()
            .groups
            .push(group(0x32, "Sub", at(100)));
        let mut a = base.duplicate();
        let mut b = base.duplicate();
        let mut h = base.duplicate();
        edit::move_entries(&mut b, &[id(E)], id(PRIVATE), at(1000)).unwrap();
        {
            let e = gm(&mut b.root, PRIVATE)
                .unwrap()
                .entries
                .first_mut()
                .unwrap();
            e.set_field(
                "Password".into(),
                Field {
                    value: SecretString::new("private-demo".into()),
                    protected: true,
                },
            );
            e.times.last_modification = at(1001);
        }
        edit::move_entries(&mut h, &[id(E)], id(0x32), at(2000)).unwrap();
        let c = container::build(id(TEAM), true, &h, NOW).expect("the holder's export");
        import(&mut a, TEAM, &c);
        println!("A5h {kind:?} A after import: {}", show(&a, E));
        sm(&mut b, &a, kind);
        println!(
            "A5h {kind:?} B after merge: {} export leaks private {}",
            show(&b, E),
            export_leaks(&b, TEAM, "private-demo")
        );
        if !where_is(&b, E).ends_with("Private") || export_leaks(&b, TEAM, "private-demo") {
            bad.push(format!("{kind:?}: {}", show(&b, E)));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

// A5e: the same three people, but H only edits E's title inside the share. No move.
#[test]
fn a5e_an_honest_members_edit_inside_the_share_overwrites_what_b_moved_out() {
    let mut bad = Vec::new();
    for kind in KINDS {
        let mut base = common();
        gm(&mut base.root, TEAM)
            .unwrap()
            .entries
            .push(entry(E, "shared-demo", at(100)));
        let mut a = base.duplicate();
        let mut b = base.duplicate();
        let mut h = base.duplicate();
        edit::move_entries(&mut b, &[id(E)], id(PRIVATE), at(1000)).unwrap();
        {
            let e = gm(&mut b.root, PRIVATE)
                .unwrap()
                .entries
                .first_mut()
                .unwrap();
            e.set_field(
                "Password".into(),
                Field {
                    value: SecretString::new("private-demo".into()),
                    protected: true,
                },
            );
            e.times.last_modification = at(1001);
        }
        {
            let e = gm(&mut h.root, TEAM).unwrap().entries.first_mut().unwrap();
            e.set_field(
                "Title".into(),
                Field {
                    value: SecretString::new("renamed by a member".into()),
                    protected: false,
                },
            );
            e.times.last_modification = at(2000);
        }
        let c = container::build(id(TEAM), true, &h, NOW).expect("the holder's export");
        import(&mut a, TEAM, &c);
        sm(&mut b, &a, kind);
        println!(
            "A5e {kind:?} B after merge: {} export leaks private {}",
            show(&b, E),
            export_leaks(&b, TEAM, "private-demo")
        );
        if pw(&b, E).as_deref() != Some("private-demo") {
            bad.push(format!("{kind:?}: {}", show(&b, E)));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

// A5g: the same for a group the member moved out, with a private entry put in it.
#[test]
fn a5g_a_moved_out_group_the_share_never_brought_is_pulled_back() {
    let mut base = common();
    let mut o = group(0x31, "O", at(100));
    o.times.location_changed = at(100);
    gm(&mut base.root, TEAM).unwrap().groups.push(o);
    gm(&mut base.root, TEAM)
        .unwrap()
        .groups
        .push(group(0x32, "Sub", at(100)));
    let mut a = base.duplicate();
    let mut b = base.duplicate();
    edit::move_group(&mut b, id(0x31), id(PRIVATE), Position::End, at(1000)).unwrap();
    gm(&mut b.root, 0x31)
        .unwrap()
        .entries
        .push(entry(E, "private-demo", at(1100)));
    // The container moves O under Sub, inside the share, with a later location.
    let mut c = cont();
    let mut sub = group(0x32, "Sub", at(100));
    let mut o2 = group(0x31, "O", at(100));
    o2.times.location_changed = at(2000);
    sub.groups.push(o2);
    c.root.groups.push(sub);
    import(&mut a, TEAM, &c);
    println!("A5g A after import: O at {}", where_group(&a, 0x31));
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!(
        "A5g B after merge: O at {}, {}, export leaks {}",
        where_group(&b, 0x31),
        show(&b, E),
        export_leaks(&b, TEAM, "private-demo")
    );
    assert!(!export_leaks(&b, TEAM, "private-demo"));
}

// ---------------------------------------------------------------------------
// A6: a dormant scoped record beside a live object. The user later moves the group holding
// it into the share: the next import, or merge, erases it though the user just shared it.
#[test]
fn a6_a_dormant_record_erases_what_the_user_moves_in_with_a_group() {
    let mut a = common();
    let mut b = common();
    let mut o = group(0x31, "O", at(1000));
    o.entries.push(entry(E, "mac-b-demo", at(1000)));
    gm(&mut b.root, PRIVATE).unwrap().groups.push(o);
    let mut c = cont();
    c.deleted_objects.push(record_of(E, at(2000)));
    import(&mut a, TEAM, &c);
    println!("A6 A: {}", show(&a, E));
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!("A6 B after merge: {}", show(&b, E));
    assert_eq!(pw(&b, E).as_deref(), Some("mac-b-demo"));
    // Months later: the user shares group O.
    edit::move_group(&mut b, id(0x31), id(TEAM), Position::End, at(90000)).unwrap();
    let mut empty = cont();
    empty.root.name = "Team".into();
    import(&mut b, TEAM, &empty);
    println!("A6 B after a move in and one empty import: {}", show(&b, E));
    assert_eq!(
        pw(&b, E).as_deref(),
        Some("mac-b-demo"),
        "the import erased it"
    );
}

#[test]
fn a6b_a_dormant_record_erases_at_the_next_same_vault_merge() {
    let mut a = common();
    let mut b = common();
    let mut o = group(0x31, "O", at(1000));
    o.entries.push(entry(E, "mac-b-demo", at(1000)));
    gm(&mut b.root, PRIVATE).unwrap().groups.push(o);
    let mut c = cont();
    c.deleted_objects.push(record_of(E, at(2000)));
    import(&mut a, TEAM, &c);
    sm(&mut b, &a, Kind::ChangeOnDisk);
    edit::move_group(&mut b, id(0x31), id(TEAM), Position::End, at(90000)).unwrap();
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!("A6b B: {}", show(&b, E));
    assert_eq!(
        pw(&b, E).as_deref(),
        Some("mac-b-demo"),
        "the merge erased it"
    );
}

// A6c: the single-entry move in: the Mod moves, so it stays?
#[test]
fn a6c_a_dormant_record_and_a_single_entry_move_in() {
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    let mut c = cont();
    c.deleted_objects.push(record_of(E, at(2000)));
    import(&mut a, TEAM, &c);
    sm(&mut b, &a, Kind::ChangeOnDisk);
    edit::move_entries(&mut b, &[id(E)], id(TEAM), at(90000)).unwrap();
    let empty = cont();
    import(&mut b, TEAM, &empty);
    println!(
        "A6c B after a move in and one empty import: {}",
        show(&b, E)
    );
    assert_eq!(pw(&b, E).as_deref(), Some("mac-b-demo"));
}

// ---------------------------------------------------------------------------
// A7: the user's own deletion of an outside object beside a scoped record.
#[test]
fn a7_a_users_own_deletion_beside_a_scoped_record_converges() {
    for bin in [false, true] {
        let mut a = common();
        let mut b = common();
        a.meta.recycle_bin_enabled = bin;
        b.meta.recycle_bin_enabled = bin;
        gm(&mut b.root, PRIVATE)
            .unwrap()
            .entries
            .push(entry(E, "mac-b-demo", at(1000)));
        let mut c = cont();
        c.deleted_objects.push(record_of(E, at(2000)));
        import(&mut a, TEAM, &c);
        sm(&mut b, &a, Kind::ChangeOnDisk);
        // Mac C: a copy of B, holding E and the record.
        let mut d = b.duplicate();
        // On Mac B the user deletes E for good (to the bin first when the bin is on).
        recycle::delete_entries(&mut b, &[id(E)], at(5000), |_, _| References::Delete).unwrap();
        if bin {
            recycle::delete_entries(&mut b, &[id(E)], at(5001), |_, _| References::Delete).unwrap();
        }
        println!("A7 bin {bin} B after delete: {}", show(&b, E));
        sm(&mut d, &b, Kind::ChangeOnDisk);
        println!("A7 bin {bin} other Mac after merge: {}", show(&d, E));
        let mut b2 = b.duplicate();
        sm(&mut b2, &d, Kind::ChangeOnDisk);
        println!("A7 bin {bin} B after merging back: {}", show(&b2, E));
        assert_eq!(pw(&d, E), None, "the deleted entry lives on the other Mac");
        assert_eq!(pw(&b2, E), None, "the deleted entry came back");
    }
}

// ---------------------------------------------------------------------------
// A8: a file another app merged: records kept, both keys lost; what Larsal does.
#[test]
fn a8_a_file_with_records_off_the_list_takes_every_record_off() {
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    let mut c = cont();
    c.deleted_objects.push(record_of(E, at(2000)));
    import(&mut a, TEAM, &c);
    let mut other = a.duplicate();
    origin::strip(&mut other);
    println!("A8 other app's copy: {}", show(&other, E));
    // Mac A merges the other app's file: the list goes for good.
    sm(&mut a, &other, Kind::ChangeOnDisk);
    println!("A8 A after merging it: {}", show(&a, E));
    // Changed by R6: a row is not a record off a list, and a file without rows
    // takes nothing away (limit 11). It stays with its share.
    assert!(
        origin::read_rows(&a.meta.custom_data)
            .keys()
            .any(|(x, _)| *x == id(E))
    );
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!("A8 B: {}", show(&b, E));
    println!("A8 known limit (a): B's entry is {:?}", pw(&b, E));
}

// ---------------------------------------------------------------------------
// A9: a marked copy that a third, unmarked copy inside clears.
#[test]
fn a9_a_user_move_out_and_back_on_another_mac_unmarks_for_all() {
    let mut a = common();
    let mut c = cont();
    c.root.entries.push(entry(E, "planted-demo", at(2000)));
    import(&mut a, TEAM, &c);
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    // Mac D is another copy that took A's E, its user moves it out and back.
    let mut d = a.duplicate();
    edit::move_entries(&mut d, &[id(E)], id(PRIVATE), at(3000)).unwrap();
    edit::move_entries(&mut d, &[id(E)], id(TEAM), at(3001)).unwrap();
    sm(&mut a, &d, Kind::ChangeOnDisk);
    println!("A9 A: {}", show(&a, E));
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!(
        "A9 B: {} leaks {}",
        show(&b, E),
        export_leaks(&b, TEAM, "mac-b-demo")
    );
}

// ---------------------------------------------------------------------------
// A10: cycles. Mac A: T/P(m)/Q(m). Mac B: Q/P/T.
#[test]
fn a10_planted_ancestors_of_the_share() {
    let mut a = common();
    let mut b = common();
    // Mac B moved Team under P under Q.
    let team = {
        let i = b
            .root
            .groups
            .iter()
            .position(|g| g.uuid == id(TEAM))
            .unwrap();
        b.root.groups.remove(i)
    };
    let mut p = group(0x41, "P", at(1000));
    p.times.location_changed = at(1000);
    p.groups.push(team);
    p.entries.push(entry(E, "mac-b-demo", at(1000)));
    let mut q = group(0x42, "Q", at(1000));
    q.times.location_changed = at(1000);
    q.groups.push(p);
    b.root.groups.push(q);
    gm(&mut b.root, TEAM).unwrap().times.location_changed = at(1000);
    // Container: P{Q{}} with later times.
    let mut c = cont();
    let mut cp = group(0x41, "planted", at(2000));
    cp.times.location_changed = at(2000);
    let mut cq = group(0x42, "planted", at(2000));
    cq.times.location_changed = at(2000);
    cq.entries.push(entry(0x51, "planted-demo", at(2000)));
    cp.groups.push(cq);
    c.root.groups.push(cp);
    import(&mut a, TEAM, &c);
    println!(
        "A10 A: P {} Q {} T {}",
        where_group(&a, 0x41),
        where_group(&a, 0x42),
        where_group(&a, TEAM)
    );
    for kind in KINDS {
        let mut b1 = b.duplicate();
        let ch = sm(&mut b1, &a, kind);
        println!(
            "A10 {kind:?} B<-A: P {} Q {} T {} E {} N {} changes {}",
            where_group(&b1, 0x41),
            where_group(&b1, 0x42),
            where_group(&b1, TEAM),
            where_is(&b1, E),
            where_is(&b1, 0x51),
            ch.len()
        );
        let mut a1 = a.duplicate();
        let ch = sm(&mut a1, &b, kind);
        println!(
            "A10 {kind:?} A<-B: P {} Q {} T {} E {} N {} changes {}",
            where_group(&a1, 0x41),
            where_group(&a1, 0x42),
            where_group(&a1, TEAM),
            where_is(&a1, E),
            where_is(&a1, 0x51),
            ch.len()
        );
        assert_eq!(larsal_model::invariants::check(&b1), Ok(()));
        assert_eq!(larsal_model::invariants::check(&a1), Ok(()));
        assert_eq!(where_group(&b1, 0x41), "Root/Q/P");
        assert_eq!(where_group(&a1, 0x41), "Root/Q/P");
        assert_eq!(pw(&b1, E).as_deref(), Some("mac-b-demo"));
        assert_eq!(pw(&a1, E).as_deref(), Some("mac-b-demo"));
    }
}

// A11: the planted group's children are unmarked because they were in the share before.
#[test]
fn a11_a_change_record_never_holds_a_value() {
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    let mut c = cont();
    let mut e = entry(E, "planted-demo", at(2000));
    e.set_field(
        "Title".into(),
        Field {
            value: SecretString::new("planted-title".into()),
            protected: false,
        },
    );
    c.root.entries.push(e);
    import(&mut a, TEAM, &c);
    for ch in sm(&mut a, &b, Kind::Window) {
        println!("A11 A<-B {}", ch.line());
        assert_ne!(ch.kind, ChangeKind::Deleted);
    }
}

// A12: entry id equals a group id on the other Mac, with a list item.
#[test]
fn a12_an_entry_and_a_group_with_one_id() {
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .groups
        .push(group(0x31, "Real group", at(1000)));
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    // The container brings an entry with the group's id and a group with the entry's id.
    let mut c = cont();
    c.root.entries.push(entry(0x31, "planted-demo", at(2000)));
    c.root.groups.push(group(E, "planted", at(2000)));
    import(&mut a, TEAM, &c);
    let mut c2 = cont();
    c2.deleted_objects.push(record_of(0x31, far()));
    c2.deleted_objects.push(record_of(E, far()));
    import(&mut a, TEAM, &c2);
    println!(
        "A12 A: entry31 {} group50 {} scopes {:?}",
        where_is(&a, 0x31),
        where_group(&a, E),
        origin::read_rows(&a.meta.custom_data).len()
    );
    for kind in KINDS {
        let mut b1 = b.duplicate();
        sm(&mut b1, &a, kind);
        let mut a1 = a.duplicate();
        sm(&mut a1, &b, kind);
        for v in [&b1, &a1] {
            assert!(
                where_group(v, 0x31).ends_with("Private/Real group"),
                "{}",
                where_group(v, 0x31)
            );
            assert_eq!(pw(v, E).as_deref(), Some("mac-b-demo"));
        }
    }
}

// ---------------------------------------------------------------------------
// A13: a custom icon whose id is an outside entry. Removing the icon writes a plain record.
#[test]
fn a13_an_icon_with_an_outside_entrys_id() {
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, PRIVATE)
        .unwrap()
        .entries
        .push(entry(E, "mac-b-demo", at(1000)));
    let mut c = cont();
    c.meta.custom_icons.push(larsal_model::CustomIcon {
        uuid: id(E),
        name: String::new(),
        last_modified: None,
        data: vec![0x89, 0x50, 0x4E, 0x47],
        unknown: Vec::new(),
    });
    import(&mut a, TEAM, &c);
    println!("A13 A icons {}", a.meta.custom_icons.len());
    let gone = larsal_core::icons::purge(&mut a, at(9000));
    println!("A13 A purged {gone}: {}", show(&a, E));
    sm(&mut b, &a, Kind::ChangeOnDisk);
    println!("A13 B: {}", show(&b, E));
    assert_eq!(
        pw(&b, E).as_deref(),
        Some("mac-b-demo"),
        "the icon's record erased the outside entry"
    );
}

// A14: A6 after the share is gone: the record outlives the share, and the attacker's reach.
#[test]
fn a14_a_dormant_record_outlives_the_share() {
    let mut a = common();
    let mut b = common();
    let mut o = group(0x31, "O", at(1000));
    o.entries.push(entry(E, "mac-b-demo", at(1000)));
    gm(&mut b.root, PRIVATE).unwrap().groups.push(o);
    let mut c = cont();
    c.deleted_objects.push(record_of(E, at(2000)));
    import(&mut a, TEAM, &c);
    sm(&mut b, &a, Kind::ChangeOnDisk);
    // No share item in this model at all from here on: Team is an ordinary group.
    edit::move_group(&mut b, id(0x31), id(TEAM), Position::End, at(90000)).unwrap();
    let copy = b.duplicate();
    sm(&mut b, &copy, Kind::ChangeOnDisk);
    println!(
        "A14 B, a merge with its own copy after the move: {}",
        show(&b, E)
    );
    assert_eq!(
        pw(&b, E).as_deref(),
        Some("mac-b-demo"),
        "the old share's item erased it"
    );
}

// H: honest flows, all kinds, both directions, three rounds.
fn converge(a: &mut Vault, b: &mut Vault, kind: Kind) {
    for _ in 0..3 {
        sm(b, a, kind);
        sm(a, b, kind);
    }
}

#[test]
fn h1_honest_flows_converge() {
    for kind in KINDS {
        // Deletion across a member's two Macs, a holder.
        let mut base = common();
        gm(&mut base.root, TEAM)
            .unwrap()
            .entries
            .push(entry(E, "shared-demo", at(100)));
        let (mut a, mut b) = (base.duplicate(), base.duplicate());
        let mut c = cont();
        c.deleted_objects.push(record_of(E, at(2000)));
        import(&mut a, TEAM, &c);
        converge(&mut a, &mut b, kind);
        assert_eq!((pw(&a, E), pw(&b, E)), (None, None), "{kind:?} holder");
        // A newcomer.
        let (mut a, mut b) = (common(), base.duplicate());
        let mut c = cont();
        c.deleted_objects.push(record_of(E, at(2000)));
        import(&mut a, TEAM, &c);
        converge(&mut a, &mut b, kind);
        assert_eq!((pw(&a, E), pw(&b, E)), (None, None), "{kind:?} newcomer");
        // Re-add after a deletion: a later container brings it back, newer.
        let mut c = cont();
        c.root.entries.push(entry(E, "again-demo", at(5000)));
        import(&mut a, TEAM, &c);
        println!("H1 {kind:?} A re-add: {}", show(&a, E));
        converge(&mut a, &mut b, kind);
        println!("H1 {kind:?} B re-add: {}", show(&b, E));
        assert_eq!(pw(&a, E).as_deref(), Some("again-demo"), "{kind:?} re-add");
        assert_eq!(pw(&b, E).as_deref(), Some("again-demo"), "{kind:?} re-add");
        assert!(where_is(&b, E).ends_with("Team"));
        // Move out of an unmarked entry, nothing hostile.
        let (mut a, mut b) = (base.duplicate(), base.duplicate());
        edit::move_entries(&mut b, &[id(E)], id(PRIVATE), at(1000)).unwrap();
        converge(&mut a, &mut b, kind);
        assert!(where_is(&a, E).ends_with("Private"), "{kind:?} move out");
        // Move in, nothing hostile.
        let mut base2 = common();
        gm(&mut base2.root, PRIVATE)
            .unwrap()
            .entries
            .push(entry(E, "mine-demo", at(100)));
        let (mut a, mut b) = (base2.duplicate(), base2.duplicate());
        edit::move_entries(&mut b, &[id(E)], id(TEAM), at(1000)).unwrap();
        converge(&mut a, &mut b, kind);
        assert!(where_is(&a, E).ends_with("Team"), "{kind:?} move in");
        assert!(
            export_leaks(&a, TEAM, "mine-demo"),
            "{kind:?} a move in is exported"
        );
        // A move out wins over an imported copy; the move back is ordinary.
        let (mut a, mut b) = (common(), common());
        let mut c = cont();
        c.root.entries.push(entry(E, "brought-demo", at(100)));
        import(&mut a, TEAM, &c);
        import(&mut b, TEAM, &c);
        edit::move_entries(&mut b, &[id(E)], id(PRIVATE), at(1000)).unwrap();
        converge(&mut a, &mut b, kind);
        assert!(
            where_is(&a, E).ends_with("Private"),
            "{kind:?} marked move out"
        );
        edit::move_entries(&mut a, &[id(E)], id(TEAM), at(2000)).unwrap();
        converge(&mut a, &mut b, kind);
        assert!(
            where_is(&b, E).ends_with("Team"),
            "{kind:?} marked move back"
        );
        // Changed by R6: the marker stays, and the move back's stamp carries the
        // object in (R6 B, E3). Round 2 cleared the marker.
        assert!(mark(&a, E) && mark(&b, E));
        for v in [&a, &b] {
            let stamp = find(v, E).and_then(|e| origin::stamp_of(&e.custom_data));
            assert_eq!(stamp.map(|s| s.group), Some(id(TEAM)), "{kind:?}");
        }
    }
}

// F: three copies, random imports on two of them, any merge order and kind.
fn rng(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

/// Outside on Mac B: Q(40) -> {P(41) -> {E(50), R(43) -> F(51)}}, S(42) -> H(52); Team stays
/// at the root, or sits under P when `under`.
fn holder(under: bool) -> Vault {
    let mut v = common();
    let t0 = at(1000);
    let mut p = group(0x41, "P", t0);
    p.entries.push(entry(0x50, "outside-demo", t0));
    let mut r = group(0x43, "R", t0);
    r.entries.push(entry(0x51, "outside-demo", t0));
    p.groups.push(r);
    if under {
        let i = v
            .root
            .groups
            .iter()
            .position(|g| g.uuid == id(TEAM))
            .unwrap();
        let mut t = v.root.groups.remove(i);
        t.times.location_changed = t0;
        p.groups.push(t);
    }
    let mut q = group(0x40, "Q", t0);
    q.groups.push(p);
    let mut s = group(0x42, "S", t0);
    s.entries.push(entry(0x52, "outside-demo", t0));
    v.root.groups.push(q);
    v.root.groups.push(s);
    v
}

fn random_container(x: &mut u64) -> Vault {
    let mut c = cont();
    let pool: [u8; 12] = [
        0x40, 0x41, 0x42, 0x43, 0x50, 0x51, 0x52, 0x60, 0x61, 0x62, 0x30, 0x20,
    ];
    let mut stack: Vec<Group> = Vec::new();
    for _ in 0..(rng(x) % 5) {
        let n = pool[(rng(x) % 12) as usize];
        let when = at((rng(x) % 3000) as i64 * 2);
        let mut g = group(n, "planted", when);
        g.times.location_changed = when;
        for _ in 0..(rng(x) % 3) {
            let m = pool[(rng(x) % 12) as usize];
            let t = at((rng(x) % 3000) as i64 * 2);
            g.entries.push(entry(m, "planted-demo", t));
        }
        stack.push(g);
    }
    while stack.len() > 1 {
        let g = stack.pop().unwrap();
        if rng(x) % 2 == 0 {
            stack.last_mut().unwrap().groups.push(g);
        } else {
            c.root.groups.push(g);
        }
    }
    if let Some(g) = stack.pop() {
        c.root.groups.push(g);
    }
    for _ in 0..(rng(x) % 4) {
        let m = pool[(rng(x) % 12) as usize];
        let t = at((rng(x) % 3000) as i64 * 2);
        c.root.entries.push(entry(m, "planted-demo", t));
    }
    if rng(x) % 2 == 0 {
        for _ in 0..(rng(x) % 5) {
            let m = pool[(rng(x) % 12) as usize];
            c.deleted_objects.push(record_of(m, far()));
        }
    }
    c
}

fn reality(v: &Vault) -> Result<(), String> {
    larsal_model::invariants::check(v).map_err(|e| format!("invariants {e:?}"))?;
    for (e, place) in [(0x50u8, 0x41u8), (0x51, 0x43), (0x52, 0x42)] {
        let holds = v
            .root
            .find_group(id(place))
            .is_some_and(|g| g.entries.iter().any(|x| x.uuid == id(e)));
        if !holds {
            return Err(format!("{e:x}: {}", show(v, e)));
        }
        if pw(v, e).as_deref() != Some("outside-demo") {
            return Err(format!("{e:x} value: {}", show(v, e)));
        }
        // Changed by R6 E5, limit 10: the losing copy's value may stay as a history
        // item here, and is never exported while this copy is outside.
        if hist(v, e).iter().any(|h| h != "planted-demo") {
            return Err(format!("{e:x} history: {}", show(v, e)));
        }
        if export_leaks(v, TEAM, "outside-demo") {
            return Err(format!("{e:x} exported: {}", show(v, e)));
        }
    }
    for (g, want) in [(0x40u8, "Q"), (0x41, "P"), (0x42, "S"), (0x43, "R")] {
        let f = v.root.find_group(id(g));
        if f.is_none_or(|x| x.name != want) {
            return Err(format!("group {g:x} {}", where_group(v, g)));
        }
    }
    Ok(())
}

fn digest(v: &Vault) -> Vec<(Uuid, Vec<Uuid>, String)> {
    let mut out = Vec::new();
    fn walk(g: &Group, path: &mut Vec<Uuid>, out: &mut Vec<(Uuid, Vec<Uuid>, String)>) {
        path.push(g.uuid);
        for e in &g.entries {
            out.push((e.uuid, path.clone(), e.value("Password").to_owned()));
        }
        for c in &g.groups {
            walk(c, path, out);
        }
        path.pop();
    }
    walk(&v.root, &mut Vec::new(), &mut out);
    out.sort();
    out
}

#[test]
fn f1_three_copies_any_order() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut fails = 0usize;
    let mut unconverged = 0usize;
    let rounds: usize = std::env::var("C1R2_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    for n in 0..rounds {
        let under = rng(&mut x) % 3 == 0;
        let mut a = common();
        let mut d = common();
        let b = holder(under);
        for _ in 0..1 + rng(&mut x) % 3 {
            let c = random_container(&mut x);
            if larsal_model::invariants::check(&c).is_ok() {
                let _ = run::merge_into(&mut a, id(TEAM), &c, NOW);
            }
            if rng(&mut x) % 2 == 0 {
                let c = random_container(&mut x);
                if larsal_model::invariants::check(&c).is_ok() {
                    let _ = run::merge_into(&mut d, id(TEAM), &c, NOW);
                }
            }
        }
        let kind = KINDS[(rng(&mut x) % 6) as usize];
        let mut bb = b.duplicate();
        let mut trail = String::new();
        let mut got_b = [false, true, false]; // a, b, d
        for _ in 0..3 + rng(&mut x) % 6 {
            let (t, s) = ((rng(&mut x) % 3) as usize, (rng(&mut x) % 3) as usize);
            if t == s {
                continue;
            }
            trail.push_str(&format!("{t}<-{s} "));
            let source = match s {
                0 => a.duplicate(),
                1 => bb.duplicate(),
                _ => d.duplicate(),
            };
            let target = match t {
                0 => &mut a,
                1 => &mut bb,
                _ => &mut d,
            };
            merge(target, &source, &Options::new(kind), NOW).expect("merge");
            got_b[t] = got_b[t] || got_b[s];
            if got_b[t] {
                if let Err(e) = reality(target) {
                    fails += 1;
                    if fails <= 12 {
                        println!("F1 #{n} under {under} {kind:?} copy {t} after {trail}: {e}");
                    }
                    break;
                }
            }
        }
        for _ in 0..3 {
            let s = bb.duplicate();
            merge(&mut a, &s, &Options::new(kind), NOW).unwrap();
            let s = a.duplicate();
            merge(&mut d, &s, &Options::new(kind), NOW).unwrap();
            let s = d.duplicate();
            merge(&mut bb, &s, &Options::new(kind), NOW).unwrap();
        }
        if reality(&a).is_err() || reality(&bb).is_err() || reality(&d).is_err() {
            fails += 1;
            if fails <= 12 {
                println!(
                    "F1 #{n} after sweeps: {:?} {:?} {:?}",
                    reality(&a).err(),
                    reality(&bb).err(),
                    reality(&d).err()
                );
            }
        }
        if digest(&a) != digest(&bb) || digest(&a) != digest(&d) {
            unconverged += 1;
            if unconverged <= 4 {
                println!(
                    "F1 #{n} under {under} {kind:?} does not converge after {trail}\n a {:?}\n b {:?}\n d {:?}",
                    digest(&a),
                    digest(&bb),
                    digest(&d)
                );
            }
        }
    }
    println!("F1 rounds {rounds} fails {fails} unconverged {unconverged}");
    assert_eq!(fails, 0);
    assert_eq!(unconverged, 0);
}
