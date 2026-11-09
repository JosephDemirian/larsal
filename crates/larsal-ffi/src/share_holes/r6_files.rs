//! Rule R6 on real files, through two or three sessions (INT-08.32): the attacks of
//! both checkers of round 2, F1 to F5 and CR2-01 to CR2-06 among them. Each asserts
//! what the cards claim, so red is a finding. An assertion R6 changes says so.

use super::*;
use larsal_core::edit::{self, Position};
use larsal_core::origin;
use larsal_model::Entry;
use larsal_model::custom_data::CustomDataItem;

fn at(n: i64) -> Time {
    Time(T2.0 + n)
}

const FAR: i64 = 3_000_000_000;

fn place(s: &Session, v: u64, n: u8) -> String {
    fn walk(g: &Group, n: u8, trail: &mut Vec<String>) -> bool {
        trail.push(g.name.clone());
        if g.entries.iter().any(|e| e.uuid == id(n)) {
            return true;
        }
        if g.groups.iter().any(|c| walk(c, n, trail)) {
            return true;
        }
        trail.pop();
        false
    }
    model(s, v, |m| {
        let mut t = Vec::new();
        if walk(&m.root, n, &mut t) {
            t.join("/")
        } else {
            "GONE".into()
        }
    })
}

fn state(s: &Session, v: u64, n: u8) -> String {
    let hist: Vec<String> = model(s, v, |m| {
        find(m, n)
            .map(|e| {
                e.history
                    .iter()
                    .map(|h| h.value("Password").to_owned())
                    .collect()
            })
            .unwrap_or_default()
    });
    let marked = model(s, v, |m| {
        find(m, n).is_some_and(|e| origin::mark_of(&e.custom_data).is_some())
    });
    let records = model(s, v, |m| {
        m.deleted_objects.iter().filter(|d| d.uuid == id(n)).count()
    });
    let rows = model(s, v, |m| {
        origin::read_rows(&m.meta.custom_data)
            .keys()
            .filter(|(x, _)| *x == id(n))
            .count()
    });
    format!(
        "at {} password {:?} history {:?} marked {} records {} rows {}",
        place(s, v, n),
        password_of(s, v, n),
        hist,
        marked,
        records,
        rows
    )
}

fn scene(tag: &str) -> (TempDir, PathBuf, String, Vault) {
    let dir = TempDir::new(&format!("r6-{tag}"));
    let path = dir.join("team.larsalvault");
    let path_text = path.to_string_lossy().into_owned();
    let mut common = base();
    set_share(team(&mut common), settings(true, true, &path_text));
    common
        .root
        .groups
        .push(Group::new(id(0x30), "Private".into(), T2));
    (dir, path, path_text, common)
}

fn planted(n: u8, when: Time) -> Entry {
    let mut e = entry(n, "Planted", "demo-a", "planted-demo");
    e.times.last_modification = when;
    e.times.location_changed = when;
    e
}

fn gm(g: &mut Group, n: u8) -> &mut Group {
    fn inner(g: &mut Group, n: u8) -> Option<&mut Group> {
        if g.uuid == id(n) {
            return Some(g);
        }
        g.groups.iter_mut().find_map(|c| inner(c, n))
    }
    inner(g, n).expect("the group")
}

/// Mac B's vault: `common` and E in Private with `mac-b-demo`, later than the plants.
fn with_outside(common: &Vault) -> Vault {
    let mut v = common.duplicate();
    let mut own = entry(0x50, "Outside", "demo-b", "mac-b-demo");
    own.times.last_modification = at(1000);
    own.times.location_changed = at(1000);
    gm(&mut v.root, 0x30).entries.push(own);
    v
}

fn item(n: u8, when: Time) -> DeletedObject {
    DeletedObject {
        uuid: id(n),
        deleted_at: when,
        unknown: Vec::new(),
    }
}

/// F1: an entry the member made inside the share carries no marker. On Mac B the
/// member moves it out and gives it a private password; Mac A, which has not merged
/// that yet, imports a container with later times on E.
#[test]
fn f1_real_files_a_moved_out_entry_stays_out_and_nothing_leaks() {
    let (dir, path, path_text, mut common) = scene("f1");
    team(&mut common)
        .entries
        .push(entry(0x50, "E", "demo", "shared-demo"));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, _b_file) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x30), at(1000)).unwrap();
        let e = gm(&mut m.root, 0x30);
        let e = e.entries.iter_mut().find(|e| e.uuid == id(0x50)).unwrap();
        set(e, "Password", "private-demo", true);
        e.times.last_modification = at(1001);
    });
    saved_as(&b, vb, "B1");
    // The holder of the share key knows E's id: it was shared.
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root.entries.push(planted(0x50, at(2000)));
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A1");
    merge_file(&b, vb, &a_file, &dir, "from-a");
    println!("F1 B after merge: {}", state(&b, vb, 0x50));
    saved_as(&b, vb, "B2");
    assert!(
        !held_in_container(&path, SHARE, "private-demo"),
        "leaked to the share"
    );
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("private-demo"));
    assert!(place(&b, vb, 0x50).ends_with("Private"));
}

/// F1 for a group: the member moves group O out of the share and puts a private
/// entry in it. Mac A imports a container that moves O inside the share, later.
#[test]
fn f1_real_files_a_moved_out_group_stays_out_and_nothing_leaks() {
    let (dir, path, path_text, mut common) = scene("f1g");
    team(&mut common)
        .groups
        .push(Group::new(id(0x31), "O".into(), T2));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, _b_file) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_group(m, id(0x31), id(0x30), Position::End, at(1000)).unwrap();
        let o = gm(&mut m.root, 0x31);
        let mut e = entry(0x50, "Mine", "demo", "private-demo");
        e.times.last_modification = at(1100);
        e.times.location_changed = at(1100);
        o.entries.push(e);
    });
    saved_as(&b, vb, "B1");
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let mut o = Group::new(id(0x31), "O".into(), T2);
    o.times.location_changed = at(2000);
    c.root.groups.first_mut().unwrap().groups.push(o);
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A1");
    merge_file(&b, vb, &a_file, &dir, "from-a");
    println!("F1 group B after merge: {}", state(&b, vb, 0x50));
    saved_as(&b, vb, "B2");
    assert!(
        !held_in_container(&path, SHARE, "private-demo"),
        "leaked to the share"
    );
}

/// F2: Mac A's user deletes the planted entry, the natural answer to it.
fn delete_scene(bin: bool, tag: &str) {
    let (dir, path, _path_text, mut common) = scene(tag);
    common.meta.recycle_bin_enabled = bin;
    let mac_b_vault = with_outside(&common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root.entries.push(planted(0x50, at(500)));
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    let done = a.delete_entry(va, hex(id(0x50))).unwrap();
    println!(
        "F2 {tag} delete: to bin {} for good {}",
        done.to_bin, done.for_good
    );
    println!("F2 {tag} A after delete: {}", state(&a, va, 0x50));
    saved_as(&a, va, "A1");
    std::fs::remove_file(&path).ok();
    let (b, vb, _bf) = mac("b", &dir, &mac_b_vault);
    merge_file(&b, vb, &a_file, &dir, "from-a");
    println!("F2 {tag} B after merge: {}", state(&b, vb, 0x50));
    if bin {
        a.empty_bin(va).unwrap();
        saved_as(&a, va, "A2");
        merge_file(&b, vb, &a_file, &dir, "from-a-2");
        println!(
            "F2 {tag} B after A emptied its bin: {}",
            state(&b, vb, 0x50)
        );
    }
    assert_eq!(
        password_of(&b, vb, 0x50).as_deref(),
        Some("mac-b-demo"),
        "{tag}: Mac B's entry"
    );
    assert!(place(&b, vb, 0x50).ends_with("Private"), "{tag}");
}

#[test]
fn f2_real_files_deleting_the_planted_copy_with_the_bin_off() {
    delete_scene(false, "bin-off");
}

#[test]
fn f2_real_files_deleting_the_planted_copy_with_the_bin_on() {
    delete_scene(true, "bin-on");
}

/// F3: two nested shares: Team's container moves what Sub's brought out of Sub,
/// inside Team.
#[test]
fn f3_real_files_nested_shares() {
    let (dir, path, path_text, mut common) = scene("f3");
    let sub_path = dir.join("sub.larsalvault");
    let sub_text = sub_path.to_string_lossy().into_owned();
    {
        let sub = gm(&mut common.root, 0x21);
        set_share(sub, settings(true, false, &sub_text));
    }
    let mac_c_vault = with_outside(&common);
    let (a, va, a_file) = mac("a", &dir, &common);
    // Sub's container brings E.
    let mut c1 = Vault::new(Group::new(id(0x66), "Sub".into(), T2), T2);
    c1.root.entries.push(planted(0x50, at(2000)));
    c1.encryption.kdf = larsal_model::Kdf::AesKdf { rounds: 1_000 };
    write(&sub_path, &c1, SHARE);
    a.share_look(va, sub_text.clone()).unwrap();
    a.share_wait(va);
    // Team's container holds E in Other, a later location.
    let mut c0 = container::build(id(0x20), true, &member(), T2).unwrap();
    let mut other = Group::new(id(0x23), "Other".into(), T2);
    other.entries.push(planted(0x50, at(3000)));
    c0.root.groups.push(other);
    write(&path, &c0, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    println!("F3 A after Team's import: {}", state(&a, va, 0x50));
    saved_as(&a, va, "A1");
    let (c, vc, _cf) = mac("c", &dir, &mac_c_vault);
    merge_file(&c, vc, &a_file, &dir, "from-a");
    println!("F3 C after merge: {}", state(&c, vc, 0x50));
    saved_as(&c, vc, "C1");
    assert!(!held_in_container(&path, SHARE, "mac-b-demo"), "leaked");
    assert_eq!(password_of(&c, vc, 0x50).as_deref(), Some("mac-b-demo"));
}

/// F4: a dormant row. Honest: E moved out on Mac B, a member deleted it in the
/// share, Mac A imported that. E stays on Mac B with the row beside it. Later the
/// user moves the group holding E into the share.
#[test]
fn f4_real_files_a_group_move_in_after_a_deletion_keeps_the_entry() {
    let (dir, path, path_text, mut common) = scene("f4");
    team(&mut common)
        .entries
        .push(entry(0x50, "E", "demo", "shared-demo"));
    common
        .root
        .groups
        .push(Group::new(id(0x31), "O".into(), T2));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, _bf) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x31), at(1000)).unwrap();
    });
    saved_as(&b, vb, "B1");
    // Another member deletes E: their export lists it.
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.deleted_objects.push(item(0x50, at(2000)));
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A1");
    merge_file(&b, vb, &a_file, &dir, "from-a");
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("shared-demo"));
    saved_as(&b, vb, "B2");
    // Much later: the user shares group O, through the screen layer's route.
    change(&b, vb, |m| {
        edit::move_group(m, id(0x31), id(0x20), Position::End, Time(T2.0 + 900_000)).unwrap();
    });
    saved_as(&b, vb, "B3");
    merge_file(&b, vb, &a_file, &dir, "from-a-2");
    println!("F4 B after the next merge: {}", state(&b, vb, 0x50));
    assert_eq!(
        password_of(&b, vb, 0x50).as_deref(),
        Some("shared-demo"),
        "the user moved it into the share after that deletion"
    );
}

/// F5: a user's own deletion of E beside a row of the same id.
#[test]
fn f5_real_files_a_users_own_deletion_stays() {
    let (dir, path, _path_text, mut common) = scene("f5");
    common.meta.recycle_bin_enabled = false;
    let mac_b_vault = with_outside(&common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.deleted_objects.push(item(0x50, at(2000)));
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    saved_as(&a, va, "A1");
    std::fs::remove_file(&path).ok();
    let (b, vb, b_file) = mac("b", &dir, &mac_b_vault);
    let (d, vd, _df) = mac("d", &dir, &mac_b_vault);
    merge_file(&b, vb, &a_file, &dir, "b-from-a");
    merge_file(&d, vd, &a_file, &dir, "d-from-a");
    b.delete_entry(vb, hex(id(0x50))).unwrap();
    saved_as(&b, vb, "B1");
    merge_file(&d, vd, &b_file, &dir, "d-from-b");
    let d_file = dir.join("d").join("v.larsalvault");
    saved_as(&d, vd, "D1");
    merge_file(&b, vb, &d_file, &dir, "b-from-d");
    println!("F5 B after merging D: {}", state(&b, vb, 0x50));
    assert_eq!(
        password_of(&d, vd, 0x50),
        None,
        "the deletion did not reach Mac D"
    );
    assert_eq!(
        password_of(&b, vb, 0x50),
        None,
        "the deleted entry came back"
    );
}

/// Limit 11 on real files: what a Larsal save does when the vault merges a file
/// without the rule's items. Changed by R6: round 2's list went with the file, and
/// Mac B's entry was then erased (its known limit (a)). The rows now stay with the
/// copy that holds them, Larsal's file holds them again, and nothing is erased.
#[test]
fn limit_11_real_files_a_file_without_the_rules_items_erases_nothing() {
    let (dir, path, _path_text, common) = scene("l11");
    let mac_b_vault = with_outside(&common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root.entries.push(planted(0x51, at(500)));
    c.deleted_objects.push(item(0x50, at(2000)));
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    saved_as(&a, va, "A1");
    std::fs::remove_file(&path).ok();
    // Another app's merge of A's file.
    let on_disk = read(&a_file, MAIN).unwrap();
    assert!(origin::held(&on_disk));
    let mut other = on_disk.duplicate();
    origin::strip(&mut other);
    let other_file = dir.join("other.larsalvault");
    write(&other_file, &other, MAIN);
    // Larsal merges that file, and saves.
    merge_file(&a, va, &other_file, &dir, "a-from-other");
    saved_as(&a, va, "A2");
    let again = read(&a_file, MAIN).unwrap();
    assert!(origin::held(&again), "the rows stay with this copy");
    // Mac B merges a file that lost the items: its entry stays.
    let (b, vb, _bf) = mac("b", &dir, &mac_b_vault);
    merge_file(&b, vb, &other_file, &dir, "b-from-other");
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("mac-b-demo"));
    merge_file(&b, vb, &a_file, &dir, "b-from-a");
    println!("Limit 11 B after merging A: {}", state(&b, vb, 0x50));
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("mac-b-demo"));
}

/// A copy a share brought, edited through the real editor, keeps the marker; a Mac B
/// copy outside still wins and the edit stays as a history item: the stated cost.
#[test]
fn limit_10_real_files_an_editor_edit_of_a_brought_copy() {
    let (dir, path, _path_text, common) = scene("l10");
    let mac_b_vault = with_outside(&common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root.entries.push(planted(0x50, at(500)));
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    a.begin_edit(va, hex(id(0x50))).unwrap();
    a.set_password(va, "my-edit-demo".into()).unwrap();
    a.commit_edit(va).unwrap();
    assert!(model(&a, va, |m| origin::mark_of(
        &find(m, 0x50).unwrap().custom_data
    )
    .is_some()));
    saved_as(&a, va, "A1");
    std::fs::remove_file(&path).ok();
    let (b, vb, b_file) = mac("b", &dir, &mac_b_vault);
    merge_file(&b, vb, &a_file, &dir, "from-a");
    saved_as(&b, vb, "B1");
    merge_file(&a, va, &b_file, &dir, "from-b");
    println!("Limit 10 A after merge: {}", state(&a, va, 0x50));
    assert_eq!(password_of(&a, va, 0x50).as_deref(), Some("mac-b-demo"));
}

/// Honest flow, real files: a re-add after a deletion comes back on both Macs.
#[test]
fn rf8a_real_files_a_re_add_after_a_deletion() {
    let (dir, path, path_text, mut common) = scene("rf8a");
    team(&mut common)
        .entries
        .push(entry(0x50, "E", "demo", "shared-demo"));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, b_file) = mac("b", &dir, &common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.deleted_objects.push(item(0x50, at(2000)));
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A1");
    merge_file(&b, vb, &a_file, &dir, "b1");
    assert_eq!(password_of(&b, vb, 0x50), None);
    saved_as(&b, vb, "B1");
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let mut again = planted(0x50, at(5000));
    set(&mut again, "Password", "again-demo", true);
    c.root.entries.push(again);
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A2");
    merge_file(&b, vb, &a_file, &dir, "b2");
    saved_as(&b, vb, "B2");
    merge_file(&a, va, &b_file, &dir, "a2");
    assert_eq!(password_of(&a, va, 0x50).as_deref(), Some("again-demo"));
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("again-demo"));
}

/// Honest flow, real files: a move in reaches the other Mac and the export.
#[test]
fn rf8b_real_files_a_move_in() {
    let (dir, path, _path_text, mut common) = scene("rf8b");
    gm(&mut common.root, 0x30)
        .entries
        .push(entry(0x50, "E", "demo", "mine-demo"));
    let (a, va, _a_file) = mac("a", &dir, &common);
    let (b, vb, b_file) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x20), at(1000)).unwrap();
    });
    saved_as(&b, vb, "B1");
    merge_file(&a, va, &b_file, &dir, "a1");
    assert!(place(&a, va, 0x50).ends_with("Team"));
    saved_as(&a, va, "A1");
    assert!(
        held_in_container(&path, SHARE, "mine-demo"),
        "the move in is exported"
    );
}

/// RF8c on real files: the share comes off the group while its rows stay. A row never
/// reaches outside, the group still counts as a share through the known list (it
/// fails safe), a move back counts, and it all converges.
#[test]
fn rf8c_real_files_a_share_removed_while_its_rows_stay() {
    let (dir, path, path_text, mut common) = scene("rf8c");
    team(&mut common)
        .entries
        .push(entry(0x50, "E", "demo", "shared-demo"));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, b_file) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x30), at(1000)).unwrap();
    });
    saved_as(&b, vb, "B1");
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.deleted_objects.push(item(0x50, at(2000)));
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A1");
    merge_file(&b, vb, &a_file, &dir, "b1");
    change(&b, vb, |m| team(m).custom_data.items.clear());
    saved_as(&b, vb, "B2");
    assert!(
        model(&b, vb, origin::known).contains(&id(0x20)),
        "the list outlives the item"
    );
    merge_file(&b, vb, &a_file, &dir, "b2");
    assert!(place(&b, vb, 0x50).ends_with("Private"));
    saved_as(&b, vb, "B3");
    merge_file(&a, va, &b_file, &dir, "a1");
    assert!(place(&a, va, 0x50).ends_with("Private"));
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x20), Time(T2.0 + 900_000)).unwrap();
    });
    saved_as(&b, vb, "B4");
    saved_as(&a, va, "A2");
    merge_file(&b, vb, &a_file, &dir, "b3");
    saved_as(&b, vb, "B5");
    merge_file(&a, va, &b_file, &dir, "a2");
    println!(
        "RF8c after the move back: A {} / B {}",
        state(&a, va, 0x50),
        state(&b, vb, 0x50)
    );
    assert_eq!(place(&a, va, 0x50), place(&b, vb, 0x50));
    assert!(place(&b, vb, 0x50).ends_with("Team"));
}

/// RF8c: the share group itself deleted for good, with rows. What it holds gets rows
/// or plain records by the rule; the group a plain record. The rows stay dormant,
/// nothing outside moves, and both copies converge.
#[test]
fn rf8c_real_files_a_share_group_deleted_for_good_with_rows() {
    let (dir, path, path_text, mut common) = scene("rf8c-gone");
    common.meta.recycle_bin_enabled = false;
    team(&mut common)
        .entries
        .push(entry(0x52, "Inside", "demo", "shared-demo"));
    let mac_b_vault = with_outside(&common);
    let (a, va, a_file) = mac("a", &dir, &common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.deleted_objects.push(item(0x50, at(2000)));
    write(&path, &c, SHARE);
    a.share_look(va, path_text.clone()).unwrap();
    a.share_wait(va);
    change(&a, va, |m| {
        larsal_core::recycle::delete_group(m, id(0x20), at(3000)).unwrap();
    });
    saved_as(&a, va, "A1");
    let on_file = read(&a_file, MAIN).unwrap();
    assert!(on_file.root.find_group(id(0x20)).is_none());
    assert!(
        on_file.deleted_objects.iter().any(|d| d.uuid == id(0x20)),
        "the group: a plain record"
    );
    assert!(
        !on_file.deleted_objects.iter().any(|d| d.uuid == id(0x52)),
        "what it held, unstamped: a row"
    );
    let rows = origin::read_rows(&on_file.meta.custom_data);
    assert!(rows.contains_key(&(id(0x52), id(0x20))));
    assert!(rows.contains_key(&(id(0x50), id(0x20))));
    let (b, vb, b_file) = mac("b", &dir, &mac_b_vault);
    for round in 0..2 {
        merge_file(&b, vb, &a_file, &dir, &format!("b{round}"));
        assert_eq!(
            password_of(&b, vb, 0x50).as_deref(),
            Some("mac-b-demo"),
            "a row outside its share: round {round}"
        );
        assert!(place(&b, vb, 0x50).ends_with("Private"));
        saved_as(&b, vb, &format!("B{round}"));
        merge_file(&a, va, &b_file, &dir, &format!("a{round}"));
        assert_eq!(password_of(&a, va, 0x50).as_deref(), Some("mac-b-demo"));
        saved_as(&a, va, &format!("A{round}"));
    }
    assert!(model(&b, vb, |m| m.root.find_group(id(0x20)).is_none()));
    assert_eq!(password_of(&b, vb, 0x52), None);
    assert!(!path.exists() || read(&path, SHARE).is_ok());
}

// ---------------------------------------------------------------------------
// The second checker's probes of round 2: printed there, asserted here.

/// CR2-02: an entry made in the share, so no marker. Mac B's user moves it out and
/// changes its password. Mac A has not merged yet; it imports a container that dates
/// E far ahead. Then Mac B merges Mac A's file.
fn holder_scene(variant: &str) {
    let (dir, path, text, mut common) = scene(&format!("holder-{variant}"));
    team(&mut common)
        .entries
        .push(entry(0x50, "E", "demo", "was-shared-demo"));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, _b_file) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x30), at(500)).unwrap();
        let e = gm(&mut m.root, 0x30);
        let e = e.entries.iter_mut().find(|e| e.uuid == id(0x50)).unwrap();
        set(e, "Password", "mac-b-private-demo", true);
        e.times.last_modification = at(600);
    });
    saved_as(&b, vb, "B0");
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let far = at(FAR);
    if variant == "mod-and-loc" {
        c.root.entries.push(planted(0x50, far));
    } else {
        // The same old content, in a new group inside the share: a move.
        let mut p = entry(0x50, "E", "demo", "was-shared-demo");
        p.times.location_changed = far;
        let mut sub = Group::new(id(0x41), "Sub2".into(), T2);
        sub.entries.push(p);
        c.root.groups.push(sub);
    }
    write(&path, &c, SHARE);
    a.share_look(va, text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A1");
    merge_file(&b, vb, &a_file, &dir, "from-a");
    println!("CR2-02 {variant}: Mac B: {}", state(&b, vb, 0x50));
    assert_eq!(
        password_of(&b, vb, 0x50).as_deref(),
        Some("mac-b-private-demo"),
        "{variant}"
    );
    assert!(place(&b, vb, 0x50).ends_with("Private"), "{variant}");
    saved_as(&b, vb, "B1");
    assert!(
        !held_in_container(&path, SHARE, "mac-b-private-demo"),
        "{variant}: the export"
    );
}

#[test]
fn cr2_02_real_files_a_holder_future_dated_mod_and_loc() {
    holder_scene("mod-and-loc");
}

#[test]
fn cr2_02_real_files_a_holder_future_dated_loc_only() {
    holder_scene("loc-only");
}

/// CR2-04: the planted entry comes with a history item. Mac A's user restores that
/// version; the marker stays. Mac B holds E outside. `time` dates the plant.
fn restore_scene(tag: &str, time: Time) {
    let (dir, path, _text, common) = scene(tag);
    let mac_b_vault = with_outside(&common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let mut p = planted(0x50, time);
    p.history
        .push(entry(0x50, "Planted", "demo-a", "planted-old-demo"));
    c.root.entries.push(p);
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    let mark = |m: &Vault| find(m, 0x50).and_then(|e| origin::mark_of(&e.custom_data));
    assert_eq!(model(&a, va, mark), Some(id(0x20)));
    a.begin_edit(va, hex(id(0x50))).unwrap();
    a.restore_version(va, 0).unwrap();
    a.commit_edit(va).unwrap();
    assert_eq!(
        model(&a, va, mark),
        Some(id(0x20)),
        "{tag}: Restore keeps it"
    );
    saved_as(&a, va, "A1");
    std::fs::remove_file(&path).ok();
    let (b, vb, _) = mac("b", &dir, &mac_b_vault);
    merge_file(&b, vb, &a_file, &dir, "from-a");
    println!("CR2-04 {tag}: Mac B: {}", state(&b, vb, 0x50));
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("mac-b-demo"));
    assert!(place(&b, vb, 0x50).ends_with("Private"), "{tag}");
    saved_as(&b, vb, "B1");
    assert!(!held_in_container(&path, SHARE, "mac-b-demo"), "{tag}");
}

#[test]
fn cr2_04_real_files_restoring_a_version_keeps_the_marker() {
    restore_scene("restore", at(200));
}

#[test]
fn cr2_04_real_files_restoring_a_version_of_a_far_plant() {
    restore_scene("restore-far", at(FAR));
}

/// CR2-05: the planted copy to the bin and back on Mac A: the marker stays.
#[test]
fn cr2_05_real_files_bin_and_back_keeps_the_marker() {
    let (dir, path, _text, mut common) = scene("bin");
    common.meta.recycle_bin_enabled = true;
    let mac_b_vault = with_outside(&common);
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.root
        .entries
        .push(entry(0x50, "Planted", "demo-a", "planted-demo"));
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    let mark = |m: &Vault| find(m, 0x50).and_then(|e| origin::mark_of(&e.custom_data));
    change(&a, va, |m| {
        larsal_core::recycle::delete_entries(m, &[id(0x50)], T2, |_, _| {
            larsal_core::recycle::References::Delete
        })
        .unwrap();
    });
    assert_eq!(model(&a, va, mark), Some(id(0x20)), "in the bin");
    a.restore_entry(va, hex(id(0x50))).unwrap();
    assert_eq!(model(&a, va, mark), Some(id(0x20)), "restored");
    assert!(place(&a, va, 0x50).ends_with("Team"));
    saved_as(&a, va, "A1");
    std::fs::remove_file(&path).ok();
    let (b, vb, _) = mac("b", &dir, &mac_b_vault);
    merge_file(&b, vb, &a_file, &dir, "from-a");
    println!("CR2-05: Mac B: {}", state(&b, vb, 0x50));
    assert_eq!(password_of(&b, vb, 0x50).as_deref(), Some("mac-b-demo"));
    assert!(place(&b, vb, 0x50).ends_with("Private"));
    saved_as(&b, vb, "B1");
    assert!(!held_in_container(&path, SHARE, "mac-b-demo"));
}

/// An entry at exactly the reader's custom data limit (round 5, C1R4-03): base takes
/// this import, so it is not refused; the import's marker does not fit (one door), the
/// entry comes in without it, and the vault saves and opens with the entry at the limit.
#[test]
fn c2_real_files_custom_data_limit_imports_without_the_marker() {
    let dir = TempDir::new("r6-limit");
    let path = dir.join("team.larsalvault");
    let file = dir.join("v.larsalvault");
    let text = path.to_string_lossy().into_owned();
    let mut vault = base();
    set_share(team(&mut vault), settings(true, false, &text));
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    let mut heavy = entry(0x50, "Heavy", "demo", "heavy-demo");
    let limit = larsal_format::limits::Limits::DEFAULT.custom_data_items;
    for i in 0..limit {
        heavy.custom_data.items.push(CustomDataItem {
            key: format!("k{i}"),
            value: secret("v"),
            last_modified: None,
            unknown: Vec::new(),
        });
    }
    c.root.entries.push(heavy);
    write(&path, &c, SHARE);
    let s = session(false);
    let v = approved(&s, &file, &vault);
    unlock(&s, v);
    assert!(banner(&s, v).is_none_or(|(level, _)| level != ShareLevel::Error));
    let heavy = |m: &Vault| {
        find(m, 0x50).map(|e| (e.custom_data.items.len(), origin::mark_of(&e.custom_data)))
    };
    assert_eq!(model(&s, v, heavy), Some((limit, None)));
    saved_as(&s, v, "V2");
    let again = read(&file, MAIN).unwrap();
    assert_eq!(again.meta.name, "V2");
    assert_eq!(heavy(&again), Some((limit, None)));
}

/// CR2-01 on real files, honest: E was in the share; Mac B moved it out; a member
/// deleted it in the share; so a row stands beside E on both Macs. Later the user
/// deletes E for good. It stays deleted.
#[test]
fn cr2_01_real_files_a_users_later_deletion_sticks() {
    let (dir, path, text, mut common) = scene("cr2-01");
    common.meta.recycle_bin_enabled = false;
    team(&mut common)
        .entries
        .push(entry(0x50, "E", "demo", "e-demo"));
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, b_file) = mac("b", &dir, &common);
    change(&b, vb, |m| {
        edit::move_entries(m, &[id(0x50)], id(0x30), at(500)).unwrap();
    });
    saved_as(&b, vb, "B0");
    let mut c = container::build(id(0x20), true, &member(), T2).unwrap();
    c.deleted_objects.push(item(0x50, at(400)));
    write(&path, &c, SHARE);
    a.share_look(va, text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A0");
    merge_file(&b, vb, &a_file, &dir, "b-from-a");
    saved_as(&b, vb, "B1");
    merge_file(&a, va, &b_file, &dir, "a-from-b");
    saved_as(&a, va, "A1");
    for (s, v) in [(&a, va), (&b, vb)] {
        assert!(place(s, v, 0x50).ends_with("Private"), "settled");
    }
    change(&b, vb, |m| {
        larsal_core::recycle::delete_entries(m, &[id(0x50)], at(900), |_, _| {
            larsal_core::recycle::References::Delete
        })
        .unwrap();
    });
    saved_as(&b, vb, "B2");
    for round in 0..2 {
        merge_file(&a, va, &b_file, &dir, &format!("a-from-b-{round}"));
        saved_as(&a, va, &format!("A2{round}"));
        merge_file(&b, vb, &a_file, &dir, &format!("b-from-a-{round}"));
        saved_as(&b, vb, &format!("B2{round}"));
        assert_eq!(password_of(&a, va, 0x50), None, "round {round}: Mac A");
        assert_eq!(password_of(&b, vb, 0x50), None, "round {round}: Mac B");
    }
}

fn many(tag: u8, n: u32, when: Time) -> Vec<DeletedObject> {
    (0..n)
        .map(|i| {
            let mut u = [tag; 16];
            u[..4].copy_from_slice(&i.to_le_bytes());
            DeletedObject {
                uuid: larsal_model::Uuid(u),
                deleted_at: when,
                unknown: Vec::new(),
            }
        })
        .collect()
}

/// CR2-06: a hostile container fills the reader's limit of records with ids V never
/// held. Changed by R6: they are rows, at most the cap, off the main list, so the
/// user's own deletion still saves. Run by hand, it takes minutes.
#[test]
#[ignore = "scale"]
fn cr2_06_real_files_a_full_container_list_no_longer_blocks_a_save() {
    let (dir, path, text, mut common) = scene("cr2-06");
    common.meta.recycle_bin_enabled = false;
    gm(&mut common.root, 0x30)
        .entries
        .push(entry(0x50, "Mine", "demo", "mine-demo"));
    let mut c = Vault::new(Group::new(id(0x66), "Share".into(), T2), T2);
    c.meta.recycle_bin_enabled = false;
    c.encryption.kdf = larsal_model::Kdf::AesKdf { rounds: 1_000 };
    c.deleted_objects = many(0xD0, 1_000_000, T2);
    write(&path, &c, SHARE);
    let (a, va, a_file) = mac("a", &dir, &common);
    a.share_look(va, text.clone()).unwrap();
    a.share_wait(va);
    assert_eq!(model(&a, va, |m| m.deleted_objects.len()), 0);
    assert_eq!(
        model(&a, va, |m| origin::read_rows(&m.meta.custom_data).len()),
        origin::ROW_CAP
    );
    change(&a, va, |m| {
        larsal_core::recycle::delete_entries(m, &[id(0x50)], at(900), |_, _| {
            larsal_core::recycle::References::Delete
        })
        .unwrap();
    });
    assert_eq!(a.save(va).map(|o| o.failure).unwrap(), None);
    a.share_wait(va);
    assert_eq!(read(&a_file, MAIN).unwrap().deleted_objects.len(), 1);
}

/// CR2-06, what is left: a list the user's own deletions fill to the reader's limit
/// still blocks a save that adds a record; nothing is lost on disk.
#[test]
#[ignore = "scale"]
fn cr2_06_real_files_a_full_plain_list_still_blocks_a_save_that_adds_one() {
    let (dir, _path, _text, mut common) = scene("cr2-06b");
    common.meta.recycle_bin_enabled = false;
    gm(&mut common.root, 0x30)
        .entries
        .push(entry(0x50, "Mine", "demo", "mine-demo"));
    common.deleted_objects = many(0xD0, 1_000_000, T2);
    let (a, va, a_file) = mac("a", &dir, &common);
    change(&a, va, |m| {
        larsal_core::recycle::delete_entries(m, &[id(0x50)], at(900), |_, _| {
            larsal_core::recycle::References::Delete
        })
        .unwrap();
    });
    assert!(a.save(va).map(|o| o.failure).unwrap().is_some());
    assert!(
        read(&a_file, MAIN)
            .unwrap()
            .root
            .all_entries()
            .any(|e| e.uuid == id(0x50)),
        "the last good file stays"
    );
}

/// CR2-06: two Macs of one vault, each with a hostile container of the limit, ids
/// apart: the rows of one share stay at the cap, so the merge saves.
#[test]
#[ignore = "scale"]
fn cr2_06_real_files_two_full_container_lists_merge_and_save() {
    let (dir, path, text, mut common) = scene("cr2-06c");
    common.meta.recycle_bin_enabled = false;
    let (a, va, a_file) = mac("a", &dir, &common);
    let (b, vb, b_file) = mac("b", &dir, &common);
    let mut c = Vault::new(Group::new(id(0x66), "Share".into(), T2), T2);
    c.meta.recycle_bin_enabled = false;
    c.encryption.kdf = larsal_model::Kdf::AesKdf { rounds: 1_000 };
    c.deleted_objects = many(0xD0, 1_000_000, T2);
    write(&path, &c, SHARE);
    a.share_look(va, text.clone()).unwrap();
    a.share_wait(va);
    saved_as(&a, va, "A0");
    c.deleted_objects = many(0xD1, 1_000_000, T2);
    write(&path, &c, SHARE);
    b.share_look(vb, text.clone()).unwrap();
    b.share_wait(vb);
    saved_as(&b, vb, "B0");
    std::fs::remove_file(&path).ok();
    merge_file(&b, vb, &a_file, &dir, "from-a");
    assert_eq!(
        model(&b, vb, |m| origin::read_rows(&m.meta.custom_data).len()),
        origin::ROW_CAP
    );
    saved_as(&b, vb, "B1");
    assert!(read(&b_file, MAIN).is_ok());
}
