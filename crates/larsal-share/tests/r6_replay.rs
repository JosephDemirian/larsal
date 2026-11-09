//! Rule R6's model against the real code, step by step (INT-08.32): after every step of
//! a trace, the state of every copy must be the state the model computed. Demo data only.
//! `r6_replay/traces.in` is a corpus chosen from the model's runs, so that undoing a clause
//! of the rule goes red here, and `traces.want` is the model's answer to it. The `r5r1.`
//! traces come from round 5's model and each has an import erase that writes a row for a
//! share inside the imported one (C1R4-01). The `r6r1.` and `r6r2.` traces come from round
//! 6's model and each has a merge of one vault's copies whose erase writes a row for a share
//! inside the one whose row applied (C1R5-01). A bigger run, by hand: MDL_IN names the
//! traces and the states go to MDL_OUT.
#![allow(
    clippy::all,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use larsal_core::edit::{self, Position};
use larsal_core::history;
use larsal_core::merge::{ChangeKind, Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::secret::SecretString;
use larsal_model::custom_data::CustomDataItem;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const T0: Time = Time(63_902_822_400);
const KINDS: [Kind; 6] = [
    Kind::ChangeOnDisk,
    Kind::ConflictCopy,
    Kind::ServerSync,
    Kind::Window,
    Kind::CommandLine,
    Kind::RemoteSync,
];

fn at(n: i64) -> Time {
    Time(T0.0 + n)
}
fn back(t: Time) -> i64 {
    t.0 - T0.0
}
fn idof(s: &str) -> Uuid {
    // The model compares names in its ties: B < E < F < O < P < R < S < T < U.
    Uuid([s.as_bytes()[0]; 16])
}
fn nameof(u: Uuid) -> String {
    (u.0[0] as char).to_string()
}
fn isg(x: &str) -> bool {
    x.starts_with('O')
}

fn world(shares: &[String]) -> Vault {
    let mut root = Group::new(idof("R"), "R".into(), T0);
    let mut t = Group::new(idof("T"), "T".into(), T0);
    t.groups.push(Group::new(idof("S"), "S".into(), T0));
    root.groups.push(Group::new(idof("P"), "P".into(), T0));
    root.groups.push(t);
    root.groups.push(Group::new(idof("U"), "U".into(), T0));
    root.groups.push(Group::new(idof("B"), "B".into(), T0));
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.history_max_items = -1;
    v.meta.history_max_size = -1;
    v.meta.recycle_bin = Some(idof("B"));
    let key = std::str::from_utf8(edit::SHARED_KEY).unwrap().to_owned();
    let mut known = origin::Set::new();
    for s in shares {
        known.insert(idof(s));
        gm(&mut v.root, idof(s))
            .unwrap()
            .custom_data
            .items
            .push(CustomDataItem {
                key: key.clone(),
                value: SecretString::new(String::new()),
                last_modified: None,
                unknown: Vec::new(),
            });
    }
    origin::write_known(&mut v.meta.custom_data, &known);
    v
}

fn gm<'a>(g: &'a mut Group, id: Uuid) -> Option<&'a mut Group> {
    if g.uuid == id {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| gm(c, id))
}

fn set_pw(e: &mut Entry, v: i64) {
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(format!("v{v}")),
            protected: true,
        },
    );
}

fn val(s: &str) -> i64 {
    s.strip_prefix('v')
        .and_then(|t| t.parse().ok())
        .unwrap_or(-9)
}

fn own(d: &larsal_model::CustomData) -> String {
    let st = origin::stamp_of(d).map_or("-".to_owned(), |s| {
        format!("{}/{}", nameof(s.group), back(s.at))
    });
    format!("{st}:{}", i32::from(d.get(origin::MARK).is_some()))
}

fn entry_row(e: &Entry, par: &str, out: &mut BTreeMap<String, String>) {
    // A private item (INT-08.32) ends with `!`, as the model writes a tagged row.
    let mut h: Vec<(i64, i64, bool)> = e
        .history
        .iter()
        .map(|i| {
            (
                back(i.times.last_modification),
                val(i.value("Password")),
                origin::private_item(i),
            )
        })
        .collect();
    h.sort();
    let hs: Vec<String> = h
        .iter()
        .map(|(m, v, p)| format!("{m}/{v}{}", if *p { "!" } else { "" }))
        .collect();
    out.insert(
        nameof(e.uuid),
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            nameof(e.uuid),
            par,
            e.previous_parent.map_or("-".to_owned(), nameof),
            back(e.times.location_changed),
            back(e.times.last_modification),
            val(e.value("Password")),
            hs.join(","),
            own(&e.custom_data)
        ),
    );
}

fn walk_dig(g: &Group, out: &mut BTreeMap<String, String>) {
    for e in &g.entries {
        entry_row(e, &nameof(g.uuid), out);
    }
    for c in &g.groups {
        if c.uuid == idof("O") {
            out.insert(
                nameof(c.uuid),
                format!(
                    "{}:{}:{}:{}:{}:{}::{}",
                    nameof(c.uuid),
                    nameof(g.uuid),
                    c.previous_parent.map_or("-".to_owned(), nameof),
                    back(c.times.location_changed),
                    back(c.times.last_modification),
                    val(&c.notes),
                    own(&c.custom_data)
                ),
            );
        }
        walk_dig(c, out);
    }
}

/// One import, by the door the session uses, with what it told (MOD-11.26). A record of
/// an object added and erased again in one import is told as MOD-11.24 says, so a state
/// that does not change may carry that pair and nothing else real.
fn import(
    v: &mut Vault,
    a: usize,
    g: larsal_model::Uuid,
    c: &Vault,
    now: larsal_model::Time,
    said: &mut String,
) -> (usize, bool, bool) {
    let mut twin = v.duplicate();
    let o = Options {
        target_start: Some(g),
        ..Options::new(Kind::SharedImport)
    };
    let m = merge(&mut twin, c, &o, now).expect("import");
    let got = run::merge_into(v, g, c, now).expect("import");
    let pair = |x: &larsal_core::merge::Change| {
        x.id.is_some_and(|id| {
            let (mut added, mut gone) = (false, false);
            for y in &m.changes {
                if y.id == Some(id) && y.object == x.object {
                    added |= y.kind == ChangeKind::Added;
                    gone |= y.kind == ChangeKind::Deleted;
                }
            }
            added && gone
        })
    };
    let real = m
        .changes
        .iter()
        .any(|x| x.kind != ChangeKind::Conflict && !pair(x));
    for x in &m.changes {
        said.push_str(&x.line());
    }
    (a, got.changed, real)
}

fn dig(v: &Vault) -> String {
    let mut m = BTreeMap::new();
    walk_dig(&v.root, &mut m);
    let objs: Vec<String> = m.into_values().collect();
    let mut recs: Vec<(String, i64)> = v
        .deleted_objects
        .iter()
        .map(|d| (nameof(d.uuid), back(d.deleted_at)))
        .collect();
    recs.sort();
    let rs: Vec<String> = recs.iter().map(|(i, t)| format!("{i}/{t}")).collect();
    let mut sc: Vec<(String, String, i64)> = origin::read_rows(&v.meta.custom_data)
        .into_iter()
        .map(|((i, g), t)| (nameof(i), nameof(g), back(t)))
        .collect();
    sc.sort();
    let sc: Vec<String> = sc.iter().map(|(i, g, t)| format!("{i}/{g}/{t}")).collect();
    format!("{}|{}|{}", objs.join(";"), rs.join(","), sc.join(","))
}

fn untag(g: &mut Group) {
    for e in &mut g.entries {
        for h in &mut e.history {
            h.custom_data.items.retain(|i| i.key != origin::PRIVATE);
        }
    }
    for c in &mut g.groups {
        untag(c);
    }
}

fn del_good(v: &mut Vault, id: Uuid, group: bool, now: Time) {
    let was = v.meta.recycle_bin_enabled;
    v.meta.recycle_bin_enabled = false;
    if group {
        recycle::delete_group(v, id, now).expect("delete group");
    } else {
        recycle::delete_entries(v, &[id], now, |_, _| References::Delete).expect("delete entries");
    }
    v.meta.recycle_bin_enabled = was;
}

fn edit_val(v: &mut Vault, x: &str, nv: i64, now: Time) {
    if isg(x) {
        edit::edit_group(v, idof(x), now, |d| d.notes = format!("v{nv}")).expect("edit group");
    } else {
        edit::edit_entry(v, idof(x), now, |d| set_pw(d, nv)).expect("edit entry");
    }
}

fn move_to(v: &mut Vault, x: &str, to: &str, now: Time) {
    if isg(x) {
        edit::move_group(v, idof(x), idof(to), Position::End, now).expect("move group");
    } else {
        edit::move_entries(v, &[idof(x)], idof(to), now).expect("move entry");
    }
}

fn find_e<'a>(v: &'a Vault, x: &str) -> &'a Entry {
    v.root
        .all_entries()
        .find(|e| e.uuid == idof(x))
        .expect("entry")
}

/// Builds the container a member made from the model's listing.
fn hostile(share: &str, lines: &[String]) -> Vault {
    let mut c = Vault::new(Group::new(idof(share), "C".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    for l in lines {
        let p: Vec<&str> = l.split_whitespace().collect();
        if p[0] == "D" {
            c.deleted_objects.push(DeletedObject {
                uuid: idof(p[1]),
                deleted_at: at(p[2].parse().unwrap()),
                unknown: Vec::new(),
            });
        }
    }
    // Groups first, parents before children.
    for l in lines {
        let p: Vec<&str> = l.split_whitespace().collect();
        if p[0] == "C" && isg(p[1]) {
            let (loc, md): (i64, i64) = (p[4].parse().unwrap(), p[5].parse().unwrap());
            let mut g = Group::new(idof(p[1]), p[1].into(), T0);
            g.notes = format!("v{}", p[6]);
            g.times.location_changed = at(loc);
            g.times.last_modification = at(md);
            g.previous_parent = Some(idof(p[3]));
            if p[2] == "S" && share != "S" && gm(&mut c.root, idof("S")).is_none() {
                gm(&mut c.root, idof(share))
                    .unwrap()
                    .groups
                    .push(Group::new(idof("S"), "S".into(), T0));
            }
            gm(&mut c.root, idof(p[2])).unwrap().groups.push(g);
        }
    }
    for l in lines {
        let p: Vec<&str> = l.split_whitespace().collect();
        if p[0] == "C" && !isg(p[1]) {
            let (loc, md): (i64, i64) = (p[4].parse().unwrap(), p[5].parse().unwrap());
            let mut e = Entry::new(idof(p[1]), T0);
            set_pw(&mut e, p[6].parse().unwrap());
            e.times.location_changed = at(loc);
            e.times.last_modification = at(md);
            e.previous_parent = Some(idof(p[3]));
            if p.len() > 7 {
                for item in p[7].split(',') {
                    let (m, v) = item.split_once('/').unwrap();
                    let mut h = Entry::new(idof(p[1]), T0);
                    set_pw(&mut h, v.parse().unwrap());
                    h.times.last_modification = at(m.parse().unwrap());
                    e.history.push(h);
                }
            }
            if p[2] == "S" && share != "S" && gm(&mut c.root, idof("S")).is_none() {
                gm(&mut c.root, idof(share))
                    .unwrap()
                    .groups
                    .push(Group::new(idof("S"), "S".into(), T0));
            }
            gm(&mut c.root, idof(p[2])).unwrap().entries.push(e);
        }
    }
    c
}

#[test]
fn the_models_traces_replay_step_by_step() {
    if let (Ok(input), Ok(output)) = (std::env::var("MDL_IN"), std::env::var("MDL_OUT")) {
        let text = std::fs::read_to_string(input).unwrap();
        run(&text, &mut std::fs::File::create(output).unwrap());
        return;
    }
    let mut got = Vec::new();
    run(include_str!("r6_replay/traces.in"), &mut got);
    let got = String::from_utf8(got).unwrap();
    let want = include_str!("r6_replay/traces.want");
    for (g, w) in got.lines().zip(want.lines()) {
        assert_eq!(g, w, "the line starts with the trace and the step");
    }
    assert_eq!(got.lines().count(), want.lines().count());
}

fn run(text: &str, file: &mut dyn std::io::Write) {
    let mut out = String::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    let mut copies: Vec<Vault> = Vec::new();
    let mut files: BTreeMap<String, Vault> = BTreeMap::new();
    let mut tr = String::new();
    let mut step = 0;
    let mut kind = 0usize;
    while i < lines.len() {
        let p: Vec<&str> = lines[i].split_whitespace().collect();
        i += 1;
        if p.is_empty() {
            continue;
        }
        match p[0] {
            "TRACE" => {
                tr = p[1].to_owned();
                step = 0;
                kind = p[3].parse().unwrap();
                let shares: Vec<String> = if p.get(4).is_none_or(|x| *x == "-") {
                    Vec::new()
                } else {
                    p[4].split(',').map(str::to_owned).collect()
                };
                copies = (0..p[2].parse::<usize>().unwrap())
                    .map(|_| world(&shares))
                    .collect();
                files.clear();
            }
            "OBJ" => {
                let k: usize = p[1].parse().unwrap();
                let (x, par, loc, md, v): (&str, &str, i64, i64, i64) = (
                    p[2],
                    p[3],
                    p[4].parse().unwrap(),
                    p[5].parse().unwrap(),
                    p[6].parse().unwrap(),
                );
                if isg(x) {
                    let mut g = Group::new(idof(x), x.into(), T0);
                    g.notes = format!("v{v}");
                    g.times.location_changed = at(loc);
                    g.times.last_modification = at(md);
                    gm(&mut copies[k].root, idof(par)).unwrap().groups.push(g);
                } else {
                    let mut e = Entry::new(idof(x), T0);
                    set_pw(&mut e, v);
                    e.times.location_changed = at(loc);
                    e.times.last_modification = at(md);
                    gm(&mut copies[k].root, idof(par)).unwrap().entries.push(e);
                }
            }
            "KNOWN" => {
                let k: usize = p[1].parse().unwrap();
                let known: origin::Set = p[2].split(',').map(idof).collect();
                origin::write_known(&mut copies[k].meta.custom_data, &known);
            }
            "GO" => {
                let d: Vec<String> = copies.iter().map(dig).collect();
                writeln!(out, "{tr} {step} {}", d.join(" ## ")).unwrap();
                file.write_all(out.as_bytes()).unwrap();
                out.clear();
            }
            "OP" => {
                step += 1;
                let op = p[1];
                let with_known =
                    |v: &Vault| format!("{} {:?}", dig(v), origin::read_known(&v.meta.custom_data));
                let before: Vec<String> = copies.iter().map(with_known).collect();
                let mut said: Option<(usize, bool, bool)> = None;
                let mut lines_said = String::new();
                match op {
                    "merge" => {
                        let (a, b): (usize, usize) = (p[2].parse().unwrap(), p[3].parse().unwrap());
                        let s = copies[b].duplicate();
                        let m = merge(
                            &mut copies[a],
                            &s,
                            &Options::new(KINDS[kind]),
                            at(p[4].parse().unwrap()),
                        )
                        .expect("merge");
                        for c in &m.changes {
                            lines_said.push_str(&c.line());
                        }
                        said = Some((
                            a,
                            !m.changes.is_empty(),
                            m.changes.iter().any(|c| c.kind != ChangeKind::Conflict),
                        ));
                    }
                    "him" => {
                        let a: usize = p[2].parse().unwrap();
                        let (s, now) = (p[3], at(p[4].parse().unwrap()));
                        let mut body = Vec::new();
                        while lines[i] != "GO2" {
                            body.push(lines[i].to_owned());
                            i += 1;
                        }
                        i += 1;
                        let c = hostile(s, &body);
                        said = Some(import(&mut copies[a], a, idof(s), &c, now, &mut lines_said));
                    }
                    "fex" => {
                        let a: usize = p[2].parse().unwrap();
                        let s = p[3];
                        let mut c =
                            container::build(idof(s), true, &copies[a], at(p[4].parse().unwrap()))
                                .expect("build");
                        c.meta.recycle_bin_enabled = false;
                        files.insert(s.to_owned(), c);
                    }
                    "fim" => {
                        let a: usize = p[2].parse().unwrap();
                        let s = p[3];
                        let c = files[s].duplicate();
                        said = Some(import(
                            &mut copies[a],
                            a,
                            idof(s),
                            &c,
                            at(p[4].parse().unwrap()),
                            &mut lines_said,
                        ));
                    }
                    "med" => {
                        let f = files.get_mut(p[2]).unwrap();
                        edit_val(f, p[3], p[5].parse().unwrap(), at(p[4].parse().unwrap()));
                    }
                    "mmv" => {
                        let f = files.get_mut(p[2]).unwrap();
                        move_to(f, p[3], p[4], at(p[5].parse().unwrap()));
                    }
                    "mdl" => {
                        let f = files.get_mut(p[2]).unwrap();
                        del_good(f, idof(p[3]), isg(p[3]), at(p[4].parse().unwrap()));
                    }
                    "edit" => {
                        let a: usize = p[2].parse().unwrap();
                        edit_val(
                            &mut copies[a],
                            p[3],
                            p[5].parse().unwrap(),
                            at(p[4].parse().unwrap()),
                        );
                    }
                    "move" => {
                        let a: usize = p[2].parse().unwrap();
                        move_to(&mut copies[a], p[3], p[4], at(p[5].parse().unwrap()));
                    }
                    "bin" => {
                        let a: usize = p[2].parse().unwrap();
                        let now = at(p[4].parse().unwrap());
                        if isg(p[3]) {
                            recycle::delete_group(&mut copies[a], idof(p[3]), now)
                                .expect("bin group");
                        } else {
                            recycle::delete_entries(&mut copies[a], &[idof(p[3])], now, |_, _| {
                                References::Delete
                            })
                            .expect("bin");
                        }
                    }
                    "rest" => {
                        let a: usize = p[2].parse().unwrap();
                        let now = at(p[4].parse().unwrap());
                        if isg(p[3]) {
                            recycle::restore_group(&mut copies[a], idof(p[3]), now)
                                .expect("restore group");
                        } else {
                            recycle::restore_entries(&mut copies[a], &[idof(p[3])], now)
                                .expect("restore");
                        }
                    }
                    "rver" => {
                        let a: usize = p[2].parse().unwrap();
                        let (m, v): (i64, i64) = (p[4].parse().unwrap(), p[5].parse().unwrap());
                        let now = at(p[6].parse().unwrap());
                        let e = find_e(&copies[a], p[3]);
                        let item = e
                            .history
                            .iter()
                            .find(|h| {
                                back(h.times.last_modification) == m
                                    && val(h.value("Password")) == v
                            })
                            .expect("item")
                            .duplicate(false);
                        edit::edit_entry(&mut copies[a], idof(p[3]), now, |d| {
                            history::restore_into(d, &item)
                        })
                        .expect("rver");
                    }
                    "forget" => {
                        let a: usize = p[2].parse().unwrap();
                        origin::write_rows(&mut copies[a].meta.custom_data, &origin::Rows::new());
                    }
                    "strip" => {
                        // Another app's save: what only this app keeps goes. The list stays
                        // here as the model's does: the shares' items still name them. It
                        // keeps a history item and drops its custom data, the tag with it.
                        let a: usize = p[2].parse().unwrap();
                        let known = origin::known(&copies[a]);
                        untag(&mut copies[a].root);
                        origin::strip(&mut copies[a]);
                        origin::write_known(&mut copies[a].meta.custom_data, &known);
                    }
                    "del" => {
                        let a: usize = p[2].parse().unwrap();
                        del_good(
                            &mut copies[a],
                            idof(p[3]),
                            isg(p[3]),
                            at(p[4].parse().unwrap()),
                        );
                    }
                    "empty" => {
                        let a: usize = p[2].parse().unwrap();
                        recycle::empty_bin(&mut copies[a], at(p[3].parse().unwrap()))
                            .expect("empty");
                    }
                    other => panic!("op {other}"),
                }
                let d: Vec<String> = copies.iter().map(dig).collect();
                let fs: Vec<String> = files
                    .iter()
                    .map(|(k, f)| format!("{k}={}", dig(f)))
                    .collect();
                // MOD-11.26: a change has a record; no state change has no record but a Conflict.
                let bad = said.is_some_and(|(a, any, real)| {
                    // An import's write of the known list alone is silent: the id is on the
                    // share item an import needs, and a copy with no change is not kept.
                    let moved = if op == "merge" {
                        before[a] != with_known(&copies[a])
                    } else {
                        before[a].split(" {").next() != with_known(&copies[a]).split(" {").next()
                    };
                    (moved && !any) || (!moved && real)
                });
                let flag = if bad {
                    format!(" !RECORDS {lines_said}")
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "{tr} {step} {} @@ {}{flag}",
                    d.join(" ## "),
                    fs.join(" ## ")
                )
                .unwrap();
                file.write_all(out.as_bytes()).unwrap();
                out.clear();
            }
            other => panic!("line {other}"),
        }
    }
}
