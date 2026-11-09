//! Rule R6 of shared groups (INT-08.32, MOD-11.15, FMT-15.11): a merge in a vault
//! that knows a share. A share never wins by time, and only a user's stamped move
//! brings an object into a share across a merge. When two copies count in
//! different shares, the inside copy wins only if the user moved it in and nothing
//! happened later on the other copy; otherwise the outside copy wins.
//!
//! One function in both directions, all six same-vault kinds: every verdict reads
//! the two copies as they were before the merge, never the walk's work. Larsal's
//! own design, searched by a small model to a bound; proven apps of this kind have
//! no such rule to follow (INT-08.32 says what the search covers and what it does
//! not).
//!
//! Guarantees: a merge leaves an object in the shares of the copy that won; a
//! share's record reaches only objects that count in that share; and with no share
//! known none of this runs ([`super::Merger::run`]).

use super::{
    ChangeKind, Merger, Move, Moving, Object, Versions, has_unknown, join, later, own_copy,
    own_flag, protect_passwords, same_items, same_version, same_versions,
};
use crate::health::shown_title;
use crate::origin::{self, Places, Rows, Set, Shares, Stamp};
use crate::{Error, recycle};
use larsal_model::custom_data::CustomData;
use larsal_model::{DeletedObject, Entry, Group, Time, Uuid, Vault};
use std::collections::{BTreeSet, HashMap, HashSet};

/// The detail of a whole verdict on an entry: what became of the loser.
const WHOLE_KEPT: &str =
    "a share's edge between the copies: one stays whole, the other's values as private history";
/// The detail of a whole verdict on a group, which has no history.
const WHOLE_DROPPED: &str =
    "a share's edge between the copies: one stays whole, the other's value goes";
/// The detail of a change that is only the rule's own: place, time or stamp.
const OWN: &str = "Origin";

/// An object's parent and previous parent.
type Place = (Uuid, Option<Uuid>);

/// One copy of one object as it was before this merge.
#[derive(Clone)]
struct Seen {
    parent: Uuid,
    prev: Option<Uuid>,
    stamp: Option<Stamp>,
    marked: bool,
    loc: Time,
    modified: Time,
    /// `Later`: the largest of Loc, Mod and any history item's time.
    last: Time,
}

impl Seen {
    fn of_entry(e: &Entry, parent: Uuid) -> Self {
        let rows = e.history.iter().map(|h| h.times.last_modification).max();
        Self {
            last: later(&e.times).max(rows.unwrap_or(Time(i64::MIN))),
            ..Self::of(&e.custom_data, &e.times, parent, e.previous_parent)
        }
    }

    fn of_group(g: &Group, parent: Uuid) -> Self {
        Self::of(&g.custom_data, &g.times, parent, g.previous_parent)
    }

    fn of(data: &CustomData, t: &larsal_model::Times, parent: Uuid, prev: Option<Uuid>) -> Self {
        Self {
            parent,
            prev,
            stamp: origin::stamp_of(data),
            marked: origin::brought(data),
            loc: t.location_changed,
            modified: t.last_modification,
            last: later(t),
        }
    }

    fn place(&self) -> Place {
        (self.parent, self.prev)
    }

    /// True when the rule's own part of the two differs.
    fn differs(&self, o: &Self) -> bool {
        (self.parent, self.prev, self.loc, self.stamp, self.marked)
            != (o.parent, o.prev, o.loc, o.stamp, o.marked)
    }
}

/// One copy of the vault as it was before this merge. Dead copies leave `entries`.
struct Before {
    places: Places,
    entries: HashMap<Uuid, Seen>,
    groups: HashMap<Uuid, Seen>,
}

impl Before {
    /// `like`: a tree of the same merge, whose sets this one shares.
    fn new(v: &Vault, known: Set, like: Option<&Places>) -> Self {
        let (mut entries, mut groups) = (HashMap::new(), HashMap::new());
        let mut stack = vec![&v.root];
        while let Some(g) = stack.pop() {
            for e in &g.entries {
                entries
                    .entry(e.uuid)
                    .or_insert_with(|| Seen::of_entry(e, g.uuid));
            }
            for c in &g.groups {
                groups
                    .entry(c.uuid)
                    .or_insert_with(|| Seen::of_group(c, g.uuid));
                stack.push(c);
            }
        }
        Self {
            places: match like {
                Some(p) => Places::sharing(v, known, p),
                None => Places::new(v, known),
            },
            entries,
            groups,
        }
    }

    /// True when this copy counts in a share or a share brought it.
    fn counts(&mut self, c: &Seen) -> bool {
        c.marked || !self.places.shares_at(c.parent, c.prev, None).is_empty()
    }
}

/// Either copy's latest stamp of each object, before the merge. One map per kind,
/// since an entry may share a group's id (MOD-11.22).
#[derive(Default)]
struct Stamps {
    entries: HashMap<Uuid, Time>,
    groups: HashMap<Uuid, Time>,
}

impl Stamps {
    fn add(&mut self, b: &Before) {
        let one = |to: &mut HashMap<Uuid, Time>, from: &HashMap<Uuid, Seen>| {
            for (id, c) in from {
                if let Some(s) = c.stamp {
                    let at = to.entry(*id).or_insert(s.at);
                    *at = (*at).max(s.at);
                }
            }
        };
        one(&mut self.entries, &b.entries);
        one(&mut self.groups, &b.groups);
    }
}

/// Who wins, from the two copies as they were (R6 E3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// One set: an ordinary merge. Each side keeps what it keeps today.
    Ordinary,
    /// That inside copy holds a user's stamp not older than the other copy.
    InTarget,
    InSource,
    /// That copy wins whole: the outside copy, when the other has no valid stamp.
    WholeTarget,
    WholeSource,
}

impl Verdict {
    fn target_wins(self) -> bool {
        matches!(self, Self::InTarget | Self::WholeTarget)
    }

    fn source_wins(self) -> bool {
        matches!(self, Self::InSource | Self::WholeSource)
    }
}

/// The verdict of one object with two copies.
struct Judged {
    verdict: Verdict,
    /// The sets of the target's and the source's copy.
    a: Shares,
    b: Shares,
}

impl Judged {
    /// The set the object must end with: the winner's.
    fn want(&self) -> Shares {
        if self.verdict.source_wins() {
            self.b
        } else {
            self.a
        }
    }
}

fn judge(me: Option<Uuid>, tc: &Seen, sc: &Seen, bt: &mut Before, bs: &mut Before) -> Judged {
    let a = bt.places.shares_at(tc.parent, tc.prev, me);
    let b = bs.places.shares_at(sc.parent, sc.prev, me);
    if a == b {
        let verdict = match (a.is_empty(), tc.marked, sc.marked) {
            (true, true, false) => Verdict::WholeSource,
            (true, false, true) => Verdict::WholeTarget,
            _ => Verdict::Ordinary,
        };
        return Judged { verdict, a, b };
    }
    let (sa, sb) = (bt.places.set_of(a), bs.places.set_of(b));
    let dt: Set = sa.difference(&sb).copied().collect();
    let ds: Set = sb.difference(&sa).copied().collect();
    let valid = |places: &mut Places, own: &Seen, other: &Seen, diff: &Set| {
        places.covers(own.stamp, diff)
            && !(own.marked && !other.marked)
            && own.stamp.is_some_and(|s| s.at >= other.last)
    };
    let tv = !dt.is_empty() && valid(&mut bt.places, tc, sc, &dt);
    let sv = !ds.is_empty() && valid(&mut bs.places, sc, tc, &ds);
    let verdict = if dt.is_empty() {
        if sv {
            Verdict::InSource
        } else {
            Verdict::WholeTarget
        }
    } else if ds.is_empty() {
        if tv {
            Verdict::InTarget
        } else {
            Verdict::WholeSource
        }
    } else {
        let (low_t, low_s) = (dt.first().copied(), ds.first().copied());
        match (tv, sv) {
            (true, false) => Verdict::InTarget,
            (false, true) => Verdict::InSource,
            (true, true) => {
                let time = |s: &Seen| s.stamp.map(|x| x.at);
                if (time(tc), low_t) > (time(sc), low_s) {
                    Verdict::InTarget
                } else {
                    Verdict::InSource
                }
            }
            // Neither: the lowest group id among the differences.
            (false, false) => {
                if low_t < low_s {
                    Verdict::WholeTarget
                } else {
                    Verdict::WholeSource
                }
            }
        }
    };
    Judged { verdict, a, b }
}

/// R6 E3, a whole win: the winner's history, and each value of the loser it does not
/// hold as a private item (INT-08.32), older versions too, so nothing joins a share's
/// history and nothing is lost but by pruning, or a version at the custom data item
/// limit that cannot take the tag. `None` when the history stays.
fn whole_history(
    winner: &Entry,
    loser: &Entry,
    max_items: i32,
    max_size: i32,
) -> Option<Vec<Entry>> {
    let private = |x: &Entry| {
        let mut x = x.duplicate(false);
        origin::make_private(&mut x).then_some(x)
    };
    let holds = Versions::new(&winner.history);
    let lost: Vec<Entry> = loser
        .history
        .iter()
        .filter(|h| !same_version(h, winner) && (origin::private_item(h) || !holds.holds(h)))
        .filter_map(private)
        .collect();
    // The loser's current version at the limit stays out: as the winner's own version
    // it adds nothing to the join.
    let mut current = private(loser).unwrap_or_else(|| winner.duplicate(false));
    current.uuid = winner.uuid;
    join(
        &winner.history,
        &lost,
        &current,
        winner,
        &winner.history,
        max_items,
        max_size,
    )
}

/// The later stamp; between equal times the higher group id.
fn stamp_max(a: Option<Stamp>, b: Option<Stamp>) -> Option<Stamp> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(if (x.at, x.group) >= (y.at, y.group) {
            x
        } else {
            y
        }),
    }
}

/// `data` takes the stamp, and loses the marker unless `marked`.
fn settle(data: &mut CustomData, stamp: Option<Stamp>, marked: bool) {
    if origin::stamp_of(data) != stamp {
        origin::set_stamp(data, stamp);
    }
    if !marked {
        origin::clear_mark(data);
    }
}

/// R6 E6: outside there is no stamp; it names a share the object counts in.
fn norm_stamp(data: &mut CustomData, merged: &mut Places, place: Place, me: Option<Uuid>) {
    let Some(s) = origin::stamp_of(data) else {
        return;
    };
    let set = merged.shares_at(place.0, place.1, me);
    if set.is_empty() {
        origin::set_stamp(data, None);
    } else if !merged.holds(set, s.group) {
        let group = merged.innermost(&merged.set_of(set)).unwrap_or(s.group);
        origin::set_stamp(data, Some(Stamp { group, ..s }));
    }
}

/// True when an object fits at `place`: it would end with `want`, with no cycle.
fn fits(merged: &mut Places, place: Place, me: Option<Uuid>, want: Shares) -> bool {
    merged.shares_at(place.0, place.1, me) == want && me.is_none_or(|x| !merged.within(place.0, x))
}

/// No place of either copy fits: the innermost share of `want`, or when none is
/// left the nearest group on the copy's own way up that adds no share. A bin item
/// stays in the bin, naming that group (R6 E4).
fn fallback(merged: &mut Places, own: &Before, x: &Seen, me: Option<Uuid>, want: Shares) -> Place {
    let want = merged.set_of(want);
    let live: Set = want
        .iter()
        .copied()
        .filter(|g| merged.has(*g) && me.is_none_or(|m| !merged.within(*g, m)))
        .collect();
    if let Some(g) = merged.innermost(&live) {
        return (g, None);
    }
    let bin = own.places.bin;
    let root = merged.root;
    let binned = Some(x.parent) == bin;
    let home = merged.bin.or(bin).filter(|b| merged.has(*b));
    let done = |g: Uuid| match (binned, home) {
        (true, Some(b)) => (b, Some(g)),
        _ => (g, Some(x.parent)),
    };
    let (mut at, mut prev) = if binned {
        (x.prev, None)
    } else {
        (Some(x.parent), x.prev)
    };
    for _ in 0..own.places.bound() {
        let Some(g) = at else {
            break;
        };
        if Some(g) == bin {
            (at, prev) = (prev, None);
            continue;
        }
        if g == own.places.root {
            break;
        }
        let safe = merged.has(g)
            && merged.set_at(g, None, None).is_subset(&want)
            && me.is_none_or(|m| !merged.within(g, m));
        if safe {
            return done(g);
        }
        (at, prev) = own
            .places
            .place_of(g)
            .map_or((None, None), |(p, q)| (Some(p), q));
    }
    done(root)
}

/// An object only one copy holds, at `place` on the merged tree: no share entered
/// or left by a merge.
fn one_side(
    merged: &mut Places,
    own: &Before,
    x: &Seen,
    me: Option<Uuid>,
    place: Place,
    want: Shares,
) -> Place {
    if merged.shares_at(place.0, place.1, me) == want {
        place
    } else {
        fallback(merged, own, x, me, want)
    }
}

/// R6 E4: the place of an object with two copies: it ends with the winner's set.
fn choose_place(
    merged: &mut Places,
    (own, x): (&Before, &Seen),
    me: Option<Uuid>,
    v: Verdict,
    (tp, sp): (Place, Place),
    (tloc, sloc): (Time, Time),
    want: Shares,
) -> Place {
    let ok_t = fits(merged, tp, me, want);
    let ok_s = fits(merged, sp, me, want);
    if v.target_wins() && ok_t {
        return tp;
    }
    if v.source_wins() && ok_s {
        return sp;
    }
    match (ok_t, ok_s) {
        (true, true) => {
            let target = if tp.0 == sp.0 {
                tloc >= sloc
            } else if tloc != sloc {
                tloc > sloc
            } else {
                tp.0 < sp.0
            };
            if target { tp } else { sp }
        }
        (true, false) => tp,
        (false, true) => sp,
        (false, false) => fallback(merged, own, x, me, want),
    }
}

/// What the merge works from.
struct Shared {
    bt: Before,
    bs: Before,
    merged: Places,
    /// Each group's wanted set and whether that is its source copy's.
    wants: HashMap<Uuid, (Shares, bool)>,
    /// Each source group's group on the merged tree (the bins map, MOD-11.16).
    map: HashMap<Uuid, Uuid>,
    erased: bool,
}

/// The deletion pass's records.
struct Pass<'a> {
    merged: &'a mut Places,
    stamps: &'a Stamps,
    source_times: HashMap<Uuid, Time>,
    source_group_times: HashMap<Uuid, Time>,
    plain: HashMap<Uuid, Time>,
    rows: Rows,
    /// Plain records that go: their object stays and counts nowhere. An id on a
    /// kept and an erased object stays on the list.
    beaten: HashSet<Uuid>,
    needed: HashSet<Uuid>,
    erased: bool,
    quiet_entries: HashSet<Uuid>,
    quiet_groups: HashSet<Uuid>,
    /// Each erased group, and what a bin item that named it now names.
    renamed: HashMap<Uuid, Option<Uuid>>,
}

impl Pass<'_> {
    /// `true` when the object goes. It counts in `set`; `time`: its own time, its
    /// stamp's, the source copy's. R6 E7.
    fn goes(
        &mut self,
        id: Uuid,
        set: Shares,
        times: [Option<Time>; 3],
        holds: bool,
        marked: bool,
    ) -> bool {
        let plain = self.plain.get(&id).copied();
        // The object's rows, in group order, that apply: their group is in its set.
        let ends = (id, Uuid([0; 16]))..=(id, Uuid([0xff; 16]));
        let applying: Vec<(Uuid, Time)> = self
            .rows
            .range(ends)
            .filter(|((_, g), _)| self.merged.holds(set, *g))
            .map(|((_, g), at)| (*g, *at))
            .collect();
        let row = applying.iter().map(|(_, at)| *at).max();
        let Some(when) = row.into_iter().chain(plain).max() else {
            return false;
        };
        if !holds && !times.iter().flatten().any(|t| *t > when) {
            self.needed.insert(id);
            self.inner_rows(id, set, &applying);
            return true;
        }
        if plain.is_some() && set.is_empty() && !marked {
            self.beaten.insert(id);
        } else {
            self.needed.insert(id);
        }
        for (g, _) in applying {
            self.rows.remove(&(id, g));
        }
        false
    }

    /// R6 C3: a share's row erased the object, in a merge of any kind, so each share
    /// inside that row's share that the object counted in takes a row too, at that row's
    /// time (the later one if a row is there), as a user's delete writes (INT-08.32):
    /// that share's own export then tells its members, whichever Mac took the row first.
    fn inner_rows(&mut self, id: Uuid, set: Shares, applying: &[(Uuid, Time)]) {
        if applying.is_empty() {
            return;
        }
        let shares = self.merged.set_of(set);
        for (g, at) in self.merged.rows_above(&shares, applying) {
            let row = self.rows.entry((id, g)).or_insert(at);
            *row = (*row).max(at);
        }
    }
}

impl<'s> Merger<'_, 's> {
    /// The shares this merge knows: the target's, a same-vault source's, and the
    /// share group of an import.
    pub(super) fn known_shares(&self) -> Set {
        let mut known = origin::known(self.t);
        if self.same_vault {
            known.extend(origin::known(self.s));
        } else if self.synchronize() {
            known.insert(self.target_start);
        }
        known
    }

    fn write_known(&mut self, known: &Set) {
        if origin::write_known(&mut self.t.meta.custom_data, known) {
            let why = vec!["known shares changed".into()];
            self.record(ChangeKind::Metadata, Object::Vault, "", "", None, why);
        }
    }

    /// R6 C: a share's import: today's walk from the share group, then the pass.
    /// It reads no stamp of the container, which has none, and sets none.
    pub(super) fn shared_import(&mut self, start: &'s Group, known: Set) -> Result<(), Error> {
        let mut stamps = Stamps::default();
        stamps.add(&Before::new(self.t, Set::new(), None));
        self.walk(start, self.target_start)?;
        self.retry_moves();
        let mut merged = Places::new(self.t, known.clone());
        self.shared_pass(&mut merged, &stamps, false);
        // No record of its own: the group holds its share item, so a copy that does
        // not save this still knows the share.
        origin::write_known(&mut self.t.meta.custom_data, &known);
        Ok(())
    }

    /// R6 E: a same-vault merge with a share known.
    pub(super) fn shared_merge(&mut self, start: &'s Group, known: Set) {
        let bt = Before::new(self.t, known.clone(), None);
        let bs = Before::new(self.s, known.clone(), Some(&bt.places));
        let merged = Places::sharing(self.t, known.clone(), &bt.places);
        let mut cx = Shared {
            bt,
            bs,
            merged,
            wants: HashMap::new(),
            map: HashMap::from([(start.uuid, self.target_start)]),
            erased: false,
        };
        self.dead_copies(&mut cx);
        let mut stamps = Stamps::default();
        stamps.add(&cx.bt);
        stamps.add(&cx.bs);
        self.shared_groups(start, self.target_start, &mut cx);
        self.retry_moves();
        cx.merged = Places::sharing(self.t, known.clone(), &cx.bt.places);
        self.check_groups(&mut cx);
        self.shared_entries(start, &mut cx);
        let erased = cx.erased;
        self.shared_pass(&mut cx.merged, &stamps, erased);
        self.write_known(&known);
    }

    /// R6 E2: a copy no later than a user's own record, where either copy counts
    /// inside or was brought, is dead: it adds nothing, not even to history.
    fn dead_copies(&mut self, cx: &mut Shared) {
        let mut plain: Vec<(Uuid, Time)> = Vec::new();
        let mut at: HashMap<Uuid, usize> = HashMap::new();
        let lists = [&self.t.deleted_objects, &self.s.deleted_objects];
        for d in lists.into_iter().flatten() {
            let i = *at.entry(d.uuid).or_insert_with(|| {
                plain.push((d.uuid, d.deleted_at));
                plain.len().saturating_sub(1)
            });
            if let Some(p) = plain.get_mut(i) {
                p.1 = p.1.max(d.deleted_at);
            }
        }
        for (id, when) in plain {
            let dead =
                |c: &Seen| c.loc.max(c.modified) <= when && c.stamp.is_none_or(|s| s.at <= when);
            let (tc, sc) = (
                cx.bt.entries.get(&id).cloned(),
                cx.bs.entries.get(&id).cloned(),
            );
            let t_counts = tc.as_ref().is_some_and(|c| cx.bt.counts(c));
            let s_counts = sc.as_ref().is_some_and(|c| cx.bs.counts(c));
            let t_dead = tc.as_ref().is_some_and(dead) && (t_counts || s_counts);
            if t_dead {
                cx.bt.entries.remove(&id);
                self.erase_entry(id);
                cx.erased = true;
            }
            let t_left = t_counts && !t_dead;
            if sc.as_ref().is_some_and(dead) && (t_left || s_counts) {
                cx.bs.entries.remove(&id);
            }
        }
    }

    /// R6 E3, groups, parents first: the merged tree of groups.
    fn shared_groups(&mut self, sg: &'s Group, tg: Uuid, cx: &mut Shared) {
        for c in &sg.groups {
            if let Some(next) = self.shared_group(c, tg, cx) {
                cx.map.insert(c.uuid, next);
                self.shared_groups(c, next, cx);
            }
        }
    }

    fn shared_group(&mut self, c: &'s Group, parent: Uuid, cx: &mut Shared) -> Option<Uuid> {
        let id = c.uuid;
        if id == self.ix.root {
            return Some(id);
        }
        let sc = cx.bs.groups.get(&id)?.clone();
        let Some(tc) = cx.bt.groups.get(&id).cloned() else {
            return self.new_group(c, parent, &sc, cx);
        };
        let judged = judge(Some(id), &tc, &sc, &mut cx.bt, &mut cx.bs);
        let want = judged.want();
        let v = judged.verdict;
        let count = self.changes.len();
        let stamp = stamp_max(tc.stamp, sc.stamp);
        let marked = tc.marked && sc.marked;
        let places = (tc.place(), (parent, sc.prev));
        let locs = (tc.loc, sc.loc);
        let who = if v.source_wins() {
            (&cx.bs, &sc)
        } else {
            (&cx.bt, &tc)
        };
        if v == Verdict::Ordinary && want.is_empty() {
            self.source_group_times.insert(id, later(&c.times));
            let wanted = Move {
                id,
                parent,
                loc: sc.loc,
                force: tc.loc == sc.loc && parent < tc.parent,
            };
            match self.try_move(&wanted) {
                Moving::Moved => cx.merged.set_place(id, parent, Some(tc.parent)),
                Moving::Cycle => self.deferred.push(wanted),
                Moving::Stays => {}
            }
            self.group_fields(c, id);
            self.settle_group(id, stamp, marked);
            let now_at = cx.merged.place_of(id).unwrap_or(tc.place());
            if cx.merged.shares_at(now_at.0, now_at.1, Some(id)) != want {
                let p = choose_place(&mut cx.merged, who, Some(id), v, places, locs, want);
                let loc = self.group_loc(id, sc.loc);
                self.put_group(&mut cx.merged, id, p, loc);
            }
        } else {
            let p = choose_place(&mut cx.merged, who, Some(id), v, places, locs, want);
            let loc = match v {
                Verdict::WholeTarget => tc.loc,
                Verdict::WholeSource => {
                    self.group_take(c, id);
                    self.group_data_from(c, id);
                    sc.loc
                }
                _ => {
                    self.source_group_times.insert(id, later(&c.times));
                    self.group_fields(c, id);
                    self.settle_group(id, stamp, marked);
                    tc.loc.max(sc.loc)
                }
            };
            self.put_group(&mut cx.merged, id, p, loc);
        }
        self.finish_group(id, &tc, count, v, &mut cx.merged);
        cx.wants.insert(id, (want, v.source_wins()));
        Some(id)
    }

    /// A group only the source holds.
    fn new_group(
        &mut self,
        c: &'s Group,
        parent: Uuid,
        sc: &Seen,
        cx: &mut Shared,
    ) -> Option<Uuid> {
        let id = c.uuid;
        if let Some(bin) = self.map_bin(c) {
            if cx.merged.bin != Some(bin) {
                cx.merged.set_place(bin, self.ix.root, None);
                cx.merged.set_bin(bin);
            }
            return Some(bin);
        }
        let want = cx.bs.places.shares_at(sc.parent, sc.prev, Some(id));
        let p = one_side(
            &mut cx.merged,
            &cx.bs,
            sc,
            Some(id),
            (parent, sc.prev),
            want,
        );
        let mut own = own_copy(c);
        own.previous_parent = p.1;
        if !self.push_group(p.0, own) {
            return None;
        }
        cx.merged.set_place(id, p.0, p.1);
        self.added_groups.insert(id);
        self.raise_version(!c.unknown.is_empty() || !c.times.unknown.is_empty());
        let path = self.path_of(id);
        let why = vec![format!("{} entries", c.entries.len())];
        self.record(ChangeKind::Added, Object::Group, &path, "", Some(id), why);
        cx.wants.insert(id, (want, true));
        Some(id)
    }

    fn group_loc(&self, id: Uuid, or: Time) -> Time {
        self.ix
            .group(&self.t.root, id)
            .map_or(or, |g| g.times.location_changed)
    }

    /// A whole win of the source's copy: its stamp, marker, times and unknown parts
    /// come with it. The caller sets Loc.
    fn group_data_from(&mut self, c: &Group, id: Uuid) {
        if let Some(g) = self.ix.group_mut(&mut self.t.root, id) {
            origin::keep_own(&c.custom_data, &mut g.custom_data);
            g.times = c.times.clone();
            g.unknown.clone_from(&c.unknown);
        }
        self.raise_version(!c.unknown.is_empty() || !c.times.unknown.is_empty());
    }

    fn settle_group(&mut self, id: Uuid, stamp: Option<Stamp>, marked: bool) {
        if let Some(g) = self.ix.group_mut(&mut self.t.root, id) {
            settle(&mut g.custom_data, stamp, marked);
        }
    }

    /// Puts matched group `id` at `place`, with Loc `loc`. It never makes a cycle:
    /// the place was checked on the merged tree.
    fn put_group(&mut self, merged: &mut Places, id: Uuid, place: Place, loc: Time) {
        let (parent, prev) = place;
        if merged.place_of(id).is_some_and(|(old, _)| old != parent) {
            let wanted = Move {
                id,
                parent,
                loc,
                force: true,
            };
            if self.try_move(&wanted) != Moving::Moved {
                return;
            }
        }
        if let Some(g) = self.ix.group_mut(&mut self.t.root, id) {
            g.previous_parent = prev;
            g.times.location_changed = loc;
        }
        merged.set_place(id, parent, prev);
    }

    /// A merge tries today's move, then the rule may put the object elsewhere: the
    /// records say one move from where it was, none when it is back there.
    fn one_move(&mut self, count: usize, back: bool) {
        let mut tail = self.changes.split_off(count);
        let moved = |c: &super::Change| c.kind == ChangeKind::Moved;
        let from = tail.iter().find(|c| moved(c)).map(|c| c.details.clone());
        if let (Some(from), Some(last)) = (from, tail.iter().rposition(moved)) {
            let mut i = 0usize;
            tail.retain_mut(|c| {
                let here = i;
                i = i.saturating_add(1);
                if !moved(c) {
                    return true;
                }
                c.details.clone_from(&from);
                here == last && !back
            });
        }
        self.changes.append(&mut tail);
    }

    /// The stamp's normal form, and the record: every change has one (MOD-11.26).
    fn finish_group(&mut self, id: Uuid, tc: &Seen, count: usize, v: Verdict, merged: &mut Places) {
        let at = merged.place_of(id).unwrap_or(tc.place());
        self.one_move(count, at.0 == tc.parent);
        let Some(g) = self.ix.group_mut(&mut self.t.root, id) else {
            return;
        };
        norm_stamp(&mut g.custom_data, merged, at, Some(id));
        let moved = Seen::of_group(g, at.0).differs(tc);
        let recorded = self.changes.len() > count;
        if !moved && !recorded {
            return;
        }
        let whole = matches!(v, Verdict::WholeTarget | Verdict::WholeSource);
        if !whole && recorded {
            return;
        }
        let path = self.path_of(id);
        let (kind, why) = if whole {
            (ChangeKind::Conflict, WHOLE_DROPPED)
        } else {
            (ChangeKind::Modified, OWN)
        };
        self.record(kind, Object::Group, &path, "", Some(id), vec![why.into()]);
    }

    /// R6 E4 for what the walk could not see: a group only the target holds, and a
    /// group whose parent moved after its turn, stay in the shares they wanted.
    fn check_groups(&mut self, cx: &mut Shared) {
        let mut order = Vec::new();
        let mut stack = vec![&self.t.root];
        while let Some(g) = stack.pop() {
            let live = g.groups.iter().filter(|c| c.uuid != Uuid::default());
            order.extend(live.clone().map(|c| c.uuid));
            stack.extend(live.rev());
        }
        for id in order {
            let Some(at) = cx.merged.place_of(id) else {
                continue;
            };
            let target_copy = cx.bt.groups.get(&id).cloned();
            let (want, source) = match cx.wants.get(&id) {
                Some((w, s)) => (*w, *s),
                None => match &target_copy {
                    Some(c) => (cx.bt.places.shares_at(c.parent, c.prev, Some(id)), false),
                    None => continue,
                },
            };
            if cx.merged.shares_at(at.0, at.1, Some(id)) == want {
                continue;
            }
            let (own, x) = if source {
                (&cx.bs, cx.bs.groups.get(&id))
            } else {
                (&cx.bt, target_copy.as_ref())
            };
            let Some(x) = x else {
                continue;
            };
            let p = fallback(&mut cx.merged, own, x, Some(id), want);
            let loc = self.group_loc(id, x.loc);
            let count = self.changes.len();
            self.put_group(&mut cx.merged, id, p, loc);
            if let Some(g) = self.ix.group_mut(&mut self.t.root, id) {
                norm_stamp(&mut g.custom_data, &mut cx.merged, p, Some(id));
            }
            if self.changes.len() == count {
                let path = self.path_of(id);
                let why = vec![OWN.into()];
                self.record(
                    ChangeKind::Modified,
                    Object::Group,
                    &path,
                    "",
                    Some(id),
                    why,
                );
            }
        }
    }

    /// R6 E3, entries: the source's, then those only the target holds.
    fn shared_entries(&mut self, start: &'s Group, cx: &mut Shared) {
        let mut done = HashSet::new();
        let mut stack = vec![start];
        while let Some(sg) = stack.pop() {
            stack.extend(sg.groups.iter().rev());
            let Some(g) = cx.map.get(&sg.uuid).copied() else {
                continue;
            };
            for e in &sg.entries {
                if done.insert(e.uuid) {
                    self.shared_entry(e, g, cx);
                }
            }
        }
        let mut only: Vec<Uuid> = cx
            .bt
            .entries
            .keys()
            .filter(|id| !cx.bs.entries.contains_key(*id))
            .copied()
            .collect();
        only.sort_unstable();
        for id in only {
            let Some(tc) = cx.bt.entries.get(&id).cloned() else {
                continue;
            };
            let want = cx.bt.places.shares_at(tc.parent, tc.prev, None);
            let p = one_side(&mut cx.merged, &cx.bt, &tc, None, tc.place(), want);
            if p != tc.place() {
                self.put_entry(id, p, false);
            }
        }
    }

    fn shared_entry(&mut self, e: &'s Entry, g: Uuid, cx: &mut Shared) {
        let id = e.uuid;
        let Some(sc) = cx.bs.entries.get(&id).cloned() else {
            return;
        };
        let Some(tc) = cx.bt.entries.get(&id).cloned() else {
            self.new_entry(e, g, &sc, cx);
            return;
        };
        let judged = judge(None, &tc, &sc, &mut cx.bt, &mut cx.bs);
        let want = judged.want();
        let v = judged.verdict;
        let places = (tc.place(), (g, sc.prev));
        let locs = (tc.loc, sc.loc);
        let who = if v.source_wins() {
            (&cx.bs, &sc)
        } else {
            (&cx.bt, &tc)
        };
        let stamp = stamp_max(tc.stamp, sc.stamp);
        let marked = tc.marked && sc.marked;
        let flagged = own_flag(e);
        let count = self.changes.len();
        let sib = !judged.a.is_empty() && !judged.b.is_empty();
        let mut touched = false;
        let mut whole = None;
        if v == Verdict::Ordinary && want.is_empty() {
            self.source_times.insert(id, later(&e.times));
            self.entry_move(e, tc.parent, g, true);
            self.entry_conflict(e);
            self.settle_entry(id, stamp, marked);
            let at = self.entry_place(id).unwrap_or(tc.place());
            if cx.merged.shares_at(at.0, at.1, None) != want {
                let p = choose_place(&mut cx.merged, who, None, v, places, locs, want);
                self.put_entry(id, p, flagged);
            }
        } else {
            let p = choose_place(&mut cx.merged, who, None, v, places, locs, want);
            let v = match v {
                Verdict::InTarget if sib => Verdict::WholeTarget,
                Verdict::InSource if sib => Verdict::WholeSource,
                x => x,
            };
            let loc = match v {
                Verdict::WholeTarget => {
                    whole = Some(WHOLE_KEPT);
                    touched = self.keep_whole(e);
                    tc.loc
                }
                Verdict::WholeSource => {
                    whole = Some(WHOLE_KEPT);
                    touched = self.take_whole(e);
                    sc.loc
                }
                _ => {
                    self.source_times.insert(id, later(&e.times));
                    self.entry_conflict(e);
                    self.settle_entry(id, stamp, marked);
                    tc.loc.max(sc.loc)
                }
            };
            self.put_entry(id, p, flagged);
            if let Some(te) = self.ix.entry_mut(&mut self.t.root, id) {
                te.times.location_changed = loc;
            }
        }
        self.finish_entry(e, &tc, count, whole, touched, &mut cx.merged);
    }

    /// An entry only the source holds.
    fn new_entry(&mut self, e: &'s Entry, g: Uuid, sc: &Seen, cx: &mut Shared) {
        let id = e.uuid;
        let want = cx.bs.places.shares_at(sc.parent, sc.prev, None);
        let p = one_side(&mut cx.merged, &cx.bs, sc, None, (g, sc.prev), want);
        let mut copy = e.duplicate(true);
        protect_passwords(&mut copy);
        copy.previous_parent = p.1;
        let Some(to) = self.ix.group_mut(&mut self.t.root, p.0) else {
            return;
        };
        to.entries.push(copy);
        let at = to.entries.len().saturating_sub(1);
        self.ix.epos.insert(id, (p.0, at));
        self.added_entries.insert(id);
        self.raise_version(has_unknown(e));
        let path = self.path_of(p.0);
        let title = shown_title(e, self.mask_titles);
        self.record(
            ChangeKind::Added,
            Object::Entry,
            &path,
            title,
            Some(id),
            Vec::new(),
        );
    }

    fn entry_place(&self, id: Uuid) -> Option<Place> {
        let (g, _) = self.ix.epos.get(&id)?;
        let e = self.ix.entry(&self.t.root, id)?;
        Some((*g, e.previous_parent))
    }

    fn settle_entry(&mut self, id: Uuid, stamp: Option<Stamp>, marked: bool) {
        if let Some(te) = self.ix.entry_mut(&mut self.t.root, id) {
            settle(&mut te.custom_data, stamp, marked);
        }
    }

    /// A whole win of the target's copy: the loser's values stay as private items.
    /// True when that changed something.
    fn keep_whole(&mut self, e: &Entry) -> bool {
        let (max_items, max_size) = (self.t.meta.history_max_items, self.t.meta.history_max_size);
        let Some(te) = self.ix.entry_mut(&mut self.t.root, e.uuid) else {
            return false;
        };
        let Some(mut h) = whole_history(te, e, max_items, max_size) else {
            return false;
        };
        for item in &mut h {
            protect_passwords(item);
        }
        te.history = h;
        true
    }

    /// A whole win of the source's copy: its fields, history, stamp and marker, and
    /// the target's values as private items. True when that changed content.
    fn take_whole(&mut self, e: &Entry) -> bool {
        let (max_items, max_size) = (self.t.meta.history_max_items, self.t.meta.history_max_size);
        let Some(te) = self.ix.entry_mut(&mut self.t.root, e.uuid) else {
            return false;
        };
        let joined = whole_history(e, te, max_items, max_size);
        let same =
            joined.is_none() && same_version(te, e) && same_versions(&te.history, &e.history);
        if same {
            origin::keep_own(&e.custom_data, &mut te.custom_data);
            return false;
        }
        let mut copy = e.duplicate(true);
        if let Some(h) = joined {
            copy.history = h;
        }
        protect_passwords(&mut copy);
        *te = copy;
        self.raise_version(has_unknown(e));
        true
    }

    /// Puts entry `id` at `place`; `flagged`: the source's copy flags its Title
    /// (F-066).
    fn put_entry(&mut self, id: Uuid, place: Place, flagged: bool) {
        let (parent, prev) = place;
        let Some(&(at, pos)) = self.ix.epos.get(&id) else {
            return;
        };
        if at != parent && self.ix.has_group(parent) {
            let slot = self
                .ix
                .group_mut(&mut self.t.root, at)
                .and_then(|from| from.entries.get_mut(pos))
                .filter(|x| x.uuid == id);
            let Some(slot) = slot else {
                return;
            };
            let moved = core::mem::replace(slot, super::tomb_entry());
            let title = shown_title(&moved, self.mask_titles || flagged || own_flag(&moved));
            let title = title.to_owned();
            let Some(to) = self.ix.group_mut(&mut self.t.root, parent) else {
                return;
            };
            to.entries.push(moved);
            let new_pos = to.entries.len().saturating_sub(1);
            self.ix.epos.insert(id, (parent, new_pos));
            let (previous, path) = (self.path_of(at), self.path_of(parent));
            let why = vec![previous];
            self.record(
                ChangeKind::Moved,
                Object::Entry,
                &path,
                &title,
                Some(id),
                why,
            );
        }
        if let Some(te) = self.ix.entry_mut(&mut self.t.root, id) {
            te.previous_parent = prev;
        }
    }

    /// The stamp's normal form, and the record: every change has one (MOD-11.26).
    fn finish_entry(
        &mut self,
        e: &Entry,
        tc: &Seen,
        count: usize,
        whole: Option<&str>,
        touched: bool,
        merged: &mut Places,
    ) {
        let id = e.uuid;
        let at = self.entry_place(id).unwrap_or(tc.place());
        self.one_move(count, at.0 == tc.parent);
        let Some(te) = self.ix.entry_mut(&mut self.t.root, id) else {
            return;
        };
        norm_stamp(&mut te.custom_data, merged, at, None);
        let title = shown_title(te, self.mask_titles || own_flag(e)).to_owned();
        let moved = Seen::of_entry(te, at.0).differs(tc);
        let recorded = self.changes.len() > count;
        if !(moved || recorded || touched) {
            return;
        }
        if whole.is_none() && recorded {
            return;
        }
        let path = self.path_of(at.0);
        let kind = if whole.is_some() {
            ChangeKind::Conflict
        } else {
            ChangeKind::Modified
        };
        let why = vec![whole.unwrap_or(OWN).into()];
        self.record(kind, Object::Entry, &path, &title, Some(id), why);
    }

    /// R6 E7 and C4, the deletion pass. Plain records are a user's and always
    /// apply; a row applies only if its group is in the object's set after the
    /// merge. A row that does not apply stays dormant. An import reaches only
    /// objects within its share group, and its keep test reads Mod and the stamp.
    fn shared_pass(&mut self, merged: &mut Places, stamps: &Stamps, erased: bool) {
        let same = self.same_vault;
        let start = self.target_start;
        let mut list: Vec<DeletedObject> = Vec::new();
        let mut plain: HashMap<Uuid, Time> = HashMap::new();
        {
            let mut add = |d: &DeletedObject| {
                let at = plain.entry(d.uuid).or_insert_with(|| {
                    list.push(d.clone());
                    d.deleted_at
                });
                *at = (*at).max(d.deleted_at);
            };
            self.t.deleted_objects.iter().for_each(&mut add);
            if same {
                self.s.deleted_objects.iter().for_each(&mut add);
            }
        }
        let mut rows = origin::read_rows(&self.t.meta.custom_data);
        let mut add_row = |key: (Uuid, Uuid), at: Time| {
            let row = rows.entry(key).or_insert(at);
            *row = (*row).max(at);
        };
        if same {
            for (key, at) in origin::read_rows(&self.s.meta.custom_data) {
                add_row(key, at);
            }
        } else {
            // R6 C3: a container's record, unless a plain record has the id.
            for d in self
                .s
                .deleted_objects
                .iter()
                .filter(|d| !plain.contains_key(&d.uuid))
            {
                add_row((d.uuid, start), d.deleted_at);
            }
        }
        rows.retain(|(id, _), at| plain.get(id).is_none_or(|p| *at > *p));
        let ids: BTreeSet<Uuid> = plain
            .keys()
            .copied()
            .chain(rows.keys().map(|(id, _)| *id))
            .collect();
        let mut pass = Pass {
            merged,
            stamps,
            source_times: core::mem::take(&mut self.source_times),
            source_group_times: core::mem::take(&mut self.source_group_times),
            plain,
            rows,
            beaten: HashSet::new(),
            needed: HashSet::new(),
            erased,
            quiet_entries: HashSet::new(),
            quiet_groups: HashSet::new(),
            renamed: HashMap::new(),
        };
        for id in &ids {
            self.pass_entry(*id, &mut pass);
        }
        let mut groups: Vec<Uuid> = ids
            .iter()
            .copied()
            .filter(|id| self.ix.has_group(*id) && *id != self.ix.root && *id != start)
            .collect();
        groups
            .sort_by_cached_key(|id| core::cmp::Reverse(self.ix.chain(*id).map_or(0, |c| c.len())));
        for id in groups {
            self.pass_group(id, &mut pass);
        }
        origin::gone_groups(&mut self.t.root, pass.merged.bin, &pass.renamed);
        self.quiet(&pass.quiet_entries, &pass.quiet_groups);
        if pass.erased {
            // FMT-10.16, FMT-11.37: nothing names an erased object, so the vault
            // still holds its invariants and can be saved.
            recycle::clean_references(self.t, self.now);
        }
        list.retain(|d| !pass.beaten.contains(&d.uuid) || pass.needed.contains(&d.uuid));
        for d in &mut list {
            if let Some(at) = pass.plain.get(&d.uuid) {
                d.deleted_at = *at;
            }
        }
        let rows_changed = origin::write_rows(&mut self.t.meta.custom_data, &pass.rows);
        let list_changed = !same_items(&list, &self.t.deleted_objects);
        if list_changed {
            self.t.deleted_objects = list;
        }
        if list_changed || rows_changed {
            let why = vec!["deleted objects changed".into()];
            self.record(ChangeKind::Metadata, Object::Vault, "", "", None, why);
        }
    }

    fn pass_entry(&mut self, id: Uuid, pass: &mut Pass<'_>) {
        let Some(&(at, _)) = self.ix.epos.get(&id) else {
            return;
        };
        if !self.in_scope(at) {
            return;
        }
        let Some(te) = self.ix.entry(&self.t.root, id) else {
            return;
        };
        let own = if self.same_vault {
            later(&te.times)
        } else {
            te.times.last_modification
        };
        let marked = origin::brought(&te.custom_data);
        let prev = te.previous_parent;
        let set = pass.merged.shares_at(at, prev, None);
        let source = pass.source_times.get(&id).filter(|_| self.same_vault);
        let times = [
            Some(own),
            pass.stamps.entries.get(&id).copied(),
            source.copied(),
        ];
        if pass.goes(id, set, times, false, marked) {
            self.erase_entry(id);
            pass.erased = true;
            if self.same_vault && self.added_entries.contains(&id) {
                pass.quiet_entries.insert(id);
            }
        }
    }

    fn pass_group(&mut self, id: Uuid, pass: &mut Pass<'_>) {
        if !self.in_scope(id) {
            return;
        }
        let Some(g) = self.ix.group(&self.t.root, id) else {
            return;
        };
        let own = if self.same_vault {
            later(&g.times)
        } else {
            g.times.last_modification
        };
        let marked = origin::brought(&g.custom_data);
        // Not `g`'s own: the tree takes the renames of erased groups once, at the end.
        let prev = pass.merged.place_of(id).map_or(g.previous_parent, |p| p.1);
        let live = |x: Uuid| x != Uuid::default();
        let holds = g.entries.iter().any(|e| live(e.uuid)) || g.groups.iter().any(|c| live(c.uuid));
        let parent = self.ix.parent.get(&id).copied().unwrap_or(self.ix.root);
        let set = pass.merged.shares_at(parent, prev, Some(id));
        let source = pass.source_group_times.get(&id).filter(|_| self.same_vault);
        let times = [
            Some(own),
            pass.stamps.groups.get(&id).copied(),
            source.copied(),
        ];
        if pass.goes(id, set, times, holds, marked) && self.erase_group(id) {
            let to = pass.merged.gone(id);
            pass.renamed.insert(id, to);
            pass.erased = true;
            if self.same_vault && self.added_groups.contains(&id) {
                pass.quiet_groups.insert(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid {
        Uuid([n; 16])
    }

    /// R6 E6 (C1-07, S1): a stamp whose share the object no longer counts in names the
    /// innermost share it counts in now, as a user's move would; not the lowest id.
    #[test]
    fn origin_a_stamp_whose_share_left_names_the_innermost() {
        let mut root = Group::new(id(2), "R".into(), Time(0));
        let mut t = Group::new(id(0x30), "T".into(), Time(0));
        t.groups.push(Group::new(id(0x40), "S".into(), Time(0)));
        root.groups.push(t);
        let v = Vault::new(root, Time(0));
        let mut places = Places::new(&v, Set::from([id(0x30), id(0x40), id(0x50)]));
        let mut data = CustomData::default();
        let gone = Stamp {
            group: id(0x50),
            at: Time(9),
        };
        origin::set_stamp(&mut data, Some(gone));
        norm_stamp(&mut data, &mut places, (id(0x40), None), None);
        assert_eq!(
            origin::stamp_of(&data),
            Some(Stamp {
                group: id(0x40),
                ..gone
            })
        );
        norm_stamp(&mut data, &mut places, (id(2), None), None);
        assert_eq!(origin::stamp_of(&data), None, "outside there is no stamp");
    }

    /// C1R6-03, mutant c11: a stamp naming a share the object still counts in stays as it
    /// is, the outer share too; it does not move to the innermost.
    #[test]
    fn origin_a_stamp_whose_share_holds_the_object_stays() {
        let mut root = Group::new(id(2), "R".into(), Time(0));
        let mut t = Group::new(id(0x30), "T".into(), Time(0));
        t.groups.push(Group::new(id(0x40), "S".into(), Time(0)));
        root.groups.push(t);
        let v = Vault::new(root, Time(0));
        let mut places = Places::new(&v, Set::from([id(0x30), id(0x40)]));
        let mut data = CustomData::default();
        let outer = Stamp {
            group: id(0x30),
            at: Time(9),
        };
        origin::set_stamp(&mut data, Some(outer));
        norm_stamp(&mut data, &mut places, (id(0x40), None), None);
        assert_eq!(origin::stamp_of(&data), Some(outer));
    }
}
