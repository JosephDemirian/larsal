//! E3-S11: random valid vaults survive a save and an open with an identical
//! model, and a second save and open is identical again.
//!
//! The strategy builds a plan (plain data, so a failing case prints in
//! full), then the vault: groups in a tree, entries with standard and custom
//! fields (protected and not), history, attachments (shared and not),
//! custom data, custom icons, tags, deleted objects, kept unknown elements
//! of every layout kind, times over the whole i64 range, public custom
//! data, every cipher, both compressions, AES-KDF and both Argon2 types
//! (cheap parameters).
//!
//! The vaults are in the canonical form a read gives (Meta references name
//! groups, attachments and public items sorted, standard fields protected
//! when their vault flag is on: FMT-11.20 raises them on the first save).
//! Before comparing, the parts every save sets are removed: the padding
//! item and `_LAST_MODIFIED` of the vault custom data (FMT-14.21), the read
//! version, and, for a vault written as 4.0, the custom data item times that
//! 4.0 does not hold (FMT-16.11).
//!
//! `random_vaults_round_trip` runs a few cases in the normal suite;
//! `ten_thousand_random_vaults_round_trip` (ignored) runs 10,000:
//! `cargo test --release -p app-format --test property -- --ignored`.

mod write_common;

use app_crypto::secret::{SecretBytes, SecretString};
use app_format::document::write::PADDING_KEY;
use app_model::entry::{STANDARD_FIELDS, cmp_utf16};
use app_model::{
    Argon2Kind, Association, Attachment, AutoType, Cipher, Compression, CustomData, CustomDataItem,
    CustomIcon, DeletedObject, Encryption, Entry, Field, Group, Icon, Kdf, PublicItem, Switch,
    Time, Times, UnknownElement, UnknownNode, Uuid, Vault,
};
use proptest::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use write_common::{open_pw, save_pw};

// ---------------------------------------------------------------------------
// Text.

/// A character a written text keeps (not in the FMT-12.25 removal set).
fn safe_char() -> impl Strategy<Value = char> {
    prop_oneof![
        8 => proptest::char::range('a', 'z'),
        2 => prop::sample::select(vec![' ', '\t', '\n', '\r', '&', '<', '>', '"', '\'', ';', ',', '\u{85}', '\u{A0}', '\u{FEFF}', '\u{E000}', '\u{FFFD}', '\u{1F600}', 'é']),
        1 => any::<char>().prop_filter("kept on write", |c| keep(*c)),
    ]
}

fn keep(c: char) -> bool {
    !matches!(c,
        '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}'
        | '\u{7F}'..='\u{84}' | '\u{86}'..='\u{9F}' | '\u{FFFE}' | '\u{FFFF}')
}

/// Text that a written vault keeps exactly.
fn text(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(safe_char(), 0..max).prop_map(|v| v.into_iter().collect())
}

/// Any text, for protected values (never stripped, FMT-11.46).
fn any_text(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..max).prop_map(|v| v.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Kept unknown elements, in the canonical forms a read gives (FMT-10.27).

#[derive(Debug, Clone)]
enum UKind {
    Empty,
    Text(String),
    Elements(Vec<UPlan>),
    /// Text parts and elements alternating, at least one text that is not
    /// only whitespace.
    Mixed(Vec<(String, UPlan)>, String),
}

#[derive(Debug, Clone)]
struct UPlan {
    name: u8,
    attrs: Vec<(u8, String)>,
    kind: Box<UKind>,
}

fn unknown_plan() -> impl Strategy<Value = UPlan> {
    let leaf = (
        0u8..6,
        prop::collection::vec((0u8..4, text(6)), 0..3),
        prop_oneof![
            Just(UKind::Empty),
            text(6).prop_map(|t| UKind::Text(format!("t{t}"))),
        ],
    )
        .prop_map(|(name, attrs, kind)| UPlan {
            name,
            attrs,
            kind: Box::new(kind),
        });
    leaf.prop_recursive(2, 8, 3, |inner| {
        (
            0u8..6,
            prop::collection::vec((0u8..4, text(6)), 0..3),
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..3).prop_map(UKind::Elements),
                (prop::collection::vec((text(4), inner), 1..3), text(4))
                    .prop_map(|(parts, tail)| UKind::Mixed(parts, tail)),
            ],
        )
            .prop_map(|(name, attrs, kind)| UPlan {
                name,
                attrs,
                kind: Box::new(kind),
            })
    })
}

fn unknowns() -> impl Strategy<Value = Vec<UPlan>> {
    prop::collection::vec(unknown_plan(), 0..2)
}

fn build_unknown(p: &UPlan) -> UnknownElement {
    let mut seen = HashSet::new();
    let attributes = p
        .attrs
        .iter()
        .filter(|(n, _)| seen.insert(*n))
        .map(|(n, v)| {
            (
                ["a", "b", "k", "z"][usize::from(*n % 4)].to_owned(),
                v.clone(),
            )
        })
        .collect();
    let content = match p.kind.as_ref() {
        UKind::Empty => Vec::new(),
        UKind::Text(t) => vec![UnknownNode::Text(t.clone())],
        UKind::Elements(children) => children
            .iter()
            .map(|c| UnknownNode::Element(build_unknown(c)))
            .collect(),
        UKind::Mixed(parts, tail) => {
            // The first text part carries an `x`, so the element is mixed.
            let mut out = Vec::new();
            for (i, (t, e)) in parts.iter().enumerate() {
                let t = if i == 0 { format!("x{t}") } else { t.clone() };
                if !t.is_empty() {
                    out.push(UnknownNode::Text(t));
                }
                out.push(UnknownNode::Element(build_unknown(e)));
            }
            if !tail.is_empty() {
                out.push(UnknownNode::Text(tail.clone()));
            }
            out
        }
    };
    UnknownElement {
        name: format!("Ux{}", p.name),
        attributes,
        content,
    }
}

fn build_unknowns(list: &[UPlan]) -> Vec<UnknownElement> {
    list.iter().map(build_unknown).collect()
}

// ---------------------------------------------------------------------------
// Plans.

#[derive(Debug, Clone)]
struct CdPlan {
    items: Vec<(String, String, Option<i64>, Vec<UPlan>)>,
    unknown: Vec<UPlan>,
}

fn cd_plan() -> impl Strategy<Value = CdPlan> {
    (
        prop::collection::vec(
            (
                text(6),
                text(8),
                prop::option::of(any::<i64>()),
                prop::collection::vec(unknown_plan(), 0..1),
            ),
            0..3,
        ),
        prop::collection::vec(unknown_plan(), 0..1),
    )
        .prop_map(|(items, unknown)| CdPlan { items, unknown })
}

fn build_cd(p: &CdPlan) -> CustomData {
    let mut seen = HashSet::new();
    let padding = String::from_utf8(PADDING_KEY.to_vec()).unwrap();
    CustomData {
        items: p
            .items
            .iter()
            .filter(|(k, ..)| {
                *k != "KnownBad"
                    && *k != "_LAST_MODIFIED"
                    && *k != padding
                    && seen.insert(k.clone())
            })
            .map(|(k, v, t, u)| CustomDataItem {
                key: k.clone(),
                value: v.clone(),
                last_modified: t.map(Time),
                unknown: build_unknowns(u),
            })
            .collect(),
        unknown: build_unknowns(&p.unknown),
    }
}

#[derive(Debug, Clone)]
struct TimesPlan([i64; 6], bool, i32, Vec<UPlan>);

fn times_plan() -> impl Strategy<Value = TimesPlan> {
    (
        any::<[i64; 6]>(),
        any::<bool>(),
        any::<i32>(),
        prop::collection::vec(unknown_plan(), 0..1),
    )
        .prop_map(|(t, e, u, k)| TimesPlan(t, e, u, k))
}

fn build_times(p: &TimesPlan) -> Times {
    let t = p.0;
    Times {
        last_modification: Time(t[0]),
        creation: Time(t[1]),
        last_access: Time(t[2]),
        expiry: Time(t[3]),
        expires: p.1,
        usage_count: p.2,
        location_changed: Time(t[4]),
        unknown: build_unknowns(&p.3),
    }
}

/// `None`: standard icon `n`; `Some(i)`: custom icon `i` (an index past the
/// icon list names no icon, which is kept, FMT-11.38).
#[derive(Debug, Clone)]
struct IconPlan(u16, Option<u8>);

fn icon_plan() -> impl Strategy<Value = IconPlan> {
    (0u16..200, prop::option::of(0u8..4)).prop_map(|(n, c)| IconPlan(n, c))
}

fn build_icon(p: &IconPlan) -> Icon {
    match p.1 {
        Some(i) => Icon::Custom(icon_id(usize::from(i))),
        None => Icon::Standard(i32::from(p.0)),
    }
}

/// Auto-type plan: enabled, obfuscation, default sequence, associations
/// (window, sequence, unknown children), unknown children.
type AutoTypePlan = (
    bool,
    i32,
    String,
    Vec<(String, String, Vec<UPlan>)>,
    Vec<UPlan>,
);
/// Custom icon plan: name, time, data, unknown children.
type IconItemPlan = (String, Option<i64>, Vec<u8>, Vec<UPlan>);

#[derive(Debug, Clone)]
struct EntryPlan {
    std: Vec<(String, bool)>,
    custom: Vec<(String, String, bool)>,
    icon: IconPlan,
    colors: (String, String, String),
    tags: Vec<String>,
    times: TimesPlan,
    exclude: bool,
    previous_parent: Option<u8>,
    attachments: Vec<(String, u8, Vec<u8>)>,
    auto_type: AutoTypePlan,
    custom_data: CdPlan,
    unknown: Vec<UPlan>,
}

fn entry_plan() -> impl Strategy<Value = EntryPlan> {
    let fields = (
        prop::collection::vec((any_text(8), any::<bool>()), 5),
        prop::collection::vec((text(5), any_text(8), any::<bool>()), 0..3),
    );
    let looks = (
        icon_plan(),
        (text(4), text(4), text(6)),
        prop::collection::vec(text(4), 0..3),
        times_plan(),
    );
    let flags = (any::<bool>(), prop::option::weighted(0.2, 0u8..8));
    let attachments = prop::collection::vec(
        (text(5), 0u8..6, prop::collection::vec(any::<u8>(), 0..24)),
        0..3,
    );
    let auto_type = (
        any::<bool>(),
        any::<i32>(),
        text(6),
        prop::collection::vec(
            (
                text(5),
                text(5),
                prop::collection::vec(unknown_plan(), 0..1),
            ),
            0..2,
        ),
        prop::collection::vec(unknown_plan(), 0..1),
    );
    (
        fields,
        looks,
        flags,
        attachments,
        auto_type,
        cd_plan(),
        unknowns(),
    )
        .prop_map(
            |(
                (std, custom),
                (icon, colors, tags, times),
                (exclude, previous_parent),
                attachments,
                auto_type,
                custom_data,
                unknown,
            )| EntryPlan {
                std,
                custom,
                icon,
                colors,
                tags,
                times,
                exclude,
                previous_parent,
                attachments,
                auto_type,
                custom_data,
                unknown,
            },
        )
}

#[derive(Debug, Clone)]
struct GroupPlan {
    parent: u8,
    texts: (String, String, String, String),
    icon: IconPlan,
    times: TimesPlan,
    expanded: bool,
    switches: (u8, u8),
    last_top_visible_entry: Option<u8>,
    custom_data: CdPlan,
    previous_parent: Option<u8>,
    unknown: Vec<UPlan>,
}

fn group_plan() -> impl Strategy<Value = GroupPlan> {
    (
        any::<u8>(),
        (
            text(6),
            text(6),
            prop::option::weighted(0.2, text(5)).prop_map(Option::unwrap_or_default),
            text(5),
        ),
        icon_plan(),
        times_plan(),
        any::<bool>(),
        (0u8..3, 0u8..3),
        prop::option::of(any::<u8>()),
        cd_plan(),
        prop::option::weighted(0.15, 0u8..8),
        unknowns(),
    )
        .prop_map(
            |(
                parent,
                texts,
                icon,
                times,
                expanded,
                switches,
                last_top_visible_entry,
                custom_data,
                previous_parent,
                unknown,
            )| GroupPlan {
                parent,
                texts,
                icon,
                times,
                expanded,
                switches,
                last_top_visible_entry,
                custom_data,
                previous_parent,
                unknown,
            },
        )
}

#[derive(Debug, Clone)]
struct MetaPlan {
    texts: (String, String, String, String, String),
    times: [i64; 7],
    numbers: (i32, i32, i32, i32, i32),
    force_once: bool,
    protection: [bool; 5],
    recycle_bin_enabled: bool,
    refs: [Option<u8>; 4],
    custom_data: CdPlan,
    unknown: (Vec<UPlan>, Vec<UPlan>, Vec<UPlan>),
}

fn meta_plan() -> impl Strategy<Value = MetaPlan> {
    (
        (text(6), text(6), text(6), text(6), text(6)),
        any::<[i64; 7]>(),
        (
            any::<i32>(),
            any::<i32>(),
            any::<i32>(),
            -1i32..1000,
            -1i32..100_000_000,
        ),
        any::<bool>(),
        any::<[bool; 5]>(),
        any::<bool>(),
        any::<[Option<u8>; 4]>(),
        cd_plan(),
        (unknowns(), unknowns(), unknowns()),
    )
        .prop_map(
            |(
                texts,
                times,
                numbers,
                force_once,
                protection,
                recycle_bin_enabled,
                refs,
                custom_data,
                unknown,
            )| MetaPlan {
                texts,
                times,
                numbers,
                force_once,
                protection,
                recycle_bin_enabled,
                refs,
                custom_data,
                unknown,
            },
        )
}

#[derive(Debug, Clone)]
struct Plan {
    meta: MetaPlan,
    icons: Vec<IconItemPlan>,
    groups: Vec<GroupPlan>,
    entries: Vec<(u8, EntryPlan, Vec<EntryPlan>)>,
    deleted: Vec<(i64, Vec<UPlan>)>,
    top_unknown: (Vec<UPlan>, Vec<UPlan>, Vec<UPlan>),
    public: Vec<(u8, String, Vec<u8>)>,
    settings: (u8, bool, u8, u8),
}

fn plan() -> impl Strategy<Value = Plan> {
    (
        meta_plan(),
        prop::collection::vec(
            (
                text(5),
                prop::option::of(any::<i64>()),
                prop::collection::vec(any::<u8>(), 0..16),
                prop::collection::vec(unknown_plan(), 0..1),
            ),
            0..3,
        ),
        prop::collection::vec(group_plan(), 1..5),
        prop::collection::vec(
            (
                any::<u8>(),
                entry_plan(),
                prop::collection::vec(entry_plan(), 0..3),
            ),
            0..5,
        ),
        prop::collection::vec(
            (any::<i64>(), prop::collection::vec(unknown_plan(), 0..1)),
            0..3,
        ),
        (unknowns(), unknowns(), unknowns()),
        prop::collection::vec(
            (0u8..7, text(5), prop::collection::vec(any::<u8>(), 0..10)),
            0..3,
        ),
        (0u8..3, any::<bool>(), 0u8..3, 1u8..4),
    )
        .prop_map(
            |(meta, icons, groups, entries, deleted, top_unknown, public, settings)| Plan {
                meta,
                icons,
                groups,
                entries,
                deleted,
                top_unknown,
                public,
                settings,
            },
        )
}

// ---------------------------------------------------------------------------
// Building the vault.

fn id(space: u128, i: usize) -> Uuid {
    Uuid((space << 64 | (i as u128 + 1)).to_be_bytes())
}

fn group_id(i: usize) -> Uuid {
    id(1, i)
}

fn entry_id(i: usize) -> Uuid {
    id(2, i)
}

fn icon_id(i: usize) -> Uuid {
    id(3, i)
}

/// The shared attachment contents: an entry's attachment picks one of these
/// (so equal content appears in many entries) or carries its own bytes.
fn shared(n: u8) -> Option<Vec<u8>> {
    match n {
        0 => Some(b"shared one".to_vec()),
        1 => Some(Vec::new()),
        2 => Some((0..=255).collect()),
        _ => None,
    }
}

fn build_entry(
    p: &EntryPlan,
    uuid: Uuid,
    flags: &app_model::MemoryProtection,
    groups: usize,
) -> Entry {
    let mut e = Entry::new(uuid, Time(0));
    let secret = |v: &str| SecretString::new(v.to_owned());
    for (name, (value, own)) in STANDARD_FIELDS.iter().zip(&p.std) {
        // FMT-11.20: a vault flag protects its standard field on write.
        let protected = *own || flags.for_field(name);
        let value = if protected {
            value.clone()
        } else {
            value.chars().filter(|c| keep(*c)).collect()
        };
        e.set_field(
            (*name).to_owned(),
            Field {
                value: secret(&value),
                protected,
            },
        );
    }
    for (key, value, protected) in &p.custom {
        let key = format!("c{key}");
        if e.field(&key).is_none() {
            let value = if *protected {
                value.clone()
            } else {
                value.chars().filter(|c| keep(*c)).collect()
            };
            e.set_field(
                key,
                Field {
                    value: secret(&value),
                    protected: *protected,
                },
            );
        }
    }
    e.icon = build_icon(&p.icon);
    e.foreground_color = p.colors.0.clone();
    e.background_color = p.colors.1.clone();
    e.override_url = p.colors.2.clone();
    e.set_tags(app_model::entry::parse_tags(&p.tags.join(",")));
    e.times = build_times(&p.times);
    e.exclude_from_reports = p.exclude;
    e.previous_parent = p
        .previous_parent
        .map(|i| group_id(usize::from(i) % (groups + 2)));
    let mut seen = HashSet::new();
    let mut attachments: Vec<Attachment> = p
        .attachments
        .iter()
        .filter(|(name, ..)| seen.insert(name.clone()))
        .map(|(name, pick, own)| Attachment {
            name: name.clone(),
            data: Arc::new(SecretBytes::new(
                shared(*pick).unwrap_or_else(|| own.clone()),
            )),
        })
        .collect();
    attachments.sort_by(|a, b| cmp_utf16(&a.name, &b.name));
    e.attachments = attachments;
    let (enabled, obfuscation, sequence, associations, unknown) = &p.auto_type;
    e.auto_type = AutoType {
        enabled: *enabled,
        obfuscation: *obfuscation,
        default_sequence: sequence.clone(),
        associations: associations
            .iter()
            .map(|(w, s, u)| Association {
                window: w.clone(),
                sequence: s.clone(),
                unknown: build_unknowns(u),
            })
            .collect(),
        unknown: build_unknowns(unknown),
    };
    e.custom_data = build_cd(&p.custom_data);
    e.unknown = build_unknowns(&p.unknown);
    e
}

fn build(p: &Plan) -> Vault {
    let n = p.groups.len();
    // Each group but the root hangs under an earlier one.
    let parents: Vec<usize> = (0..n)
        .map(|i| {
            if i == 0 {
                0
            } else {
                usize::from(p.groups[i].parent) % i
            }
        })
        .collect();
    let mut meta = app_model::Meta::new(Time(p.meta.times[0]));
    let flags = &p.meta.protection;
    meta.memory_protection = app_model::MemoryProtection {
        title: flags[0],
        user_name: flags[1],
        password: flags[2],
        url: flags[3],
        notes: flags[4],
        unknown: build_unknowns(&p.meta.unknown.1),
    };
    // Entries per group, with history carrying the owner's id.
    let mut entries: Vec<Vec<Entry>> = (0..n).map(|_| Vec::new()).collect();
    let mut entry_ids = Vec::new();
    for (i, (g, e, history)) in p.entries.iter().enumerate() {
        let uuid = entry_id(i);
        let mut entry = build_entry(e, uuid, &meta.memory_protection, n);
        entry.history = history
            .iter()
            .map(|h| build_entry(h, uuid, &meta.memory_protection, n))
            .collect();
        entries[usize::from(*g) % n].push(entry);
        entry_ids.push(uuid);
    }
    let mut built: Vec<Option<Group>> = (0..n).map(|_| None).collect();
    for i in (0..n).rev() {
        let gp = &p.groups[i];
        let mut g = Group::new(group_id(i), gp.texts.0.clone(), Time(0));
        g.notes = gp.texts.1.clone();
        g.tags = gp.texts.2.clone();
        g.default_sequence = gp.texts.3.clone();
        g.icon = build_icon(&gp.icon);
        g.times = build_times(&gp.times);
        g.expanded = gp.expanded;
        let switch = |s: u8| [Switch::Inherit, Switch::On, Switch::Off][usize::from(s % 3)];
        g.auto_type = switch(gp.switches.0);
        g.searching = switch(gp.switches.1);
        g.last_top_visible_entry = gp
            .last_top_visible_entry
            .filter(|_| !entry_ids.is_empty())
            .map(|k| entry_ids[usize::from(k) % entry_ids.len()]);
        g.custom_data = build_cd(&gp.custom_data);
        g.previous_parent = gp
            .previous_parent
            .map(|k| group_id(usize::from(k) % (n + 2)));
        g.unknown = build_unknowns(&gp.unknown);
        g.entries = std::mem::take(&mut entries[i]);
        for c in (i + 1)..n {
            if parents[c] == i
                && let Some(child) = built[c].take()
            {
                g.groups.push(child);
            }
        }
        built[i] = Some(g);
    }
    let root = built[0].take().unwrap();
    let m = &p.meta;
    meta.generator = m.texts.0.clone();
    meta.name = m.texts.1.clone();
    meta.description = m.texts.2.clone();
    meta.default_user_name = m.texts.3.clone();
    meta.color = m.texts.4.clone();
    meta.name_changed = Time(m.times[1]);
    meta.description_changed = Time(m.times[2]);
    meta.default_user_name_changed = Time(m.times[3]);
    meta.master_key_changed = Time(m.times[4]);
    meta.recycle_bin_changed = Time(m.times[5]);
    meta.settings_changed = Time(m.times[6]);
    meta.entry_templates_group_changed = Time(m.times[0]);
    meta.maintenance_history_days = m.numbers.0;
    meta.master_key_change_rec = m.numbers.1;
    meta.master_key_change_force = m.numbers.2;
    meta.history_max_items = m.numbers.3;
    meta.history_max_size = m.numbers.4;
    meta.master_key_change_force_once = m.force_once;
    meta.recycle_bin_enabled = m.recycle_bin_enabled;
    let gref = |r: Option<u8>| r.map(|k| group_id(usize::from(k) % n));
    meta.recycle_bin = gref(m.refs[0]);
    meta.entry_templates_group = gref(m.refs[1]);
    meta.last_selected_group = gref(m.refs[2]);
    meta.last_top_visible_group = gref(m.refs[3]);
    meta.custom_icons = p
        .icons
        .iter()
        .enumerate()
        .map(|(i, (name, t, data, u))| CustomIcon {
            uuid: icon_id(i),
            name: name.clone(),
            last_modified: t.map(Time),
            data: data.clone(),
            unknown: build_unknowns(u),
        })
        .collect();
    meta.custom_icons_unknown = build_unknowns(&p.meta.unknown.2);
    meta.custom_data = build_cd(&m.custom_data);
    meta.unknown = build_unknowns(&p.meta.unknown.0);
    let mut v = Vault::new(root, Time(0));
    v.meta = meta;
    v.deleted_objects = p
        .deleted
        .iter()
        .enumerate()
        .map(|(i, (t, u))| DeletedObject {
            uuid: id(4, i),
            deleted_at: Time(*t),
            unknown: build_unknowns(u),
        })
        .collect();
    v.unknown_document = build_unknowns(&p.top_unknown.0);
    v.unknown_root = build_unknowns(&p.top_unknown.1);
    v.unknown_deleted_objects = build_unknowns(&p.top_unknown.2);
    let (cipher, gzip, kdf, cost) = p.settings;
    v.encryption = Encryption {
        cipher: [Cipher::Aes256, Cipher::Twofish256, Cipher::ChaCha20][usize::from(cipher)],
        compression: if gzip {
            Compression::Gzip
        } else {
            Compression::None
        },
        kdf: match kdf {
            0 => Kdf::AesKdf {
                rounds: u64::from(cost),
            },
            k => Kdf::Argon2 {
                kind: if k == 1 {
                    Argon2Kind::D
                } else {
                    Argon2Kind::Id
                },
                iterations: 1,
                memory_kib: 8 * u64::from(cost),
                lanes: 1,
            },
        },
    };
    // Public custom data: valid types, unique names, sorted by name (FMT-03.22).
    let mut names = HashSet::new();
    let mut public: Vec<PublicItem> = p
        .public
        .iter()
        .filter(|(_, name, _)| names.insert(name.clone()))
        .map(|(kind, name, bytes)| {
            let (kind, size) = [
                (0x04, Some(4)),
                (0x05, Some(8)),
                (0x08, Some(1)),
                (0x0C, Some(4)),
                (0x0D, Some(8)),
                (0x18, None),
                (0x42, None),
            ][usize::from(*kind)];
            let mut value = bytes.clone();
            if let Some(s) = size {
                value.resize(s, 0);
            }
            PublicItem {
                kind,
                name: name.as_bytes().to_vec(),
                value,
            }
        })
        .collect();
    public.sort_by(|a, b| a.name.cmp(&b.name));
    v.public_custom_data = public;
    v
}

// ---------------------------------------------------------------------------
// Comparing.

/// Removes what every save sets or may drop by design (module docs).
fn normalize(v: &mut Vault, minor: u16) {
    let padding = String::from_utf8(PADDING_KEY.to_vec()).unwrap();
    v.meta
        .custom_data
        .items
        .retain(|i| i.key != padding && i.key != "_LAST_MODIFIED");
    v.read_version = None;
    if minor == 0 {
        let strip = |cd: &mut CustomData| cd.items.iter_mut().for_each(|i| i.last_modified = None);
        strip(&mut v.meta.custom_data);
        let mut stack = vec![&mut v.root];
        while let Some(g) = stack.pop() {
            strip(&mut g.custom_data);
            for e in &mut g.entries {
                strip(&mut e.custom_data);
                e.history.iter_mut().for_each(|h| strip(&mut h.custom_data));
            }
            stack.extend(g.groups.iter_mut());
        }
    }
}

/// Where two vaults first differ, in words (the Debug of `Vault` prints
/// counts only, LD-88).
fn first_difference(a: &Vault, b: &Vault) -> String {
    if a.meta != b.meta {
        return format!("meta:\n{:?}\n{:?}", a.meta, b.meta);
    }
    if a.encryption != b.encryption || a.public_custom_data != b.public_custom_data {
        return "encryption or public custom data".into();
    }
    if a.deleted_objects != b.deleted_objects {
        return format!(
            "deleted objects:\n{:?}\n{:?}",
            a.deleted_objects, b.deleted_objects
        );
    }
    if (
        &a.unknown_document,
        &a.unknown_root,
        &a.unknown_deleted_objects,
    ) != (
        &b.unknown_document,
        &b.unknown_root,
        &b.unknown_deleted_objects,
    ) {
        return format!(
            "top unknown:\n{:?}\n{:?}",
            (
                &a.unknown_document,
                &a.unknown_root,
                &a.unknown_deleted_objects
            ),
            (
                &b.unknown_document,
                &b.unknown_root,
                &b.unknown_deleted_objects
            )
        );
    }
    let (ga, gb) = (a.root.subtree(), b.root.subtree());
    if ga.len() != gb.len() {
        return format!("group count {} vs {}", ga.len(), gb.len());
    }
    for (x, y) in ga.iter().zip(&gb) {
        let gx = (
            (
                &x.uuid, &x.name, &x.notes, &x.tags, &x.icon, &x.times, x.expanded,
            ),
            (
                &x.default_sequence,
                x.auto_type,
                x.searching,
                &x.last_top_visible_entry,
                &x.custom_data,
                &x.previous_parent,
                &x.unknown,
            ),
        );
        let gy = (
            (
                &y.uuid, &y.name, &y.notes, &y.tags, &y.icon, &y.times, y.expanded,
            ),
            (
                &y.default_sequence,
                y.auto_type,
                y.searching,
                &y.last_top_visible_entry,
                &y.custom_data,
                &y.previous_parent,
                &y.unknown,
            ),
        );
        if gx != gy {
            return format!("group:\n{gx:?}\n{gy:?}");
        }
        if x.entries.len() != y.entries.len() {
            return "entry count".into();
        }
        for (e, f) in x.entries.iter().zip(&y.entries) {
            let pairs = std::iter::once((e, f)).chain(e.history.iter().zip(&f.history));
            for (e, f) in pairs {
                let fe: Vec<(&str, &str, bool)> = e
                    .fields()
                    .map(|(k, v)| (k, v.value.expose(), v.protected))
                    .collect();
                let ff: Vec<(&str, &str, bool)> = f
                    .fields()
                    .map(|(k, v)| (k, v.value.expose(), v.protected))
                    .collect();
                if fe != ff {
                    return format!("fields:\n{fe:?}\n{ff:?}");
                }
                let ex = (
                    (
                        &e.uuid,
                        &e.icon,
                        &e.foreground_color,
                        &e.background_color,
                        &e.override_url,
                        e.tags(),
                        &e.times,
                    ),
                    (
                        e.exclude_from_reports,
                        &e.previous_parent,
                        &e.attachments,
                        &e.auto_type,
                        &e.custom_data,
                        &e.unknown,
                        e.history.len(),
                    ),
                );
                let ey = (
                    (
                        &f.uuid,
                        &f.icon,
                        &f.foreground_color,
                        &f.background_color,
                        &f.override_url,
                        f.tags(),
                        &f.times,
                    ),
                    (
                        f.exclude_from_reports,
                        &f.previous_parent,
                        &f.attachments,
                        &f.auto_type,
                        &f.custom_data,
                        &f.unknown,
                        f.history.len(),
                    ),
                );
                if ex != ey {
                    return format!("entry:\n{ex:?}\n{ey:?}");
                }
            }
        }
    }
    "no difference found by the walk".into()
}

/// The property: save, open, compare; save, open, compare again.
fn round_trip(p: &Plan) -> Result<(), TestCaseError> {
    let mut v = build(p);
    prop_assert_eq!(app_model::invariants::check(&v), Ok(()));
    let first = save_pw(&v, "demo-pass");
    let mut a = open_pw(&first.bytes, "demo-pass").vault;
    prop_assert_eq!(app_model::invariants::check(&a), Ok(()));
    let second = save_pw(&a, "demo-pass");
    prop_assert_eq!(
        second.version,
        first.version,
        "the second save writes the same version"
    );
    let mut b = open_pw(&second.bytes, "demo-pass").vault;
    normalize(&mut v, first.version.minor);
    normalize(&mut a, first.version.minor);
    normalize(&mut b, second.version.minor);
    prop_assert!(a == v, "first save and open: {}", first_difference(&v, &a));
    prop_assert!(b == a, "second save and open: {}", first_difference(&a, &b));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn random_vaults_round_trip(p in plan()) {
        round_trip(&p)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    #[ignore = "10,000 cases: run with --release -- --ignored"]
    fn ten_thousand_random_vaults_round_trip(p in plan()) {
        round_trip(&p)?;
    }
}
