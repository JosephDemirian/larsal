//! Test helper: turns a `Vault` into the expected-content JSON shape of
//! `scripts/testdata/to_json.py` (testdata/README.md, "The JSON files").
//!
//! The JSON files hold the reference CLI's XML export of each demo vault,
//! so the element tree built here follows that export's write rules for the
//! vault's file version: version 3.1 writes text times and the attachment
//! pool in `Meta/Binaries`; version 4.1 writes binary times, 4.x-only fields,
//! and every attachment reference as `Ref="0"` without bytes (README, "Things
//! to know"). Then the to_json.py rules apply: CustomData items sorted by key,
//! volatile items "normalized", banned words as "hex:" (read from the name
//! guard, the one list), keys sorted.
#![allow(dead_code, clippy::arithmetic_side_effects)]

use larsal_format::document::encode::{base64_decode, base64_encode, time_to_binary, uuid_to_text};
use larsal_model::entry::{STANDARD_FIELDS, cmp_utf16};
use larsal_model::json::{Map, Value};
use larsal_model::{CustomData, Entry, Group, Icon, Switch, Time, Uuid, Vault};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

/// The document root element name (stored encoded, name rule).
pub const ROOT_NAME: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
];

/// One element of the export.
#[derive(Debug, Clone)]
pub struct El {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: Option<String>,
    pub kids: Vec<El>,
}

fn leaf(name: &str, text: impl Into<String>) -> El {
    El {
        name: name.into(),
        attrs: Vec::new(),
        text: Some(text.into()),
        kids: Vec::new(),
    }
}

fn node(name: &str, kids: Vec<El>) -> El {
    El {
        name: name.into(),
        attrs: Vec::new(),
        text: None,
        kids,
    }
}

/// How the export writes a vault of one file version.
#[derive(Clone, Copy)]
pub struct Shape {
    pub major: u16,
    pub minor: u16,
    /// The header's compression flag (the 3.1 pool marks items compressed).
    pub compressed: bool,
}

impl Shape {
    fn v4(self) -> bool {
        self.major >= 4
    }
    fn v41(self) -> bool {
        self.major >= 4 && self.minor >= 1
    }
}

fn time(t: Time, sh: Shape) -> String {
    if sh.v4() {
        return time_to_binary(t);
    }
    match t.to_civil() {
        Some(c) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        ),
        None => String::new(),
    }
}

fn b(v: bool) -> &'static str {
    if v { "True" } else { "False" }
}

fn uuid(u: Option<Uuid>) -> String {
    uuid_to_text(u.unwrap_or(Uuid::ZERO))
}

fn switch(s: Switch) -> &'static str {
    match s {
        Switch::Inherit => "null",
        Switch::On => "true",
        Switch::Off => "false",
    }
}

/// The attachment pool in FMT-13.16 order, deduplicated by content.
fn pool(root: &Group) -> Vec<Arc<larsal_crypto::secret::SecretBytes>> {
    let mut out: Vec<Arc<larsal_crypto::secret::SecretBytes>> = Vec::new();
    let mut add = |e: &Entry| {
        let mut atts: Vec<_> = e.attachments.iter().collect();
        atts.sort_by(|a, b| cmp_utf16(&a.name, &b.name));
        for a in atts {
            if !out.iter().any(|p| **p == *a.data) {
                out.push(Arc::clone(&a.data));
            }
        }
    };
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        g.entries.iter().for_each(&mut add);
        g.entries
            .iter()
            .flat_map(|e| e.history.iter())
            .for_each(&mut add);
        stack.extend(g.groups.iter().rev());
    }
    out
}

fn custom_data(cd: &CustomData, sh: Shape, vault_level: bool) -> Option<El> {
    if cd.items.is_empty() {
        return None;
    }
    let items = cd
        .items
        .iter()
        .map(|i| {
            let mut kids = vec![leaf("Key", i.key.clone()), leaf("Value", i.value.clone())];
            if let (true, true, Some(t)) = (vault_level, sh.v41(), i.last_modified) {
                kids.push(leaf("LastModificationTime", time(t, sh)));
            }
            node("Item", kids)
        })
        .collect();
    Some(node("CustomData", items))
}

fn times(t: &larsal_model::Times, sh: Shape) -> El {
    node(
        "Times",
        vec![
            leaf("LastModificationTime", time(t.last_modification, sh)),
            leaf("CreationTime", time(t.creation, sh)),
            leaf("LastAccessTime", time(t.last_access, sh)),
            leaf("ExpiryTime", time(t.expiry, sh)),
            leaf("Expires", b(t.expires)),
            leaf("UsageCount", t.usage_count.to_string()),
            leaf("LocationChanged", time(t.location_changed, sh)),
        ],
    )
}

fn icon(kids: &mut Vec<El>, i: Icon) {
    match i {
        Icon::Standard(n) => kids.push(leaf("IconID", n.to_string())),
        Icon::Custom(id) => {
            kids.push(leaf("IconID", "0"));
            kids.push(leaf("CustomIconUUID", uuid_to_text(id)));
        }
    }
}

struct Ctx<'a> {
    sh: Shape,
    vault: &'a Vault,
    pool: Vec<Arc<larsal_crypto::secret::SecretBytes>>,
}

fn entry(e: &Entry, cx: &Ctx<'_>, live: bool) -> El {
    let sh = cx.sh;
    let mut k = vec![leaf("UUID", uuid_to_text(e.uuid))];
    icon(&mut k, e.icon);
    k.push(leaf("ForegroundColor", e.foreground_color.clone()));
    k.push(leaf("BackgroundColor", e.background_color.clone()));
    k.push(leaf("OverrideURL", e.override_url.clone()));
    k.push(leaf("Tags", e.tags().join(",")));
    k.push(times(&e.times, sh));
    if sh.v41() && e.exclude_from_reports {
        k.push(leaf("QualityCheck", "False"));
    }
    if sh.v41()
        && let Some(p) = e.previous_parent
    {
        k.push(leaf("PreviousParentGroup", uuid_to_text(p)));
    }
    let mp = &cx.vault.meta.memory_protection;
    for (name, f) in e.fields() {
        let protected = f.protected || (STANDARD_FIELDS.contains(&name) && mp.for_field(name));
        let mut value = leaf("Value", f.value.expose());
        if protected {
            value.attrs.push(("ProtectInMemory".into(), "True".into()));
        }
        k.push(node("String", vec![leaf("Key", name), value]));
    }
    let mut atts: Vec<_> = e.attachments.iter().collect();
    atts.sort_by(|a, b| cmp_utf16(&a.name, &b.name));
    for a in atts {
        let r = if sh.v4() {
            "0".to_owned()
        } else {
            cx.pool
                .iter()
                .position(|p| **p == *a.data)
                .unwrap_or(usize::MAX)
                .to_string()
        };
        let mut value = leaf("Value", "");
        value.attrs.push(("Ref".into(), r));
        k.push(node("Binary", vec![leaf("Key", a.name.clone()), value]));
    }
    let at = &e.auto_type;
    let mut ak = vec![
        leaf("Enabled", b(at.enabled)),
        leaf("DataTransferObfuscation", at.obfuscation.to_string()),
        leaf("DefaultSequence", at.default_sequence.clone()),
    ];
    for a in &at.associations {
        ak.push(node(
            "Association",
            vec![
                leaf("Window", a.window.clone()),
                leaf("KeystrokeSequence", a.sequence.clone()),
            ],
        ));
    }
    k.push(node("AutoType", ak));
    if sh.v4()
        && let Some(cd) = custom_data(&e.custom_data, sh, false)
    {
        k.push(cd);
    }
    if live {
        let items: Vec<El> = e.history.iter().map(|h| entry(h, cx, false)).collect();
        k.push(if items.is_empty() {
            leaf("History", "")
        } else {
            node("History", items)
        });
    }
    node("Entry", k)
}

fn group(g: &Group, cx: &Ctx<'_>) -> El {
    let sh = cx.sh;
    let mut k = vec![
        leaf("UUID", uuid_to_text(g.uuid)),
        leaf("Name", g.name.clone()),
        leaf("Notes", g.notes.clone()),
    ];
    if sh.v41() && !g.tags.is_empty() {
        k.push(leaf("Tags", g.tags.clone()));
    }
    icon(&mut k, g.icon);
    k.push(times(&g.times, sh));
    k.push(leaf("IsExpanded", b(g.expanded)));
    k.push(leaf("DefaultAutoTypeSequence", g.default_sequence.clone()));
    k.push(leaf("EnableAutoType", switch(g.auto_type)));
    k.push(leaf("EnableSearching", switch(g.searching)));
    k.push(leaf("LastTopVisibleEntry", uuid(g.last_top_visible_entry)));
    if sh.v4()
        && let Some(cd) = custom_data(&g.custom_data, sh, false)
    {
        k.push(cd);
    }
    if sh.v41()
        && let Some(p) = g.previous_parent
    {
        k.push(leaf("PreviousParentGroup", uuid_to_text(p)));
    }
    k.extend(g.entries.iter().map(|e| entry(e, cx, true)));
    k.extend(g.groups.iter().map(|c| group(c, cx)));
    node("Group", k)
}

/// The export element tree of a vault.
pub fn export_tree(v: &Vault, sh: Shape) -> El {
    let cx = Ctx {
        sh,
        vault: v,
        pool: pool(&v.root),
    };
    let m = &v.meta;
    let mp = &m.memory_protection;
    let mut k = vec![
        leaf("DatabaseName", m.name.clone()),
        leaf("DatabaseNameChanged", time(m.name_changed, sh)),
        leaf("DatabaseDescription", m.description.clone()),
        leaf(
            "DatabaseDescriptionChanged",
            time(m.description_changed, sh),
        ),
        leaf("DefaultUserName", m.default_user_name.clone()),
        leaf(
            "DefaultUserNameChanged",
            time(m.default_user_name_changed, sh),
        ),
        leaf(
            "MaintenanceHistoryDays",
            m.maintenance_history_days.to_string(),
        ),
        leaf("Color", m.color.clone()),
        leaf("MasterKeyChanged", time(m.master_key_changed, sh)),
        leaf("MasterKeyChangeRec", m.master_key_change_rec.to_string()),
        leaf(
            "MasterKeyChangeForce",
            m.master_key_change_force.to_string(),
        ),
        node(
            "MemoryProtection",
            vec![
                leaf("ProtectTitle", b(mp.title)),
                leaf("ProtectUserName", b(mp.user_name)),
                leaf("ProtectPassword", b(mp.password)),
                leaf("ProtectURL", b(mp.url)),
                leaf("ProtectNotes", b(mp.notes)),
            ],
        ),
    ];
    let icons: Vec<El> = m
        .custom_icons
        .iter()
        .map(|i| {
            let mut ik = vec![leaf("UUID", uuid_to_text(i.uuid))];
            if sh.v41() && !i.name.is_empty() {
                ik.push(leaf("Name", i.name.clone()));
            }
            if let (true, Some(t)) = (sh.v41(), i.last_modified) {
                ik.push(leaf("LastModificationTime", time(t, sh)));
            }
            ik.push(leaf("Data", base64_encode(&i.data)));
            node("Icon", ik)
        })
        .collect();
    k.push(if icons.is_empty() {
        leaf("CustomIcons", "")
    } else {
        node("CustomIcons", icons)
    });
    k.extend([
        leaf("RecycleBinEnabled", b(m.recycle_bin_enabled)),
        leaf("RecycleBinUUID", uuid(m.recycle_bin)),
        leaf("RecycleBinChanged", time(m.recycle_bin_changed, sh)),
        leaf("EntryTemplatesGroup", uuid(m.entry_templates_group)),
        leaf(
            "EntryTemplatesGroupChanged",
            time(m.entry_templates_group_changed, sh),
        ),
        leaf("LastSelectedGroup", uuid(m.last_selected_group)),
        leaf("LastTopVisibleGroup", uuid(m.last_top_visible_group)),
        leaf("HistoryMaxItems", m.history_max_items.to_string()),
        leaf("HistoryMaxSize", m.history_max_size.to_string()),
    ]);
    if sh.v4() {
        k.push(leaf("SettingsChanged", time(m.settings_changed, sh)));
    } else {
        let items: Vec<El> = cx
            .pool
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let mut e = leaf("Binary", base64_encode(data.expose()));
                e.attrs.push(("ID".into(), i.to_string()));
                if sh.compressed {
                    e.attrs.push(("Compressed".into(), "True".into()));
                }
                e
            })
            .collect();
        k.push(if items.is_empty() {
            leaf("Binaries", "")
        } else {
            node("Binaries", items)
        });
    }
    if let Some(cd) = custom_data(&m.custom_data, sh, true) {
        k.push(cd);
    }
    let deleted: Vec<El> = v
        .deleted_objects
        .iter()
        .map(|d| {
            node(
                "DeletedObject",
                vec![
                    leaf("UUID", uuid_to_text(d.uuid)),
                    leaf("DeletionTime", time(d.deleted_at, sh)),
                ],
            )
        })
        .collect();
    let root = node(
        "Root",
        vec![
            group(&v.root, &cx),
            if deleted.is_empty() {
                leaf("DeletedObjects", "")
            } else {
                node("DeletedObjects", deleted)
            },
        ],
    );
    node(
        std::str::from_utf8(ROOT_NAME).unwrap(),
        vec![node("Meta", k), root],
    )
}

/// to_json.py `normalize`: CustomData items sorted by key; volatile items
/// (`_LAST_MODIFIED`, keys ending in `_RANDOM_SLUG`) get "normalized" in
/// every field but `Key`.
fn normalize(el: &mut El) {
    if el.name == "CustomData" {
        let key = |e: &El| {
            e.kids
                .iter()
                .find(|k| k.name == "Key")
                .and_then(|k| k.text.clone())
                .unwrap_or_default()
        };
        el.kids.sort_by_key(key);
        for item in &mut el.kids {
            let k = key(item);
            if k == "_LAST_MODIFIED" || k.ends_with("_RANDOM_SLUG") {
                for f in item.kids.iter_mut().filter(|f| f.name != "Key") {
                    f.text = Some("normalized".into());
                }
            }
        }
    }
    el.kids.iter_mut().for_each(normalize);
}

fn convert(el: &El) -> Value {
    if el.attrs.is_empty() && el.kids.is_empty() {
        return Value::String(el.text.clone().unwrap_or_default());
    }
    let mut obj = Map::new();
    for (k, v) in &el.attrs {
        obj.insert(format!("@{k}"), Value::String(v.clone()));
    }
    if el.kids.is_empty() {
        obj.insert(
            "#text".into(),
            Value::String(el.text.clone().unwrap_or_default()),
        );
    }
    let mut count: BTreeMap<&str, usize> = BTreeMap::new();
    for kid in &el.kids {
        *count.entry(kid.name.as_str()).or_default() += 1;
    }
    for kid in &el.kids {
        let v = convert(kid);
        if count[kid.name.as_str()] > 1 {
            obj.entry(kid.name.clone())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .unwrap()
                .push(v);
        } else {
            obj.insert(kid.name.clone(), v);
        }
    }
    Value::Object(obj)
}

/// The name guard's banned words (scripts/check-names.sh `WORDS_HEX`).
pub fn banned() -> Vec<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/check-names.sh");
    let script = std::fs::read_to_string(path).expect("name guard script");
    let line = script
        .lines()
        .find_map(|l| l.strip_prefix("WORDS_HEX=\""))
        .expect("WORDS_HEX line");
    line.trim_end_matches('"')
        .split_whitespace()
        .map(|h| String::from_utf8(hex(h)).unwrap())
        .collect()
}

fn hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn clean_str(s: &str, words: &[String]) -> String {
    let low = s.to_lowercase();
    if words.iter().any(|w| low.contains(w.as_str())) {
        format!(
            "hex:{}",
            s.bytes().map(|b| format!("{b:02x}")).collect::<String>()
        )
    } else {
        s.to_owned()
    }
}

fn clean(v: Value, words: &[String]) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| (clean_str(&k, words), clean(v, words)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(|v| clean(v, words)).collect()),
        Value::String(s) => Value::String(clean_str(&s, words)),
        other => other,
    }
}

/// The expected-content JSON of a vault, as to_json.py writes it.
pub fn vault_to_json(v: &Vault, sh: Shape) -> Value {
    let mut tree = export_tree(v, sh);
    normalize(&mut tree);
    let mut top = Map::new();
    top.insert(tree.name.clone(), convert(&tree));
    clean(Value::Object(top), &banned())
}

/// Replaces each compressed `Meta/Binaries/Binary` text of an expected JSON
/// with the base64 of its gunzipped content: gzip bytes depend on the
/// compressor, the content does not.
pub fn normalize_expected(mut json: Value) -> Value {
    let words = banned();
    let root = clean_str(std::str::from_utf8(ROOT_NAME).unwrap(), &words);
    if let Some(bins) = json
        .get_mut(&root)
        .and_then(|r| r.get_mut("Meta"))
        .and_then(|m| m.get_mut("Binaries"))
    {
        let items: Vec<&mut Value> = match bins {
            Value::Array(_) => unreachable!(),
            Value::Object(o) => match o.get_mut("Binary") {
                Some(Value::Array(a)) => a.iter_mut().collect(),
                Some(one) => vec![one],
                None => Vec::new(),
            },
            _ => Vec::new(),
        };
        for item in items {
            let compressed = item.get("@Compressed").and_then(Value::as_str) == Some("True");
            let text = item
                .get("#text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            if compressed && !text.is_empty() {
                let mut raw = Vec::new();
                flate2::read::GzDecoder::new(base64_decode(&text).as_slice())
                    .read_to_end(&mut raw)
                    .unwrap();
                if let Some(t) = item.get_mut("#text") {
                    *t = Value::String(base64_encode(&raw));
                }
            }
        }
    }
    json
}

/// The first path where two JSON values differ, for a readable failure.
pub fn first_diff(a: &Value, b: &Value, path: &str) -> Option<String> {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for k in x.keys().chain(y.keys()) {
                match (x.get(k), y.get(k)) {
                    (Some(p), Some(q)) => {
                        if let Some(d) = first_diff(p, q, &format!("{path}/{k}")) {
                            return Some(d);
                        }
                    }
                    (p, q) => return Some(format!("{path}/{k}: {p:?} vs {q:?}")),
                }
            }
            None
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                return Some(format!("{path}: {} items vs {}", x.len(), y.len()));
            }
            x.iter()
                .zip(y)
                .enumerate()
                .find_map(|(i, (p, q))| first_diff(p, q, &format!("{path}[{i}]")))
        }
        _ if a == b => None,
        _ => Some(format!("{path}: {a} vs {b}")),
    }
}

// --- the other direction, for documents rebuilt from an export ------------

fn unhex(s: &str) -> String {
    match s.strip_prefix("hex:") {
        Some(h) => String::from_utf8(hex(h)).unwrap(),
        None => s.to_owned(),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\r', "&#13;")
}

fn xml_of(name: &str, v: &Value, out: &mut String) {
    let name = unhex(name);
    match v {
        Value::String(s) => out.push_str(&format!("<{name}>{}</{name}>", esc(&unhex(s)))),
        Value::Object(o) => {
            out.push_str(&format!("<{name}"));
            for (k, v) in o.iter().filter(|(k, _)| k.starts_with('@')) {
                out.push_str(&format!(" {}=\"{}\"", &k[1..], esc(v.as_str().unwrap())));
            }
            out.push('>');
            if let Some(t) = o.get("#text").and_then(Value::as_str) {
                out.push_str(&esc(&unhex(t)));
            }
            // The export writes `IconID` before `CustomIconUUID`, and the
            // order matters on read (FMT-11.11); keys are sorted otherwise.
            let mut kids: Vec<_> = o
                .iter()
                .filter(|(k, _)| !k.starts_with('@') && *k != "#text")
                .collect();
            kids.sort_by_key(|(k, _)| *k != "IconID");
            for (k, v) in kids {
                match v {
                    Value::Array(items) => items.iter().for_each(|i| xml_of(k, i, out)),
                    one => xml_of(k, one, out),
                }
            }
            out.push_str(&format!("</{name}>"));
        }
        _ => panic!("unexpected JSON value at {name}"),
    }
}

/// An XML document rebuilt from an expected JSON (the export it came from,
/// with sibling order by name and without the dropped `Generator`).
pub fn json_to_xml(json: &Value) -> String {
    let (name, v) = json.as_object().unwrap().iter().next().unwrap();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    xml_of(name, v, &mut out);
    out
}
