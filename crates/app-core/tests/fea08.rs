//! Story E4-S13, card FEA-08 (import): one test per case (`fea08_NN_…`),
//! sections A to J. Import time 2026-10-25T10:00:00Z, UTC unless a case
//! says otherwise.
//!
//! Test files: CSV, Proton Pass and plain Bitwarden inputs are demo JSON and
//! text written here. The two password-protected Bitwarden files in
//! `tests/data/` were made by `scripts/testdata/make_import_samples.py`
//! with Python's hashlib and hmac and the `openssl enc` command (not App's
//! code): `bw-encrypted-pbkdf2.json` (password `demo-pass`, PBKDF2 5,000
//! rounds, salt text `c2FsdA==`, the card's case 08-44 inputs) and
//! `bw-encrypted-argon2.json` (password `demo-argon-pass`, Argon2id 3
//! iterations, 64 MiB, 4 lanes). Part 2's files come from the same script
//! (Python zipfile, hashlib, hmac and `openssl enc`): `demo.1pux`,
//! `demo.opvault/` (password `demo-opv-pass`, PBKDF2-SHA512 1,000
//! rounds), and the version 1 files `v1-aes.bin` (`demo-v1-pass`, 50
//! AES-KDF rounds), `v1-keyfile-hex.bin` (key file `v1-hex.appkey`),
//! `v1-composite.bin` (`demo-v1-pass` and `v1-binary.appkey`),
//! `v1-keyfile-hashed.bin` (`v1-hashed.appkey`) and `v1-cp1252.bin`
//! (`„password”`). No file from another tool is used (LD-143 (14)).
//!
//! Screen-only parts (the assistant's clicks, the banner, a memory dump)
//! are E5's and the Verify agent's; each test says which part it covers.

mod common;

use app_core::import::csv::{self, Encoding, Options, Problem, Question, Target};
use app_core::import::{
    self, Context, ImportError, Imported, Kind, Limit, PASSWORD_MASK, SkipReason, bitwarden,
    onepux, opvault, proton, v1,
};
use app_core::recycle::{BIN_ICON, BIN_NAME};
use app_core::time::{Utc, Zone};
use app_core::totp;
use app_crypto::kdf::{self, Prf};
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::{CustomIcon, Encryption, Entry, Field, Group, Icon, Switch, Time, Uuid, Vault};
use common::{Berlin, at};
use std::sync::atomic::{AtomicBool, Ordering};

static NO_CANCEL: AtomicBool = AtomicBool::new(false);
const PBKDF2_FILE: &str = include_str!("data/bw-encrypted-pbkdf2.json");
const ARGON2_FILE: &str = include_str!("data/bw-encrypted-argon2.json");

fn now() -> Time {
    at(2026, 10, 25, 10, 0, 0)
}

fn ctx() -> Context<'static> {
    ctx_in(&Utc)
}

fn ctx_in(zone: &dyn Zone) -> Context<'_> {
    Context::new(now(), zone, &NO_CANCEL)
}

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sub<'a>(g: &'a Group, name: &str) -> &'a Group {
    g.groups
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("group {name}"))
}

fn titled<'a>(g: &'a Group, title: &str) -> &'a Entry {
    g.entries
        .iter()
        .find(|e| e.value("Title") == title)
        .unwrap_or_else(|| panic!("entry {title}"))
}

fn find<'a>(v: &'a Vault, title: &str) -> &'a Entry {
    v.root
        .all_entries()
        .find(|e| e.value("Title") == title)
        .unwrap_or_else(|| panic!("entry {title}"))
}

fn names(g: &Group) -> Vec<&str> {
    g.groups.iter().map(|c| c.name.as_str()).collect()
}

fn protected(e: &Entry, name: &str) -> bool {
    e.field(name)
        .unwrap_or_else(|| panic!("field {name}"))
        .protected
}

/// The custom field whose name is `base` + `_` + 5 lowercase hex digits.
fn suffixed<'a>(e: &'a Entry, base: &str) -> &'a str {
    let (_, f) = e
        .fields()
        .find(|(n, _)| {
            n.strip_prefix(base)
                .and_then(|r| r.strip_prefix('_'))
                .is_some_and(|h| {
                    h.len() == 5
                        && h.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
        })
        .unwrap_or_else(|| panic!("suffixed {base}"));
    f.value.expose()
}

fn parse(text: &str, o: Options) -> csv::Parsed {
    csv::parse(text.as_bytes(), &o).unwrap()
}

fn rows(p: &csv::Parsed) -> Vec<Vec<String>> {
    (0..p.rows())
        .map(|r| (0..p.columns).map(|c| p.cell(r, c).to_owned()).collect())
        .collect()
}

fn csv_import_in(text: &str, zone: &dyn Zone) -> Imported {
    let p = parse(text, Options::default());
    let map = csv::auto_map(&p, None);
    let (skip, _) = p.skip_range();
    csv::build(&p, &map, skip, "/tmp/a.csv", &ctx_in(zone)).unwrap()
}

fn csv_import(text: &str) -> Imported {
    csv_import_in(text, &Utc)
}

fn bw(json: &str) -> Imported {
    bitwarden::read(json.as_bytes(), None, &ctx()).unwrap()
}

fn bw_err(json: &str, password: &str) -> ImportError {
    bitwarden::read(json.as_bytes(), Some(&secret(password)), &ctx()).unwrap_err()
}

fn set(e: &mut Entry, name: &str, v: &str) {
    e.set_field(
        name.into(),
        Field {
            value: secret(v),
            protected: false,
        },
    );
}

fn entry(id: u8, title: &str) -> Entry {
    let mut e = Entry::new(Uuid([id; 16]), at(2026, 1, 1, 0, 0, 0));
    set(&mut e, "Title", title);
    e
}

fn group(id: u8, name: &str) -> Group {
    Group::new(Uuid([id; 16]), name.into(), at(2026, 1, 1, 0, 0, 0))
}

/// A hand-built import result (part 2's readers make the same shape).
fn result(root: Group) -> Imported {
    Imported {
        vault: Vault::new(root, now()),
        trashed: Vec::new(),
        skipped: Vec::new(),
    }
}

/// Target vault: root "Root" (01) with group Work (02).
fn target() -> Vault {
    let mut root = group(0x01, "Root");
    root.groups.push(group(0x02, "Work"));
    Vault::new(root, at(2026, 1, 1, 0, 0, 0))
}

fn ok(v: &Vault) {
    assert_eq!(app_model::invariants::check(v), Ok(()));
}

// -- A. The assistant and placement --------------------------------------

#[test]
fn fea08_01_kinds() {
    assert_eq!(
        import::KINDS,
        [
            Kind::Csv,
            Kind::OnePux,
            Kind::OpVault,
            Kind::Bitwarden,
            Kind::Proton,
            Kind::V1
        ]
    );
    let v1 = Kind::V1.fields();
    assert!(v1.file && v1.password && v1.key_file);
    for k in [Kind::Csv, Kind::OnePux, Kind::Proton] {
        let f = k.fields();
        assert!(f.file && !f.password && !f.key_file, "{k:?}");
    }
    for k in [Kind::Bitwarden, Kind::OpVault] {
        let f = k.fields();
        assert!(f.file && f.password && !f.key_file, "{k:?}");
    }
    assert!(!Kind::Remote.fields().file);
}

/// F-112 (INT-09.30, T51): while remote sync is not built the assistant
/// lists no IMP-REMOTE kind.
#[test]
fn f_112_no_remote_vault_kind_is_listed() {
    assert!(!import::KINDS.contains(&Kind::Remote));
}

#[test]
fn fea08_02_targets() {
    let mut root = group(0x01, "Root");
    let mut work = group(0x02, "Work");
    work.groups.push(group(0x03, "Sub"));
    let mut bin = group(0x04, "Recycle Bin");
    bin.groups.push(group(0x05, "Old"));
    root.groups.push(work);
    root.groups.push(bin);
    let mut v = Vault::new(root, now());
    v.meta.recycle_bin = Some(Uuid([0x04; 16]));
    let rows: Vec<String> = import::target_rows("Demo", &v)
        .into_iter()
        .map(|r| r.text)
        .collect();
    assert_eq!(rows, ["Demo (Root)", "  / Work", "  / Work / Sub"]);
    assert_eq!(import::target_rows("Demo", &v)[2].group, Uuid([0x03; 16]));
}

#[test]
fn fea08_03_preview_mask() {
    let r = bw(
        r#"{"folders":[],"items":[{"name":"One","login":{"username":"u","password":"demo-pw"}},{"name":"Two"}]}"#,
    );
    let rows = import::preview(&r);
    assert_eq!(rows.len(), 2, "Entry count: 2");
    assert_eq!(rows[0].password, PASSWORD_MASK);
    assert_eq!(rows[1].password, "");
    assert_eq!(
        (rows[0].title.as_str(), rows[0].user_name.as_str()),
        ("One", "u")
    );
    // The rows the screen gets never hold the password.
    assert!(!format!("{rows:?}").contains("demo-pw"));
}

#[test]
fn fea08_04_new_vault() {
    let r = csv_import("Group,Title\nPersonal,A\nPersonal/Sub,B\n");
    assert_eq!(r.vault.root.name, "Personal");
    // APP-07's new vault, with its own encryption settings.
    let mut new = Vault::new(group(0x09, "New vault"), now());
    new.encryption = Encryption::default();
    let before = new.encryption;
    import::into_new_vault(&mut new, r, now()).unwrap();
    assert_eq!(new.root.name, "Personal");
    assert_eq!(new.root.notes, "Imported from CSV file: /tmp/a.csv");
    assert_eq!(
        new.root.uuid,
        Uuid([0x09; 16]),
        "the new vault's root stays"
    );
    assert_eq!(titled(&new.root, "A").value("Title"), "A");
    assert_eq!(titled(sub(&new.root, "Sub"), "B").value("Title"), "B");
    assert_eq!(new.encryption, before, "cipher and KDF stay APP-07's");
    ok(&new);
    // Cancel in APP-07: the result is dropped (and wiped); nothing is made.
    drop(csv_import("Title\nX\n"));
}

#[test]
fn placement_icon_rules() {
    let png = vec![0x89, b'P', b'N', b'G', 1, 2, 3];
    let other = vec![0x89, b'P', b'N', b'G', 9];
    let icon = |id: u8, data: &[u8]| CustomIcon {
        uuid: Uuid([id; 16]),
        name: String::new(),
        last_modified: None,
        data: data.to_vec(),
        unknown: Vec::new(),
    };
    let mut g = group(0x21, "G");
    g.icon = Icon::Custom(Uuid([0x31; 16]));
    let mut e = entry(0x22, "E");
    e.icon = Icon::Custom(Uuid([0x32; 16]));
    let mut h = entry(0x22, "E");
    h.icon = Icon::Custom(Uuid([0x33; 16]));
    e.history.push(h);
    g.entries.push(e);
    let mut root = group(0x20, "Root");
    root.groups.push(g);
    let mut r = result(root);
    r.vault.meta.custom_icons = vec![
        icon(0x31, &png),
        icon(0x32, &other),
        icon(0x33, b"h"),
        icon(0x34, b"unused"),
    ];
    let mut t = target();
    // The target already has `png` under another id, and a different icon
    // under 0x32's id.
    t.meta.custom_icons = vec![icon(0x41, &png), icon(0x32, b"taken")];
    import::into_group(&mut t, Uuid([0x02; 16]), r, now()).unwrap();
    let g = sub(sub(sub(&t.root, "Work"), "Root"), "G");
    let e = titled(g, "E");
    let data = |i: Icon| match i {
        Icon::Custom(id) => t
            .meta
            .custom_icons
            .iter()
            .find(|c| c.uuid == id)
            .map(|c| c.data.clone()),
        Icon::Standard(_) => None,
    };
    assert_eq!(
        data(g.icon),
        Some(png.clone()),
        "nested group icon present (reused)"
    );
    assert_eq!(g.icon, Icon::Custom(Uuid([0x41; 16])));
    assert_eq!(
        data(e.icon),
        Some(other),
        "entry icon copied, fresh id for the clash"
    );
    assert_ne!(e.icon, Icon::Custom(Uuid([0x32; 16])));
    assert_eq!(data(e.history[0].icon), Some(b"h".to_vec()));
    assert_eq!(
        t.meta.custom_icons.len(),
        4,
        "unused icon not copied, equal one reused"
    );
    ok(&t);
}

#[test]
fn placement_id_rules() {
    let mut t = target();
    t.root.entries.push(entry(0x01, "Existing"));
    let mut e = entry(0x01, "Imported");
    e.history = vec![entry(0x01, "old 1"), entry(0x01, "old 2")];
    let mut keep = entry(0x07, "No clash");
    keep.history = vec![entry(0x07, "h")];
    // The group id clashes with the target's Work group.
    let mut g = group(0x02, "Same id as Work");
    g.entries.push(keep);
    let mut root = group(0x30, "Import");
    root.entries.push(e);
    root.groups.push(g);
    let into = t.root.uuid;
    import::into_group(&mut t, into, result(root), now()).unwrap();
    let imported = find(&t, "Imported");
    assert_ne!(imported.uuid, Uuid([0x01; 16]));
    assert!(imported.history.iter().all(|h| h.uuid == imported.uuid));
    assert_eq!(find(&t, "Existing").uuid, Uuid([0x01; 16]));
    assert_eq!(
        find(&t, "No clash").uuid,
        Uuid([0x07; 16]),
        "ids without a clash stay"
    );
    let moved = sub(sub(&t.root, "Import"), "Same id as Work");
    assert_ne!(moved.uuid, Uuid([0x02; 16]));
    ok(&t);
}

#[test]
fn placement_trashed_rules() {
    let make = || {
        let mut root = group(0x30, "Import");
        root.entries.push(entry(0x31, "Kept"));
        root.entries.push(entry(0x32, "Trashed"));
        let mut r = result(root);
        r.trashed = vec![Uuid([0x32; 16])];
        r
    };
    // Bin on, no bin yet: made per MOD-04.2.
    let mut t = target();
    import::into_group(&mut t, Uuid([0x02; 16]), make(), now()).unwrap();
    let bin_id = t.meta.recycle_bin.expect("a bin was made");
    let bin = t.root.groups.iter().find(|g| g.uuid == bin_id).unwrap();
    assert_eq!(
        (bin.name.as_str(), bin.icon),
        (BIN_NAME, Icon::Standard(BIN_ICON))
    );
    assert_eq!(
        t.root.groups.last().unwrap().uuid,
        bin_id,
        "last child of the root"
    );
    assert_eq!(t.meta.recycle_bin_changed, now());
    titled(bin, "Trashed");
    let import_root = sub(sub(&t.root, "Work"), "Import");
    assert_eq!(import_root.entries.len(), 1);
    titled(import_root, "Kept");
    ok(&t);
    // Bin off: a normal group named like the bin, under the moved root.
    let mut t = target();
    t.meta.recycle_bin_enabled = false;
    import::into_group(&mut t, Uuid([0x02; 16]), make(), now()).unwrap();
    assert!(t.meta.recycle_bin.is_none());
    let plain = sub(sub(sub(&t.root, "Work"), "Import"), BIN_NAME);
    titled(plain, "Trashed");
    assert_eq!(plain.icon, Icon::Standard(BIN_ICON), "LD-148");
    assert_eq!(
        (plain.searching, plain.auto_type),
        (Switch::Off, Switch::Off)
    );
    ok(&t);
    // Into a new vault: its bin.
    let mut new = Vault::new(group(0x09, "New"), now());
    import::into_new_vault(&mut new, make(), now()).unwrap();
    let bin_id = new.meta.recycle_bin.unwrap();
    titled(
        new.root.groups.iter().find(|g| g.uuid == bin_id).unwrap(),
        "Trashed",
    );
    titled(&new.root, "Kept");
    ok(&new);
}

#[test]
fn fea08_08_defaults() {
    let r = csv_import("Title\nT\n");
    let e = find(&r.vault, "T");
    let t = &e.times;
    for x in [
        t.creation,
        t.last_modification,
        t.last_access,
        t.location_changed,
    ] {
        assert_eq!(x, at(2026, 10, 25, 10, 0, 0));
    }
    assert!(!t.expires);
    assert!(e.history.is_empty());
    assert!(e.tags().is_empty());
    ok(&r.vault);
}

#[test]
fn fea08_09_bare_totp() {
    let r = bw(
        r#"{"folders":[],"items":[{"name":"My Site","login":{"username":"a b","totp":"JBSWY3DP"}}]}"#,
    );
    let e = find(&r.vault, "My Site");
    assert_eq!(
        e.value("otp"),
        "otpauth://totp/My%20Site:a%20b?secret=JBSWY3DP&period=30&digits=6&issuer=My%20Site"
    );
    assert!(protected(e, "otp"));
    let s = totp::settings(e).unwrap();
    assert_eq!((s.digits, s.period), (6, 30));
    assert_eq!(s.key().unwrap().expose(), b"Hello");
    // A link that parses without a secret sets nothing (FEA-08.10).
    let none = bw(
        r#"{"folders":[],"items":[{"name":"x","login":{"totp":"otpauth://totp/x?digits=8"}},{"name":"y","login":{"totp":null}}]}"#,
    );
    assert!(
        none.vault
            .root
            .all_entries()
            .all(|e| totp::settings(e).is_none())
    );
}

#[test]
fn fea08_10_urls_and_clashes() {
    let r = bw(
        r#"{"folders":[],"items":[{"name":"U","login":{"password":"lp","uris":[{"uri":""},{"uri":"https://a/"},{"uri":"https://b/"},{"uri":null},{"uri":"https://c/"}]},
        "fields":[{"name":"Password","value":"x","type":0},{"name":"PIN","value":"1","type":0},{"name":"PIN","value":"2","type":1}]}]}"#,
    );
    let e = find(&r.vault, "U");
    assert_eq!(e.value("URL"), "https://a/");
    assert_eq!(e.value("KP2A_URL_1"), "https://b/");
    assert_eq!(e.value("KP2A_URL_2"), "https://c/");
    assert_eq!(suffixed(e, "Password"), "x");
    assert_eq!(e.value("PIN"), "1");
    assert_eq!(suffixed(e, "PIN"), "2");
    assert_eq!(e.value("Password"), "lp", "standard Password unchanged");
}

#[test]
fn fea08_11_worker_and_cancel() {
    // Core part of FEA-08.12: the reader runs on a worker thread while this
    // thread goes on, and Cancel during the derivation ends it with
    // nothing kept.
    let slow = PBKDF2_FILE.replace("\"kdfIterations\": 5000", "\"kdfIterations\": 2000000");
    let cancel = AtomicBool::new(false);
    let target = target();
    let before = target.duplicate();
    let outcome = std::thread::scope(|s| {
        let worker = s.spawn(|| {
            let c = Context::new(now(), &Utc, &cancel);
            bitwarden::read(slow.as_bytes(), Some(&secret("demo-pass")), &c)
        });
        let started = std::time::Instant::now();
        let mut ticks = 0u32;
        while started.elapsed().as_millis() < 30 {
            ticks += 1;
            std::thread::yield_now();
        }
        cancel.store(true, Ordering::Relaxed);
        assert!(ticks > 0, "the screen thread stayed responsive");
        worker.join().unwrap()
    });
    assert_eq!(outcome.unwrap_err(), ImportError::Cancelled);
    assert!(target == before, "nothing imported");
}

// -- B. CSV ----------------------------------------------------------------

#[test]
fn fea08_12_csv_defaults() {
    let o = Options::default();
    assert_eq!(o.encoding, Encoding::Utf8);
    assert_eq!((o.qualifier, o.separator, o.comment), ('"', ',', '#'));
    assert!(!o.backslash && o.first_row_names);
    assert_eq!(csv::QUALIFIERS, ['"', '\'', ':', '.', '|']);
    assert_eq!(csv::SEPARATORS, [',', ';', '-', ':', '.', '\t']);
    assert_eq!(csv::COMMENTS, ['#', ';', ':', '@']);
    let p = parse("a\nb\nc\n", o);
    assert_eq!(p.skip_range(), (1, 2), "CSV-SKIP-ROWS starts at 1");
    let off = parse(
        "a\nb\nc\n",
        Options {
            first_row_names: false,
            ..o
        },
    );
    assert_eq!(off.skip_range(), (0, 2));
    assert_eq!(parse("a\n", o).skip_range(), (1, 1));
    assert_eq!(p.size, 6);
}

#[test]
fn fea08_13_decoding() {
    let off = Options {
        first_row_names: false,
        ..Options::default()
    };
    let p = csv::parse(b"\xEF\xBB\xBFa,b", &off).unwrap();
    assert_eq!(rows(&p), [["a", "b"]]);
    let mut le = vec![0xFF, 0xFE];
    le.extend("č,d\r\ne,f".encode_utf16().flat_map(u16::to_le_bytes));
    let p = csv::parse(&le, &off).unwrap();
    assert_eq!(
        rows(&p),
        [["č", "d"], ["e", "f"]],
        "the BOM wins over UTF-8"
    );
    let mut be = vec![0xFE, 0xFF];
    be.extend("x,ü".encode_utf16().flat_map(u16::to_be_bytes));
    assert_eq!(rows(&csv::parse(&be, &off).unwrap()), [["x", "ü"]]);
    let w = Options {
        encoding: Encoding::Windows1252,
        ..off
    };
    assert_eq!(
        rows(&csv::parse(b"\x80,\x9f\x81", &w).unwrap()),
        [["€", "Ÿ\u{81}"]]
    );
    assert_eq!(
        rows(&csv::parse(b"a\xffb", &off).unwrap()),
        [["a\u{FFFD}b"]]
    );
    let le_choice = Options {
        encoding: Encoding::Utf16Le,
        ..off
    };
    let raw: Vec<u8> = "q,r".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(rows(&csv::parse(&raw, &le_choice).unwrap()), [["q", "r"]]);
    // UTF-16 without a byte order mark is little-endian (LD-148, case 08-13).
    let utf16 = Options {
        encoding: Encoding::Utf16,
        ..off
    };
    let p = csv::parse(&[0x61, 0x00, 0x2C, 0x00, 0x62, 0x00], &utf16).unwrap();
    assert_eq!(rows(&p), [["a", "b"]]);
}

#[test]
fn fea08_14_plain_and_comments() {
    let off = Options {
        first_row_names: false,
        ..Options::default()
    };
    let p = parse("  #one\n \t # two\nuseful,text #1!\nA,,B\"", off);
    assert_eq!(rows(&p), [["useful", "text #1!", ""], ["A", "", "B\""]]);
    assert!(p.problems.is_empty());
}

#[test]
fn fea08_14_tab_separator_leading_white_space() {
    // Checker 1 issue 1: the spaces and tabs read for the comment check go
    // through the field logic, so a leading TAB ends an empty first field.
    let tab = Options {
        separator: '\t',
        first_row_names: false,
        ..Options::default()
    };
    assert_eq!(rows(&parse("\tb", tab)), [["", "b"]]);
    assert_eq!(rows(&parse(" \tc", tab)), [[" ", "c"]]);
    assert_eq!(
        rows(&parse("\t\t\"q\"\nz\t\ty", tab)),
        [["", "", "q"], ["z", "", "y"]]
    );
    // The comment check still comes first (FEA-08.15).
    assert_eq!(rows(&parse("\t # x\n\tb", tab)), [["", "b"]]);
    assert_eq!(
        rows(&parse(" \t\"q\"", tab)),
        [[" ", "q"]],
        "a quoted field after the TAB"
    );
    // With the comma separator the leading spaces stay field text.
    let comma = Options {
        first_row_names: false,
        ..Options::default()
    };
    assert_eq!(rows(&parse(" \t\"q\",x", comma)), [[" \t\"q\"", "x"]]);
}

#[test]
fn fea08_19_screen_names_mask() {
    // LD-144: a file without a header row and "first row as names" on: the
    // screen gets row 1's names only through screen_names, which masks a
    // column mapped to Password or TOTP.
    let p = parse(
        "demo-title,demo-secret-pw,JBSWY3DP\nT,P,S",
        Options::default(),
    );
    let mut map: csv::Mapping = [None; 11];
    map[1] = Some(0);
    map[3] = Some(1);
    map[7] = Some(2);
    let shown = p.screen_names(&map);
    assert_eq!(shown, ["demo-title", PASSWORD_MASK, PASSWORD_MASK]);
    assert!(!format!("{p:?}").contains("demo-secret-pw"));
    map[3] = None;
    assert_eq!(
        p.screen_names(&map)[1],
        "demo-secret-pw",
        "unmapped: the name"
    );
}

#[test]
fn fea08_15_quoted() {
    let off = Options {
        first_row_names: false,
        ..Options::default()
    };
    let p = parse("ro,w,\"end, of \"\"\"\"\"\"row\"\"\"\"\"\n2", off);
    assert_eq!(p.cell(0, 2), "end, of \"\"\"row\"\"");
    assert_eq!(p.cell(1, 0), "2");
    let colon = Options {
        qualifier: ':',
        ..off
    };
    let p = parse(":1\r\n2a::b:,:3\r4:", colon);
    assert_eq!(rows(&p), [["1\n2a:b", "3\n4"]]);
    assert!(p.problems.is_empty());
}

#[test]
fn fea08_16_malformed() {
    let o = Options {
        qualifier: ':',
        first_row_names: false,
        ..Options::default()
    };
    let p = parse("A,B,C\n:BM::,1,:2:", o);
    assert_eq!(p.problems, [Problem::Malformed { record: 2 }]);
    // L08-7g: the character after the closing qualifier starts a record.
    assert_eq!(p.cell(1, 0), "BM:,1,");
    assert_eq!(p.cell(2, 0), "2:");
    let map = csv::auto_map(&p, None);
    assert_eq!(csv::questions(&p, &map)[0], Question::ImportAnyway);
}

#[test]
fn fea08_17_unclosed() {
    let o = Options {
        qualifier: ':',
        ..Options::default()
    };
    let p = parse("A,B\n:BM,1", o);
    assert_eq!(p.problems, [Problem::Unclosed { record: 2 }]);
    assert_eq!(p.cell(1, 0), "BM,1");
}

#[test]
fn fea08_18_backslash() {
    let o = Options {
        backslash: true,
        qualifier: 'X',
        first_row_names: false,
        ..Options::default()
    };
    let p = parse("Xone\\\"\\\\t\\\\\\\"w\noX", o);
    assert_eq!(p.cell(0, 0), "one\"\\t\\\"w\no");
    // A field starting with a backslash is plain (L08-7e).
    let p = parse("XaX,\\Xc", o);
    assert_eq!(rows(&p), [["a", "\\Xc"]]);
    assert!(p.problems.is_empty());
    // A doubled qualifier is no escape then: the first one closes.
    let p = parse("XaXXb", o);
    assert_eq!(
        p.problems,
        [
            Problem::Malformed { record: 1 },
            Problem::Unclosed { record: 2 }
        ]
    );
    assert_eq!((p.cell(0, 0), p.cell(1, 0)), ("a", "b"));
    // A backslash as the last character stays a backslash.
    let p = parse("Xend\\", o);
    assert_eq!(p.cell(0, 0), "end\\");
}

#[test]
fn fea08_19_empty_and_padding() {
    let off = Options {
        first_row_names: false,
        ..Options::default()
    };
    let p = parse("1,2\n,,,,,,,,,a\na,b,c,d\n\"\"\n\"\n\"", off);
    assert_eq!(p.rows(), 3);
    assert_eq!(p.columns, 10);
    let r = rows(&p);
    assert_eq!(r[0][..2], ["1", "2"]);
    assert!(
        r[0][2..].iter().all(String::is_empty),
        "padded with 8 empty fields"
    );
    assert_eq!(r[1][9], "a");
    assert_eq!(r[2][..4], ["a", "b", "c", "d"]);
}

#[test]
fn fea08_20_names_and_mapping() {
    let p = parse("title,USERNAME,,Pass\nT,U,x,P", Options::default());
    let none: csv::Mapping = [None; 11];
    assert_eq!(
        p.screen_names(&none),
        ["title", "USERNAME", "Column 2", "Pass"]
    );
    let map = csv::auto_map(&p, None);
    let at = |t: Target| map[csv::TARGETS.iter().position(|x| *x == t).unwrap()];
    assert_eq!(at(Target::Title), Some(0));
    assert_eq!(at(Target::Username), Some(1));
    assert_eq!(at(Target::Password), None);
    // A manual choice survives a parse with the same names, not new ones.
    let mut chosen = map;
    chosen[3] = Some(3);
    assert_eq!(csv::auto_map(&p, Some((&p, &chosen)))[3], Some(3));
    let other = parse("x", Options::default());
    assert_eq!(csv::auto_map(&p, Some((&other, &chosen)))[3], None);
    let off = parse(
        "a,b",
        Options {
            first_row_names: false,
            ..Options::default()
        },
    );
    assert_eq!(off.screen_names(&none), ["Column 0", "Column 1"]);
    // FEA-09.3's header maps all 10 of its columns by itself.
    let p = parse(app_core::export::csv::HEADER, Options::default());
    let map = csv::auto_map(&p, None);
    assert_eq!(map.iter().filter(|m| m.is_some()).count(), 10);
    assert_eq!(map[5], None, "no Tags column");
}

#[test]
fn fea08_21_skip() {
    let p = parse("# c\nTitle\n\nT1\nT2", Options::default());
    assert_eq!(p.rows(), 3, "records Title, T1, T2");
    let map = csv::auto_map(&p, None);
    let r = csv::build(&p, &map, 2, "/tmp/s.csv", &ctx()).unwrap();
    let titles: Vec<&str> = r
        .vault
        .root
        .all_entries()
        .map(|e| e.value("Title"))
        .collect();
    assert_eq!(titles, ["T2"]);
}

#[test]
fn fea08_22_no_title() {
    let p = parse("Name,Password\nn,p", Options::default());
    let map = csv::auto_map(&p, None);
    assert_eq!(map[1], None);
    assert_eq!(csv::questions(&p, &map), [Question::NoTitle]);
    // With parse problems as well, the import-anyway question comes first.
    let bad = parse("Name\n\"a\"b", Options::default());
    let map = csv::auto_map(&bad, None);
    assert_eq!(
        csv::questions(&bad, &map),
        [Question::ImportAnyway, Question::NoTitle]
    );
}

#[test]
fn fea08_23_common_root_case() {
    let r = csv_import("Group,Title\nPasswords/Work,a\npasswords/Home,b\nPasswords,c\n");
    let root = &r.vault.root;
    assert_eq!(root.name, "Passwords");
    assert_eq!(names(root), ["Passwords", "passwords"]);
    let upper = sub(root, "Passwords");
    assert_eq!(names(upper), ["Work"]);
    titled(upper, "c");
    titled(sub(sub(root, "passwords"), "Home"), "b");
}

#[test]
fn fea08_24_root_skip() {
    let r = csv_import("Group,Title\nPersonal/Work,a\nPersonal/Work/Sub,b\nPersonal,c\n");
    let root = &r.vault.root;
    assert_eq!(root.name, "Personal");
    assert_eq!(root.notes, "Imported from CSV file: /tmp/a.csv");
    let work = sub(root, "Work");
    titled(work, "a");
    titled(sub(work, "Sub"), "b");
    titled(root, "c");
    // A//B/: empty parts dropped. No Group column or no rows: Passwords.
    let r = csv_import("Group,Title\nX,1\nX//B/,2\n");
    titled(sub(&r.vault.root, "B"), "2");
    assert_eq!(csv_import("Title\nx\n").vault.root.name, "Passwords");
    assert_eq!(csv_import("Group,Title\n").vault.root.name, "Passwords");
}

#[test]
fn fea08_25_text_fields() {
    let r = csv_import("Title,Tags,TOTP,Notes\n T ,\"b, a;a\",JBSWY3DPEHPK3PXP,\"two\nlines\"\n");
    let e = find(&r.vault, " T ");
    assert_eq!(e.tags(), ["a", "b"]);
    assert_eq!(e.value("Notes"), "two\nlines");
    assert_eq!(e.value("TOTP Seed"), "JBSWY3DPEHPK3PXP");
    assert!(protected(e, "TOTP Seed"));
    assert_eq!(e.value("TOTP Settings"), "30;6");
    assert!(e.field("otp").is_none());
    let s = totp::settings(e).unwrap();
    assert_eq!((s.digits, s.period, s.form), (6, 30, totp::Form::L));
    // A link is stored in its own form, with the resolved labels.
    let r = csv_import("Title,Username,TOTP\nSite,me,otpauth://totp/x?secret=JBSWY3DP&digits=8\n");
    let e = find(&r.vault, "Site");
    assert_eq!(
        e.value("otp"),
        "otpauth://totp/Site:me?secret=JBSWY3DP&period=30&digits=8&issuer=Site"
    );
    assert!(
        protected(e, "Password"),
        "passwords are protected (MOD-12.17)"
    );
}

#[test]
fn fea08_26_icon() {
    let r = csv_import("Title,Icon\na,5\nb,69\nc,-1\nd,x\ne,68\n");
    let icon = |t: &str| find(&r.vault, t).icon;
    assert_eq!(icon("a"), Icon::Standard(5));
    for t in ["b", "c", "d"] {
        assert_eq!(icon(t), Icon::Standard(0), "{t}");
    }
    assert_eq!(icon("e"), Icon::Standard(68));
}

#[test]
fn fea08_27_times() {
    let text = "Title,Last Modified,Created\n\
                1,1700000000,\n\
                2,1700000000000,\n\
                3,2147483648,\n\
                4,2024-03-10T12:00:00+02:00,\n\
                5,20240101,\n\
                6,soon,2024-01-15 08:00\n";
    let r = csv_import_in(text, &Berlin);
    let m = |t: &str| {
        let e = find(&r.vault, t);
        assert_eq!(
            e.times.last_access, e.times.last_modification,
            "accessed equals modified"
        );
        e.times.last_modification
    };
    assert_eq!(m("1"), at(2023, 11, 14, 22, 13, 20));
    assert_eq!(m("2"), at(2023, 11, 14, 22, 13, 20));
    assert_eq!(
        m("3"),
        at(1970, 1, 25, 20, 31, 23),
        "milliseconds, whole seconds kept"
    );
    assert_eq!(m("4"), at(2024, 3, 10, 10, 0, 0));
    assert_eq!(m("5"), at(1970, 8, 23, 6, 15, 1));
    assert_eq!(m("6"), now(), "the import time stays");
    assert_eq!(find(&r.vault, "6").times.creation, at(2024, 1, 15, 7, 0, 0));
    assert_eq!(find(&r.vault, "1").times.creation, now());
}

// -- E. Bitwarden JSON -----------------------------------------------------

#[test]
fn fea08_40_bw_layout() {
    let r = bw(r#"{"items":[{"name":"x"}]}"#);
    assert_eq!(
        r.vault.root.all_entries().count(),
        0,
        "no folders: empty result"
    );
    assert_eq!(r.vault.root.name, bitwarden::ROOT);
    assert_eq!(bw(r#"{"folders":[]}"#).vault.root.all_entries().count(), 0);
    let r = bw(
        r#"{"folders":[{"id":"1","name":"A/B"},{"id":"2","name":"A//B"},{"id":"3","name":"/C"},{"id":"4","name":"/"}],
        "items":[{"name":"i1","folderId":"1"},{"name":"i2","folderId":"2"},{"name":"i3","folderId":"3"},{"name":"i4","folderId":"4"},{"name":"i5","folderId":"nope"}]}"#,
    );
    let root = &r.vault.root;
    assert_eq!(names(root), ["A", "C"]);
    let ab = sub(sub(root, "A"), "B");
    assert_eq!(ab.entries.len(), 2);
    titled(ab, "i1");
    titled(ab, "i2");
    titled(sub(root, "C"), "i3");
    titled(root, "i4");
    titled(root, "i5");
    // A folder without an id: items without a folder still go to the root.
    let r = bw(r#"{"folders":[{"name":"No id"}],"items":[{"name":"loose","folderId":null}]}"#);
    titled(&r.vault.root, "loose");
    // Organization exports: collections when folders is missing.
    let r = bw(
        r#"{"collections":[{"id":"c","name":"Team"}],"items":[{"name":"t","folderId":null,"collectionIds":["c"]}]}"#,
    );
    titled(sub(&r.vault.root, "Team"), "t");
    // A parse error: MSG-JSON with the offset.
    assert_eq!(
        bitwarden::read(b"{\"items\":[1,]}", None, &ctx()).unwrap_err(),
        ImportError::Json {
            offset: 12,
            reason: import::JsonReason::Unexpected
        }
    );
}

const BW_DEMO: &str = r#"{"encrypted":false,
 "folders":[{"id":"f1","name":"My Folder"},{"id":"f2","name":"Second Folder"}],
 "items":[
  {"id":"1","folderId":"f1","type":1,"name":"Login Name","notes":null,"favorite":true,
   "login":{"username":"demo-user@example.com","password":"demo-pass-1","totp":null,
     "uris":[{"uri":"https://example.com"},{"uri":"https://example.org"},{"uri":"https://example.net"}]},
   "fields":[{"name":"flag","value":"false","type":2},{"name":"linked","value":"x","type":3}],
   "creationDate":"2024-12-01T12:00:00.000Z","revisionDate":"2024-12-25T12:00:00.000Z",
   "passwordHistory":[{"lastUsedDate":"2024-12-01T12:00:00.000Z","password":"old-demo-pass"},
     {"lastUsedDate":"bad","password":"x"},{"lastUsedDate":"2024-12-02T00:00:00Z","password":""}]},
  {"id":"2","folderId":null,"type":4,"name":"My Identity",
   "identity":{"title":"Mx","firstName":"Demo","middleName":null,"lastName":"Person",
     "address1":" 1 Demo Street ","address2":null,"address3":"","city":"Demo City","state":"DC",
     "postalCode":"00000","country":"Demoland ","company":"","email":"demo@example.com","phone":"",
     "ssn":"000-00-0000","username":"demo-id-user","passportNumber":"P000","licenseNumber":""}},
  {"id":"3","folderId":"f2","type":3,"name":"Card Name",
   "card":{"cardholderName":"Demo Person","brand":"Visa","number":"4111111111111111","expMonth":"1","expYear":"2030","code":"123"}}
 ]}"#;

#[test]
fn fea08_41_bw_items() {
    let r = bw(BW_DEMO);
    let root = &r.vault.root;
    let login = titled(sub(root, "My Folder"), "Login Name");
    assert_eq!(login.value("UserName"), "demo-user@example.com");
    assert_eq!(login.value("URL"), "https://example.com");
    assert_eq!(login.value("KP2A_URL_1"), "https://example.org");
    assert_eq!(login.value("KP2A_URL_2"), "https://example.net");
    assert_eq!(login.tags(), ["Favorite"]);
    assert_eq!(login.value("flag"), "false");
    assert_eq!(login.value("linked"), "", "linked fields give empty");
    assert_eq!(login.times.last_modification, at(2024, 12, 25, 12, 0, 0));
    assert_eq!(login.times.last_access, at(2024, 12, 25, 12, 0, 0));
    assert_eq!(login.times.creation, at(2024, 12, 1, 12, 0, 0));
    assert_eq!(login.history.len(), 1);
    let h = &login.history[0];
    assert_eq!(h.value("Password"), "old-demo-pass");
    assert_eq!(
        (h.value("Title"), h.value("UserName"), h.value("URL")),
        ("Login Name", "demo-user@example.com", "https://example.com")
    );
    assert_eq!(h.times.last_modification, at(2024, 12, 1, 12, 0, 0));
    assert_eq!(h.times.creation, login.times.creation);
    assert_eq!(h.uuid, login.uuid);
    assert!(
        h.field("flag").is_none(),
        "custom fields are not copied into history"
    );
    let id = titled(root, "My Identity");
    assert_eq!(id.value("identity_name"), "Mx Demo Person");
    assert_eq!(
        id.value("identity_address"),
        " 1 Demo Street \nDemo City, DC 00000\nDemoland "
    );
    assert_eq!(id.value("identity_ssn"), "000-00-0000");
    assert!(protected(id, "identity_ssn") && protected(id, "identity_passportNumber"));
    assert!(!protected(id, "identity_email"));
    assert!(id.field("identity_company").is_none() && id.field("identity_licenseNumber").is_none());
    assert_eq!(
        id.value("UserName"),
        "demo-id-user",
        "identity user name into an empty Username"
    );
    let card = titled(sub(root, "Second Folder"), "Card Name");
    assert!(protected(card, "card_code"));
    assert!(!protected(card, "card_number"));
    assert_eq!(card.value("card_brand"), "Visa");
    // identity.username when Username is taken.
    let r = bw(
        r#"{"folders":[],"items":[{"name":"i","login":{"username":"first"},"identity":{"username":"second"}}]}"#,
    );
    assert_eq!(find(&r.vault, "i").value("identity_username"), "second");
    ok(&r.vault);
}

#[test]
fn fea08_42_bw_passkey() {
    let r = bw(
        r#"{"folders":[],"items":[{"name":"P","login":{"username":"u","fido2Credentials":[
        {"credentialId":"00","keyValue":"AA","rpId":"old.example","userName":"old","userHandle":"old"},
        {"credentialId":"6f1c1a2e-0d3b-4c5a-9e8f-1a2b3c4d5e6f","keyValue":"MIGHAgEAERERERERERERERERERERERERERE",
         "rpId":"example.com","userName":"demo-user","userHandle":"ZGVtby1oYW5kbGU"}]}},
        {"name":"Odd","login":{"fido2Credentials":[{"credentialId":"a-bc","keyValue":"","rpId":"x","userName":"","userHandle":""}]}}]}"#,
    );
    let e = find(&r.vault, "P");
    assert_eq!(
        e.value("KPEX_PASSKEY_CREDENTIAL_ID"),
        "bxwaLg07TFqejxorPE1ebw"
    );
    assert_eq!(e.value("KPEX_PASSKEY_RELYING_PARTY"), "example.com");
    assert_eq!(e.value("KPEX_PASSKEY_USERNAME"), "demo-user");
    assert_eq!(e.value("KPEX_PASSKEY_USER_HANDLE"), "ZGVtby1oYW5kbGU");
    assert_eq!(
        e.value("KPEX_PASSKEY_PRIVATE_KEY_PEM"),
        "-----BEGIN PRIVATE KEY-----MIGHAgEAERERERERERERERERERERERERERE=-----END PRIVATE KEY-----"
    );
    for n in [
        "KPEX_PASSKEY_CREDENTIAL_ID",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "KPEX_PASSKEY_USER_HANDLE",
    ] {
        assert!(protected(e, n), "{n}");
    }
    assert!(!protected(e, "KPEX_PASSKEY_RELYING_PARTY"));
    assert_eq!(e.tags(), ["Passkey"]);
    assert_eq!(
        find(&r.vault, "Odd").value("KPEX_PASSKEY_CREDENTIAL_ID"),
        "Crw"
    );
}

#[test]
fn fea08_42_bw_invalid_key_leaves_no_pem() {
    // LD-143 (4): a keyValue that is not valid base64url sets no PEM, and
    // removes one an earlier credential set.
    let r = bw(r#"{"folders":[],"items":[
        {"name":"Bad","login":{"fido2Credentials":[{"credentialId":"aa","keyValue":"%%%","rpId":"x","userName":"u","userHandle":"h"}]}},
        {"name":"Later bad","login":{"fido2Credentials":[
            {"credentialId":"aa","keyValue":"AAAA","rpId":"x","userName":"u","userHandle":"h"},
            {"credentialId":"bb","keyValue":"A","rpId":"y","userName":"v","userHandle":"i"}]}}]}"#);
    for t in ["Bad", "Later bad"] {
        let e = find(&r.vault, t);
        assert!(e.field("KPEX_PASSKEY_PRIVATE_KEY_PEM").is_none(), "{t}");
        assert_eq!(e.tags(), ["Passkey"]);
    }
    assert_eq!(
        find(&r.vault, "Later bad").value("KPEX_PASSKEY_RELYING_PARTY"),
        "y"
    );
}

#[test]
fn fea08_67_result_limits() {
    // The FMT-08.12 counts of the result (FEA-08.67), lowered for the test.
    let small = |f: &dyn Fn(&mut import::ResultLimits)| {
        let mut c = ctx();
        f(&mut c.limits);
        c
    };
    let csv_with = |text: &str, c: &Context<'_>| {
        let p = parse(text, Options::default());
        let map = csv::auto_map(&p, None);
        csv::build(&p, &map, 1, "/tmp/l.csv", c).err()
    };
    // Two first path parts, so no common root (FEA-08.24).
    let c = small(&|l| l.groups = 3);
    assert_eq!(csv_with("Group,Title\nA,x\nC,y\n", &c), None, "root, A, C");
    assert_eq!(
        csv_with("Group,Title\nA/B,x\nC,y\n", &c),
        Some(ImportError::TooLarge(Limit::Groups))
    );
    let c = small(&|l| l.entries = 2);
    assert_eq!(csv_with("Title\na\nb\n", &c), None);
    assert_eq!(
        csv_with("Title\na\nb\nc\n", &c),
        Some(ImportError::TooLarge(Limit::Entries))
    );
    let c = small(&|l| l.depth = 2);
    assert_eq!(csv_with("Group,Title\nA/B,x\nZ,y\n", &c), None);
    assert_eq!(
        csv_with("Group,Title\nA/B/C,x\nZ,y\n", &c),
        Some(ImportError::TooLarge(Limit::Depth))
    );
    // Fields of one entry: the five standard ones plus custom fields.
    let c = small(&|l| l.strings = 7);
    let fields = |n: usize| {
        let list: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"name":"f{i}","value":"v"}}"#))
            .collect();
        format!(
            r#"{{"folders":[],"items":[{{"name":"x","fields":[{}]}}]}}"#,
            list.join(",")
        )
    };
    assert!(bitwarden::read(fields(2).as_bytes(), None, &c).is_ok());
    assert_eq!(
        bitwarden::read(fields(3).as_bytes(), None, &c).unwrap_err(),
        ImportError::TooLarge(Limit::Strings)
    );
    // History items of one entry, and entries plus history items.
    let history = |n: usize| {
        let list: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#"{{"lastUsedDate":"2024-01-0{}T00:00:00Z","password":"p{i}"}}"#,
                    i + 1
                )
            })
            .collect();
        format!(
            r#"{{"folders":[],"items":[{{"name":"x","passwordHistory":[{}]}}]}}"#,
            list.join(",")
        )
    };
    let c = small(&|l| l.history = 2);
    assert!(bitwarden::read(history(2).as_bytes(), None, &c).is_ok());
    assert_eq!(
        bitwarden::read(history(3).as_bytes(), None, &c).unwrap_err(),
        ImportError::TooLarge(Limit::History)
    );
    let c = small(&|l| l.entry_elements = 2);
    assert!(bitwarden::read(history(1).as_bytes(), None, &c).is_ok());
    assert_eq!(
        bitwarden::read(history(2).as_bytes(), None, &c).unwrap_err(),
        ImportError::TooLarge(Limit::EntryElements)
    );
    // The defaults are the FMT-08.12 values of app-format.
    let f = app_format::limits::Limits::DEFAULT;
    let d = import::ResultLimits::DEFAULT;
    assert_eq!(
        (
            d.groups,
            d.entries,
            d.entry_elements,
            d.strings,
            d.history,
            d.attachments,
            d.one_attachment,
            d.all_attachments,
            d.icons
        ),
        (
            f.groups,
            f.entries,
            f.entry_elements,
            f.strings,
            f.history,
            f.attachments,
            f.one_attachment,
            f.all_attachments,
            f.icons
        )
    );
    assert_eq!(d.depth, app_core::edit::MAX_GROUP_LEVEL);
}

#[test]
fn fea08_43_bw_encrypted_pbkdf2() {
    // The chain against the values Python computed (make_import_samples.py).
    let pw = SecretBytes::new(b"demo-pass".to_vec());
    let k = kdf::pbkdf2(Prf::Sha256, &pw, b"c2FsdA==", 5_000, 32).unwrap();
    let enc = kdf::hkdf_expand_sha256(&k, b"enc", 32).unwrap();
    let mac = kdf::hkdf_expand_sha256(&k, b"mac", 32).unwrap();
    assert!(hex(k.expose()).starts_with("3f4717b796aa1719"));
    assert!(hex(enc.expose()).starts_with("52c30d8b3e3ceb1c"));
    assert!(hex(mac.expose()).starts_with("0bdbdb72da7019a5"));
    let r = bitwarden::read(PBKDF2_FILE.as_bytes(), Some(&secret("demo-pass")), &ctx()).unwrap();
    let e = titled(sub(&r.vault.root, "Demo Folder"), "Encrypted demo login");
    assert_eq!(e.value("Password"), "enc-demo-pw");
    assert_eq!(e.value("URL"), "https://example.com/");
    assert_eq!(e.times.creation, at(2026, 1, 2, 3, 4, 5));
    assert_eq!(bw_err(PBKDF2_FILE, "b"), ImportError::WrongPassword);
    // No password at all: refused before any derivation.
    let started = std::time::Instant::now();
    assert_eq!(
        bitwarden::read(PBKDF2_FILE.as_bytes(), None, &ctx()).unwrap_err(),
        ImportError::WrongPassword
    );
    assert!(started.elapsed().as_millis() < 100);
}

#[test]
fn fea08_44_bw_vectors() {
    let pw = SecretBytes::new(b"demo-pass".to_vec());
    let k = kdf::pbkdf2(Prf::Sha256, &pw, b"c2FsdA==", 5_000, 32).unwrap();
    assert_eq!(
        hex(k.expose()),
        "3f4717b796aa1719b2f074be9b8546b48713baa1952b33e186d3ddb6a41f6084"
    );
    let enc = kdf::hkdf_expand_sha256(&k, b"enc", 32).unwrap();
    assert_eq!(
        hex(enc.expose()),
        "52c30d8b3e3ceb1cde6ade1d2e0f3a5676421a7c0b0d503a1b8179e6d596a79d"
    );
    let mac = kdf::hkdf_expand_sha256(&k, b"mac", 32).unwrap();
    assert_eq!(
        hex(mac.expose()),
        "0bdbdb72da7019a5f97182b27155406027c9a9efdd1195612228eb344a00fb70"
    );
    let salt = app_crypto::hash::sha256(&[b"c2FsdA=="]);
    assert_eq!(
        hex(salt.expose()),
        "f0135775b8b1614b8076f40459c7fcb0aa7616b020a63d9d8b80cb2fefcb87b5"
    );
}

/// The file with one base64 character of the `data` ciphertext changed.
fn damaged_data(file: &str) -> String {
    let start = file.find("\"data\": \"2.").unwrap();
    let bar = start + file[start..].find('|').unwrap();
    let at = bar + 11;
    let old = file.as_bytes()[at];
    let new = if old == b'A' { "B" } else { "A" };
    format!("{}{}{}", &file[..at], new, &file[at + 1..])
}

#[test]
fn fea08_45_bw_argon2_and_damage() {
    let r = bitwarden::read(
        ARGON2_FILE.as_bytes(),
        Some(&secret("demo-argon-pass")),
        &ctx(),
    )
    .unwrap();
    find(&r.vault, "Encrypted demo login");
    assert_eq!(bw_err(ARGON2_FILE, "demo-pass"), ImportError::WrongPassword);
    assert_eq!(
        bw_err(&damaged_data(PBKDF2_FILE), "demo-pass"),
        ImportError::BwDamaged
    );
    assert_eq!(
        bw_err(&damaged_data(ARGON2_FILE), "demo-argon-pass"),
        ImportError::BwDamaged
    );
    let no_salt = PBKDF2_FILE.replace("\"salt\": \"c2FsdA==\",", "");
    assert_eq!(bw_err(&no_salt, "demo-pass"), ImportError::BwAccount);
    let no_kdf = PBKDF2_FILE.replace("\"kdfType\": 0,", "");
    assert_eq!(bw_err(&no_kdf, "demo-pass"), ImportError::BwAccount);
    // L08-8: type 2 and three parts in both values.
    let type1 = PBKDF2_FILE.replace("\"data\": \"2.", "\"data\": \"1.");
    assert_eq!(bw_err(&type1, "demo-pass"), ImportError::BwDamaged);
    let two_parts = PBKDF2_FILE.replacen('|', "", 1);
    assert_eq!(bw_err(&two_parts, "demo-pass"), ImportError::BwDamaged);
    let other_kdf = PBKDF2_FILE.replace("\"kdfType\": 0", "\"kdfType\": 7");
    assert_eq!(bw_err(&other_kdf, "demo-pass"), ImportError::BwKdf);
    let zero = PBKDF2_FILE.replace("\"kdfIterations\": 5000", "\"kdfIterations\": 0");
    assert_eq!(bw_err(&zero, "demo-pass"), ImportError::BwKdf);
    let negative = PBKDF2_FILE.replace("\"kdfIterations\": 5000", "\"kdfIterations\": -5");
    assert_eq!(bw_err(&negative, "demo-pass"), ImportError::BwKdf);
}

// -- F. Proton Pass JSON ---------------------------------------------------

const PROTON_DEMO: &str = r#"{"version":"1.0","userId":"u","encrypted":false,"vaults":{
 "share-b":{"name":"Test","description":"","items":[
   {"data":{"metadata":{"name":"Test note","note":"n"},"extraFields":[],"type":"note","content":{}},"state":1,"createTime":1700000000,"modifyTime":1700000100,"pinned":false}]},
 "share-a":{"name":"Personal","description":"Personal vault","items":[
   {"data":{"metadata":{"name":"Test Login","note":"login note"},
     "extraFields":[{"fieldName":"hidden field","type":"hidden","data":{"content":"hidden value"}},
       {"fieldName":"second 2fa secret","type":"totp","data":{"totpUri":"TOTPCODE"}},
       {"fieldName":"text field","type":"text","data":{"content":"t"}},
       {"fieldName":"Password","type":"text","data":{"content":"clash"}}],
     "type":"login","content":{"itemEmail":"demo@example.com","password":"demo-pw",
       "urls":["","https://example.com/","https://example2.com/"],"totpUri":"otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP","passkeys":[],"itemUsername":"Username"}},
     "state":1,"createTime":1700000000,"modifyTime":1700000200,"pinned":true},
   {"data":{"metadata":{"name":"Test Card","note":""},"extraFields":[],"type":"creditCard",
     "content":{"cardholderName":"Demo Person","cardType":0,"number":"1234222233334444","verificationNumber":"333","expirationDate":"2030-01","pin":"1234"}},"state":1,"createTime":1,"modifyTime":2},
   {"data":{"metadata":{"name":"My Deleted Note","note":"x"},"extraFields":[],"type":"note","content":{}},"state":2,"createTime":1,"modifyTime":2},
   {"data":{"metadata":{"name":"Unknown Type","note":"old"},"extraFields":[],"type":"futureKind","content":{"attr2":"value2","attr1":"value1","empty":"","n":5}},"state":1},
   {"data":{"metadata":{"name":"Wifi","note":""},"type":"WIFI","content":{"ssid":"demo-net","password":"wifi-pw","security":"WPA2"}},"state":1},
   {"data":{"metadata":{"name":"SSH","note":""},"type":"sshKey","content":{"privateKey":"demo-private","publicKey":"demo-public"}},"state":1},
   {"data":{"metadata":{"name":"Email only","note":""},"type":"login","content":{"itemEmail":"only@example.com","itemUsername":""}},"state":1}
 ]}}}"#;

#[test]
fn fea08_46_proton() {
    let r = proton::read(PROTON_DEMO.as_bytes(), &ctx()).unwrap();
    let root = &r.vault.root;
    assert_eq!(root.name, proton::ROOT);
    assert_eq!(names(root), ["Personal", "Test"], "sorted vault keys");
    let personal = sub(root, "Personal");
    assert_eq!(personal.notes, "Personal vault");
    let login = titled(personal, "Test Login");
    assert_eq!(login.value("UserName"), "Username");
    assert_eq!(login.value("login_email"), "demo@example.com");
    assert_eq!(login.value("URL"), "https://example.com/");
    assert_eq!(login.value("KP2A_URL_1"), "https://example2.com/");
    assert!(totp::settings(login).is_some(), "TOTP set");
    assert!(protected(login, "hidden field"));
    assert_eq!(login.value("second 2fa secret"), "TOTPCODE");
    assert!(!protected(login, "second 2fa secret"));
    assert_eq!(suffixed(login, "Password"), "clash");
    assert_eq!(login.tags(), ["Favorite"]);
    assert_eq!(login.value("Notes"), "login note");
    assert_eq!(login.times.creation, at(2023, 11, 14, 22, 13, 20));
    assert_eq!(login.times.last_modification, at(2023, 11, 14, 22, 16, 40));
    let card = titled(personal, "Test Card");
    assert_eq!(
        (card.value("UserName"), card.value("Password")),
        ("1234222233334444", "333")
    );
    assert!(protected(card, "card_pin"));
    assert_eq!(card.value("card_cardholderName"), "Demo Person");
    assert_eq!(card.value("card_expirationDate"), "2030-01");
    let gone = titled(personal, "My Deleted Note");
    assert!(gone.times.expires);
    assert_eq!(gone.times.expiry, now());
    let unknown = titled(personal, "Unknown Type");
    assert_eq!(
        unknown.value("Notes"),
        format!("{}\n\nold", proton::unknown_type_note("futureKind"))
    );
    assert_eq!(unknown.value("content_attr1"), "value1");
    assert_eq!(unknown.value("content_attr2"), "value2");
    assert_eq!(unknown.value("content_n"), "5");
    assert!(unknown.field("content_empty").is_none());
    assert_eq!(
        unknown.times.creation,
        Time::from_unix(0).unwrap(),
        "missing counts as 0"
    );
    let wifi = titled(personal, "Wifi");
    assert_eq!(
        (wifi.value("UserName"), wifi.value("wifi_security")),
        ("demo-net", "WPA2")
    );
    let ssh = titled(personal, "SSH");
    assert_eq!(ssh.value("ssh_public_key"), "demo-public");
    assert!(protected(ssh, "ssh_private_key"));
    assert_eq!(
        titled(personal, "Email only").value("UserName"),
        "only@example.com"
    );
    titled(sub(root, "Test"), "Test note");
    ok(&r.vault);
}

#[test]
fn fea08_47_proton_encrypted() {
    assert_eq!(
        proton::read(br#"{"encrypted":true}"#, &ctx()).unwrap_err(),
        ImportError::ProtonEncrypted
    );
    assert!(matches!(
        proton::read(b"{x", &ctx()),
        Err(ImportError::Json { offset: 1, .. })
    ));
}

// -- J. Limits and hostile files -------------------------------------------

#[test]
fn fea08_61_failure_clean() {
    // Wrong JSON types read as empty or missing values, never a crash.
    let r = bw(r#"{"folders":[],"items":5}"#);
    assert_eq!(r.vault.root.all_entries().count(), 0);
    let r = bw(
        r#"{"folders":"x","collections":[{"id":1,"name":5},{"id":"c","name":["n"]}],
        "items":[{"name":7,"login":"no","fields":{"a":1},"passwordHistory":3,"favorite":"yes","card":[1],"identity":"x"},5,null,
          {"name":"t","login":{"uris":"no","totp":5,"fido2Credentials":[1,{"credentialId":7}]},"fields":[{"name":null,"value":{"x":1},"type":"1"}],"creationDate":12}]}"#,
    );
    assert_eq!(r.vault.root.all_entries().count(), 4);
    assert_eq!(find(&r.vault, "7").value("Title"), "7");
    ok(&r.vault);
    let r = proton::read(br#"{"vaults":{"a":5,"b":{"items":[1,{"data":"x"},{"data":{"type":7,"content":[],"extraFields":{}}}]}}}"#, &ctx()).unwrap();
    assert_eq!(r.vault.root.all_entries().count(), 3);
    ok(&r.vault);
    // A failing reader returns no result; a refused placement changes nothing.
    assert!(bitwarden::read(br#"{"items":["#, None, &ctx()).is_err());
    let mut deep = target();
    let mut g = &mut deep.root;
    for i in 0..504 {
        g.groups.push(Group::new(
            Uuid([
                0x80,
                (i >> 8) as u8,
                i as u8,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                9,
            ]),
            "d".into(),
            now(),
        ));
        g = g.groups.last_mut().unwrap();
    }
    let deepest = g.uuid;
    let before = deep.duplicate();
    let r = csv_import("Group,Title\nA/B,x\n");
    assert_eq!(
        import::into_group(&mut deep, deepest, r, now()),
        Err(app_core::Error::TooDeep)
    );
    assert!(deep == before);
    let r = csv_import("Title\nx\n");
    assert_eq!(
        import::into_group(&mut deep, Uuid([0x77; 16]), r, now()),
        Err(app_core::Error::NoSuchGroup),
        "MSG-IMP-TARGET-GONE"
    );
    assert!(deep == before);
}

#[test]
fn fea08_62_secrets() {
    // Core part of FEA-08.66 (the memory dump and log read are the Verify
    // agent's, AT-C01 and AT-C06): debug output and error texts hold no
    // value from the file; values live in secret types.
    let r = bw(
        r#"{"folders":[],"items":[{"name":"S","login":{"password":"demo-pw","totp":"JBSWY3DP"},"fields":[{"name":"k","value":"demo-field","type":1}]}]}"#,
    );
    let shown = format!("{r:?} {:?}", r.vault.root);
    for secret in ["demo-pw", "demo-field", "JBSWY3DP"] {
        assert!(!shown.contains(secret), "{secret}");
    }
    let e = bitwarden::read(br#"{"items":[{"password":"demo-pw" x}]}"#, None, &ctx()).unwrap_err();
    assert!(!format!("{e} {e:?}").contains("demo-pw"));
    assert_eq!(
        e.to_string(),
        "not valid JSON at byte 32: a separator or closing bracket is missing"
    );
    for e in [
        ImportError::WrongPassword,
        ImportError::BwDamaged,
        ImportError::TooLarge(Limit::Columns),
        ImportError::KdfCost,
    ] {
        assert!(!e.to_string().is_empty());
    }
    // The file is read into wiping memory.
    let dir = std::env::temp_dir().join(format!("fea08-62-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("in.json");
    std::fs::write(&path, b"{\"items\":[]}").unwrap();
    let bytes: SecretBytes = import::read_file(&path, import::MAX_FILE).unwrap();
    assert_eq!(bytes.expose(), b"{\"items\":[]}");
    assert_eq!(
        import::read_file(&dir.join("missing"), import::MAX_FILE).unwrap_err(),
        ImportError::NoFile
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fea08_63_limits() {
    // JSON nested 600 deep, both readers.
    let deep = format!("{{\"items\":{}{}}}", "[".repeat(600), "]".repeat(600));
    assert_eq!(
        bitwarden::read(deep.as_bytes(), None, &ctx()).unwrap_err(),
        ImportError::TooLarge(Limit::Depth)
    );
    assert_eq!(
        proton::read(deep.as_bytes(), &ctx()).unwrap_err(),
        ImportError::TooLarge(Limit::Depth)
    );
    assert_eq!(
        ImportError::TooLarge(Limit::Depth).to_string(),
        "too large: nesting depth"
    );
    // CSV with 10,001 columns; 10,000 is fine.
    let wide = |n: usize| vec!["a"; n].join(",");
    assert_eq!(
        csv::parse(wide(10_001).as_bytes(), &Options::default()).unwrap_err(),
        ImportError::TooLarge(Limit::Columns)
    );
    assert_eq!(
        csv::parse(wide(10_000).as_bytes(), &Options::default())
            .unwrap()
            .columns,
        10_000
    );
    // 1,000,001 records; empty ones do not count.
    let many = "a\n".repeat(1_000_001);
    assert_eq!(
        csv::parse(many.as_bytes(), &Options::default()).unwrap_err(),
        ImportError::TooLarge(Limit::Records)
    );
    assert_eq!(
        csv::parse("\n".repeat(2_000_000).as_bytes(), &Options::default())
            .unwrap()
            .rows(),
        0
    );
    // One JSON text over 64 MiB.
    let mut big = b"{\"items\":[\"".to_vec();
    big.resize(big.len() + (64 << 20) + 1, b'a');
    big.extend(b"\"]}");
    assert_eq!(
        bitwarden::read(&big, None, &ctx()).unwrap_err(),
        ImportError::TooLarge(Limit::Text)
    );
    // A file over 256 MiB is refused from its size, before any allocation
    // (a sparse file: nothing is written).
    let dir = std::env::temp_dir().join(format!("fea08-63-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.csv");
    std::fs::File::create(&path)
        .unwrap()
        .set_len((256 << 20) + 1)
        .unwrap();
    assert_eq!(
        import::read_file(&path, import::MAX_FILE).unwrap_err(),
        ImportError::TooLarge(Limit::File)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fea08_64_kdf_cost() {
    let started = std::time::Instant::now();
    let pbkdf2 = PBKDF2_FILE.replace("\"kdfIterations\": 5000", "\"kdfIterations\": 10000001");
    assert_eq!(bw_err(&pbkdf2, "demo-pass"), ImportError::KdfCost);
    let memory = ARGON2_FILE.replace("\"kdfMemory\": 64", "\"kdfMemory\": 2048");
    assert_eq!(bw_err(&memory, "demo-argon-pass"), ImportError::KdfCost);
    for (from, to) in [
        ("\"kdfIterations\": 3", "\"kdfIterations\": 101"),
        ("\"kdfParallelism\": 4", "\"kdfParallelism\": 17"),
        ("\"kdfParallelism\": 4", "\"kdfParallelism\": null"),
    ] {
        assert_eq!(
            bw_err(&ARGON2_FILE.replace(from, to), "demo-argon-pass"),
            ImportError::KdfCost,
            "{to}"
        );
    }
    assert!(started.elapsed().as_millis() < 500, "no derivation ran");
}

// -- Part 2 helpers ----------------------------------------------------------

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// An OPVault `default` folder in memory.
struct Mem(Vec<(String, Vec<u8>)>);

impl opvault::Folder for Mem {
    fn file(&self, name: &str, max: u64, over: Limit) -> Result<Option<SecretBytes>, ImportError> {
        match self.0.iter().find(|(n, _)| n == name) {
            None => Ok(None),
            Some((_, b)) if b.len() as u64 > max => Err(ImportError::TooLarge(over)),
            Some((_, b)) => Ok(Some(SecretBytes::new(b.clone()))),
        }
    }
    fn names(&self) -> Result<Vec<String>, ImportError> {
        Ok(self.0.iter().map(|(n, _)| n.clone()).collect())
    }
}

impl Mem {
    fn set(&mut self, name: &str, bytes: Vec<u8>) {
        self.0.retain(|(n, _)| n != name);
        self.0.push((name.to_owned(), bytes));
    }
    fn text(&self, name: &str) -> String {
        String::from_utf8(self.0.iter().find(|(n, _)| n == name).unwrap().1.clone()).unwrap()
    }
}

fn demo_opv() -> Mem {
    let dir = format!(
        "{}/tests/data/demo.opvault/default",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    Mem(files)
}

fn opv(mem: &Mem, name: &str, pw: &str) -> Result<Imported, ImportError> {
    opvault::read(mem, name, Some(&secret(pw)), &ctx())
}

fn opv_demo() -> Imported {
    opv(&demo_opv(), "demo.opvault", "demo-opv-pass").unwrap()
}

fn host() -> app_crypto::kdf::Host {
    app_crypto::kdf::Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(app_crypto::kdf::SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

const CEILINGS: app_crypto::kdf::Ceilings = app_crypto::kdf::Ceilings {
    refuse_iterations: 1_000_000_000,
    ask_memory_kib: 1_048_576,
    ask_lanes: 128,
    ask_ms: 10_000,
};

fn v1_outcome(
    file: &[u8],
    pw: Option<&str>,
    kf: Option<&[u8]>,
) -> Result<v1::Outcome, ImportError> {
    let pw = pw.map(secret);
    let kf = kf.map(|k| SecretBytes::new(k.to_vec()));
    let keys = v1::Keys {
        password: pw.as_ref(),
        key_file: kf.as_ref(),
    };
    v1::read(file, &keys, &mut host(), &CEILINGS, None, &ctx())
}

fn v1_read(file: &[u8], pw: Option<&str>, kf: Option<&[u8]>) -> Result<Imported, ImportError> {
    match v1_outcome(file, pw, kf)? {
        v1::Outcome::Imported(r) => Ok(*r),
        v1::Outcome::Ask(_) => panic!("no question expected"),
    }
}

fn v1_demo() -> Imported {
    v1_read(&data("v1-aes.bin"), Some("demo-v1-pass"), None).unwrap()
}

/// The final key of a version 1 header for a password (the FEA-08.54
/// chain through app-crypto), to re-encrypt demo content.
fn v1_key(header: &[u8], pw: &str) -> SecretBytes {
    use app_crypto::kdf::{KdfParams, Verdict};
    let rounds = u32::from_le_bytes(header[120..124].try_into().unwrap());
    let params = KdfParams::AesKdf {
        rounds: u64::from(rounds),
        seed: header[88..120].to_vec(),
    };
    let Verdict::Run(c) = kdf::assess(&params, &mut host(), &CEILINGS, None).unwrap() else {
        panic!("cheap")
    };
    let t = kdf::derive(&app_crypto::hash::sha256(&[pw.as_bytes()]), &c).unwrap();
    app_crypto::hash::sha256(&[&header[16..32], t.expose()])
}

/// The demo plaintext (decrypted from `v1-aes.bin`).
fn v1_plain() -> Vec<u8> {
    let file = data("v1-aes.bin");
    let key = v1_key(&file, "demo-v1-pass");
    let plain = app_crypto::cipher::decrypt(
        app_crypto::cipher::Cipher::Aes256Cbc,
        &key,
        &file[32..48],
        &file[124..],
    )
    .unwrap();
    plain.expose().to_vec()
}

/// A version 1 file with `plain` as content, re-encrypted with the demo
/// header's key.
fn v1_wrap(plain: &[u8], groups: u32, entries: u32, flags: u32) -> Vec<u8> {
    let mut file = data("v1-aes.bin");
    file.truncate(124);
    file[8..12].copy_from_slice(&flags.to_le_bytes());
    file[48..52].copy_from_slice(&groups.to_le_bytes());
    file[52..56].copy_from_slice(&entries.to_le_bytes());
    file[56..88].copy_from_slice(app_crypto::hash::sha256(&[plain]).expose());
    let key = v1_key(&file, "demo-v1-pass");
    let cipher = if flags & 8 != 0 {
        app_crypto::cipher::Cipher::Twofish256Cbc
    } else {
        app_crypto::cipher::Cipher::Aes256Cbc
    };
    let content = app_crypto::cipher::encrypt(cipher, &key, &file[32..48], plain).unwrap();
    file.extend(content);
    file
}

/// A ZIP file for tests: (name, content, deflate, declared size).
fn zip(members: &[(&str, &[u8], bool, Option<u32>)]) -> Vec<u8> {
    use std::io::Write;
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, content, deflate, declared) in members {
        let body = if *deflate {
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(content).unwrap();
            e.finish().unwrap()
        } else {
            content.to_vec()
        };
        let mut crc = flate2::Crc::new();
        crc.update(content);
        let method: u16 = if *deflate { 8 } else { 0 };
        let size = declared.unwrap_or(content.len() as u32);
        let offset = out.len() as u32;
        let head = |v: &mut Vec<u8>| {
            v.extend(method.to_le_bytes());
            v.extend([0u8; 4]);
            v.extend(crc.sum().to_le_bytes());
            v.extend((body.len() as u32).to_le_bytes());
            v.extend(size.to_le_bytes());
            v.extend((name.len() as u16).to_le_bytes());
            v.extend(0u16.to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend([20, 0, 0, 0]);
        head(&mut out);
        out.extend(name.as_bytes());
        out.extend(&body);
        cd.extend(0x0201_4b50u32.to_le_bytes());
        cd.extend([20, 0, 20, 0, 0, 0]);
        head(&mut cd);
        // Comment length, disk, internal and external attributes.
        cd.extend([0u8; 10]);
        cd.extend(offset.to_le_bytes());
        cd.extend(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend(&cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend([0u8; 2]);
    out
}

/// The field named 5 lowercase hex digits + `_` + `tail` (an empty
/// section title gives a random prefix, FEA-08.31).
fn prefixed<'a>(e: &'a Entry, tail: &str) -> &'a Field {
    e.fields()
        .find(|(n, _)| {
            n.len() == 6 + tail.len()
                && n.ends_with(&format!("_{tail}"))
                && n[..5]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .map(|(_, f)| f)
        .unwrap_or_else(|| panic!("prefixed {tail}"))
}

fn attachment<'a>(e: &'a Entry, name: &str) -> &'a [u8] {
    e.attachments
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("attachment {name}"))
        .data
        .expose()
}

// -- A, placement with real readers ------------------------------------------

#[test]
fn fea08_05_existing_vault_icons() {
    // The version 1 demo: entry "Custom Icon" in group "Internet" uses a
    // custom icon (meta record, FEA-08.58); imported into Work.
    let r = v1_demo();
    let mut t = target();
    import::into_group(&mut t, Uuid([0x02; 16]), r, now()).unwrap();
    let internet = sub(sub(sub(&t.root, "Work"), "Root"), "Internet");
    let e = titled(internet, "Custom Icon");
    let Icon::Custom(id) = e.icon else {
        panic!("custom icon")
    };
    let icon = t
        .meta
        .custom_icons
        .iter()
        .find(|i| i.uuid == id)
        .expect("in the target's list");
    assert!(icon.data.starts_with(b"\x89PNG"));
    let Icon::Custom(mail) = sub(sub(sub(&t.root, "Work"), "Root"), "eMail").icon else {
        panic!("group icon")
    };
    assert_eq!(mail, id, "one icon, shared by the entry and the group");
    ok(&t);
}

#[test]
fn fea08_06_id_clash() {
    let mut t = target();
    t.root.entries.push(entry(0x00, "Existing"));
    t.root.entries[0].uuid = Uuid([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let r = opv_demo();
    let into = t.root.uuid;
    import::into_group(&mut t, into, r, now()).unwrap();
    let e = find(&t, "Demo login");
    assert_ne!(
        e.uuid,
        Uuid([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
    assert!(e.history.iter().all(|h| h.uuid == e.uuid));
    assert_eq!(
        find(&t, "Existing").uuid,
        Uuid([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(
        find(&t, "My Credit Card").uuid.0[15],
        2,
        "ids without a clash stay"
    );
    ok(&t);
}

#[test]
fn fea08_07_trashed() {
    let r = opv_demo();
    assert_eq!(r.trashed.len(), 1);
    let mut t = target();
    import::into_group(&mut t, Uuid([0x02; 16]), r, now()).unwrap();
    let bin_id = t.meta.recycle_bin.expect("a bin was made (MOD-04.2)");
    let bin = t.root.groups.iter().find(|g| g.uuid == bin_id).unwrap();
    assert_eq!(bin.name, BIN_NAME);
    titled(bin, "Trashed Password");
    assert!(
        !sub(sub(&t.root, "Work"), "demo")
            .entries
            .iter()
            .any(|e| e.value("Title") == "Trashed Password")
    );
    ok(&t);
}

// -- C. The .1pux format ------------------------------------------------------

#[test]
fn fea08_28_1pux_container() {
    assert_eq!(
        onepux::read(b"just text, renamed x.1pux", &ctx()).unwrap_err(),
        ImportError::OnePuxNotZip
    );
    let no_data = zip(&[("export.attributes", b"{}", false, None)]);
    assert_eq!(
        onepux::read(&no_data, &ctx()).unwrap_err(),
        ImportError::OnePuxNoData
    );
    let bad = zip(&[("EXPORT.DATA", b"{bad", true, None)]);
    assert!(matches!(
        onepux::read(&bad, &ctx()),
        Err(ImportError::Json { offset: 1, .. })
    ));
    // LD-142 (2): ZIP64, encryption and other methods are refused.
    let mut zip64 = no_data.clone();
    let n = zip64.len();
    zip64[n - 12..n - 10].copy_from_slice(&[0xFF, 0xFF]);
    zip64[n - 14..n - 12].copy_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        onepux::read(&zip64, &ctx()).unwrap_err(),
        ImportError::ZipUnsupported
    );
    let mut encrypted = data("demo.1pux");
    let cd = encrypted
        .windows(4)
        .position(|w| w == [0x50, 0x4B, 0x01, 0x02])
        .unwrap();
    encrypted[cd + 8] |= 1;
    assert_eq!(
        onepux::read(&encrypted, &ctx()).unwrap_err(),
        ImportError::ZipUnsupported
    );
    let mut bzip = data("demo.1pux");
    bzip[cd + 10] = 12;
    assert_eq!(
        onepux::read(&bzip, &ctx()).unwrap_err(),
        ImportError::ZipUnsupported
    );
    // A wrong CRC is damage.
    let mut crc = zip(&[("export.data", b"{}", false, None)]);
    let content = 30 + "export.data".len();
    crc[content] = b'[';
    assert_eq!(
        onepux::read(&crc, &ctx()).unwrap_err(),
        ImportError::OnePuxNotZip
    );
}

#[test]
fn fea08_29_1pux_items() {
    let r = onepux::read(&data("demo.1pux"), &ctx()).unwrap();
    let root = &r.vault.root;
    assert_eq!(root.name, onepux::ROOT);
    assert_eq!(
        names(root),
        ["Personal", "Shared"],
        "a vault needs attrs and items; one account"
    );
    let personal = sub(root, "Personal");
    let Icon::Custom(avatar) = personal.icon else {
        panic!("avatar icon")
    };
    let icon = r
        .vault
        .meta
        .custom_icons
        .iter()
        .find(|i| i.uuid == avatar)
        .unwrap();
    assert_eq!(icon.data, b"\x89PNG\r\n\x1a\ndemo-avatar");
    let login = titled(personal, "Login");
    assert_eq!(login.value("UserName"), "demo-user@example.com");
    assert_eq!(login.value("Password"), "password");
    assert_eq!(login.value("Notes"), "Note to self");
    assert_eq!(login.value("URL"), "https://example.com/");
    assert_eq!(login.value("KP2A_URL_1"), "https://example.org/");
    assert!(login.field("KP2A_URL_2").is_none());
    assert_eq!(login.tags(), ["Favorite", "work"]);
    assert_eq!(
        login.value("otp"),
        "otpauth://totp/Login:demo-user%40example.com?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Login"
    );
    assert_eq!(
        login.value("otp_1"),
        "otpauth://totp/Login:demo-user%40example.com?secret=JBSWY3DP"
    );
    assert!(protected(login, "otp_1"));
    let pin = prefixed(login, "pin");
    assert_eq!((pin.value.expose(), pin.protected), ("1234", true));
    assert_eq!(login.value("More_born"), "2023-11-14T22:13:20Z");
    assert_eq!(login.value("More_mail"), "a@example.com");
    assert_eq!(
        login.value("More_home"),
        "1 Demo St\nDemo City, DC 00000\nDemoland"
    );
    assert_eq!(login.value("More_until"), "202206");
    assert!(
        login.field("More_obj").is_none() && login.field("More_zero").is_none(),
        "empty results set nothing"
    );
    assert_eq!(attachment(login, "note.txt"), b"attachment one\n");
    let second = login
        .attachments
        .iter()
        .find(|a| a.name.ends_with("_note.txt"))
        .unwrap();
    assert_eq!(second.data.expose(), b"attachment two\n");
    assert_eq!(login.times.creation, at(2023, 11, 14, 22, 13, 20));
    assert_eq!(login.times.last_modification, at(2023, 11, 14, 22, 15, 0));
    let archived = titled(personal, "Login Archived");
    assert_eq!(archived.tags(), ["Archived"]);
    assert_eq!(archived.value("Password"), "uuid005password");
    assert!(
        r.vault
            .root
            .all_entries()
            .all(|e| e.value("Title") != "dropped")
    );
    ok(&r.vault);
}

#[test]
fn fea08_30_1pux_times() {
    let r = onepux::read(&data("demo.1pux"), &ctx()).unwrap();
    let e = find(&r.vault, "No times");
    assert_eq!(e.times.creation, at(1970, 1, 1, 0, 0, 0));
    assert!(
        e.attachments.is_empty(),
        "a missing member is skipped without error"
    );
}

// -- D. OPVault -----------------------------------------------------------------

#[test]
fn fea08_31_opv_layout() {
    let dir = std::env::temp_dir().join(format!("fea08-31-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("demo.opvault")).unwrap();
    assert_eq!(
        opvault::DiskFolder::open(&dir.join("demo.opvault")).unwrap_err(),
        ImportError::OpvLayout
    );
    assert_eq!(
        opvault::DiskFolder::open(&dir.join("missing.opvault")).unwrap_err(),
        ImportError::OpvLayout
    );
    std::fs::remove_dir_all(&dir).unwrap();
    // The demo's profile.js ends with `;` and a line feed: it reads.
    let mem = demo_opv();
    assert!(mem.text("profile.js").ends_with(";\n"));
    // From disk too.
    let disk = opvault::DiskFolder::open(std::path::Path::new(&format!(
        "{}/tests/data/demo.opvault",
        env!("CARGO_MANIFEST_DIR")
    )))
    .unwrap();
    assert!(
        opvault::read(
            &disk,
            "demo.opvault",
            Some(&secret("demo-opv-pass")),
            &ctx()
        )
        .is_ok()
    );
    let mut no_object = demo_opv();
    no_object.set("profile.js", b"var profile=[1];".to_vec());
    assert_eq!(
        opv(&no_object, "d", "demo-opv-pass").unwrap_err(),
        ImportError::OpvLayout
    );
    let mut missing = demo_opv();
    missing.0.retain(|(n, _)| n != "profile.js");
    assert_eq!(
        opv(&missing, "d", "demo-opv-pass").unwrap_err(),
        ImportError::OpvLayout
    );
}

#[test]
fn fea08_33_opv_keys() {
    // PBKDF2-SHA512, 1,000 rounds; the MAC key validates masterKey
    // (336 bytes: L = 256, P = 16).
    let mem = demo_opv();
    let profile = mem.text("profile.js");
    let master = profile
        .split("\"masterKey\": \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let blob = app_crypto::base64::decode(app_crypto::base64::Form::Padded, master).unwrap();
    assert_eq!(blob.len(), 336);
    assert_eq!(u64::from_le_bytes(blob[8..16].try_into().unwrap()), 256);
    assert!(opv(&mem, "demo.opvault", "demo-opv-pass").is_ok());
    assert_eq!(
        opv(&mem, "demo.opvault", "b").unwrap_err(),
        ImportError::WrongPassword
    );
    assert_eq!(
        opvault::read(&mem, "demo.opvault", None, &ctx()).unwrap_err(),
        ImportError::WrongPassword
    );
}

#[test]
fn fea08_34_opv_items() {
    let r = opv_demo();
    let root = &r.vault.root;
    let login = sub(root, "Login");
    let e = titled(login, "Demo login");
    assert_eq!(
        e.uuid,
        Uuid([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(e.value("UserName"), "demo-user");
    assert_eq!(e.value("Password"), "opvault");
    assert_eq!(e.value("Notes"), "demo note");
    assert_eq!(e.value("URL"), "https://example.com");
    assert_eq!(e.value("KP2A_URL_1"), "https://example.org");
    assert_eq!(e.tags(), ["demo"]);
    assert_eq!(
        e.value("otp"),
        "otpauth://totp/Demo%20login:demo-user?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Demo%20login"
    );
    assert_eq!(e.value("otp_1"), "JBSWY3DP");
    assert!(protected(e, "otp_1"));
    assert_eq!(attachment(e, "attachment.txt"), b"attachment");
    assert_eq!(
        e.attachments.len(),
        1,
        "the trashed and the damaged attachment are skipped"
    );
    assert_eq!(e.times.creation, Time::from_unix(1_600_000_001).unwrap());
    assert_eq!(
        e.times.last_modification,
        Time::from_unix(1_600_000_101).unwrap()
    );
    titled(login, "Expired Login");
    let card = titled(sub(root, "Credit Card"), "My Credit Card");
    assert_eq!(card.value("cardholder name"), "Demo Person");
    assert_eq!(card.value("Additional Details_PIN"), "1234");
    assert!(protected(card, "Additional Details_PIN"));
    let complex = titled(sub(root, "Password"), "Complex Password");
    let s = totp::settings(complex).unwrap();
    assert_eq!((s.digits, s.period), (8, 45));
    titled(sub(root, "Secure Note"), "Second band");
    titled(root, "Unknown category");
    let trashed = titled(root, "Trashed Password");
    assert_eq!(r.trashed, [trashed.uuid]);
    for g in &root.groups {
        assert!(
            !g.entries.is_empty() || !g.groups.is_empty(),
            "empty group {} kept",
            g.name
        );
    }
    assert_eq!(
        names(root),
        ["Login", "Credit Card", "Secure Note", "Password"],
        "code order"
    );
    // The import report.
    let skipped: Vec<(&str, SkipReason)> = r
        .skipped
        .iter()
        .map(|s| (s.item.as_str(), s.reason))
        .collect();
    assert!(skipped.contains(&("00000000000000000000000000000006", SkipReason::CheckFailed)));
    assert!(
        skipped
            .iter()
            .any(|(n, r)| n.ends_with("3333.attachment") && *r == SkipReason::Attachment)
    );
    ok(&r.vault);
}

#[test]
fn fea08_42_opv_too_large_attachment_is_skipped() {
    // LD-146: an attachment file over the limit skips only that attachment.
    let mut c = ctx();
    c.limits.one_attachment = 1;
    let r = opvault::read(
        &demo_opv(),
        "demo.opvault",
        Some(&secret("demo-opv-pass")),
        &c,
    )
    .unwrap();
    let e = titled(sub(&r.vault.root, "Login"), "Demo login");
    assert!(e.attachments.is_empty());
    let count = |r: &Imported| {
        r.skipped
            .iter()
            .filter(|s| s.reason == SkipReason::Attachment)
            .count()
    };
    assert!(count(&r) > count(&opv_demo()));
    ok(&r.vault);
}

#[test]
fn fea08_35_opv_folders() {
    let r = opv_demo();
    let root = &r.vault.root;
    assert!(!names(root).contains(&"F") && !names(root).contains(&"Smart"));
    assert_eq!(sub(root, "Login").entries.len(), 2);
}

#[test]
fn fea08_36_opv_k_size_and_uuid() {
    let r = opv_demo();
    let titles: Vec<&str> = r
        .vault
        .root
        .all_entries()
        .map(|e| e.value("Title"))
        .collect();
    assert!(
        !titles.contains(&"Short k")
            && !titles.contains(&"Short uuid")
            && !titles.contains(&"Bad check")
    );
    assert_eq!(titles.len(), 7);
    let skipped: Vec<(&str, SkipReason)> = r
        .skipped
        .iter()
        .map(|s| (s.item.as_str(), s.reason))
        .collect();
    assert!(skipped.contains(&("00000000000000000000000000000007", SkipReason::Damaged)));
    assert!(skipped.contains(&("0000000000000000000000000000008", SkipReason::Damaged)));
}

#[test]
fn fea08_37_opv_root() {
    let r = opv(&demo_opv(), "x.opvault.opvault", "demo-opv-pass").unwrap();
    let root = &r.vault.root;
    assert_eq!(root.name, "x");
    let mut id = [0u8; 16];
    id[0] = 0xE4;
    id[1] = 0xF7;
    id[14] = 0xA4;
    id[15] = 0xEE;
    assert_eq!(root.uuid, Uuid(id));
    assert_eq!(root.times.creation, at(2020, 4, 18, 14, 9, 9));
}

#[test]
fn fea08_38_opv_section_names() {
    let r = opv_demo();
    let e = find(&r.vault, "Demo login");
    assert_eq!(suffixed(e, "Password"), "s3");
    let (_, f) = e
        .fields()
        .find(|(n, _)| n.starts_with("Password_"))
        .unwrap();
    assert!(f.protected);
    assert_eq!(e.value("Extra_PIN"), "1");
    assert!(!protected(e, "Extra_PIN"));
    assert_eq!(e.value("Extra_born"), "2023-11-14");
    assert_eq!(e.value("Extra_home_city"), "Demo City");
    assert_eq!(e.value("Extra_home_street"), "1 Demo St");
}

#[test]
fn fea08_39_opv_expiry() {
    let r = opv_demo();
    let e = find(&r.vault, "Expired Login");
    assert!(e.times.expires);
    assert_eq!(e.times.expiry, at(2025, 6, 1, 0, 0, 0));
}

// -- G. The version 1 format ----------------------------------------------------

#[test]
fn fea08_48_v1_header() {
    let mut cipher = vec![
        0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5, 0x01, 0, 0, 0, 0x02, 0, 0x03, 0,
    ];
    cipher.resize(124, 0);
    assert_eq!(
        v1_outcome(&cipher, Some("x"), None).unwrap_err(),
        ImportError::V1Cipher
    );
    let mut version = cipher.clone();
    version[8] = 0x02;
    version[12..16].copy_from_slice(&[0x02, 0x00, 0x04, 0x00]);
    assert_eq!(
        v1_outcome(&version, Some("x"), None).unwrap_err(),
        ImportError::V1Version
    );
    assert_eq!(
        v1_outcome(&cipher[..100], Some("x"), None).unwrap_err(),
        ImportError::V1Damaged
    );
    let mut other = cipher.clone();
    other[4] = 0x67;
    assert_eq!(
        v1_outcome(&other, Some("x"), None).unwrap_err(),
        ImportError::V1NotVault
    );
}

#[test]
fn fea08_49_v1_key() {
    let file = data("v1-aes.bin");
    assert_eq!(
        u32::from_le_bytes(file[48..52].try_into().unwrap()),
        6,
        "6 groups"
    );
    assert_eq!(
        u32::from_le_bytes(file[52..56].try_into().unwrap()),
        9,
        "9 entry records"
    );
    assert_eq!(
        u32::from_le_bytes(file[120..124].try_into().unwrap()),
        50,
        "50 rounds"
    );
    let r = v1_demo();
    assert_eq!(
        r.vault.root.all_entries().count(),
        7,
        "7 entries, 2 meta records not imported"
    );
    assert_eq!(
        v1_read(&file, Some("wrong"), None).unwrap_err(),
        ImportError::WrongCredentials
    );
    // The content hash is checked: one changed plaintext byte fails.
    let mut plain = v1_plain();
    let hash_ok = v1_wrap(&plain, 6, 9, 2);
    assert!(v1_read(&hash_ok, Some("demo-v1-pass"), None).is_ok());
    plain[30] ^= 1;
    let mut bad = v1_wrap(&plain, 6, 9, 2);
    bad[56..88].copy_from_slice(&file[56..88]);
    assert_eq!(
        v1_read(&bad, Some("demo-v1-pass"), None).unwrap_err(),
        ImportError::WrongCredentials
    );
}

#[test]
fn fea08_50_v1_key_files() {
    let hex = data("v1-hex.appkey");
    assert_eq!(hex.len(), 64);
    let r = v1_read(&data("v1-keyfile-hex.bin"), None, Some(&hex)).unwrap();
    assert_eq!(r.vault.root.name, "Root");
    let binary = data("v1-binary.appkey");
    assert_eq!(binary.len(), 32);
    assert!(
        v1_read(
            &data("v1-composite.bin"),
            Some("demo-v1-pass"),
            Some(&binary)
        )
        .is_ok()
    );
    assert_eq!(
        v1_read(&data("v1-composite.bin"), Some("demo-v1-pass"), None).unwrap_err(),
        ImportError::WrongCredentials
    );
    let hashed = data("v1-hashed.appkey");
    assert!(v1_read(&data("v1-keyfile-hashed.bin"), None, Some(&hashed)).is_ok());
    assert_eq!(
        v1_read(&data("v1-keyfile-hex.bin"), None, Some(&[])).unwrap_err(),
        ImportError::V1KeyFile
    );
    // Twofish: the same content under the flag-8 cipher.
    let twofish = v1_wrap(&v1_plain(), 6, 9, 8);
    let r = v1_read(&twofish, Some("demo-v1-pass"), None).unwrap();
    find(&r.vault, "Test entry");
}

#[test]
fn fea08_51_v1_cp1252() {
    let r = v1_read(
        &data("v1-cp1252.bin"),
        Some("\u{201E}password\u{201D}"),
        None,
    )
    .unwrap();
    find(&r.vault, "Test entry");
}

#[test]
fn fea08_52_v1_records_and_tree() {
    let r = v1_demo();
    let root = &r.vault.root;
    assert_eq!(root.name, "Root");
    assert_eq!(names(root), ["Internet", "eMail", "Backup"]);
    let internet = sub(root, "Internet");
    assert_eq!(internet.icon, Icon::Standard(1));
    assert_eq!(names(internet), ["Subgroup 1", "Subgroup 2"]);
    assert_eq!(names(sub(internet, "Subgroup 1")), ["Unexpanded"]);
    let backup = sub(root, "Backup");
    assert_eq!(
        (backup.searching, backup.auto_type),
        (app_model::Switch::Off, app_model::Switch::Off)
    );
    let e = titled(internet, "Test entry");
    assert_eq!(e.value("UserName"), "I");
    assert_eq!(e.value("URL"), "http://example.com/");
    assert_eq!(e.value("Password"), "secretpassword");
    assert_eq!(e.value("Notes"), "Lorem ipsum\ndolor sit amet");
    assert_eq!(attachment(e, "attachment.txt"), b"hello world\n");
    assert_eq!(e.times.creation, at(2012, 1, 2, 3, 4, 5));
    titled(internet, "");
    assert_eq!(
        titled(sub(root, "eMail"), "Mail entry").icon,
        Icon::Standard(0),
        "icon 99 is outside the set"
    );
    titled(root, "Lost group");
    // Fresh ids (FEA-08.60): not the file's 0A…0A.
    assert_ne!(e.uuid, Uuid([0x0A; 16]));
    ok(&r.vault);
}

#[test]
fn fea08_53_v1_packed_time() {
    let r = v1_demo();
    let e = find(&r.vault, "Test entry");
    assert!(e.times.expires);
    assert_eq!(e.times.expiry, at(2012, 5, 9, 10, 32, 0));
    assert!(
        !find(&r.vault, "Custom Icon").times.expires,
        "\"never\" sets nothing"
    );
}

#[test]
fn fea08_54_v1_meta() {
    let r = v1_demo();
    assert!(
        r.vault
            .root
            .all_entries()
            .all(|e| e.value("Title") != "Meta-Info")
    );
    assert_eq!(r.vault.meta.custom_icons.len(), 1);
    assert!(matches!(
        find(&r.vault, "Custom Icon").icon,
        Icon::Custom(_)
    ));
    let internet = sub(&r.vault.root, "Internet");
    assert!(internet.expanded);
    let s1 = sub(internet, "Subgroup 1");
    assert!(s1.expanded);
    assert!(!sub(s1, "Unexpanded").expanded);
}

#[test]
fn fea08_55_v1_auto_type() {
    let r = v1_demo();
    let s1 = sub(sub(&r.vault.root, "Internet"), "Subgroup 1");
    let a1 = titled(s1, "Auto 1");
    assert_eq!(a1.value("Notes"), "last line");
    assert_eq!(a1.auto_type.default_sequence, "{USERNAME}{ENTER}");
    let pairs: Vec<(&str, &str)> = a1
        .auto_type
        .associations
        .iter()
        .map(|a| (a.window.as_str(), a.sequence.as_str()))
        .collect();
    assert_eq!(pairs, [("W0", ""), ("W1", "{PASSWORD}")]);
    let a2 = titled(s1, "Auto 2");
    assert_eq!(a2.value("Notes"), "start line\nend line\nsee Auto-Type: y");
    assert_eq!(a2.auto_type.default_sequence, "x");
}

#[test]
fn fea08_56_v1_damaged() {
    // A field size of 2^31 in the first group record: refused from the
    // size, before any allocation.
    let mut plain = v1_plain();
    plain[2..6].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let started = std::time::Instant::now();
    assert_eq!(
        v1_read(&v1_wrap(&plain, 6, 9, 2), Some("demo-v1-pass"), None).unwrap_err(),
        ImportError::V1Damaged
    );
    assert!(started.elapsed().as_millis() < 2_000);
    // Levels 0 then 2.
    let level = |n: u16| {
        let mut r = Vec::new();
        for (kind, data) in [
            (1u16, 7u32.to_le_bytes().to_vec()),
            (8, n.to_le_bytes().to_vec()),
        ] {
            r.extend(kind.to_le_bytes());
            r.extend((data.len() as u32).to_le_bytes());
            r.extend(data);
        }
        r.extend([0xFF, 0xFF, 0, 0, 0, 0]);
        r
    };
    let jump = [level(0), level(2)].concat();
    assert_eq!(
        v1_read(&v1_wrap(&jump, 2, 0, 2), Some("demo-v1-pass"), None).unwrap_err(),
        ImportError::V1Damaged
    );
    assert!(
        v1_read(
            &v1_wrap(&[level(0), level(1)].concat(), 2, 0, 2),
            Some("demo-v1-pass"),
            None
        )
        .is_ok()
    );
    // A huge record count with little data, an unknown field, a group
    // without a level.
    assert_eq!(
        v1_read(
            &v1_wrap(&level(0), u32::MAX, 0, 2),
            Some("demo-v1-pass"),
            None
        )
        .unwrap_err(),
        ImportError::V1Damaged
    );
    let unknown = [
        77u16.to_le_bytes().to_vec(),
        vec![0, 0, 0, 0],
        vec![0xFF, 0xFF, 0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(
        v1_read(&v1_wrap(&unknown, 1, 0, 2), Some("demo-v1-pass"), None).unwrap_err(),
        ImportError::V1Damaged
    );
}

// -- H. The XML document, I. Our own format ---------------------------------------

fn rich_v3() -> Vault {
    let bytes = std::fs::read(format!(
        "{}/../../testdata/rich-v3.appvault",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let pw = secret("demo-pass-4");
    let creds = app_format::keys::Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let app_format::Opened::Vault(o) = app_format::open(
        &bytes,
        &creds,
        &mut host(),
        &app_format::limits::Limits::DEFAULT,
        None,
    )
    .unwrap() else {
        panic!("no ask")
    };
    o.vault
}

#[test]
fn fea08_57_xml_import() {
    let rich = rich_v3();
    let exported = app_core::export::xml::xml(&rich).unwrap();
    let v = import::xml::read(exported.expose(), now()).unwrap();
    let full = find(&v, "Full demo entry");
    assert!(attachment(full, "notes.txt").starts_with(b"demo attachment one"));
    assert_eq!(
        attachment(full, "notes.txt"),
        attachment(find(&rich, "Full demo entry"), "notes.txt")
    );
    assert_eq!(full.attachments.len(), 3);
    assert!(protected(full, "Password"), "ProtectInMemory sets the flag");
    ok(&v);
}

#[test]
fn fea08_58_xml_protected() {
    let exported = app_core::export::xml::xml(&rich_v3()).unwrap();
    let text = String::from_utf8(exported.expose().to_vec()).unwrap();
    let changed = text.replacen(
        "<Value ProtectInMemory=\"True\">",
        "<Value Protected=\"True\">",
        1,
    );
    assert_ne!(changed, text);
    assert_eq!(
        import::xml::read(changed.as_bytes(), now()).unwrap_err(),
        ImportError::XmlProtected
    );
}

#[test]
fn fea08_59_xml_errors() {
    let dir = std::env::temp_dir().join(format!("fea08-59-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let taken = dir.join("taken.appvault");
    std::fs::write(&taken, b"x").unwrap();
    assert_eq!(
        import::xml::check_target(&taken, true).unwrap_err(),
        ImportError::XmlExists
    );
    let free = dir.join("new.appvault");
    assert_eq!(
        import::xml::check_target(&free, false).unwrap_err(),
        ImportError::XmlNoKey
    );
    assert!(import::xml::check_target(&free, true).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        import::xml::read(b"<x/>", now()).unwrap_err(),
        ImportError::XmlNoRoot
    );
    let dtd = b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><x/>";
    assert_eq!(
        import::xml::read(dtd, now()).unwrap_err(),
        ImportError::XmlInvalid
    );
}

#[test]
fn fea08_60_our_format() {
    // No kind for a vault of our format; Merge does it (MOD-11).
    assert_eq!(import::KINDS.len(), 6);
    let merge: fn(
        &mut Vault,
        &Vault,
        &app_core::merge::Options,
        Time,
    ) -> Result<app_core::merge::Merged, app_core::Error> = app_core::merge::merge;
    let _ = merge;
}

// -- J, part 2 ----------------------------------------------------------------

#[test]
fn fea08_61_opv_broken_folder() {
    let mut mem = demo_opv();
    let folders = mem.text("folders.js");
    let broken = folders.replacen("\"overview\": \"", "\"overview\": \"AAAA", 1);
    mem.set("folders.js", broken.into_bytes());
    let mut t = target();
    let before = t.duplicate();
    assert_eq!(
        opv(&mem, "demo.opvault", "demo-opv-pass").unwrap_err(),
        ImportError::OpvDamaged
    );
    assert!(t == before, "no groups added anywhere");
    let _ = &mut t;
}

#[test]
fn fea08_63_zip_limits() {
    // export.data declared past 256 MiB: refused from the declared size,
    // before anything is inflated.
    let lie = zip(&[("export.data", b"{}", true, Some((256 << 20) + 1))]);
    let started = std::time::Instant::now();
    assert_eq!(
        onepux::read(&lie, &ctx()).unwrap_err(),
        ImportError::TooLarge(Limit::File)
    );
    assert!(started.elapsed().as_millis() < 100);
    // A large member that inflates past its declared size stops there;
    // one that inflates to less is damaged too.
    let (export, big) = big_export();
    for declared in [1 << 20, 4 << 20] {
        let lying = zip(&[
            ("export.data", export.as_bytes(), true, Some(declared)),
            ("files/d__big.bin", &big, true, None),
        ]);
        assert_eq!(
            onepux::read(&lying, &ctx()).unwrap_err(),
            ImportError::OnePuxNotZip,
            "{declared}"
        );
    }
    let mut short_member = zip(&[
        ("export.data", export.as_bytes(), true, None),
        ("files/d__big.bin", &big, true, Some((1 << 20) - 1)),
    ]);
    assert_eq!(
        onepux::read(&short_member, &ctx()).unwrap_err(),
        ImportError::OnePuxNotZip
    );
    short_member.clear();
    // Attachment and icon limits of the result (FEA-08.67).
    let mut c = ctx();
    c.limits.one_attachment = 14;
    assert_eq!(
        onepux::read(&data("demo.1pux"), &c).unwrap_err(),
        ImportError::TooLarge(Limit::OneAttachment)
    );
    let mut c = ctx();
    c.limits.all_attachments = 20;
    assert_eq!(
        onepux::read(&data("demo.1pux"), &c).unwrap_err(),
        ImportError::TooLarge(Limit::AllAttachments)
    );
    let mut c = ctx();
    c.limits.attachments = 1;
    assert_eq!(
        onepux::read(&data("demo.1pux"), &c).unwrap_err(),
        ImportError::TooLarge(Limit::Attachments)
    );
    let mut c = ctx();
    c.limits.icons = 0;
    assert_eq!(
        onepux::read(&data("demo.1pux"), &c).unwrap_err(),
        ImportError::TooLarge(Limit::Icons)
    );
}

#[test]
fn fea08_64_v1_and_opv_kdf_cost() {
    // Rounds within CRY-02's range but over the ask threshold: the cost
    // comes back, nothing is derived before the answer.
    let mut slow = data("v1-aes.bin");
    slow[120..124].copy_from_slice(&2_000_000_000u32.to_le_bytes());
    let started = std::time::Instant::now();
    let v1::Outcome::Ask(report) = v1_outcome(&slow, Some("demo-v1-pass"), None).unwrap() else {
        panic!("question expected")
    };
    assert!(started.elapsed().as_millis() < 500);
    assert_eq!(report.work(), 2_000_000_000);
    assert!(report.estimated_ms() > 10_000);
    // 4,294,967,295 rounds pass CRY-02's AES-KDF range: refused, never run.
    let mut max = data("v1-aes.bin");
    max[120..124].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        v1_outcome(&max, Some("demo-v1-pass"), None).unwrap_err(),
        ImportError::KdfCost
    );
    // OPVault PBKDF2 past 10,000,000 iterations.
    let mut mem = demo_opv();
    let profile = mem
        .text("profile.js")
        .replace("\"iterations\": 1000", "\"iterations\": 10000001");
    mem.set("profile.js", profile.into_bytes());
    assert_eq!(
        opv(&mem, "demo.opvault", "demo-opv-pass").unwrap_err(),
        ImportError::KdfCost
    );
}

// -- Checker 1, second pass ------------------------------------------------------

/// An `export.data` of about 1.1 MiB with one entry "Big" whose notes hold
/// 1,100,000 characters and which names `files/d__big.bin`, and that
/// member: 1 MiB of mixed bytes.
fn big_export() -> (String, Vec<u8>) {
    let note: String = (0..1_100_000u32)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    let export = format!(
        r#"{{"accounts":[{{"vaults":[{{"attrs":{{"name":"V"}},"items":[{{"overview":{{"title":"Big"}},"details":{{"notesPlain":"{note}","documentAttributes":{{"documentId":"d","fileName":"big.bin"}}}}}}]}}]}}]}}"#
    );
    let big: Vec<u8> = (0..1_048_576u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    (export, big)
}

#[test]
fn fea08_29_1pux_large_deflated_members() {
    // Checker 1 issue 1: deflated members far past the 64 KiB inflate
    // buffer read back exactly.
    let (export, big) = big_export();
    let file = zip(&[
        ("export.data", export.as_bytes(), true, None),
        ("files/d__big.bin", &big, true, None),
    ]);
    let r = onepux::read(&file, &ctx()).unwrap();
    let e = find(&r.vault, "Big");
    assert_eq!(e.value("Notes").len(), 1_100_000);
    assert!(
        e.value("Notes")
            .starts_with("abcdefghijklmnopqrstuvwxyzabc")
    );
    assert_eq!(attachment(e, "big.bin"), big.as_slice());
    // Python's zipfile wrote demo.1pux with deflated members too.
    assert!(onepux::read(&data("demo.1pux"), &ctx()).is_ok());
}

#[test]
fn fea08_67_attachment_budget_before_reading() {
    // Checker 1 issue 2: 4,000 file fields name one 64 KiB member. The
    // reader asks for the room left before each read, so it stops at the
    // budget instead of holding 4,000 copies.
    let member = vec![7u8; 64 << 10];
    let fields: Vec<String> = (0..4_000)
        .map(|i| {
            format!(r#"{{"title":"f{i}","value":{{"file":{{"documentId":"d","fileName":"x"}}}}}}"#)
        })
        .collect();
    let export = format!(
        r#"{{"accounts":[{{"vaults":[{{"attrs":{{"name":"V"}},"items":[{{"overview":{{"title":"Many"}},"details":{{"sections":[{{"title":"S","fields":[{}]}}]}}}}]}}]}}]}}"#,
        fields.join(",")
    );
    let file = zip(&[
        ("export.data", export.as_bytes(), true, None),
        ("files/d__x", &member, true, None),
    ]);
    let mut c = ctx();
    c.limits.all_attachments = 1 << 20;
    assert_eq!(
        onepux::read(&file, &c).unwrap_err(),
        ImportError::TooLarge(Limit::AllAttachments)
    );
    let mut c = ctx();
    c.limits.total = 1 << 20;
    assert_eq!(
        onepux::read(&file, &c).unwrap_err(),
        ImportError::TooLarge(Limit::Total)
    );
    // Icons count against the total at their base64 size: the 19-byte
    // avatar needs 28.
    let mut c = ctx();
    c.limits.total = 27;
    assert_eq!(
        onepux::read(&data("demo.1pux"), &c).unwrap_err(),
        ImportError::TooLarge(Limit::Total)
    );
    c.limits.total = 28 + 15 + 15;
    assert!(
        onepux::read(&data("demo.1pux"), &c).is_ok(),
        "avatar and both attachments fit exactly"
    );
    // OPVault: a file past what the budget has left stops the import; past
    // the one-attachment limit it is skipped (LD-146 (6)).
    let mut c = ctx();
    c.limits.all_attachments = 100;
    assert_eq!(
        opvault::read(
            &demo_opv(),
            "demo.opvault",
            Some(&secret("demo-opv-pass")),
            &c
        )
        .unwrap_err(),
        ImportError::TooLarge(Limit::AllAttachments)
    );
    assert_eq!(
        import::ResultLimits::DEFAULT.total,
        app_format::limits::Limits::DEFAULT.total
    );
}

#[test]
fn fea08_42_many_attachments_with_one_name() {
    // Checker 1 issue 5: 20,000 attachments all named `x` get unique names
    // without a scan per name.
    let fields: Vec<String> = (0..20_000)
        .map(|i| {
            format!(r#"{{"title":"f{i}","value":{{"file":{{"documentId":"d","fileName":"x"}}}}}}"#)
        })
        .collect();
    let export = format!(
        r#"{{"accounts":[{{"vaults":[{{"attrs":{{"name":"V"}},"items":[{{"overview":{{"title":"Many"}},"details":{{"sections":[{{"title":"S","fields":[{}]}}]}}}}]}}]}}]}}"#,
        fields.join(",")
    );
    let file = zip(&[
        ("export.data", export.as_bytes(), true, None),
        ("files/d__x", b"1", false, None),
    ]);
    let started = std::time::Instant::now();
    let r = onepux::read(&file, &ctx()).unwrap();
    assert!(started.elapsed().as_secs() < 30);
    assert_eq!(find(&r.vault, "Many").attachments.len(), 20_000);
    ok(&r.vault);
}

#[test]
fn fea08_55_v1_record_counts_stop_at_the_limits() {
    // Checker 1 issue 3: the header's counts drive no allocation; parsing
    // stops as soon as groups or kept entries pass the limits.
    let empty_entry = [0xFF, 0xFF, 0, 0, 0, 0];
    let file = v1_wrap(&empty_entry.repeat(2_000), 0, 2_000, 2);
    let pw = secret("demo-v1-pass");
    let keys = v1::Keys {
        password: Some(&pw),
        key_file: None,
    };
    let read = |file: &[u8], c: &Context<'_>| {
        v1::read(file, &keys, &mut host(), &CEILINGS, None, c).map(|_| ())
    };
    let mut c = ctx();
    c.limits.entries = 100;
    assert_eq!(
        read(&file, &c).unwrap_err(),
        ImportError::TooLarge(Limit::Entries)
    );
    assert!(read(&file, &ctx()).is_ok());
    let group = |id: u32| {
        let mut r = Vec::new();
        for (kind, data) in [
            (1u16, id.to_le_bytes().to_vec()),
            (8, 0u16.to_le_bytes().to_vec()),
        ] {
            r.extend(kind.to_le_bytes());
            r.extend((data.len() as u32).to_le_bytes());
            r.extend(data);
        }
        r.extend(empty_entry);
        r
    };
    let groups: Vec<u8> = (0..500).flat_map(group).collect();
    let file = v1_wrap(&groups, 500, 0, 2);
    let mut c = ctx();
    c.limits.groups = 100;
    assert_eq!(
        read(&file, &c).unwrap_err(),
        ImportError::TooLarge(Limit::Groups)
    );
    assert!(read(&file, &ctx()).is_ok());
}

#[test]
fn fea08_48_v1_short_file_signature() {
    // LD-146 (12): the bytes there are compared with the signatures.
    assert_eq!(
        v1_outcome(&[0x03, 0xD9, 0x00], Some("x"), None).unwrap_err(),
        ImportError::V1NotVault
    );
    assert_eq!(
        v1_outcome(b"PK\x03", Some("x"), None).unwrap_err(),
        ImportError::V1NotVault
    );
    assert_eq!(
        v1_outcome(&[0x03, 0xD9], Some("x"), None).unwrap_err(),
        ImportError::V1Damaged
    );
    assert_eq!(
        v1_outcome(&[], Some("x"), None).unwrap_err(),
        ImportError::V1Damaged
    );
}

#[test]
fn fea08_41_opv_date_with_a_standard_name() {
    // Checker 1 issue 4: a date field whose name resolves to URL becomes a
    // suffixed custom field; the standard URL stays.
    let r = opv_demo();
    let e = find(&r.vault, "Expired Login");
    assert_eq!(e.value("URL"), "");
    assert_eq!(suffixed(e, "URL"), "2023-11-14");
}

#[test]
fn fea08_67_pux_file_limit() {
    // LD-146 (3): a .1pux file may be up to 2 GiB; sparse files, nothing
    // written.
    let dir = std::env::temp_dir().join(format!("fea08-67-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let over = dir.join("over.1pux");
    std::fs::File::create(&over)
        .unwrap()
        .set_len((2 << 30) + 1)
        .unwrap();
    assert_eq!(
        import::read_file(&over, import::MAX_PUX_FILE).unwrap_err(),
        ImportError::TooLarge(Limit::File)
    );
    let under = dir.join("under.1pux");
    std::fs::File::create(&under)
        .unwrap()
        .set_len((256 << 20) + 1)
        .unwrap();
    assert_eq!(
        import::read_file(&under, import::MAX_PUX_FILE)
            .unwrap()
            .len(),
        (256 << 20) + 1
    );
    assert_eq!(
        import::read_file(&under, import::MAX_FILE).unwrap_err(),
        ImportError::TooLarge(Limit::File)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn r5_bw_passkey_key_is_base64url() {
    // FEA-08.47: `keyValue` is base64url, padding optional; the PEM body is
    // standard base64 with padding; the id is base64url without padding.
    let r = bw(r#"{"folders":[],"items":[
        {"name":"Bare","login":{"fido2Credentials":[{"credentialId":"fbff","keyValue":"-_8","rpId":"x","userName":"u","userHandle":"h"}]}},
        {"name":"Padded","login":{"fido2Credentials":[{"credentialId":"fbff","keyValue":"-_8=","rpId":"x","userName":"u","userHandle":"h"}]}},
        {"name":"Standard","login":{"fido2Credentials":[{"credentialId":"fbff","keyValue":"+/8","rpId":"x","userName":"u","userHandle":"h"}]}}]}"#);
    for t in ["Bare", "Padded"] {
        let e = find(&r.vault, t);
        assert_eq!(
            e.value("KPEX_PASSKEY_PRIVATE_KEY_PEM"),
            "-----BEGIN PRIVATE KEY-----+/8=-----END PRIVATE KEY-----",
            "{t}"
        );
        assert_eq!(e.value("KPEX_PASSKEY_CREDENTIAL_ID"), "-_8", "{t}");
    }
    let e = find(&r.vault, "Standard");
    assert!(e.field("KPEX_PASSKEY_PRIVATE_KEY_PEM").is_none());
}

#[test]
fn r5_imports_read_base64_without_padding() {
    // FEA-08.50: both Bitwarden cipher strings with every `=` taken out.
    let mut file = PBKDF2_FILE.to_owned();
    for key in ["\"encKeyValidation_DO_NOT_EDIT\": \"", "\"data\": \""] {
        let start = file.find(key).unwrap() + key.len();
        let end = start + file[start..].find('"').unwrap();
        let bare = file[start..end].replace('=', "");
        file.replace_range(start..end, &bare);
    }
    assert_ne!(file, PBKDF2_FILE);
    let r = bitwarden::read(file.as_bytes(), Some(&secret("demo-pass")), &ctx()).unwrap();
    find(&r.vault, "Encrypted demo login");
    // FEA-08.35: the OPVault profile and folders with no `=` in their base64
    // (the items' own HMAC covers their text, FEA-08.37, so they stay).
    let mut mem = demo_opv();
    for name in ["profile.js", "folders.js"] {
        let text = mem.text(name);
        let bare = text.replace("=\"", "\"").replace("=\"", "\"");
        assert_ne!(bare, text, "{name}");
        mem.set(name, bare.into_bytes());
    }
    let titles = |r: &Imported| -> Vec<String> {
        r.vault
            .root
            .all_entries()
            .map(|e| e.value("Title").to_owned())
            .collect()
    };
    let r = opv(&mem, "demo.opvault", "demo-opv-pass").unwrap();
    assert_eq!(titles(&r), titles(&opv_demo()));
    assert_eq!(titles(&r).len(), 7);
}
