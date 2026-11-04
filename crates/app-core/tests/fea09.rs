//! Story E4-S13 part 1, card FEA-09 (export): one test per case
//! (`fea09_NN_…`), T01 to T24, on the card's demo vault V (built here with
//! V's names, values and times) and the project's `rich-v3.appvault` and
//! `rich-v4.appvault` (testdata, passwords `demo-pass-4` and
//! `demo-pass-5`).
//!
//! HTML markup checked here (FEA-09.8, recorded in export/html.rs): the
//! `<h2>` of each `section.group`, `div.entry` with `<h3>` titles, and
//! `<dd>` values of class `user-name`, `password`, `url`, `field`, `notes`.
//! Screen-only parts (menu items, the question's default button, the save
//! dialog, a memory dump) are E5's and the Verify agent's; each test says
//! which part it covers.

mod common;

use app_core::export::html::{self, Options as HtmlOptions, SORTS, Sort};
use app_core::export::{self, CONFIRM_TEXT, CONFIRM_TITLE, FORMULA_NOTE, Format, csv, xml};
use app_core::import;
use app_core::storage::write_export;
use app_core::time::Utc;
use app_crypto::kdf::{Host, SpeedRecord};
use app_crypto::secret::{SecretBytes, SecretString};
use app_crypto::stream::FieldStream;
use app_format::document::encode::time_to_binary;
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Opened, document};
use app_model::{
    Attachment, CustomDataItem, DeletedObject, Entry, Field, Group, Icon, Time, Uuid, Vault,
};
use common::at;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn t(s: u32) -> Time {
    at(2026, 10, 24, 22, 53, s)
}

fn now() -> Time {
    at(2026, 10, 25, 12, 0, 0)
}

fn set(e: &mut Entry, name: &str, v: &str) {
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(v.to_owned()),
            protected: name == "Password",
        },
    );
}

fn ent(id: u8, title: &str, user: &str, pw: &str, modified: Time) -> Entry {
    let mut e = Entry::new(Uuid([id; 16]), t(24));
    set(&mut e, "Title", title);
    set(&mut e, "UserName", user);
    set(&mut e, "Password", pw);
    e.times.last_modification = modified;
    e.times.last_access = modified;
    e
}

fn grp(id: u8, name: &str) -> Group {
    Group::new(Uuid([id; 16]), name.into(), t(24))
}

/// The card's demo vault V.
fn v() -> Vault {
    let top = ent(0x10, "Top Entry", "zoë", "root-pw", t(24));
    let mut mail = ent(0x11, "Mail", "alice2", "demo-secret-1", t(25));
    set(&mut mail, "URL", "https://example.com");
    set(&mut mail, "Notes", "line1\nline2 \"quoted\", comma");
    mail.attachments.push(Attachment {
        name: "note.txt".into(),
        data: Arc::new(SecretBytes::new(b"hello attachment\n".to_vec())),
    });
    let mut first = ent(0x11, "Mail", "alice", "demo-secret-1", t(24));
    first.attachments.push(Attachment {
        name: "note.txt".into(),
        data: Arc::clone(&mail.attachments[0].data),
    });
    let second = ent(0x11, "Mail", "alice2", "demo-secret-0", t(24));
    mail.history = vec![first, second];
    let bank = ent(0x12, "Bank", "bob", "pw,with\"quote", t(26));
    let old = ent(0x13, "Old", "carol", "gone-pw", t(27));
    let mut sub = grp(0x03, "Sub");
    sub.entries.push(bank);
    let mut work = grp(0x02, "Work");
    work.entries.push(mail);
    work.groups.push(sub);
    let mut bin = grp(0x04, "Recycle Bin");
    bin.entries.push(old);
    let mut root = grp(0x01, "Passwords");
    root.entries.push(top);
    root.groups.push(work);
    root.groups.push(bin);
    let mut v = Vault::new(root, t(24));
    v.meta.recycle_bin = Some(Uuid([0x04; 16]));
    v.meta.custom_data.items.push(CustomDataItem {
        key: "demo-key".into(),
        value: "demo-value".into(),
        last_modified: Some(t(24)),
        unknown: Vec::new(),
    });
    v.deleted_objects.push(DeletedObject {
        uuid: Uuid([0x55; 16]),
        deleted_at: t(26),
        unknown: Vec::new(),
    });
    v
}

fn text(b: &SecretBytes) -> &str {
    core::str::from_utf8(b.expose()).unwrap()
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

fn testdata(name: &str, password: &str) -> Vault {
    let path = format!("{}/../../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = fs::read(path).unwrap();
    let pw = SecretString::new(password.into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let Opened::Vault(o) =
        app_format::open(&bytes, &creds, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    o.vault
}

fn cli(vault: &Vault, sort: Sort) -> String {
    let o = HtmlOptions {
        sort,
        path: "/tmp/spec/v.appvault",
        icon: None,
    };
    text(&html::html(vault, &o)).to_owned()
}

/// The text of every `<h2>`, in page order.
fn headings(page: &str) -> Vec<&str> {
    page.split("<h2>")
        .skip(1)
        .map(|s| s.split("</h2>").next().unwrap())
        .collect()
}

/// The text of every `<h3>` (entry titles), in page order.
fn titles(page: &str) -> Vec<&str> {
    page.split("<h3>")
        .skip(1)
        .map(|s| s.split("</h3>").next().unwrap())
        .collect()
}

/// The `div.entry` of the entry titled `title`.
fn entry_div<'a>(page: &'a str, title: &str) -> &'a str {
    let start = page
        .find(&format!("<h3>{title}</h3>"))
        .unwrap_or_else(|| panic!("{title}"));
    let rest = &page[start..];
    &rest[..rest.find("</div>").unwrap()]
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fea09-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn read_back(xml: &[u8]) -> Vault {
    let mut stream = FieldStream::chacha20_from_stream_key(&SecretBytes::new(vec![0; 32])).unwrap();
    let opts = document::Options {
        open_time: now(),
        limits: &Limits::DEFAULT,
        v3_header: None,
    };
    document::read(xml, &mut stream, &[], &opts).unwrap().vault
}

#[test]
fn fea09_01_availability() {
    // Core part: export reads the vault in memory, unsaved change
    // included, and changes nothing (no draw, no save: `&Vault` only).
    let mut vault = v();
    set(&mut vault.root.entries[0], "Title", "Top");
    let before = vault.duplicate();
    let out = csv::csv(&vault, now());
    assert!(text(&out).contains("\"Passwords\",\"Top\",\"zoë\""));
    let _ = html::html(
        &vault,
        &HtmlOptions {
            sort: Sort::default(),
            path: "",
            icon: None,
        },
    );
    let _ = xml::xml(&vault).unwrap();
    assert!(vault == before, "the vault is unchanged");
}

#[test]
fn fea09_02_warning() {
    assert_eq!(CONFIRM_TITLE, "Export without encryption?");
    assert_eq!(
        CONFIRM_TEXT,
        "The file will hold every password and secret in this vault as plain text. Anyone who can open the file can read them."
    );
    assert!(Format::Csv.asks_first() && Format::Xml.asks_first());
    assert!(!Format::Html.asks_first(), "HTML: banner, no question");
    // LD-43: the CSV warning names the formula characters.
    let w = export::warning(Format::Csv);
    assert!(w.starts_with(CONFIRM_TEXT) && w.ends_with(FORMULA_NOTE));
    for c in ["=", "+", "-", "@"] {
        assert!(FORMULA_NOTE.contains(c));
    }
    assert_eq!(export::warning(Format::Html), CONFIRM_TEXT);
    assert_eq!(export::warning(Format::Xml), CONFIRM_TEXT);
}

const V_CSV: &str = concat!(
    "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n",
    "\"Passwords\",\"Top Entry\",\"zoë\",\"root-pw\",\"\",\"\",\"\",\"0\",\"2026-10-24T22:53:24Z\",\"2026-10-24T22:53:24Z\"\n",
    "\"Passwords/Work\",\"Mail\",\"alice2\",\"demo-secret-1\",\"https://example.com\",\"line1\nline2 \"\"quoted\"\", comma\",\"\",\"0\",\"2026-10-24T22:53:25Z\",\"2026-10-24T22:53:24Z\"\n",
    "\"Passwords/Work/Sub\",\"Bank\",\"bob\",\"pw,with\"\"quote\",\"\",\"\",\"\",\"0\",\"2026-10-24T22:53:26Z\",\"2026-10-24T22:53:24Z\"\n",
    "\"Passwords/Recycle Bin\",\"Old\",\"carol\",\"gone-pw\",\"\",\"\",\"\",\"0\",\"2026-10-24T22:53:27Z\",\"2026-10-24T22:53:24Z\"\n",
);

#[test]
fn fea09_03_csv_exact() {
    let out = csv::csv(&v(), now());
    assert_eq!(text(&out), V_CSV);
    assert!(
        out.expose().windows(2).any(|w| w == [0xC3, 0xAB]),
        "ë as C3 AB"
    );
    assert!(!out.expose().starts_with(&[0xEF, 0xBB, 0xBF]), "no BOM");
    assert!(out.expose().ends_with(b"\n"));
}

#[test]
fn fea09_04_csv_empty() {
    let empty = Vault::new(grp(0x01, "Root"), t(24));
    assert_eq!(text(&csv::csv(&empty, now())), csv::HEADER);
    assert_eq!(
        csv::HEADER,
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n"
    );
}

#[test]
fn fea09_05_csv_scope() {
    let mut vault = v();
    vault.root.groups.push(grp(0x05, "Empty group"));
    let out = csv::csv(&vault, now());
    let s = text(&out);
    assert_eq!(s.matches("\n\"Passwords").count(), 4, "4 records");
    assert!(!s.contains("alice\""), "no history line");
    assert!(!s.contains("demo-secret-0"));
    assert!(!s.contains("hello attachment"), "no attachment data");
    assert!(
        !s.contains("Empty group"),
        "no line for a group without entries"
    );
}

#[test]
fn fea09_06_csv_totp() {
    let rich = testdata("rich-v3.appvault", "demo-pass-4");
    let out = csv::csv(&rich, now());
    let s = text(&out);
    let record = &s[s.find("\"Full demo entry\"").unwrap()..];
    // The TOTP column, then Icon `0` although a custom icon is set.
    let totp = "\"otpauth://totp/Full%20demo%20entry:demo-user?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Full%20demo%20entry\",\"0\",";
    assert!(record[..record.find("Z\"\n").unwrap()].contains(totp));
    let full = rich
        .root
        .all_entries()
        .find(|e| e.value("Title") == "Full demo entry")
        .unwrap();
    assert!(matches!(full.icon, Icon::Custom(_)));
}

#[test]
fn fea09_07_csv_no_resolving() {
    let mut vault = v();
    let reference = app_core::refs::reference('U', Uuid([0x12; 16]));
    set(&mut vault.root.entries[0], "UserName", &reference);
    let out = csv::csv(&vault, now());
    assert!(text(&out).contains(&format!("\"Top Entry\",\"{reference}\"")));
    assert!(!text(&out).contains("\"Top Entry\",\"bob\""));
}

#[test]
fn fea09_08_html_dialog() {
    assert_eq!(
        SORTS,
        [Sort::NameAscending, Sort::NameDescending, Sort::VaultOrder]
    );
    assert_eq!(Sort::default(), Sort::NameAscending);
}

#[test]
fn fea09_09_html_frame() {
    let vault = v();
    assert!(vault.meta.name.is_empty() && vault.meta.description.is_empty());
    let o = HtmlOptions {
        sort: Sort::default(),
        path: "/tmp/spec/d1.appvault",
        icon: None,
    };
    let out = html::html(&vault, &o);
    let page = text(&out);
    let head = &page[..page.find("</head>").unwrap()];
    assert!(head.contains("<meta charset=\"UTF-8\">"));
    assert!(head.contains(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">"
    ));
    assert!(head.contains("<title></title>"));
    assert!(page.contains("<h1></h1>"));
    assert!(!page.contains("<p class=\"vault-description\">"));
    let path = page.find("/tmp/spec/d1.appvault").unwrap();
    assert!(
        path < page.find("<section").unwrap(),
        "path before the first group section"
    );
    // A name and a description are escaped; line breaks kept.
    let mut named = v();
    named.meta.name = "Demo <vault>".into();
    named.meta.description = "one\ntwo".into();
    let page = cli(&named, Sort::default());
    assert!(
        page.contains("<title>Demo &lt;vault&gt;</title>")
            && page.contains("<h1>Demo &lt;vault&gt;</h1>")
    );
    assert!(page.contains("<p class=\"vault-description\">one\ntwo</p>"));
    assert!(page.contains(".vault-description,.group-notes,.field,.notes{white-space:pre-wrap}"));
}

#[test]
fn fea09_10_html_groups() {
    let page = cli(&v(), Sort::default());
    assert_eq!(
        headings(&page),
        ["Passwords", "Passwords › Work", "Passwords › Work › Sub"]
    );
    assert!(!page.contains("Recycle Bin") && !page.contains("Old") && !page.contains("gone-pw"));
    // Group notes, escaped, after the heading; a group with nothing adds nothing.
    let mut vault = v();
    vault.root.groups[0].notes = "a & b\nc".into();
    vault.root.groups.push(grp(0x06, "Nothing"));
    let mut notes_only = grp(0x07, "Notes only");
    notes_only.notes = "n".into();
    vault.root.groups.push(notes_only);
    let page = cli(&vault, Sort::VaultOrder);
    assert!(page.contains("<h2>Passwords › Work</h2>\n<p class=\"group-notes\">a &amp; b\nc</p>"));
    assert!(!page.contains("Nothing"));
    assert!(headings(&page).contains(&"Passwords › Notes only"));
}

#[test]
fn fea09_11_html_sort() {
    let mut root = grp(0x01, "R");
    for (id, title) in [(0x10, "b"), (0x11, "A"), (0x12, "c")] {
        root.entries.push(ent(id, title, "u", "", t(24)));
    }
    for (id, name) in [(0x02, "y"), (0x03, "X")] {
        let mut g = grp(id, name);
        g.entries
            .push(ent(id + 0x20, &format!("in {name}"), "u", "", t(24)));
        root.groups.push(g);
    }
    let vault = Vault::new(root, t(24));
    let case = |s| {
        let page = cli(&vault, s);
        let t: Vec<String> = titles(&page).into_iter().map(str::to_owned).collect();
        let g: Vec<String> = headings(&page)
            .into_iter()
            .skip(1)
            .map(str::to_owned)
            .collect();
        (t[..3].to_vec(), g)
    };
    assert_eq!(
        case(Sort::NameAscending),
        (
            vec!["A".to_owned(), "b".into(), "c".into()],
            vec!["R › X".to_owned(), "R › y".into()]
        )
    );
    assert_eq!(
        case(Sort::NameDescending),
        (
            vec!["c".to_owned(), "b".into(), "A".into()],
            vec!["R › y".to_owned(), "R › X".into()]
        )
    );
    assert_eq!(
        case(Sort::VaultOrder),
        (
            vec!["b".to_owned(), "A".into(), "c".into()],
            vec!["R › y".to_owned(), "R › X".into()]
        )
    );
}

#[test]
fn fea09_12_html_rows() {
    let rich = testdata("rich-v3.appvault", "demo-pass-4");
    let page = cli(&rich, Sort::default());
    let div = entry_div(&page, "Full demo entry");
    let order = [
        "<dt>User name</dt><dd class=\"user-name\">demo-user</dd>",
        "<dt>Password</dt><dd class=\"password\">",
        "<dt>URL</dt><dd class=\"url\"><a href=\"https://example.com/full\">https://example.com/full</a></dd>",
        "<dt>Demo PIN</dt><dd class=\"field\">0000</dd>",
        "<dt>Demo hint</dt><dd class=\"field\">not protected</dd>",
        "<dt>Empty custom field</dt><dd class=\"field\"></dd>",
        "<dt>Spaces</dt><dd class=\"field\">  leading and trailing  </dd>",
        "<dt>otp</dt><dd class=\"field\">otpauth://",
        "<dt>Notes</dt><dd class=\"notes\">Line one\nLine two\n",
    ];
    let mut at = 0;
    for part in order {
        let found = div[at..]
            .find(part)
            .unwrap_or_else(|| panic!("{part} after {at} in {div}"));
        at += found + part.len();
    }
    let shown = titles(&page);
    assert!(!shown.contains(&"Shared attachment 1") && !shown.contains(&"Shared attachment 2"));
    assert!(!shown.contains(&""), "the untitled empty entry is left out");
    assert!(shown.contains(&"Server login"));
}

#[test]
fn fea09_13_html_escaping_and_links() {
    let mut root = grp(0x01, "R");
    let mut special = ent(
        0x10,
        "Specials <tag> & \"quotes\" 'apos' ]]>",
        "u",
        "",
        t(24),
    );
    set(&mut special, "URL", "javascript:alert(1)");
    let mut long = ent(0x11, "Long", "u", "", t(24));
    let url = format!("https://{}", "a".repeat(150));
    set(&mut long, "URL", &url);
    let mut plain = ent(0x12, "Plain", "u", "", t(24));
    set(&mut plain, "URL", "HTTP://Example.com/?a=1&b=2");
    // LD-74: passkey fields are left out; other custom fields stay.
    set(
        &mut plain,
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "-----BEGIN PRIVATE KEY-----demo",
    );
    let foreign = String::from_utf8(vec![
        0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x41, 0x53, 0x53, 0x4B, 0x45, 0x59, 0x5F, 0x55, 0x53,
        0x45, 0x52, 0x4E, 0x41, 0x4D, 0x45,
    ])
    .unwrap();
    set(&mut plain, &foreign, "demo-foreign-user");
    set(&mut plain, "PIN", "1 2");
    root.entries.extend([special, long, plain]);
    let page = cli(&Vault::new(root, t(24)), Sort::VaultOrder);
    assert!(
        page.contains(
            "<h3>Specials &lt;tag&gt; &amp; &quot;quotes&quot; &#39;apos&#39; ]]&gt;</h3>"
        )
    );
    assert!(
        page.contains("<dd class=\"url\">javascript:alert(1)</dd>"),
        "not a link"
    );
    assert!(!page.contains("href=\"javascript"));
    let shown = format!("<a href=\"{url}\">https://{}…</a>", "a".repeat(92));
    assert!(page.contains(&shown), "100 characters, then an ellipsis");
    assert!(page.contains(
        "<a href=\"HTTP://Example.com/?a=1&amp;b=2\">HTTP://Example.com/?a=1&amp;b=2</a>"
    ));
    assert!(
        !page.contains("PRIVATE KEY")
            && !page.contains("KPEX_PASSKEY")
            && !page.contains("demo-foreign-user")
    );
    assert!(page.contains("<dt>PIN</dt><dd class=\"field\">1 2</dd>"));
    assert!(!page.contains("<script"));
}

#[test]
fn fea09_14_html_icons() {
    let png: &dyn Fn(Icon) -> Option<Vec<u8>> = &|_| Some(vec![0x89, b'P', b'N', b'G']);
    let o = HtmlOptions {
        sort: Sort::default(),
        path: "/Users/demo/v.appvault",
        icon: Some(png),
    };
    let out = html::html(&v(), &o);
    let page = text(&out);
    let images = page
        .matches("<img class=\"icon\" alt=\"\" src=\"data:image/png;base64,iVBORw==\">")
        .count();
    assert_eq!(images, 3 + 3, "3 group headings and 3 entries");
    assert!(headings(page).iter().all(|h| h.starts_with("<img")));
    assert!(titles(page).iter().all(|h| h.starts_with("<img")));
    assert!(
        !cli(&v(), Sort::default()).contains("<img"),
        "command line: no image at all"
    );
}

#[test]
fn fea09_15_xml_protected() {
    let out = xml::xml(&v()).unwrap();
    let s = text(&out);
    assert!(s.contains("<Value ProtectInMemory=\"True\">root-pw</Value>"));
    assert!(s.contains("<Value ProtectInMemory=\"True\">pw,with&quot;quote</Value>"));
    assert!(!s.contains("Protected="));
    assert!(!s.contains("HeaderHash"));
    let mut start = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<".to_vec();
    start.extend([
        0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65, b'>',
    ]);
    assert!(out.expose().starts_with(&start));
    assert!(s.contains(&format!(
        "<LastModificationTime>{}</LastModificationTime>",
        time_to_binary(t(25))
    )));
    // An empty protected value.
    let mut vault = v();
    set(&mut vault.root.entries[0], "Password", "");
    let out = xml::xml(&vault).unwrap();
    assert!(text(&out).contains("<Value ProtectInMemory=\"True\"/>"));
}

#[test]
fn fea09_16_xml_version() {
    assert_eq!(time_to_binary(at(2024, 1, 1, 0, 0, 0)), "gPcj3Q4AAAA=");
    for (file, pw) in [
        ("rich-v3.appvault", "demo-pass-4"),
        ("rich-v4.appvault", "demo-pass-5"),
    ] {
        let out = xml::xml(&testdata(file, pw)).unwrap();
        let s = text(&out);
        assert!(
            s.contains("<LastModificationTime>gPcj3Q4AAAA=</LastModificationTime>"),
            "{file}"
        );
        assert!(
            !s.contains(">2024-01-01T00:00:00Z<"),
            "{file}: no text times"
        );
    }
    let v4 = testdata("rich-v4.appvault", "demo-pass-5");
    let out = xml::xml(&v4).unwrap();
    let s = text(&out);
    assert!(s.contains("<QualityCheck>False</QualityCheck>"));
    assert!(s.contains("<PreviousParentGroup>"));
    let tagged = v4
        .root
        .subtree()
        .into_iter()
        .find(|g| !g.tags.is_empty())
        .expect("a group with tags");
    assert!(
        s.contains(&format!("<Tags>{}</Tags>", tagged.tags)),
        "group tags (4.1)"
    );
}

#[test]
fn fea09_17_xml_attachments() {
    let out = xml::xml(&v()).unwrap();
    let s = text(&out);
    let pool =
        "<Binaries>\n\t\t\t<Binary ID=\"0\">aGVsbG8gYXR0YWNobWVudAo=</Binary>\n\t\t</Binaries>";
    assert!(s.contains(pool), "one pool item, base64, uncompressed");
    assert!(s.find("<HistoryMaxSize>").unwrap() < s.find("<Binaries>").unwrap());
    assert!(s.find("<Binaries>").unwrap() < s.find("<CustomData>").unwrap());
    let binary = &s[s.find("<Key>note.txt</Key>").unwrap()..];
    assert!(binary[..binary.find("</Binary>").unwrap()].contains("<Value Ref=\"0\"/>"));
    // Read back with App's document reader: the attachment is restored.
    let back = read_back(out.expose());
    let mail = back
        .root
        .all_entries()
        .find(|e| e.value("Title") == "Mail")
        .unwrap();
    assert_eq!(mail.attachments[0].name, "note.txt");
    assert_eq!(mail.attachments[0].data.expose(), b"hello attachment\n");
    // Empty content and the rich vault's three attachments come back too.
    let rich = testdata("rich-v3.appvault", "demo-pass-4");
    let back = read_back(xml::xml(&rich).unwrap().expose());
    let full = |v: &Vault| -> Vec<(String, Vec<u8>)> {
        let e = v
            .root
            .all_entries()
            .find(|e| e.value("Title") == "Full demo entry")
            .unwrap();
        e.attachments
            .iter()
            .map(|a| (a.name.clone(), a.data.expose().to_vec()))
            .collect()
    };
    assert_eq!(full(&back), full(&rich));
    assert_eq!(full(&rich).len(), 3);
}

#[test]
fn fea09_18_xml_everything() {
    let vault = v();
    let out = xml::xml(&vault).unwrap();
    let s = text(&out);
    assert!(s.contains("<Name>Recycle Bin</Name>") && s.contains("<Value>Old</Value>"));
    assert_eq!(s.matches("<History>").count(), 1);
    assert!(s.contains("<DeletedObjects>"));
    assert!(s.contains("<Key>demo-key</Key>") && s.contains("<Value>demo-value</Value>"));
    let padding = String::from_utf8(app_format::document::write::PADDING_KEY.to_vec()).unwrap();
    assert!(!s.contains(&padding), "no new padding item");
    assert!(!s.contains("_LAST_MODIFIED"), "no save time");
    // Everything comes back.
    let back = read_back(out.expose());
    assert!(back.root == vault.root, "groups, entries, history, bin");
    assert_eq!(back.deleted_objects, vault.deleted_objects);
    // Item times are 4.1 only (FMT-16): V saves as 4.0, so key and value.
    let kv = |v: &Vault| {
        v.meta
            .custom_data
            .items
            .iter()
            .map(|i| (i.key.clone(), i.value.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(kv(&back), kv(&vault));
    assert_eq!(back.meta.recycle_bin, vault.meta.recycle_bin);
    let mail = back
        .root
        .all_entries()
        .find(|e| e.value("Title") == "Mail")
        .unwrap();
    assert_eq!(mail.history[0].value("UserName"), "alice");
}

#[test]
fn fea09_19_file_writing() {
    let dir = temp_dir("19");
    let target = dir.join("out.csv");
    fs::write(&target, "x").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let out = csv::csv(&v(), now());
    write_export(&target, out.expose()).unwrap();
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&target).unwrap(), out.expose());
    assert_eq!(
        fs::read_dir(&dir).unwrap().count(),
        1,
        "no temporary file left"
    );
    // A read-only folder: an error, no file, no temporary file.
    let ro = dir.join("ro");
    fs::create_dir(&ro).unwrap();
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(write_export(&ro.join("out.csv"), out.expose()).is_err());
    assert_eq!(fs::read_dir(&ro).unwrap().count(), 0);
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
    // A folder at the target path: an error, the folder untouched.
    let folder = dir.join("taken");
    fs::create_dir(&folder).unwrap();
    assert!(write_export(&folder, out.expose()).is_err());
    assert!(folder.is_dir());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fea09_20_link_at_target() {
    let dir = temp_dir("20");
    let victim = dir.join("victim.txt");
    fs::write(&victim, "victim").unwrap();
    let link = dir.join("out.csv");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let out = csv::csv(&v(), now());
    write_export(&link, out.expose()).unwrap();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "victim");
    let meta = fs::symlink_metadata(&link).unwrap();
    assert!(
        meta.file_type().is_file(),
        "the link was replaced by a regular file"
    );
    assert_eq!(fs::read(&link).unwrap(), out.expose());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fea09_21_command_line_formats() {
    assert_eq!(Format::from_option(None), Ok(Format::Xml));
    assert_eq!(Format::from_option(Some("")), Ok(Format::Xml));
    assert_eq!(Format::from_option(Some("csv")), Ok(Format::Csv));
    assert_eq!(Format::from_option(Some("HTML")), Ok(Format::Html));
    assert_eq!(Format::from_option(Some("xml")), Ok(Format::Xml));
    assert_eq!(
        Format::from_option(Some("bogus")),
        Err("bogus is not an export format. Use xml, csv or html.".to_owned())
    );
    // The command line's CSV equals 09-03; its HTML is sorted ascending
    // without icons.
    assert_eq!(text(&csv::csv(&v(), now())), V_CSV);
    let page = cli(&v(), Sort::NameAscending);
    assert!(!page.contains("<img"));
    // LD-42: the warning it prints on standard error.
    assert!(!export::warning(Format::Xml).is_empty());
}

#[test]
fn fea09_22_no_other_formats() {
    // Exactly three formats: a fourth breaks this match.
    for f in [Format::Csv, Format::Html, Format::Xml] {
        match f {
            Format::Csv | Format::Html | Format::Xml => {}
        }
    }
    assert_eq!(
        [Format::Csv, Format::Html, Format::Xml].map(Format::extension),
        ["csv", "html", "xml"]
    );
}

#[test]
fn fea09_23_secrets() {
    // Core part of FEA-09.18 (the memory dump and logs are the Verify
    // agent's): every export comes back in a wiping secret buffer that
    // prints as [hidden].
    let vault = v();
    let csv_out: SecretBytes = csv::csv(&vault, now());
    let html_out: SecretBytes = html::html(
        &vault,
        &HtmlOptions {
            sort: Sort::default(),
            path: "",
            icon: None,
        },
    );
    let xml_out: SecretBytes = xml::xml(&vault).unwrap();
    for out in [&csv_out, &html_out, &xml_out] {
        assert_eq!(format!("{out:?}"), "[hidden]");
        assert!(text(out).contains("demo-secret-1"));
    }
}

#[test]
fn fea09_24_round_trip() {
    let exported = csv::csv(&v(), now());
    let parsed = import::csv::parse(exported.expose(), &import::csv::Options::default()).unwrap();
    let map = import::csv::auto_map(&parsed, None);
    let (skip, _) = parsed.skip_range();
    let cancel = AtomicBool::new(false);
    let ctx = import::Context::new(now(), &Utc, &cancel);
    let r = import::csv::build(&parsed, &map, skip, "/tmp/v.csv", &ctx).unwrap();
    let root = &r.vault.root;
    assert_eq!(root.name, "Passwords");
    let names: Vec<&str> = root.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["Work", "Recycle Bin"]);
    assert_eq!(root.groups[0].groups[0].name, "Sub");
    assert!(
        r.vault.meta.recycle_bin.is_none(),
        "the bin comes back as a normal group"
    );
    assert!(
        root.all_entries()
            .all(|e| e.attachments.is_empty() && e.history.is_empty())
    );
    // The same 10 columns: exporting the import gives the same bytes.
    assert_eq!(text(&csv::csv(&r.vault, now())), V_CSV);
}

#[test]
fn sd_07_passkey_file_is_int04_49() {
    // INT-04.49: six members sorted by name, 4 spaces, `": "`, LF, a final
    // LF, `/` not escaped; the generated id and the other apps' user name
    // win (INT-04.4); no backup flags. INT-04.50: the clean file name.
    let mut e = ent(0x30, " Bank: \"main\" / A|B ", "bob", "pw", t(24));
    set(&mut e, "URL", "https://bank.example/login");
    set(&mut e, "KPEX_PASSKEY_RELYING_PARTY", "bank.example");
    set(&mut e, "KPEX_PASSKEY_USERNAME", "bob@bank");
    set(&mut e, "KPEX_PASSKEY_CREDENTIAL_ID", "Y3JlZA");
    set(&mut e, "KPEX_PASSKEY_USER_HANDLE", "dXNlcg");
    set(
        &mut e,
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "-----BEGIN PRIVATE KEY-----\nAB/C\n-----END PRIVATE KEY-----",
    );
    set(&mut e, "KPEX_PASSKEY_FLAG_BE", "1");
    let file = export::passkey::file(&e).unwrap();
    assert_eq!(
        std::str::from_utf8(file.expose()).unwrap(),
        "{\n    \"credentialId\": \"Y3JlZA\",\n    \"privateKey\": \"-----BEGIN PRIVATE KEY-----\\nAB/C\\n-----END PRIVATE KEY-----\",\n    \"relyingParty\": \"bank.example\",\n    \"url\": \"https://bank.example/login\",\n    \"userHandle\": \"dXNlcg\",\n    \"username\": \"bob@bank\"\n}\n"
    );
    assert_eq!(export::passkey::file_name(&e), "Bank main _ AB.passkey");
    set(&mut e, "KPEX_PASSKEY_GENERATED_USER_ID", "Zm9yZWlnbg");
    let foreign = String::from_utf8(vec![
        0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x41, 0x53, 0x53, 0x4B, 0x45, 0x59, 0x5F, 0x55, 0x53,
        0x45, 0x52, 0x4E, 0x41, 0x4D, 0x45,
    ])
    .unwrap();
    set(&mut e, &foreign, "bob-other");
    set(&mut e, "Title", " / ");
    let text = String::from_utf8(export::passkey::file(&e).unwrap().expose().to_vec()).unwrap();
    assert!(text.contains("\"credentialId\": \"Zm9yZWlnbg\""), "{text}");
    assert!(text.contains("\"username\": \"bob-other\""), "{text}");
    assert_eq!(export::passkey::file_name(&e), "_.passkey");
    set(&mut e, "Title", " :* ");
    assert_eq!(export::passkey::file_name(&e), "bank.example.passkey");
    // No private key field: not a passkey of the report.
    assert!(export::passkey::file(&ent(0x31, "x", "", "", t(24))).is_none());
    assert!(export::passkey::WARNING.contains("not encrypted"));
}
