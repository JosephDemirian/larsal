//! Document reader tests (story E3-S6), named by the card test rows of
//! FMT-09, FMT-10, FMT-11, FMT-12, FMT-13, FMT-14 and FMT-15, plus the
//! attacks AT-A07 (XML attacks) and AT-A08 (hostile documents).
#![allow(clippy::arithmetic_side_effects)] // test arithmetic (Rust rule 4 is about input)

use app_crypto::secret::SecretBytes;
use app_crypto::stream::FieldStream;
use app_format::Error;
use app_format::document::encode::{base64_encode, uuid_to_text};
use app_format::document::{Document, Limit, Options, Reason, Warning, read};
use app_format::limits::Limits;
use app_model::{Icon, Switch, Time, UnknownElement, UnknownNode, Uuid, Vault};
use std::time::Instant;

/// The document root element name (stored encoded, name rule).
const ROOT_NAME: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
];
/// 2026-10-24T19:19:32Z, the open time of the FMT-11 rows.
const OPEN: Time = Time(63_928_466_372);

fn root_name() -> &'static str {
    std::str::from_utf8(ROOT_NAME).unwrap()
}

fn id(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn idt(b: u8) -> String {
    uuid_to_text(id(b))
}

/// The protected-field stream with an all-zero 64-byte key (FMT-12.22 rows).
fn zero_key() -> Vec<u8> {
    vec![0; 64]
}

/// S4 = 00 01 … 3F (FMT-09 common vector, version 4).
fn s4() -> Vec<u8> {
    (0u8..64).collect()
}

fn chacha(key: &[u8]) -> FieldStream {
    FieldStream::chacha20_from_stream_key(&SecretBytes::new(key.to_vec())).unwrap()
}

/// `plain` XORed with the version 4 keystream of `key` from byte `at`, as base64.
fn enc(key: &[u8], at: usize, plain: &[u8]) -> String {
    let mut s = chacha(key);
    s.apply(&mut vec![0; at]).unwrap();
    let mut buf = plain.to_vec();
    s.apply(&mut buf).unwrap();
    base64_encode(&buf)
}

fn doc(meta: &str, root: &str) -> String {
    let r = root_name();
    format!("<{r}><Meta>{meta}</Meta><Root>{root}</Root></{r}>")
}

/// A document whose root group, id(01), holds `content`.
fn g(content: &str) -> String {
    doc(
        "",
        &format!("<Group><UUID>{}</UUID>{content}</Group>", idt(1)),
    )
}

/// An entry with id `n` holding `content`.
fn entry(n: u8, content: &str) -> String {
    format!("<Entry><UUID>{}</UUID>{content}</Entry>", idt(n))
}

fn s(key: &str, value: &str) -> String {
    format!("<String><Key>{key}</Key><Value>{value}</Value></String>")
}

fn sp(key: &str, b64: &str) -> String {
    format!("<String><Key>{key}</Key><Value Protected=\"True\">{b64}</Value></String>")
}

struct Run {
    key: Vec<u8>,
    pool: Vec<Vec<u8>>,
    lim: Limits,
    v3_header: Option<Vec<u8>>,
}

impl Default for Run {
    fn default() -> Self {
        Run {
            key: zero_key(),
            pool: Vec::new(),
            lim: Limits::DEFAULT,
            v3_header: None,
        }
    }
}

impl Run {
    fn bytes(&self, xml: &[u8]) -> Result<Document, Reason> {
        let mut stream = chacha(&self.key);
        let pool: Vec<&[u8]> = self.pool.iter().map(Vec::as_slice).collect();
        let opts = Options {
            open_time: OPEN,
            limits: &self.lim,
            v3_header: self.v3_header.as_deref(),
        };
        read(xml, &mut stream, &pool, &opts)
    }
    fn ok(&self, xml: &str) -> Vault {
        match self.bytes(xml.as_bytes()) {
            Ok(d) => d.vault,
            Err(e) => panic!("read failed: {e:?}"),
        }
    }
    fn doc(&self, xml: &str) -> Document {
        self.bytes(xml.as_bytes()).unwrap()
    }
    fn err(&self, xml: &str) -> Reason {
        match self.bytes(xml.as_bytes()) {
            Ok(_) => panic!("read should fail"),
            Err(e) => e,
        }
    }
}

fn ok(xml: &str) -> Vault {
    Run::default().ok(xml)
}

fn err(xml: &str) -> Reason {
    Run::default().err(xml)
}

fn pool(items: &[&[u8]]) -> Run {
    Run {
        pool: items.iter().map(|i| i.to_vec()).collect(),
        ..Run::default()
    }
}

fn keyed(key: Vec<u8>) -> Run {
    Run {
        key,
        ..Run::default()
    }
}

fn first_entry(v: &Vault) -> &app_model::Entry {
    v.root.all_entries().next().expect("an entry")
}

fn att<'v>(e: &'v app_model::Entry, name: &str) -> &'v [u8] {
    e.attachments
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("attachment {name}"))
        .data
        .expose()
}

fn renamed<'v>(e: &'v app_model::Entry, name: &str) -> &'v [u8] {
    let a = e
        .attachments
        .iter()
        .find(|a| {
            a.name.len() == 9 + name.len()
                && a.name.ends_with(&format!("_{name}"))
                && a.name[..8]
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .expect("renamed attachment");
    a.data.expose()
}

fn names(groups: &[app_model::Group]) -> Vec<&str> {
    groups.iter().map(|g| g.name.as_str()).collect()
}

fn titles(entries: &[app_model::Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.value("Title")).collect()
}

fn text(el: &UnknownElement) -> &str {
    match el.content.as_slice() {
        [UnknownNode::Text(t)] => t,
        [] => "",
        _ => panic!("not text only"),
    }
}

// ===========================================================================
// FMT-10: frame, XML input, Meta.

#[test]
fn fmt_10_5_no_meta() {
    let r = root_name();
    let v = ok(&format!(
        "<{r}><Root><Group><UUID>rH4xp1/3SoWQeYTLdwFNVA==</UUID><Name>R</Name></Group></Root></{r}>"
    ));
    let m = &v.meta;
    assert_eq!(m.generator, "App");
    assert_eq!(m.maintenance_history_days, 365);
    assert_eq!(
        (m.master_key_change_rec, m.master_key_change_force),
        (-1, -1)
    );
    assert!(m.recycle_bin_enabled && m.memory_protection.password);
    assert_eq!((m.history_max_items, m.history_max_size), (10, 6_291_456));
    for t in [
        m.name_changed,
        m.description_changed,
        m.default_user_name_changed,
        m.master_key_changed,
        m.recycle_bin_changed,
        m.entry_templates_group_changed,
        m.settings_changed,
    ] {
        assert_eq!(t, OPEN);
    }
    assert_eq!(v.root.name, "R");
}

#[test]
fn fmt_10_5_meta_after_root_and_two_meta() {
    let r = root_name();
    let v = ok(&format!(
        "<{r}><Root><Group/></Root><Meta><DatabaseName>Né</DatabaseName></Meta></{r}>"
    ));
    assert_eq!(v.meta.name, "Né");
    let v = ok(&format!(
        "<{r}><Meta><DatabaseName>A</DatabaseName><Color>#000000</Color></Meta>\
         <Meta><DatabaseName>B</DatabaseName></Meta><Root><Group/></Root></{r}>"
    ));
    assert_eq!(
        (v.meta.name.as_str(), v.meta.color.as_str()),
        ("B", "#000000")
    );
}

#[test]
fn fmt_10_5_two_root_and_wrong_root_name() {
    let r = root_name();
    let e = err(&format!(
        "<{r}><Root><Group/></Root><Root><Group/></Root></{r}>"
    ));
    assert_eq!(e, Reason::TwoRootGroups);
    assert_eq!(e.kind(), Error::Corrupt);
    // 11-02 wrong root name.
    let e = err(
        r#"<?xml version="1.0"?><Other><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></Other>"#,
    );
    assert_eq!(e, Reason::NoRootGroup);
}

#[test]
fn fmt_10_5_trailing_content() {
    let base = g("");
    for tail in [
        &b"<x/>"[..],
        b"\x01",
        b"garbage<",
        b"\xFF",
        b"\n<junk>not closed\n",
    ] {
        let mut x = base.as_bytes().to_vec();
        x.extend_from_slice(tail);
        Run::default().bytes(&x).unwrap();
    }
    let mut x = base.into_bytes();
    x.extend(std::iter::repeat_n(b' ', 9000));
    x.push(0xFF);
    Run::default().bytes(&x).unwrap();
}

#[test]
fn fmt_10_5_stray_content_in_meta_containers() {
    let st = "junk &amp; text<!-- c --><?pi x?>";
    let meta = format!(
        "{st}<DatabaseName>Ne</DatabaseName>{st}<MemoryProtection>{st}<ProtectTitle>True</ProtectTitle>\
         {st}<ProtectPassword>False</ProtectPassword>{st}</MemoryProtection>{st}<Binaries>{st}\
         <Binary ID=\"0\">QUFB</Binary>{st}<Binary ID=\"1\">QkJC</Binary>{st}</Binaries>{st}\
         <DatabaseDescription>D</DatabaseDescription>{st}"
    );
    let e = entry(
        0x10,
        "<Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary><Binary><Key>b.txt</Key><Value Ref=\"1\"/></Binary>",
    );
    let v = ok(&doc(
        &meta,
        &format!("<Group><UUID>{}</UUID>{e}</Group>", idt(1)),
    ));
    assert_eq!(
        (v.meta.name.as_str(), v.meta.description.as_str()),
        ("Ne", "D")
    );
    assert!(v.meta.memory_protection.title && !v.meta.memory_protection.password);
    let en = first_entry(&v);
    assert_eq!(att(en, "a.txt"), b"AAA");
    assert_eq!(att(en, "b.txt"), b"BBB");
    assert!(v.meta.unknown.is_empty());
}

#[test]
fn fmt_10_5_unknown_top_child() {
    let r = root_name();
    let v = ok(&format!(
        "<{r}><Extra>1</Extra><Meta/><Root><Group/></Root><After/></{r}>"
    ));
    let names: Vec<&str> = v.unknown_document.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, ["Extra", "After"]);
    assert_eq!(text(&v.unknown_document[0]), "1");
}

#[test]
fn fmt_10_6_root_without_group_and_two_groups() {
    assert_eq!(err(&doc("", "")), Reason::NoRootGroup); // also 11-04
    assert_eq!(
        err(&doc(
            "",
            &format!(
                "<Group><UUID>{}</UUID></Group><Group><UUID>{}</UUID></Group>",
                idt(1),
                idt(0x10)
            )
        )),
        Reason::TwoRootGroups // 11-05
    );
    let r = root_name();
    assert_eq!(err(&format!("<{r}><Meta/></{r}>")), Reason::NoRootGroup);
}

#[test]
fn fmt_10_7_names_and_namespaces() {
    let v = ok(&doc("<databasename>X</databasename>", "<Group/>"));
    assert_eq!(v.meta.name, "");
    assert_eq!(v.meta.unknown[0].name, "databasename");
    let r = root_name();
    let v = ok(&format!(
        "<{r} xmlns:x=\"urn:x\"><x:Meta><x:DatabaseName>P</x:DatabaseName></x:Meta><Root><Group/></Root></{r}>"
    ));
    assert_eq!(v.meta.name, "P");
    let e = err(&format!(
        "<{r}><x:Meta><x:DatabaseName>P</x:DatabaseName></x:Meta><Root><Group/></Root></{r}>"
    ));
    assert_eq!(e, Reason::NotXml);
    // Default namespace is ignored.
    let v = ok(&format!(
        "<{r} xmlns=\"urn:d\"><Meta><DatabaseName>D</DatabaseName></Meta><Root><Group/></Root></{r}>"
    ));
    assert_eq!(v.meta.name, "D");
}

#[test]
fn fmt_10_7_attributes_not_by_local_name() {
    // Also FMT-12.13 attribute name, prefix and case.
    let r = root_name();
    let v = ok(&format!(
        "<{r} xmlns:x=\"urn:x\"><Meta><DatabaseName x:Protected=\"True\">RxjmIZKk</DatabaseName>\
         <DatabaseDescription Protected=\"True\">RxjmIZKk</DatabaseDescription></Meta><Root><Group/></Root></{r}>"
    ));
    assert_eq!(v.meta.name, "RxjmIZKk");
    assert_eq!(v.meta.description, "Secret");
    for attr in ["protected", "PROTECTED"] {
        let v = ok(&doc(
            &format!(
                "<DatabaseName {attr}=\"True\">RxjmIZKk</DatabaseName><DatabaseDescription Protected=\"True\">RxjmIZKk</DatabaseDescription>"
            ),
            "<Group/>",
        ));
        assert_eq!(
            (v.meta.name.as_str(), v.meta.description.as_str()),
            ("RxjmIZKk", "Secret")
        );
    }
}

fn body(name: &str) -> String {
    let r = root_name();
    format!("<{r}><Meta><DatabaseName>{name}</DatabaseName></Meta><Root><Group/></Root></{r}>")
}

#[test]
fn fmt_10_8_declaration_bom_and_detection() {
    let plain = body("Ne");
    assert_eq!(ok(&plain).meta.name, "Ne");
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(plain.as_bytes());
    assert_eq!(Run::default().bytes(&bom).unwrap().vault.meta.name, "Ne");
    assert_eq!(ok(&format!("\n{plain}")).meta.name, "Ne");
    let mut nul = vec![0, 0];
    nul.extend_from_slice(plain.as_bytes());
    assert_eq!(Run::default().bytes(&nul).unwrap_err(), Reason::NotXml);

    let utf16le: Vec<u8> = plain.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let utf16be: Vec<u8> = plain.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let utf32le: Vec<u8> = plain
        .chars()
        .flat_map(|c| (c as u32).to_le_bytes())
        .collect();
    let utf32be: Vec<u8> = plain
        .chars()
        .flat_map(|c| (c as u32).to_be_bytes())
        .collect();
    let with = |mark: &[u8], b: &[u8]| [mark, b].concat();
    for x in [
        utf16le.clone(),
        utf16be.clone(),
        with(&[0xFF, 0xFE], &utf16le),
        with(&[0xFE, 0xFF], &utf16be),
        utf32le.clone(),
        utf32be.clone(),
        with(&[0xFF, 0xFE, 0, 0], &utf32le),
        with(&[0, 0, 0xFE, 0xFF], &utf32be),
    ] {
        let e = Run::default().bytes(&x).unwrap_err();
        assert_eq!(
            (e, e.kind()),
            (Reason::UnsupportedEncoding, Error::Unsupported)
        );
    }
}

#[test]
fn fmt_10_8_versions_and_broken_declarations() {
    let b = body("Ne");
    for (decl, want) in [
        (r#"<?xml version="1.1"?>"#, Reason::UnsupportedXmlVersion),
        (r#"<?xml version="1.00"?>"#, Reason::UnsupportedXmlVersion),
        (r#"<?xml version="2.0"?>"#, Reason::NotXml),
        (r#"<?xml version="1.0 "?>"#, Reason::NotXml),
        (r#"<?xml encoding="UTF-8"?>"#, Reason::NotXml),
        (r#"<?XML version="1.0"?>"#, Reason::NotXml),
        (r#" <?xml version="1.0"?>"#, Reason::NotXml),
        (
            r#"<?xml version="1.0" standalone="yes" encoding="UTF-8"?>"#,
            Reason::NotXml,
        ),
        (
            r#"<?xml version="1.0" standalone="maybe"?>"#,
            Reason::NotXml,
        ),
    ] {
        let e = err(&format!("{decl}{b}"));
        assert_eq!(e, want, "{decl}");
    }
    assert_eq!(
        err(r#"<?xml version="1.1"?><a/>"#).kind(),
        Error::Unsupported
    );
    assert_eq!(
        ok(&format!("<?xml version='1.0' encoding='UTF-8'?>{b}"))
            .meta
            .name,
        "Ne"
    );
    assert_eq!(
        ok(&format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>{b}"#
        ))
        .meta
        .name,
        "Ne"
    );
    // A second declaration anywhere later is refused.
    assert_eq!(
        err(&format!(r#"<?xml version="1.0"?>{b}"#)
            .replace("<Meta>", "<Meta><?xml version=\"1.0\"?>")),
        Reason::NotXml
    );
}

#[test]
fn fmt_10_8_encoding_names() {
    let b = body("Ne");
    for name in [
        "utf-8", "Utf-8", "uTf-8", "UTF8", "UTF_8", "utf.8", "U.T.F.8", "u-t_f.8", "UTF-8",
    ] {
        assert_eq!(
            ok(&format!(r#"<?xml version="1.0" encoding="{name}"?>{b}"#))
                .meta
                .name,
            "Ne",
            "{name}"
        );
    }
    for name in ["_utf8", "utf 8", "UTF+8"] {
        assert_eq!(
            err(&format!(r#"<?xml version="1.0" encoding="{name}"?>{b}"#)),
            Reason::NotXml,
            "{name}"
        );
    }
    for name in ["US-ASCII", "ascii", "ISO-8859-1", "latin1", "UTF-16"] {
        let e = err(&format!(r#"<?xml version="1.0" encoding="{name}"?>{b}"#));
        assert_eq!(
            (e, e.kind()),
            (Reason::UnsupportedEncoding, Error::Unsupported),
            "{name}"
        );
    }
    let mut latin = br#"<?xml version="1.0" encoding="ISO-8859-1"?>"#.to_vec();
    latin.extend_from_slice(body("N\u{e9}").as_bytes());
    assert_eq!(
        Run::default().bytes(&latin).unwrap_err(),
        Reason::UnsupportedEncoding
    );
}

#[test]
fn fmt_10_9_doctype_and_undefined_entity() {
    // Also 11-49 and AT-A07 entity expansion.
    let r = root_name();
    let e = err(&format!(
        "<!DOCTYPE {r} [<!ENTITY e \"EXPANDED\">]><{r}><Meta><DatabaseName>&e;</DatabaseName></Meta><Root><Group/></Root></{r}>"
    ));
    assert_eq!(
        (e, e.kind()),
        (Reason::ForbiddenDeclaration, Error::Corrupt)
    );
    assert_eq!(err(&body("&nbsp;")), Reason::ForbiddenDeclaration);
}

#[test]
fn fmt_10_11_row_28_known_without_keystream() {
    let v = ok(&doc(
        "<MasterKeyChangeForceOnce Protected=\"True\">QUJD</MasterKeyChangeForceOnce><DatabaseName Protected=\"True\">RxjmIZKk</DatabaseName>",
        "<Group/>",
    ));
    assert!(!v.meta.master_key_change_force_once);
    assert_eq!(v.meta.name, "Secret");
    assert!(v.meta.unknown.is_empty());
    let v = ok(&doc(
        "<MasterKeyChangeForceOnce>tRUE</MasterKeyChangeForceOnce>",
        "<Group/>",
    ));
    assert!(v.meta.master_key_change_force_once);
    let v = ok(&doc(
        "<MasterKeyChangeForceOnce>yes</MasterKeyChangeForceOnce>",
        "<Group/>",
    ));
    assert!(!v.meta.master_key_change_force_once);
}

#[test]
fn fmt_10_11_any_order_and_containers_take_no_keystream() {
    let v = ok(&doc(
        "<HistoryMaxSize>5</HistoryMaxSize><DatabaseName>N</DatabaseName><Generator>G</Generator>",
        "<Group/>",
    ));
    assert_eq!(
        (
            v.meta.history_max_size,
            v.meta.name.as_str(),
            v.meta.generator.as_str()
        ),
        (5, "N", "G")
    );
    let v = ok(&doc(
        "<MemoryProtection Protected=\"True\">QUJD<ProtectTitle>True</ProtectTitle></MemoryProtection>\
         <CustomIcons Protected=\"True\"/><CustomData Protected=\"True\">QUJD</CustomData>\
         <DatabaseName Protected=\"True\">RxjmIZKk</DatabaseName>",
        "<Group/>",
    ));
    assert!(v.meta.memory_protection.title);
    assert_eq!(v.meta.name, "Secret");
}

#[test]
fn fmt_10_11_v3_only_elements_in_v4() {
    let v = ok(&doc("<Binaries/><HeaderHash>AAAA</HeaderHash>", "<Group/>"));
    assert!(v.meta.unknown.is_empty());
}

#[test]
fn fmt_10_11_binaries_in_v4_join_the_pool() {
    // Also T13-11.
    let e = entry(
        0x10,
        "<Binary><Key>a</Key><Value Ref=\"0\"/></Binary><Binary><Key>b</Key><Value Ref=\"7\"/></Binary>",
    );
    let v = pool(&[b"zero"]).ok(&doc(
        &format!(
            "<Binaries><Binary ID=\"0\">{}</Binary><Binary ID=\"7\">{}</Binary></Binaries>",
            base64_encode(b"from-meta"),
            base64_encode(b"seven")
        ),
        &format!("<Group>{e}</Group>"),
    ));
    let en = first_entry(&v);
    assert_eq!(att(en, "a"), b"from-meta");
    assert_eq!(att(en, "b"), b"seven");
}

#[test]
fn fmt_10_12_to_10_14_values() {
    for meta in [
        "<DatabaseName>N</DatabaseName><DatabaseNameChanged>Zd/www4AAAA=</DatabaseNameChanged>",
        "<DatabaseNameChanged>Zd/www4AAAA=</DatabaseNameChanged><DatabaseName>N</DatabaseName>",
    ] {
        assert_eq!(
            ok(&doc(meta, "<Group/>")).meta.name_changed,
            Time(63_416_885_093)
        );
    }
    assert_eq!(
        ok(&doc(
            "<DatabaseName>A</DatabaseName><DatabaseName>B</DatabaseName>",
            "<Group/>"
        ))
        .meta
        .name,
        "B"
    );
    assert_eq!(
        err(&doc(
            "<MaintenanceHistoryDays></MaintenanceHistoryDays>",
            "<Group/>"
        )),
        Reason::InvalidNumber
    );
    assert_eq!(
        err(&doc(
            "<RecycleBinEnabled>yes</RecycleBinEnabled>",
            "<Group/>"
        )),
        Reason::InvalidBoolean
    );
    assert_eq!(
        ok(&doc(
            "<RecycleBinChanged>garbage</RecycleBinChanged>",
            "<Group/>"
        ))
        .meta
        .recycle_bin_changed,
        OPEN
    );
    assert!(
        !ok(&doc("<RecycleBinEnabled/>", "<Group/>"))
            .meta
            .recycle_bin_enabled
    );
    assert_eq!(
        ok(&doc("<HistoryMaxItems> 7 </HistoryMaxItems>", "<Group/>"))
            .meta
            .history_max_items,
        7
    );
    for bad in ["0x10", "7.0", "2147483648"] {
        assert_eq!(
            err(&doc(
                &format!("<HistoryMaxItems>{bad}</HistoryMaxItems>"),
                "<Group/>"
            )),
            Reason::InvalidNumber
        );
    }
}

#[test]
fn fmt_10_15_history_limits() {
    let v = ok(&doc(
        "<HistoryMaxItems>-2</HistoryMaxItems><HistoryMaxSize>-5</HistoryMaxSize>",
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.history_max_items, v.meta.history_max_size),
        (10, 6_291_456)
    );
    let v = ok(&doc(
        "<HistoryMaxItems>5</HistoryMaxItems><HistoryMaxItems>-2</HistoryMaxItems>",
        "<Group/>",
    ));
    assert_eq!(v.meta.history_max_items, 5);
    let v = ok(&doc(
        "<HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>-1</HistoryMaxSize>",
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.history_max_items, v.meta.history_max_size),
        (-1, -1)
    );
}

#[test]
fn fmt_10_16_group_references() {
    let d = Run::default().doc(&doc(
        "<RecycleBinUUID>6w7wZdhAp0qVlXjkemuCYw==</RecycleBinUUID>",
        "<Group/>",
    ));
    assert_eq!(d.vault.meta.recycle_bin, None);
    assert!(d.warnings.contains(&Warning::UnresolvedReference {
        element: "RecycleBinUUID"
    }));
    // Resolves late: the group comes after Meta.
    let v = ok(&doc(
        &format!("<LastSelectedGroup>{}</LastSelectedGroup>", idt(2)),
        &format!(
            "<Group><UUID>{}</UUID><Group><UUID>{}</UUID></Group></Group>",
            idt(1),
            idt(2)
        ),
    ));
    assert_eq!(v.meta.last_selected_group, Some(id(2)));
    // Root as target: all four references kept (FMT-10.16).
    let r = "rH4xp1/3SoWQeYTLdwFNVA==";
    let v = ok(&doc(
        &format!(
            "<RecycleBinUUID>{r}</RecycleBinUUID><EntryTemplatesGroup>{r}</EntryTemplatesGroup><LastSelectedGroup>{r}</LastSelectedGroup><LastTopVisibleGroup>{r}</LastTopVisibleGroup>"
        ),
        &format!("<Group><UUID>{r}</UUID></Group>"),
    ));
    let rid = v.root.uuid;
    assert_eq!(v.meta.recycle_bin, Some(rid));
    assert_eq!(v.meta.entry_templates_group, Some(rid));
    assert_eq!(v.meta.last_selected_group, Some(rid));
    assert_eq!(v.meta.last_top_visible_group, Some(rid));
    assert_eq!(app_model::invariants::check(&v), Ok(()));
}

#[test]
fn fmt_10_17_memory_protection() {
    let v = ok(&doc(
        "<MemoryProtection><ProtectUserName>True</ProtectUserName><Foo/></MemoryProtection>",
        "<Group/>",
    ));
    let p = &v.meta.memory_protection;
    assert!(!p.title && p.user_name && p.password && !p.url && !p.notes);
    assert_eq!(p.unknown[0].name, "Foo");
    let v = ok(&doc(
        "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectPassword>False</ProtectPassword></MemoryProtection>\
         <MemoryProtection><ProtectNotes>True</ProtectNotes></MemoryProtection>",
        "<Group/>",
    ));
    let p = &v.meta.memory_protection;
    assert!(p.title && !p.user_name && !p.password && !p.url && p.notes);
}

#[test]
fn fmt_10_18_and_10_19_carried_values() {
    let v = ok(&doc(
        &format!(
            "<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>{}</RecycleBinUUID>\
                  <MasterKeyChangeRec>0</MasterKeyChangeRec><MasterKeyChangeForce>30</MasterKeyChangeForce>\
                  <MaintenanceHistoryDays>-5</MaintenanceHistoryDays><Color>red</Color>",
            idt(2)
        ),
        &format!(
            "<Group><UUID>{}</UUID><Group><UUID>{}</UUID></Group></Group>",
            idt(1),
            idt(2)
        ),
    ));
    assert!(!v.meta.recycle_bin_enabled);
    assert_eq!(v.meta.recycle_bin, Some(id(2)));
    assert_eq!(
        (v.meta.master_key_change_rec, v.meta.master_key_change_force),
        (0, 30)
    );
    assert_eq!(v.meta.maintenance_history_days, -5);
    assert_eq!(v.meta.color, "red");
}

#[test]
fn fmt_10_20_unknown_meta_children() {
    let v = ok(&doc(
        "<U1/><DatabaseName>n</DatabaseName><FooBar a=\"1\" b=\"2\">x<Baz/></FooBar><U2>t</U2>",
        "<Group/>",
    ));
    let names: Vec<&str> = v.meta.unknown.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, ["U1", "FooBar", "U2"]);
    let f = &v.meta.unknown[1];
    assert_eq!(
        f.attributes,
        [("a".into(), "1".into()), ("b".into(), "2".into())]
    );
    assert!(
        matches!(&f.content[..], [UnknownNode::Text(t), UnknownNode::Element(b)] if t == "x" && b.name == "Baz")
    );
    // Unknown attribute on a known element is dropped; comment in a kept element joins text.
    let v = ok(&doc("<Ext>a<!-- c -->b</Ext>", "<Group/>"));
    assert_eq!(text(&v.meta.unknown[0]), "ab");
    let r = root_name();
    let v = ok(&format!(
        "<{r}><Meta foo=\"1\"/><Root><Group/></Root></{r}>"
    ));
    assert!(v.meta.unknown.is_empty());
}

#[test]
fn fmt_10_20_prefixes_and_namespaces() {
    let r = root_name();
    let v = ok(&format!(
        "<{r} xmlns:x=\"urn:x\"><Meta><x:Ext xmlns:y=\"urn:y\" k=\"v\">1</x:Ext><x:Ext x:k=\"1\" k=\"2\"/>\
         <Ext xml:lang=\"en\" a=\"1\"/><Ext xmlns=\"urn:d\"><x:In x:k=\"1\" k=\"2\"/></Ext></Meta><Root><Group/></Root></{r}>"
    ));
    let u = &v.meta.unknown;
    assert_eq!(
        (u[0].name.as_str(), u[0].attributes.clone()),
        ("Ext", vec![("k".into(), "v".into())])
    );
    assert_eq!(u[1].attributes, [("k".into(), "2".into())]);
    assert_eq!(u[2].attributes, [("a".into(), "1".into())]);
    assert!(u[3].attributes.is_empty());
    assert!(
        matches!(&u[3].content[..], [UnknownNode::Element(i)] if i.name == "In" && i.attributes == [("k".into(), "2".into())])
    );
}

#[test]
fn fmt_10_20_protected_in_unknown() {
    // Also FMT-12.22 "unknown element not decoded" and T09-14.
    let pw = sp("Password", "ZAqoPJm1");
    let v = ok(&doc(
        "<X Protected=\"True\">QUJD</X>",
        &format!("<Group>{}</Group>", entry(0x10, &pw)),
    ));
    assert_eq!(text(&v.meta.unknown[0]), "QUJD");
    assert_eq!(
        v.meta.unknown[0].attributes,
        [("Protected".into(), "True".into())]
    );
    assert_eq!(first_entry(&v).value("Password"), "pw-one");
    // Its writer took bytes: the password decodes from byte 0 to garbage, as in the reference.
    let v = ok(&doc(
        "<X Protected=\"True\">VT/G</X>",
        &format!(
            "<Group>{}</Group>",
            entry(0x10, &sp("Password", "I4D9HhA1"))
        ),
    ));
    assert_ne!(first_entry(&v).value("Password"), "pw-one");
    // T09-14 with S4, inside an entry.
    let foo = "<FooBar Protected=\"True\">QUJD</FooBar>";
    let v = keyed(s4()).ok(&g(&entry(
        0x10,
        &format!("{foo}{}", sp("Password", "/J+RDmSl")),
    )));
    let e = first_entry(&v);
    assert_eq!(e.value("Password"), "pw-one");
    assert_eq!(text(&e.unknown[0]), "QUJD");
    // T09-37: a known name inside an unknown element is not decoded either.
    let v = keyed(s4()).ok(&g(&entry(
        0x10,
        &format!(
            "<FooBar><Value Protected=\"True\">QUJD</Value></FooBar>{}",
            sp("Password", "/J+RDmSl")
        ),
    )));
    assert_eq!(first_entry(&v).value("Password"), "pw-one");
}

#[test]
fn fmt_10_21_header_hash() {
    // Formula vector.
    let header = [
        0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x01, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00,
        0x0D, 0x0A, 0x0D, 0x0A,
    ];
    let hash = base64_encode(app_crypto::hash::sha256(&[&header]).expose());
    assert_eq!(hash, "n/jx1dVaryThUgTEOzDpyhDrRHlaLga9fkWJQvMzUxY=");
    let v3 = Run {
        v3_header: Some(header.to_vec()),
        ..Run::default()
    };
    v3.ok(&doc(
        &format!("<HeaderHash>{hash}</HeaderHash>"),
        "<Group/>",
    ));
    v3.ok(&doc("", "<Group/>")); // missing: nothing checked (LD-11)
    v3.ok(&doc("<HeaderHash/>", "<Group/>"));
    v3.ok(&doc(
        &format!("<HeaderHash>AAAA</HeaderHash><HeaderHash>{hash}</HeaderHash>"),
        "<Group/>",
    ));
    let e = v3.err(&doc("<HeaderHash>AAAA</HeaderHash>", "<Group/>"));
    assert_eq!((e, e.kind()), (Reason::HeaderHashMismatch, Error::Corrupt));
    // Version 4: read and ignored.
    ok(&doc("<HeaderHash>AAAA</HeaderHash>", "<Group/>"));
}

#[test]
fn fmt_10_22_generator_kept() {
    assert_eq!(
        ok(&doc("<Generator>OtherApp 1.0</Generator>", "<Group/>"))
            .meta
            .generator,
        "OtherApp 1.0"
    );
}

#[test]
fn fmt_10_28_attribute_values_on_read() {
    let v = ok(&doc(
        "<Ext a=\"x&#9;y\"/><Ext a=\"&lt;&amp;&quot;'&gt;\" b=\"l1&#10;l2&#13;\" c=\"p\tq\"/>",
        "<Group/>",
    ));
    assert_eq!(v.meta.unknown[0].attributes, [("a".into(), "x\ty".into())]);
    assert_eq!(
        v.meta.unknown[1].attributes,
        [
            ("a".into(), "<&\"'>".into()),
            ("b".into(), "l1\nl2\r".into()),
            ("c".into(), "p q".into())
        ]
    );
}

// ===========================================================================
// FMT-11: groups and entries.

#[test]
fn fmt_11_06_to_11_08_group_children() {
    // 11-08 UUID last; 11-09 repeated Name.
    let v = ok(&doc(
        "",
        &format!(
            "<Group><Name>R</Name><Entry>{}<UUID>{}</UUID></Entry><UUID>{}</UUID></Group>",
            s("Title", "E"),
            idt(0x10),
            idt(1)
        ),
    ));
    assert_eq!((v.root.uuid, v.root.name.as_str()), (id(1), "R"));
    assert_eq!(v.root.entries[0].uuid, id(0x10));
    assert_eq!(ok(&g("<Name>a</Name><Name>b</Name>")).root.name, "b");
    // Defaults of a group with nothing.
    let v = ok(&doc("", "<Group/>"));
    assert_eq!(v.root.icon, Icon::Standard(48));
    assert!(v.root.expanded);
    assert_eq!(v.root.times, app_model::Times::all(OPEN));
}

#[test]
fn fmt_11_10_tri_state() {
    let v = ok(&g(
        "<EnableAutoType>TRUE</EnableAutoType><EnableSearching>nuLL</EnableSearching>",
    ));
    assert_eq!(
        (v.root.auto_type, v.root.searching),
        (Switch::On, Switch::Inherit)
    );
    assert_eq!(
        err(&g("<EnableAutoType>inherit</EnableAutoType>")),
        Reason::InvalidSwitch
    );
    assert_eq!(err(&g("<EnableAutoType/>")), Reason::InvalidSwitch);
}

#[test]
fn fmt_11_11_icon_numbers() {
    let v = ok(&g(&format!(
        "<IconID>9999</IconID>{}{}<Group><UUID>{}</UUID></Group>",
        entry(0xA, "<IconID>-3</IconID>"),
        entry(0xB, "<IconID>2147483647</IconID>"),
        idt(2)
    )));
    assert_eq!(v.root.icon, Icon::Standard(9999));
    assert_eq!(v.root.entries[0].icon, Icon::Standard(0));
    assert_eq!(v.root.entries[1].icon, Icon::Standard(2_147_483_647));
    assert_eq!(v.root.groups[0].icon, Icon::Standard(48));
    assert_eq!(err(&g(&entry(0xC, "<IconID/>"))), Reason::InvalidNumber);
}

#[test]
fn fmt_11_12_icon_order() {
    let a1 = "oaGhoaGhoaGhoaGhoaGhoQ==";
    let v = ok(&doc(
        &format!("<CustomIcons><Icon><UUID>{a1}</UUID><Data>QUFB</Data></Icon></CustomIcons>"),
        &format!(
            "<Group>{}{}{}</Group>",
            entry(
                0x10,
                &format!("<IconID>5</IconID><CustomIconUUID>{a1}</CustomIconUUID>")
            ),
            entry(
                0x11,
                &format!("<CustomIconUUID>{a1}</CustomIconUUID><IconID>7</IconID>")
            ),
            entry(
                0x12,
                "<CustomIconUUID>7u7u7u7u7u7u7u7u7u7u7g==</CustomIconUUID>"
            ),
        ),
    ));
    let e = &v.root.entries;
    assert_eq!(e[0].icon, Icon::Custom(id(0xA1)));
    assert_eq!(e[1].icon, Icon::Standard(7));
    assert_eq!(e[2].icon, Icon::Custom(id(0xEE)));
    // Zero, empty or wrong-length custom ids are ignored.
    let v = ok(&g(&entry(
        0x13,
        "<IconID>4</IconID><CustomIconUUID/><CustomIconUUID>AAAAAAAAAAAAAAAAAAAAAA==</CustomIconUUID><CustomIconUUID>QUJD</CustomIconUUID>",
    )));
    assert_eq!(v.root.entries[0].icon, Icon::Standard(4));
}

#[test]
fn fmt_11_13_times() {
    // 11-13 defaults, 11-14 text time, 11-15 lenient, 11-16 empty count, 11-16b negatives.
    let v = ok(&g(&entry(
        0x10,
        "<Times><CreationTime>yesterday</CreationTime><LastModificationTime>AAAA</LastModificationTime>\
         <LastAccessTime/><ExpiryTime>2020-07-07T07:07:07Z</ExpiryTime><UsageCount>-5</UsageCount></Times>\
         <AutoType><DataTransferObfuscation>-7</DataTransferObfuscation></AutoType>",
    )));
    let t = &v.root.entries[0].times;
    assert_eq!(
        (t.creation, t.last_modification, t.last_access),
        (OPEN, Time(0), Time(0))
    );
    assert_eq!(t.expiry, Time(63_729_702_427));
    assert_eq!(
        (t.usage_count, t.location_changed, t.expires),
        (-5, OPEN, false)
    );
    assert_eq!(v.root.entries[0].auto_type.obfuscation, -7);
    assert_eq!(
        err(&g(&entry(0x10, "<Times><UsageCount/></Times>"))),
        Reason::InvalidNumber
    );
}

#[test]
fn fmt_11_17_booleans() {
    assert!(!ok(&g("<IsExpanded/>")).root.expanded);
    assert!(ok(&g("<IsExpanded>tRuE</IsExpanded>")).root.expanded);
    assert_eq!(
        err(&g("<IsExpanded>1</IsExpanded>")),
        Reason::InvalidBoolean
    );
}

#[test]
fn fmt_11_18_to_11_22_strings() {
    // 11-18 standard fields.
    let v = ok(&g(&entry(0x10, &s("Title", "E"))));
    let e = &v.root.entries[0];
    let fields: Vec<(&str, &str, bool)> = e
        .fields()
        .map(|(n, f)| (n, f.value.expose(), f.protected))
        .collect();
    assert_eq!(
        fields,
        [
            ("Notes", "", false),
            ("Password", "", false),
            ("Title", "E", false),
            ("URL", "", false),
            ("UserName", "", false)
        ]
    );
    // 11-19 incomplete strings.
    assert_eq!(
        err(&g(&entry(0x10, "<String><Value>v</Value></String>"))),
        Reason::IncompleteField
    );
    assert_eq!(
        err(&g(&entry(0x10, "<String><Key>k</Key></String>"))),
        Reason::IncompleteField
    );
    assert_eq!(
        ok(&g(&entry(0x10, "<String><Key/><Value>v</Value></String>")))
            .root
            .entries[0]
            .value(""),
        "v"
    );
    // 11-20 white space kept.
    let v = ok(&g(&format!(
        "<Name>  spaced  </Name>{}",
        entry(0x10, &s(" k ", "  v  "))
    )));
    assert_eq!(v.root.name, "  spaced  ");
    assert_eq!(v.root.entries[0].value(" k "), "  v  ");
    // 11-21 duplicate keys.
    assert_eq!(
        err(&g(&entry(
            0x10,
            &format!("{}{}", s("Title", "E"), s("Title", "again"))
        ))),
        Reason::DuplicateField
    );
    assert_eq!(
        ok(&g(&entry(
            0x10,
            &format!("{}{}", s("X", ""), s("X", "later"))
        )))
        .root
        .entries[0]
            .value("X"),
        "later"
    );
    // 11-22 protected flag on read.
    let v = ok(&g(&entry(
        0x10,
        "<String><Key>Password</Key><Value ProtectInMemory=\"False\">pw</Value></String>\
        <String><Key>c1</Key><Value ProtectInMemory=\"1\">x</Value></String>\
        <String><Key>c2</Key><Value ProtectInMemory=\"yes\">x</Value></String>",
    )));
    let e = &v.root.entries[0];
    assert!(!e.field("Password").unwrap().protected);
    assert!(e.field("c1").unwrap().protected && !e.field("c2").unwrap().protected);
    assert_eq!(e.value("c1"), "x");
}

#[test]
fn fmt_11_24_own_flag_read() {
    let v = ok(&g(&entry(0x10, &sp("Password", "ZAqoPJm1"))));
    let f = v.root.entries[0].field("Password").unwrap();
    assert!(f.protected);
    assert_eq!(f.value.expose(), "pw-one");
}

#[test]
fn fmt_11_26_to_11_28_attachment_refs() {
    let v = pool(&[b"attach-zero", b"", b"", b"", b"", b"", b"", b"attach-seven"]).ok(&g(&entry(
        0x10,
        "<Binary><Key>b.txt</Key><Value Ref=\"7\"/></Binary><Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary>",
    )));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "a.txt"), att(e, "b.txt")),
        (&b"attach-zero"[..], &b"attach-seven"[..])
    );
    // 11-27 inline duplicate (LD-29).
    let d = Run::default().doc(&g(&entry(0x10, "<Binary><Key>f.txt</Key><Value>QUFB</Value></Binary><Binary><Key>f.txt</Key><Value>QkJC</Value></Binary>")));
    let e = first_entry(&d.vault);
    assert_eq!(
        (att(e, "f.txt"), renamed(e, "f.txt")),
        (&b"AAA"[..], &b"BBB"[..])
    );
    assert!(
        d.warnings
            .contains(&Warning::AttachmentRenamed { entry: id(0x10) })
    );
    // 11-28 broken binary.
    assert_eq!(
        err(&g(&entry(0x10, "<Binary><Key>f.txt</Key></Binary>"))),
        Reason::IncompleteAttachment
    );
    let v = pool(&[b"AAA", b"BBB"]).ok(&g(&entry(
        0x10,
        "<Binary><Key>g.txt</Key><Value Ref=\"1\"/></Binary>",
    )));
    assert_eq!(att(first_entry(&v), "g.txt"), b"BBB");
}

#[test]
fn fmt_11_29_auto_type() {
    let v = ok(&g(&entry(
        0x10,
        "<AutoType><Enabled>False</Enabled><DataTransferObfuscation>1</DataTransferObfuscation>\
        <DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>Win B</Window><KeystrokeSequence>seqB</KeystrokeSequence></Association>\
        <Association><Window>Win A</Window><KeystrokeSequence/></Association></AutoType>",
    )));
    let at = &v.root.entries[0].auto_type;
    assert!(!at.enabled);
    assert_eq!(
        (at.obfuscation, at.default_sequence.as_str()),
        (1, "{PASSWORD}")
    );
    let assoc: Vec<(&str, &str)> = at
        .associations
        .iter()
        .map(|a| (a.window.as_str(), a.sequence.as_str()))
        .collect();
    assert_eq!(assoc, [("Win B", "seqB"), ("Win A", "")]);
    // 11-30 errors and defaults.
    assert_eq!(
        err(&g(&entry(
            0x10,
            "<AutoType><Association><Window>w</Window></Association></AutoType>"
        ))),
        Reason::IncompleteAssociation
    );
    let at = &ok(&g(&entry(0x10, ""))).root.entries[0].auto_type;
    assert!(
        at.enabled
            && at.obfuscation == 0
            && at.default_sequence.is_empty()
            && at.associations.is_empty()
    );
}

#[test]
fn fmt_11_31_to_11_34_carried_texts() {
    let v = ok(&g(&format!(
        "<Tags>gt2;gt1</Tags>{}{}",
        entry(
            0x10,
            "<ForegroundColor>red</ForegroundColor><BackgroundColor>#GG0000</BackgroundColor><OverrideURL>cmd://demo</OverrideURL>\
         <Tags>zeta; alpha,beta&#9;alpha ,Alpha</Tags>"
        ),
        entry(
            0x11,
            "<BackgroundColor>#00ff00</BackgroundColor><Tags>a, ,b;;c</Tags>"
        )
    )));
    let e = &v.root.entries;
    assert_eq!(
        (
            e[0].foreground_color.as_str(),
            e[0].background_color.as_str()
        ),
        ("red", "#GG0000")
    );
    assert_eq!(e[1].background_color, "#00ff00");
    assert_eq!(e[0].override_url, "cmd://demo");
    assert_eq!(e[0].tags(), ["Alpha", "alpha", "beta", "zeta"]);
    assert_eq!(e[1].tags(), ["a", "b", "c"]);
    assert_eq!(v.root.tags, "gt2;gt1");
    // 11-59 Unicode white space in tags.
    assert_eq!(
        ok(&g(&entry(0x10, "<Tags>\u{A0}x\u{A0},\u{3000}y</Tags>")))
            .root
            .entries[0]
            .tags(),
        ["x", "y"]
    );
}

#[test]
fn fmt_11_35_quality_check_and_11_36_previous_parent() {
    let v = ok(&g(&format!(
        "{}{}{}{}{}",
        entry(0xA, "<QualityCheck>False</QualityCheck>"),
        entry(0xB, "<QualityCheck>True</QualityCheck>"),
        entry(0xC, "<QualityCheck/>"),
        entry(0xD, ""),
        entry(
            0xE,
            &format!("<PreviousParentGroup>{}</PreviousParentGroup>", idt(0x98))
        ),
    )));
    let ex: Vec<bool> = v
        .root
        .entries
        .iter()
        .map(|e| e.exclude_from_reports)
        .collect();
    assert_eq!(ex, [true, false, true, false, false]);
    assert_eq!(v.root.entries[4].previous_parent, Some(id(0x98))); // dangling kept (FMT-11.38)
    let v = ok(&g(&entry(
        0xF,
        "<PreviousParentGroup>QUJD</PreviousParentGroup>",
    )));
    assert_eq!(v.root.entries[0].previous_parent, None);
}

#[test]
fn fmt_11_37_to_11_39_history() {
    // 11-38 nested history.
    assert_eq!(
        err(&g(&entry(
            0x10,
            "<History><Entry><History/></Entry></History>"
        ))),
        Reason::NestedHistory
    );
    // 11-39 history ids.
    let v = ok(&g(&entry(
        0x10,
        &format!(
            "<History><Entry><UUID>{}</UUID></Entry><Entry/></History>",
            idt(0x20)
        ),
    )));
    let h: Vec<Uuid> = v.root.entries[0].history.iter().map(|h| h.uuid).collect();
    assert_eq!(h, [id(0x10), id(0x10)]);
    // 11-54 two History blocks.
    let hist = |t: &str| {
        format!(
            "<History><Entry><UUID>{}</UUID>{}</Entry></History>",
            idt(0x10),
            s("Title", t)
        )
    };
    let v = ok(&g(&entry(0x10, &format!("{}{}", hist("H1"), hist("H2")))));
    assert_eq!(titles(&v.root.entries[0].history), ["H2"]);
}

#[test]
fn t09_44_dropped_history_block_takes_keystream() {
    let e = format!(
        "<UUID>qqqqqqqqqqqqqqqqqqqqqg==</UUID>{}{}<History><Entry>{}</Entry></History><History><Entry>{}</Entry></History>{}",
        s("Title", "T1"),
        sp("Password", "/J+RDmSl"),
        sp("Password", "L4XOsuTQ"),
        sp("Password", "6mMprOE4"),
        sp("Zeta", "deZDZwY=")
    );
    let v = keyed(s4()).ok(&g(&format!("<Entry>{e}</Entry>")));
    let en = &v.root.entries[0];
    assert_eq!(
        (en.value("Password"), en.value("Zeta")),
        ("pw-one", "after")
    );
    assert_eq!(en.history.len(), 1);
    assert_eq!(en.history[0].value("Password"), "pw-new");
}

#[test]
fn fmt_11_40_shared_id_across_kinds() {
    let v = ok(&g(&format!(
        "{}<Group><UUID>{}</UUID></Group>",
        entry(2, ""),
        idt(2)
    )));
    assert_eq!(
        (v.root.entries[0].uuid, v.root.groups[0].uuid),
        (id(2), id(2))
    );
    assert_eq!(app_model::invariants::check(&v), Ok(()));
}

#[test]
fn fmt_11_41_bad_ids() {
    let v = ok(&doc(
        "",
        &format!(
            "<Group><Entry><UUID>QUJD</UUID></Entry><Group/><Group><uuid>{}</uuid></Group></Group>",
            idt(1)
        ),
    ));
    let ids = [
        v.root.uuid,
        v.root.entries[0].uuid,
        v.root.groups[0].uuid,
        v.root.groups[1].uuid,
    ];
    for i in ids {
        assert!(!i.is_zero());
    }
    assert_eq!(v.root.groups[1].unknown[0].name, "uuid");
    assert_eq!(app_model::invariants::check(&v), Ok(()));
}

#[test]
fn fmt_11_42_duplicate_entry_id() {
    let v = ok(&g(&format!(
        "{}<Group><UUID>{}</UUID>{}</Group>",
        entry(0x10, &s("Title", "first")),
        idt(2),
        entry(0x10, &s("Title", "second"))
    )));
    assert_eq!(titles(&v.root.entries), ["second"]);
    assert!(v.root.groups[0].entries.is_empty());
}

#[test]
fn fmt_11_43_duplicate_group_id() {
    let v = ok(&g(&format!(
        "<Group><UUID>{a}</UUID><Name>A</Name>{e11}</Group><Group><UUID>{b}</UUID><Name>B</Name>\
         <Group><UUID>{a}</UUID><Name>A2</Name>{e12}</Group></Group>",
        a = idt(2),
        b = idt(3),
        e11 = entry(0x11, ""),
        e12 = entry(0x12, "")
    )));
    assert_eq!(names(&v.root.groups), ["A2", "B"]);
    let ids: Vec<Uuid> = v.root.groups[0].entries.iter().map(|e| e.uuid).collect();
    assert_eq!(ids, [id(0x11), id(0x12)]);
    assert!(v.root.groups[1].groups.is_empty());
}

#[test]
fn fmt_11_44_group_inside_itself() {
    // Also AT-A08 group cycles; LD-26.
    let start = Instant::now();
    let e = err(&g(&format!(
        "<Group><UUID>{a}</UUID><Name>A</Name><Group><UUID>{a}</UUID><Name>A-inner</Name></Group></Group>",
        a = idt(2)
    )));
    assert_eq!((e, e.kind()), (Reason::GroupInsideItself, Error::Corrupt));
    assert_eq!(
        err(&g(&format!("<Group><UUID>{}</UUID></Group>", idt(1)))),
        Reason::GroupInsideItself
    );
    assert!(start.elapsed().as_secs() < 1);
}

#[test]
fn fmt_11_45_forward_and_broken_refs() {
    let d = Run::default().doc(&doc(
        &format!(
            "<RecycleBinUUID>{}</RecycleBinUUID><LastSelectedGroup>{}</LastSelectedGroup>",
            idt(0x10),
            idt(1)
        ),
        &format!(
            "<Group><UUID>{}</UUID><LastTopVisibleEntry>{}</LastTopVisibleEntry>{}</Group>",
            idt(1),
            idt(0x99),
            entry(0x10, "")
        ),
    ));
    let v = &d.vault;
    assert_eq!(v.meta.recycle_bin, None);
    assert_eq!(v.meta.last_selected_group, Some(id(1)));
    assert_eq!(v.root.last_top_visible_entry, None);
    assert!(d.warnings.contains(&Warning::UnresolvedReference {
        element: "LastTopVisibleEntry"
    }));
}

#[test]
fn fmt_11_46_first_error_reported() {
    assert_eq!(
        err(&g(
            "<IsExpanded>1</IsExpanded><EnableAutoType>x</EnableAutoType>"
        )),
        Reason::InvalidBoolean
    );
    // 11-46b failures from FMT-10 (C is 11-65 with a lowered limit).
    assert_eq!(
        err(&format!(
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>{}",
            g("")
        ))
        .kind(),
        Error::Unsupported
    );
    assert_eq!(
        err(&doc(
            "<RecycleBinEnabled>yes</RecycleBinEnabled>",
            "<Group/>"
        ))
        .kind(),
        Error::Corrupt
    );
}

#[test]
fn fmt_11_47_lenient_by_default_and_11_48_syntax() {
    let v = ok(&doc("", "<Group><Name>Test</Name></Group>"));
    assert!(!v.root.uuid.is_zero());
    let r = root_name();
    assert_eq!(
        err(&format!("<{r}><Root><Group><Name>R</Group></Root></{r}>")),
        Reason::NotXml
    );
    assert_eq!(
        err(&format!("<{r}><Root><Group><Name>R</Name></Group></Root>")),
        Reason::NotXml
    );
}

#[test]
fn fmt_11_50_empty_forms_and_layout() {
    let a = ok(&g("<Name></Name>"));
    let b = ok(&g("<Name/>"));
    assert_eq!((a.root.name.as_str(), b.root.name.as_str()), ("", ""));
    let flat = g(&entry(0x10, &s("Title", "T")));
    let spaced = flat.replace("><", ">\n    <");
    let tabbed = flat.replace("><", ">\n\t\t<");
    assert_eq!(ok(&flat), ok(&spaced));
    assert_eq!(ok(&flat), ok(&tabbed));
}

#[test]
fn fmt_11_50b_stray_content() {
    let v = ok(&doc(
        "",
        &format!(
            "rootjunk<Group><UUID>{}</UUID>gjunk<!--c--><Entry>ejunk<?pi x?><UUID>{}</UUID>\
         <Times>tjunk<UsageCount>4</UsageCount></Times><String>sjunk<Key>Title</Key><Value>T</Value></String>\
         <AutoType>ajunk<Association>xjunk<Window>W</Window><KeystrokeSequence>s</KeystrokeSequence></Association></AutoType></Entry></Group>",
            idt(1),
            idt(0x10)
        ),
    ));
    let e = &v.root.entries[0];
    assert_eq!(
        (
            e.times.usage_count,
            e.value("Title"),
            e.auto_type.associations[0].window.as_str()
        ),
        (4, "T", "W")
    );
    assert!(e.unknown.is_empty() && v.root.unknown.is_empty() && v.unknown_root.is_empty());
    let r = root_name();
    let v = ok(&format!(
        "<p:{r} xmlns:p=\"urn:x\"><Root><Group>{}</Group></Root></p:{r}>",
        entry(0x10, &s("Title", "T"))
    ));
    assert_eq!(v.root.entries[0].value("Title"), "T");
}

#[test]
fn fmt_11_51_unknown_elements() {
    let v = ok(&g(&format!(
        "<UnknownGroupThing a=\"1\">x</UnknownGroupThing>{}",
        entry(
            0x10,
            "<UnknownEntryThing>y</UnknownEntryThing><Times><UnknownTimesThing/></Times>\
                     <String><Key>k</Key><Value>v</Value><StringExtra/></String>"
        )
    )));
    assert_eq!(v.root.unknown[0].name, "UnknownGroupThing");
    assert_eq!(v.root.unknown[0].attributes, [("a".into(), "1".into())]);
    let e = &v.root.entries[0];
    assert_eq!(
        (e.unknown[0].name.as_str(), text(&e.unknown[0])),
        ("UnknownEntryThing", "y")
    );
    assert_eq!(e.times.unknown[0].name, "UnknownTimesThing");
    assert_eq!(e.value("k"), "v");
}

#[test]
fn fmt_11_55_two_times_blocks() {
    let v = ok(&g(&entry(
        0x10,
        "<Times><LastModificationTime>GxaW1g4AAAA=</LastModificationTime><UsageCount>3</UsageCount></Times>\
        <Times><CreationTime>m2eX1g4AAAA=</CreationTime></Times>",
    )));
    let t = &v.root.entries[0].times;
    assert_eq!(t.creation, Time(63_729_788_827));
    assert_eq!(
        (
            t.last_modification,
            t.last_access,
            t.expiry,
            t.location_changed
        ),
        (OPEN, OPEN, OPEN, OPEN)
    );
    assert_eq!((t.usage_count, t.expires), (0, false));
}

#[test]
fn fmt_11_56_two_auto_type_blocks() {
    let v = ok(&g(&entry(
        0x10,
        "<AutoType><Enabled>False</Enabled><DefaultSequence>{USERNAME}</DefaultSequence>\
        <Association><Window>W1</Window><KeystrokeSequence>s1</KeystrokeSequence></Association></AutoType>\
        <AutoType><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence>\
        <Association><Window>W2</Window><KeystrokeSequence>s2</KeystrokeSequence></Association></AutoType>",
    )));
    let at = &v.root.entries[0].auto_type;
    assert!(!at.enabled);
    assert_eq!(
        (at.obfuscation, at.default_sequence.as_str()),
        (1, "{PASSWORD}")
    );
    let w: Vec<&str> = at.associations.iter().map(|a| a.window.as_str()).collect();
    assert_eq!(w, ["W1", "W2"]);
}

#[test]
fn fmt_11_57_duplicate_entry_history_and_attachments() {
    let v = pool(&[b"AAA", b"BBB"]).ok(&g(&format!(
        "{}{}<Group><UUID>{}</UUID>{}</Group>",
        entry(0x10, &format!("{}<Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary><Binary><Key>c.txt</Key><Value>Q0ND</Value></Binary><History><Entry>{}</Entry></History>", s("Title", "first"), s("Title", "h-first"))),
        entry(0x20, ""),
        idt(2),
        entry(0x10, &format!("{}<Binary><Key>b.txt</Key><Value Ref=\"1\"/></Binary><History><Entry>{}</Entry></History>", s("Title", "second"), s("Title", "h-second"))),
    )));
    let ids: Vec<Uuid> = v.root.entries.iter().map(|e| e.uuid).collect();
    assert_eq!(ids, [id(0x10), id(0x20)]);
    let e = &v.root.entries[0];
    assert_eq!(e.value("Title"), "second");
    assert_eq!(
        (att(e, "a.txt"), att(e, "b.txt")),
        (&b"AAA"[..], &b"BBB"[..])
    );
    assert!(!e.attachments.iter().any(|a| a.name == "c.txt"));
    assert_eq!(titles(&e.history), ["h-first", "h-second"]);
    assert!(v.root.groups[0].entries.is_empty());
}

#[test]
fn fmt_11_58_duplicate_positions() {
    let grp =
        |n: u8, name: &str| format!("<Group><UUID>{}</UUID><Name>{name}</Name></Group>", idt(n));
    let v = ok(&g(&format!(
        "{}{}{}{}{}{}{}{}",
        grp(2, "X1"),
        grp(3, "Y"),
        grp(2, "X2"),
        grp(4, "Z"),
        entry(0x10, &s("Title", "E-first")),
        entry(0x11, &s("Title", "F")),
        entry(0x10, &s("Title", "E-second")),
        entry(0x12, &s("Title", "G")),
    )));
    assert_eq!(names(&v.root.groups), ["Y", "X2", "Z"]);
    assert_eq!(titles(&v.root.entries), ["E-second", "F", "G"]);
}

#[test]
fn fmt_11_60_cross_nested_duplicates() {
    // AT-A08: cycles through duplicates fail fast, where the reference hangs.
    let grp = |n: u8, inner: &str| format!("<Group><UUID>{}</UUID>{inner}</Group>", idt(n));
    let start = Instant::now();
    let a = format!("{}{}", grp(2, &grp(3, "")), grp(3, &grp(2, "")));
    assert_eq!(err(&g(&a)), Reason::GroupInsideItself);
    let b = format!(
        "{}{}{}",
        grp(2, &grp(3, "")),
        grp(3, &grp(4, "")),
        grp(4, &grp(2, ""))
    );
    assert_eq!(err(&g(&b)), Reason::GroupInsideItself);
    let e = |n| entry(n, "");
    let c = grp(
        5,
        &format!(
            "{}{}",
            grp(2, &format!("{}{}", e(0x20), grp(3, &e(0x21)))),
            grp(3, &format!("{}{}", e(0x22), grp(2, &e(0x23))))
        ),
    );
    assert_eq!(err(&g(&c)), Reason::GroupInsideItself);
    assert!(start.elapsed().as_secs() < 1);
}

#[test]
fn fmt_11_61_duplicates_without_a_cycle() {
    let grp = |n: u8, name: &str, inner: &str| {
        format!(
            "<Group><UUID>{}</UUID><Name>{name}</Name>{inner}</Group>",
            idt(n)
        )
    };
    let v = ok(&g(&format!(
        "{}{}",
        grp(2, "A", &grp(3, "B'", "")),
        grp(5, "X", &grp(3, "B", &grp(4, "Y", "")))
    )));
    assert_eq!(names(&v.root.groups), ["A", "X"]);
    assert!(v.root.groups[0].groups.is_empty());
    let x = &v.root.groups[1];
    assert_eq!(names(&x.groups), ["B"]);
    assert_eq!(names(&x.groups[0].groups), ["Y"]);
}

#[test]
fn fmt_11_62_unknown_children_of_repeated_parents() {
    let v = ok(&g(&format!(
        "{}{}{}{}",
        entry(
            0x10,
            "<Times><UnknownT1/></Times><Times><UnknownT2/></Times><AutoType><UnknownA1/></AutoType><AutoType><UnknownA2/></AutoType>"
        ),
        entry(0x11, "<UnknownE1/>"),
        entry(0x11, "<UnknownE2/>"),
        entry(
            0x12,
            &format!(
                "<History><Entry>{}<UnknownH1/></Entry></History><History><Entry>{}<UnknownH2/></Entry></History>",
                s("Title", "H1"),
                s("Title", "H2")
            )
        ),
    )));
    let n = |u: &[UnknownElement]| u.iter().map(|x| x.name.clone()).collect::<Vec<_>>();
    let e = &v.root.entries;
    assert_eq!(n(&e[0].times.unknown), ["UnknownT2"]);
    assert_eq!(n(&e[0].auto_type.unknown), ["UnknownA1", "UnknownA2"]);
    assert_eq!(n(&e[1].unknown), ["UnknownE2"]);
    assert_eq!(titles(&e[2].history), ["H2"]);
    assert_eq!(n(&e[2].history[0].unknown), ["UnknownH2"]);
}

#[test]
fn fmt_11_63_entry_placed_through_another_group() {
    let v = ok(&g(&format!(
        "<Group><UUID>{x}</UUID><Name>X1</Name>{e}{f}</Group><Group><UUID>{y}</UUID><Name>Y</Name>{e}</Group>\
         <Group><UUID>{x}</UUID><Name>X2</Name>{e}</Group>",
        x = idt(2),
        y = idt(3),
        e = entry(0x10, &s("Title", "E")),
        f = entry(0x11, &s("Title", "F"))
    )));
    assert_eq!(names(&v.root.groups), ["Y", "X2"]);
    assert!(v.root.groups[0].entries.is_empty());
    assert_eq!(titles(&v.root.groups[1].entries), ["F", "E"]);
}

fn nested(levels: usize) -> String {
    let mut x = String::with_capacity(levels * 16);
    for _ in 0..levels {
        x.push_str("<Group>");
    }
    x.push_str("<Group/>");
    for _ in 0..levels {
        x.push_str("</Group>");
    }
    g(&x)
}

#[test]
fn fmt_11_64_depth_limit() {
    // AT-A07: deep nesting. Root group at depth 2; 510 nested children put the
    // innermost `<Group/>` at depth 512.
    let v = ok(&nested(509));
    let mut depth = 0;
    let mut gr = &v.root;
    while let Some(c) = gr.groups.first() {
        gr = c;
        depth += 1;
    }
    assert_eq!(depth, 510);
    assert_eq!(err(&nested(510)), Reason::Limit(Limit::Depth));
    let start = Instant::now();
    let e = err(&nested(100_000));
    assert_eq!(
        (e, e.kind()),
        (Reason::Limit(Limit::Depth), Error::TooLarge(Limit::Depth))
    );
    assert!(start.elapsed().as_secs() < 1);
}

fn lowered(f: impl FnOnce(&mut Limits)) -> Run {
    let mut r = Run::default();
    f(&mut r.lim);
    r
}

#[test]
fn fmt_11_65_to_11_73_counted_limits() {
    // Lowered limits (FMT-08.12: tests must be able to lower every limit).
    let r = lowered(|l| l.groups = 100);
    r.ok(&g(&"<Group/>".repeat(99)));
    assert_eq!(
        r.err(&g(&"<Group/>".repeat(100))),
        Reason::Limit(Limit::Groups)
    );
    let r = lowered(|l| l.entries = 100);
    let v = r.ok(&g(&"<Entry/>".repeat(100)));
    assert!(
        v.root
            .entries
            .iter()
            .all(|e| e.fields().count() == 5 && !e.uuid.is_zero())
    );
    assert_eq!(
        r.err(&g(&"<Entry/>".repeat(101))),
        Reason::Limit(Limit::Entries)
    );
    let r = lowered(|l| l.entry_elements = 400);
    let h = |n| format!("<Entry><History>{}</History></Entry>", "<Entry/>".repeat(n));
    r.ok(&g(&h(99).repeat(4)));
    assert_eq!(
        r.err(&g(&format!("{}{}", h(99).repeat(3), h(100)))),
        Reason::Limit(Limit::EntryElements)
    );
    let r = lowered(|l| l.history = 100);
    assert_eq!(r.ok(&g(&h(100))).root.entries[0].history.len(), 100);
    assert_eq!(r.err(&g(&h(101))), Reason::Limit(Limit::History));
    let two = format!(
        "<Entry><History>{0}</History><History>{0}</History></Entry>",
        "<Entry/>".repeat(60)
    );
    assert_eq!(r.err(&g(&two)), Reason::Limit(Limit::History));
    let r = lowered(|l| l.strings = 100);
    let st = |n: usize| (0..n).map(|i| s(&format!("k{i}"), "")).collect::<String>();
    assert_eq!(
        r.ok(&g(&format!("<Entry>{}</Entry>", st(100))))
            .root
            .entries[0]
            .fields()
            .count(),
        105
    );
    assert_eq!(
        r.err(&g(&format!("<Entry>{}</Entry>", st(101)))),
        Reason::Limit(Limit::Strings)
    );
    let mut r = lowered(|l| l.attachments = 100);
    r.pool = vec![b"AAA".to_vec()];
    let bi = |n: usize| {
        (0..n)
            .map(|i| format!("<Binary><Key>b{i}</Key><Value Ref=\"0\"/></Binary>"))
            .collect::<String>()
    };
    let v = r.ok(&g(&format!("<Entry>{}</Entry>", bi(100))));
    assert_eq!(v.root.entries[0].attachments.len(), 100);
    assert_eq!(
        r.err(&g(&format!("<Entry>{}</Entry>", bi(101)))),
        Reason::Limit(Limit::Attachments)
    );
    let r = lowered(|l| l.associations = 100);
    let asc = |n: usize| {
        format!(
            "<AutoType>{}</AutoType>",
            "<Association><Window/><KeystrokeSequence/></Association>".repeat(n)
        )
    };
    assert_eq!(
        r.ok(&g(&format!("<Entry>{}{}</Entry>", asc(50), asc(50))))
            .root
            .entries[0]
            .auto_type
            .associations
            .len(),
        100
    );
    assert_eq!(
        r.err(&g(&format!("<Entry>{}{}</Entry>", asc(50), asc(51)))),
        Reason::Limit(Limit::Associations)
    );
    let r = lowered(|l| l.kept_unknown = 100);
    assert_eq!(r.ok(&g(&"<U/>".repeat(100))).root.unknown.len(), 100);
    assert_eq!(
        r.err(&g(&"<U/>".repeat(101))),
        Reason::Limit(Limit::KeptUnknown)
    );
    assert_eq!(
        r.err(&g(&format!("<U>{}</U>", "<V/>".repeat(100)))),
        Reason::Limit(Limit::KeptUnknown)
    );
    let r = lowered(|l| l.text = 1 << 20);
    r.ok(&g(&entry(0x10, &s("Notes", &"a".repeat(1 << 20)))));
    assert_eq!(
        r.err(&g(&entry(0x10, &s("Notes", &"a".repeat((1 << 20) + 1))))),
        Reason::Limit(Limit::Text)
    );
    let r = lowered(|l| l.elements = 50);
    assert_eq!(
        r.err(&g(&"<Group/>".repeat(50))),
        Reason::Limit(Limit::Elements)
    );
}

#[test]
fn fmt_11_66_live_entry_limit_full_size() {
    // 11-66 at the real number: 1,000,000 entries open, 1,000,001 do not.
    let a = g(&"<Entry/>".repeat(1_000_000));
    let v = ok(&a);
    assert_eq!(v.root.entries.len(), 1_000_000);
    let b = g(&"<Entry/>".repeat(1_000_001));
    assert_eq!(err(&b), Reason::Limit(Limit::Entries));
}

// ===========================================================================
// FMT-12: values in documents (the pure encodings are unit tests in encode.rs).

#[test]
fn fmt_12_22_protected_metadata() {
    let v = ok(&doc(
        "<DatabaseName Protected=\"True\">RxjmIZKk</DatabaseName><DatabaseNameChanged Protected=\"True\">Kxp/ZyIwGYoSwu8D</DatabaseNameChanged>",
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.name.as_str(), v.meta.name_changed),
        ("Secret", Time(63_416_885_093))
    );
    // Leading byte order mark (LD-25).
    let v = ok(&doc(
        "<DatabaseName Protected=\"True\">+8Y6Eg==</DatabaseName><DatabaseDescription Protected=\"True\">pLUSDDVk</DatabaseDescription>",
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.name.as_str(), v.meta.description.as_str()),
        ("A", "Secret")
    );
    // Zero-byte protected value takes no keystream.
    let v = ok(&doc(
        "<DatabaseName Protected=\"True\">====</DatabaseName><DatabaseDescription Protected=\"True\">RxjmIZKk</DatabaseDescription>",
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.name.as_str(), v.meta.description.as_str()),
        ("", "Secret")
    );
    assert_eq!(
        err(&doc(
            "<HistoryMaxItems Protected=\"True\">====</HistoryMaxItems>",
            "<Group/>"
        )),
        Reason::InvalidNumber
    );
    let v = ok(&doc(
        "<RecycleBinEnabled Protected=\"True\">====</RecycleBinEnabled><RecycleBinUUID Protected=\"True\">====</RecycleBinUUID><DatabaseName Protected=\"True\">RxjmIZKk</DatabaseName>",
        "<Group/>",
    ));
    assert!(!v.meta.recycle_bin_enabled);
    assert_eq!((v.meta.recycle_bin, v.meta.name.as_str()), (None, "Secret"));
}

#[test]
fn fmt_12_22_empty_protected_and_t09_17_t09_19() {
    let v = ok(&g(&entry(
        0x10,
        &format!(
            "<String><Key>A</Key><Value Protected=\"True\"/></String><String><Key>B</Key><Value Protected=\"True\">  </Value></String>\
         <String><Key>C</Key><Value ProtectInMemory=\"True\">pw-one</Value></String>{}",
            sp("Password", "ZAqoPJm1")
        ),
    )));
    let e = &v.root.entries[0];
    assert_eq!(
        (
            e.value("A"),
            e.value("B"),
            e.value("C"),
            e.value("Password")
        ),
        ("", "", "pw-one", "pw-one")
    );
    assert!(e.field("A").unwrap().protected && e.field("C").unwrap().protected);
}

#[test]
fn fmt_12_22_version_3_salsa20() {
    // S = 32 zero bytes, Salsa20 (FMT-09.10).
    let mut stream = FieldStream::salsa20_from_stream_key(&SecretBytes::new(vec![0; 32])).unwrap();
    let x = doc(
        "<DatabaseName Protected=\"True\">uLPZ9gPA</DatabaseName>",
        "<Group/>",
    );
    let lim = Limits::DEFAULT;
    let opts = Options {
        open_time: OPEN,
        limits: &lim,
        v3_header: None,
    };
    let d = read(x.as_bytes(), &mut stream, &[], &opts).unwrap();
    assert_eq!(d.vault.meta.name, "Secret");
}

#[test]
fn fmt_12_29_string_key_window_deleted_uuid() {
    let v = ok(&doc(
        "",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group><DeletedObjects><DeletedObject><UUID Protected=\"True\">eJ4G1vtr0SgqxjT4FfC1TQ==</UUID><DeletionTime>Zd/www4AAAA=</DeletionTime></DeletedObject></DeletedObjects>",
            idt(1),
            entry(
                0x10,
                "<String><Key Protected=\"True\">RBTr</Key><Value Protected=\"True\">YsXjRQ==</Value></String>\
            <AutoType><Association><Window Protected=\"True\">OjV9Om0=</Window><KeystrokeSequence>s</KeystrokeSequence></Association></AutoType>"
            )
        ),
    ));
    let e = &v.root.entries[0];
    assert_eq!(e.value("Pin"), "1234");
    assert_eq!(e.auto_type.associations[0].window, "Demo*");
    assert_eq!(v.deleted_objects[0].uuid, id(0x55));
}

#[test]
fn fmt_12_29_sweep() {
    // One protected value in every value element, keystream offsets as in the card; 210 bytes in all.
    let k = zero_key();
    let p = |at: usize, plain: &[u8]| enc(&k, at, plain);
    let pr = |name: &str, at: usize, plain: &[u8]| {
        format!("<{name} Protected=\"True\">{}</{name}>", p(at, plain))
    };
    let root_id = app_format::document::encode::base64_decode("rH4xp1/3SoWQeYTLdwFNVA==");
    let entry_id = app_format::document::encode::base64_decode("6w7wZdhAp0qVlXjkemuCYw==");
    let mut icon_id = vec![0x11; 15];
    icon_id.push(0x01);
    let meta = format!(
        "{}<MemoryProtection>{}</MemoryProtection><CustomIcons><Icon>{}{}{}{}</Icon></CustomIcons>{}<CustomData><Item>{}{}</Item></CustomData>",
        pr("Generator", 0, b"Gen"),
        pr("ProtectTitle", 3, b"True"),
        pr("UUID", 7, &icon_id),
        pr(
            "Data",
            23,
            &[0x89, 0x50, 0x4E, 0x47, 0x69, 0x63, 0x6F, 0x6E]
        ),
        pr("Name", 31, b"Ico"),
        pr("LastModificationTime", 34, b"Zd/www4AAAA="),
        pr("HistoryMaxItems", 46, b"7"),
        pr("Key", 47, b"mk"),
        pr("Value", 49, b"mv"),
    );
    let entry_xml = format!(
        "<Entry>{}{}{}{}{}{}<String>{}{}</String><Binary>{}{}</Binary><AutoType>{}{}{}<Association>{}{}</Association></AutoType></Entry>",
        pr("UUID", 110, &entry_id),
        pr("IconID", 126, b"9"),
        pr("ForegroundColor", 127, b"#112233"),
        pr("OverrideURL", 134, b"cmd://x"),
        pr("Tags", 141, b"et"),
        pr("QualityCheck", 143, b"False"),
        pr("Key", 148, b"Title"),
        pr("Value", 153, b"T1"),
        pr("Key", 155, b"att.txt"),
        pr("Value", 162, b"inline"),
        pr("Enabled", 168, b"False"),
        pr("DataTransferObfuscation", 173, b"1"),
        pr("DefaultSequence", 174, b"{Y}"),
        pr("Window", 177, b"W*"),
        pr("KeystrokeSequence", 179, b"{Z}"),
    );
    let root = format!(
        "<Group>{}{}{}{}{}<Times Protected=\"True\">{}{}{}</Times>{}{}{}{}{entry_xml}</Group>\
         <DeletedObjects><DeletedObject>{}{}</DeletedObject></DeletedObjects>",
        pr("UUID", 51, &root_id),
        pr("Name", 67, b"Root"),
        pr("Notes", 71, b"GN"),
        pr("Tags", 73, b"gt"),
        pr("IconID", 75, b"5"),
        pr("CreationTime", 76, b"Zd/www4AAAA="),
        pr("Expires", 88, b"False"),
        pr("UsageCount", 93, b"3"),
        pr("IsExpanded", 94, b"True"),
        pr("DefaultAutoTypeSequence", 98, b"{X}"),
        pr("EnableAutoType", 101, b"false"),
        pr("EnableSearching", 106, b"null"),
        pr("UUID", 182, &[0x55; 16]),
        pr("DeletionTime", 198, b"Zd/www4AAAA="),
    );
    assert_eq!(p(0, b"Gen"), "Uxjr");
    assert_eq!(p(198, b"Zd/www4AAAA="), "prRv7UmFz6P6QifR");
    let v = ok(&doc(&meta, &root));
    let m = &v.meta;
    assert_eq!(m.generator, "Gen");
    assert!(m.memory_protection.title);
    let icon = &m.custom_icons[0];
    assert_eq!((icon.uuid.0.to_vec(), icon.name.as_str()), (icon_id, "Ico"));
    assert_eq!(base64_encode(&icon.data), "iVBOR2ljb24=");
    assert_eq!(icon.last_modified, Some(Time(63_416_885_093)));
    assert_eq!(m.history_max_items, 7);
    assert_eq!(
        (
            m.custom_data.items[0].key.as_str(),
            m.custom_data.items[0].value.as_str()
        ),
        ("mk", "mv")
    );
    let r = &v.root;
    assert_eq!(uuid_to_text(r.uuid), "rH4xp1/3SoWQeYTLdwFNVA==");
    assert_eq!(
        (r.name.as_str(), r.notes.as_str(), r.tags.as_str(), r.icon),
        ("Root", "GN", "gt", Icon::Standard(5))
    );
    assert_eq!(
        (r.times.creation, r.times.expires, r.times.usage_count),
        (Time(63_416_885_093), false, 3)
    );
    assert!(r.expanded);
    assert_eq!(
        (r.default_sequence.as_str(), r.auto_type, r.searching),
        ("{X}", Switch::Off, Switch::Inherit)
    );
    let e = &r.entries[0];
    assert_eq!(uuid_to_text(e.uuid), "6w7wZdhAp0qVlXjkemuCYw==");
    assert_eq!(
        (e.icon, e.foreground_color.as_str(), e.override_url.as_str()),
        (Icon::Standard(9), "#112233", "cmd://x")
    );
    assert_eq!(e.tags(), ["et"]);
    assert!(e.exclude_from_reports);
    assert_eq!(e.value("Title"), "T1");
    assert_eq!(att(e, "att.txt"), b"inline");
    let at = &e.auto_type;
    assert_eq!(
        (at.enabled, at.obfuscation, at.default_sequence.as_str()),
        (false, 1, "{Y}")
    );
    assert_eq!(
        (
            at.associations[0].window.as_str(),
            at.associations[0].sequence.as_str()
        ),
        ("W*", "{Z}")
    );
    assert_eq!(
        (v.deleted_objects[0].uuid, v.deleted_objects[0].deleted_at),
        (id(0x55), Time(63_416_885_093))
    );
}

#[test]
fn fmt_12_29_not_a_value_element() {
    // Also T09-36 and T13-28.
    let pw = "<String><Key>Password</Key><key Protected=\"True\">QUJD</key><Value Protected=\"True\">ZAqoPJm1</Value></String>";
    let bin =
        "<Binary><Key>f.txt</Key><Value Ref=\"0\" Protected=\"True\">QUJDRA==</Value></Binary>";
    for content in [format!("{bin}{pw}"), pw.to_owned()] {
        let v = pool(&[b"AAA"]).ok(&g(&entry(0x10, &content)));
        let e = first_entry(&v);
        assert_eq!(e.value("Password"), "pw-one");
        if content.contains("Binary") {
            assert_eq!(att(e, "f.txt"), b"AAA");
        }
    }
}

#[test]
fn fmt_12_23_text_on_read() {
    let mut raw = doc("<DatabaseName>a\r\nb\rc</DatabaseName>", "<Group/>").into_bytes();
    raw.retain(|_| true);
    assert_eq!(
        Run::default().bytes(&raw).unwrap().vault.meta.name,
        "a\nb\nc"
    );
    assert_eq!(ok(&body("a&#13;&#10;b&#9;c")).meta.name, "a\r\nb\tc");
    assert_eq!(
        ok(&body("&lt;a&gt; &amp; &quot;q&quot; &apos;s&apos;"))
            .meta
            .name,
        "<a> & \"q\" 's'"
    );
    assert_eq!(ok(&body("<![CDATA[a<b&c]]>")).meta.name, "a<b&c");
    assert_eq!(ok(&body("a<!-- c -->b<?pi x?>c")).meta.name, "abc");
    assert_eq!(err(&body("a<b/>c")), Reason::ChildInValue);
    assert_eq!(ok(&body("  N  ")).meta.name, "  N  ");
    assert_eq!(ok(&body("\u{A0}x\u{A0}")).meta.name, "\u{A0}x\u{A0}");
}

#[test]
fn fmt_12_24_forbidden_characters() {
    for bad in ["\u{1}", "&#1;", "&#xFFFE;", "&#xD800;"] {
        assert_eq!(err(&body(bad)), Reason::NotXml, "{bad:?}");
    }
    let mut x = body("Ne").into_bytes();
    let at = x.iter().position(|&b| b == b'N').unwrap();
    x[at] = 0xFF;
    assert_eq!(Run::default().bytes(&x).unwrap_err(), Reason::NotXml);
    assert_eq!(ok(&body("x&#x80;y")).meta.name, "x\u{80}y");
}

// ===========================================================================
// FMT-09: protected text decoding in documents.

#[test]
fn t09_12_t09_16_t09_18_t09_35() {
    let k = s4();
    let v = keyed(k.clone()).ok(&g(&entry(0x10, &format!(
        "<String><Key>a</Key><Value Protected=\"1\">{}</Value></String><String><Key>b</Key><Value Protected=\"true\">{}</Value></String>\
         <String><Key>c</Key><Value Protected=\"yes\">QUJD</Value></String>",
        enc(&k, 0, b"one"),
        {
            let t = enc(&k, 3, b"two");
            format!("{}\n {}", &t[..2], &t[2..])
        }
    ))));
    let e = &v.root.entries[0];
    assert_eq!(
        (e.value("a"), e.value("b"), e.value("c")),
        ("one", "two", "QUJD")
    );
    let v = keyed(s4()).ok(&g(&entry(0x10, &sp("X", "zRf+og=="))));
    assert_eq!(v.root.entries[0].value("X"), "A\u{FFFD}B\u{FFFD}");
    let v = keyed(s4()).ok(&g(&entry(
        0x10,
        &format!("{}{}", sp("Password", "zej+Ik4="), sp("Zeta", "oTmGhq8=")),
    )));
    let e = &v.root.entries[0];
    assert_eq!(
        (e.value("Password"), e.value("Zeta")),
        ("A\u{0}BCD", "after")
    );
}

#[test]
fn t09_34_and_t09_38_attachment_values() {
    let k = s4();
    let v = keyed(k.clone()).ok(&g(&entry(
        0x10,
        &format!(
            "{}<Binary><Key>a</Key><Value Protected=\"True\">{}</Value></Binary>",
            sp("Password", &enc(&k, 0, b"pw-one")),
            enc(&k, 6, b"inl-prot")
        ),
    )));
    assert_eq!(att(first_entry(&v), "a"), b"inl-prot");
    let v = keyed(s4()).ok(&doc(
        "<DatabaseName ProtectInMemory=\"True\">db</DatabaseName>",
        &format!("<Group>{}</Group>", entry(0x10, &format!("<Binary><Key>f.txt</Key><Value ProtectInMemory=\"True\">QUJD</Value></Binary>{}", sp("Password", "/J+RDmSl")))),
    ));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "f.txt"), e.value("Password"), v.meta.name.as_str()),
        (&b"ABC"[..], "pw-one", "db")
    );
}

#[test]
fn t09_41_t09_42_replacement_rule() {
    let k = s4();
    let cases: [(&str, &str, &str); 14] = [
        ("K01", "bmr9", "\u{FFFD}\u{FFFD}A"),
        ("K02", "kYpAHg==", "\u{FFFD}\u{FFFD}\u{FFFD}A"),
        ("K03", "H0NdyQ==", "\u{FFFD}\u{FFFD}\u{FFFD}A"),
        ("K04", "9XiW", "A\u{FFFD}\u{FFFD}"),
        ("K05", "9F0cDg==", "\u{FFFD}\u{FFFD}\u{FFFD}A"),
        ("K06", "1C92", "\u{FFFD}\u{FFFD}A"),
        ("K07", "7c/J+Q==", "A"),
        ("K08", "fLdO39g=", "A\u{FEFF}B"),
        ("K09", "MNpGuw==", "\u{FFFE}A"),
        ("K10", "c0g1dWk=", "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}A"),
        ("K11", "/y0=", "\u{FFFD}A"),
        ("K12", "Hz8a", "\u{20AC}"),
        ("K13", "dWUd", ""),
        ("K14", "Cd18", "\u{FFFD}\u{FFFD}\u{FFFD}"),
    ];
    let strings: String = cases.iter().map(|(k, b, _)| sp(k, b)).collect();
    let v = keyed(k).ok(&g(&entry(0x10, &format!("{}{strings}", s("Title", "T1")))));
    let e = &v.root.entries[0];
    for (key, _, want) in cases {
        assert_eq!(e.value(key), want, "{key}");
    }
}

// ===========================================================================
// FMT-13: attachments.

fn v3_pool_doc(items: &str, entry_xml: &str) -> String {
    doc(
        &format!("<Binaries>{items}</Binaries>"),
        &format!("<Group>{entry_xml}</Group>"),
    )
}

#[test]
fn t13_05_to_t13_07_compressed_items() {
    let e = entry(
        0x10,
        "<Binary><Key>t</Key><Value Ref=\"0\"/></Binary><Binary><Key>e</Key><Value Ref=\"2\"/></Binary><Binary><Key>z</Key><Value Ref=\"3\"/></Binary>",
    );
    let empty_gz = "H4sIAAAAAAAAEwMAAAAAAAAAAAA=";
    let v = ok(&v3_pool_doc(
        &format!(
            "<Binary ID=\"0\" Compressed=\"True\">H4sIAAAAAAAAEyszVkjOzy0oSi0uTk1RSEksSQQAfyMrRBIAAAA=</Binary>\
         <Binary ID=\"2\" Compressed=\"True\"/><Binary ID=\"3\" Compressed=\"1\">{empty_gz}</Binary>"
        ),
        &e,
    ));
    let en = first_entry(&v);
    assert_eq!(att(en, "t"), b"v3 compressed data");
    assert_eq!((att(en, "e"), att(en, "z")), (&b""[..], &b""[..]));
    let bad = base64_encode(b"not gzip at all!!");
    let e1 = entry(0x10, "<Binary><Key>t</Key><Value Ref=\"0\"/></Binary>");
    let r = err(&v3_pool_doc(
        &format!("<Binary ID=\"0\" Compressed=\"True\">{bad}</Binary>"),
        &e1,
    ));
    assert_eq!(
        (r, r.kind()),
        (Reason::BadCompressedAttachment, Error::Corrupt)
    );
}

#[test]
fn t13_08_protected_and_compressed() {
    let s3: Vec<u8> = (0u8..32).collect();
    let mut stream = FieldStream::salsa20_from_stream_key(&SecretBytes::new(s3)).unwrap();
    let x = v3_pool_doc(
        "<Binary ID=\"0\" Compressed=\"True\" Protected=\"True\">5jW9KWKDiiw8kQzmJ7/bPgk42i7hKKLJcdVn+GPrnR1/kWW2+4S/MA==</Binary>",
        &entry(
            0x10,
            &format!(
                "<Binary><Key>p</Key><Value Ref=\"0\"/></Binary>{}",
                sp("Password", "Exx8dFpyw1Y=")
            ),
        ),
    );
    let lim = Limits::DEFAULT;
    let opts = Options {
        open_time: OPEN,
        limits: &lim,
        v3_header: None,
    };
    let v = read(x.as_bytes(), &mut stream, &[], &opts).unwrap().vault;
    let e = first_entry(&v);
    assert_eq!(att(e, "p"), b"protected+compressed");
    assert_eq!(e.value("Password"), "Password");
}

#[test]
fn t13_09_t13_10_t13_30_pool_keys() {
    let e = |r: &str| {
        entry(
            0x10,
            &format!("<Binary><Key>f</Key><Value Ref=\"{r}\"/></Binary>"),
        )
    };
    assert_eq!(
        att(
            first_entry(&ok(&v3_pool_doc(
                "<Binary ID=\"z9\">QUJD</Binary>",
                &e("z9")
            ))),
            "f"
        ),
        b"ABC"
    );
    let v = ok(&v3_pool_doc(
        &format!(
            "<Binary ID=\"0\">{}</Binary><Binary ID=\"0\">{}</Binary>",
            base64_encode(b"first"),
            base64_encode(b"second")
        ),
        &e("0"),
    ));
    assert_eq!(att(first_entry(&v), "f"), b"second");
    let d = Run::default().doc(&v3_pool_doc(
        "<Binary Compressed=\"False\">QUJD</Binary>",
        &e(""),
    ));
    assert_eq!(att(first_entry(&d.vault), "f"), b"");
    assert!(
        d.warnings
            .contains(&Warning::DanglingAttachment { entry: id(0x10) })
    );
}

#[test]
fn t13_12_t13_13_dangling_refs() {
    let refs = ["5", "abc", "-1", "", "01", " 1"];
    let bins: String = refs
        .iter()
        .enumerate()
        .map(|(i, r)| format!("<Binary><Key>n{i}</Key><Value Ref=\"{r}\"/></Binary>"))
        .collect();
    let d = pool(&[b"x", b"y"]).doc(&g(&entry(0x10, &bins)));
    let e = first_entry(&d.vault);
    assert_eq!(e.attachments.len(), 6);
    assert!(e.attachments.iter().all(|a| a.data.is_empty()));
    assert!(
        d.warnings
            .contains(&Warning::DanglingAttachment { entry: id(0x10) })
    );
}

#[test]
fn t13_14_to_t13_16_inline_missing_and_empty_name() {
    assert_eq!(
        att(
            first_entry(&ok(&g(&entry(
                0x10,
                "<Binary><Key>i</Key><Value>aW5saW5lIQ==</Value></Binary>"
            )))),
            "i"
        ),
        b"inline!"
    );
    assert_eq!(
        err(&g(&entry(0x10, "<Binary><Key>a.txt</Key></Binary>"))),
        Reason::IncompleteAttachment
    );
    assert_eq!(
        err(&g(&entry(0x10, "<Binary><Value>QUJD</Value></Binary>"))),
        Reason::IncompleteAttachment
    );
    let v = pool(&[b"zero"]).ok(&g(&entry(
        0x10,
        "<Binary><Key></Key><Value Ref=\"0\"/></Binary>",
    )));
    assert_eq!(att(first_entry(&v), ""), b"zero");
}

#[test]
fn t13_17_t13_27_t13_34_duplicate_names() {
    let b = |name: &str, v: &str| format!("<Binary><Key>{name}</Key>{v}</Binary>");
    let r = |n: u8| format!("<Value Ref=\"{n}\"/>");
    let i = |b64: &str| format!("<Value>{b64}</Value>");
    let p = || pool(&[b"zero", b"one"]);
    let d = p().doc(&g(&entry(
        0x10,
        &format!("{}{}", b("a.txt", &r(0)), b("a.txt", &r(1))),
    )));
    let e = first_entry(&d.vault);
    assert_eq!(
        (att(e, "a.txt"), renamed(e, "a.txt")),
        (&b"zero"[..], &b"one"[..])
    );
    assert!(
        d.warnings
            .contains(&Warning::AttachmentRenamed { entry: id(0x10) })
    );
    let d = p().doc(&g(&entry(
        0x10,
        &format!("{}{}", b("a.txt", &r(0)), b("a.txt", &r(0))),
    )));
    assert_eq!(first_entry(&d.vault).attachments.len(), 1);
    assert!(d.warnings.is_empty());
    let q = || pool(&[b"AAA", b"BBB"]);
    // A: inline AAA then Ref BBB.
    let v = q().ok(&g(&entry(
        0x10,
        &format!("{}{}", b("f.txt", &i("QUFB")), b("f.txt", &r(1))),
    )));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "f.txt"), renamed(e, "f.txt")),
        (&b"AAA"[..], &b"BBB"[..])
    );
    // B: Ref AAA then inline BBB.
    let v = q().ok(&g(&entry(
        0x10,
        &format!("{}{}", b("f.txt", &r(0)), b("f.txt", &i("QkJC"))),
    )));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "f.txt"), renamed(e, "f.txt")),
        (&b"AAA"[..], &b"BBB"[..])
    );
    // C and D: one attachment.
    for c in [
        format!("{0}{0}", b("f.txt", &i("QUFB"))),
        format!("{}{}", b("f.txt", &r(0)), b("f.txt", &i("QUFB"))),
    ] {
        let d = q().doc(&g(&entry(0x10, &c)));
        assert_eq!(first_entry(&d.vault).attachments.len(), 1);
        assert!(d.warnings.is_empty());
    }
    // E and F (T13-34).
    let v = q().ok(&g(&entry(
        0x10,
        &format!("{}{}", b("f.txt", "<Value/>"), b("f.txt", &r(1))),
    )));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "f.txt"), renamed(e, "f.txt")),
        (&b""[..], &b"BBB"[..])
    );
    let v = q().ok(&g(&entry(
        0x10,
        &format!("{}{}", b("f.txt", &r(1)), b("f.txt", "<Value/>")),
    )));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "f.txt"), renamed(e, "f.txt")),
        (&b"BBB"[..], &b""[..])
    );
}

#[test]
fn t13_26_t13_36_t13_37_value_order_and_repeats() {
    let v = pool(&[b"zero"]).ok(&g(&entry(
        0x10,
        "<Binary><Value Ref=\"0\"/><Key>a.txt</Key></Binary>",
    )));
    assert_eq!(att(first_entry(&v), "a.txt"), b"zero");
    let cases = [
        (
            "<Key>a.txt</Key><Value Ref=\"0\"/><Key>b.txt</Key>",
            "b.txt",
            &b"AAA"[..],
        ),
        (
            "<Key>a.txt</Key><Value>QkJC</Value><Value Ref=\"0\"/>",
            "a.txt",
            b"AAA",
        ),
        (
            "<Key>a.txt</Key><Value Ref=\"0\"/><Value>QkJC</Value>",
            "a.txt",
            b"AAA",
        ),
        (
            "<Key>a.txt</Key><Value>QUFB</Value><Value>QkJC</Value>",
            "a.txt",
            b"BBB",
        ),
        (
            "<Key>a.txt</Key><Key>b.txt</Key><Value>QUJD</Value>",
            "b.txt",
            b"ABC",
        ),
    ];
    for (bin, name, want) in cases {
        let mut r = pool(&[b"AAA"]);
        r.key = s4();
        let v = r.ok(&g(&entry(0x10, &format!("<Binary>{bin}</Binary>"))));
        let e = first_entry(&v);
        assert_eq!(e.attachments.len(), 1, "{bin}");
        assert_eq!(att(e, name), want, "{bin}");
    }
    let mut r = pool(&[b"AAA"]);
    r.key = s4();
    let v = r.ok(&g(&entry(0x10, &format!("<Binary><Key>a.txt</Key><Value Protected=\"True\">1LHm</Value><Value Ref=\"0\"/></Binary>{}", sp("Password", "EX3tMJyG")))));
    let e = first_entry(&v);
    assert_eq!(
        (att(e, "a.txt"), e.value("Password")),
        (&b"AAA"[..], "pw-one")
    );
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn t13_29_t13_35_gzip_damage() {
    let e = entry(0x10, "<Binary><Key>t.txt</Key><Value Ref=\"0\"/></Binary>");
    let gz = gzip(b"abc");
    let cut = base64_encode(&gz[..gz.len() - 8]);
    assert_eq!(
        err(&v3_pool_doc(
            &format!("<Binary ID=\"0\" Compressed=\"True\">{cut}</Binary>"),
            &e
        )),
        Reason::BadCompressedAttachment
    );
    assert_eq!(
        err(&v3_pool_doc(
            "<Binary ID=\"0\" Compressed=\"True\">H4sIAAAAAAAAE0tMSgYAwkEkNQMAAADerb7v</Binary>",
            &e
        )),
        Reason::BadCompressedAttachment
    );
    let mut crc = gz.clone();
    let n = crc.len();
    crc[n - 8] ^= 1;
    assert_eq!(
        err(&v3_pool_doc(
            &format!(
                "<Binary ID=\"0\" Compressed=\"True\">{}</Binary>",
                base64_encode(&crc)
            ),
            &e
        )),
        Reason::BadCompressedAttachment
    );
}

#[test]
fn t13_31_to_t13_33_attachment_limits() {
    // T13-31: base64 attachment text is exempt from the text limit.
    let r = lowered(|l| {
        l.text = 1 << 20;
        l.document = 4 << 20;
    });
    let big = base64_encode(&vec![7u8; 2 << 20]);
    let e = entry(0x10, "<Binary><Key>t</Key><Value Ref=\"0\"/></Binary>");
    r.ok(&v3_pool_doc(
        &format!("<Binary ID=\"0\">{big}</Binary>"),
        &e,
    ));
    r.ok(&g(&entry(
        0x10,
        &format!("<Binary><Key>t</Key><Value>{big}</Value></Binary>"),
    )));
    let huge = base64_encode(&vec![7u8; 3 << 20]);
    assert_eq!(
        r.err(&v3_pool_doc(
            &format!("<Binary ID=\"0\">{huge}</Binary>"),
            &e
        )),
        Reason::Limit(Limit::Document)
    );
    // T13-32: a gzip bomb is stopped while inflating (64 MiB of zeros against a 4 MiB limit).
    let r = lowered(|l| {
        l.one_attachment = 4 << 20;
        l.all_attachments = 4 << 20;
    });
    let bomb = base64_encode(&gzip(&vec![0u8; 64 << 20]));
    assert_eq!(
        r.err(&v3_pool_doc(
            &format!("<Binary ID=\"0\" Compressed=\"True\">{bomb}</Binary>"),
            &e
        )),
        Reason::Limit(Limit::OneAttachment)
    );
    // T13-33: three items of 1.5 MiB pass the all-attachments limit at the third.
    let part = base64_encode(&gzip(&vec![0u8; 3 << 19]));
    for ids in [["0", "1", "2"], ["0", "0", "0"]] {
        let items: String = ids
            .iter()
            .map(|i| format!("<Binary ID=\"{i}\" Compressed=\"True\">{part}</Binary>"))
            .collect();
        assert_eq!(
            r.err(&v3_pool_doc(&items, &e)),
            Reason::Limit(Limit::AllAttachments)
        );
    }
    // Pool items limit counts inner items and document items together.
    let mut r = lowered(|l| l.pool_items = 2);
    r.pool = vec![b"a".to_vec(), b"b".to_vec()];
    assert_eq!(
        r.err(&v3_pool_doc("<Binary ID=\"9\">QUJD</Binary>", &e)),
        Reason::Limit(Limit::PoolItems)
    );
}

#[test]
fn t13_38_dropped_history_block_attachment() {
    let v = pool(&[b"AAA", b"BBB"]).ok(&g(&entry(
        0x10,
        "<Binary><Key>a.txt</Key><Value Ref=\"1\"/></Binary>\
         <History><Entry><Binary><Key>h.txt</Key><Value Ref=\"0\"/></Binary></Entry></History>\
         <History><Entry><Binary><Key>h.txt</Key><Value Ref=\"1\"/></Binary></Entry></History>",
    )));
    let e = first_entry(&v);
    assert_eq!(att(e, "a.txt"), b"BBB");
    assert_eq!(e.history.len(), 1);
    assert_eq!(att(&e.history[0], "h.txt"), b"BBB");
    // Shared content is one stored copy.
    assert!(std::sync::Arc::ptr_eq(
        &e.attachments[0].data,
        &e.history[0].attachments[0].data
    ));
}

// ===========================================================================
// FMT-14: custom icons and custom data.

#[test]
fn fmt_14_04_to_14_08_icons() {
    let a1 = "oaGhoaGhoaGhoaGhoaGhoQ==";
    let v = ok(&doc(
        &format!("<CustomIcons><Icon><UUID>{a1}</UUID><Data/></Icon></CustomIcons>"),
        "<Group/>",
    ));
    assert!(v.meta.custom_icons[0].data.is_empty());
    for icon in [
        format!("<UUID>{a1}</UUID>"),
        "<Data>QUFB</Data>".to_owned(),
        "<UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Data>QUFB</Data>".to_owned(),
        "<UUID>QUJD</UUID><Data>QUFB</Data>".to_owned(),
        format!("<UUID>{a1}</UUID><UUID/><Data>QUFB</Data>"),
    ] {
        assert_eq!(
            err(&doc(
                &format!("<CustomIcons><Icon>{icon}</Icon></CustomIcons>"),
                "<Group/>"
            )),
            Reason::IncompleteIcon
        );
    }
    let v = ok(&doc(
        &format!(
            "<CustomIcons><Icon><UUID>{a1}</UUID><Data>QUFB</Data></Icon><Icon><UUID>{a1}</UUID><Data>QkJC</Data></Icon></CustomIcons>"
        ),
        &format!(
            "<Group>{}</Group>",
            entry(0x10, &format!("<CustomIconUUID>{a1}</CustomIconUUID>"))
        ),
    ));
    let icons = &v.meta.custom_icons;
    assert_eq!(
        (icons[0].uuid, icons[0].data.as_slice()),
        (id(0xA1), &b"AAA"[..])
    );
    assert!(icons[1].uuid != id(0xA1) && !icons[1].uuid.is_zero());
    assert_eq!(icons[1].data, b"BBB");
    assert_eq!(v.root.entries[0].icon, Icon::Custom(id(0xA1)));
    assert_eq!(app_model::invariants::check(&v), Ok(()));
    let v = ok(&doc(
        &format!(
            "<CustomIcons><Icon><UUID>{}</UUID><Data/></Icon><Icon><UUID>{a1}</UUID><Data/></Icon></CustomIcons>",
            idt(0xA2)
        ),
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.custom_icons[0].uuid, v.meta.custom_icons[1].uuid),
        (id(0xA2), id(0xA1))
    );
}

#[test]
fn fmt_14_17_to_14_19_items() {
    assert_eq!(
        err(&doc(
            "<CustomData><Item><Key>k</Key></Item></CustomData>",
            "<Group/>"
        )),
        Reason::IncompleteCustomData
    );
    assert_eq!(
        err(&doc(
            "<CustomData><Item><Value>v</Value></Item></CustomData>",
            "<Group/>"
        )),
        Reason::IncompleteCustomData
    );
    let v = ok(&doc(
        "<CustomData><Item><Key/><Value>v</Value></Item><Item><Key>k</Key><Value/></Item></CustomData>",
        "<Group/>",
    ));
    assert_eq!(
        (v.meta.custom_data.get(""), v.meta.custom_data.get("k")),
        (Some("v"), Some(""))
    );
    let v = ok(&doc(
        "<CustomData><Item><Key>k</Key><Value>first</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item>\
        <Item><Key>k</Key><Value>second</Value></Item><Item><Key>j</Key><Value>same</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item>\
        <Item><Key>j</Key><Value>same</Value><LastModificationTime>GxaW1g4AAAA=</LastModificationTime></Item></CustomData>",
        "<Group/>",
    ));
    let items = &v.meta.custom_data.items;
    assert_eq!(items.len(), 2);
    assert_eq!(
        (items[0].value.as_str(), items[0].last_modified),
        ("second", None)
    );
    assert_eq!(items[1].last_modified, Some(Time(63_745_056_000)));
    let v = ok(&g(
        "<CustomData><Item><Key>a</Key><Value>1</Value></Item></CustomData><CustomData><Item><Key>b</Key><Value>2</Value></Item></CustomData>",
    ));
    let keys: Vec<&str> = v
        .root
        .custom_data
        .items
        .iter()
        .map(|i| i.key.as_str())
        .collect();
    assert_eq!(keys, ["a", "b"]);
}

#[test]
fn fmt_14_22_to_14_24b_last_modified_and_legacy_flag() {
    let lm = "<Item><Key>_LAST_MODIFIED</Key><Value>Mon Jan 1 00:00:00 2018 GMT</Value></Item>";
    let v = ok(&g(&format!("<CustomData>{lm}</CustomData>")));
    assert_eq!(
        v.root.custom_data.get("_LAST_MODIFIED"),
        Some("Mon Jan 1 00:00:00 2018 GMT")
    );
    let item = |k: &str, v: &str| format!("<Item><Key>{k}</Key><Value>{v}</Value></Item>");
    let v = ok(&g(&format!(
        "{}{}{}{}{}",
        entry(
            0xA,
            &format!("<CustomData>{}</CustomData>", item("KnownBad", "true"))
        ),
        entry(
            0xB,
            &format!("<CustomData>{}</CustomData>", item("KnownBad", "True"))
        ),
        entry(
            0xC,
            &format!(
                "<QualityCheck>False</QualityCheck><CustomData>{}</CustomData>",
                item("KnownBad", "false")
            )
        ),
        entry(
            0xE,
            &format!(
                "<CustomData>{}{}</CustomData>",
                item("X", "1"),
                item("KnownBad", "true")
            )
        ),
        entry(
            0xF,
            &format!("<CustomData>{lm}{}</CustomData>", item("KnownBad", "true"))
        ),
    )));
    let e = &v.root.entries;
    let ex: Vec<bool> = e.iter().map(|x| x.exclude_from_reports).collect();
    assert_eq!(ex, [true, false, false, true, true]);
    assert!(e[0].custom_data.items.is_empty() && e[1].custom_data.items.is_empty());
    let keys: Vec<&str> = e[3]
        .custom_data
        .items
        .iter()
        .map(|i| i.key.as_str())
        .collect();
    assert_eq!(keys, ["X"]);
    assert!(e[4].custom_data.items.is_empty());
}

#[test]
fn fmt_14_31_protected_custom_data() {
    let v = ok(&g(&entry(
        0x10,
        "<CustomData><Item><Key>k</Key><Value Protected=\"True\">RxjmIZKk</Value></Item></CustomData>\
        <String><Key>Password</Key><Value Protected=\"True\">AQk=</Value></String>",
    )));
    let e = &v.root.entries[0];
    assert_eq!(
        (e.custom_data.get("k"), e.value("Password")),
        (Some("Secret"), "pw")
    );
}

#[test]
fn fmt_14_32_and_14_33_blocks_and_v41_children() {
    let a1 = "oaGhoaGhoaGhoaGhoaGhoQ==";
    let v = ok(&doc(
        &format!(
            "<CustomIcons><Icon><UUID>{a1}</UUID><Name>n</Name><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime><Data>QUFB</Data></Icon></CustomIcons>"
        ),
        &format!(
            "<Group><UUID>{}</UUID><CustomData><Item><Key>g</Key><Value>1</Value><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime></Item></CustomData></Group>",
            idt(1)
        ),
    ));
    let icon = &v.meta.custom_icons[0];
    assert_eq!(
        (icon.name.as_str(), icon.last_modified),
        ("n", Some(Time(63_729_702_427)))
    );
    assert_eq!(
        v.root.custom_data.items[0].last_modified,
        Some(Time(63_729_702_427))
    );
    let first = format!(
        "<CustomIcons><Icon><UUID>{a1}</UUID><Data>QUFB</Data></Icon></CustomIcons><CustomData><Item><Key>a</Key><Value>1</Value></Item></CustomData>"
    );
    let second = "<CustomIcons><Icon><UUID>oqKioqKioqKioqKioqKiog==</UUID><Data>QkJC</Data></Icon><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>Q0ND</Data></Icon></CustomIcons><CustomData><Item><Key>b</Key><Value>2</Value></Item></CustomData>";
    let r = root_name();
    let a = ok(&format!(
        "<{r}><Meta>{first}</Meta><Meta>{second}</Meta><Root><Group><UUID>{}</UUID></Group></Root></{r}>",
        idt(1)
    ));
    let b = ok(&format!(
        "<{r}><Meta>{first}{second}</Meta><Root><Group><UUID>{}</UUID></Group></Root></{r}>",
        idt(1)
    ));
    for v in [&a, &b] {
        let icons: Vec<&[u8]> = v
            .meta
            .custom_icons
            .iter()
            .map(|i| i.data.as_slice())
            .collect();
        assert_eq!(icons, [&b"AAA"[..], b"BBB", b"CCC"]);
        assert_eq!(
            (v.meta.custom_icons[0].uuid, v.meta.custom_icons[1].uuid),
            (id(0xA1), id(0xA2))
        );
        let keys: Vec<&str> = v
            .meta
            .custom_data
            .items
            .iter()
            .map(|i| i.key.as_str())
            .collect();
        assert_eq!(keys, ["a", "b"]);
    }
}

#[test]
fn fmt_14_35_to_14_38_limits() {
    let r = lowered(|l| l.icons = 100);
    let icons = |from: usize, n: usize| {
        (from..from + n)
            .map(|i| {
                format!(
                    "<Icon><UUID>{}</UUID><Data/></Icon>",
                    base64_encode(&(i as u128 + 1).to_be_bytes())
                )
            })
            .collect::<String>()
    };
    assert_eq!(
        r.ok(&doc(
            &format!("<CustomIcons>{}</CustomIcons>", icons(0, 100)),
            "<Group/>"
        ))
        .meta
        .custom_icons
        .len(),
        100
    );
    assert_eq!(
        r.err(&doc(
            &format!(
                "<CustomIcons>{}</CustomIcons><CustomIcons>{}</CustomIcons>",
                icons(0, 50),
                icons(50, 51)
            ),
            "<Group/>"
        )),
        Reason::Limit(Limit::Icons)
    );
    let r = lowered(|l| l.custom_data_items = 100);
    let items = |from: usize, n: usize| {
        (from..from + n)
            .map(|i| format!("<Item><Key>k{i}</Key><Value/></Item>"))
            .collect::<String>()
    };
    assert_eq!(
        r.ok(&g(&format!(
            "<CustomData>{}</CustomData><CustomData>{}</CustomData>",
            items(0, 50),
            items(50, 50)
        )))
        .root
        .custom_data
        .items
        .len(),
        100
    );
    assert_eq!(
        r.err(&g(&format!(
            "<CustomData>{}</CustomData><CustomData>{}{}</CustomData>",
            items(0, 50),
            items(50, 50),
            items(0, 1)
        ))),
        Reason::Limit(Limit::CustomDataItems)
    );
    let r = lowered(|l| l.custom_data_items_all = 1000);
    let ents = |n: usize, each: usize| {
        (0..n)
            .map(|i| {
                entry(
                    i as u8 + 1,
                    &format!("<CustomData>{}</CustomData>", items(0, each)),
                )
            })
            .collect::<String>()
    };
    r.ok(&g(&ents(10, 100)));
    assert_eq!(
        r.err(&g(&ents(11, 91))),
        Reason::Limit(Limit::CustomDataItemsAll)
    );
    let r = lowered(|l| l.text = 1 << 20);
    r.ok(&doc(
        &format!(
            "<CustomIcons><Icon><UUID>{}</UUID><Data>{}</Data></Icon></CustomIcons>",
            idt(0xA1),
            "A".repeat(1 << 20)
        ),
        "<Group/>",
    ));
    assert_eq!(
        r.err(&doc(
            &format!(
                "<CustomIcons><Icon><UUID>{}</UUID><Data>{}</Data></Icon></CustomIcons>",
                idt(0xA1),
                "A".repeat((1 << 20) + 4)
            ),
            "<Group/>"
        )),
        Reason::Limit(Limit::Text)
    );
    assert_eq!(
        r.err(&doc(
            &format!(
                "<CustomData><Item><Key>k</Key><Value>{}</Value></Item></CustomData>",
                "a".repeat((1 << 20) + 1)
            ),
            "<Group/>"
        )),
        Reason::Limit(Limit::Text)
    );
}

#[test]
fn fmt_14_unknown_children_kept() {
    let v = ok(&doc(
        &format!(
            "<CustomIcons><X1/><Icon><UUID>{}</UUID><Data/><X2/></Icon></CustomIcons><CustomData><X3/><Item><Key>k</Key><Value/><X4/></Item></CustomData>",
            idt(0xA1)
        ),
        "<Group/>",
    ));
    assert_eq!(v.meta.custom_icons_unknown[0].name, "X1");
    assert_eq!(v.meta.custom_icons[0].unknown[0].name, "X2");
    assert_eq!(v.meta.custom_data.unknown[0].name, "X3");
    assert_eq!(v.meta.custom_data.items[0].unknown[0].name, "X4");
}

// ===========================================================================
// FMT-15: deleted objects.

fn deleted(items: &str) -> Vault {
    ok(&doc(
        "",
        &format!(
            "<Group><UUID>{}</UUID></Group><DeletedObjects>{items}</DeletedObjects>",
            idt(1)
        ),
    ))
}

fn list(v: &Vault) -> Vec<(Uuid, Time)> {
    v.deleted_objects
        .iter()
        .map(|d| (d.uuid, d.deleted_at))
        .collect()
}

#[test]
fn fmt_15_02_to_15_07() {
    let v = deleted(&format!(
        "<DeletedObject><UUID>{}</UUID><DeletionTime>2020-07-07T07:07:07Z</DeletionTime></DeletedObject>\
         <DeletedObject><UUID>{}</UUID><DeletionTime>2020-07-08T07:07:07Z</DeletionTime></DeletedObject>",
        idt(0x77),
        idt(0x78)
    ));
    assert_eq!(
        list(&v),
        [
            (id(0x77), Time(63_729_702_427)),
            (id(0x78), Time(63_729_788_827))
        ]
    );
    let v = deleted(
        "<DeletedObject><UUID/><DeletionTime>2010-08-25T16:14:12Z</DeletionTime></DeletedObject><DeletedObject/>\
                     <DeletedObject><UUID>5K/bzWCSmkCv5OZxYl4N/w==</UUID><DeletionTime/></DeletedObject>",
    );
    assert_eq!(v.deleted_objects.len(), 1);
    assert_eq!(
        (
            uuid_to_text(v.deleted_objects[0].uuid),
            v.deleted_objects[0].deleted_at
        ),
        ("5K/bzWCSmkCv5OZxYl4N/w==".to_owned(), Time(0))
    );
    let v = deleted(&format!(
        "<DeletedObject><DeletionTime>2021-01-01T00:00:00Z</DeletionTime><UUID>{}</UUID></DeletedObject>\
         <DeletedObject><UUID>QUJD</UUID><DeletionTime>Zd/www4AAAA=</DeletionTime></DeletedObject>\
         <DeletedObject><UUID>{}</UUID><DeletionTime>yesterday</DeletionTime></DeletedObject>\
         <DeletedObject><UUID>{}</UUID></DeletedObject>",
        idt(0x31),
        idt(0x32),
        idt(0x33)
    ));
    assert_eq!(
        list(&v),
        [(id(0x31), Time(63_745_056_000)), (id(0x32), OPEN)]
    );
    // 15-06 no clean-up, 15-07 two blocks (also 11-06).
    let item = |n: u8, t: &str| {
        format!(
            "<DeletedObject><UUID>{}</UUID><DeletionTime>{t}</DeletionTime></DeletedObject>",
            idt(n)
        )
    };
    let v = ok(&doc(
        "",
        &format!(
            "<DeletedObjects>{}</DeletedObjects><Group><UUID>{}</UUID>{}</Group><DeletedObjects>{}{}{}</DeletedObjects>",
            item(0x10, "2020-01-01"),
            idt(1),
            entry(0x10, ""),
            item(0x30, "2020-01-01"),
            item(0x30, "2021-01-01"),
            item(0x40, "2099-01-01")
        ),
    ));
    let ids: Vec<Uuid> = v.deleted_objects.iter().map(|d| d.uuid).collect();
    assert_eq!(ids, [id(0x10), id(0x30), id(0x30), id(0x40)]);
    assert_eq!(v.root.entries[0].uuid, id(0x10));
}

#[test]
fn fmt_15_20_to_15_23() {
    let r = lowered(|l| l.deleted_objects = 100);
    let items = |n: usize| {
        (0..n)
            .map(|i| {
                format!(
                    "<DeletedObject><UUID>{}</UUID><DeletionTime/></DeletedObject>",
                    base64_encode(&(i as u128 + 1).to_be_bytes())
                )
            })
            .collect::<String>()
    };
    let d = |x: &str| doc("", &format!("<Group/><DeletedObjects>{x}</DeletedObjects>"));
    assert_eq!(r.ok(&d(&items(100))).deleted_objects.len(), 100);
    assert_eq!(
        r.err(&d(&format!(
            "{}</DeletedObjects><DeletedObjects>{}",
            items(50),
            items(51)
        ))),
        Reason::Limit(Limit::DeletedObjects)
    );
    assert_eq!(
        r.err(&d(&format!("{}<DeletedObject/>", items(100)))),
        Reason::Limit(Limit::DeletedObjects)
    );
    // 15-21 repeated children.
    let v = deleted(
        "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><UUID/><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject>\
        <DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DeletionTime>m2eX1g4AAAA=</DeletionTime></DeletedObject>\
        <DeletedObject><UUID>MTExMTExMTExMTExMTExMQ==</UUID><UUID>QUJD</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject>",
    );
    assert_eq!(
        list(&v),
        [
            (id(0x30), Time(63_729_702_427)),
            (id(0x31), Time(63_729_788_827)),
            (id(0x31), Time(63_729_702_427))
        ]
    );
    // 15-22 unknown children.
    let v = deleted(
        "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra a=\"1\"/></DeletedObject>\
        <DeletedObject><DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra2/></DeletedObject><Other/>",
    );
    assert_eq!(v.deleted_objects.len(), 1);
    assert_eq!(v.deleted_objects[0].unknown[0].name, "DelExtra");
    assert_eq!(v.unknown_deleted_objects[0].name, "Other");
    // 15-23 times out of range kept.
    let v = deleted(
        "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>/////////38=</DeletionTime></DeletedObject>\
        <DeletedObject><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>2f////////8=</DeletionTime></DeletedObject>",
    );
    assert_eq!(
        list(&v),
        [(id(0x30), Time(i64::MAX)), (id(0x31), Time(-39))]
    );
}

// ===========================================================================
// AT-A07 and AT-A08.

#[test]
fn at_a07_xml_attacks() {
    let r = root_name();
    // DOCTYPE with entity expansion, external entity, parameter entity: refused before any entity work.
    for dtd in [
        format!(
            "<!DOCTYPE {r} [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]>"
        ),
        format!("<!DOCTYPE {r} [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"),
        format!("<!DOCTYPE {r} SYSTEM \"http://example.com/x.dtd\">"),
        format!("<!DOCTYPE {r} [<!ENTITY % p SYSTEM \"file:///etc/passwd\"> %p;]>"),
    ] {
        let x = format!(
            "{dtd}<{r}><Meta><DatabaseName>&c;&x;</DatabaseName></Meta><Root><Group/></Root></{r}>"
        );
        assert_eq!(err(&x), Reason::ForbiddenDeclaration);
    }
    // 100,000 nesting levels of unknown elements and of groups: refused at depth 513, fast.
    let start = Instant::now();
    let deep = format!("{}{}", "<U>".repeat(100_000), "</U>".repeat(100_000));
    assert_eq!(err(&g(&deep)), Reason::Limit(Limit::Depth));
    assert_eq!(err(&nested(100_000)), Reason::Limit(Limit::Depth));
    assert!(start.elapsed().as_secs() < 2);
    // A text node over the text limit (64 MiB) is refused; a document over the
    // document limit is refused before parsing (a 1 GB node cannot fit in one).
    // Built in one buffer, so peak memory shows the reader adds no copy.
    let wrapped = g(&entry(0x10, &s("Notes", "@")));
    let (head, tail) = wrapped.split_once('@').unwrap();
    let mut big = String::with_capacity(head.len() + (64 << 20) + 1 + tail.len());
    big.push_str(head);
    big.extend(std::iter::repeat_n('a', (64 << 20) + 1));
    big.push_str(tail);
    assert_eq!(err(&big), Reason::Limit(Limit::Text));
    let r2 = lowered(|l| l.document = 1 << 20);
    assert_eq!(
        r2.err(&g(&entry(0x10, &s("Notes", &"a".repeat(2 << 20))))),
        Reason::Limit(Limit::Document)
    );
}

#[test]
fn at_a08_hostile_documents() {
    // Duplicate ids, group cycles, missing fields, bad refs and huge counts:
    // each ends in a clean result or a clean error, never a panic or hang.
    let start = Instant::now();
    let cases: Vec<(String, Result<(), Reason>)> = vec![
        (
            g(&format!("{0}{0}{0}", entry(0x10, &s("Title", "dup")))),
            Ok(()),
        ),
        (
            g(&format!(
                "<Group><UUID>{a}</UUID></Group><Group><UUID>{a}</UUID></Group>",
                a = idt(2)
            )),
            Ok(()),
        ),
        (
            g(&format!(
                "<Group><UUID>{a}</UUID><Group><UUID>{a}</UUID></Group></Group>",
                a = idt(2)
            )),
            Err(Reason::GroupInsideItself),
        ),
        (
            g(&entry(0x10, "<String><Key>k</Key></String>")),
            Err(Reason::IncompleteField),
        ),
        (
            g(&entry(0x10, "<Binary><Key>k</Key></Binary>")),
            Err(Reason::IncompleteAttachment),
        ),
        (
            g(&entry(
                0x10,
                "<Binary><Key>k</Key><Value Ref=\"99\"/></Binary>",
            )),
            Ok(()),
        ),
        (
            doc(
                &format!("<RecycleBinUUID>{}</RecycleBinUUID>", idt(1)),
                &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
            ),
            Ok(()),
        ),
        (g(&"<Group/>".repeat(20_000)), Ok(())),
    ];
    for (x, want) in cases {
        let got = Run::default().bytes(x.as_bytes()).map(|d| {
            assert_eq!(app_model::invariants::check(&d.vault), Ok(()));
        });
        assert_eq!(got, want);
    }
    // A long chain of duplicate moves is bounded by the depth limit.
    let mut chain = String::new();
    for i in 0..600u32 {
        let a = base64_encode(&(u128::from(i) + 10).to_be_bytes());
        let b = base64_encode(&(u128::from(i) + 11).to_be_bytes());
        chain.push_str(&format!(
            "<Group><UUID>{a}</UUID><Group><UUID>{b}</UUID></Group></Group>"
        ));
    }
    assert_eq!(err(&g(&chain)), Reason::Limit(Limit::Depth));
    // Many duplicate placements stay linear.
    let many = format!(
        "<Group/>{}",
        format!("<Group><UUID>{}</UUID></Group>", idt(2)).repeat(50_000)
    );
    let v = ok(&g(&many));
    assert_eq!(v.root.groups.len(), 2);
    assert!(start.elapsed().as_secs() < 10);
}

#[test]
fn errors_name_no_value() {
    let e = err(&g(&entry(
        0x10,
        &format!("{}{}", s("Title", "SECRET-TITLE"), s("Title", "x")),
    )));
    assert!(!format!("{e:?} {}", e.kind()).contains("SECRET"));
}

#[test]
fn at_a08_hostile_orders_stay_fast() {
    // Orders that would cost quadratic time with naive lookups, at the
    // default limits: each read must finish in seconds, not hours.
    let start = Instant::now();
    // 100,000 fields in reverse name order (11-69 at full size).
    let strings: String = (0..100_000)
        .rev()
        .map(|i| s(&format!("k{i:06}"), ""))
        .collect();
    let v = ok(&g(&format!("<Entry>{strings}</Entry>")));
    assert_eq!(v.root.entries[0].fields().count(), 100_005);
    // 100,000 custom data items in one group (14-36 at full size).
    let items: String = (0..100_000)
        .map(|i| format!("<Item><Key>k{i}</Key><Value/></Item>"))
        .collect();
    assert_eq!(
        ok(&g(&format!("<CustomData>{items}</CustomData>")))
            .root
            .custom_data
            .items
            .len(),
        100_000
    );
    // 50,000 entry custom data blocks, each with the legacy flag.
    let blocks: String = (0..50_000)
        .map(|i| format!("<CustomData><Item><Key>x{i}</Key><Value/></Item><Item><Key>KnownBad</Key><Value>true</Value></Item></CustomData>"))
        .collect();
    let v = ok(&g(&format!("<Entry>{blocks}</Entry>")));
    assert_eq!(v.root.entries[0].custom_data.items.len(), 50_000);
    assert!(v.root.entries[0].exclude_from_reports);
    // 100,000 icons (14-35 at full size).
    let icons: String = (0..100_000u128)
        .map(|i| {
            format!(
                "<Icon><UUID>{}</UUID><Data/></Icon>",
                base64_encode(&(i + 1).to_be_bytes())
            )
        })
        .collect();
    assert_eq!(
        ok(&doc(
            &format!("<CustomIcons>{icons}</CustomIcons>"),
            "<Group/>"
        ))
        .meta
        .custom_icons
        .len(),
        100_000
    );
    // 100,000 same-name attachments alternating between two 1 MiB items.
    let r = Run {
        pool: vec![vec![1; 1 << 20], vec![2; 1 << 20]],
        ..Run::default()
    };
    let bins: String = (0..100_000)
        .map(|i| {
            format!(
                "<Binary><Key>f.txt</Key><Value Ref=\"{}\"/></Binary>",
                i % 2
            )
        })
        .collect();
    let v = r.ok(&g(&format!("<Entry>{bins}</Entry>")));
    assert_eq!(v.root.entries[0].attachments.len(), 50_001);
    assert!(start.elapsed().as_secs() < 30, "{:?}", start.elapsed());
}

// ===========================================================================
// E3 fix pass (Checker B1 to B4, LD-80, LD-81 and the minor findings).

/// Builds protected values at a running keystream offset (zero key).
struct Sweep {
    key: Vec<u8>,
    at: usize,
}

impl Sweep {
    fn pr(&mut self, name: &str, plain: &[u8]) -> String {
        let s = format!(
            "<{name} Protected=\"True\">{}</{name}>",
            enc(&self.key, self.at, plain)
        );
        self.at += plain.len();
        s
    }
}

/// 2010-08-08T17:24:53Z in the binary form, and its value.
const T1: &[u8] = b"Zd/www4AAAA=";
const T1_VALUE: Time = Time(63_416_885_093);

#[test]
fn fmt_12_29_sweep_remaining_elements() {
    // B1: a protected value in every FMT-12.29 element the first sweep does
    // not hold, at a known offset, ending with a protected Password that must
    // decode: an element read without the field stream garbles it.
    let mut w = Sweep {
        key: zero_key(),
        at: 0,
    };
    let root = id(1);
    let sub = id(0x20);
    let ent = id(0x30);
    let mut meta = String::new();
    meta += &w.pr("DatabaseName", b"DB");
    meta += &w.pr("DatabaseNameChanged", T1);
    meta += &w.pr("DatabaseDescription", b"Desc");
    meta += &w.pr("DatabaseDescriptionChanged", T1);
    meta += &w.pr("DefaultUserName", b"user");
    meta += &w.pr("DefaultUserNameChanged", T1);
    meta += &w.pr("MaintenanceHistoryDays", b"365");
    meta += &w.pr("Color", b"#AABBCC");
    meta += &w.pr("MasterKeyChanged", T1);
    meta += &w.pr("MasterKeyChangeRec", b"30");
    meta += &w.pr("MasterKeyChangeForce", b"90");
    meta += "<MasterKeyChangeForceOnce Protected=\"True\">true</MasterKeyChangeForceOnce>"; // takes none
    meta += "<MemoryProtection>";
    meta += &w.pr("ProtectUserName", b"True");
    meta += &w.pr("ProtectPassword", b"False");
    meta += &w.pr("ProtectURL", b"True");
    meta += &w.pr("ProtectNotes", b"True");
    meta += "</MemoryProtection>";
    meta += &w.pr("RecycleBinEnabled", b"False");
    meta += &w.pr("RecycleBinUUID", &root.0);
    meta += &w.pr("RecycleBinChanged", T1);
    meta += &w.pr("EntryTemplatesGroup", &sub.0);
    meta += &w.pr("EntryTemplatesGroupChanged", T1);
    meta += &w.pr("LastSelectedGroup", &root.0);
    meta += &w.pr("LastTopVisibleGroup", &sub.0);
    meta += &w.pr("HistoryMaxSize", b"1000");
    meta += &w.pr("SettingsChanged", T1);
    meta += &w.pr("HeaderHash", &[0xAB; 32]); // version 4: read and ignored, bytes still taken
    meta += "<Binaries>";
    meta += &w
        .pr("Binary", b"pool!")
        .replacen("<Binary ", "<Binary ID=\"0\" ", 1);
    meta += "</Binaries><CustomData><Item><Key>mk</Key><Value>mv</Value>";
    meta += &w.pr("LastModificationTime", T1);
    meta += "</Item></CustomData>";
    let mut group = format!("<Group><UUID>{}</UUID>", idt(1));
    group += &w.pr("CustomIconUUID", &[0x77; 16]);
    group += &w.pr("LastTopVisibleEntry", &ent.0);
    group += &w.pr("PreviousParentGroup", &[0x66; 16]);
    group += "<Times>";
    group += &w.pr("LastModificationTime", T1);
    group += &w.pr("LastAccessTime", T1);
    group += &w.pr("ExpiryTime", T1);
    group += &w.pr("LocationChanged", T1);
    group += "</Times><CustomData><Item><Key>gk</Key><Value>gv</Value>";
    group += &w.pr("LastModificationTime", T1);
    group += "</Item></CustomData>";
    group += &format!("<Group><UUID>{}</UUID><Name>Sub</Name></Group>", idt(0x20));
    group += &format!("<Entry><UUID>{}</UUID>", idt(0x30));
    group += &w.pr("CustomIconUUID", &[0x88; 16]);
    group += &w.pr("BackgroundColor", b"#010203");
    group += &w.pr("PreviousParentGroup", &[0x99; 16]);
    group += "<Times>";
    group += &w.pr("ExpiryTime", T1);
    group += &w.pr("LocationChanged", T1);
    group += "</Times><CustomData><Item><Key>ek</Key><Value>ev</Value>";
    group += &w.pr("LastModificationTime", T1);
    group += "</Item></CustomData><Binary><Key>p.txt</Key><Value Ref=\"0\"/></Binary>";
    group += &format!("<History><Entry><UUID>{}</UUID>", idt(0x30));
    group += &w.pr("BackgroundColor", b"#0A0B0C");
    group += "<String><Key>Password</Key>";
    group += &w.pr("Value", b"old-pw");
    group += "</String></Entry></History><String><Key>Password</Key>";
    group += &w.pr("Value", b"final-pw");
    group += "</String></Entry></Group>";
    let v = ok(&doc(&meta, &group));
    let m = &v.meta;
    assert_eq!(
        (
            m.name.as_str(),
            m.description.as_str(),
            m.default_user_name.as_str()
        ),
        ("DB", "Desc", "user")
    );
    for t in [
        m.name_changed,
        m.description_changed,
        m.default_user_name_changed,
        m.master_key_changed,
        m.recycle_bin_changed,
        m.entry_templates_group_changed,
        m.settings_changed,
    ] {
        assert_eq!(t, T1_VALUE);
    }
    assert_eq!(
        (m.maintenance_history_days, m.color.as_str()),
        (365, "#AABBCC")
    );
    assert_eq!(
        (
            m.master_key_change_rec,
            m.master_key_change_force,
            m.master_key_change_force_once
        ),
        (30, 90, true)
    );
    let mp = &m.memory_protection;
    assert_eq!(
        (mp.user_name, mp.password, mp.url, mp.notes),
        (true, false, true, true)
    );
    assert!(!m.recycle_bin_enabled);
    assert_eq!(
        (m.recycle_bin, m.entry_templates_group),
        (Some(root), Some(sub))
    );
    assert_eq!(
        (m.last_selected_group, m.last_top_visible_group),
        (Some(root), Some(sub))
    );
    assert_eq!(m.history_max_size, 1000);
    assert_eq!(m.custom_data.items[0].last_modified, Some(T1_VALUE));
    let g = &v.root;
    assert_eq!(g.icon, Icon::Custom(Uuid([0x77; 16])));
    assert_eq!(
        (g.last_top_visible_entry, g.previous_parent),
        (Some(ent), Some(Uuid([0x66; 16])))
    );
    let t = &g.times;
    assert_eq!(
        [
            t.last_modification,
            t.last_access,
            t.expiry,
            t.location_changed
        ],
        [T1_VALUE; 4]
    );
    assert_eq!(g.custom_data.items[0].last_modified, Some(T1_VALUE));
    let e = &g.entries[0];
    assert_eq!(e.icon, Icon::Custom(Uuid([0x88; 16])));
    assert_eq!(
        (e.background_color.as_str(), e.previous_parent),
        ("#010203", Some(Uuid([0x99; 16])))
    );
    assert_eq!([e.times.expiry, e.times.location_changed], [T1_VALUE; 2]);
    assert_eq!(e.custom_data.items[0].last_modified, Some(T1_VALUE));
    assert_eq!(att(e, "p.txt"), b"pool!");
    assert_eq!(
        (
            e.history[0].background_color.as_str(),
            e.history[0].value("Password")
        ),
        ("#0A0B0C", "old-pw")
    );
    assert_eq!(
        e.value("Password"),
        "final-pw",
        "the last value decodes only if every element before took its bytes"
    );
}

/// A shallow document whose duplicate ids build a group chain `n` deep:
/// each wrapper absorbs a re-placement, and each later occurrence pulls the
/// earlier group under it (LD-76(3)). The deepest group ends at level n + 1
/// (the root group is level 0).
fn duplicate_chain(n: u32) -> String {
    let idn = |k: u32| base64_encode(&(u128::from(k) + 100).to_be_bytes());
    let mut x = String::new();
    for k in (1..n).rev() {
        x.push_str(&format!(
            "<Group><Group><UUID>{}</UUID><Group><UUID>{}</UUID></Group></Group></Group>",
            idn(k),
            idn(k + 1)
        ));
    }
    g(&x)
}

fn deepest(gr: &app_model::Group) -> usize {
    let mut d = 0;
    let mut stack = vec![(gr, 0usize)];
    while let Some((gr, l)) = stack.pop() {
        d = d.max(l);
        stack.extend(gr.groups.iter().map(|c| (c, l + 1)));
    }
    d
}

#[test]
fn ld76_3_tree_depth_from_duplicates() {
    // B2: at the depth limit 512 the deepest group may sit at level 510
    // (document depth 512); level 511 is TooLarge. The cycle walk never sees
    // these chains, so only the tree-depth check stops them.
    let v = ok(&duplicate_chain(509));
    assert_eq!(deepest(&v.root), 510);
    assert_eq!(app_model::invariants::check(&v), Ok(()));
    assert_eq!(err(&duplicate_chain(510)), Reason::Limit(Limit::Depth));
    // Without the check a 50,000-deep chain overflows the stack on drop.
    let start = Instant::now();
    assert_eq!(err(&duplicate_chain(50_000)), Reason::Limit(Limit::Depth));
    assert!(start.elapsed().as_secs() < 60);
}

#[test]
fn at_a07_doctype_alone() {
    // B3: a DOCTYPE is refused for itself, even when the body uses no entity.
    let r = root_name();
    let plain = format!("<!DOCTYPE {r}>{}", g(""));
    assert_eq!(err(&plain), Reason::ForbiddenDeclaration);
    let subset = format!("<!DOCTYPE {r} [<!ENTITY a \"aaaa\">]>{}", g(""));
    assert_eq!(err(&subset), Reason::ForbiddenDeclaration);
    let decl = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE {r}>{}",
        g("")
    );
    assert_eq!(err(&decl), Reason::ForbiddenDeclaration);
}

#[test]
fn b4_values_split_by_references_and_cdata() {
    // B4: text in several pieces is joined or decoded once, exactly.
    let v = ok(&g(&entry(
        0x10,
        &format!(
            "{}<Binary><Key>a</Key><Value>QU&#74;DR\r\nA==</Value></Binary>",
            s("Notes", "a&amp;b<![CDATA[<c>]]>d&#13;e\r\nf<!-- x -->g")
        ),
    )));
    let e = first_entry(&v);
    assert_eq!(e.value("Notes"), "a&b<c>d\re\nfg");
    assert_eq!(att(e, "a"), b"ABCD");
    // A version 3 pool item split the same way.
    let p = ok(&doc(
        "<Binaries><Binary ID=\"0\">QU&#74;D\r\nRA==</Binary></Binaries>",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, "<Binary><Key>b</Key><Value Ref=\"0\"/></Binary>")
        ),
    ));
    assert_eq!(att(first_entry(&p), "b"), b"ABCD");
}

#[test]
fn ld80_stray_text_in_containers_counts() {
    let lim = Limits {
        text: 30,
        ..Limits::DEFAULT
    };
    let run = Run {
        lim,
        ..Run::default()
    };
    let x = "x".repeat(31);
    // Directly in Meta, in a group, in an entry, and in a dropped child.
    assert_eq!(
        run.err(&doc(&x, &format!("<Group><UUID>{}</UUID></Group>", idt(1)))),
        Reason::Limit(Limit::Text)
    );
    assert_eq!(run.err(&g(&x)), Reason::Limit(Limit::Text));
    assert_eq!(run.err(&g(&entry(0x10, &x))), Reason::Limit(Limit::Text));
    let dropped = entry(
        0x10,
        &format!("<String><Key>k</Key><Value>v</Value><Junk><J>{x}</J></Junk></String>"),
    );
    assert_eq!(run.err(&g(&dropped)), Reason::Limit(Limit::Text));
    // Pieces of one element add up; text in different elements does not.
    let split = format!(
        "<Group><UUID>{}</UUID>{}<Name>n</Name>{}</Group>",
        idt(1),
        "y".repeat(16),
        "y".repeat(16)
    );
    assert_eq!(run.err(&doc("", &split)), Reason::Limit(Limit::Text));
    let spread = g(&format!(
        "{}<Group>{}</Group>",
        "z".repeat(20),
        "z".repeat(20)
    ));
    run.ok(&spread);
}

#[test]
fn ld81_layout_whitespace_in_kept_elements_is_dropped() {
    let indented = ok(&g("<U a=\"1\">\n\t\t<V>v</V>\n\t\t<W/>\n\t</U>"));
    let flat = ok(&g("<U a=\"1\"><V>v</V><W/></U>"));
    assert_eq!(indented.root.unknown, flat.root.unknown);
    assert_eq!(flat.root.unknown[0].content.len(), 2);
    // Text that is not only whitespace, or a text-only element, is kept.
    let mixed = ok(&g("<U>a<V/> </U>"));
    assert_eq!(mixed.root.unknown[0].content.len(), 3);
    let text_only = ok(&g("<U>  </U>"));
    assert_eq!(text(&text_only.root.unknown[0]), "  ");
}

#[test]
fn ld81_nothing_inside_mixed_content_is_dropped() {
    // R3-m1 (FMT-10.27): E is element-only but sits inside the mixed M, so
    // it keeps its whitespace; the element-only form stays flat (above).
    let v = ok(&g("<M>t<E>\n  <C/>\n</E></M>"));
    let m = &v.root.unknown[0];
    assert_eq!(m.content.len(), 2);
    let UnknownNode::Element(e) = &m.content[1] else {
        panic!("E expected")
    };
    assert_eq!(e.content.len(), 3, "E keeps its layout text");
    assert!(matches!(&e.content[0], UnknownNode::Text(t) if t == "\n  "));
    // An element-only parent above a mixed child: the parent is flattened,
    // the mixed child is kept whole.
    let v = ok(&g("<P>\n  <M>t<E> <C/> </E></M>\n</P>"));
    let p = &v.root.unknown[0];
    assert_eq!(p.content.len(), 1);
    let UnknownNode::Element(m) = &p.content[0] else {
        panic!("M expected")
    };
    let UnknownNode::Element(e) = &m.content[1] else {
        panic!("E expected")
    };
    assert_eq!(e.content.len(), 3);
}

#[test]
fn ld80_container_text_exactly_at_the_limit() {
    // R3-m2: stray direct text of exactly the limit opens; one byte more is
    // TooLarge, in Meta and in an entry (both read by `children`).
    let run = Run {
        lim: Limits {
            text: 30,
            ..Limits::DEFAULT
        },
        ..Run::default()
    };
    let root = format!("<Group><UUID>{}</UUID></Group>", idt(1));
    run.ok(&doc(&"m".repeat(30), &root));
    assert_eq!(
        run.err(&doc(&"m".repeat(31), &root)),
        Reason::Limit(Limit::Text)
    );
    run.ok(&g(&entry(0x10, &"e".repeat(30))));
    assert_eq!(
        run.err(&g(&entry(0x10, &"e".repeat(31)))),
        Reason::Limit(Limit::Text)
    );
}

#[test]
fn fmt_08_12_unknown_text_and_attribute_limits() {
    // The text limit is 30 here (the UUID text is 24 characters).
    let lim = Limits {
        text: 30,
        ..Limits::DEFAULT
    };
    let run = Run {
        lim,
        ..Run::default()
    };
    let (at, over) = ("t".repeat(30), "t".repeat(31));
    run.ok(&g(&format!("<U>{at}</U>")));
    assert_eq!(
        run.err(&g(&format!("<U>{over}</U>"))),
        Reason::Limit(Limit::Text)
    );
    run.ok(&g(&format!("<U a=\"{at}\"/>")));
    assert_eq!(
        run.err(&g(&format!("<U a=\"{over}\"/>"))),
        Reason::Limit(Limit::Text)
    );
}

#[test]
fn fmt_13_20_exact_attachment_limits() {
    // One attachment and all attachments: exactly the limit opens, one more is TooLarge.
    let ref0 = entry(0x10, "<Binary><Key>a</Key><Value Ref=\"0\"/></Binary>");
    let one = |n: usize| Run {
        pool: vec![vec![1; 10]],
        lim: Limits {
            one_attachment: n,
            ..Limits::DEFAULT
        },
        ..Run::default()
    };
    one(10).ok(&g(&ref0));
    assert_eq!(one(9).err(&g(&ref0)), Reason::Limit(Limit::OneAttachment));
    let all = |n: usize| Run {
        pool: vec![vec![1; 10], vec![2; 6]],
        lim: Limits {
            all_attachments: n,
            ..Limits::DEFAULT
        },
        ..Run::default()
    };
    all(16).ok(&g(&ref0));
    assert_eq!(all(15).err(&g(&ref0)), Reason::Limit(Limit::AllAttachments));
    // Inline attachment bytes count too (FMT-13.20(b)).
    let inline = entry(
        0x10,
        &format!(
            "<Binary><Key>i</Key><Value>{}</Value></Binary>",
            base64_encode(&[7; 12])
        ),
    );
    let lim = |one: usize, all: usize| Run {
        lim: Limits {
            one_attachment: one,
            all_attachments: all,
            ..Limits::DEFAULT
        },
        ..Run::default()
    };
    lim(12, 12).ok(&g(&inline));
    assert_eq!(
        lim(11, 100).err(&g(&inline)),
        Reason::Limit(Limit::OneAttachment)
    );
    assert_eq!(
        lim(100, 11).err(&g(&inline)),
        Reason::Limit(Limit::AllAttachments)
    );
    // Version 3 pool items count as they are read.
    let v3 = doc(
        &format!(
            "<Binaries><Binary ID=\"0\">{}</Binary></Binaries>",
            base64_encode(&[3; 12])
        ),
        &format!("<Group><UUID>{}</UUID>{ref0}</Group>", idt(1)),
    );
    lim(12, 12).ok(&v3);
    assert_eq!(lim(100, 11).err(&v3), Reason::Limit(Limit::AllAttachments));
}

#[test]
fn fmt_11_negative_group_icon_reads_as_zero() {
    let v = ok(&doc(
        "",
        &format!("<Group><UUID>{}</UUID><IconID>-5</IconID></Group>", idt(1)),
    ));
    assert_eq!(v.root.icon, Icon::Standard(0));
}

#[test]
fn fmt_13_5_non_binary_children_of_binaries_skipped() {
    let x = doc(
        "<Binaries><Foo ID=\"0\">QUJD</Foo></Binaries>",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, "<Binary><Key>a</Key><Value Ref=\"0\"/></Binary>")
        ),
    );
    let d = Run::default().doc(&x);
    assert_eq!(att(first_entry(&d.vault), "a"), b"");
    assert!(
        d.warnings
            .contains(&Warning::DanglingAttachment { entry: id(0x10) })
    );
}

#[test]
fn fmt_10_8_bom_then_declaration() {
    let mut x = vec![0xEF, 0xBB, 0xBF];
    x.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    x.extend_from_slice(g("").as_bytes());
    assert!(Run::default().bytes(&x).is_ok());
}

#[test]
fn fmt_10_8_declaration_inside_the_document() {
    let r = root_name();
    for pi in [
        "<?XML version=\"1.0\"?>",
        "<?xml version=\"1.0\"?>",
        "<?xMl a?>",
    ] {
        let x = format!("<{r}>{pi}<Meta/><Root><Group/></Root></{r}>");
        assert_eq!(err(&x), Reason::NotXml, "{pi}");
    }
}

#[test]
fn fmt_10_5_text_before_the_root() {
    assert_eq!(err(&format!("x{}", g(""))), Reason::NotXml);
    assert!(
        Run::default()
            .bytes(format!(" \n\t{}", g("")).as_bytes())
            .is_ok()
    );
}

#[test]
fn fmt_12_4_base64_shape_padding() {
    // "A===" has three pad characters: not the base64 shape, so it is an
    // invalid text time and the open time is used (not the binary zero).
    let times = |t: &str| {
        ok(&doc("", &format!("<Group><UUID>{}</UUID><Times><LastModificationTime>{t}</LastModificationTime></Times></Group>", idt(1)))).root.times.last_modification
    };
    assert_eq!(times("A==="), OPEN);
    assert_eq!(times("AAA="), Time(0));
}

// The card rows at the real FMT-08.12 numbers (slow; run with --ignored).

#[test]
#[ignore = "full size: run with --ignored"]
fn fmt_11_65_group_limit_full_size() {
    assert!(
        Run::default()
            .bytes(g(&"<Group/>".repeat(999_999)).as_bytes())
            .is_ok()
    );
    assert_eq!(
        err(&g(&"<Group/>".repeat(1_000_000))),
        Reason::Limit(Limit::Groups)
    );
}

#[test]
#[ignore = "full size: run with --ignored"]
fn fmt_11_67_entry_elements_full_size() {
    let hist = |n: usize| format!("<Entry><History>{}</History></Entry>", "<Entry/>".repeat(n));
    let a: String = (0..40).map(|_| hist(99_999)).collect();
    assert!(Run::default().bytes(g(&a).as_bytes()).is_ok());
    let b = format!(
        "{}{}",
        (0..39).map(|_| hist(99_999)).collect::<String>(),
        hist(100_000)
    );
    assert_eq!(err(&g(&b)), Reason::Limit(Limit::EntryElements));
}

#[test]
#[ignore = "full size: run with --ignored"]
fn fmt_11_68_history_limit_full_size() {
    let a = ok(&g(&entry(
        0x10,
        &format!("<History>{}</History>", "<Entry/>".repeat(100_000)),
    )));
    assert_eq!(a.root.entries[0].history.len(), 100_000);
    assert!(a.root.entries[0].history.iter().all(|h| h.uuid == id(0x10)));
    assert_eq!(
        err(&g(&entry(
            0x10,
            &format!("<History>{}</History>", "<Entry/>".repeat(100_001))
        ))),
        Reason::Limit(Limit::History)
    );
    let c = format!(
        "<History>{0}</History><History>{0}</History>",
        "<Entry/>".repeat(60_000)
    );
    assert_eq!(err(&g(&entry(0x10, &c))), Reason::Limit(Limit::History));
}

#[test]
#[ignore = "full size: run with --ignored"]
fn fmt_11_71_association_limit_full_size() {
    let a = |n: usize| {
        format!(
            "<AutoType>{}</AutoType>",
            "<Association><Window>w</Window><KeystrokeSequence>k</KeystrokeSequence></Association>"
                .repeat(n)
        )
    };
    let v = ok(&g(&entry(0x10, &format!("{}{}", a(50_000), a(50_000)))));
    assert_eq!(v.root.entries[0].auto_type.associations.len(), 100_000);
    assert_eq!(
        err(&g(&entry(0x10, &format!("{}{}", a(50_000), a(50_001))))),
        Reason::Limit(Limit::Associations)
    );
}

#[test]
#[ignore = "full size: run with --ignored"]
fn fmt_11_72_kept_unknown_limit_full_size() {
    let v = ok(&g(&"<U/>".repeat(1_000_000)));
    assert_eq!(v.root.unknown.len(), 1_000_000);
    assert_eq!(
        err(&g(&"<U/>".repeat(1_000_001))),
        Reason::Limit(Limit::KeptUnknown)
    );
    assert_eq!(
        err(&g(&format!("<U>{}</U>", "<V/>".repeat(1_000_000)))),
        Reason::Limit(Limit::KeptUnknown)
    );
}
