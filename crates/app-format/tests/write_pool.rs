//! E3-S7 writer rows of FMT-13 (attachments and the pool), FMT-14 (custom
//! icons and custom data) and FMT-15 (deleted objects). Each test names its
//! card row.

mod format_common;
mod write_common;

use app_crypto::secret::SecretString;
use app_format::document::encode::{base64_encode, time_to_binary};
use app_format::document::write::{self, PADDING_KEY, last_modified_text};
use app_model::times::Civil;
use app_model::{CustomDataItem, CustomIcon, DeletedObject, Field, Time, Vault};
use format_common::{Demo, inner_header, s4};
use write_common::*;

fn at(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Time {
    Time::from_civil(Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
    .unwrap()
}

/// A version 4 demo vault file with the document `xml` and pool `pool`.
fn demo_file(xml: &str, pool: &[(u8, &[u8])]) -> Vec<u8> {
    Demo {
        inner: inner_header(3, &s4(), pool),
        xml: xml.as_bytes().to_vec(),
        ..Demo::new()
    }
    .build()
}

fn bin_ref(name: &str, r: &str) -> String {
    format!("<Binary><Key>{name}</Key><Value Ref=\"{r}\"/></Binary>")
}

fn bin_inline(name: &str, data: &[u8]) -> String {
    format!(
        "<Binary><Key>{name}</Key><Value>{}</Value></Binary>",
        base64_encode(data)
    )
}

/// The `Ref` of the attachment `name` in the first entry block `entry_xml`.
fn ref_of(entry_xml: &str, name: &str) -> String {
    let rest = entry_xml
        .split(&format!("<Key>{name}</Key>"))
        .nth(1)
        .unwrap();
    rest.split("Ref=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

/// Writes `v` and returns the document and the pool contents.
fn write_pool(v: &Vault, minor: u16) -> (String, Vec<Vec<u8>>) {
    let w = write::write(v, minor, &mut chacha(&zero_key()), &stamp()).unwrap();
    let pool = w.pool.iter().map(|p| p.expose().to_vec()).collect();
    (String::from_utf8(w.xml().to_vec()).unwrap(), pool)
}

// -- FMT-13 -----------------------------------------------------------------

#[test]
fn t13_03_flags() {
    let xml = g(&entry(
        0x10,
        &format!("{}{}", bin_ref("a", "0"), bin_ref("b", "1")),
    ));
    let file = demo_file(&xml, &[(0x00, b"a0"), (0xFE, b"b0")]);
    let saved = resave(&file);
    let pool = saved_pool(&saved, "demo-pass");
    assert_eq!(pool, [(0x01, b"a0".to_vec()), (0x01, b"b0".to_vec())]);
}

#[test]
fn t13_14_inline_becomes_a_pool_item() {
    let file = demo_file(
        &g(&entry(
            0x10,
            "<Binary><Key>f</Key><Value>aW5saW5lIQ==</Value></Binary>",
        )),
        &[],
    );
    let saved = resave(&file);
    assert_eq!(
        saved_pool(&saved, "demo-pass"),
        [(0x01, b"inline!".to_vec())]
    );
    assert!(saved_doc(&saved, "demo-pass").contains("<Key>f</Key>\n\t\t\t\t\t<Value Ref=\"0\"/>"));
}

#[test]
fn t13_18_pool_order() {
    let e = |n: u8, bins: &str, hist: &[String]| {
        let h: String = hist.iter().map(|b| entry(n, b)).collect();
        entry(n, &format!("{bins}<History>{h}</History>"))
    };
    let root = format!(
        "{}{}<Group><UUID>{}</UUID>{}</Group>",
        e(
            0x11,
            &bin_inline("f.txt", b"e1cur"),
            &[bin_inline("f.txt", b"e1old")]
        ),
        e(
            0x12,
            &bin_inline("f.txt", b"e2cur"),
            &[bin_inline("f.txt", b"e2old")]
        ),
        idt(2),
        e(
            0x13,
            &format!(
                "{}{}",
                bin_inline("f.txt", b"e3cur"),
                bin_inline("zz.txt", b"y")
            ),
            &[bin_inline("f.txt", b"e3old"), bin_inline("f.txt", b"e3cur")]
        )
    );
    let (xml, pool) = write_pool(&read_doc(&g(&root)), 0);
    let want: Vec<&[u8]> = vec![
        b"e1cur", b"e2cur", b"e1old", b"e2old", b"e3cur", b"y", b"e3old",
    ];
    assert_eq!(pool, want);
    let e3 = xml.split("<Entry>").filter(|s| s.contains("e3")).count();
    assert!(e3 == 0, "content is never in the document");
    let h2 = xml
        .split("<History>")
        .nth(3)
        .unwrap()
        .split("\t\t\t\t\t\t<Entry>")
        .nth(2)
        .unwrap();
    assert_eq!(ref_of(h2, "f.txt"), "4");
}

#[test]
fn t13_19_pool_rebuilt() {
    let alpha = entry(
        0x10,
        &format!(
            "{}{}{}{}<History>{}</History>",
            s("Title", "Alpha"),
            bin_ref("b.txt", "1"),
            bin_ref("a.txt", "4"),
            bin_ref("empty.bin", "2"),
            entry(0x10, &bin_ref("a.txt", "0"))
        ),
    );
    let beta = entry(
        0x20,
        &format!(
            "{}{}{}",
            s("Title", "Beta"),
            bin_ref("x.txt", "0"),
            bin_ref("new.txt", "4")
        ),
    );
    let xml = g(&format!(
        "{alpha}<Group><UUID>{}</UUID>{beta}</Group>",
        idt(2)
    ));
    let file = demo_file(
        &xml,
        &[
            (1, b"hello attachment\n"),
            (1, b"hello attachment\n"),
            (1, b""),
            (1, b"unused item"),
            (0, b"second file"),
        ],
    );
    let saved = resave(&file);
    assert_eq!(
        saved_pool(&saved, "demo-pass"),
        [
            (1, b"second file".to_vec()),
            (1, b"hello attachment\n".to_vec()),
            (1, Vec::new())
        ]
    );
    let d = saved_doc(&saved, "demo-pass");
    let alpha_xml = d.split("<Value>Alpha</Value>").nth(1).unwrap();
    let (live, hist) = alpha_xml.split_once("<History>").unwrap();
    assert_eq!(
        (
            ref_of(live, "a.txt"),
            ref_of(live, "b.txt"),
            ref_of(live, "empty.bin")
        ),
        ("0".into(), "1".into(), "2".into())
    );
    assert_eq!(ref_of(hist, "a.txt"), "1");
    let beta_xml = d.split("<Value>Beta</Value>").nth(1).unwrap();
    assert_eq!(
        (ref_of(beta_xml, "new.txt"), ref_of(beta_xml, "x.txt")),
        ("0".into(), "1".into())
    );
    assert!(!d.contains("unused"));
}

#[test]
fn t13_20_no_attachments() {
    let saved = resave(&demo_file(&g(&entry(0x10, "")), &[]));
    assert_eq!(saved_inner_ids(&saved, "demo-pass"), [1, 2, 0]);
}

#[test]
fn t13_22_version_3_pool_moves() {
    let file = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/rich-v3.appvault"
    ))
    .unwrap();
    let mut v = open_pw(&file, "demo-pass-4").vault;
    let before: Vec<(String, Vec<u8>)> = v
        .root
        .all_entries()
        .flat_map(|e| e.attachments.iter())
        .map(|a| (a.name.clone(), a.data.expose().to_vec()))
        .collect();
    assert!(!before.is_empty());
    cheap(&mut v);
    let saved = save_pw(&v, "demo-pass");
    assert_eq!(saved.version.major, 4);
    let d = saved_doc(&saved.bytes, "demo-pass");
    assert!(!d.contains("<Binaries"));
    assert!(d.contains("Ref=\"0\""));
    assert!(!saved_pool(&saved.bytes, "demo-pass").is_empty());
    let back = open_pw(&saved.bytes, "demo-pass").vault;
    let after: Vec<(String, Vec<u8>)> = back
        .root
        .all_entries()
        .flat_map(|e| e.attachments.iter())
        .map(|a| (a.name.clone(), a.data.expose().to_vec()))
        .collect();
    assert_eq!(before, after);
}

#[test]
fn t13_30_id_less_item_not_written() {
    let input = doc(
        "<Binaries><Binary Compressed=\"False\">QUJD</Binary></Binaries>",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, &bin_ref("f.txt", ""))
        ),
    );
    let v = read_doc(&input);
    assert!(v.root.entries[0].attachments[0].data.expose().is_empty());
    let (_, pool) = write_pool(&v, 0);
    assert_eq!(pool, [Vec::<u8>::new()], "only the 0-byte f.txt; never ABC");
}

#[test]
fn t13_38_dropped_history_block_item_not_written() {
    let hist = |r: &str| format!("<History>{}</History>", entry(0x10, &bin_ref("h.txt", r)));
    let xml = g(&entry(
        0x10,
        &format!("{}{}{}", bin_ref("a.txt", "1"), hist("0"), hist("1")),
    ));
    let saved = resave(&demo_file(&xml, &[(1, b"AAA"), (1, b"BBB")]));
    assert_eq!(saved_pool(&saved, "demo-pass"), [(1, b"BBB".to_vec())]);
    let d = saved_doc(&saved, "demo-pass");
    assert_eq!(d.matches("Ref=\"0\"").count(), 2);
}

// -- FMT-14 -----------------------------------------------------------------

const PNG_HEX: &str = "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b4944415478da636000020000050001e9fadcd80000000049454e44ae426082";
const PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNgAAIAAAUAAen63NgAAAAASUVORK5CYII=";

fn png() -> Vec<u8> {
    (0..PNG_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&PNG_HEX[i..i + 2], 16).unwrap())
        .collect()
}

fn icon_vault() -> Vault {
    let mut v = read_doc(&g(""));
    v.meta.custom_icons.push(CustomIcon {
        uuid: id(0xA1),
        name: "demo icon".into(),
        last_modified: Some(at(2020, 1, 2, 3, 4, 5)),
        data: png(),
        unknown: Vec::new(),
    });
    v
}

fn icon_lines(xml: &str) -> String {
    between(xml, "<Icon>", "</Icon>")
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn row_14_01_icon_at_4_1() {
    let xml = write_minor(&icon_vault(), 1, &zero_key());
    assert_eq!(
        icon_lines(&xml),
        format!(
            "<UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Name>demo icon</Name><LastModificationTime>pVSf1Q4AAAA=</LastModificationTime><Data>{PNG_B64}</Data>"
        )
    );
}

#[test]
fn row_14_02_icon_below_4_1() {
    let v = icon_vault();
    assert_eq!(write::minor_version(&v), 1);
    let xml = write_minor(&v, 0, &zero_key());
    assert_eq!(
        icon_lines(&xml),
        format!("<UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>{PNG_B64}</Data>")
    );
}

#[test]
fn row_14_03_no_icons() {
    assert!(write_minor(&read_doc(&g("")), 0, &zero_key()).contains("\n\t\t<CustomIcons/>\n"));
}

#[test]
fn row_14_04_empty_data() {
    let xml = rw(&doc(
        "<CustomIcons><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data/></Icon></CustomIcons>",
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ));
    assert_eq!(
        icon_lines(&xml),
        "<UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data/>"
    );
}

#[test]
fn row_14_06_duplicate_icon_id() {
    let a1 = "oaGhoaGhoaGhoaGhoaGhoQ==";
    let input = doc(
        &format!(
            "<CustomIcons><Icon><UUID>{a1}</UUID><Data>QUFB</Data></Icon><Icon><UUID>{a1}</UUID><Data>QkJC</Data></Icon></CustomIcons>"
        ),
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, &format!("<CustomIconUUID>{a1}</CustomIconUUID>"))
        ),
    );
    let back = read_doc(&rw(&input));
    let icons = &back.meta.custom_icons;
    assert_eq!(icons.len(), 2);
    assert_eq!(
        (icons[0].uuid, icons[0].data.as_slice()),
        (id(0xA1), &b"AAA"[..])
    );
    assert!(icons[1].uuid != id(0xA1) && !icons[1].uuid.is_zero() && icons[1].data == b"BBB");
    assert_eq!(back.root.entries[0].icon, app_model::Icon::Custom(id(0xA1)));
}

#[test]
fn row_14_07_icon_order() {
    let ic = |n: u8| format!("<Icon><UUID>{}</UUID><Data>AA==</Data></Icon>", idt(n));
    let xml = rw(&doc(
        &format!("<CustomIcons>{}{}</CustomIcons>", ic(0xA2), ic(0xA1)),
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ));
    let a2 = xml.find(&idt(0xA2)).unwrap();
    assert!(a2 < xml.find(&idt(0xA1)).unwrap());
}

#[test]
fn row_14_08_dangling_and_unused() {
    let input = doc(
        &format!(
            "<CustomIcons><Icon><UUID>{}</UUID><Data>AA==</Data></Icon></CustomIcons>",
            idt(0xA2)
        ),
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(
                0x10,
                &format!("<CustomIconUUID>{}</CustomIconUUID>", idt(0xEE))
            )
        ),
    );
    let xml = rw(&input);
    assert!(xml.contains(&format!("<UUID>{}</UUID>", idt(0xA2))));
    assert!(xml.contains(&format!("<CustomIconUUID>{}</CustomIconUUID>", idt(0xEE))));
}

#[test]
fn row_14_09_remove_icon() {
    // Removing is MOD-06 (E4); the writer writes the record it leaves.
    let mut v = icon_vault();
    let removed = v.meta.custom_icons.remove(0);
    v.deleted_objects.push(DeletedObject {
        uuid: removed.uuid,
        deleted_at: Time(63_928_432_800),
        unknown: Vec::new(),
    });
    let xml = write_minor(&v, 0, &zero_key());
    assert_eq!(
        between(&xml, "<DeletedObjects>", "</DeletedObjects>")
            .iter()
            .map(|l| l.trim())
            .collect::<String>(),
        "<DeletedObject><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><DeletionTime>oHhu4g4AAAA=</DeletionTime></DeletedObject>"
    );
}

#[test]
fn row_14_10_group_item_at_4_0() {
    let xml = write_minor(
        &read_doc(&g(&format!(
            "<CustomData><Item><Key>GroupKey</Key><Value>g1</Value></Item></CustomData>{}",
            entry(0x10, "")
        ))),
        0,
        &zero_key(),
    );
    let rg: Vec<&str> = between(&xml, "\t\t<Group>", "\t\t</Group>")
        .iter()
        .map(|l| l.trim())
        .collect();
    let at = rg
        .iter()
        .position(|l| l.starts_with("<LastTopVisibleEntry>"))
        .unwrap();
    assert_eq!(
        rg[at + 1..at + 7].join(""),
        "<CustomData><Item><Key>GroupKey</Key><Value>g1</Value></Item></CustomData>"
    );
    assert_eq!(rg[at + 7], "<Entry>");
}

#[test]
fn row_14_11_vault_data_at_4_0() {
    let mut v = read_doc(&g(""));
    v.meta.custom_data.items.push(CustomDataItem {
        key: "DemoMetaKey".into(),
        value: "m1".into(),
        last_modified: Some(at(2021, 1, 1, 0, 0, 0)),
        unknown: Vec::new(),
    });
    assert_eq!(write::minor_version(&v), 0);
    let xml = write_doc(&v);
    let cd: String = between(&xml, "<CustomData>", "</CustomData>")
        .iter()
        .map(|l| l.trim())
        .collect();
    assert!(cd.starts_with("<Item><Key>DemoMetaKey</Key><Value>m1</Value></Item>"));
    assert!(!cd.contains("LastModificationTime"));
}

#[test]
fn row_14_13_no_empty_block() {
    let xml = write_minor(&read_doc(&g("")), 1, &zero_key());
    assert!(
        !between(&xml, "\t\t<Group>", "\t\t</Group>")
            .join("")
            .contains("CustomData")
    );
}

#[test]
fn row_14_14_item_times() {
    let mut v = read_doc(&g(&entry(0x10, "")));
    let item = |k: &str, t: Time| CustomDataItem {
        key: k.into(),
        value: "x".into(),
        last_modified: Some(t),
        unknown: Vec::new(),
    };
    v.meta
        .custom_data
        .items
        .push(item("DemoMetaKey", at(2021, 1, 1, 0, 0, 0)));
    v.root.entries[0]
        .custom_data
        .items
        .push(item("EntryKeyB", at(2022, 2, 2, 2, 2, 2)));
    let at41 = write_minor(&v, 1, &zero_key());
    assert!(at41.contains("<Key>DemoMetaKey</Key>\n\t\t\t\t<Value>x</Value>\n\t\t\t\t<LastModificationTime>AF2A1w4AAAA=</LastModificationTime>"));
    let entry_cd = at41.split("<Entry>").nth(1).unwrap();
    assert!(entry_cd.contains(&format!(
        "<LastModificationTime>{}</LastModificationTime>",
        time_to_binary(at(2022, 2, 2, 2, 2, 2))
    )));
    let at40 = write_minor(&v, 0, &zero_key());
    assert!(
        !between(&at40, "\t\t<CustomData>", "\t\t</CustomData>")
            .join("")
            .contains("LastModificationTime")
    );
    assert!(!at40.split("<Entry>").nth(1).unwrap().contains("<Item>\n\t\t\t\t\t\t<Key>EntryKeyB</Key>\n\t\t\t\t\t\t<Value>x</Value>\n\t\t\t\t\t\t<LastModificationTime>"));
}

#[test]
fn row_14_15_item_without_time() {
    let mut v = read_doc(&doc(
        "<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>",
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ));
    let xml = write_minor(&v, 1, &zero_key());
    assert!(xml.contains("<Key>k</Key>\n\t\t\t\t<Value>v</Value>\n\t\t\t</Item>"));
    // The change itself is E4 (FMT-14.14 sets the time); the writer writes it.
    let item = &mut v.meta.custom_data.items[0];
    item.value = "w".into();
    item.last_modified = Some(SAVE);
    let xml = write_minor(&v, 1, &zero_key());
    assert!(xml.contains(&format!(
        "<Value>w</Value>\n\t\t\t\t<LastModificationTime>{}</LastModificationTime>",
        time_to_binary(SAVE)
    )));
}

#[test]
fn row_14_16_order_kept() {
    let cd = "<CustomData><Item><Key>EntryKeyB</Key><Value>b</Value></Item><Item><Key>EntryKeyA</Key><Value>a</Value></Item></CustomData>";
    let xml = rw(&g(&entry(0x10, cd)));
    assert!(xml.find("EntryKeyB").unwrap() < xml.find("EntryKeyA").unwrap());
}

#[test]
fn row_14_18_duplicate_key() {
    let cd = "<CustomData><Item><Key>k</Key><Value>first</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item><Item><Key>k</Key><Value>second</Value></Item><Item><Key>j</Key><Value>same</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item><Item><Key>j</Key><Value>same</Value><LastModificationTime>GxaW1g4AAAA=</LastModificationTime></Item></CustomData>";
    let v = read_doc(&doc(cd, &format!("<Group><UUID>{}</UUID></Group>", idt(1))));
    let xml = write_minor(&v, 1, &zero_key());
    assert_eq!(xml.matches("<Key>k</Key>").count(), 1);
    assert!(xml.contains("<Key>k</Key>\n\t\t\t\t<Value>second</Value>\n\t\t\t</Item>"));
    assert!(xml.contains("<Key>j</Key>\n\t\t\t\t<Value>same</Value>\n\t\t\t\t<LastModificationTime>AF2A1w4AAAA=</LastModificationTime>"));
}

#[test]
fn row_14_20_plain_text() {
    let mut v = read_doc(&g(&format!(
        "{}{}",
        entry(
            0x10,
            "<CustomData><Item><Key>k</Key><Value>secret-looking</Value></Item></CustomData>"
        ),
        entry(0x11, &s("Password", "pw"))
    )));
    v.root.entries[0].custom_data.items[0].value = "secret-looking".into();
    let xml = write_doc(&v);
    assert!(xml.contains("<Value>secret-looking</Value>"));
    assert_eq!(
        xml.matches("Protected").count(),
        2,
        "only the two passwords"
    );
    let second = xml.split("<Entry>").nth(2).unwrap();
    assert!(
        second.contains(&enc(&zero_key(), 0, b"pw")),
        "the stream did not move"
    );
}

#[test]
fn row_14_22_last_modified_only() {
    let xml = write_minor(
        &read_doc(&g(
            "<CustomData><Item><Key>_LAST_MODIFIED</Key><Value>Mon Jan 1 00:00:00 2018 GMT</Value></Item></CustomData>",
        )),
        0,
        &zero_key(),
    );
    let rg = between(&xml, "\t\t<Group>", "\t\t</Group>").join("\n");
    assert!(
        rg.contains("<Key>_LAST_MODIFIED</Key>")
            && rg.contains("<Value>Mon Jan 1 00:00:00 2018 GMT</Value>")
    );
}

#[test]
fn row_14_23_last_modified_kept() {
    let xml = rw(&g(
        "<CustomData><Item><Key>a</Key><Value>1</Value></Item><Item><Key>_LAST_MODIFIED</Key><Value>Mon Jan 1 00:00:00 2018 GMT</Value></Item></CustomData>",
    ));
    assert!(
        between(&xml, "\t\t<Group>", "\t\t</Group>")
            .join("\n")
            .contains("<Value>Mon Jan 1 00:00:00 2018 GMT</Value>")
    );
}

#[test]
fn row_14_24_legacy_flag() {
    let kb = |v: &str| {
        format!("<CustomData><Item><Key>KnownBad</Key><Value>{v}</Value></Item></CustomData>")
    };
    let xml = write_minor(
        &read_doc(&g(&format!(
            "{}{}{}",
            entry(0x0A, &kb("true")),
            entry(0x0B, &kb("True")),
            entry(
                0x0C,
                &format!("<QualityCheck>False</QualityCheck>{}", kb("false"))
            )
        ))),
        1,
        &zero_key(),
    );
    let entries: Vec<&str> = xml.split("\n\t\t\t<Entry>\n").skip(1).collect();
    assert!(entries[0].contains("<QualityCheck>False</QualityCheck>"));
    assert!(!entries[1].contains("QualityCheck") && !entries[2].contains("QualityCheck"));
    assert!(
        !xml.contains("KnownBad") && !xml.split("<Root>").nth(1).unwrap().contains("<CustomData>")
    );
}

#[test]
fn row_14_24b_legacy_flag_and_last_modified() {
    let e = entry(
        0x0E,
        "<CustomData><Item><Key>X</Key><Value>1</Value></Item><Item><Key>KnownBad</Key><Value>true</Value></Item></CustomData>",
    );
    let f = entry(
        0x0F,
        "<CustomData><Item><Key>_LAST_MODIFIED</Key><Value>Mon Jan 1 00:00:00 2018 GMT</Value></Item><Item><Key>KnownBad</Key><Value>true</Value></Item></CustomData>",
    );
    let xml = write_minor(&read_doc(&g(&format!("{e}{f}"))), 1, &zero_key());
    let entries: Vec<&str> = xml.split("\n\t\t\t<Entry>\n").skip(1).collect();
    assert!(entries[0].contains("<QualityCheck>False</QualityCheck>"));
    let cd: String = entries[0]
        .split("<CustomData>")
        .nth(1)
        .unwrap()
        .split("</CustomData>")
        .next()
        .unwrap()
        .replace(['\t', '\n'], "");
    assert_eq!(cd, "<Item><Key>X</Key><Value>1</Value></Item>");
    assert!(
        entries[1].contains("<QualityCheck>False</QualityCheck>")
            && !entries[1].contains("<CustomData>")
    );
}

#[test]
fn row_14_25_reference_keys_round_trip() {
    let key = String::from_utf8(vec![
        0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73,
        0x65, 0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
    ])
    .unwrap();
    let value = "{&quot;Allow&quot;:[&quot;example.com&quot;],&quot;Deny&quot;:[],&quot;Realm&quot;:&quot;&quot;}";
    let input = g(&format!(
        "<CustomData><Item><Key>BrowserHideEntry</Key><Value>true</Value></Item><Item><Key>BrowserRestrictKey</Key><Value/></Item></CustomData>{}",
        entry(
            0x10,
            &format!(
                "<CustomData><Item><Key>{key}</Key><Value>{value}</Value></Item></CustomData>"
            )
        )
    ));
    let xml = write_minor(&read_doc(&input), 0, &zero_key());
    assert!(
        xml.contains(&format!("<Key>{key}</Key>"))
            && xml.contains(&format!("<Value>{value}</Value>"))
    );
    assert!(xml.contains("<Key>BrowserHideEntry</Key>\n\t\t\t\t\t<Value>true</Value>"));
    assert!(xml.contains("<Key>BrowserRestrictKey</Key>\n\t\t\t\t\t<Value/>"));
}

#[test]
fn row_14_26_padding_item_form() {
    let padding = String::from_utf8(PADDING_KEY.to_vec()).unwrap();
    let first = cheap_vault(&g("<Tags>t</Tags>"));
    let mut second = cheap_vault(&g("<Tags>t</Tags>"));
    second.meta.custom_data.items.push(CustomDataItem {
        key: padding.clone(),
        value: "00".into(),
        last_modified: None,
        unknown: Vec::new(),
    });
    for v in [&first, &second] {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let file = save_pw(v, "demo-pass");
            assert_eq!(file.version.minor, 1);
            let back = open_pw(&file.bytes, "demo-pass").vault;
            let items: Vec<&CustomDataItem> = back
                .meta
                .custom_data
                .items
                .iter()
                .filter(|i| i.key == padding)
                .collect();
            assert_eq!(items.len(), 1);
            let hex = &items[0].value;
            assert!((128..=1022).contains(&hex.len()) && hex.len().is_multiple_of(2));
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let t = items[0].last_modified.expect("a time at 4.1");
            assert_eq!(
                back.meta.custom_data.get("_LAST_MODIFIED"),
                Some(last_modified_text(t).as_str())
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            assert!((Time::from_unix(now).unwrap().0 - t.0).abs() < 60);
            seen.push(hex.clone());
        }
        assert_ne!(seen[0], seen[1]);
        assert!(seen.iter().all(|h| h != "00"));
    }
}

#[test]
fn row_14_27_reserved_strings() {
    let v = read_doc(&g(&entry(
        0x10,
        &format!(
            "<String><Key>otp</Key><Value Protected=\"True\">{}</Value></String>{}{}",
            enc(
                &zero_key(),
                0,
                b"otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP"
            ),
            s("KP2A_URL_1", "https://b.example"),
            s("_EXEC_CMD", "1")
        ),
    )));
    let xml = write_doc(&v);
    assert!(xml.contains("<Key>otp</Key>\n\t\t\t\t\t<Value Protected=\"True\">"));
    assert!(xml.contains("<Key>KP2A_URL_1</Key>\n\t\t\t\t\t<Value>https://b.example</Value>"));
    assert!(xml.contains("<Key>_EXEC_CMD</Key>\n\t\t\t\t\t<Value>1</Value>"));
    assert_eq!(
        read_doc(&xml).root.entries[0].value("otp"),
        "otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP"
    );
}

#[test]
fn row_14_27b_other_apps_one_time_password_fields() {
    let xml = rw(&g(&entry(
        0x10,
        &format!(
            "{}{}",
            s("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP"),
            s("TimeOtp-Period", "60")
        ),
    )));
    assert!(
        xml.contains("<Key>TimeOtp-Secret-Base32</Key>\n\t\t\t\t\t<Value>JBSWY3DPEHPK3PXP</Value>")
    );
    assert!(xml.contains("<Key>TimeOtp-Period</Key>\n\t\t\t\t\t<Value>60</Value>"));
    assert!(!xml.contains("<Key>otp</Key>"));
}

#[test]
fn row_14_28_unknown_key() {
    let xml = write_minor(
        &read_doc(&doc(
            "<CustomData><Item><Key>Some.Plugin/Setting</Key><Value>x</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item></CustomData>",
            &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
        )),
        1,
        &zero_key(),
    );
    assert!(xml.contains("<Key>Some.Plugin/Setting</Key>\n\t\t\t\t<Value>x</Value>\n\t\t\t\t<LastModificationTime>AF2A1w4AAAA=</LastModificationTime>"));
}

#[test]
fn row_14_30_adding_an_icon() {
    // Image work and the add itself are MOD-06 (E4); the writer side: a
    // named, timed icon needs 4.1; a downloaded icon has no Name element;
    // an icon with neither leaves 4.0.
    let mut v = read_doc(&g(""));
    let icon = |n: u8, name: &str, t: Option<Time>| CustomIcon {
        uuid: id(n),
        name: name.into(),
        last_modified: t,
        data: vec![1, 2, 3],
        unknown: Vec::new(),
    };
    v.meta
        .custom_icons
        .push(icon(0xA1, "photo", Some(at(2026, 10, 24, 10, 0, 0))));
    v.meta
        .custom_icons
        .push(icon(0xA2, "", Some(at(2026, 10, 24, 10, 5, 0))));
    assert_eq!(write::minor_version(&v), 1);
    let xml = write_doc(&v);
    let second = xml
        .split("<Icon>")
        .nth(2)
        .unwrap()
        .split("</Icon>")
        .next()
        .unwrap();
    assert!(!second.contains("<Name") && second.contains("<LastModificationTime>"));
    let mut plain = read_doc(&g(""));
    plain.meta.custom_icons.push(icon(0xA3, "", None));
    assert_eq!(write::minor_version(&plain), 0);
}

#[test]
fn row_14_31_protected_custom_data_on_read() {
    let input = g(&entry(
        0x10,
        "<CustomData><Item><Key>k</Key><Value Protected=\"True\">RxjmIZKk</Value></Item></CustomData><String><Key>Password</Key><Value Protected=\"True\">AQk=</Value></String>",
    ));
    let v = read_doc(&input);
    assert_eq!(v.root.entries[0].value("Password"), "pw");
    let xml = write_doc(&v);
    assert!(xml.contains("<Key>k</Key>\n\t\t\t\t\t\t<Value>Secret</Value>"));
    let pw = xml.split("<Key>Password</Key>").nth(1).unwrap();
    assert!(
        pw.contains(&enc(&zero_key(), 0, b"pw")),
        "the custom data took no keystream"
    );
}

#[test]
fn row_14_32_version_4_1_children_read_in_a_3_1_file() {
    let input = doc(
        "<CustomIcons><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Name>n</Name><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime><Data>QUFB</Data></Icon></CustomIcons>",
        &format!(
            "<Group><UUID>{}</UUID><CustomData><Item><Key>g</Key><Value>1</Value><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime></Item></CustomData></Group>",
            idt(1)
        ),
    );
    let xml = write_minor(&read_doc(&input), 1, &zero_key());
    assert_eq!(
        icon_lines(&xml),
        "<UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Name>n</Name><LastModificationTime>GxaW1g4AAAA=</LastModificationTime><Data>QUFB</Data>"
    );
    assert!(xml.contains("<Key>g</Key>\n\t\t\t\t\t<Value>1</Value>\n\t\t\t\t\t<LastModificationTime>GxaW1g4AAAA=</LastModificationTime>"));
}

#[test]
fn row_14_33_several_icon_and_custom_data_blocks() {
    let icons1 = "<CustomIcons><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>QUFB</Data></Icon></CustomIcons>";
    let icons2 = "<CustomIcons><Icon><UUID>oqKioqKioqKioqKioqKiog==</UUID><Data>QkJC</Data></Icon><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>Q0ND</Data></Icon></CustomIcons>";
    let cd1 = "<CustomData><Item><Key>a</Key><Value>1</Value></Item></CustomData>";
    let cd2 = "<CustomData><Item><Key>b</Key><Value>2</Value></Item></CustomData>";
    let group = format!("<Group><UUID>{}</UUID></Group>", idt(1));
    let r = root_name();
    let a = format!(
        "<{r}><Meta>{icons1}{cd1}</Meta><Meta>{icons2}{cd2}</Meta><Root>{group}</Root></{r}>"
    );
    let b = doc(&format!("{icons1}{icons2}{cd1}{cd2}"), &group);
    let (va, vb) = (read_doc(&a), read_doc(&b));
    let data: Vec<&[u8]> = va
        .meta
        .custom_icons
        .iter()
        .map(|i| i.data.as_slice())
        .collect();
    assert_eq!(data, [&b"AAA"[..], b"BBB", b"CCC"]);
    let xml = write_doc(&va);
    assert_eq!(xml.matches("<CustomIcons>").count(), 1);
    assert_eq!(xml.matches("<CustomData>").count(), 1);
    assert!(xml.contains("<Key>a</Key>") && xml.contains("<Key>b</Key>"));
    assert_eq!(va.meta.custom_data, vb.meta.custom_data);
}

#[test]
fn row_14_34_passkey_field_protection() {
    // INT-04 sets the protected flags; the writer honours them.
    let mut v = read_doc(&g(&entry(0x10, "")));
    let e = &mut v.root.entries[0];
    for (k, val, p) in [
        ("KPEX_PASSKEY_CREDENTIAL_ID", "cid", true),
        ("KPEX_PASSKEY_PRIVATE_KEY_PEM", "pem", true),
        ("KPEX_PASSKEY_USER_HANDLE", "uh", true),
        ("KPEX_PASSKEY_USERNAME", "demo-user", false),
        ("KPEX_PASSKEY_RELYING_PARTY", "example.com", false),
    ] {
        e.set_field(
            k.into(),
            Field {
                value: SecretString::new(val.into()),
                protected: p,
            },
        );
    }
    let xml = write_doc(&v);
    for k in ["CREDENTIAL_ID", "PRIVATE_KEY_PEM", "USER_HANDLE"] {
        assert!(
            xml.contains(&format!(
                "<Key>KPEX_PASSKEY_{k}</Key>\n\t\t\t\t\t<Value Protected=\"True\">"
            )),
            "{k}"
        );
    }
    assert!(xml.contains("<Key>KPEX_PASSKEY_USERNAME</Key>\n\t\t\t\t\t<Value>demo-user</Value>"));
    assert!(
        xml.contains("<Key>KPEX_PASSKEY_RELYING_PARTY</Key>\n\t\t\t\t\t<Value>example.com</Value>")
    );
}

#[test]
fn row_14_39_last_modified_with_a_single_digit_day() {
    let text = last_modified_text(at(2026, 10, 4, 19, 17, 16));
    assert_eq!(
        text.as_bytes(),
        [
            0x53, 0x75, 0x6E, 0x20, 0x4F, 0x63, 0x74, 0x20, 0x34, 0x20, 0x31, 0x39, 0x3A, 0x31,
            0x37, 0x3A, 0x31, 0x36, 0x20, 0x32, 0x30, 0x32, 0x36, 0x20, 0x47, 0x4D, 0x54
        ]
    );
    assert_eq!(
        last_modified_text(at(2026, 10, 24, 19, 17, 16)),
        "Sat Oct 24 19:17:16 2026 GMT"
    );
    assert_eq!(
        last_modified_text(at(2026, 3, 1, 0, 0, 0)),
        "Sun Mar 1 00:00:00 2026 GMT"
    );
    let xml = rw(&g(
        "<CustomData><Item><Key>a</Key><Value>1</Value></Item><Item><Key>_LAST_MODIFIED</Key><Value>So. Okt. 4 19:17:16 2026 GMT</Value></Item></CustomData>",
    ));
    assert!(xml.contains("<Value>So. Okt. 4 19:17:16 2026 GMT</Value>"));
}

// -- FMT-15 -----------------------------------------------------------------

fn deleted_vault(items: &[(u8, Time)]) -> Vault {
    let mut v = read_doc(&g(""));
    for (n, t) in items {
        v.deleted_objects.push(DeletedObject {
            uuid: id(*n),
            deleted_at: *t,
            unknown: Vec::new(),
        });
    }
    v
}

fn deleted_lines(xml: &str) -> String {
    between(xml, "<DeletedObjects>", "</DeletedObjects>")
        .iter()
        .map(|l| l.trim())
        .collect()
}

const D77: &str = "<DeletedObject><UUID>d3d3d3d3d3d3d3d3d3d3dw==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject>";
const D78: &str = "<DeletedObject><UUID>eHh4eHh4eHh4eHh4eHh4eA==</UUID><DeletionTime>m2eX1g4AAAA=</DeletionTime></DeletedObject>";

#[test]
fn row_15_01_write_at_4_0() {
    let v = deleted_vault(&[
        (0x77, at(2020, 7, 7, 7, 7, 7)),
        (0x78, at(2020, 7, 8, 7, 7, 7)),
    ]);
    let xml = write_minor(&v, 0, &zero_key());
    assert_eq!(deleted_lines(&xml), format!("{D77}{D78}"));
    assert!(xml.contains("\t\t</Group>\n\t\t<DeletedObjects>\n"));
}

#[test]
fn row_15_02_text_times_read() {
    let list = "<DeletedObjects><DeletedObject><UUID>d3d3d3d3d3d3d3d3d3d3dw==</UUID><DeletionTime>2020-07-07T07:07:07Z</DeletionTime></DeletedObject><DeletedObject><UUID>eHh4eHh4eHh4eHh4eHh4eA==</UUID><DeletionTime>2020-07-08T07:07:07Z</DeletionTime></DeletedObject></DeletedObjects>";
    let xml = rw(&doc(
        "",
        &format!("<Group><UUID>{}</UUID></Group>{list}", idt(1)),
    ));
    assert_eq!(deleted_lines(&xml), format!("{D77}{D78}"));
}

#[test]
fn row_15_03_empty_list() {
    assert!(write_doc(&deleted_vault(&[])).contains("\t\t</Group>\n\t\t<DeletedObjects/>\n"));
}

#[test]
fn row_15_04_broken_sample() {
    let list = "<DeletedObjects><DeletedObject><UUID/><DeletionTime>2010-08-25T16:14:12Z</DeletionTime></DeletedObject><DeletedObject/><DeletedObject><UUID>5K/bzWCSmkCv5OZxYl4N/w==</UUID><DeletionTime/></DeletedObject></DeletedObjects>";
    let xml = write_minor(
        &read_doc(&doc(
            "",
            &format!("<Group><UUID>{}</UUID></Group>{list}", idt(1)),
        )),
        0,
        &zero_key(),
    );
    assert_eq!(
        deleted_lines(&xml),
        "<DeletedObject><UUID>5K/bzWCSmkCv5OZxYl4N/w==</UUID><DeletionTime>AAAAAAAAAAA=</DeletionTime></DeletedObject>"
    );
}

#[test]
fn row_15_06_no_clean_up() {
    let t20 = at(2020, 1, 1, 0, 0, 0);
    let mut v = deleted_vault(&[
        (0x10, t20),
        (0x30, t20),
        (0x30, at(2021, 1, 1, 0, 0, 0)),
        (0x40, at(2099, 1, 1, 0, 0, 0)),
    ]);
    v.root.entries = read_doc(&g(&entry(0x10, ""))).root.entries;
    let back = read_doc(&write_doc(&v));
    assert_eq!(back.deleted_objects, v.deleted_objects);
    assert_eq!(back.root.entries[0].uuid, id(0x10));
}

#[test]
fn row_15_07_two_blocks() {
    let d = |n: u8| {
        format!(
            "<DeletedObjects><DeletedObject><UUID>{}</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject></DeletedObjects>",
            idt(n)
        )
    };
    let xml = rw(&doc(
        "",
        &format!(
            "{}<Group><UUID>{}</UUID></Group>{}",
            d(0x77),
            idt(1),
            d(0x78)
        ),
    ));
    assert_eq!(xml.matches("<DeletedObjects>").count(), 1);
    assert!(xml.find(&idt(0x77)).unwrap() < xml.find(&idt(0x78)).unwrap());
}

#[test]
fn row_15_13_no_pruning() {
    let mut v = deleted_vault(&[
        (0x31, at(2001, 1, 1, 0, 0, 0)),
        (0x32, at(2010, 1, 1, 0, 0, 0)),
        (0x33, at(2020, 1, 1, 0, 0, 0)),
    ]);
    cheap(&mut v);
    let want = v.deleted_objects.clone();
    let mut file = save_pw(&v, "demo-pass").bytes;
    for _ in 0..100 {
        let back = open_pw(&file, "demo-pass");
        assert_eq!(back.vault.deleted_objects, want);
        file = save_pw(&back.vault, "demo-pass").bytes;
    }
}

#[test]
fn row_15_19_version() {
    let v = deleted_vault(&[
        (1, Time(1)),
        (2, Time(2)),
        (3, Time(3)),
        (4, Time(4)),
        (5, Time(5)),
    ]);
    assert_eq!(write::minor_version(&v), 0);
    assert_eq!(write::minor_version(&deleted_vault(&[])), 0);
}

#[test]
fn row_15_21_repeated_children() {
    let a = "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><UUID/><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject>";
    let b = "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DeletionTime>m2eX1g4AAAA=</DeletionTime></DeletedObject>";
    let c = "<DeletedObject><UUID>MTExMTExMTExMTExMTExMQ==</UUID><UUID>QUJD</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject>";
    let xml = write_minor(
        &read_doc(&doc(
            "",
            &format!(
                "<Group><UUID>{}</UUID></Group><DeletedObjects>{a}{b}{c}</DeletedObjects>",
                idt(1)
            ),
        )),
        0,
        &zero_key(),
    );
    assert_eq!(
        deleted_lines(&xml),
        "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject><DeletedObject><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>m2eX1g4AAAA=</DeletionTime></DeletedObject><DeletedObject><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject>"
    );
}

const ITEM_D: &str = "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra a=\"1\"/></DeletedObject>";

#[test]
fn row_15_22_unknown_children() {
    let e = "<DeletedObject><DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra2/></DeletedObject>";
    let xml = write_minor(
        &read_doc(&doc(
            "",
            &format!(
                "<Group><UUID>{}</UUID></Group><DeletedObjects>{ITEM_D}{e}</DeletedObjects>",
                idt(1)
            ),
        )),
        0,
        &zero_key(),
    );
    assert_eq!(deleted_lines(&xml), ITEM_D);
}

#[test]
fn row_15_22b_unknown_child_keeps_the_version() {
    use app_model::FileVersion;
    for (file_minor, want) in [(1u16, 1u16), (0, 0), (2, 2)] {
        let mut v = read_doc(&doc(
            "",
            &format!(
                "<Group><UUID>{}</UUID></Group><DeletedObjects>{ITEM_D}</DeletedObjects>",
                idt(1)
            ),
        ));
        v.read_version = Some(FileVersion {
            major: 4,
            minor: file_minor,
        });
        assert_eq!(write::minor_version(&v), want);
        assert_eq!(deleted_lines(&write_doc(&v)), ITEM_D);
    }
}

#[test]
fn row_15_23_time_out_of_range() {
    let f = "<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>/////////38=</DeletionTime></DeletedObject>";
    let g_ = "<DeletedObject><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>2f////////8=</DeletionTime></DeletedObject>";
    let xml = write_minor(
        &read_doc(&doc(
            "",
            &format!(
                "<Group><UUID>{}</UUID></Group><DeletedObjects>{f}{g_}</DeletedObjects>",
                idt(1)
            ),
        )),
        1,
        &zero_key(),
    );
    assert_eq!(deleted_lines(&xml), format!("{f}{g_}"));
}

#[test]
fn t13_21_one_namespace_until_int_08() {
    // App until INT-08: every equal content shares one item, shared groups
    // included (FMT-13.17).
    let share = String::from_utf8(vec![
        0x4B, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x2F, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65,
        0x6E, 0x63, 0x65,
    ])
    .unwrap();
    let same = |n: u8, names: &[&str]| {
        entry(
            n,
            &names
                .iter()
                .map(|k| bin_inline(k, b"same"))
                .collect::<String>(),
        )
    };
    let t = format!(
        "<Group><UUID>{}</UUID>{}</Group>",
        idt(4),
        same(0x14, &["t"])
    );
    let s_group = format!(
        "<Group><UUID>{}</UUID><CustomData><Item><Key>{share}</Key><Value>x</Value></Item></CustomData>{}{t}</Group>",
        idt(3),
        same(0x13, &["s1", "s2"])
    );
    let (xml, pool) = write_pool(
        &read_doc(&g(&format!("{}{s_group}", same(0x10, &["r"])))),
        0,
    );
    assert_eq!(pool, [b"same".to_vec()]);
    assert_eq!(xml.matches("Ref=\"0\"").count(), 4);
}

#[test]
fn t13_16_child_groups_in_order() {
    // Depth first, child groups in stored order (FMT-13.16).
    let child = |n: u8, data: &[u8], grand: &str| {
        format!(
            "<Group><UUID>{}</UUID>{}{grand}</Group>",
            idt(n),
            entry(n, &bin_inline("f", data))
        )
    };
    let g2 = child(2, b"two", &child(4, b"two-sub", ""));
    let root = format!("{g2}{}", child(3, b"three", ""));
    let (_, pool) = write_pool(&read_doc(&g(&root)), 0);
    let want: Vec<&[u8]> = vec![b"two", b"two-sub", b"three"];
    assert_eq!(pool, want);
}
