//! E3-S7 writer rows of FMT-10 (metadata, document frame, kept unknown
//! elements). Each test names its card row.

mod write_common;

use larsal_format::document::write::{self, PADDING_KEY};
use larsal_model::times::Civil;
use larsal_model::{Group, Time, Vault};
use write_common::*;

fn padding_key() -> String {
    String::from_utf8(PADDING_KEY.to_vec()).unwrap()
}

/// 2026-10-24T00:00:00Z.
fn day() -> Time {
    Time::from_civil(Civil {
        year: 2026,
        month: 10,
        day: 24,
        hour: 0,
        minute: 0,
        second: 0,
    })
    .unwrap()
}

#[test]
fn fmt_10_1_declaration() {
    let xml = rw(&g(""));
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"));
    assert_eq!(
        &xml.as_bytes()[..20],
        &[
            0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3D,
            0x22, 0x31, 0x2E, 0x30, 0x22, 0x20
        ]
    );
    assert_eq!(xml.as_bytes()[55], 0x0A);
}

#[test]
fn fmt_10_2_layout_full_meta_vector() {
    let root = Group::new(
        larsal_format::document::encode::parse_uuid("rH4xp1/3SoWQeYTLdwFNVA=="),
        "Root".into(),
        day(),
    );
    let rid = root.uuid;
    let mut v = Vault::new(root, day());
    v.meta.name = "Demo vault".into();
    v.meta.default_user_name = "demo".into();
    v.meta.recycle_bin = Some(rid);
    v.meta.last_selected_group = Some(rid);
    let xml = write_minor(&v, 0, &zero_key());
    let t = "AOxt4g4AAAA=";
    let r = root_name();
    let expected = [
        (
            0,
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>".to_owned(),
        ),
        (0, format!("<{r}>")),
        (1, "<Meta>".into()),
        (2, "<Generator>Larsal</Generator>".into()),
        (2, "<DatabaseName>Demo vault</DatabaseName>".into()),
        (2, format!("<DatabaseNameChanged>{t}</DatabaseNameChanged>")),
        (2, "<DatabaseDescription/>".into()),
        (
            2,
            format!("<DatabaseDescriptionChanged>{t}</DatabaseDescriptionChanged>"),
        ),
        (2, "<DefaultUserName>demo</DefaultUserName>".into()),
        (
            2,
            format!("<DefaultUserNameChanged>{t}</DefaultUserNameChanged>"),
        ),
        (
            2,
            "<MaintenanceHistoryDays>365</MaintenanceHistoryDays>".into(),
        ),
        (2, "<Color/>".into()),
        (2, format!("<MasterKeyChanged>{t}</MasterKeyChanged>")),
        (2, "<MasterKeyChangeRec>-1</MasterKeyChangeRec>".into()),
        (2, "<MasterKeyChangeForce>-1</MasterKeyChangeForce>".into()),
        (2, "<MemoryProtection>".into()),
        (3, "<ProtectTitle>False</ProtectTitle>".into()),
        (3, "<ProtectUserName>False</ProtectUserName>".into()),
        (3, "<ProtectPassword>True</ProtectPassword>".into()),
        (3, "<ProtectURL>False</ProtectURL>".into()),
        (3, "<ProtectNotes>False</ProtectNotes>".into()),
        (2, "</MemoryProtection>".into()),
        (2, "<CustomIcons/>".into()),
        (2, "<RecycleBinEnabled>True</RecycleBinEnabled>".into()),
        (
            2,
            "<RecycleBinUUID>rH4xp1/3SoWQeYTLdwFNVA==</RecycleBinUUID>".into(),
        ),
        (2, format!("<RecycleBinChanged>{t}</RecycleBinChanged>")),
        (
            2,
            "<EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>".into(),
        ),
        (
            2,
            format!("<EntryTemplatesGroupChanged>{t}</EntryTemplatesGroupChanged>"),
        ),
        (
            2,
            "<LastSelectedGroup>rH4xp1/3SoWQeYTLdwFNVA==</LastSelectedGroup>".into(),
        ),
        (
            2,
            "<LastTopVisibleGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleGroup>".into(),
        ),
        (2, "<HistoryMaxItems>10</HistoryMaxItems>".into()),
        (2, "<HistoryMaxSize>6291456</HistoryMaxSize>".into()),
        (2, format!("<SettingsChanged>{t}</SettingsChanged>")),
        (2, "<CustomData>".into()),
        (3, "<Item>".into()),
        (4, format!("<Key>{}</Key>", padding_key())),
        (4, format!("<Value>{}</Value>", "ab".repeat(64))),
        (3, "</Item>".into()),
        (3, "<Item>".into()),
        (4, "<Key>_LAST_MODIFIED</Key>".into()),
        (4, "<Value>Sat Oct 24 19:17:16 2026 GMT</Value>".into()),
        (3, "</Item>".into()),
        (2, "</CustomData>".into()),
        (1, "</Meta>".into()),
    ];
    for (i, (tabs, text)) in expected.iter().enumerate() {
        let want = format!("{}{text}", "\t".repeat(*tabs));
        assert_eq!(xml.lines().nth(i).unwrap(), want, "line {}", i + 1);
    }
    assert!(!xml.contains('\r'));
}

#[test]
fn fmt_10_2_end_of_document() {
    let xml = rw(&g(""));
    assert!(xml.ends_with(&format!("</{}>\n", root_name())));
    assert!(!xml.ends_with("\n\n"));
}

#[test]
fn fmt_10_2_empty_containers() {
    let xml = rw(&g(""));
    assert_eq!(line(&xml, "CustomIcons"), "\t\t<CustomIcons/>");
    assert_eq!(line(&xml, "DeletedObjects"), "\t\t<DeletedObjects/>");
}

#[test]
fn fmt_10_3_attribute_order() {
    let xml = rw(&g(&entry(0x10, &s("Password", "pw"))));
    assert!(line(&xml, "<Value Protected").starts_with("\t\t\t\t\t<Value Protected=\"True\">"));
}

#[test]
fn fmt_10_4_top_order() {
    let xml = rw(&g(&entry(0x10, "")));
    assert_eq!(names_at(&xml, 1), ["Meta", "Root"]);
    let root_children = between(&xml, "\t<Root>", "\t</Root>");
    assert_eq!(
        names_at(&root_children.join("\n"), 2),
        ["Group", "DeletedObjects"]
    );
}

#[test]
fn fmt_10_5_no_meta() {
    let r = root_name();
    let xml = rw(&format!(
        "<{r}><Root><Group><UUID>rH4xp1/3SoWQeYTLdwFNVA==</UUID><Name>R</Name></Group></Root></{r}>"
    ));
    let open = larsal_format::document::encode::time_to_binary(OPEN);
    for name in [
        "DatabaseNameChanged",
        "MasterKeyChanged",
        "RecycleBinChanged",
        "SettingsChanged",
    ] {
        assert_eq!(
            line(&xml, &format!("<{name}>")).trim(),
            format!("<{name}>{open}</{name}>")
        );
    }
    assert_eq!(
        line(&xml, "<HistoryMaxItems>").trim(),
        "<HistoryMaxItems>10</HistoryMaxItems>"
    );
    assert_eq!(
        line(&xml, "<Generator>").trim(),
        "<Generator>Larsal</Generator>"
    );
}

#[test]
fn fmt_10_5_stray_content_in_meta_containers() {
    let st = "junk &amp; text<!-- c --><?pi x?>";
    let meta = format!(
        "{st}<DatabaseName>Ne</DatabaseName>{st}<MemoryProtection>{st}<ProtectTitle>True</ProtectTitle>{st}<ProtectPassword>False</ProtectPassword>{st}</MemoryProtection>{st}<Binaries>{st}<Binary ID=\"0\">QUFB</Binary>{st}<Binary ID=\"1\">QkJC</Binary>{st}</Binaries>{st}<DatabaseDescription>D</DatabaseDescription>{st}"
    );
    let bins = "<Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary><Binary><Key>b.txt</Key><Value Ref=\"1\"/></Binary>";
    let input = doc(
        &meta,
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, bins)
        ),
    );
    let v = read_doc(&input);
    let w = write::write(
        &v,
        write::minor_version(&v),
        &mut chacha(&zero_key()),
        &stamp(),
    )
    .unwrap();
    let xml = String::from_utf8(w.xml().to_vec()).unwrap();
    assert!(!xml.contains("junk") && !xml.contains("<!--") && !xml.contains("<?pi"));
    assert!(!xml.contains("<Binaries"));
    let pool: Vec<&[u8]> = w.pool.iter().map(|p| p.expose()).collect();
    let back = read_with(&xml, &zero_key(), &pool);
    assert_eq!(
        (back.meta.name.as_str(), back.meta.description.as_str()),
        ("Ne", "D")
    );
    assert!(back.meta.memory_protection.title && !back.meta.memory_protection.password);
    let e = &back.root.entries[0];
    let got: Vec<(&str, &[u8])> = e
        .attachments
        .iter()
        .map(|a| (a.name.as_str(), a.data.expose()))
        .collect();
    assert_eq!(got, [("a.txt", &b"AAA"[..]), ("b.txt", &b"BBB"[..])]);
}

#[test]
fn fmt_10_5_unknown_top_child() {
    let r = root_name();
    let xml = rw(&format!(
        "<{r}><Extra>1</Extra><Meta/><Root><Group><UUID>{}</UUID></Group></Root><After/></{r}>",
        idt(1)
    ));
    let tail: Vec<&str> = xml.lines().skip_while(|l| *l != "\t</Root>").collect();
    assert_eq!(
        tail,
        [
            "\t</Root>",
            "\t<Extra>1</Extra>",
            "\t<After/>",
            &format!("</{r}>")
        ]
    );
}

#[test]
fn fmt_10_10_defaults_new_vault() {
    let v = Vault::new(Group::new(id(1), "R".into(), day()), day());
    let xml = write_doc(&v);
    for (name, value) in [
        ("MaintenanceHistoryDays", "365"),
        ("MasterKeyChangeRec", "-1"),
        ("MasterKeyChangeForce", "-1"),
        ("RecycleBinEnabled", "True"),
        ("HistoryMaxItems", "10"),
        ("HistoryMaxSize", "6291456"),
        ("ProtectPassword", "True"),
        ("ProtectTitle", "False"),
        ("ProtectUserName", "False"),
        ("ProtectURL", "False"),
        ("ProtectNotes", "False"),
        ("RecycleBinUUID", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ("EntryTemplatesGroup", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ("LastSelectedGroup", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ("LastTopVisibleGroup", "AAAAAAAAAAAAAAAAAAAAAA=="),
    ] {
        assert_eq!(
            line(&xml, &format!("<{name}>")).trim(),
            format!("<{name}>{value}</{name}>")
        );
    }
    assert!(!xml.contains("HeaderHash") && !xml.contains("Binaries"));
    assert!(xml.contains("<SettingsChanged>"));
}

#[test]
fn fmt_10_10_order() {
    let mut v = read_doc(&g(""));
    v.meta.master_key_change_force_once = true;
    let meta = between(&write_doc(&v), "\t<Meta>", "\t</Meta>").join("\n");
    assert_eq!(
        names_at(&meta, 2),
        [
            "Generator",
            "DatabaseName",
            "DatabaseNameChanged",
            "DatabaseDescription",
            "DatabaseDescriptionChanged",
            "DefaultUserName",
            "DefaultUserNameChanged",
            "MaintenanceHistoryDays",
            "Color",
            "MasterKeyChanged",
            "MasterKeyChangeRec",
            "MasterKeyChangeForce",
            "MasterKeyChangeForceOnce",
            "MemoryProtection",
            "CustomIcons",
            "RecycleBinEnabled",
            "RecycleBinUUID",
            "RecycleBinChanged",
            "EntryTemplatesGroup",
            "EntryTemplatesGroupChanged",
            "LastSelectedGroup",
            "LastTopVisibleGroup",
            "HistoryMaxItems",
            "HistoryMaxSize",
            "SettingsChanged",
            "CustomData",
        ]
    );
}

#[test]
fn fmt_10_10_row_28_write_and_read() {
    let mut v = read_doc(&g(""));
    let before = write::minor_version(&v);
    v.meta.master_key_change_force_once = true;
    assert_eq!(write::minor_version(&v), before, "raises no version");
    let xml = write_doc(&v);
    let lines: Vec<&str> = xml.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains("<MasterKeyChangeForce>"))
        .unwrap();
    assert_eq!(
        lines[at + 1],
        "\t\t<MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce>"
    );
    assert!(read_doc(&xml).meta.master_key_change_force_once);
    v.meta.master_key_change_force_once = false;
    assert!(!write_doc(&v).contains("MasterKeyChangeForceOnce"));
}

#[test]
fn fmt_10_11_row_28_known_no_keystream() {
    let input = doc(
        "<MasterKeyChangeForceOnce Protected=\"True\">QUJD</MasterKeyChangeForceOnce><DatabaseName Protected=\"True\">RxjmIZKk</DatabaseName>",
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    );
    let v = read_doc(&input);
    assert!(!v.meta.master_key_change_force_once);
    assert_eq!(v.meta.name, "Secret");
    assert!(v.meta.unknown.is_empty());
    let xml = write_doc(&v);
    assert!(!xml.contains("MasterKeyChangeForceOnce"));
    assert!(xml.contains("<DatabaseName>Secret</DatabaseName>"));
}

#[test]
fn fmt_10_11_v3_only_elements_in_v4() {
    let xml = rw(&doc(
        "<Binaries/><HeaderHash>AAAA</HeaderHash>",
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ));
    assert!(!xml.contains("Binaries") && !xml.contains("HeaderHash"));
}

fn meta_rw(meta: &str) -> String {
    rw(&doc(
        meta,
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ))
}

#[test]
fn fmt_10_15_below_minus_one() {
    let xml = meta_rw("<HistoryMaxItems>-2</HistoryMaxItems><HistoryMaxSize>-5</HistoryMaxSize>");
    assert!(xml.contains("<HistoryMaxItems>10</HistoryMaxItems>"));
    assert!(xml.contains("<HistoryMaxSize>6291456</HistoryMaxSize>"));
}

#[test]
fn fmt_10_15_below_minus_one_after_a_valid_value() {
    let xml = meta_rw("<HistoryMaxItems>5</HistoryMaxItems><HistoryMaxItems>-2</HistoryMaxItems>");
    assert!(xml.contains("<HistoryMaxItems>5</HistoryMaxItems>"));
}

#[test]
fn fmt_10_15_no_limit() {
    let xml = meta_rw("<HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>-1</HistoryMaxSize>");
    assert!(xml.contains("<HistoryMaxItems>-1</HistoryMaxItems>"));
    assert!(xml.contains("<HistoryMaxSize>-1</HistoryMaxSize>"));
}

#[test]
fn fmt_10_16_dangling() {
    let xml = meta_rw("<RecycleBinUUID>6w7wZdhAp0qVlXjkemuCYw==</RecycleBinUUID>");
    assert!(xml.contains("<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>"));
}

#[test]
fn fmt_10_16_root_as_target() {
    let r = "rH4xp1/3SoWQeYTLdwFNVA==";
    let refs = [
        "RecycleBinUUID",
        "EntryTemplatesGroup",
        "LastSelectedGroup",
        "LastTopVisibleGroup",
    ];
    let meta: String = refs.iter().map(|n| format!("<{n}>{r}</{n}>")).collect();
    let xml = rw(&doc(&meta, &format!("<Group><UUID>{r}</UUID></Group>")));
    for n in refs {
        assert!(xml.contains(&format!("<{n}>{r}</{n}>")), "{n}");
    }
}

#[test]
fn fmt_10_16_carried_only() {
    let child = format!("<Group><UUID>{}</UUID></Group>", idt(2));
    let input = doc(
        &format!("<LastTopVisibleGroup>{}</LastTopVisibleGroup>", idt(2)),
        &format!(
            "<Group><UUID>{}</UUID>{}{child}</Group>",
            idt(1),
            entry(0x10, &s("Title", "a"))
        ),
    );
    let mut v = read_doc(&input);
    v.root.entries[0].set_field(
        "Title".into(),
        larsal_model::Field {
            value: larsal_crypto::secret::SecretString::new("b".into()),
            protected: false,
        },
    );
    assert!(write_doc(&v).contains(&format!(
        "<LastTopVisibleGroup>{}</LastTopVisibleGroup>",
        idt(2)
    )));
}

#[test]
fn fmt_10_17_flags() {
    let xml = meta_rw(
        "<MemoryProtection><ProtectUserName>True</ProtectUserName><Foo/></MemoryProtection>",
    );
    let mp = between(&xml, "<MemoryProtection>", "</MemoryProtection>");
    assert_eq!(
        mp,
        [
            "\t\t\t<ProtectTitle>False</ProtectTitle>",
            "\t\t\t<ProtectUserName>True</ProtectUserName>",
            "\t\t\t<ProtectPassword>True</ProtectPassword>",
            "\t\t\t<ProtectURL>False</ProtectURL>",
            "\t\t\t<ProtectNotes>False</ProtectNotes>",
            "\t\t\t<Foo/>",
        ]
    );
}

#[test]
fn fmt_10_17_repeated_containers_merge() {
    let xml = meta_rw(
        "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectPassword>False</ProtectPassword></MemoryProtection><MemoryProtection><ProtectNotes>True</ProtectNotes></MemoryProtection>",
    );
    assert_eq!(xml.matches("<MemoryProtection>").count(), 1);
    for (n, b) in [
        ("Title", "True"),
        ("UserName", "False"),
        ("Password", "False"),
        ("URL", "False"),
        ("Notes", "True"),
    ] {
        assert!(
            xml.contains(&format!("<Protect{n}>{b}</Protect{n}>")),
            "{n}"
        );
    }
}

#[test]
fn fmt_10_18_recycle_bin_kept_when_disabled() {
    let input = doc(
        &format!(
            "<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>{}</RecycleBinUUID>",
            idt(1)
        ),
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    );
    let xml = rw(&input);
    assert!(xml.contains("<RecycleBinEnabled>False</RecycleBinEnabled>"));
    assert!(xml.contains(&format!("<RecycleBinUUID>{}</RecycleBinUUID>", idt(1))));
}

#[test]
fn fmt_10_19_key_change_values() {
    let xml = meta_rw(
        "<MasterKeyChangeRec>0</MasterKeyChangeRec><MasterKeyChangeForce>30</MasterKeyChangeForce><MaintenanceHistoryDays>-5</MaintenanceHistoryDays>",
    );
    assert!(xml.contains("<MasterKeyChangeRec>0</MasterKeyChangeRec>"));
    assert!(xml.contains("<MasterKeyChangeForce>30</MasterKeyChangeForce>"));
    assert!(xml.contains("<MaintenanceHistoryDays>-5</MaintenanceHistoryDays>"));
}

/// The lines of `Meta` after `</CustomData>`.
fn after_custom_data(xml: &str) -> Vec<&str> {
    between(xml, "\t\t</CustomData>", "\t</Meta>")
}

#[test]
fn fmt_10_20_unknown_meta_child_kept() {
    let xml = meta_rw("<FooBar a=\"1\" b=\"2\">x<Baz/></FooBar>");
    let lines = after_custom_data(&xml);
    assert_eq!(lines, ["\t\t<FooBar a=\"1\" b=\"2\">x<Baz/></FooBar>"]);
    assert_eq!(format!("{}\n", lines[0]).len(), 39);
}

#[test]
fn fmt_10_20_order_of_kept_elements() {
    let xml = meta_rw(
        "<U1/><Generator>G</Generator><DatabaseName>N</DatabaseName><U2>t</U2><CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>",
    );
    assert_eq!(after_custom_data(&xml), ["\t\t<U1/>", "\t\t<U2>t</U2>"]);
}

#[test]
fn fmt_10_20_prefix_and_namespace() {
    let r = root_name();
    let xml = rw(&format!(
        "<{r} xmlns:x=\"urn:x\"><Meta><x:Ext xmlns:y=\"urn:y\" k=\"v\">1</x:Ext></Meta><Root><Group><UUID>{}</UUID></Group></Root></{r}>",
        idt(1)
    ));
    assert_eq!(after_custom_data(&xml), ["\t\t<Ext k=\"v\">1</Ext>"]);
    assert!(!xml.contains("xmlns"));
    read_doc(&xml);
}

#[test]
fn fmt_10_20_prefixed_attributes() {
    let first = meta_rw("<x:Ext xmlns:x=\"urn:x\" x:k=\"1\" k=\"2\"/>");
    let l = format!("{}\n", after_custom_data(&first)[0]);
    assert_eq!(
        l.as_bytes(),
        [
            0x09, 0x09, 0x3C, 0x45, 0x78, 0x74, 0x20, 0x6B, 0x3D, 0x22, 0x32, 0x22, 0x2F, 0x3E,
            0x0A
        ]
    );
    assert_eq!(rw(&first), first, "a second save gives the same bytes");
    let second = meta_rw("<Ext xml:lang=\"en\" a=\"1\"/>");
    assert_eq!(after_custom_data(&second), ["\t\t<Ext a=\"1\"/>"]);
    assert_eq!(rw(&second), second);
}

#[test]
fn fmt_10_20_prefixes_inside_a_kept_element() {
    let first = meta_rw("<Ext xmlns:x=\"urn:x\"><x:In x:k=\"1\" k=\"2\"/></Ext>");
    let lines = after_custom_data(&first);
    let bytes = format!("{}\n", lines.join("\n"));
    assert_eq!(
        bytes.as_bytes(),
        [
            0x09, 0x09, 0x3C, 0x45, 0x78, 0x74, 0x3E, 0x0A, 0x09, 0x09, 0x09, 0x3C, 0x49, 0x6E,
            0x20, 0x6B, 0x3D, 0x22, 0x32, 0x22, 0x2F, 0x3E, 0x0A, 0x09, 0x09, 0x3C, 0x2F, 0x45,
            0x78, 0x74, 0x3E, 0x0A
        ]
    );
    assert!(!first.contains("xmlns") && !first.contains("x:"));
    assert_eq!(rw(&first), first);
}

#[test]
fn fmt_10_20_protected_in_unknown() {
    let input = doc(
        "<X Protected=\"True\">QUJD</X>",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(
                0x10,
                "<String><Key>Password</Key><Value Protected=\"True\">ZAqoPJm1</Value></String>"
            )
        ),
    );
    let v = read_doc(&input);
    assert_eq!(v.root.entries[0].value("Password"), "pw-one");
    let new_key: Vec<u8> = (100u8..164).collect();
    let xml = write_with(&v, &new_key);
    assert_eq!(
        after_custom_data(&xml),
        ["\t\t<X Protected=\"True\">QUJD</X>"]
    );
    let pw = line(&xml, "<Value Protected").trim();
    let b64 = pw
        .trim_start_matches("<Value Protected=\"True\">")
        .trim_end_matches("</Value>");
    assert_eq!(
        dec(&new_key, 0, b64),
        b"pw-one",
        "from byte 0 of the new key"
    );
    assert_eq!(
        read_with(&xml, &new_key, &[]).root.entries[0].value("Password"),
        "pw-one"
    );
}

#[test]
fn fmt_10_20_unknown_attribute() {
    let r = root_name();
    let xml = rw(&format!(
        "<{r}><Meta foo=\"1\"/><Root><Group><UUID>{}</UUID></Group></Root></{r}>",
        idt(1)
    ));
    assert!(!xml.contains("foo"));
    assert_eq!(line(&xml, "<Meta").trim(), "<Meta>");
}

#[test]
fn fmt_10_20_comment_in_kept_element() {
    assert_eq!(
        after_custom_data(&meta_rw("<Ext>a<!-- c -->b</Ext>")),
        ["\t\t<Ext>ab</Ext>"]
    );
}

#[test]
fn fmt_10_21_v4_ignored() {
    assert!(!meta_rw("<HeaderHash>AAAA</HeaderHash>").contains("HeaderHash"));
}

#[test]
fn fmt_10_22_generator_kept() {
    assert!(
        meta_rw("<Generator>OtherApp 1.0</Generator>")
            .contains("\t\t<Generator>OtherApp 1.0</Generator>\n")
    );
}

#[test]
fn fmt_10_22_generator_new() {
    let v = Vault::new(Group::new(id(1), "R".into(), day()), day());
    assert!(write_doc(&v).contains("\t\t<Generator>Larsal</Generator>\n"));
}

#[test]
fn fmt_10_23_version_gates() {
    let v = read_doc(&g(""));
    let xml = write_minor(&v, 1, &zero_key());
    assert!(xml.contains("<SettingsChanged>"));
    assert!(!xml.contains("HeaderHash") && !xml.contains("Binaries"));
    assert!(
        between(&xml, "<CustomData>", "</CustomData>")
            .join("\n")
            .contains(&padding_key())
    );
}

#[test]
fn fmt_10_23_kept_unknown_element_keeps_the_version() {
    use larsal_model::FileVersion;
    let cases = [
        ("a", 1, true, 1),
        ("b", 1, false, 0),
        ("c", 0, true, 0),
        ("d", 2, true, 2),
    ];
    for (case, read_minor, foo, want) in cases {
        let meta = if foo { "<FooBar/>" } else { "" };
        let mut v = read_doc(&doc(
            meta,
            &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
        ));
        v.read_version = Some(FileVersion {
            major: 4,
            minor: read_minor,
        });
        assert_eq!(write::minor_version(&v), want, "case {case}");
        let xml = write_doc(&v);
        assert_eq!(
            after_custom_data(&xml).contains(&"\t\t<FooBar/>"),
            foo,
            "case {case}"
        );
    }
}

#[test]
fn fmt_10_27_empty_and_text_only() {
    let xml = meta_rw("<E1></E1><E2 a=\"1\"/><W>  </W><T>a&#13;b</T>");
    assert_eq!(
        after_custom_data(&xml),
        [
            "\t\t<E1/>",
            "\t\t<E2 a=\"1\"/>",
            "\t\t<W>  </W>",
            "\t\t<T>a&#13;b</T>"
        ]
    );
}

#[test]
fn fmt_10_27_elements_only() {
    let xml = meta_rw("<Ext>\n   <A>1</A>\n   <B/>\n</Ext>");
    assert_eq!(
        after_custom_data(&xml),
        ["\t\t<Ext>", "\t\t\t<A>1</A>", "\t\t\t<B/>", "\t\t</Ext>"]
    );
}

#[test]
fn fmt_10_27_mixed() {
    let xml = meta_rw("<M> <A>\n</A> t </M>");
    assert!(xml.contains("\n\t\t<M> <A>\n</A> t </M>\n\t</Meta>"));
}

#[test]
fn fmt_10_27_stable_over_saves() {
    for meta in [
        "<E1></E1><E2 a=\"1\"/><W>  </W><T>a&#13;b</T>",
        "<Ext>\n   <A>1</A>\n   <B/>\n</Ext>",
        "<M> <A>\n</A> t </M>",
    ] {
        let first = meta_rw(meta);
        assert_eq!(rw(&first), first, "{meta:?}");
    }
}

#[test]
fn fmt_10_28_attribute_tab() {
    let xml = meta_rw("<Ext a=\"x&#9;y\"/>");
    let l = format!("{}\n", after_custom_data(&xml)[0]);
    assert_eq!(
        l.as_bytes(),
        [
            0x09, 0x09, 0x3C, 0x45, 0x78, 0x74, 0x20, 0x61, 0x3D, 0x22, 0x78, 0x26, 0x23, 0x39,
            0x3B, 0x79, 0x22, 0x2F, 0x3E, 0x0A
        ]
    );
    let back = read_doc(&xml);
    assert_eq!(back.meta.unknown[0].attributes[0].1, "x\ty");
}

#[test]
fn fmt_10_28_attribute_escapes() {
    let xml = meta_rw("<Ext a=\"&lt;&amp;&quot;'&gt;\" b=\"l1&#10;l2&#13;\" c=\"p\tq\"/>");
    assert_eq!(
        after_custom_data(&xml),
        ["\t\t<Ext a=\"&lt;&amp;&quot;'&gt;\" b=\"l1&#10;l2&#13;\" c=\"p q\"/>"]
    );
}

#[test]
fn fmt_10_25_random_item_place() {
    let mut v = cheap_vault(&g(""));
    v.meta.custom_data.items.push(larsal_model::CustomDataItem {
        key: padding_key(),
        value: "old".into(),
        last_modified: None,
        unknown: Vec::new(),
    });
    let mut values = Vec::new();
    for _ in 0..2 {
        let file = save_pw(&v, "demo-pass");
        let xml = saved_doc(&file.bytes, "demo-pass");
        let meta = between(&xml, "\t<Meta>", "\t</Meta>").join("\n");
        assert_eq!(names_at(&meta, 2).last().unwrap(), "CustomData");
        let back = open_pw(&file.bytes, "demo-pass");
        let items: Vec<&larsal_model::CustomDataItem> = back
            .vault
            .meta
            .custom_data
            .items
            .iter()
            .filter(|i| i.key == padding_key())
            .collect();
        assert_eq!(items.len(), 1, "replaced, never kept twice");
        let hex = &items[0].value;
        assert!((128..=1022).contains(&hex.len()) && hex.len().is_multiple_of(2));
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        values.push(hex.clone());
    }
    assert_ne!(values[0], values[1]);
}

#[test]
fn fmt_10_26_pointers() {
    let input = doc(
        &format!(
            "<CustomIcons><Icon><UUID>{}</UUID><Data>AAEC</Data></Icon></CustomIcons><CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>",
            idt(9)
        ),
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, "<Binary><Key>f</Key><Value>QUFB</Value></Binary>")
        ),
    );
    let v = read_doc(&input);
    let w = write::write(&v, 0, &mut chacha(&zero_key()), &stamp()).unwrap();
    let xml = String::from_utf8(w.xml().to_vec()).unwrap();
    let meta = names_at(&between(&xml, "\t<Meta>", "\t</Meta>").join("\n"), 2);
    let icons = meta.iter().position(|n| n == "CustomIcons").unwrap();
    assert_eq!(meta[icons - 1], "MemoryProtection");
    assert_eq!(meta.last().unwrap(), "CustomData");
    assert!(!xml.contains("Binaries"));
    assert_eq!(w.pool.len(), 1);
    assert_eq!(w.pool[0].expose(), b"AAA");
    assert!(xml.contains(&format!("<UUID>{}</UUID>", idt(9))) && xml.contains("<Data>AAEC</Data>"));
}

#[test]
fn fmt_10_27_mixed_text_escaped() {
    // Text inside a mixed kept element is escaped like any text (FMT-10.27
    // kind 4, FMT-12.26), and reads back the same.
    let xml = meta_rw("<M>a&amp;b<X>c&lt;d</X>e&quot;f&#13;</M>");
    assert_eq!(
        after_custom_data(&xml),
        ["\t\t<M>a&amp;b<X>c&lt;d</X>e&quot;f&#13;</M>"]
    );
    assert_eq!(rw(&xml), xml);
}
