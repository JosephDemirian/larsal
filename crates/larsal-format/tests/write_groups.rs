//! E3-S7 writer rows of FMT-11 (groups, entries, times, history). Each test
//! names its card row.

mod write_common;

use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::document::write;
use larsal_model::{Attachment, Field, Uuid, Vault};
use std::sync::Arc;
use write_common::*;

/// The lines of the first element `<name>` … `</name>` at any depth,
/// without the start and end lines.
fn block<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    between(xml, &format!("<{name}>"), &format!("</{name}>"))
}

/// The text of every line, without TABs.
fn trimmed<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    lines.iter().map(|l| l.trim_start_matches('\t')).collect()
}

/// The element sequence (names and nesting) of a document: each line's TAB
/// count and element name, without text.
fn shape(xml: &str) -> Vec<(usize, String)> {
    xml.lines()
        .map(|l| {
            let tabs = l.bytes().take_while(|&b| b == b'\t').count();
            let name = l[tabs..]
                .split(['>', ' '])
                .next()
                .unwrap()
                .trim_end_matches('/')
                .to_owned();
            (tabs, name)
        })
        .collect()
}

fn field(v: &str, protected: bool) -> Field {
    Field {
        value: SecretString::new(v.to_owned()),
        protected,
    }
}

#[test]
fn row_11_01_frame() {
    let input = doc(
        "",
        &format!(
            "<Group><UUID>{}</UUID><Name>RootG</Name>{}<Group><UUID>{}</UUID><Name>Child</Name></Group></Group>",
            idt(1),
            entry(0x10, &s("Title", "T1")),
            idt(2)
        ),
    );
    let xml = write_minor(&read_doc(&input), 0, &zero_key());
    assert!(xml.lines().nth(1).unwrap() == format!("<{}>", root_name()));
    assert_eq!(names_at(&xml, 1), ["Meta", "Root"]);
    let root = between(&xml, "\t<Root>", "\t</Root>").join("\n");
    assert_eq!(names_at(&root, 2), ["Group", "DeletedObjects"]);
    assert!(root.contains("\t\t<DeletedObjects/>"));
    let rg = between(&xml, "\t\t<Group>", "\t\t</Group>").join("\n");
    assert_eq!(
        names_at(&rg, 3),
        [
            "UUID",
            "Name",
            "Notes",
            "IconID",
            "Times",
            "IsExpanded",
            "DefaultAutoTypeSequence",
            "EnableAutoType",
            "EnableSearching",
            "LastTopVisibleEntry",
            "Entry",
            "Group"
        ]
    );
    assert!(rg.contains("\t\t\t<UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID>"));
    assert!(rg.contains("\t\t\t<EnableAutoType>null</EnableAutoType>"));
    assert!(rg.contains("\t\t\t<EnableSearching>null</EnableSearching>"));
    assert!(
        rg.contains("\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>")
    );
}

#[test]
fn row_11_10_tri_state() {
    let xml = rw(&g("<EnableAutoType>TRUE</EnableAutoType>"));
    assert!(xml.contains("<EnableAutoType>true</EnableAutoType>"));
    let xml = rw(&g("<EnableSearching>FaLsE</EnableSearching>"));
    assert!(xml.contains("<EnableSearching>false</EnableSearching>"));
}

#[test]
fn row_11_12_icon_order() {
    let a1 = "oaGhoaGhoaGhoaGhoaGhoQ==";
    let input = doc(
        &format!("<CustomIcons><Icon><UUID>{a1}</UUID><Data>AA==</Data></Icon></CustomIcons>"),
        &format!(
            "<Group><UUID>{}</UUID>{}{}{}</Group>",
            idt(1),
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
            )
        ),
    );
    let xml = write_minor(&read_doc(&input), 0, &zero_key());
    let entries: Vec<&str> = xml.split("<Entry>").skip(1).collect();
    assert!(entries[0].contains(&format!(
        "<IconID>0</IconID>\n\t\t\t\t<CustomIconUUID>{a1}</CustomIconUUID>"
    )));
    assert!(entries[1].contains("<IconID>7</IconID>") && !entries[1].contains("CustomIconUUID"));
    assert!(entries[2].contains(
        "<IconID>0</IconID>\n\t\t\t\t<CustomIconUUID>7u7u7u7u7u7u7u7u7u7u7g==</CustomIconUUID>"
    ));
}

#[test]
fn row_11_13_times_defaults() {
    let xml = write_minor(&read_doc(&g("")), 0, &zero_key());
    let times = trimmed(&block(&xml, "Times"));
    assert_eq!(
        times,
        [
            "<LastModificationTime>xPtu4g4AAAA=</LastModificationTime>",
            "<CreationTime>xPtu4g4AAAA=</CreationTime>",
            "<LastAccessTime>xPtu4g4AAAA=</LastAccessTime>",
            "<ExpiryTime>xPtu4g4AAAA=</ExpiryTime>",
            "<Expires>False</Expires>",
            "<UsageCount>0</UsageCount>",
            "<LocationChanged>xPtu4g4AAAA=</LocationChanged>",
        ]
    );
}

#[test]
fn row_11_14_time_encodings() {
    let mut v = read_doc(&g(&entry(0x10, "")));
    v.root.entries[0].times.last_modification = larsal_model::Time(63_729_702_427);
    let xml = write_minor(&v, 0, &zero_key());
    assert!(xml.contains("<LastModificationTime>GxaW1g4AAAA=</LastModificationTime>"));
    let text = rw(&g(&entry(
        0x10,
        "<Times><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime></Times>",
    )));
    assert!(text.contains("<LastModificationTime>GxaW1g4AAAA=</LastModificationTime>"));
    assert!(!text.contains("2020-07-07T"));
}

#[test]
fn row_11_15_lenient_times() {
    let xml = rw(&g(&entry(
        0x10,
        "<Times><CreationTime>yesterday</CreationTime><LastModificationTime>AAAA</LastModificationTime><LastAccessTime/></Times>",
    )));
    let e = xml.split("<Entry>").nth(1).unwrap();
    assert!(e.contains("<CreationTime>xPtu4g4AAAA=</CreationTime>"));
    assert!(e.contains("<LastModificationTime>AAAAAAAAAAA=</LastModificationTime>"));
    assert!(e.contains("<LastAccessTime>AAAAAAAAAAA=</LastAccessTime>"));
}

#[test]
fn row_11_16b_negative_counts_kept() {
    let xml = rw(&g(&entry(
        0x10,
        "<Times><UsageCount>-5</UsageCount></Times><AutoType><DataTransferObfuscation>-7</DataTransferObfuscation></AutoType>",
    )));
    assert!(xml.contains("<UsageCount>-5</UsageCount>"));
    assert!(xml.contains("<DataTransferObfuscation>-7</DataTransferObfuscation>"));
}

#[test]
fn row_11_17_booleans() {
    assert!(rw(&g("<IsExpanded/>")).contains("<IsExpanded>False</IsExpanded>"));
    assert!(rw(&g("<IsExpanded>tRuE</IsExpanded>")).contains("<IsExpanded>True</IsExpanded>"));
}

#[test]
fn row_11_18_standard_fields() {
    let xml = write_minor(
        &read_doc(&g(&entry(0x10, &s("Title", "E")))),
        0,
        &zero_key(),
    );
    let strings: Vec<String> = xml
        .split("<String>")
        .skip(1)
        .map(|s| {
            s.split("</String>")
                .next()
                .unwrap()
                .replace(['\t', '\n'], "")
        })
        .collect();
    assert_eq!(
        strings,
        [
            "<Key>Notes</Key><Value/>",
            "<Key>Password</Key><Value Protected=\"True\"/>",
            "<Key>Title</Key><Value>E</Value>",
            "<Key>URL</Key><Value/>",
            "<Key>UserName</Key><Value/>",
        ]
    );
}

#[test]
fn row_11_19_incomplete_string() {
    let xml = rw(&g(&entry(0x10, "<String><Key/><Value>v</Value></String>")));
    assert!(xml.contains("<String>\n\t\t\t\t\t<Key/>\n\t\t\t\t\t<Value>v</Value>\n"));
}

#[test]
fn row_11_20_white_space_kept() {
    let xml = rw(&g(&format!(
        "<Group><UUID>{}</UUID><Name>  spaced  </Name>{}</Group>",
        idt(2),
        entry(0x10, "<String><Key> k </Key><Value>  v  </Value></String>")
    )));
    assert!(xml.contains("<Name>  spaced  </Name>"));
    assert!(xml.contains("<Key> k </Key>") && xml.contains("<Value>  v  </Value>"));
}

#[test]
fn row_11_22_protected_read() {
    let xml = rw(&g(&entry(
        0x10,
        "<String><Key>Password</Key><Value ProtectInMemory=\"False\">pw</Value></String><String><Key>c1</Key><Value ProtectInMemory=\"1\">x</Value></String><String><Key>c2</Key><Value ProtectInMemory=\"yes\">x</Value></String>",
    )));
    let value_of = |k: &str| {
        let s = xml.split(&format!("<Key>{k}</Key>")).nth(1).unwrap();
        s.lines().nth(1).unwrap().trim().to_owned()
    };
    assert!(value_of("Password").starts_with("<Value Protected=\"True\">"));
    assert!(value_of("c1").starts_with("<Value Protected=\"True\">"));
    assert_eq!(value_of("c2"), "<Value>x</Value>");
    assert!(!xml.contains("ProtectInMemory"));
}

#[test]
fn row_11_23_protected_write_and_keystream() {
    let mut v = read_doc(&g(&format!("{}{}", entry(0x10, ""), entry(0x11, ""))));
    let e = &mut v.root.entries[0];
    e.set_field("Apple".into(), field("p-secret", true));
    e.set_field("Password".into(), field("", false));
    e.set_field("Title".into(), field("T1", false));
    v.root.entries[1].set_field("Next".into(), field("nx", true));
    let key: Vec<u8> = (0u8..64).collect();
    let xml = write_with(&v, &key);
    let first = xml.split("<Entry>").nth(1).unwrap();
    assert!(first.contains(&format!(
        "<Key>Apple</Key>\n\t\t\t\t\t<Value Protected=\"True\">{}</Value>",
        enc(&key, 0, b"p-secret")
    )));
    assert!(first.contains("<Key>Password</Key>\n\t\t\t\t\t<Value Protected=\"True\"/>"));
    assert!(first.contains("<Key>Title</Key>\n\t\t\t\t\t<Value>T1</Value>"));
    let second = xml.split("<Entry>").nth(2).unwrap();
    assert!(
        second.contains(&enc(&key, 8, b"nx")),
        "the next value starts at byte 8"
    );
}

#[test]
fn row_11_24_own_flag_sticks() {
    let input = g(&entry(
        0x10,
        &format!(
            "<String><Key>Password</Key><Value Protected=\"True\">{}</Value></String>",
            enc(&zero_key(), 0, b"pw")
        ),
    ));
    let mut v = read_doc(&input);
    v.meta.memory_protection.password = false;
    assert!(write_doc(&v).contains("<Key>Password</Key>\n\t\t\t\t\t<Value Protected=\"True\">"));
}

#[test]
fn row_11_25_string_order() {
    let keys = [
        "Title",
        "zlower",
        "_under",
        "KP2A_URL",
        "Apple",
        "Password",
        " sp",
        "1",
        "Z",
        "a",
        "é",
        "\u{1F600}",
        "\u{FFFD}",
        "\u{E000}",
    ];
    let strings: String = keys.iter().map(|k| s(k, "v")).collect();
    let xml = rw(&g(&entry(0x10, &strings)));
    let got: Vec<&str> = xml
        .split("<String>")
        .skip(1)
        .map(|s| {
            s.split("<Key>")
                .nth(1)
                .unwrap()
                .split("</Key>")
                .next()
                .unwrap()
        })
        .collect();
    assert_eq!(
        got,
        [
            " sp",
            "1",
            "Apple",
            "KP2A_URL",
            "Notes",
            "Password",
            "Title",
            "URL",
            "UserName",
            "Z",
            "_under",
            "a",
            "zlower",
            "é",
            "\u{1F600}",
            "\u{E000}",
            "\u{FFFD}"
        ]
    );
}

#[test]
fn row_11_26_attachment_refs() {
    let mut items: Vec<Vec<u8>> = (0..8).map(|i| vec![b'0' + i]).collect();
    items[0] = b"attach-zero".to_vec();
    items[7] = b"attach-seven".to_vec();
    let pool: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    let input = g(&entry(
        0x10,
        "<Binary><Key>b.txt</Key><Value Ref=\"7\"/></Binary><Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary>",
    ));
    let v = read_with(&input, &zero_key(), &pool);
    let w = write::write(&v, 0, &mut chacha(&zero_key()), &stamp()).unwrap();
    let xml = String::from_utf8(w.xml().to_vec()).unwrap();
    let bins: Vec<String> = xml
        .split("<Binary>")
        .skip(1)
        .map(|b| {
            b.split("</Binary>")
                .next()
                .unwrap()
                .replace(['\t', '\n'], "")
        })
        .collect();
    assert_eq!(
        bins,
        [
            "<Key>a.txt</Key><Value Ref=\"0\"/>",
            "<Key>b.txt</Key><Value Ref=\"1\"/>"
        ]
    );
    let got: Vec<&[u8]> = w.pool.iter().map(|p| p.expose()).collect();
    assert_eq!(got, [&b"attach-zero"[..], &b"attach-seven"[..]]);
}

#[test]
fn row_11_29_auto_type() {
    let at = "<AutoType><Enabled>False</Enabled><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>Win B</Window><KeystrokeSequence>seqB</KeystrokeSequence></Association><Association><Window>Win A</Window><KeystrokeSequence/></Association></AutoType>";
    let xml = rw(&g(&entry(0x10, at)));
    assert_eq!(
        trimmed(&block(&xml, "AutoType")),
        [
            "<Enabled>False</Enabled>",
            "<DataTransferObfuscation>1</DataTransferObfuscation>",
            "<DefaultSequence>{PASSWORD}</DefaultSequence>",
            "<Association>",
            "<Window>Win B</Window>",
            "<KeystrokeSequence>seqB</KeystrokeSequence>",
            "</Association>",
            "<Association>",
            "<Window>Win A</Window>",
            "<KeystrokeSequence/>",
            "</Association>",
        ]
    );
}

#[test]
fn row_11_30_auto_type_errors_and_defaults() {
    let xml = rw(&g(&entry(0x10, "")));
    assert_eq!(
        trimmed(&block(&xml, "AutoType")),
        [
            "<Enabled>True</Enabled>",
            "<DataTransferObfuscation>0</DataTransferObfuscation>",
            "<DefaultSequence/>"
        ]
    );
}

#[test]
fn row_11_31_colors() {
    let xml = rw(&g(&format!(
        "{}{}",
        entry(
            0x10,
            "<ForegroundColor>red</ForegroundColor><BackgroundColor>#GG0000</BackgroundColor>"
        ),
        entry(0x11, "<BackgroundColor>#00ff00</BackgroundColor>")
    )));
    assert!(xml.contains("<ForegroundColor>red</ForegroundColor>"));
    assert!(xml.contains("<BackgroundColor>#GG0000</BackgroundColor>"));
    assert!(xml.contains("<BackgroundColor>#00ff00</BackgroundColor>"));
}

#[test]
fn row_11_32_entry_tags() {
    let xml = rw(&g(&format!(
        "{}{}",
        entry(0x10, "<Tags>zeta; alpha,beta&#9;alpha ,Alpha</Tags>"),
        entry(0x11, "<Tags>a, ,b;;c</Tags>")
    )));
    assert!(xml.contains("<Tags>Alpha,alpha,beta,zeta</Tags>"));
    assert!(xml.contains("<Tags>a,b,c</Tags>"));
}

#[test]
fn row_11_33_group_tags() {
    let v = read_doc(&g("<Tags>gt2;gt1</Tags>"));
    assert_eq!(write::minor_version(&v), 1);
    let xml = write_doc(&v);
    let rg = trimmed(&block(&xml, "Group"));
    let at = rg
        .iter()
        .position(|l| *l == "<Tags>gt2;gt1</Tags>")
        .unwrap();
    assert!(rg[at - 1].starts_with("<Notes") && rg[at + 1].starts_with("<IconID>"));
}

#[test]
fn row_11_34_override_url() {
    assert!(
        rw(&g(&entry(0x10, "<OverrideURL>cmd://demo</OverrideURL>")))
            .contains("<OverrideURL>cmd://demo</OverrideURL>")
    );
}

#[test]
fn row_11_35_quality_check() {
    let v = read_doc(&g(&format!(
        "{}{}{}{}",
        entry(0x0A, "<QualityCheck>False</QualityCheck>"),
        entry(0x0B, "<QualityCheck>True</QualityCheck>"),
        entry(0x0C, "<QualityCheck/>"),
        entry(0x0D, "")
    )));
    let at41 = write_minor(&v, 1, &zero_key());
    let entries: Vec<&str> = at41.split("<Entry>").skip(1).collect();
    for (i, excluded) in [true, false, true, false].into_iter().enumerate() {
        assert_eq!(
            entries[i].contains("</Times>\n\t\t\t\t<QualityCheck>False</QualityCheck>\n"),
            excluded,
            "entry {i}"
        );
        assert_eq!(entries[i].contains("QualityCheck"), excluded);
    }
    assert!(!write_minor(&v, 0, &zero_key()).contains("QualityCheck"));
}

#[test]
fn row_11_36_previous_parent() {
    let child = format!("<Group><UUID>{}</UUID></Group>", idt(2));
    let pp = |n: u8| {
        format!(
            "<PreviousParentGroup>{}</PreviousParentGroup>{}",
            idt(n),
            s("Title", "T")
        )
    };
    for (n, text) in [
        (2u8, "AgICAgICAgICAgICAgICAg=="),
        (0x98, "mJiYmJiYmJiYmJiYmJiYmA=="),
    ] {
        let v = read_doc(&g(&format!("{}{child}", entry(0x10, &pp(n)))));
        assert_eq!(write::minor_version(&v), 1, "id {n}");
        let xml = write_doc(&v);
        let e: Vec<&str> = trimmed(&block(&xml, "Entry"));
        let at = e
            .iter()
            .position(|l| l.starts_with("<PreviousParentGroup>"))
            .unwrap();
        assert_eq!(
            e[at],
            format!("<PreviousParentGroup>{text}</PreviousParentGroup>")
        );
        assert_eq!(e[at - 1], "</Times>");
        assert_eq!(e[at + 1], "<String>");
        assert_eq!(read_doc(&xml).root.entries[0].previous_parent, Some(id(n)));
    }
}

#[test]
fn row_11_36b_history_flags_need_4_1() {
    let item = entry(
        0x10,
        &format!(
            "{}<QualityCheck>False</QualityCheck><PreviousParentGroup>{}</PreviousParentGroup>",
            s("Title", "T0"),
            idt(2)
        ),
    );
    let input = g(&format!(
        "{}<Group><UUID>{}</UUID></Group>",
        entry(
            0x10,
            &format!("{}<History>{item}</History>", s("Title", "T1"))
        ),
        idt(2)
    ));
    let v = read_doc(&input);
    assert_eq!(write::minor_version(&v), 1);
    let xml = write_doc(&v);
    let hist = trimmed(&block(&xml, "History"));
    let at = hist.iter().position(|l| *l == "</Times>").unwrap();
    assert_eq!(hist[at + 1], "<QualityCheck>False</QualityCheck>");
    assert_eq!(
        hist[at + 2],
        "<PreviousParentGroup>AgICAgICAgICAgICAgICAg==</PreviousParentGroup>"
    );
    let back = read_doc(&xml);
    let e = &back.root.entries[0];
    assert!(e.history[0].exclude_from_reports && e.history[0].previous_parent == Some(id(2)));
    assert!(!e.exclude_from_reports && e.previous_parent.is_none());
}

#[test]
fn row_11_37_history_shape() {
    let xml = rw(&g(&format!(
        "{}{}",
        entry(
            0x10,
            &format!("<History>{}</History>", entry(0x10, &s("Title", "T0")))
        ),
        entry(0x11, "")
    )));
    let entries: Vec<&str> = xml.split("\n\t\t\t<Entry>\n").skip(1).collect();
    assert!(entries[0].contains("\t\t\t\t<History>\n\t\t\t\t\t<Entry>\n"));
    let item = entries[0].split("\t\t\t\t\t<Entry>\n").nth(1).unwrap();
    assert!(
        item.contains("<Times>")
            && !item
                .split("\t\t\t\t\t</Entry>")
                .next()
                .unwrap()
                .contains("History")
    );
    assert!(entries[1].contains("\t\t\t\t<History/>\n\t\t\t</Entry>"));
}

#[test]
fn row_11_39_history_ids() {
    let xml = rw(&g(&entry(
        0x10,
        &format!(
            "<History><Entry><UUID>{}</UUID></Entry><Entry></Entry></History>",
            idt(0x20)
        ),
    )));
    let hist = block(&xml, "History").join("\n");
    assert_eq!(
        hist.matches("<UUID>EBAQEBAQEBAQEBAQEBAQEA==</UUID>")
            .count(),
        2
    );
}

#[test]
fn row_11_40_shared_id_across_kinds() {
    let xml = rw(&g(&format!(
        "{}<Group><UUID>{}</UUID></Group>",
        entry(2, ""),
        idt(2)
    )));
    assert_eq!(xml.matches(&format!("<UUID>{}</UUID>", idt(2))).count(), 2);
}

#[test]
fn row_11_45_forward_and_broken_refs() {
    let input = doc(
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
    );
    let xml = rw(&input);
    assert!(xml.contains("<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>"));
    assert!(xml.contains("<LastSelectedGroup>AQEBAQEBAQEBAQEBAQEBAQ==</LastSelectedGroup>"));
    assert!(xml.contains("<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>"));
}

#[test]
fn row_11_50_empty_forms_and_layout() {
    let id1 = idt(1);
    let forms = [
        doc(
            "",
            &format!("<Group><UUID>{id1}</UUID><Name></Name></Group>"),
        ),
        doc("", &format!("<Group><UUID>{id1}</UUID><Name/></Group>")),
        doc(
            "",
            &format!("<Group>\n  <UUID>{id1}</UUID>\n  <Name/>\n</Group>"),
        ),
        doc(
            "",
            &format!("<Group>\n\t<UUID>{id1}</UUID>\n\t<Name/>\n</Group>"),
        ),
    ];
    let outs: Vec<String> = forms
        .iter()
        .map(|d| write_minor(&read_doc(d), 0, &zero_key()))
        .collect();
    for o in &outs {
        assert_eq!(o, &outs[0]);
    }
    let name = format!("{}\n", line(&outs[0], "<Name/>"));
    assert_eq!(
        name.as_bytes(),
        [
            0x09, 0x09, 0x09, 0x3C, 0x4E, 0x61, 0x6D, 0x65, 0x2F, 0x3E, 0x0A
        ]
    );
    assert_eq!(
        line(&outs[0], "<UUID>"),
        format!("\t\t\t<UUID>{id1}</UUID>")
    );
}

#[test]
fn row_11_50b_stray_content() {
    let at = "<AutoType>ajunk<Association>xjunk<Window>W</Window><KeystrokeSequence>s</KeystrokeSequence></Association></AutoType>";
    let e = format!(
        "<Entry>ejunk<?pi x?><UUID>{}</UUID><Times>tjunk<UsageCount>4</UsageCount></Times><String>sjunk<Key>Title</Key><Value>T</Value></String>{at}</Entry>",
        idt(0x10)
    );
    let input = doc(
        "",
        &format!(
            "rootjunk<Group>gjunk<!--c--><UUID>{}</UUID>{e}</Group>",
            idt(1)
        ),
    );
    let xml = rw(&input);
    for junk in ["junk", "<!--", "<?pi"] {
        assert!(!xml.contains(junk), "{junk}");
    }
    assert!(
        xml.contains("<UsageCount>4</UsageCount>")
            && xml.contains("<Value>T</Value>")
            && xml.contains("<Window>W</Window>")
    );
    let r = root_name();
    let prefixed = format!(
        "<p:{r} xmlns:p=\"urn:x\"><Meta/><Root><Group><UUID>{}</UUID>{}</Group></Root></p:{r}>",
        idt(1),
        entry(0x10, &s("Title", "T"))
    );
    let plain = doc(
        "",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, &s("Title", "T"))
        ),
    );
    assert_eq!(rw(&prefixed), rw(&plain));
}

#[test]
fn row_11_51_unknown_elements() {
    let e = entry(
        0x10,
        "<Times><UnknownTimesThing/></Times><UnknownEntryThing>y</UnknownEntryThing><String><Key>k</Key><Value>v</Value><StringExtra/></String>",
    );
    let xml = rw(&g(&format!(
        "<UnknownGroupThing a=\"1\">x</UnknownGroupThing>{e}"
    )));
    let e = xml.split("<Entry>").nth(1).unwrap();
    let times = e
        .split("<Times>")
        .nth(1)
        .unwrap()
        .split("</Times>")
        .next()
        .unwrap();
    assert!(times.trim_end().ends_with("\t\t\t\t\t<UnknownTimesThing/>"));
    assert!(xml.contains("\t\t\t\t<UnknownEntryThing>y</UnknownEntryThing>\n\t\t\t</Entry>"));
    assert!(xml.contains("\t\t\t<UnknownGroupThing a=\"1\">x</UnknownGroupThing>\n\t\t</Group>"));
    assert!(!xml.contains("StringExtra"));
    assert!(xml.contains("<Key>k</Key>\n\t\t\t\t\t<Value>v</Value>"));
}

#[test]
fn row_11_52_removing_characters() {
    let mut v = read_doc(&g(&entry(0x10, "")));
    v.root.name = "a\u{84}b".into();
    let e = &mut v.root.entries[0];
    e.set_field(
        "PlainInvalid".into(),
        field("\u{2}\u{19}\u{FFFE}\u{FFFF}", false),
    );
    e.set_field("Sec".into(), field("x\u{1}y", true));
    e.attachments.push(Attachment {
        name: "f\u{1}.txt".into(),
        data: Arc::new(SecretBytes::new(b"d".to_vec())),
    });
    let xml = write_doc(&v);
    assert!(xml.contains("<Key>PlainInvalid</Key>\n\t\t\t\t\t<Value/>"));
    assert!(xml.contains("<Name>ab</Name>"));
    assert!(xml.contains("<Key>f.txt</Key>"));
    let back = read_doc(&xml);
    assert_eq!(back.root.entries[0].value("Sec"), "x\u{1}y");
}

#[test]
fn row_11_53_fixed_sequence() {
    let input = doc(
        "",
        &format!(
            "<Group><UUID>{}</UUID><Name>RootG</Name>{}<Group><UUID>{}</UUID><Name>Child</Name></Group></Group>",
            idt(1),
            entry(0x10, &s("Title", "T1")),
            idt(2)
        ),
    );
    let v = read_doc(&input);
    let a = write_minor(&v, 0, &zero_key());
    let b = write_minor(&v, 0, &(1u8..65).collect::<Vec<u8>>());
    assert_eq!(shape(&a), shape(&b));
}

#[test]
fn row_11_54_two_history_blocks() {
    let h = |t: &str| format!("<History>{}</History>", entry(0x10, &s("Title", t)));
    let xml = rw(&g(&entry(0x10, &format!("{}{}", h("H1"), h("H2")))));
    assert_eq!(xml.matches("<History>").count(), 1);
    assert!(xml.contains("<Value>H2</Value>") && !xml.contains("H1"));
}

#[test]
fn row_11_55_two_times_blocks() {
    let xml = rw(&g(&entry(
        0x10,
        "<Times><LastModificationTime>GxaW1g4AAAA=</LastModificationTime><UsageCount>3</UsageCount></Times><Times><CreationTime>m2eX1g4AAAA=</CreationTime></Times>",
    )));
    let e = xml.split("<Entry>").nth(1).unwrap();
    assert_eq!(e.matches("<Times>").count(), 1);
    assert!(e.contains("<CreationTime>m2eX1g4AAAA=</CreationTime>"));
    for n in [
        "LastModificationTime",
        "LastAccessTime",
        "ExpiryTime",
        "LocationChanged",
    ] {
        assert!(e.contains(&format!("<{n}>xPtu4g4AAAA=</{n}>")), "{n}");
    }
    assert!(e.contains("<UsageCount>0</UsageCount>") && e.contains("<Expires>False</Expires>"));
}

#[test]
fn row_11_56_two_auto_type_blocks() {
    let at = "<AutoType><Enabled>False</Enabled><DefaultSequence>{USERNAME}</DefaultSequence><Association><Window>W1</Window><KeystrokeSequence>s1</KeystrokeSequence></Association></AutoType><AutoType><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>W2</Window><KeystrokeSequence>s2</KeystrokeSequence></Association></AutoType>";
    let xml = rw(&g(&entry(0x10, at)));
    assert_eq!(xml.matches("<AutoType>").count(), 1);
    assert_eq!(
        trimmed(&block(&xml, "AutoType")).join(""),
        "<Enabled>False</Enabled><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>W1</Window><KeystrokeSequence>s1</KeystrokeSequence></Association><Association><Window>W2</Window><KeystrokeSequence>s2</KeystrokeSequence></Association>"
    );
}

#[test]
fn row_11_57_duplicate_entry_history_and_attachments() {
    let first = entry(
        0x10,
        &format!(
            "{}<Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary><Binary><Key>c.txt</Key><Value>Q0ND</Value></Binary><History>{}</History>",
            s("Title", "first"),
            entry(0x10, &s("Title", "h-first"))
        ),
    );
    let second = entry(
        0x10,
        &format!(
            "{}<Binary><Key>b.txt</Key><Value Ref=\"1\"/></Binary><History>{}</History>",
            s("Title", "second"),
            entry(0x10, &s("Title", "h-second"))
        ),
    );
    let input = g(&format!(
        "{first}{}<Group><UUID>{}</UUID>{second}</Group>",
        entry(0x20, ""),
        idt(2)
    ));
    let v = read_with(&input, &zero_key(), &[b"AAA", b"BBB"]);
    let w = write::write(&v, 0, &mut chacha(&zero_key()), &stamp()).unwrap();
    let pool: Vec<&[u8]> = w.pool.iter().map(|p| p.expose()).collect();
    let back = read_with(std::str::from_utf8(w.xml()).unwrap(), &zero_key(), &pool);
    let ids: Vec<Uuid> = back.root.entries.iter().map(|e| e.uuid).collect();
    assert_eq!(ids, [id(0x10), id(0x20)]);
    let e = &back.root.entries[0];
    assert_eq!(e.value("Title"), "second");
    let att: Vec<(&str, &[u8])> = e
        .attachments
        .iter()
        .map(|a| (a.name.as_str(), a.data.expose()))
        .collect();
    assert_eq!(att, [("a.txt", &b"AAA"[..]), ("b.txt", &b"BBB"[..])]);
    let hist: Vec<&str> = e.history.iter().map(|h| h.value("Title")).collect();
    assert_eq!(hist, ["h-first", "h-second"]);
    assert!(back.root.groups[0].entries.is_empty());
}

#[test]
fn row_11_58_duplicate_positions() {
    let gr =
        |n: u8, name: &str| format!("<Group><UUID>{}</UUID><Name>{name}</Name></Group>", idt(n));
    let en = |n: u8, t: &str| entry(n, &s("Title", t));
    let input = g(&format!(
        "{}{}{}{}{}{}{}{}",
        gr(2, "X1"),
        gr(3, "Y"),
        gr(2, "X2"),
        gr(4, "Z"),
        en(0x10, "E-first"),
        en(0x11, "F"),
        en(0x10, "E-second"),
        en(0x12, "G")
    ));
    let back = read_doc(&rw(&input));
    let groups: Vec<&str> = back.root.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(groups, ["Y", "X2", "Z"]);
    let entries: Vec<&str> = back.root.entries.iter().map(|e| e.value("Title")).collect();
    assert_eq!(entries, ["E-second", "F", "G"]);
}

#[test]
fn row_11_59_unicode_white_space_in_tags() {
    assert!(
        rw(&g(&entry(0x10, "<Tags>\u{A0}x\u{A0},\u{3000}y</Tags>"))).contains("<Tags>x,y</Tags>")
    );
}

#[test]
fn row_11_61_duplicates_without_a_cycle() {
    let input = g(&format!(
        "<Group><UUID>{}</UUID><Name>A</Name><Group><UUID>{}</UUID><Name>B'</Name></Group></Group><Group><UUID>BQUFBQUFBQUFBQUFBQUFBQ==</UUID><Name>X</Name><Group><UUID>{}</UUID><Name>B</Name><Group><UUID>{}</UUID><Name>Y</Name></Group></Group></Group>",
        idt(2),
        idt(3),
        idt(3),
        idt(4)
    ));
    let back = read_doc(&rw(&input));
    let names: Vec<&str> = back.root.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["A", "X"]);
    assert!(back.root.groups[0].groups.is_empty());
    let b = &back.root.groups[1].groups[0];
    assert_eq!((b.name.as_str(), b.groups[0].name.as_str()), ("B", "Y"));
}

#[test]
fn row_11_62_unknown_children_of_repeated_parents() {
    let e10 = entry(
        0x10,
        "<Times><UnknownT1/></Times><Times><UnknownT2/></Times><AutoType><UnknownA1/></AutoType><AutoType><UnknownA2/></AutoType>",
    );
    let e11a = entry(0x11, "<UnknownE1/>");
    let e11b = entry(0x11, "<UnknownE2/>");
    let h = |t: &str, u: &str| {
        format!(
            "<History>{}</History>",
            entry(0x12, &format!("{}<{u}/>", s("Title", t)))
        )
    };
    let e12 = entry(
        0x12,
        &format!("{}{}", h("H1", "UnknownH1"), h("H2", "UnknownH2")),
    );
    let xml = rw(&g(&format!("{e10}{e11a}{e11b}{e12}")));
    let entries: Vec<&str> = xml.split("\n\t\t\t<Entry>\n").skip(1).collect();
    let times = entries[0]
        .split("<Times>")
        .nth(1)
        .unwrap()
        .split("</Times>")
        .next()
        .unwrap();
    assert!(times.contains("<UnknownT2/>") && !times.contains("UnknownT1"));
    assert!(times.trim_end().ends_with("<UnknownT2/>"));
    let at = entries[0]
        .split("<AutoType>")
        .nth(1)
        .unwrap()
        .split("</AutoType>")
        .next()
        .unwrap();
    assert!(at.contains("<DefaultSequence/>\n\t\t\t\t\t<UnknownA1/>\n\t\t\t\t\t<UnknownA2/>"));
    assert!(
        entries[1].contains("\t\t\t\t<UnknownE2/>\n\t\t\t</Entry>") && !xml.contains("UnknownE1")
    );
    assert!(
        entries[2].contains("\t\t\t\t\t\t<UnknownH2/>\n\t\t\t\t\t</Entry>")
            && !xml.contains("UnknownH1")
    );
}

#[test]
fn row_11_62b_unknown_element_keeps_the_version() {
    use larsal_model::FileVersion;
    for (file_minor, want) in [(1u16, 1u16), (0, 0), (2, 2)] {
        let mut v = read_doc(&g(&entry(0x10, "<UnknownEntryThing>y</UnknownEntryThing>")));
        v.read_version = Some(FileVersion {
            major: 4,
            minor: file_minor,
        });
        assert_eq!(write::minor_version(&v), want);
        let xml = write_doc(&v);
        assert!(xml.contains("\t\t\t\t<UnknownEntryThing>y</UnknownEntryThing>\n\t\t\t</Entry>"));
    }
}

#[test]
fn row_11_63_entry_placed_through_another_group() {
    let input = g(&format!(
        "<Group><UUID>{}</UUID><Name>X1</Name>{}{}</Group><Group><UUID>{}</UUID><Name>Y</Name>{}</Group><Group><UUID>{}</UUID><Name>X2</Name>{}</Group>",
        idt(2),
        entry(0x10, &s("Title", "E")),
        entry(0x11, &s("Title", "F")),
        idt(3),
        entry(0x10, &s("Title", "E")),
        idt(2),
        entry(0x10, &s("Title", "E"))
    ));
    let back: Vault = read_doc(&rw(&input));
    let names: Vec<&str> = back.root.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["Y", "X2"]);
    assert!(back.root.groups[0].entries.is_empty());
    let x: Vec<&str> = back.root.groups[1]
        .entries
        .iter()
        .map(|e| e.value("Title"))
        .collect();
    assert_eq!(x, ["F", "E"]);
}

#[test]
fn row_11_51b_group_unknown_after_child_groups() {
    // Kept unknown children of a group come after all its known children,
    // child groups included (FMT-11.45).
    let child = format!("<Group><UUID>{}</UUID><Name>C</Name></Group>", idt(2));
    let xml = rw(&g(&format!("<Unk>u</Unk>{}{child}", entry(0x10, ""))));
    assert!(xml.contains("\t\t\t</Group>\n\t\t\t<Unk>u</Unk>\n\t\t</Group>\n"));
    assert_eq!(
        xml.matches("<Unk>").count(),
        1,
        "written once, after the child groups"
    );
}
