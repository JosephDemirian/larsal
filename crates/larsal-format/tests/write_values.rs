//! E3-S7 writer rows of FMT-12 (value encodings on write). Each test names
//! its card row.

mod write_common;

use larsal_crypto::secret::SecretString;
use larsal_format::document::encode::{time_to_binary, uuid_to_text};
use larsal_model::{Field, Time, Uuid};
use write_common::*;

/// The written `DatabaseNameChanged` text after reading `text` there.
fn time_rw(text: &str) -> String {
    let xml = rw(&doc(
        &format!("<DatabaseNameChanged>{text}</DatabaseNameChanged>"),
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ));
    let l = line(&xml, "<DatabaseNameChanged>").trim().to_owned();
    l.trim_start_matches("<DatabaseNameChanged>")
        .trim_end_matches("</DatabaseNameChanged>")
        .to_owned()
}

/// The written value of a `Meta` text element `name` holding `value`.
fn meta_text(name: &str, value: &str) -> String {
    let mut v = read_doc(&g(""));
    match name {
        "DatabaseName" => v.meta.name = value.to_owned(),
        _ => v.meta.color = value.to_owned(),
    }
    line(&write_doc(&v), &format!("<{name}")).trim().to_owned()
}

fn open_time() -> String {
    time_to_binary(OPEN)
}

#[test]
fn fmt_12_2_binary_write() {
    assert_eq!(time_to_binary(Time(63_416_885_093)), "Zd/www4AAAA=");
    assert_eq!(
        larsal_format::document::encode::base64_decode("Zd/www4AAAA="),
        [0x65, 0xDF, 0xF0, 0xC3, 0x0E, 0, 0, 0]
    );
    let mut v = read_doc(&g(""));
    v.meta.name_changed = Time(63_416_885_093);
    assert!(write_doc(&v).contains("<DatabaseNameChanged>Zd/www4AAAA=</DatabaseNameChanged>"));
}

#[test]
fn fmt_12_2_binary_write_2() {
    assert_eq!(time_to_binary(Time(63_928_396_800)), "AOxt4g4AAAA=");
}

#[test]
fn fmt_12_2_binary_write_3() {
    assert_eq!(time_to_binary(Time(0)), "AAAAAAAAAAA=");
    assert_eq!(time_to_binary(Time(315_537_897_599)), "fziGd0kAAAA=");
    assert_eq!(
        time_to_binary(Time::from_unix(2_147_483_648).unwrap()),
        "APeR9w4AAAA="
    );
}

#[test]
fn fmt_12_5_negative() {
    assert_eq!(time_rw("//////////8="), "//////////8=");
}

#[test]
fn fmt_12_6_text_z() {
    for t in [
        "2010-08-08T17:24:53Z",
        "2010-08-08T17:24:53z",
        "2010-08-08t17:24:53Z",
    ] {
        assert_eq!(time_rw(t), "Zd/www4AAAA=", "{t}");
    }
}

#[test]
fn fmt_12_6_offset() {
    assert_eq!(time_rw("2010-08-08T17:24:53+02:00"), "RcPwww4AAAA=");
}

#[test]
fn fmt_12_6_offset_shapes() {
    for t in [
        "2010-08-08T17:24:53+05:00",
        "2010-08-08T17:24:53+0500",
        "2010-08-08T17:24:53+05",
    ] {
        assert_eq!(time_rw(t), "FZnwww4AAAA=", "{t}");
    }
}

#[test]
fn fmt_12_6_end_of_day() {
    for t in ["2010-08-08T24:00:00Z", "2010-08-08T24:00Z"] {
        assert_eq!(time_rw(t), "ADzxww4AAAA=", "{t}");
    }
}

#[test]
fn fmt_12_6_offset_then_z() {
    for t in ["2010-08-08T17:24:53+02:00Z", "2010-08-08T17:24:53+05:00Z"] {
        assert_eq!(time_rw(t), "Zd/www4AAAA=", "{t}");
    }
}

#[test]
fn fmt_12_6_result_out_of_range() {
    assert_eq!(time_rw("9999-12-31T24:00:00Z"), "gDiGd0kAAAA=");
    assert_eq!(time_rw("0001-01-01T00:00:00+01:00"), "8PH///////8=");
    assert_eq!(time_rw("9999-12-31T23:59:59-01:00"), "j0aGd0kAAAA=");
}

#[test]
fn fmt_12_28_a_no_zone() {
    assert_eq!(
        time_rw("2010-08-08T17:24:53"),
        "Zd/www4AAAA=",
        "Larsal: read as UTC"
    );
}

#[test]
fn fmt_12_28_b_trailing_text() {
    for t in [
        "2010-08-08T17:24:53 ",
        "2010-08-08T17:24:53Z ",
        "2010-08-08T17:24:53garbage",
        "2010-08-08T17:24:53UTC",
        "2010-08-08T17:24:53Zgarbage",
    ] {
        assert_eq!(time_rw(t), open_time(), "{t:?}");
    }
}

#[test]
fn fmt_12_28_g_minute_fraction() {
    for t in [
        "2010-08-08T17:24.5Z",
        "2010-08-08T17:24,5Z",
        "2010-08-08T17:24.25+05:00",
        "2010-08-08T24:00.0Z",
        "2010-08-08T17:24.5",
    ] {
        assert_eq!(time_rw(t), open_time(), "{t:?}");
    }
}

#[test]
fn fmt_12_28_k_offset_then_z_app_only() {
    for t in [
        "2010-08-08T17:24+02:00Z",
        "2010-08-08T17:24+0200Z",
        "2010-08-08T17:24-05Z",
    ] {
        assert_eq!(time_rw(t), "MN/www4AAAA=", "{t}");
    }
    assert_eq!(time_rw("2010-08-08T24:00+02:00Z"), "ADzxww4AAAA=");
    for t in [
        "2010-08-08T17:24:53.5+02:00Z",
        "2010-08-08T17:24:53,5+02:00Z",
        "2010-08-08T17:24:53.12+02:00Z",
        "2010-08-08T17:24:53.123+02:00Z",
    ] {
        assert_eq!(time_rw(t), "Zd/www4AAAA=", "{t}");
    }
}

#[test]
fn fmt_12_28_k_offset_then_z_same_in_both() {
    for t in [
        "2010-08-08T17:24:53+0200Z",
        "2010-08-08T17:24:53+02Z",
        "2010-08-08T17:24:53-05:30z",
        "2010-08-08T17:24:53.1234+02:00Z",
        "2010-08-08T17:24:53.12345+02:00Z",
    ] {
        assert_eq!(time_rw(t), "Zd/www4AAAA=", "{t}");
    }
    for t in ["2010-08-08T24:00:00+02:00Z", "2010-08-08T24:00:00-05:00Z"] {
        assert_eq!(time_rw(t), "ADzxww4AAAA=", "{t}");
    }
}

#[test]
fn fmt_12_28_l_end_of_day_with_a_fraction() {
    for t in [
        "2010-08-08T24:00:00.0Z",
        "2010-08-08T24:00:00,000Z",
        "2010-08-08T24:00:00.0004Z",
        "2010-08-08T24:00:00.0+02:00",
    ] {
        assert_eq!(time_rw(t), open_time(), "{t}");
    }
}

#[test]
fn fmt_12_8_range_kept() {
    assert_eq!(time_rw("gDiGd0kAAAA="), "gDiGd0kAAAA=");
}

#[test]
fn fmt_12_8_extremes() {
    assert_eq!(time_rw("/////////38="), "/////////38=");
    assert_eq!(time_rw("AAAAAAAAAIA="), "AAAAAAAAAIA=");
}

#[test]
fn fmt_12_9_utc() {
    assert_eq!(time_rw("Zd/www4AAAA="), "Zd/www4AAAA=");
}

#[test]
fn fmt_12_11_write() {
    let mut v = read_doc(&g(""));
    v.meta.recycle_bin_enabled = false;
    v.root.expanded = true;
    let xml = write_doc(&v);
    assert!(xml.contains("<RecycleBinEnabled>False</RecycleBinEnabled>"));
    assert!(xml.contains("<IsExpanded>True</IsExpanded>"));
}

#[test]
fn fmt_12_12_three_state() {
    for (text, want) in [
        ("null", "null"),
        ("NULL", "null"),
        ("true", "true"),
        ("TRUE", "true"),
        ("false", "false"),
    ] {
        let xml = rw(&g(&format!("<EnableAutoType>{text}</EnableAutoType>")));
        assert!(
            xml.contains(&format!("<EnableAutoType>{want}</EnableAutoType>")),
            "{text}"
        );
    }
}

#[test]
fn fmt_12_12_unicode_fold() {
    assert!(
        rw(&g("<EnableAutoType>fal\u{17F}e</EnableAutoType>"))
            .contains("<EnableAutoType>false</EnableAutoType>")
    );
    assert!(
        rw(&g("<EnableAutoType>nuLL</EnableAutoType>"))
            .contains("<EnableAutoType>null</EnableAutoType>")
    );
}

#[test]
fn fmt_12_13_write() {
    assert!(rw(&g(&entry(0x10, &s("Password", "x")))).contains("<Value Protected=\"True\">"));
}

#[test]
fn fmt_12_13_attribute_name_prefix() {
    let r = root_name();
    let input = format!(
        "<{r} xmlns:x=\"urn:x\"><Meta><DatabaseName x:Protected=\"True\">RxjmIZKk</DatabaseName><DatabaseDescription Protected=\"True\">RxjmIZKk</DatabaseDescription></Meta><Root><Group><UUID>{}</UUID></Group></Root></{r}>",
        idt(1)
    );
    let xml = rw(&input);
    assert!(xml.contains("\t\t<DatabaseName>RxjmIZKk</DatabaseName>\n"));
    assert!(xml.contains("<DatabaseDescription>Secret</DatabaseDescription>"));
}

#[test]
fn fmt_12_14_write() {
    let mut v = read_doc(&g(""));
    v.meta.master_key_change_rec = 0;
    v.meta.master_key_change_force = -1;
    v.meta.history_max_size = 6_291_456;
    let xml = write_doc(&v);
    assert!(xml.contains("<MasterKeyChangeRec>0</MasterKeyChangeRec>"));
    assert!(xml.contains("<MasterKeyChangeForce>-1</MasterKeyChangeForce>"));
    assert!(xml.contains("<HistoryMaxSize>6291456</HistoryMaxSize>"));
}

#[test]
fn fmt_12_16_write() {
    let u = Uuid([
        0xac, 0x7e, 0x31, 0xa7, 0x5f, 0xf7, 0x4a, 0x85, 0x90, 0x79, 0x84, 0xcb, 0x77, 0x01, 0x4d,
        0x54,
    ]);
    assert_eq!(uuid_to_text(u), "rH4xp1/3SoWQeYTLdwFNVA==");
    assert_eq!(uuid_to_text(Uuid::ZERO), "AAAAAAAAAAAAAAAAAAAAAA==");
    let mut v = read_doc(&g(""));
    v.root.uuid = u;
    v.meta.recycle_bin = None;
    let xml = write_doc(&v);
    assert!(xml.contains("<UUID>rH4xp1/3SoWQeYTLdwFNVA==</UUID>"));
    assert!(xml.contains("<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>"));
}

#[test]
fn fmt_12_18_colors_kept() {
    for (c, want) in [
        ("red", "<Color>red</Color>"),
        ("#ffef00", "<Color>#ffef00</Color>"),
        ("#FFEF00", "<Color>#FFEF00</Color>"),
        ("", "<Color/>"),
    ] {
        assert_eq!(meta_text("Color", c), want);
    }
}

#[test]
fn fmt_12_18_app_made_color() {
    // The writer writes the stored text exactly; Larsal's color pickers store
    // `#rrggbb` lowercase (the picker itself is E4, MOD-12).
    let mut v = read_doc(&g(&entry(0x10, "")));
    v.root.entries[0].background_color = "#ff0000".into();
    let xml = write_doc(&v);
    assert!(xml.contains("<BackgroundColor>#ff0000</BackgroundColor>"));
}

#[test]
fn fmt_12_18_app_made_color_lowercase() {
    let mut v = read_doc(&g(&entry(0x10, "")));
    v.root.entries[0].background_color = format!("#{:02x}{:02x}{:02x}", 0x1A, 0x2B, 0x3C);
    assert!(write_doc(&v).contains("<BackgroundColor>#1a2b3c</BackgroundColor>"));
}

#[test]
fn fmt_12_18_read_color_not_recased() {
    let mut v = read_doc(&g(&entry(
        0x10,
        "<ForegroundColor>#AABBCC</ForegroundColor>",
    )));
    v.root.entries[0].set_field(
        "Title".into(),
        Field {
            value: SecretString::new("new".into()),
            protected: false,
        },
    );
    assert!(write_doc(&v).contains("<ForegroundColor>#AABBCC</ForegroundColor>"));
}

#[test]
fn fmt_12_22_unknown_element_not_decoded() {
    let xml = rw(&doc(
        "<X Protected=\"True\">QUJD</X><DatabaseName Protected=\"True\">RxjmIZKk</DatabaseName>",
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    ));
    assert!(xml.contains("<DatabaseName>Secret</DatabaseName>"));
    assert!(xml.contains("\t\t<X Protected=\"True\">QUJD</X>\n"));
}

#[test]
fn fmt_12_23_whitespace_kept() {
    assert_eq!(
        meta_text("DatabaseName", "  N  "),
        "<DatabaseName>  N  </DatabaseName>"
    );
    assert_eq!(
        meta_text("DatabaseName", "\u{A0}x\u{A0}"),
        "<DatabaseName>\u{A0}x\u{A0}</DatabaseName>"
    );
}

#[test]
fn fmt_12_25_strip() {
    let v = String::from_utf8(vec![
        0x78, 0xC2, 0x80, 0x79, 0xC2, 0x85, 0x7A, 0xC2, 0x9F, 0x77, 0x7F, 0x76,
    ])
    .unwrap();
    let written = meta_text("DatabaseName", &v);
    let text = written
        .trim_start_matches("<DatabaseName>")
        .trim_end_matches("</DatabaseName>");
    assert_eq!(text.as_bytes(), [0x78, 0x79, 0xC2, 0x85, 0x7A, 0x77, 0x76]);
}

#[test]
fn fmt_12_25_keep_set() {
    let keep = "\t\n \u{D7FF}\u{E000}\u{FFFD}\u{10437}";
    let mut v = read_doc(&g(""));
    v.meta.name = keep.into();
    assert_eq!(read_doc(&write_doc(&v)).meta.name, keep);
}

#[test]
fn fmt_12_25_strip_all() {
    assert_eq!(
        meta_text("DatabaseName", "\u{2}\u{19}\u{FFFE}\u{FFFF}"),
        "<DatabaseName/>"
    );
}

#[test]
fn fmt_12_26_escapes() {
    assert_eq!(
        meta_text("DatabaseName", "a<b>&\"c\"'d"),
        "<DatabaseName>a&lt;b&gt;&amp;&quot;c&quot;'d</DatabaseName>"
    );
}

#[test]
fn fmt_12_26_raw_utf8() {
    let written = meta_text("DatabaseName", "x\u{1F600}y");
    assert!(
        written
            .as_bytes()
            .windows(6)
            .any(|w| w == [0x78, 0xF0, 0x9F, 0x98, 0x80, 0x79])
    );
}

#[test]
fn fmt_12_26_cr() {
    let mut v = read_doc(&g(""));
    v.meta.name = "l1\r\nl2".into();
    let xml = write_doc(&v);
    assert!(xml.contains("<DatabaseName>l1&#13;\nl2</DatabaseName>"));
    assert_eq!(read_doc(&xml).meta.name, "l1\r\nl2");
}

#[test]
fn fmt_12_27_empty() {
    assert_eq!(meta_text("DatabaseName", ""), "<DatabaseName/>");
    assert_eq!(meta_text("DatabaseName", "\u{80}"), "<DatabaseName/>");
}
