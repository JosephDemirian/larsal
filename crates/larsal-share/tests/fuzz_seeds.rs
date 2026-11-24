//! E11-S2: writes the seed corpora of the `share_settings` and
//! `share_container` fuzz targets in fuzz/corpus/ from the INT-08 test
//! cases, so no seed is made by hand. Ignored by default because it writes
//! files; run it once after the card's cases or the targets change:
//! `cargo test -p larsal-share --test fuzz_seeds -- --ignored`
//!
//! Seed formats: see fuzz/fuzz_targets/share_settings.rs and
//! share_container.rs. The seeds hold placeholders (`@S`, `@R`, `@K`) for
//! the names the targets put in, and the zip archives are built by the
//! target, so no seed carries those names as text (AGENTS.md rule 1).

mod common;

use common::*;
use larsal_format::limits::Limits;
use larsal_share::container;
use std::path::PathBuf;

fn write_seeds(target: &str, seeds: &[Vec<u8>]) {
    let dir = PathBuf::from(format!(
        "{}/../../fuzz/corpus/{target}",
        env!("CARGO_MANIFEST_DIR")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

fn joined(mode: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![mode];
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(0x1E);
        }
        out.extend(*p);
    }
    out
}

/// Seeds of `share_settings`: the items of INT-08 cases T02 to T05 and the
/// reader's edge cases.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_share_settings_seeds() {
    let xml: [&[u8]; 6] = [
        b"<?xml version=\"1.0\"?><@S><Type><Import/><Export/></Type><Group>EREREREREREREREREREREQ==</Group><Path>dGVhbS9zaGFyZWQubGFyc2FsdmF1bHQ=</Path><Password>ZGVtby1zaGFyZS0x</Password><KeepGroups>True</KeepGroups></@S>",
        b"<@S><Password>ZGVtby1zaGFyZS0x</Password><Path>dGVhbS5sYXJzYWx2YXVsdA==</Path><Type><Export/><Import/></Type><X><Y/>t</X></@S>",
        b"<@S><Password>Z&#71;Vtby1zaGFyZS0x</Password><KeepGroups>Tru&#x65;</KeepGroups><Path><![CDATA[eA==]]></Path></@S>",
        b"<!DOCTYPE @S [<!ENTITY x \"y\">]><@S><Path>&x;</Path></@S>",
        b"<@S><Type><Import/><Other/><Export/></Type><Group>AAEC</Group><Path>a<b/>c</Path></@S>",
        b"<?xml version=\"1.0\"?><Share><Type><Import/>",
    ];
    let mut seeds: Vec<Vec<u8>> = xml.iter().map(|x| joined(1, &[x])).collect();
    seeds.push(joined(0, &[b"!!!!"]));
    seeds.push(joined(0, &[b"dGVh\nbS5s-YXJz_YWx2YXVsdA=="]));
    write_seeds("share_settings", &seeds);
}

/// Seeds of `share_container`: Larsal's unsigned container of V's Team group
/// (INT-08 case T11) as a file and zipped, with a signature entry (T15) and
/// twice (T16); a document whose subgroup carries a share item (T55) and
/// one with a duplicate entry id (AT-A08); a file of another kind (T17).
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_share_container_seeds() {
    let v = v();
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let d = Dir::new("seeds");
    let p = d.path("team.larsalvault");
    let password = secret(SHARE_PASSWORD);
    container::write_file(&p, &c, &password, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    let file = std::fs::read(&p).unwrap();
    let shared_sub = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><@R><Meta></Meta><Root><Group><UUID>ICAgICAgICAgICAgICAgIA==</UUID><Name>Team</Name><Group><UUID>ISEhISEhISEhISEhISEhIQ==</UUID><Name>Sub</Name><CustomData><Item><Key>@K</Key><Value>x</Value></Item></CustomData><Entry><UUID>DAwMDAwMDAwMDAwMDAwMDA==</UUID><String><Key>Title</Key><Value>Wiki</Value></String></Entry></Group></Group></Root></@R>";
    let duplicate = b"<@R><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Name>G</Name><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID></Entry><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID></Entry></Group></Root></@R>";
    write_seeds(
        "share_container",
        &[
            joined(0x00, &[&file]),
            joined(0x81, &[&file]),
            joined(0x80, &[&file, b"<Signature/>", b"x"]),
            joined(0x83, &[&file, &file]),
            joined(0x40, &[shared_sub]),
            joined(0xC1, &[shared_sub]),
            joined(0x40, &[duplicate]),
            joined(0x00, &[b"%PDF-1.7 demo"]),
        ],
    );
}
