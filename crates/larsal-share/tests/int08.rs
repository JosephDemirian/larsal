//! INT-08 test cases for E11-S2: the share settings item, the share key,
//! reading unsigned and zip containers, and building and writing
//! containers; with the attacks AT-A05, AT-A06, AT-A08 and AT-I06.

mod common;

use common::*;
use larsal_core::edit::is_shared;
use larsal_core::refs::Context;
use larsal_crypto::base64::{self, Form};
use larsal_crypto::hash::sha256;
use larsal_crypto::kdf::KdfParams;
use larsal_format::limits::{Limit, Limits};
use larsal_model::{Argon2Kind, Cipher, Compression, CustomIcon, DeletedObject, Icon, Kdf};
use larsal_share::container::{self, VAULT_ENTRY};
use larsal_share::settings::{self, Item, Mode, ROOT, Settings};
use larsal_share::{Error, NotShare};
use std::path::Path;

fn root_text() -> String {
    String::from_utf8(ROOT.to_vec()).unwrap()
}

/// The XML text of an item value.
fn decoded(value: &str) -> String {
    String::from_utf8(base64::decode(Form::Padded, value).unwrap()).unwrap()
}

/// An item value holding `body` inside the root element, with the
/// declaration.
fn item(body: &str) -> String {
    let r = root_text();
    let xml = format!("<?xml version=\"1.0\"?><{r}>{body}</{r}>");
    base64::encode(Form::Padded, xml.as_bytes())
}

fn b64(s: &str) -> String {
    base64::encode(Form::Padded, s.as_bytes())
}

// ---------------------------------------------------------------------------
// Share settings (INT-08.1 to INT-08.5).

#[test]
fn t01_int08_1_share_group_and_its_subtree_are_shared() {
    let v = v();
    for g in [id(0x20), id(0x21)] {
        assert!(is_shared(&v, g));
        assert_eq!(settings::share_group(&v, g), Some(id(0x20)));
    }
    assert!(!is_shared(&v, id(0x01)));
    assert_eq!(settings::share_group(&v, id(0x01)), None);
    assert!(matches!(
        settings::of(group(&v, id(0x20))),
        Some(Item::Settings(_))
    ));
    assert!(settings::of(group(&v, id(0x21))).is_none());
    // The root may be a share: then the whole vault is shared.
    let mut w = v;
    set_share(&mut w.root, &mut export_to("all.larsalvault"));
    assert_eq!(settings::share_group(&w, id(0x01)), Some(id(0x01)));
    // The nearest share counts.
    assert_eq!(settings::share_group(&w, id(0x21)), Some(id(0x20)));
}

#[test]
fn t02_int08_2_int08_3_synchronize_item_is_written_exactly() {
    let mut s = Settings {
        import: true,
        export: true,
        group: id(0x11),
        path: "team/shared.larsalvault".into(),
        password: secret("demo-share-1"),
        keep_groups: true,
    };
    let value = s.write().unwrap();
    assert!(!value.contains(['\n', '\r', ' ']));
    let r = root_text();
    assert_eq!(
        decoded(&value),
        format!(
            "<?xml version=\"1.0\"?><{r}><Type><Import/><Export/></Type>\
             <Group>EREREREREREREREREREREQ==</Group><Path>dGVhbS9zaGFyZWQubGFyc2FsdmF1bHQ=</Path>\
             <Password>ZGVtby1zaGFyZS0x</Password><KeepGroups>True</KeepGroups></{r}>"
        )
    );
}

#[test]
fn t03_int08_3_import_only_with_empty_password() {
    let mut s = Settings {
        import: true,
        group: id(0x22),
        path: "../in.larsalvault".into(),
        keep_groups: false,
        ..Settings::new()
    };
    let text = decoded(&s.write().unwrap());
    for part in [
        "<Type><Import/></Type>",
        "<Group>IiIiIiIiIiIiIiIiIiIiIg==</Group>",
        "<Path>Li4vaW4ubGFyc2FsdmF1bHQ=</Path>",
        "<Password></Password>",
        "<KeepGroups>False</KeepGroups>",
    ] {
        assert!(text.contains(part), "{part}");
    }
    // Inactive: an empty Type; an empty path as a text element.
    let mut s = Settings::new();
    let text = decoded(&s.write().unwrap());
    assert!(text.contains("<Type/><Group>"), "{text}");
    assert!(text.contains("<Path></Path>"), "{text}");
}

#[test]
fn t04_int08_3_children_in_any_order_unknown_skipped_keep_missing() {
    let value = item(&format!(
        "<Password>{}</Password><Path>{}</Path><Type><Export/><Import/></Type><X><Y/>t</X>",
        b64("demo-share-1"),
        b64("team.larsalvault")
    ));
    let s = settings::read(&value).unwrap();
    assert_eq!(s.mode(), Mode::Synchronize);
    assert_eq!(s.path, "team.larsalvault");
    assert_eq!(s.password.expose(), "demo-share-1");
    assert!(!s.keep_groups, "a missing KeepGroups is false");
}

#[test]
fn t05_int08_3_int08_4_wrong_root_is_invalid_but_shared() {
    let xml = "<?xml version=\"1.0\"?><Share><Type><Export/></Type></Share>";
    let value = base64::encode(Form::Padded, xml.as_bytes());
    assert!(settings::read(&value).is_none());
    let mut v = v();
    let team = v.root.groups.get_mut(0).unwrap();
    team.custom_data.items.get_mut(0).unwrap().value = value;
    assert!(matches!(
        settings::of(group(&v, id(0x20))),
        Some(Item::Invalid)
    ));
    assert!(is_shared(&v, id(0x21)));
}

#[test]
fn int08_4_items_that_decode_to_nothing_usable_are_invalid() {
    let r = root_text();
    let raw = |x: &str| base64::encode(Form::Padded, x.as_bytes());
    let cases = [
        String::new(),
        "!!!!".to_owned(),
        raw("not xml"),
        raw(&format!("<!DOCTYPE {r}><{r}/>")),
        raw(&format!("<{r}><Path>&unknown;</Path></{r}>")),
        raw(&format!("<{r}><Path>a<b/>c</Path></{r}>")),
        raw(&format!("<{r}><Type><Import/>")),
        raw(&format!("<{r}><Type></Path></{r}>")),
        raw(&format!("text<{r}/>")),
        raw(&format!("<x/><{r}/>")),
        raw(&format!("<{}/>", r.to_lowercase())),
    ];
    for (i, c) in cases.iter().enumerate() {
        assert!(settings::read(c).is_none(), "case {i}");
    }
    // An empty root is readable: Inactive, no path, so never valid.
    let s = settings::read(&raw(&format!("<{r}/>"))).unwrap();
    assert_eq!(s.mode(), Mode::Inactive);
    assert!(!s.valid());
}

#[test]
fn t06_int08_4_export_without_path_is_not_valid() {
    let mut s = export_to("");
    assert!(!s.exporting() && !s.importing() && !s.valid());
    s.path = "x.larsalvault".into();
    assert!(s.exporting() && !s.importing() && s.valid());
    s.export = false;
    assert!(!s.valid(), "Inactive with a path");
    s.import = true;
    assert!(s.importing() && !s.exporting() && s.valid());
}

#[test]
fn int08_2_value_and_fields_are_read_leniently() {
    let value = item(&format!(
        "<Type><Import/></Type><Path>{}</Path><Password>{}</Password><KeepGroups>True</KeepGroups>",
        "dGVh\nbS5s-YXJz_YWx2YXVsdA==",
        b64("pw")
    ));
    // Line breaks and characters outside the alphabet in the value too.
    let wrapped: String = value
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i % 10 == 9 {
                vec![c, '\n', '*']
            } else {
                vec![c]
            }
        })
        .collect();
    for v in [&value, &wrapped] {
        let s = settings::read(v).unwrap();
        assert_eq!(s.path, "team.larsalvault");
        assert_eq!(s.password.expose(), "pw");
        assert!(s.keep_groups && s.importing());
    }
}

#[test]
fn int08_3_entities_and_character_references_in_values() {
    // `&#100;` is the d of `ZGVtby1zaGFyZS0x`.
    let value = item("<Password>Z&#71;Vtby1zaGFyZS0x</Password><KeepGroups>Tru&#x65;</KeepGroups>");
    let s = settings::read(&value).unwrap();
    assert_eq!(s.password.expose(), "demo-share-1");
    assert!(s.keep_groups);
    let value = item("<Path><![CDATA[eA==]]></Path>");
    assert_eq!(settings::read(&value).unwrap().path, "x");
}

#[test]
fn int08_3_keep_groups_true_only_for_exact_text() {
    for (text, keep) in [
        ("True", true),
        ("true", false),
        ("TRUE", false),
        (" True", false),
        ("1", false),
    ] {
        let s = settings::read(&item(&format!("<KeepGroups>{text}</KeepGroups>"))).unwrap();
        assert_eq!(s.keep_groups, keep, "{text}");
    }
}

#[test]
fn int08_3_type_reading_stops_at_the_first_other_child() {
    let s = settings::read(&item("<Type><Import/><Other/><Export/></Type>")).unwrap();
    assert_eq!(s.mode(), Mode::Import);
    let s = settings::read(&item("<Type><Import>x<y/></Import><Export/></Type>")).unwrap();
    assert_eq!(s.mode(), Mode::Synchronize);
    // A repeated Type: the later one wins, its flags are not added.
    let s = settings::read(&item("<Type><Import/></Type><Type><Export/></Type>")).unwrap();
    assert_eq!(s.mode(), Mode::Export);
    let s = settings::read(&item("<Type><Import/><Export/></Type><Type/>")).unwrap();
    assert_eq!(s.mode(), Mode::Inactive);
}

#[test]
fn int08_3_missing_group_is_zero_then_random_on_write() {
    let mut s = settings::read(&item("<Type><Import/></Type>")).unwrap();
    assert!(s.group.is_zero());
    let first = s.write().unwrap();
    assert!(!s.group.is_zero());
    let again = settings::read(&first).unwrap();
    assert_eq!(again.group, s.group);
    // The id stays once drawn: the next write is the same text.
    assert_eq!(s.write().unwrap(), first);
    // A Group of another length reads as missing.
    let s = settings::read(&item("<Group>AAEC</Group>")).unwrap();
    assert!(s.group.is_zero());
}

#[test]
fn t65_int08_3_every_new_share_gets_its_own_id() {
    let (mut a, mut b) = (Settings::new(), Settings::new());
    a.import = true;
    b.import = true;
    a.path = "a.larsalvault".into();
    b.path = "a.larsalvault".into();
    let (va, vb) = (a.write().unwrap(), b.write().unwrap());
    let (ga, gb) = (
        settings::read(&va).unwrap().group,
        settings::read(&vb).unwrap().group,
    );
    assert!(!ga.is_zero() && !gb.is_zero());
    assert_ne!(ga, gb);
}

#[test]
fn int08_21_new_settings_start_inactive_with_keep_on() {
    let s = Settings::new();
    assert_eq!(s.mode(), Mode::Inactive);
    assert!(s.keep_groups && s.path.is_empty() && s.password.is_empty());
}

#[test]
fn t07_int08_5_path_resolution() {
    let v = Path::new("/tmp/spec-int08/v.larsalvault");
    let r = |p: &str| settings::resolve(p, Some(v));
    assert_eq!(
        r("team.larsalvault").unwrap(),
        Path::new("/tmp/spec-int08/team.larsalvault")
    );
    assert_eq!(
        r("~/team.larsalvault").unwrap(),
        Path::new("/tmp/spec-int08/~/team.larsalvault")
    );
    assert_eq!(
        r("../in.larsalvault").unwrap(),
        Path::new("/tmp/spec-int08/../in.larsalvault")
    );
    assert_eq!(
        r("/x/y.larsalvault").unwrap(),
        Path::new("/x/y.larsalvault")
    );
    assert_eq!(r(""), None);
    assert_eq!(settings::resolve("team.larsalvault", None), None);
}

#[test]
fn t07_int08_5_export_writes_beside_the_vault_and_fails_without_the_folder() {
    let d = Dir::new("t07");
    let vault_file = d.path("v.larsalvault");
    let v = v();
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let pw = secret(SHARE_PASSWORD);
    let to = settings::resolve("~/team.larsalvault", Some(&vault_file)).unwrap();
    let e = container::write_file(&to, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap_err();
    assert_eq!(e, Error::Io(std::io::ErrorKind::NotFound));
    std::fs::create_dir(d.path("~")).unwrap();
    container::write_file(&to, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    assert!(d.path("~/team.larsalvault").is_file());
}

#[test]
fn int08_39_debug_and_errors_hold_no_password_or_path() {
    let mut s = export_to("secret-place/team.larsalvault");
    s.password = secret("hunter2-demo");
    let value = s.write().unwrap();
    let read = settings::read(&value).unwrap();
    for text in [
        format!("{s:?}"),
        format!("{read:?}"),
        format!("{:?}", Item::Settings(read)),
    ] {
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("secret-place"), "{text}");
        assert!(text.contains("[hidden]"), "{text}");
    }
    // A container read with that password: no error names it.
    let v = v();
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let d = Dir::new("t62");
    let p = d.path("team.larsalvault");
    container::write_file(&p, &c, &s.password, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    let wrong = container::open_file(&p, &secret("other"), &mut host(), &Limits::DEFAULT);
    let e = wrong.unwrap_err();
    for text in [format!("{e}"), format!("{e:?}")] {
        assert!(
            !text.contains("hunter2") && !text.contains("other"),
            "{text}"
        );
    }
}

mod round_trip {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        // Rust rule 10: every item Larsal writes reads back the same.
        #[test]
        fn int08_3_item_round_trip(
            import: bool,
            export: bool,
            group in proptest::array::uniform16(any::<u8>()),
            path in ".{0,40}",
            password in ".{0,40}",
            keep: bool,
        ) {
            let mut s = Settings {
                import,
                export,
                group: larsal_model::Uuid(group),
                path,
                password: secret(&password),
                keep_groups: keep,
            };
            let value = s.write().unwrap();
            let r = settings::read(&value).unwrap();
            prop_assert_eq!(r.mode(), s.mode());
            prop_assert_eq!(r.group, s.group);
            prop_assert_eq!(&r.path, &s.path);
            prop_assert_eq!(r.password.expose(), s.password.expose());
            prop_assert_eq!(r.keep_groups, s.keep_groups);
        }
    }
}

// ---------------------------------------------------------------------------
// Containers: the share key and reading (INT-08.6, INT-08.8, INT-08.9).

/// Writes the Team container of `v` with `password` and returns its bytes.
fn team_container(v: &larsal_model::Vault, keep: bool, password: &str) -> Vec<u8> {
    let c = container::build(id(0x20), keep, v, NOW).unwrap();
    let d = Dir::new("bytes");
    let p = d.path("team.larsalvault");
    container::write_file(
        &p,
        &c,
        &secret(password),
        &mut host(),
        &Limits::DEFAULT,
        &[],
    )
    .unwrap();
    std::fs::read(p).unwrap()
}

fn open(bytes: &[u8], password: &str) -> Result<larsal_format::OpenedVault, Error> {
    container::open(bytes, &secret(password), &mut host(), &Limits::DEFAULT)
}

#[test]
fn t08_int08_6_empty_share_password_is_a_password_part() {
    let bytes = team_container(&v(), true, "");
    let opened = open(&bytes, "").unwrap();
    assert_eq!(opened.vault.meta.name, "Team");
    // No password at all is not the empty password: with no other part it
    // is no key, refused before any key work (FMT-04.16).
    let none = larsal_format::open(
        &bytes,
        &larsal_format::keys::Credentials::default(),
        &mut host(),
        &Limits::DEFAULT,
        None,
    );
    assert_eq!(none.err(), Some(larsal_format::Error::NoCredentials));
    // The share key has exactly the one password part: SHA-256("").
    let empty = secret("");
    let key = container::credentials(&empty);
    assert!(key.key_file.is_none() && key.hardware_key.is_none());
    assert_eq!(
        hex(larsal_format::keys::password_part(key.password.unwrap()).expose()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // Reference-made (E11-S1): kept file e opens with an empty password.
    let e = reference_file("ref-2.7.11-unsigned-export-empty-share-password.larsalvault");
    let opened = open(&e, "").unwrap();
    assert_eq!(titles(&opened.vault.root), ["Em1"]);
    assert_eq!(
        open(&e, "x").unwrap_err(),
        Error::Vault(larsal_format::Error::WrongKey)
    );
}

#[test]
fn t46_int08_28_signed_suffix_still_gets_an_unsigned_container() {
    // INT-08.11, INT-08.28 option (a): the reference's signed suffix, stored
    // encoded, gets a plain vault file, never a zip.
    let suffix = [
        0x2E, 0x6B, 0x64, 0x62, 0x78, 0x2E, 0x73, 0x68, 0x61, 0x72, 0x65,
    ];
    let name = format!("team{}", std::str::from_utf8(&suffix).unwrap());
    let v = v();
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let d = Dir::new("t46");
    let p = d.path(&name);
    let pw = secret(SHARE_PASSWORD);
    container::write_file(&p, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    let bytes = std::fs::read(&p).unwrap();
    assert_eq!(bytes.get(..4), Some(&[0x03, 0xD9, 0xA2, 0x9A][..]));
    let o = container::open_file(&p, &pw, &mut host(), &Limits::DEFAULT).unwrap();
    assert_eq!(o.vault.root.name, "Team");
    assert_eq!(titles(&o.vault.root), ["Mail", "Bank"]);
}

#[test]
fn t11_int08_8_int08_12_container_content_and_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let v = v();
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let d = Dir::new("t11");
    let p = d.path("team.larsalvault");
    // An existing file of another mode and a link are replaced, 0600.
    std::fs::write(&p, b"old").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pw = secret(SHARE_PASSWORD);
    container::write_file(&p, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = std::fs::read(&p).unwrap();
    assert_eq!(bytes.get(..4), Some(&[0x03, 0xD9, 0xA2, 0x9A][..]));
    let o = container::open_file(&p, &pw, &mut host(), &Limits::DEFAULT).unwrap();
    let w = &o.vault;
    assert_eq!(w.meta.name, "Team");
    assert!(!w.meta.recycle_bin_enabled);
    assert_eq!(w.root.uuid, id(0x20));
    assert_eq!(w.root.name, "Team");
    assert!(w.root.custom_data.get(&share_key()).is_none());
    assert_eq!(titles(&w.root), ["Mail", "Bank"]);
    let mail = find(w, id(0x0A));
    assert_eq!(mail.value("Password"), "pw-1");
    assert_eq!(mail.history.len(), 1);
    assert_eq!(mail.history[0].value("Password"), "pw-0");
    assert_eq!(find(w, id(0x0B)).value("Password"), "pw-b");
    let sub = group(w, id(0x21));
    assert_eq!(titles(sub), ["Wiki"]);
    assert_eq!(o.vault.read_version.unwrap().major, 4);
    // A symbolic link at the path is replaced, never written through.
    let target = d.path("elsewhere");
    std::fs::write(&target, b"keep").unwrap();
    let link = d.path("link.larsalvault");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    container::write_file(&link, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(!std::fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(
        std::fs::metadata(&link).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn t12_int08_12_keep_groups_off_copies_the_group_alone() {
    let o = open(&team_container(&v(), false, SHARE_PASSWORD), SHARE_PASSWORD).unwrap();
    assert_eq!(titles(&o.vault.root), ["Mail", "Bank"]);
    assert!(o.vault.root.groups.is_empty());
    assert!(o.vault.root.all_entries().all(|e| e.uuid != id(0x0C)));
}

#[test]
fn t13_int08_12_int08_33_no_share_item_in_the_container() {
    let mut v = v();
    let sub = v.root.groups[0].groups.get_mut(0).unwrap();
    let mut s = Settings {
        import: true,
        path: "x.larsalvault".into(),
        password: secret("p"),
        ..Settings::new()
    };
    set_share(sub, &mut s);
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    assert!(
        c.root
            .subtree()
            .iter()
            .all(|g| g.custom_data.get(&share_key()).is_none())
    );
    // Other custom data of the groups is kept.
    let mut v = v;
    v.root.groups[0].groups[0]
        .custom_data
        .items
        .push(larsal_model::CustomDataItem {
            key: "other".into(),
            value: "kept".into(),
            last_modified: None,
            unknown: Vec::new(),
        });
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    assert_eq!(group(&c, id(0x21)).custom_data.get("other"), Some("kept"));
}

#[test]
fn t55_int08_33_share_items_below_the_root_are_dropped_on_read() {
    // A crafted container (written without Larsal's builder) whose child
    // group carries a share item, as a reference export can.
    let mut v = v();
    v.root.groups[0].groups[0].custom_data = v.root.groups[0].custom_data.clone();
    let mut team = v.root.groups.remove(0);
    team.custom_data = Default::default();
    let mut crafted = larsal_model::Vault::new(team, T0);
    crafted.encryption.kdf = Kdf::AesKdf { rounds: 1_000 };
    let pw = secret(SHARE_PASSWORD);
    let Ok(larsal_format::Saved::File(f)) = larsal_format::save(
        &crafted,
        &container::credentials(&pw),
        None,
        &mut host(),
        &Limits::DEFAULT,
        None,
    ) else {
        panic!("saved")
    };
    let o = open(&f.bytes, SHARE_PASSWORD).unwrap();
    assert!(
        group(&o.vault, id(0x21))
            .custom_data
            .get(&share_key())
            .is_none()
    );
}

#[test]
fn t14_int08_9_reference_zip_layout() {
    for (name, sum) in [
        (
            "ref-2.7.11-signed-export-team-keepgroups-on.zip.hex",
            "e448ac54916de512abc287a7c3480dd985bab2ab61f4e7981aa93e2c290e7951",
        ),
        (
            "ref-2.7.11-signed-export-team-empty-signer-name.zip.hex",
            "9860614cb686349442febd4815585d887ea89431cbd05b0d0f69da7f5c9db86a",
        ),
    ] {
        let z = reference_file(name);
        assert_eq!(hex(sha256(&[&z]).expose()), sum, "{name}");
        let u16_at = |at: usize| u16::from_le_bytes([z[at], z[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes(z[at..at + 4].try_into().unwrap());
        // The plain 22-byte end record, no ZIP64 end record or locator.
        let end = z.len() - 22;
        assert_eq!(u32_at(end), 0x0605_4b50);
        assert_eq!(u16_at(end + 10), 2);
        assert!(!z.windows(4).any(|w| w == [0x50, 0x4B, 0x06, 0x06]));
        assert!(!z.windows(4).any(|w| w == [0x50, 0x4B, 0x06, 0x07]));
        let mut at = u32_at(end + 16) as usize;
        let mut names = Vec::new();
        for _ in 0..2 {
            assert_eq!(u32_at(at), 0x0201_4b50);
            assert_eq!((u16_at(at + 4), u16_at(at + 6)), (0, 20), "made by, needed");
            assert_eq!(u16_at(at + 8), 0x0002);
            assert_eq!(u16_at(at + 10), 8, "deflate");
            assert_eq!((u16_at(at + 12), u16_at(at + 14)), (0, 0), "time, date");
            assert_eq!(u16_at(at + 30), 0, "no central extra field");
            let n = u16_at(at + 28) as usize;
            names.push(z[at + 46..at + 46 + n].to_vec());
            let local = u32_at(at + 42) as usize;
            assert_eq!(u32_at(local), 0x0403_4b50);
            assert_eq!(u16_at(local + 4), 45);
            assert_eq!(u16_at(local + 6) & 0x0008, 0, "no data descriptor");
            assert_eq!(u32_at(local + 18), u32_at(at + 20), "real sizes");
            assert_eq!(u32_at(local + 22), u32_at(at + 24), "real sizes");
            assert_eq!(u16_at(local + 28), 20);
            let extra = local + 30 + u16_at(local + 26) as usize;
            assert_eq!(&z[extra..extra + 4], &[0x01, 0x00, 0x10, 0x00]);
            assert!(z[extra + 4..extra + 20].iter().all(|&b| b == 0));
            at += 46 + n;
        }
        assert_eq!(names[0], b"container.share.signature");
        assert_eq!(names[1], VAULT_ENTRY);
    }
}

#[test]
fn t66_int08_9_int08_10_reference_zips_open_through_larsal_cores_reader() {
    for (name, signature) in [
        ("ref-2.7.11-signed-export-team-keepgroups-on.zip.hex", 1_020),
        ("ref-2.7.11-signed-export-team-empty-signer-name.zip.hex", 0),
    ] {
        let z = reference_file(name);
        let a = larsal_core::import::zip::open(&z).unwrap();
        let m = a.members();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].name, "container.share.signature");
        assert_eq!(m[1].name.as_bytes(), VAULT_ENTRY);
        let lim = larsal_core::import::Limit::File;
        assert_eq!(a.read(&m[0], 1 << 20, lim).unwrap().len(), signature);
        let entry = a.read(&m[1], 1 << 20, lim).unwrap();
        assert_eq!(entry.len(), 2_279);
        assert_eq!(&entry.expose()[..4], &[0x03, 0xD9, 0xA2, 0x9A]);
        let o = open(&z, SHARE_PASSWORD).unwrap();
        let w = &o.vault;
        assert_eq!(w.meta.name, "Team");
        assert_eq!(
            w.read_version,
            Some(larsal_model::FileVersion { major: 4, minor: 0 })
        );
        assert_eq!(w.root.uuid, id(0x20));
        assert_eq!(titles(&w.root), ["Mail", "Bank", "Alias", "Alias2"]);
        let sub = group(w, id(0x21));
        assert_eq!(titles(sub), ["Wiki"]);
        // INT-08.33: Sub's share item (Import, password `p`) is dropped.
        assert!(sub.custom_data.get(&share_key()).is_none());
        assert_eq!(find(w, id(0x0E)).value("Password"), "pw-h");
    }
}

#[test]
fn int08_8_reference_unsigned_containers_open() {
    for (name, password, sum, titles_, version) in [
        (
            "ref-2.7.11-unsigned-export-plain-keepgroups-off.larsalvault",
            "demo-share-2",
            "f2886a3e169513d1b5057b16c6f79a509738af16aad651eb8c21bc6484c65e89",
            ["P1"],
            (3, 1),
        ),
        (
            "ref-2.7.11-unsigned-export-capital-signed-suffix.larsalvault",
            "demo-share-3",
            "d12f98a366bd905fb9845c327073ca3fa32d61a54a0420e230510470f102a629",
            ["C1"],
            (3, 1),
        ),
        (
            "ref-2.7.11-unsigned-export-empty-share-password.larsalvault",
            "",
            "e37593e8cbdd0f2925fd459c87b5ef7364117bbeead5769003d04884a3a82fa6",
            ["Em1"],
            (3, 1),
        ),
    ] {
        let f = reference_file(name);
        assert_eq!(hex(sha256(&[&f]).expose()), sum, "{name}");
        let o = open(&f, password).unwrap();
        assert_eq!(titles(&o.vault.root), titles_, "{name}");
        assert!(o.vault.root.groups.is_empty(), "{name}");
        let v = o.vault.read_version.unwrap();
        assert_eq!((v.major, v.minor), version, "{name}");
    }
}

#[test]
fn t15_int08_9_other_members_are_ignored() {
    let inner = team_container(&v(), true, SHARE_PASSWORD);
    for z in [
        zip(&[
            member(b"a.txt", b"hello", true),
            member(VAULT_ENTRY, &inner, true),
        ]),
        zip(&[
            member(VAULT_ENTRY, &inner, false),
            member(b"a.txt", b"x", false),
        ]),
    ] {
        let o = open(&z, SHARE_PASSWORD).unwrap();
        assert_eq!(o.vault.meta.name, "Team");
    }
}

#[test]
fn t16_int08_9_two_vault_entries_is_not_a_share_file() {
    let inner = team_container(&v(), true, SHARE_PASSWORD);
    let z = zip(&[
        member(VAULT_ENTRY, &inner, true),
        member(VAULT_ENTRY, &inner, true),
    ]);
    assert_eq!(
        open(&z, SHARE_PASSWORD).unwrap_err(),
        Error::NotShare(NotShare::TwoVaults)
    );
}

#[test]
fn int08_9_no_vault_entry_or_another_case_is_not_a_share_file() {
    let inner = team_container(&v(), true, SHARE_PASSWORD);
    let upper = VAULT_ENTRY.to_ascii_uppercase();
    for z in [
        zip(&[member(b"a.txt", b"x", false)]),
        zip(&[member(&upper, &inner, true)]),
    ] {
        assert_eq!(
            open(&z, SHARE_PASSWORD).unwrap_err(),
            Error::NotShare(NotShare::NoVault)
        );
    }
}

#[test]
fn t17_int08_9_other_first_bytes_are_not_a_share_file() {
    for f in [
        &b"%PDF-1.7 demo"[..],
        b"",
        b"PK",
        b"PK\x05\x06",
        b"\x03\xD9\xA2",
    ] {
        assert_eq!(
            open(f, SHARE_PASSWORD).unwrap_err(),
            Error::NotShare(NotShare::UnknownKind)
        );
    }
}

#[test]
fn int08_9_damaged_or_unsupported_archives() {
    let inner = team_container(&v(), true, SHARE_PASSWORD);
    let mut z = zip(&[member(VAULT_ENTRY, &inner, true)]);
    // Cut off: no end record.
    let cut = &z[..z.len() - 10];
    assert_eq!(
        open(cut, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::Corrupt)
    );
    // A flipped content byte fails the CRC-32 check.
    let body = 30 + VAULT_ENTRY.len() + 10;
    z[body] ^= 0xFF;
    assert!(matches!(
        open(&z, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::Corrupt)
    ));
    // ZIP64 sizes are refused as unsupported.
    let z64 = zip(&[Member {
        declared: Some(u32::MAX),
        ..member(VAULT_ENTRY, b"x", true)
    }]);
    assert_eq!(
        open(&z64, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::Unsupported)
    );
}

#[test]
fn t27_int08_16_int08_6_wrong_share_password() {
    let bytes = team_container(&v(), true, "other");
    assert_eq!(
        open(&bytes, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::WrongKey)
    );
}

#[test]
fn int08_16_missing_or_unreadable_file_gives_the_system_reason() {
    let d = Dir::new("io");
    let pw = secret(SHARE_PASSWORD);
    let missing = container::open_file(&d.path("none"), &pw, &mut host(), &Limits::DEFAULT);
    assert_eq!(
        missing.unwrap_err(),
        Error::Io(std::io::ErrorKind::NotFound)
    );
    // A folder, not a regular file, is refused before any read.
    let folder = container::open_file(&d.0, &pw, &mut host(), &Limits::DEFAULT);
    assert_eq!(
        folder.unwrap_err(),
        Error::Io(std::io::ErrorKind::InvalidInput)
    );
}

// ---------------------------------------------------------------------------
// Hostile containers (INT-08.36): AT-A05, AT-A06, AT-A08.

/// `file` (version 4) with its KDF map's memory field set to `m` bytes and
/// the header hash made right again, so the cost check is reached.
fn with_argon2_memory(file: &[u8], m: u64) -> Vec<u8> {
    let mut f = file.to_vec();
    let h = larsal_format::header::read_header(&f, &Limits::DEFAULT).unwrap();
    let key = [0x05, 0x01, 0, 0, 0, b'M', 0x08, 0, 0, 0];
    let at = f[..h.len]
        .windows(key.len())
        .position(|w| w == key)
        .unwrap()
        + key.len();
    f[at..at + 8].copy_from_slice(&m.to_le_bytes());
    let hash = sha256(&[&f[..h.len]]);
    f[h.len..h.len + 32].copy_from_slice(hash.expose());
    f
}

fn argon2_container() -> Vec<u8> {
    let mut v = v();
    v.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 1,
        memory_kib: 64,
        lanes: 1,
    };
    team_container(&v, true, SHARE_PASSWORD)
}

#[test]
fn t58_at_a05_kdf_cost_refused_without_a_question() {
    let file = argon2_container();
    assert!(open(&file, SHARE_PASSWORD).is_ok());
    let start = std::time::Instant::now();
    // Above the Mac's memory: refused (CRY-02.14 refuse rule).
    let huge = with_argon2_memory(&file, ((1u64 << 32) - 1) << 10);
    assert_eq!(
        open(&huge, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::TooLarge(Limit::KdfCost))
    );
    // 4 TiB is outside the format's range.
    let four_tib = with_argon2_memory(&file, 1u64 << 42);
    assert_eq!(
        open(&four_tib, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::Unsupported)
    );
    // The ask band (2 GiB) would need a question: refused, nobody is asked.
    let ask = with_argon2_memory(&file, 2 << 30);
    assert_eq!(
        open(&ask, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::TooLarge(Limit::KdfCost))
    );
    // No key work ran: three refusals in well under the time of one 2 GiB
    // Argon2 run.
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
    // With the ask band lowered below the file's 64 KiB, the plain
    // container is refused too: a question is never answered for the user.
    let low = Limits {
        kdf: larsal_crypto::kdf::Ceilings {
            ask_memory_kib: 32,
            ..Limits::DEFAULT.kdf
        },
        ..Limits::DEFAULT
    };
    let pw = secret(SHARE_PASSWORD);
    assert_eq!(
        container::open(&file, &pw, &mut host(), &low).unwrap_err(),
        Error::Vault(larsal_format::Error::TooLarge(Limit::KdfCost))
    );
}

#[test]
fn t59_at_a06_zip_entry_stops_at_the_vault_file_limit() {
    // Declared over the vault file limit: refused before any inflating.
    let z = zip(&[Member {
        declared: Some(u32::MAX - 1),
        ..member(VAULT_ENTRY, b"x", true)
    }]);
    assert_eq!(
        open(&z, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::TooLarge(Limit::TotalFile))
    );
    // A lowered limit holds the same way (FMT-08.12: every limit can be
    // lowered), and the archive itself is checked against it too.
    let inner = team_container(&v(), true, SHARE_PASSWORD);
    let z = zip(&[member(VAULT_ENTRY, &inner, true)]);
    let small = Limits {
        total_file: inner.len() - 1,
        ..Limits::DEFAULT
    };
    let pw = secret(SHARE_PASSWORD);
    assert_eq!(
        container::open(&z, &pw, &mut host(), &small).unwrap_err(),
        Error::Vault(larsal_format::Error::TooLarge(Limit::TotalFile))
    );
    let tiny = Limits {
        total_file: z.len() - 1,
        ..Limits::DEFAULT
    };
    assert_eq!(
        container::open(&z, &pw, &mut host(), &tiny).unwrap_err(),
        Error::Vault(larsal_format::Error::TooLarge(Limit::TotalFile))
    );
    // A bomb that lies about its size: 256 MiB of zeros declared as 1 KiB
    // stops as soon as the output passes the declared size.
    let zeros = vec![0u8; 256 << 20];
    let z = zip(&[Member {
        declared: Some(1_024),
        ..member(VAULT_ENTRY, &zeros, true)
    }]);
    drop(zeros);
    let start = std::time::Instant::now();
    assert_eq!(
        open(&z, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::Corrupt)
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

/// A version 3.1 file around the document `xml` under the share password
/// (FMT-17; AES-KDF 100 rounds, no gzip), so a hostile document gets past
/// the key and the encryption (AT-A08).
fn seal_v3(xml: &[u8], password: &str) -> Vec<u8> {
    use larsal_crypto::cipher::{self, Cipher as C};
    use larsal_format::keys::{cipher_key_v3, composite_key, password_part};
    let (seed, kdf_seed, iv, start, stream_key) =
        ([0x11; 32], [0x4B; 32], [0x22; 16], [0x39; 32], [0x38; 32]);
    let field = |out: &mut Vec<u8>, id: u8, data: &[u8]| {
        out.push(id);
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
    };
    let mut head = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];
    field(
        &mut head,
        2,
        &larsal_format::header::cipher_id(C::Aes256Cbc),
    );
    field(&mut head, 3, &0u32.to_le_bytes());
    field(&mut head, 4, &seed);
    field(&mut head, 5, &kdf_seed);
    field(&mut head, 6, &100u64.to_le_bytes());
    field(&mut head, 7, &iv);
    field(&mut head, 8, &stream_key);
    field(&mut head, 9, &start);
    field(&mut head, 10, &2u32.to_le_bytes());
    field(&mut head, 0, b"\r\n\r\n");
    let mut stream = start.to_vec();
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(sha256(&[xml]).expose());
    stream.extend_from_slice(&(xml.len() as u32).to_le_bytes());
    stream.extend_from_slice(xml);
    stream.extend_from_slice(&1u32.to_le_bytes());
    stream.extend_from_slice(&[0; 32]);
    stream.extend_from_slice(&0u32.to_le_bytes());
    let params = KdfParams::AesKdf {
        rounds: 100,
        seed: kdf_seed.to_vec(),
    };
    let composite = composite_key(Some(&password_part(&secret(password))), None, None);
    let larsal_crypto::kdf::Verdict::Run(c) =
        larsal_crypto::kdf::assess(&params, &mut host(), &Limits::DEFAULT.kdf, None).unwrap()
    else {
        panic!("100 rounds need no question")
    };
    let t = larsal_crypto::kdf::derive(&composite, &c).unwrap();
    let key = cipher_key_v3(&seed, None, &t);
    [
        head,
        cipher::encrypt(C::Aes256Cbc, &key, &iv, &stream).unwrap(),
    ]
    .concat()
}

/// The document root element name, stored encoded (AGENTS rule 1).
const DOCUMENT_ROOT: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
];

fn document(root: &str) -> Vec<u8> {
    let r = String::from_utf8(DOCUMENT_ROOT.to_vec()).unwrap();
    format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><{r}><Root>{root}</Root></{r}>").into_bytes()
}

#[test]
fn at_a08_hostile_document_inside_a_container_is_handled() {
    let uid = |n: u8| base64::encode(Form::Padded, &[n; 16]);
    let e = |n: u8| format!("<Entry><UUID>{}</UUID></Entry>", uid(n));
    let g = |n: u8, inner: &str| {
        format!(
            "<Group><UUID>{}</UUID><Name>G</Name>{inner}</Group>",
            uid(n)
        )
    };
    let deep = (0..600).fold(String::new(), |acc, i| g((i % 200 + 1) as u8, &acc));
    let r = String::from_utf8(DOCUMENT_ROOT.to_vec()).unwrap();
    let docs: Vec<Vec<u8>> = vec![
        document(&g(1, "")),
        document(&g(1, &format!("{}{}", e(2), e(2)))),
        document(&g(1, &g(1, &e(3)))),
        document(&g(
            1,
            &format!(
                "<Entry><Binary><Key>a</Key><Value Ref=\"9\"/></Binary><UUID>{}</UUID></Entry>",
                uid(4)
            ),
        )),
        document("<Group></Group>"),
        document(""),
        document(&deep),
        format!("<!DOCTYPE {r} [<!ENTITY x \"y\">]><{r}><Root/></{r}>").into_bytes(),
        b"<not closed".to_vec(),
        vec![0xFF, 0xFE, 0x00],
        document(&g(1, &(0..2_000).map(|_| e(5)).collect::<String>())),
    ];
    let small = Limits {
        entries: 1_000,
        ..Limits::DEFAULT
    };
    let pw = secret(SHARE_PASSWORD);
    let mut opened = 0;
    for (i, d) in docs.iter().enumerate() {
        let f = seal_v3(d, SHARE_PASSWORD);
        match container::open(&f, &pw, &mut host(), &small) {
            Ok(o) => {
                opened += 1;
                assert_eq!(larsal_model::invariants::check(&o.vault), Ok(()), "doc {i}");
            }
            Err(Error::Vault(_)) => {}
            Err(other) => panic!("doc {i}: {other:?}"),
        }
    }
    assert!(opened >= 1, "the plain document opens");
    // The same through a zip container.
    let f = seal_v3(&docs[1], SHARE_PASSWORD);
    let z = zip(&[member(VAULT_ENTRY, &f, true)]);
    let o = container::open(&z, &pw, &mut host(), &small).unwrap();
    assert_eq!(larsal_model::invariants::check(&o.vault), Ok(()));
}

// ---------------------------------------------------------------------------
// Building and writing (INT-08.12 to INT-08.14, INT-08.35).

#[test]
fn int08_12_name_bin_icons_and_deleted_objects() {
    let mut v = v();
    let icon = |n: u8| CustomIcon {
        uuid: id(n),
        name: String::new(),
        last_modified: None,
        data: vec![n],
        unknown: Vec::new(),
    };
    v.meta.custom_icons = vec![icon(0x71), icon(0x72), icon(0x73), icon(0x74)];
    let team = &mut v.root.groups[0];
    team.icon = Icon::Custom(id(0x71));
    let mut h = team.entries[1].duplicate(false);
    h.icon = Icon::Custom(id(0x73));
    team.entries[1].history.push(h);
    team.groups[0].entries[0].icon = Icon::Custom(id(0x72));
    v.deleted_objects.push(DeletedObject {
        uuid: id(0x99),
        deleted_at: T0,
        unknown: Vec::new(),
    });
    // Step 1 (F-143): no vault metadata of the source enters a container.
    v.meta.description = "demo-description".into();
    v.meta.default_user_name = "demo-user".into();
    v.meta.custom_data.items.push(larsal_model::CustomDataItem {
        key: "demo-key".into(),
        value: "demo-value".into(),
        last_modified: None,
        unknown: Vec::new(),
    });
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    assert_eq!(c.meta.name, "Team");
    assert_eq!(c.meta.description, "");
    assert_eq!(c.meta.default_user_name, "");
    assert!(c.meta.custom_data.is_empty());
    assert!(!c.meta.recycle_bin_enabled);
    let ids: Vec<_> = c.meta.custom_icons.iter().map(|i| i.uuid).collect();
    assert_eq!(ids, [id(0x71), id(0x72), id(0x73)]);
    assert_eq!(c.deleted_objects.len(), 1);
    assert_eq!(c.deleted_objects[0].uuid, id(0x99));
    // Keep off: the subgroup's icon is not used any more.
    let c = container::build(id(0x20), false, &v, NOW).unwrap();
    let ids: Vec<_> = c.meta.custom_icons.iter().map(|i| i.uuid).collect();
    assert_eq!(ids, [id(0x71), id(0x73)]);
    // The source is untouched.
    assert!(v.root.groups[0].custom_data.get(&share_key()).is_some());
    assert_eq!(
        container::build(id(0x55), true, &v, NOW).unwrap_err(),
        Error::NoGroup
    );
}

#[test]
fn t20_int08_13_references_are_kept_as_written() {
    let mut v = v();
    let inside = format!("{{REF:P@I:{}}}", "0B".repeat(16));
    let outside = format!("{{REF:P@I:{}}}", "0F".repeat(16));
    let mut alias = entry(0x0D, "Alias", "", "");
    alias.set_field("Password".into(), field(&inside, true));
    let mut alias2 = entry(0x0E, "Alias2", "", "");
    alias2.set_field("Password".into(), field(&outside, true));
    alias2.set_field("Other".into(), field(&outside, false));
    let old = alias2.duplicate(false);
    alias2.history.push(old);
    alias2.times.last_modification = T0;
    let team = &mut v.root.groups[0];
    team.entries.push(alias);
    team.entries.push(alias2);
    let mut home = larsal_model::Group::new(id(0x30), "Home".into(), T0);
    home.entries.push(entry(0x0F, "Home", "", "pw-h"));
    v.root.groups.push(home);
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    assert_eq!(find(&c, id(0x0D)).value("Password"), inside);
    let b = find(&c, id(0x0E));
    assert_eq!(b.value("Password"), outside);
    assert!(b.field("Password").unwrap().protected);
    assert_eq!(b.value("Other"), outside);
    assert_eq!(b.history.len(), 1);
    assert_eq!(b.history[0].value("Password"), outside);
    assert_eq!(b.times.last_modification, T0);
    assert!(c.root.find_group(id(0x30)).is_none());
}

/// F-140, MOD-08 "references can exfiltrate": anyone who can write the
/// container plants an entry in the share whose fields search the
/// importing vault (by user name, title, URL, notes or a kept id, alone or
/// with more spans). The next export of a member must carry none of the
/// values found outside the share; every planted text stays as written.
#[test]
fn f140_int08_13_planted_reference_takes_no_value_from_outside_the_share() {
    const SECRET: &str = "gmail-secret-demo";
    let mut v = v();
    let mut gmail = entry(0x0F, "Gmail", "ann@example.com", SECRET);
    gmail.set_field("URL".into(), field("https://mail.example.com", false));
    gmail.set_field("Notes".into(), field("demo gmail notes", false));
    let mut home = larsal_model::Group::new(id(0x30), "Home".into(), T0);
    home.entries.push(gmail);
    v.root.groups.push(home);
    let planted = [
        "{REF:P@U:ann@example.com}".to_owned(),
        "{REF:P@T:Gmail}".to_owned(),
        "{REF:P@A:https://mail.example.com}".to_owned(),
        "{REF:P@N:demo gmail notes}".to_owned(),
        format!("{{REF:P@I:{}}}", "0F".repeat(16)),
        "{REF:P@U:ann@example.com}{DB_DIR}".to_owned(),
        "x {REF:P@U:ann@example.com} y".to_owned(),
    ];
    let n = |i: usize| 0x40 + u8::try_from(i).unwrap();
    // Each text sits in the password and in one other standard field that
    // is not its own search field, so it never finds itself.
    let other = |text: &str| {
        if text.contains("@N:") {
            "UserName"
        } else {
            "Notes"
        }
    };
    for (i, text) in planted.iter().enumerate() {
        let mut e = entry(n(i), &format!("Planted {i}"), "", "");
        e.set_field("Password".into(), field(text, true));
        e.set_field(other(text).into(), field(text, false));
        v.root.groups[0].entries.push(e);
    }
    // Each text is a live attack outside the share: an entry at the root
    // resolves it to the secret. Inside the share it finds nothing outside
    // it (MOD-08.32, LD-279 (2), F-142).
    v.root.entries.push(entry(0x3F, "Probe", "", ""));
    let source = Context::new(Some(&v), NOW);
    for (i, text) in planted.iter().enumerate() {
        let r = larsal_core::refs::resolve(text, find(&v, id(0x3F)), &source);
        assert!(r.text.expose().contains(SECRET), "{text}");
        let r = larsal_core::refs::resolve(text, find(&v, id(n(i))), &source);
        assert!(!r.text.expose().contains(SECRET), "{text}");
    }
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let d = Dir::new("planted");
    let p = d.path("team.larsalvault");
    let password = secret(SHARE_PASSWORD);
    container::write_file(&p, &c, &password, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    let opened = container::open_file(&p, &password, &mut host(), &Limits::DEFAULT).unwrap();
    let c = &opened.vault;
    for (i, text) in planted.iter().enumerate() {
        let e = find(c, id(n(i)));
        assert_eq!(e.value("Password"), text.as_str());
        assert!(e.field("Password").unwrap().protected);
        assert_eq!(e.value(other(text)), text.as_str());
        assert!(e.history.is_empty());
        assert_eq!(e.times.last_modification, T0);
    }
    for e in c.root.all_entries() {
        for item in std::iter::once(e).chain(&e.history) {
            for (name, f) in item.fields() {
                assert!(!f.value.expose().contains(SECRET), "{name}");
            }
        }
    }
}

#[test]
fn t22_int08_14_container_takes_the_source_encryption() {
    let mut v = v();
    v.encryption.cipher = Cipher::ChaCha20;
    v.encryption.compression = Compression::None;
    v.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 3,
        memory_kib: 65_536,
        lanes: 4,
    };
    let pw = secret("demo-v");
    let Ok(larsal_format::Saved::File(saved)) = larsal_format::save(
        &v,
        &container::credentials(&pw),
        None,
        &mut host(),
        &Limits::DEFAULT,
        None,
    ) else {
        panic!("V saved")
    };
    let file = team_container(&v, true, SHARE_PASSWORD);
    let lim = Limits::DEFAULT;
    let (hv, hc) = (
        larsal_format::header::read_header(&saved.bytes, &lim).unwrap(),
        larsal_format::header::read_header(&file, &lim).unwrap(),
    );
    assert_eq!(hc.major, 4);
    assert_eq!(hc.cipher, larsal_crypto::cipher::Cipher::ChaCha20);
    assert_eq!(hc.compression, larsal_format::header::Compression::Gzip);
    let salt = |k: &KdfParams| match k {
        KdfParams::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
            salt,
            ..
        } => (*kind, *iterations, *memory_kib, *lanes, salt.clone()),
        KdfParams::AesKdf { .. } => panic!("Argon2"),
    };
    let (a, b) = (salt(&hv.kdf), salt(&hc.kdf));
    assert_eq!((a.0, a.1, a.2, a.3), (b.0, b.1, b.2, b.3));
    assert_eq!((b.1, b.2, b.3), (3, 65_536, 4));
    assert_ne!(a.4, b.4, "fresh salt");
    // Each write draws fresh values.
    assert_ne!(file, team_container(&v, true, SHARE_PASSWORD));
}

#[test]
fn t57_int08_35_share_in_the_bin_is_inactive_and_root_export_leaves_the_bin_out() {
    let mut v = v();
    let mut bin = larsal_model::Group::new(id(0x40), "Recycle Bin".into(), T0);
    bin.entries.push(entry(0x41, "Gone", "", "pw-g"));
    let team = v.root.groups.remove(0);
    bin.groups.push(team);
    v.root.groups.push(bin);
    v.root.entries.push(entry(0x42, "Top", "", "pw-t"));
    v.meta.recycle_bin = Some(id(0x40));
    assert_eq!(
        container::build(id(0x20), true, &v, NOW).unwrap_err(),
        Error::Recycled
    );
    assert_eq!(
        container::build(id(0x21), true, &v, NOW).unwrap_err(),
        Error::Recycled
    );
    let c = container::build(id(0x01), true, &v, NOW).unwrap();
    assert_eq!(titles(&c.root), ["Top"]);
    assert!(c.root.groups.is_empty());
    assert!(c.root.all_entries().all(|e| e.uuid != id(0x41)));
    // With the bin off there is no bin: the group exports as any other.
    v.meta.recycle_bin = None;
    let c = container::build(id(0x01), true, &v, NOW).unwrap();
    assert_eq!(c.root.groups.len(), 1);
}

#[test]
fn int08_14_failed_write_leaves_the_file_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let v = v();
    let c = container::build(id(0x20), true, &v, NOW).unwrap();
    let d = Dir::new("ro");
    let p = d.path("team.larsalvault");
    std::fs::write(&p, b"old").unwrap();
    std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = container::write_file(&p, &c, &secret("x"), &mut host(), &Limits::DEFAULT, &[]);
    std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        r.unwrap_err(),
        Error::Io(std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(std::fs::read(&p).unwrap(), b"old");
    assert_eq!(
        std::fs::read_dir(&d.0).unwrap().count(),
        1,
        "no temp file left"
    );
}

// ---------------------------------------------------------------------------
// E11-S6 Red-team run: the two attack rows that had no test named after them
// (AT-A05, AT-A06, AT-A08, AT-I04 and AT-C06 already do: t58, t59,
// at_a08_hostile_document..., t52/f162, t62). Each undoes its defence with
// one mutant, named in the doc comment, in a private copy of the tree
// (AGENTS.md rule 11); the mutant makes the test fail.

/// AT-A10 (INT-08.36): the share container parser never panics, hangs or
/// allocates past the limit over a deterministic hostile sweep of a real
/// container's bytes and over a decompression bomb that lies about its
/// size; every container that still opens holds the model invariants and
/// carries no share item below its root (INT-08.33). The fuzz targets
/// `share_settings` and `share_container` cover the same parsers in the
/// smoke; this is their deterministic twin.
///
/// Mutant (crates/larsal-core/src/import/zip.rs `read`): replace the checked
/// `d.get(start..end).ok_or(bad)?` with `&d[start..end]`, so a member whose
/// local header the sweep corrupted panics on an out-of-range slice.
#[test]
fn at_a10_the_share_container_parser_never_blows_up_on_hostile_bytes() {
    let base = team_container(&v(), true, SHARE_PASSWORD);
    let as_zip = zip(&[member(VAULT_ENTRY, &base, true)]);
    let pw = secret(SHARE_PASSWORD);
    let mut small = Limits::DEFAULT;
    small.total_file = 64 << 20;
    // A deterministic byte sweep: truncations, bit flips and junk tails of a
    // real container and a real zip. Any panic fails the test; every vault
    // that opens is well formed and holds no nested share item.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for seed in [&base, &as_zip] {
        for _ in 0..2_000 {
            let mut bytes = seed.clone();
            match next() % 3 {
                0 => bytes.truncate((next() as usize) % (bytes.len() + 1)),
                1 => {
                    for _ in 0..(1 + next() % 8) {
                        let at = (next() as usize) % bytes.len();
                        bytes[at] ^= (next() & 0xFF) as u8;
                    }
                }
                _ => bytes.extend((0..(next() % 64)).map(|_| (next() & 0xFF) as u8)),
            }
            if let Ok(o) = container::open(&bytes, &pw, &mut host(), &small) {
                assert_eq!(larsal_model::invariants::check(&o.vault), Ok(()));
                for g in o.vault.root.subtree().into_iter().skip(1) {
                    assert!(
                        g.custom_data.get(&share_key()).is_none(),
                        "a nested share survived"
                    );
                }
            }
        }
    }
    // The classic fuzzing find: 256 MiB of zeros declared as 1 KiB. The
    // inflate stops as soon as the output passes the declared size.
    let zeros = vec![0u8; 256 << 20];
    let bomb = zip(&[Member {
        declared: Some(1_024),
        ..member(VAULT_ENTRY, &zeros, true)
    }]);
    drop(zeros);
    let start = std::time::Instant::now();
    assert_eq!(
        open(&bomb, SHARE_PASSWORD).unwrap_err(),
        Error::Vault(larsal_format::Error::Corrupt)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "the bomb was not stopped fast"
    );
}

/// AT-I06 (SD-09, INT-08.14): a container is written with owner-only
/// permissions (0600); a pre-existing world-readable file is replaced
/// 0600, and a symbolic link at the path is replaced, never written
/// through (its target is left untouched).
///
/// Mutant (crates/larsal-core/src/storage.rs): `pub const OWNER_ONLY: u32 =
/// 0o600;` -> `0o644`; the written container is then 0644 and the test
/// fails.
#[test]
fn at_i06_a_container_is_written_owner_only_0600() {
    use std::os::unix::fs::PermissionsExt;
    let c = container::build(id(0x20), true, &v(), NOW).unwrap();
    let d = Dir::new("at-i06");
    let p = d.path("team.larsalvault");
    std::fs::write(&p, b"old").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pw = secret(SHARE_PASSWORD);
    container::write_file(&p, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let target = d.path("target");
    std::fs::write(&target, b"keep").unwrap();
    let link = d.path("link.larsalvault");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    container::write_file(&link, &c, &pw, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(!std::fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(
        std::fs::metadata(&link).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
