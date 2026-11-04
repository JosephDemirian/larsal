//! E4-S5: the rules of MOD-06 (icons), with real images made in the test
//! (PNG through `png`, ICO through the test encoder in `common/ico.rs`; no
//! binary files are stored) and App's decoder `Images` (LD-109). Each test
//! names its rule and checks the invariants where it changes the vault;
//! `mod_06_19_hostile_images` holds the hostile set.

mod common;

use app_core::edit::{
    Item, Position, add_group, change_entry, copy_into, edit_entry, edit_group, new_entry,
    new_group,
};
use app_core::icons::{
    Added, Choice, FullSize, GROUP_DEFAULT, Images, Kind, Limits, MAX_ICO_IMAGES, STANDARD_COUNT,
    Shown, add_download, add_files, add_png, apply_bulk_download, apply_to_children, check, decode,
    find_png, icon_name, in_use, picked, purge, remove, scaled_size, screen_png, shown,
};
use app_model::{CustomIcon, Icon, Time, Uuid, Vault};
use common::*;
use std::io::Write;

const L: Limits = Limits::DEFAULT;

/// A real PNG of one colour.
fn png_of(w: u32, h: u32, rgba: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(png::ColorType::Rgba);
    e.set_depth(png::BitDepth::Eight);
    let mut wr = e.write_header().unwrap();
    wr.write_image_data(&rgba.repeat((w * h) as usize)).unwrap();
    wr.finish().unwrap();
    out
}

/// A real ICO of one colour (small opaque images as BMP, larger ones as
/// PNG, as the old crate wrote them).
fn ico_of(w: u32, h: u32, rgba: [u8; 4]) -> Vec<u8> {
    common::ico::ico(&[(w, h, &rgba.repeat((w * h) as usize))])
}

/// Only a PNG header declaring `w` × `h`, then `tag` (no image data).
fn png_header(w: u32, h: u32, tag: u8) -> Vec<u8> {
    let mut d = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
    d.extend(w.to_be_bytes());
    d.extend(h.to_be_bytes());
    d.extend([8, 6, 0, 0, 0, tag]);
    d
}

/// The size and first pixel of PNG bytes.
fn read_png(data: &[u8]) -> (u32, u32, [u8; 4]) {
    let mut r = png::Decoder::new(std::io::Cursor::new(data))
        .read_info()
        .unwrap();
    let mut buf = vec![0; r.output_buffer_size().unwrap()];
    let info = r.next_frame(&mut buf).unwrap();
    assert_eq!(info.color_type, png::ColorType::Rgba);
    (info.width, info.height, [buf[0], buf[1], buf[2], buf[3]])
}

fn icon(n: u8, data: Vec<u8>) -> CustomIcon {
    CustomIcon {
        uuid: id(n),
        name: String::new(),
        last_modified: None,
        data,
        unknown: Vec::new(),
    }
}

const RED: [u8; 4] = [255, 0, 0, 255];
const BLUE: [u8; 4] = [0, 0, 255, 255];

#[test]
fn mod_06_1_standard_set() {
    assert_eq!(STANDARD_COUNT, 69);
    let v = sample();
    assert_eq!(
        shown(&v, Icon::Standard(68), Kind::Entry, &Images, &L),
        Shown::Standard(68)
    );
    assert_eq!(
        shown(&v, Icon::Standard(0), Kind::Group, &Images, &L),
        Shown::Standard(0)
    );
}

#[test]
fn mod_06_2_icons_app_sets() {
    let mut v = sample();
    let g = new_group(&v).unwrap();
    let gid = add_group(&mut v, id(1), g, NOW).unwrap();
    assert_eq!(group(&v, gid).icon, Icon::Standard(GROUP_DEFAULT));
    assert_eq!(
        new_entry(&v, id(4), true).unwrap().icon,
        Icon::Standard(0),
        "group icon 48 gives 0"
    );
    app_core::recycle::delete_entries(&mut v, &[id(0x10)], NOW, |_, _| unreachable!()).unwrap();
    let bin = app_core::recycle::bin_id(&v).unwrap();
    assert_eq!(group(&v, bin).icon, Icon::Standard(43));
    assert_eq!(
        (app_core::icons::BROWSER, app_core::icons::PASSKEY),
        (1, 13)
    );
    ok(&v);
}

#[test]
fn mod_06_3_group_icon_for_new_entries() {
    let mut v = sample();
    v.root.groups[1].icon = Icon::Standard(12);
    assert_eq!(new_entry(&v, id(4), true).unwrap().icon, Icon::Standard(12));
    assert_eq!(
        new_entry(&v, id(4), false).unwrap().icon,
        Icon::Standard(0),
        "setting off"
    );
    v.root.groups[1].icon = Icon::Custom(id(0xA1));
    assert_eq!(
        new_entry(&v, id(4), true).unwrap().icon,
        Icon::Custom(id(0xA1))
    );
    v.root.groups[1].icon = Icon::Standard(49);
    assert_eq!(new_entry(&v, id(4), true).unwrap().icon, Icon::Standard(0));
}

#[test]
fn mod_06_4_numbers_outside_the_set() {
    let mut v = sample();
    v.root.entries[0].icon = Icon::Standard(99);
    assert_eq!(
        shown(&v, Icon::Standard(99), Kind::Entry, &Images, &L),
        Shown::Standard(0)
    );
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.set_field("Notes".into(), field("n"));
    })
    .unwrap();
    assert_eq!(
        find(&v, id(0x10)).icon,
        Icon::Standard(99),
        "kept until the user picks (D-06-1)"
    );
    edit_entry(&mut v, id(0x10), NOW, |e| e.icon = Icon::Standard(5)).unwrap();
    assert_eq!(find(&v, id(0x10)).icon, Icon::Standard(5));
    ok(&v);
}

#[test]
fn mod_06_5_list_order() {
    let mut v = sample();
    v.meta.custom_icons = vec![
        icon(0xA1, png_of(1, 1, RED)),
        icon(0xA2, png_of(1, 1, BLUE)),
    ];
    let (z, added) = add_png(&mut v, png_of(2, 2, RED), "z".into(), Some(NOW)).unwrap();
    assert!(added);
    let order: Vec<Uuid> = v.meta.custom_icons.iter().map(|i| i.uuid).collect();
    assert_eq!(order, [id(0xA1), id(0xA2), z]);
    ok(&v);
}

#[test]
fn mod_06_6_adding_from_files() {
    let mut v = sample();
    let red = png_of(16, 16, RED);
    let r = add_files(&mut v, &[("red.png", &red)], &Images, &L, NOW).unwrap();
    assert_eq!((r.picked, r.added, r.existing), (1, 1, 0));
    let i = &v.meta.custom_icons[0];
    assert_eq!(
        (i.name.as_str(), i.last_modified, r.selected),
        ("red", Some(NOW), Some(i.uuid))
    );
    assert_eq!(read_png(&i.data), (16, 16, RED), "a 16 × 16 PNG");
    assert_eq!(icon_name("bank.logo.png"), "bank");
    assert_eq!(icon_name(".hidden.png"), "");
    // Mixed: one already there, one failed, one new; the last good one is
    // selected.
    let big = png_of(300, 300, BLUE);
    let r = add_files(
        &mut v,
        &[("red.png", &red), ("note.txt", b"text"), ("big.png", &big)],
        &Images,
        &L,
        NOW,
    )
    .unwrap();
    assert_eq!(
        (r.picked, r.added, r.existing, r.failed.clone()),
        (3, 1, 1, vec!["note.txt".to_owned()])
    );
    assert_eq!(r.selected, Some(v.meta.custom_icons[1].uuid));
    // Only the first 8 failed names.
    let bad: Vec<(String, Vec<u8>)> = (1..=12)
        .map(|n| (format!("a{n}.png"), b"text".to_vec()))
        .collect();
    let files: Vec<(&str, &[u8])> = bad
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let r = add_files(&mut v, &files, &Images, &L, NOW).unwrap();
    assert_eq!(r.added, 0);
    assert_eq!(
        r.failed,
        (1..=8).map(|n| format!("a{n}.png")).collect::<Vec<_>>()
    );
    assert_eq!(Added::default().selected, None);
    ok(&v);
}

#[test]
fn mod_06_7_formats_and_limits() {
    // PNG and ICO (BMP and PNG inside) are accepted, each stored as PNG.
    for (what, file) in [
        ("png", png_of(16, 16, RED)),
        ("ico bmp", ico_of(16, 16, BLUE)),
        ("ico png", ico_of(128, 128, RED)),
    ] {
        let out = decode(&file, &Images, &L).unwrap_or_else(|| panic!("{what}"));
        assert!(out.starts_with(b"\x89PNG"), "{what}");
    }
    assert_eq!(
        read_png(&decode(&ico_of(16, 16, BLUE), &Images, &L).unwrap()),
        (16, 16, BLUE)
    );
    // JPEG (LD-109), GIF, BMP, TIFF, WebP and HEIC are unsupported.
    let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, b'J', b'F', b'I', b'F'];
    for refused in [
        &jpeg[..],
        b"GIF89a\x01\x00\x01\x00",
        b"BM\x00\x00",
        b"II*\x00",
        b"RIFF\x00\x00\x00\x00WEBPVP8 ",
        b"\x00\x00\x00\x18ftypheic",
    ] {
        assert_eq!(check(refused, &L), None);
        assert_eq!(decode(refused, &Images, &L), None);
    }
    // The pixel and byte limits, from the header, before any decode.
    let low = Limits {
        bytes: 16 << 20,
        pixels: 100,
    };
    assert_eq!(decode(&png_of(300, 300, RED), &Images, &low), None);
    assert_eq!(check(&png_header(4097, 10, 0), &L), None);
    assert!(check(&png_header(4096, 10, 0), &L).is_some());
    assert_eq!(
        decode(
            &png_of(1, 1, RED),
            &Images,
            &Limits {
                bytes: 10,
                pixels: 4096
            }
        ),
        None
    );
}

#[test]
fn mod_06_8_scaling() {
    let wide = decode(&png_of(256, 64, RED), &Images, &L).unwrap();
    assert_eq!(read_png(&wide), (128, 128, RED), "aspect ratio not kept");
    assert_eq!(
        read_png(&decode(&png_of(1, 1, BLUE), &Images, &L).unwrap()),
        (1, 1, BLUE)
    );
    assert_eq!(
        read_png(&decode(&png_of(128, 128, RED), &Images, &L).unwrap()).0,
        128
    );
    assert_eq!(
        read_png(&decode(&png_of(300, 300, BLUE), &Images, &L).unwrap()),
        (128, 128, BLUE)
    );
    assert_eq!(
        (scaled_size(129, 5), scaled_size(5, 5)),
        ((128, 128), (5, 5))
    );
    // The smooth filter averages: half red, half blue columns give purple.
    let mut half = Vec::new();
    for _ in 0..256 {
        for x in 0..256 {
            half.extend(if x % 2 == 0 { RED } else { BLUE });
        }
    }
    let mut src = Vec::new();
    let mut e = png::Encoder::new(&mut src, 256, 256);
    e.set_color(png::ColorType::Rgba);
    e.set_depth(png::BitDepth::Eight);
    let mut wr = e.write_header().unwrap();
    wr.write_image_data(&half).unwrap();
    wr.finish().unwrap();
    assert_eq!(
        read_png(&decode(&src, &Images, &L).unwrap()).2,
        [127, 0, 127, 255]
    );
}

#[test]
fn mod_06_9_deduplication() {
    let mut v = sample();
    let x = decode(&png_of(4, 4, RED), &Images, &L).unwrap();
    v.meta.custom_icons = vec![icon(0xA1, x.clone()), icon(0xA2, x.clone())];
    assert_eq!(find_png(&v, &x), Some(id(0xA1)), "first in stored order");
    let r = add_files(
        &mut v,
        &[("again.png", &png_of(4, 4, RED))],
        &Images,
        &L,
        NOW,
    )
    .unwrap();
    assert_eq!((r.added, r.existing, r.selected), (0, 1, Some(id(0xA1))));
    assert_eq!(v.meta.custom_icons.len(), 2);
    ok(&v);
}

#[test]
fn mod_06_10_icon_joins_at_once() {
    let mut v = sample();
    add_files(
        &mut v,
        &[("red.png", &png_of(16, 16, RED))],
        &Images,
        &L,
        NOW,
    )
    .unwrap();
    // The edit screen is cancelled: no edit session runs.
    assert_eq!(v.meta.custom_icons.len(), 1);
    assert_eq!(find(&v, id(0x10)).icon, Icon::Standard(0));
    assert!(
        v.meta.custom_icons[0].last_modified.is_some(),
        "has a time: saves as 4.1"
    );
    ok(&v);
}

#[test]
fn mod_06_11_downloads() {
    let mut v = sample();
    let t1 = Time(NOW.0 + 300);
    let site = png_of(32, 32, BLUE);
    let icon_id = apply_bulk_download(&mut v, &[id(0x10), id(0x11)], &site, &Images, &L, t1)
        .unwrap()
        .unwrap();
    let i = &v.meta.custom_icons[0];
    assert_eq!(
        (i.name.as_str(), i.last_modified),
        ("", None),
        "no name, no time"
    );
    for n in [0x10, 0x11] {
        let e = find(&v, id(n));
        assert_eq!(
            (e.icon, e.times.last_modification, e.history.len()),
            (Icon::Custom(icon_id), t1, 0)
        );
    }
    let one = png_of(8, 8, RED);
    let (new, added) = add_download(&mut v, &one, &Images, &L, t1)
        .unwrap()
        .unwrap();
    assert!(added);
    assert_eq!(v.meta.custom_icons.last().unwrap().last_modified, Some(t1));
    assert_eq!(
        add_download(&mut v, &one, &Images, &L, t1).unwrap(),
        Some((new, false)),
        "existing selected"
    );
    assert_eq!(
        add_download(&mut v, b"nothing", &Images, &L, t1).unwrap(),
        None,
        "could not be fetched"
    );
    ok(&v);
}

#[test]
fn mod_06_12_choosing_an_icon() {
    assert_eq!(picked(Choice::Standard(5), Kind::Entry), Icon::Standard(5));
    assert_eq!(
        picked(Choice::Custom(Some(id(0xA1))), Kind::Group),
        Icon::Custom(id(0xA1))
    );
    assert_eq!(
        picked(Choice::Custom(None), Kind::Group),
        Icon::Standard(48)
    );
    assert_eq!(picked(Choice::Custom(None), Kind::Entry), Icon::Standard(0));
}

#[test]
fn mod_06_13_apply_to_children() {
    let mut v = sample();
    let mut h = find(&v, id(0x13)).duplicate(false);
    h.icon = Icon::Standard(3);
    v.root.groups[0].groups[0].entries[0].history.push(h);
    edit_group(&mut v, id(2), NOW, |g| g.icon = Icon::Standard(7)).unwrap();
    assert_eq!(
        apply_to_children(&mut v, id(2), true, true, NOW).unwrap(),
        3,
        "G2, E3 and E4"
    );
    assert_eq!(group(&v, id(3)).icon, Icon::Standard(7));
    let e4 = find(&v, id(0x13));
    assert_eq!(
        (e4.icon, e4.times.last_modification),
        (Icon::Standard(7), NOW)
    );
    assert_eq!(
        (e4.history.len(), e4.history[0].icon),
        (1, Icon::Standard(3)),
        "history untouched"
    );
    let mut w = sample();
    w.meta.recycle_bin = Some(id(4));
    edit_group(&mut w, id(1), NOW, |g| g.icon = Icon::Standard(9)).unwrap();
    apply_to_children(&mut w, id(1), true, false, NOW).unwrap();
    assert_eq!(group(&w, id(4)).icon, Icon::Standard(9), "the bin too");
    assert_eq!(
        find(&w, id(0x10)).icon,
        Icon::Standard(0),
        "entries not chosen"
    );
    ok(&v);
    ok(&w);
}

#[test]
fn mod_06_14_removing_selected_icons() {
    let mut v = sample();
    let t1 = Time(NOW.0 + 300);
    v.meta.custom_icons = vec![
        icon(0xA1, png_of(1, 1, RED)),
        icon(0xA2, png_of(1, 1, BLUE)),
    ];
    v.root.entries[0].icon = Icon::Custom(id(0xA1));
    let mut h = find(&v, id(0x10)).duplicate(false);
    h.times.last_modification = T0;
    v.root.entries[0].history.push(h);
    v.root.groups[1].icon = Icon::Custom(id(0xA1));
    assert!(in_use(&v, &[id(0xA1), id(0xA2)]));
    assert_eq!(remove(&mut v, &[id(0xA1), id(0xA2)], false, t1), 1, "Skip");
    assert_eq!(
        v.deleted_objects.iter().map(|d| d.uuid).collect::<Vec<_>>(),
        [id(0xA2)]
    );
    assert_eq!(remove(&mut v, &[id(0xA1)], true, t1), 1, "Delete");
    let e = find(&v, id(0x10));
    assert_eq!(
        (e.icon, e.times.last_modification, e.history.len()),
        (Icon::Standard(0), t1, 1)
    );
    assert_eq!(
        (e.history[0].icon, e.history[0].times.last_modification),
        (Icon::Standard(0), T0)
    );
    assert_eq!(group(&v, id(4)).icon, Icon::Standard(48));
    assert!(v.meta.custom_icons.is_empty());
    assert!(
        v.deleted_objects
            .iter()
            .any(|d| d.uuid == id(0xA1) && d.deleted_at == t1)
    );
    ok(&v);
}

#[test]
fn mod_06_15_purge() {
    let mut v = sample();
    v.meta.custom_icons = vec![
        icon(0xA1, png_of(1, 1, RED)),
        icon(0xA2, png_of(1, 1, BLUE)),
        icon(0xA3, png_of(2, 1, RED)),
    ];
    v.root.groups[0].icon = Icon::Custom(id(0xA1));
    let mut h = find(&v, id(0x10)).duplicate(false);
    h.icon = Icon::Custom(id(0xA2));
    h.times.last_modification = T0;
    v.root.entries[0].history.push(h);
    assert_eq!(purge(&mut v, NOW), 2);
    assert_eq!(
        v.meta
            .custom_icons
            .iter()
            .map(|i| i.uuid)
            .collect::<Vec<_>>(),
        [id(0xA1)]
    );
    let item = &find(&v, id(0x10)).history[0];
    assert_eq!(
        (item.icon, item.times.last_modification),
        (Icon::Standard(0), T0)
    );
    assert_eq!(purge(&mut v, NOW), 0, "all in use: msg.icons_all_in_use");
    ok(&v);
}

#[test]
fn mod_06_16_which_icon_shows() {
    let mut v = sample();
    v.meta.custom_icons = vec![icon(0xA1, png_of(16, 16, RED)), icon(0xA2, vec![0, 1, 2])];
    assert_eq!(
        shown(&v, Icon::Custom(id(0xA1)), Kind::Entry, &Images, &L),
        Shown::Custom(id(0xA1))
    );
    assert_eq!(
        shown(&v, Icon::Custom(id(0x77)), Kind::Entry, &Images, &L),
        Shown::Standard(0),
        "dangling id"
    );
    assert_eq!(
        shown(&v, Icon::Custom(id(0x77)), Kind::Group, &Images, &L),
        Shown::Standard(48)
    );
    assert_eq!(
        shown(&v, Icon::Custom(id(0xA2)), Kind::Group, &Images, &L),
        Shown::Standard(48),
        "bytes do not decode"
    );
    assert_eq!(v.meta.custom_icons[1].data, [0, 1, 2], "bytes kept");
    v.root.entries[0].icon = Icon::Custom(id(0x77));
    change_entry(&mut v, id(0x10), NOW, |e| {
        e.set_field("Title".into(), field("t"));
    })
    .unwrap();
    assert_eq!(
        find(&v, id(0x10)).icon,
        Icon::Custom(id(0x77)),
        "the dangling id is kept"
    );
}

#[test]
fn mod_06_17_copies_between_vaults() {
    let mut a = sample();
    a.meta.custom_icons = vec![CustomIcon {
        name: "bank".into(),
        last_modified: Some(T0),
        ..icon(0xA1, png_of(1, 1, RED))
    }];
    a.root.groups[0].icon = Icon::Custom(id(0xA1));
    let mut w = Vault::new(app_model::Group::new(id(0x90), "W".into(), T0), T0);
    copy_into(&a, Item::Group(id(2)), &mut w, id(0x90), Position::End, NOW).unwrap();
    let i = &w.meta.custom_icons[0];
    assert_eq!(
        (i.uuid, i.name.as_str(), i.last_modified),
        (id(0xA1), "bank", Some(T0))
    );
    a.meta.custom_icons.push(CustomIcon {
        name: "mail".into(),
        ..icon(0xA2, png_of(1, 1, BLUE))
    });
    a.root.entries[0].icon = Icon::Custom(id(0xA2));
    copy_into(
        &a,
        Item::Entry(id(0x10)),
        &mut w,
        id(0x90),
        Position::End,
        NOW,
    )
    .unwrap();
    assert_eq!(w.meta.custom_icons[1].name, "mail", "D-06-4");
    ok(&w);
}

#[test]
fn mod_06_18_history_keeps_the_icon() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| e.icon = Icon::Standard(9)).unwrap();
    let e = find(&v, id(0x10));
    assert_eq!(
        (e.icon, e.history[0].icon),
        (Icon::Standard(9), Icon::Standard(0))
    );
    ok(&v);
}

#[test]
fn mod_06_19_untrusted_image_data() {
    let mut v = sample();
    let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
    let ico = ico_of(16, 16, BLUE);
    v.meta.custom_icons = vec![
        icon(0xA1, vec![0, 1, 2]),
        icon(0xA2, gif.clone()),
        icon(0xA3, ico.clone()),
        icon(0xA4, png_header(100_000, 100_000, 0)),
    ];
    assert_eq!(screen_png(&v, id(0xA1), &Images, &L), None);
    assert_eq!(screen_png(&v, id(0xA2), &Images, &L), None, "GIF refused");
    assert_eq!(
        screen_png(&v, id(0xA4), &Images, &L),
        None,
        "header over the limit"
    );
    let out = screen_png(&v, id(0xA3), &Images, &L).unwrap();
    assert!(
        out.starts_with(b"\x89PNG"),
        "the screen gets PNG, never the ICO bytes"
    );
    assert_eq!(v.meta.custom_icons[1].data, gif, "kept byte for byte");
    assert_eq!(v.meta.custom_icons[2].data, ico);
    ok(&v);
}

/// The hostile set (LD-109): each refuses safely within the limits.
#[test]
fn mod_06_19_hostile_images() {
    let started = std::time::Instant::now();
    // A huge declared size: refused from the header, before any decode.
    assert_eq!(decode(&png_header(100_000, 100_000, 0), &Images, &L), None);
    let mut liar = png_of(16, 16, RED);
    liar[16..20].copy_from_slice(&5000u32.to_be_bytes());
    assert_eq!(decode(&liar, &Images, &L), None);
    // A bad CRC (IHDR's) and a truncated file.
    let mut bad_crc = png_of(16, 16, RED);
    bad_crc[29] ^= 0xFF;
    assert_eq!(decode(&bad_crc, &Images, &L), None);
    let whole = png_of(64, 64, BLUE);
    assert_eq!(decode(&whole[..whole.len() / 2], &Images, &L), None);
    // ICOs pointing past their end, or whose entries overlap to claim more
    // than the file holds.
    let mut past = ico_of(16, 16, RED);
    let len = past.len() as u32;
    past[14..18].copy_from_slice(&len.to_le_bytes());
    assert_eq!(decode(&past, &Images, &L), None);
    let one = ico_of(16, 16, RED);
    let (size, offset) = (&one[14..18], &one[18..22]);
    let mut many = vec![0, 0, 1, 0, 200, 0];
    for _ in 0..200 {
        many.extend(&one[6..14]);
        many.extend(size);
        many.extend((u32::from_le_bytes(offset.try_into().unwrap()) + 200 * 16 - 16).to_le_bytes());
    }
    many.extend(&one[22..]);
    assert!(check(&many, &L).is_some(), "its header alone passes");
    assert_eq!(
        decode(&many, &Images, &L),
        None,
        "App's directory check refuses it"
    );
    // A PNG inside an ICO that declares a huge size.
    let mut inner = ico_of(128, 128, RED);
    let at = inner.windows(4).position(|w| w == b"IHDR").unwrap();
    inner[at + 4..at + 8].copy_from_slice(&100_000u32.to_be_bytes());
    assert_eq!(decode(&inner, &Images, &L), None);
    // A BMP inside an ICO that is 0 wide, or whose height field is odd (it
    // counts the colour rows and the mask's, so it is always even).
    assert!(decode(&bmp_ico(1, 2), &Images, &L).is_some(), "the control");
    assert_eq!(decode(&bmp_ico(0, 2), &Images, &L), None, "0 wide");
    assert_eq!(decode(&bmp_ico(1, 3), &Images, &L), None, "odd height");
    // Decompression bombs: a tiny file declaring more pixels than allowed,
    // and a small image whose compressed data inflates far past it.
    let low = Limits {
        bytes: 16 << 20,
        pixels: 1024,
    };
    let big = png_of(4096, 4096, [0; 4]);
    assert!(big.len() < 200_000, "a small file");
    assert_eq!(decode(&big, &Images, &low), None);
    assert!(started.elapsed().as_secs() < 2, "all refused quickly");
    let bomb = bomb();
    let started = std::time::Instant::now();
    let out = decode(&bomb, &Images, &L);
    assert_eq!(
        out.map(|p| read_png(&p)),
        Some((16, 16, [0; 4])),
        "only the declared 16 × 16"
    );
    assert!(
        started.elapsed().as_millis() < 1000,
        "the rest is never inflated"
    );
}

/// An ICO of 126 bytes: a 1 × 1 directory entry, then one 32-bit BMP with
/// this width and height field and 64 bytes of pixels.
fn bmp_ico(width: i32, height: i32) -> Vec<u8> {
    let mut d = vec![0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 32, 0];
    d.extend(104u32.to_le_bytes());
    d.extend(22u32.to_le_bytes());
    d.extend(40u32.to_le_bytes());
    d.extend(width.to_le_bytes());
    d.extend(height.to_le_bytes());
    d.extend([1, 0, 32, 0]);
    d.extend([0; 24]);
    d.extend([255; 64]);
    assert_eq!(d.len(), 126);
    d
}

/// A 16 × 16 PNG whose image data stream holds 64 MiB of zeros.
fn bomb() -> Vec<u8> {
    let chunk = |kind: &[u8], body: &[u8]| {
        let mut crc = flate2::Crc::new();
        crc.update(kind);
        crc.update(body);
        [
            &(body.len() as u32).to_be_bytes()[..],
            kind,
            body,
            &crc.sum().to_be_bytes(),
        ]
        .concat()
    };
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let zeros = vec![0u8; 1 << 20];
    for _ in 0..64 {
        z.write_all(&zeros).unwrap();
    }
    let data = z.finish().unwrap();
    let mut ihdr = 16u32.to_be_bytes().to_vec();
    ihdr.extend(16u32.to_be_bytes());
    ihdr.extend([8, 6, 0, 0, 0]);
    [
        &b"\x89PNG\r\n\x1a\n"[..],
        &chunk(b"IHDR", &ihdr),
        &chunk(b"IDAT", &data),
        &chunk(b"IEND", &[]),
    ]
    .concat()
}

#[test]
fn mod_06_hostile_set_never_panics() {
    // Every prefix and a byte flip at every position of a small PNG and ICO.
    for file in [png_of(8, 8, RED), ico_of(8, 8, BLUE)] {
        for n in 0..file.len() {
            let _ = decode(&file[..n], &Images, &L);
            let mut flipped = file.clone();
            flipped[n] ^= 0x55;
            let _ = decode(&flipped, &Images, &L);
        }
    }
}

#[test]
fn mod_06_mutant_probes() {
    // I07: 69 is past the standard set.
    let v = sample();
    assert_eq!(
        shown(&v, Icon::Standard(69), Kind::Entry, &Images, &L),
        Shown::Standard(0)
    );
    // I05: an ICO whose directory understates a BMP image's size: the real
    // size is checked before decoding.
    let mut liar = ico_of(64, 64, BLUE);
    liar[6] = 16;
    liar[7] = 16;
    let low = Limits {
        bytes: 16 << 20,
        pixels: 32,
    };
    assert!(check(&liar, &low).is_some(), "the directory claims 16 × 16");
    assert_eq!(decode(&liar, &Images, &low), None);
    assert!(
        decode(&liar, &Images, &L).is_some(),
        "within the default limits it decodes"
    );
}

/// F-043, found by the icon_decode fuzz target: `ico` 0.6 panicked on a
/// palette BMP whose colour table is shorter than its depth allows. App's
/// own reader refuses it.
#[test]
fn mod_06_19_short_colour_table_refused() {
    for colours in [2usize, 16, 256] {
        // An opaque image with this many colours: a 1-, 4- or 8-bit BMP with
        // a full colour table.
        let (w, h) = (32u32, 32u32);
        let rgba: Vec<u8> = (0..w * h)
            .flat_map(|i| {
                let c = (i as usize % colours) as u8;
                [c, c.wrapping_mul(7), 255 - c, 255]
            })
            .collect();
        let mut file = common::ico::bmp(&[(w, h, &rgba)]);
        assert!(
            decode(&file, &Images, &L).is_some(),
            "{colours} colours, full table"
        );
        // "Colours used" = 1: the table is shorter than the pixel values.
        let at = u32::from_le_bytes(file[18..22].try_into().unwrap()) as usize + 32;
        file[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            decode(&file, &Images, &L),
            None,
            "{colours} colours, short table"
        );
    }
}

/// One PNG chunk with its CRC.
fn chunk(kind: &[u8], body: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(kind);
    crc.update(body);
    [
        &(body.len() as u32).to_be_bytes()[..],
        kind,
        body,
        &crc.sum().to_be_bytes(),
    ]
    .concat()
}

/// A 4 × 4 PNG of colour type `color` (8 bits) with the given IHDR length
/// padding, PLTE and tRNS, correct CRCs, every pixel byte 0.
fn png_with(color: u8, ihdr_extra: usize, plte: Option<&[u8]>, trns: Option<&[u8]>) -> Vec<u8> {
    let channels = match color {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        _ => 4,
    };
    let mut ihdr = 4u32.to_be_bytes().to_vec();
    ihdr.extend(4u32.to_be_bytes());
    ihdr.extend([8, color, 0, 0, 0]);
    ihdr.extend(vec![0; ihdr_extra]);
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    for _ in 0..4 {
        z.write_all(&vec![0; 1 + 4 * channels]).unwrap();
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &ihdr));
    if let Some(p) = plte {
        out.extend(chunk(b"PLTE", p));
    }
    if let Some(t) = trns {
        out.extend(chunk(b"tRNS", t));
    }
    out.extend(chunk(b"IDAT", &z.finish().unwrap()));
    out.extend(chunk(b"IEND", &[]));
    out
}

/// A PNG wrapped in a one-entry ICO.
fn in_ico(png: &[u8]) -> Vec<u8> {
    let mut d = vec![0, 0, 1, 0, 1, 0, 4, 4, 0, 0, 1, 0, 32, 0];
    d.extend((png.len() as u32).to_le_bytes());
    d.extend(22u32.to_le_bytes());
    d.extend(png);
    d
}

/// F-044 (LD-117): App checks the PNG chunk sizes before the crate reads
/// them; indexed PNGs with a PLTE not in threes made the crate panic.
#[test]
fn mod_06_19_png_chunk_rules() {
    let ok = |f: &[u8]| decode(f, &Images, &L).is_some();
    for len in [4usize, 5, 7, 8, 766, 767] {
        let bad = png_with(3, 0, Some(&vec![0x40; len]), None);
        assert!(!ok(&bad), "PLTE {len} bytes");
        assert!(!ok(&in_ico(&bad)), "PLTE {len} bytes in an ICO");
    }
    for len in [0usize, 1, 2, 3, 768, 771] {
        let f = png_with(3, 0, Some(&vec![0x40; len]), None);
        assert_eq!(ok(&f), len == 3 || len == 768, "PLTE {len} bytes");
    }
    // A good indexed PNG, with tRNS up to one byte per palette entry.
    assert!(ok(&png_with(
        3,
        0,
        Some(&[1, 2, 3, 4, 5, 6]),
        Some(&[0, 255])
    )));
    assert!(ok(&in_ico(&png_with(3, 0, Some(&[1, 2, 3]), None))));
    assert!(
        !ok(&png_with(3, 0, Some(&[1, 2, 3]), Some(&[0, 255]))),
        "tRNS longer than the palette"
    );
    assert!(!ok(&png_with(3, 0, None, None)), "indexed without PLTE");
    // tRNS sizes for grey and RGB; none with alpha.
    assert!(ok(&png_with(0, 0, None, Some(&[0, 7]))));
    assert!(!ok(&png_with(0, 0, None, Some(&[0, 7, 1]))));
    assert!(ok(&png_with(2, 0, None, Some(&[0; 6]))));
    assert!(!ok(&png_with(2, 0, None, Some(&[0; 5]))));
    assert!(!ok(&png_with(6, 0, None, Some(&[0; 4]))));
    // IHDR exactly 13 bytes; a chunk length past the end of the file.
    assert!(!ok(&png_with(6, 1, None, None)));
    let mut past = png_with(6, 0, None, None);
    let idat = past.windows(4).position(|w| w == b"IDAT").unwrap() - 4;
    past[idat..idat + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(!ok(&past));
    assert!(ok(&png_with(6, 0, None, None)));
}

/// Every pixel of PNG bytes, as RGBA.
fn png_pixels(data: &[u8]) -> Vec<[u8; 4]> {
    let mut r = png::Decoder::new(std::io::Cursor::new(data))
        .read_info()
        .unwrap();
    let mut buf = vec![0; r.output_buffer_size().unwrap()];
    r.next_frame(&mut buf).unwrap();
    buf.chunks(4).map(|p| p.try_into().unwrap()).collect()
}

/// A 2 × 2 BMP of `bits` per pixel for an ICO: the header, `table`, the
/// colour rows from the bottom up as given, then (but at 32 bits) the mask
/// with the top right pixel transparent.
fn bmp_2x2(bits: u16, table: &[[u8; 4]], rows: [&[u8]; 2]) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [40u32, 2, 4] {
        d.extend(v.to_le_bytes());
    }
    d.extend(1u16.to_le_bytes());
    d.extend(bits.to_le_bytes());
    d.extend([0; 24]);
    d.extend(table.concat());
    d.extend(rows.concat());
    if bits != 32 {
        d.extend([0, 0, 0, 0, 0x40, 0, 0, 0]);
    }
    d
}

/// E0-S7 R10: App's own BMP reader at every depth an ICO holds: the colour
/// table (1, 4, 8 bits), 5 bits per channel (16), BGR (24), BGRA with no
/// mask (32), rows from the bottom up, each padded to 4 bytes, and the mask.
#[test]
fn mod_06_ico_bmp_every_depth() {
    let grey = |n: u8| [n, n, n, 0];
    let palette = |n: usize| (0..n).map(|i| grey(i as u8 * 10)).collect::<Vec<_>>();
    let (top, clear) = (255, 0);
    // Bits per pixel, the colour table, the two rows as stored, the pixels.
    type Case<'a> = (u16, Vec<[u8; 4]>, [&'a [u8]; 2], [[u8; 4]; 4]);
    let cases: [Case; 6] = [
        (
            1,
            palette(2),
            [&[0b0100_0000, 0, 0, 0], &[0b1000_0000, 0, 0, 0]],
            [
                [10, 10, 10, top],
                [0, 0, 0, clear],
                [0, 0, 0, top],
                [10, 10, 10, top],
            ],
        ),
        (
            4,
            palette(16),
            [&[0x79, 0, 0, 0], &[0x35, 0, 0, 0]],
            [
                [30, 30, 30, top],
                [50, 50, 50, clear],
                [70, 70, 70, top],
                [90, 90, 90, top],
            ],
        ),
        (
            8,
            (0..=255).map(grey).collect(),
            [&[7, 9, 0, 0], &[3, 5, 0, 0]],
            [
                [3, 3, 3, top],
                [5, 5, 5, clear],
                [7, 7, 7, top],
                [9, 9, 9, top],
            ],
        ),
        (
            16,
            Vec::new(),
            // 0b0_11111_00000_10000 (red 31, green 0, blue 16) and black.
            [&[0x10, 0x7C, 0, 0], &[0, 0, 0x10, 0x7C]],
            [
                [0, 0, 0, top],
                [255, 0, 132, clear],
                [255, 0, 132, top],
                [0, 0, 0, top],
            ],
        ),
        (
            24,
            Vec::new(),
            [
                &[90, 80, 70, 120, 110, 100, 0, 0],
                &[30, 20, 10, 60, 50, 40, 0, 0],
            ],
            [
                [10, 20, 30, top],
                [40, 50, 60, clear],
                [70, 80, 90, top],
                [100, 110, 120, top],
            ],
        ),
        (
            32,
            Vec::new(),
            [
                &[90, 80, 70, 255, 120, 110, 100, 128],
                &[30, 20, 10, 255, 60, 50, 40, 7],
            ],
            [
                [10, 20, 30, 255],
                [40, 50, 60, 7],
                [70, 80, 90, 255],
                [100, 110, 120, 128],
            ],
        ),
    ];
    for (bits, table, rows, want) in cases {
        let file = in_ico(&bmp_2x2(bits, &table, rows));
        let png = decode(&file, &FullSize, &L).unwrap_or_else(|| panic!("{bits} bits"));
        assert_eq!(png_pixels(&png), want, "{bits} bits");
        // One byte short of the data: refused, never read past the end.
        let mut short = file.clone();
        short.pop();
        let size = (short.len() - 22) as u32;
        short[14..18].copy_from_slice(&size.to_le_bytes());
        assert_eq!(decode(&short, &FullSize, &L), None, "{bits} bits, cut");
    }
    // Depths a BMP icon never has.
    for bits in [0u16, 2, 7, 64] {
        assert_eq!(
            decode(
                &in_ico(&bmp_2x2(bits, &[], [&[0; 8], &[0; 8]])),
                &FullSize,
                &L
            ),
            None
        );
    }
}

/// E0-S7 R10: an ICO lists at most MAX_ICO_IMAGES images; the largest one,
/// the last of equals, is the one decoded.
#[test]
fn mod_06_ico_image_count_and_choice() {
    let one = |rgba: [u8; 4]| {
        bmp_2x2(
            24,
            &[],
            [&[rgba[2], rgba[1], rgba[0], 0, 0, 0, 0, 0], &[0; 8]],
        )
    };
    let file = |images: &[Vec<u8>]| {
        let mut d = vec![0, 0, 1, 0];
        d.extend((images.len() as u16).to_le_bytes());
        let mut at = 6 + 16 * images.len() as u32;
        for i in images {
            d.extend([2, 2, 0, 0, 1, 0, 24, 0]);
            d.extend((i.len() as u32).to_le_bytes());
            d.extend(at.to_le_bytes());
            at += i.len() as u32;
        }
        d.extend(images.concat());
        d
    };
    let red = one([200, 0, 0, 255]);
    let blue = one([0, 0, 200, 255]);
    let mut many = vec![red.clone(); MAX_ICO_IMAGES - 1];
    many.push(blue);
    let png = decode(&file(&many), &FullSize, &L).expect("256 images");
    assert_eq!(
        png_pixels(&png)[2],
        [0, 0, 200, 255],
        "the last of equal size"
    );
    many.push(red);
    assert!(check(&file(&many), &L).is_some(), "the header passes");
    assert_eq!(decode(&file(&many), &FullSize, &L), None, "257 images");
    // A reserved byte that is not 0.
    let mut bad = file(&[one([1, 2, 3, 255])]);
    bad[9] = 1;
    assert_eq!(decode(&bad, &FullSize, &L), None);
}
