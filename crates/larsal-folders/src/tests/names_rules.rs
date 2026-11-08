//! FIL-04-T09 to T11 and FIL-06-T02, T03: names, nodes, links and tree bounds.

use super::common::*;
use super::{Fx, fx};
use crate::error::Error;
use crate::limits::{MAX_CHILDREN, MAX_PAGE};
use crate::{Kind, Node};
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::siv;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

fn content_path(fx: &Fx, id: &[u8]) -> PathBuf {
    fx.path.join(dir_path(&ENC, &MAC, id))
}

/// A folder node and its content folder, by hand.
fn plant_dir(fx: &Fx, parent: &[u8], name: &str, id: &[u8]) {
    let node = content_path(fx, parent).join(raw_name(&ENC, &MAC, parent, name));
    fs::create_dir_all(&node).unwrap();
    fs::write(node.join("dir.c9r"), id).unwrap();
    let content = content_path(fx, id);
    fs::create_dir_all(&content).unwrap();
    fs::write(
        content.join("dirid.c9r"),
        seal_with(&ENC, &[0x66; 32], id, false),
    )
    .unwrap();
}

fn plant_file(fx: &Fx, parent: &[u8], name: &str, plain: &[u8]) -> PathBuf {
    let path = content_path(fx, parent).join(raw_name(&ENC, &MAC, parent, name));
    fs::write(&path, seal_plain(&ENC, plain)).unwrap();
    path
}

/// FIL-04.9: names by the public rule: another parent, another name; absent associated
/// data is not one empty part; the top folder's place, by a writer that is not this crate.
#[test]
fn fil04_t09_names_and_paths_by_the_public_rule() {
    let fx = fx("names");
    let root = fx.root();
    let sub = fx.vault.make_dir(&root, "sub").unwrap();
    fx.write(&root, "same.txt", b"in the top folder");
    fx.write(&sub, "same.txt", b"in the sub folder");
    let id = sub.dir_id.clone().unwrap();
    let in_top = raw_name(&ENC, &MAC, b"", "same.txt");
    let in_sub = raw_name(&ENC, &MAC, &id, "same.txt");
    assert_ne!(in_top, in_sub);
    assert!(content_path(&fx, b"").join(&in_top).is_file());
    assert!(content_path(&fx, &id).join(&in_sub).is_file());
    // New folders have fresh UUID text as their ID.
    assert_eq!(id.len(), 36);
    assert_eq!(id.iter().filter(|b| **b == b'-').count(), 4);
    assert_ne!(
        fx.vault.make_dir(&root, "other").unwrap().dir_id.unwrap(),
        id
    );
    // Absent is not empty.
    let key = siv_key(&ENC, &MAC);
    let none: [&[u8]; 0] = [];
    assert_ne!(
        siv::seal(&key, &none, b"x").unwrap(),
        siv::seal(&key, &[b""], b"x").unwrap()
    );
    // A name moved to another parent fails its proof, and stays on disk.
    fs::rename(
        content_path(&fx, b"").join(&in_top),
        content_path(&fx, &id).join(&in_top),
    )
    .unwrap();
    let rows = fx.rows(&sub);
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|r| r.kind == Kind::Invalid && r.name.is_none())
    );
    assert!(content_path(&fx, &id).join(&in_top).is_file());
    // The same bytes under the other key order: no such file.
    let swapped = SecretBytes::new([&ENC[..], &MAC[..]].concat());
    assert_ne!(
        siv::seal(&swapped, &[b""], b"same.txt").unwrap(),
        siv::seal(&key, &[b""], b"same.txt").unwrap()
    );
}

/// FIL-04.10: long names and empty folders work, at and past the threshold.
#[test]
fn fil04_t10_long_names_and_empty_folders_work() {
    let fx = fx("long");
    let root = fx.root();
    // 220 characters of stored text is 160-odd bytes of name: walk across the threshold.
    for len in [150usize, 158, 162, 163, 164, 165, 170, 200, 255] {
        let name = format!("{}.txt", "n".repeat(len - 4));
        let raw = raw_name(&ENC, &MAC, b"", &name);
        let node = fx.write(&root, &name, name.as_bytes());
        assert_eq!(fx.read(&node), name.as_bytes(), "{len}");
        assert_eq!(fx.find(&root, &name).size, Some(len as u64));
        let folder = content_path(&fx, b"");
        if raw.len() > 220 {
            let home = folder.join(deflated(&raw));
            assert_eq!(fs::read(home.join("name.c9s")).unwrap(), raw.as_bytes());
            assert!(home.join("contents.c9r").is_file());
            assert!(!folder.join(&raw).exists());
        } else {
            assert!(folder.join(&raw).is_file());
        }
    }
    let long_dir = format!("{}-folder", "d".repeat(240));
    let dir = fx.vault.make_dir(&root, &long_dir).unwrap();
    assert_eq!(fx.find(&root, &long_dir).kind, Kind::Dir);
    assert!(fx.names(&dir).is_empty(), "an empty folder lists empty");
    let inside = fx.write(&dir, "inside.txt", b"inside");
    assert_eq!(fx.read(&inside), b"inside");

    // Every way across the threshold keeps the content, not one byte changed.
    let name_long = format!("{}.bin", "m".repeat(220));
    let node = fx.write(&root, &name_long, b"moved");
    let raw_before = fx.digest(&node);
    let short = fx.vault.rename(&node, &root, "short.bin").unwrap();
    assert_eq!(fx.digest(&short), raw_before);
    assert!(fx.vault.lookup(&root, &name_long).unwrap().is_none());
    let long_again = fx.vault.rename(&short, &root, &name_long).unwrap();
    assert_eq!(fx.digest(&long_again), raw_before);
    let elsewhere = fx.vault.rename(&long_again, &dir, "short.bin").unwrap();
    assert_eq!(fx.read(&elsewhere), b"moved");
    // A folder, both ways, holding its children.
    let dir_short = fx.vault.rename(&dir, &root, "short-dir").unwrap();
    assert_eq!(fx.names(&dir_short).len(), 2);
    let dir_long = fx.vault.rename(&dir_short, &root, &long_dir).unwrap();
    assert_eq!(fx.read(&fx.find(&dir_long, "short.bin").node), b"moved");
    assert!(fx.no_staging_left());
}

/// FIL-04.10: a malformed node is shown, refused and left exactly as it is, whatever is
/// wrong with it; a good file beside it still reads.
#[test]
fn fil04_t10_malformed_nodes_are_preserved_and_refused() {
    let fx = fx("malformed");
    let root = fx.root();
    let folder = content_path(&fx, b"");
    let control = fx.write(&root, "control.txt", b"control");
    let long = format!("{}.txt", "x".repeat(200));
    let long_raw = raw_name(&ENC, &MAC, b"", &long);
    let other_raw = raw_name(&ENC, &MAC, b"", &format!("{}.dat", "y".repeat(200)));
    let good_body = seal_plain(&ENC, b"body");

    // Wrong mapping: the name inside hashes to another node.
    let wrong = folder.join(deflated(&long_raw));
    fs::create_dir(&wrong).unwrap();
    fs::write(wrong.join("name.c9s"), other_raw.as_bytes()).unwrap();
    fs::write(wrong.join("contents.c9r"), &good_body).unwrap();
    // A mapping too short to be shortened, whatever it hashes to.
    let tiny = raw_name(&ENC, &MAC, b"", "tiny");
    let under = folder.join(deflated(&tiny));
    fs::create_dir(&under).unwrap();
    fs::write(under.join("name.c9s"), tiny.as_bytes()).unwrap();
    fs::write(under.join("contents.c9r"), &good_body).unwrap();
    // Two kinds in one node.
    let two = folder.join(raw_name(&ENC, &MAC, b"", "two-kinds"));
    fs::create_dir(&two).unwrap();
    fs::write(two.join("dir.c9r"), b"11111111-2222-3333-4444-555555555555").unwrap();
    fs::write(two.join("symlink.c9r"), &good_body).unwrap();
    // A folder node with no marker at all.
    fs::create_dir(folder.join(raw_name(&ENC, &MAC, b"", "no-marker"))).unwrap();
    // A missing and a bad directory ID: empty, too long, not printable.
    for (name, id) in [
        ("empty-id", &b""[..]),
        ("long-id", &[b'a'; 37][..]),
        ("space-id", &b"not an id"[..]),
    ] {
        let node = folder.join(raw_name(&ENC, &MAC, b"", name));
        fs::create_dir(&node).unwrap();
        fs::write(node.join("dir.c9r"), id).unwrap();
    }
    // A shortened node's contents in a plain node, and an unknown file in a node.
    let plain_contents = folder.join(raw_name(&ENC, &MAC, b"", "plain-with-contents"));
    fs::create_dir(&plain_contents).unwrap();
    fs::write(plain_contents.join("contents.c9r"), &good_body).unwrap();
    let extra = folder.join(raw_name(&ENC, &MAC, b"", "with-extra"));
    fs::create_dir(&extra).unwrap();
    fs::write(
        extra.join("dir.c9r"),
        b"11111111-2222-3333-4444-555555555555",
    )
    .unwrap();
    fs::write(extra.join("something.else"), b"x").unwrap();
    // Names that are not the one text of their bytes: no padding, stray bits, not sealed.
    let padded = raw_name(&ENC, &MAC, b"", "pad.txt");
    let body = padded.strip_suffix(".c9r").unwrap();
    assert!(body.ends_with('='));
    fs::write(
        folder.join(format!("{}.c9r", body.trim_end_matches('='))),
        &good_body,
    )
    .unwrap();
    fs::write(folder.join("AAAAAAAAAAAAAAAAAAAAAA==.c9r"), &good_body).unwrap();
    fs::write(folder.join("no-extension"), b"unknown").unwrap();
    fs::write(folder.join(".DS_Store"), b"storage's own").unwrap();
    // A plain stored name past the threshold.
    let past = raw_name(&ENC, &MAC, b"", &"z".repeat(170));
    assert!(past.len() > 220);
    fs::write(folder.join(&past), &good_body).unwrap();

    let before = raw_tree(&fx.path);
    let rows = fx.rows(&root);
    assert_eq!(rows.len(), 15, "nothing is skipped");
    let count = |k: Kind| rows.iter().filter(|r| r.kind == k).count();
    assert_eq!(count(Kind::File), 1);
    assert_eq!(count(Kind::Ambiguous), 1);
    assert_eq!(count(Kind::Unsupported), 2, "an unknown file in a node");
    assert_eq!(count(Kind::Invalid), 11);
    for row in rows.iter().filter(|r| r.kind != Kind::File) {
        let mut out = Vec::new();
        assert_eq!(
            fx.vault
                .read_to(&row.node, &mut out, &mut |_, _| true)
                .err(),
            Some(Error::Open)
        );
        assert!(out.is_empty());
        assert!(fx.vault.rename(&row.node, &root, "repaired").is_err());
        assert!(fx.vault.delete_dir(&row.node).is_err());
        assert!(
            fx.vault
                .delete_file(&row.node, &fx.digest(&control))
                .is_err()
        );
    }
    assert_eq!(fx.read(&control), b"control");
    let after = raw_tree(&fx.path);
    assert_eq!(after.len(), before.len());
    for (path, hash) in &before {
        assert_eq!(after.get(path), Some(hash), "{path}");
    }
    // A folder holding any of them gives no authority to remove it.
    let sub = fx.vault.make_dir(&root, "keeper").unwrap();
    fx.write(&sub, "good.txt", b"good");
    fs::write(
        content_path(&fx, sub.dir_id.as_ref().unwrap()).join("no-extension"),
        b"unknown",
    )
    .unwrap();
    assert_eq!(fx.vault.delete_tree(&sub).err(), Some(Error::Open));
    assert_eq!(
        fx.read(&fx.find(&sub, "good.txt").node),
        b"good",
        "nothing removed"
    );
}

fn mkfifo(path: &std::path::Path) {
    let done = std::process::Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(done.success());
}

/// FIL-04.11: a link in the format is listed and never followed or made; its target is
/// bytes. Real links, a FIFO and a second hard link are visible and untouched.
#[test]
fn fil04_t11_links_and_special_objects_are_visible_and_never_followed() {
    let fx = fx("special");
    let root = fx.root();
    let folder = content_path(&fx, b"");
    let outside = fx.top.join("outside.txt");
    fs::write(&outside, b"OUTSIDE BYTES").unwrap();
    let control = fx.write(&root, "control.txt", b"control");

    // A link in the format, with a target that climbs out.
    let link = folder.join(raw_name(&ENC, &MAC, b"", "format-link"));
    fs::create_dir(&link).unwrap();
    fs::write(
        link.join("symlink.c9r"),
        seal_plain(&ENC, b"../../../../outside.txt"),
    )
    .unwrap();
    let row = fx.find(&root, "format-link");
    assert_eq!(row.kind, Kind::Link);
    assert_eq!(
        fx.read(&row.node),
        b"../../../../outside.txt",
        "bytes, not a path"
    );
    assert_eq!(
        fx.vault.rename(&row.node, &root, "moved").err(),
        Some(Error::Open)
    );
    assert!(fs::symlink_metadata(&link).unwrap().is_dir());

    // A real link in a name's place, to a file and to a folder.
    symlink(
        &outside,
        folder.join(raw_name(&ENC, &MAC, b"", "real-link")),
    )
    .unwrap();
    symlink(
        &fx.top,
        folder.join(raw_name(&ENC, &MAC, b"", "real-dir-link")),
    )
    .unwrap();
    // A real link as a node's own marker.
    let marker_link = folder.join(raw_name(&ENC, &MAC, b"", "marker-link"));
    fs::create_dir(&marker_link).unwrap();
    symlink(&outside, marker_link.join("dir.c9r")).unwrap();
    // A FIFO, which a careless open would wait on forever.
    mkfifo(&folder.join(raw_name(&ENC, &MAC, b"", "fifo")));
    // A second hard link to a stored file.
    let shared = folder.join(raw_name(&ENC, &MAC, b"", "shared"));
    fs::write(&shared, seal_plain(&ENC, b"shared")).unwrap();
    fs::hard_link(&shared, fx.top.join("the-other-name")).unwrap();

    let before = raw_tree(&fx.path);
    for name in [
        "real-link",
        "real-dir-link",
        "fifo",
        "shared",
        "marker-link",
    ] {
        let row = fx.find(&root, name);
        assert_eq!(row.kind, Kind::Unsupported, "{name}");
        assert_eq!(row.size, None);
        let mut out = Vec::new();
        assert_eq!(
            fx.vault
                .read_to(&row.node, &mut out, &mut |_, _| true)
                .err(),
            Some(Error::Open),
            "{name}"
        );
        assert!(out.is_empty());
        assert!(fx.vault.delete_tree(&row.node).is_err());
        assert!(fx.vault.rename(&row.node, &root, "moved").is_err());
    }
    // A file that became one of these after its handle was made: opening it says no.
    let path_of_old = folder.join(raw_name(&ENC, &MAC, b"", "was-a-file"));
    let was = fx.write(&root, "was-a-file", b"file");
    fs::remove_file(&path_of_old).unwrap();
    symlink(&outside, &path_of_old).unwrap();
    assert!(fx.vault.capture(&was, &mut |_, _| true).is_err());
    fs::remove_file(&path_of_old).unwrap();
    mkfifo(&path_of_old);
    assert!(fx.vault.capture(&was, &mut |_, _| true).is_err());
    fs::remove_file(&path_of_old).unwrap();
    assert_eq!(fs::read(&outside).unwrap(), b"OUTSIDE BYTES");
    assert_eq!(
        fx.read(&control),
        b"control",
        "an ordinary file still reads"
    );
    assert_eq!(raw_tree(&fx.path).len(), before.len());
}

/// FIL-06.2: safe names round-trip; every unsafe one is refused before any work, with no
/// character stripped to make a different name.
#[test]
fn fil06_t02_names_refused_and_kept() {
    let fx = fx("safe");
    let root = fx.root();
    let before = raw_tree(&fx.path);
    let at_bound = "a".repeat(255);
    let past_bound = "a".repeat(256);
    // U+0958 goes from 3 bytes to 6 in NFC: under the bound as typed, past it normalized.
    let grows = "\u{958}".repeat(42);
    let long_by_nfc = "\u{958}".repeat(43);
    assert!(long_by_nfc.len() < 255);
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "/",
        "a\\b",
        "a:b",
        "a\0b",
        "a\nb",
        "a\u{7f}b",
        "a\u{202e}b",
        "a\u{200f}b",
        "a\u{2066}b",
        "trailing.",
        "trailing ",
        "CON",
        "con",
        "nul.txt",
        "COM1",
        "lpt9.tar.gz",
        "AUX.c",
        past_bound.as_str(),
        long_by_nfc.as_str(),
    ] {
        assert_eq!(
            fx.vault
                .create_file(&root, bad, &mut &b"x"[..], 1, &mut |_, _| true)
                .err(),
            Some(Error::Name),
            "{bad:?}"
        );
        assert_eq!(
            fx.vault.make_dir(&root, bad).err(),
            Some(Error::Name),
            "{bad:?}"
        );
        assert_eq!(
            fx.vault.lookup(&root, bad).err(),
            Some(Error::Name),
            "{bad:?}"
        );
    }
    assert_eq!(raw_tree(&fx.path), before, "no work at all");
    for good in [
        at_bound.as_str(),
        grows.as_str(),
        "<b>[markup](x) `quoted`.txt",
        "name with spaces.txt",
        "CONSOLE",
        "COM10",
        "Za\u{17c}\u{f3}\u{142}\u{107}.txt",
        ".hidden",
    ] {
        let node = fx.write(&root, good, good.as_bytes());
        assert_eq!(fx.read(&node), good.as_bytes(), "{good:?}");
        let row = fx.find(&root, good);
        assert!(row.safe);
    }
    // One name, as the disk may see it, is one item: composed and decomposed, and by case.
    let node = fx.write(&root, "caf\u{e9}.txt", b"first");
    assert_eq!(
        fx.vault
            .create_file(&root, "cafe\u{301}.txt", &mut &b"x"[..], 1, &mut |_, _| {
                true
            })
            .err(),
        Some(Error::Exists)
    );
    assert_eq!(
        fx.read(&fx.find(&root, "cafe\u{301}.txt").node),
        b"first",
        "one stored form"
    );
    assert_eq!(
        fx.vault
            .create_file(&root, "CAF\u{c9}.TXT", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Exists)
    );
    assert_eq!(
        fx.vault.make_dir(&root, "CAF\u{c9}.TXT").err(),
        Some(Error::Exists)
    );
    let other = fx.write(&root, "other.txt", b"other");
    assert_eq!(
        fx.vault.rename(&other, &root, "Caf\u{e9}.txt").err(),
        Some(Error::Exists)
    );
    // A rename by case alone of the same item is not a collision.
    let renamed = fx.vault.rename(&node, &root, "CAF\u{c9}.TXT").unwrap();
    assert_eq!(fx.read(&renamed), b"first");
    assert_eq!(fx.read(&other), b"other");
}

/// FIL-06.2: a name a peer wrote that is not safe here is a proven row, marked, and left.
#[test]
fn fil06_t02_a_foreign_unsafe_name_is_an_unsupported_row() {
    let fx = fx("foreign-name");
    let root = fx.root();
    for name in ["a:b", "con", "x\u{202e}txt.exe", "cafe\u{301}"] {
        let path = plant_file(&fx, b"", name, b"foreign");
        let rows = fx.rows(&root);
        let row = rows
            .iter()
            .find(|r| r.name.as_ref().is_some_and(|n| n.expose() == name))
            .unwrap();
        assert!(!row.safe, "{name:?}");
        assert_eq!(
            row.kind,
            Kind::File,
            "its bytes can still be saved under a new name"
        );
        assert_eq!(fx.read(&row.node), b"foreign");
        assert!(path.is_file());
        fs::remove_file(path).unwrap();
    }
    // Two peer names one normal form apart stay two rows: never merged, never repaired.
    let a = plant_file(&fx, b"", "cafe\u{301}.txt", b"decomposed");
    let b = plant_file(&fx, b"", "caf\u{e9}.txt", b"composed");
    let rows = fx.rows(&root);
    assert_eq!(rows.len(), 2);
    assert!(a.is_file() && b.is_file());
    assert_eq!(rows.iter().filter(|r| r.safe).count(), 1);
}

/// FIL-06.3: a page is at most 256 rows; a folder at the limit lists whole; one past it is
/// a refusal, not a short list.
#[test]
fn fil06_t03_listings_are_paged_and_bounded() {
    let fx = fx("pages");
    let root = fx.root();
    let folder = content_path(&fx, b"");
    for i in 0..MAX_CHILDREN {
        // The backup is one more entry on disk, and is no row.
        fs::write(
            folder.join(raw_name(&ENC, &MAC, b"", &format!("f{i}"))),
            b"short",
        )
        .unwrap();
    }
    let mut listing = fx.vault.open_listing(&root).unwrap();
    assert_eq!(listing.total(), MAX_CHILDREN);
    let mut seen = 0;
    loop {
        let page = listing.next_page(usize::MAX).unwrap();
        assert!(page.len() <= MAX_PAGE);
        if page.is_empty() {
            break;
        }
        seen += page.len();
    }
    assert_eq!(seen, MAX_CHILDREN);
    fs::write(folder.join(raw_name(&ENC, &MAC, b"", "one-more")), b"short").unwrap();
    assert_eq!(fx.vault.open_listing(&root).err(), Some(Error::Open));
    // One name can still be found, read or refused.
    assert!(fx.vault.lookup(&root, "f1").unwrap().is_some());
}

/// FIL-06.3: the tree delete's look stops at its depth limit, and at a directory ID seen
/// twice: nothing is removed.
#[test]
fn fil06_t03_tree_limits_and_id_cycles_remove_nothing() {
    let fx = fx("cycle");
    let root = fx.root();
    plant_dir(&fx, b"", "a", b"id-of-a");
    plant_dir(&fx, b"id-of-a", "b", b"id-of-b");
    // A cycle: b holds a folder whose ID is a's.
    let looped = content_path(&fx, b"id-of-b").join(raw_name(&ENC, &MAC, b"id-of-b", "back-to-a"));
    fs::create_dir(&looped).unwrap();
    fs::write(looped.join("dir.c9r"), b"id-of-a").unwrap();
    plant_file(&fx, b"id-of-a", "kept.txt", b"kept");
    let before = raw_tree(&fx.path);
    let a = fx.find(&root, "a").node;
    // Each listing is one step: walking it by hand ends where a person stops.
    let b = fx.find(&a, "b").node;
    let back = fx.find(&b, "back-to-a").node;
    assert_eq!(back.kind(), Kind::Dir);
    assert_eq!(fx.read(&fx.find(&back, "kept.txt").node), b"kept");
    assert_eq!(fx.vault.delete_tree(&a).err(), Some(Error::Open));
    assert_eq!(raw_tree(&fx.path), before);
    // Two nodes with one ID: the same refusal.
    plant_dir(&fx, b"", "twin-1", b"id-of-twins");
    plant_dir(&fx, b"id-of-twins", "twin-2", b"id-of-twins");
    let before = raw_tree(&fx.path);
    assert_eq!(
        fx.vault.delete_tree(&fx.find(&root, "twin-1").node).err(),
        Some(Error::Open)
    );
    assert_eq!(raw_tree(&fx.path), before);
    // Two folders side by side with one ID, no cycle: the depth limit never comes into it,
    // and the ID seen twice alone stops the look before anything goes.
    plant_dir(&fx, b"", "diamond", b"id-of-diamond");
    plant_dir(&fx, b"id-of-diamond", "left", b"id-of-shared");
    plant_dir(&fx, b"id-of-diamond", "right", b"id-of-shared");
    plant_file(&fx, b"id-of-shared", "shared.txt", b"shared");
    let before = raw_tree(&fx.path);
    assert_eq!(
        fx.vault.delete_tree(&fx.find(&root, "diamond").node).err(),
        Some(Error::Open)
    );
    assert_eq!(raw_tree(&fx.path), before);

    // Depth: the top folder of a chain is depth 0, and the limit is 128.
    let chain = |fx: &Fx, top: &str, levels: usize| -> Node {
        let mut parent: Vec<u8> = Vec::new();
        for level in 0..levels {
            let id = format!("{top}-{level}").into_bytes();
            let name = if level == 0 {
                top.to_owned()
            } else {
                format!("n{level}")
            };
            plant_dir(fx, &parent, &name, &id);
            parent = id;
        }
        fx.find(&fx.root(), top).node
    };
    let too_deep = chain(&fx, "deep", 130);
    let before = raw_tree(&fx.path);
    assert_eq!(fx.vault.delete_tree(&too_deep).err(), Some(Error::Open));
    assert_eq!(raw_tree(&fx.path), before);
    let fits = chain(&fx, "fits", 129);
    fx.vault.delete_tree(&fits).unwrap();
    assert!(fx.vault.lookup(&root, "fits").unwrap().is_none());
}

/// FIL-06.3: everything goes through descriptors with no link followed: a link anywhere on
/// the way down, or another folder at the chosen path, stops the session's work.
#[test]
fn fil06_t03_root_swap_and_links_on_the_way_stop() {
    let fx = fx("root-swap");
    let root = fx.root();
    let node = fx.write(&root, "file.txt", b"file");
    let d = fx.path.join("d");
    let moved = fx.top.join("d-elsewhere");
    fs::rename(&d, &moved).unwrap();
    symlink(&moved, &d).unwrap();
    let mut out = Vec::new();
    assert!(
        fx.vault.read_to(&node, &mut out, &mut |_, _| true).is_err(),
        "link at d"
    );
    assert!(fx.vault.open_listing(&root).is_err());
    assert!(out.is_empty());
    fs::remove_file(&d).unwrap();
    fs::rename(&moved, &d).unwrap();
    assert_eq!(fx.read(&node), b"file");

    let (first, second) = {
        let rel = dir_path(&ENC, &MAC, b"");
        let mut parts = rel.split('/').skip(1);
        (
            parts.next().unwrap().to_owned(),
            parts.next().unwrap().to_owned(),
        )
    };
    // A link at each level below `d`.
    let level1 = d.join(&first);
    fs::rename(&level1, &moved).unwrap();
    symlink(&moved, &level1).unwrap();
    assert!(
        fx.vault.open_listing(&root).is_err(),
        "link at the first level"
    );
    fs::remove_file(&level1).unwrap();
    fs::rename(&moved, &level1).unwrap();
    let level2 = level1.join(&second);
    fs::rename(&level2, &moved).unwrap();
    symlink(&moved, &level2).unwrap();
    assert!(
        fx.vault.open_listing(&root).is_err(),
        "link at the second level"
    );
    fs::remove_file(&level2).unwrap();
    fs::rename(&moved, &level2).unwrap();
    assert_eq!(fx.read(&node), b"file");

    // Another folder moved to the chosen path, then a link to the real one.
    let aside = fx.top.join("folder-aside");
    fs::rename(&fx.path, &aside).unwrap();
    fs::create_dir(&fx.path).unwrap();
    assert_eq!(fx.vault.root_dir().err(), Some(Error::Changed));
    assert_eq!(
        fx.vault
            .create_file(&root, "new", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Changed)
    );
    fs::remove_dir(&fx.path).unwrap();
    symlink(&aside, &fx.path).unwrap();
    assert_eq!(fx.vault.root_dir().err(), Some(Error::Changed));
    fs::remove_file(&fx.path).unwrap();
    fs::rename(&aside, &fx.path).unwrap();
    assert_eq!(
        fx.read(&node),
        b"file",
        "the same folder back: the same session"
    );

    // A folder that is a link, opened as a vault.
    let via = fx.top.join("via-link");
    symlink(&fx.path, &via).unwrap();
    let stores = crate::Stores::open(&fx.top.join("stores2")).unwrap();
    let got = crate::Vault::unlock(&via, &secret(PASSWORD), &stores, &mut |_, _| true);
    assert_eq!(got.err(), Some(Error::Input));
}
