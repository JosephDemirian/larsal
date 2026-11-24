//! E4-S4: the rules of MOD-05 (attachments). Each test names its rule and
//! checks the invariants where it changes the vault. Files on disk (open,
//! watch, save) are written by larsal-platform; here are their names, checks
//! and the vault side.

mod common;

use common::*;
use larsal_core::attachments::{
    Action, Limits, Place, Preview, TextDisplay, actions, asks_big_file, asks_overwrite, can_edit,
    disk_name, double_click, export, extension, find as find_attachment, import, name_from_path,
    new_text, new_text_name, prepare, preview, put, remove, remove_named, rename, replace, risky,
    shown_name, size_label, sniff, sorted, temp_name,
};
use larsal_core::edit::edit_entry;
use larsal_core::{Error, NameProblem};
use larsal_crypto::secret::SecretBytes;
use larsal_model::{Attachment, Entry, Vault};
use std::sync::Arc;

fn bytes(b: &[u8]) -> SecretBytes {
    SecretBytes::new(b.to_vec())
}

fn att(name: &str, b: &[u8]) -> Attachment {
    Attachment {
        name: name.into(),
        data: Arc::new(bytes(b)),
    }
}

fn names(e: &Entry) -> Vec<&str> {
    sorted(e).into_iter().map(|a| a.name.as_str()).collect()
}

/// Adds content to live entry `id` the way the editor commits a draft.
fn commit(v: &mut Vault, id_: larsal_model::Uuid, name: &str, b: &[u8]) -> Result<bool, Error> {
    let draft = find(v, id_).duplicate(false);
    let a = prepare(v, &draft, name, bytes(b), &Limits::DEFAULT)?;
    edit_entry(v, id_, NOW, |d| put(d, a))
}

#[test]
fn mod_05_1_the_set() {
    let mut e = entry(0x10, "E");
    e.attachments = vec![att("b.txt", b"1"), att("B.txt", b"2"), att("a.txt", b"")];
    assert_eq!(
        names(&e),
        ["B.txt", "a.txt", "b.txt"],
        "UTF-16 order, case-sensitive"
    );
    assert_eq!(
        find_attachment(&e, "a.txt").unwrap().data.len(),
        0,
        "0 bytes allowed"
    );
}

#[test]
fn mod_05_2_names() {
    let mut v = sample();
    let e = find(&v, id(0x10)).duplicate(false);
    assert_eq!(
        prepare(&v, &e, "", bytes(b"hello"), &Limits::DEFAULT).err(),
        Some(Error::AttachmentName(NameProblem::Empty))
    );
    assert_eq!(
        import(
            &mut v,
            id(0x10),
            "",
            bytes(b"hello"),
            false,
            &Limits::DEFAULT,
            NOW
        ),
        Err(Error::AttachmentName(NameProblem::Empty))
    );
    for odd in ["dir/x.txt", "a\\b", "c:d", ".hidden"] {
        assert!(commit(&mut v, id(0x10), odd, b"x").unwrap(), "{odd}");
    }
    assert_eq!(shown_name(""), "(no name)");
    assert_eq!(shown_name("a"), "a");
    ok(&v);
}

#[test]
fn mod_05_3_places() {
    assert_eq!(
        actions(Place::PreviewPanel),
        [Action::Preview, Action::Open, Action::Save]
    );
    assert_eq!(
        actions(Place::HistoryItem),
        [Action::Preview, Action::Open, Action::Save]
    );
    assert!(
        actions(Place::Editor).contains(&Action::Remove)
            && actions(Place::Editor).contains(&Action::Drop)
    );
    assert_eq!(double_click(Place::Editor), Action::Edit);
    assert_eq!(double_click(Place::HistoryItem), Action::Preview);
}

#[test]
fn mod_05_4_draft_and_history() {
    let mut v = sample();
    // Add a.txt, then Cancel: the draft is dropped.
    let mut draft = find(&v, id(0x10)).duplicate(false);
    put(&mut draft, att("a.txt", b"a"));
    drop(draft);
    assert!(find(&v, id(0x10)).attachments.is_empty());
    // Add a.txt, Apply, add b.txt, OK: two history items.
    commit(&mut v, id(0x10), "a.txt", b"a").unwrap();
    commit(&mut v, id(0x10), "b.txt", b"b").unwrap();
    let e = find(&v, id(0x10));
    assert_eq!((names(e), e.history.len()), (vec!["a.txt", "b.txt"], 2));
    // Applying an equal draft is no change.
    let same = find(&v, id(0x10))
        .attachments
        .iter()
        .map(|a| Attachment {
            name: a.name.clone(),
            data: Arc::clone(&a.data),
        })
        .collect::<Vec<_>>();
    assert!(!edit_entry(&mut v, id(0x10), NOW, |d| d.attachments = same).unwrap());
    ok(&v);
}

#[test]
fn mod_05_5_add_from_disk() {
    let mut v = sample();
    commit(&mut v, id(0x10), "f.txt", b"old").unwrap();
    let draft = find(&v, id(0x10)).duplicate(false);
    assert!(asks_overwrite(&draft, "f.txt") && !asks_overwrite(&draft, "g.txt"));
    // Overwrite: the draft gets the new content; OK keeps one history item
    // with the old one.
    commit(&mut v, id(0x10), "f.txt", b"new").unwrap();
    let e = find(&v, id(0x10));
    assert_eq!(find_attachment(e, "f.txt").unwrap().data.expose(), b"new");
    assert_eq!(
        find_attachment(&e.history[1], "f.txt")
            .unwrap()
            .data
            .expose(),
        b"old"
    );
    assert!(!asks_big_file(5_242_880) && asks_big_file(5_242_881));
    assert_eq!(size_label(5_242_881), "5.0 MB");
    assert_eq!(name_from_path("/tmp/scratch/s.bin"), "s.bin");
    // Two files with one name: the later wins.
    let mut d = entry(0x20, "D");
    put(&mut d, att("a.txt", b"first"));
    put(&mut d, att("a.txt", b"second"));
    assert_eq!(
        (d.attachments.len(), d.attachments[0].data.expose()),
        (1, &b"second"[..])
    );
    ok(&v);
}

#[test]
fn mod_05_6_drag_and_drop() {
    // Drops ask the same two questions as add from disk (L05-2).
    let mut d = entry(0x10, "E");
    put(&mut d, att("f.txt", b"x"));
    assert!(asks_overwrite(&d, "f.txt"));
    assert!(asks_big_file(6 * 1024 * 1024));
}

#[test]
fn mod_05_7_new_text_attachment() {
    let mut d = entry(0x10, "E");
    d.attachments = vec![
        att("New Attachment.txt", b""),
        att("New Attachment_1.txt", b""),
    ];
    assert_eq!(new_text_name(&d), "New Attachment_2.txt");
    let n = new_text(&mut d);
    assert_eq!(
        (n.as_str(), find_attachment(&d, &n).unwrap().data.len()),
        ("New Attachment_2.txt", 0)
    );
    assert_eq!(new_text_name(&entry(0x11, "F")), "New Attachment.txt");
}

#[test]
fn mod_05_8_edit_text() {
    assert!(can_edit(&att("n.txt", b"a\nb")));
    assert!(!can_edit(&att("p.png", b"\x89PNG\r\n\x1a\n\x00\x00")));
    assert!(can_edit(&att("e.txt", b"")), "application/x-zerosize");
    assert_eq!(sniff(b""), "application/x-zerosize");
    assert!(!can_edit(&att("b.bin", &[0, 1, 2, 255])));
    let mut v = sample();
    commit(&mut v, id(0x10), "n.txt", b"a\nb").unwrap();
    commit(&mut v, id(0x10), "n.txt", b"a\nc").unwrap();
    assert_eq!(
        find_attachment(find(&v, id(0x10)), "n.txt")
            .unwrap()
            .data
            .expose(),
        b"a\nc"
    );
    ok(&v);
}

#[test]
fn mod_05_9_preview() {
    assert_eq!(
        preview(&att("p.png", b"\x89PNG\r\n\x1a\nxxxx")),
        Preview::Image
    );
    assert_eq!(
        preview(&att("x.html", b"<script>alert(1)</script>")),
        Preview::Text(TextDisplay::Html)
    );
    assert_eq!(
        preview(&att("r.md", b"# t")),
        Preview::Text(TextDisplay::Markdown)
    );
    assert_eq!(
        preview(&att("n.txt", b"plain")),
        Preview::Text(TextDisplay::Plain)
    );
    assert_eq!(
        preview(&att("b.bin", &[0, 159, 146, 150])),
        Preview::Unsupported
    );
}

#[test]
fn mod_05_10_rename() {
    let mut d = entry(0x10, "E");
    d.attachments = vec![att("a.txt", b"a"), att("b.txt", b"b")];
    rename(&mut d, "a.txt", " c.txt ").unwrap();
    assert_eq!(names(&d), ["b.txt", "c.txt"]);
    assert_eq!(
        rename(&mut d, "c.txt", "b.txt"),
        Err(Error::AttachmentName(NameProblem::Taken))
    );
    assert_eq!(
        rename(&mut d, "c.txt", "   "),
        Err(Error::AttachmentName(NameProblem::Empty))
    );
    rename(&mut d, "c.txt", "C.txt").unwrap();
    assert_eq!(names(&d), ["C.txt", "b.txt"]);
    assert_eq!(
        find_attachment(&d, "C.txt").unwrap().data.expose(),
        b"a",
        "content moves"
    );
}

#[test]
fn mod_05_11_remove() {
    let mut v = sample();
    commit(&mut v, id(0x10), "a.txt", b"a").unwrap();
    edit_entry(&mut v, id(0x10), NOW, |d| {
        assert_eq!(remove(d, &["a.txt"]), 1);
    })
    .unwrap();
    let e = find(&v, id(0x10));
    assert!(e.attachments.is_empty());
    assert!(
        find_attachment(e.history.last().unwrap(), "a.txt").is_some(),
        "history keeps it"
    );
    assert!(v.deleted_objects.is_empty());
    ok(&v);
}

#[test]
fn mod_05_12_open() {
    assert_eq!(extension("report.final.pdf"), Some(".pdf"));
    assert_eq!(extension("notes"), None);
    assert_eq!(extension(".profile"), Some(".profile"));
    let n = temp_name("report.final.pdf").unwrap();
    assert_eq!(n.len(), 16);
    assert!(n.ends_with(".pdf") && n[..12].bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_ne!(
        temp_name("x").unwrap(),
        temp_name("x").unwrap(),
        "random each time"
    );
    assert!(risky("run.terminal") && risky("A.APP") && risky("x.html"));
    assert!(!risky("report.pdf") && !risky("notes"));
}

#[test]
fn mod_05_13_changes_from_outside() {
    let mut v = sample();
    commit(&mut v, id(0x10), "n.txt", b"one").unwrap();
    let before = find(&v, id(0x10)).history.len();
    // From the preview panel: one edit session, one history item.
    assert!(
        replace(
            &mut v,
            id(0x10),
            "n.txt",
            bytes(b"two"),
            &Limits::DEFAULT,
            NOW
        )
        .unwrap()
    );
    let e = find(&v, id(0x10));
    assert_eq!(
        (
            find_attachment(e, "n.txt").unwrap().data.expose(),
            e.history.len()
        ),
        (&b"two"[..], before + 1)
    );
    ok(&v);
}

#[test]
fn mod_05_14_save_to_disk() {
    assert_eq!(disk_name("a/b\\c.txt").as_deref(), Some("abc.txt"));
    assert_eq!(disk_name("dir/x.txt").as_deref(), Some("dirx.txt"));
    assert_eq!(disk_name("c:d").as_deref(), Some("cd"));
    for bad in ["", "/", ".", "..", "/.:"] {
        assert_eq!(disk_name(bad), None, "{bad:?}");
    }
}

#[test]
fn mod_05_15_command_line() {
    let mut v = sample();
    commit(&mut v, id(0x10), "f.txt", b"hello").unwrap();
    let h = find(&v, id(0x10)).history.len();
    assert_eq!(
        import(
            &mut v,
            id(0x10),
            "f.txt",
            bytes(b"b"),
            false,
            &Limits::DEFAULT,
            NOW
        ),
        Err(Error::AttachmentName(NameProblem::Taken))
    );
    assert_eq!(
        import(
            &mut v,
            id(0x10),
            "f.txt",
            bytes(b"hello"),
            true,
            &Limits::DEFAULT,
            NOW
        ),
        Ok(false),
        "equal content: no change"
    );
    assert_eq!(find(&v, id(0x10)).history.len(), h);
    assert!(
        import(
            &mut v,
            id(0x10),
            "g.txt",
            bytes(b"g"),
            false,
            &Limits::DEFAULT,
            NOW
        )
        .unwrap()
    );
    assert_eq!(export(&v, id(0x10), "g.txt").unwrap().expose(), b"g");
    assert!(remove_named(&mut v, id(0x10), "g.txt", NOW).unwrap());
    assert!(!remove_named(&mut v, id(0x10), "g.txt", NOW).unwrap());
    assert_eq!(
        find(&v, id(0x10)).history.len(),
        h + 2,
        "import and remove are edit sessions"
    );
    ok(&v);
}

#[test]
fn mod_05_16_size_limits() {
    let mib = 1 << 20;
    let low = Limits {
        one: mib,
        all: 2 * mib,
    };
    let mut v = sample();
    let big = vec![1u8; mib as usize];
    let half = vec![2u8; mib as usize / 2];
    v.root.entries[0].attachments = vec![att("one", &big), att("half", &half)];
    let e2 = find(&v, id(0x11)).duplicate(false);
    let size = |n: usize| bytes(&vec![3u8; n]);
    assert_eq!(
        prepare(&v, &e2, "x", size(mib as usize * 3 / 2), &low).err(),
        Some(Error::TooLarge),
        "one attachment"
    );
    assert!(prepare(&v, &e2, "y", size(mib as usize * 2 / 5), &low).is_ok());
    assert!(
        prepare(&v, &e2, "z", bytes(&big), &low).is_ok(),
        "equal content counts once"
    );
    assert_eq!(
        prepare(&v, &e2, "w", size(mib as usize * 3 / 5), &low).err(),
        Some(Error::TooLarge),
        "all attachments"
    );
}

#[test]
fn mod_05_17_shared_content() {
    let mut v = sample();
    v.root.entries[0].attachments = vec![att("a.txt", b"same")];
    let e2 = find(&v, id(0x11)).duplicate(false);
    let a = prepare(&v, &e2, "copy.txt", bytes(b"same"), &Limits::DEFAULT).unwrap();
    assert!(
        Arc::ptr_eq(&a.data, &v.root.entries[0].attachments[0].data),
        "one copy in memory"
    );
    edit_entry(&mut v, id(0x11), NOW, |d| put(d, a)).unwrap();
    // Changing one never changes the other.
    commit(&mut v, id(0x11), "copy.txt", b"other").unwrap();
    assert_eq!(v.root.entries[0].attachments[0].data.expose(), b"same");
    ok(&v);
}

#[test]
fn mod_05_18_history() {
    let mut v = sample();
    let four = vec![7u8; 4_000_000];
    commit(&mut v, id(0x10), "big.bin", &four).unwrap();
    for t in ["a", "b"] {
        edit_entry(&mut v, id(0x10), NOW, |e| {
            e.set_field("Title".into(), field(t));
        })
        .unwrap();
    }
    assert_eq!(
        find(&v, id(0x10)).history.len(),
        1,
        "default limits keep about one item"
    );
    ok(&v);
}

#[test]
fn mod_05_19_names_as_text() {
    let name = "<img src=x onerror=alert(1)>.txt";
    let mut v = sample();
    commit(&mut v, id(0x10), name, b"x").unwrap();
    assert_eq!(
        find(&v, id(0x10)).attachments[0].name,
        name,
        "kept literally"
    );
    assert_eq!(shown_name(name), name);
    ok(&v);
}

#[test]
fn mod_05_mutant_probes() {
    let mib = 1usize << 20;
    let mut v = sample();
    // A02: the one attachment limit alone.
    let only_one = Limits {
        one: mib as u64,
        all: 1 << 40,
    };
    let e2 = find(&v, id(0x11)).duplicate(false);
    assert_eq!(
        prepare(&v, &e2, "x", bytes(&vec![1; mib * 3 / 2]), &only_one).err(),
        Some(Error::TooLarge)
    );
    assert!(prepare(&v, &e2, "x", bytes(&vec![1; mib]), &only_one).is_ok());
    // A16: history content counts toward all attachments.
    let mut h = find(&v, id(0x10)).duplicate(false);
    h.attachments = vec![att("old.bin", &vec![9; mib * 3 / 2])];
    v.root.entries[0].history.push(h);
    let low = Limits {
        one: 1 << 40,
        all: 2 * mib as u64,
    };
    assert_eq!(
        prepare(&v, &e2, "y", bytes(&vec![2; mib * 3 / 5]), &low).err(),
        Some(Error::TooLarge)
    );
    // A06: the size label rounds.
    assert_eq!(size_label(2_055_209), "2.0 MB");
    assert_eq!(size_label(1_048_576), "1.0 MB");
    // A10: the first number is 1.
    let mut d = entry(0x20, "D");
    d.attachments = vec![att("New Attachment.txt", b"")];
    assert_eq!(new_text_name(&d), "New Attachment_1.txt");
    // A11: control characters make content binary.
    assert_eq!(sniff(b"a\x01b"), "application/octet-stream");
    assert_eq!(sniff(b"a\tb\r\n"), "text/plain");
    // A17: `.htm` previews as HTML.
    assert_eq!(
        preview(&att("x.htm", b"<b>t</b>")),
        Preview::Text(TextDisplay::Html)
    );
    // m4: the open copy's extension is cleaned like a disk name.
    let n = temp_name("evil./../x:y").unwrap();
    assert!(
        !n.contains('/') && !n.contains(':') && n.ends_with(".xy"),
        "{n}"
    );
    assert_eq!(temp_name("a.p\u{7}df").unwrap().get(12..), Some(".pdf"));
}
