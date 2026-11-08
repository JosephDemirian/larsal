//! E23-S3 check 3: one changed file changes only its own encrypted file. A snapshot of
//! every raw object's hash and identity before and after one write, one rename and one
//! delete, and the exact names that may change. Anything else that changed fails.

mod common;

use common::{
    CHUNK, ENC, MAC, PASSWORD, deflated, demo_bytes, dir_path, fresh, make_folder, raw_name, secret,
};
use larsal_folders::{Node, Outcome, Stores, Vault};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Hash and inode of every raw object; a folder only has its inode.
fn snapshot(root: &Path) -> BTreeMap<String, (String, u64)> {
    common::raw_tree(root)
        .into_iter()
        .map(|(path, hash)| {
            let ino = fs::symlink_metadata(root.join(path.trim_end_matches('/')))
                .unwrap()
                .ino();
            (path, (hash, ino))
        })
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Change {
    removed: BTreeSet<String>,
    added: BTreeSet<String>,
    changed: BTreeSet<String>,
}

fn diff(a: &BTreeMap<String, (String, u64)>, b: &BTreeMap<String, (String, u64)>) -> Change {
    let mut out = Change::default();
    for (path, old) in a {
        match b.get(path) {
            None => {
                out.removed.insert(path.clone());
            }
            // A folder's own listing changes with its children, not its identity.
            Some(new) if new != old => {
                out.changed.insert(path.clone());
            }
            Some(_) => {}
        }
    }
    for path in b.keys() {
        if !a.contains_key(path) {
            out.added.insert(path.clone());
        }
    }
    out
}

fn set(items: &[String]) -> BTreeSet<String> {
    items.iter().cloned().collect()
}

struct Fix {
    path: PathBuf,
    vault: Vault,
    root: Node,
    _stores: Stores,
}

fn raw(parent: &[u8], name: &str) -> String {
    format!(
        "{}/{}",
        dir_path(&ENC, &MAC, parent),
        raw_name(&ENC, &MAC, parent, name)
    )
}

fn long_entry(parent: &[u8], name: &str) -> String {
    format!(
        "{}/{}",
        dir_path(&ENC, &MAC, parent),
        deflated(&raw_name(&ENC, &MAC, parent, name))
    )
}

fn built() -> Fix {
    let top = fresh("raw");
    let path = top.join("folder");
    make_folder(&path, PASSWORD);
    let stores = Stores::open(&top.join("stores")).unwrap();
    let vault = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap();
    let root = vault.root_dir().unwrap();
    let write = |parent: &Node, name: &str, plain: &[u8]| {
        vault
            .create_file(
                parent,
                name,
                &mut &plain[..],
                plain.len() as u64,
                &mut |_, _| true,
            )
            .unwrap()
    };
    write(&root, "unrelated-1.bin", &demo_bytes(CHUNK * 2 + 9, 1));
    write(&root, "change-me.bin", &demo_bytes(CHUNK + 9, 2));
    write(&root, "rename-me.bin", &demo_bytes(100, 3));
    write(&root, "delete-me.bin", &demo_bytes(100, 4));
    write(&root, &long_name("change"), b"long to change");
    write(&root, &long_name("rename"), b"long to rename");
    write(&root, &long_name("delete"), b"long to delete");
    let dir = vault.make_dir(&root, "dir").unwrap();
    write(&dir, "inner.bin", &demo_bytes(500, 5));
    let sub = vault.make_dir(&dir, "sub").unwrap();
    write(&sub, "deep.bin", &demo_bytes(500, 6));
    Fix {
        path,
        vault,
        root,
        _stores: stores,
    }
}

fn long_name(what: &str) -> String {
    format!("{what}-{}.bin", "l".repeat(200))
}

impl Fix {
    fn node(&self, name: &str) -> Node {
        self.vault.lookup(&self.root, name).unwrap().unwrap().node
    }

    fn digest(&self, node: &Node) -> larsal_folders::Digest {
        self.vault.capture(node, &mut |_, _| true).unwrap().digest()
    }

    /// The change one call makes; the parent folders on the way must keep their identity.
    fn change(&self, work: impl FnOnce(&Self)) -> Change {
        let before = snapshot(&self.path);
        work(self);
        let after = snapshot(&self.path);
        diff(&before, &after)
    }
}

/// One write: only that file's object, and it is a new object, never written in place.
#[test]
fn one_write_changes_only_its_own_object() {
    let fix = built();
    let node = fix.node("change-me.bin");
    let base = fix.digest(&node);
    let got = fix.change(|f| {
        let plain = demo_bytes(CHUNK + 10, 7);
        let saved = f
            .vault
            .update_file(
                &node,
                &base,
                &mut &plain[..],
                plain.len() as u64,
                &mut |_, _| true,
            )
            .unwrap();
        assert_eq!(saved.outcome, Outcome::Replaced);
    });
    assert_eq!(
        got,
        Change {
            changed: set(&[raw(b"", "change-me.bin")]),
            ..Change::default()
        }
    );
    // The same for a shortened node: only its contents file.
    let node = fix.node(&long_name("change"));
    let base = fix.digest(&node);
    let got = fix.change(|f| {
        f.vault
            .update_file(&node, &base, &mut &b"another"[..], 7, &mut |_, _| true)
            .unwrap();
    });
    assert_eq!(
        got,
        Change {
            changed: set(&[format!(
                "{}/contents.c9r",
                long_entry(b"", &long_name("change"))
            )]),
            ..Change::default()
        }
    );
}

/// A new file: exactly its own object is added.
#[test]
fn one_new_file_adds_only_its_own_object() {
    let fix = built();
    let got = fix.change(|f| {
        f.vault
            .create_file(&f.root, "added.bin", &mut &b"added"[..], 5, &mut |_, _| {
                true
            })
            .unwrap();
    });
    assert_eq!(
        got,
        Change {
            added: set(&[raw(b"", "added.bin")]),
            ..Change::default()
        }
    );
}

/// One rename: the same object under another name, not one byte different, and nothing
/// else. Inside a folder too; a folder's rename leaves its contents untouched.
#[test]
fn one_rename_moves_only_its_own_object() {
    let fix = built();
    let node = fix.node("rename-me.bin");
    let before = snapshot(&fix.path)[&raw(b"", "rename-me.bin")].clone();
    let got = fix.change(|f| {
        f.vault.rename(&node, &f.root, "renamed.bin").unwrap();
    });
    assert_eq!(
        got,
        Change {
            removed: set(&[raw(b"", "rename-me.bin")]),
            added: set(&[raw(b"", "renamed.bin")]),
            ..Change::default()
        }
    );
    assert_eq!(
        snapshot(&fix.path)[&raw(b"", "renamed.bin")],
        before,
        "the same bytes, the same object"
    );

    // A shortened node to a plain name: its old folder goes, the contents move, whole.
    let name = long_name("rename");
    let node = fix.node(&name);
    let entry = long_entry(b"", &name);
    let contents = snapshot(&fix.path)[&format!("{entry}/contents.c9r")].clone();
    let got = fix.change(|f| {
        f.vault.rename(&node, &f.root, "was-long.bin").unwrap();
    });
    assert_eq!(
        got,
        Change {
            removed: set(&[
                format!("{entry}/"),
                format!("{entry}/contents.c9r"),
                format!("{entry}/name.c9s")
            ]),
            added: set(&[raw(b"", "was-long.bin")]),
            ..Change::default()
        }
    );
    assert_eq!(snapshot(&fix.path)[&raw(b"", "was-long.bin")], contents);

    // A folder: its node moves. Every object it holds stays, with its identity.
    let dir = fix.node("dir");
    let old = raw(b"", "dir");
    let got = fix.change(|f| {
        f.vault.rename(&dir, &f.root, "dir renamed").unwrap();
    });
    let new = raw(b"", "dir renamed");
    assert_eq!(
        got,
        Change {
            removed: set(&[format!("{old}/"), format!("{old}/dir.c9r")]),
            added: set(&[format!("{new}/"), format!("{new}/dir.c9r")]),
            ..Change::default()
        }
    );
}

/// One delete: only its own object goes.
#[test]
fn one_delete_removes_only_its_own_object() {
    let fix = built();
    let node = fix.node("delete-me.bin");
    let base = fix.digest(&node);
    let got = fix.change(|f| f.vault.delete_file(&node, &base).unwrap());
    assert_eq!(
        got,
        Change {
            removed: set(&[raw(b"", "delete-me.bin")]),
            ..Change::default()
        }
    );

    let name = long_name("delete");
    let node = fix.node(&name);
    let base = fix.digest(&node);
    let entry = long_entry(b"", &name);
    let got = fix.change(|f| f.vault.delete_file(&node, &base).unwrap());
    assert_eq!(
        got,
        Change {
            removed: set(&[
                format!("{entry}/"),
                format!("{entry}/contents.c9r"),
                format!("{entry}/name.c9s")
            ]),
            ..Change::default()
        }
    );
}

/// A folder made and removed: its node, its content folder and its backup, and only those
/// (the shared first level of the path goes only when empty).
#[test]
fn a_folder_touches_only_its_own_objects() {
    let fix = built();
    let mut made = None;
    let got = fix.change(|f| made = Some(f.vault.make_dir(&f.root, "made").unwrap()));
    let node = made.unwrap();
    assert!(got.removed.is_empty() && got.changed.is_empty(), "{got:?}");
    let entry = raw(b"", "made");
    assert!(got.added.contains(&format!("{entry}/dir.c9r")));
    assert_eq!(
        got.added
            .iter()
            .filter(|p| p.ends_with("/dirid.c9r"))
            .count(),
        1
    );
    // Node folder + marker + content folder + backup, and at most a new first level.
    assert!(got.added.len() == 4 || got.added.len() == 5, "{got:?}");
    let undo = fix.change(|f| f.vault.delete_dir(&node).unwrap());
    assert_eq!(undo.removed, got.added, "exactly what it added");
    assert!(undo.added.is_empty() && undo.changed.is_empty());
}
