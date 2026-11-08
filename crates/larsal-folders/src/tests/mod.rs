//! Tests that reach seams: faults, crash points, the KDF count.

#[path = "../../tests/common/mod.rs"]
pub(crate) mod common;

mod changes;
mod content_rules;
mod metadata;
mod names_rules;
mod session;

use crate::{Entry, Kind, Node, Stores, Vault};
use common::{PASSWORD, fresh, make_folder, secret};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static SLOW_FIRST_MS: AtomicU64 = AtomicU64::new(0);

/// A worker that sits on the first chunk while the others go on (FIL-04-T06).
pub(crate) fn slow_first_chunk(index: u64) {
    let ms = SLOW_FIRST_MS.load(Ordering::SeqCst);
    if index == 0 && ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

thread_local! {
    pub(crate) static SWAP_UNSUPPORTED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn swap_says_unsupported() -> bool {
    SWAP_UNSUPPORTED.with(Cell::get)
}

/// A hand-made folder, opened, with its paths.
pub(crate) struct Fx {
    pub(crate) top: PathBuf,
    pub(crate) path: PathBuf,
    pub(crate) stores_path: PathBuf,
    pub(crate) stores: Stores,
    pub(crate) vault: Vault,
}

pub(crate) fn fx(tag: &str) -> Fx {
    let top = fresh(tag);
    let path = top.join("folder");
    let stores_path = top.join("stores");
    make_folder(&path, PASSWORD);
    let stores = Stores::open(&stores_path).unwrap();
    let vault = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap();
    Fx {
        top,
        path,
        stores_path,
        stores,
        vault,
    }
}

impl Fx {
    pub(crate) fn reopen(&mut self) {
        self.vault.lock();
        self.vault = Vault::unlock(&self.path, &secret(PASSWORD), &self.stores, &mut |_, _| {
            true
        })
        .unwrap();
    }

    pub(crate) fn root(&self) -> Node {
        self.vault.root_dir().unwrap()
    }

    pub(crate) fn write(&self, parent: &Node, name: &str, bytes: &[u8]) -> Node {
        self.vault
            .create_file(
                parent,
                name,
                &mut &bytes[..],
                bytes.len() as u64,
                &mut |_, _| true,
            )
            .unwrap()
    }

    pub(crate) fn read(&self, node: &Node) -> Vec<u8> {
        let mut out = Vec::new();
        self.vault
            .read_to(node, &mut out, &mut |_, _| true)
            .unwrap();
        out
    }

    pub(crate) fn digest(&self, node: &Node) -> crate::Digest {
        self.vault.capture(node, &mut |_, _| true).unwrap().digest()
    }

    /// Every row of a folder.
    pub(crate) fn rows(&self, dir: &Node) -> Vec<Entry> {
        let mut listing = self.vault.open_listing(dir).unwrap();
        let mut all = Vec::new();
        loop {
            let page = listing.next_page(256).unwrap();
            if page.is_empty() {
                return all;
            }
            all.extend(page);
        }
    }

    /// (name, kind) of every row, sorted; an invalid row shows as `?`.
    pub(crate) fn names(&self, dir: &Node) -> Vec<(String, Kind)> {
        let mut rows: Vec<_> = self
            .rows(dir)
            .into_iter()
            .map(|r| {
                (
                    r.name
                        .map_or_else(|| "?".to_owned(), |n| n.expose().to_owned()),
                    r.kind,
                )
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    pub(crate) fn find(&self, dir: &Node, name: &str) -> Entry {
        self.vault.lookup(dir, name).unwrap().unwrap()
    }

    pub(crate) fn no_staging_left(&self) -> bool {
        std::fs::read_dir(&self.path).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".larsal-staging-")
        })
    }
}
