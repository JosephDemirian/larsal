//! E23-S3 check 6, FIL-04-T13: after every ending of every operation, no freed heap block
//! holds the password, a master key, the key that unwraps them, a derived local key, a
//! content key, plaintext or a clear name. Each ending runs on its own, for each secret,
//! so a failure names both. A file of whole chunks, a file of one short chunk and a mixed
//! file all go through each ending that reads or writes one (F-342 not repeated). One test
//! only: the probe counts every block the process frees.
//!
//! What this cannot see, and does not claim: stacks (this one and the workers'), registers,
//! a crypto backend's copies on the stack, kernel buffers and page cache, swap, live blocks
//! still held, allocator metadata, memory not from the allocator, and any target but this
//! Mac's. The independent memory proof on both Mac targets stays open (FIL-04.13).

mod common;

use common::{
    CHUNK, ENC, HEADER, KeySettings, MAC, dir_path, jws, key_file, make_folder_with, raw_name,
    seal_with,
};
use larsal_crypto::kdf;
use larsal_crypto::mac;
use larsal_crypto::secret::SecretString;
use larsal_folders::{Error, Kept, Kind, Node, Phase, Stores, Vault};
use larsal_platform::memory::{Probe, Seen, set_needle};
use std::alloc::System;
use std::fs;
use std::hint::black_box;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

/// In NFC, and as typed: decomposed. Both are secrets with their own needle.
const PASSWORD_NFC: &str = "E23pass\u{e9}-demo-word";
const PASSWORD_TYPED: &str = "E23passe\u{301}-demo-word";
const NAME: &str = "E23name-marker.txt";
const NAME_LOWER: [u8; 8] = *b"e23name-";
const LONG_NAME: &str = "E23name-long-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt";
const CONTENT_KEY: [u8; 32] = *b"E23-demo-content-key-E23-demo-co";
const SALT: [u8; 16] = [0x5A; 16];
const MARKER: [u8; 8] = *b"E23plain";

const MIXED_LEN: usize = CHUNK * 2 + 1000;
static PLAINTEXT: [u8; MIXED_LEN] = {
    let mut bytes = [0x20; MIXED_LEN];
    let mut i = 0;
    while i + 8 <= MIXED_LEN {
        let mut j = 0;
        while j < 8 {
            bytes[i + j] = MARKER[j];
            j += 1;
        }
        i += 512;
    }
    bytes
};

/// Whole chunks only; one short chunk; both.
const SIZES: [(&str, usize); 3] = [
    ("whole.bin", CHUNK * 2),
    ("short.bin", 1000),
    ("mixed.bin", MIXED_LEN),
];

fn plain(len: usize) -> &'static [u8] {
    &PLAINTEXT[..len]
}

fn first8(bytes: &[u8]) -> [u8; 8] {
    bytes[..8].try_into().unwrap()
}

struct Ctx {
    folder: PathBuf,
    stores: Stores,
    bad_version: PathBuf,
    bad_signature: PathBuf,
    other_cipher: PathBuf,
    top: PathBuf,
}

fn secret(text: &'static str) -> SecretString {
    SecretString::from(text)
}

fn open(ctx: &Ctx) -> Vault {
    Vault::unlock(
        &ctx.folder,
        &secret(PASSWORD_TYPED),
        &ctx.stores,
        &mut |_, _| true,
    )
    .unwrap()
}

fn node(vault: &Vault, name: &str) -> Node {
    let root = vault.root_dir().unwrap();
    vault.lookup(&root, name).unwrap().unwrap().node
}

struct Refuses;
impl Write for Refuses {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("no"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for Refuses {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("no"))
    }
}

/// Reads part of `plain`, then fails: an input that dies in the middle.
struct DiesAfter(&'static [u8]);
impl Read for DiesAfter {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::Error::other("no"));
        }
        let n = out.len().min(self.0.len());
        out[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

fn each_stored(mut work: impl FnMut(&str)) {
    for (name, _) in SIZES {
        work(name);
    }
}

fn unlock_wrong_password(c: &Ctx) {
    let got = Vault::unlock(
        &c.folder,
        &secret("E23passewrong-demo-word"),
        &c.stores,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Open));
}
fn unlock_cancel_before_kdf(c: &Ctx) {
    let got = Vault::unlock(
        &c.folder,
        &secret(PASSWORD_TYPED),
        &c.stores,
        &mut |_, _| false,
    );
    assert_eq!(got.err(), Some(Error::Cancelled));
}
fn unlock_cancel_after_kdf(c: &Ctx) {
    let mut calls = 0;
    let got = Vault::unlock(
        &c.folder,
        &secret(PASSWORD_TYPED),
        &c.stores,
        &mut |_, _| {
            calls += 1;
            calls < 2
        },
    );
    assert_eq!(got.err(), Some(Error::Cancelled));
}
fn unlock_bad_version_mac(c: &Ctx) {
    let got = Vault::unlock(
        &c.bad_version,
        &secret(PASSWORD_TYPED),
        &c.stores,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Open));
}
fn unlock_bad_signature(c: &Ctx) {
    let got = Vault::unlock(
        &c.bad_signature,
        &secret(PASSWORD_TYPED),
        &c.stores,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Open));
}
fn unlock_other_cipher(c: &Ctx) {
    let got = Vault::unlock(
        &c.other_cipher,
        &secret(PASSWORD_TYPED),
        &c.stores,
        &mut |_, _| true,
    );
    assert!(matches!(got.err(), Some(Error::Profile(_))));
}
fn drop_without_lock(c: &Ctx) {
    drop(black_box(open(c)));
}
fn lock_then_drop(c: &Ctx) {
    let v = open(c);
    v.lock();
    drop(black_box(v));
}
fn list_lookup_then_lock(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    let mut listing = v.open_listing(&root).unwrap();
    let mut names = 0;
    loop {
        let page = listing.next_page(256).unwrap();
        if page.is_empty() {
            break;
        }
        names += page.iter().filter(|r| r.name.is_some()).count();
    }
    assert!(names >= 4);
    assert_eq!(v.lookup(&root, NAME).unwrap().unwrap().kind, Kind::File);
    assert_eq!(
        v.lookup(&root, LONG_NAME).unwrap().unwrap().kind,
        Kind::File
    );
    v.lock();
}
fn listing_left_open_at_lock(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    let mut listing = v.open_listing(&root).unwrap();
    let page = listing.next_page(2).unwrap();
    v.lock();
    drop(black_box(page));
    assert_eq!(listing.next_page(2).err(), Some(Error::Locked));
}
fn read_success(c: &Ctx) {
    let v = open(c);
    each_stored(|name| {
        let got = v.read_to(&node(&v, name), &mut io::sink(), &mut |_, _| true);
        assert!(got.is_ok(), "{name}");
    });
    v.lock();
}
fn read_cancel_each_pass(c: &Ctx) {
    let v = open(c);
    for phase in [Phase::Capture, Phase::Validate, Phase::Write] {
        each_stored(|name| {
            let got = v.read_to(&node(&v, name), &mut io::sink(), &mut |p, _| p != phase);
            assert_eq!(got.err(), Some(Error::Cancelled), "{name} {phase:?}");
        });
    }
    v.lock();
}
fn read_bad_last_chunk(c: &Ctx) {
    let v = open(c);
    for name in ["bad-whole.bin", "bad-short.bin", "bad-mixed.bin"] {
        let got = v.read_to(&node(&v, name), &mut io::sink(), &mut |_, _| true);
        assert_eq!(got.err(), Some(Error::Open), "{name}");
    }
    v.lock();
}
fn read_bad_header(c: &Ctx) {
    let v = open(c);
    let got = v.read_to(&node(&v, "bad-header.bin"), &mut io::sink(), &mut |_, _| {
        true
    });
    assert_eq!(got.err(), Some(Error::Open));
    v.lock();
}
fn read_sink_fails(c: &Ctx) {
    let v = open(c);
    each_stored(|name| {
        let got = v.read_to(&node(&v, name), &mut Refuses, &mut |_, _| true);
        assert_eq!(got.err(), Some(Error::Io), "{name}");
    });
    v.lock();
}
fn states_dropped_unused(c: &Ctx) {
    let v = open(c);
    each_stored(|name| {
        let n = node(&v, name);
        drop(black_box(v.capture(&n, &mut |_, _| true).unwrap()));
        let proven = v
            .capture(&n, &mut |_, _| true)
            .unwrap()
            .validate(&mut |_, _| true)
            .unwrap();
        drop(black_box(proven));
    });
    v.lock();
}
fn revoke_each_pass(c: &Ctx) {
    for phase in [Phase::Validate, Phase::Write] {
        each_stored(|name| {
            let v = open(c);
            let n = node(&v, name);
            let got = v.read_to(&n, &mut io::sink(), &mut |p, _| {
                if p == phase {
                    v.revoke();
                }
                true
            });
            // One short chunk is already out when the release pass first asks: nothing is left
            // to stop. The rule itself is in the crate's session tests.
            if name != "short.bin" || phase != Phase::Write {
                assert_eq!(got.err(), Some(Error::Locked), "{name} {phase:?}");
            }
            v.lock();
        });
    }
}
fn lock_from_another_thread(c: &Ctx) {
    each_stored(|name| {
        let v = open(c);
        let n = node(&v, name);
        let done = std::sync::Barrier::new(2);
        std::thread::scope(|s| {
            let locker = s.spawn(|| {
                done.wait();
                v.lock();
            });
            let mut once = true;
            let got = v.read_to(&n, &mut io::sink(), &mut |p, _| {
                if once && p == Phase::Write {
                    once = false;
                    done.wait();
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                true
            });
            locker.join().unwrap();
            assert!(got.is_err() || name == "short.bin", "{name}");
        });
    });
}
fn write_success(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    for (name, len) in SIZES {
        let target = match name {
            "whole.bin" => "E23name-new-whole",
            "short.bin" => "E23name-new-short",
            _ => "E23name-new-mixed",
        };
        let n = v
            .create_file(&root, target, &mut plain(len), len as u64, &mut |_, _| true)
            .unwrap();
        v.read_to(&n, &mut io::sink(), &mut |_, _| true).unwrap();
        let base = v.capture(&n, &mut |_, _| true).unwrap().digest();
        v.delete_file(&n, &base).unwrap();
    }
    v.lock();
}
fn write_cancel(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    for (_, len) in SIZES {
        let got = v.create_file(
            &root,
            "E23name-cancel",
            &mut plain(len),
            len as u64,
            &mut |_, _| false,
        );
        assert_eq!(got.err(), Some(Error::Cancelled));
    }
    v.lock();
}
fn write_input_fails(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    let got = v.create_file(&root, "E23name-fail", &mut Refuses, 10, &mut |_, _| true);
    assert_eq!(got.err(), Some(Error::Io));
    let got = v.create_file(
        &root,
        "E23name-dies",
        &mut DiesAfter(plain(CHUNK + 10)),
        MIXED_LEN as u64,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Io));
    v.lock();
}
fn write_length_mismatch(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    for (_, len) in SIZES {
        let got = v.create_file(
            &root,
            "E23name-len",
            &mut plain(len),
            len as u64 + 1,
            &mut |_, _| true,
        );
        assert_eq!(got.err(), Some(Error::Input));
    }
    v.lock();
}
fn revoke_during_encrypt(c: &Ctx) {
    for (_, len) in SIZES {
        let v = open(c);
        let root = v.root_dir().unwrap();
        let got = v.create_file(
            &root,
            "E23name-revoked",
            &mut plain(len),
            len as u64,
            &mut |_, _| {
                v.revoke();
                true
            },
        );
        assert_eq!(got.err(), Some(Error::Locked));
        v.lock();
    }
}
fn update_and_rename_and_delete(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    let n = v
        .create_file(
            &root,
            "E23name-update",
            &mut plain(1000),
            1000,
            &mut |_, _| true,
        )
        .unwrap();
    let base = v.capture(&n, &mut |_, _| true).unwrap().digest();
    v.update_file(
        &n,
        &base,
        &mut plain(MIXED_LEN),
        MIXED_LEN as u64,
        &mut |_, _| true,
    )
    .unwrap();
    // A stale base: both kept.
    v.update_file(&n, &base, &mut plain(CHUNK), CHUNK as u64, &mut |_, _| true)
        .unwrap();
    let moved = v.rename(&n, &root, "E23name-renamed").unwrap();
    let dir = v.make_dir(&root, "E23name-dir").unwrap();
    let inner = v
        .create_file(&dir, "E23name-inner", &mut plain(10), 10, &mut |_, _| true)
        .unwrap();
    let _ = inner;
    v.delete_tree(&dir).unwrap();
    let rows = v.recovery_items().unwrap();
    assert!(rows.iter().any(|r| r.name.is_some()));
    for row in &rows {
        if row.base.is_some() {
            let copy = v
                .capture_recovery(&row.id, Kept::Base, &mut |_, _| true)
                .unwrap();
            copy.validate(&mut |_, _| true)
                .unwrap()
                .write_to(&mut io::sink(), &mut |_, _| true)
                .unwrap();
            break;
        }
    }
    let base = v.capture(&moved, &mut |_, _| true).unwrap().digest();
    v.delete_file(&moved, &base).unwrap();
    // Whatever kept versions are left stay as they are for the next ending.
    v.lock();
}
fn admit_a_version(c: &Ctx) {
    let v = open(c);
    let root = v.root_dir().unwrap();
    let raw = fs::read(c.top.join("candidate")).unwrap();
    let got = v.admit_version(
        &root,
        "E23name-admit",
        &mut &raw[..],
        raw.len() as u64,
        &mut |_, _| true,
    );
    assert!(got.is_ok());
    let bad = fs::read(c.top.join("bad-candidate")).unwrap();
    let got = v.admit_version(
        &root,
        "E23name-admit-bad",
        &mut &bad[..],
        bad.len() as u64,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Open));
    v.lock();
}
fn create_a_new_folder(c: &Ctx) {
    let path = c.top.join("made-new");
    let v = Vault::create(&path, &secret(PASSWORD_TYPED), &c.stores, &mut |_, _| true).unwrap();
    let root = v.root_dir().unwrap();
    v.create_file(
        &root,
        "E23name-in-new",
        &mut plain(1000),
        1000,
        &mut |_, _| true,
    )
    .unwrap();
    v.lock();
    drop(v);
    let cancelled = c.top.join("made-cancelled");
    let got = Vault::create(
        &cancelled,
        &secret(PASSWORD_TYPED),
        &c.stores,
        &mut |_, _| false,
    );
    assert_eq!(got.err(), Some(Error::Cancelled));
}

type Ending = (&'static str, fn(&Ctx));

const ENDINGS: [Ending; 24] = [
    ("unlock: wrong password", unlock_wrong_password),
    (
        "unlock: cancel before the key work",
        unlock_cancel_before_kdf,
    ),
    ("unlock: cancel after the key work", unlock_cancel_after_kdf),
    ("unlock: bad version MAC", unlock_bad_version_mac),
    ("unlock: bad signature", unlock_bad_signature),
    (
        "unlock: another cipher, refused by name",
        unlock_other_cipher,
    ),
    ("session: dropped with no lock", drop_without_lock),
    ("session: locked, then dropped", lock_then_drop),
    (
        "names: listed and looked up, then lock",
        list_lookup_then_lock,
    ),
    (
        "names: a listing left open at lock",
        listing_left_open_at_lock,
    ),
    ("read: success", read_success),
    ("read: cancel in each pass", read_cancel_each_pass),
    ("read: bad last chunk", read_bad_last_chunk),
    ("read: bad header", read_bad_header),
    ("read: the sink fails", read_sink_fails),
    ("read: states dropped unused", states_dropped_unused),
    ("read: revoke in each pass", revoke_each_pass),
    ("read: lock from another thread", lock_from_another_thread),
    ("write: success, read, delete", write_success),
    ("write: cancel", write_cancel),
    ("write: the input fails", write_input_fails),
    ("write: the input is not its length", write_length_mismatch),
    ("write: revoke while encrypting", revoke_during_encrypt),
    (
        "change: update, stale update, rename, tree delete, recovery names",
        update_and_rename_and_delete,
    ),
];

fn make_context(tag: &str) -> Ctx {
    let top = common::fresh(tag);
    let folder = top.join("folder");
    let settings = KeySettings {
        salt: SALT.to_vec(),
        ..KeySettings::default()
    };
    let key = key_file(PASSWORD_NFC, &settings);
    let config = jws(&ENC, &MAC, HEADER, common::CLAIMS);
    make_folder_with(&folder, &key, &config);
    let dir = folder.join(dir_path(&ENC, &MAC, b""));
    let raw_at = |name: &str| dir.join(raw_name(&ENC, &MAC, b"", name));
    for (name, len) in SIZES {
        fs::write(
            raw_at(name),
            seal_with(&ENC, &CONTENT_KEY, plain(len), false),
        )
        .unwrap();
        let mut bad = seal_with(&ENC, &CONTENT_KEY, plain(len), false);
        let end = bad.len() - 1;
        bad[end] ^= 1;
        fs::write(raw_at(&format!("bad-{name}")), bad).unwrap();
    }
    let mut bad_header = seal_with(&ENC, &CONTENT_KEY, plain(1000), false);
    bad_header[60] ^= 1;
    fs::write(raw_at("bad-header.bin"), bad_header).unwrap();
    fs::write(
        raw_at(NAME),
        seal_with(&ENC, &CONTENT_KEY, plain(1000), false),
    )
    .unwrap();
    let long = dir.join(common::deflated(&raw_name(&ENC, &MAC, b"", LONG_NAME)));
    fs::create_dir(&long).unwrap();
    fs::write(long.join("name.c9s"), raw_name(&ENC, &MAC, b"", LONG_NAME)).unwrap();
    fs::write(
        long.join("contents.c9r"),
        seal_with(&ENC, &CONTENT_KEY, plain(1000), false),
    )
    .unwrap();

    let bad_version = top.join("bad-version");
    let good = larsal_model::json::from_str(&key).unwrap();
    let tag_text = good.get("versionMac").unwrap().as_str().unwrap().to_owned();
    let mut tag_bytes =
        larsal_crypto::base64::decode(larsal_crypto::base64::Form::Padded, &tag_text).unwrap();
    tag_bytes[0] ^= 1;
    let other_tag = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, &tag_bytes);
    make_folder_with(&bad_version, &key.replace(&tag_text, &other_tag), &config);
    let bad_signature = top.join("bad-signature");
    make_folder_with(
        &bad_signature,
        &key,
        &jws(&[1; 32], &[2; 32], HEADER, common::CLAIMS),
    );
    let other_cipher = top.join("other-cipher");
    let claims = common::CLAIMS.replace("SIV_GCM", "SIV_CTRMAC");
    make_folder_with(&other_cipher, &key, &jws(&ENC, &MAC, HEADER, &claims));

    fs::write(
        top.join("candidate"),
        seal_with(&ENC, &CONTENT_KEY, plain(MIXED_LEN), false),
    )
    .unwrap();
    let mut bad_candidate = seal_with(&ENC, &CONTENT_KEY, plain(MIXED_LEN), false);
    let end = bad_candidate.len() - 1;
    bad_candidate[end] ^= 1;
    fs::write(top.join("bad-candidate"), bad_candidate).unwrap();

    let stores = Stores::open(&top.join("stores")).unwrap();
    Ctx {
        folder,
        stores,
        bad_version,
        bad_signature,
        other_cipher,
        top,
    }
}

fn check(what: &str, ending: &str, needle: [u8; 8], ctx: &Ctx, work: fn(&Ctx)) {
    set_needle(needle);
    SEEN.reset();
    work(ctx);
    let found = SEEN.with_needle.load(Relaxed);
    let largest = SEEN.largest_with_needle.load(Relaxed);
    set_needle([0; 8]);
    assert_eq!(
        found, 0,
        "{what} after \"{ending}\": {found} freed blocks, the largest {largest} bytes"
    );
}

fn scratch_is_empty(path: &Path) -> bool {
    fs::read_dir(path.join("stores/scratch"))
        .unwrap()
        .next()
        .is_none()
}

#[test]
fn fil04_t13_every_ending_leaves_no_secret_in_a_freed_block() {
    // Control: the probe sees a block that was not wiped.
    set_needle(MARKER);
    SEEN.reset();
    drop(black_box(b"E23plain demo".to_vec()));
    assert!(SEEN.with_needle.load(Relaxed) >= 1, "the probe saw nothing");
    set_needle([0; 8]);

    let kek = kdf::scrypt(PASSWORD_NFC.as_bytes(), &SALT, 4, 8, 1, 32).unwrap();
    let journal_key = mac::hmac_sha256(&MAC, &[b"larsal-folders journal v1"]).unwrap();
    let ledger_key = mac::hmac_sha256(&MAC, &[b"larsal-folders ledger v1"]).unwrap();
    let needles: [(&str, [u8; 8]); 11] = [
        ("password as typed", first8(PASSWORD_TYPED.as_bytes())),
        ("password in NFC", first8(PASSWORD_NFC.as_bytes())),
        ("key from the password", first8(kek.expose())),
        ("encryption master key", first8(&ENC)),
        ("MAC master key", first8(&MAC)),
        ("journal key", first8(journal_key.expose())),
        ("ledger key", first8(ledger_key.expose())),
        ("content key", first8(&CONTENT_KEY)),
        ("plaintext", MARKER),
        ("clear name", first8(NAME.as_bytes())),
        ("folded name", NAME_LOWER),
    ];
    for (what, needle) in needles {
        let ctx = make_context("wipe");
        for (ending, work) in ENDINGS {
            check(what, ending, needle, &ctx, work);
        }
        check(
            what,
            "change: a version admitted, a bad one refused",
            needle,
            &ctx,
            admit_a_version,
        );
        assert!(scratch_is_empty(&ctx.top), "no scratch stays");
        // The costly key work once per secret that goes through it.
        if what.starts_with("password") {
            check(
                what,
                "create: a new folder, then a cancelled one",
                needle,
                &ctx,
                create_a_new_folder,
            );
        }
    }
    println!(
        "{} secrets, {} endings each, nothing found",
        needles.len(),
        ENDINGS.len() + 1
    );
}
