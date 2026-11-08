//! E23-S3 check 5, the exact original check (LD-373): every byte of a header, nonce,
//! payload and tag in a small file, changed, gives the one generic error and no plaintext,
//! with no early plaintext. Authentic substitution, replay and whole-chunk removal are not
//! changed bytes: they are S6's disclosure limits, recorded in the crate's unit tests
//! `fil04_t07_*` and `fil04_t08_*`, as LD-373 says.

mod common;

use common::{
    CHUNK, ENC, MAC, PASSWORD, demo_bytes, dir_path, fresh, make_folder, raw_name, seal_plain,
    secret,
};
use larsal_folders::{Error, Kind, Node, Phase, Stores, Vault};
use std::fs;
use std::path::PathBuf;

struct Fix {
    path: PathBuf,
    vault: Vault,
    root: Node,
    _stores: Stores,
}

fn built(tag: &str) -> Fix {
    let top = fresh(tag);
    let path = top.join("folder");
    make_folder(&path, PASSWORD);
    let stores = Stores::open(&top.join("stores")).unwrap();
    let vault = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap();
    let root = vault.root_dir().unwrap();
    Fix {
        path,
        vault,
        root,
        _stores: stores,
    }
}

impl Fix {
    fn raw_path(&self, name: &str) -> PathBuf {
        self.path
            .join(dir_path(&ENC, &MAC, b""))
            .join(raw_name(&ENC, &MAC, b"", name))
    }
}

/// The regions of a one-chunk file, by the public layout.
const REGIONS: [(&str, usize, usize); 6] = [
    ("header nonce", 0, 12),
    ("header payload", 12, 52),
    ("header tag", 52, 68),
    ("chunk nonce", 68, 80),
    ("chunk payload", 80, 180),
    ("chunk tag", 180, 196),
];

#[test]
fn every_changed_byte_of_a_small_file_is_the_one_error_with_no_plaintext() {
    let fix = built("flip");
    let plain = demo_bytes(100, 3);
    let node = fix
        .vault
        .create_file(&fix.root, "small.bin", &mut &plain[..], 100, &mut |_, _| {
            true
        })
        .unwrap();
    let path = fix.raw_path("small.bin");
    let good = fs::read(&path).unwrap();
    assert_eq!(good.len(), 196);
    let mut out = Vec::new();
    assert_eq!(
        fix.vault.read_to(&node, &mut out, &mut |_, _| true),
        Ok(100),
        "control"
    );
    assert_eq!(out, plain);

    let mut tried = 0;
    for (region, from, to) in REGIONS {
        for at in from..to {
            for bit in [0x01u8, 0x80] {
                let mut bad = good.clone();
                bad[at] ^= bit;
                fs::write(&path, &bad).unwrap();
                let mut out = Vec::new();
                let mut write_phase = false;
                let got = fix.vault.read_to(&node, &mut out, &mut |p, _| {
                    write_phase |= p == Phase::Write;
                    true
                });
                assert_eq!(got.err(), Some(Error::Open), "{region} byte {at}");
                assert_eq!(
                    got.err().unwrap().to_string(),
                    "This encrypted folder or file could not be opened. Check the password and try again."
                );
                assert!(
                    out.is_empty(),
                    "{region} byte {at}: plaintext reached the sink"
                );
                assert!(!write_phase, "{region} byte {at}: the release pass began");
                tried += 1;
            }
        }
    }
    assert_eq!(tried, 196 * 2, "every byte of the file, twice");
    fs::write(&path, &good).unwrap();
    assert_eq!(
        fix.vault.read_to(&node, &mut Vec::new(), &mut |_, _| true),
        Ok(100),
        "and back"
    );
}

/// FIL-04.5: a header sealed under the right key, whose eight reserved bytes are not the
/// format's 0xFF, is refused with the one error and no plaintext; the same file with them
/// right opens.
#[test]
fn a_header_with_other_reserved_bytes_is_refused() {
    use larsal_crypto::gcm;
    use larsal_crypto::secret::SecretBytes;
    let fix = built("reserved");
    let good = common::seal_with(&ENC, &[0x42; 32], b"reserved bytes", false);
    for (name, first) in [("right.bin", 0xFFu8), ("other.bin", 0xFE)] {
        let mut raw = good.clone();
        let mut payload = vec![0xFF; 8];
        payload[0] = first;
        payload.extend_from_slice(&[0x42; 32]);
        let nonce: [u8; 12] = raw[..12].try_into().unwrap();
        let tag =
            gcm::seal_in_place(&SecretBytes::new(ENC.to_vec()), &nonce, b"", &mut payload).unwrap();
        raw[12..52].copy_from_slice(&payload);
        raw[52..68].copy_from_slice(&tag);
        fs::write(fix.raw_path(name), &raw).unwrap();
        let row = fix.vault.lookup(&fix.root, name).unwrap().unwrap();
        let mut out = Vec::new();
        let got = fix.vault.read_to(&row.node, &mut out, &mut |_, _| true);
        if first == 0xFF {
            assert_eq!(got, Ok(14), "control");
        } else {
            assert_eq!(got.err(), Some(Error::Open));
            assert!(out.is_empty());
        }
    }
}

/// A bad byte at the very end of a long file: no earlier chunk's plaintext ever comes
/// out, with one worker or with four.
#[test]
fn no_early_plaintext_when_the_last_chunk_is_bad() {
    let fix = built("late");
    let plain = demo_bytes(CHUNK * 3 + 50, 4);
    let node = fix
        .vault
        .create_file(
            &fix.root,
            "late.bin",
            &mut &plain[..],
            plain.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    let path = fix.raw_path("late.bin");
    let good = fs::read(&path).unwrap();
    let tail_tag = good.len() - 1;
    let last_payload = good.len() - 17;
    let last_nonce = good.len() - (50 + 28);
    let first_tag = 68 + 12 + CHUNK + 15;
    for workers in [1, 4] {
        fix.vault.set_workers(workers);
        for at in [tail_tag, last_payload, last_nonce, first_tag] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            fs::write(&path, &bad).unwrap();
            let mut out = Vec::new();
            let mut progress = 0u64;
            let got = fix.vault.read_to(&node, &mut out, &mut |p, n| {
                if p == Phase::Write {
                    progress = n;
                }
                true
            });
            assert_eq!(got.err(), Some(Error::Open), "{workers} {at}");
            assert!(out.is_empty(), "{workers} {at}");
            assert_eq!(progress, 0, "{workers} {at}");
        }
    }
    fs::write(&path, &good).unwrap();
    let mut out = Vec::new();
    fix.vault
        .read_to(&node, &mut out, &mut |_, _| true)
        .unwrap();
    assert_eq!(out, plain);
}

/// Every byte of an encrypted name, changed: no name, a visible invalid row, and the row
/// holds no raw text. The file stays.
#[test]
fn every_changed_byte_of_a_stored_name_gives_no_name() {
    let fix = built("name");
    let plain = b"named";
    fix.vault
        .create_file(&fix.root, "n.txt", &mut &plain[..], 5, &mut |_, _| true)
        .unwrap();
    let folder = fix.path.join(dir_path(&ENC, &MAC, b""));
    let stored = raw_name(&ENC, &MAC, b"", "n.txt");
    let body = stored
        .strip_suffix(".c9r")
        .unwrap()
        .trim_end_matches('=')
        .to_owned();
    let padding = &stored[body.len()..];
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut good_path = folder.join(&stored);
    for at in 0..body.len() {
        let was = body.as_bytes()[at];
        let now = ALPHABET.bytes().find(|c| *c != was).unwrap();
        let mut changed = body.clone().into_bytes();
        changed[at] = now;
        let changed = format!("{}{padding}", String::from_utf8(changed).unwrap());
        let next = folder.join(&changed);
        fs::rename(&good_path, &next).unwrap();
        good_path = next;
        let mut listing = fix.vault.open_listing(&fix.root).unwrap();
        let rows = listing.next_page(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, Kind::Invalid, "byte {at}");
        assert!(rows[0].name.is_none(), "byte {at}");
    }
    assert_eq!(
        fs::read_dir(&folder).unwrap().count(),
        2,
        "the object and the backup"
    );
}

/// FIL-04.7's list, separately: what the format does not authenticate, shown doing what it
/// does, with no claim. A folder's ID link can point at another authentic folder; a key
/// file's spacing and member order are free; storage times mean nothing. A name's mapping
/// file only ever leads to a name that proves itself.
#[test]
fn fil04_t07_the_unauthenticated_representations_itemized() {
    let fix = built("unauth");
    let a = fix.vault.make_dir(&fix.root, "a").unwrap();
    let b = fix.vault.make_dir(&fix.root, "b").unwrap();
    fix.vault
        .create_file(&a, "in-a.txt", &mut &b"in a"[..], 4, &mut |_, _| true)
        .unwrap();
    fix.vault
        .create_file(&b, "in-b.txt", &mut &b"in b"[..], 4, &mut |_, _| true)
        .unwrap();
    let marker_a = fix.raw_path("a").join("dir.c9r");
    let marker_b = fix.raw_path("b").join("dir.c9r");
    // The link text: another authentic ID opens that folder under this one's name.
    let id_b = fs::read(&marker_b).unwrap();
    fs::write(&marker_a, &id_b).unwrap();
    let row = fix.vault.lookup(&fix.root, "a").unwrap().unwrap();
    let inside = fix.vault.lookup(&row.node, "in-b.txt").unwrap().unwrap();
    let mut out = Vec::new();
    fix.vault
        .read_to(&inside.node, &mut out, &mut |_, _| true)
        .unwrap();
    assert_eq!(out, b"in b", "not authenticated: S6 discloses it");

    // The key file's representation: other spacing and another order open the same keys.
    let key_path = fix.path.join("masterkey.cryptomator");
    let text = fs::read_to_string(&key_path).unwrap();
    fs::write(
        &key_path,
        format!("\n  {}\n", text.replace(",\"", ",\n \"")),
    )
    .unwrap();
    let stores = Stores::open(&fix.path.with_file_name("other-stores")).unwrap();
    assert!(Vault::unlock(&fix.path, &secret(PASSWORD), &stores, &mut |_, _| true).is_ok());

    // Times are never believed: a changed time on a stored file changes nothing it says.
    let file = fix.raw_path("t.bin");
    fs::write(&file, seal_plain(&ENC, b"timed")).unwrap();
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH)
        .unwrap();
    let row = fix.vault.lookup(&fix.root, "t.bin").unwrap().unwrap();
    let mut out = Vec::new();
    fix.vault
        .read_to(&row.node, &mut out, &mut |_, _| true)
        .unwrap();
    assert_eq!(out, b"timed");
}
