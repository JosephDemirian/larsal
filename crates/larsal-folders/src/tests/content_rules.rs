//! FIL-04-T05 to T08, T12 and FIL-06-T04, T05, T16: content, custody and budgets.

use super::common::*;
use super::{SLOW_FIRST_MS, fx};
use crate::content::{self, Gate, Plan};
use crate::error::Error;
use crate::keys::MasterKeys;
use crate::limits::{GCM_INVOCATIONS, QUEUE, RESERVE_BLOCK};
use crate::seam;
use crate::{Phase, Vault};
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::{gcm, hash};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

fn demo_keys() -> MasterKeys {
    MasterKeys::new(
        SecretBytes::new(ENC.to_vec()),
        SecretBytes::new(MAC.to_vec()),
    )
    .unwrap()
}

/// The raw path of a top-level plain file.
fn raw_path(fx: &super::Fx, name: &str) -> PathBuf {
    fx.path
        .join(dir_path(&ENC, &MAC, b""))
        .join(raw_name(&ENC, &MAC, b"", name))
}

const BOUNDARIES: [usize; 7] = [0, 1, 32_767, 32_768, 32_769, 65_536, 100_000];

/// FIL-04.5: the layout, by hand: header shape, chunk sizes, AAD, nothing extra.
#[test]
fn fil04_t05_every_boundary_size_has_the_public_layout() {
    let fx = fx("layout");
    let root = fx.root();
    for (i, size) in BOUNDARIES.into_iter().enumerate() {
        let name = format!("b{i}.bin");
        let plain = demo_bytes(size, i as u8);
        let node = fx.write(&root, &name, &plain);
        assert_eq!(fx.read(&node), plain, "{size}");
        let raw = fs::read(raw_path(&fx, &name)).unwrap();
        let chunks = size.div_ceil(CHUNK);
        assert_eq!(raw.len(), 68 + size + chunks * 28, "{size}");

        // Opened here by hand, through larsal-crypto, not by the crate's reader.
        let enc = SecretBytes::new(ENC.to_vec());
        let nonce: [u8; 12] = raw[..12].try_into().unwrap();
        let tag: [u8; 16] = raw[52..68].try_into().unwrap();
        let mut payload = raw[12..52].to_vec();
        gcm::open_in_place(&enc, &nonce, b"", &mut payload, &tag).unwrap();
        assert_eq!(&payload[..8], &[0xFF; 8]);
        let ck = SecretBytes::new(payload[8..].to_vec());
        let mut got = Vec::new();
        let mut at = 68;
        for index in 0..chunks {
            let part = (size - index * CHUNK).min(CHUNK);
            let n: [u8; 12] = raw[at..at + 12].try_into().unwrap();
            let mut data = raw[at + 12..at + 12 + part].to_vec();
            let t: [u8; 16] = raw[at + 12 + part..at + 28 + part].try_into().unwrap();
            let mut aad = (index as u64).to_be_bytes().to_vec();
            aad.extend_from_slice(&nonce);
            gcm::open_in_place(&ck, &n, &aad, &mut data, &t).unwrap();
            got.extend_from_slice(&data);
            at += 28 + part;
        }
        assert_eq!(at, raw.len());
        assert_eq!(got, plain);
    }
}

/// FIL-04.5: the same content written again, or retried: a fresh header, key and nonces.
#[test]
fn fil04_t05_every_write_is_fresh_even_of_the_same_content() {
    let fx = fx("fresh");
    let root = fx.root();
    let plain = demo_bytes(70_000, 9);
    let node = fx.write(&root, "same.bin", &plain);
    let first = fs::read(raw_path(&fx, "same.bin")).unwrap();
    let base = fx.digest(&node);
    let saved = fx
        .vault
        .update_file(
            &node,
            &base,
            &mut &plain[..],
            plain.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    assert_eq!(saved.outcome, crate::Outcome::Replaced);
    let second = fs::read(raw_path(&fx, "same.bin")).unwrap();
    assert_ne!(first[..12], second[..12], "header nonce");
    assert_ne!(first[12..52], second[12..52], "wrapped content key");
    for (a, b) in [(68usize, 68 + 12), (68 + 32_796, 68 + 32_796 + 12)] {
        assert_ne!(first[a..b], second[a..b], "a chunk nonce");
    }
    // A retry after a failure draws fresh too: a failed write leaves nothing to resume.
    seam::fail_at("write.chunk", Error::Io);
    let base = fx.digest(&node);
    assert_eq!(
        fx.vault
            .update_file(
                &node,
                &base,
                &mut &plain[..],
                plain.len() as u64,
                &mut |_, _| true
            )
            .err(),
        Some(Error::Io)
    );
    seam::clear();
    assert_eq!(
        fs::read(raw_path(&fx, "same.bin")).unwrap(),
        second,
        "no completed update"
    );
    assert!(fx.no_staging_left());
    fx.vault
        .update_file(
            &node,
            &base,
            &mut &plain[..],
            plain.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    assert_ne!(
        fs::read(raw_path(&fx, "same.bin")).unwrap()[..12],
        second[..12]
    );
}

/// The content key of a stored file, opened here by hand with the demo encryption key,
/// and every chunk nonce of it.
fn key_and_chunk_nonces(raw: &[u8]) -> ([u8; 32], Vec<[u8; 12]>) {
    let enc = SecretBytes::new(ENC.to_vec());
    let nonce: [u8; 12] = raw[..12].try_into().unwrap();
    let tag: [u8; 16] = raw[52..68].try_into().unwrap();
    let mut payload = raw[12..52].to_vec();
    gcm::open_in_place(&enc, &nonce, b"", &mut payload, &tag).unwrap();
    let key = payload[8..].try_into().unwrap();
    let nonces = raw[68..]
        .chunks(CHUNK + 28)
        .map(|slot| slot[..12].try_into().unwrap())
        .collect();
    (key, nonces)
}

/// Bits in which two byte strings of one length differ.
fn bits_apart(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// FIL-04.5, C2-01, C2R2-01: within one file every chunk has its own nonce, and every
/// write, of the same content too, has its own content key, never all zero, and its own
/// header nonce. Each pair of content keys differs in at least 64 of 256 bits and each
/// pair of header nonces in at least 16 of 96, so a counter or another guessable source
/// fails; two random draws fail this less than once in 10^9. Read from the stored bytes,
/// by opening each header with the vault's key here.
#[test]
fn fil04_t05_every_chunk_nonce_and_every_content_key_is_fresh() {
    let fx = fx("fresh-keys");
    let root = fx.root();
    let plain = demo_bytes(16 * CHUNK + 100, 5);
    let node = fx.write(&root, "many.bin", &plain);
    let first = fs::read(raw_path(&fx, "many.bin")).unwrap();
    let base = fx.digest(&node);
    fx.vault
        .update_file(
            &node,
            &base,
            &mut &plain[..],
            plain.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    let second = fs::read(raw_path(&fx, "many.bin")).unwrap();
    fx.write(&root, "twin.bin", &plain);
    let third = fs::read(raw_path(&fx, "twin.bin")).unwrap();
    let mut keys = std::collections::BTreeSet::new();
    let mut drawn = Vec::new();
    for raw in [&first, &second, &third] {
        let (key, nonces) = key_and_chunk_nonces(raw);
        assert_eq!(nonces.len(), 17, "a many-chunk file");
        let distinct: std::collections::BTreeSet<_> = nonces.iter().collect();
        assert_eq!(
            distinct.len(),
            nonces.len(),
            "a chunk nonce used twice in one file"
        );
        assert_ne!(key, [0u8; 32], "an all-zero content key");
        keys.insert(key);
        drawn.push((key, raw[..12].to_vec()));
    }
    assert_eq!(keys.len(), 3, "a content key used twice");
    for (i, (key, nonce)) in drawn.iter().enumerate() {
        for (other_key, other_nonce) in &drawn[i + 1..] {
            let keys_apart = bits_apart(key, other_key);
            let nonces_apart = bits_apart(nonce, other_nonce);
            assert!(
                keys_apart >= 64,
                "content keys {keys_apart} of 256 bits apart"
            );
            assert!(
                nonces_apart >= 16,
                "header nonces {nonces_apart} of 96 bits apart"
            );
        }
    }
}

/// FIL-04.12, FIL-04-T05: a failed random source stops before any usable output.
#[test]
fn fil04_t12_a_failed_random_source_gives_no_output() {
    let fx = fx("rng");
    let root = fx.root();
    let node = fx.write(&root, "old.bin", b"old");
    let before = raw_tree(&fx.path);
    let base = fx.digest(&node);
    seam::fail_rng(true);
    assert_eq!(
        fx.vault
            .update_file(&node, &base, &mut &b"new"[..], 3, &mut |_, _| true)
            .err(),
        Some(Error::Io)
    );
    assert_eq!(
        fx.vault
            .create_file(&root, "new.bin", &mut &b"new"[..], 3, &mut |_, _| true)
            .err(),
        Some(Error::Io)
    );
    seam::clear();
    assert_eq!(raw_tree(&fx.path), before);
    assert_eq!(fx.read(&node), b"old");
    assert!(fx.no_staging_left());
}

/// FIL-04.12: only larsal-crypto imports crypto, and this crate has no network, process
/// or plugin road: a scan of its own sources and manifest.
#[test]
fn fil04_t12_and_t15_the_crate_imports_no_primitive_and_no_network() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split('[')
        .next()
        .unwrap();
    let names: Vec<&str> = deps
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(names, ["larsal-crypto", "larsal-model", "larsal-platform"]);
    assert!(
        !deps.contains("net"),
        "the platform's network feature stays off"
    );
    for entry in fs::read_dir(root.join("src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for banned in [
            "aes_gcm",
            "aes_siv",
            "aes_kw",
            "scrypt::",
            "sha1::",
            "sha2::",
            "getrandom",
            "std::net",
            "std::process",
            "TcpStream",
            "UdpSocket",
            "Command::new",
            "println!",
            "eprintln!",
            "dbg!",
            "log::",
        ] {
            let hit = text
                .lines()
                .any(|l| !l.trim_start().starts_with("//") && l.contains(banned));
            assert!(!hit, "{banned} in {path:?}");
        }
    }
}

/// FIL-04.12, FIL-06.16, C2R2-02: every MAC or tag this crate checks goes through
/// larsal-crypto's constant-time verify, and the code that checks one holds no ordinary
/// equality, as larsal-crypto's own `no_ordinary_equality_in_the_mac_code` scan. Every
/// verify call of the crate is in one of these functions, so a new one cannot go unseen.
#[test]
fn fil04_t12_no_mac_or_tag_is_compared_with_ordinary_equality() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let checks = [
        ("budget.rs", "fn read_copy("),
        ("recovery.rs", "fn read_journal("),
        ("format.rs", "fn signed_by("),
        ("format.rs", "fn version_proven("),
    ];
    let mut scanned = std::collections::BTreeMap::new();
    for (file, start) in checks {
        let text = fs::read_to_string(src.join(file)).unwrap();
        let at = text.find(start).unwrap();
        let line_start = text[..at].rfind('\n').map_or(0, |n| n + 1);
        let indent: String = text[line_start..]
            .chars()
            .take_while(|c| *c == ' ')
            .collect();
        let end = at + text[at..].find(&format!("\n{indent}}}\n")).unwrap();
        let body = &text[at..end];
        assert!(
            body.contains("mac::verify_"),
            "{file} {start} verifies nothing"
        );
        for line in body.lines().filter(|l| !l.trim_start().starts_with("//")) {
            for op in ["==", "!=", ".eq(", ".ne("] {
                assert!(!line.contains(op), "{file} {start} uses {op}: {line}");
            }
        }
        *scanned.entry(file).or_insert(0) += body.matches("mac::verify_").count();
    }
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let calls = fs::read_to_string(&path)
            .unwrap()
            .matches("mac::verify_")
            .count();
        assert_eq!(
            calls,
            scanned.get(name.as_str()).copied().unwrap_or(0),
            "a MAC check outside the scan in {name}"
        );
    }
}

fn store(fx: &super::Fx, name: &str, raw: &[u8]) -> crate::Node {
    let dir = fx.path.join(dir_path(&ENC, &MAC, b""));
    fs::write(dir.join(raw_name(&ENC, &MAC, b"", name)), raw).unwrap();
    fx.find(&fx.root(), name).node
}

/// What an attempt released: an error must come with no bytes at all.
fn attempt(fx: &super::Fx, node: &crate::Node) -> (Result<u64, Error>, Vec<u8>) {
    let mut out = Vec::new();
    let got = fx.vault.read_to(node, &mut out, &mut |_, _| true);
    (got, out)
}

/// FIL-04.6: a right file from another writer opens; every way of breaking it is the one
/// error and no plaintext reaches the sink: a bad tag anywhere, a swap, a repeat, a
/// splice from another file, a cut fragment, an append.
#[test]
fn fil04_t06_bad_chunks_release_nothing() {
    let fx = fx("chunks");
    let plain = demo_bytes(CHUNK * 3 + 500, 1);
    let good = seal_plain(&ENC, &plain);
    let node = store(&fx, "a.bin", &good);
    assert_eq!(attempt(&fx, &node), (Ok(plain.len() as u64), plain.clone()));
    let slot = 12 + CHUNK + 16;
    let chunk = |i: usize| good[68 + i * slot..68 + (i + 1) * slot].to_vec();
    let last = good[68 + 3 * slot..].to_vec();
    let other = seal_plain(&ENC, &demo_bytes(CHUNK * 3 + 500, 2));
    let head = good[..68].to_vec();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    for (what, at) in [
        ("first tag", 68 + slot - 1),
        ("middle tag", 68 + 2 * slot - 1),
        ("last tag", good.len() - 1),
    ] {
        let mut bad = good.clone();
        bad[at] ^= 1;
        cases.push((what, bad));
    }
    cases.push((
        "swap",
        [head.clone(), chunk(1), chunk(0), chunk(2), last.clone()].concat(),
    ));
    cases.push((
        "repeat",
        [head.clone(), chunk(0), chunk(0), chunk(2), last.clone()].concat(),
    ));
    cases.push((
        "splice",
        [
            head.clone(),
            chunk(0),
            other[68 + slot..68 + 2 * slot].to_vec(),
            chunk(2),
            last.clone(),
        ]
        .concat(),
    ));
    cases.push((
        "another header",
        [
            other[..68].to_vec(),
            chunk(0),
            chunk(1),
            chunk(2),
            last.clone(),
        ]
        .concat(),
    ));
    cases.push((
        "short fragment",
        [head.clone(), chunk(0), vec![1u8; 27]].concat(),
    ));
    cases.push(("append bytes", [good.clone(), vec![0u8; 5]].concat()));
    cases.push(("append empty chunk", [good.clone(), vec![0u8; 28]].concat()));
    cases.push(("no header", good[..67].to_vec()));
    cases.push(("nothing", Vec::new()));
    for (what, bad) in cases {
        let node = store(&fx, "a.bin", &bad);
        assert_eq!(
            attempt(&fx, &node),
            (Err(Error::Open), Vec::new()),
            "{what}"
        );
    }
}

/// FIL-04.6: an empty file both ways: header only from this crate and the peers, and the
/// one zero-payload chunk, legal only alone.
#[test]
fn fil04_t06_the_empty_forms() {
    let fx = fx("empty");
    let node = fx.write(&fx.root(), "empty.txt", b"");
    assert_eq!(fs::metadata(raw_path(&fx, "empty.txt")).unwrap().len(), 68);
    assert_eq!(fx.read(&node), b"");
    let node = store(&fx, "one-empty.bin", &seal_with(&ENC, &[3; 32], b"", true));
    assert_eq!(fx.read(&node), b"");
    assert_eq!(fx.find(&fx.root(), "one-empty.bin").size, Some(0));
    assert_eq!(
        content::plan(68),
        Ok(Plan {
            chunks: 0,
            plain: 0
        })
    );
    assert_eq!(
        content::plan(68 + 28),
        Ok(Plan {
            chunks: 1,
            plain: 0
        })
    );
    assert_eq!(
        content::plan(68 + 32_796),
        Ok(Plan {
            chunks: 1,
            plain: 32_768
        })
    );
    assert_eq!(
        content::plan(68 + 32_796 + 28),
        Err(Error::Open),
        "an empty chunk behind a full one"
    );
    assert_eq!(content::plan(68 + 27), Err(Error::Open));
    assert_eq!(content::plan(67), Err(Error::Open));
    assert_eq!(content::plan(u64::MAX), Err(Error::Open));
    assert_eq!(content::plan(i64::MAX as u64 + 1), Err(Error::Open));
    assert_eq!(content::stored_len(0), Ok(68));
    assert_eq!(content::stored_len(1), Ok(68 + 29));
    assert_eq!(content::stored_len(32_768), Ok(68 + 32_796));
    assert_eq!(content::stored_len(32_769), Ok(68 + 32_796 + 29));
    assert_eq!(content::stored_len(u64::MAX), Err(Error::Input));
}

/// FIL-04.6, FIL-06.1: a worker that sits on the first chunk holds up the whole line, and
/// the line never grows past 8 chunks: no unbounded queue, and output stays in order.
#[test]
fn fil04_t06_the_queue_stays_bounded_under_a_slow_first_worker() {
    let keys = demo_keys();
    let plain = demo_bytes(CHUNK * 40 + 7, 3);
    let raw = seal_plain(&ENC, &plain);
    let plan = content::plan(raw.len() as u64).unwrap();
    assert_eq!(plan.chunks, 41);
    let header: [u8; 68] = raw[..68].try_into().unwrap();
    let (key, nonce) = content::open_header(&keys, &header).unwrap();
    let revoked = AtomicBool::new(false);
    let mut go = |_: Phase, _: u64| true;
    let mut gate = Gate {
        revoked: &revoked,
        control: &mut go,
        phase: Phase::Validate,
        done: 0,
    };
    let read_at = std::cell::Cell::new(0u64);
    let peak = std::cell::Cell::new(0u64);
    let taken = std::cell::Cell::new(0u64);
    let mut got = Vec::new();
    SLOW_FIRST_MS.store(120, Ordering::SeqCst);
    let result = content::open_chunks(
        &key,
        &nonce,
        plan,
        4,
        &mut |at, room| {
            room.copy_from_slice(&raw[at as usize..at as usize + room.len()]);
            read_at.set(read_at.get() + 1);
            peak.set(peak.get().max(read_at.get() - taken.get()));
            Ok(())
        },
        &mut gate,
        &mut |bytes| {
            got.extend_from_slice(bytes);
            taken.set(taken.get() + 1);
            Ok(())
        },
    );
    SLOW_FIRST_MS.store(0, Ordering::SeqCst);
    result.unwrap();
    assert_eq!(got, plain, "in order, whatever the workers did");
    assert_eq!(
        peak.get(),
        QUEUE as u64,
        "reached the bound and stayed there"
    );
}

/// The same bound on the writing side, and one worker gives the same bytes.
#[test]
fn fil06_t16_the_seal_pipeline_keeps_order_with_1_and_4_workers() {
    let keys = demo_keys();
    let plain = demo_bytes(CHUNK * 20 + 3, 4);
    for workers in [1, 2, 4, 9] {
        let (header, key, nonce) = content::new_header(&keys).unwrap();
        let revoked = AtomicBool::new(false);
        let mut go = |_: Phase, _: u64| true;
        let mut gate = Gate {
            revoked: &revoked,
            control: &mut go,
            phase: Phase::Encrypt,
            done: 0,
        };
        let mut raw = header.to_vec();
        let n = content::seal_chunks(
            &key,
            &nonce,
            workers,
            GCM_INVOCATIONS,
            &mut &plain[..],
            &mut gate,
            &mut |b| {
                raw.extend_from_slice(b);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(n, plain.len() as u64);
        let mut back = Vec::new();
        content::open_bytes(&keys, &raw, workers, &mut |b| {
            back.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(back, plain, "{workers}");
    }
}

/// FIL-06.16: the per-key limit stops before the chunk past it, not after.
#[test]
fn fil06_t16_a_content_key_stops_at_its_limit() {
    let keys = demo_keys();
    let plain = demo_bytes(CHUNK * 3, 5);
    let (_, key, nonce) = content::new_header(&keys).unwrap();
    let revoked = AtomicBool::new(false);
    let run = |limit: u64| {
        let mut go = |_: Phase, _: u64| true;
        let mut gate = Gate {
            revoked: &revoked,
            control: &mut go,
            phase: Phase::Encrypt,
            done: 0,
        };
        let mut written = 0usize;
        let got = content::seal_chunks(
            &key,
            &nonce,
            4,
            limit,
            &mut &plain[..],
            &mut gate,
            &mut |b| {
                written += b.len();
                Ok(())
            },
        );
        (got, written)
    };
    assert_eq!(run(3).0, Ok(plain.len() as u64));
    let (got, _) = run(2);
    assert_eq!(got, Err(Error::Budget));
    // The reader's plan refuses a file past 2^32 chunks.
    let past = 68 + 32_796 * (GCM_INVOCATIONS + 1);
    assert_eq!(content::plan(past), Err(Error::Open));
    assert_eq!(
        content::plan(68 + 32_796 * GCM_INVOCATIONS).map(|p| p.chunks),
        Ok(GCM_INVOCATIONS)
    );
}

/// FIL-04.7, FIL-06.5: whole trailing chunks removed from a right file open as a shorter
/// file. There is no cryptographic signal for this in the format: it is recorded as S6's
/// disclosure limit (LD-373), not a pass and not a defect of this crate.
#[test]
fn fil04_t07_authentic_trailing_chunk_removal_is_a_disclosed_limit() {
    let fx = fx("cut");
    let plain = demo_bytes(CHUNK * 3, 6);
    let good = seal_plain(&ENC, &plain);
    let slot = 12 + CHUNK + 16;
    let node = store(&fx, "cut.bin", &good[..68 + 2 * slot]);
    assert_eq!(
        fx.read(&node),
        &plain[..CHUNK * 2],
        "S6 limit: opens shorter, no signal"
    );
    let node = store(&fx, "cut.bin", &good[..68]);
    assert_eq!(fx.read(&node), b"", "S6 limit: down to nothing");
}

/// FIL-04.8: a whole other authentic file in a name's place, and an older version, open
/// as if nothing happened: names bind to a parent, not content to a name. S6's disclosure
/// limits. The local known-history check that stops automatic use is E23-S4 with S6.
#[test]
fn fil04_t08_authentic_swap_and_replay_pass_and_are_disclosed() {
    let fx = fx("swap");
    let root = fx.root();
    let a = fx.write(&root, "a.txt", b"content of a");
    let b = fx.write(&root, "b.txt", b"content of b");
    let (pa, pb) = (raw_path(&fx, "a.txt"), raw_path(&fx, "b.txt"));
    let (ra, rb) = (fs::read(&pa).unwrap(), fs::read(&pb).unwrap());
    fs::write(&pa, &rb).unwrap();
    fs::write(&pb, &ra).unwrap();
    assert_eq!(fx.read(&a), b"content of b", "S6 limit: swap in place");
    assert_eq!(fx.read(&b), b"content of a");
    // Replay of an older version of one file.
    fs::write(&pa, &ra).unwrap();
    let base = fx.digest(&a);
    let saved = fx
        .vault
        .update_file(&a, &base, &mut &b"newer"[..], 5, &mut |_, _| true)
        .unwrap();
    assert_eq!(saved.outcome, crate::Outcome::Replaced);
    fs::write(&pa, &ra).unwrap();
    assert_eq!(fx.read(&a), b"content of a", "S6 limit: replay, no signal");
}

/// FIL-06.4: only a stable source is captured: a change while copying, by size or by time,
/// aborts before anything could be proven.
#[test]
fn fil06_t04_a_source_changed_during_capture_is_refused() {
    let fx = fx("custody");
    let root = fx.root();
    let node = fx.write(&root, "c.bin", &demo_bytes(3_000_000, 7));
    let path = raw_path(&fx, "c.bin");
    let good = fs::read(&path).unwrap();
    let (grow, trunc, touch) = (path.clone(), path.clone(), path.clone());
    seam::at_every_point(move |point| {
        if point == "capture.before_recheck" {
            let mut bytes = fs::read(&grow).unwrap();
            bytes.push(1);
            fs::write(&grow, bytes).unwrap();
        }
    });
    assert_eq!(
        fx.vault.capture(&node, &mut |_, _| true).err(),
        Some(Error::Io)
    );
    seam::clear();
    fs::write(&trunc, &good).unwrap();
    let t2 = trunc.clone();
    seam::at_every_point(move |point| {
        if point == "capture.after_open" {
            let f = fs::OpenOptions::new().write(true).open(&t2).unwrap();
            f.set_len(10).unwrap();
        }
    });
    assert_eq!(
        fx.vault.capture(&node, &mut |_, _| true).err(),
        Some(Error::Io)
    );
    seam::clear();
    fs::write(&touch, &good).unwrap();
    let t3 = touch.clone();
    seam::at_every_point(move |point| {
        if point == "capture.before_recheck" {
            // Same size, same inode, other time.
            let f = fs::OpenOptions::new().write(true).open(&t3).unwrap();
            let when =
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
            f.set_modified(when).unwrap();
        }
    });
    assert_eq!(
        fx.vault.capture(&node, &mut |_, _| true).err(),
        Some(Error::Io)
    );
    seam::clear();
    fs::write(&path, &good).unwrap();
    assert_eq!(
        fx.read(&node),
        demo_bytes(3_000_000, 7),
        "a stable source reads"
    );
    // Nothing stayed in scratch.
    let scratch = fx.stores_path.join("scratch");
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
}

/// FIL-06.4: custody is one read handle on a nameless file, and storage changing after
/// the capture changes nothing: same bytes, same result, no reopen of the original path.
#[test]
fn fil06_t04_after_capture_storage_no_longer_matters() {
    let fx = fx("sealed");
    let root = fx.root();
    let plain = demo_bytes(200_000, 8);
    let node = fx.write(&root, "s.bin", &plain);
    let path = raw_path(&fx, "s.bin");
    let snapshot = fx.vault.capture(&node, &mut |_, _| true).unwrap();
    assert_eq!(
        fs::read_dir(fx.stores_path.join("scratch"))
            .unwrap()
            .count(),
        0,
        "no name left"
    );
    fs::write(&path, b"storage changed under the capture").unwrap();
    let validated = snapshot.validate(&mut |_, _| true).unwrap();
    fs::remove_file(&path).unwrap();
    let mut out = Vec::new();
    validated.write_to(&mut out, &mut |_, _| true).unwrap();
    assert_eq!(out, plain);
}

/// FIL-06.4, FIL-04.11: a second name made for a stored object after it was listed (a hard
/// link, another way to change it) is refused when the object is opened, and nothing is
/// captured; with the second name gone it reads.
#[test]
fn fil06_t04_a_second_name_made_after_listing_is_refused() {
    let fx = fx("second-name");
    let root = fx.root();
    let node = fx.write(&root, "h.bin", b"one name only");
    let other = fx.top.join("the-other-name");
    fs::hard_link(raw_path(&fx, "h.bin"), &other).unwrap();
    assert_eq!(
        fx.vault.capture(&node, &mut |_, _| true).err(),
        Some(Error::Open)
    );
    fs::remove_file(&other).unwrap();
    assert_eq!(fx.read(&node), b"one name only");
}

/// FIL-06.5: the release pass is a full second pass. Validation is complete before any
/// plaintext goes: a sink is never called while validating, even for good chunks.
#[test]
fn fil06_t05_the_sink_sees_nothing_until_the_whole_file_is_proven() {
    let fx = fx("two-pass");
    let root = fx.root();
    let plain = demo_bytes(CHUNK * 3 + 9, 4);
    let node = fx.write(&root, "t.bin", &plain);
    let mut phases = Vec::new();
    let snapshot = fx
        .vault
        .capture(&node, &mut |p, _| {
            phases.push(p);
            true
        })
        .unwrap();
    let digest = snapshot.digest();
    let validated = snapshot
        .validate(&mut |p, _| {
            phases.push(p);
            true
        })
        .unwrap();
    assert_eq!(validated.digest(), digest);
    assert_eq!(validated.plain_len(), plain.len() as u64);
    let mut out = Vec::new();
    validated
        .write_to(&mut out, &mut |p, _| {
            phases.push(p);
            true
        })
        .unwrap();
    assert_eq!(out, plain);
    let first_write = phases.iter().position(|p| *p == Phase::Write).unwrap();
    let last_validate = phases.iter().rposition(|p| *p == Phase::Validate).unwrap();
    assert!(last_validate < first_write);
    assert_eq!(phases.iter().filter(|p| **p == Phase::Validate).count(), 4);
}

/// FIL-06.16, FIL-04-T05: every header and backup takes from one ledger, whatever the
/// content key; a fresh key resets nothing, restart loses nothing, and the end is an end.
#[test]
fn fil06_t16_the_shared_budget_counts_every_header_and_stops_at_the_end() {
    let mut fx = fx("budget");
    let root = fx.root();
    let start = fx.vault.budget_report().unwrap();
    assert_eq!(start.limit, 1 << 32);
    assert!(
        !start.peer_history_certified,
        "another Mac's use is unknown"
    );
    fx.write(&root, "one.bin", b"1");
    let reserved = fx.vault.budget_report().unwrap().reserved;
    assert_eq!(
        reserved,
        start.reserved + RESERVE_BLOCK,
        "reserved before use, in a block"
    );
    // A restart never reuses a reservation: the unused rest is lost, never handed back.
    fx.reopen();
    assert_eq!(fx.vault.budget_report().unwrap().reserved, reserved);
    let root = fx.root();
    fx.write(&root, "two.bin", b"2");
    assert_eq!(
        fx.vault.budget_report().unwrap().reserved,
        reserved + RESERVE_BLOCK
    );

    // A boundary: exactly one left. A file takes it; the next attempt stops.
    let keys = demo_keys();
    fx.vault
        .budget
        .set_for_tests(&keys, GCM_INVOCATIONS - 1)
        .unwrap();
    fx.write(&root, "last.bin", b"3");
    assert_eq!(fx.vault.budget_report().unwrap().reserved, GCM_INVOCATIONS);
    let before = raw_tree(&fx.path);
    assert_eq!(
        fx.vault
            .create_file(&root, "over.bin", &mut &b"4"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Budget)
    );
    // A folder's backup is an invocation like any other.
    assert_eq!(fx.vault.make_dir(&root, "sub").err(), Some(Error::Budget));
    assert_eq!(raw_tree(&fx.path), before, "nothing changed");
    assert!(fx.no_staging_left());
    // An update of an old file: a fresh content key does not reset the header budget.
    let one = fx.find(&root, "one.bin").node;
    let base = fx.digest(&one);
    assert_eq!(
        fx.vault
            .update_file(&one, &base, &mut &b"5"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Budget)
    );
    assert_eq!(fx.read(&one), b"1", "reads go on");
    // Exhausted stays exhausted across a restart.
    fx.reopen();
    let root = fx.root();
    assert_eq!(
        fx.vault
            .create_file(&root, "over.bin", &mut &b"4"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Budget)
    );
}

/// FIL-06.16: a failed or cancelled attempt spends what it took; nothing is refunded.
#[test]
fn fil06_t16_failed_and_cancelled_attempts_are_not_refunded() {
    let fx = fx("no-refund");
    let root = fx.root();
    let keys = demo_keys();
    // Two left: each attempt takes one, used or not.
    fx.vault
        .budget
        .set_for_tests(&keys, GCM_INVOCATIONS - 2)
        .unwrap();
    seam::fail_at("write.chunk", Error::Io);
    assert_eq!(
        fx.vault
            .create_file(&root, "a", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Io)
    );
    seam::clear();
    assert_eq!(
        fx.vault
            .create_file(&root, "b", &mut &b"x"[..], 1, &mut |_, _| false)
            .err(),
        Some(Error::Cancelled)
    );
    assert_eq!(
        fx.vault
            .create_file(&root, "c", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Budget)
    );
}

/// FIL-06.16: two instances on one store get different blocks: nothing is used twice.
#[test]
fn fil06_t16_concurrent_instances_reserve_different_blocks() {
    let fx = fx("two-instances");
    let other = Vault::unlock(&fx.path, &secret(PASSWORD), &fx.stores, &mut |_, _| true).unwrap();
    let (a, b): (&Vault, &Vault) = (&fx.vault, &other);
    std::thread::scope(|s| {
        for v in [a, b] {
            s.spawn(move || {
                let keys = demo_keys();
                for _ in 0..(RESERVE_BLOCK as usize + 10) {
                    v.budget.take(&keys).unwrap();
                }
            });
        }
    });
    let reserved = fx.vault.budget_report().unwrap().reserved;
    assert_eq!(reserved, RESERVE_BLOCK * 4, "two blocks each, none shared");
}

/// FIL-06.16: one copy rolled back or damaged moves nothing back; both damaged stops
/// writes; both rolled back together is the disclosed limit.
#[test]
fn fil06_t16_ledger_rollback_and_damage() {
    let mut fx = fx("ledger");
    let root = fx.root();
    fx.write(&root, "a", b"a");
    let store_id = demo_keys().store_id().unwrap();
    let dir = fx.stores_path.join("ledger").join(store_id);
    let (pa, pb) = (dir.join("ledger.a"), dir.join("ledger.b"));
    let early = fs::read(&pa).unwrap();
    fx.write(&root, "b", b"b");
    fx.reopen();
    let root = fx.root();
    fx.write(&root, "c", b"c");
    let high = fx.vault.budget_report().unwrap().reserved;
    assert!(high >= 2 * RESERVE_BLOCK);
    // One copy rolled back: the other wins.
    fs::write(&pa, &early).unwrap();
    assert_eq!(fx.vault.budget_report().unwrap().reserved, high);
    // One copy damaged: the other wins, and the next reservation goes above it.
    fs::write(&pb, b"not a ledger").unwrap();
    assert!(fx.vault.budget_report().is_ok());
    fs::write(&pa, b"not a ledger either").unwrap();
    assert_eq!(fx.vault.budget_report().err(), Some(Error::Budget));
    fx.reopen();
    let root = fx.root();
    assert_eq!(
        fx.vault
            .create_file(&root, "d", &mut &b"d"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Budget)
    );
    assert_eq!(fx.read(&fx.find(&root, "a").node), b"a", "reads go on");
    // Both rolled back together: not detectable. Disclosed, not defended.
    fs::write(&pa, &early).unwrap();
    fs::write(&pb, &early).unwrap();
    assert!(
        fx.vault.budget_report().unwrap().reserved < high,
        "disclosed limit"
    );
}

/// FIL-06.16, C2-03: a copy that reads well but whose MAC is not its count's is believed
/// by nothing: a changed MAC, or a higher count under an old MAC.
#[test]
fn fil06_t16_a_ledger_copy_with_a_changed_mac_is_refused() {
    let fx = fx("ledger-mac");
    let root = fx.root();
    fx.write(&root, "a", b"a");
    let store_id = demo_keys().store_id().unwrap();
    let dir = fx.stores_path.join("ledger").join(store_id);
    let (pa, pb) = (dir.join("ledger.a"), dir.join("ledger.b"));
    let high = fx.vault.budget_report().unwrap().reserved;
    let good = fs::read_to_string(&pa).unwrap();
    let (count, tag) = good.trim_end().split_once('\n').unwrap();
    assert_eq!(count, high.to_string(), "the control reads");
    let flipped = format!(
        "{}{}",
        if tag.starts_with('0') { '1' } else { '0' },
        &tag[1..]
    );
    // Higher counts under a changed MAC and under the old one: the good copy wins.
    let far = high + 10 * RESERVE_BLOCK;
    for forged in [format!("{far}\n{flipped}\n"), format!("{far}\n{tag}\n")] {
        fs::write(&pa, &forged).unwrap();
        assert_eq!(fx.vault.budget_report().unwrap().reserved, high, "{forged}");
    }
    // Both copies forged: nothing proves itself, so writes stop.
    fs::write(&pa, format!("5\n{flipped}\n")).unwrap();
    fs::write(&pb, format!("5\n{flipped}\n")).unwrap();
    assert_eq!(fx.vault.budget_report().err(), Some(Error::Budget));
    // The same count, MAC and all, in another text: refused too, one text per count.
    fs::write(&pa, format!("{count}\n{}\n", tag.to_uppercase())).unwrap();
    fs::write(&pb, format!("0{count}\n{tag}\n")).unwrap();
    assert_eq!(fx.vault.budget_report().err(), Some(Error::Budget));
    fs::write(&pa, &good).unwrap();
    assert_eq!(fx.vault.budget_report().unwrap().reserved, high);
}

/// FIL-06.16: a crash between the two copies leaves the higher count standing.
#[test]
fn fil06_t16_a_crash_between_the_ledger_copies_does_not_reuse() {
    let mut fx = fx("ledger-crash");
    let root = fx.root();
    fx.write(&root, "a", b"a");
    let high = fx.vault.budget_report().unwrap().reserved;
    fx.reopen();
    let root = fx.root();
    seam::crash_at("budget.after_first_copy");
    assert!(
        fx.vault
            .create_file(&root, "b", &mut &b"b"[..], 1, &mut |_, _| true)
            .is_err()
    );
    seam::clear();
    assert_eq!(
        fx.vault.budget_report().unwrap().reserved,
        high + RESERVE_BLOCK
    );
}

/// The whole-file hash a version is known by is the ciphertext's, in full (FIL-06.10).
#[test]
fn fil06_t10_a_version_digest_is_the_sha256_of_all_its_ciphertext() {
    let fx = fx("digest");
    let root = fx.root();
    let node = fx.write(&root, "d.bin", &demo_bytes(70_000, 2));
    let raw = fs::read(raw_path(&fx, "d.bin")).unwrap();
    assert_eq!(fx.digest(&node).hex(), hex(hash::sha256(&[&raw]).expose()));
}
