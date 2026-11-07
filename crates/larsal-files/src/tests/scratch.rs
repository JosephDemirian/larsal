//! Story check 4: plaintext is never written to a temporary file. A test that
//! watches the scratch folder and every file system call the crate makes.

use super::*;
use crate::{OutputFolder, ScratchRoot, SourceFile};
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};

const MARKER: &[u8] = b"PLAINTEXT-MARKER-E22S3";

fn marked_plain(size: usize) -> Vec<u8> {
    let mut plain = MARKER.repeat(size / MARKER.len() + 1);
    plain.truncate(size);
    plain
}

fn holds_marker(bytes: &[u8]) -> bool {
    bytes.windows(MARKER.len()).any(|w| w == MARKER)
}

/// Every file under `dir`, read through its name, right now.
fn scan(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            found.extend(scan(&path));
        } else if meta.is_file() && fs::read(&path).is_ok_and(|b| holds_marker(&b)) {
            found.push(path.display().to_string());
        }
    }
    found
}

#[test]
fn check4_no_plaintext_reaches_scratch_in_a_whole_decrypt() {
    let t = Temp::new();
    let scratch_dir = t.sub("scratch");
    let out_dir = t.sub("out");
    let plain = marked_plain(3 * crate::limits::CHUNK + 99);
    let ciphertext = seal_to(&plain, &[rec(ID_A)]);
    assert!(!holds_marker(&ciphertext));
    let input = t.file("demo.age", &ciphertext);

    let root = ScratchRoot::open(&scratch_dir).unwrap();
    let folder = OutputFolder::open(&out_dir).unwrap();
    let keys = ids(ID_A);
    watch::take();

    // The watcher runs after every chunk of every phase.
    let mut scans = 0;
    let mut phases = Vec::new();
    let mut watcher = |phase: Phase, _: u64| {
        scans += 1;
        if phases.last() != Some(&phase) {
            phases.push(phase);
        }
        assert!(
            scan(&scratch_dir).is_empty(),
            "plaintext in scratch at {phase:?}"
        );
        if phase != Phase::Write {
            assert!(
                names_in(&out_dir).is_empty(),
                "output before the check, at {phase:?}"
            );
        }
        true
    };
    let sealed = root
        .capture_file(SourceFile::open(&input).unwrap(), &mut watcher)
        .unwrap();
    assert!(
        names_in(&scratch_dir).is_empty(),
        "sealed: nothing has a name"
    );
    let unwrapped = sealed.unlock(&Unlock::Identities(&keys)).unwrap();
    let validation = unwrapped.validate(&mut watcher).unwrap();
    let Validation::Ready(validated) = validation else {
        panic!("X25519 files have no work factor");
    };
    let name: &OsStr = "demo.out".as_ref();
    validated.save_new(&folder, name, &mut watcher).unwrap();
    assert_eq!(phases, [Phase::Capture, Phase::Validate, Phase::Write]);
    assert!(scans > 8);
    assert_eq!(fs::read(out_dir.join(name)).unwrap(), plain);

    // The order of every call the crate made, and what each was given.
    let events = watch::take();
    let (mut seen_seal, mut seen_output) = (false, false);
    let mut captured = Vec::new();
    for event in &events {
        match event {
            Event::ScratchDir | Event::ScratchCreate => {
                assert!(!seen_seal && !seen_output);
            }
            Event::ScratchWrite(bytes) => {
                assert!(!seen_seal, "a scratch write after the seal");
                assert!(!holds_marker(bytes), "plaintext written to scratch");
                captured.extend_from_slice(bytes);
            }
            Event::ScratchSeal => seen_seal = true,
            Event::OutputCreate => {
                assert!(seen_seal, "output before the snapshot was sealed");
                seen_output = true;
            }
            Event::OutputWrite(_) => assert!(seen_output),
        }
    }
    assert!(seen_seal && seen_output);
    assert_eq!(captured, ciphertext, "scratch took exactly the ciphertext");

    // And a fresh capture's sealed inode still holds the ciphertext only.
    let mut fresh = root
        .capture_file(SourceFile::open(&input).unwrap(), &mut keep)
        .unwrap();
    let mut bytes = Vec::new();
    fresh.src.seek(SeekFrom::Start(0)).unwrap();
    fresh.src.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, ciphertext);
}

#[test]
fn check4_a_failed_decrypt_touches_no_output_and_leaves_no_scratch() {
    let t = Temp::new();
    let scratch_dir = t.sub("scratch");
    let plain = marked_plain(100_000);
    let mut bad = seal_to(&plain, &[rec(ID_A)]);
    *bad.last_mut().unwrap() ^= 1;
    let input = t.file("demo.age", &bad);
    let root = ScratchRoot::open(&scratch_dir).unwrap();
    let keys = ids(ID_A);
    watch::take();
    let snapshot = root
        .capture_file(SourceFile::open(&input).unwrap(), &mut keep)
        .unwrap();
    let result = snapshot
        .unlock(&Unlock::Identities(&keys))
        .and_then(|u| u.validate(&mut keep));
    assert_eq!(result.map(|_| ()), Err(Error::Decrypt));
    assert!(no_output(&watch::take()));
    assert!(names_in(&scratch_dir).is_empty());
}

#[test]
fn check4_encrypting_uses_no_scratch_and_writes_only_ciphertext() {
    let t = Temp::new();
    let plain = marked_plain(200_000);
    let input = t.file("demo.bin", &plain);
    let out_dir = t.sub("out");
    let folder = OutputFolder::open(&out_dir).unwrap();
    let recipients = [rec(ID_A)];
    watch::take();
    crate::encrypt_file(
        SourceFile::open(&input).unwrap(),
        &folder,
        "demo.age".as_ref(),
        &Lock::Recipients(&recipients),
        &mut keep,
    )
    .unwrap();
    let events = watch::take();
    assert!(matches!(events.first(), Some(Event::OutputCreate)));
    for event in &events {
        match event {
            Event::OutputCreate => {}
            Event::OutputWrite(bytes) => assert!(!holds_marker(bytes)),
            other => panic!("encrypting asked for {other:?}"),
        }
    }
    let written = fs::read(out_dir.join("demo.age")).unwrap();
    assert!(!holds_marker(&written));
    let keys = ids(ID_A);
    assert_eq!(open(&written, &Unlock::Identities(&keys)).unwrap(), plain);
}

#[test]
fn check4_only_the_file_system_module_can_reach_the_disk() {
    // Whole words of code, with comments out: `fs` bans all of std::fs, whatever
    // the path says around it. Nothing outside fsio.rs needs one of these, and
    // this crate forbids unsafe, so no other door is left. fsio.rs has its own
    // scan below.
    let banned = [
        "fs",
        "File",
        "os",
        "libc",
        "larsal_platform",
        "OpenOptions",
        "DirBuilder",
        "NamedTempFile",
        "tempfile",
        "mmap",
        "create_in",
        "remove_in",
        "rename_in",
        "open_regular",
        "open_regular_nofollow",
        "write_scratch",
        "temp_dir",
        "stdout",
        "stderr",
        "print",
        "println",
        "eprint",
        "eprintln",
        "dbg",
        "Command",
    ];
    let mut scanned = 0;
    for (name, source) in production_sources() {
        if name == "fsio.rs" {
            continue;
        }
        scanned += 1;
        for line in source.lines() {
            let code = line.split("//").next().unwrap();
            for word in code.split(|c: char| !c.is_alphanumeric() && c != '_') {
                assert!(!banned.contains(&word), "{name} names {word}: {line}");
            }
        }
    }
    assert!(scanned >= 10);
    // Within it, scratch gets bytes in one place only: the capture's copy, whose
    // input is the source reader. It has no parameter a plaintext could arrive by.
    let fsio =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fsio.rs")).unwrap();
    let calls = fsio.matches("write_scratch(").count();
    assert_eq!(calls, 2, "one definition and one call");
    assert!(!fsio.contains("Unwrapped") && !fsio.contains("Validated<"));

    // fsio.rs itself: no print and no temp file, and no helper the rest of the crate
    // could hand plaintext to beyond the output's own.
    let production = fsio
        .split("#[cfg(test)]\npub(crate) mod watch")
        .next()
        .unwrap();
    let words = [
        "temp_dir",
        "tempfile",
        "NamedTempFile",
        "mmap",
        "Command",
        "stdout",
        "stderr",
        "print",
        "println",
        "eprint",
        "eprintln",
        "dbg",
    ];
    for line in production.lines() {
        let code = line.split("//").next().unwrap();
        for word in code.split(|c: char| !c.is_alphanumeric() && c != '_') {
            assert!(!words.contains(&word), "fsio.rs names {word}: {line}");
        }
        for call in ["fs::write", "fs::copy"] {
            assert!(!code.contains(call), "fsio.rs calls {call}: {line}");
        }
    }
    let doors: Vec<&str> = production
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub(crate) fn "))
        .map(|rest| rest.split(['(', '<']).next().unwrap())
        .collect();
    assert_eq!(
        doors,
        [
            "reader",
            "check_unchanged",
            "create",
            "write",
            "finish",
            "abort"
        ]
    );
}
